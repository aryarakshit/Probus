"""
Aegis Subnet Server & Interactive Command Center (server.py)
Hosts the FastAPI REST API and live Web Dashboard for hackathon judges and developers.
Coordinates Validator, Translator Miners, and Breaker Miners with real-time visualization.
"""

import sys
import os
import time
import json
import logging
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Set defaults for standalone server execution
if not os.environ.get("AEGIS_ALLOW_UNSANDBOXED"):
    os.environ["AEGIS_ALLOW_UNSANDBOXED"] = "1"
if not os.environ.get("AEGIS_MOCK"):
    os.environ["AEGIS_MOCK"] = "1"

import substrate as bt
from protocol import TranslationSynapse, BreakerSynapse
from neurons.miner_translator import TranslatorMiner, parse_args as parse_tr_args
from neurons.miner_breaker import BreakerMiner, parse_args as parse_br_args
from neurons.validator import Validator, static_analysis_gate, parse_args as parse_val_args
from neurons.scoring import calculate_translator_pre_score
from dataset.tasks import sample_task

logger = logging.getLogger("server")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s")

app = FastAPI(title="Aegis Subnet - C-to-Safe-Rust Subnet", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global subnet state
SUBNET_STATE = {
    "validator": None,
    "miners": {},
    "round_history": [],
    "total_rounds": 0,
    "current_block": 1000,
    "active_weights": {}
}


def load_round_history_from_disk(log_file="rounds.jsonl") -> List[Dict[str, Any]]:
    history = []
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        history.append(json.loads(line))
                    except Exception:
                        pass
    return history


def init_subnet():
    """Spin up Validator and the 4 archetypal Miners."""
    logger.info("Initializing Subnet Nodes...")
    
    # 1. Validator
    v_args = parse_val_args([])
    v_args.wallet_hotkey = "val_prime"
    v_args.mock = True
    v_args.no_docker = True
    v_args.log_file = "rounds.jsonl"
    val = Validator(v_args)
    SUBNET_STATE["validator"] = val

    # 2. Honest Translator
    m1_args = parse_tr_args([])
    m1_args.wallet_hotkey = "miner_translator_honest"
    m1_args.mode = "honest"
    m1_args.mock = True
    m_honest = TranslatorMiner(m1_args).run()

    # 3. Weak Translator
    m2_args = parse_tr_args([])
    m2_args.wallet_hotkey = "miner_translator_weak"
    m2_args.mode = "weak"
    m2_args.mock = True
    m_weak = TranslatorMiner(m2_args).run()

    # 4. Cheater Translator
    m3_args = parse_tr_args([])
    m3_args.wallet_hotkey = "miner_translator_cheater"
    m3_args.mode = "cheater"
    m3_args.mock = True
    m_cheater = TranslatorMiner(m3_args).run()

    # 5. Breaker Fuzzer
    m4_args = parse_br_args([])
    m4_args.wallet_hotkey = "miner_breaker"
    m4_args.mock = True
    m_breaker = BreakerMiner(m4_args).run()

    SUBNET_STATE["miners"] = {
        "honest": m_honest,
        "weak": m_weak,
        "cheater": m_cheater,
        "breaker": m_breaker
    }
    
    # Load past rounds from disk
    SUBNET_STATE["round_history"] = load_round_history_from_disk()
    SUBNET_STATE["total_rounds"] = len(SUBNET_STATE["round_history"])
    logger.info(f"All Subnet nodes online. Loaded {SUBNET_STATE['total_rounds']} past rounds from rounds.jsonl.")


@app.on_event("startup")
def on_startup():
    init_subnet()


class ValidationRequest(BaseModel):
    task_name: Optional[str] = "reverse_bytes"
    num_tests: int = 20


class GateCheckRequest(BaseModel):
    rust_code: str


@app.get("/api/status")
def get_status():
    val = SUBNET_STATE["validator"]
    return {
        "status": "online",
        "netuid": 1,
        "current_block": val.subtensor.get_current_block() if val else 1000,
        "total_rounds_completed": len(load_round_history_from_disk()),
        "miners_active": len(SUBNET_STATE["miners"]),
        "latest_weights": SUBNET_STATE["active_weights"],
        "docker_sandbox_active": val.sandbox.docker_available if val else False
    }


@app.get("/api/leaderboard")
def get_leaderboard():
    history = load_round_history_from_disk()
    if not history:
        return {"leaderboard": []}

    scores: Dict[str, List[float]] = {}
    for r in history:
        r_scores = r.get("round_scores", {})
        for hk, sc in r_scores.items():
            scores.setdefault(hk, []).append(float(sc))

    board = []
    for idx, (hk, sc_list) in enumerate(sorted(scores.items(), key=lambda x: sum(x[1])/len(x[1]), reverse=True)):
        avg = sum(sc_list) / len(sc_list)
        role = "Breaker" if "breaker" in hk else "Translator"
        status = "ZERO EMISSION" if avg == 0 else ("ACTIVE" if avg < 0.8 else "STRONG")
        board.append({
            "uid": idx,
            "hotkey": hk,
            "role": role,
            "avg_score": round(avg, 4),
            "status": status,
            "decision": f"Avg Score: {avg:.4f}"
        })
    return {"leaderboard": board}



@app.post("/api/run-round")
def run_round(req: ValidationRequest):
    val: Validator = SUBNET_STATE["validator"]
    miners = SUBNET_STATE["miners"]

    translator_axons = [
        miners["honest"].axon,
        miners["weak"].axon,
        miners["cheater"].axon
    ]
    breaker_axons = [
        miners["breaker"].axon
    ]

    t_start = time.time()
    res = val.run_validation_round(
        translator_axons=translator_axons,
        breaker_axons=breaker_axons,
        num_tests=req.num_tests,
        task_name=req.task_name
    )
    elapsed = time.time() - t_start

    SUBNET_STATE["active_weights"] = res["weights"]
    
    round_payload = {
        "round_id": res["round_id"],
        "timestamp": time.time(),
        "task_name": res["task_name"],
        "elapsed_seconds": round(elapsed, 3),
        "scores": res["round_scores"],
        "weights": res["weights"],
        "details": res.get("details", {}),
        "translator_evals": res.get("translator_evals", {})
    }
    SUBNET_STATE["round_history"] = load_round_history_from_disk()
    return round_payload


@app.post("/api/check-gate")
def check_gate(req: GateCheckRequest):
    t_start = time.time()
    passed, reason = static_analysis_gate(req.rust_code)
    elapsed = time.time() - t_start
    score = calculate_translator_pre_score(
        passed_hidden=1,
        total_hidden=1,
        compile_success=True,
        gate_success=passed,
        code_size_bytes=len(req.rust_code.encode("utf-8"))
    )
    return {
        "passed": passed,
        "reason": reason,
        "elapsed_seconds": round(elapsed, 4),
        "pre_score": score
    }


@app.get("/api/dataset")
def get_dataset():
    task = sample_task("reverse_bytes", seed=42)
    return {
        "task_name": task.task_name,
        "constants": task.constants,
        "sample_c_code": task.c_code,
        "reference_rust": task.reference_rust
    }


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.get("/", response_class=HTMLResponse)
def dashboard():
    html_path = os.path.join(BASE_DIR, "templates", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return Response(content=f.read(), media_type="text/html")


@app.get("/static/css/bauhaus.css")
def get_bauhaus_css():
    css_path = os.path.join(BASE_DIR, "static", "css", "bauhaus.css")
    with open(css_path, "r", encoding="utf-8") as f:
        return Response(content=f.read(), media_type="text/css")


@app.get("/static/js/dashboard.js")
def get_dashboard_js():
    js_path = os.path.join(BASE_DIR, "static", "js", "dashboard.js")
    with open(js_path, "r", encoding="utf-8") as f:
        return Response(content=f.read(), media_type="application/javascript")


def main():
    import uvicorn
    logger.info("Starting Aegis Subnet Command Center on http://127.0.0.1:8000 ...")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()

"""
Probus Subnet command center (server.py)

FastAPI backend for the dashboard. Hosts a validator and four neurons on the mock
substrate, runs rounds in a background thread, and streams every validator
event and log line to the browser over Server-Sent Events so a round can be
watched as it happens: gate verdicts, compile results, breaker hits with their
minimized reproducers, weights, and the ledger commit.

    python server.py            ->  http://127.0.0.1:8000
"""

import sys
import os
import json
import time
import queue
import base64
import logging
import threading
from typing import Optional, List, Dict, Any

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

os.environ.setdefault("PROBUS_ALLOW_UNSANDBOXED", "1")
os.environ.setdefault("PROBUS_MOCK", "1")

from neurons.miner_translator import TranslatorMiner, parse_args as parse_tr_args
from neurons.miner_breaker import BreakerMiner, parse_args as parse_br_args
from neurons.validator import Validator, static_analysis_gate, parse_args as parse_val_args
from neurons.scoring import calculate_translator_pre_score
from neurons.llm import LLMClient
from neurons.ledger import Ledger
from dataset.tasks import sample_task, list_tasks, TASK_DESCRIPTIONS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROUNDS_LOG = os.environ.get("PROBUS_ROUNDS_LOG") or os.path.join(BASE_DIR, "rounds.jsonl")
LEDGER_DIR = os.environ.get("PROBUS_LEDGER_DIR")  # None -> ./ledger
REPLAY_SEEDS = [101, 202, 303]

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("server")

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_subnet()
    yield


app = FastAPI(title="Probus Subnet", version="2.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


# --------------------------------------------------------------------------- events
class EventBus:
    """Fan-out of validator events + log lines to every open SSE connection."""

    def __init__(self):
        self.subscribers: List[queue.Queue] = []
        self.lock = threading.Lock()
        self.recent: List[Dict[str, Any]] = []

    def publish(self, evt: Dict[str, Any]):
        with self.lock:
            self.recent.append(evt)
            self.recent = self.recent[-400:]
            for q in list(self.subscribers):
                try:
                    q.put_nowait(evt)
                except queue.Full:
                    pass

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=2000)
        with self.lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)


BUS = EventBus()


class BusLogHandler(logging.Handler):
    def emit(self, record):
        try:
            BUS.publish({"t": time.time(), "kind": "log", "source": record.name,
                         "level": record.levelname, "msg": record.getMessage()})
        except Exception:
            pass


for name in ("validator", "miner_translator", "miner_breaker", "sandbox", "llm", "substrate"):
    logging.getLogger(name).addHandler(BusLogHandler())


# --------------------------------------------------------------------------- state
STATE: Dict[str, Any] = {"validator": None, "miners": {}, "running": False, "current": None, "llm": None}


def init_subnet():
    v_args = parse_val_args(["--mock", "--no_docker"])
    v_args.wallet_hotkey = "validator"
    v_args.log_file = ROUNDS_LOG
    v_args.ledger_dir = LEDGER_DIR
    STATE["validator"] = Validator(v_args, on_event=BUS.publish)

    def mk_tr(hotkey, mode, extra=()):
        return TranslatorMiner(parse_tr_args(["--mock", "--mode", mode, "--wallet_hotkey", hotkey, *extra])).run()

    STATE["miners"] = {
        "translator_llm": mk_tr("translator_llm", "llm", ["--self_fuzz_seconds", "4"]),
        "translator_weak": mk_tr("translator_weak", "weak"),
        "translator_cheater": mk_tr("translator_cheater", "cheater"),
        "breaker": BreakerMiner(parse_br_args(["--mock", "--wallet_hotkey", "breaker", "--fuzz_seconds", "8"])).run(),
    }
    probe = LLMClient()
    STATE["llm"] = {"provider": probe.provider, "model": probe.model, "mode": "live" if probe.provider else "replay",
                    "replay_files": len(os.listdir(os.path.join(BASE_DIR, "dataset", "llm_replay")))
                    if os.path.isdir(os.path.join(BASE_DIR, "dataset", "llm_replay")) else 0}
    logger.info(f"Subnet online. LLM: {STATE['llm']}")


def load_rounds() -> List[Dict[str, Any]]:
    out = []
    if os.path.exists(ROUNDS_LOG):
        with open(ROUNDS_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if "ledger" in r:          # ignore rows from the pre-ledger schema
                    out.append(r)
    return out


# --------------------------------------------------------------------------- models
class RunRequest(BaseModel):
    task_name: Optional[str] = None
    num_tests: int = 20
    seed: Optional[int] = None


class GateRequest(BaseModel):
    rust_code: str


# --------------------------------------------------------------------------- api
@app.get("/api/status")
def status():
    val: Validator = STATE["validator"]
    rounds = load_rounds()
    return {
        "status": "online",
        "netuid": 1,
        "network": "mock-local",
        "block": val.subtensor.get_current_block() if val else 0,
        "rounds": len(rounds),
        "running": STATE["running"],
        "current": STATE["current"],
        "neurons": {k: {"role": "breaker" if k == "breaker" else "translator",
                        "mode": getattr(m, "mode", "fuzz")} for k, m in STATE["miners"].items()},
        "sandbox": "docker" if (val and val.sandbox.use_docker) else "host-toolchain",
        "llm": STATE["llm"],
        "ledger": val.ledger.stats() if val else {},
        "tasks": len(list_tasks()),
        "ema": val.ema_scores if val else {},
    }


@app.get("/api/tasks")
def tasks():
    out = []
    for name in list_tasks():
        t = sample_task(name, seed=1)
        out.append({"name": name, "description": TASK_DESCRIPTIONS.get(name, ""),
                    "constants": list(t.constants.keys()), "c_lines": t.c_code.count("\n")})
    return {"tasks": out}


@app.get("/api/task/{name}")
def task_source(name: str, seed: int = 1):
    if name not in list_tasks():
        raise HTTPException(404, "unknown task")
    t = sample_task(name, seed=seed)
    return {"name": name, "constants": t.constants, "c_code": t.c_code, "description": TASK_DESCRIPTIONS.get(name, "")}


@app.get("/api/rounds")
def rounds(limit: int = 50):
    rs = load_rounds()
    return {"rounds": rs[-limit:][::-1], "total": len(rs)}


@app.get("/api/rounds/{round_id}")
def round_detail(round_id: int):
    for r in load_rounds():
        if r.get("round_id") == round_id:
            return r
    raise HTTPException(404, "no such round")


@app.get("/api/leaderboard")
def leaderboard():
    rs = load_rounds()
    agg: Dict[str, Dict[str, Any]] = {}
    for r in rs:
        for hk, sc in r.get("round_scores", {}).items():
            a = agg.setdefault(hk, {"hotkey": hk, "rounds": 0, "total": 0.0, "broken": 0, "gated": 0, "bounties": 0})
            a["rounds"] += 1
            a["total"] += float(sc)
            ev = r.get("translator_evals", {}).get(hk)
            if ev:
                a["role"] = "translator"
                if ev.get("broken_by"):
                    a["broken"] += 1
                if not ev.get("gate_success"):
                    a["gated"] += 1
            if hk in r.get("breaker_evals", {}):
                a["role"] = "breaker"
                if float(r["breaker_evals"][hk].get("final_score", 0)) > 0:
                    a["bounties"] += 1
    val: Validator = STATE["validator"]
    latest = rs[-1] if rs else {}
    weights = {hk: float(latest.get("normalized_weights", {}).get(str(uid), 0.0)) for hk, uid in latest.get("uids", {}).items()}
    board = []
    for hk, a in agg.items():
        board.append({**a, "avg": round(a["total"] / max(1, a["rounds"]), 4),
                      "ema": val.ema_scores.get(hk, 0.0) if val else 0.0, "weight": weights.get(hk, 0.0)})
    board.sort(key=lambda x: -x["avg"])
    return {"leaderboard": board}


@app.get("/api/ledger")
def ledger(limit: int = 20):
    val: Validator = STATE["validator"]
    led: Ledger = val.ledger
    entries = []
    if os.path.exists(led.chain_path):
        with open(led.chain_path, "r", encoding="utf-8") as f:
            entries = [json.loads(l) for l in f if l.strip()]
    return {"stats": led.stats(), "chain": entries[-limit:][::-1]}


@app.get("/api/ledger/verify")
def ledger_verify():
    val: Validator = STATE["validator"]
    t0 = time.perf_counter()
    rep = val.ledger.verify()
    rep["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return rep


@app.get("/api/ledger/round/{height}")
def ledger_round(height: int):
    val: Validator = STATE["validator"]
    path = os.path.join(val.ledger.rounds, f"{height:06d}.json")
    if not os.path.exists(path):
        raise HTTPException(404, "no such height")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/api/ledger/object/{digest}")
def ledger_object(digest: str):
    val: Validator = STATE["validator"]
    blob = val.ledger.get(digest)
    if blob is None:
        raise HTTPException(404, "no such object")
    try:
        text = blob.decode("utf-8")
        kind = "text"
    except UnicodeDecodeError:
        text = None
        kind = "binary"
    return {"sha256": digest, "size": len(blob), "kind": kind, "text": text,
            "hex": blob[:512].hex(), "repr": repr(blob[:128]), "b64": base64.b64encode(blob).decode("ascii")}


@app.post("/api/check-gate")
def check_gate(req: GateRequest):
    t0 = time.perf_counter()
    passed, reason = static_analysis_gate(req.rust_code)
    ms = (time.perf_counter() - t0) * 1000
    return {"passed": passed, "reason": reason, "elapsed_ms": round(ms, 4),
            "pre_score": calculate_translator_pre_score(1, 1, True, passed, len(req.rust_code.encode()))}


@app.post("/api/run-round")
def run_round(req: RunRequest):
    if STATE["running"]:
        raise HTTPException(409, "a round is already running")
    val: Validator = STATE["validator"]
    m = STATE["miners"]
    task = req.task_name if req.task_name in list_tasks() else None
    seed = req.seed
    if seed is None and STATE["llm"] and STATE["llm"]["mode"] == "replay":
        seed = REPLAY_SEEDS[val.total_rounds % len(REPLAY_SEEDS)]

    def work():
        STATE["running"] = True
        STATE["current"] = {"task": task or "random", "seed": seed, "started": time.time()}
        try:
            val.run_validation_round(
                translator_axons=[m["translator_llm"].axon, m["translator_weak"].axon, m["translator_cheater"].axon],
                breaker_axons=[m["breaker"].axon], num_tests=req.num_tests, task_name=task, seed=seed)
        except Exception as e:
            logger.exception("round failed")
            BUS.publish({"t": time.time(), "kind": "error", "msg": str(e)})
        finally:
            STATE["running"] = False
            STATE["current"] = None

    threading.Thread(target=work, daemon=True).start()
    return {"started": True, "task": task or "random", "seed": seed}


@app.get("/api/events")
def events():
    q = BUS.subscribe()

    def gen():
        try:
            yield "retry: 2000\n\n"
            yield f"data: {json.dumps({'kind': 'hello', 't': time.time(), 'running': STATE['running']})}\n\n"
            while True:
                try:
                    evt = q.get(timeout=15)
                    yield f"data: {json.dumps(evt, default=str)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            BUS.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/", response_class=HTMLResponse)
def dashboard():
    with open(os.path.join(BASE_DIR, "templates", "index.html"), "r", encoding="utf-8") as f:
        return Response(content=f.read(), media_type="text/html")


def main():
    import uvicorn
    logger.info("Probus command center on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")


if __name__ == "__main__":
    main()

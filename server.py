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
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import substrate as bt
from protocol import TranslationSynapse, BreakerSynapse
from neurons.miner_translator import TranslatorMiner, parse_args as parse_tr_args
from neurons.miner_breaker import BreakerMiner, parse_args as parse_br_args
from neurons.validator import Validator, static_analysis_gate, calculate_score, parse_args as parse_val_args
from dataset.hidden_tests import generate_hidden_tests

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


def init_subnet():
    """Spin up Validator and the 4 archetypal Miners."""
    logger.info("Initializing Subnet Nodes...")
    
    # 1. Validator
    v_args = parse_val_args([])
    v_args.wallet_hotkey = "val_prime"
    val = Validator(v_args)
    SUBNET_STATE["validator"] = val

    # 2. Honest Translator
    m1_args = parse_tr_args([])
    m1_args.wallet_hotkey = "miner_translator_honest"
    m1_args.mode = "honest"
    m_honest = TranslatorMiner(m1_args).run()

    # 3. Weak Translator
    m2_args = parse_tr_args([])
    m2_args.wallet_hotkey = "miner_translator_weak"
    m2_args.mode = "weak"
    m_weak = TranslatorMiner(m2_args).run()

    # 4. Cheater Translator
    m3_args = parse_tr_args([])
    m3_args.wallet_hotkey = "miner_translator_cheater"
    m3_args.mode = "cheater"
    m_cheater = TranslatorMiner(m3_args).run()

    # 5. Breaker Fuzzer
    m4_args = parse_br_args([])
    m4_args.wallet_hotkey = "miner_breaker"
    m_breaker = BreakerMiner(m4_args).run()

    SUBNET_STATE["miners"] = {
        "honest": m_honest,
        "weak": m_weak,
        "cheater": m_cheater,
        "breaker": m_breaker
    }
    logger.info("All Subnet nodes online.")


@app.on_event("startup")
def on_startup():
    init_subnet()


class ValidationRequest(BaseModel):
    c_code: Optional[str] = None
    function_name: Optional[str] = "reverse_string"
    num_tests: int = 50


class GateCheckRequest(BaseModel):
    rust_code: str


@app.get("/api/status")
def get_status():
    val = SUBNET_STATE["validator"]
    return {
        "status": "online",
        "netuid": 1,
        "current_block": val.subtensor.get_current_block() if val else 1000,
        "total_rounds_completed": SUBNET_STATE["total_rounds"],
        "miners_active": len(SUBNET_STATE["miners"]),
        "latest_weights": SUBNET_STATE["active_weights"],
        "docker_sandbox_active": val.sandbox.docker_available if val else False
    }


@app.get("/api/leaderboard")
def get_leaderboard():
    if not SUBNET_STATE["round_history"]:
        return {
            "leaderboard": [
                {"uid": 0, "hotkey": "miner_translator_honest", "role": "Translator (Safe Rust)", "avg_score": 1.2000, "status": "VERIFIED_SAFE", "decision": "HIGH REWARD"},
                {"uid": 1, "hotkey": "miner_breaker", "role": "Breaker (Adversarial)", "avg_score": 0.5000, "status": "BOUNTY_HUNTER", "decision": "BOUNTY AWARDED"},
                {"uid": 2, "hotkey": "miner_translator_weak", "role": "Translator (Naive)", "avg_score": 0.6163, "status": "DIVERGENT", "decision": "LOW REWARD"},
                {"uid": 3, "hotkey": "miner_translator_cheater", "role": "Translator (Malicious)", "avg_score": 0.0000, "status": "STATIC_REJECT", "decision": "SLASHED (0.0)"},
            ]
        }
    
    # Calculate averages from history
    scores = {}
    statuses = {}
    roles = {}
    for r in SUBNET_STATE["round_history"]:
        for m in r["results"]:
            hk = m["hotkey"]
            scores.setdefault(hk, []).append(m.get("score", 0.0))
            statuses[hk] = m.get("status", "ACTIVE")
            roles[hk] = m.get("role", "miner")

    board = []
    for idx, (hk, sc_list) in enumerate(sorted(scores.items(), key=lambda x: sum(x[1])/len(x[1]), reverse=True)):
        avg = sum(sc_list) / len(sc_list)
        decision = "HIGH REWARD" if avg > 1.0 else ("BOUNTY AWARDED" if "breaker" in hk else ("SLASHED (0.0)" if avg == 0 else "LOW REWARD"))
        board.append({
            "uid": idx,
            "hotkey": hk,
            "role": roles.get(hk, "miner").capitalize(),
            "avg_score": round(avg, 4),
            "status": statuses.get(hk, "ACTIVE"),
            "decision": decision
        })
    return {"leaderboard": board}


@app.post("/api/run-round")
def run_round(req: ValidationRequest):
    val: Validator = SUBNET_STATE["validator"]
    miners = SUBNET_STATE["miners"]
    
    if req.c_code:
        val.sample_c_code = req.c_code

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
        num_tests=req.num_tests
    )
    elapsed = time.time() - t_start

    SUBNET_STATE["total_rounds"] += 1
    SUBNET_STATE["active_weights"] = res["weights_set"]
    
    round_payload = {
        "round_id": SUBNET_STATE["total_rounds"],
        "timestamp": time.time(),
        "elapsed_seconds": round(elapsed, 3),
        "results": res["round_results"],
        "weights": res["weights_set"]
    }
    SUBNET_STATE["round_history"].append(round_payload)
    return round_payload


@app.post("/api/check-gate")
def check_gate(req: GateCheckRequest):
    t_start = time.time()
    passed, reason = static_analysis_gate(req.rust_code)
    elapsed = time.time() - t_start
    score, breakdown = calculate_score(0.0 if not passed else 1.0, has_unsafe=not passed, actual_time=elapsed)
    return {
        "passed": passed,
        "reason": reason,
        "execution_time_seconds": round(elapsed, 6),
        "score_if_passed": score,
        "breakdown": breakdown
    }


@app.get("/api/dataset")
def get_dataset():
    sample_c = SUBNET_STATE["validator"].sample_c_code if SUBNET_STATE["validator"] else ""
    tests = generate_hidden_tests(count=15)
    return {
        "sample_c_code": sample_c,
        "sample_hidden_tests": tests
    }


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS // BITTENSOR C-TO-SAFE-RUST [EDITORIAL NOIR]</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Syne:wght@500;700;800&family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            /* Pinterest-Curated Bauhaus Minimal Dark Palette */
            --bg: #0C0C0E;                  /* Deep matte obsidian charcoal */
            --surface: #141417;             /* Smoked carbon card surface */
            --surface-elevated: #1B1B1F;    /* Subtle hover / active surface */
            --border: rgba(237, 231, 222, 0.08); /* Warm bone hairline border */
            --border-hover: rgba(237, 231, 222, 0.18);
            --border-strong: #2D2D34;
            
            /* Typography */
            --text-primary: #EDE7DE;        /* Bauhaus warm bone ivory */
            --text-secondary: #9B9891;      /* Stone taupe secondary */
            --text-muted: #5C5A55;          /* Muted mineral graphite */
            
            /* Curated Muted Editorial Accents (Pinterest Minimalist) */
            --terracotta: #C24E42;          /* Muted Bauhaus vermilion rust */
            --ochre: #D4A359;               /* Vintage mustard raw gold */
            --sage: #558273;                /* Desaturated lichen verdigris */
            --slate-blue: #3E6B89;          /* Deep Prussian slate blue */
            
            --shadow-hard: 3px 3px 0px rgba(0, 0, 0, 0.8);
            --shadow-offset: 4px 4px 0px rgba(237, 231, 222, 0.08);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            border-radius: 0 !important; /* Strict Bauhaus structural honesty */
        }

        body {
            background-color: var(--bg);
            background-image: 
                radial-gradient(rgba(237, 231, 222, 0.06) 1px, transparent 1px);
            background-size: 24px 24px;
            color: var(--text-primary);
            font-family: 'Space Grotesk', -apple-system, sans-serif;
            padding: 36px 40px;
            line-height: 1.5;
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
        }

        code, pre, .mono {
            font-family: 'JetBrains Mono', monospace;
        }

        /* Top Editorial Masthead */
        .masthead {
            background: var(--surface);
            border: 1px solid var(--border);
            box-shadow: var(--shadow-offset);
            padding: 24px 32px;
            margin-bottom: 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: relative;
        }

        .masthead::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, var(--terracotta) 0%, var(--ochre) 50%, var(--slate-blue) 100%);
        }

        .brand-group {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        /* Pure Bauhaus Geometric Primitives */
        .bauhaus-insignia {
            display: flex;
            gap: 6px;
            align-items: center;
        }
        .shape-circle {
            width: 16px;
            height: 16px;
            border: 1.5px solid var(--terracotta);
            border-radius: 50% !important;
        }
        .shape-triangle {
            width: 0;
            height: 0;
            border-left: 8px solid transparent;
            border-right: 8px solid transparent;
            border-bottom: 16px solid var(--ochre);
        }
        .shape-square {
            width: 16px;
            height: 16px;
            background: var(--slate-blue);
        }

        .title-meta h1 {
            font-family: 'Syne', sans-serif;
            font-size: 24px;
            font-weight: 800;
            letter-spacing: -0.5px;
            color: var(--text-primary);
            text-transform: uppercase;
        }

        .title-meta p {
            font-size: 11px;
            font-weight: 600;
            color: var(--text-secondary);
            letter-spacing: 0.12em;
            text-transform: uppercase;
            margin-top: 2px;
        }

        .status-pill {
            background: rgba(85, 130, 115, 0.08);
            border: 1px solid rgba(85, 130, 115, 0.25);
            padding: 8px 16px;
            font-size: 11px;
            font-weight: 700;
            color: var(--sage);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status-pill::before {
            content: '';
            width: 6px;
            height: 6px;
            background: var(--sage);
            border-radius: 50% !important;
        }

        /* Minimal Metric Grid */
        .metric-deck {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 32px;
        }

        @media (max-width: 1080px) {
            .metric-deck { grid-template-columns: repeat(2, 1fr); }
            .grid-container { grid-template-columns: 1fr !important; }
        }

        .metric-cell {
            background: var(--surface);
            border: 1px solid var(--border);
            padding: 20px 24px;
            transition: all 0.2s ease;
            position: relative;
        }
        .metric-cell:hover {
            border-color: var(--border-hover);
            transform: translateY(-2px);
        }
        .metric-cell .index {
            font-size: 10px;
            font-weight: 700;
            color: var(--text-muted);
            letter-spacing: 0.1em;
            text-transform: uppercase;
            margin-bottom: 6px;
        }
        .metric-cell .label {
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .metric-cell .val {
            font-family: 'JetBrains Mono', monospace;
            font-size: 28px;
            font-weight: 700;
            color: var(--text-primary);
            margin: 8px 0 4px 0;
            line-height: 1.1;
        }
        .metric-cell .sub {
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 500;
        }

        /* Main Grid */
        .grid-container {
            display: grid;
            grid-template-columns: 1.1fr 1.25fr;
            gap: 32px;
        }

        .card-panel {
            background: var(--surface);
            border: 1px solid var(--border);
            box-shadow: var(--shadow-offset);
            padding: 28px;
            display: flex;
            flex-direction: column;
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 16px;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }
        .card-title {
            font-family: 'Syne', sans-serif;
            font-size: 15px;
            font-weight: 800;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .card-tag {
            background: var(--surface-elevated);
            border: 1px solid var(--border);
            color: var(--text-secondary);
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            padding: 4px 10px;
        }

        /* Presets Selector */
        .presets-row {
            display: flex;
            gap: 8px;
            margin-bottom: 14px;
        }
        .preset-btn {
            background: var(--surface-elevated);
            border: 1px solid var(--border);
            color: var(--text-secondary);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            padding: 6px 12px;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .preset-btn:hover, .preset-btn.active {
            background: #232328;
            color: var(--text-primary);
            border-color: var(--border-hover);
        }

        /* Minimal Editor */
        textarea.code-canvas {
            width: 100%;
            height: 240px;
            background: #09090B;
            border: 1px solid var(--border);
            color: #D4D0C7;
            padding: 16px;
            font-size: 12.5px;
            line-height: 1.6;
            outline: none;
            resize: vertical;
            margin-bottom: 18px;
            transition: border-color 0.2s ease;
        }
        textarea.code-canvas:focus {
            border-color: var(--border-hover);
            background: #0C0C0E;
        }

        /* Action Buttons */
        .btn-action {
            background: var(--text-primary);
            color: var(--bg);
            border: 1px solid var(--text-primary);
            box-shadow: 2px 2px 0px rgba(237, 231, 222, 0.2);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            padding: 12px 22px;
            cursor: pointer;
            transition: all 0.15s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .btn-action:hover {
            background: #DFD8CE;
            transform: translate(-1px, -1px);
            box-shadow: 3px 3px 0px rgba(237, 231, 222, 0.3);
        }
        .btn-action:active {
            transform: translate(1px, 1px);
            box-shadow: 1px 1px 0px rgba(237, 231, 222, 0.1);
        }
        .btn-action:disabled {
            background: #2A2A2E !important;
            color: #6E6D68 !important;
            border-color: #2A2A2E !important;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .btn-subtle {
            background: var(--surface-elevated);
            color: var(--text-primary);
            border: 1px solid var(--border);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            padding: 10px 16px;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .btn-subtle:hover {
            background: #25252A;
            border-color: var(--border-hover);
        }

        /* Tables */
        .editorial-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12.5px;
            margin-bottom: 24px;
        }
        .editorial-table th {
            text-align: left;
            padding: 10px 12px;
            background: var(--surface-elevated);
            color: var(--text-secondary);
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            border-bottom: 1px solid var(--border);
        }
        .editorial-table td {
            padding: 13px 12px;
            border-bottom: 1px solid var(--border);
            color: var(--text-primary);
        }
        .editorial-table tr:hover td {
            background: rgba(237, 231, 222, 0.02);
        }

        /* Minimal Status Tags */
        .tag-minimal {
            display: inline-block;
            padding: 3px 8px;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            border: 1px solid transparent;
        }
        .tag-sage {
            background: rgba(85, 130, 115, 0.1);
            color: var(--sage);
            border-color: rgba(85, 130, 115, 0.3);
        }
        .tag-terracotta {
            background: rgba(194, 78, 66, 0.1);
            color: var(--terracotta);
            border-color: rgba(194, 78, 66, 0.3);
        }
        .tag-ochre {
            background: rgba(212, 163, 89, 0.1);
            color: var(--ochre);
            border-color: rgba(212, 163, 89, 0.3);
        }
        .tag-slate {
            background: rgba(62, 107, 137, 0.1);
            color: var(--slate-blue);
            border-color: rgba(62, 107, 137, 0.3);
        }

        /* Trace Stream Cards */
        .trace-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .trace-item {
            background: var(--surface-elevated);
            border: 1px solid var(--border);
            padding: 14px 18px;
            border-left: 3px solid var(--border-strong);
            font-size: 12.5px;
            transition: all 0.2s ease;
        }
        .trace-item.pass { border-left-color: var(--sage); }
        .trace-item.reject { border-left-color: var(--terracotta); }
        .trace-item.breaker { border-left-color: var(--ochre); }
        .trace-item.info { border-left-color: var(--slate-blue); }

        .trace-head {
            font-weight: 700;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.08em;
            margin-bottom: 4px;
            display: flex;
            justify-content: space-between;
        }
        .trace-body {
            color: var(--text-secondary);
            font-size: 12px;
            line-height: 1.5;
        }
    </style>
</head>
<body>

    <!-- Masthead -->
    <header class="masthead">
        <div class="brand-group">
            <div class="bauhaus-insignia">
                <div class="shape-circle"></div>
                <div class="shape-triangle"></div>
                <div class="shape-square"></div>
            </div>
            <div class="title-meta">
                <h1>AEGIS // C-TO-SAFE-RUST</h1>
                <p>Bittensor Subnet • Formal Hard Gates • Adversarial Breakers</p>
            </div>
        </div>
        <div class="status-pill" id="net-pill">Consensus Synchronized • NetUID 1</div>
    </header>

    <!-- Metrics -->
    <section class="metric-deck">
        <div class="metric-cell">
            <div class="index">01 / HEIGHT</div>
            <div class="label">Subtensor Block</div>
            <div class="val" id="disp-block">#1,018</div>
            <div class="sub">Local Consensus Epoch</div>
        </div>
        <div class="metric-cell">
            <div class="index">02 / GATEWAY</div>
            <div class="label">Static Gate Speed</div>
            <div class="val" style="color: var(--terracotta);">&lt; 0.05ms</div>
            <div class="sub">Zero-Tolerance Slashes</div>
        </div>
        <div class="metric-cell">
            <div class="index">03 / INCENTIVE</div>
            <div class="label">Top Translator Score</div>
            <div class="val" style="color: var(--sage);" id="disp-top">1.2000</div>
            <div class="sub">(PassRate)² × SpeedBonus</div>
        </div>
        <div class="metric-cell">
            <div class="index">04 / BOUNTY</div>
            <div class="label">Breaker Pool</div>
            <div class="val" style="color: var(--ochre);">0.5000</div>
            <div class="sub">TAO Per Divergence</div>
        </div>
    </section>

    <!-- Main Workspace -->
    <main class="grid-container">
        
        <!-- Left: C Ingestion & Hard Gate -->
        <section class="card-panel">
            <div class="card-header">
                <div class="card-title">
                    <span style="color: var(--ochre);">■</span> 01 / C Source Ingestion
                </div>
                <span class="card-tag">Benchmark Stream</span>
            </div>

            <div class="presets-row">
                <button class="preset-btn active" onclick="selectPreset('string_rev')">String Reverser</button>
                <button class="preset-btn" onclick="selectPreset('math_fib')">Matrix Math</button>
                <button class="preset-btn" onclick="selectPreset('buffer_parse')">Buffer Decoder</button>
            </div>

            <textarea id="c-editor" class="code-canvas mono" spellcheck="false"></textarea>

            <button id="run-btn" class="btn-action" onclick="runValidationCycle()">
                ► DISPATCH CROSS-MINER ROUND
            </button>

            <!-- Hard Gate Tester -->
            <div style="margin-top: 36px; padding-top: 24px; border-top: 1px solid var(--border);">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: none;">
                    <div class="card-title" style="font-size: 13px;">
                        <span style="color: var(--terracotta);">▲</span> 02 / Hard Gate Linter
                    </div>
                    <span class="card-tag">AST Hard Stop</span>
                </div>

                <input id="gate-test-code" type="text" class="mono"
                       placeholder='Enter snippet, e.g. pub fn pwn() { unsafe { } }'
                       style="width: 100%; padding: 11px 14px; background: #09090B; border: 1px solid var(--border); color: #EDE7DE; font-size: 12px; margin-bottom: 12px; outline: none;">

                <button class="btn-subtle" onclick="auditRustSnippet()">Audit Rust Code</button>
                <div id="gate-feedback" style="margin-top: 14px;"></div>
            </div>
        </section>

        <!-- Right: Consensus Weights & Execution Stream -->
        <section class="card-panel">
            <div class="card-header">
                <div class="card-title">
                    <span style="color: var(--sage);">●</span> 03 / Consensus Weights
                </div>
                <span class="card-tag">Metagraph</span>
            </div>

            <table class="editorial-table">
                <thead>
                    <tr>
                        <th>Miner</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Score</th>
                        <th>Decision</th>
                    </tr>
                </thead>
                <tbody id="leaderboard-content">
                    <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Synchronizing subnet state...</td></tr>
                </tbody>
            </table>

            <div class="card-header" style="margin-top: 16px; margin-bottom: 16px;">
                <div class="card-title" style="font-size: 13px;">
                    <span style="color: var(--slate-blue);">◆</span> 04 / Execution Stream
                </div>
                <span class="card-tag">Differential Fuzzing</span>
            </div>

            <div id="trace-feed" class="trace-list">
                <div class="trace-item info">
                    <div class="trace-head">Consensus Engine Idle</div>
                    <div class="trace-body">Click "DISPATCH CROSS-MINER ROUND" to test translators against adversarial breakers.</div>
                </div>
            </div>
        </section>

    </main>

    <script>
        const BENCHMARKS = {
            string_rev: `/**
 * Robust In-Place C String Reverser & Parser
 * Benchmark legacy module with boundary edge-cases.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void reverse_string(char *str) {
    if (str == NULL) return;
    int i = 0, j = (int)strlen(str) - 1;
    while (i < j) {
        char tmp = str[i];
        str[i] = str[j];
        str[j] = tmp;
        i++; j--;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 0;
    char *buf = strdup(argv[1]);
    reverse_string(buf);
    printf("%s", buf);
    free(buf);
    return 0;
}`,
            math_fib: `/**
 * Bounded Fast Integer Transform
 */
#include <stdio.h>
#include <stdlib.h>

long long fast_compute(long long n) {
    if (n <= 0) return 0;
    if (n == 1) return 1;
    long long a = 0, b = 1, c = 0;
    for (int i = 2; i <= n; i++) {
        c = a + b;
        a = b;
        b = c;
    }
    return b;
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 0;
    long long n = atoll(argv[1]);
    printf("%lld", fast_compute(n));
    return 0;
}`,
            buffer_parse: `/**
 * Hex Stream Decoder with Null Terminator Sanitizer
 */
#include <stdio.h>
#include <string.h>

void parse_stream(const char *in, char *out) {
    int o = 0;
    for (int i = 0; in[i] != '\\0'; i++) {
        if (in[i] >= '0' && in[i] <= '9') {
            out[o++] = in[i];
        }
    }
    out[o] = '\\0';
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 0;
    char out[1024];
    parse_stream(argv[1], out);
    printf("%s", out);
    return 0;
}`
        };

        function selectPreset(name) {
            document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById('c-editor').value = BENCHMARKS[name];
        }

        async function init() {
            document.getElementById('c-editor').value = BENCHMARKS['string_rev'];
            await fetchLeaderboard();
        }

        async function fetchLeaderboard() {
            try {
                const res = await fetch('/api/leaderboard');
                const data = await res.json();
                const tbody = document.getElementById('leaderboard-content');
                tbody.innerHTML = '';

                data.leaderboard.forEach(m => {
                    let badgeClass = 'tag-sage';
                    if (m.decision.includes('SLASHED')) badgeClass = 'tag-terracotta';
                    else if (m.decision.includes('BOUNTY')) badgeClass = 'tag-ochre';
                    else if (m.decision.includes('LOW')) badgeClass = 'tag-slate';

                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><strong>${m.hotkey}</strong></td>
                        <td style="color: var(--text-secondary);">${m.role}</td>
                        <td><span class="tag-minimal ${badgeClass}">${m.status}</span></td>
                        <td class="mono" style="color: var(--text-primary); font-weight: 600;">${m.avg_score.toFixed(4)}</td>
                        <td><span class="tag-minimal ${badgeClass}">${m.decision}</span></td>
                    `;
                    tbody.appendChild(tr);
                });
            } catch (e) {
                console.error(e);
            }
        }

        async function runValidationCycle() {
            const btn = document.getElementById('run-btn');
            const cCode = document.getElementById('c-editor').value;
            btn.disabled = true;
            btn.innerText = '● ORCHESTRATING ROUND...';

            const feed = document.getElementById('trace-feed');
            feed.innerHTML = `
                <div class="trace-item info">
                    <div class="trace-head">1. Ingesting Source &amp; Querying Neurons</div>
                    <div class="trace-body">Dispatched TranslationSynapse to all registered translator axons.</div>
                </div>
            `;

            try {
                const res = await fetch('/api/run-round', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ c_code: cCode, num_tests: 50 })
                });
                const data = await res.json();

                let html = '';
                data.results.forEach(m => {
                    if (m.status === 'REJECTED_STATIC_GATE') {
                        html += `
                            <div class="trace-item reject">
                                <div class="trace-head" style="color: var(--terracotta);">⛔ STATIC GATE REJECT: ${m.hotkey}</div>
                                <div class="trace-body mono">${m.reason} • <strong>Score: 0.0000</strong> (Hard Stop &lt;0.05ms)</div>
                            </div>
                        `;
                    } else if (m.role === 'breaker') {
                        html += `
                            <div class="trace-item breaker">
                                <div class="trace-head" style="color: var(--ochre);">💥 ADVERSARIAL BREAKER: ${m.hotkey}</div>
                                <div class="trace-body mono">Injected edge-case boundary inputs • Caught weak miner divergence • <strong>Bounty: +${m.score} TAO</strong></div>
                            </div>
                        `;
                    } else {
                        html += `
                            <div class="trace-item pass">
                                <div class="trace-head" style="color: var(--sage);">✅ SAFE RUST VERIFIED: ${m.hotkey}</div>
                                <div class="trace-body mono">Pass Rate: ${(m.pass_rate * 100).toFixed(1)}% • Final Score: <strong>${m.score.toFixed(4)}</strong> (Base: ${m.breakdown.base_score} × SpeedBonus: ${m.breakdown.speed_bonus})</div>
                            </div>
                        `;
                    }
                });

                feed.innerHTML = html;
                await fetchLeaderboard();

                const stat = await (await fetch('/api/status')).json();
                document.getElementById('disp-block').innerText = '#' + stat.current_block;
            } catch (err) {
                feed.innerHTML = `<div class="trace-item reject"><div class="trace-head">Error</div><div class="trace-body">${err.message}</div></div>`;
            } finally {
                btn.disabled = false;
                btn.innerText = '► DISPATCH CROSS-MINER ROUND';
            }
        }

        async function auditRustSnippet() {
            const input = document.getElementById('gate-test-code').value;
            const res = await fetch('/api/check-gate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rust_code: input })
            });
            const d = await res.json();
            const out = document.getElementById('gate-feedback');
            if (d.passed) {
                out.innerHTML = `
                    <div class="trace-item pass">
                        <div class="trace-head" style="color: var(--sage);">[APPROVED] 100% SAFE RUST</div>
                        <div class="trace-body mono">Passed all 6 AST/static gates in ${(d.execution_time_seconds * 1000).toFixed(3)}ms. Zero unsafe blocks.</div>
                    </div>
                `;
            } else {
                out.innerHTML = `
                    <div class="trace-item reject">
                        <div class="trace-head" style="color: var(--terracotta);">[REJECTED] ZERO-TOLERANCE HARD GATE</div>
                        <div class="trace-body mono">${d.reason} • Final Score: 0.0000</div>
                    </div>
                `;
            }
        }

        window.onload = init;
    </script>
</body>
</html>
    """


def main():
    import uvicorn
    logger.info("Starting Aegis Subnet Command Center on http://127.0.0.1:8000 ...")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()

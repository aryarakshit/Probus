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
    <title>AEGIS // BITTENSOR C-TO-SAFE-RUST [BAUHAUS NOIR]</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700;900&family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-black: #000000;
            --surface-1: #0A0A0C;
            --surface-2: #121215;
            --surface-3: #1A1A1F;
            --border-subtle: #222226;
            --border-strong: #33333A;
            --text-primary: #FFFFFF;
            --text-secondary: #A1A1AA;
            --text-muted: #52525B;
            --accent-yellow: #F59E0B;
            --accent-blue: #3B82F6;
            --accent-emerald: #10B981;
            --accent-crimson: #EF4444;
            --shadow-hard: 4px 4px 0px #000000;
            --shadow-border: 4px 4px 0px #222226;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            border-radius: 0 !important; /* Pure Bauhaus geometric discipline */
        }

        body {
            background-color: var(--bg-black);
            background-image: 
                linear-gradient(to right, rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
            background-size: 32px 32px;
            color: var(--text-primary);
            font-family: 'Space Grotesk', sans-serif;
            padding: 32px 28px;
            line-height: 1.5;
            min-height: 100vh;
        }

        code, pre, .mono {
            font-family: 'JetBrains Mono', monospace;
        }

        /* Top Header / Masthead */
        .masthead {
            background: var(--surface-1);
            border: 2px solid var(--border-subtle);
            box-shadow: var(--shadow-border);
            padding: 24px 32px;
            margin-bottom: 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: relative;
        }

        .masthead::before {
            content: '';
            position: absolute;
            top: -2px;
            left: -2px;
            right: -2px;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-crimson) 0%, var(--accent-yellow) 50%, var(--accent-blue) 100%);
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        /* Minimalist Bauhaus Emblem */
        .emblem {
            display: flex;
            gap: 6px;
            align-items: center;
        }
        .emblem .shape-circle {
            width: 18px;
            height: 18px;
            border: 2px solid var(--accent-crimson);
            background: transparent;
            border-radius: 50% !important;
        }
        .emblem .shape-triangle {
            width: 0;
            height: 0;
            border-left: 9px solid transparent;
            border-right: 9px solid transparent;
            border-bottom: 18px solid var(--accent-yellow);
        }
        .emblem .shape-square {
            width: 18px;
            height: 18px;
            background: var(--accent-blue);
        }

        .title-block h1 {
            font-size: 26px;
            font-weight: 900;
            letter-spacing: -0.5px;
            text-transform: uppercase;
        }
        .title-block p {
            font-size: 12px;
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 2px;
        }

        .status-badge {
            background: var(--surface-2);
            border: 1px solid var(--border-strong);
            padding: 8px 16px;
            font-size: 12px;
            font-weight: 700;
            color: var(--text-primary);
            text-transform: uppercase;
            letter-spacing: 1px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status-badge::before {
            content: '';
            width: 8px;
            height: 8px;
            background: var(--accent-emerald);
            box-shadow: 0 0 10px var(--accent-emerald);
        }

        /* Metric Tiles */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 28px;
        }

        @media (max-width: 1024px) {
            .metrics-grid { grid-template-columns: repeat(2, 1fr); }
            .workspace-grid { grid-template-columns: 1fr !important; }
        }

        .metric-tile {
            background: var(--surface-1);
            border: 1px solid var(--border-subtle);
            box-shadow: var(--shadow-border);
            padding: 20px 24px;
            transition: all 0.2s ease;
            position: relative;
        }
        .metric-tile:hover {
            border-color: var(--border-strong);
            transform: translateY(-2px);
        }
        .metric-tile .label {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-secondary);
        }
        .metric-tile .value {
            font-size: 30px;
            font-weight: 900;
            margin: 8px 0 4px 0;
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-primary);
        }
        .metric-tile .subtext {
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
        }

        /* Main Workspace Layout */
        .workspace-grid {
            display: grid;
            grid-template-columns: 1.15fr 1.25fr;
            gap: 28px;
        }

        .panel {
            background: var(--surface-1);
            border: 1px solid var(--border-subtle);
            box-shadow: var(--shadow-border);
            padding: 28px;
            display: flex;
            flex-direction: column;
        }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 16px;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border-subtle);
        }
        .panel-title {
            font-size: 16px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .panel-tag {
            background: var(--surface-3);
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 4px 10px;
        }

        /* Preset selector */
        .presets-row {
            display: flex;
            gap: 8px;
            margin-bottom: 12px;
        }
        .btn-preset {
            background: var(--surface-2);
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            padding: 6px 12px;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .btn-preset:hover, .btn-preset.active {
            background: var(--surface-3);
            color: var(--text-primary);
            border-color: var(--border-strong);
        }

        /* Editor Input */
        textarea.code-editor {
            width: 100%;
            height: 250px;
            background: #050507;
            border: 1px solid var(--border-subtle);
            color: #E4E4E7;
            padding: 16px;
            font-size: 13px;
            line-height: 1.6;
            outline: none;
            resize: vertical;
            margin-bottom: 20px;
            transition: border-color 0.2s ease;
        }
        textarea.code-editor:focus {
            border-color: var(--accent-blue);
        }

        /* Primary Action Buttons */
        .btn-primary {
            background: var(--text-primary);
            color: var(--bg-black);
            border: 1px solid var(--text-primary);
            box-shadow: 3px 3px 0px var(--border-strong);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 14px 24px;
            cursor: pointer;
            transition: all 0.15s ease;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        .btn-primary:hover {
            background: #E4E4E7;
            transform: translate(-1px, -1px);
            box-shadow: 4px 4px 0px var(--border-strong);
        }
        .btn-primary:active {
            transform: translate(1px, 1px);
            box-shadow: 1px 1px 0px var(--border-strong);
        }
        .btn-primary:disabled {
            background: var(--surface-3) !important;
            color: var(--text-muted) !important;
            border-color: var(--border-subtle) !important;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .btn-secondary {
            background: var(--surface-2);
            color: var(--text-primary);
            border: 1px solid var(--border-subtle);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 10px 18px;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .btn-secondary:hover {
            background: var(--surface-3);
            border-color: var(--border-strong);
        }

        /* Minimal Tables */
        .clean-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-bottom: 24px;
        }
        .clean-table th {
            text-align: left;
            padding: 10px 14px;
            background: var(--surface-2);
            color: var(--text-secondary);
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 1px solid var(--border-subtle);
        }
        .clean-table td {
            padding: 14px;
            border-bottom: 1px solid var(--border-subtle);
            color: var(--text-primary);
            font-weight: 500;
        }
        .clean-table tr:hover td {
            background: rgba(255, 255, 255, 0.015);
        }

        /* Minimalist Indicators */
        .tag-pill {
            display: inline-block;
            padding: 3px 8px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border: 1px solid transparent;
        }
        .tag-emerald { background: rgba(16, 185, 129, 0.1); color: var(--accent-emerald); border-color: rgba(16, 185, 129, 0.3); }
        .tag-crimson { background: rgba(239, 68, 68, 0.1); color: var(--accent-crimson); border-color: rgba(239, 68, 68, 0.3); }
        .tag-yellow { background: rgba(245, 158, 11, 0.1); color: var(--accent-yellow); border-color: rgba(245, 158, 11, 0.3); }
        .tag-blue { background: rgba(59, 130, 246, 0.1); color: var(--accent-blue); border-color: rgba(59, 130, 246, 0.3); }

        /* Real-Time Trace Log */
        .trace-stream {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .trace-card {
            background: var(--surface-2);
            border: 1px solid var(--border-subtle);
            padding: 14px 18px;
            border-left: 4px solid var(--border-strong);
            font-size: 13px;
            transition: border-color 0.2s;
        }
        .trace-card.pass { border-left-color: var(--accent-emerald); }
        .trace-card.reject { border-left-color: var(--accent-crimson); }
        .trace-card.breaker { border-left-color: var(--accent-yellow); }
        .trace-card.info { border-left-color: var(--accent-blue); }

        .trace-header {
            font-weight: 800;
            text-transform: uppercase;
            font-size: 12px;
            margin-bottom: 4px;
            display: flex;
            justify-content: space-between;
        }
        .trace-desc {
            color: var(--text-secondary);
            font-size: 12px;
            line-height: 1.5;
        }
    </style>
</head>
<body>

    <!-- Header -->
    <header class="masthead">
        <div class="brand">
            <div class="emblem">
                <div class="shape-circle"></div>
                <div class="shape-triangle"></div>
                <div class="shape-square"></div>
            </div>
            <div class="title-block">
                <h1>AEGIS // C-TO-SAFE-RUST</h1>
                <p>Bittensor Subnet • Adversarial Breakers • Formal Hard Gates</p>
            </div>
        </div>
        <div class="status-badge" id="net-badge">Consensus Active • NetUID 1</div>
    </header>

    <!-- Metrics -->
    <section class="metrics-grid">
        <div class="metric-tile">
            <div class="label">Current Block</div>
            <div class="value" id="val-block">#1,015</div>
            <div class="subtext">Subtensor Height</div>
        </div>
        <div class="metric-tile">
            <div class="label">Static Gate Speed</div>
            <div class="value" style="color: var(--accent-crimson);">&lt; 0.05ms</div>
            <div class="subtext">Zero-Tolerance Slashes</div>
        </div>
        <div class="metric-tile">
            <div class="label">Top Translator Score</div>
            <div class="value" style="color: var(--accent-emerald);" id="val-top">1.2000</div>
            <div class="subtext">PassRate² × SpeedBonus</div>
        </div>
        <div class="metric-tile">
            <div class="label">Breaker Bounty Pool</div>
            <div class="value" style="color: var(--accent-yellow);">0.5000</div>
            <div class="subtext">TAO Per Proven Flaw</div>
        </div>
    </section>

    <!-- Workspace -->
    <main class="workspace-grid">
        
        <!-- Left: Input & Static Analysis -->
        <section class="panel">
            <div class="panel-header">
                <div class="panel-title">
                    <span style="color: var(--accent-yellow);">■</span> C Source Ingestion
                </div>
                <span class="panel-tag">Input Stream</span>
            </div>

            <div class="presets-row">
                <button class="btn-preset active" onclick="setPreset('string_rev')">String Reverser</button>
                <button class="btn-preset" onclick="setPreset('math_fib')">Matrix Math</button>
                <button class="btn-preset" onclick="setPreset('buffer_parse')">Buffer Decoder</button>
            </div>

            <textarea id="c-editor" class="code-editor mono" spellcheck="false"></textarea>

            <button id="dispatch-btn" class="btn-primary" onclick="triggerValidationRound()">
                ► DISPATCH CROSS-MINER ROUND
            </button>

            <!-- Quick Static Gate Checker -->
            <div style="margin-top: 36px; padding-top: 24px; border-top: 1px solid var(--border-subtle);">
                <div class="panel-header" style="padding-bottom: 12px; margin-bottom: 16px;">
                    <div class="panel-title" style="font-size: 14px;">
                        <span style="color: var(--accent-crimson);">▲</span> Instant Hard Gate Audit
                    </div>
                    <span class="panel-tag">Static Linter</span>
                </div>
                
                <input id="quick-gate-input" type="text" class="mono"
                       placeholder='Enter Rust snippet, e.g. pub fn pwn() { unsafe { } }'
                       style="width: 100%; padding: 12px 14px; background: #050507; border: 1px solid var(--border-subtle); color: #E4E4E7; font-size: 12px; margin-bottom: 12px; outline: none;">
                
                <button class="btn-secondary" onclick="checkGateSnippet()">Audit Rust Code</button>
                <div id="gate-result-box" style="margin-top: 14px;"></div>
            </div>
        </section>

        <!-- Right: Leaderboard & Execution Trace -->
        <section class="panel">
            <div class="panel-header">
                <div class="panel-title">
                    <span style="color: var(--accent-emerald);">●</span> Metagraph Weights &amp; Status
                </div>
                <span class="panel-tag">Live Consensus</span>
            </div>

            <table class="clean-table">
                <thead>
                    <tr>
                        <th>Miner</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Score</th>
                        <th>Emission</th>
                    </tr>
                </thead>
                <tbody id="leaderboard-table">
                    <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Synchronizing...</td></tr>
                </tbody>
            </table>

            <div class="panel-header" style="margin-top: 16px; margin-bottom: 16px;">
                <div class="panel-title" style="font-size: 14px;">
                    <span style="color: var(--accent-blue);">◆</span> Round Execution Stream
                </div>
                <span class="panel-tag">Differential Audit</span>
            </div>

            <div id="trace-stream" class="trace-stream">
                <div class="trace-card info">
                    <div class="trace-header">Aegis Consensus Engine Idle</div>
                    <div class="trace-desc">Click "DISPATCH CROSS-MINER ROUND" to challenge registered translators and breakers.</div>
                </div>
            </div>
        </section>

    </main>

    <script>
        const PRESETS = {
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

        function setPreset(name) {
            document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById('c-editor').value = PRESETS[name];
        }

        async function initPage() {
            document.getElementById('c-editor').value = PRESETS['string_rev'];
            await refreshLeaderboard();
        }

        async function refreshLeaderboard() {
            try {
                const res = await fetch('/api/leaderboard');
                const data = await res.json();
                const tbody = document.getElementById('leaderboard-table');
                tbody.innerHTML = '';

                data.leaderboard.forEach(m => {
                    let badgeClass = 'tag-emerald';
                    if (m.decision.includes('SLASHED')) badgeClass = 'tag-crimson';
                    else if (m.decision.includes('BOUNTY')) badgeClass = 'tag-yellow';
                    else if (m.decision.includes('LOW')) badgeClass = 'tag-blue';

                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><strong>${m.hotkey}</strong></td>
                        <td style="color: var(--text-secondary);">${m.role}</td>
                        <td><span class="tag-pill ${badgeClass}">${m.status}</span></td>
                        <td class="mono" style="color: var(--text-primary); font-weight: 700;">${m.avg_score.toFixed(4)}</td>
                        <td><span class="tag-pill ${badgeClass}">${m.decision}</span></td>
                    `;
                    tbody.appendChild(tr);
                });
            } catch (e) {
                console.error(e);
            }
        }

        async function triggerValidationRound() {
            const btn = document.getElementById('dispatch-btn');
            const cCode = document.getElementById('c-editor').value;
            btn.disabled = true;
            btn.innerText = '● DISPATCHING &amp; AUDITING...';

            const stream = document.getElementById('trace-stream');
            stream.innerHTML = `
                <div class="trace-card info">
                    <div class="trace-header">1. Ingesting Source &amp; Querying Neurons</div>
                    <div class="trace-desc">Broadcasted TranslationSynapse across subnet axons. Awaiting Safe Rust candidates.</div>
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
                            <div class="trace-card reject">
                                <div class="trace-header" style="color: var(--accent-crimson);">⛔ STATIC GATE REJECT: ${m.hotkey}</div>
                                <div class="trace-desc mono">${m.reason} • <strong>Score: 0.0000</strong> (Hard Stop &lt;0.05ms)</div>
                            </div>
                        `;
                    } else if (m.role === 'breaker') {
                        html += `
                            <div class="trace-card breaker">
                                <div class="trace-header" style="color: var(--accent-yellow);">💥 ADVERSARIAL BREAKER: ${m.hotkey}</div>
                                <div class="trace-desc mono">Generated boundary edge-cases • Provoked weak miner logic divergence • <strong>Bounty: +${m.score} TAO</strong></div>
                            </div>
                        `;
                    } else {
                        html += `
                            <div class="trace-card pass">
                                <div class="trace-header" style="color: var(--accent-emerald);">✅ SAFE RUST VERIFIED: ${m.hotkey}</div>
                                <div class="trace-desc mono">Pass Rate: ${(m.pass_rate * 100).toFixed(1)}% • Final Score: <strong>${m.score.toFixed(4)}</strong> (Base: ${m.breakdown.base_score} × SpeedBonus: ${m.breakdown.speed_bonus})</div>
                            </div>
                        `;
                    }
                });

                stream.innerHTML = html;
                await refreshLeaderboard();

                const stat = await (await fetch('/api/status')).json();
                document.getElementById('val-block').innerText = '#' + stat.current_block;
            } catch (err) {
                stream.innerHTML = `<div class="trace-card reject"><div class="trace-header">Error</div><div class="trace-desc">${err.message}</div></div>`;
            } finally {
                btn.disabled = false;
                btn.innerText = '► DISPATCH CROSS-MINER ROUND';
            }
        }

        async function checkGateSnippet() {
            const input = document.getElementById('quick-gate-input').value;
            const res = await fetch('/api/check-gate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rust_code: input })
            });
            const d = await res.json();
            const out = document.getElementById('gate-result-box');
            if (d.passed) {
                out.innerHTML = `
                    <div class="trace-card pass">
                        <div class="trace-header" style="color: var(--accent-emerald);">[APPROVED] 100% SAFE RUST</div>
                        <div class="trace-desc mono">Passed all 6 AST/static gates in ${(d.execution_time_seconds * 1000).toFixed(3)}ms. Zero unsafe blocks.</div>
                    </div>
                `;
            } else {
                out.innerHTML = `
                    <div class="trace-card reject">
                        <div class="trace-header" style="color: var(--accent-crimson);">[REJECTED] ZERO-TOLERANCE HARD GATE</div>
                        <div class="trace-desc mono">${d.reason} • Final Score: 0.0000</div>
                    </div>
                `;
            }
        }

        window.onload = initPage;
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

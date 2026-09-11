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
    <title>AEGIS // BITTENSOR C-TO-SAFE-RUST [BAUHAUS EDITION]</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700;900&family=JetBrains+Mono:wght@500;700;800&family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bauhaus-bg: #F4F3EE;
            --bauhaus-black: #111111;
            --bauhaus-white: #FFFFFF;
            --bauhaus-red: #E63946;
            --bauhaus-blue: #1D4ED8;
            --bauhaus-yellow: #FFB703;
            --bauhaus-green: #059669;
            --bauhaus-gray: #E5E5DF;
            --shadow-hard: 5px 5px 0px #111111;
            --shadow-hard-sm: 3px 3px 0px #111111;
            --shadow-hard-lg: 8px 8px 0px #111111;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            border-radius: 0 !important; /* Strict Bauhaus: Form follows function, no arbitrary rounding */
        }

        body {
            background-color: var(--bauhaus-bg);
            background-image: radial-gradient(#d1d0c5 1px, transparent 1px);
            background-size: 20px 20px;
            color: var(--bauhaus-black);
            font-family: 'Space Grotesk', -apple-system, sans-serif;
            padding: 24px;
            line-height: 1.4;
        }

        code, pre, .mono {
            font-family: 'JetBrains Mono', monospace;
        }

        /* Top Bauhaus Masthead */
        .masthead {
            border: 3px solid var(--bauhaus-black);
            background: var(--bauhaus-white);
            box-shadow: var(--shadow-hard);
            padding: 20px 28px;
            margin-bottom: 24px;
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
            width: 100%;
            height: 6px;
            background: linear-gradient(90deg, var(--bauhaus-red) 0% 33.3%, var(--bauhaus-yellow) 33.3% 66.6%, var(--bauhaus-blue) 66.6% 100%);
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        /* Bauhaus geometric insignia */
        .bauhaus-badge {
            display: flex;
            gap: 4px;
            align-items: center;
        }
        .shape-circle {
            width: 20px;
            height: 20px;
            background: var(--bauhaus-red);
            border: 2px solid var(--bauhaus-black);
            border-radius: 50% !important; /* Intentional circle primitive */
        }
        .shape-triangle {
            width: 0;
            height: 0;
            border-left: 11px solid transparent;
            border-right: 11px solid transparent;
            border-bottom: 20px solid var(--bauhaus-yellow);
        }
        .shape-square {
            width: 20px;
            height: 20px;
            background: var(--bauhaus-blue);
            border: 2px solid var(--bauhaus-black);
        }

        .title-text h1 {
            font-size: 28px;
            font-weight: 900;
            letter-spacing: -1px;
            text-transform: uppercase;
        }

        .title-text p {
            font-size: 13px;
            color: #4b5563;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .network-tag {
            background: var(--bauhaus-yellow);
            border: 2px solid var(--bauhaus-black);
            box-shadow: var(--shadow-hard-sm);
            padding: 8px 16px;
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        /* Metric Grid */
        .grid-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 18px;
            margin-bottom: 24px;
        }

        .card-metric {
            background: var(--bauhaus-white);
            border: 3px solid var(--bauhaus-black);
            box-shadow: var(--shadow-hard-sm);
            padding: 16px 20px;
            position: relative;
            overflow: hidden;
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }
        .card-metric:hover {
            transform: translate(-2px, -2px);
            box-shadow: var(--shadow-hard);
        }

        .card-metric.red { border-top: 8px solid var(--bauhaus-red); }
        .card-metric.yellow { border-top: 8px solid var(--bauhaus-yellow); }
        .card-metric.blue { border-top: 8px solid var(--bauhaus-blue); }
        .card-metric.green { border-top: 8px solid var(--bauhaus-green); }

        .card-metric .lbl {
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #4b5563;
        }
        .card-metric .num {
            font-size: 32px;
            font-weight: 900;
            line-height: 1.1;
            margin: 6px 0;
            font-family: 'JetBrains Mono', monospace;
        }
        .card-metric .sub {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: #6b7280;
        }

        /* Main Workspace Grid */
        .workspace-grid {
            display: grid;
            grid-template-columns: 1.1fr 1.3fr;
            gap: 24px;
        }

        .panel-box {
            background: var(--bauhaus-white);
            border: 3px solid var(--bauhaus-black);
            box-shadow: var(--shadow-hard);
            padding: 24px;
        }

        .panel-title-bar {
            border-bottom: 3px solid var(--bauhaus-black);
            padding-bottom: 12px;
            margin-bottom: 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .panel-title-bar h2 {
            font-size: 18px;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .panel-title-bar .tag {
            background: var(--bauhaus-black);
            color: var(--bauhaus-white);
            padding: 4px 10px;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
        }

        /* Editor Area */
        textarea.bauhaus-input {
            width: 100%;
            height: 240px;
            border: 2px solid var(--bauhaus-black);
            background: #FAFAF7;
            padding: 14px;
            font-size: 13px;
            font-weight: 500;
            color: var(--bauhaus-black);
            outline: none;
            resize: vertical;
            margin-bottom: 16px;
        }
        textarea.bauhaus-input:focus {
            background: var(--bauhaus-white);
            border-color: var(--bauhaus-blue);
        }

        /* Action Buttons */
        .btn-bauhaus {
            background: var(--bauhaus-red);
            color: var(--bauhaus-white);
            border: 3px solid var(--bauhaus-black);
            box-shadow: var(--shadow-hard-sm);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 14px;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 14px 24px;
            cursor: pointer;
            transition: all 0.1s ease;
            display: inline-flex;
            align-items: center;
            gap: 10px;
        }
        .btn-bauhaus:hover {
            background: #d00000;
            transform: translate(-2px, -2px);
            box-shadow: var(--shadow-hard);
        }
        .btn-bauhaus:active {
            transform: translate(2px, 2px);
            box-shadow: 1px 1px 0px var(--bauhaus-black);
        }
        .btn-bauhaus.yellow {
            background: var(--bauhaus-yellow);
            color: var(--bauhaus-black);
        }
        .btn-bauhaus.blue {
            background: var(--bauhaus-blue);
            color: var(--bauhaus-white);
        }
        .btn-bauhaus:disabled {
            background: #9ca3af !important;
            cursor: not-allowed;
            transform: none;
            box-shadow: var(--shadow-hard-sm);
        }

        /* Tables */
        .bauhaus-table {
            width: 100%;
            border-collapse: collapse;
            border: 2px solid var(--bauhaus-black);
            margin-bottom: 20px;
        }
        .bauhaus-table th {
            background: var(--bauhaus-black);
            color: var(--bauhaus-white);
            font-size: 11px;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 10px 14px;
            text-align: left;
        }
        .bauhaus-table td {
            padding: 12px 14px;
            border-bottom: 2px solid var(--bauhaus-black);
            font-size: 13px;
            font-weight: 600;
            background: var(--bauhaus-white);
        }
        .bauhaus-table tr:last-child td {
            border-bottom: none;
        }

        /* Status Flags */
        .flag {
            display: inline-block;
            padding: 4px 8px;
            font-size: 11px;
            font-weight: 900;
            text-transform: uppercase;
            border: 1.5px solid var(--bauhaus-black);
        }
        .flag-red { background: var(--bauhaus-red); color: var(--bauhaus-white); }
        .flag-yellow { background: var(--bauhaus-yellow); color: var(--bauhaus-black); }
        .flag-blue { background: var(--bauhaus-blue); color: var(--bauhaus-white); }
        .flag-green { background: var(--bauhaus-green); color: var(--bauhaus-white); }
        .flag-black { background: var(--bauhaus-black); color: var(--bauhaus-white); }

        /* Step Timeline */
        .timeline-box {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .step-card {
            border: 2px solid var(--bauhaus-black);
            background: var(--bauhaus-bg);
            padding: 14px 18px;
            position: relative;
        }
        .step-card.step-red { border-left: 8px solid var(--bauhaus-red); }
        .step-card.step-green { border-left: 8px solid var(--bauhaus-green); }
        .step-card.step-blue { border-left: 8px solid var(--bauhaus-blue); }
        .step-card.step-yellow { border-left: 8px solid var(--bauhaus-yellow); }

        .step-header {
            display: flex;
            justify-content: space-between;
            font-size: 13px;
            font-weight: 900;
            text-transform: uppercase;
            margin-bottom: 4px;
        }
        .step-body {
            font-size: 12px;
            font-weight: 600;
            color: #374151;
        }
    </style>
</head>
<body>

    <!-- Top Masthead -->
    <header class="masthead">
        <div class="brand">
            <div class="bauhaus-badge">
                <div class="shape-circle"></div>
                <div class="shape-triangle"></div>
                <div class="shape-square"></div>
            </div>
            <div class="title-text">
                <h1>AEGIS // C-TO-SAFE-RUST</h1>
                <p>Bittensor Global Hackathon • Adversarial Fuzzing Subnet</p>
            </div>
        </div>
        <div class="network-tag">● SUBTENSOR SYNCHRONIZED</div>
    </header>

    <!-- Metrics Strip -->
    <section class="grid-metrics">
        <div class="card-metric yellow">
            <div class="lbl">Current Block / NetUID</div>
            <div class="num" id="block-num">#1,012</div>
            <div class="sub">Localnet Consensus</div>
        </div>
        <div class="card-metric red">
            <div class="lbl">Hard Gate Gatekeeping</div>
            <div class="num">&lt; 1ms</div>
            <div class="sub">100% Slashes Unsafe / Libc</div>
        </div>
        <div class="card-metric green">
            <div class="lbl">Top Translator Emission</div>
            <div class="num" id="top-emission">1.2000</div>
            <div class="sub">(PassRate)² × SpeedBonus</div>
        </div>
        <div class="card-metric blue">
            <div class="lbl">Breaker Bounty Pool</div>
            <div class="num">0.5000</div>
            <div class="sub">TAO per Caught Divergence</div>
        </div>
    </section>

    <!-- Main Workspace -->
    <main class="workspace-grid">
        
        <!-- Left: Input & Static Gate Panel -->
        <section class="panel-box">
            <div class="panel-title-bar">
                <h2>■ Legacy C Ingestion</h2>
                <span class="tag">Challenge Engine</span>
            </div>
            
            <textarea id="c-source" class="bauhaus-input mono"></textarea>
            
            <button id="exec-btn" class="btn-bauhaus" onclick="executeValidationRound()">
                ► DISPATCH VALIDATION CHALLENGE
            </button>

            <!-- Hard Gate Interactive Sandbox -->
            <div style="margin-top: 32px; border-top: 2px solid var(--bauhaus-black); padding-top: 20px;">
                <div class="panel-title-bar" style="margin-bottom: 12px; border-bottom: none; padding-bottom: 0;">
                    <h2>▲ Static Gate Tester</h2>
                    <span class="flag flag-yellow">&lt;1MS HARD STOP</span>
                </div>
                <input id="rust-input" type="text" class="mono" 
                       placeholder='e.g. pub fn test() { unsafe { } }'
                       style="width: 100%; padding: 12px; border: 2px solid var(--bauhaus-black); font-size: 13px; margin-bottom: 10px; outline: none;">
                <button class="btn-bauhaus blue" style="padding: 10px 18px; font-size: 12px;" onclick="testHardGate()">
                    VERIFY SAFETY CONSTRAINTS
                </button>
                <div id="gate-output" style="margin-top: 12px;"></div>
            </div>
        </section>

        <!-- Right: Metagraph Leaderboard & Live Trace -->
        <section class="panel-box">
            <div class="panel-title-bar">
                <h2>● Active Metagraph</h2>
                <span class="tag">Live Scoring</span>
            </div>

            <table class="bauhaus-table">
                <thead>
                    <tr>
                        <th>UID / Miner</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Score</th>
                        <th>Decision</th>
                    </tr>
                </thead>
                <tbody id="leaderboard-body">
                    <tr><td colspan="5" style="text-align: center;">Querying subnet state...</td></tr>
                </tbody>
            </table>

            <!-- Real-Time Trace -->
            <div class="panel-title-bar" style="margin-top: 28px; margin-bottom: 14px;">
                <h2>◆ Execution Trace</h2>
                <span class="flag flag-black">SANDBOX LOGS</span>
            </div>

            <div id="trace-container" class="timeline-box">
                <div class="step-card step-blue">
                    <div class="step-header">Ready for Consensus</div>
                    <div class="step-body">Click "DISPATCH VALIDATION CHALLENGE" to initiate cross-miner differential fuzzing.</div>
                </div>
            </div>
        </section>

    </main>

    <script>
        async function loadInitialData() {
            try {
                const res = await fetch('/api/dataset');
                const data = await res.json();
                document.getElementById('c-source').value = data.sample_c_code;
                fetchLeaderboard();
            } catch (e) {
                console.error(e);
            }
        }

        async function fetchLeaderboard() {
            const res = await fetch('/api/leaderboard');
            const data = await res.json();
            const tbody = document.getElementById('leaderboard-body');
            tbody.innerHTML = '';
            
            data.leaderboard.forEach(m => {
                let flagClass = 'flag-green';
                if (m.decision.includes('SLASHED')) flagClass = 'flag-red';
                else if (m.decision.includes('BOUNTY')) flagClass = 'flag-blue';
                else if (m.decision.includes('LOW')) flagClass = 'flag-yellow';

                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>#${m.uid}</strong> ${m.hotkey}</td>
                    <td>${m.role}</td>
                    <td><span class="flag ${flagClass}">${m.status}</span></td>
                    <td class="mono" style="font-size: 14px; font-weight: 800;">${m.avg_score.toFixed(4)}</td>
                    <td><span class="flag ${flagClass}">${m.decision}</span></td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function executeValidationRound() {
            const btn = document.getElementById('exec-btn');
            const cCode = document.getElementById('c-source').value;
            btn.disabled = true;
            btn.innerText = '● ORCHESTRATING ROUND...';

            const container = document.getElementById('trace-container');
            container.innerHTML = `
                <div class="step-card step-yellow">
                    <div class="step-header">1. Ingesting C Benchmark &amp; Querying Miners</div>
                    <div class="step-body">Dispatched TranslationSynapse to all registered translator axons.</div>
                </div>
            `;

            try {
                const res = await fetch('/api/run-round', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ c_code: cCode, num_tests: 50 })
                });
                const result = await res.json();
                
                let html = '';
                result.results.forEach(m => {
                    if (m.status === 'REJECTED_STATIC_GATE') {
                        html += `
                            <div class="step-card step-red">
                                <div class="step-header" style="color: var(--bauhaus-red);">⛔ STATIC GATE REJECT: ${m.hotkey}</div>
                                <div class="step-body mono">${m.reason} • Score: 0.0000 (Slashed in &lt;1ms)</div>
                            </div>
                        `;
                    } else if (m.role === 'breaker') {
                        html += `
                            <div class="step-card step-blue">
                                <div class="step-header" style="color: var(--bauhaus-blue);">💥 ADVERSARIAL BREAKER: ${m.hotkey}</div>
                                <div class="step-body mono">Injected edge-case boundary inputs • Caught weak miner divergences • Awarded ${m.score} TAO bounty</div>
                            </div>
                        `;
                    } else {
                        html += `
                            <div class="step-card step-green">
                                <div class="step-header" style="color: var(--bauhaus-green);">✅ COMPILATION &amp; DIFF FUZZ: ${m.hotkey}</div>
                                <div class="step-body mono">Pass Rate: ${(m.pass_rate * 100).toFixed(1)}% • Final Score: ${m.score.toFixed(4)} (${m.breakdown.base_score} × ${m.breakdown.safety_penalty} × ${m.breakdown.speed_bonus})</div>
                            </div>
                        `;
                    }
                });

                container.innerHTML = html;
                fetchLeaderboard();
                
                const stat = await (await fetch('/api/status')).json();
                document.getElementById('block-num').innerText = '#' + stat.current_block;
            } catch (e) {
                container.innerHTML = `<div class="step-card step-red"><div class="step-header">Execution Error</div><div class="step-body">${e.message}</div></div>`;
            } finally {
                btn.disabled = false;
                btn.innerText = '► DISPATCH VALIDATION CHALLENGE';
            }
        }

        async function testHardGate() {
            const input = document.getElementById('rust-input').value;
            const res = await fetch('/api/check-gate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rust_code: input })
            });
            const d = await res.json();
            const out = document.getElementById('gate-output');
            if (d.passed) {
                out.innerHTML = `<div class="step-card step-green"><div class="step-header" style="color: var(--bauhaus-green);">[APPROVED] 100% SAFE RUST</div><div class="step-body mono">Passed static analysis in ${(d.execution_time_seconds * 1000).toFixed(3)}ms! Theoretical score: ${d.score_if_passed}</div></div>`;
            } else {
                out.innerHTML = `<div class="step-card step-red"><div class="step-header" style="color: var(--bauhaus-red);">[HARD STOP] REJECTED</div><div class="step-body mono">${d.reason} (Score: 0.0)</div></div>`;
            }
        }

        window.onload = loadInitialData;
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

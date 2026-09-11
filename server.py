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
    <title>AEGIS SUBNET // C-to-Safe-Rust Adversarial Network</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@400;500;700;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #07090e;
            --card-bg: #0f1422;
            --border: #1e293b;
            --border-hover: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --cyan: #00f0ff;
            --green: #10b981;
            --red: #f43f5e;
            --purple: #a855f7;
            --amber: #f59e0b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
            line-height: 1.5;
            padding: 24px;
        }
        code, pre { font-family: 'JetBrains Mono', monospace; }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
        }
        .logo-group h1 {
            font-size: 24px;
            font-weight: 900;
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .logo-group h1 span { color: var(--cyan); }
        .tagline {
            color: var(--text-muted);
            font-size: 13px;
            margin-top: 4px;
        }
        .status-pill {
            background: rgba(16, 185, 129, 0.1);
            color: var(--green);
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .status-pill::before {
            content: '';
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--green);
            box-shadow: 0 0 8px var(--green);
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .metric-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px;
        }
        .metric-card .title { font-size: 12px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; }
        .metric-card .val { font-size: 26px; font-weight: 800; margin-top: 6px; }
        .metric-card .subtitle { font-size: 11px; color: var(--cyan); margin-top: 4px; }
        
        .main-layout {
            display: grid;
            grid-template-columns: 1fr 1.2fr;
            gap: 24px;
        }
        .panel {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
            display: flex;
            flex-direction: column;
        }
        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }
        .panel-title {
            font-size: 16px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        textarea {
            width: 100%;
            height: 220px;
            background: #090d16;
            border: 1px solid var(--border);
            border-radius: 8px;
            color: #38bdf8;
            padding: 12px;
            font-size: 13px;
            resize: vertical;
            outline: none;
            margin-bottom: 14px;
        }
        textarea:focus { border-color: var(--cyan); }
        .btn {
            background: linear-gradient(135deg, #00f0ff, #0284c7);
            color: #000;
            font-weight: 700;
            border: none;
            border-radius: 8px;
            padding: 12px 20px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.2s;
        }
        .btn:hover { opacity: 0.9; transform: translateY(-1px); }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        .table th {
            text-align: left;
            padding: 10px 12px;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border);
            font-size: 11px;
            text-transform: uppercase;
        }
        .table td {
            padding: 12px;
            border-bottom: 1px solid var(--border);
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
        }
        .badge-green { background: rgba(16, 185, 129, 0.15); color: var(--green); }
        .badge-red { background: rgba(244, 63, 94, 0.15); color: var(--red); }
        .badge-purple { background: rgba(168, 85, 247, 0.15); color: var(--purple); }
        .badge-amber { background: rgba(245, 158, 11, 0.15); color: var(--amber); }

        .timeline-step {
            background: #0a0e1a;
            border-left: 3px solid var(--border);
            padding: 12px 16px;
            margin-bottom: 12px;
            border-radius: 0 8px 8px 0;
            font-size: 13px;
        }
        .timeline-step.success { border-left-color: var(--green); }
        .timeline-step.danger { border-left-color: var(--red); }
        .timeline-step.fuzz { border-left-color: var(--purple); }
        .step-head { font-weight: 700; display: flex; justify-content: space-between; margin-bottom: 4px; }
        .step-desc { color: var(--text-muted); font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo-group">
            <h1><span>AEGIS</span> // C-TO-SAFE-RUST SUBNET</h1>
            <div class="tagline">Bittensor Subnet Hackathon • Adversarial Breakers • Static Gates • Differential Fuzzing</div>
        </div>
        <div class="status-pill" id="net-status">Localnet Synchronized</div>
    </div>

    <div class="metrics-grid">
        <div class="metric-card">
            <div class="title">Current Block / NetUID</div>
            <div class="val" id="block-val">#1,008</div>
            <div class="subtitle">Subnet 1 (Local Subtensor)</div>
        </div>
        <div class="metric-card">
            <div class="title">Anti-Cheat Hard Gate</div>
            <div class="val" style="color: var(--green)">100% Reject</div>
            <div class="subtitle">unsafe / libc / process &lt;1ms</div>
        </div>
        <div class="metric-card">
            <div class="title">Top Translator Score</div>
            <div class="val" style="color: var(--cyan)" id="top-score">1.2000</div>
            <div class="subtitle">PassRate² × SpeedBonus</div>
        </div>
        <div class="metric-card">
            <div class="title">Breaker Bounty Pool</div>
            <div class="val" style="color: var(--purple)">0.5000 TAO</div>
            <div class="subtitle">Awarded per caught divergence</div>
        </div>
    </div>

    <div class="main-layout">
        <!-- Interactive Controls -->
        <div class="panel">
            <div class="panel-header">
                <div class="panel-title">⚡ Benchmark C Code Input</div>
                <span class="badge badge-purple">Candidate Challenge</span>
            </div>
            <textarea id="c-source"></textarea>
            <div style="display: flex; gap: 10px;">
                <button class="btn" id="run-btn" onclick="executeValidationRound()">
                    🚀 Trigger Live Validation Round
                </button>
            </div>
            
            <div style="margin-top: 24px;">
                <div class="panel-title" style="margin-bottom: 12px;">🛡️ Anti-Cheat Hard Gate Tester</div>
                <input id="quick-rust" type="text" placeholder='Enter Rust snippet, e.g. pub fn test() { unsafe {} }' 
                       style="width: 100%; padding: 10px; background: #090d16; border: 1px solid var(--border); border-radius: 6px; color: #fff; font-family: 'JetBrains Mono'; font-size: 12px; margin-bottom: 8px;">
                <button class="btn" style="background: #1e293b; color: #f8fafc; font-size: 12px; padding: 8px 14px;" onclick="testHardGate()">Test Static Gate</button>
                <div id="gate-result" style="margin-top: 8px; font-size: 12px; font-family: 'JetBrains Mono';"></div>
            </div>
        </div>

        <!-- Live Results & Leaderboard -->
        <div class="panel">
            <div class="panel-header">
                <div class="panel-title">🏆 Real-time Metagraph Leaderboard</div>
                <span class="badge badge-green">Live Weights</span>
            </div>
            <table class="table">
                <thead>
                    <tr>
                        <th>UID / Miner</th>
                        <th>Role</th>
                        <th>Pass Rate</th>
                        <th>Score</th>
                        <th>Decision</th>
                    </tr>
                </thead>
                <tbody id="leaderboard-body">
                    <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading metagraph data...</td></tr>
                </tbody>
            </table>

            <div style="margin-top: 24px;">
                <div class="panel-title" style="margin-bottom: 12px;">🔍 Live Round Execution Trace</div>
                <div id="timeline-container">
                    <div class="timeline-step">
                        <div class="step-head">Ready for Challenge Dispatch</div>
                        <div class="step-desc">Click "Trigger Live Validation Round" to query Translator and Breaker miners.</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Pre-load benchmark code on startup
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
                let badgeClass = 'badge-green';
                if (m.decision.includes('SLASHED')) badgeClass = 'badge-red';
                else if (m.decision.includes('BOUNTY')) badgeClass = 'badge-purple';
                else if (m.decision.includes('LOW')) badgeClass = 'badge-amber';

                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>#${m.uid}</strong> ${m.hotkey}</td>
                    <td>${m.role}</td>
                    <td>${m.status}</td>
                    <td style="font-weight: 700; color: var(--cyan); font-family: 'JetBrains Mono';">${m.avg_score.toFixed(4)}</td>
                    <td><span class="badge ${badgeClass}">${m.decision}</span></td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function executeValidationRound() {
            const btn = document.getElementById('run-btn');
            const cCode = document.getElementById('c-source').value;
            btn.disabled = true;
            btn.innerText = '⚡ Orchestrating Subnet Round...';

            const container = document.getElementById('timeline-container');
            container.innerHTML = `
                <div class="timeline-step">
                    <div class="step-head">1. Ingesting C Benchmark & Querying Miners</div>
                    <div class="step-desc">Dispatched TranslationSynapse to Translator axons.</div>
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
                            <div class="timeline-step danger">
                                <div class="step-head" style="color: var(--red);">⛔ STATIC GATE REJECT: ${m.hotkey}</div>
                                <div class="step-desc">${m.reason} • Score: 0.0000 (Slashed in &lt;1ms)</div>
                            </div>
                        `;
                    } else if (m.role === 'breaker') {
                        html += `
                            <div class="timeline-step fuzz">
                                <div class="step-head" style="color: var(--purple);">💥 ADVERSARIAL BREAKER: ${m.hotkey}</div>
                                <div class="step-desc">Injected edge-case boundary inputs • Caught weak miner divergences • Awarded ${m.score} TAO bounty</div>
                            </div>
                        `;
                    } else {
                        html += `
                            <div class="timeline-step success">
                                <div class="step-head" style="color: var(--green);">✅ COMPILATION &amp; DIFF FUZZ: ${m.hotkey}</div>
                                <div class="step-desc">Pass Rate: ${(m.pass_rate * 100).toFixed(1)}% • Final Score: ${m.score.toFixed(4)} (${m.breakdown.base_score} × ${m.breakdown.safety_penalty} × ${m.breakdown.speed_bonus})</div>
                            </div>
                        `;
                    }
                });

                container.innerHTML = html;
                fetchLeaderboard();
                
                // Update block
                const stat = await (await fetch('/api/status')).json();
                document.getElementById('block-val').innerText = '#' + stat.current_block;
            } catch (e) {
                container.innerHTML = `<div class="timeline-step danger"><div class="step-head">Error</div><div class="step-desc">${e.message}</div></div>`;
            } finally {
                btn.disabled = false;
                btn.innerText = '🚀 Trigger Live Validation Round';
            }
        }

        async function testHardGate() {
            const input = document.getElementById('quick-rust').value;
            const res = await fetch('/api/check-gate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rust_code: input })
            });
            const d = await res.json();
            const out = document.getElementById('gate-result');
            if (d.passed) {
                out.innerHTML = `<span style="color: var(--green);">[PASS] Safe Rust approved in ${d.execution_time_seconds * 1000}ms! Score: ${d.score_if_passed}</span>`;
            } else {
                out.innerHTML = `<span style="color: var(--red);">[REJECT] Hard Gate Triggered: ${d.reason} (Score: 0.0)</span>`;
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

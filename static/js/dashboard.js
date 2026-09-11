/**
 * AEGIS SUBNET — CONSTRUCTIVIST COMMAND CENTER CONTROLLER
 * Architecture: Form Follows Function // Mechanical Interaction
 */

(function () {
    'use strict';

    // DOM References
    const dom = {
        netuid: document.getElementById('disp-netuid'),
        blockTop: document.getElementById('disp-block-top'),
        statusText: document.getElementById('disp-status-text'),
        block: document.getElementById('disp-block'),
        rounds: document.getElementById('disp-rounds'),
        miners: document.getElementById('disp-miners'),
        sandbox: document.getElementById('disp-sandbox'),
        taskSelect: document.getElementById('task-select'),
        testCountSelect: document.getElementById('test-count-select'),
        btnTrigger: document.getElementById('btn-trigger'),
        gateCode: document.getElementById('gate-test-code'),
        btnGate: document.getElementById('btn-gate'),
        gateFeedback: document.getElementById('gate-feedback'),
        leaderboardBody: document.getElementById('leaderboard-body'),
        terminalStream: document.getElementById('terminal-stream')
    };

    // Terminal Logging Helper
    function appendTerminal(tag, tagClass, message) {
        if (!dom.terminalStream) return;
        const line = document.createElement('div');
        line.className = 'terminal-line';
        
        const now = new Date();
        const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
        
        const timeSpan = document.createElement('span');
        timeSpan.className = 'dim';
        timeSpan.textContent = `[${timeStr}] `;
        
        const tagSpan = document.createElement('span');
        tagSpan.className = tagClass;
        tagSpan.textContent = `[${tag}] `;
        
        const msgSpan = document.createElement('span');
        msgSpan.textContent = message;
        
        line.appendChild(timeSpan);
        line.appendChild(tagSpan);
        line.appendChild(msgSpan);
        
        dom.terminalStream.appendChild(line);
        
        // Limit buffer
        while (dom.terminalStream.children.length > 150) {
            dom.terminalStream.removeChild(dom.terminalStream.firstChild);
        }
        
        // Auto scroll
        dom.terminalStream.scrollTop = dom.terminalStream.scrollHeight;
    }

    // Fetch Subnet Status
    async function fetchStatus() {
        try {
            const res = await fetch('/api/status');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            if (dom.netuid) dom.netuid.textContent = `NETUID: ${data.netuid || 1}`;
            if (dom.blockTop) dom.blockTop.textContent = `BLOCK: #${data.current_block || 1000}`;
            if (dom.block) dom.block.textContent = `#${data.current_block || 1000}`;
            if (dom.rounds) dom.rounds.textContent = data.total_rounds_completed ?? 0;
            if (dom.miners) dom.miners.textContent = `${data.miners_active || 4}`;
            if (dom.sandbox) {
                dom.sandbox.textContent = data.docker_sandbox_active ? "DOCKER ACTIVE" : "PROCESS ISOLATED";
            }
        } catch (err) {
            console.error("Status fetch error:", err);
            if (dom.statusText) dom.statusText.textContent = "OFFLINE";
        }
    }

    // Fetch Metagraph Leaderboard
    async function fetchLeaderboard() {
        try {
            const res = await fetch('/api/leaderboard');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            const board = data.leaderboard || [];

            if (!dom.leaderboardBody) return;

            if (board.length === 0) {
                dom.leaderboardBody.innerHTML = `
                    <tr>
                        <td colspan="5" style="text-align: center; color: #888; padding: 24px;">
                            No validation rounds executed yet. Click "DISPATCH VALIDATION ROUND" above.
                        </td>
                    </tr>
                `;
                return;
            }

            let html = '';
            board.forEach(row => {
                let pillClass = 'pill-zero';
                if (row.status === 'STRONG' || row.avg_score >= 0.8) {
                    pillClass = 'pill-strong';
                } else if (row.status === 'ACTIVE' || row.avg_score > 0) {
                    pillClass = 'pill-active';
                }

                html += `
                    <tr>
                        <td style="font-weight: 800; font-family: var(--font-mono);">${row.uid}</td>
                        <td><span class="mono" style="font-weight: 700;">${row.hotkey}</span></td>
                        <td style="font-weight: 700; text-transform: uppercase;">${row.role}</td>
                        <td><span class="mono" style="font-weight: 800; font-size: 14px;">${Number(row.avg_score).toFixed(4)}</span></td>
                        <td><span class="pill-status ${pillClass}">${row.status}</span></td>
                    </tr>
                `;
            });

            dom.leaderboardBody.innerHTML = html;
        } catch (err) {
            console.error("Leaderboard fetch error:", err);
            if (dom.leaderboardBody) {
                dom.leaderboardBody.innerHTML = `
                    <tr>
                        <td colspan="5" style="text-align: center; color: var(--primary-red); padding: 16px;">
                            Failed to load leaderboard: ${err.message}
                        </td>
                    </tr>
                `;
            }
        }
    }

    // Dispatch Validation Round
    async function triggerValidationRound() {
        const taskName = dom.taskSelect ? dom.taskSelect.value : "reverse_bytes";
        const numTests = dom.testCountSelect ? parseInt(dom.testCountSelect.value, 10) : 20;

        dom.btnTrigger.disabled = true;
        dom.btnTrigger.innerText = '⏳ EXECUTING PIPELINE & CONSENSUS...';

        appendTerminal('DISPATCH', 'yellow', `Starting validation round on task "${taskName}" with ${numTests} hidden sanitizer tests...`);

        try {
            const res = await fetch('/api/run-round', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ task_name: taskName, num_tests: numTests })
            });

            if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
            const data = await res.json();

            appendTerminal('ROUND', 'blue', `Round #${data.round_id} completed in ${data.elapsed_seconds}s for task "${data.task_name}"`);

            // Log individual miner outcomes
            const scores = data.scores || {};
            for (const [hotkey, sc] of Object.entries(scores)) {
                const scoreVal = Number(sc).toFixed(4);
                if (hotkey.includes('honest')) {
                    appendTerminal('HONEST', 'blue', `${hotkey} -> score: ${scoreVal} (Sound safe translation verified)`);
                } else if (hotkey.includes('cheater')) {
                    appendTerminal('GATE_REJECT', 'red', `${hotkey} -> score: ${scoreVal} (Rejected by Zero-Unsafe Gate)`);
                } else if (hotkey.includes('weak')) {
                    appendTerminal('WEAK_MINER', 'yellow', `${hotkey} -> score: ${scoreVal} (Partial pass / boundary caught)`);
                } else if (hotkey.includes('breaker')) {
                    appendTerminal('BREAKER', 'yellow', `${hotkey} -> score: ${scoreVal} (Adversarial fuzzer reward evaluated)`);
                } else {
                    appendTerminal('MINER', 'dim', `${hotkey} -> score: ${scoreVal}`);
                }
            }

            // Refresh UI
            await fetchStatus();
            await fetchLeaderboard();
        } catch (err) {
            appendTerminal('ERROR', 'red', `Round failed: ${err.message}`);
        } finally {
            dom.btnTrigger.disabled = false;
            dom.btnTrigger.innerText = '► DISPATCH VALIDATION ROUND';
        }
    }

    // Static AST Gate Check
    async function runGateCheck() {
        const code = dom.gateCode ? dom.gateCode.value : "";
        if (!code.trim()) {
            alert("Please provide Rust code to audit.");
            return;
        }

        dom.btnGate.disabled = true;
        dom.btnGate.innerText = '⚡ SCANNING AST TOKENS...';

        try {
            const res = await fetch('/api/check-gate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rust_code: code })
            });

            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            if (data.passed) {
                dom.gateFeedback.innerHTML = `
                    <div style="margin-top: 14px; padding: 14px; background: var(--yellow-light); border: 3px solid var(--border); box-shadow: var(--shadow-sm);">
                        <div style="font-size: 13px; font-weight: 900; color: #008000; text-transform: uppercase;">✔ GATE PASSED: ZERO-UNSAFE COMPLIANT</div>
                        <div class="mono" style="font-size: 12px; margin-top: 6px; color: var(--fg);">
                            Verified 0 unsafe blocks, 0 raw pointers, 0 inline asm in ${(data.elapsed_seconds * 1000).toFixed(2)}ms.
                            <br><strong>Gate Score Multiplier: 1.0000</strong>
                        </div>
                    </div>
                `;
                appendTerminal('GATE_PASS', 'blue', `AST Gate PASSED in ${(data.elapsed_seconds * 1000).toFixed(2)}ms. Code adheres to Safe Rust rules.`);
            } else {
                dom.gateFeedback.innerHTML = `
                    <div style="margin-top: 14px; padding: 14px; background: #FFE8E8; border: 3px solid var(--primary-red); box-shadow: var(--shadow-sm);">
                        <div style="font-size: 13px; font-weight: 900; color: var(--primary-red); text-transform: uppercase;">⛔ GATE REJECTED: ZERO-TOLERANCE HARD STOP</div>
                        <div class="mono" style="font-size: 12px; margin-top: 6px; color: var(--fg);">
                            Violation: <strong>${data.reason}</strong>
                            <br>Pre-score instantly assigned: <strong>0.0000</strong>
                        </div>
                    </div>
                `;
                appendTerminal('GATE_REJECT', 'red', `AST Gate REJECTED: ${data.reason} -> Score: 0.0000`);
            }
        } catch (err) {
            dom.gateFeedback.innerHTML = `
                <div style="margin-top: 14px; padding: 14px; background: #FFE8E8; border: 3px solid var(--primary-red);">
                    <div class="mono" style="font-size: 12px; color: var(--primary-red);">Audit request error: ${err.message}</div>
                </div>
            `;
            appendTerminal('ERROR', 'red', `Gate audit request error: ${err.message}`);
        } finally {
            dom.btnGate.disabled = false;
            dom.btnGate.innerText = '⚡ RUN ZERO-TOLERANCE GATE CHECK';
        }
    }

    // Initialize Accordion Interactive Handlers
    function initAccordions() {
        const items = document.querySelectorAll('.accordion-item');
        items.forEach(item => {
            const header = item.querySelector('.accordion-header');
            if (header) {
                header.addEventListener('click', () => {
                    item.classList.toggle('active');
                });
            }
        });
    }

    // Setup Event Listeners
    function init() {
        if (dom.btnTrigger) {
            dom.btnTrigger.addEventListener('click', triggerValidationRound);
        }
        if (dom.btnGate) {
            dom.btnGate.addEventListener('click', runGateCheck);
        }

        initAccordions();

        // Initial Data Fetch
        fetchStatus();
        fetchLeaderboard();

        // Background Polling (Every 4s)
        setInterval(() => {
            fetchStatus();
        }, 4000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();

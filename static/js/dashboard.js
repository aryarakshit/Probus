/**
 * PROBUS dashboard controller.
 * One EventSource carries every validator event and log line; the rest is plain fetch.
 */
(function () {
    'use strict';

    const $ = (id) => document.getElementById(id);
    const NEURONS = [
        { key: 'translator_llm',     role: 'translator', label: 'LLM miner',  fixture: false },
        { key: 'translator_weak',    role: 'translator', label: 'fixture',    fixture: true },
        { key: 'translator_cheater', role: 'translator', label: 'fixture',    fixture: true },
        { key: 'breaker',            role: 'breaker',    label: 'red team',   fixture: false },
    ];
    const STAGES = ['translate', 'gate', 'rustc', 'hidden', 'attack'];

    const state = { round: null, neurons: {}, lines: 0, llm: null };

    // ------------------------------------------------------------ helpers
    function esc(s) { return String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
    function fmt(n, d = 4) { return (typeof n === 'number') ? n.toFixed(d) : '—'; }
    function short(h, n = 12) { return h ? h.slice(0, n) + '…' : '—'; }
    function b64bytes(b64) { const s = atob(b64 || ''); const out = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i); return out; }
    function hexdump(bytes, max = 64) {
        const rows = [];
        for (let i = 0; i < Math.min(bytes.length, max); i += 8) {
            const chunk = bytes.slice(i, i + 8);
            const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
            const asc = Array.from(chunk).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '·').join('');
            rows.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(23)}  ${asc}`);
        }
        if (bytes.length > max) rows.push(`… ${bytes.length - max} more bytes`);
        if (!bytes.length) rows.push('(empty input — zero bytes)');
        return rows.join('\n');
    }
    function reprBytes(bytes, max = 200) {
        let s = '';
        for (let i = 0; i < Math.min(bytes.length, max); i++) {
            const b = bytes[i];
            if (b === 10) s += '\\n'; else if (b === 13) s += '\\r'; else if (b === 9) s += '\\t';
            else if (b >= 32 && b < 127) s += String.fromCharCode(b);
            else s += '\\x' + b.toString(16).padStart(2, '0');
        }
        if (bytes.length > max) s += ` … (${bytes.length} bytes)`;
        return s.length ? s : '(no output)';
    }

    // ------------------------------------------------------------ terminal
    function term(source, msg, level) {
        const el = $('stream');
        const d = new Date();
        const line = document.createElement('div');
        const hit = /BROKEN|divergence #|REJECT|GATE REJECT|LEDGER|SCORED/.test(msg);
        line.innerHTML = `<span class="t">${d.toTimeString().slice(0, 8)}</span> <span class="src">${esc(source)}</span> <span class="${level === 'WARNING' || /REJECT|BROKEN|failed/i.test(msg) ? 'warn' : ''}${hit ? ' hit' : ''}">${esc(msg)}</span>`;
        el.appendChild(line);
        while (el.children.length > 400) el.removeChild(el.firstChild);
        el.scrollTop = el.scrollHeight;
        state.lines++;
        $('term-count').textContent = `${state.lines} lines`;
    }

    // ------------------------------------------------------------ neuron cards
    function resetNeurons() {
        const host = $('neurons');
        host.innerHTML = '';
        state.neurons = {};
        for (const n of NEURONS) {
            const mode = state.llm ? (n.key === 'translator_llm' ? (state.llm.mode === 'live' ? `${state.llm.provider}:${state.llm.model}` : 'replay of recorded model output') : '') : '';
            const card = document.createElement('div');
            card.className = 'neuron';
            card.id = 'n-' + n.key;
            card.innerHTML = `
                <div class="who"><h4>${esc(n.key)}</h4><span class="role ${n.fixture ? 'fixture' : ''}">${esc(n.label)}</span></div>
                <div class="state dim" data-state>queued</div>
                <div class="pipeline">${n.role === 'translator' ? STAGES.map(s => `<span data-stage="${s}" title="${s}"></span>`).join('') : '<span data-stage="attack"></span>'}</div>
                <div class="kv" data-kv>${mode ? `<span>model</span><b>${esc(mode)}</b>` : ''}</div>
                <div class="fuzzlog" data-fuzz></div>
                <div class="score"><div class="lbl"><span>${n.role === 'breaker' ? 'bounty' : 'final score'}</span><span data-pre></span></div>
                    <div class="big" data-score>—</div><div class="bar"><i data-bar></i></div></div>`;
            host.appendChild(card);
            state.neurons[n.key] = { card, role: n.role };
        }
    }
    function setState(key, text, cls) {
        const n = state.neurons[key]; if (!n) return;
        const el = n.card.querySelector('[data-state]');
        el.textContent = text; el.className = 'state ' + (cls || '');
    }
    function stage(key, name, ok) {
        const n = state.neurons[key]; if (!n) return;
        const el = n.card.querySelector(`[data-stage="${name}"]`); if (!el) return;
        el.className = ok === false ? 'bad' : 'on';
    }
    function kv(key, pairs) {
        const n = state.neurons[key]; if (!n) return;
        const el = n.card.querySelector('[data-kv]');
        for (const [k, v] of pairs) {
            let row = el.querySelector(`[data-k="${k}"]`);
            if (!row) { el.insertAdjacentHTML('beforeend', `<span>${esc(k)}</span><b data-k="${k}"></b>`); row = el.querySelector(`[data-k="${k}"]`); }
            row.textContent = v;
        }
    }
    function fuzz(key, msg) {
        const n = state.neurons[key]; if (!n) return;
        const el = n.card.querySelector('[data-fuzz]');
        el.insertAdjacentHTML('beforeend', `<div>${esc(msg)}</div>`);
        while (el.children.length > 5) el.removeChild(el.firstChild);
    }
    function score(key, value, pre, red) {
        const n = state.neurons[key]; if (!n) return;
        const big = n.card.querySelector('[data-score]'); big.textContent = fmt(value); big.className = 'big ' + (red ? 'red' : '');
        if (pre !== undefined) n.card.querySelector('[data-pre]').textContent = pre;
        const bar = n.card.querySelector('[data-bar]'); bar.style.width = `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`; bar.className = red ? 'red' : '';
    }

    // ------------------------------------------------------------ spotlight
    function spotlight(entry) {
        const sp = $('spotlight');
        let best = null;
        for (const [hk, ev] of Object.entries(entry.translator_evals || {})) {
            if (ev.broken_by && ev.broken_by.length && ev.reproducers && ev.reproducers.length) {
                const r = ev.reproducers[0];
                if (!best || r.input_len < best.r.input_len) best = { hk, ev, r };
            }
        }
        if (!best) { sp.classList.remove('show'); return; }
        const { hk, ev, r } = best;
        const inp = b64bytes(r.input_b64);
        $('sp-head').innerHTML = `<em>${esc(hk)}</em> broken by ${esc(ev.broken_by.join(', '))} with <em>${inp.length} byte${inp.length === 1 ? '' : 's'}</em>`;
        $('sp-meta').className = 'kv';
        $('sp-meta').innerHTML = [
            ['task', `${entry.task_name} ${JSON.stringify(entry.constants)}`],
            ['hidden tests', `${ev.passed_hidden}/${ev.total_hidden} passed — the suite missed it`],
            ['reason', r.reason],
            ['score', `pre_t ${fmt(ev.pre_t)} → final ${fmt(ev.final_score)}; bounty ${fmt((entry.breaker_evals[ev.broken_by[0]] || {}).final_score)}`],
        ].map(([k, v]) => `<span>${esc(k)}</span><b>${esc(v)}</b>`).join('');
        $('sp-hex').textContent = hexdump(inp);
        $('sp-c').textContent = reprBytes(b64bytes(r.c_stdout_b64));
        $('sp-r').textContent = reprBytes(b64bytes(r.rust_stdout_b64));
        $('sp-exit').textContent = `exit codes — C: ${r.c_exit}   Rust: ${r.rust_exit}${r.rust_timed_out ? ' (timed out)' : ''}`;
        sp.classList.add('show');
    }

    // Paint the final state of a round onto the cards. `hydrate` = page opened after the
    // round already ran, so the live stages are reconstructed from the record.
    function finalize(entry, hydrate) {
        if (hydrate) {
            resetNeurons();
            $('r-id').textContent = `round ${entry.round_id}`;
            $('r-hidden').textContent = `hidden ${entry.hidden_tests}`;
            $('r-elapsed').textContent = `${entry.elapsed_seconds}s`;
            $('r-task').firstChild.textContent = entry.task_name + ' ';
            $('r-consts').textContent = JSON.stringify(entry.constants) + '  c ' + short(entry.c_sha256, 10);
        }
        for (const [hk, ev] of Object.entries(entry.translator_evals)) {
            const broken = ev.broken_by && ev.broken_by.length;
            if (hydrate) {
                stage(hk, 'translate', true);
                kv(hk, [['attempts', String(ev.attempts ?? 1)], ['rust', short(ev.rust_sha256, 10)], ['gate', `${ev.gate_ms} ms`]]);
                if (!ev.gate_success) { stage(hk, 'gate', false); setState(hk, 'gate reject', 'red'); kv(hk, [['why', ev.reject_reason]]); score(hk, 0, 'pre_t 0', true); continue; }
                stage(hk, 'gate', true);
                if (!ev.compile_success) { stage(hk, 'rustc', false); setState(hk, 'rustc fail', 'red'); kv(hk, [['why', (ev.compile_error || '').slice(0, 80)]]); score(hk, 0, 'pre_t 0', true); continue; }
                stage(hk, 'rustc', true); stage(hk, 'hidden', ev.passed_hidden === ev.total_hidden);
                kv(hk, [['hidden', `${ev.passed_hidden}/${ev.total_hidden}`], ['notes', (ev.miner_notes || '').slice(0, 60)]]);
            }
            if (ev.gate_success && ev.compile_success) {
                const failed = !broken && ev.final_score === 0;
                setState(hk, broken ? 'broken' : failed ? 'failed hidden' : 'survived', (broken || failed) ? 'red' : '');
                if (!failed) stage(hk, 'attack', !broken);
                score(hk, ev.final_score, `pre_t ${fmt(ev.pre_t)}`, broken || ev.final_score === 0);
                if (broken) kv(hk, [['reproducer', `${ev.reproducers[0].input_len} B ${ev.reproducers[0].reason}`]]);
            }
        }
        for (const [hk, ev] of Object.entries(entry.breaker_evals)) {
            setState(hk, ev.final_score > 0 ? 'bounty' : 'no hit', ev.final_score > 0 ? 'red' : 'dim');
            kv(hk, [['valid', `${ev.valid_inputs}/${ev.inputs_submitted}`], ['invalid', String(ev.invalid_inputs)]]);
            if (hydrate) for (const line of (ev.rationale || []).slice(0, 3)) fuzz(hk, line.slice(0, 90));
            score(hk, ev.final_score, 'earned', false);
        }
        spotlight(entry);
    }

    // ------------------------------------------------------------ events
    function onEvent(e) {
        switch (e.kind) {
            case 'hello':
                if (e.running) setRunning(true);
                break;
            case 'log':
                term(e.source.replace('miner_', ''), e.msg, e.level);
                if (e.source === 'miner_breaker' && /divergence #/.test(e.msg)) fuzz('breaker', e.msg);
                if (e.source === 'miner_translator' && /\[attempt (\d+)\]/.test(e.msg)) {
                    const m = e.msg.match(/\[attempt (\d+)\] (.*)/);
                    fuzz('translator_llm', `attempt ${m[1]} rejected by self-test: ${m[2].slice(0, 70)}`);
                    kv('translator_llm', [['attempts', String(Number(m[1]) + 1)]]);
                }
                break;
            case 'round_start':
                setRunning(true); resetNeurons(); $('spotlight').classList.remove('show');
                $('r-id').textContent = `round ${e.round_id}`; $('r-hidden').textContent = 'hidden —'; $('r-elapsed').textContent = '';
                $('r-task').firstChild.textContent = 'sampling task ';
                break;
            case 'task':
                $('r-task').firstChild.textContent = e.task + ' ';
                $('r-consts').textContent = JSON.stringify(e.constants) + '  c ' + short(e.c_sha256, 10);
                break;
            case 'hidden_tests':
                $('r-hidden').textContent = `hidden ${e.count}`;
                break;
            case 'translators_query':
                for (const k of ['translator_llm', 'translator_weak', 'translator_cheater']) setState(k, 'translating', '');
                setState('breaker', 'waiting', 'dim');
                break;
            case 'translator_eval': {
                const k = e.hotkey;
                stage(k, 'translate', true);
                kv(k, [['attempts', String(e.attempts ?? 1)], ['rust', short(e.rust_sha256, 10)], ['gate', `${e.gate_ms} ms`]]);
                if (!e.gate) { stage(k, 'gate', false); setState(k, 'gate reject', 'red'); kv(k, [['why', e.reason]]); score(k, 0, 'pre_t 0', true); break; }
                stage(k, 'gate', true);
                if (!e.compile) { stage(k, 'rustc', false); setState(k, 'rustc fail', 'red'); kv(k, [['why', (e.error || '').slice(0, 80)]]); score(k, 0, 'pre_t 0', true); break; }
                stage(k, 'rustc', true); stage(k, 'hidden', e.passed === e.total);
                kv(k, [['hidden', `${e.passed}/${e.total}`], ['notes', (e.notes || '').slice(0, 60)]]);
                setState(k, e.pre_t > 0 ? 'under attack' : 'failed', e.pre_t > 0 ? '' : 'red');
                score(k, e.pre_t, `pre_t ${fmt(e.pre_t)}`, e.pre_t === 0);
                break;
            }
            case 'breaker_query':
                setState('breaker', `fuzzing ${e.target.replace('translator_', '')}`, '');
                stage(e.target, 'attack', true);
                break;
            case 'breaker_result':
                kv('breaker', [[`vs ${e.target.replace('translator_', '')}`, `${e.inputs} inputs`]]);
                break;
            case 'weights': {
                setState('breaker', 'scored', 'dim');
                break;
            }
            case 'round_end':
                setRunning(false);
                $('r-elapsed').textContent = `${e.elapsed}s`;
                fetch(`/api/rounds/${e.round_id}`).then(r => r.json()).then(entry => { finalize(entry, false); refreshAll(); });
                break;
            case 'error':
                term('server', e.msg, 'WARNING'); setRunning(false);
                break;
        }
    }

    function connect() {
        const es = new EventSource('/api/events');
        es.onmessage = (m) => { try { onEvent(JSON.parse(m.data)); } catch (err) { console.error(err); } };
        es.onerror = () => { $('dot-net').classList.add('red'); };
        es.onopen = () => { $('dot-net').classList.remove('red'); };
    }

    // ------------------------------------------------------------ controls
    function setRunning(on) {
        $('controls').classList.toggle('running', on);
        $('run').disabled = on;
        $('run').innerHTML = on ? '<span class="g-circle"></span>running…' : '<span class="g-circle"></span>Run round';
        $('dot-net').classList.toggle('live', on);
    }
    async function runRound() {
        const body = { task_name: $('task').value || null, num_tests: Number($('tests').value), seed: $('seed').value ? Number($('seed').value) : null };
        const res = await fetch('/api/run-round', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!res.ok) { term('server', (await res.json()).detail, 'WARNING'); return; }
        const j = await res.json();
        term('server', `dispatched: task=${j.task} seed=${j.seed ?? 'auto'}`);
        setRunning(true);
    }
    async function runGate() {
        const res = await fetch('/api/check-gate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rust_code: $('gate-code').value }) });
        const j = await res.json();
        const out = $('gate-out');
        out.innerHTML = `<div class="v ${j.passed ? '' : 'red'}">${j.passed ? 'pass' : 'reject'}</div><div>${esc(j.reason || 'no banned pattern; rustc -F unsafe_code is the real enforcement')}</div><div style="color:var(--grey);margin-top:6px">${j.elapsed_ms} ms</div>`;
        out.classList.add('show');
    }
    async function verifyLedger() {
        const btn = $('verify'); btn.disabled = true;
        const j = await fetch('/api/ledger/verify').then(r => r.json());
        const out = $('verify-out');
        out.className = 'verify-out show ' + (j.ok ? 'ok' : 'bad');
        out.innerHTML = `${j.ok ? 'VERIFIED' : 'FAILED'} — ${j.rounds} round(s), ${j.objects_checked} object(s) re-hashed, chain head ${short(j.head, 16)} — ${j.elapsed_ms} ms` +
            (j.problems.length ? '<br>' + j.problems.map(esc).join('<br>') : '');
        btn.disabled = false;
    }

    // ------------------------------------------------------------ data panels
    async function loadStatus() {
        const s = await fetch('/api/status').then(r => r.json());
        state.llm = s.llm;
        $('s-net').textContent = `${s.network} · uid ${s.netuid}`;
        $('s-block').textContent = '#' + s.block;
        $('s-rounds').textContent = s.rounds;
        $('s-llm').textContent = s.llm.mode === 'live' ? `${s.llm.provider}:${s.llm.model}` : `replay (${s.llm.replay_files} recorded)`;
        $('s-sandbox').textContent = s.sandbox;
        $('s-ledger').textContent = `h${s.ledger.rounds} ${short(s.ledger.head, 8)}`;
        if (s.running && !$('controls').classList.contains('running')) setRunning(true);
        if (!Object.keys(state.neurons).length) resetNeurons();
    }
    async function loadTasks() {
        const j = await fetch('/api/tasks').then(r => r.json());
        const sel = $('task');
        for (const t of j.tasks) { const o = document.createElement('option'); o.value = t.name; o.textContent = `${t.name}  (${t.c_lines} lines)`; o.dataset.desc = t.description; sel.appendChild(o); }
        sel.onchange = () => { $('task-desc').textContent = sel.selectedOptions[0].dataset.desc || ''; };
    }
    function cell(ev) {
        if (!ev) return '<td>—</td>';
        if (!ev.gate_success) return `<td><span class="tag red">gate</span></td>`;
        if (!ev.compile_success) return `<td><span class="tag red">rustc</span></td>`;
        const broken = ev.broken_by && ev.broken_by.length;
        return `<td><span class="mini-bar"><i class="${broken ? 'red' : ''}" style="width:${Math.round(ev.pre_t * 100)}%"></i></span>${ev.passed_hidden}/${ev.total_hidden} ${broken ? `<span class="tag red">broken ${ev.reproducers[0] ? ev.reproducers[0].input_len + 'B' : ''}</span>` : `<span class="tag fill">${fmt(ev.final_score, 2)}</span>`}</td>`;
    }
    async function loadRounds() {
        const j = await fetch('/api/rounds?limit=40').then(r => r.json());
        const body = $('rounds-body');
        if (!j.rounds.length) return;
        body.innerHTML = j.rounds.map(r => {
            const te = r.translator_evals || {}, be = r.breaker_evals || {};
            const br = be.breaker;
            const w = Object.values(r.normalized_weights || {}).map(v => fmt(v, 2)).join(' ');
            return `<tr class="clickable" data-id="${r.round_id}">
                <td>${r.round_id}</td><td>${esc(r.task_name)}</td><td>${esc(JSON.stringify(r.constants))}</td><td>${r.hidden_tests}</td>
                ${cell(te.translator_llm)}${cell(te.translator_weak)}${cell(te.translator_cheater)}
                <td>${br ? `${br.valid_inputs} valid · <span class="tag ${br.final_score > 0 ? 'red' : 'dim'}">${fmt(br.final_score, 2)}</span>` : '—'}</td>
                <td>${esc(w)}</td><td>${short(r.ledger && r.ledger.root, 12)}</td><td>${r.elapsed_seconds}s</td></tr>`;
        }).join('');
        body.querySelectorAll('tr').forEach(tr => tr.onclick = () => openRecord(Number(tr.dataset.id)));
    }
    async function openRecord(id) {
        const r = await fetch(`/api/rounds/${id}`).then(r => r.json());
        $('modal-title').textContent = `round ${id} · ${r.task_name}`;
        $('modal-body').textContent = JSON.stringify(r, null, 2);
        $('modal').classList.add('show');
    }
    async function loadBoard() {
        const j = await fetch('/api/leaderboard').then(r => r.json());
        const body = $('board-body');
        if (!j.leaderboard.length) return;
        body.innerHTML = j.leaderboard.map(b => `<tr>
            <td>${esc(b.hotkey)}</td><td><span class="tag ${b.role === 'breaker' ? 'red' : 'dim'}">${b.role || ''}</span></td>
            <td>${fmt(b.avg)}</td>
            <td><span class="mini-bar"><i class="${b.weight === 0 ? 'red' : ''}" style="width:${Math.round(Math.min(1, b.weight) * 100)}%"></i></span>${fmt(b.weight)} <span style="color:var(--grey)">ema ${fmt(b.ema, 3)}</span></td>
            <td>${b.role === 'breaker' ? `${b.bounties}/${b.rounds} bounties` : `${b.broken} broken · ${b.gated} gated / ${b.rounds}`}</td></tr>`).join('');
    }
    async function loadLedger() {
        const j = await fetch('/api/ledger?limit=12').then(r => r.json());
        $('l-height').textContent = j.stats.rounds; $('l-objects').textContent = j.stats.objects; $('l-head').textContent = j.stats.head;
        $('chain').innerHTML = j.chain.map(c => `<div><b>h${c.height}</b><span>${esc(c.task)} · ${c.root}</span><span>prev ${short(c.prev_root, 16)}</span></div>`).join('') || '<div><b>—</b><span>no commits yet</span><span></span></div>';
    }
    function refreshAll() { loadStatus(); loadRounds(); loadBoard(); loadLedger(); }

    // ------------------------------------------------------------ boot
    $('run').onclick = runRound;
    $('gate-run').onclick = runGate;
    $('verify').onclick = verifyLedger;
    $('modal-close').onclick = () => $('modal').classList.remove('show');
    $('modal').onclick = (e) => { if (e.target === $('modal')) $('modal').classList.remove('show'); };
    loadTasks();
    loadStatus().then(async () => {
        resetNeurons(); loadRounds(); loadBoard(); loadLedger();
        // Show the last completed round cold, so the page is never empty after a demo.
        const j = await fetch('/api/rounds?limit=1').then(r => r.json());
        if (j.rounds.length && !$('controls').classList.contains('running')) finalize(j.rounds[0], true);
    });
    connect();
    setInterval(loadStatus, 15000);
    term('ui', 'connected — dispatch a round to watch the pipeline');
})();

/* ═══════════════════════════════════════════════════════════
   Quantum Threat Detection — Frontend Controller
   ═══════════════════════════════════════════════════════════ */

// ── State ────────────────────────────────────────────────────
let currentSessionId = null;
let dashboardInterval = null;
let attackKnowledgeCache = null;

// ── DOM Ready ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    checkServerStatus();
    setInterval(checkServerStatus, 15000);

    // Restore active tab
    const savedTab = sessionStorage.getItem('qds_active_tab');
    if (savedTab && savedTab !== 'overview') {
        switchTab(savedTab);
    }

    // Restore session ID across tabs
    const savedSessionId = sessionStorage.getItem('qds_session_id');
    if (savedSessionId) {
        currentSessionId = savedSessionId;
        const verifyInput = document.getElementById('verify-session');
        const attackInput = document.getElementById('attack-session');
        if (verifyInput && !verifyInput.value) verifyInput.value = savedSessionId;
        if (attackInput && !attackInput.value) attackInput.value = savedSessionId;
    }

    // Restore generated signature display if available
    const savedSigJson = sessionStorage.getItem('qds_last_signature');
    if (savedSigJson) {
        try {
            const sig = JSON.parse(savedSigJson);
            const resultContainer = document.getElementById('generate-result');
            if (resultContainer && sig) {
                renderGeneratedSignature(sig, resultContainer);
            }
        } catch (e) {}
    }
});

// ── Tab System ───────────────────────────────────────────────
function initTabs() {
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });
}

function switchTab(tabName) {
    sessionStorage.setItem('qds_active_tab', tabName);

    // Update nav tabs
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    const activeNav = document.querySelector(`.nav-tab[data-tab="${tabName}"]`);
    if (activeNav) activeNav.classList.add('active');

    // Update panels
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    const panel = document.getElementById(`panel-${tabName}`);
    if (panel) {
        panel.classList.add('active');
    }

    // Auto-load dashboard data when switching to dashboard tab
    if (tabName === 'dashboard') {
        loadDashboard();
        startDashboardRefresh();
    } else {
        stopDashboardRefresh();
    }

    // Load attack knowledge base when switching to attacks tab
    if (tabName === 'attacks') {
        loadAttackKnowledge();
    }

    // Auto-fill session ID in verify & attack tabs
    if ((tabName === 'verify' || tabName === 'attacks') && currentSessionId) {
        const sessionInput = panel.querySelector('[data-field="session_id"]');
        if (sessionInput && !sessionInput.value) {
            sessionInput.value = currentSessionId;
        }
    }
}

// ── API & Server Connection Helper ───────────────────────────
const API_BASE = (window.location.protocol === 'file:' || (window.location.port !== '5000' && window.location.port !== ''))
    ? 'http://127.0.0.1:5000'
    : '';

async function apiPost(url, data) {
    try {
        const fullUrl = url.startsWith('http') ? url : (API_BASE + url);
        const res = await fetch(fullUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        if (res.status === 429) {
            showToast('Rate limit exceeded. Please wait a moment.', 'error');
            return null;
        }

        const json = await res.json();
        return json;
    } catch (err) {
        const serverHint = API_BASE ? ` at ${API_BASE}` : '';
        showToast(`Network error. Is the Flask server running${serverHint}?`, 'error');
        return null;
    }
}

async function apiGet(url) {
    try {
        const fullUrl = url.startsWith('http') ? url : (API_BASE + url);
        const res = await fetch(fullUrl);
        if (res.status === 429) {
            showToast('Rate limit reached. Auto-refresh paused.', 'warning');
            return null;
        }
        if (!res.ok) {
            return null;
        }
        return await res.json();
    } catch (err) {
        const serverHint = API_BASE ? ` at ${API_BASE}` : '';
        showToast(`Network error loading data from server${serverHint}.`, 'error');
        return null;
    }
}

// ── Render Generated Signature Card ──────────────────────────
function renderGeneratedSignature(sig, resultContainer) {
    if (!sig || !resultContainer) return;
    resultContainer.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <span class="result-status generated">⚡ ${sig.status}</span>
                <div>
                    <span class="session-id-display">${sig.session_id}</span>
                    <button type="button" class="copy-btn" onclick="copySessionId('${sig.session_id}', this)" style="margin-left:8px">📋 Copy ID</button>
                </div>
            </div>
            <div class="result-body">
                <div class="result-grid">
                    <div class="result-field">
                        <div class="field-label">Session ID</div>
                        <div class="field-value">${sig.session_id}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Signer</div>
                        <div class="field-value">${sig.signer}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Bell State</div>
                        <div class="field-value">${sig.bell_state}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Bell Measurement</div>
                        <div class="field-value">${sig.bell_measurement}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Pauli Correction</div>
                        <div class="field-value">${sig.pauli_correction}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Measurement Match</div>
                        <div class="field-value large">${sig.measurement_match}%</div>
                    </div>
                </div>
                <div class="result-reason">
                    <strong>Message Hash (SHA-256):</strong><br>
                    <code style="color:var(--accent-cyan);font-family:'JetBrains Mono',monospace;font-size:12px;word-break:break-all">${sig.message_hash}</code>
                </div>
            </div>
        </div>
    `;
    resultContainer.classList.add('visible');
}

// ── Generate Signature ───────────────────────────────────────
async function generateSignature(e) {
    if (e && e.preventDefault) e.preventDefault();

    const messageEl = document.getElementById('gen-message');
    const signerEl = document.getElementById('gen-signer');
    const btn = document.getElementById('btn-generate');
    const resultContainer = document.getElementById('generate-result');

    const message = messageEl.value.trim();
    const signer = signerEl.value.trim();

    // Validate
    if (!message) {
        showToast('Please enter a message to sign.', 'error');
        messageEl.focus();
        return;
    }
    if (!signer) {
        showToast('Please enter a signer name.', 'error');
        signerEl.focus();
        return;
    }

    // Loading state
    setButtonLoading(btn, true);

    const data = await apiPost('/api/generate', { message, signer });

    setButtonLoading(btn, false);

    if (!data) return;

    if (!data.ok) {
        showToast(data.error || 'Failed to generate signature.', 'error');
        return;
    }

    const sig = data.signature;
    currentSessionId = sig.session_id;

    // Persist to session storage so auto-reloads don't wipe it
    try {
        sessionStorage.setItem('qds_session_id', sig.session_id);
        sessionStorage.setItem('qds_last_signature', JSON.stringify(sig));
        sessionStorage.setItem('qds_active_tab', 'generate');
    } catch (err) {}

    // Pre-populate verify and attack fields
    const verifyInput = document.getElementById('verify-session');
    const attackInput = document.getElementById('attack-session');
    if (verifyInput) verifyInput.value = sig.session_id;
    if (attackInput) attackInput.value = sig.session_id;

    // Render result
    renderGeneratedSignature(sig, resultContainer);
    showToast(`Signature generated! Session: ${sig.session_id}`, 'success');
}

// ── Inspect Signature ────────────────────────────────────────
async function inspectSignature(e) {
    if (e && e.preventDefault) e.preventDefault();
    const sessionEl = document.getElementById('verify-session');
    const btn = document.getElementById('btn-inspect');
    const inspectContainer = document.getElementById('inspect-result');

    const session_id = sessionEl.value.trim();
    if (!session_id) {
        showToast('Please enter a Session ID to inspect.', 'error');
        sessionEl.focus();
        return;
    }

    setButtonLoading(btn, true);
    const data = await apiGet(`/api/signature/${encodeURIComponent(session_id)}`);
    setButtonLoading(btn, false);

    if (!data || !data.ok) {
        showToast(data?.error || 'Signature not found.', 'error');
        inspectContainer.innerHTML = '';
        inspectContainer.classList.remove('visible');
        return;
    }

    const sig = data.signature;
    const statusClass = sig.consumed ? 'reject' : 'generated';
    const statusLabel = sig.consumed ? '🔒 CONSUMED' : '🟢 ACTIVE';

    inspectContainer.innerHTML = `
        <div class="result-card inspector-card">
            <div class="result-header">
                <span class="result-status ${statusClass}">${statusLabel}</span>
                <span style="font-size:13px;color:var(--text-muted)">Signature Inspector</span>
            </div>
            <div class="result-body">
                <div class="result-grid">
                    <div class="result-field">
                        <div class="field-label">Session ID</div>
                        <div class="field-value">${sig.session_id}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Signer</div>
                        <div class="field-value">${sig.signer}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Status</div>
                        <div class="field-value">${sig.status}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Created</div>
                        <div class="field-value" style="font-size:11px">${sig.created_at}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Bell State</div>
                        <div class="field-value">${sig.bell_state}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Pauli Correction</div>
                        <div class="field-value">${sig.pauli_correction}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Measurement Match</div>
                        <div class="field-value large">${sig.measurement_match}%</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Consumed</div>
                        <div class="field-value large" style="color:var(--accent-${sig.consumed ? 'rose' : 'emerald'})">${sig.consumed ? 'Yes' : 'No'}</div>
                    </div>
                </div>

                <!-- Expandable Sections -->
                <div class="accordion" style="margin-top:16px">
                    <button class="accordion-toggle" onclick="toggleAccordion(this)">
                        <span>📝 Signed Message Content</span>
                        <span class="accordion-arrow">▸</span>
                    </button>
                    <div class="accordion-content">
                        <div class="accordion-inner">
                            <pre style="white-space:pre-wrap;word-break:break-word;color:var(--text-secondary);font-size:13px;margin:0">${escapeHtml(sig.message)}</pre>
                        </div>
                    </div>
                </div>
                <div class="accordion">
                    <button class="accordion-toggle" onclick="toggleAccordion(this)">
                        <span>🔗 SHA-256 Hash</span>
                        <span class="accordion-arrow">▸</span>
                    </button>
                    <div class="accordion-content">
                        <div class="accordion-inner">
                            <code style="color:var(--accent-cyan);font-family:'JetBrains Mono',monospace;font-size:12px;word-break:break-all">${sig.message_hash}</code>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    inspectContainer.classList.add('visible');
    showToast('Signature details loaded.', 'info');
}

// ── Verify Signature (Animated Multi-Step) ───────────────────
async function verifySignature(e) {
    if (e && e.preventDefault) e.preventDefault();
    const sessionEl = document.getElementById('verify-session');
    const verifierEl = document.getElementById('verify-verifier');
    const btn = document.getElementById('btn-verify');
    const stepsContainer = document.getElementById('verify-steps');
    const resultContainer = document.getElementById('verify-result');

    const session_id = sessionEl.value.trim();
    const verifier = verifierEl.value.trim();

    if (!session_id) {
        showToast('Please enter a Session ID.', 'error');
        sessionEl.focus();
        return;
    }
    if (!verifier) {
        showToast('Please enter a verifier name.', 'error');
        verifierEl.focus();
        return;
    }

    // Clear previous results
    resultContainer.innerHTML = '';
    resultContainer.classList.remove('visible');

    // Show the verification timeline skeleton with "pending" steps
    const allCheckNames = [
        { name: 'session_exists', label: 'Session Lookup', icon: '🔍' },
        { name: 'authorization', label: 'Authorization Check', icon: '🔐' },
        { name: 'replay', label: 'Replay Detection', icon: '🔄' },
        { name: 'channel_integrity', label: 'Channel Integrity', icon: '📡' },
        { name: 'hash_integrity', label: 'Hash Integrity', icon: '🔗' },
    ];

    stepsContainer.innerHTML = `
        <div class="verification-timeline">
            <div class="timeline-header">
                <h3>🛡 Verification Protocol</h3>
                <span class="timeline-status running">Running checks...</span>
            </div>
            <div class="timeline-steps">
                ${allCheckNames.map((c, i) => `
                    <div class="timeline-step pending" id="vstep-${c.name}" data-index="${i}">
                        <div class="step-connector"></div>
                        <div class="step-icon-wrap">
                            <div class="step-icon pending">${c.icon}</div>
                        </div>
                        <div class="step-content">
                            <div class="step-label">${c.label}</div>
                            <div class="step-desc">Waiting...</div>
                        </div>
                        <div class="step-badge pending">PENDING</div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
    stepsContainer.classList.add('visible');

    // Run the actual verification
    setButtonLoading(btn, true);
    const data = await apiPost('/api/verify', { session_id, verifier });
    setButtonLoading(btn, false);

    if (!data) {
        stepsContainer.querySelector('.timeline-status').textContent = 'Error';
        stepsContainer.querySelector('.timeline-status').className = 'timeline-status error';
        return;
    }

    // Animate each check step-by-step
    const checks = data.checks || [];
    await animateVerificationSteps(checks, allCheckNames, data);

    // Show final result
    const isAccept = data.decision === 'ACCEPT';
    const statusClass = isAccept ? 'accept' : 'reject';
    const statusIcon = isAccept ? '✅' : '🚫';
    const threatLevel = getThreatLevel(data.threat_score);

    // Update timeline header
    const timelineStatus = stepsContainer.querySelector('.timeline-status');
    timelineStatus.textContent = isAccept ? 'All Checks Passed' : `Blocked: ${data.category}`;
    timelineStatus.className = `timeline-status ${isAccept ? 'success' : 'error'}`;

    resultContainer.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <span class="result-status ${statusClass}">${statusIcon} ${data.decision}</span>
                <span class="result-status ${statusClass}">${data.category}</span>
            </div>
            <div class="result-body">
                <div class="result-grid">
                    <div class="result-field">
                        <div class="field-label">Decision</div>
                        <div class="field-value large" style="color:var(--accent-${isAccept ? 'emerald' : 'rose'})">${data.decision}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Category</div>
                        <div class="field-value">${data.category}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Threat Score</div>
                        <div class="field-value large" style="color:var(--accent-${threatLevel.color})">${data.threat_score}%</div>
                    </div>
                    ${data.measurement_match !== undefined ? `
                    <div class="result-field">
                        <div class="field-label">Measurement Match</div>
                        <div class="field-value large">${data.measurement_match}%</div>
                    </div>` : ''}
                </div>
                <div class="threat-gauge">
                    <div class="threat-bar-bg">
                        <div class="threat-bar-fill ${threatLevel.level}" style="width:${data.threat_score}%"></div>
                    </div>
                    <span class="threat-score-label ${threatLevel.level}">${data.threat_score}%</span>
                </div>
                <div class="result-reason">${data.reason}</div>
            </div>
        </div>
    `;
    resultContainer.classList.add('visible');
    showToast(`Verification: ${data.decision}`, isAccept ? 'success' : 'error');
}

// ── Animate Verification Steps ───────────────────────────────
async function animateVerificationSteps(checks, allCheckNames, data) {
    for (let i = 0; i < allCheckNames.length; i++) {
        const checkDef = allCheckNames[i];
        const stepEl = document.getElementById(`vstep-${checkDef.name}`);
        if (!stepEl) continue;

        // Find matching check from results
        const check = checks.find(c => c.name === checkDef.name);

        // Mark as running
        stepEl.className = 'timeline-step running';
        stepEl.querySelector('.step-icon').className = 'step-icon running';
        stepEl.querySelector('.step-badge').className = 'step-badge running';
        stepEl.querySelector('.step-badge').textContent = 'CHECKING...';
        stepEl.querySelector('.step-desc').textContent = 'Analyzing...';

        // Animate delay for visual effect
        await sleep(400 + Math.random() * 300);

        if (check) {
            const isPassed = check.status === 'pass';
            stepEl.className = `timeline-step ${isPassed ? 'passed' : 'failed'}`;
            stepEl.querySelector('.step-icon').className = `step-icon ${isPassed ? 'passed' : 'failed'}`;
            stepEl.querySelector('.step-badge').className = `step-badge ${isPassed ? 'passed' : 'failed'}`;
            stepEl.querySelector('.step-badge').textContent = isPassed ? 'PASS' : 'FAIL';
            stepEl.querySelector('.step-desc').textContent = check.description;
        } else {
            // This check was skipped (earlier check failed)
            stepEl.className = 'timeline-step skipped';
            stepEl.querySelector('.step-icon').className = 'step-icon skipped';
            stepEl.querySelector('.step-badge').className = 'step-badge skipped';
            stepEl.querySelector('.step-badge').textContent = 'SKIPPED';
            stepEl.querySelector('.step-desc').textContent = 'Previous check failed — this check was not executed.';
        }

        // If this check failed, mark remaining as skipped (don't animate them)
        if (check && check.status === 'fail') {
            await sleep(200);
            for (let j = i + 1; j < allCheckNames.length; j++) {
                const skipEl = document.getElementById(`vstep-${allCheckNames[j].name}`);
                if (skipEl) {
                    skipEl.className = 'timeline-step skipped';
                    skipEl.querySelector('.step-icon').className = 'step-icon skipped';
                    skipEl.querySelector('.step-badge').className = 'step-badge skipped';
                    skipEl.querySelector('.step-badge').textContent = 'SKIPPED';
                    skipEl.querySelector('.step-desc').textContent = 'Previous check failed — this check was not executed.';
                }
            }
            break;
        }
    }
}

// ── Rehash — Iterative Hash Chain ────────────────────────────
async function computeRehash(e) {
    if (e && e.preventDefault) e.preventDefault();
    const textEl = document.getElementById('rehash-text');
    const roundsEl = document.getElementById('rehash-rounds');
    const btn = document.getElementById('btn-rehash');
    const resultContainer = document.getElementById('rehash-result');

    const text = textEl.value.trim();
    const rounds = parseInt(roundsEl.value, 10);

    if (!text) {
        showToast('Please enter text to hash.', 'error');
        textEl.focus();
        return;
    }

    setButtonLoading(btn, true);
    const data = await apiPost('/api/rehash', { text, rounds });
    setButtonLoading(btn, false);

    if (!data) return;

    if (!data.ok) {
        showToast(data.error || 'Rehash failed.', 'error');
        return;
    }

    const chain = data.chain || [];

    // Build the animated hash chain visualization
    let chainHtml = `
        <div class="hash-chain">
            <div class="hash-chain-header">
                <h3>🔗 SHA-256 Hash Chain — ${data.rounds} Round${data.rounds > 1 ? 's' : ''}</h3>
                <span class="timeline-status success">Complete</span>
            </div>

            <!-- Original Input -->
            <div class="chain-node chain-origin">
                <div class="chain-node-badge">📝 ORIGINAL</div>
                <div class="chain-node-content">
                    <div class="chain-label">Input Text</div>
                    <div class="chain-value-text">${escapeHtml(data.original_text)}</div>
                </div>
            </div>
    `;

    chain.forEach((step, i) => {
        chainHtml += `
            <div class="chain-arrow">
                <div class="chain-arrow-line"></div>
                <div class="chain-arrow-label">SHA-256 Round ${step.round}</div>
                <div class="chain-arrow-line"></div>
            </div>
            <div class="chain-node chain-hash" style="animation-delay: ${i * 0.15}s">
                <div class="chain-node-badge chain-round-badge">Round ${step.round}</div>
                <div class="chain-node-content">
                    <div class="chain-label">${i === 0 ? 'Hash of original text' : `Hash of Round ${step.round - 1} output`}</div>
                    <code class="chain-hash-value">${step.output}</code>
                </div>
                ${i < chain.length - 1 ? `
                    <div class="chain-input-hint">
                        <span class="chain-hint-icon">↓</span> This hash becomes the input for the next round
                    </div>
                ` : ''}
            </div>
        `;
    });

    // Final result box
    chainHtml += `
            <div class="chain-final">
                <div class="chain-final-label">🏁 Final Hash (after ${data.rounds} round${data.rounds > 1 ? 's' : ''})</div>
                <code class="chain-final-hash">${data.final_hash}</code>
                <button class="copy-btn copy-btn-spaced" onclick="copyToClipboard('${data.final_hash}', this)">📋 Copy Final Hash</button>
            </div>

            <div class="chain-explanation">
                <strong>💡 Why does rehashing matter?</strong>
                <p>Each round of SHA-256 produces a completely different 256-bit output. Even though Round 1 and Round ${data.rounds} both use SHA-256, their outputs are entirely unrelated. This property (called the <em>avalanche effect</em>) means that reversing the chain requires breaking each hash independently — making the computational cost grow exponentially with each round.</p>
                <p class="chain-explanation-extra">In quantum threat detection, rehashing strengthens the cryptographic binding between the message and its signature, adding defense-in-depth against brute-force and preimage attacks.</p>
            </div>
        </div>
    `;

    resultContainer.innerHTML = chainHtml;
    resultContainer.classList.add('visible');
    showToast(`Hash chain computed! ${data.rounds} round${data.rounds > 1 ? 's' : ''} of SHA-256.`, 'success');
}

function copyToClipboard(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
        btn.classList.add('copied');
        btn.textContent = '✅ Copied!';
        showToast('Hash copied to clipboard!', 'success');
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.textContent = '📋 Copy Final Hash';
        }, 2000);
    }).catch(() => {
        showToast('Failed to copy.', 'error');
    });
}

// ── Launch Attack ────────────────────────────────────────────
async function launchAttack(e) {
    if (e && e.preventDefault) e.preventDefault();
    const sessionEl = document.getElementById('attack-session');
    const attackerEl = document.getElementById('attack-attacker');
    const attackTypeEl = document.getElementById('attack-type');
    const btn = document.getElementById('btn-attack');
    const resultContainer = document.getElementById('attack-result');

    const session_id = sessionEl.value.trim();
    const attacker = attackerEl.value.trim();
    const attack_type = attackTypeEl.value;

    if (!session_id) {
        showToast('Please enter a Session ID. Generate a signature first!', 'error');
        sessionEl.focus();
        return;
    }

    setButtonLoading(btn, true);
    const data = await apiPost('/api/attack', { session_id, attack_type, attacker });
    setButtonLoading(btn, false);

    if (!data) return;

    if (!data.ok) {
        showToast(data.error || 'Attack simulation failed.', 'error');
        return;
    }

    const threatLevel = getThreatLevel(data.threat_score);
    const info = data.attack_info || {};

    resultContainer.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <span class="result-status reject">🚫 ${data.decision}</span>
                <span class="result-status reject">⚔️ ${data.category}</span>
            </div>
            <div class="result-body">
                <div class="result-grid">
                    <div class="result-field">
                        <div class="field-label">Attack Type</div>
                        <div class="field-value">${data.category}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Attacker</div>
                        <div class="field-value">${data.attacker}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Decision</div>
                        <div class="field-value large" style="color:var(--accent-rose)">${data.decision}</div>
                    </div>
                    <div class="result-field">
                        <div class="field-label">Threat Score</div>
                        <div class="field-value large" style="color:var(--accent-${threatLevel.color})">${data.threat_score}%</div>
                    </div>
                </div>
                <div class="threat-gauge">
                    <div class="threat-bar-bg">
                        <div class="threat-bar-fill ${threatLevel.level}" style="width:${data.threat_score}%"></div>
                    </div>
                    <span class="threat-score-label ${threatLevel.level}">${data.threat_score}%</span>
                </div>
                <div class="result-reason">
                    <strong>🛡 Detection Detail:</strong><br>
                    ${data.reason}
                </div>
            </div>
        </div>

        ${info.name ? renderAttackExplanation(info) : ''}
    `;
    resultContainer.classList.add('visible');
    showToast(`Attack detected & blocked! Score: ${data.threat_score}%`, 'info');
}

// ── Render Attack Explanation Panel ──────────────────────────
function renderAttackExplanation(info) {
    const severityColors = {
        'CRITICAL': 'rose',
        'HIGH': 'amber',
        'MEDIUM': 'blue',
        'LOW': 'emerald',
    };
    const sevColor = severityColors[info.severity] || 'blue';

    return `
        <div class="attack-explanation">
            <div class="explanation-header">
                <div>
                    <span style="font-size:24px;margin-right:8px">${info.icon}</span>
                    <span class="explanation-title">${info.name}</span>
                </div>
                <span class="severity-badge severity-${info.severity?.toLowerCase()}">${info.severity}</span>
            </div>

            <p class="explanation-desc">${info.description}</p>

            <!-- How It Works -->
            <div class="accordion">
                <button class="accordion-toggle" onclick="toggleAccordion(this)">
                    <span>⚙️ How This Attack Works</span>
                    <span class="accordion-arrow">▸</span>
                </button>
                <div class="accordion-content">
                    <div class="accordion-inner">
                        <ol class="attack-steps-list">
                            ${(info.how_it_works || []).map(step => `<li>${step}</li>`).join('')}
                        </ol>
                    </div>
                </div>
            </div>

            <!-- Real World Example -->
            ${info.real_world_example ? `
            <div class="accordion">
                <button class="accordion-toggle" onclick="toggleAccordion(this)">
                    <span>🌍 Real-World Example</span>
                    <span class="accordion-arrow">▸</span>
                </button>
                <div class="accordion-content">
                    <div class="accordion-inner">
                        <p style="color:var(--text-secondary);line-height:1.7;margin:0">${info.real_world_example}</p>
                    </div>
                </div>
            </div>` : ''}

            <!-- Countermeasures -->
            <div class="accordion">
                <button class="accordion-toggle" onclick="toggleAccordion(this)">
                    <span>🛡 Countermeasures</span>
                    <span class="accordion-arrow">▸</span>
                </button>
                <div class="accordion-content">
                    <div class="accordion-inner">
                        <ul class="countermeasure-list">
                            ${(info.countermeasures || []).map(cm => `<li>${cm}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Quantum Defense -->
            ${info.quantum_defense ? `
            <div class="accordion">
                <button class="accordion-toggle" onclick="toggleAccordion(this)">
                    <span>⚛ Quantum Defense Mechanism</span>
                    <span class="accordion-arrow">▸</span>
                </button>
                <div class="accordion-content">
                    <div class="accordion-inner">
                        <div class="quantum-defense-box">
                            <p style="margin:0;line-height:1.7">${info.quantum_defense}</p>
                        </div>
                    </div>
                </div>
            </div>` : ''}
        </div>
    `;
}

// ── Attack Knowledge Base ────────────────────────────────────
async function loadAttackKnowledge() {
    const grid = document.getElementById('attack-knowledge-grid');
    if (!grid) return;

    // Use cache if available
    if (attackKnowledgeCache) {
        renderAttackKnowledgeGrid(grid, attackKnowledgeCache);
        return;
    }

    grid.innerHTML = '<div class="empty-state"><div class="empty-icon">⏳</div><p>Loading attack knowledge base...</p></div>';

    const data = await apiGet('/api/attack-info');
    if (!data || !data.ok) {
        grid.innerHTML = '<div class="empty-state"><div class="empty-icon">⚠️</div><p>Failed to load attack knowledge base.</p></div>';
        return;
    }

    attackKnowledgeCache = data.attacks;
    renderAttackKnowledgeGrid(grid, data.attacks);
}

function renderAttackKnowledgeGrid(grid, attacks) {
    const attackOrder = ['forgery', 'impersonation', 'replay', 'unauthorized', 'channel'];
    const severityColors = {
        'CRITICAL': 'rose',
        'HIGH': 'amber',
        'MEDIUM': 'blue',
        'LOW': 'emerald',
    };

    grid.innerHTML = attackOrder.map(key => {
        const a = attacks[key];
        if (!a) return '';
        const sevColor = severityColors[a.severity] || 'blue';

        return `
            <div class="knowledge-card">
                <div class="knowledge-header">
                    <span class="knowledge-icon">${a.icon}</span>
                    <div>
                        <div class="knowledge-name">${a.name}</div>
                        <span class="severity-badge severity-${a.severity?.toLowerCase()}">${a.severity}</span>
                    </div>
                </div>
                <p class="knowledge-desc">${a.description}</p>

                <div class="accordion">
                    <button class="accordion-toggle" onclick="toggleAccordion(this)">
                        <span>⚙️ How It Works</span>
                        <span class="accordion-arrow">▸</span>
                    </button>
                    <div class="accordion-content">
                        <div class="accordion-inner">
                            <ol class="attack-steps-list">
                                ${a.how_it_works.map(step => `<li>${step}</li>`).join('')}
                            </ol>
                        </div>
                    </div>
                </div>

                <div class="accordion">
                    <button class="accordion-toggle" onclick="toggleAccordion(this)">
                        <span>🛡 Countermeasures</span>
                        <span class="accordion-arrow">▸</span>
                    </button>
                    <div class="accordion-content">
                        <div class="accordion-inner">
                            <ul class="countermeasure-list">
                                ${a.countermeasures.map(cm => `<li>${cm}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                </div>

                <div class="accordion">
                    <button class="accordion-toggle" onclick="toggleAccordion(this)">
                        <span>⚛ Quantum Defense</span>
                        <span class="accordion-arrow">▸</span>
                    </button>
                    <div class="accordion-content">
                        <div class="accordion-inner">
                            <div class="quantum-defense-box">
                                <p style="margin:0;line-height:1.7">${a.quantum_defense}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// ── Dashboard ────────────────────────────────────────────────
async function loadDashboard() {
    const data = await apiGet('/api/dashboard');
    if (!data || !data.metrics) return;

    // Render metrics
    const metricsEl = document.getElementById('dash-metrics');
    const metricConfigs = [
        { key: 'total_signatures', label: 'Total Signatures', color: 'cyan', icon: '🔐' },
        { key: 'attacks_detected', label: 'Attacks Detected', color: 'rose', icon: '⚔️' },
        { key: 'legitimate_verifications', label: 'Legit Verifications', color: 'emerald', icon: '✅' },
        { key: 'verification_accuracy', label: 'Accuracy', color: 'amber', icon: '🎯', suffix: '%' },
        { key: 'detection_rate', label: 'Detection Rate', color: 'purple', icon: '📡', suffix: '%' },
        { key: 'total_events', label: 'Total Events', color: 'blue', icon: '📊' },
    ];

    metricsEl.innerHTML = metricConfigs.map(cfg => `
        <div class="metric-card">
            <div class="metric-label">${cfg.icon} ${cfg.label}</div>
            <div class="metric-value ${cfg.color}">${data.metrics[cfg.key] ?? 0}${cfg.suffix || ''}</div>
        </div>
    `).join('');

    // Render events
    const eventsEl = document.getElementById('dash-events');
    if (!data.events || data.events.length === 0) {
        eventsEl.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📭</div>
                <p>No security events yet. Generate a signature and start testing!</p>
            </div>
        `;
        return;
    }

    eventsEl.innerHTML = data.events.map(e => {
        const isAccept = e.decision === 'ACCEPT';
        const scoreClass = e.threat_score > 50 ? 'high' : 'low';
        return `
            <div class="event-item">
                <div class="event-dot ${isAccept ? 'accept' : 'reject'}"></div>
                <div class="event-info">
                    <div class="event-category">${e.category} — ${e.decision}</div>
                    <div class="event-details">${e.details || 'No details'} • Actor: ${e.actor || 'unknown'}</div>
                </div>
                <div class="event-score ${scoreClass}">${e.threat_score}%</div>
            </div>
        `;
    }).join('');
}

function startDashboardRefresh() {
    stopDashboardRefresh();
    dashboardInterval = setInterval(loadDashboard, 10000);
}

function stopDashboardRefresh() {
    if (dashboardInterval) {
        clearInterval(dashboardInterval);
        dashboardInterval = null;
    }
}

// ── Accordion ────────────────────────────────────────────────
function toggleAccordion(btn) {
    const accordion = btn.closest('.accordion');
    const isOpen = accordion.classList.contains('open');

    // Close all sibling accordions in same parent (optional: remove for independent)
    // accordion.parentElement.querySelectorAll('.accordion.open').forEach(a => {
    //     if (a !== accordion) a.classList.remove('open');
    // });

    accordion.classList.toggle('open', !isOpen);
    const arrow = btn.querySelector('.accordion-arrow');
    if (arrow) {
        arrow.textContent = isOpen ? '▸' : '▾';
    }
}

// ── Helpers ──────────────────────────────────────────────────
function getThreatLevel(score) {
    if (score <= 30) return { level: 'low', color: 'emerald' };
    if (score <= 70) return { level: 'medium', color: 'amber' };
    return { level: 'high', color: 'rose' };
}

function setButtonLoading(btn, loading) {
    if (loading) {
        btn.classList.add('loading');
        btn.disabled = true;
    } else {
        btn.classList.remove('loading');
        btn.disabled = false;
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

function copySessionId(sessionId, btn) {
    navigator.clipboard.writeText(sessionId).then(() => {
        btn.classList.add('copied');
        btn.textContent = '✅ Copied!';
        showToast('Session ID copied to clipboard!', 'success');
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.textContent = '📋 Copy ID';
        }, 2000);
    }).catch(() => {
        // Fallback for older browsers
        const input = document.createElement('input');
        input.value = sessionId;
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        document.body.removeChild(input);
        showToast('Session ID copied!', 'success');
    });
}

// ── Toast System ─────────────────────────────────────────────
function showToast(message, type = 'info') {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const icons = { success: '✅', error: '❌', info: 'ℹ️' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ── Navigate to tab (from workflow steps / hero) ─────────────
function goToTab(tabName) {
    switchTab(tabName);
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ── Server Health Check ───────────────────────────────────────
async function checkServerStatus() {
    const dot = document.getElementById('server-status-dot');
    const text = document.getElementById('server-status-text');
    if (!dot || !text) return;

    try {
        const fullUrl = API_BASE ? `${API_BASE}/api/attack-info` : '/api/attack-info';
        const res = await fetch(fullUrl, { method: 'GET' });
        if (res.ok) {
            dot.className = 'status-dot connected';
            text.textContent = 'API Connected' + (API_BASE ? ' (127.0.0.1:5000)' : '');
            text.title = 'Connected to Quantum Detection Backend';
        } else {
            dot.className = 'status-dot disconnected';
            text.textContent = 'API Error (' + res.status + ')';
        }
    } catch (e) {
        dot.className = 'status-dot disconnected';
        text.textContent = 'API Offline (start app.py)';
        text.title = 'Could not connect to Flask server. Run: python app.py';
    }
}

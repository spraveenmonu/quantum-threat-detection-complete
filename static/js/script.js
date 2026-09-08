/* ═══════════════════════════════════════════════════════════
   Quantum Threat Detection — Frontend Controller
   ═══════════════════════════════════════════════════════════ */

// ── State ────────────────────────────────────────────────────
let currentSessionId = null;
let dashboardInterval = null;

// ── DOM Ready ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
});

// ── Tab System ───────────────────────────────────────────────
function initTabs() {
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });
}

function switchTab(tabName) {
    // Update nav tabs
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`.nav-tab[data-tab="${tabName}"]`).classList.add('active');

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

    // Auto-fill session ID in verify & attack tabs
    if ((tabName === 'verify' || tabName === 'attacks') && currentSessionId) {
        const sessionInput = panel.querySelector('[data-field="session_id"]');
        if (sessionInput && !sessionInput.value) {
            sessionInput.value = currentSessionId;
        }
    }
}

// ── API Helper ───────────────────────────────────────────────
async function apiPost(url, data) {
    try {
        const res = await fetch(url, {
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
        showToast('Network error. Is the server running?', 'error');
        return null;
    }
}

async function apiGet(url) {
    try {
        const res = await fetch(url);
        return await res.json();
    } catch (err) {
        showToast('Network error loading data.', 'error');
        return null;
    }
}

// ── Generate Signature ───────────────────────────────────────
async function generateSignature() {
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

    // Render beautiful result
    resultContainer.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <span class="result-status generated">⚡ ${sig.status}</span>
                <div>
                    <span class="session-id-display">${sig.session_id}</span>
                    <button class="copy-btn" onclick="copySessionId('${sig.session_id}', this)" style="margin-left:8px">📋 Copy ID</button>
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
    showToast(`Signature generated! Session: ${sig.session_id}`, 'success');
}

// ── Verify Signature ─────────────────────────────────────────
async function verifySignature() {
    const sessionEl = document.getElementById('verify-session');
    const verifierEl = document.getElementById('verify-verifier');
    const btn = document.getElementById('btn-verify');
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

    setButtonLoading(btn, true);
    const data = await apiPost('/api/verify', { session_id, verifier });
    setButtonLoading(btn, false);

    if (!data) return;

    const isAccept = data.decision === 'ACCEPT';
    const statusClass = isAccept ? 'accept' : 'reject';
    const statusIcon = isAccept ? '✅' : '🚫';
    const threatLevel = getThreatLevel(data.threat_score);

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

// ── Launch Attack ────────────────────────────────────────────
async function launchAttack() {
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
    `;
    resultContainer.classList.add('visible');
    showToast(`Attack detected & blocked! Score: ${data.threat_score}%`, 'info');
}

// ── Dashboard ────────────────────────────────────────────────
async function loadDashboard() {
    const data = await apiGet('/api/dashboard');
    if (!data) return;

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
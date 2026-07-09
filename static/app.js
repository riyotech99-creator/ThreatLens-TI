// --- Global State ---
let lastScanData = null;
let navigatedFromBulk = false;

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

// --- Toast Notification System ---
function showToast(message, type = 'info', duration = 3000) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = 'position:fixed;top:80px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;';
        document.body.appendChild(container);
    }
    const icons = { info: 'fa-circle-info', success: 'fa-circle-check', error: 'fa-circle-xmark', warning: 'fa-triangle-exclamation' };
    const colors = { info: '#0ea5e9', success: '#00ff66', error: '#ff3366', warning: '#ff9f1c' };
    const toast = document.createElement('div');
    toast.style.cssText = `display:flex;align-items:center;gap:10px;padding:12px 18px;border-radius:6px;font-size:0.82rem;font-weight:600;color:#e2e8f0;backdrop-filter:blur(12px);border:1px solid ${colors[type]}33;background:rgba(8,10,18,0.92);box-shadow:0 4px 20px rgba(0,0,0,0.4);animation:fadeIn 0.3s ease;min-width:200px;`;
    toast.innerHTML = `<i class="fa-solid ${icons[type]}" style="color:${colors[type]}"></i> ${message}`;
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; toast.style.transition = 'opacity 0.3s'; setTimeout(() => toast.remove(), 300); }, duration);
}

document.addEventListener('DOMContentLoaded', () => {
    setupClock();
    checkApiStatus();
    setupSearch();
    setupSamples();
    setupHistory();
    setupNewSearchBtn();
    setupBackToBulkBtn();
    setupErrorDismiss();
    setupKeyboardShortcuts();
    setupBulkSearch();
});

// --- Keyboard Shortcuts ---
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Ctrl+K or Cmd+K → focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const headerInput = document.getElementById('header-search-input');
            const mainInput = document.getElementById('search-input');
            if (headerInput && headerInput.offsetParent !== null) { headerInput.focus(); headerInput.select(); }
            else if (mainInput) { mainInput.focus(); mainInput.select(); }
        }
        // Escape → back to hero or bulk-results
        if (e.key === 'Escape') {
            const results = document.getElementById('results-dashboard');
            if (results && results.style.display === 'block' && navigatedFromBulk) {
                showView('bulk-results');
            } else {
                const hero = document.getElementById('search-hero');
                if (hero && hero.style.display === 'none') showView('hero');
            }
        }
    });
}

// --- CSV Export ---
function exportCSV() {
    if (!lastScanData) { showToast('No scan data to export', 'warning'); return; }
    fetch('/api/export/csv', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(lastScanData)
    }).then(r => {
        if (!r.ok) throw new Error('Export failed');
        return r.blob();
    }).then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `threatlens_${lastScanData.query}_${lastScanData.ioc_type}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('CSV exported successfully', 'success');
    }).catch(() => showToast('CSV export failed', 'error'));
}

// --- Live UTC Clock ---
function setupClock() {
    const el = document.getElementById('live-clock');
    if (!el) return;
    const update = () => {
        const now = new Date();
        el.innerHTML = `<i class="fa-regular fa-clock"></i> ${now.toISOString().replace('T',' ').substring(0,19)} UTC`;
    };
    update();
    setInterval(update, 1000);
}

// --- API Status Check ---
function checkApiStatus() {
    fetch('/api/status').then(r => r.json()).then(data => {
        setDot('dot-vt', data.virustotal);
        setDot('dot-abuse', data.abuseipdb);
        setDot('dot-ipinfo', data.ipinfo);
        setDot('dot-otx', data.otx);
        setDot('dot-emailrep', data.emailrep);
        setDot('dot-hunterio', data.hunterio);
        setDot('dot-urlscan', data.urlscan);
        setDot('dot-domain_checker', data.domain_checker);
    }).catch(() => {});
}

function setDot(id, active) {
    const el = document.getElementById(id);
    if (el) { el.className = `api-dot ${active ? 'active' : 'inactive'}`; }
}

// --- IOC Type Detection (client-side preview) ---
function detectType(q) {
    q = q.trim();
    if (/^https?:\/\//i.test(q) || q.includes('/')) return 'url';
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(q)) return 'ip';
    if (/^([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(q) || /^::/.test(q) || /::$/.test(q)) return 'ip';
    if (/^[a-fA-F0-9]{32}$/.test(q) || /^[a-fA-F0-9]{40}$/.test(q) || /^[a-fA-F0-9]{64}$/.test(q)) return 'hash';
    if (/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(q)) return 'email';
    if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(q)) return 'domain';
    return '';
}

// --- Search Setup ---
function setupSearch() {
    const form = document.getElementById('search-form');
    const input = document.getElementById('search-input');
    const badge = document.getElementById('ioc-type-badge');

    const headerForm = document.getElementById('header-search-form');
    const headerInput = document.getElementById('header-search-input');
    const headerBadge = document.getElementById('header-ioc-badge');

    const updateBadge = (inp, bdg) => {
        const t = detectType(inp.value);
        bdg.textContent = t ? t.toUpperCase() : 'TYPE';
        bdg.className = `ioc-type-badge header-ioc-badge ${t}`;
    };

    input.addEventListener('input', () => {
        const t = detectType(input.value);
        badge.textContent = t ? t.toUpperCase() : 'TYPE';
        badge.className = `ioc-type-badge ${t}`;
    });

    if (headerInput && headerBadge) {
        headerInput.addEventListener('input', () => updateBadge(headerInput, headerBadge));
    }

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        const q = input.value.trim();
        if (!q) return;
        runLookup(q);
    });

    if (headerForm && headerInput) {
        headerForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const q = headerInput.value.trim();
            if (!q) return;
            runLookup(q);
        });
    }
}

function setupSamples() {
    document.querySelectorAll('.sample-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const q = btn.dataset.query;
            document.getElementById('search-input').value = q;
            const t = detectType(q);
            const badge = document.getElementById('ioc-type-badge');
            badge.textContent = t ? t.toUpperCase() : 'TYPE';
            badge.className = `ioc-type-badge ${t}`;
            runLookup(q);
        });
    });
}

function setupNewSearchBtn() {
    const btn = document.getElementById('btn-new-search');
    if (btn) btn.addEventListener('click', () => showView('hero'));
}

function setupBackToBulkBtn() {
    const btn = document.getElementById('btn-back-to-bulk');
    if (btn) btn.addEventListener('click', () => showView('bulk-results'));
}

function setupErrorDismiss() {
    const btn = document.getElementById('btn-dismiss-error');
    if (btn) btn.addEventListener('click', () => showView('hero'));
}

// --- View State Management ---
function showView(view) {
    const hero = document.getElementById('search-hero');
    const loading = document.getElementById('loading-state');
    const error = document.getElementById('error-state');
    const results = document.getElementById('results-dashboard');
    const bulkResults = document.getElementById('bulk-results-dashboard');
    const headerSearch = document.getElementById('header-search-container');
    
    [hero, loading, error, results, bulkResults].forEach(el => { if(el) el.style.display = 'none'; });

    if (view === 'hero') {
        if (hero) hero.style.display = 'flex';
        if (headerSearch) headerSearch.style.display = 'none';
    }
    else if (view === 'loading') {
        if (loading) loading.style.display = 'flex';
    }
    else if (view === 'error') {
        if (error) error.style.display = 'block';
        if (headerSearch) headerSearch.style.display = 'none';
    }
    else if (view === 'results') {
        if (results) results.style.display = 'block';
        const btnBackToBulk = document.getElementById('btn-back-to-bulk');
        if (btnBackToBulk) {
            btnBackToBulk.style.display = navigatedFromBulk ? 'inline-flex' : 'none';
        }
        if (headerSearch) {
            headerSearch.style.display = 'block';
            const lastQuery = document.getElementById('search-input').value;
            const headerInput = document.getElementById('header-search-input');
            const headerBadge = document.getElementById('header-ioc-badge');
            if (headerInput && lastQuery) {
                headerInput.value = lastQuery;
                const t = detectType(lastQuery);
                if (headerBadge) {
                    headerBadge.textContent = t ? t.toUpperCase() : 'TYPE';
                    headerBadge.className = `ioc-type-badge header-ioc-badge ${t}`;
                }
            }
        }
    }
    else if (view === 'bulk-results') {
        if (bulkResults) bulkResults.style.display = 'block';
        if (headerSearch) headerSearch.style.display = 'none';
    }
}

// --- Main Lookup ---
async function runLookup(query, fromBulk = false) {
    navigatedFromBulk = fromBulk;
    // Sync main input
    const input = document.getElementById('search-input');
    if (input) input.value = query;

    showView('loading');
    const scanBtn = document.getElementById('btn-scan');
    const headerScanBtn = document.getElementById('btn-header-scan');
    if (scanBtn) scanBtn.disabled = true;
    if (headerScanBtn) headerScanBtn.disabled = true;

    try {
        const resp = await fetch('/api/lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        });

        const data = await resp.json();

        if (!resp.ok) {
            document.getElementById('error-message').textContent = data.error || 'Lookup failed.';
            showView('error');
            return;
        }

        lastScanData = data;
        if (data.from_cache) showToast('Results loaded from cache', 'info');
        saveHistory(query, data.ioc_type, data.unified_score, data.threat_level);
        renderResults(data);
        showView('results');
    } catch (err) {
        document.getElementById('error-message').textContent = `Network error: ${err.message}`;
        showView('error');
    } finally {
        if (scanBtn) scanBtn.disabled = false;
        if (headerScanBtn) headerScanBtn.disabled = false;
    }
}

// --- Render Results ---
function renderResults(data) {
    // Header
    const typeBadge = document.getElementById('result-type-badge');
    typeBadge.textContent = data.ioc_type.toUpperCase();
    typeBadge.className = `result-type-badge ${data.ioc_type}`;
    document.getElementById('result-query-display').textContent = data.query;
    document.getElementById('result-timestamp').textContent = `Scanned at: ${data.timestamp}`;

    // Unified Score Gauge
    renderGauge(data.unified_score, data.threat_level);

    // Score description
    const desc = document.getElementById('score-description');
    if (data.unified_score >= 75) desc.textContent = 'High-confidence malicious indicator detected across multiple intelligence feeds.';
    else if (data.unified_score >= 50) desc.textContent = 'Suspicious activity reported. Manual review recommended.';
    else if (data.unified_score >= 25) desc.textContent = 'Low-level indicators found. Monitor for further activity.';
    else if (data.unified_score > 0) desc.textContent = 'Minor signals detected. Likely benign but noted in some feeds.';
    else desc.textContent = 'No threat indicators found across configured intelligence sources.';

    // Source score pills
    const pillsEl = document.getElementById('source-score-pills');
    pillsEl.innerHTML = '';
    const sourceMap = { virustotal: 'vt', abuseipdb: 'abuse', ipinfo: 'ipinfo', otx: 'otx', emailrep: 'emailrep', hunterio: 'hunterio', urlscan: 'urlscan', domain_checker: 'domain_checker', dns_history: 'dns_history' };
    const nameMap = { virustotal: 'VirusTotal', abuseipdb: 'AbuseIPDB', ipinfo: 'IPInfo', otx: 'OTX', emailrep: 'EmailRep', hunterio: 'Hunter.io', urlscan: 'URLScan', domain_checker: 'Domain Checker', dns_history: 'DNS History' };
    data.results.forEach(r => {
        const cls = sourceMap[r.source] || '';
        const name = nameMap[r.source] || r.source;
        let scoreText = '—';
        if (r.success && r.data && !r.data.not_applicable && r.data.found !== false) {
            scoreText = `${r.data.score ?? 0}%`;
        } else if (r.success && r.data && r.data.not_applicable) {
            scoreText = 'N/A';
        } else if (!r.success && r.error?.includes('No API key')) {
            scoreText = 'No Key';
        } else if (!r.success) {
            scoreText = 'Error';
        }
        pillsEl.innerHTML += `<span class="score-pill ${cls}">${name}: ${scoreText}</span>`;
    });

    // Render each source card
    data.results.forEach(r => renderSourceCard(r));

    // Containment scripts
    renderContainment(data.containment);
}

function renderGauge(score, level) {
    const gauge = document.getElementById('score-gauge');
    const numEl = document.getElementById('score-number');
    const levelEl = document.getElementById('score-level');
    const targetDeg = (score / 100) * 360;

    let color = 'var(--neon-green)';
    if (score >= 75) color = 'var(--neon-red)';
    else if (score >= 50) color = 'var(--neon-orange)';
    else if (score >= 25) color = '#fbbf24';

    // Animated count-up
    const duration = 1200;
    const startTime = performance.now();
    const animate = (now) => {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        const currentScore = Math.round(score * eased);
        const currentDeg = targetDeg * eased;

        gauge.style.background = `conic-gradient(${color} 0deg ${currentDeg}deg, rgba(255,255,255,0.04) ${currentDeg}deg 360deg)`;
        numEl.textContent = currentScore;

        if (progress < 1) requestAnimationFrame(animate);
    };
    requestAnimationFrame(animate);

    numEl.style.color = color.startsWith('var') ? color.replace('var(','').replace(')','') : color;
    levelEl.textContent = level;

    if (score >= 75) { levelEl.style.color = 'var(--neon-red)'; levelEl.style.textShadow = '0 0 10px rgba(255,51,102,0.4)'; }
    else if (score >= 50) { levelEl.style.color = 'var(--neon-orange)'; levelEl.style.textShadow = '0 0 10px rgba(255,159,28,0.3)'; }
    else if (score >= 25) { levelEl.style.color = '#fbbf24'; levelEl.style.textShadow = 'none'; }
    else { levelEl.style.color = 'var(--neon-green)'; levelEl.style.textShadow = '0 0 10px rgba(0,255,102,0.3)'; }
}

function renderSourceCard(r) {
    const bodyMap = { virustotal: 'vt-body', abuseipdb: 'abuse-body', ipinfo: 'ipinfo-body', otx: 'otx-body', emailrep: 'emailrep-body', hunterio: 'hunterio-body', urlscan: 'urlscan-body', domain_checker: 'domain_checker-body', dns_history: 'dns_history-body' };
    const statusMap = { virustotal: 'vt-status', abuseipdb: 'abuse-status', ipinfo: 'ipinfo-status', otx: 'otx-status', emailrep: 'emailrep-status', hunterio: 'hunterio-status', urlscan: 'urlscan-status', domain_checker: 'domain_checker-status', dns_history: 'dns_history-status' };
    const bodyEl = document.getElementById(bodyMap[r.source]);
    const statusEl = document.getElementById(statusMap[r.source]);
    if (!bodyEl || !statusEl) return;

    // Status badge
    if (!r.success) {
        const isNoKey = r.error?.includes('No API key');
        statusEl.textContent = isNoKey ? 'NO KEY' : 'ERROR';
        statusEl.className = `source-status ${isNoKey ? 'nokey' : 'error'}`;
        bodyEl.innerHTML = `<p class="no-data-message">${r.error || 'Unknown error'}</p>`;
        return;
    }
    if (r.data?.not_applicable) {
        statusEl.textContent = 'N/A';
        statusEl.className = 'source-status na';
        bodyEl.innerHTML = `<p class="no-data-message">${r.data.message}</p>`;
        return;
    }
    if (r.data?.found === false) {
        statusEl.textContent = 'NOT FOUND';
        statusEl.className = 'source-status na';
        bodyEl.innerHTML = `<p class="no-data-message">${r.data.message || 'IOC not found in this database.'}</p>`;
        return;
    }

    statusEl.textContent = 'OK';
    statusEl.className = 'source-status success';
    const d = r.data;

    if (r.source === 'virustotal') {
        const mal = d.malicious || 0, sus = d.suspicious || 0, total = d.total_engines || 0;
        const detected = mal + sus;
        const pct = total > 0 ? ((detected / total) * 100) : 0;
        let barClass = 'safe'; if (pct >= 50) barClass = 'danger'; else if (pct >= 15) barClass = 'medium';
        let html = `<div class="detail-grid">`;
        html += row('Detection Ratio', `<span class="${pct>=50?'red':pct>=15?'':'green'}">${detected} / ${total} engines</span>`);
        html += `<div class="d-row"><span class="d-key">Detection Bar</span><span class="d-value" style="flex:1;margin-left:10px;">
            <div class="detection-bar-bg"><div class="detection-bar-fill ${barClass}" style="width:${pct}%"></div></div></span></div>`;
        html += row('Malicious', `<span class="red">${mal}</span>`);
        html += row('Suspicious', `${sus}`);
        html += row('Reputation', `${d.reputation ?? 'N/A'}`);
        if (d.as_owner) html += row('AS Owner', d.as_owner);
        if (d.country) html += row('Country', d.country);
        if (d.file_name) html += row('File Name', `<span class="mono">${d.file_name}</span>`);
        if (d.file_type) html += row('File Type', d.file_type);
        if (d.registrar) html += row('Registrar', d.registrar);
        if (d.categories && Object.keys(d.categories).length > 0) {
            const catVals = Object.values(d.categories);
            html += `<div class="d-row"><span class="d-key">Categories</span><span class="d-value">${catVals.slice(0,3).join(', ')}</span></div>`;
        }
        if (d.tags && d.tags.length > 0) {
            html += `<div class="d-row"><span class="d-key">Tags</span><span class="d-value"><div class="tag-list">${d.tags.slice(0,6).map(t=>`<span class="mini-tag">${t}</span>`).join('')}</div></span></div>`;
        }
        html += `</div>`;
        bodyEl.innerHTML = html;
    }
    else if (r.source === 'abuseipdb') {
        let html = `<div class="detail-grid">`;
        const score = d.abuse_confidence_score || 0;
        html += row('Abuse Confidence', `<span class="${score>=75?'red':score>=30?'':'green'}">${score}%</span>`);
        html += row('Total Reports', `<span class="${d.total_reports>100?'red':''}">${d.total_reports}</span>`);
        html += row('Distinct Reporters', `${d.num_distinct_users}`);
        html += row('ISP', d.isp || '—');
        html += row('Usage Type', d.usage_type || '—');
        html += row('Country', d.country_code || '—');
        html += row('Is Tor', `<span class="${d.is_tor?'red':'green'}">${d.is_tor ? 'Yes' : 'No'}</span>`);
        if (d.is_whitelisted !== undefined) html += row('Whitelisted', `<span class="${d.is_whitelisted?'green':''}">${d.is_whitelisted ? 'Yes' : 'No'}</span>`);
        if (d.last_reported_at) html += row('Last Reported', d.last_reported_at.substring(0,19));
        
        if (d.tags && d.tags.length > 0) {
            html += `<div class="d-row"><span class="d-key">Community Tags</span><span class="d-value"><div class="tag-list">${d.tags.map(t=>`<span class="mini-tag">${t}</span>`).join('')}</div></span></div>`;
        }
        
        if (d.comments && d.comments.length > 0) {
            html += `</div><div class="abuse-comments-section">`;
            html += `<div class="comments-header-container">`;
            html += `<p class="comments-header"><i class="fa-solid fa-comments"></i> Recent Community Reports</p>`;
            if (d.comments.length > 1) {
                html += `<button class="btn-see-all-comments" data-expanded="false">See all (${d.comments.length})</button>`;
            }
            html += `</div><ul class="abuse-comments-list">`;
            d.comments.forEach((c, idx) => {
                const truncated = c.length > 150 ? c.substring(0, 147) + '...' : c;
                const style = idx === 0 ? '' : 'style="display:none;"';
                const cls = idx === 0 ? 'abuse-comment-item' : 'abuse-comment-item more-comment';
                html += `<li class="${cls}" ${style}>${escapeHtml(truncated)}</li>`;
            });
            html += `</ul></div>`;
        } else {
            html += `</div>`;
        }
        bodyEl.innerHTML = html;

        // Set up the click handler for the toggle button
        const btnToggle = bodyEl.querySelector('.btn-see-all-comments');
        if (btnToggle) {
            btnToggle.addEventListener('click', () => {
                const moreComments = bodyEl.querySelectorAll('.more-comment');
                const isExpanded = btnToggle.getAttribute('data-expanded') === 'true';
                if (isExpanded) {
                    moreComments.forEach(item => item.style.display = 'none');
                    btnToggle.textContent = `See all (${d.comments.length})`;
                    btnToggle.setAttribute('data-expanded', 'false');
                } else {
                    moreComments.forEach(item => item.style.display = 'block');
                    btnToggle.textContent = 'Show less';
                    btnToggle.setAttribute('data-expanded', 'true');
                }
            });
        }
    }
    else if (r.source === 'ipinfo') {
        let html = `<div class="detail-grid">`;
        html += row('Organization', `<span class="cyan">${d.org || '—'}</span>`);
        html += row('Hostname', `<span class="mono">${d.hostname || '—'}</span>`);
        html += row('Location', `${d.city || '—'}, ${d.region || '—'}`);
        html += row('Country', d.country || '—');
        html += row('Coordinates', `<span class="mono">${d.loc || '—'}</span>`);
        html += row('Timezone', d.timezone || '—');
        
        let bogonStatus = d.is_bogon ? `<span class="red">Yes (Internal IP) ⚠</span>` : 'No';
        let anycastStatus = d.anycast ? `<span class="cyan">Yes</span>` : 'No';
        html += row('Bogon Status', bogonStatus);
        html += row('Anycast routing', anycastStatus);

        if (d.privacy) {
            let flags = [];
            if (d.privacy.vpn) flags.push('<span class="flag-tag">VPN ⚠</span>');
            if (d.privacy.proxy) flags.push('<span class="flag-tag">Proxy ⚠</span>');
            if (d.privacy.tor) flags.push('<span class="flag-tag">Tor Exit ⚠</span>');
            if (d.privacy.relay) flags.push('<span class="flag-tag">Relay ⚠</span>');
            if (d.privacy.hosting) flags.push('<span class="flag-tag">Hosting</span>');
            
            if (flags.length > 0) {
                html += `<div class="d-row"><span class="d-key">Privacy Flags</span><span class="d-value"><div class="flag-list">${flags.join('')}</div></span></div>`;
                if (d.privacy.service) {
                    html += row('VPN Provider', `<span class="cyan">${d.privacy.service}</span>`);
                }
            } else {
                html += row('Privacy Status', `<span class="green">Direct Connection ✓</span>`);
            }
        }
        html += `</div>`;
        bodyEl.innerHTML = html;
    }
    else if (r.source === 'otx') {
        let html = `<div class="detail-grid">`;
        const pc = d.pulse_count || 0;
        html += row('Pulse Count', `<span class="${pc>10?'red':pc>0?'':'green'}">${pc} pulses</span>`);
        if (d.country) html += row('Country', d.country);
        if (d.asn) html += row('ASN', d.asn);
        if (d.malware_families && d.malware_families.length > 0) {
            html += `<div class="d-row"><span class="d-key">Malware Families</span><span class="d-value"><div class="tag-list">${d.malware_families.map(m=>`<span class="mini-tag">${m}</span>`).join('')}</div></span></div>`;
        }
        if (d.tags && d.tags.length > 0) {
            html += `<div class="d-row"><span class="d-key">Tags</span><span class="d-value"><div class="tag-list">${d.tags.slice(0,8).map(t=>`<span class="mini-tag">${t}</span>`).join('')}</div></span></div>`;
        }
        html += `</div>`;
        bodyEl.innerHTML = html;
    }
    else if (r.source === 'emailrep') {
        const d = r.data;
        const boolIcon = (val) => val ? '<span class="red">Yes ⚠</span>' : '<span class="green">No ✓</span>';
        let html = `<div class="detail-grid">`;
        html += row('Reputation', `<span class="${d.reputation==='high'?'green':d.reputation==='low'||d.reputation==='none'?'red':''}">${(d.reputation||'unknown').toUpperCase()}</span>`);
        html += row('Suspicious', boolIcon(d.suspicious));
        html += row('Blacklisted', boolIcon(d.blacklisted));
        html += row('Malicious Activity', boolIcon(d.malicious_activity));
        html += row('Credentials Leaked', boolIcon(d.credential_leaked));
        html += row('Data Breach', boolIcon(d.data_breach));
        html += row('Spam', boolIcon(d.spam));
        html += row('Disposable', boolIcon(d.disposable));
        html += row('Valid MX', `${d.valid_mx ? 'Yes' : 'No'}`);
        html += row('SPF Strict', `${d.spf_strict ? 'Yes' : 'No'}`);
        html += row('DMARC Enforced', `${d.dmarc_enforced ? 'Yes' : 'No'}`);
        html += row('Domain Rep.', `${(d.domain_reputation||'unknown').toUpperCase()}`);
        if (d.profiles && d.profiles.length > 0) {
            html += `<div class="d-row"><span class="d-key">Profiles</span><span class="d-value"><div class="profile-list">${d.profiles.map(p=>`<span class="profile-tag">${p}</span>`).join('')}</div></span></div>`;
        }
        html += row('Last Seen', d.last_seen || 'Never');
        html += `</div>`;
        bodyEl.innerHTML = html;
    }
    else if (r.source === 'hunterio') {
        const d = r.data;
        let html = `<div class="detail-grid">`;
        html += row('Result', `<span class="${d.result==='deliverable'?'green':d.result==='undeliverable'?'red':''}">${(d.result||'unknown').toUpperCase()}</span>`);
        html += row('Hunter Score', `${d.hunter_score}%`);
        html += row('Status', (d.status||'unknown').toUpperCase());
        html += row('Disposable', `<span class="${d.disposable?'red':'green'}">${d.disposable?'Yes ⚠':'No'}</span>`);
        html += row('Webmail', d.webmail ? 'Yes' : 'No');
        html += row('MX Records', d.mx_records ? 'Valid' : 'None');
        html += row('SMTP Server', d.smtp_server ? 'Reachable' : 'Not Found');
        html += row('SMTP Check', d.smtp_check ? 'Pass' : 'Fail');
        html += row('Accept All', d.accept_all ? 'Yes' : 'No');
        html += row('Blocked', `<span class="${d.block?'red':''}">${d.block?'Yes ⚠':'No'}</span>`);
        html += `</div>`;
        bodyEl.innerHTML = html;
    }
    else if (r.source === 'urlscan') {
        const d = r.data;
        let html = `<div class="detail-grid">`;
        html += row('Malicious', `<span class="${d.malicious?'red':'green'}">${d.malicious?'Yes ⚠':'No ✓'}</span>`);
        html += row('Scan Score', `${d.score}/100`);
        html += row('Page Title', d.page_title || '—');
        html += row('Page IP', `<span class="mono">${d.page_ip || '—'}</span>`);
        html += row('Server', d.server || '—');
        html += row('ASN', `<span class="mono">${d.asn || '—'}</span> (${d.asn_name || '—'})`);
        html += row('Country', d.page_country || '—');
        html += row('Requests Count', d.requests_count || '0');
        html += row('Unique IPs', d.unique_ips || '0');
        html += row('Unique Countries', d.unique_countries || '0');
        html += row('Scan Time', d.scan_time || '—');
        html += `</div>`;

        if (d.screenshot_url) {
            html += `<div class="urlscan-preview">`;
            html += `<a href="${d.result_url}" target="_blank" title="View Full Report on URLScan.io">`;
            html += `<img src="${d.screenshot_url}" class="urlscan-img" alt="URLScan.io Screenshot" onerror="this.style.display='none'">`;
            html += `</a>`;
            html += `</div>`;
        }
        if (d.result_url) {
            html += `<a href="${d.result_url}" target="_blank" class="urlscan-link-btn"><i class="fa-solid fa-arrow-up-right-from-square"></i> Open Full URLScan Report</a>`;
        }
        bodyEl.innerHTML = html;
    }
    else if (r.source === 'domain_checker') {
        const d = r.data;
        let html = `<div class="detail-grid">`;
        html += row('Registrar', d.registrar || '—');
        html += row('Creation Date', d.creation_date ? d.creation_date.substring(0,19).replace('T',' ') : '—');
        html += row('Expiration Date', d.expiration_date ? d.expiration_date.substring(0,19).replace('T',' ') : '—');
        html += row('Last Changed', d.last_changed ? d.last_changed.substring(0,19).replace('T',' ') : '—');

        if (d.age_days !== null) {
            const ageYears = (d.age_days / 365).toFixed(1);
            let ageClass = 'green';
            if (d.age_days < 30) ageClass = 'red';
            else if (d.age_days < 180) ageClass = 'orange';

            html += row('Domain Age', `<span class="${ageClass}">${d.age_days} days (~${ageYears} years)</span>`);
        }

        if (d.nameservers && d.nameservers.length > 0) {
            html += `<div class="d-row"><span class="d-key">Name Servers</span><span class="d-value mono">${d.nameservers.join('<br>')}</span></div>`;
        }

        if (d.risk_flags && d.risk_flags.length > 0) {
            html += `<div class="d-row"><span class="d-key">Risk Flags</span><span class="d-value"><div class="flag-list">${d.risk_flags.map(f=>`<span class="flag-tag">${f}</span>`).join('')}</div></span></div>`;
        }

        html += `</div>`;
        bodyEl.innerHTML = html;
    }
    else if (r.source === 'dns_history') {
        const d = r.data;
        let html = `
            <div class="dns-subtabs">
                <button type="button" class="dns-subtab active" id="dns-tab-active">Active DNS (${d.active ? d.active.length : 0})</button>
                <button type="button" class="dns-subtab" id="dns-tab-passive">Passive DNS (${d.passive ? d.passive.length : 0})</button>
            </div>
            
            <div class="dns-tab-content" id="dns-content-active">
        `;
        
        if (d.active && d.active.length > 0) {
            html += `
                <table class="dns-table">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            d.active.forEach(record => {
                html += `
                    <tr>
                        <td class="mono" style="color: var(--neon-cyan); font-weight:700;">${escapeHtml(record.type)}</td>
                        <td class="mono">${escapeHtml(record.value)}</td>
                    </tr>
                `;
            });
            html += `</tbody></table>`;
        } else {
            html += `<p class="no-data-message" style="padding: 10px 0;">No active DNS records found.</p>`;
        }
        
        html += `
            </div>
            <div class="dns-tab-content" id="dns-content-passive" style="display:none;">
        `;
        
        if (d.passive && d.passive.length > 0) {
            html += `
                <table class="dns-table">
                    <thead>
                        <tr>
                            <th>Resolved IP</th>
                            <th>Type</th>
                            <th>First Seen</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            d.passive.forEach(record => {
                html += `
                    <tr>
                        <td class="mono" style="color: var(--text-light);">${escapeHtml(record.answer)}</td>
                        <td class="mono" style="color: var(--text-muted);">${escapeHtml(record.rrtype)}</td>
                        <td style="font-size:0.7rem;">${escapeHtml(record.first_seen)}</td>
                        <td style="font-size:0.7rem;">${escapeHtml(record.last_seen)}</td>
                    </tr>
                `;
            });
            html += `</tbody></table>`;
        } else {
            html += `<p class="no-data-message" style="padding: 10px 0;">No passive DNS history found.</p>`;
        }
        
        html += `</div>`;
        bodyEl.innerHTML = html;
        
        // Add tab toggle events
        const tabActive = bodyEl.querySelector('#dns-tab-active');
        const tabPassive = bodyEl.querySelector('#dns-tab-passive');
        const contentActive = bodyEl.querySelector('#dns-content-active');
        const contentPassive = bodyEl.querySelector('#dns-content-passive');
        
        if (tabActive && tabPassive && contentActive && contentPassive) {
            tabActive.addEventListener('click', () => {
                tabActive.classList.add('active');
                tabPassive.classList.remove('active');
                contentActive.style.display = 'block';
                contentPassive.style.display = 'none';
            });
            tabPassive.addEventListener('click', () => {
                tabPassive.classList.add('active');
                tabActive.classList.remove('active');
                contentActive.style.display = 'none';
                contentPassive.style.display = 'block';
            });
        }
    }
}

function row(key, value) {
    return `<div class="d-row"><span class="d-key">${key}</span><span class="d-value">${value}</span></div>`;
}

// --- Containment Scripts ---
function renderContainment(scripts) {
    const tabsEl = document.getElementById('containment-tabs');
    const codeEl = document.getElementById('containment-code');
    const nameEl = document.getElementById('containment-tab-name');
    if (!tabsEl || !scripts) return;

    const keys = Object.keys(scripts);
    if (keys.length === 0) {
        document.getElementById('containment-section').style.display = 'none';
        return;
    }
    document.getElementById('containment-section').style.display = 'block';

    tabsEl.innerHTML = '';
    keys.forEach((key, i) => {
        const btn = document.createElement('button');
        btn.className = `c-tab ${i === 0 ? 'active' : ''}`;
        btn.textContent = key;
        btn.addEventListener('click', () => {
            tabsEl.querySelectorAll('.c-tab').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            codeEl.textContent = scripts[key];
            nameEl.textContent = key;
        });
        tabsEl.appendChild(btn);
    });

    codeEl.textContent = scripts[keys[0]];
    nameEl.textContent = keys[0];

    // Copy button
    const copyBtn = document.getElementById('btn-copy-script');
    copyBtn.onclick = () => {
        navigator.clipboard.writeText(codeEl.textContent).then(() => {
            copyBtn.innerHTML = '<i class="fa-solid fa-check"></i>';
            showToast('Script copied to clipboard', 'success');
            setTimeout(() => { copyBtn.innerHTML = '<i class="fa-regular fa-copy"></i>'; }, 1500);
        });
    };
}

// --- Search History (localStorage) ---
function setupHistory() {
    renderHistory();
    const clearBtn = document.getElementById('btn-clear-history');
    if (clearBtn) clearBtn.addEventListener('click', () => {
        localStorage.removeItem('tl_history');
        renderHistory();
    });
}

function saveHistory(query, type, score, level) {
    let history = JSON.parse(localStorage.getItem('tl_history') || '[]');
    // Remove duplicate
    history = history.filter(h => h.query !== query);
    history.unshift({ query, type, score: Math.round(score), level, time: new Date().toISOString().substring(0,16) });
    if (history.length > 20) history = history.slice(0, 20);
    localStorage.setItem('tl_history', JSON.stringify(history));
    renderHistory();
}

function renderHistory() {
    const listEl = document.getElementById('history-list');
    if (!listEl) return;
    const history = JSON.parse(localStorage.getItem('tl_history') || '[]');

    if (history.length === 0) {
        listEl.innerHTML = '<p class="empty-state">No searches yet.</p>';
        return;
    }

    listEl.innerHTML = '';
    history.forEach(h => {
        const item = document.createElement('div');
        item.className = 'history-item';
        item.innerHTML = `
            <span class="h-query" title="${h.query}">${h.query}</span>
            <div class="h-meta">
                <span class="h-type-badge">${h.type}</span>
                <span>Score: ${h.score} (${h.level})</span>
            </div>
        `;
        item.addEventListener('click', () => {
            document.getElementById('search-input').value = h.query;
            runLookup(h.query);
        });
        listEl.appendChild(item);
    });
}

// --- Bulk Search ---
function setupBulkSearch() {
    const tabSingle = document.getElementById('tab-single');
    const tabBulk = document.getElementById('tab-bulk');
    const singleForm = document.getElementById('search-form');
    const bulkForm = document.getElementById('bulk-search-form');
    const samplesWrapper = document.getElementById('quick-samples-wrapper');
    const bulkInput = document.getElementById('bulk-input');
    const bulkResultsBody = document.getElementById('bulk-results-body');
    const btnBulkNewSearch = document.getElementById('btn-bulk-new-search');

    if (!tabSingle || !tabBulk) return;

    // Tab Switching
    tabSingle.addEventListener('click', () => {
        tabSingle.classList.add('active');
        tabBulk.classList.remove('active');
        singleForm.style.display = 'flex';
        bulkForm.style.display = 'none';
        if (samplesWrapper) samplesWrapper.style.display = 'flex';
    });

    tabBulk.addEventListener('click', () => {
        tabBulk.classList.add('active');
        tabSingle.classList.remove('active');
        bulkForm.style.display = 'flex';
        singleForm.style.display = 'none';
        if (samplesWrapper) samplesWrapper.style.display = 'none';
    });

    // Bulk Form Submit
    bulkForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const rawInput = bulkInput.value;
        const queries = rawInput.split('\n')
                                .map(q => q.trim())
                                .filter(q => q.length > 0)
                                .slice(0, 15);

        if (queries.length === 0) {
            showToast('Please enter at least one valid query', 'warning');
            return;
        }

        // Show loading and clear progress list
        const loaderText = document.querySelector('.loader-text');
        const apiScanProgress = document.querySelector('.api-scan-progress');
        if (loaderText) loaderText.textContent = `Processing bulk lookup for ${queries.length} indicators (this may take a moment)...`;
        if (apiScanProgress) apiScanProgress.style.display = 'none';

        showView('loading');

        try {
            const resp = await fetch('/api/lookup/bulk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ queries })
            });

            const data = await resp.json();

            // Restore loader text & visibility for single scans
            if (loaderText) loaderText.textContent = 'Scanning across 9 threat intelligence sources...';
            if (apiScanProgress) apiScanProgress.style.display = 'flex';

            if (!resp.ok) {
                document.getElementById('error-message').textContent = data.error || 'Bulk lookup failed.';
                showView('error');
                return;
            }

            renderBulkResults(data);
            showView('bulk-results');
            showToast(`Bulk scan complete. Evaluated ${data.count} indicators.`, 'success');
        } catch (err) {
            if (loaderText) loaderText.textContent = 'Scanning across 9 threat intelligence sources...';
            if (apiScanProgress) apiScanProgress.style.display = 'flex';
            document.getElementById('error-message').textContent = `Network error: ${err.message}`;
            showView('error');
        }
    });

    // Row Actions: Click Analyze to Pivot
    if (bulkResultsBody) {
        bulkResultsBody.addEventListener('click', (e) => {
            const btn = e.target.closest('.btn-action');
            if (!btn) return;
            const query = btn.dataset.query;
            if (!query) return;

            // Switch UI back to Single Scan, populate, and scan
            tabSingle.click();
            const searchInput = document.getElementById('search-input');
            if (searchInput) {
                searchInput.value = query;
                // update badge
                const badge = document.getElementById('ioc-type-badge');
                if (badge) {
                    const t = detectType(query);
                    badge.textContent = t ? t.toUpperCase() : 'TYPE';
                    badge.className = `ioc-type-badge ${t}`;
                }
            }
            runLookup(query, true);
        });
    }

    if (btnBulkNewSearch) {
        btnBulkNewSearch.addEventListener('click', () => {
            showView('hero');
        });
    }
}

function renderBulkResults(data) {
    const body = document.getElementById('bulk-results-body');
    const timestampEl = document.getElementById('bulk-result-timestamp');
    if (!body) return;

    if (timestampEl) timestampEl.textContent = `Scanned at: ${data.timestamp}`;
    body.innerHTML = '';

    data.results.forEach((r, idx) => {
        const tr = document.createElement('tr');
        
        let scorePill = '—';
        let threatBadge = 'UNKNOWN';
        let threatClass = 'na';
        
        if (r.success) {
            scorePill = `<span class="score-pill-mini" style="font-weight:700; color:${getScoreColor(r.unified_score)};">${r.unified_score}/100</span>`;
            threatBadge = r.threat_level;
            threatClass = r.threat_level.toLowerCase();
        } else {
            threatBadge = 'ERROR';
            threatClass = 'error';
        }

        const typeClass = r.ioc_type ? r.ioc_type : 'unknown';
        const typeBadge = `<span class="h-type-badge ${typeClass}">${r.ioc_type.toUpperCase()}</span>`;

        tr.innerHTML = `
            <td style="color: var(--text-muted); font-weight:700;">${idx + 1}</td>
            <td class="mono" style="font-weight:600; color:var(--text-light); max-width:250px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                ${escapeHtml(r.query)}
                <button class="btn-copy-mini" onclick="navigator.clipboard.writeText('${r.query}'); showToast('Copied indicator', 'success');" style="background:transparent; border:none; color:var(--text-muted); cursor:pointer; margin-left:6px;"><i class="fa-regular fa-copy"></i></button>
            </td>
            <td>${typeBadge}</td>
            <td>${scorePill}</td>
            <td><span class="source-status ${threatClass}" style="padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700;">${threatBadge}</span></td>
            <td style="max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color: var(--text-muted); font-size: 0.8rem;">${escapeHtml(r.summary || r.error || 'N/A')}</td>
            <td style="text-align: right;">
                <button class="btn btn-outline btn-action" data-query="${escapeHtml(r.query)}">
                    <i class="fa-solid fa-magnifying-glass"></i> Analyze
                </button>
            </td>
        `;
        body.appendChild(tr);
    });
}

function getScoreColor(score) {
    if (score >= 75) return 'var(--neon-red)';
    if (score >= 50) return 'var(--neon-orange)';
    if (score >= 25) return '#fbbf24';
    return 'var(--neon-green)';
}


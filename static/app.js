function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

document.addEventListener('DOMContentLoaded', () => {
    setupClock();
    checkApiStatus();
    setupSearch();
    setupSamples();
    setupHistory();
    setupNewSearchBtn();
    setupErrorDismiss();
});

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
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(q)) return 'ip';
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
    const headerSearch = document.getElementById('header-search-container');
    
    [hero, loading, error, results].forEach(el => { if(el) el.style.display = 'none'; });

    if (view === 'hero') {
        if (hero) hero.style.display = 'flex';
        if (headerSearch) headerSearch.style.display = 'none';
    }
    else if (view === 'loading') {
        if (loading) loading.style.display = 'flex';
        // Keep header search visible during loading if we are performing a lookup from results page
    }
    else if (view === 'error') {
        if (error) error.style.display = 'block';
        if (headerSearch) headerSearch.style.display = 'none';
    }
    else if (view === 'results') {
        if (results) results.style.display = 'block';
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
}

// --- Main Lookup ---
async function runLookup(query) {
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
    const sourceMap = { virustotal: 'vt', abuseipdb: 'abuse', ipinfo: 'ipinfo', otx: 'otx', emailrep: 'emailrep', hunterio: 'hunterio', urlscan: 'urlscan', domain_checker: 'domain_checker' };
    const nameMap = { virustotal: 'VirusTotal', abuseipdb: 'AbuseIPDB', ipinfo: 'IPInfo', otx: 'OTX', emailrep: 'EmailRep', hunterio: 'Hunter.io', urlscan: 'URLScan', domain_checker: 'Domain Checker' };
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
    const deg = (score / 100) * 360;

    let color = 'var(--neon-green)';
    if (score >= 75) color = 'var(--neon-red)';
    else if (score >= 50) color = 'var(--neon-orange)';
    else if (score >= 25) color = '#fbbf24';

    gauge.style.background = `conic-gradient(${color} 0deg ${deg}deg, rgba(255,255,255,0.04) ${deg}deg 360deg)`;
    numEl.textContent = Math.round(score);
    numEl.style.color = color.startsWith('var') ? color.replace('var(','').replace(')','') : color;
    levelEl.textContent = level;

    if (score >= 75) { levelEl.style.color = 'var(--neon-red)'; levelEl.style.textShadow = '0 0 10px rgba(255,51,102,0.4)'; }
    else if (score >= 50) { levelEl.style.color = 'var(--neon-orange)'; levelEl.style.textShadow = '0 0 10px rgba(255,159,28,0.3)'; }
    else if (score >= 25) { levelEl.style.color = '#fbbf24'; levelEl.style.textShadow = 'none'; }
    else { levelEl.style.color = 'var(--neon-green)'; levelEl.style.textShadow = '0 0 10px rgba(0,255,102,0.3)'; }
}

function renderSourceCard(r) {
    const bodyMap = { virustotal: 'vt-body', abuseipdb: 'abuse-body', ipinfo: 'ipinfo-body', otx: 'otx-body', emailrep: 'emailrep-body', hunterio: 'hunterio-body', urlscan: 'urlscan-body', domain_checker: 'domain_checker-body' };
    const statusMap = { virustotal: 'vt-status', abuseipdb: 'abuse-status', ipinfo: 'ipinfo-status', otx: 'otx-status', emailrep: 'emailrep-status', hunterio: 'hunterio-status', urlscan: 'urlscan-status', domain_checker: 'domain_checker-status' };
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
        
        if (d.comments && d.comments.length > 0) {
            html += `</div><div class="abuse-comments-section"><p class="comments-header"><i class="fa-solid fa-comments"></i> Recent Community Reports</p><ul class="abuse-comments-list">`;
            d.comments.forEach(c => {
                const truncated = c.length > 120 ? c.substring(0, 117) + '...' : c;
                html += `<li class="abuse-comment-item">${escapeHtml(truncated)}</li>`;
            });
            html += `</ul>`;
        } else {
            html += `</div>`;
        }
        bodyEl.innerHTML = html;
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

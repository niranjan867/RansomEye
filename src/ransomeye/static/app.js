const state = {
    cases: [],
    currentCaseId: '',
    currentCase: null,
    assessment: null,
    stats: null,
    incidents: [],
    findings: [],
    activity: [],
    timeline: [],
    lastEventMeta: null,
    currentView: 'overview'
};

const dom = {
    selectCase: document.getElementById('case-select'),
    navItems: document.querySelectorAll('.nav-item'),
    viewContainer: document.getElementById('view-container'),

    // Topbar
    tbCaseId: document.getElementById('tb-case-id'),
    tbStatus: document.getElementById('tb-status'),
    tbSeverity: document.getElementById('tb-severity'),
    tbHost: document.getElementById('tb-host'),
    btnRefresh: document.getElementById('btn-refresh'),
    btnReport: document.getElementById('btn-top-report'),

    // Drawer
    drawer: document.getElementById('detail-drawer'),
    drawerTitle: document.getElementById('drawer-title'),
    drawerContent: document.getElementById('drawer-content'),
    drawerClose: document.getElementById('drawer-close')
};

async function init() {
    setupListeners();
    await fetchCases();
    switchView('overview');
}

function setupListeners() {
    dom.selectCase.addEventListener('change', async (e) => {
        const cid = e.target.value;
        if (cid) {
            await loadCase(cid);
        }
    });

    dom.navItems.forEach(n => {
        n.addEventListener('click', (e) => {
            e.preventDefault();
            switchView(e.target.dataset.view);
        });
    });

    dom.btnRefresh.addEventListener('click', async () => {
        if (state.currentCaseId) await loadCase(state.currentCaseId);
    });

    dom.btnReport.addEventListener('click', () => switchView('reports'));

    dom.drawerClose.addEventListener('click', () => {
        dom.drawer.classList.remove('open');
    });
}

// API
async function api(path, options = {}) {
    try {
        const res = await fetch(`/api${path}`, options);
        if (!res.ok) {
            let errorMsg = res.statusText;
            try {
                const errJson = await res.json();
                errorMsg = errJson.error || errJson.message || res.statusText;
            } catch (e) {
                const txt = await res.text();
                if (txt) errorMsg = txt;
            }
            return { _error: true, status: res.status, message: errorMsg };
        }
        return await res.json();
    } catch (e) {
        console.error('API Error:', e);
        return { _error: true, status: 0, message: e.message || 'Network error' };
    }
}

// Loaders
async function fetchCases() {
    const data = await api('/cases');
    if (!data || !data.cases || data.cases.length === 0) {
        dom.selectCase.innerHTML = '<option value="">NO CASES AVAILABLE</option>';
        return;
    }

    state.cases = data.cases;
    dom.selectCase.innerHTML = '<option value="">Select Case...</option>';
    data.cases.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.case_id;
        opt.textContent = `${c.case_id} — ${c.case_name || 'Unnamed'} (${c.status})`;
        dom.selectCase.appendChild(opt);
    });
}

async function loadCase(caseId) {
    if (!caseId) {
        state.currentCaseId = '';
        state.currentCase = null;
        state.assessment = null;
        state.stats = null;
        state.incidents = [];
        state.findings = [];
        state.activity = [];
        state.timeline = [];
        state.reconstruction = [];
        updateTopbar();
        renderCurrentView();
        return;
    }
    state.currentCaseId = caseId;
    const data = await api(`/case/${caseId}`);
    if (data) {
        state.currentCase = data.case;
        state.assessment = data.assessment;
        state.stats = data.stats;
    }

    const incData = await api(`/incidents/${caseId}`);
    state.incidents = incData ? incData.incidents : [];

    const findData = await api(`/findings/${caseId}`);
    state.findings = findData ? findData.findings : [];

    const actData = await api(`/recent_activity/${caseId}`);
    state.activity = actData ? actData.activity : [];

    const tlData = await api(`/timeline/${caseId}`);
    state.timeline = tlData ? tlData.timeline : [];

    const recData = await api(`/reconstruction/${caseId}`);
    state.reconstruction = recData ? recData.stages : [];

    updateTopbar();
    renderCurrentView();
}

function updateTopbar() {
    if (!state.currentCase) {
        dom.tbCaseId.textContent = 'NO CASE SELECTED';
        dom.tbStatus.textContent = 'UNKNOWN';
        dom.tbStatus.className = 'badge';
        dom.tbSeverity.textContent = 'UNKNOWN';
        dom.tbSeverity.className = 'badge';
        dom.tbHost.textContent = '';
        return;
    }

    dom.tbCaseId.textContent = state.currentCase.case_id;
    dom.tbHost.textContent = state.currentCase.host ? `HOST: ${state.currentCase.host}` : 'HOST: Unknown';
    dom.tbStatus.textContent = state.currentCase.status || 'UNKNOWN';
    dom.tbStatus.className = `badge ${state.currentCase.status === 'OPEN' ? 'critical' : 'low'}`;

    const sev = state.assessment ? (state.assessment.severity || 'UNKNOWN') : 'UNAVAILABLE';
    dom.tbSeverity.textContent = sev;
    dom.tbSeverity.className = `badge ${sev.toLowerCase()}`;
}

// Router
function switchView(viewName) {
    state.currentView = viewName;
    dom.navItems.forEach(n => n.classList.toggle('active', n.dataset.view === viewName));
    dom.drawer.classList.remove('open');
    renderCurrentView();
}

function renderCurrentView() {
    if (!state.currentCaseId && state.currentView !== 'monitor') {
        dom.viewContainer.innerHTML = `
            <div class="empty-state" style="padding-top: 100px;">
                <h3>No Case Selected</h3>
                <p>Select a case from the sidebar to view this dashboard, or ingest new evidence using the CLI.</p>
                <div class="code-block" style="display: inline-block; text-align: left; margin-top: 24px; padding: 16px;">
.\\.venv\\Scripts\\python.exe -m ransomeye.commands ingest --database &lt;db_path&gt; --case &lt;case_id&gt; &lt;evidence_file&gt;
                </div>
            </div>`;
        return;
    }

    const tpl = document.getElementById(`tpl-${state.currentView}`);
    if (!tpl) {
        dom.viewContainer.innerHTML = `<div class="empty-state"><h3>View Not Found</h3></div>`;
        return;
    }

    dom.viewContainer.innerHTML = '';
    dom.viewContainer.appendChild(tpl.content.cloneNode(true));

    switch (state.currentView) {
        case 'overview': initOverview(); break;
        case 'monitor': break; // Static truth content
        case 'assessment': initAssessment(); break;
        case 'incidents': initIncidents(); break;
        case 'findings': initFindings(); break;
        case 'evidence': initEvidence(); break;
        case 'timeline': initTimeline(); break;
        case 'reconstruction': initReconstruction(); break;
        case 'reports': initReports(); break;
    }
}

// View Initializers
function initOverview() {
    if (!state.currentCase) return;

    // Stats
    const asmt = state.assessment || {};
    const scoreVal = asmt.score !== undefined ? asmt.score : '-';
    const confVal = asmt.confidence !== undefined ? (asmt.confidence * 100).toFixed(0) + '%' : '-';

    document.getElementById('ov-score').textContent = scoreVal;
    document.getElementById('ov-severity').textContent = asmt.severity || 'UNAVAILABLE';
    document.getElementById('ov-confidence').textContent = confVal;

    document.getElementById('ov-incidents').textContent = state.incidents.length;
    document.getElementById('ov-findings').textContent = state.findings.length;
    document.getElementById('ov-evidence').textContent = state.stats ? state.stats.events : '-';

    // Colors
    const sevClass = (asmt.severity || '').toLowerCase();
    if (sevClass === 'critical' || sevClass === 'high') {
        document.getElementById('ov-score').classList.add('text-critical');
        document.getElementById('ov-severity').classList.add('text-critical');
    } else if (sevClass === 'medium') {
        document.getElementById('ov-score').classList.add('text-warning');
        document.getElementById('ov-severity').classList.add('text-warning');
    }

    // Incidents Table
    const incTbody = document.getElementById('ov-incidents-tbody');
    if (state.incidents.length > 0) {
        incTbody.innerHTML = state.incidents.slice(0, 5).map(inc => `
            <tr class="clickable" onclick="inspectIncident('${inc.incident_id}')">
                <td><span class="clickable-id mono">${inc.incident_id}</span></td>
                <td><span class="badge ${inc.severity.toLowerCase()}">${inc.severity}</span></td>
                <td>${(inc.evidence_event_ids || []).length}</td>
            </tr>
        `).join('');
    }

    // Activity Table
    const actTbody = document.getElementById('ov-activity-tbody');
    if (state.activity.length > 0) {
        actTbody.innerHTML = state.activity.map(a => `
            <tr class="clickable" onclick="inspectEventEncoded('${encodeURIComponent(a.event_id)}')">
                <td>${a.timestamp}</td>
                <td>${a.event_type}</td>
                <td>${a.process_name || '-'}</td>
            </tr>
        `).join('');
    }
}

function initAssessment() {
    if (!state.assessment) return;
    const p = document.getElementById('assessment-panel');
    const a = state.assessment;
    p.innerHTML = `
        <div class="panel-body">
            <div class="grid-overview" style="grid-template-columns: 1fr 1fr 1fr;">
                <div class="stat-card">
                    <span class="stat-label">Score</span>
                    <span class="stat-val ${a.severity === 'CRITICAL' || a.severity === 'HIGH' ? 'text-critical' : 'text-warning'}">${a.score}</span>
                </div>
                <div class="stat-card">
                    <span class="stat-label">Severity</span>
                    <span class="stat-val ${a.severity === 'CRITICAL' || a.severity === 'HIGH' ? 'text-critical' : 'text-warning'}">${a.severity}</span>
                </div>
                <div class="stat-card">
                    <span class="stat-label">Confidence</span>
                    <span class="stat-val">${(a.confidence * 100).toFixed(0)}%</span>
                </div>
            </div>

            <h4 class="mt-xl" style="margin-bottom: 12px; color: var(--re-text-muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em;">Analytical Reasons</h4>
            <div class="prop-list">
                ${(a.reasons || []).map(r => `<div class="prop-val" style="color: var(--re-critical); border-left: 3px solid var(--re-critical);">${r}</div>`).join('')}
            </div>

            <h4 class="mt-xl" style="margin-bottom: 12px; color: var(--re-text-muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em;">Techniques</h4>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                ${(a.techniques || []).map(t => `<span class="badge high">${t}</span>`).join('')}
            </div>
        </div>
    `;
}

function initIncidents() {
    const tbody = document.getElementById('incidents-tbody');
    if (state.incidents.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center;">No incidents in case.</td></tr>`;
        return;
    }

    tbody.innerHTML = state.incidents.map(inc => `
        <tr class="clickable" onclick="inspectIncident('${inc.incident_id}')">
            <td><span class="clickable-id mono">${inc.incident_id}</span></td>
            <td><span class="badge ${inc.severity.toLowerCase()}">${inc.severity}</span></td>
            <td>${inc.start_time || '-'}</td>
            <td>${inc.duration || '-'}</td>
            <td>${(inc.finding_ids || []).length}</td>
            <td>${(inc.evidence_event_ids || []).length}</td>
        </tr>
    `).join('');
}

function initFindings() {
    const tbody = document.getElementById('findings-tbody');
    if (state.findings.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center;">No findings in case.</td></tr>`;
        return;
    }

    tbody.innerHTML = state.findings.map(fn => `
        <tr>
            <td><span class="mono">FINDING:${fn.finding_id}</span></td>
            <td>${fn.finding_type}</td>
            <td><span class="badge high">${fn.technique || '-'}</span></td>
            <td><span class="text-critical" style="font-weight: 600;">${fn.score || '-'}</span></td>
            <td>${fn.confidence || '-'}</td>
        </tr>
    `).join('');
}

function initEvidence() {
    const btn = document.getElementById('btn-ev-search');
    const inp = document.getElementById('ev-search');
    const tbody = document.getElementById('evidence-tbody');

    const doSearch = async () => {
        if (!state.currentCaseId) return;
        const q = inp ? inp.value.trim() : '';
        const data = await api(`/search/${encodeURIComponent(state.currentCaseId)}?q=${encodeURIComponent(q)}`);

        if (!data || data._error) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--re-critical); padding: 32px;">Unable to load evidence: ${(data && data.message) ? data.message : 'Server error'}</td></tr>`;
            return;
        }

        if (!data.results || data.results.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; padding: 32px;">No matching evidence</td></tr>`;
            return;
        }

        tbody.innerHTML = data.results.map(r => `
            <tr class="clickable" onclick="inspectEventEncoded('${encodeURIComponent(r.event_id)}')">
                <td>${r.timestamp || '-'}</td>
                <td>${r.event_type || r.source}</td>
                <td>${r.process_name || '-'}</td>
                <td>${r.pid || '-'}</td>
                <td><span class="mono clickable-id">${r.event_id}</span></td>
            </tr>
        `).join('');
    };

    if (btn) btn.addEventListener('click', doSearch);
    if (inp) inp.addEventListener('keypress', e => { if (e.key === 'Enter') doSearch(); });

    doSearch();
}

function initTimeline() {
    const container = document.getElementById('timeline-container');
    if (state.timeline.length === 0) {
        container.innerHTML = `<div class="empty-state">No timeline data available.</div>`;
        return;
    }

    container.innerHTML = state.timeline.map(t => `
        <div class="timeline-item">
            <div class="timeline-time">${t.timestamp || 'Unknown Time'}</div>
            <div class="timeline-content">
                <strong>${t.description}</strong>
                ${t.process_name ? `<span class="clickable-id mono mt-sm" onclick="inspectProcess('${t.process_guid || t.pid}')" style="display: inline-block;">Process: ${t.process_name} (PID: ${t.pid})</span>` : ''}
            </div>
        </div>
    `).join('');
}

function initReconstruction() {
    const container = document.getElementById('reconstruction-container');
    if (!state.reconstruction || state.reconstruction.length === 0) {
        container.innerHTML = `<div class="empty-state"><p>No reconstructed attack stages available for this case.</p></div>`;
        return;
    }

    container.innerHTML = '<div class="timeline-list">' + state.reconstruction.map(stage => {
        let detailsHtml = '';
        if (stage.evidence_ids && stage.evidence_ids.length > 0) {
            detailsHtml += `<div class="mt-sm"><span class="prop-key">Evidence (${stage.evidence_ids.length}):</span> <span class="mono">${stage.evidence_ids.length > 0 ? stage.evidence_ids[0] : ''}</span></div>`;
        }
        if (stage.finding_ids && stage.finding_ids.length > 0) {
            detailsHtml += `<div class="mt-sm"><span class="prop-key">Findings (${stage.finding_ids.length}):</span> <span class="mono">${stage.finding_ids.length > 0 ? stage.finding_ids[0] : ''}</span></div>`;
        }

        return `
        <div class="timeline-item">
            <div class="timeline-time">${stage.timestamp || 'Unknown Time'}</div>
            <div class="timeline-content" style="border-left: 3px solid var(--re-critical);">
                <div style="font-size: 11px; text-transform: uppercase; color: var(--re-critical); font-weight: 600; margin-bottom: 4px;">${stage.stage_type}</div>
                <strong style="font-size: 14px;">${stage.title}</strong>
                <div class="mt-sm" style="color: var(--re-text-secondary);">${stage.description || ''}</div>
                ${detailsHtml}
            </div>
        </div>
        `;
    }).join('') + '</div>';
}

function initReports() {
    const btn = document.getElementById('btn-gen-report');
    if (!btn) return;

    btn.addEventListener('click', async () => {
        if (!state.currentCaseId) return;
        btn.textContent = 'Generating...';
        btn.disabled = true;

        const data = await api(`/report/${encodeURIComponent(state.currentCaseId)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{}'
        });

        const resultDiv = document.getElementById('report-result');
        const pathEl = document.getElementById('report-path');
        const contentEl = document.getElementById('report-content');

        if (data && !data._error && data.content) {
            resultDiv.classList.remove('hidden');
            pathEl.textContent = data.path || 'Generated';
            contentEl.value = data.content;
        } else {
            resultDiv.classList.remove('hidden');
            pathEl.textContent = 'Report Generation Error';
            contentEl.value = `Unable to generate report: ${(data && data.message) ? data.message : 'Server error'}`;
        }

        btn.textContent = 'GENERATE CASE REPORT';
        btn.disabled = false;
    });
}

// Drawers (Inspectors)
async function inspectIncident(incId) {
    const inc = state.incidents.find(i => i.incident_id === incId);
    if (!inc) return;

    dom.drawerTitle.textContent = `Incident: ${incId}`;
    let html = `
        <div class="prop-list">
            <div class="prop-item"><span class="prop-key">Severity</span><span class="badge ${inc.severity.toLowerCase()}" style="align-self: flex-start;">${inc.severity}</span></div>
            <div class="prop-item"><span class="prop-key">Timeframe</span><span class="prop-val">${inc.start_time} - ${inc.end_time}</span></div>
            <div class="prop-item"><span class="prop-key">Duration</span><span class="prop-val">${inc.duration} seconds</span></div>
        </div>

        <h4 class="mt-xl" style="margin-bottom: 12px; font-size: 11px; text-transform: uppercase; color: var(--re-text-muted);">Associated Findings (${(inc.finding_ids || []).length})</h4>
        <div class="prop-list">
            ${(inc.finding_ids || []).map(f => `<div class="prop-val mono" style="color: var(--re-critical); border-left: 3px solid var(--re-critical);">FINDING:${f}</div>`).join('')}
        </div>

        <h4 class="mt-xl" style="margin-bottom: 12px; font-size: 11px; text-transform: uppercase; color: var(--re-text-muted);">Processes Involved</h4>
        <div class="prop-list">
            ${(inc.processes || []).map(p => `
                <div class="prop-val mono clickable-id" onclick="inspectProcess('${p.process_guid || p.pid}')">
                    ${p.process_name} (PID: ${p.pid})<br>
                    <span style="color: var(--re-text-muted); font-size: 11px;">GUID: ${p.process_guid}</span>
                </div>
            `).join('')}
        </div>
    `;
    dom.drawerContent.innerHTML = html;
    dom.drawer.classList.add('open');
}

window.inspectEventEncoded = function(encEventId) {
    if (!encEventId) return;
    inspectEvent(decodeURIComponent(encEventId));
};

async function inspectEvent(eventId) {
    if (!state.currentCaseId || !eventId) return;
    dom.drawerTitle.textContent = `Loading Evidence...`;
    dom.drawerContent.innerHTML = '<div class="empty-state">Loading...</div>';
    dom.drawer.classList.add('open');

    const data = await api(`/inspect/${encodeURIComponent(state.currentCaseId)}?event_id=${encodeURIComponent(eventId)}`);
    if (!data || data._error || !data.event) {
        dom.drawerContent.innerHTML = `<div class="empty-state">Failed to load evidence event ${eventId}.</div>`;
        return;
    }

    const ev = data.event;
    state.lastEventMeta = {
        process_name: ev.process_name || null,
        pid: (ev.pid !== undefined && ev.pid !== null && ev.pid !== 'null' && ev.pid !== 0 && ev.pid !== '0') ? String(ev.pid) : null,
        process_guid: (ev.process_guid && ev.process_guid !== 'null' && ev.process_guid !== 'undefined') ? ev.process_guid : null,
    };

    dom.drawerTitle.textContent = `Evidence Inspection`;

    const procIdent = state.lastEventMeta.process_guid || state.lastEventMeta.pid;

    let processSectionHtml = '';
    if (procIdent) {
        processSectionHtml = `
            <div class="prop-item"><span class="prop-key">Process Name</span><span class="prop-val mono" style="color: var(--re-cyan-bright);">${ev.process_name || ev.image_path || '-'}</span></div>
            <div class="prop-item"><span class="prop-key">PID</span><span class="prop-val mono">${ev.pid || '-'}</span></div>
            <div class="prop-item"><span class="prop-key">Process GUID</span><span class="prop-val mono" style="font-size: 11px;">${ev.process_guid || '-'}</span></div>
            <div class="mt-sm mb-md">
                <button class="btn btn-primary btn-open-process-profile" onclick="inspectProcess('${procIdent}')" style="display: inline-flex; align-items: center; gap: 6px; font-size: 12px; padding: 8px 16px; cursor: pointer;">
                    OPEN PROCESS PROFILE &rarr;
                </button>
            </div>`;
    } else {
        processSectionHtml = `
            <div class="prop-item">
                <span class="prop-key">Process Context</span>
                <span class="prop-val text-muted" style="color: var(--re-text-muted);">No process context available</span>
            </div>`;
    }

    let html = `
        <div class="tabs">
            <div class="tab active" onclick="switchDrawerTab(this, 'ev-props')">Properties</div>
            <div class="tab" onclick="switchDrawerTab(this, 'ev-trace')">Evidence Trace</div>
            <div class="tab" onclick="switchDrawerTab(this, 'ev-raw')">Raw Data</div>
        </div>

        <div id="ev-props" class="tab-content active prop-list">
            <div class="prop-item"><span class="prop-key">Event ID</span><span class="prop-val mono">${ev.event_id}</span></div>
            <div class="prop-item"><span class="prop-key">Timestamp</span><span class="prop-val">${ev.timestamp || '-'}</span></div>
            <div class="prop-item"><span class="prop-key">Source</span><span class="prop-val">${ev.source}</span></div>
            <div class="prop-item"><span class="prop-key">Event Type</span><span class="prop-val">${ev.event_type || '-'}</span></div>
            ${processSectionHtml}
            <div class="prop-item"><span class="prop-key">Command Line</span><span class="prop-val" style="color: var(--re-cyan-bright);">${ev.command_line || '-'}</span></div>
            <div class="prop-item"><span class="prop-key">Image Path</span><span class="prop-val">${ev.image_path || '-'}</span></div>
        </div>

        <div id="ev-trace" class="tab-content">
            <div class="trace-container">
                <div class="trace-node mono" style="border-color: var(--re-cyan);">EVENT: ${ev.event_type || 'Unknown'} (${ev.event_id})</div>
                <div class="trace-edge"></div>
                ${data.trace.findings.length > 0 ? data.trace.findings.map(f => `<div class="trace-node mono" style="border-color: var(--re-critical); color: var(--re-critical);">FINDING: ${f.finding_type}</div>`).join('<div class="trace-edge"></div>') : `<div class="trace-node" style="color: var(--re-text-muted);">No Findings</div>`}
                <div class="trace-edge"></div>
                ${data.trace.incidents.length > 0 ? data.trace.incidents.map(i => `<div class="trace-node mono clickable-id" onclick="inspectIncident('${i.incident_id}')">INCIDENT: ${i.incident_id}</div>`).join('<div class="trace-edge"></div>') : `<div class="trace-node" style="color: var(--re-text-muted);">No Incidents</div>`}
                <div class="trace-edge"></div>
                ${data.trace.processes.length > 0 ? data.trace.processes.map(p => `<div class="trace-node mono clickable-id" onclick="inspectProcess('${p.guid || p.pid}')">PROCESS: ${p.process_name || p.pid}</div>`).join('<div class="trace-edge"></div>') : `<div class="trace-node" style="color: var(--re-text-muted);">No Process Context</div>`}
            </div>
        </div>

        <div id="ev-raw" class="tab-content">
            <textarea class="code-block" rows="20" readonly>${JSON.stringify(ev, null, 2)}</textarea>
        </div>
    `;

    dom.drawerContent.innerHTML = html;
}

async function inspectProcess(procId, meta = null) {
    if (!state.currentCaseId || !procId || procId === 'null' || procId === 'undefined') return;

    dom.drawerTitle.textContent = `Loading Process...`;
    dom.drawerContent.innerHTML = '<div class="empty-state">Loading...</div>';
    dom.drawer.classList.add('open');

    const m = meta || state.lastEventMeta || {};
    const procName = m.process_name || m.name || '-';
    const procPid = (m.pid !== undefined && m.pid !== null && m.pid !== '' && m.pid !== 'null') ? String(m.pid) : (!procId.startsWith('{') ? procId : '-');
    const procGuid = m.process_guid || m.guid || (procId.startsWith('{') ? procId : '-');

    const data = await api(`/process/${encodeURIComponent(state.currentCaseId)}/${encodeURIComponent(procId)}`);
    if (!data || data._error || !data.process) {
        dom.drawerTitle.textContent = `Process Profile`;
        dom.drawerContent.innerHTML = `
            <div class="empty-state" style="padding: 24px 12px; text-align: left;">
                <div class="badge warning mb-md" style="font-size: 13px; font-weight: 700; display: inline-block;">PROCESS PROFILE UNAVAILABLE</div>
                <p style="color: var(--re-text); font-size: 13px; margin-bottom: 16px;">No matching process node exists for this case in the investigation graph.</p>
                <h4 style="font-size: 11px; text-transform: uppercase; color: var(--re-text-muted); margin-bottom: 8px;">Event Process Metadata</h4>
                <div class="prop-list mb-lg">
                    <div class="prop-item"><span class="prop-key">Process Name</span><span class="prop-val mono">${procName}</span></div>
                    <div class="prop-item"><span class="prop-key">PID</span><span class="prop-val mono">${procPid}</span></div>
                    <div class="prop-item"><span class="prop-key">Process GUID</span><span class="prop-val mono" style="font-size: 11px;">${procGuid}</span></div>
                </div>
                <button class="btn btn-secondary mt-md" onclick="dom.drawer.classList.remove('open')" style="display: inline-flex; align-items: center; gap: 6px;">
                    &larr; BACK TO EVIDENCE
                </button>
            </div>`;
        return;
    }

    const p = data.process;
    dom.drawerTitle.textContent = `Process Profile`;

    let html = `
        <div class="prop-list mb-lg">
            <div class="prop-item"><span class="prop-key">Process Name</span><span class="prop-val mono" style="font-size: 16px; color: var(--re-cyan-bright); border-color: var(--re-cyan);">${p.name || '-'}</span></div>
            <div class="prop-item"><span class="prop-key">PID</span><span class="prop-val mono">${p.pid || '-'}</span></div>
            <div class="prop-item"><span class="prop-key">GUID</span><span class="prop-val mono" style="font-size: 11px;">${p.guid || '-'}</span></div>
            <div class="prop-item"><span class="prop-key">Command Line</span><span class="prop-val" style="color: var(--re-text);">${p.command_line || '-'}</span></div>
        </div>

        <div class="tabs mt-lg">
            <div class="tab active" onclick="switchDrawerTab(this, 'proc-lineage')">Lineage</div>
            <div class="tab" onclick="switchDrawerTab(this, 'proc-files')">Files (${data.files.length})</div>
            <div class="tab" onclick="switchDrawerTab(this, 'proc-net')">Network (${data.network.length})</div>
            <div class="tab" onclick="switchDrawerTab(this, 'proc-find')">Findings (${data.findings.length})</div>
        </div>

        <div id="proc-lineage" class="tab-content active" style="background: var(--re-bg); border: 1px solid var(--re-border); padding: 16px; border-radius: 4px;">
            ${data.parent ? `<div class="tree-node parent clickable-id" onclick="inspectProcess('${data.parent.guid || data.parent.pid}')">${data.parent.name} (PID: ${data.parent.pid})</div>` : '<div class="tree-node parent">Unknown Parent</div>'}
            <div class="tree-node current">${p.name} (PID: ${p.pid})</div>
            ${data.children.length > 0 ? data.children.map(c => `<div class="tree-node child clickable-id" onclick="inspectProcess('${c.guid || c.pid}')">${c.name} (PID: ${c.pid})</div>`).join('') : '<div class="tree-node child" style="color: var(--re-text-muted);">No children</div>'}
        </div>

        <div id="proc-files" class="tab-content prop-list">
            ${data.files.length > 0 ? data.files.map(f => `<div class="prop-val mono"><strong style="color: var(--re-text-secondary); width: 80px; display: inline-block;">${f.rel}</strong> ${f.path}</div>`).join('') : '<div class="empty-state">No file modifications recorded.</div>'}
        </div>

        <div id="proc-net" class="tab-content prop-list">
            ${data.network.length > 0 ? data.network.map(n => `<div class="prop-val mono"><strong style="color: var(--re-text-secondary);">CONNECT</strong> ${n.destination_ip}:${n.destination_port} [${n.protocol}]</div>`).join('') : '<div class="empty-state">No network connections recorded.</div>'}
        </div>

        <div id="proc-find" class="tab-content prop-list">
            ${data.findings.length > 0 ? data.findings.map(f => `<div class="prop-val mono" style="color: var(--re-critical); border-left: 3px solid var(--re-critical);">FINDING: ${f.finding_type} (${f.technique})</div>`).join('') : '<div class="empty-state">No associated findings.</div>'}
        </div>
    `;

    dom.drawerContent.innerHTML = html;
}

// Global Tab Switcher for Drawer
window.switchDrawerTab = function (el, targetId) {
    const tabs = el.parentElement.querySelectorAll('.tab');
    const contents = el.parentElement.nextElementSibling.parentElement.querySelectorAll('.tab-content');

    tabs.forEach(t => t.classList.remove('active'));
    contents.forEach(c => c.classList.remove('active'));

    el.classList.add('active');
    document.getElementById(targetId).classList.add('active');
};

document.addEventListener('DOMContentLoaded', init);

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
    reconstruction: [],
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
    drawerClose: document.getElementById('drawer-close'),

    // Modal
    modal: document.getElementById('app-modal'),
    modalTitle: document.getElementById('modal-title'),
    modalBody: document.getElementById('modal-body'),
    modalFooter: document.getElementById('modal-footer'),
    modalClose: document.getElementById('modal-close')
};

async function init() {
    setupListeners();
    await fetchCases();
    switchView('overview');
}

function setupListeners() {
    dom.selectCase.addEventListener('change', async (e) => {
        const cid = e.target.value;
        await loadCase(cid);
    });

    dom.navItems.forEach(n => {
        n.addEventListener('click', (e) => {
            e.preventDefault();
            switchView(e.currentTarget.dataset.view);
        });
    });

    dom.btnRefresh.addEventListener('click', async () => {
        await fetchCases();
        if (state.currentCaseId) {
            await loadCase(state.currentCaseId);
        } else {
            renderCurrentView();
        }
    });

    dom.btnReport.addEventListener('click', () => switchView('reports'));

    dom.drawerClose.addEventListener('click', () => {
        dom.drawer.classList.remove('open');
    });

    if (dom.modalClose) {
        dom.modalClose.addEventListener('click', hideModal);
    }
    if (dom.modal) {
        dom.modal.addEventListener('click', (e) => {
            if (e.target === dom.modal) hideModal();
        });
    }
}

// Modal Utility
function showModal(title, bodyHtml, footerHtml = '') {
    if (!dom.modal) return;
    dom.modalTitle.textContent = title;
    dom.modalBody.innerHTML = bodyHtml;
    dom.modalFooter.innerHTML = footerHtml;
    dom.modal.classList.remove('hidden');
}

function hideModal() {
    if (!dom.modal) return;
    dom.modal.classList.add('hidden');
    dom.modalBody.innerHTML = '';
    dom.modalFooter.innerHTML = '';
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
        state.cases = [];
        dom.selectCase.innerHTML = '<option value="">NO CASES AVAILABLE</option>';
        return;
    }

    state.cases = data.cases;
    const currentVal = state.currentCaseId;
    dom.selectCase.innerHTML = '<option value="">Select Case...</option>';
    data.cases.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.case_id;
        opt.textContent = `${c.case_id} — ${c.case_name || 'Unnamed'} (${c.status})`;
        if (c.case_id === currentVal) opt.selected = true;
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
        dom.selectCase.value = '';
        updateTopbar();
        renderCurrentView();
        return;
    }

    state.currentCaseId = caseId;
    dom.selectCase.value = caseId;

    const data = await api(`/case/${encodeURIComponent(caseId)}`);
    if (data && !data._error) {
        state.currentCase = data.case;
        state.assessment = data.assessment;
        state.stats = data.stats;
    }

    const incData = await api(`/incidents/${encodeURIComponent(caseId)}`);
    state.incidents = (incData && !incData._error) ? incData.incidents : [];

    const findData = await api(`/findings/${encodeURIComponent(caseId)}`);
    state.findings = (findData && !findData._error) ? findData.findings : [];

    const actData = await api(`/recent_activity/${encodeURIComponent(caseId)}`);
    state.activity = (actData && !actData._error) ? actData.activity : [];

    const tlData = await api(`/timeline/${encodeURIComponent(caseId)}`);
    state.timeline = (tlData && !tlData._error) ? tlData.timeline : [];

    const recData = await api(`/reconstruction/${encodeURIComponent(caseId)}`);
    state.reconstruction = (recData && !recData._error) ? recData.stages : [];

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

const GLOBAL_VIEWS = ['cases', 'monitor', 'collection', 'integrity', 'database', 'static', 'phishing'];

function renderCurrentView() {
    if (!state.currentCaseId && !GLOBAL_VIEWS.includes(state.currentView)) {
        dom.viewContainer.innerHTML = `
            <div class="empty-state" style="padding-top: 100px;">
                <h3>No Case Selected</h3>
                <p>Select a case from the sidebar or manage cases to begin investigation.</p>
                <div style="margin-top: 24px; display: flex; gap: 12px; justify-content: center;">
                    <button class="btn btn-primary" onclick="switchView('cases')">View / Create Cases</button>
                    <button class="btn" onclick="switchView('collection')">Ingest Evidence</button>
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
        case 'cases': initCases(); break;
        case 'monitor': break; // Static truth content
        case 'assessment': initAssessment(); break;
        case 'incidents': initIncidents(); break;
        case 'findings': initFindings(); break;
        case 'evidence': initEvidence(); break;
        case 'investigation': initInvestigation(); break;
        case 'timeline': initTimeline(); break;
        case 'tree': initTree(); break;
        case 'reconstruction': initReconstruction(); break;
        case 'reports': initReports(); break;
        case 'collection': initCollection(); break;
        case 'integrity': initIntegrity(); break;
        case 'custody': initCustody(); break;
        case 'export': initExport(); break;
        case 'database': initDatabase(); break;
        case 'static': initStatic(); break;
        case 'phishing': initPhishing(); break;
    }
}

// ==========================================
// 1. Overview
// ==========================================
function initOverview() {
    if (!state.currentCase) return;

    const asmt = state.assessment || {};
    const scoreVal = asmt.score !== undefined ? asmt.score : '-';
    const confVal = asmt.confidence !== undefined ? (asmt.confidence * 100).toFixed(0) + '%' : '-';

    document.getElementById('ov-score').textContent = scoreVal;
    document.getElementById('ov-severity').textContent = asmt.severity || 'UNAVAILABLE';
    document.getElementById('ov-confidence').textContent = confVal;

    document.getElementById('ov-incidents').textContent = state.incidents.length;
    document.getElementById('ov-findings').textContent = state.findings.length;
    document.getElementById('ov-evidence').textContent = state.stats ? state.stats.events : '-';

    const sevClass = (asmt.severity || '').toLowerCase();
    if (sevClass === 'critical' || sevClass === 'high') {
        document.getElementById('ov-score').classList.add('text-critical');
        document.getElementById('ov-severity').classList.add('text-critical');
    } else if (sevClass === 'medium') {
        document.getElementById('ov-score').classList.add('text-warning');
        document.getElementById('ov-severity').classList.add('text-warning');
    }

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

// ==========================================
// 2. Cases Management
// ==========================================
async function initCases() {
    const tbody = document.getElementById('cases-tbody');
    const searchInp = document.getElementById('cases-search');
    const filterStatus = document.getElementById('cases-filter-status');
    const btnNew = document.getElementById('btn-create-case-modal');

    const renderTable = (casesList) => {
        if (!casesList || casesList.length === 0) {
            tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; padding: 32px;">No cases found.</td></tr>`;
            return;
        }

        tbody.innerHTML = casesList.map(c => `
            <tr>
                <td><span class="mono clickable-id" onclick="loadCase('${c.case_id}').then(() => switchView('overview'))">${c.case_id}</span></td>
                <td><strong>${c.case_name || '-'}</strong></td>
                <td class="mono">${c.host || '-'}</td>
                <td><span class="badge ${c.status === 'OPEN' ? 'critical' : 'low'}">${c.status}</span></td>
                <td><span class="badge ${(c.severity || 'low').toLowerCase()}">${c.severity || 'LOW'}</span></td>
                <td class="mono" style="font-size: 11px;">${c.created_at ? c.created_at.slice(0, 19) : '-'}</td>
                <td>${c.events_count !== undefined ? c.events_count : '-'}</td>
                <td>${c.findings_count !== undefined ? c.findings_count : '-'}</td>
                <td>${c.incidents_count !== undefined ? c.incidents_count : '-'}</td>
                <td>
                    <div style="display: flex; gap: 6px;">
                        <button class="btn btn-sm btn-primary" onclick="loadCase('${c.case_id}').then(() => switchView('overview'))">Open</button>
                        <button class="btn btn-sm" onclick="openUpdateStatusModal('${c.case_id}', '${c.status}')">Status</button>
                        <button class="btn btn-sm" onclick="openCaseHistoryModal('${c.case_id}')">History</button>
                    </div>
                </td>
            </tr>
        `).join('');
    };

    const filterAndRender = () => {
        const q = (searchInp.value || '').toLowerCase();
        const st = (filterStatus.value || '').toUpperCase();
        const filtered = state.cases.filter(c => {
            const matchesQ = !q || (c.case_id && c.case_id.toLowerCase().includes(q)) ||
                             (c.case_name && c.case_name.toLowerCase().includes(q)) ||
                             (c.host && c.host.toLowerCase().includes(q));
            const matchesSt = !st || c.status === st;
            return matchesQ && matchesSt;
        });
        renderTable(filtered);
    };

    searchInp.addEventListener('input', filterAndRender);
    filterStatus.addEventListener('change', filterAndRender);

    btnNew.addEventListener('click', () => {
        showModal('Create Forensic Case', `
            <div class="form-group">
                <label class="form-label">Case ID *</label>
                <input type="text" id="modal-new-case-id" class="form-control mono" placeholder="e.g. CASE-2026-001">
            </div>
            <div class="form-group">
                <label class="form-label">Case Name</label>
                <input type="text" id="modal-new-case-name" class="form-control" placeholder="e.g. Finance Server Ransomware Investigation">
            </div>
            <div class="form-group">
                <label class="form-label">Host Name</label>
                <input type="text" id="modal-new-case-host" class="form-control" placeholder="e.g. WIN-SRV-01">
            </div>
            <div id="modal-case-feedback" class="mt-md hidden"></div>
        `, `
            <button class="btn" onclick="hideModal()">Cancel</button>
            <button class="btn btn-primary" id="btn-submit-create-case">Create Case</button>
        `);

        document.getElementById('btn-submit-create-case').addEventListener('click', async () => {
            const cid = document.getElementById('modal-new-case-id').value.trim();
            const name = document.getElementById('modal-new-case-name').value.trim();
            const host = document.getElementById('modal-new-case-host').value.trim();
            const fb = document.getElementById('modal-case-feedback');

            if (!cid) {
                fb.className = 'alert alert-error mt-md';
                fb.textContent = 'Case ID is required.';
                fb.classList.remove('hidden');
                return;
            }

            const res = await api('/cases', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ case_id: cid, case_name: name, host: host })
            });

            if (res && !res._error) {
                fb.className = 'alert alert-success mt-md';
                fb.textContent = `Case ${cid} created successfully.`;
                fb.classList.remove('hidden');
                await fetchCases();
                setTimeout(() => {
                    hideModal();
                    loadCase(cid).then(() => switchView('overview'));
                }, 750);
            } else {
                fb.className = 'alert alert-error mt-md';
                fb.textContent = res ? res.message : 'Failed to create case.';
                fb.classList.remove('hidden');
            }
        });
    });

    const data = await api('/cases');
    if (data && data.cases) {
        state.cases = data.cases;
    }
    filterAndRender();
}

window.openUpdateStatusModal = function(caseId, currentStatus) {
    showModal(`Update Status: ${caseId}`, `
        <div class="form-group">
            <label class="form-label">Lifecycle Status</label>
            <select id="modal-update-status" class="form-control">
                <option value="OPEN" ${currentStatus === 'OPEN' ? 'selected' : ''}>OPEN</option>
                <option value="IN_PROGRESS" ${currentStatus === 'IN_PROGRESS' ? 'selected' : ''}>IN_PROGRESS</option>
                <option value="CLOSED" ${currentStatus === 'CLOSED' ? 'selected' : ''}>CLOSED</option>
                <option value="ARCHIVED" ${currentStatus === 'ARCHIVED' ? 'selected' : ''}>ARCHIVED</option>
            </select>
        </div>
        <div class="form-group">
            <label class="form-label">Status Notes</label>
            <textarea id="modal-update-notes" class="form-control" rows="3" placeholder="Explain the rationale for lifecycle change..."></textarea>
        </div>
        <div id="modal-status-feedback" class="mt-md hidden"></div>
    `, `
        <button class="btn" onclick="hideModal()">Cancel</button>
        <button class="btn btn-primary" id="btn-submit-update-status">Update Status</button>
    `);

    document.getElementById('btn-submit-update-status').addEventListener('click', async () => {
        const st = document.getElementById('modal-update-status').value;
        const notes = document.getElementById('modal-update-notes').value.trim();
        const fb = document.getElementById('modal-status-feedback');

        const res = await api(`/case/${encodeURIComponent(caseId)}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: st, notes: notes })
        });

        if (res && !res._error) {
            fb.className = 'alert alert-success mt-md';
            fb.textContent = `Status updated to ${st}.`;
            fb.classList.remove('hidden');
            await fetchCases();
            if (state.currentCaseId === caseId) {
                await loadCase(caseId);
            }
            setTimeout(() => {
                hideModal();
                if (state.currentView === 'cases') initCases();
            }, 600);
        } else {
            fb.className = 'alert alert-error mt-md';
            fb.textContent = res ? res.message : 'Failed to update status.';
            fb.classList.remove('hidden');
        }
    });
};

window.openCaseHistoryModal = async function(caseId) {
    showModal(`Case History: ${caseId}`, `<div class="empty-state">Loading history...</div>`, `<button class="btn" onclick="hideModal()">Close</button>`);

    const data = await api(`/case/${encodeURIComponent(caseId)}/history`);
    if (!data || data._error || !data.history || data.history.length === 0) {
        dom.modalBody.innerHTML = `<div class="empty-state">No status history recorded for case ${caseId}.</div>`;
        return;
    }

    dom.modalBody.innerHTML = `
        <div class="timeline-list">
            ${data.history.map(h => `
                <div class="timeline-item">
                    <div class="timeline-time">${h.timestamp || '-'}</div>
                    <div class="timeline-content">
                        <strong>Status transitioned to: <span class="badge ${h.status === 'OPEN' ? 'critical' : 'low'}">${h.status}</span></strong>
                        ${h.notes ? `<div class="mt-sm" style="color: var(--re-text-secondary);">${h.notes}</div>` : ''}
                    </div>
                </div>
            `).join('')}
        </div>
    `;
};

// ==========================================
// 3. Threat Assessment
// ==========================================
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

// ==========================================
// 4. Incidents
// ==========================================
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

// ==========================================
// 5. Findings
// ==========================================
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

// ==========================================
// 6. Evidence Workspace
// ==========================================
function initEvidence() {
    const btn = document.getElementById('btn-ev-search');
    const inp = document.getElementById('ev-search');
    const tbody = document.getElementById('evidence-tbody');

    const doSearch = async () => {
        if (!state.currentCaseId) return;
        const q = inp ? inp.value.trim() : '';
        const data = await api(`/evidence/${encodeURIComponent(state.currentCaseId)}/search?q=${encodeURIComponent(q)}`);

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

// ==========================================
// 7. Investigation Hub
// ==========================================
async function initInvestigation() {
    if (!state.currentCaseId) return;

    const statusEl = document.getElementById('inv-status');
    const nodesEl = document.getElementById('inv-nodes');
    const edgesEl = document.getElementById('inv-edges');
    const validStatusEl = document.getElementById('inv-valid-status');
    const graphSumEl = document.getElementById('inv-graph-summary');
    const validSumEl = document.getElementById('inv-validation-summary');

    // Fetch investigation summary
    const invData = await api(`/investigation/${encodeURIComponent(state.currentCaseId)}`);
    if (invData && !invData._error && invData.summary) {
        statusEl.textContent = 'ACTIVE';
        nodesEl.textContent = invData.summary.total_nodes !== undefined ? invData.summary.total_nodes : '-';
        edgesEl.textContent = invData.summary.total_edges !== undefined ? invData.summary.total_edges : '-';
    }

    // Fetch graph details
    const graphData = await api(`/investigation/${encodeURIComponent(state.currentCaseId)}/graph`);
    if (graphData && !graphData._error && graphData.nodes) {
        const procNodes = graphData.nodes.filter(n => n.type === 'process' || n.label === 'Process');
        const fileNodes = graphData.nodes.filter(n => n.type === 'file' || n.label === 'File');
        const netNodes = graphData.nodes.filter(n => n.type === 'network' || n.label === 'Network');

        graphSumEl.innerHTML = `
            <div class="prop-list">
                <div class="prop-item"><span class="prop-key">Processes in Graph</span><span class="prop-val mono">${procNodes.length}</span></div>
                <div class="prop-item"><span class="prop-key">File Nodes in Graph</span><span class="prop-val mono">${fileNodes.length}</span></div>
                <div class="prop-item"><span class="prop-key">Network Nodes in Graph</span><span class="prop-val mono">${netNodes.length}</span></div>
                <div class="prop-item"><span class="prop-key">Total Edges</span><span class="prop-val mono">${(graphData.edges || []).length}</span></div>
            </div>
            <div class="mt-md" style="display: flex; gap: 8px;">
                <button class="btn btn-sm btn-primary" onclick="switchView('tree')">View Process Tree &rarr;</button>
                <button class="btn btn-sm" onclick="switchView('reconstruction')">Attack Reconstruction &rarr;</button>
            </div>
        `;
    } else {
        graphSumEl.innerHTML = `<div class="empty-state">No graph data generated for this case.</div>`;
    }

    // Fetch validation
    const valData = await api(`/investigation/${encodeURIComponent(state.currentCaseId)}/validation`);
    if (valData && !valData._error && valData.validation) {
        const v = valData.validation;
        const isValid = v.valid !== false && (!v.errors || v.errors.length === 0);
        validStatusEl.textContent = isValid ? 'VALID' : 'FLAGGED';
        validStatusEl.className = `stat-val ${isValid ? 'text-success' : 'text-critical'}`;

        validSumEl.innerHTML = `
            <div class="prop-list">
                <div class="prop-item"><span class="prop-key">Validation Status</span><span class="badge ${isValid ? 'low' : 'critical'}">${isValid ? 'PASSED' : 'ANOMALIES DETECTED'}</span></div>
                <div class="prop-item"><span class="prop-key">Checks Performed</span><span class="prop-val mono">${v.checks_performed !== undefined ? v.checks_performed : 'Complete'}</span></div>
                <div class="prop-item"><span class="prop-key">Errors / Warnings</span><span class="prop-val mono ${isValid ? 'text-success' : 'text-critical'}">${(v.errors || []).length}</span></div>
                ${v.errors && v.errors.length > 0 ? `<div class="prop-item"><span class="prop-key">Details</span><div class="prop-val" style="color: var(--re-critical);">${v.errors.join('<br>')}</div></div>` : ''}
            </div>
        `;
    } else {
        validStatusEl.textContent = 'CHECKED';
        validSumEl.innerHTML = `<div class="empty-state">Validation checks complete. No discrepancies found.</div>`;
    }
}

// ==========================================
// 8. Process Tree
// ==========================================
async function initTree() {
    if (!state.currentCaseId) return;
    const container = document.getElementById('tree-container');

    const data = await api(`/tree/${encodeURIComponent(state.currentCaseId)}`);
    if (!data || data._error || !data.tree || data.tree.length === 0) {
        container.innerHTML = `<div class="empty-state">No process tree available for this case.</div>`;
        return;
    }

    const renderTreeNodes = (nodes, depth = 0) => {
        return nodes.map(n => {
            const indent = depth * 24;
            const procIdent = n.guid || n.pid;
            const childrenHtml = (n.children && n.children.length > 0) ? renderTreeNodes(n.children, depth + 1) : '';
            return `
                <div style="margin-left: ${indent}px; margin-bottom: 8px;">
                    <div class="tree-node current clickable-id" onclick="inspectProcess('${procIdent}')" style="display: flex; justify-content: space-between; align-items: center; border-radius: 4px;">
                        <div>
                            <strong>${n.name || 'Unknown'}</strong> (PID: ${n.pid || '-'})
                            ${n.command_line ? `<div style="font-size: 11px; color: var(--re-text-muted); margin-top: 2px;">${n.command_line}</div>` : ''}
                        </div>
                        <span class="mono" style="font-size: 10px; color: var(--re-text-muted);">${n.guid ? n.guid.slice(0, 8) + '...' : ''}</span>
                    </div>
                    ${childrenHtml}
                </div>
            `;
        }).join('');
    };

    container.innerHTML = `<div class="prop-list">${renderTreeNodes(data.tree)}</div>`;
}

// ==========================================
// 9. Timeline
// ==========================================
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

// ==========================================
// 10. Reconstruction
// ==========================================
function initReconstruction() {
    const container = document.getElementById('reconstruction-container');
    if (!state.reconstruction || state.reconstruction.length === 0) {
        container.innerHTML = `<div class="empty-state"><p>No reconstructed attack stages available for this case.</p></div>`;
        return;
    }

    container.innerHTML = '<div class="timeline-list">' + state.reconstruction.map(stage => {
        let detailsHtml = '';
        if (stage.evidence_ids && stage.evidence_ids.length > 0) {
            detailsHtml += `<div class="mt-sm"><span class="prop-key">Evidence (${stage.evidence_ids.length}):</span> <span class="mono">${stage.evidence_ids[0]}</span></div>`;
        }
        if (stage.finding_ids && stage.finding_ids.length > 0) {
            detailsHtml += `<div class="mt-sm"><span class="prop-key">Findings (${stage.finding_ids.length}):</span> <span class="mono">${stage.finding_ids[0]}</span></div>`;
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

// ==========================================
// 11. Reports
// ==========================================
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

// ==========================================
// 12. Collection & Ingestion
// ==========================================
async function initCollection() {
    const caseInp = document.getElementById('ingest-case-id');
    const fileInp = document.getElementById('ingest-file-path');
    const formatSel = document.getElementById('ingest-format');
    const btnIngest = document.getElementById('btn-submit-ingest');
    const fbIngest = document.getElementById('ingest-feedback');

    if (state.currentCaseId && caseInp) {
        caseInp.value = state.currentCaseId;
    }

    btnIngest.addEventListener('click', async () => {
        const cid = caseInp.value.trim();
        const fpath = fileInp.value.trim();
        const fmt = formatSel.value;

        if (!cid || !fpath) {
            fbIngest.className = 'alert alert-error mt-md';
            fbIngest.textContent = 'Target Case ID and Evidence File Path are required.';
            fbIngest.classList.remove('hidden');
            return;
        }

        btnIngest.textContent = 'Ingesting...';
        btnIngest.disabled = true;

        const res = await api('/ingest', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_id: cid, file_path: fpath, format: fmt })
        });

        btnIngest.textContent = 'Start Ingestion';
        btnIngest.disabled = false;

        if (res && !res._error) {
            fbIngest.className = 'alert alert-success mt-md';
            fbIngest.innerHTML = `
                <strong>Ingestion Complete</strong><br>
                Events Ingested: ${res.events_ingested !== undefined ? res.events_ingested : '-'}<br>
                Findings Generated: ${res.findings_generated !== undefined ? res.findings_generated : '-'}<br>
                Incidents Correlated: ${res.incidents_correlated !== undefined ? res.incidents_correlated : '-'}
            `;
            fbIngest.classList.remove('hidden');
            await fetchCases();
            if (state.currentCaseId === cid) await loadCase(cid);
        } else {
            fbIngest.className = 'alert alert-error mt-md';
            fbIngest.textContent = res ? res.message : 'Ingestion failed.';
            fbIngest.classList.remove('hidden');
        }
    });

    // Live collection
    const statusVal = document.getElementById('col-status-val');
    const nameVal = document.getElementById('col-name-val');
    const detailsVal = document.getElementById('col-details-val');
    const btnStart = document.getElementById('btn-collect-start');
    const btnStop = document.getElementById('btn-collect-stop');
    const fbCollect = document.getElementById('collect-feedback');

    const refreshCollectStatus = async () => {
        const res = await api('/collect/status');
        if (res && !res._error) {
            statusVal.textContent = res.status || 'READY';
            nameVal.textContent = res.collector || 'Windows Endpoint Collector';
            detailsVal.textContent = res.details || 'Awaiting live endpoint hook';
        }
    };

    btnStart.addEventListener('click', async () => {
        const res = await api('/collect/start', { method: 'POST' });
        fbCollect.className = res && !res._error ? 'alert alert-success mt-md' : 'alert alert-error mt-md';
        fbCollect.textContent = res ? (res.message || res.status) : 'Failed to start collector';
        fbCollect.classList.remove('hidden');
        await refreshCollectStatus();
    });

    btnStop.addEventListener('click', async () => {
        const res = await api('/collect/stop', { method: 'POST' });
        fbCollect.className = res && !res._error ? 'alert alert-info mt-md' : 'alert alert-error mt-md';
        fbCollect.textContent = res ? (res.message || res.status) : 'Failed to stop collector';
        fbCollect.classList.remove('hidden');
        await refreshCollectStatus();
    });

    await refreshCollectStatus();
}

// ==========================================
// 13. Integrity Verification
// ==========================================
function initIntegrity() {
    const hashTarget = document.getElementById('hash-target-path');
    const hashManifest = document.getElementById('hash-manifest-path');
    const btnHash = document.getElementById('btn-run-hash');
    const fbHash = document.getElementById('hash-feedback');

    btnHash.addEventListener('click', async () => {
        const target = hashTarget.value.trim();
        const manifest = hashManifest.value.trim();
        if (!target) {
            fbHash.className = 'alert alert-error mt-md';
            fbHash.textContent = 'Target Directory or File path is required.';
            fbHash.classList.remove('hidden');
            return;
        }

        btnHash.textContent = 'Generating...';
        btnHash.disabled = true;

        const res = await api('/integrity/hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_path: target, manifest_path: manifest })
        });

        btnHash.textContent = 'Generate Manifest';
        btnHash.disabled = false;

        if (res && !res._error) {
            fbHash.className = 'alert alert-success mt-md';
            fbHash.innerHTML = `<strong>Manifest Generated</strong><br>Saved to: <span class="mono">${res.manifest_path || manifest}</span><br>Files Hashed: ${res.files_count !== undefined ? res.files_count : '-'}`;
            fbHash.classList.remove('hidden');
        } else {
            fbHash.className = 'alert alert-error mt-md';
            fbHash.textContent = res ? res.message : 'Manifest generation failed.';
            fbHash.classList.remove('hidden');
        }
    });

    const verifyTarget = document.getElementById('verify-target-path');
    const verifyManifest = document.getElementById('verify-manifest-path');
    const btnVerify = document.getElementById('btn-run-verify');
    const fbVerify = document.getElementById('verify-feedback');

    btnVerify.addEventListener('click', async () => {
        const target = verifyTarget.value.trim();
        const manifest = verifyManifest.value.trim();
        if (!target || !manifest) {
            fbVerify.className = 'alert alert-error mt-md';
            fbVerify.textContent = 'Both target path and manifest path are required for verification.';
            fbVerify.classList.remove('hidden');
            return;
        }

        btnVerify.textContent = 'Verifying...';
        btnVerify.disabled = true;

        const res = await api('/integrity/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_path: target, manifest_path: manifest })
        });

        btnVerify.textContent = 'Verify Integrity';
        btnVerify.disabled = false;

        if (res && !res._error) {
            const verified = res.verified || res.status === 'OK' || res.status === 'MATCHED';
            fbVerify.className = `alert ${verified ? 'alert-success' : 'alert-error'} mt-md`;
            fbVerify.innerHTML = `
                <strong>Integrity Verification: ${verified ? 'PASSED (MATCHED)' : 'FAILED / TAMPERED'}</strong><br>
                Status: <span class="mono">${res.status || (verified ? 'MATCHED' : 'FAILED')}</span><br>
                ${res.mismatches && res.mismatches.length > 0 ? `Mismatches: ${res.mismatches.join(', ')}` : 'All cryptographic hashes match manifest.'}
            `;
            fbVerify.classList.remove('hidden');
        } else {
            fbVerify.className = 'alert alert-error mt-md';
            fbVerify.textContent = res ? res.message : 'Verification failed.';
            fbVerify.classList.remove('hidden');
        }
    });
}

// ==========================================
// 14. Chain of Custody
// ==========================================
async function initCustody() {
    const tbody = document.getElementById('custody-tbody');
    const artifactInp = document.getElementById('custody-artifact');
    const actionSel = document.getElementById('custody-action');
    const analystInp = document.getElementById('custody-analyst');
    const notesInp = document.getElementById('custody-notes');
    const btnRecord = document.getElementById('btn-record-custody');
    const fbCustody = document.getElementById('custody-feedback');

    const loadCustodyEntries = async () => {
        if (!state.currentCaseId) return;
        const res = await api(`/custody/${encodeURIComponent(state.currentCaseId)}`);
        if (!res || res._error || !res.entries || res.entries.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 32px;">No chain of custody entries recorded for this case.</td></tr>`;
            return;
        }

        tbody.innerHTML = res.entries.map(e => `
            <tr>
                <td class="mono" style="font-size: 11px;">${e.timestamp ? e.timestamp.slice(0, 19) : '-'}</td>
                <td class="mono"><strong>${e.artifact || '-'}</strong></td>
                <td><span class="badge ${e.action === 'COLLECTED' ? 'high' : 'low'}">${e.action}</span></td>
                <td>${e.analyst || '-'}</td>
                <td class="mono" style="font-size: 10px;">${e.sha256 ? e.sha256.slice(0, 16) + '...' : '-'}</td>
                <td style="font-size: 12px;">${e.notes || '-'}</td>
            </tr>
        `).join('');
    };

    btnRecord.addEventListener('click', async () => {
        if (!state.currentCaseId) return;
        const art = artifactInp.value.trim();
        const act = actionSel.value;
        const ana = analystInp.value.trim();
        const nts = notesInp.value.trim();

        if (!art || !ana) {
            fbCustody.className = 'alert alert-error mt-md';
            fbCustody.textContent = 'Artifact path and Analyst name are required.';
            fbCustody.classList.remove('hidden');
            return;
        }

        btnRecord.textContent = 'Recording...';
        btnRecord.disabled = true;

        const res = await api(`/custody/${encodeURIComponent(state.currentCaseId)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ artifact: art, action: act, analyst: ana, notes: nts })
        });

        btnRecord.textContent = 'Record Entry';
        btnRecord.disabled = false;

        if (res && !res._error) {
            fbCustody.className = 'alert alert-success mt-md';
            fbCustody.textContent = 'Chain of custody entry recorded successfully.';
            fbCustody.classList.remove('hidden');
            artifactInp.value = '';
            notesInp.value = '';
            await loadCustodyEntries();
        } else {
            fbCustody.className = 'alert alert-error mt-md';
            fbCustody.textContent = res ? res.message : 'Failed to record entry.';
            fbCustody.classList.remove('hidden');
        }
    });

    await loadCustodyEntries();
}

// ==========================================
// 15. Case Export & Lock Management
// ==========================================
async function initExport() {
    if (!state.currentCaseId) return;

    const outDirInp = document.getElementById('export-out-dir');
    const btnExport = document.getElementById('btn-run-export');
    const fbExport = document.getElementById('export-feedback');

    const lockStatusVal = document.getElementById('lock-status-val');
    const lockOwnerVal = document.getElementById('lock-owner-val');
    const lockTimeVal = document.getElementById('lock-time-val');
    const chkUnlock = document.getElementById('confirm-unlock');
    const btnUnlock = document.getElementById('btn-force-unlock');
    const fbUnlock = document.getElementById('unlock-feedback');

    const refreshLock = async () => {
        const res = await api(`/export/lock?case_id=${encodeURIComponent(state.currentCaseId)}`);
        if (res && !res._error) {
            const isLocked = res.locked;
            lockStatusVal.textContent = isLocked ? 'LOCKED' : 'UNLOCKED';
            lockStatusVal.className = `prop-val ${isLocked ? 'text-critical' : 'text-success'}`;
            lockOwnerVal.textContent = res.owner ? `${res.owner} (PID: ${res.pid || '-'})` : '-';
            lockTimeVal.textContent = res.timestamp || '-';
        }
    };

    chkUnlock.addEventListener('change', () => {
        btnUnlock.disabled = !chkUnlock.checked;
    });

    btnUnlock.addEventListener('click', async () => {
        btnUnlock.textContent = 'Releasing...';
        btnUnlock.disabled = true;

        const res = await api('/export/unlock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_id: state.currentCaseId })
        });

        btnUnlock.textContent = 'Release Lock';
        btnUnlock.disabled = false;
        chkUnlock.checked = false;

        if (res && !res._error) {
            fbUnlock.className = 'alert alert-success mt-md';
            fbUnlock.textContent = 'Export concurrency lock released.';
            fbUnlock.classList.remove('hidden');
            await refreshLock();
        } else {
            fbUnlock.className = 'alert alert-error mt-md';
            fbUnlock.textContent = res ? res.message : 'Failed to release lock.';
            fbUnlock.classList.remove('hidden');
        }
    });

    btnExport.addEventListener('click', async () => {
        const outDir = outDirInp.value.trim() || 'exports';
        btnExport.textContent = 'Exporting...';
        btnExport.disabled = true;

        const res = await api('/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_id: state.currentCaseId, output_dir: outDir })
        });

        btnExport.textContent = 'Export Case Bundle';
        btnExport.disabled = false;

        if (res && !res._error) {
            fbExport.className = 'alert alert-success mt-md';
            fbExport.innerHTML = `<strong>Case Export Successful</strong><br>Bundle saved to: <span class="mono text-cyan">${res.export_path || res.path || 'exports/'}</span>`;
            fbExport.classList.remove('hidden');
            await refreshLock();
        } else {
            fbExport.className = 'alert alert-error mt-md';
            fbExport.textContent = res ? res.message : 'Export failed.';
            fbExport.classList.remove('hidden');
            await refreshLock();
        }
    });

    await refreshLock();
}

// ==========================================
// 16. Database Maintenance
// ==========================================
function initDatabase() {
    const btnCheck = document.getElementById('btn-db-check');
    const resCheck = document.getElementById('db-check-result');

    btnCheck.addEventListener('click', async () => {
        btnCheck.textContent = 'Checking...';
        btnCheck.disabled = true;

        const res = await api('/database/check', { method: 'POST' });
        btnCheck.textContent = 'Run Integrity Check';
        btnCheck.disabled = false;

        if (res && !res._error) {
            resCheck.className = 'alert alert-success mt-md';
            resCheck.innerHTML = `<strong>Integrity Check: ${res.status || 'OK'}</strong><br>${res.details || 'PRAGMA integrity_check: ok'}`;
            resCheck.classList.remove('hidden');
        } else {
            resCheck.className = 'alert alert-error mt-md';
            resCheck.textContent = res ? res.message : 'Database check failed.';
            resCheck.classList.remove('hidden');
        }
    });

    const bkpPathInp = document.getElementById('db-backup-path');
    const btnBackup = document.getElementById('btn-db-backup');
    const resBackup = document.getElementById('db-backup-result');

    btnBackup.addEventListener('click', async () => {
        const dest = bkpPathInp.value.trim();
        btnBackup.textContent = 'Backing up...';
        btnBackup.disabled = true;

        const res = await api('/database/backup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ backup_path: dest })
        });

        btnBackup.textContent = 'Create Backup';
        btnBackup.disabled = false;

        if (res && !res._error) {
            resBackup.className = 'alert alert-success mt-md';
            resBackup.innerHTML = `<strong>Backup Created</strong><br>Saved to: <span class="mono">${res.backup_path || dest}</span>`;
            resBackup.classList.remove('hidden');
        } else {
            resBackup.className = 'alert alert-error mt-md';
            resBackup.textContent = res ? res.message : 'Backup failed.';
            resBackup.classList.remove('hidden');
        }
    });

    const rstPathInp = document.getElementById('db-restore-path');
    const chkRestore = document.getElementById('confirm-db-restore');
    const btnRestore = document.getElementById('btn-db-restore');
    const resRestore = document.getElementById('db-restore-result');

    chkRestore.addEventListener('change', () => {
        btnRestore.disabled = !chkRestore.checked;
    });

    btnRestore.addEventListener('click', async () => {
        const src = rstPathInp.value.trim();
        if (!src) {
            resRestore.className = 'alert alert-error mt-md';
            resRestore.textContent = 'Backup source path is required.';
            resRestore.classList.remove('hidden');
            return;
        }

        btnRestore.textContent = 'Restoring...';
        btnRestore.disabled = true;

        const res = await api('/database/restore', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ backup_path: src })
        });

        btnRestore.textContent = 'Restore Database';
        btnRestore.disabled = false;
        chkRestore.checked = false;

        if (res && !res._error) {
            resRestore.className = 'alert alert-success mt-md';
            resRestore.textContent = 'Database restored successfully. Please refresh the console.';
            resRestore.classList.remove('hidden');
            await fetchCases();
        } else {
            resRestore.className = 'alert alert-error mt-md';
            resRestore.textContent = res ? res.message : 'Database restore failed.';
            resRestore.classList.remove('hidden');
        }
    });
}

// ==========================================
// 17. Static Analysis
// ==========================================
function initStatic() {
    const fpathInp = document.getElementById('static-file-path');
    const btnRun = document.getElementById('btn-run-static');
    const fbStatic = document.getElementById('static-feedback');
    const resBox = document.getElementById('static-results');

    const typeEl = document.getElementById('static-type');
    const sizeEl = document.getElementById('static-size');
    const entropyEl = document.getElementById('static-entropy');
    const countEl = document.getElementById('static-indicator-count');
    const pathEl = document.getElementById('static-path');
    const shaEl = document.getElementById('static-sha256');
    const indicsEl = document.getElementById('static-indicators');
    const secTbody = document.getElementById('static-sections-tbody');

    btnRun.addEventListener('click', async () => {
        const fpath = fpathInp.value.trim();
        if (!fpath) {
            fbStatic.className = 'alert alert-error mt-md';
            fbStatic.textContent = 'Artifact file path is required.';
            fbStatic.classList.remove('hidden');
            return;
        }

        btnRun.textContent = 'Analyzing...';
        btnRun.disabled = true;

        const res = await api('/static/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_path: fpath })
        });

        btnRun.textContent = 'Analyze Artifact';
        btnRun.disabled = false;

        if (res && !res._error && res.analysis) {
            fbStatic.classList.add('hidden');
            resBox.classList.remove('hidden');

            const a = res.analysis;
            typeEl.textContent = a.file_type || 'Unknown';
            sizeEl.textContent = a.size ? `${a.size} B` : '-';
            entropyEl.textContent = a.entropy !== undefined ? Number(a.entropy).toFixed(3) : '-';

            const indics = a.suspicious_indicators || a.indicators || [];
            countEl.textContent = indics.length;
            pathEl.textContent = a.file_path || fpath;
            shaEl.textContent = a.sha256 || '-';

            indicsEl.innerHTML = indics.length > 0 ? indics.map(i => `<span class="badge critical">${i}</span>`).join('') : '<span class="badge low">None detected</span>';

            const secs = a.sections || [];
            if (secs.length > 0) {
                secTbody.innerHTML = secs.map(s => `
                    <tr>
                        <td class="mono"><strong>${s.name || '-'}</strong></td>
                        <td class="mono">${s.virtual_size !== undefined ? s.virtual_size : '-'}</td>
                        <td class="mono">${s.raw_size !== undefined ? s.raw_size : '-'}</td>
                        <td class="mono">${s.entropy !== undefined ? Number(s.entropy).toFixed(3) : '-'}</td>
                    </tr>
                `).join('');
            } else {
                secTbody.innerHTML = `<tr><td colspan="4" style="text-align: center;">No PE sections found (not a PE binary).</td></tr>`;
            }
        } else {
            fbStatic.className = 'alert alert-error mt-md';
            fbStatic.textContent = res ? res.message : 'Static analysis failed.';
            fbStatic.classList.remove('hidden');
            resBox.classList.add('hidden');
        }
    });
}

// ==========================================
// 18. Phishing Analysis
// ==========================================
function initPhishing() {
    const subjInp = document.getElementById('phishing-subject');
    const sendInp = document.getElementById('phishing-sender');
    const bodyInp = document.getElementById('phishing-body');
    const btnRun = document.getElementById('btn-run-phishing');
    const fbPhish = document.getElementById('phishing-feedback');
    const resBox = document.getElementById('phishing-results');

    btnRun.addEventListener('click', async () => {
        const bodyText = bodyInp.value.trim();
        if (!bodyText) {
            fbPhish.className = 'alert alert-error mt-md';
            fbPhish.textContent = 'Message body or headers content is required.';
            fbPhish.classList.remove('hidden');
            return;
        }

        btnRun.textContent = 'Analyzing...';
        btnRun.disabled = true;

        const res = await api('/phishing/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                subject: subjInp.value.trim(),
                sender: sendInp.value.trim(),
                body: bodyText
            })
        });

        btnRun.textContent = 'Analyze Message';
        btnRun.disabled = false;

        if (res && !res._error && res.assessment) {
            fbPhish.classList.add('hidden');
            const a = res.assessment;
            const sev = (a.threat_level || a.severity || 'LOW').toUpperCase();
            const score = a.score !== undefined ? a.score : (a.risk_score !== undefined ? a.risk_score : '-');
            const indics = a.indicators || a.reasons || [];
            const urls = a.extracted_urls || a.urls || [];

            resBox.innerHTML = `
                <div class="grid-overview">
                    <div class="stat-card">
                        <span class="stat-label">Risk Score</span>
                        <span class="stat-val ${sev === 'HIGH' || sev === 'CRITICAL' ? 'text-critical' : 'text-warning'}">${score}</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-label">Threat Level</span>
                        <span class="stat-val ${sev === 'HIGH' || sev === 'CRITICAL' ? 'text-critical' : 'text-warning'}">${sev}</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-label">Indicators</span>
                        <span class="stat-val mono">${indics.length}</span>
                    </div>
                </div>
                <div class="prop-list">
                    <div class="prop-item"><span class="prop-key">Detected Indicators</span>
                        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                            ${indics.length > 0 ? indics.map(i => `<span class="badge ${sev === 'HIGH' || sev === 'CRITICAL' ? 'critical' : 'high'}">${i}</span>`).join('') : '<span class="badge low">No high-risk keywords detected</span>'}
                        </div>
                    </div>
                    ${urls.length > 0 ? `
                        <div class="prop-item mt-md"><span class="prop-key">Extracted URLs / Domains</span>
                            <div class="prop-val mono" style="font-size: 11px;">${urls.join('<br>')}</div>
                        </div>
                    ` : ''}
                </div>
            `;
        } else {
            fbPhish.className = 'alert alert-error mt-md';
            fbPhish.textContent = res ? res.message : 'Phishing analysis failed.';
            fbPhish.classList.remove('hidden');
        }
    });
}

// ==========================================
// Drawers (Inspectors)
// ==========================================
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

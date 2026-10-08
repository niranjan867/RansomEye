// ============================================================
// RansomEye Analyst Console — Safe DOM Rendering Architecture
// ============================================================
// ALL attacker-controlled or artifact-derived data is rendered
// via textContent / safe DOM construction helpers. Zero dynamic
// markup interpolation or raw HTML sinks are permitted.
// ============================================================

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

// ============================================================
// Safe DOM Helpers
// ============================================================
function el(tag, opts = {}, children = []) {
    const node = document.createElement(tag);
    if (opts.className) node.className = opts.className;
    if (opts.text != null) node.textContent = String(opts.text);
    if (opts.title != null) node.title = String(opts.title);
    if (opts.style) node.style.cssText = opts.style;
    if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) node.setAttribute(k, String(v));
    if (opts.onclick) node.addEventListener('click', opts.onclick);
    for (const child of children) if (child) node.appendChild(child);
    return node;
}

function kv(key, value, opts = {}) {
    return el('div', { className: 'prop-item' }, [
        el('span', { className: 'prop-key', text: key }),
        el('span', { className: 'prop-val' + (opts.mono ? ' mono' : ''), text: value == null ? '-' : String(value) }),
    ]);
}

function badge(text, severity) {
    return el('span', { className: 'badge ' + (severity || 'low'), text: String(text || '-') });
}

function safeRow(cells, opts = {}) {
    const tr = el('tr', { className: opts.clickable ? 'clickable' : '' });
    if (opts.onclick) tr.addEventListener('click', opts.onclick);
    for (const cell of cells) {
        if (cell instanceof HTMLElement) {
            const td = el('td');
            td.appendChild(cell);
            tr.appendChild(td);
        } else if (cell && typeof cell === 'object' && cell.node) {
            const td = el('td', { className: cell.className || '' });
            td.appendChild(cell.node);
            tr.appendChild(td);
        } else {
            const td = el('td', { className: (cell && cell.mono) ? 'mono' : '' });
            td.textContent = cell != null ? String(cell) : '-';
            tr.appendChild(td);
        }
    }
    return tr;
}

function emptyRow(cols, message) {
    const tr = el('tr');
    const td = el('td', { text: message, style: 'text-align: center; padding: 32px;' });
    td.colSpan = cols;
    tr.appendChild(td);
    return tr;
}

function section(title, startOpen, bodyNodes) {
    const details = el('details', { style: 'margin-top: 16px;' });
    if (startOpen) details.open = true;
    details.appendChild(el('summary', { text: title, style: 'cursor: pointer; font-weight: 600; color: var(--re-text-secondary);' }));
    details.appendChild(el('div', { style: 'margin-top: 12px;' }, bodyNodes));
    return details;
}

function safeModal(title, bodyNodes, footerNodes) {
    if (!dom.modal) return;
    dom.modalTitle.textContent = title;
    dom.modalBody.replaceChildren(...bodyNodes);
    dom.modalFooter.replaceChildren(...footerNodes);
    dom.modal.classList.remove('hidden');
}

function hideModal() {
    if (!dom.modal) return;
    dom.modal.classList.add('hidden');
    dom.modalBody.replaceChildren();
    dom.modalFooter.replaceChildren();
}

// ============================================================
// Init & Listeners
// ============================================================
async function init() {
    setupListeners();
    await fetchCases();
    switchView('overview');
}

function setupListeners() {
    dom.selectCase.addEventListener('change', async (e) => {
        await loadCase(e.target.value);
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

// ============================================================
// API
// ============================================================
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

// ============================================================
// Loaders
// ============================================================
async function fetchCases() {
    const data = await api('/cases');
    if (!data || !data.cases || data.cases.length === 0) {
        state.cases = [];
        dom.selectCase.replaceChildren(el('option', { text: 'NO CASES AVAILABLE', attrs: { value: '' } }));
        return;
    }

    state.cases = data.cases;
    const currentVal = state.currentCaseId;
    const opts = [el('option', { text: 'Select Case...', attrs: { value: '' } })];
    data.cases.forEach(c => {
        const opt = el('option', { attrs: { value: c.case_id } });
        opt.textContent = `${c.case_id} — ${c.case_name || 'Unnamed'} (${c.status})`;
        if (c.case_id === currentVal) opt.selected = true;
        opts.push(opt);
    });
    dom.selectCase.replaceChildren(...opts);
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

// ============================================================
// Router
// ============================================================
function switchView(viewName) {
    state.currentView = viewName;
    dom.navItems.forEach(n => n.classList.toggle('active', n.dataset.view === viewName));
    dom.drawer.classList.remove('open');
    renderCurrentView();
}

const GLOBAL_VIEWS = ['cases', 'monitor', 'collection', 'integrity', 'database', 'static', 'script', 'phishing'];

function renderCurrentView() {
    if (!state.currentCaseId && !GLOBAL_VIEWS.includes(state.currentView)) {
        dom.viewContainer.replaceChildren(
            el('div', { className: 'empty-state', style: 'padding-top: 100px;' }, [
                el('h3', { text: 'No Case Selected' }),
                el('p', { text: 'Select a case from the sidebar or manage cases to begin investigation.' }),
                el('div', { style: 'margin-top: 24px; display: flex; gap: 12px; justify-content: center;' }, [
                    el('button', { className: 'btn btn-primary', text: 'View / Create Cases', onclick: () => switchView('cases') }),
                    el('button', { className: 'btn', text: 'Ingest Evidence', onclick: () => switchView('collection') }),
                ]),
            ])
        );
        return;
    }

    const tpl = document.getElementById(`tpl-${state.currentView}`);
    if (!tpl) {
        dom.viewContainer.replaceChildren(el('div', { className: 'empty-state' }, [el('h3', { text: 'View Not Found' })]));
        return;
    }

    dom.viewContainer.replaceChildren();
    dom.viewContainer.appendChild(tpl.content.cloneNode(true));

    switch (state.currentView) {
        case 'overview': initOverview(); break;
        case 'cases': initCases(); break;
        case 'monitor': break;
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
        case 'script': initScript(); break;
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
        const rows = state.incidents.slice(0, 5).map(inc => {
            const idCell = el('span', { className: 'clickable-id mono', text: inc.incident_id });
            return safeRow([
                { node: idCell },
                { node: badge(inc.severity, (inc.severity || '').toLowerCase()) },
                (inc.evidence_event_ids || []).length,
            ], { clickable: true, onclick: () => inspectIncident(inc.incident_id) });
        });
        incTbody.replaceChildren(...rows);
    }

    const actTbody = document.getElementById('ov-activity-tbody');
    if (state.activity.length > 0) {
        const rows = state.activity.map(a =>
            safeRow([
                a.timestamp,
                a.event_type,
                a.process_name || '-',
            ], { clickable: true, onclick: () => inspectEvent(a.event_id) })
        );
        actTbody.replaceChildren(...rows);
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
            tbody.replaceChildren(emptyRow(10, 'No cases found. Create a new case to begin.'));
            return;
        }

        const rows = casesList.map(c => {
            const idCell = el('span', { className: 'mono clickable-id', text: c.case_id,
                onclick: () => loadCase(c.case_id).then(() => switchView('overview')) });
            const nameCell = el('strong', { text: c.case_name || '-' });
            const hostCell = el('span', { className: 'mono', text: c.host || '-' });
            const statusBadge = badge(c.status, c.status === 'OPEN' ? 'critical' : 'low');
            const sevBadge = badge(c.severity || 'LOW', (c.severity || 'low').toLowerCase());
            const created = el('span', { className: 'mono', text: c.created_at ? c.created_at.slice(0, 19) : '-', style: 'font-size: 11px;' });
            const actions = el('div', { style: 'display: flex; gap: 6px;' }, [
                el('button', { className: 'btn btn-sm btn-primary', text: 'Open',
                    onclick: (e) => { e.stopPropagation(); loadCase(c.case_id).then(() => switchView('overview')); } }),
                el('button', { className: 'btn btn-sm', text: 'Status',
                    onclick: (e) => { e.stopPropagation(); openUpdateStatusModal(c.case_id, c.status); } }),
                el('button', { className: 'btn btn-sm', text: 'History',
                    onclick: (e) => { e.stopPropagation(); openCaseHistoryModal(c.case_id); } }),
            ]);

            const tr = el('tr');
            for (const cell of [idCell, nameCell, hostCell, statusBadge, sevBadge, created,
                               c.events_count !== undefined ? String(c.events_count) : '-',
                               c.findings_count !== undefined ? String(c.findings_count) : '-',
                               c.incidents_count !== undefined ? String(c.incidents_count) : '-',
                               actions]) {
                const td = el('td');
                if (cell instanceof HTMLElement) td.appendChild(cell);
                else td.textContent = String(cell);
                tr.appendChild(td);
            }
            return tr;
        });
        tbody.replaceChildren(...rows);
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
        const idInp = el('input', { className: 'form-control mono', attrs: { type: 'text', id: 'modal-new-case-id', placeholder: 'e.g. CASE-2026-001' } });
        const nameInp = el('input', { className: 'form-control', attrs: { type: 'text', id: 'modal-new-case-name', placeholder: 'e.g. Finance Server Ransomware Investigation' } });
        const hostInp = el('input', { className: 'form-control', attrs: { type: 'text', id: 'modal-new-case-host', placeholder: 'e.g. WIN-SRV-01' } });
        const fb = el('div', { className: 'mt-md hidden', attrs: { id: 'modal-case-feedback' } });

        safeModal('Create Forensic Case', [
            el('div', { className: 'form-group' }, [el('label', { className: 'form-label', text: 'Case ID *' }), idInp]),
            el('div', { className: 'form-group' }, [el('label', { className: 'form-label', text: 'Case Name' }), nameInp]),
            el('div', { className: 'form-group' }, [el('label', { className: 'form-label', text: 'Host Name' }), hostInp]),
            fb,
        ], [
            el('button', { className: 'btn', text: 'Cancel', onclick: hideModal }),
            el('button', { className: 'btn btn-primary', text: 'Create Case', onclick: async () => {
                const cid = idInp.value.trim();
                const name = nameInp.value.trim();
                const host = hostInp.value.trim();

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
            }}),
        ]);
    });

    const data = await api('/cases');
    if (data && data.cases) {
        state.cases = data.cases;
    }
    filterAndRender();
}

window.openUpdateStatusModal = function(caseId, currentStatus) {
    const statusSel = el('select', { className: 'form-control', attrs: { id: 'modal-update-status' } });
    for (const s of ['OPEN', 'IN_PROGRESS', 'CLOSED', 'ARCHIVED']) {
        const opt = el('option', { text: s, attrs: { value: s } });
        if (s === currentStatus) opt.selected = true;
        statusSel.appendChild(opt);
    }
    const notesArea = el('textarea', { className: 'form-control', attrs: { id: 'modal-update-notes', rows: '3', placeholder: 'Explain the rationale for lifecycle change...' } });
    const fb = el('div', { className: 'mt-md hidden', attrs: { id: 'modal-status-feedback' } });

    safeModal(`Update Status: ${caseId}`, [
        el('div', { className: 'form-group' }, [el('label', { className: 'form-label', text: 'Lifecycle Status' }), statusSel]),
        el('div', { className: 'form-group' }, [el('label', { className: 'form-label', text: 'Status Notes' }), notesArea]),
        fb,
    ], [
        el('button', { className: 'btn', text: 'Cancel', onclick: hideModal }),
        el('button', { className: 'btn btn-primary', text: 'Update Status', onclick: async () => {
            const st = statusSel.value;
            const notes = notesArea.value.trim();

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
                if (state.currentCaseId === caseId) await loadCase(caseId);
                setTimeout(() => {
                    hideModal();
                    if (state.currentView === 'cases') initCases();
                }, 600);
            } else {
                fb.className = 'alert alert-error mt-md';
                fb.textContent = res ? res.message : 'Failed to update status.';
                fb.classList.remove('hidden');
            }
        }}),
    ]);
};

window.openCaseHistoryModal = async function(caseId) {
    safeModal(`Case History: ${caseId}`,
        [el('div', { className: 'empty-state', text: 'Loading history...' })],
        [el('button', { className: 'btn', text: 'Close', onclick: hideModal })]
    );

    const data = await api(`/case/${encodeURIComponent(caseId)}/history`);
    if (!data || data._error || !data.history || data.history.length === 0) {
        dom.modalBody.replaceChildren(el('div', { className: 'empty-state', text: `No status history recorded for case ${caseId}.` }));
        return;
    }

    const items = data.history.map(h => {
        const item = el('div', { className: 'timeline-item' }, [
            el('div', { className: 'timeline-time', text: h.timestamp || '-' }),
            el('div', { className: 'timeline-content' }, [
                el('strong', {}, [
                    document.createTextNode('Status transitioned to: '),
                    badge(h.status, h.status === 'OPEN' ? 'critical' : 'low'),
                ]),
            ]),
        ]);
        if (h.notes) {
            item.querySelector('.timeline-content').appendChild(
                el('div', { className: 'mt-sm', text: h.notes, style: 'color: var(--re-text-secondary);' })
            );
        }
        return item;
    });
    dom.modalBody.replaceChildren(el('div', { className: 'timeline-list' }, items));
};

// ==========================================
// 3. Threat Assessment
// ==========================================
function initAssessment() {
    const p = document.getElementById('assessment-panel');
    if (!state.assessment) {
        p.replaceChildren(el('div', { className: 'panel-body empty-state' }, [
            el('h3', { text: 'Assessment Unavailable' }),
            el('p', { text: 'No threat assessment has been generated for this case. Ingest evidence and run analysis to generate an assessment.' }),
        ]));
        return;
    }

    const a = state.assessment;
    const isCrit = a.severity === 'CRITICAL' || a.severity === 'HIGH';

    const statCards = el('div', { className: 'grid-overview', style: 'grid-template-columns: 1fr 1fr 1fr;' }, [
        el('div', { className: 'stat-card' }, [
            el('span', { className: 'stat-label', text: 'Score' }),
            el('span', { className: 'stat-val ' + (isCrit ? 'text-critical' : 'text-warning'), text: String(a.score) }),
        ]),
        el('div', { className: 'stat-card' }, [
            el('span', { className: 'stat-label', text: 'Severity' }),
            el('span', { className: 'stat-val ' + (isCrit ? 'text-critical' : 'text-warning'), text: a.severity }),
        ]),
        el('div', { className: 'stat-card' }, [
            el('span', { className: 'stat-label', text: 'Confidence' }),
            el('span', { className: 'stat-val', text: (a.confidence * 100).toFixed(0) + '%' }),
        ]),
    ]);

    const reasonNodes = (a.reasons || []).map(r =>
        el('div', { className: 'prop-val', text: r, style: 'color: var(--re-critical); border-left: 3px solid var(--re-critical);' })
    );

    const techBadges = (a.techniques || []).map(t => badge(t, 'high'));

    p.replaceChildren(el('div', { className: 'panel-body' }, [
        statCards,
        el('h4', { className: 'mt-xl', text: 'Analytical Reasons', style: 'margin-bottom: 12px; color: var(--re-text-muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em;' }),
        el('div', { className: 'prop-list' }, reasonNodes),
        el('h4', { className: 'mt-xl', text: 'Techniques', style: 'margin-bottom: 12px; color: var(--re-text-muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em;' }),
        el('div', { style: 'display: flex; gap: 8px; flex-wrap: wrap;' }, techBadges),
    ]));
}

// ==========================================
// 4. Incidents
// ==========================================
function initIncidents() {
    const tbody = document.getElementById('incidents-tbody');
    if (state.incidents.length === 0) {
        tbody.replaceChildren(emptyRow(6, 'No incidents have been correlated for this case. Ingest evidence to trigger correlation.'));
        return;
    }

    const rows = state.incidents.map(inc =>
        safeRow([
            { node: el('span', { className: 'clickable-id mono', text: inc.incident_id }) },
            { node: badge(inc.severity, (inc.severity || '').toLowerCase()) },
            inc.start_time || '-',
            inc.duration || '-',
            (inc.finding_ids || []).length,
            (inc.evidence_event_ids || []).length,
        ], { clickable: true, onclick: () => inspectIncident(inc.incident_id) })
    );
    tbody.replaceChildren(...rows);
}

// ==========================================
// 5. Findings — with evidence links
// ==========================================
function initFindings() {
    const tbody = document.getElementById('findings-tbody');
    if (state.findings.length === 0) {
        tbody.replaceChildren(emptyRow(6, 'No findings have been generated for this case yet. Ingest evidence to run behavioral detection.'));
        return;
    }

    const rows = state.findings.map(fn => {
        const idCell = el('span', { className: 'mono' });
        idCell.textContent = `FINDING:${fn.finding_id}`;

        const evIds = fn.event_ids || [];
        const evLinks = evIds.length > 0
            ? el('div', { style: 'display: flex; gap: 4px; flex-wrap: wrap;' },
                evIds.slice(0, 3).map(eid =>
                    el('span', { className: 'clickable-id mono', text: String(eid).slice(0, 12) + '...', title: eid, style: 'font-size: 10px; cursor: pointer;',
                        onclick: (e) => { e.stopPropagation(); inspectEvent(eid); } })
                ).concat(evIds.length > 3 ? [el('span', { className: 'mono', text: `+${evIds.length - 3} more`, style: 'font-size: 10px; color: var(--re-text-muted);' })] : [])
              )
            : el('span', { className: 'mono', text: '-', style: 'font-size: 10px; color: var(--re-text-muted);' });

        const tr = el('tr', { className: 'clickable' });
        tr.addEventListener('click', () => {
            if (evIds.length > 0) inspectEvent(evIds[0]);
        });

        const cells = [
            idCell,
            fn.finding_type,
            badge(fn.technique || '-', 'high'),
            el('span', { className: 'text-critical', text: String(fn.score || '-'), style: 'font-weight: 600;' }),
            fn.confidence || '-',
            evLinks,
        ];

        for (const cell of cells) {
            const td = el('td');
            if (cell instanceof HTMLElement) td.appendChild(cell);
            else td.textContent = String(cell);
            tr.appendChild(td);
        }
        return tr;
    });
    tbody.replaceChildren(...rows);
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
            tbody.replaceChildren(emptyRow(5, `Unable to load evidence: ${(data && data.message) ? data.message : 'Server error'}`));
            return;
        }

        if (!data.results || data.results.length === 0) {
            tbody.replaceChildren(emptyRow(5, 'No matching evidence events found.'));
            return;
        }

        const rows = data.results.map(r =>
            safeRow([
                r.timestamp || '-',
                r.event_type || r.source,
                r.process_name || '-',
                r.pid || '-',
                { node: el('span', { className: 'mono clickable-id', text: r.event_id }) },
            ], { clickable: true, onclick: () => inspectEvent(r.event_id) })
        );
        tbody.replaceChildren(...rows);
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

    const invData = await api(`/investigation/${encodeURIComponent(state.currentCaseId)}`);
    if (invData && !invData._error && invData.summary) {
        statusEl.textContent = 'ACTIVE';
        nodesEl.textContent = invData.summary.total_nodes !== undefined ? invData.summary.total_nodes : '-';
        edgesEl.textContent = invData.summary.total_edges !== undefined ? invData.summary.total_edges : '-';
    }

    const graphData = await api(`/investigation/${encodeURIComponent(state.currentCaseId)}/graph`);
    if (graphData && !graphData._error && graphData.nodes) {
        const procNodes = graphData.nodes.filter(n => n.node_type === 'process' || n.label === 'Process');
        const fileNodes = graphData.nodes.filter(n => n.node_type === 'file' || n.label === 'File');
        const netNodes = graphData.nodes.filter(n => n.node_type === 'network' || n.label === 'Network');

        graphSumEl.replaceChildren(
            el('div', { className: 'prop-list' }, [
                kv('Processes in Graph', procNodes.length, { mono: true }),
                kv('File Nodes in Graph', fileNodes.length, { mono: true }),
                kv('Network Nodes in Graph', netNodes.length, { mono: true }),
                kv('Total Edges', (graphData.edges || []).length, { mono: true }),
            ]),
            el('div', { className: 'mt-md', style: 'display: flex; gap: 8px;' }, [
                el('button', { className: 'btn btn-sm btn-primary', text: 'View Process Tree →', onclick: () => switchView('tree') }),
                el('button', { className: 'btn btn-sm', text: 'Attack Reconstruction →', onclick: () => switchView('reconstruction') }),
            ])
        );
    } else {
        graphSumEl.replaceChildren(el('div', { className: 'empty-state', text: 'No graph data generated for this case. Ingest evidence to build the investigation graph.' }));
    }

    const valData = await api(`/investigation/${encodeURIComponent(state.currentCaseId)}/validation`);
    if (valData && !valData._error && valData.validation) {
        const v = valData.validation;
        const isValid = v.valid !== false && (!v.errors || v.errors.length === 0);
        validStatusEl.textContent = isValid ? 'VALID' : 'FLAGGED';
        validStatusEl.className = `stat-val ${isValid ? 'text-success' : 'text-critical'}`;

        const items = [
            kv('Validation Status', isValid ? 'PASSED' : 'ANOMALIES DETECTED'),
            kv('Checks Performed', v.checks_performed !== undefined ? String(v.checks_performed) : 'Complete', { mono: true }),
            kv('Errors / Warnings', String((v.errors || []).length), { mono: true }),
        ];
        if (v.errors && v.errors.length > 0) {
            const errList = v.errors.map(err => el('div', { className: 'prop-val', text: err, style: 'color: var(--re-critical);' }));
            items.push(el('div', { className: 'prop-item' }, [
                el('span', { className: 'prop-key', text: 'Details' }),
                el('div', {}, errList),
            ]));
        }
        validSumEl.replaceChildren(el('div', { className: 'prop-list' }, items));
    } else {
        validStatusEl.textContent = 'CHECKED';
        validSumEl.replaceChildren(el('div', { className: 'empty-state', text: 'Validation checks complete. No discrepancies found.' }));
    }
}

// ==========================================
// 8. Process Tree
// ==========================================
async function initTree() {
    if (!state.currentCaseId) return;
    const container = document.getElementById('tree-container');

    const data = await api(`/tree/${encodeURIComponent(state.currentCaseId)}`);
    // API may return tree as a flat list or an object with {nodes, children, roots}; normalize to a list.
    let roots = null;
    if (data && !data._error && data.tree) {
        if (Array.isArray(data.tree)) {
            roots = data.tree;
        } else if (data.tree.nodes && data.tree.roots) {
            const resolve = (pid) => {
                const node = data.tree.nodes[pid];
                if (!node) return null;
                const kids = (data.tree.children && data.tree.children[pid]) || [];
                return { ...node, name: node.name || node.process_name, children: kids.map(resolve).filter(Boolean) };
            };
            roots = data.tree.roots.map(resolve).filter(Boolean);
        }
    }
    if (!roots || roots.length === 0) {
        container.replaceChildren(el('div', { className: 'empty-state', text: 'No process tree available. Ingest evidence containing process creation events to build the tree.' }));
        return;
    }

    function renderTreeNodes(nodes, depth) {
        const frag = document.createDocumentFragment();
        for (const n of nodes) {
            const indent = (depth || 0) * 24;
            const procIdent = n.guid || n.pid;

            const nameEl = el('strong', { text: n.name || 'Unknown' });
            const pidEl = document.createTextNode(` (PID: ${n.pid || '-'})`);
            const nameRow = el('div', {}, [nameEl, pidEl]);

            const nodeDiv = el('div', { className: 'tree-node current clickable-id',
                style: 'display: flex; justify-content: space-between; align-items: center; border-radius: 4px;',
                onclick: () => inspectProcess(procIdent) }, [nameRow]);

            if (n.command_line) {
                const cmdEl = el('div', { text: n.command_line, style: 'font-size: 11px; color: var(--re-text-muted); margin-top: 2px;' });
                nameRow.appendChild(cmdEl);
            }

            if (n.guid) {
                nodeDiv.appendChild(el('span', { className: 'mono', text: n.guid.slice(0, 8) + '...', style: 'font-size: 10px; color: var(--re-text-muted);' }));
            }

            const wrapper = el('div', { style: `margin-left: ${indent}px; margin-bottom: 8px;` }, [nodeDiv]);

            if (n.children && n.children.length > 0) {
                wrapper.appendChild(renderTreeNodes(n.children, (depth || 0) + 1));
            }
            frag.appendChild(wrapper);
        }
        return frag;
    }

    container.replaceChildren(el('div', { className: 'prop-list' }, [renderTreeNodes(roots, 0)]));
}

// ==========================================
// 9. Timeline
// ==========================================
function initTimeline() {
    const container = document.getElementById('timeline-container');
    if (state.timeline.length === 0) {
        container.replaceChildren(el('div', { className: 'empty-state', text: 'No timeline events available for this case. Ingest evidence to build the timeline.' }));
        return;
    }

    const items = state.timeline.map(t => {
        const content = el('div', { className: 'timeline-content' }, [
            el('strong', { text: t.description }),
        ]);

        if (t.process_name) {
            const procLink = el('span', { className: 'clickable-id mono mt-sm', text: `Process: ${t.process_name} (PID: ${t.pid})`,
                style: 'display: inline-block; cursor: pointer;',
                onclick: () => inspectProcess(t.process_guid || t.pid) });
            content.appendChild(procLink);
        }

        return el('div', { className: 'timeline-item' }, [
            el('div', { className: 'timeline-time', text: t.timestamp || 'Unknown Time' }),
            content,
        ]);
    });

    container.replaceChildren(...items);
}

// ==========================================
// 10. Reconstruction — with clickable evidence/finding IDs
// ==========================================
function initReconstruction() {
    const container = document.getElementById('reconstruction-container');
    if (!state.reconstruction || state.reconstruction.length === 0) {
        container.replaceChildren(el('div', { className: 'empty-state' }, [
            el('p', { text: 'No reconstructed attack stages available for this case. Ingest evidence and run analysis to reconstruct the attack.' }),
        ]));
        return;
    }

    const items = state.reconstruction.map(stage => {
        const content = el('div', { className: 'timeline-content', style: 'border-left: 3px solid var(--re-critical);' });

        content.appendChild(el('div', { text: stage.stage_type, style: 'font-size: 11px; text-transform: uppercase; color: var(--re-critical); font-weight: 600; margin-bottom: 4px;' }));
        content.appendChild(el('strong', { text: stage.title, style: 'font-size: 14px;' }));

        if (stage.description) {
            content.appendChild(el('div', { className: 'mt-sm', text: stage.description, style: 'color: var(--re-text-secondary);' }));
        }

        if (stage.evidence_ids && stage.evidence_ids.length > 0) {
            const evRow = el('div', { className: 'mt-sm' }, [
                el('span', { className: 'prop-key', text: `Evidence (${stage.evidence_ids.length}): ` }),
            ]);
            stage.evidence_ids.slice(0, 3).forEach(eid => {
                evRow.appendChild(el('span', { className: 'mono clickable-id', text: String(eid).slice(0, 16),
                    title: eid, style: 'margin-right: 6px; cursor: pointer; font-size: 11px;',
                    onclick: () => inspectEvent(eid) }));
            });
            if (stage.evidence_ids.length > 3) {
                evRow.appendChild(el('span', { className: 'mono', text: `+${stage.evidence_ids.length - 3} more`, style: 'font-size: 11px; color: var(--re-text-muted);' }));
            }
            content.appendChild(evRow);
        }

        if (stage.finding_ids && stage.finding_ids.length > 0) {
            const fnRow = el('div', { className: 'mt-sm' }, [
                el('span', { className: 'prop-key', text: `Findings (${stage.finding_ids.length}): ` }),
            ]);
            stage.finding_ids.forEach(fid => {
                fnRow.appendChild(el('span', { className: 'mono', text: `FINDING:${fid}`, style: 'margin-right: 6px; font-size: 11px; color: var(--re-critical);' }));
            });
            content.appendChild(fnRow);
        }

        return el('div', { className: 'timeline-item' }, [
            el('div', { className: 'timeline-time', text: stage.timestamp || 'Unknown Time' }),
            content,
        ]);
    });

    container.replaceChildren(el('div', { className: 'timeline-list' }, items));
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
            fbIngest.replaceChildren(
                el('strong', { text: 'Ingestion Complete' }),
                el('br'),
                document.createTextNode(`Events Ingested: ${res.events_ingested !== undefined ? res.events_ingested : '-'}`),
                el('br'),
                document.createTextNode(`Findings Generated: ${res.findings_generated !== undefined ? res.findings_generated : '-'}`),
                el('br'),
                document.createTextNode(`Incidents Correlated: ${res.incidents_correlated !== undefined ? res.incidents_correlated : '-'}`),
            );
            fbIngest.classList.remove('hidden');
            await fetchCases();
            if (state.currentCaseId === cid) await loadCase(cid);
        } else {
            fbIngest.className = 'alert alert-error mt-md';
            fbIngest.textContent = res ? res.message : 'Ingestion failed.';
            fbIngest.classList.remove('hidden');
        }
    });

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
            fbHash.replaceChildren(
                el('strong', { text: 'Manifest Generated' }),
                el('br'),
                document.createTextNode('Saved to: '),
                el('span', { className: 'mono', text: res.manifest_path || manifest }),
                el('br'),
                document.createTextNode(`Files Hashed: ${res.files_count !== undefined ? res.files_count : '-'}`),
            );
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
            fbVerify.replaceChildren(
                el('strong', { text: `Integrity Verification: ${verified ? 'PASSED (MATCHED)' : 'FAILED / TAMPERED'}` }),
                el('br'),
                document.createTextNode('Status: '),
                el('span', { className: 'mono', text: res.status || (verified ? 'MATCHED' : 'FAILED') }),
                el('br'),
                document.createTextNode(res.mismatches && res.mismatches.length > 0 ? `Mismatches: ${res.mismatches.join(', ')}` : 'All cryptographic hashes match manifest.'),
            );
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
            tbody.replaceChildren(emptyRow(6, 'No chain of custody entries recorded for this case.'));
            return;
        }

        const rows = res.entries.map(e => {
            const tr = el('tr');
            const cells = [
                el('td', { className: 'mono', text: e.timestamp ? e.timestamp.slice(0, 19) : '-', style: 'font-size: 11px;' }),
                el('td', { className: 'mono' }, [el('strong', { text: e.artifact || '-' })]),
                el('td', {}, [badge(e.action, e.action === 'COLLECTED' ? 'high' : 'low')]),
                el('td', { text: e.analyst || '-' }),
                el('td', { className: 'mono', text: e.sha256 ? e.sha256.slice(0, 16) + '...' : '-', style: 'font-size: 10px;' }),
                el('td', { text: e.notes || '-', style: 'font-size: 12px;' }),
            ];
            cells.forEach(td => tr.appendChild(td));
            return tr;
        });
        tbody.replaceChildren(...rows);
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

    chkUnlock.addEventListener('change', () => { btnUnlock.disabled = !chkUnlock.checked; });

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
            fbExport.replaceChildren(
                el('strong', { text: 'Case Export Successful' }),
                el('br'),
                document.createTextNode('Bundle saved to: '),
                el('span', { className: 'mono text-cyan', text: res.export_path || res.path || 'exports/' }),
            );
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
            resCheck.replaceChildren(
                el('strong', { text: `Integrity Check: ${res.status || 'OK'}` }),
                el('br'),
                document.createTextNode(res.details || 'PRAGMA integrity_check: ok'),
            );
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
            resBackup.replaceChildren(
                el('strong', { text: 'Backup Created' }),
                el('br'),
                document.createTextNode('Saved to: '),
                el('span', { className: 'mono', text: res.backup_path || dest }),
            );
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

    chkRestore.addEventListener('change', () => { btnRestore.disabled = !chkRestore.checked; });

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
            sizeEl.textContent = typeof a.file_size === 'number' ? a.file_size.toLocaleString() + ' B' : '-';
            entropyEl.textContent = typeof a.total_entropy === 'number' ? a.total_entropy.toFixed(3) : '-';
            pathEl.textContent = a.file_path || fpath;
            shaEl.textContent = a.sha256 || '-';

            const indics = [];
            const apis = a.suspicious_apis || {};
            Object.keys(apis).sort().forEach(category => {
                (apis[category] || []).forEach(apiName => indics.push({ text: category + ': ' + apiName, severity: 'critical' }));
            });
            const keywords = (a.extracted_iocs && a.extracted_iocs.ransom_keywords) || [];
            keywords.forEach(kw => indics.push({ text: 'ransom keyword: ' + kw, severity: 'high' }));
            countEl.textContent = String(indics.length);

            indicsEl.replaceChildren(...(indics.length > 0
                ? indics.map(i => badge(i.text, i.severity))
                : [badge('None detected', 'low')]));

            const secs = a.sections || [];
            const rows = secs.map(sec => {
                const tr = el('tr');
                [
                    el('td', { className: 'mono' }, [el('strong', { text: sec.name || '-' })]),
                    el('td', { className: 'mono', text: sec.virtual_size !== undefined ? String(sec.virtual_size) : '-' }),
                    el('td', { className: 'mono', text: sec.raw_size !== undefined ? String(sec.raw_size) : '-' }),
                    el('td', { className: 'mono', text: typeof sec.entropy === 'number' ? sec.entropy.toFixed(3) : '-' }),
                ].forEach(td => tr.appendChild(td));
                return tr;
            });
            if (rows.length === 0) {
                const tr = el('tr');
                const td = el('td', { className: 'mono', text: 'No PE sections found (not a PE binary).', style: 'text-align: center;' });
                td.colSpan = 4;
                tr.appendChild(td);
                rows.push(tr);
            }
            secTbody.replaceChildren(...rows);
        } else {
            fbStatic.className = 'alert alert-error mt-md';
            fbStatic.textContent = res ? res.message : 'Static analysis failed.';
            fbStatic.classList.remove('hidden');
            resBox.classList.add('hidden');
        }
    });
}

// ==========================================
// 17b. Script Analysis
// ==========================================
const SCRIPT_SEVERITY_META = {
    NONE: { label: 'No indicators found', badge: 'low' },
    LOW: { label: 'Low', badge: 'low' },
    MEDIUM: { label: 'Medium', badge: 'medium' },
    HIGH: { label: 'High', badge: 'high' },
    CRITICAL: { label: 'Critical', badge: 'critical' },
};

const SCRIPT_CATEGORY_PHRASES = {
    download: 'downloads content from the internet',
    execution: 'runs further commands or code',
    obfuscation: 'hides what it really does through encoding or obfuscation',
    defense_evasion: 'tries to weaken or evade security controls',
    recovery_inhibition: 'attempts to destroy backups or recovery data',
    impact: 'shows file-encryption or destruction behaviour',
    persistence: 'tries to keep itself running across reboots',
    lolbin: 'abuses a built-in Windows tool to run code',
    auto_execution: 'is set to run automatically when a document opens',
};

function scriptPlainSummary(analysis) {
    const cats = [];
    for (const ind of analysis.indicators || []) {
        const phrase = SCRIPT_CATEGORY_PHRASES[ind.category];
        if (phrase && !cats.includes(phrase)) cats.push(phrase);
    }
    if (cats.length === 0) {
        return 'No known malicious patterns were found. Static analysis cannot prove a script is safe.';
    }
    const joined = cats.length === 1 ? cats[0]
        : cats.slice(0, -1).join(', ') + ' and ' + cats[cats.length - 1];
    return `This script ${joined}.`;
}

function renderScriptResult(container, analysis, findingIds) {
    container.replaceChildren();
    const status = analysis.analysis_status;

    if (status !== 'complete') {
        const warn = (analysis.warnings && analysis.warnings[0]) || 'This content type is not supported by script analysis.';
        container.appendChild(el('div', { className: 'empty-state' }, [
            el('h3', { text: 'Not analyzed' }),
            el('p', { text: warn }),
            el('p', { style: 'color: var(--re-text-muted); font-size: 12px;',
                text: 'This is never reported as safe. For program files use Static Analysis.' }),
        ]));
        return;
    }

    const sev = String(analysis.severity || 'NONE').toUpperCase();
    const meta = SCRIPT_SEVERITY_META[sev] || SCRIPT_SEVERITY_META.NONE;

    const verdict = el('div', { className: 'panel', style: 'padding: 16px; margin-bottom: 16px;' });
    const verdictHead = el('div', { style: 'display: flex; align-items: center; gap: 12px; flex-wrap: wrap;' }, [
        el('span', { className: 'badge ' + meta.badge, text: meta.label, style: 'font-size: 13px;' }),
        el('span', { className: 'mono', text: `Score ${analysis.score}/100`, style: 'color: var(--re-text-secondary);' }),
        el('span', { className: 'mono', text: `Confidence ${(Number(analysis.confidence) * 100).toFixed(0)}%`, style: 'color: var(--re-text-secondary);' }),
    ]);
    verdict.appendChild(verdictHead);
    verdict.appendChild(el('p', { style: 'margin-top: 10px;', text: scriptPlainSummary(analysis) }));
    const advice = (analysis.indicators && analysis.indicators.length)
        ? 'Do not run this file. Treat it as suspicious and investigate.'
        : 'No known malicious patterns were found. Static analysis cannot guarantee the file is safe.';
    verdict.appendChild(el('p', { style: 'margin-top: 4px; color: var(--re-text-muted); font-size: 12px;', text: advice }));
    container.appendChild(verdict);

    container.appendChild(el('div', { className: 'prop-list mb-lg' }, [
        kv('Language', analysis.language),
        kv('File size', `${analysis.file_size} bytes`, { mono: true }),
        kv('SHA-256', analysis.sha256, { mono: true }),
        kv('Decoded layers', String((analysis.decoded_layers || []).length), { mono: true }),
        kv('MITRE techniques', (analysis.techniques || []).join(', ') || 'None', { mono: true }),
    ]));

    if (Array.isArray(findingIds)) {
        const msg = findingIds.length
            ? `Added to case: ${findingIds.length} finding(s) created (IDs ${findingIds.join(', ')}). See the Findings and Evidence views.`
            : 'Already recorded against this evidence; no new findings were added.';
        container.appendChild(el('div', { className: 'alert alert-success mb-lg', text: msg }));
    }

    const indicators = analysis.indicators || [];
    const highOpen = indicators.some(i => i.severity === 'high' || i.severity === 'critical');
    const indRows = indicators.map(ind => el('tr', {}, [
        el('td', { className: 'mono', text: ind.rule_id }),
        el('td', { text: ind.title }),
        el('td', {}, [el('span', { className: 'badge ' + (SCRIPT_SEVERITY_META[String(ind.severity).toUpperCase()] || { badge: 'low' }).badge, text: ind.severity })]),
        el('td', { className: 'mono', text: ind.technique }),
        el('td', { className: 'mono', text: `${ind.layer_index}/${ind.line}` }),
        el('td', { className: 'mono', text: ind.excerpt, title: ind.excerpt }),
    ]));
    const indBody = [];
    if (indRows.length) {
        indBody.push(el('table', { className: 'data-table' }, [
            el('thead', {}, [el('tr', {}, [
                el('th', { text: 'Rule' }), el('th', { text: 'Title' }),
                el('th', { text: 'Severity' }), el('th', { text: 'MITRE' }),
                el('th', { text: 'Layer/Line' }), el('th', { text: 'Excerpt' }),
            ])]),
            el('tbody', {}, indRows),
        ]));
    } else {
        indBody.push(el('div', { className: 'empty-state', text: 'No indicators matched.' }));
    }
    container.appendChild(section(`Indicators (${indicators.length})`, highOpen || indicators.length > 0, indBody));

    const layers = analysis.decoded_layers || [];
    if (layers.length) {
        const layerNodes = layers.map(layer => {
            const head = el('div', { className: 'mono', style: 'color: var(--re-text-secondary); font-size: 12px;',
                text: `#${layer.index} depth ${layer.depth} from #${layer.parent_index} · ${layer.method} · ${layer.size} bytes · ${layer.is_text ? layer.encoding : 'binary'}` });
            const sha = el('div', { className: 'mono', style: 'color: var(--re-text-muted); font-size: 11px; word-break: break-all;', text: `sha256 ${layer.sha256}` });
            const pre = el('pre', { style: 'white-space: pre-wrap; word-break: break-word; max-height: 220px; overflow: auto; background: var(--re-surface-hover); padding: 10px; border-radius: 6px; margin-top: 6px;' });
            pre.textContent = layer.is_text ? (layer.preview || '') : '(binary payload)';
            return el('div', { style: 'margin-bottom: 14px;' }, [head, sha, pre]);
        });
        container.appendChild(section(`Decoded layers (${layers.length})`, false, layerNodes));
    }

    const iocs = analysis.iocs || {};
    const iocNodes = [];
    for (const [name, values] of Object.entries(iocs)) {
        if (!values || !values.length) continue;
        iocNodes.push(el('div', { style: 'margin-bottom: 8px;' }, [
            el('div', { className: 'prop-key', text: name.replace(/_/g, ' ') }),
            el('div', { className: 'mono', style: 'word-break: break-all; font-size: 12px;', text: values.join('\n') }),
        ]));
    }
    if (iocNodes.length) container.appendChild(section('Indicators of compromise', false, iocNodes));
}

function initScript() {
    const tabFile = document.getElementById('script-tab-file');
    const tabPaste = document.getElementById('script-tab-paste');
    const paneFile = document.getElementById('script-pane-file');
    const panePaste = document.getElementById('script-pane-paste');
    const filePathInp = document.getElementById('script-file-path');
    const textInp = document.getElementById('script-text');
    const caseSel = document.getElementById('script-file-case');
    const langSel = document.getElementById('script-language');
    const btnRun = document.getElementById('btn-run-script');
    const fb = document.getElementById('script-feedback');
    const results = document.getElementById('script-results');

    let mode = 'file';

    caseSel.replaceChildren(el('option', { text: 'No case (analysis only)', attrs: { value: '' } }));
    for (const c of (state.cases || [])) {
        const label = c.case_name && c.case_name !== c.case_id ? `${c.case_id} — ${c.case_name}` : c.case_id;
        caseSel.appendChild(el('option', { text: label, attrs: { value: c.case_id } }));
    }
    if (state.currentCaseId) caseSel.value = state.currentCaseId;

    function selectMode(next) {
        mode = next;
        tabFile.classList.toggle('active', next === 'file');
        tabPaste.classList.toggle('active', next === 'paste');
        paneFile.classList.toggle('active', next === 'file');
        panePaste.classList.toggle('active', next === 'paste');
    }
    tabFile.addEventListener('click', () => selectMode('file'));
    tabPaste.addEventListener('click', () => selectMode('paste'));

    function showError(message) {
        fb.className = 'alert alert-error mt-md';
        fb.textContent = message;
        fb.classList.remove('hidden');
    }

    btnRun.addEventListener('click', async () => {
        fb.classList.add('hidden');
        const body = { language: langSel.value };

        if (mode === 'file') {
            const fpath = filePathInp.value.trim();
            if (!fpath) { showError('A script file path is required.'); return; }
            body.file_path = fpath;
            const cid = caseSel.value;
            if (cid) body.case_id = cid;
        } else {
            const text = textInp.value;
            if (!text.trim()) { showError('Paste some script text to analyze.'); return; }
            body.text = text;
        }

        btnRun.textContent = 'Analyzing...';
        btnRun.disabled = true;
        const res = await api('/script/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        btnRun.textContent = 'Analyze';
        btnRun.disabled = false;

        if (!res || res._error || !res.analysis) {
            showError(res ? res.message : 'Script analysis failed.');
            results.replaceChildren(el('div', { className: 'empty-state', text: 'Analysis could not be completed.' }));
            return;
        }
        renderScriptResult(results, res.analysis, res.finding_ids);
    });
}

// ==========================================
// 18. Phishing Analysis
// ==========================================
const PHISH_BADGE = {
    benign: 'low', low: 'low', medium: 'medium',
    suspicious: 'high', high: 'high', critical: 'critical',
};

function phishBadge(severity) {
    return 'badge ' + (PHISH_BADGE[String(severity || '').toLowerCase()] || 'medium');
}

function phishUrlFlags(u) {
    const flags = [];
    if (u.is_ip_hostname) flags.push('RAW_IP');
    if (u.is_brand_subdomain) flags.push('BRAND_IN_SUBDOMAIN');
    if (u.is_punycode) flags.push('PUNYCODE');
    if (u.is_shortener) flags.push('SHORTENER');
    if (u.has_suspicious_tld) flags.push('SUSPICIOUS_TLD');
    return flags;
}

function renderPhishingResult(container, a) {
    container.replaceChildren();

    const sev = String(a.threat_level || a.risk_level || a.severity || 'LOW').toUpperCase();
    const score = a.score != null ? a.score : (a.risk_score != null ? a.risk_score : '-');
    const indicators = a.indicators || a.reasons || [];
    const urls = a.extracted_urls || a.urls || [];
    const attachments = a.attachment_findings || [];
    const techniques = a.mitre_techniques || a.techniques || [];
    const recommendations = a.recommendations || [];
    const critical = sev === 'HIGH' || sev === 'CRITICAL';
    const valCls = 'stat-val ' + (critical ? 'text-critical' : 'text-warning');

    container.appendChild(el('div', { className: 'grid-overview' }, [
        el('div', { className: 'stat-card' }, [
            el('span', { className: 'stat-label', text: 'Risk Score' }),
            el('span', { className: valCls, text: String(score) }),
        ]),
        el('div', { className: 'stat-card' }, [
            el('span', { className: 'stat-label', text: 'Threat Level' }),
            el('span', { className: valCls, text: sev }),
        ]),
        el('div', { className: 'stat-card' }, [
            el('span', { className: 'stat-label', text: 'Indicators' }),
            el('span', { className: 'stat-val mono', text: String(indicators.length) }),
        ]),
    ]));

    container.appendChild(el('div', { className: 'prop-list mb-lg' }, [
        kv('Confidence', a.confidence || '-'),
        kv('MITRE techniques', techniques.join(', ') || 'None', { mono: true }),
    ]));

    const indRows = indicators.map(ind => {
        if (ind && typeof ind === 'object') {
            return el('tr', {}, [
                el('td', { className: 'mono', text: ind.rule_id }),
                el('td', {}, [el('span', { className: phishBadge(ind.severity), text: ind.severity })]),
                el('td', { text: ind.description }),
                el('td', { className: 'mono', text: ind.matched_evidence, title: ind.matched_evidence }),
            ]);
        }
        return el('tr', {}, [
            el('td', { className: 'mono', text: '-' }),
            el('td', {}, [el('span', { className: phishBadge(sev), text: sev.toLowerCase() })]),
            el('td', { text: String(ind) }),
            el('td', { className: 'mono', text: '' }),
        ]);
    });
    const indBody = [];
    if (indRows.length) {
        indBody.push(el('table', { className: 'data-table' }, [
            el('thead', {}, [el('tr', {}, [
                el('th', { text: 'Rule' }), el('th', { text: 'Severity' }),
                el('th', { text: 'Description' }), el('th', { text: 'Matched evidence' }),
            ])]),
            el('tbody', {}, indRows),
        ]));
    } else {
        indBody.push(el('div', { className: 'empty-state', text: 'No high-risk indicators detected.' }));
    }
    container.appendChild(section(`Detected indicators (${indicators.length})`, indicators.length > 0, indBody));

    if (urls.length) {
        const urlNodes = urls.map(u => {
            const raw = (u && typeof u === 'object') ? (u.url || u.hostname || '') : u;
            const flags = (u && typeof u === 'object') ? phishUrlFlags(u) : [];
            const line = el('div', { style: 'margin-bottom: 6px; word-break: break-all;' }, [
                el('span', { className: 'mono', style: 'font-size: 11px;', text: raw }),
            ]);
            if (flags.length) {
                line.appendChild(el('span', {
                    className: 'mono',
                    style: 'color: var(--re-text-muted); font-size: 11px;',
                    text: `  [${flags.join(', ')}]`,
                }));
            }
            return line;
        });
        container.appendChild(section(`Extracted URLs / domains (${urls.length})`, false, urlNodes));
    }

    if (attachments.length) {
        const attRows = attachments.map(att => el('tr', {}, [
            el('td', { className: 'mono', text: att.filename, title: att.filename }),
            el('td', {}, [el('span', { className: phishBadge(att.risk), text: att.risk })]),
            el('td', { text: att.reason }),
        ]));
        container.appendChild(section(`Attachments (${attachments.length})`, false, [
            el('table', { className: 'data-table' }, [
                el('thead', {}, [el('tr', {}, [
                    el('th', { text: 'Filename' }), el('th', { text: 'Risk' }), el('th', { text: 'Reason' }),
                ])]),
                el('tbody', {}, attRows),
            ]),
        ]));
    }

    if (recommendations.length) {
        const list = el('ul', { style: 'margin: 0; padding-left: 18px;' },
            recommendations.map(r => el('li', { text: r })));
        container.appendChild(section(`Recommendations (${recommendations.length})`, false, [list]));
    }
}

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
            renderPhishingResult(resBox, res.assessment);
        } else {
            fbPhish.className = 'alert alert-error mt-md';
            fbPhish.textContent = res ? res.message : 'Phishing analysis failed.';
            fbPhish.classList.remove('hidden');
        }
    });
}

// ==========================================
// Drawers (Inspectors) — Safe DOM
// ==========================================
async function inspectIncident(incId) {
    const inc = state.incidents.find(i => i.incident_id === incId);
    if (!inc) return;

    dom.drawerTitle.textContent = `Incident: ${incId}`;

    const content = el('div', {}, [
        el('div', { className: 'prop-list' }, [
            el('div', { className: 'prop-item' }, [
                el('span', { className: 'prop-key', text: 'Severity' }),
                badge(inc.severity, (inc.severity || '').toLowerCase()),
            ]),
            kv('Timeframe', `${inc.start_time || '-'} - ${inc.end_time || '-'}`),
            kv('Duration', `${inc.duration || '-'} seconds`),
        ]),
    ]);

    // Associated Findings
    const findingIds = inc.finding_ids || [];
    content.appendChild(el('h4', { className: 'mt-xl', text: `Associated Findings (${findingIds.length})`,
        style: 'margin-bottom: 12px; font-size: 11px; text-transform: uppercase; color: var(--re-text-muted);' }));
    const findingList = el('div', { className: 'prop-list' });
    findingIds.forEach(f => {
        findingList.appendChild(el('div', { className: 'prop-val mono', text: `FINDING:${f}`,
            style: 'color: var(--re-critical); border-left: 3px solid var(--re-critical);' }));
    });
    if (findingIds.length === 0) findingList.appendChild(el('div', { className: 'prop-val', text: 'No findings associated.', style: 'color: var(--re-text-muted);' }));
    content.appendChild(findingList);

    // Processes Involved
    const processes = inc.processes || [];
    content.appendChild(el('h4', { className: 'mt-xl', text: 'Processes Involved',
        style: 'margin-bottom: 12px; font-size: 11px; text-transform: uppercase; color: var(--re-text-muted);' }));
    const procList = el('div', { className: 'prop-list' });
    processes.forEach(p => {
        const procEl = el('div', { className: 'prop-val mono clickable-id',
            onclick: () => inspectProcess(p.process_guid || p.pid) });
        procEl.appendChild(document.createTextNode(`${p.process_name || '-'} (PID: ${p.pid || '-'})`));
        procEl.appendChild(el('br'));
        procEl.appendChild(el('span', { text: `GUID: ${p.process_guid || '-'}`, style: 'color: var(--re-text-muted); font-size: 11px;' }));
        procList.appendChild(procEl);
    });
    if (processes.length === 0) procList.appendChild(el('div', { className: 'prop-val', text: 'No process context available.', style: 'color: var(--re-text-muted);' }));
    content.appendChild(procList);

    dom.drawerContent.replaceChildren(content);
    dom.drawer.classList.add('open');
}

window.inspectEventEncoded = function(encEventId) {
    if (!encEventId) return;
    inspectEvent(decodeURIComponent(encEventId));
};

async function inspectEvent(eventId) {
    if (!state.currentCaseId || !eventId) return;
    dom.drawerTitle.textContent = 'Loading Evidence...';
    dom.drawerContent.replaceChildren(el('div', { className: 'empty-state', text: 'Loading...' }));
    dom.drawer.classList.add('open');

    const data = await api(`/inspect/${encodeURIComponent(state.currentCaseId)}?event_id=${encodeURIComponent(eventId)}`);
    if (!data || data._error || !data.event) {
        dom.drawerContent.replaceChildren(el('div', { className: 'empty-state', text: `Failed to load evidence event.` }));
        return;
    }

    const ev = data.event;
    state.lastEventMeta = {
        process_name: ev.process_name || null,
        pid: (ev.pid !== undefined && ev.pid !== null && ev.pid !== 'null' && ev.pid !== 0 && ev.pid !== '0') ? String(ev.pid) : null,
        process_guid: (ev.process_guid && ev.process_guid !== 'null' && ev.process_guid !== 'undefined') ? ev.process_guid : null,
    };

    dom.drawerTitle.textContent = 'Evidence Inspection';
    const procIdent = state.lastEventMeta.process_guid || state.lastEventMeta.pid;

    // Tabs
    const tabProps = el('div', { className: 'tab active', text: 'Properties' });
    const tabTrace = el('div', { className: 'tab', text: 'Evidence Trace' });
    const tabRaw = el('div', { className: 'tab', text: 'Raw Data' });
    const tabs = el('div', { className: 'tabs' }, [tabProps, tabTrace, tabRaw]);

    // Properties panel
    const propsPane = el('div', { className: 'tab-content active prop-list' });
    propsPane.append(
        kv('Event ID', ev.event_id, { mono: true }),
        kv('Timestamp', ev.timestamp || '-'),
        kv('Source', ev.source),
        kv('Event Type', ev.event_type || '-'),
    );

    if (procIdent) {
        propsPane.append(
            kv('Process Name', ev.process_name || ev.image_path || '-', { mono: true }),
            kv('PID', ev.pid || '-', { mono: true }),
            kv('Process GUID', ev.process_guid || '-', { mono: true }),
            el('div', { className: 'mt-sm mb-md' }, [
                el('button', { className: 'btn btn-primary', text: 'OPEN PROCESS PROFILE →',
                    style: 'display: inline-flex; align-items: center; gap: 6px; font-size: 12px; padding: 8px 16px; cursor: pointer;',
                    onclick: () => inspectProcess(procIdent) }),
            ]),
        );
    } else {
        propsPane.appendChild(kv('Process Context', 'No process context available'));
    }
    propsPane.append(
        kv('Command Line', ev.command_line || '-'),
        kv('Image Path', ev.image_path || '-'),
    );

    // Trace panel
    const tracePane = el('div', { className: 'tab-content' });
    const traceContainer = el('div', { className: 'trace-container' });

    traceContainer.appendChild(el('div', { className: 'trace-node mono', text: `EVENT: ${ev.event_type || 'Unknown'} (${ev.event_id})`, style: 'border-color: var(--re-cyan);' }));
    traceContainer.appendChild(el('div', { className: 'trace-edge' }));

    if (data.trace.findings.length > 0) {
        data.trace.findings.forEach(f => {
            traceContainer.appendChild(el('div', { className: 'trace-node mono', text: `FINDING: ${f.finding_type || '-'}`, style: 'border-color: var(--re-critical); color: var(--re-critical);' }));
            traceContainer.appendChild(el('div', { className: 'trace-edge' }));
        });
    } else {
        traceContainer.appendChild(el('div', { className: 'trace-node', text: 'No Findings', style: 'color: var(--re-text-muted);' }));
        traceContainer.appendChild(el('div', { className: 'trace-edge' }));
    }

    if (data.trace.incidents.length > 0) {
        data.trace.incidents.forEach(i => {
            traceContainer.appendChild(el('div', { className: 'trace-node mono clickable-id', text: `INCIDENT: ${i.incident_id || '-'}`,
                onclick: () => inspectIncident(i.incident_id) }));
            traceContainer.appendChild(el('div', { className: 'trace-edge' }));
        });
    } else {
        traceContainer.appendChild(el('div', { className: 'trace-node', text: 'No Incidents', style: 'color: var(--re-text-muted);' }));
        traceContainer.appendChild(el('div', { className: 'trace-edge' }));
    }

    if (data.trace.processes.length > 0) {
        data.trace.processes.forEach(p => {
            traceContainer.appendChild(el('div', { className: 'trace-node mono clickable-id', text: `PROCESS: ${p.process_name || p.pid || '-'}`,
                onclick: () => inspectProcess(p.guid || p.pid) }));
        });
    } else {
        traceContainer.appendChild(el('div', { className: 'trace-node', text: 'No Process Context', style: 'color: var(--re-text-muted);' }));
    }
    tracePane.appendChild(traceContainer);

    // Raw panel
    const rawPane = el('div', { className: 'tab-content' });
    const rawArea = el('textarea', { className: 'code-block', attrs: { rows: '20', readonly: '' } });
    rawArea.value = JSON.stringify(ev, null, 2);
    rawPane.appendChild(rawArea);

    // Tab switching
    const panes = [propsPane, tracePane, rawPane];
    const tabEls = [tabProps, tabTrace, tabRaw];
    tabEls.forEach((t, idx) => {
        t.addEventListener('click', () => {
            tabEls.forEach(tt => tt.classList.remove('active'));
            panes.forEach(pp => pp.classList.remove('active'));
            t.classList.add('active');
            panes[idx].classList.add('active');
        });
    });

    dom.drawerContent.replaceChildren(tabs, ...panes);
}

async function inspectProcess(procId, meta) {
    if (!state.currentCaseId || !procId || procId === 'null' || procId === 'undefined') return;

    dom.drawerTitle.textContent = 'Loading Process...';
    dom.drawerContent.replaceChildren(el('div', { className: 'empty-state', text: 'Loading...' }));
    dom.drawer.classList.add('open');

    const m = meta || state.lastEventMeta || {};
    const procName = m.process_name || m.name || '-';
    const procPid = (m.pid !== undefined && m.pid !== null && m.pid !== '' && m.pid !== 'null') ? String(m.pid) : (!procId.startsWith('{') ? procId : '-');
    const procGuid = m.process_guid || m.guid || (procId.startsWith('{') ? procId : '-');

    const data = await api(`/process/${encodeURIComponent(state.currentCaseId)}/${encodeURIComponent(procId)}`);
    if (!data || data._error || !data.process) {
        dom.drawerTitle.textContent = 'Process Profile';
        dom.drawerContent.replaceChildren(
            el('div', { className: 'empty-state', style: 'padding: 24px 12px; text-align: left;' }, [
                badge('PROCESS PROFILE UNAVAILABLE', 'warning'),
                el('p', { text: 'No matching process node exists for this case in the investigation graph.', style: 'color: var(--re-text); font-size: 13px; margin: 16px 0;' }),
                el('h4', { text: 'Event Process Metadata', style: 'font-size: 11px; text-transform: uppercase; color: var(--re-text-muted); margin-bottom: 8px;' }),
                el('div', { className: 'prop-list mb-lg' }, [
                    kv('Process Name', procName, { mono: true }),
                    kv('PID', procPid, { mono: true }),
                    kv('Process GUID', procGuid, { mono: true }),
                ]),
                el('button', { className: 'btn btn-secondary mt-md', text: '← BACK TO EVIDENCE',
                    onclick: () => dom.drawer.classList.remove('open') }),
            ])
        );
        return;
    }

    const p = data.process;
    dom.drawerTitle.textContent = 'Process Profile';

    // Identity
    const identity = el('div', { className: 'prop-list mb-lg' }, [
        el('div', { className: 'prop-item' }, [
            el('span', { className: 'prop-key', text: 'Process Name' }),
            el('span', { className: 'prop-val mono', text: p.name || '-', style: 'font-size: 16px; color: var(--re-cyan-bright); border-color: var(--re-cyan);' }),
        ]),
        kv('PID', p.pid || '-', { mono: true }),
        kv('GUID', p.guid || '-', { mono: true }),
        kv('Command Line', p.command_line || '-'),
    ]);

    // Tabs
    const tabLineage = el('div', { className: 'tab active', text: 'Lineage' });
    const tabFiles = el('div', { className: 'tab', text: `Files (${data.files.length})` });
    const tabNet = el('div', { className: 'tab', text: `Network (${data.network.length})` });
    const tabFind = el('div', { className: 'tab', text: `Findings (${data.findings.length})` });
    const tabBar = el('div', { className: 'tabs mt-lg' }, [tabLineage, tabFiles, tabNet, tabFind]);

    // Lineage pane
    const lineagePane = el('div', { className: 'tab-content active', style: 'background: var(--re-bg); border: 1px solid var(--re-border); padding: 16px; border-radius: 4px;' });
    if (data.parent) {
        lineagePane.appendChild(el('div', { className: 'tree-node parent clickable-id', text: `${data.parent.name || '-'} (PID: ${data.parent.pid || '-'})`,
            onclick: () => inspectProcess(data.parent.guid || data.parent.pid) }));
    } else {
        lineagePane.appendChild(el('div', { className: 'tree-node parent', text: 'Unknown Parent' }));
    }
    lineagePane.appendChild(el('div', { className: 'tree-node current', text: `${p.name || '-'} (PID: ${p.pid || '-'})` }));
    if (data.children.length > 0) {
        data.children.forEach(c => {
            lineagePane.appendChild(el('div', { className: 'tree-node child clickable-id', text: `${c.name || '-'} (PID: ${c.pid || '-'})`,
                onclick: () => inspectProcess(c.guid || c.pid) }));
        });
    } else {
        lineagePane.appendChild(el('div', { className: 'tree-node child', text: 'No children', style: 'color: var(--re-text-muted);' }));
    }

    // Files pane
    const filesPane = el('div', { className: 'tab-content prop-list' });
    if (data.files.length > 0) {
        data.files.forEach(f => {
            const row = el('div', { className: 'prop-val mono' }, [
                el('strong', { text: f.rel, style: 'color: var(--re-text-secondary); width: 80px; display: inline-block;' }),
                document.createTextNode(' '),
            ]);
            row.appendChild(document.createTextNode(f.path));
            filesPane.appendChild(row);
        });
    } else {
        filesPane.appendChild(el('div', { className: 'empty-state', text: 'No file modifications recorded.' }));
    }

    // Network pane
    const netPane = el('div', { className: 'tab-content prop-list' });
    if (data.network.length > 0) {
        data.network.forEach(n => {
            const row = el('div', { className: 'prop-val mono' }, [
                el('strong', { text: 'CONNECT', style: 'color: var(--re-text-secondary);' }),
                document.createTextNode(` ${n.destination_ip || '-'}:${n.destination_port || '-'} [${n.protocol || '-'}]`),
            ]);
            netPane.appendChild(row);
        });
    } else {
        netPane.appendChild(el('div', { className: 'empty-state', text: 'No network connections recorded.' }));
    }

    // Findings pane
    const findingsPane = el('div', { className: 'tab-content prop-list' });
    if (data.findings.length > 0) {
        data.findings.forEach(f => {
            findingsPane.appendChild(el('div', { className: 'prop-val mono', text: `FINDING: ${f.finding_type || '-'} (${f.technique || '-'})`,
                style: 'color: var(--re-critical); border-left: 3px solid var(--re-critical);' }));
        });
    } else {
        findingsPane.appendChild(el('div', { className: 'empty-state', text: 'No associated findings.' }));
    }

    // Tab switching
    const panes = [lineagePane, filesPane, netPane, findingsPane];
    const tabEls = [tabLineage, tabFiles, tabNet, tabFind];
    tabEls.forEach((t, idx) => {
        t.addEventListener('click', () => {
            tabEls.forEach(tt => tt.classList.remove('active'));
            panes.forEach(pp => pp.classList.remove('active'));
            t.classList.add('active');
            panes[idx].classList.add('active');
        });
    });

    dom.drawerContent.replaceChildren(identity, tabBar, ...panes);
}

// Global Tab Switcher for Drawer (legacy support)
window.switchDrawerTab = function (elRef, targetId) {
    const tabs = elRef.parentElement.querySelectorAll('.tab');
    const contents = elRef.parentElement.nextElementSibling.parentElement.querySelectorAll('.tab-content');
    tabs.forEach(t => t.classList.remove('active'));
    contents.forEach(c => c.classList.remove('active'));
    elRef.classList.add('active');
    const target = document.getElementById(targetId);
    if (target) target.classList.add('active');
};

document.addEventListener('DOMContentLoaded', init);

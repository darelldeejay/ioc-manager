/* ========================================================
   Gestión de Tema (Claro / Oscuro)
   ======================================================== */
(function () {

    function applyTheme(theme) {
        const body = document.body;
        const isDark = (theme === 'dark');

        // Clases globales en el body
        body.classList.remove('bg-light', 'bg-dark', 'text-white');
        if (isDark) {
            body.classList.add('bg-dark', 'text-white');
        } else {
            body.classList.add('bg-light');
        }

        // Atributo global para CSS
        document.documentElement.setAttribute('data-theme', theme);

        // Tabla principal
        const tbl = document.getElementById('tablaIps');
        if (tbl) {
            tbl.classList.toggle('table-dark', isDark);
        }

        // Botón de notificaciones
        const notifBtn = document.getElementById('notif-btn');
        if (notifBtn) {
            notifBtn.classList.remove('btn-outline-primary', 'btn-outline-light');
            notifBtn.classList.add(isDark ? 'btn-outline-light' : 'btn-outline-primary');
        }

        // Botón de tema (icono + texto)
        const icon = document.getElementById('themeToggleIcon');
        const text = document.getElementById('themeToggleText');
        if (icon && text) {
            if (isDark) {
                icon.classList.remove('bi-moon-stars');
                icon.classList.add('bi-sun');
                text.textContent = 'Claro';
            } else {
                icon.classList.remove('bi-sun');
                icon.classList.add('bi-moon-stars');
                text.textContent = 'Oscuro';
            }
        }
    }

    // Función global que llama el onclick del botón
    window.toggleTheme = function () {
        const current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
        const next = (current === 'dark') ? 'light' : 'dark';

        // Guardar preferencia
        try {
            localStorage.setItem('theme', next);
        } catch (e) { }

        // Si pasamos a claro, quitamos el estilo anti-flash
        const anti = document.getElementById('anti-flash-dark');
        if (next === 'light' && anti) {
            anti.remove();
        }

        applyTheme(next);
    };

    // Aplicar tema guardado al cargar la página
    document.addEventListener('DOMContentLoaded', function () {
        let theme = 'light';
        try {
            const saved = localStorage.getItem('theme');
            if (saved === 'dark') theme = 'dark';
        } catch (e) { }
        applyTheme(theme);
    });

})();

/* ========================================================
   Estado de tabla (server-side)
   ======================================================== */
var tableState = {
    page: 1,
    page_size: 50,
    sort: 'fecha',
    order: 'desc',
    q: '',
    date_from: '',
    date_to: ''
};
let serverMode = true; // intentamos server JSON; si falla, fallback local

/* ========================================================
   Buscador local (fallback)
   ======================================================== */
function initLocalSearchFallback() {
    const wrap = document.getElementById('localSearchWrap');
    wrap.classList.remove('d-none');
    const input = document.getElementById('buscadorIp');
    const table = document.getElementById('tablaIps');
    if (input && table) {
        input.addEventListener('keyup', function () {
            const filtro = input.value.toLowerCase();
            const filas = table.getElementsByTagName('tr');
            for (let i = 1; i < filas.length; i++) {
                const celdas = filas[i].getElementsByTagName('td');
                if (celdas.length > 1) {
                    const ip = celdas[1].textContent.toLowerCase();
                    filas[i].style.display = ip.includes(filtro) ? '' : 'none';
                }
            }
        });
    }
}

/* ========================================================
   Marcar tipo de acción (manual vs csv)
   ======================================================== */
(function wireActionMarkers() {
    const mark = (type) => {
        try {
            sessionStorage.setItem('lastActionType', type);
            sessionStorage.setItem('lastActionTs', String(Date.now()));
        } catch { }
    };

    document.getElementById('addManualBtn')?.addEventListener('click', () => mark('manual'));
    document.getElementById('uploadCsvBtn')?.addEventListener('click', () => mark('csv'));

    document.getElementById('mainForm')?.addEventListener('submit', () => {
        const fileHasValue = !!document.querySelector('input[type="file"][name="file"]')?.value;
        if (!sessionStorage.getItem('lastActionType')) {
            mark(fileHasValue ? 'csv' : 'manual');
        }
    });
})();

/* ========================================================
   Helpers Tags (manual y csv)
   ======================================================== */
function selectedTags(cls) {
    return Array.from(document.querySelectorAll('.' + cls + ':checked')).map(el => el.value);
}
function syncHiddenTags() {
    const man = selectedTags('tag-manual');
    const csv = selectedTags('tag-csv');
    const manInput = document.getElementById('tagsManualInput');
    const csvInput = document.getElementById('tagsCsvInput');
    if (manInput) manInput.value = man.join(',');
    if (csvInput) csvInput.value = csv.join(',');
}
document.querySelectorAll('.tag-manual, .tag-csv').forEach(el => {
    el.addEventListener('change', syncHiddenTags);
});

function showManualTagError(show) {
    const fb = document.getElementById('tagManualFeedback');
    const hidden = document.getElementById('tagsManualInput');
    if (!fb || !hidden) return;
    fb.style.display = show ? 'block' : 'none';
    hidden.classList.toggle('is-invalid', !!show);
}

function showCsvTagError(show) {
    const fb = document.getElementById('tagCsvFeedback');
    const group = document.getElementById('tagCsvGroup');
    if (!fb || !group) return;
    fb.style.display = show ? 'block' : 'none';
    group.classList.toggle('is-invalid', !!show);
}

const setLoading = (btn, textWhileLoading) => {
    if (!btn) return;
    btn.dataset.originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `
      <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
      <span class="ms-1">${textWhileLoading}</span>
    `;
};

document.getElementById('mainForm')?.addEventListener('submit', (ev) => {
    // --- Validación de tags ---
    syncHiddenTags();
    const fileHasValue = !!document.querySelector('input[type="file"][name="file"]')?.value;

    if (!fileHasValue) {            // === Flujo MANUAL ===
        const man = selectedTags('tag-manual');
        if (man.length === 0) {
            ev.preventDefault(); ev.stopPropagation();
            showManualTagError(true);
            document.querySelector('.tag-manual')?.focus();
            return;
        } else {
            showManualTagError(false);
        }
    } else {                        // === Flujo CSV (OBLIGATORIO) ===
        const csv = selectedTags('tag-csv');
        if (csv.length === 0) {
            ev.preventDefault(); ev.stopPropagation();
            showCsvTagError(true);
            document.querySelector('.tag-csv')?.focus();
            return;
        } else {
            showCsvTagError(false);
        }
    }

    // Spinners (igual que tenías)
    const manualBtn = document.getElementById('addManualBtn');
    const csvBtn = document.getElementById('uploadCsvBtn');
    if (fileHasValue) {
        setLoading(csvBtn, 'Subiendo…');
    } else {
        setLoading(manualBtn, 'Añadiendo…');
    }
});

window.addEventListener('pageshow', () => {
    ['addManualBtn', 'uploadCsvBtn'].forEach(id => {
        const b = document.getElementById(id);
        if (b && b.dataset.originalHtml) {
            b.innerHTML = b.dataset.originalHtml;
            b.disabled = false;
            delete b.dataset.originalHtml;
        }
    });
});

// (Función showCombinedActionToast eliminada - reemplazada por script inline en index.html)

function mapToastColor(kind) {
    if (kind === 'error' || kind === 'danger' || kind === 'accion_no_permitida') return 'danger';
    if (kind === 'warning') return 'warning';
    if (kind === 'success') return 'success';
    return 'primary';
}

function escapeHtml(text) {
    if (!text) return '';
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return text.replace(/[&<>"']/g, function (m) { return map[m]; });
}

function showInlineToast(kind, text, delay = 6000) {
    const portal = document.getElementById('toast-portal');
    const el = document.createElement('div');
    el.className = 'toast align-items-center text-bg-' + mapToastColor(kind) + ' border-0';
    el.innerHTML = `
      <div class="d-flex">
        <div class="toast-body">${escapeHtml(text || '')}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto"
                data-bs-dismiss="toast" aria-label="Close"></button>
      </div>`;
    portal.appendChild(el);
    new bootstrap.Toast(el, { autohide: true, delay }).show();
}

document.getElementById('markReadBtn').addEventListener('click', async () => {
    try { await fetch('/notifications/read-all', { method: 'POST' }); } catch (e) { }
    markAllReadUI();
    showInlineToast('success', 'Notificaciones marcadas como leídas');
});
const offcanvasEl = document.getElementById('offcanvasNotifs');
if (offcanvasEl) {
    offcanvasEl.addEventListener('shown.bs.offcanvas', async () => {
        try { await fetch('/notifications/read-all', { method: 'POST' }); } catch (e) { }
        markAllReadUI();
    });
}

const PAGE_SIZE_NOTIF = 10;

// Usamos window.serverMessages que se inyectó en el HTML
let notifData = (window.serverMessages || []).map((m, i) => {
    const txt = m.message || '';
    const theMatch = txt.match(/^(\d{4}-\d{2}-\d{2})(?:\s+(\d{2}:\d{2}:\d{2}))?\s+(.*)$/);
    let dt = null;
    let cleanMsg = txt;
    if (theMatch) {
        const ymd = theMatch[1];
        const hms = theMatch[2] || '00:00:00';
        dt = new Date(`${ymd}T${hms}`);
        cleanMsg = theMatch[3];
    }
    return { id: i + 1, category: m.category, message: cleanMsg, date: dt };
});

notifData.sort((a, b) => {
    const ad = a.date ? a.date.getTime() : -Infinity;
    const bd = b.date ? b.date.getTime() : -Infinity;
    return bd - ad;
});

const listEl = document.getElementById('notifList');
const pagEl = document.getElementById('notifPagination');
const infoEl = document.getElementById('notifCountInfo');

let filterType = '';
let filterDate = '';
let currentPage = 1;

document.getElementById('applyFilters').addEventListener('click', () => {
    filterType = document.getElementById('filterType').value;
    filterDate = document.getElementById('filterDate').value;
    currentPage = 1;
    renderList();
});
document.getElementById('clearFilters').addEventListener('click', () => {
    document.getElementById('filterType').value = '';
    document.getElementById('filterDate').value = '';
    filterType = filterDate = '';
    currentPage = 1;
    renderList();
});

function filtered() {
    return notifData.filter(n => {
        if (filterType && n.category !== filterType) return false;
        if (filterDate) {
            const d = n.date;
            if (!d || isNaN(d.getTime())) return false; // Protección contra fechas inválidas
            try {
                const ymd = d.toISOString().slice(0, 10);
                if (ymd !== filterDate) return false;
            } catch (e) { return false; }
        }
        return true;
    });
}

function renderList() {
    const data = filtered();
    const totalPages = Math.max(1, Math.ceil(data.length / PAGE_SIZE_NOTIF));
    if (currentPage > totalPages) currentPage = totalPages;

    const start = (currentPage - 1) * PAGE_SIZE_NOTIF;
    const pageItems = data.slice(start, start + PAGE_SIZE_NOTIF);

    infoEl.textContent = `Mostrando ${pageItems.length} de ${data.length} notificaciones`;

    listEl.innerHTML = '';
    if (data.length === 0) {
        listEl.innerHTML = `<div class="p-2 text-danger small">
            DEBUG: Count=0<br>
            RawLen=${(window.serverMessages || []).length}<br>
            Sample=${escapeHtml(JSON.stringify((window.serverMessages || []).slice(0, 1)))}
        </div>`;
    }
    pageItems.forEach(n => {
        const cls = mapToastColor(n.category);
        const pill = n.category === 'success' ? '✅' :
            n.category === 'warning' ? '⚠️' :
                (n.category === 'danger' || n.category === 'accion_no_permitida') ? '❌' : 'ℹ️';
        const dtTxt = n.date ? n.date.toLocaleString() : '';
        const item = document.createElement('div');
        // FIX: Forzar text-dark porque bg-white no cambia el color de texto, y en modo oscuro el texto es blanco -> invisible
        item.className = `border rounded p-2 bg-white text-dark mb-1`;
        item.innerHTML = `
        <div class="d-flex align-items-center justify-content-between">
          <span class="badge text-bg-${cls}">${pill}</span>
          <span class="small text-muted ms-2">${escapeHtml(dtTxt)}</span>
        </div>
        <div class="mt-1">${escapeHtml(n.message)}</div>
      `;
        listEl.appendChild(item);
    });

    pagEl.innerHTML = '';
    const mkPage = (p, label = p, disabled = false, active = false) => {
        const li = document.createElement('li');
        li.className = `page-item ${disabled ? 'disabled' : ''} ${active ? 'active' : ''}`;
        const a = document.createElement('a');
        a.className = 'page-link';
        a.href = '#';
        a.textContent = label;
        a.addEventListener('click', (e) => {
            e.preventDefault();
            if (!disabled && currentPage !== p) {
                currentPage = p;
                renderList();
            }
        });
        li.appendChild(a);
        return li;
    };
    const pages = Math.max(1, Math.ceil(data.length / PAGE_SIZE_NOTIF));
    pagEl.appendChild(mkPage(Math.max(1, currentPage - 1), '«', currentPage === 1, false));
    for (let p = 1; p <= pages; p++) pagEl.appendChild(mkPage(p, String(p), false, p === currentPage));
    pagEl.appendChild(mkPage(Math.min(pages, currentPage + 1), '»', currentPage >= pages, false));
}



(function initDeletePreview() {
    const input = document.getElementById('delete_net_input');
    const preview = document.getElementById('previewResult');
    if (!input || !preview) return;

    let lastController = null;

    input.addEventListener('input', () => {
        const val = input.value.trim();
        if (!val) {
            preview.textContent = "Escribe un patrón para ver cuántas IPs coinciden.";
            preview.className = 'mt-2 small text-muted';
            return;
        }

        //   if (lastController) lastController.abort();
        //   lastController = new AbortController();
        // NOTA: AbortController comentado si da problemas, pero recomendado

        const controller = new AbortController();
        lastController = controller;

        fetch(`/preview-delete?pattern=${encodeURIComponent(val)}`, { signal: controller.signal })
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    preview.textContent = `❌ ${data.error}`;
                    preview.className = 'mt-2 small text-danger';
                } else {
                    preview.textContent = `Coinciden ${data.count} IP(s).`;
                    preview.className = 'mt-2 small text-success';
                }
            })
            .catch(err => {
                if (err.name === 'AbortError') return;
                preview.textContent = "❌ Error al consultar coincidencias.";
                preview.className = 'mt-2 small text-danger';
            });
    });
})();

(function initInstantValidate() {
    const input = document.getElementById('ipInput');
    const feedback = document.getElementById('ipFeedback');
    const form = document.getElementById('mainForm');

    if (!input || !feedback || !form) return;

    const OCTET = '(25[0-5]|2[0-4]\\d|1?\\d?\\d)';
    const ipv4Re = new RegExp(`^${OCTET}(\\.${OCTET}){3}$`);
    const cidrRe = new RegExp(`^${OCTET}(\\.${OCTET}){3}\\/(?:[0-9]|[12][0-9]|3[0-2])$`);
    const rangeRe = new RegExp(`^${OCTET}(\\.${OCTET}){3}\\s*-\\s*${OCTET}(\\.${OCTET}){3}$`);
    const ipMaskRe = new RegExp(`^${OCTET}(\\.${OCTET}){3}\\s+${OCTET}(\\.${OCTET}){3}$`);

    const validMasks = new Set([
        '255.255.255.255', '255.255.255.254', '255.255.255.252', '255.255.255.248',
        '255.255.255.240', '255.255.255.224', '255.255.255.192', '255.255.255.128',
        '255.255.255.0', '255.255.254.0', '255.255.252.0', '255.255.248.0',
        '255.255.240.0', '255.255.224.0', '255.255.192.0', '255.255.128.0',
        '255.255.0.0', '255.254.0.0', '255.252.0.0', '255.248.0.0', '255.240.0.0',
        '255.224.0.0', '255.192.0.0', '255.128.0.0', '255.0.0.0',
        '254.0.0.0', '252.0.0.0', '248.0.0.0', '240.0.0.0', '224.0.0.0',
        '192.0.0.0', '128.0.0.0', '0.0.0.0'
    ]);

    function isForbiddenZero(val) {
        const v = val.trim();
        if (v === '0.0.0.0') return true;
        if (v.startsWith('0.0.0.0/')) return true;
        if (v.startsWith('0.0.0.0 ')) return true;
        if (/^\s*0\.0\.0\.0\s*-\s*/.test(v)) return true;
        return false;
    }

    function validate(val) {
        if (!val || !val.trim()) {
            return { ok: false, msg: 'Introduce una IP, CIDR, rango o IP con máscara.' };
        }
        if (isForbiddenZero(val)) {
            return { ok: false, msg: 'Acción no permitida: bloqueo de absolutamente todo (0.0.0.0).' };
        }
        if (ipv4Re.test(val)) return { ok: true };
        if (cidrRe.test(val)) return { ok: true };
        if (rangeRe.test(val)) return { ok: true };
        if (ipMaskRe.test(val)) {
            const mask = val.trim().split(/\s+/)[1];
            if (validMasks.has(mask)) return { ok: true };
            return { ok: false, msg: 'Máscara inválida. Usa máscara de red contigua (p.ej. 255.255.255.0).' };
        }
        return { ok: false, msg: 'Formato inválido. Ejemplos: 1.2.3.4 · 1.2.3.0/24 · 1.2.3.4-1.2.3.20 · 1.2.3.0 255.255.255.0' };
    }

    function setState(state) {
        if (state.ok) {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            feedback.textContent = '';
        } else {
            input.classList.remove('is-valid');
            input.classList.add('is-invalid');
            feedback.textContent = state.msg || 'Formato inválido';
        }
    }

    input.addEventListener('input', () => {
        const state = validate(input.value);
        if (!input.value.trim()) {
            input.classList.remove('is-valid', 'is-invalid');
            feedback.textContent = '';
            return;
        }
        setState(state);
    });

    form.addEventListener('submit', (e) => {
        if (input.value.trim()) {
            const state = validate(input.value);
            if (!state.ok) {
                e.preventDefault();
                e.stopPropagation();
                setState(state);
                input.focus();
            }
        }
    });
})();

function mapToastColor(cat) {
    if (cat === 'success') return 'success';
    if (cat === 'warning') return 'warning';
    if (cat === 'accion_no_permitida' || cat === 'danger') return 'danger';
    return 'secondary';
}
function escapeHtml(str) {
    return (str || '').replace(/[&<>\"']/g, s => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[s]));
}

function confirmDeletePattern() {
    const val = document.getElementById('delete_net_input').value.trim();
    return confirm(`Vas a eliminar todas las IPs que coincidan con:\n\n${val}\n\n¿Confirmas?`);
}
function markAllReadUI() {
    localStorage.setItem('notif_unread', '0');
    const badge = document.getElementById('notif-badge');
    if (badge) {
        badge.textContent = '0';
        badge.classList.add('d-none');
    }
}

function getSelectedIPs() {
    return Array.from(document.querySelectorAll('.row-chk:checked')).map(chk => chk.value);
}

function updateBulkUI() {
    const count = getSelectedIPs().length;
    const btn = document.getElementById('bulkDeleteBtn');
    const label = document.getElementById('bulkSelectedCount');
    if (label) label.textContent = String(count);
    if (btn) btn.disabled = (count === 0);
}

function attachTableSelectionHandlers() {
    document.querySelectorAll('.row-chk').forEach(chk => {
        chk.addEventListener('change', () => {
            updateBulkUI();
            const tr = chk.closest('tr');
            if (tr) tr.classList.toggle('table-active-selected', !!chk.checked);
        });
    });

    const master = document.getElementById('chkAll');
    if (master) {
        master.checked = false;
        master.addEventListener('change', () => {
            const rows = document.querySelectorAll('.row-chk');
            rows.forEach(chk => {
                chk.checked = master.checked;
                const tr = chk.closest('tr');
                if (tr) tr.classList.toggle('table-active-selected', !!chk.checked);
            });
            updateBulkUI();
        });
    }

    updateBulkUI();
}

const tbody = document.querySelector('#tablaIps tbody');
const pageInfo = document.getElementById('pageInfo');
const prevBtn = document.getElementById('prevPage');
const nextBtn = document.getElementById('nextPage');

const qInput = document.getElementById('qInput');
const dateFrom = document.getElementById('dateFrom');
const dateTo = document.getElementById('dateTo');
const sortSelect = document.getElementById('sortSelect');
const orderDesc = document.getElementById('orderDesc');
const orderAsc = document.getElementById('orderAsc');
const pageSizeSel = document.getElementById('pageSize');
const applyBtn = document.getElementById('applyTableFilters');
const clearBtn = document.getElementById('clearTableFilters');

orderDesc.addEventListener('click', () => { tableState.order = 'desc'; orderDesc.classList.add('active'); orderAsc.classList.remove('active'); reloadTable(true); });
orderAsc.addEventListener('click', () => { tableState.order = 'asc'; orderAsc.classList.add('active'); orderDesc.classList.remove('active'); reloadTable(true); });
sortSelect.addEventListener('change', () => { tableState.sort = sortSelect.value; reloadTable(true); });
pageSizeSel.addEventListener('change', () => { tableState.page_size = parseInt(pageSizeSel.value, 10) || 50; tableState.page = 1; reloadTable(true); });

applyBtn.addEventListener('click', () => {
    tableState.q = qInput.value.trim();
    tableState.date_from = dateFrom.value || '';
    tableState.date_to = dateTo.value || '';
    tableState.page = 1;
    reloadTable(true);
});

clearBtn.addEventListener('click', () => {
    qInput.value = ''; dateFrom.value = ''; dateTo.value = '';
    sortSelect.value = 'fecha'; tableState.sort = 'fecha';
    tableState.order = 'desc'; orderDesc.classList.add('active'); orderAsc.classList.remove('active');
    pageSizeSel.value = '50'; tableState.page_size = 50; tableState.page = 1;
    reloadTable(true);
});

prevBtn.addEventListener('click', () => { if (tableState.page > 1) { tableState.page--; reloadTable(false); } });
nextBtn.addEventListener('click', () => { tableState.page++; reloadTable(false); });

async function reloadTable(resetIfEmpty) {
    try {
        const params = new URLSearchParams();
        params.set('format', 'json');
        params.set('page', String(tableState.page));
        params.set('page_size', String(tableState.page_size));
        params.set('sort', tableState.sort);
        params.set('order', tableState.order);
        if (tableState.q) params.set('q', tableState.q);
        const hasRange = (tableState.date_from || tableState.date_to);
        if (hasRange) {
            const val = `${tableState.date_from || ''}${tableState.date_from || tableState.date_to ? ',' : ''}${tableState.date_to || ''}`;
            params.set('date', val);
        }
        const r = await fetch(`/?${params.toString()}`, { headers: { 'Accept': 'application/json' } });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const data = await r.json();
        renderRows(data.items || []);
        updateCounters(data.counters);
        updatePager(data.page, data.page_size, data.total);
        serverMode = true;
        document.getElementById('localSearchWrap').classList.add('d-none');
    } catch (e) {
        serverMode = false;
        initLocalSearchFallback();
    }
}

function tagBadge(t) {
    // Colores simples por tipo de tag
    const cls = (t === 'BPE') ? 'text-bg-warning' : (t === 'Test' ? 'text-bg-secondary' : 'text-bg-primary');
    return `<span class="badge ${cls}" style="margin-right:6px;">${escapeHtml(t)}</span>`;
}

function alertsCellHtml(row) {
    const ids = row.alert_ids || [];
    if (!ids.length) {
        return '<span class="text-muted">—</span>';
    }
    const count = ids.length;
    const listPreview = ids.slice(0, 6).map(escapeHtml).join(', ');
    const more = ids.length > 6 ? ' …' : '';
    const plural = count === 1 ? '' : 's';
    return `
      <span class="badge text-bg-info">${count} alerta${plural}</span>
      <div class="alert-ids-list text-muted">${listPreview}${more}</div>
    `;
}

function renderRows(items) {
    tbody.innerHTML = '';
    items.forEach((row) => {
        const tr = document.createElement('tr');
        const ttlText = (row.ttl === 0 || row.ttl === '0') ? '∞' : String(row.ttl);
        tr.innerHTML = `
        <td><input type="checkbox" class="row-chk" value="${escapeHtml(row.ip)}"></td>
        <td>${escapeHtml(row.ip)}</td>
        <td>${escapeHtml(row.fecha_alta || '')}</td>
        <td>${escapeHtml(ttlText)}</td>
        <td>${(row.tags && row.tags.length)
                ? row.tags.map(tagBadge).join(' ')
                : '<span class="text-muted">—</span>'
            }</td>
        <td>${alertsCellHtml(row)}</td>
        <td>
          <form method="POST" onsubmit="return confirm('¿Eliminar ${escapeHtml(row.ip)}?');">
            <input type="hidden" name="delete_ip" value="${escapeHtml(row.ip)}">
            <button type="submit" class="btn btn-sm btn-outline-danger">Eliminar</button>
          </form>
        </td>
      `;
        tbody.appendChild(tr);
    });
    attachTableSelectionHandlers();
}

function updatePager(page, pageSize, total) {
    const pages = Math.max(1, Math.ceil((total || 0) / (pageSize || 50)));
    tableState.page = Math.min(Math.max(1, parseInt(page || 1, 10)), pages);
    pageInfo.textContent = `Página ${tableState.page} de ${pages} — ${total || 0} IPs`;
    prevBtn.disabled = (tableState.page <= 1);
    nextBtn.disabled = (tableState.page >= pages);
}

// ===>> Actualiza totales globales (incluye API y Tags)
function updateCounters(counters) {
    if (!counters) return;
    const t = document.getElementById('totalCount');
    const m = document.getElementById('manualCount');
    const c = document.getElementById('csvCount');
    const a = document.getElementById('apiCount');
    const tm = document.getElementById('tagMultiCount');
    const tb = document.getElementById('tagBpeCount');

    if (t && counters.total !== undefined) t.textContent = counters.total;
    if (m && counters.manual !== undefined) m.textContent = counters.manual;
    if (c && counters.csv !== undefined) c.textContent = counters.csv;
    if (a && counters.api !== undefined) a.textContent = counters.api;

    const tags = (counters.tags || {});
    if (tm && tags['Multicliente'] !== undefined) tm.textContent = tags['Multicliente'];
    if (tb && tags['BPE'] !== undefined) tb.textContent = tags['BPE'];
}

async function bulkDeleteSelected() {
    const ips = getSelectedIPs();
    if (ips.length === 0) return;

    const preview = ips.slice(0, 10).join(', ') + (ips.length > 10 ? ` … (+${ips.length - 10})` : '');
    const ok = confirm(`Vas a eliminar ${ips.length} IP(s):\n\n${preview}\n\n¿Confirmas?`);
    if (!ok) return;

    const btn = document.getElementById('bulkDeleteBtn');
    const origHtml = btn?.innerHTML;
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `
        <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
        <span class="ms-1">Eliminando…</span>`;
    }

    let okCount = 0, failCount = 0;

    for (const ip of ips) {
        try {
            const fd = new FormData();
            fd.append('delete_ip', ip);
            const r = await fetch('/', { method: 'POST', body: fd });
            if (r.ok) okCount++; else failCount++;
        } catch (e) {
            failCount++;
        }
    }

    if (okCount && !failCount) {
        showInlineToast('warning', `${okCount} IP(s) eliminada(s).`);
    } else if (okCount && failCount) {
        showInlineToast('warning', `${okCount} eliminada(s) · ${failCount} error(es).`);
    } else {
        showInlineToast('danger', 'No se pudo eliminar ninguna IP.');
    }

    document.getElementById('chkAll')?.click();
    updateBulkUI();

    if (typeof reloadTable === 'function') {
        await reloadTable(true);
    } else {
        const rows = Array.from(document.querySelectorAll('#tablaIps tbody tr'));
        ips.forEach(ip => {
            const row = rows.find(tr => tr.cells[1] && tr.cells[1].textContent.trim() === ip);
            if (row) row.remove();
        });
    }

    if (btn && origHtml) {
        btn.innerHTML = origHtml;
        btn.disabled = false;
    }
}
document.getElementById('bulkDeleteBtn')?.addEventListener('click', bulkDeleteSelected);


document.addEventListener("DOMContentLoaded", function () {
    // Inicializar lógica de carga
    reloadTable(true);
    attachTableSelectionHandlers();

    // Renderizar historial de notificaciones
    renderList();

    // Renderizar toasts iniciales (Flash messages)
    if (window.newFlashes && window.newFlashes.length) {
        window.newFlashes.forEach(f => {
            // Mapeo categorías Flask -> Bootstrap
            let cat = f.category || 'info';
            if (cat === 'message') cat = 'info';
            showInlineToast(cat, f.message);
        });
    }

    const checkboxes = document.querySelectorAll(".tag-manual");
    const hiddenInput = document.getElementById("tagsManualInput");

    function updateTagsManual() {
        const selected = Array.from(checkboxes)
            .filter(chk => chk.checked)
            .map(chk => chk.value);
        hiddenInput.value = selected.join(","); // ejemplo: "Multicliente,BPE"
    }

    checkboxes.forEach(chk => chk.addEventListener("change", updateTagsManual));

    // Inicializar lista de notificaciones
    if (typeof renderList === 'function') renderList();
});

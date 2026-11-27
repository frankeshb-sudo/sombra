// Sombra - lógica de la interfaz. Licencia GPL-3.0-or-later.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const $ = (id) => document.getElementById(id);

const COUNTRIES = ['', 'DE', 'NL', 'FR', 'US', 'GB', 'CH', 'SE', 'FI', 'NO', 'AT', 'RO', 'CA', 'LU', 'PL', 'ES', 'IT', 'CZ', 'IS', 'JP'];
// [nombre, URL, privacidad: max | good | low]
const ENGINES = [
  ['DuckDuckGo (.onion)', 'https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/?q=%s', 'max'],
  ['DuckDuckGo', 'https://duckduckgo.com/?q=%s', 'good'],
  ['Startpage', 'https://www.startpage.com/do/search?q=%s', 'good'],
  ['Brave Search', 'https://search.brave.com/search?q=%s', 'good'],
  ['Mojeek', 'https://www.mojeek.com/search?q=%s', 'good'],
  ['Qwant', 'https://www.qwant.com/?q=%s', 'good'],
  ['Ecosia', 'https://www.ecosia.org/search?q=%s', 'good'],
  ['Google', 'https://www.google.com/search?q=%s', 'low'],
  ['Bing', 'https://www.bing.com/search?q=%s', 'low'],
];
function engineLevel(url) { const e = ENGINES.find(x => x[1] === url); return e ? e[2] : 'custom'; }
function privacyNote(url) {
  const lvl = engineLevel(url);
  return { cls: lvl, text: lvl === 'max' ? t('engMax') : lvl === 'good' ? t('engGood') : lvl === 'low' ? t('engLow') : t('engCustom') };
}
const ACCENTS = { violet: '#7f77dd', blue: '#378add', green: '#1d9e75', pink: '#d4537e', orange: '#d85a30' };

let S = null;           // último estado recibido de Rust
let editingAddr = false;
let pageOpen = null;    // 'settings' | 'history' | null
let lastLang = null;

/* ---------- utilidades ---------- */
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
function hostOf(u) { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return u; } }
function activeTab() { return S && S.tabs.find(x => x.id === S.active); }
function engineName(url) { const e = ENGINES.find(x => x[1] === url || x[1].replace('%s', '') === url); return e ? e[0] : hostOf(url); }
function countryName(code) {
  if (!code) return t('any');
  try { return new Intl.DisplayNames([LANG], { type: 'region' }).of(code); } catch { return code; }
}

/* ---------- zona de contenido: le dice a Rust dónde dibujar la web ---------- */
function reportRect() {
  const r = $('content').getBoundingClientRect();
  const narrowPanel = !$('panel').classList.contains('hidden') && window.innerWidth <= 720;
  const hide = narrowPanel || !!pageOpen;
  invoke('set_content_rect', { x: r.left, y: r.top, w: hide ? 0 : r.width, h: hide ? 0 : r.height }).catch(() => {});
}
new ResizeObserver(reportRect).observe($('content'));
window.addEventListener('resize', reportRect);

/* ---------- apariencia ---------- */
function applyAppearance(s) {
  const root = document.documentElement;
  const theme = s.theme === 'system' ? (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark') : s.theme;
  root.dataset.theme = theme;
  root.dataset.accent = s.accent || 'violet';
  root.dataset.compact = s.compact ? '1' : '0';
  root.style.setProperty('--fs', (s.font_size || 13) + 'px');
  $('bookmarks').classList.toggle('hidden', !s.show_bookmarks);
  if (s.language !== lastLang) {
    lastLang = s.language;
    applyI18n(s.language);
    fillStaticLists();
    if (pageOpen) openPage(pageOpen);
  }
  if (S.tabs) updateSearchUI();
}
matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => S && applyAppearance(S.settings));

/* ---------- pintado ---------- */
const MASK_SVG = '<svg viewBox="0 0 24 24"><path d="M3 11h18M6 11l2.2-6h7.6L18 11"/><circle cx="7.5" cy="16" r="2.6"/><circle cx="16.5" cy="16" r="2.6"/><path d="M10.1 16h3.8"/></svg>';
// Buscador de la pestaña activa: un buscador .onion solo existe dentro de Tor; en modo normal
// Sombra usa su versión de internet (igual que hace el motor al buscar).
function activeSearch() {
  const a = activeTab(), s = S.settings.search;
  const normal = a ? !a.private : !S.settings.default_private;
  return normal && s.includes('.onion') ? 'https://duckduckgo.com/?q=%s' : s;
}
function updateSearchUI() {
  const se = activeSearch();
  const a = activeTab();
  const normal = a ? !a.private : !S.settings.default_private;
  $('search').placeholder = t(normal ? 'searchPhNormal' : 'searchPh', { e: engineName(se) });
  const n = privacyNote(se);
  if (normal) n.text = t('engNormal');
  $('search-note').textContent = n.text;
  $('search-note').className = 'priv ' + n.cls;
}

let lastTabsKey = '';
function renderTabs() {
  // Solo se redibuja si algo ha cambiado (evita parpadeos con webs que cambian sin parar).
  const key = JSON.stringify([S.tabs, S.active, S.bookmarks.map(b => b.url), LANG, editingAddr]);
  if (key === lastTabsKey) return;
  lastTabsKey = key;
  const box = $('tabs');
  box.textContent = '';
  for (const tab of S.tabs) {
    const b = el('button', 'tab' + (tab.id === S.active ? ' active' : '') + (tab.private ? ' private' : ''));
    b.setAttribute('role', 'tab');
    b.title = (tab.private ? t('modeSombra') + ' · ' : '') + (tab.url || t('newTabTitle'));
    if (tab.loading) b.append(el('span', 'spin'));
    else if (tab.private) { const m = el('span', 'pv'); m.innerHTML = MASK_SVG; b.append(m); }
    b.append(el('span', 't', tab.has_view || tab.https_warn ? (tab.title || hostOf(tab.url)) : t('newTabTitle')));
    const x = el('span', 'x');
    x.innerHTML = '<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg>';
    x.onclick = (ev) => { ev.stopPropagation(); invoke('close_tab', { id: tab.id }); };
    b.append(x);
    b.onclick = () => { closePage(); invoke('activate_tab', { id: tab.id }); };
    b.onauxclick = (ev) => { if (ev.button === 1) invoke('close_tab', { id: tab.id }); };
    box.append(b);
  }
  const a = activeTab();
  // Modo de la pestaña activa: la barra se tiñe en modo Sombra para no confundirlos nunca.
  const priv = !!(a && a.private);
  document.body.classList.toggle('sombra', priv);
  $('mode-name').textContent = t(priv ? 'modeSombra' : 'modeNormal');
  $('mode-note').textContent = t(priv ? 'modeSombraNote' : 'modeNormalNote');
  $('addr').placeholder = t(priv ? 'addrPhSombra' : 'addrPh');
  updateSearchUI();
  const warn = !!(a && !a.has_view && a.https_warn);
  $('newtab').classList.toggle('hidden', !!(a && a.has_view) || warn);
  $('httpswarn').classList.toggle('hidden', !warn);
  if (warn) {
    $('hw-text').textContent = t('hwText', { host: hostOf(a.url) });
    $('hw-url').textContent = a.url;
  }
  if (!editingAddr) $('addr').value = a && (a.has_view || warn) ? a.url : '';
  const isHttps = a && a.url.startsWith('https://');
  $('addr-lock').style.color = !a || (!a.has_view && !warn) ? 'var(--muted)' : isHttps ? 'var(--ok)' : 'var(--warn)';
  const marked = a && S.bookmarks.some(b => b.url === a.url);
  $('btn-star').classList.toggle('on', !!marked);
  document.title = a && a.has_view ? (a.title || 'Sombra') + ' · Sombra' : 'Sombra';
}

let bmKey = '';
function renderBookmarks() {
  const key = JSON.stringify(S.bookmarks) + LANG;
  if (key === bmKey) return;
  bmKey = key;
  const bar = $('bookmarks'); bar.textContent = '';
  const sp = $('speed'); sp.textContent = '';
  for (const b of S.bookmarks) {
    const btn = el('button', 'bm', b.title || hostOf(b.url));
    btn.title = b.url + '\n' + t('removeBm');
    btn.onclick = () => { closePage(); invoke('navigate', { id: null, input: b.url }); };
    btn.oncontextmenu = (ev) => { ev.preventDefault(); invoke('remove_bookmark', { url: b.url }).then(refresh); };
    bar.append(btn);
    const d = el('div', 'dial');
    d.append(el('div', 'l', ((b.title || hostOf(b.url)).trim()[0] || '?').toUpperCase()), el('div', 'n', b.title || hostOf(b.url)));
    d.onclick = btn.onclick;
    d.oncontextmenu = btn.oncontextmenu;
    sp.append(d);
  }
}

function renderStatus() {
  const tor = S.tor;
  const sh = $('shield');
  sh.className = 'pill ' + (tor.ready ? (S.settings.blocking_enabled ? 'ok' : 'warn') : tor.error ? 'bad' : 'warn');
  $('shield-txt').textContent = tor.ready ? (S.settings.blocking_enabled ? t('shieldOk') : t('blockingOff')) : tor.error ? t('shieldBad') : t('shieldWait') + ' ' + Math.round(tor.progress * 100) + '%';
  $('tor-line').textContent = tor.ready ? t('ready') : (tor.error ? t('torErr') + ': ' + tor.error : t('shieldWait') + '… ' + Math.round(tor.progress * 100) + '%');
  $('tor-fill').style.width = Math.round((tor.ready ? 1 : tor.progress) * 100) + '%';
  $('tor-bar').classList.toggle('hidden', tor.ready);
  $('p-tor').textContent = tor.ready ? t('ready') : Math.round(tor.progress * 100) + '%';
  $('p-country').textContent = countryName(tor.country);
  $('p-leaks').textContent = S.stats.leaks;
  $('s-page').textContent = S.stats.page;
  $('s-ads').textContent = S.stats.ads;
  $('s-trk').textContent = S.stats.trackers;
  $('t-block').checked = S.settings.blocking_enabled;
  if (document.activeElement !== $('country')) $('country').value = tor.country || '';
  const c = S.control;
  $('t-ai').checked = c.enabled;
  $('btn-cut').classList.toggle('hidden', !c.enabled);
  // Pestaña normal: no usa Tor; el escudo solo indica el bloqueador.
  const an = activeTab();
  if (an && !an.private) {
    sh.className = 'pill ' + (S.settings.blocking_enabled ? 'ok' : 'warn');
    $('shield-txt').textContent = t('modeNormal') + ' · ' + (S.settings.blocking_enabled ? t('shieldNormal') : t('blockingOff'));
  }
  let info = c.enabled ? t('aiOn', { p: c.port, f: c.token_file }) : t('aiOff');
  const recent = c.client && (Date.now() / 1000 - c.client.time) < 30;
  if (c.enabled && c.client) info += '\n' + t('aiNow', { n: c.client.name, a: c.client.action });
  $('ai-info').textContent = info;
  $('ai-pill').classList.toggle('hidden', !(c.enabled && recent));
  if (c.client) $('ai-name').textContent = c.client.name;
}

async function refresh() {
  try {
    S = await invoke('get_state');
    applyAppearance(S.settings);
    renderTabs(); renderBookmarks(); renderStatus();
  } catch (e) { console.error(e); }
}

async function refreshPrivacy() {
  try {
    const p = await invoke('page_privacy');
    renderJs(p);
    if (!p) { $('fp').textContent = t('fpNone'); return; }
    const kinds = Object.keys(p.kinds || {}).join(', ');
    $('fp').textContent = p.fp ? t('fpSome', { n: p.fp, k: kinds }) : t('fpNone');
  } catch { $('fp').textContent = t('fpNone'); renderJs(null); }
}

// Nivel de seguridad: JavaScript de la web abierta, con botón para permitirlo o bloquearlo.
let jsInfo = null;
function renderJs(p) {
  jsInfo = p && p.level > 0 && p.host ? p : null;
  $('js-card').classList.toggle('hidden', !jsInfo);
  if (!jsInfo) return;
  $('js-state').textContent = t(jsInfo.js ? 'jsOn' : 'jsOff', { host: jsInfo.host });
  $('js-toggle').textContent = t(jsInfo.site_allowed ? 'jsBlock' : 'jsAllow', { host: jsInfo.host });
  // Si está permitida solo por el nivel (más seguro + https), no hace falta el botón.
  $('js-toggle').classList.toggle('hidden', jsInfo.js && !jsInfo.site_allowed);
}
$('js-toggle').onclick = async () => {
  if (!jsInfo) return;
  await invoke('set_js_site', { host: jsInfo.host, allow: !jsInfo.site_allowed }).catch(err => showAlert('notice', errText(err), [[t('ok'), '', null]]));
  setTimeout(refreshPrivacy, 1500);
};

// Las horas de la interfaz, en tu zona real (con la huella reforzada el motor va en UTC).
function tzo(o) {
  const z = window.__SYS_TZ;
  try { if (z) { new Intl.DateTimeFormat('en', { timeZone: z }); return Object.assign({ timeZone: z }, o); } } catch (e) {}
  return o || {};
}

function logText(l) {
  if (l.code && has('log_' + l.code)) {
    const p = Object.assign({}, l.params || {});
    if (Array.isArray(p.what)) p.what = p.what.map(w => t('c' + w[0].toUpperCase() + w.slice(1))).join(', ');
    return t('log_' + l.code, p);
  }
  return l.message;
}

async function refreshLogs() {
  const logs = await invoke('get_logs');
  const box = $('logs'); box.textContent = '';
  for (const l of logs.slice(-80).reverse()) {
    const d = el('div', 'log ' + l.kind);
    const time = new Date(l.time * 1000).toLocaleTimeString(LANG, tzo());
    d.append(el('span', 'k', t('kind_' + l.kind) + ' ' + time), document.createTextNode(logText(l)));
    box.append(d);
  }
}

/* ---------- avisos (sobre la web, empujando el contenido hacia abajo) ---------- */
function showAlert(kind, msg, buttons) {
  const a = el('div', 'alert ' + kind);
  a.append(el('span', 'msg', msg));
  for (const [label, cls, fn] of buttons) {
    const b = el('button', cls, label);
    b.onclick = () => { fn && fn(); a.remove(); reportRect(); };
    a.append(b);
  }
  $('alerts').append(a);
  reportRect();
  return a;
}
const approvalEls = new Map();
function errText(e) { const s = String(e); return has(s) ? t(s) : s; }

/* ---------- páginas internas ---------- */
function openPage(which) {
  pageOpen = which;
  $('page').classList.remove('hidden');
  $('view-settings').classList.toggle('hidden', which !== 'settings');
  $('view-history').classList.toggle('hidden', which !== 'history');
  $('view-passwords').classList.toggle('hidden', which !== 'passwords');
  $('page-title').textContent = t(which);
  reportRect();
  if (which === 'settings') fillSettings();
  if (which === 'history') loadHistory();
  if (which === 'passwords') showVault();
}
function closePage() {
  if (!pageOpen) return;
  if (pageOpen === 'passwords') clearVaultForms();
  pageOpen = null;
  $('page').classList.add('hidden');
  reportRect();
}

function fillStaticLists() {
  const sl = $('s-lang'); sl.textContent = '';
  const auto = el('option', null, t('langAuto')); auto.value = 'auto'; sl.append(auto);
  for (const [code, name] of Object.entries(LANG_NAMES)) { const o = el('option', null, name); o.value = code; sl.append(o); }
  const se = $('s-engine'); se.textContent = '';
  for (const [name, url, lvl] of ENGINES) { const o = el('option', null, name + (lvl === 'max' ? ' — ' + t('recommended') : '')); o.value = url; se.append(o); }
  const oc = el('option', null, t('custom')); oc.value = 'custom'; se.append(oc);
  const co = $('country'); const cur = co.value; co.textContent = '';
  for (const code of COUNTRIES) { const o = el('option', null, countryName(code)); o.value = code; co.append(o); }
  co.value = cur;
  const sw = $('s-accent'); sw.textContent = '';
  for (const [k, color] of Object.entries(ACCENTS)) {
    const b = el('button', 'sw'); b.style.background = color; b.title = k; b.dataset.k = k;
    b.onclick = () => save({ accent: k });
    sw.append(b);
  }
}

function fillSettings() {
  const s = S.settings;
  $('s-lang').value = s.language;
  $('s-theme').value = s.theme;
  $('s-fs').value = s.font_size; $('s-fs-val').textContent = s.font_size + 'px';
  $('s-compact').checked = s.compact;
  $('s-bmbar').checked = s.show_bookmarks;
  $('s-cleanexit').checked = s.clean_on_exit;
  $('s-histsearch').checked = s.history_searches;
  $('s-fpstrict').checked = s.fp_strict !== false;
  $('s-httpsonly').checked = s.https_only !== false;
  $('s-defprivate').checked = !!s.default_private;
  const n = privacyNote(s.search);
  $('s-engine-priv').textContent = n.text;
  $('s-engine-priv').className = 'priv ' + n.cls;
  document.querySelectorAll('input[name=hmode]').forEach(r => { r.checked = r.value === s.history_mode; });
  document.querySelectorAll('input[name=seclvl]').forEach(r => { r.checked = Number(r.value) === (s.security_level || 0); });
  document.querySelectorAll('#s-accent .sw').forEach(b => b.classList.toggle('on', b.dataset.k === s.accent));
  invoke('cert_info').then(c => {
    $('cert-mgr').classList.toggle('hidden', !c.manager);
    $('cert-mgr-note').classList.toggle('hidden', !c.manager);
    $('cert-af').textContent = t(c.autofirma ? 'afOk' : 'afNo');
    $('cert-af').className = 'priv ' + (c.autofirma ? 'max' : 'low');
    $('cert-afdl').classList.toggle('hidden', !!c.autofirma);
  }).catch(() => {});
  const known = ENGINES.find(e => e[1] === s.search);
  $('s-engine').value = known ? s.search : 'custom';
  $('s-engine-custom').classList.toggle('hidden', !!known);
  if (!known) $('s-engine-custom').value = s.search;
}

async function save(patch) {
  try {
    S.settings = await invoke('set_settings', { patch });
    applyAppearance(S.settings);
    if (pageOpen === 'settings') fillSettings();
    $('s-engine-err').classList.add('hidden');
    return true;
  } catch (e) {
    $('s-engine-err').textContent = errText(e);
    $('s-engine-err').classList.remove('hidden');
    return false;
  }
}

async function loadHistory() {
  const q = $('h-search').value;
  const r = await invoke('get_history', { query: q, limit: 500 });
  const list = $('h-list'); list.textContent = '';
  const mode = S.settings.history_mode;
  $('h-mode').textContent = t('historyMode') + ': ' + t(mode === 'off' ? 'histOff' : mode === 'save' ? 'histSave' : 'histSession');
  if (!r.items.length) { list.append(el('p', 'muted', t('histEmpty'))); return; }
  let day = '';
  for (const it of r.items) {
    const d = new Date(it.time * 1000);
    const dk = d.toLocaleDateString(LANG, tzo({ weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }));
    if (dk !== day) { day = dk; list.append(el('div', 'h-day', dk)); }
    const row = el('div', 'h-item');
    const tx = el('div', 'tx');
    tx.append(el('div', 'tt', it.title || hostOf(it.url)), el('div', 'uu', it.url));
    const rm = el('button', 'rm'); rm.title = t('remove');
    rm.innerHTML = '<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg>';
    rm.onclick = (ev) => { ev.stopPropagation(); invoke('remove_history', { url: it.url }).then(loadHistory); };
    row.append(el('span', 'tm', d.toLocaleTimeString(LANG, tzo({ hour: '2-digit', minute: '2-digit' }))), tx, rm);
    row.onclick = () => { closePage(); invoke('navigate', { id: null, input: it.url }); };
    list.append(row);
  }
}

/* Sugerencias de la barra de direcciones: favoritos + historial */
let sugTimer = null;
$('addr').addEventListener('input', () => {
  clearTimeout(sugTimer);
  sugTimer = setTimeout(async () => {
    const q = $('addr').value.trim();
    const dl = $('suggest'); dl.textContent = '';
    if (q.length < 2) return;
    const seen = new Set();
    for (const b of S.bookmarks) if ((b.url + b.title).toLowerCase().includes(q.toLowerCase())) seen.add(b.url);
    const r = await invoke('get_history', { query: q, limit: 8 });
    for (const it of r.items) seen.add(it.url);
    [...seen].slice(0, 8).forEach(u => { const o = el('option'); o.value = u; dl.append(o); });
  }, 150);
});

/* ---------- contraseñas ---------- */
let vaultPhraseShown = false;
const VSECTIONS = ['v-create', 'v-phrase', 'v-unlock', 'v-recover', 'v-main'];
function vShow(id) { for (const s of VSECTIONS) $(s).classList.toggle('hidden', s !== id); const f = $(id).querySelector('input'); if (f) setTimeout(() => f.focus(), 0); }
function vErr(id, e) { const p = $(id); if (e) { p.textContent = errText(e); p.classList.remove('hidden'); } else p.classList.add('hidden'); }
function clearVaultForms() {
  for (const id of ['vc-pass', 'vc-pass2', 'vu-pass', 'vr-phrase', 'vr-pass', 'vr-pass2']) $(id).value = '';
  $('vm-list').textContent = ''; $('vg-out').value = '';
  if (!vaultPhraseShown) $('vp-words').textContent = '';
}
async function showVault(st) {
  if (vaultPhraseShown) return vShow('v-phrase');   // no tapar la frase mientras se apunta
  st = st || await invoke('vault_status');
  if (!st.exists) return vShow('v-create');
  if (!st.unlocked) {
    $('vu-hint').textContent = st.hint ? t('vHintIs', { hint: st.hint }) : '';
    if ($('v-recover').classList.contains('hidden')) vShow('v-unlock');
    return;
  }
  vShow('v-main');
  $('vm-autolock').value = String(S.settings.vault_lock_min ?? 15);
  loadVault();
}
async function loadVault() {
  let r;
  try { r = await invoke('vault_list', { query: $('vm-search').value }); } catch (e) { return showVault(); }
  const list = $('vm-list'); list.textContent = '';
  if (!r.items.length) list.append(el('p', 'muted', t('vEmpty')));
  for (const it of r.items) {
    const row = el('div', 'pw-item');
    const tx = el('div', 'tx');
    const pv = el('div', 'pv hidden');
    tx.append(el('div', 'tt', it.host), el('div', 'uu', it.user || '—'), pv);
    const show = el('button', 'btn', t('vShow'));
    show.onclick = async () => {
      if (!pv.classList.contains('hidden')) { pv.textContent = ''; pv.classList.add('hidden'); show.textContent = t('vShow'); return; }
      pv.textContent = await invoke('vault_reveal', { id: it.id }); pv.classList.remove('hidden'); show.textContent = t('vHide');
    };
    const copy = el('button', 'btn', t('vCopy'));
    copy.onclick = async () => copyPass(await invoke('vault_reveal', { id: it.id }));
    const rm = el('button', 'rm'); rm.title = t('remove');
    rm.innerHTML = '<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg>';
    rm.onclick = () => showAlert('cred', t('vDeleteQ', { host: it.host, user: it.user || '—' }), [
      [t('remove'), '', () => invoke('vault_delete', { id: it.id }).then(loadVault)], [t('cancel'), 'no', null]]);
    row.append(tx, show, copy, rm);
    list.append(row);
  }
  const nv = $('vm-never'); nv.textContent = '';
  if (!r.never.length) nv.append(el('p', 'muted small', '—'));
  for (const h of r.never) {
    const c = el('span', 'chip-x', h); const x = el('button', null, '×'); x.title = t('remove');
    x.onclick = () => invoke('vault_never_remove', { host: h }).then(loadVault);
    c.append(x); nv.append(c);
  }
}
let clipTimer = null;
async function copyPass(p) {
  try { await navigator.clipboard.writeText(p); } catch { return; }
  const m = $('vm-msg'); m.textContent = t('vCopied'); m.classList.remove('hidden');
  clearTimeout(clipTimer);
  // El portapapeles se vacía a los 30 s para que la contraseña no se quede ahí.
  clipTimer = setTimeout(() => { navigator.clipboard.writeText('').catch(() => {}); m.classList.add('hidden'); }, 30000);
}
function genPassword(len, sym) {
  const sets = ['abcdefghijkmnopqrstuvwxyz', 'ABCDEFGHJKLMNPQRSTUVWXYZ', '23456789'];
  if (sym) sets.push('!#$%&*+-=?@_~.:');
  const all = sets.join('');
  const rnd = (n) => { const a = new Uint32Array(1); const lim = Math.floor(0x100000000 / n) * n; do crypto.getRandomValues(a); while (a[0] >= lim); return a[0] % n; };
  for (;;) {
    let p = ''; for (let i = 0; i < len; i++) p += all[rnd(all.length)];
    if (sets.every(s => [...p].some(c => s.includes(c)))) return p;
  }
}
$('vc-go').onclick = async () => {
  const p = $('vc-pass').value, p2 = $('vc-pass2').value;
  if (p.length < 8) return vErr('vc-err', 'vaultShort');
  if (p !== p2) return vErr('vc-err', 'vMismatch');
  vErr('vc-err'); $('vc-go').disabled = true;
  try {
    const phrase = await invoke('vault_create', { password: p, hint: $('vc-hint').value.trim(), lang: LANG });
    $('vc-pass').value = $('vc-pass2').value = '';
    const ol = $('vp-words'); ol.textContent = '';
    for (const w of phrase.split(' ')) ol.append(el('li', null, w));
    $('vp-ok').checked = false; $('vp-go').disabled = true;
    vaultPhraseShown = true; vShow('v-phrase');
  } catch (e) { vErr('vc-err', e); }
  $('vc-go').disabled = false;
};
$('vp-ok').onchange = () => { $('vp-go').disabled = !$('vp-ok').checked; };
$('vp-go').onclick = () => { vaultPhraseShown = false; $('vp-words').textContent = ''; showVault(); retryCred(); };
async function doUnlock() {
  const p = $('vu-pass').value; if (!p) return;
  $('vu-go').disabled = true;
  try { await invoke('vault_unlock', { password: p }); $('vu-pass').value = ''; vErr('vu-err'); showVault(); retryCred(); }
  catch (e) { vErr('vu-err', e); $('vu-pass').select(); }
  $('vu-go').disabled = false;
}
$('vu-go').onclick = doUnlock;
$('vu-form').onsubmit = (e) => { e.preventDefault(); doUnlock(); };
$('vu-forgot').onclick = () => { vErr('vr-err'); vShow('v-recover'); };
$('vr-back').onclick = () => vShow('v-unlock');
$('vr-go').onclick = async () => {
  const p = $('vr-pass').value;
  if (p.length < 8) return vErr('vr-err', 'vaultShort');
  if (p !== $('vr-pass2').value) return vErr('vr-err', 'vMismatch');
  $('vr-go').disabled = true;
  try {
    await invoke('vault_recover', { phrase: $('vr-phrase').value, password: p, hint: $('vr-hint').value.trim() });
    $('vr-phrase').value = $('vr-pass').value = $('vr-pass2').value = ''; vErr('vr-err');
    vShow('v-main'); showVault(); retryCred();
  } catch (e) { vErr('vr-err', e); }
  $('vr-go').disabled = false;
};
$('vm-lock').onclick = () => invoke('vault_lock').then(() => showVault());
let vTimer = null;
$('vm-search').oninput = () => { clearTimeout(vTimer); vTimer = setTimeout(loadVault, 200); };
$('vm-autolock').onchange = () => save({ vault_lock_min: Number($('vm-autolock').value) });
$('vg-len').oninput = () => { $('vg-len-val').textContent = $('vg-len').value; };
$('vg-go').onclick = () => { $('vg-out').value = genPassword(Number($('vg-len').value), $('vg-sym').checked); };
$('vg-copy').onclick = () => { if ($('vg-out').value) copyPass($('vg-out').value); };
$('btn-keys').onclick = () => (pageOpen === 'passwords' ? closePage() : openPage('passwords'));

/* "¿Guardar la contraseña?" al entrar o registrarse en una web */
let waitingCred = null;   // pregunta pendiente de desbloquear la bóveda
function retryCred() { if (waitingCred) { const c = waitingCred; waitingCred = null; answerCred(c, c.action || 'save'); } }
async function answerCred(c, action) {
  try {
    await invoke('cred_answer', { id: c.id, action });
    if (action === 'save') showAlert('cred', t('credSaved'), [[t('ok'), '', null]]);
  } catch (e) {
    if (String(e) === 'vaultLocked') { waitingCred = Object.assign(c, { action }); openPage('passwords'); }
  }
}
const credAlerts = new Map();   // una pregunta por web
listen('cred', (ev) => {
  const c = ev.payload;
  const old = credAlerts.get(c.host); if (old) { old.remove(); reportRect(); }
  const msg = c.update ? t('credUpdate', { user: c.user || '—', host: c.host })
    : c.user ? t('credSave', { user: c.user, host: c.host }) : t('credSaveNoUser', { host: c.host });
  credAlerts.set(c.host, showAlert('cred', msg, [
    [c.update ? t('vUpdate') : t('save'), '', () => answerCred(c, 'save')],
    [t('notNow'), 'no', () => answerCred(c, 'no')],
    [t('neverHere'), 'no', () => answerCred(c, 'never')],
  ]));
});
listen('vault', (ev) => {
  if (pageOpen === 'passwords') showVault(ev.payload);
  updateFill();
});

/* Botón de la llave en la barra: rellenar en esta web */
async function updateFill() {
  const a = activeTab();
  if (!a || !a.has_view) { $('btn-fill').classList.add('hidden'); return; }
  const r = await invoke('vault_matches').catch(() => null);
  $('btn-fill').classList.toggle('hidden', !r || !r.host);
  $('btn-fill').classList.toggle('on', !!(r && r.items.length));
}
let fillT = null, fillKey = '';
function updateFillSoon() { const a = activeTab(); const k = a ? a.id + a.url + a.loading : ''; if (k === fillKey) return; fillKey = k; clearTimeout(fillT); fillT = setTimeout(updateFill, 300); }
$('btn-fill').onclick = async () => {
  const r = await invoke('vault_matches');
  if (!r.vault.exists || !r.vault.unlocked) return openPage('passwords');
  const fill = (args) => invoke('vault_fill', args).then(res => { if (res === 'nofield') showAlert('notice', t('vNoField'), [[t('ok'), '', null]]); });
  const btns = r.items.slice(0, 4).map(it => [it.user || it.host, '', () => fill({ id: it.id, generated: null })]);
  btns.push([t('vGenFill'), 'no', () => fill({ id: null, generated: genPassword(20, true) })]);
  btns.push([t('cancel'), 'no', null]);
  showAlert('cred', r.items.length ? t('vFillFor', { host: r.host }) : t('vNoMatch'), btns);
};

/* ---------- eventos ---------- */
$('btn-newtab').onclick = () => { closePage(); invoke('new_tab', { url: null, private: false }); };
$('btn-newtab-private').onclick = () => { closePage(); invoke('new_tab', { url: null, private: true }); };
$('btn-back').onclick = () => invoke('nav_action', { action: 'back' });
$('btn-fwd').onclick = () => invoke('nav_action', { action: 'forward' });
$('btn-reload').onclick = () => invoke('nav_action', { action: 'reload' });
$('btn-home').onclick = () => { closePage(); invoke('nav_action', { action: 'home' }); };
$('addr').onfocus = () => { editingAddr = true; setTimeout(() => $('addr').select(), 0); };
$('addr').onblur = () => { editingAddr = false; };
$('addr-form').onsubmit = (e) => { e.preventDefault(); const v = $('addr').value; $('addr').blur(); closePage(); invoke('navigate', { id: null, input: v }).catch(err => showAlert('notice', errText(err), [[t('ok'), '', null]])); };
$('search-form').onsubmit = (e) => { e.preventDefault(); const v = $('search').value; $('search').value = ''; invoke('navigate', { id: null, input: v }); };
$('btn-star').onclick = async () => {
  const a = activeTab(); if (!a || !a.has_view) return;
  if (S.bookmarks.some(b => b.url === a.url)) await invoke('remove_bookmark', { url: a.url });
  else await invoke('add_bookmark', { url: a.url, title: a.title || hostOf(a.url), folder: null });
  refresh();
};
$('btn-panel').onclick = () => { $('panel').classList.toggle('hidden'); reportRect(); refreshLogs(); };
$('shield').onclick = $('btn-panel').onclick;
$('ai-pill').onclick = $('btn-panel').onclick;
$('btn-settings').onclick = () => (pageOpen === 'settings' ? closePage() : openPage('settings'));
$('btn-history').onclick = () => (pageOpen === 'history' ? closePage() : openPage('history'));
$('page-close').onclick = closePage;
$('country').onchange = (e) => invoke('set_country', { code: e.target.value || null }).then(refresh).catch(err => showAlert('notice', errText(err), [[t('ok'), '', null]]));
$('btn-newid').onclick = () => invoke('new_identity').then(refreshLogs);
$('btn-checkip').onclick = () => { closePage(); invoke('new_tab', { url: 'https://check.torproject.org/', private: true }); };
$('t-block').onchange = (e) => invoke('set_blocking', { enabled: e.target.checked }).then(refresh);
$('t-ai').onchange = (e) => invoke('set_control', { enabled: e.target.checked }).then(refresh).then(refreshLogs);
$('btn-cut').onclick = () => invoke('cut_ai').then(refresh).then(refreshLogs);
$('btn-clearlog').onclick = () => invoke('clear_logs').then(refreshLogs);
$('btn-quickclean').onclick = () => { openPage('settings'); setTimeout(() => $('cleaner').scrollIntoView({ behavior: 'smooth' }), 50); };

// Ajustes
$('s-lang').onchange = (e) => save({ language: e.target.value });
$('s-theme').onchange = (e) => save({ theme: e.target.value });
$('s-fs').oninput = (e) => { $('s-fs-val').textContent = e.target.value + 'px'; document.documentElement.style.setProperty('--fs', e.target.value + 'px'); };
$('s-fs').onchange = (e) => save({ font_size: Number(e.target.value) });
$('s-compact').onchange = (e) => save({ compact: e.target.checked });
$('s-bmbar').onchange = (e) => save({ show_bookmarks: e.target.checked });
$('s-cleanexit').onchange = (e) => save({ clean_on_exit: e.target.checked });
$('s-histsearch').onchange = (e) => save({ history_searches: e.target.checked });
$('s-fpstrict').onchange = (e) => save({ fp_strict: e.target.checked });
$('s-httpsonly').onchange = (e) => save({ https_only: e.target.checked });
$('s-defprivate').onchange = (e) => save({ default_private: e.target.checked });
$('cert-mgr').onclick = () => invoke('open_cert_manager').catch(err => showAlert('notice', errText(err), [[t('ok'), '', null]]));
$('cert-afdl').onclick = () => { closePage(); invoke('new_tab', { url: 'https://firmaelectronica.gob.es/Home/Descargas.html', private: false }); };
$('hw-back').onclick = () => invoke('nav_action', { action: 'home' });
$('hw-go').onclick = () => { const a = activeTab(); if (a) invoke('allow_http', { id: a.id }).catch(err => showAlert('notice', errText(err), [[t('ok'), '', null]])); };
// Botones de la ventana. En Windows ya los pone el sistema en la barra de título.
const FRAMELESS = !/Windows/.test(navigator.userAgent);
if (FRAMELESS) { $('winctl').classList.remove('hidden'); document.documentElement.classList.add('frameless'); }
// Sin barra del sistema, los bordes de la ventana (5 px) sirven para cambiar su tamaño.
const EDGE = 5;
const edgeDir = (e) => {
  let d = e.clientY < EDGE ? 'North' : e.clientY >= innerHeight - EDGE ? 'South' : '';
  d += e.clientX < EDGE ? 'West' : e.clientX >= innerWidth - EDGE ? 'East' : '';
  return d;
};
const EDGE_CURSOR = { North: 'ns-resize', South: 'ns-resize', East: 'ew-resize', West: 'ew-resize', NorthEast: 'nesw-resize', SouthWest: 'nesw-resize', NorthWest: 'nwse-resize', SouthEast: 'nwse-resize' };
if (FRAMELESS) {
  document.addEventListener('mousemove', (e) => { document.documentElement.style.cursor = EDGE_CURSOR[edgeDir(e)] || ''; });
  document.addEventListener('mousedown', (e) => {
    const d = e.button === 0 && edgeDir(e);
    if (!d) return;
    e.preventDefault(); e.stopPropagation();
    invoke('window_action', { action: 'resize:' + d });
  }, true);
}
$('btn-min').onclick = () => invoke('window_action', { action: 'min' });
$('btn-max').onclick = () => invoke('window_action', { action: 'max' });
$('btn-close').onclick = () => invoke('window_action', { action: 'close' });
// La zona vacía de la barra de pestañas mueve la ventana; doble clic la maximiza.
$('tabbar').addEventListener('mousedown', (e) => {
  if (e.button !== 0 || $('winctl').classList.contains('hidden')) return;
  if (e.target !== $('tabbar') && e.target !== $('tabs') && !e.target.closest('.brand')) return;
  e.preventDefault();
  invoke('window_action', { action: e.detail === 2 ? 'max' : 'drag' });
});
document.querySelectorAll('input[name=hmode]').forEach(r => { r.onchange = () => save({ history_mode: r.value }); });
document.querySelectorAll('input[name=seclvl]').forEach(r => { r.onchange = () => save({ security_level: Number(r.value) }); });
$('s-engine').onchange = (e) => {
  const custom = e.target.value === 'custom';
  $('s-engine-custom').classList.toggle('hidden', !custom);
  if (custom) $('s-engine-custom').focus(); else save({ search: e.target.value });
};
$('s-engine-custom').onchange = (e) => save({ search: e.target.value });
$('s-viewhist').onclick = () => openPage('history');
$('btn-clean').onclick = async () => {
  const opts = {};
  document.querySelectorAll('[data-clean]').forEach(c => { opts[c.dataset.clean] = c.checked; });
  await invoke('clean', { opts });
  $('clean-msg').textContent = t('cleanedMsg');
  $('clean-msg').classList.remove('hidden');
  setTimeout(() => $('clean-msg').classList.add('hidden'), 3000);
  refresh(); refreshLogs();
};

// Historial
let hTimer = null;
$('h-search').oninput = () => { clearTimeout(hTimer); hTimer = setTimeout(loadHistory, 200); };
$('h-clear').onclick = () => invoke('clean', { opts: { history: true } }).then(loadHistory);

window.addEventListener('keydown', (e) => {
  const k = e.key.toLowerCase();
  if (e.ctrlKey && !e.shiftKey && k === 't') { e.preventDefault(); $('btn-newtab').click(); }
  if (e.ctrlKey && e.shiftKey && k === 'n') { e.preventDefault(); $('btn-newtab-private').click(); }
  if (e.ctrlKey && k === 'w') { e.preventDefault(); if (S && S.active) invoke('close_tab', { id: S.active }); }
  if (e.ctrlKey && k === 'l') { e.preventDefault(); $('addr').focus(); }
  if (e.ctrlKey && k === 'h') { e.preventDefault(); openPage('history'); }
  if (e.ctrlKey && e.shiftKey && (k === 'delete' || k === 'supr')) { e.preventDefault(); $('btn-quickclean').click(); }
  if (e.key === 'Escape' && pageOpen) closePage();
  if (e.altKey && e.key === 'Home') { e.preventDefault(); $('btn-home').click(); }
  if (e.key === 'F5') { e.preventDefault(); invoke('nav_action', { action: 'reload' }); }
});

listen('tabs', (ev) => { if (!S) return; S.tabs = ev.payload.list; S.active = ev.payload.active; renderTabs(); updateFillSoon(); });
listen('log', () => { if (!$('panel').classList.contains('hidden')) refreshLogs(); });
listen('approval', (ev) => {
  const { id, kind, params, message } = ev.payload;
  const msg = has('ap_' + kind) ? t('ap_' + kind, params || {}) : message;
  const a = showAlert('approval', msg, [
    [t('allow'), '', () => invoke('resolve_approval', { id, allow: true })],
    [t('deny'), 'no', () => invoke('resolve_approval', { id, allow: false })],
  ]);
  approvalEls.set(id, a);
});
listen('approval-closed', (ev) => { const a = approvalEls.get(ev.payload); if (a) { a.remove(); approvalEls.delete(ev.payload); reportRect(); } });
listen('captcha', (ev) => showAlert('captcha', t('captcha', { h: ev.payload }), [[t('ok'), '', null]]));
listen('intruder', (ev) => showAlert('intruder', t('intruder', { m: logText(ev.payload) }), [[t('ok'), '', null]]));
listen('notice', (ev) => {
  const p = ev.payload;
  const msg = typeof p === 'string' ? p : (has('notice_' + p.code) ? t('notice_' + p.code) : p.message);
  // Certificado o AutoFirma en modo Sombra: se ofrece abrir la misma web en una pestaña normal.
  const btns = [[t('ok'), '', null]];
  if (p && /^https?:/.test(p.url || '')) btns.unshift([t('openNormal'), 'primary', () => invoke('new_tab', { url: p.url, private: false })]);
  showAlert('notice', msg, btns);
});
listen('ai-activity', () => refresh());

/* ---------- arranque ---------- */
(async () => {
  await refresh();
  if (!S.tabs.length) await invoke('new_tab', { url: null });
  reportRect();
  $('search').focus();
  setInterval(refresh, 1000);
  setInterval(refreshPrivacy, 3000);
})();

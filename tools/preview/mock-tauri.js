// Simulación de Tauri para ver la interfaz en un navegador normal (solo para desarrollo).
(() => {
  const now = Math.floor(Date.now() / 1000);
  const state = {
    tabs: [
      { id: 1, url: 'https://duckduckgo.com/?q=sombra', title: 'sombra en DuckDuckGo', loading: false, has_view: true, favicon: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAFklEQVR4nGO4F+xAEmIY1TCqYfhqAADKK3EQzpjpuQAAAABJRU5ErkJggg==' },
      { id: 2, url: 'https://es.wikipedia.org/wiki/Tor', title: 'Tor (red de anonimato) - Wikipedia', loading: true, has_view: true },
      { id: 3, url: 'https://www.openstreetmap.org/', title: 'OpenStreetMap', loading: false, has_view: false, favicon: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAFklEQVR4nGMwTjtDEmIY1TCqYfhqAAAyDmUQmz6KNwAAAABJRU5ErkJggg==' },
      { id: 4, url: 'https://check.torproject.org/', title: 'Check Tor', loading: false, has_view: true, private: true },
    ],
    active: 1,
    tor: { ready: true, progress: 1, message: '', country: 'DE', error: null },
    stats: { ads: 128, trackers: 342, leaks: 3, page: 17, connections: 900 },
    blocker_ready: true,
    settings: {
      control_enabled: true, blocking_enabled: true, country: 'DE', search: new URLSearchParams(location.search).get('engine') || 'https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/?q=%s',
      language: new URLSearchParams(location.search).get('lang') || 'auto', theme: new URLSearchParams(location.search).get('theme') || 'dark',
      accent: 'violet', font_size: 13, compact: false, show_bookmarks: true, history_mode: 'session', clean_on_exit: false,
    },
    bookmarks: [
      { url: 'https://es.wikipedia.org/', title: 'Wikipedia' }, { url: 'https://www.openstreetmap.org/', title: 'OpenStreetMap' },
      { url: 'https://github.com/', title: 'GitHub' }, { url: 'https://news.ycombinator.com/', title: 'Hacker News' },
    ],
    control: { enabled: true, port: 47821, client: { name: 'Claude', time: now, action: 'read' }, token_file: '/home/u/.local/share/Sombra/control.json' },
  };
  const history = [
    { url: 'https://es.wikipedia.org/wiki/Tor', title: 'Tor (red de anonimato) - Wikipedia', time: now - 60 },
    { url: 'https://duckduckgo.com/?q=sombra', title: 'sombra en DuckDuckGo', time: now - 600 },
    { url: 'https://www.openstreetmap.org/', title: 'OpenStreetMap', time: now - 90000 },
  ];
  const logs = [
    { time: now - 30, kind: 'seguridad', code: 'ctlOn', params: { port: 47821 }, message: '' },
    { time: now - 20, kind: 'intruso', code: 'badToken', params: { n: 2 }, message: '' },
    { time: now - 10, kind: 'ia', code: '', params: null, message: 'Claude: read {}' },
  ];
  const vault = { exists: new URLSearchParams(location.search).get('vault') !== 'new', unlocked: false };
  const handlers = {
    get_state: () => JSON.parse(JSON.stringify(state)),
    page_privacy: () => ({ fp: 4, kinds: { canvas: 3, webgl: 1 } }),
    get_logs: () => logs,
    get_history: ({ query }) => ({ items: history.filter(h => !query || (h.url + h.title).toLowerCase().includes(query.toLowerCase())), total: history.length }),
    set_settings: ({ patch }) => { Object.assign(state.settings, patch); return state.settings; },
    activate_tab: ({ id }) => { state.active = id; },
    site_perms: () => [{ origin: 'https://meet.jit.si', perm: 'camera', allow: true }, { origin: 'https://meet.jit.si', perm: 'microphone', allow: true }, { origin: 'https://www.openstreetmap.org', perm: 'geolocation', allow: false }, { origin: 'https://noticias-muy-largas-del-dia.example.com', perm: 'notifications', allow: false }],
    move_tab: ({ id, to }) => { const i = state.tabs.findIndex(t => t.id === id); const [t] = state.tabs.splice(i, 1); state.tabs.splice(Math.min(to, state.tabs.length), 0, t); window.__lastMove = { id, to }; },
    clean: () => ({ done: [] }),
    vault_status: () => ({ exists: vault.exists, unlocked: vault.unlocked, hint: 'el perro', count: 2 }),
    vault_create: () => { vault.exists = true; vault.unlocked = true; return 'ábaco cuerda nieve primo tarde lobo yema fino ruta salsa olor vapor'; },
    vault_unlock: ({ password }) => { if (password !== '12345678') throw 'vaultWrong'; vault.unlocked = true; },
    vault_lock: () => { vault.unlocked = false; },
    vault_list: () => { if (!vault.unlocked) throw 'vaultLocked'; return { items: [{ id: 1, host: 'github.com', user: 'ana@correo.es', updated: now }, { id: 2, host: 'wikipedia.org', user: 'Ana', updated: now }], never: ['bancomalo.com'] }; },
    vault_reveal: () => 'Xk7#pQ2m!vR9wL4z',
    downloads_list: () => [
      { id: 1, name: 'informe-2026.pdf', folder: 'C:\\Users\\ana\\Downloads', received: 2400000, total: 2400000, state: 'done', private: false, eta: null },
      { id: 2, name: 'ubuntu-24.04-desktop-amd64.iso', folder: 'C:\\Users\\ana\\Downloads', received: 1288490188, total: 6114770944, state: 'progress', private: false, eta: 412 },
      { id: 3, name: 'documento.zip', folder: 'C:\\Users\\ana\\Downloads', received: 5242880, total: 0, state: 'progress', private: true, eta: null },
      { id: 4, name: 'video.mp4', folder: 'C:\\Users\\ana\\Downloads', received: 100, total: 900, state: 'cancelled', private: false, eta: null },
    ],
    vault_matches: () => ({ vault: { exists: vault.exists, unlocked: vault.unlocked }, host: 'duckduckgo.com', items: [] }),
  };
  window.__TAURI__ = {
    core: { invoke: async (cmd, args) => (handlers[cmd] ? handlers[cmd](args || {}) : null) },
    event: { listen: async () => () => {} },
  };
})();

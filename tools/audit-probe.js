// Sombra - sonda de auditoría (solo pruebas, SOMBRA_AUDIT). Se ejecuta dentro de una página
// normal y prueba lo que podría intentar una web: saltarse las protecciones con un iframe o un
// Worker, tocar la red local o la puerta de control, y sacar datos del equipo.
// Deja el resultado en window.__audit (JSON) cuando termina.
(() => {
  window.__audit = 'esperando';
  const R = {};
  const tryv = (f) => { try { return f(); } catch (e) { return 'error: ' + String(e).slice(0, 80); } };
  // 1) Lo que ve la página.
  R.page = tryv(() => ({
    ua: navigator.userAgent,
    brands: navigator.userAgentData ? navigator.userAgentData.brands.map(b => b.brand + ' ' + b.version) : null,
    platform: navigator.platform,
    lang: navigator.language,
    hc: navigator.hardwareConcurrency,
    mem: navigator.deviceMemory,
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    off: new Date().getTimezoneOffset(),
    screen: [screen.width, screen.height, devicePixelRatio],
    webdriver: navigator.webdriver,
    plugins: navigator.plugins ? navigator.plugins.length : null,
    rtc: typeof window.RTCPeerConnection,
    battery: typeof navigator.getBattery,
    media: typeof navigator.mediaDevices,
    gpu: typeof navigator.gpu,
    usb: typeof navigator.usb,
    bt: typeof navigator.bluetooth,
    serial: typeof navigator.serial,
    hid: typeof navigator.hid,
    share: typeof navigator.share,
    notif: typeof Notification !== 'undefined' ? Notification.permission : 'n/a',
    sw: typeof navigator.serviceWorker,
    cookies: navigator.cookieEnabled,
    dnt: navigator.doNotTrack,
    gpc: navigator.globalPrivacyControl,
  }));
  // 2) Resolución del reloj (ataques de tiempo).
  R.timer = tryv(() => { const s = new Set(); let t = performance.now(); for (let i = 0; i < 20000 && s.size < 50; i++) { const n = performance.now(); if (n !== t) { s.add(Math.round((n - t) * 1e6) / 1e6); t = n; } } return [...s].sort((a, b) => a - b).slice(0, 3); });
  // 3) ¿Se salta la protección un iframe en blanco creado por la página?
  R.iframe = tryv(() => {
    const f = document.createElement('iframe');
    document.body.appendChild(f);
    const w = f.contentWindow;
    const d = new w.Date(2020, 0, 1, 12, 0);
    const c = w.document.createElement('canvas');
    return {
      hc: w.navigator.hardwareConcurrency,
      lang: w.navigator.language,
      tz: w.Intl.DateTimeFormat().resolvedOptions().timeZone,
      hours: d.getHours(),
      rtc: typeof w.RTCPeerConnection,
      screen: w.screen.width,
      canvasWrapped: w.HTMLCanvasElement.prototype.toDataURL.toString().includes('native') && w.HTMLCanvasElement.prototype.toDataURL !== c.toDataURL ? 'raro' : (w.HTMLCanvasElement.prototype.toDataURL === HTMLCanvasElement.prototype.toDataURL ? 'mismo' : 'otro'),
      gl: (() => { const g = c.getContext('webgl'); if (!g) return null; return g.getParameter(37446); })(),
    };
  });
  // 4) Canvas: ¿se nota la protección? (dibujar un píxel y leerlo)
  R.canvasLie = tryv(() => {
    const c = document.createElement('canvas'); c.width = c.height = 8;
    const x = c.getContext('2d'); x.fillStyle = 'rgb(10,20,30)'; x.fillRect(0, 0, 8, 8);
    const d = x.getImageData(0, 0, 8, 8).data;
    return [d[0], d[1], d[2], d[97], d[98]].join(',');
  });
  // 4b) Canvas con texto: huella (resumen) y si sale igual dos veces seguidas.
  R.canvasFp = tryv(() => {
    const c = document.createElement('canvas'); c.width = 220; c.height = 40;
    const x = c.getContext('2d'); x.textBaseline = 'top'; x.font = '16px Arial'; x.fillStyle = '#f60'; x.fillRect(0, 0, 100, 20); x.fillStyle = '#069'; x.fillText('Sombra 😀 audit', 2, 12);
    const h = (s) => { let v = 0; for (let i = 0; i < s.length; i++) v = (Math.imul(v, 31) + s.charCodeAt(i)) | 0; return (v >>> 0).toString(16); };
    const a = c.toDataURL(), b = c.toDataURL();
    return { hash: h(a), stable: a === b };
  });
  const jobs = [];
  // 4c) Audio: huella clásica (oscilador + compresor).
  jobs.push(new Promise(done => {
    try {
      const A = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      const ctx = new A(1, 5000, 44100); const o = ctx.createOscillator(); o.type = 'triangle'; o.frequency.value = 10000;
      const k = ctx.createDynamicsCompressor(); o.connect(k); k.connect(ctx.destination); o.start(0);
      ctx.startRendering().then(buf => { const d = buf.getChannelData(0); let s = 0; for (let i = 4500; i < 5000; i++) s += Math.abs(d[i]); R.audioFp = s; done(); }, () => { R.audioFp = 'error'; done(); });
      setTimeout(() => { if (R.audioFp === undefined) R.audioFp = 'sin respuesta'; done(); }, 5000);
    } catch (e) { R.audioFp = 'error ' + e; done(); }
  }));
  // 5) Worker: ¿qué ve el código en segundo plano?
  jobs.push(new Promise(done => {
    try {
      const src = 'postMessage({hc:navigator.hardwareConcurrency,lang:navigator.language,tz:Intl.DateTimeFormat().resolvedOptions().timeZone,off:new Date().getTimezoneOffset(),ua:navigator.userAgent.slice(0,60),mem:navigator.deviceMemory})';
      const wk = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
      wk.onmessage = (e) => { R.worker = e.data; done(); };
      wk.onerror = (e) => { R.worker = 'error ' + (e.message || ''); done(); };
      setTimeout(() => { if (!R.worker) R.worker = 'sin respuesta'; done(); }, 5000);
    } catch (e) { R.worker = 'error: ' + e; done(); }
  }));
  // 6) Red local y este PC: deberían fallar todas.
  const targets = ['http://127.0.0.1:47821/v1/status', 'http://localhost:47821/v1/status', 'http://192.168.1.1/', 'http://10.0.0.1/', 'http://[::ffff:127.0.0.1]:47821/', 'http://127.1:47821/', 'http://0.0.0.0:47821/', 'http://router.lan/'];
  R.local = {};
  for (const u of targets) {
    jobs.push(new Promise(done => {
      const t = setTimeout(() => { R.local[u] = 'tiempo agotado'; done(); }, 12000);
      fetch(u, { method: 'POST', mode: 'no-cors', body: '{}' }).then(r => { clearTimeout(t); R.local[u] = 'RESPONDE ' + r.type + ' ' + r.status; done(); }, e => { clearTimeout(t); R.local[u] = 'bloqueado'; done(); });
    }));
  }
  // 7) WebSocket a la puerta de control.
  jobs.push(new Promise(done => {
    try {
      const ws = new WebSocket('ws://127.0.0.1:47821/');
      const t = setTimeout(() => { R.ws = 'tiempo agotado'; try { ws.close(); } catch (e) {} done(); }, 8000);
      ws.onopen = () => { clearTimeout(t); R.ws = 'ABIERTO'; ws.close(); done(); };
      ws.onerror = () => { clearTimeout(t); R.ws = 'bloqueado'; done(); };
    } catch (e) { R.ws = 'error ' + e; done(); }
  }));
  // 8) Almacenamiento: ¿hay algo guardado de antes? (debería empezar vacío)
  R.storage = tryv(() => ({ ls: localStorage.length, cookie: document.cookie.length }));
  Promise.all(jobs).then(() => { window.__audit = JSON.stringify(R); });
  return 'lanzada';
})()

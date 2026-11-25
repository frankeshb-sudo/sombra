// Sombra - sistema de idiomas. Cada idioma está en ui/locales/<código>.js.
// Para añadir uno: copia locales/en.js, tradúcelo, añádelo a index.html y a LANG_NAMES.
// Licencia GPL-3.0-or-later.
const I18N = {};
const LANG_NAMES = {
  es: 'Español', en: 'English', fr: 'Français', de: 'Deutsch', it: 'Italiano', pt: 'Português',
  ca: 'Català', nl: 'Nederlands', pl: 'Polski', ru: 'Русский', zh: '中文', ja: '日本語', ar: 'العربية',
};
const RTL = ['ar'];
let LANG = 'es';

function pickLang(setting) {
  if (setting && setting !== 'auto' && I18N[setting]) return setting;
  for (const l of navigator.languages || [navigator.language || 'es']) {
    const c = String(l).toLowerCase().slice(0, 2);
    if (I18N[c]) return c;
  }
  return 'en';
}

function t(key, vars) {
  let s = (I18N[LANG] && I18N[LANG][key]) ?? (I18N.en && I18N.en[key]) ?? (I18N.es && I18N.es[key]) ?? key;
  if (vars) for (const k in vars) s = s.split('{' + k + '}').join(vars[k]);
  return s;
}

function has(key) {
  return !!((I18N[LANG] && I18N[LANG][key]) || (I18N.en && I18N.en[key]));
}

function applyI18n(setting) {
  LANG = pickLang(setting);
  document.documentElement.lang = LANG;
  document.documentElement.dir = RTL.includes(LANG) ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-t]').forEach(e => { e.textContent = t(e.dataset.t); });
  document.querySelectorAll('[data-t-title]').forEach(e => { e.title = t(e.dataset.tTitle); e.setAttribute('aria-label', e.title); });
  document.querySelectorAll('[data-t-ph]').forEach(e => { e.placeholder = t(e.dataset.tPh); });
}

// Comprueba que todos los idiomas tienen las mismas claves que el español
// y que las claves usadas en la interfaz existen. Uso: node tools/check-locales.mjs
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const ui = join(dirname(fileURLToPath(import.meta.url)), '..', 'ui');
const ctx = { I18N: {} };
vm.createContext(ctx);
for (const f of readdirSync(join(ui, 'locales'))) vm.runInContext(readFileSync(join(ui, 'locales', f), 'utf8'), ctx, { filename: f });

const base = Object.keys(ctx.I18N.es);
let bad = 0;
for (const [lang, dict] of Object.entries(ctx.I18N)) {
  const missing = base.filter(k => !(k in dict));
  const extra = Object.keys(dict).filter(k => !base.includes(k));
  const vars = base.filter(k => dict[k] && (ctx.I18N.es[k].match(/\{\w+\}/g) || []).some(v => !dict[k].includes(v)));
  if (missing.length || extra.length || vars.length) { bad++; console.log(lang, { missing, extra, varsMissing: vars }); }
}
// Claves usadas en HTML y JS
const html = readFileSync(join(ui, 'index.html'), 'utf8');
const js = readFileSync(join(ui, 'app.js'), 'utf8');
const used = new Set([...html.matchAll(/data-t(?:-title|-ph)?="(\w+)"/g)].map(m => m[1]));
for (const m of js.matchAll(/\bt\('(\w+)'\s*[,)]/g)) used.add(m[1]);
const undef = [...used].filter(k => !base.includes(k));
if (undef.length) { bad++; console.log('Claves usadas sin traducir:', undef); }
console.log(`${Object.keys(ctx.I18N).length} idiomas, ${base.length} textos cada uno. ${bad ? 'HAY PROBLEMAS' : 'Todo correcto.'}`);
process.exit(bad ? 1 : 0);

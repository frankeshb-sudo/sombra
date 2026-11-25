#!/usr/bin/env node
// Sombra MCP - puente entre cualquier IA compatible con MCP y la puerta de control de Sombra.
// Sin dependencias: solo Node.js 18+. Licencia GPL-3.0-or-later.
//
// Uso en un cliente MCP (Claude Code, Claude Desktop, LM Studio, etc.):
//   command: node   args: ["<ruta>/mcp/sombra-mcp.mjs"]   env: { "SOMBRA_CLIENT": "Claude" }
// Sombra debe estar abierto y con "Permitir que una IA use Sombra" activado.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createInterface } from 'node:readline';

const CLIENT = process.env.SOMBRA_CLIENT || null;
let clientName = CLIENT || 'IA (MCP)';

function controlFile() {
  if (process.env.SOMBRA_CONTROL_FILE) return process.env.SOMBRA_CONTROL_FILE;
  if (process.platform === 'win32') return join(process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local'), 'Sombra', 'control.json');
  if (process.platform === 'darwin') return join(homedir(), 'Library', 'Application Support', 'Sombra', 'control.json');
  return join(process.env.XDG_DATA_HOME || join(homedir(), '.local', 'share'), 'Sombra', 'control.json');
}

async function call(action, args = {}) {
  let cfg;
  try { cfg = JSON.parse(readFileSync(controlFile(), 'utf8')); }
  catch { throw new Error('Sombra no está abierto o el control para IAs está apagado. Pide al usuario que abra Sombra y active "Permitir que una IA use Sombra" en el panel.'); }
  const res = await fetch(`http://127.0.0.1:${cfg.port}/v1/${action}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${cfg.token}`, 'x-sombra-client': clientName },
    body: JSON.stringify(args),
  });
  const data = await res.json().catch(() => ({ ok: false, error: `HTTP ${res.status}` }));
  if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

const ID = { type: 'integer', description: 'Número del elemento, sacado de la lista "elements" que devuelve sombra_read o sombra_open.' };
const TAB = { type: 'integer', description: 'Pestaña (opcional, por defecto la activa).' };
const TOOLS = [
  { name: 'sombra_status', action: 'status', description: 'Estado de Sombra: conexión Tor, país de salida y pestañas abiertas.', schema: {} },
  { name: 'sombra_open', action: 'open', description: 'Abre una dirección web (o una búsqueda) en Sombra, por Tor y sin publicidad. Devuelve el texto de la página y los elementos con los que se puede interactuar.', schema: { url: { type: 'string', description: 'URL o texto a buscar' }, new_tab: { type: 'boolean' } }, required: ['url'] },
  { name: 'sombra_read', action: 'read', description: 'Lee la página actual: texto visible, si hay CAPTCHA, y lista numerada de enlaces, botones y campos.', schema: { tab: TAB, max_chars: { type: 'integer' } } },
  { name: 'sombra_click', action: 'click', description: 'Hace clic en un elemento. Si envía un formulario, Sombra pedirá permiso al usuario.', schema: { id: ID, tab: TAB }, required: ['id'] },
  { name: 'sombra_type', action: 'type', description: 'Escribe texto en un campo. Las contraseñas NO: las escribe el usuario. Con submit=true envía el formulario (con permiso del usuario).', schema: { id: ID, text: { type: 'string' }, submit: { type: 'boolean' }, tab: TAB }, required: ['id', 'text'] },
  { name: 'sombra_select', action: 'select', description: 'Elige una opción de un desplegable (value) o marca/desmarca una casilla ("true"/"false").', schema: { id: ID, value: { type: 'string' }, tab: TAB }, required: ['id', 'value'] },
  { name: 'sombra_scroll', action: 'scroll', description: 'Desplaza la página (dy en píxeles, negativo hacia arriba).', schema: { dy: { type: 'integer' }, tab: TAB } },
  { name: 'sombra_back', action: 'back', description: 'Vuelve a la página anterior.', schema: { tab: TAB } },
  { name: 'sombra_tabs', action: 'tabs', description: 'Lista las pestañas abiertas.', schema: {} },
  { name: 'sombra_switch_tab', action: 'switch_tab', description: 'Cambia a otra pestaña.', schema: { tab: TAB }, required: ['tab'] },
  { name: 'sombra_close_tab', action: 'close_tab', description: 'Cierra una pestaña.', schema: { tab: TAB }, required: ['tab'] },
  { name: 'sombra_country', action: 'country', description: 'Cambia el país desde el que se sale a internet (código de 2 letras como DE, FR, US; o "any").', schema: { code: { type: 'string' } }, required: ['code'] },
  { name: 'sombra_new_identity', action: 'new_identity', description: 'Nueva identidad de Tor (circuitos y dirección IP nuevos).', schema: {} },
];

function send(msg) { process.stdout.write(JSON.stringify(msg) + '\n'); }

async function onMessage(m) {
  const { id, method, params } = m;
  if (method === 'initialize') {
    if (!CLIENT && params?.clientInfo?.name) clientName = String(params.clientInfo.name).slice(0, 40);
    return send({ jsonrpc: '2.0', id, result: {
      protocolVersion: params?.protocolVersion || '2025-06-18',
      capabilities: { tools: {} },
      serverInfo: { name: 'sombra', version: '0.1.0' },
      instructions: 'Sombra es un navegador privado (Tor, sin publicidad). Usa sombra_open para abrir webs, sombra_read para ver los elementos numerados y sombra_click/sombra_type para actuar. Las contraseñas y los CAPTCHA los resuelve el usuario; enviar formularios requiere su permiso.',
    } });
  }
  if (method === 'notifications/initialized' || id === undefined) return;
  if (method === 'ping') return send({ jsonrpc: '2.0', id, result: {} });
  if (method === 'tools/list') {
    return send({ jsonrpc: '2.0', id, result: { tools: TOOLS.map(t => ({
      name: t.name, description: t.description,
      inputSchema: { type: 'object', properties: t.schema, required: t.required || [] },
    })) } });
  }
  if (method === 'tools/call') {
    const tool = TOOLS.find(t => t.name === params?.name);
    if (!tool) return send({ jsonrpc: '2.0', id, error: { code: -32602, message: 'Herramienta desconocida' } });
    try {
      const data = await call(tool.action, params.arguments || {});
      return send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(data, null, 1) }] } });
    } catch (e) {
      return send({ jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: String(e.message || e) }] } });
    }
  }
  send({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Método no soportado' } });
}

createInterface({ input: process.stdin }).on('line', (line) => {
  if (!line.trim()) return;
  let m; try { m = JSON.parse(line); } catch { return; }
  onMessage(m).catch(e => m.id !== undefined && send({ jsonrpc: '2.0', id: m.id, error: { code: -32000, message: String(e) } }));
});

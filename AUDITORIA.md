# Auditoría de seguridad y privacidad de Sombra

Fecha: 26-11-2026. Versión probada: rama `auditoria` (tras los niveles de seguridad). Probado en Linux (WSL, WebKitGTK 2.52); Windows sin probar.

## Cómo repetirla

```
bash tools/build-seg.sh     # compila (en WSL/Linux)
bash tools/audit.sh         # abre Sombra con SOMBRA_AUDIT=1 y vigila el DNS con tcpdump
```

La prueba (`tools/audit-probe.js`) hace lo que haría una web maliciosa: intenta saltarse las protecciones con un iframe en blanco y con un Worker, llegar a la red local y a la puerta de control para IAs, y sacar huellas (canvas, audio, idioma, hora, pantalla). Además abre CreepJS, que busca «mentiras» en la huella.

## Resultados

| Prueba | Resultado |
|---|---|
| Salida por Tor | ✅ check.torproject.org confirma Tor |
| DNS fuera de Tor (tcpdump, puerto 53) | ✅ ninguna consulta |
| WebRTC (fuga de IP) | ✅ bloqueado (CreepJS: todo «blocked») |
| Red local y este PC (127.0.0.1, 127.1, 0.0.0.0, [::ffff:127.0.0.1], 192.168.x, 10.x, .lan) | ✅ todo bloqueado |
| Puerta de control para IAs desde una web (fetch y WebSocket) | ✅ bloqueado |
| Saltarse la protección con un iframe en blanco | ✅ el iframe también está protegido |
| Descarga automática de archivos (Linux) | ✅ no se guarda nada sin preguntar |
| Resolución del reloj (ataques de tiempo) | ✅ 1 ms |
| Almacenamiento previo (cookies, localStorage) | ✅ vacío en cada sesión |
| Idioma y zona horaria en la página | ✅ en-US y UTC |
| Idioma y zona horaria en Workers | ✅ en-US y UTC (Linux) — **antes salía la zona real** |
| Huella de canvas | ✅ distinta en cada web y cada sesión, estable dentro de la misma — **antes era la misma huella desplazada** |
| Huella de audio | ✅ varía por web y sesión — **antes no estaba protegida** |
| Navegador que ve la web (Linux) | ✅ Safari en Mac — **antes «Ubuntu + WebKitGTK», muy poco común** |
| Núcleos del procesador en Workers | ⚠️ los reales (8); la página ve 4 |
| Tamaño real del monitor por reglas CSS `@media` | ⚠️ visible (2560×1440) |
| Tipos de letra instalados | ⚠️ delatan Linux (Cantarell, DejaVu, Ubuntu) |
| Plataforma en Workers (Linux) | ⚠️ «Linux x86_64» aunque la página dice Mac |

## Arreglado en esta auditoría

1. **Workers en UTC** (Linux): todo el motor funciona en UTC con la huella reforzada; la interfaz de Sombra sigue mostrando tu hora real.
2. **Canvas, WebGL y audio con ruido por web y por sesión** (como Brave), con una semilla secreta que no ve la web. Además, el canvas de la web ya no se modifica al exportarlo.
3. **Linux se presenta como Safari en Mac** (mismo motor, muchos más usuarios).
4. **Windows: se quita «WebView2» de la lista de marcas** del navegador (`navigator.userAgentData`). La cabecera `Sec-CH-UA` puede seguir diciéndolo.
5. **Puerta de control para IAs**: la acción `select` ya no puede escribir en campos de contraseña (antes era una forma de saltarse la regla).
6. **Archivos de datos** (token de la IA, contraseñas cifradas, ajustes) solo legibles por tu usuario en Linux (carpeta 700, archivos 600).

## Comparación con otros navegadores

| | Sombra | Tor Browser | Brave | Firefox | Chrome |
|---|---|---|---|---|---|
| IP oculta | Siempre, por Tor, sin salida directa | Siempre, por Tor | Solo en ventanas Tor | No | No |
| Bloqueo de anuncios y rastreadores | Sí (listas EasyList) | No (no recomienda extensiones) | Sí | Rastreadores sí, anuncios no | No |
| Anuncios de YouTube | Sí | No | Sí | No | No |
| Modo solo HTTPS | Sí, por defecto, con aviso y bloqueo en el proxy | Sí, por defecto | Opcional | Opcional | Opcional |
| Niveles de seguridad (sin JavaScript) | Sí, 3 niveles y permiso por web | Sí, 3 niveles | No | No | No |
| Huella: hora e idioma comunes | Sí (UTC, en-US), en Workers solo Linux | Sí, en todo el motor | No | Solo con «resist fingerprinting» | No |
| Huella: canvas/audio | Ruido por web y sesión | Bloqueo con permiso | Ruido por web y sesión | Parcial | No |
| Tamaño de ventana redondeado | Sí | Sí | No | Solo con RFP | No |
| Tamaño real del monitor por CSS | Visible | Oculto | Visible | Oculto con RFP | Visible |
| Tipos de letra | Los del sistema | Lista fija | Los del sistema (con ruido) | Los del sistema | Los del sistema |
| Dónde se aplica la protección | Script en la página (detectable) | Dentro del motor | Dentro del motor | Dentro del motor | — |
| Control seguro para IAs | Sí (token, permisos, contraseñas nunca) | No | No | No | No |
| Tamaño | Ligero (motor del sistema) | Grande | Grande | Grande | Grande |

**Resumen:** frente a Chrome, Firefox y Brave, Sombra protege mucho más la IP y la huella. Frente a Tor Browser, la red es igual de privada, pero la protección de la huella es más débil: Tor Browser la aplica dentro del motor (Firefox modificado), mientras que Sombra usa el motor del sistema y solo puede cambiar lo que ve el JavaScript de la página. Por eso quedan visibles el tamaño del monitor por CSS, los tipos de letra y los núcleos en Workers, y una web avanzada puede notar que hay protección.

## Pendiente (siguientes mejoras)

- **Núcleos en Workers**: inyectar la protección también en Workers.
- **Tipos de letra**: limitar a una lista fija (en Linux, con la configuración de fontconfig del motor).
- **Windows**: probar todo lo anterior allí; la hora en Workers depende del motor y no se puede cambiar con la variable TZ.
- **Descargas**: preguntar siempre antes de descargar (en Windows, WebView2 muestra su propio aviso).

## Después de la auditoría: modo solo HTTPS (hecho)

Activado por defecto. Las webs http se abren por https (también enlaces y redirecciones); antes, Sombra hace por Tor un saludo TLS real con la web y comprueba el certificado (raíces de Mozilla). Si falla (puerto cerrado, sin cifrado, certificado caducado) se muestra un aviso con *Volver* o *Continuar sin cifrar*. El proxy corta cualquier conexión al puerto 80 que no hayas aceptado. Los .onion no se tocan (ya van cifrados dentro de Tor).

Probado en Linux (`bash tools/sectest.sh https`): http://example.com → https; info.cern.ch (certificado caducado) y httpforever.com (sin https) → aviso; un enlace a http desde una web → https; *Continuar* abre la web por http; el proxy bloquea example.org:80 y deja httpforever.com:80 tras aceptarla.

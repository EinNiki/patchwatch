// Startet die UI als Produktionsbuild (`next build`, standalone) und leitet /api an den Rust-Server weiter.
// Ersetzt für lokale Tests den Reverse-Proxy (deploy/Caddyfile). Nicht für den Produktivbetrieb gedacht.
//   npm run build && npm run start:prod        (Port 3100, API http://127.0.0.1:8080)
//   PORT=3200 PATCHWATCH_API_URL=http://127.0.0.1:8080 npm run start:prod
import { createServer, request } from "node:http";
import { connect } from "node:net";
import { spawn } from "node:child_process";
import { existsSync, cpSync } from "node:fs";
import { createGzip, createBrotliCompress } from "node:zlib";

const port = Number(process.env.PORT ?? 3100);
const inner = port + 1000;
const api = new URL(process.env.PATCHWATCH_API_URL ?? "http://127.0.0.1:8080");
const dir = ".next/standalone";
if (!existsSync(`${dir}/server.js`)) {
  console.error("Kein Build gefunden: erst `npm run build` ausführen.");
  process.exit(1);
}
// Das standalone-Verzeichnis enthält weder static noch public; beides liegt neben dem Build.
if (!existsSync(`${dir}/.next/static`)) cpSync(".next/static", `${dir}/.next/static`, { recursive: true });
if (existsSync("public") && !existsSync(`${dir}/public`)) cpSync("public", `${dir}/public`, { recursive: true });

const next = spawn("node", ["server.js"], {
  cwd: dir,
  env: { ...process.env, PORT: String(inner), HOSTNAME: "127.0.0.1" },
  stdio: "inherit",
});
next.on("exit", (c) => process.exit(c ?? 1));
for (const s of ["SIGINT", "SIGTERM"]) process.on(s, () => next.kill(s));

const COMPRESSIBLE = /^(text\/|application\/(json|javascript)|image\/svg)/;
function forward(req, res, host, p, isApi) {
  const up = request({ host, port: p, path: req.url, method: req.method, headers: { ...req.headers, host: req.headers.host ?? "" } }, (r) => {
    const headers = { ...r.headers };
    const accept = String(req.headers["accept-encoding"] ?? "");
    const type = String(headers["content-type"] ?? "");
    // Wie der Reverse-Proxy: Text komprimieren, SSE (Live-Ereignisse) nie puffern.
    if (!isApi || !type.startsWith("text/event-stream")) {
      if (!headers["content-encoding"] && COMPRESSIBLE.test(type) && /\bbr\b|\bgzip\b/.test(accept) && !type.startsWith("text/event-stream")) {
        const br = /\bbr\b/.test(accept);
        delete headers["content-length"];
        headers["content-encoding"] = br ? "br" : "gzip";
        headers.vary = "Accept-Encoding";
        res.writeHead(r.statusCode ?? 502, headers);
        r.pipe(br ? createBrotliCompress() : createGzip()).pipe(res);
        return;
      }
    }
    res.writeHead(r.statusCode ?? 502, headers);
    r.pipe(res);
  });
  up.on("error", () => {
    if (!res.headersSent) res.writeHead(502);
    res.end();
  });
  req.pipe(up);
}

const server = createServer((req, res) => {
  if (req.url?.startsWith("/api/")) forward(req, res, api.hostname, Number(api.port || 80), true);
  else forward(req, res, "127.0.0.1", inner, false);
});
// WebSocket (Live-Ereignisse unter /api/v1/live): Verbindung 1:1 an den Server durchreichen.
server.on("upgrade", (req, socket, head) => {
  const up = connect(Number(api.port || 80), api.hostname, () => {
    const lines = [`${req.method} ${req.url} HTTP/1.1`, ...Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`), "", ""];
    up.write(lines.join("\r\n"));
    if (head.length) up.write(head);
    socket.pipe(up).pipe(socket);
  });
  up.on("error", () => socket.destroy());
  socket.on("error", () => up.destroy());
});
server.listen(port, "0.0.0.0", () => console.log(`UI (Produktionsbuild) auf http://0.0.0.0:${port}, /api → ${api.origin}`));

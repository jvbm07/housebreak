// Housebreak server: serves the game and grades hand-written policies.
// The API key never leaves this process. The browser only sends {attackId, policy};
// the rubric lives here, so the endpoint can't be used as a general Claude proxy.
import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

try { process.loadEnvFile(); } catch { /* no .env file: use the real environment */ }
// Imported after .env is loaded, because the grader's Claude client reads the key when it's created.
const { HB, grade, checkClaude, claudeStatus } = await import("./grader.mjs");

const here = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 8787;
const HOST = process.env.HOST || "127.0.0.1"; // loopback only; HOST=0.0.0.0 shares it on your network

const STATIC = { "/": "housebreak.html", "/housebreak.html": "housebreak.html", "/game-core.js": "game-core.js" };
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8" };
const LOCAL_HOSTS = new Set([`localhost:${PORT}`, `127.0.0.1:${PORT}`]);

const HEADERS = { "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store" };

// Anything built from a request goes out through send(), always as JSON, never as HTML.
// Escaping <, > and & keeps the JSON identical once parsed but inert if a browser ever renders it.
const JSON_ESCAPES = { "<": "\\u003c", ">": "\\u003e", "&": "\\u0026" };
function send(res, status, obj) {
  res.writeHead(status, { ...HEADERS, "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(obj).replace(/[<>&]/g, c => JSON_ESCAPES[c]));
}

// Only for the fixed files in STATIC.
function sendFile(res, data, type) {
  res.writeHead(200, { ...HEADERS, "Content-Type": type });
  res.end(data);
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", c => {
      size += c.length;
      if (size > limit) { reject(new Error("body too large")); req.pause(); }
      else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  // On loopback, refuse other Host names so a web page can't reach this server through DNS rebinding.
  if (HOST === "127.0.0.1" && !LOCAL_HOSTS.has(req.headers.host)) return send(res, 403, { error: "Forbidden host" });
  const { pathname } = new URL(req.url, "http://localhost");
  try {
    if (req.method === "GET" && STATIC[pathname]) {
      const file = STATIC[pathname];
      return sendFile(res, await readFile(path.join(here, file)), TYPES[path.extname(file)]);
    }
    if (req.method === "GET" && pathname === "/api/status") return send(res, 200, { grader: claudeStatus() });
    if (req.method === "POST" && pathname === "/api/grade") {
      // Requiring JSON forces a CORS preflight, which this server never approves, so other sites can't spend your credits.
      if (!String(req.headers["content-type"]).startsWith("application/json")) return send(res, 415, { error: "Send application/json" });
      let body;
      try { body = JSON.parse(await readBody(req)); } catch { return send(res, 400, { error: "Send JSON: {attackId, policy}" }); }
      const a = HB.ATTACKS.find(x => x.id === body?.attackId);
      if (!a || typeof body.policy !== "string") return send(res, 400, { error: "Unknown attack or missing policy" });
      const started = Date.now();
      const g = await grade(a, HB.sanitizePolicy(body.policy));
      const bad = Object.keys(g.bad);
      console.log(`[grade] ${a.id} via ${g.source} in ${((Date.now() - started) / 1000).toFixed(1)}s: covered [${Object.keys(g.covered).join(", ")}]` +
        (bad.length ? ` backfired [${bad.join(", ")}]` : "") + (g.injection ? " INJECTION ATTEMPT" : ""));
      return send(res, 200, g);
    }
    send(res, 404, { error: "Not found" });
  } catch (e) {
    console.error(e);
    send(res, 500, { error: "Server error" });
  }
});

await checkClaude();
server.listen(PORT, HOST, () => console.log(`Housebreak is running at http://localhost:${PORT}`));

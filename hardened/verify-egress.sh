#!/usr/bin/env bash
# Fail-closed network test for the hardened Ocado MCP container.
# Exits non-zero if anything is reachable that should not be, or if Ocado
# is not reachable through the proxy.
set -u
cd "$(dirname "$0")"
docker compose up -d egress >/dev/null

docker compose run --rm -T -e EXTRA_TARGETS="${EXTRA_TARGETS:-}" --entrypoint node ocado-mcp -e '
const axios = require("axios");
const net = require("net");
const fs = require("fs");
const dns = require("dns").promises;

const PROXY = "http://egress:8888";
let failures = 0;
const report = (ok, label, detail) => {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}  (${detail})`);
};

async function http(url, viaProxy) {
  try {
    const r = await axios.get(url, {
      timeout: 12000, maxRedirects: 0, validateStatus: () => true,
      ...(viaProxy ? {} : { proxy: false }),
    });
    // The proxy refusing is itself an HTTP reply: count it as blocked, not reached.
    if (viaProxy && r.status === 403 && /^tinyproxy/i.test(r.headers.server || ""))
      return { reached: false, detail: "HTTP 403 from proxy" };
    return { reached: true, detail: `HTTP ${r.status}` };
  } catch (e) {
    return { reached: false, detail: e.code || e.message };
  }
}

function tcp(host, port) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port, timeout: 6000 });
    s.on("connect", () => { s.destroy(); resolve({ reached: true, detail: "connected" }); });
    s.on("timeout", () => { s.destroy(); resolve({ reached: false, detail: "timeout" }); });
    s.on("error", (e) => resolve({ reached: false, detail: e.code || e.message }));
  });
}

function connectViaProxy(target) {
  // Raw CONNECT through the proxy, as any HTTP client would.
  return new Promise((resolve) => {
    const s = net.connect({ host: "egress", port: 8888, timeout: 8000 });
    let buf = "";
    s.on("connect", () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    s.on("data", (d) => {
      buf += d.toString();
      if (buf.includes("\r\n")) {
        s.destroy();
        const ok = / 200 /.test(buf.split("\r\n")[0]);
        resolve({ reached: ok, detail: buf.split("\r\n")[0] });
      }
    });
    s.on("timeout", () => { s.destroy(); resolve({ reached: false, detail: "timeout" }); });
    s.on("error", (e) => resolve({ reached: false, detail: e.code || e.message }));
  });
}

(async () => {
  let r;
  // Must work
  r = await http("https://www.ocado.com/", true);
  report(r.reached, "Ocado reachable through proxy", r.detail);

  // Must be blocked: other hosts through the proxy, as the real HTTP client sees it.
  // A reply header can be forged, so the raw CONNECT checks below are the deciding test.
  for (const u of ["https://example.com/", "https://api.github.com/", "https://world.openfoodfacts.org/", "https://1.1.1.1/"]) {
    r = await http(u, true);
    report(!r.reached, `proxy refuses ${u}`, r.detail);
  }

  // Must be blocked: raw CONNECT. Any "200" status line is a tunnel, so it fails the test
  // whatever happens after. Covers other hosts, Ocado on other ports, look-alike hosts,
  // and IP literal forms (IPv6, decimal and hex encodings of 1.1.1.1).
  for (const t of [
    "example.com:443", "api.github.com:443", "world.openfoodfacts.org:443", "1.1.1.1:443",
    "www.ocado.com:80", "www.ocado.com:8443", "ocado.com:443", "www.ocado.com.example.com:443",
    "www.ocado.com@example.com:443",
    "[2606:4700:4700::1111]:443", "16843009:443", "0x01010101:443",
  ]) {
    r = await connectViaProxy(t);
    report(!r.reached, `proxy refuses CONNECT ${t}`, r.detail);
  }

  // Must hold: the container itself has no other way out.
  const v6 = fs.readFileSync("/proc/net/if_inet6", "utf8").trim().split("\n").filter((l) => !/\slo$/.test(l));
  report(v6.length === 0, "no IPv6 address except loopback", v6.length ? v6.join("; ") : "loopback only");
  const v4default = fs.readFileSync("/proc/net/route", "utf8").split("\n").slice(1).filter((l) => l.split(/\s+/)[1] === "00000000");
  report(v4default.length === 0, "no IPv4 default route", v4default.length ? "default route present" : "none");
  report(!fs.existsSync("/var/run/docker.sock"), "no Docker socket", "/var/run/docker.sock absent");
  try { fs.appendFileSync("/home/node/.ocado/session.json", ""); report(false, "session file read-only", "write succeeded"); }
  catch (e) { report(e.code === "EROFS", "session file read-only", e.code); }
  for (const h of ["example.com", "www.ocado.com"]) {
    // Name lookups only through the proxy: the internal network has no outside DNS (no DNS tunnel).
    try { const a = await dns.resolve4(h); report(false, `no direct DNS for ${h}`, a.join(",")); }
    catch (e) { report(true, `no direct DNS for ${h}`, e.code); }
  }

  // Must be blocked: direct connections with no proxy
  for (const u of ["https://www.ocado.com/", "https://1.1.1.1/"]) {
    r = await http(u, false);
    report(!r.reached, `direct (no proxy) ${u}`, r.detail);
  }

  // Must be blocked: the Docker host, the Colima VM and the Mac
  for (const [h, p] of [
    ["172.30.77.1", 22], ["172.30.77.1", 80],
    ["host.docker.internal", 22], ["host.docker.internal", 80], ["host.docker.internal", 5000],
    ["192.168.5.2", 22], ["192.168.5.2", 80],
    ["192.168.1.1", 80],
    ["2606:4700:4700::1111", 443],
    // Discovered on the Mac by the runbook: "host:port host:port ..."
    ...String(process.env.EXTRA_TARGETS || "").split(/\s+/).filter(Boolean).map((t) => {
      const i = t.lastIndexOf(":"); return [t.slice(0, i), Number(t.slice(i + 1))];
    }),
  ]) {
    r = await tcp(h, p);
    report(!r.reached, `no route to ${h}:${p}`, r.detail);
  }

  // Known limitation, reported not failed: the proxy filters hosts, not HTTPS paths.
  r = await http("https://www.ocado.com/checkout", true);
  console.log(`INFO  proxy cannot see paths: /checkout via a second HTTP client is ${r.reached ? "reachable" : "not reachable"} (${r.detail}). The in-process allowlist is the path control.`);

  console.log(failures === 0 ? "ALL PASS" : `${failures} FAILURES`);
  process.exit(failures ? 1 : 0);
})();
'

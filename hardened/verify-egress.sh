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

  // Must be blocked: other hosts through the proxy
  for (const u of ["https://example.com/", "https://api.github.com/", "https://world.openfoodfacts.org/", "https://1.1.1.1/"]) {
    r = await http(u, true);
    report(!r.reached, `proxy refuses ${u}`, r.detail);
  }

  // Must be blocked: CONNECT to Ocado on other ports, and to look-alike hosts
  for (const t of ["www.ocado.com:80", "www.ocado.com:8443", "ocado.com:443", "www.ocado.com.example.com:443"]) {
    r = await connectViaProxy(t);
    report(!r.reached, `proxy refuses CONNECT ${t}`, r.detail);
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

#!/usr/bin/env bash
# Proves the MCP container can reach www.ocado.com via the proxy and nothing else.
set -u
cd "$(dirname "$0")"
docker compose up -d egress >/dev/null
run() { docker compose run --rm -T --entrypoint node ocado-mcp -e "$1"; }
run '
const axios = require("axios");
const cases = [
  ["via proxy: www.ocado.com (should be REACHED)", "https://www.ocado.com/", {}],
  ["via proxy: example.com (should be BLOCKED)", "https://example.com/", {}],
  ["via proxy: api.github.com (should be BLOCKED)", "https://api.github.com/", {}],
  ["direct, no proxy: www.ocado.com (should be BLOCKED)", "https://www.ocado.com/", { proxy: false }],
  ["direct, no proxy: 1.1.1.1 (should be BLOCKED)", "https://1.1.1.1/", { proxy: false }],
];
(async () => {
  for (const [label, url, extra] of cases) {
    try {
      const r = await axios.get(url, { timeout: 15000, maxRedirects: 0, validateStatus: () => true, ...extra });
      console.log("REACHED ", r.status, label);
    } catch (e) {
      console.log("BLOCKED ", e.code || e.message, label);
    }
  }
})();
'

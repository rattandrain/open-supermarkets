# Hardened Ocado-only build

This branch is upstream `abracadabra50/open-supermarkets` at commit `aff6880` plus the changes below. It exists so one household can let Claude Code search Ocado and build a basket, with no way to spend money or reach account and payment pages.

## What changed from upstream

| File | Change |
|---|---|
| `src/hardening/ocado-allowlist.ts` | New. Every request the Ocado HTTP client makes must match a short method + path allowlist on `https://www.ocado.com`, or it is refused in-process. GraphQL is allowed only for the exact order-history query, with only the expected keys and variables. Redirects are never followed. |
| `src/providers/ocado.ts` | Installs the allowlist; redirects off. The bodies of `login`, `logout`, `saveSession`, `getLocationIds`, `getDeliverySlots`, `bookSlot`, `checkout`, `clearBasket` and `importSession` are removed and replaced with a single throw. The order-history GraphQL query now lives in the allowlist module. |
| `src/mcp-ocado.ts` | New, Ocado-only MCP server. Tools: status, search, product, favourites, basket view, basket set, order history. No login, slots, checkout or clear-basket tool. Outputs are trimmed to needed fields and cleaned of control, zero-width and bidirectional characters. Errors are fixed categories, never raw upstream text. Basket set validates the whole request first, rejects duplicate or malformed product ids, max 6 per line and 25 lines per call; if a write fails part-way it reports exactly which changes were made and the resulting basket (writes cannot be rolled back). |
| `tsconfig.hardened.json` | New. Compiles only `src/mcp-ocado.ts` and what it imports. |
| `hardened/` | Container build, egress proxy, tests. |

The container image contains only the compiled hardened entry point and its imports. The upstream CLI, HTTP API, multi-provider MCP server, browser automation and other providers are not compiled into it, and Playwright, playwright-extra, the stealth plugin, chalk and commander are removed from its dependencies.

The upstream source files remain in the repo but are never built or run; the container's entrypoint is `dist/mcp-ocado.js` only.

## Allowed requests

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Read CSRF token |
| GET | `/search` | Search results page |
| GET | `/favorites` | Favourites page |
| GET | `/api/cart/v1/carts/active` | Read basket |
| POST | `/api/cart/v1/carts/active/apply-quantity` | Change basket quantities |
| PUT | `/api/webproductpagews/v6/products` | Product details |
| POST | `/graphql` | Only the exact `GetCompletedOrders` query and variables |
| GET | `/api/order/v6/orders/<id>` | One past order |

Anything else, including `/checkout`, `/api/ecomslots`, `/login` and account pages, is refused. Paths containing `..`, encoded slashes or dots, backslashes or `//` are refused. Any 3xx response is an error.

## Containment

- `ocado-mcp` runs on a Docker network marked `internal`: it has no route to the internet or the home network.
- That network has no gateway address (`inhibit_ipv4`), so the container cannot reach services on the Docker host or Colima VM either (an `internal` network alone still lets it reach the VM's SSH server).
- Its only way out is the `egress` proxy (tinyproxy), which allows HTTPS tunnels to `www.ocado.com:443` and nothing else, and accepts clients only from the internal subnet `172.30.77.0/24`.
- Read-only root filesystem, all Linux capabilities dropped, no privilege escalation, runs as the unprivileged `node` user.
- The session cookie file is mounted read-only from `~/.ocado-mcp/session.json`.
- Dependencies are installed with `--ignore-scripts`, so no package install script runs.

## Known limitation

The proxy filters hosts, not HTTPS paths: it cannot tell `/search` from `/checkout` on `www.ocado.com`. The in-process allowlist is the only path-level control. Code that bypassed the allowlisted HTTP client (for example a compromised dependency) could reach other paths on `www.ocado.com` with the session cookie. Mitigations outside this repo: pinned lockfile, `--ignore-scripts`, dependency scanning, and a frozen payment card on the Ocado account.

## Tests

- `hardened/test-allowlist.js`: 40 allowed and blocked request cases, including GraphQL spoofing, encodings and look-alike hosts. Exits non-zero on any failure.
- `hardened/verify-egress.sh`: fail-closed network test. Ocado must be reachable through the proxy; other hosts, other ports, look-alike hosts, IP literal encodings, direct connections, direct DNS, the Docker host, the Colima VM, the Mac, the LAN and IPv6 must not be. Raw `CONNECT` results decide the proxy checks (a `200` is a fail). It also checks the running container: no IPv6 address but loopback, no default route, no Docker socket, session file read-only. Exits non-zero on any failure. Pass `EXTRA_TARGETS="host:port ..."` to add the Mac's real addresses and listening ports (see the kitchen repo's Mac Mini runbook).

## Keeping it current

Versions are pinned (lockfile, image digests, tinyproxy), so nothing updates by itself. Rebuild deliberately when any of these happens, then rerun both tests:
- `npm audit --omit=dev` or `osv-scanner scan --lockfile package-lock.json` reports a runtime finding: `npm audit fix --package-lock-only --ignore-scripts`.
- A base image nears end of support. Alpine 3.24 (main and community) runs to 2028-06-01; Node 24 LTS to 2028-04-30. Repin with `docker pull` then `docker image inspect <image> --format '{{index .RepoDigests 0}}'`, and repin tinyproxy to the version `apk policy tinyproxy` shows.

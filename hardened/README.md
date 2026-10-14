# Hardened Ocado-only build

This branch is upstream `abracadabra50/open-supermarkets` at commit `aff6880` plus the changes below. It exists so one household can let Claude Code search Ocado and build a basket, with no way to spend money or reach account and payment pages.

## What changed from upstream

| File | Change |
|---|---|
| `src/hardening/ocado-allowlist.ts` | New. Every request the Ocado HTTP client makes, and every redirect, must match a short method + path allowlist on `https://www.ocado.com`, or it is refused in-process. |
| `src/providers/ocado.ts` | Installs the allowlist on its axios client. `login`, `getDeliverySlots`, `bookSlot` and `checkout` now throw immediately. |
| `src/mcp-ocado.ts` | New, Ocado-only MCP server. Tools: status, search, product, favourites, regulars, basket view, basket set (max 6 per line, 25 lines per call), order history. No login, slots, checkout or clear-basket tool. |
| `hardened/` | Container build, egress proxy, tests. |

The upstream multi-provider `src/mcp-server.ts`, CLI and HTTP API are untouched and are not used. The container's entrypoint is `dist/mcp-ocado.js` only.

## Allowed requests

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Read CSRF token |
| GET | `/search` | Search results page |
| GET | `/favorites` | Favourites page |
| GET | `/api/cart/v1/carts/active` | Read basket |
| POST | `/api/cart/v1/carts/active/apply-quantity` | Change basket quantities |
| PUT | `/api/webproductpagews/v6/products` | Product details |
| POST | `/graphql` | Only when `operationName` is `GetCompletedOrders` |
| GET | `/api/order/v6/orders/<id>` | One past order |
| GET | `/api/recurringshopping/v2/web/definitions` | Regulars list |

Anything else, including `/checkout`, `/api/ecomslots`, `/login` and account pages, is refused. Paths containing `..`, encoded slashes or dots, backslashes or `//` are refused.

## Containment

- `ocado-mcp` runs on a Docker network marked `internal`: it has no route to the internet or the home network.
- Its only way out is the `egress` proxy (tinyproxy), which allows HTTPS tunnels to `www.ocado.com:443` and nothing else.
- Read-only root filesystem, all Linux capabilities dropped, no privilege escalation, runs as the unprivileged `node` user.
- The session cookie file is mounted read-only from `~/.ocado-mcp/session.json`.
- Dependencies are installed with `--ignore-scripts`, so no package install script runs.

## Tests

- `hardened/test-allowlist.js`: allowed and blocked request cases against the in-process allowlist.
- `hardened/verify-egress.sh`: proves the container reaches `www.ocado.com` through the proxy and cannot reach anything else, with or without the proxy.

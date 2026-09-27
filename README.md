# Liquidity Guard

A minimal REST microservice and Dockerized REST API that validates a taker’s liquidity for an OTC RFQ on Solana and returns a signed preflight proof (commit hash, Ed25519 signature) for on‑chain verification.

## How it fits

Use the service output in a Solana preflight instruction that verifies the hash and Ed25519 signature on‑chain before running the business logic. See also:

- [experimental-preflight-sigcheck](https://github.com/unleaktrade/experimental-preflight-sigcheck)
- [settlement-engine](https://github.com/unleaktrade/settlement-engine)

## Endpoints

- GET `/health`  
  Returns service status, configured network (`devnet`, `mainnet`, `localnet`), and the Ed25519 public key used to verify signatures.

- GET `/ready`  
  Readiness probe: `200` when the Solana RPC answers, `503` otherwise. Unauthenticated.

- GET `/metrics`  
  Prometheus metrics (text format). Protected by `METRICS_TOKEN` and/or `API_KEYS` when set (either credential works).

- POST `/check`  
  Requires an API key when `API_KEYS` is set (see [Authentication](#authentication)). Validates taker liquidity for the RFQ and responds with:
  - `commit_hash`: deterministic SHA-256 hash derived from RFQ fields
  - `liquidity_proof`: Ed25519 signature of `commit_hash` using the service key
  - Echoed request context and metadata (network, timestamp, service_pubkey)

Validation rules:

- USDC balance must cover `bond_amount_usdc`
- Quote token balance must cover `quote_amount` + protocol fee uplift
  - Uplift = `floor(quote_amount * taker_fee_bps / 10_000)`, minimum 1 when `taker_fee_bps > 0`
- `taker_fee_bps` must not exceed 10,000 (100% in basis points)

### Authentication

`/check` and `/metrics` are protected by shared-secret API keys; `/health`, `/ready` and CORS preflights never are.

- Configure one or more keys with `API_KEYS` (comma-separated, e.g. one per consumer so each can be rotated on its own) and/or `API_KEY` (single key). Leading/trailing spaces and empty entries are ignored. **When neither is set, authentication is disabled** and the service logs a `WARN` at startup.
- Clients send the key as `X-API-Key: <key>` or `Authorization: Bearer <key>` (the scheme is case-sensitive). `X-API-Key` wins when both are present.
- A missing or wrong key gets `401 Unauthorized` with `WWW-Authenticate: Bearer` and `{"error":"Unauthorized"}`. The key is checked before the body is parsed, so unauthenticated callers learn nothing about validation. The rate limiter (when `RATE_LIMIT` is on) runs first, so it also throttles key guessing.
- Keys are compared through SHA-256 digests in constant time and never logged; rejected attempts log `API key rejected` with `reason` = `missing` | `invalid`.
- `/metrics` accepts `METRICS_TOKEN` or any API key (as `Authorization: Bearer` or `X-API-Key`); it stays open only when neither is configured.

```sh
curl -X POST "$API_URL/check" -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -d @check.json
```

Keys sent by a browser app are visible to anyone who opens the app: treat those as revocable client identifiers, give each consumer its own key and keep `RATE_LIMIT=1` on browser-facing instances.

### Check - Request example

```json
{
  "rfq": "6p7BsnxWgNze6wLjhHD9wN6Zo7jEpoFZ9npCDPhsJK8H",
  "taker": "8GAt381fturbi53tXBKubeKgXAdjKvu4fV7H9sn3z4pZ",
  "salt": "50f8f2e8b2bdd78400b8f20d9e526be2b7aab3346fdd043d84b35ad6ef4a5791434f243f5d84835bacc0ebfe32ba71b117a5da1301bad9ec4e297c8835387c0d",
  "quote_mint": "EoTybYbsuFWfe64MqMqVuVTNgHfQgK6xLu4fvnguy9dN",
  "quote_amount": "100000000",
  "bond_amount_usdc": "100000",
  "taker_fee_bps": "50"
}
```

### Check - Response example

```json
{
    "rfq": "6p7BsnxWgNze6wLjhHD9wN6Zo7jEpoFZ9npCDPhsJK8H",
    "salt": "50f8f2e8b2bdd78400b8f20d9e526be2b7aab3346fdd043d84b35ad6ef4a5791434f243f5d84835bacc0ebfe32ba71b117a5da1301bad9ec4e297c8835387c0d",
    "taker": "8GAt381fturbi53tXBKubeKgXAdjKvu4fV7H9sn3z4pZ",
    "usdc_mint": "5jBqJmY2mKetudVa2XaC8U6UN2BNNirDiTnDEuA6pdyR",
    "quote_mint": "EoTybYbsuFWfe64MqMqVuVTNgHfQgK6xLu4fvnguy9dN",
    "quote_amount": "100000000",
    "bond_amount_usdc": "100000",
    "taker_fee_bps": "50",
    "service_pubkey": "5gfPFweV3zJovznZqBra3rv5tWJ5EHVzQY1PqvNA4HGg",
    "commit_hash": "d3fbfcb128eea470df1b44faaa57f65f4d1009e9723dc22ea25b1be89ba103a2",
    "liquidity_proof": "77fd13bc03761e59bef613a60d9bcd013d79d0b152fd28e24c60dfbe8bc3daeb40bda9b7d348ca05c544b16ae489fbd350dab85ed94e82d7c006562aa4352b0d",
    "network": "Devnet",
    "skip_fund_checks": true,
    "timestamp": 1763639964
}
```

## Development

- Tests: `cargo test` (unit tests plus HTTP and RPC tests against an in-process mock JSON-RPC server; no network needed)
- Postman: `postman/liquidity-guard.postman_collection.json` (same collection as the team workspace). CI runs it with newman against an ephemeral local instance:

  ```sh
  cargo run --example postman_env -- /tmp/pm          # fresh keys + a valid /check fixture
  (set -a; . /tmp/pm/server.env; set +a; cargo run) &
  npx newman run postman/liquidity-guard.postman_collection.json \
    -e /tmp/pm/postman_environment.json
  ```

  Against a deployed instance, use the workspace environments and set `API_KEY` / `METRICS_TOKEN` there (empty `API_KEY` = the instance runs without keys).
- Lint: `cargo clippy --all-targets -- -D warnings`
- Format: `cargo fmt`

## Docker

- Build:  
  `docker build -t liquidity-guard .`

- Run:  
  `docker run -p 8080:8080 --env-file .env liquidity-guard`

Environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `SIGNING_KEY` | **Yes** | — | Base58-encoded keypair for Ed25519 signing |
| `USDC_MINT` | **Yes** | — | Base58-encoded USDC mint pubkey |
| `SOLANA_NETWORK` | No | — | `devnet`, `mainnet`, or `localnet` |
| `SOLANA_RPC_URL` | No | Derived from network | Solana RPC endpoint |
| `SOLANA_RPC_FALLBACK` | No | `true` | Retry once on the network's public RPC when a custom `SOLANA_RPC_URL` fails. Set to `false` or `0` to disable. |
| `SOLANA_RPC_TIMEOUT_SECS` | No | `10` | Per-request RPC timeout (connect timeout is `min(5, value)`) |
| `SOLANA_RPC_POOL_MAX_IDLE` | No | `32` | Max idle keep-alive connections per RPC host |
| `SKIP_FUND_CHECKS` | No | `false` | Skip on-chain balance checks (CI/CD) |
| `RATE_LIMIT` | No | `false` | Per-IP rate limit on `/ready` and `/check` (2 req/s sustained, burst 5) |
| `CORS` | No | `true` | Enable permissive CORS (`Access-Control-Allow-Origin: *`, any method/header, no credentials). Set to `false` or `0` to disable. |
| `CORS_MAX_AGE` | No | `3600` | Preflight cache duration in seconds |
| `PORT` | No | `8080` | HTTP listen port |
| `LOG_FORMAT` | No | `json` | `json` (one JSON object per line) or `pretty` (human-readable, for local dev) |
| `RUST_LOG` | No | `info` | Log filter, e.g. `info,liquidity_guard=debug` |
| `METRICS_TOKEN` | No | — | When set, `GET /metrics` requires `Authorization: Bearer <token>` (or an API key); open only when neither `METRICS_TOKEN` nor `API_KEYS` is set |
| `API_KEYS` | No | — | Comma-separated API keys required on `POST /check` (and accepted on `/metrics`). Unset = no authentication |
| `API_KEY` | No | — | Single API key, merged with `API_KEYS` |

## RPC resilience

- Each RPC client uses an explicit request timeout (`SOLANA_RPC_TIMEOUT_SECS`) and a keep-alive connection pool (`SOLANA_RPC_POOL_MAX_IDLE`).
- When `SOLANA_RPC_URL` is set to a custom endpoint, the network's public RPC (`api.devnet.solana.com` / `api.mainnet-beta.solana.com`) is used as a fallback: primary → one retry on the fallback → error. Every fallback is logged at `WARN`.
- No fallback is used on `localnet`, when `SOLANA_RPC_URL` already equals the network default, or when `SOLANA_RPC_FALLBACK=false`.
- At startup, the primary's genesis hash is compared with the one of `SOLANA_NETWORK`. On a mismatch (e.g. a mainnet URL with `SOLANA_NETWORK` left to `devnet`) the fallback is disabled and an error is logged, so balances are never read from the wrong cluster.
- Logged RPC URLs are reduced to `scheme://host[:port]`, so provider API keys in the path or query string never reach the logs.
- Worst case, a `/check` or `/ready` call takes about twice the timeout (20s by default). Keep that below your platform's router timeout (30s on Heroku).

## Observability

**Metrics** (`GET /metrics`, Prometheus text format):

| Metric | Type | Labels |
|---|---|---|
| `liquidity_guard_http_requests_total` | counter | `endpoint`, `method`, `status` |
| `liquidity_guard_http_requests_duration_seconds` | histogram (5ms → 30s buckets) | `endpoint`, `method`, `status` |
| `liquidity_guard_rpc_requests_total` | counter | `op`, `target` (`primary`/`fallback`), `outcome` (`ok`/`error`) |

- `endpoint` is the route pattern; unknown paths are recorded as `UNKNOWN` to keep label cardinality bounded. `/metrics` itself is not counted and is not rate limited.
- Error rate: `sum(rate(liquidity_guard_http_requests_total{status=~"5.."}[5m])) / sum(rate(liquidity_guard_http_requests_total[5m]))`
- RPC fallback rate: `sum(rate(liquidity_guard_rpc_requests_total{target="fallback"}[5m]))`

**Logs** are structured with `tracing` and written as JSON lines to stdout by default (`LOG_FORMAT=pretty` for local dev). Every request emits one `request completed` line with `request_id`, `method`, `path`, `status` and `duration_ms` (level `INFO`, `WARN` for 4xx, `ERROR` for 5xx). Other events during a request (e.g. an RPC fallback) carry the same `request_id` under `span`. The id is returned to clients in the `X-Request-Id` response header, so client-side errors can be matched with server logs.

## Quick start

1. Configure environment (.env) with network, RPC, signing key, and mints.  
2. Build and run with Cargo or Docker.  
3. Call `/health` to confirm network and retrieve the service public key.  
4. Call `/check` with RFQ details (and `X-API-Key` when `API_KEYS` is set); pass `commit_hash`, and `liquidity_proof` into your preflight program instruction (SOLANA).

## Hash Pre-Image

The `commit_hash` is a SHA-256 digest over a 178-byte buffer:

| Field          | Bytes | Type       |
|----------------|-------|------------|
| salt           | 64    | [u8; 64]   |
| rfq            | 32    | Pubkey     |
| taker          | 32    | Pubkey     |
| quote_mint     | 32    | Pubkey     |
| quote_amount   | 8     | u64 (LE)   |
| bond_amount    | 8     | u64 (LE)   |
| taker_fee_bps  | 2     | u16 (LE)   |
| **Total**      | **178** |          |

The on-chain verifier must construct the same buffer to validate signatures.

## Notes

- Keep the signing key secure and rotate as needed; clients should read the active public key from `/health`.
- Keep `commit_hash` construction identical between the service and on-chain verifier to ensure signatures validate.
- `taker_fee_bps` is a basis-point value (0–10,000) representing the taker fee percentage. When `taker_fee_bps > 0`, the protocol fee uplift is always at least 1 (floor division with minimum 1). When `taker_fee_bps = 0`, no fee is applied.

# Liquidity Guard

A minimal REST microservice and Dockerized REST API that validates a taker’s liquidity for an OTC RFQ on Solana and returns a signed preflight proof (commit hash, Ed25519 signature) for on‑chain verification.

## How it fits

Use the service output in a Solana preflight instruction that verifies the hash and Ed25519 signature on‑chain before running the business logic. See also:

- [settlement-engine](https://github.com/unleaktrade/settlement-engine): the program that verifies the proof in `commit_quote` and recomputes the hash in `reveal_quote`
- [experimental-preflight-sigcheck](https://github.com/unleaktrade/experimental-preflight-sigcheck): the historical proof of concept of the Ed25519 preflight pattern (it does not implement this service's pre-image)

## Endpoints

- GET `/health`  
  Returns `{"status":"healthy","network":…,"service_pubkey":…,"timestamp":…,"skip_fund_checks":…}`: the configured network (`"Devnet"`, `"Mainnet"` or `"Localnet"`, capitalised), the Ed25519 public key used to verify signatures, and whether balance checks are disabled.

- GET `/ready`  
  Readiness probe: `200` `{"status":"ready"}` when the Solana RPC answers, `503` `{"error":"Service not ready"}` otherwise. Unauthenticated, but rate limited when `RATE_LIMIT` is on.

- GET `/metrics`  
  Prometheus metrics (text format). Protected by `METRICS_TOKEN` and/or `API_KEYS` when set (either credential works).

- POST `/check`  
  Requires an API key when `API_KEYS` is set (see [Authentication](#authentication)). Validates taker liquidity for the RFQ and responds with:
  - `commit_hash`: deterministic SHA-256 hash derived from RFQ fields
  - `liquidity_proof`: Ed25519 signature of `commit_hash` using the service key
  - Echoed request context and metadata (network, timestamp, service_pubkey)

Validation rules:

- Every request field is a JSON **string** (amounts and `taker_fee_bps` in decimal)
- `salt` must be 128 hex characters (64 bytes) and a valid **Ed25519 signature by `taker` over the 32 raw bytes of the `rfq` pubkey**; anything else is rejected with `400`. Clients obtain it with `signMessage(rfq.toBytes())`, which also makes it re-derivable at reveal time
- USDC balance must cover `bond_amount_usdc`
- Quote token balance must cover `quote_amount` + protocol fee uplift
  - Uplift = `floor(quote_amount * taker_fee_bps / 10_000)`, minimum 1 when `taker_fee_bps > 0`
- `taker_fee_bps` must not exceed 10,000 (100% in basis points)
- Balances are read from the taker's classic SPL-Token associated token accounts only (not Token-2022); a missing account counts as a zero balance. With `SKIP_FUND_CHECKS` no balance is read at all

Error responses:

| Status | When | Body |
|---|---|---|
| `400` | Invalid pubkey, amount or salt; fee above the cap; insufficient funds | JSON `{"error":…}` for the salt-signature, fee-cap and balance checks, plain text otherwise |
| `401` | Missing or wrong API key (when `API_KEYS` is set) | `{"error":"Unauthorized"}` |
| `413` | Body over 1024 bytes, **and any body that fails JSON deserialisation** (malformed JSON, missing field, non-string value) | plain text |
| `429` | Rate limit exceeded (when `RATE_LIMIT` is on) | plain text |
| `500` | Solana RPC failure during the balance check | `Internal server error` |

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

Keys sent by a browser app are visible to anyone who opens the app: treat those as revocable client identifiers, give each consumer its own key and keep `RATE_LIMIT=1` (with `RATE_LIMIT_TRUST_PROXY=1` on Heroku) on browser-facing instances.

### Check - Request example

```json
{
  "rfq": "Z6QxihLr3dihqPuPQk1TQsShYJcL7XoGoH1BafqejWA",
  "taker": "Dfi6F1SxSQnpoPXtncwvu5BdzJw47NMY2mtgLGKAwiWC",
  "salt": "0a439225c0fd8f11cacbc223a426ce485577c91b32f2e1ba6e3da082c896d4ccde6b4edb7bac9520427f8edb91a4be9f247feed2d2f554d7281d5bc646044704",
  "quote_mint": "2BXfxddd6Mg9JAsNeqJMjg9URofaCTfzASCg6W8dMHYo",
  "quote_amount": "100000000",
  "bond_amount_usdc": "100000",
  "taker_fee_bps": "50"
}
```

### Check - Response example

```json
{
    "rfq": "Z6QxihLr3dihqPuPQk1TQsShYJcL7XoGoH1BafqejWA",
    "salt": "0a439225c0fd8f11cacbc223a426ce485577c91b32f2e1ba6e3da082c896d4ccde6b4edb7bac9520427f8edb91a4be9f247feed2d2f554d7281d5bc646044704",
    "taker": "Dfi6F1SxSQnpoPXtncwvu5BdzJw47NMY2mtgLGKAwiWC",
    "usdc_mint": "1117mWrzzrZr312ebPDHu8tbfMwFNvCvMbr6WepCNG",
    "quote_mint": "2BXfxddd6Mg9JAsNeqJMjg9URofaCTfzASCg6W8dMHYo",
    "quote_amount": "100000000",
    "bond_amount_usdc": "100000",
    "taker_fee_bps": "50",
    "service_pubkey": "8RrQiPAfwvHaNRxpTYCJHcJnt3e5K2p3e35GzB7rM7hg",
    "commit_hash": "85f529bd0a350976e6c4af0ebf9c3638ad09b6612ee03d90d42a1a4350be42f5",
    "liquidity_proof": "d58b0cfc1e784182a21584a071c03e93b58e85eb88cdc42c1df7f995bbfdcf7e9b0a7600aa2121d7ed7bc82848123ca865fab5dc1b1b8bf8d6b1f9c965100b03",
    "network": "Localnet",
    "skip_fund_checks": true,
    "timestamp": 1791895507
}
```

Both examples come from one real call to a local instance started with throwaway keys (`cargo run --example postman_env`, `SKIP_FUND_CHECKS=true`, `SOLANA_NETWORK=localnet`), so `commit_hash` is the SHA-256 of the [pre-image](#hash-pre-image) built from these exact fields and `liquidity_proof` verifies against `service_pubkey`. A deployed instance answers with its own `service_pubkey`, `usdc_mint` and `network`.

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

- Or with Compose (`docker-compose.yml`):  
  `docker compose up --build`

There is no `.env.example`: create `.env` from the table below. The image's `EXPOSE` and `HEALTHCHECK` hardcode port 8080, so a different `PORT` breaks the container health check.

Environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `SIGNING_KEY` | **Yes** | — | Base58-encoded keypair for Ed25519 signing |
| `USDC_MINT` | **Yes** | — | Base58-encoded USDC mint pubkey |
| `SOLANA_NETWORK` | No | `devnet` | `devnet`, `mainnet` (or `mainnet-beta`), or `localnet`. An unrecognised value silently falls back to `devnet` |
| `SOLANA_RPC_URL` | No | Derived from network | Solana RPC endpoint |
| `SOLANA_RPC_FALLBACK` | No | `true` | Retry once on the network's public RPC when a custom `SOLANA_RPC_URL` fails. Set to `false` or `0` to disable. |
| `SOLANA_RPC_TIMEOUT_SECS` | No | `10` | Per-request RPC timeout (connect timeout is `min(5, value)`) |
| `SOLANA_RPC_POOL_MAX_IDLE` | No | `32` | Max idle keep-alive connections per RPC host |
| `SKIP_FUND_CHECKS` | No | `false` | Skip on-chain balance checks (CI/CD) |
| `RATE_LIMIT` | No | `false` | Per-client-IP rate limit on `/ready` and `/check`: one request every 2 s sustained (0.5 req/s), burst 5; `429` with a plain-text body when exceeded |
| `RATE_LIMIT_TRUST_PROXY` | No | `false` | Key the rate limiter on the client IP from the last `X-Forwarded-For` entry (the one the proxy appends) instead of the TCP peer. **Required on Heroku**, where the peer is the router, so without it the limiter does not limit per user. Only enable behind a proxy that always appends that header |
| `CORS` | No | `true` | Enable permissive CORS (`Access-Control-Allow-Origin: *`, any method/header, no credentials). Set to `false` or `0` to disable. |
| `CORS_MAX_AGE` | No | `3600` | Preflight cache duration in seconds |
| `PORT` | No | `8080` | HTTP listen port |
| `LOG_FORMAT` | No | `json` | `json` (one JSON object per line) or `pretty` / `text` (human-readable, for local dev) |
| `RUST_LOG` | No | `info` | Log filter, e.g. `info,liquidity_guard=debug` |
| `METRICS_TOKEN` | No | — | When set, `GET /metrics` requires `Authorization: Bearer <token>` (or an API key); open only when neither `METRICS_TOKEN` nor `API_KEYS` is set |
| `API_KEYS` | No | — | Comma-separated API keys required on `POST /check` (and accepted on `/metrics`). Unset = no authentication |
| `API_KEY` | No | — | Single API key, merged with `API_KEYS` |

## Deployment (Heroku)

Three Heroku apps run the Docker image (`heroku.yml`). Deploy by pushing `main` to the app's git remote, and keep the GitHub branch of the same name in sync:

| Instance | Git remote → Heroku app | Guard key (`/health.service_pubkey`) | Settings besides `SIGNING_KEY`, `USDC_MINT`, `METRICS_TOKEN` |
|---|---|---|---|
| devnet | `devnet` → `liquidity-guard-devnet` | must equal devnet `Config.liquidity_guard` | `API_KEYS`, `RATE_LIMIT=1`, `RATE_LIMIT_TRUST_PROXY=1` |
| devnet, skip | `devnet_skip` → `liquidity-guard-devnet-skip` | test-only key (not in Config) | `API_KEYS`, `SKIP_FUND_CHECKS=1` |
| mainnet | `heroku` → `liquidity-guard-mainnet` | will have to equal mainnet `Config.liquidity_guard` (the settlement-engine program is not deployed on mainnet yet) | `SOLANA_NETWORK=mainnet`, `API_KEYS`, `RATE_LIMIT=1`, `RATE_LIMIT_TRUST_PROXY=1` |

```sh
git push devnet main && git push origin main:devnet                 # same for devnet_skip; mainnet: git push heroku main
curl -s https://<app-host>/health                                  # after each deploy
```

The devnet-skip instance signs with a key that is not the on-chain `Config.liquidity_guard`: it serves settlement-engine's test validator, not the deployed program.

### API keys: one per consumer

Each consumer gets its own random key (`openssl rand -hex 32`), listed in the `API_KEYS` of the instance it calls. Keys never go in the repo.

| Consumer | Instance(s) | Where the consumer reads it |
|---|---|---|
| Web app (`unleaktrade/app`) | devnet, mainnet | GitHub secrets `LG_API_KEY_DEVNET` / `LG_API_KEY_MAINNET`, inlined at build time: **public** in the JS bundle, a client identifier rather than a secret |
| settlement-engine CI | devnet-skip | GitHub secret `LIQUIDITY_GUARD_API_KEY` |
| `app` seed script | devnet | `--api-key` / `LG_API_KEY` (kept by the operator) |
| Postman | each instance | `API_KEY` (secret) in the matching workspace environment |

Because the app key is public, abuse protection on the browser-facing instances is the per-client rate limit; the key only lets you cut off one consumer without touching the others.

**Rotate a key** (no downtime, since `API_KEYS` takes several values): add the new key next to the old one in `API_KEYS`, update the consumer (and redeploy it, for the app), then remove the old key. **Revoke** by removing it from `API_KEYS`; changing a config var restarts the dyno.

**Check an instance** after any change:

```sh
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://<app-host>/check -H 'Content-Type: application/json' -d @check.json        # 401
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://<app-host>/check -H 'Content-Type: application/json' -H "X-API-Key: $KEY" -d @check.json   # 200, or 400 when the taker lacks funds
```

or run the Postman collection against the instance's environment (`npx newman run postman/liquidity-guard.postman_collection.json -e <env.json> --delay-request 2600`; the delay keeps the run under the rate limit).

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

1. Configure environment (.env) with at least `SIGNING_KEY` and `USDC_MINT` (the quote mint comes with each request), plus network and RPC as needed.  
2. Build and run with Cargo (`cargo run`) or Docker.  
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

# Liquidity Guard

A minimal REST microservice and Dockerized REST API that validates a taker’s liquidity for an OTC RFQ on Solana and returns a signed preflight proof (commit hash, Ed25519 signature) for on‑chain verification.

## How it fits

Use the service output in a Solana preflight instruction that verifies the hash and Ed25519 signature on‑chain before running the business logic. See also:

- [experimental-preflight-sigcheck](https://github.com/unleaktrade/experimental-preflight-sigcheck)
- [settlement-engine](https://github.com/unleaktrade/settlement-engine)

## Endpoints

- GET `/health`  
  Returns service status, configured network (`devnet`, `mainnet`, `localnet`), and the Ed25519 public key used to verify signatures.

- POST `/check`  
  Validates taker liquidity for the RFQ and responds with:
  - `commit_hash`: deterministic SHA-256 hash derived from RFQ fields
  - `liquidity_proof`: Ed25519 signature of `commit_hash` using the service key
  - Echoed request context and metadata (network, timestamp, service_pubkey)

Validation rules:

- USDC balance must cover `bond_amount_usdc`
- Quote token balance must cover `quote_amount` + protocol fee uplift
  - Uplift = `floor(quote_amount * taker_fee_bps / 10_000)`, minimum 1 when `taker_fee_bps > 0`
- `taker_fee_bps` must not exceed 10,000 (100% in basis points)

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
| `SKIP_FUND_CHECKS` | No | `false` | Skip on-chain balance checks (CI/CD) |
| `CORS` | No | `true` | Enable permissive CORS (any origin/method/header). Set to `false` or `0` to disable. |
| `CORS_MAX_AGE` | No | `3600` | Preflight cache duration in seconds |
| `PORT` | No | `8080` | HTTP listen port |

## Quick start

1. Configure environment (.env) with network, RPC, signing key, and mints.  
2. Build and run with Cargo or Docker.  
3. Call `/health` to confirm network and retrieve the service public key.  
4. Call `/check` with RFQ details; pass `commit_hash`, and `liquidity_proof` into your preflight program instruction (SOLANA).

## Hash Pre-Image

The `commit_hash` is a SHA-256 digest over a 186-byte buffer:

| Field          | Bytes | Type       |
|----------------|-------|------------|
| salt           | 64    | [u8; 64]   |
| rfq            | 32    | Pubkey     |
| taker          | 32    | Pubkey     |
| quote_mint     | 32    | Pubkey     |
| quote_amount   | 8     | u64 (LE)   |
| bond_amount    | 8     | u64 (LE)   |
| taker_fee_bps  | 2     | u16 (LE)   |
| **Total**      | **186** |          |

The on-chain verifier must construct the same buffer to validate signatures.

## Notes

- Keep the signing key secure and rotate as needed; clients should read the active public key from `/health`.
- Keep `commit_hash` construction identical between the service and on-chain verifier to ensure signatures validate.
- `taker_fee_bps` is a basis-point value (0–10,000) representing the taker fee percentage. When `taker_fee_bps > 0`, the protocol fee uplift is always at least 1 (floor division with minimum 1). When `taker_fee_bps = 0`, no fee is applied.

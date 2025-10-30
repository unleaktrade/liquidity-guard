# Liquidity Guard

A minimal REST microservice and Dockerized REST API that validates a taker’s liquidity for an OTC RFQ on Solana and returns a signed preflight proof (UUID, commit hash, ECDSA signature) for on‑chain verification.

## How it fits

Use the service output in a Solana preflight instruction that verifies the hash and ECDSA signature on‑chain before running the business logic. See also:

- [experimental-preflight-sigcheck](https://github.com/unleaktrade/experimental-preflight-sigcheck)
- [settlement-engine](https://github.com/unleaktrade/settlement-engine)

## Endpoints

- GET `/health`  
  Returns service status, configured network (`devnet`, `mainnet`, `localnet`), and the ECDSA public key used to verify signatures.

- POST `/check`  
  Validates taker liquidity for the RFQ and responds with:
  - `uuid`: unique request identifier
  - `commit_hash`: deterministic hash derived from `uuid` and RFQ fields
  - `service_signature`: ECDSA signature of `commit_hash` using the service key
  - Echoed request context and metadata (network, timestamp, service_pubkey)

Validation rules:

- USDC must cover `bond_amount_usdc + fee_amount_usdc`
- Quote-asset liquidity must cover `quote_amount`

### Check - Request example

```json
{
  "rfq": "6p7BsnxWgNze6wLjhHD9wN6Zo7jEpoFZ9npCDPhsJK8H",
  "taker": "8GAt381fturbi53tXBKubeKgXAdjKvu4fV7H9sn3z4pZ",
  "quote_mint": "EoTybYbsuFWfe64MqMqVuVTNgHfQgK6xLu4fvnguy9dN",
  "quote_amount": "100000000",
  "bond_amount_usdc": "100000",
  "fee_amount_usdc": "4567"
}
```

### Check - Response example

```json
{
  "uuid": "29cc00da-891f-42d4-a49d-23ac00fecf62",
  "rfq": "6p7BsnxWgNze6wLjhHD9wN6Zo7jEpoFZ9npCDPhsJK8H",
  "taker": "8GAt381fturbi53tXBKubeKgXAdjKvu4fV7H9sn3z4pZ",
  "usdc_mint": "5jBqJmY2mKetudVa2XaC8U6UN2BNNirDiTnDEuA6pdyR",
  "quote_mint": "EoTybYbsuFWfe64MqMqVuVTNgHfQgK6xLu4fvnguy9dN",
  "quote_amount": "100000000",
  "bond_amount_usdc": "100000",
  "fee_amount_usdc": "4567",
  "service_pubkey": "5gfPFweV3zJovznZqBra3rv5tWJ5EHVzQY1PqvNA4HGg",
  "commit_hash": "87fe5d66a030f3d3bc7586b91f4100cf2c26e79cbe90a9b603b72fceb8e4b1dd",
  "service_signature": "2718574104573fd5cadbbe362c517319c3b191add9c3355697049429cc14fd721f01d9a42f6bc6c677aa8d37c9c1c64817b29f640cf6a290c82491180fd39909",
  "network": "Devnet",
  "timestamp": 1761865975
}
```

## Docker

- Build:  
  `docker build -t liquidity-guard .`

- Run:  
  `docker run -p 8080:8080 --env-file .env liquidity-guard`

Environment variables typically include:

- `SOLANA_NETWORK` (e.g., `devnet` | `mainnet` | `localnet`)
- `SOLANA_RPC_URL`
- `SERVICE_SECRET_KEY` (ECDSA)
- `USDC_MINT`

## Quick start

1. Configure environment (.env) with network, RPC, signing key, and mints.  
2. Build and run with Cargo or Docker.  
3. Call `/health` to confirm network and retrieve the service public key.  
4. Call `/check` with RFQ details; pass `uuid`, `commit_hash`, and `service_signature` into your preflight program instruction.

## Notes

- Keep the signing key secure and rotate as needed; clients should read the active public key from `/health`.  
- Keep `commit_hash` construction identical between the service and on‑chain verifier to ensure signatures validate.

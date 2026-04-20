# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- Build: `cargo build` (release: `cargo build --release --locked`)
- Run locally: `cargo run` (needs `SIGNING_KEY` and `USDC_MINT` env vars)
- Lint: `cargo clippy --all-targets -- -D warnings`
- Format: `cargo fmt`
- Docker: `docker build -t liquidity-guard .` then `docker run -p 8080:8080 --env-file .env liquidity-guard`
- Compose: `docker compose up --build`

There is no test suite in this repo; do not invent one unless asked.

## Architecture

Single-binary Rust service (`src/main.rs`) built on actix-web. One `AppState` holds a shared `solana_client::nonblocking::RpcClient`, the service `Keypair`, the USDC mint pubkey, network label, and the `skip_fund_checks` flag. Three routes: `GET /health` (static info + service pubkey), `GET /ready` (probes Solana RPC via `get_version`), `POST /check` (the main flow).

The `/check` flow is a linear pipeline and must stay deterministic end-to-end because downstream consumers verify signatures on-chain:

1. Parse pubkeys (`rfq`, `taker`, `quote_mint`) and hex-decode `salt` (64 bytes → `Signature`).
2. Verify `salt` is an Ed25519 signature of `taker` over message `rfq` — `salt.verify(taker.as_ref(), rfq.as_ref())`. Rejection here is a client bug (400), not a server error.
3. Parse `quote_amount: u64`, `bond_amount_usdc: u64`, `taker_fee_bps: u16` (cap 10_000). Compute uplift = `floor(quote_amount * bps / 10_000)`, bumped to 1 when `bps > 0` and the floor rounds to zero. All arithmetic uses `checked_mul`/`checked_add`/`checked_div` on `u128` → `u64` with explicit error messages (see feedback memory).
4. When `skip_fund_checks` is false, a single `get_multiple_accounts([usdc_ata, quote_ata])` RPC call fetches both balances. ATAs are derived inline via `Pubkey::find_program_address` with the SPL-Token + ATA program ids (avoids pulling `spl-associated-token-account`). Balance is parsed raw from account bytes `[64..72]` as LE u64; missing account = 0.
5. Build the 186-byte SHA-256 pre-image in this exact order: `salt(64) || rfq(32) || taker(32) || quote_mint(32) || quote_amount_le(8) || bond_amount_le(8) || taker_fee_bps_le(2)`. Sign `commit_hash` with the service `Keypair`. Return hex-encoded hash and signature alongside echoed request fields.

**Critical invariant:** the pre-image byte layout in `check()` must stay byte-identical to the on-chain verifier in `experimental-preflight-sigcheck` / `settlement-engine`. Never reorder fields, change endianness, change field widths, or alter the salt semantics without coordinating with those repos — signatures will silently fail to validate.

## Configuration

Required env vars: `SIGNING_KEY` (base58 Solana keypair) and `USDC_MINT` (base58 pubkey). Both are `expect()`-ed at startup.

Optional env vars: `SOLANA_NETWORK` (`devnet` default, also `mainnet`/`mainnet-beta`/`localnet`), `SOLANA_RPC_URL` (overrides the network default), `SKIP_FUND_CHECKS` (`true`/`1` skips on-chain balance reads — used for CI/CD and echoed in responses), `RATE_LIMIT` (`true`/`1` wraps `/ready` and `/check` with `actix-governor` at 2 req/s sustained, burst 5, keyed per-IP), `PORT` (default 8080).

JSON bodies are capped at 1024 bytes via `JsonConfig::limit`; oversized payloads return 413. RPC commitment level is `confirmed`.

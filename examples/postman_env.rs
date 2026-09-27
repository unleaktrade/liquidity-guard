//! Generate ephemeral fixtures for running the Postman collection against a
//! local liquidity-guard (CI `newman` job, or by hand).
//!
//! ```sh
//! cargo run --example postman_env -- <out_dir> [api_url]
//! ```
//!
//! Writes two files into `<out_dir>`:
//! - `server.env`: `KEY=VALUE` lines to start the service with (fresh
//!   `SIGNING_KEY`, `USDC_MINT`, `API_KEYS`, `METRICS_TOKEN`, …);
//! - `postman_environment.json`: the matching Postman environment (service
//!   pubkey, network, credentials and a valid `/check` request: `SALT` is a
//!   real Ed25519 signature of `TAKER` over `RFQ`).
//!
//! Every key is freshly generated and unfunded; nothing is committed.
use serde_json::{json, Value};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use std::{env, fs, path::PathBuf};

fn secret() -> String {
    // 32 random bytes from a fresh keypair's seed, hex-encoded.
    hex::encode(&Keypair::new().to_bytes()[..32])
}

fn var(key: &str, value: impl Into<String>, secret: bool) -> Value {
    json!({
        "key": key,
        "value": value.into(),
        "type": if secret { "secret" } else { "default" },
        "enabled": true,
    })
}

fn main() {
    let mut args = env::args().skip(1);
    let out = PathBuf::from(args.next().expect("usage: postman_env <out_dir> [api_url]"));
    let api_url = args
        .next()
        .unwrap_or_else(|| "http://127.0.0.1:8080".into());
    fs::create_dir_all(&out).expect("create out dir");

    let service = Keypair::new();
    let taker = Keypair::new();
    let rfq = Pubkey::new_unique();
    let salt = hex::encode(taker.sign_message(rfq.as_ref()).as_ref());
    let (api_key, second_key, metrics_token) = (secret(), secret(), secret());

    let server_env = [
        ("SIGNING_KEY", service.to_base58_string()),
        ("USDC_MINT", Pubkey::new_unique().to_string()),
        ("SOLANA_NETWORK", "localnet".into()),
        // Nothing listens there: /check never touches RPC with SKIP_FUND_CHECKS.
        ("SOLANA_RPC_URL", "http://127.0.0.1:9".into()),
        ("SOLANA_RPC_TIMEOUT_SECS", "1".into()),
        ("SKIP_FUND_CHECKS", "true".into()),
        ("API_KEYS", format!("{api_key},{second_key}")),
        ("METRICS_TOKEN", metrics_token.clone()),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={v}\n"))
    .collect::<String>();
    fs::write(out.join("server.env"), server_env).expect("write server.env");

    let environment = json!({
        "name": "CI-liquidity guard (ephemeral)",
        "values": [
            var("API_URL", api_url, false),
            var("SERVICE_PUBKEY", service.pubkey().to_string(), false),
            var("SERVICE_NETWORK", "Localnet", false),
            var("API_KEY", api_key, true),
            var("METRICS_TOKEN", metrics_token, true),
            var("EXPECT_CHECK_STATUS", "200", false),
            var("RFQ", rfq.to_string(), false),
            var("TAKER", taker.pubkey().to_string(), false),
            var("SALT", salt, false),
            var("QUOTE_MINT", Pubkey::new_unique().to_string(), false),
            var("QUOTE_AMOUNT", "1000000", false),
            var("BOND_AMOUNT_USDC", "500000", false),
            var("TAKER_FEE_BPS", "25", false),
        ],
    });
    fs::write(
        out.join("postman_environment.json"),
        serde_json::to_string_pretty(&environment).unwrap(),
    )
    .expect("write postman_environment.json");
    println!(
        "wrote {}/{{server.env,postman_environment.json}}",
        out.display()
    );
}

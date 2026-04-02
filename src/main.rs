use actix_web::middleware::Logger;
use actix_web::{web, App, HttpResponse, HttpServer, Result};
use anyhow::Context;
use hex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use solana_account_decoder::{parse_account_data::ParsedAccount, UiAccountData};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_request::TokenAccountsFilter;
use solana_sdk::signature::Signature;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use std::{
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
enum Network {
    Localnet,
    Devnet,
    Mainnet,
}
impl Network {
    fn rpc_url(&self) -> &'static str {
        match self {
            Network::Localnet => "http://127.0.0.1:8899",
            Network::Devnet => "https://api.devnet.solana.com",
            Network::Mainnet => "https://api.mainnet-beta.solana.com",
        }
    }
    fn from_env() -> Self {
        match std::env::var("SOLANA_NETWORK")
            .unwrap_or_else(|_| "devnet".into())
            .to_lowercase()
            .as_str()
        {
            "mainnet" | "mainnet-beta" => Network::Mainnet,
            "localnet" => Network::Localnet,
            _ => Network::Devnet,
        }
    }
}

#[derive(Deserialize)]
struct CheckRequest {
    rfq: String,
    salt: String,
    taker: String,
    quote_mint: String,
    quote_amount: String,
    bond_amount_usdc: String,
    taker_fee_bps: String,
}

#[derive(Serialize)]
struct CheckResponse {
    rfq: String,
    salt: String,
    taker: String,
    usdc_mint: String,
    quote_mint: String,
    quote_amount: String,
    bond_amount_usdc: String,
    taker_fee_bps: String,
    service_pubkey: String,    // base58
    commit_hash: String,       // hex
    liquidity_proof: String, // hex
    network: String,
    #[serde(skip_serializing_if = "Clone::clone")]
    skip_fund_checks: bool,
    timestamp: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

struct AppState {
    rpc: Arc<RpcClient>,
    service_keypair: Arc<Keypair>,
    network_str: String,
    usdc_mint: Pubkey,
    skip_fund_checks: bool,
}

// Parse amount from UiAccountData::Json -> ParsedAccount { parsed: serde_json::Value, ... }
fn extract_amount_from_parsed(parsed: &ParsedAccount) -> Option<u64> {
    // parsed.parsed is a serde_json::Value with shape:
    // { "type": "account", "info": { "tokenAmount": { "amount": "123" } } }
    let v: &Value = &parsed.parsed;
    v.get("info")
        .and_then(|info| info.get("tokenAmount"))
        .and_then(|ta| ta.get("amount"))
        .and_then(|s| s.as_str())
        .and_then(|s| s.parse::<u64>().ok())
}

async fn get_token_balance(rpc: &RpcClient, owner: &Pubkey, mint: &Pubkey) -> anyhow::Result<u64> {
    // v2.3: two-arg nonblocking API; returns Vec<RpcKeyedAccount>
    let accounts = rpc
        .get_token_accounts_by_owner(owner, TokenAccountsFilter::Mint(*mint))
        .await
        .with_context(|| {
            format!(
                "get_token_accounts_by_owner failed (owner: {}, mint: {})",
                owner, mint
            )
        })?;

    let mut total: u64 = 0;
    for keyed in accounts {
        match keyed.account.data {
            UiAccountData::Json(parsed) => {
                if let Some(v) = extract_amount_from_parsed(&parsed) {
                    total = total.saturating_add(v);
                }
            }
            _ => {} // Ignore Binary/LegacyBinary
        }
    }
    Ok(total)
}

async fn check(data: web::Json<CheckRequest>, state: web::Data<AppState>) -> Result<HttpResponse> {
    let data = data.into_inner();

    // Parse keys
    let rfq = Pubkey::from_str(&data.rfq)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid rfq: {e}")))?;
    let taker = Pubkey::from_str(&data.taker)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid taker: {e}")))?;
    let quote_mint = Pubkey::from_str(&data.quote_mint)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid quote_mint: {e}")))?;

    //50f8f2e8b2bdd78400b8f20d9e526be2b7aab3346fdd043d84b35ad6ef4a5791434f243f5d84835bacc0ebfe32ba71b117a5da1301bad9ec4e297c8835387c0d
    let salt_bytes_vec = hex::decode(&data.salt).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!(
            "Invalid salt hex format for '{}': {}",
            data.salt, e
        ))
    })?;
    let salt_bytes = salt_bytes_vec.as_slice();
    let salt = Signature::try_from(salt_bytes).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Invalid salt format for '{}': {}", data.salt, e))
    })?;
    // Verify salt is valid signature of (taker || rfq)
    if !salt.verify(&taker.as_ref(), &rfq.as_ref()) {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: format!(
                "Invalid salt {} for taker {} and rfq {}",
                data.salt,
                data.taker,
                data.rfq,
            ),
        }));
    }

    // Parse amounts
    let quote_amount: u64 = data
        .quote_amount
        .parse()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid quote_amount: {e}")))?;
    let bond_amount: u64 = data
        .bond_amount_usdc
        .parse()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid bond_amount_usdc: {e}")))?;
    let taker_fee_bps: u16 = data
        .taker_fee_bps
        .parse()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid taker_fee_bps: {e}")))?;
    if taker_fee_bps > 10_000 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: format!(
                "taker_fee_bps must not exceed 10000 (100%), got {taker_fee_bps}"
            ),
        }));
    }

    // Protocol fee uplift (floor division + min 1 when taker_fee_bps > 0)
    let uplift: u64 = if taker_fee_bps > 0 {
        let fee = (quote_amount as u128)
            .checked_mul(taker_fee_bps as u128)
            .ok_or_else(|| actix_web::error::ErrorBadRequest(
                format!("Overflow computing fee: quote_amount={quote_amount} * taker_fee_bps={taker_fee_bps}")
            ))?
            .checked_div(10_000)
            .ok_or_else(|| actix_web::error::ErrorBadRequest(
                "Unexpected division error in fee computation"
            ))?;
        let fee = u64::try_from(fee).map_err(|_| actix_web::error::ErrorBadRequest(
            format!("Fee uplift {fee} exceeds maximum u64 value")
        ))?;
        if fee == 0 { 1 } else { fee }
    } else {
        0
    };
    let required_quote = quote_amount.checked_add(uplift).ok_or_else(|| {
        actix_web::error::ErrorBadRequest(
            format!("Overflow computing required quote: quote_amount={quote_amount} + uplift={uplift}")
        )
    })?;

    // Liquidity checks: USDC covers bond, quote token covers bid + protocol fees
    if !state.skip_fund_checks {
        let (usdc_balance, quote_balance) = tokio::try_join!(
            get_token_balance(&state.rpc, &taker, &state.usdc_mint),
            get_token_balance(&state.rpc, &taker, &quote_mint),
        )
        .map_err(|e| {
            log::error!("RPC error during liquidity check: {e}");
            actix_web::error::ErrorInternalServerError("Internal server error")
        })?;

        if usdc_balance < bond_amount {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: format!(
                    "Insufficient USDC: has {usdc_balance} needs {bond_amount} (bond)"
                ),
            }));
        }
        if quote_balance < required_quote {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: format!(
                    "Insufficient quote: has {quote_balance} needs {required_quote} (quote {quote_amount} + fee {uplift})"
                ),
            }));
        }
    }

    // Commit hash (186 bytes total pre-image)
    let mut hasher = Sha256::new();
    hasher.update(&salt_bytes);                       // 64 bytes
    hasher.update(rfq.as_ref());                      // 32 bytes
    hasher.update(taker.as_ref());                    // 32 bytes
    hasher.update(quote_mint.as_ref());               // 32 bytes
    hasher.update(quote_amount.to_le_bytes());        // 8 bytes
    hasher.update(bond_amount.to_le_bytes());         // 8 bytes
    hasher.update(taker_fee_bps.to_le_bytes());       // 2 bytes (u16)
    let commit_hash = hasher.finalize();

    // Sign with solana_sdk Keypair
    let signature = state.service_keypair.sign_message(&commit_hash);
    let service_pubkey_b58 = state.service_keypair.pubkey().to_string();

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let usdc_mint_b58 = state.usdc_mint.to_string();

    Ok(HttpResponse::Ok().json(CheckResponse {
        rfq: data.rfq,
        salt: data.salt,
        taker: data.taker,
        usdc_mint: usdc_mint_b58,
        quote_mint: data.quote_mint,
        quote_amount: data.quote_amount,
        bond_amount_usdc: data.bond_amount_usdc,
        taker_fee_bps: data.taker_fee_bps,
        commit_hash: hex::encode(commit_hash),
        service_pubkey: service_pubkey_b58,
        liquidity_proof: hex::encode(signature.as_ref()),
        timestamp: ts,
        skip_fund_checks: state.skip_fund_checks,
        network: state.network_str.clone(),
    }))
}

async fn health(state: web::Data<AppState>) -> Result<HttpResponse> {
    #[derive(Serialize)]
    struct Health {
        status: &'static str,
        network: String,
        service_pubkey: String,
        timestamp: u64,
        #[serde(skip_serializing_if = "Clone::clone")]
        skip_fund_checks: bool,
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Ok(HttpResponse::Ok().json(Health {
        status: "healthy",
        network: state.network_str.clone(),
        service_pubkey: state.service_keypair.pubkey().to_string(),
        timestamp: ts,
        skip_fund_checks: state.skip_fund_checks,
    }))
}

async fn ready(state: web::Data<AppState>) -> Result<HttpResponse> {
    #[derive(Serialize)]
    struct Ready {
        status: &'static str,
    }
    match state.rpc.get_version().await {
        Ok(_) => Ok(HttpResponse::Ok().json(Ready { status: "ready" })),
        Err(e) => {
            log::error!("Readiness check failed: {e}");
            Ok(HttpResponse::ServiceUnavailable().json(ErrorResponse {
                error: "Service not ready".to_string(),
            }))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let filter = "info,actix_web=info,actix_http=info,actix_server=info";
    env_logger::Builder::from_env(env_logger::Env::default())
        .filter_level(log::LevelFilter::Info)
        .parse_filters(filter)
        .init();

    let network = Network::from_env();
    let rpc_url = std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| network.rpc_url().into());
    let rpc = Arc::new(RpcClient::new_with_commitment(
        rpc_url.clone(),
        CommitmentConfig::confirmed(),
    ));

    // SIGNING_KEY is base58 keypair string
    let keypair_b58 =
        std::env::var("SIGNING_KEY").expect("SIGNING_KEY env var required (base58 Keypair)");
    let service_keypair = Arc::new(Keypair::from_base58_string(&keypair_b58));

    let usdc_mint_str =
        std::env::var("USDC_MINT").expect("USDC_MINT env var is required (base58 Pubkey)");
    let usdc_mint =
        Pubkey::from_str(&usdc_mint_str).expect("USDC_MINT must be a valid base58 Pubkey");

    let skip_fund_checks = std::env::var("SKIP_FUND_CHECKS")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false);

    let state = web::Data::new(AppState {
        rpc,
        service_keypair,
        network_str: format!("{:?}", network),
        usdc_mint,
        skip_fund_checks,
    });

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let bind = format!("0.0.0.0:{port}");

    HttpServer::new(move || {
        App::new()
            // Enable access logs for this service only
            .wrap(Logger::new(r#"%a "%r" %s %b %Dms"#))
            .app_data(state.clone())
            .route("/health", web::get().to(health))
            .route("/ready", web::get().to(ready))
            .route("/check", web::post().to(check))
    })
    .shutdown_timeout(15)
    .bind(&bind)?
    .run()
    .await
}

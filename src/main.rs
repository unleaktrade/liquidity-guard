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
use uuid::Uuid;

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
    taker: String,
    quote_mint: String,
    quote_amount: String,
    bond_amount_usdc: String,
    fee_amount_usdc: String,
}

#[derive(Serialize)]
struct CheckResponse {
    uuid: String,
    rfq: String,
    taker: String,
    usdc_mint: String,
    quote_mint: String,
    quote_amount: String,
    bond_amount_usdc: String,
    fee_amount_usdc: String,
    service_pubkey: String,    // base58
    commit_hash: String,       // hex
    service_signature: String, // hex
    network: String,
    timestamp: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

struct AppState {
    rpc: Arc<RpcClient>,
    service_keypair: Arc<Keypair>,
    network: Network,
    usdc_mint: Pubkey,
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
        .with_context(|| format!("get_token_accounts_by_owner failed (owner: {}, mint: {})", owner, mint))?;

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
    // Parse keys
    let rfq = Pubkey::from_str(&data.rfq)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid rfq: {e}")))?;
    let taker = Pubkey::from_str(&data.taker)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid taker: {e}")))?;
    let quote_mint = Pubkey::from_str(&data.quote_mint)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid quote_mint: {e}")))?;

    // Parse amounts
    let quote_amount: u64 = data
        .quote_amount
        .parse()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid quote_amount: {e}")))?;
    let bond_amount: u64 = data
        .bond_amount_usdc
        .parse()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid bond_amount_usdc: {e}")))?;
    let fee_amount: u64 = data
        .fee_amount_usdc
        .parse()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid fee_amount_usdc: {e}")))?;

    // Parallel liquidity checks
    let need_usdc = bond_amount.saturating_add(fee_amount);
    let (usdc_balance, quote_balance) = tokio::try_join!(
        get_token_balance(&state.rpc, &taker, &state.usdc_mint),
        get_token_balance(&state.rpc, &taker, &quote_mint),
    )
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("RPC error: {e}")))?;

    if usdc_balance < need_usdc {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: format!(
                "Insufficient USDC: has {usdc_balance} needs {need_usdc} (bond {bond_amount}, fee {fee_amount})"
            ),
        }));
    }
    if quote_balance < quote_amount {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: format!("Insufficient quote: has {quote_balance} needs {quote_amount}"),
        }));
    }

    // Commit hash: uuid || rfq || taker
    let uuid = Uuid::new_v4();
    let mut hasher = Sha256::new();
    hasher.update(uuid.as_bytes());
    hasher.update(rfq.to_bytes());
    hasher.update(taker.to_bytes());
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
        uuid: uuid.to_string(),
        rfq: data.rfq.clone(),
        taker: data.taker.clone(),
        usdc_mint: usdc_mint_b58,
        quote_mint: data.quote_mint.clone(),
        quote_amount: data.quote_amount.clone(),
        bond_amount_usdc: data.bond_amount_usdc.clone(),
        fee_amount_usdc: data.fee_amount_usdc.clone(),
        commit_hash: hex::encode(commit_hash),
        service_pubkey: service_pubkey_b58,
        service_signature: hex::encode(signature.as_ref()),
        timestamp: ts,
        network: format!("{:?}", state.network),
    }))
}

async fn health(state: web::Data<AppState>) -> Result<HttpResponse> {
    #[derive(Serialize)]
    struct Health {
        status: &'static str,
        network: String,
        service_pubkey: String,
    }
    Ok(HttpResponse::Ok().json(Health {
        status: "healthy",
        network: format!("{:?}", state.network),
        service_pubkey: state.service_keypair.pubkey().to_string(),
    }))
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

    let state = web::Data::new(AppState {
        rpc,
        service_keypair,
        network: network.clone(),
        usdc_mint,
    });

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let bind = format!("0.0.0.0:{port}");

    HttpServer::new(move || {
        App::new()
            // Enable access logs for this service only
            .wrap(Logger::new(r#"%a "%r" %s %b %Dms"#))
            .app_data(state.clone())
            .route("/health", web::get().to(health))
            .route("/check", web::post().to(check))
    })
    .bind(&bind)?
    .run()
    .await
}

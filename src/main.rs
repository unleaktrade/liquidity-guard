use actix_web::{web, App, HttpResponse, HttpServer, Result};
use anyhow::Context;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::Keypair,
};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
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
            .unwrap_or_else(|_| "devnet".to_string())
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
    usdc_mint: String,
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
    commit_hash: String,
    service_pubkey: String,
    service_signature: String,
    timestamp: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

struct AppState {
    rpc: Arc<RpcClient>,
    signing_key: SigningKey,
    network: Network,
}

async fn get_token_balance(
    rpc: &RpcClient,
    owner: &Pubkey,
    mint: &Pubkey,
) -> anyhow::Result<u64> {
    let accounts = rpc
        .get_token_accounts_by_owner(
            owner,
            solana_client::rpc_request::TokenAccountsFilter::Mint(*mint),
        )
        .await
        .context("Failed to fetch token accounts")?;

    let total: u64 = accounts
        .iter()
        .filter_map(|acc| {
            serde_json::from_str::<serde_json::Value>(&acc.account.data.to_string())
                .ok()
                .and_then(|v| {
                    v["parsed"]["info"]["tokenAmount"]["amount"]
                        .as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                })
        })
        .sum();

    Ok(total)
}

async fn check_liquidity(
    data: web::Json<CheckRequest>,
    state: web::Data<AppState>,
) -> Result<HttpResponse> {
    // Parse addresses
    let rfq = Pubkey::from_str(&data.rfq)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid rfq: {}", e)))?;

    let taker = Pubkey::from_str(&data.taker)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid taker: {}", e)))?;

    let usdc_mint = Pubkey::from_str(&data.usdc_mint)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid usdc_mint: {}", e)))?;

    let quote_mint = Pubkey::from_str(&data.quote_mint)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid quote_mint: {}", e)))?;

    // Parse amounts
    let quote_amount: u64 = data
        .quote_amount
        .parse()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid quote_amount: {}", e)))?;

    let bond_amount: u64 = data
        .bond_amount_usdc
        .parse()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid bond_amount_usdc: {}", e)))?;

    let fee_amount: u64 = data
        .fee_amount_usdc
        .parse()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid fee_amount_usdc: {}", e)))?;

    let required_usdc = bond_amount + fee_amount;

    // Check USDC balance
    let usdc_balance = get_token_balance(&state.rpc, &taker, &usdc_mint)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("RPC error (USDC): {}", e)))?;

    if usdc_balance < required_usdc {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: format!(
                "Insufficient USDC: has {} but needs {} (bond: {}, fee: {})",
                usdc_balance, required_usdc, bond_amount, fee_amount
            ),
        }));
    }

    // Check quote token balance
    let quote_balance = get_token_balance(&state.rpc, &taker, &quote_mint)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("RPC error (quote): {}", e)))?;

    if quote_balance < quote_amount {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: format!(
                "Insufficient quote token: has {} but needs {}",
                quote_balance, quote_amount
            ),
        }));
    }

    // Generate attestation
    let uuid = Uuid::new_v4();

    // Hash: uuid || rfq || taker
    let mut hasher = Sha256::new();
    hasher.update(uuid.as_bytes());
    hasher.update(rfq.to_bytes());
    hasher.update(taker.to_bytes());
    let hash = hasher.finalize();

    // Sign
    let signature = state.signing_key.sign(&hash);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Ok(HttpResponse::Ok().json(CheckResponse {
        uuid: uuid.to_string(),
        rfq: data.rfq.clone(),
        taker: data.taker.clone(),
        usdc_mint: data.usdc_mint.clone(),
        quote_mint: data.quote_mint.clone(),
        quote_amount: data.quote_amount.clone(),
        bond_amount_usdc: data.bond_amount_usdc.clone(),
        fee_amount_usdc: data.fee_amount_usdc.clone(),
        commit_hash: hex::encode(hash),
        service_pubkey: state.signing_key.verifying_key().to_string(),
        service_signature: hex::encode(signature.to_bytes()),
        timestamp,
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
        service_pubkey: state.signing_key.verifying_key().to_string(),
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let network = Network::from_env();
    let rpc_url = std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| network.rpc_url().to_string());

    let rpc = Arc::new(RpcClient::new_with_commitment(
        rpc_url.clone(),
        CommitmentConfig::confirmed(),
    ));

    let signing_key = load_signing_key();

    let state = web::Data::new(AppState {
        rpc,
        signing_key,
        network: network.clone(),
    });

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind = format!("0.0.0.0:{}", port);

    log::info!("🚀 Liquidity Guard");
    log::info!("   Network: {:?}", network);
    log::info!("   RPC: {}", rpc_url);
    log::info!("   Bind: {}", bind);
    log::info!("   Pubkey: {}", state.signing_key.verifying_key());

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/health", web::get().to(health))
            .route("/check", web::post().to(check_liquidity))
    })
    .bind(&bind)?
    .run()
    .await
}

fn load_signing_key() -> SigningKey {
    let key_b58 = std::env::var("SIGNING_KEY")
        .expect("SIGNING_KEY environment variable required");

    let keypair = Keypair::from_base58_string(&key_b58);
    
    log::info!("✅ Loaded signing key");
    
    SigningKey::from_bytes(&keypair.to_bytes()[..32].try_into().unwrap())
}

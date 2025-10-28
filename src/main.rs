use actix_web::{web, App, HttpResponse, HttpServer, Result};
use anyhow::Context;
use bs58;
use ed25519_dalek::{Signer, SigningKey};
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_account_decoder::UiAccountData; // use decoder (not client_types) for enum variant
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_request::TokenAccountsFilter;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Keypair};
use std::{str::FromStr, sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use uuid::Uuid;

#[derive(Debug, Clone)]
enum Network { Localnet, Devnet, Mainnet }
impl Network {
    fn rpc_url(&self) -> &'static str {
        match self {
            Network::Localnet => "http://127.0.0.1:8899",
            Network::Devnet => "https://api.devnet.solana.com",
            Network::Mainnet => "https://api.mainnet-beta.solana.com",
        }
    }
    fn from_env() -> Self {
        match std::env::var("SOLANA_NETWORK").unwrap_or_else(|_| "devnet".into()).to_lowercase().as_str() {
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
    commit_hash: String,       // hex
    service_pubkey: String,    // base58
    service_signature: String, // hex
    timestamp: u64,
}

#[derive(Serialize)]
struct ErrorResponse { error: String }

struct AppState {
    rpc: Arc<RpcClient>,
    signing_key: SigningKey,
    network: Network,
}

async fn get_token_balance(rpc: &RpcClient, owner: &Pubkey, mint: &Pubkey) -> anyhow::Result<u64> {
    // v2.3 nonblocking signature: get_token_accounts_by_owner(owner, filter)
    let accounts = rpc
        .get_token_accounts_by_owner(owner, TokenAccountsFilter::Mint(*mint))
        .await
        .context("get_token_accounts_by_owner failed")?;

    // Iterate Vec<RpcKeyedAccount> (no .value)
    let mut total: u64 = 0;
    for keyed in accounts {
        match keyed.account.data {
            UiAccountData::Json(parsed) => {
                // parsed.parsed is serde_json::Value for SPL token accounts
                if let Some(amount_str) = parsed.parsed
                    .get("info")
                    .and_then(|info| info.get("tokenAmount"))
                    .and_then(|ta| ta.get("amount"))
                    .and_then(|x| x.as_str())
                {
                    if let Ok(v) = amount_str.parse::<u64>() {
                        total = total.saturating_add(v);
                    }
                }
            }
            // If RPC returns Binary or LegacyBinary for some reason, ignore (not expected for token program with default settings)
            _ => {}
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
    let usdc_mint = Pubkey::from_str(&data.usdc_mint)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid usdc_mint: {e}")))?;
    let quote_mint = Pubkey::from_str(&data.quote_mint)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid quote_mint: {e}")))?;

    // Parse amounts
    let quote_amount: u64 = data.quote_amount.parse()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid quote_amount: {e}")))?;
    let bond_amount: u64 = data.bond_amount_usdc.parse()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid bond_amount_usdc: {e}")))?;
    let fee_amount: u64 = data.fee_amount_usdc.parse()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid fee_amount_usdc: {e}")))?;

    // Enforce both liquidity checks concurrently
    let needed_usdc = bond_amount.saturating_add(fee_amount);
    let (usdc_balance, quote_balance) = tokio::try_join!(
        get_token_balance(&state.rpc, &taker, &usdc_mint),
        get_token_balance(&state.rpc, &taker, &quote_mint),
    ).map_err(|e| actix_web::error::ErrorInternalServerError(format!("RPC error: {e}")))?;

    if usdc_balance < needed_usdc {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: format!("Insufficient USDC: has {usdc_balance} needs {needed_usdc} (bond {bond_amount}, fee {fee_amount})"),
        }));
    }
    if quote_balance < quote_amount {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: format!("Insufficient quote: has {quote_balance} needs {quote_amount}"),
        }));
    }

    // Attestation: uuid || rfq || taker
    let uuid = Uuid::new_v4();
    let mut hasher = Sha256::new();
    hasher.update(uuid.as_bytes());
    hasher.update(rfq.to_bytes());
    hasher.update(taker.to_bytes());
    let commit_hash = hasher.finalize();

    let signature = state.signing_key.sign(&commit_hash);
    let service_pubkey_b58 = bs58::encode(state.signing_key.verifying_key().to_bytes()).into_string();
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    Ok(HttpResponse::Ok().json(CheckResponse {
        uuid: uuid.to_string(),
        rfq: data.rfq.clone(),
        taker: data.taker.clone(),
        usdc_mint: data.usdc_mint.clone(),
        quote_mint: data.quote_mint.clone(),
        quote_amount: data.quote_amount.clone(),
        bond_amount_usdc: data.bond_amount_usdc.clone(),
        fee_amount_usdc: data.fee_amount_usdc.clone(),
        commit_hash: hex::encode(commit_hash),
        service_pubkey: service_pubkey_b58,
        service_signature: hex::encode(signature.to_bytes()),
        timestamp: ts,
    }))
}

async fn health(state: web::Data<AppState>) -> Result<HttpResponse> {
    #[derive(Serialize)]
    struct Health { status: &'static str, network: String, service_pubkey: String }
    let service_pubkey = bs58::encode(state.signing_key.verifying_key().to_bytes()).into_string();
    Ok(HttpResponse::Ok().json(Health {
        status: "healthy",
        network: format!("{:?}", state.network),
        service_pubkey,
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let network = Network::from_env();
    let rpc_url = std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| network.rpc_url().into());
    let rpc = Arc::new(RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed()));

    let signing_key = load_signing_key(); // from SIGNING_KEY base58 keypair
    let state = web::Data::new(AppState { rpc, signing_key, network: network.clone() });

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let bind = format!("0.0.0.0:{port}");
    log::info!("Liquidity Guard on {bind}, network {:?}", network);

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/health", web::get().to(health))
            .route("/check", web::post().to(check))
    })
    .bind(&bind)?
    .run()
    .await
}

// SIGNING_KEY="base58 keypair"
fn load_signing_key() -> SigningKey {
    let keypair_b58 = std::env::var("SIGNING_KEY").expect("SIGNING_KEY env var required (base58 Keypair)");
    let keypair = Keypair::from_base58_string(&keypair_b58);
    // Use secret_bytes() (not deprecated) -> first 32 bytes are seed for dalek SigningKey
    let secret = keypair.secret_bytes(); // 64 bytes (expanded), first 32 is seed
    let seed: [u8; 32] = secret[..32].try_into().expect("secret length");
    SigningKey::from_bytes(&seed)
}

use actix_cors::Cors;
use actix_governor::governor::middleware::NoOpMiddleware;
use actix_governor::{Governor, GovernorConfig, GovernorConfigBuilder, PeerIpKeyExtractor};
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpResponse, HttpServer, Result};
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_client::client_error::Result as ClientResult;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client::http_sender::HttpSender;
use solana_rpc_client::rpc_client::RpcClientConfig;
use solana_sdk::hash::Hash;
use solana_sdk::signature::Signature;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use std::{
    future::Future,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq)]
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
    /// Genesis hash of the public cluster, used to make sure a custom RPC URL
    /// serves the same chain as the fallback. Localnet has no fixed genesis.
    fn genesis_hash(&self) -> Option<&'static str> {
        match self {
            Network::Localnet => None,
            Network::Devnet => Some("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"),
            Network::Mainnet => Some("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"),
        }
    }
    fn parse(value: Option<&str>) -> Self {
        match value.unwrap_or("devnet").to_lowercase().as_str() {
            "mainnet" | "mainnet-beta" => Network::Mainnet,
            "localnet" => Network::Localnet,
            _ => Network::Devnet,
        }
    }
}

const DEFAULT_RPC_TIMEOUT_SECS: u64 = 10;
const DEFAULT_RPC_POOL_MAX_IDLE: usize = 32;

/// HTTP transport settings shared by the primary and fallback RPC clients.
#[derive(Debug, Clone, PartialEq)]
struct RpcSettings {
    timeout: Duration,
    pool_max_idle_per_host: usize,
}

impl Default for RpcSettings {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_RPC_TIMEOUT_SECS),
            pool_max_idle_per_host: DEFAULT_RPC_POOL_MAX_IDLE,
        }
    }
}

/// Runtime configuration read from the environment (except the signing key
/// and USDC mint, which are `expect()`-ed in `main`).
#[derive(Debug, Clone, PartialEq)]
struct Config {
    network: Network,
    rpc_url: String,
    fallback_url: Option<String>,
    rpc: RpcSettings,
    skip_fund_checks: bool,
    rate_limit: bool,
    cors_enabled: bool,
    cors_max_age: usize,
    port: String,
}

/// `true`/`1` (case-insensitive) enables; anything else, or unset, disables.
fn flag_on(value: Option<&str>) -> bool {
    value
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

/// `false`/`0` (case-insensitive) disables; anything else, or unset, enables.
fn flag_not_off(value: Option<&str>) -> bool {
    value
        .map(|v| {
            let v = v.to_lowercase();
            !(v == "false" || v == "0")
        })
        .unwrap_or(true)
}

/// Parse a strictly positive integer, falling back to `default` (with a warning)
/// when the value is missing, malformed or zero.
fn positive_or<T>(name: &str, value: Option<&str>, default: T) -> T
where
    T: FromStr + PartialEq + Default + std::fmt::Display + Copy,
{
    match value {
        None => default,
        Some(raw) => match raw.trim().parse::<T>() {
            Ok(v) if v != T::default() => v,
            _ => {
                log::warn!("Invalid {name}={raw:?}, using default {default}");
                default
            }
        },
    }
}

/// The fallback is the network's public RPC, used only when a custom
/// `SOLANA_RPC_URL` is configured and differs from it. Localnet never falls back.
fn resolve_fallback(network: &Network, custom_url: Option<&str>, enabled: bool) -> Option<String> {
    let custom = custom_url?;
    let default = network.rpc_url();
    if !enabled
        || *network == Network::Localnet
        || custom.trim_end_matches('/') == default.trim_end_matches('/')
    {
        return None;
    }
    Some(default.to_string())
}

impl Config {
    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let network = Network::parse(get("SOLANA_NETWORK").as_deref());
        let custom_url = get("SOLANA_RPC_URL");
        let rpc_url = custom_url
            .clone()
            .unwrap_or_else(|| network.rpc_url().to_string());
        let fallback_url = resolve_fallback(
            &network,
            custom_url.as_deref(),
            flag_not_off(get("SOLANA_RPC_FALLBACK").as_deref()),
        );
        let rpc = RpcSettings {
            timeout: Duration::from_secs(positive_or(
                "SOLANA_RPC_TIMEOUT_SECS",
                get("SOLANA_RPC_TIMEOUT_SECS").as_deref(),
                DEFAULT_RPC_TIMEOUT_SECS,
            )),
            pool_max_idle_per_host: positive_or(
                "SOLANA_RPC_POOL_MAX_IDLE",
                get("SOLANA_RPC_POOL_MAX_IDLE").as_deref(),
                DEFAULT_RPC_POOL_MAX_IDLE,
            ),
        };
        Self {
            network,
            rpc_url,
            fallback_url,
            rpc,
            skip_fund_checks: flag_on(get("SKIP_FUND_CHECKS").as_deref()),
            rate_limit: flag_on(get("RATE_LIMIT").as_deref()),
            // CORS: permissive by default (any origin/method/header). Set CORS=false to disable.
            cors_enabled: flag_not_off(get("CORS").as_deref()),
            cors_max_age: get("CORS_MAX_AGE")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            port: get("PORT").unwrap_or_else(|| "8080".into()),
        }
    }
}

/// Keep only `scheme://host[:port]` so provider API keys carried in the path,
/// query string or userinfo never reach the logs.
fn redact_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, url),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    match scheme {
        Some(s) => format!("{s}://{host}"),
        None => host.to_string(),
    }
}

/// Replace every occurrence of `url` in `msg` with its redacted form
/// (reqwest errors embed the full request URL).
fn sanitize(msg: &str, url: &str) -> String {
    let redacted = redact_url(url);
    let mut out = msg.replace(url, &redacted);
    let trimmed = url.trim_end_matches('/');
    if !trimmed.is_empty() && trimmed != url {
        out = out.replace(trimmed, &redacted);
    }
    out
}

/// Build an RPC client with an explicit request timeout and connection pool.
fn build_rpc_client(url: &str, settings: &RpcSettings) -> RpcClient {
    let http = reqwest::Client::builder()
        .default_headers(HttpSender::default_headers())
        .timeout(settings.timeout)
        .connect_timeout(settings.timeout.min(Duration::from_secs(5)))
        .pool_max_idle_per_host(settings.pool_max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(60))
        .build()
        .expect("failed to build reqwest client for Solana RPC");
    RpcClient::new_sender(
        HttpSender::new_with_client(url, http),
        RpcClientConfig::with_commitment(CommitmentConfig::confirmed()),
    )
}

/// Decide whether the fallback may be used, given the primary's genesis hash.
/// A primary on another chain than `network` would make the fallback read
/// balances from the wrong cluster, so the fallback is disabled in that case.
/// If the primary cannot be reached at startup the check is inconclusive and
/// the fallback stays enabled.
fn fallback_allowed(network: &Network, primary_genesis: Result<Hash, String>) -> bool {
    let Some(expected) = network.genesis_hash() else {
        return false;
    };
    match primary_genesis {
        Ok(hash) if hash.to_string() == expected => true,
        Ok(hash) => {
            log::error!(
                "SOLANA_RPC_URL genesis hash {hash} does not match {network:?} ({expected}); \
                 RPC fallback disabled. Check SOLANA_NETWORK."
            );
            false
        }
        Err(e) => {
            log::warn!(
                "Could not verify SOLANA_RPC_URL genesis hash ({e}); keeping RPC fallback enabled"
            );
            true
        }
    }
}

/// Primary RPC client with an optional single-retry fallback (primary → fallback → error).
struct SolanaRpc {
    primary: RpcClient,
    primary_url: String,
    fallback: Option<(RpcClient, String)>,
}

impl SolanaRpc {
    fn new(primary_url: &str, fallback_url: Option<&str>, settings: &RpcSettings) -> Self {
        Self {
            primary: build_rpc_client(primary_url, settings),
            primary_url: primary_url.to_string(),
            fallback: fallback_url.map(|u| (build_rpc_client(u, settings), u.to_string())),
        }
    }

    /// Like `new`, but first checks that the primary serves the configured
    /// network before enabling the fallback.
    async fn connect(
        network: &Network,
        primary_url: &str,
        fallback_url: Option<&str>,
        settings: &RpcSettings,
    ) -> Self {
        let mut rpc = Self::new(primary_url, fallback_url, settings);
        if let Some((_, fb_url)) = &rpc.fallback {
            let genesis = rpc
                .primary
                .get_genesis_hash()
                .await
                .map_err(|e| sanitize(&e.to_string(), &rpc.primary_url));
            if fallback_allowed(network, genesis) {
                log::info!(
                    "RPC primary {} with fallback {}",
                    redact_url(&rpc.primary_url),
                    redact_url(fb_url)
                );
            } else {
                rpc.fallback = None;
            }
        }
        rpc
    }

    async fn call<'s, T, F, Fut>(&'s self, op: &str, f: F) -> anyhow::Result<T>
    where
        F: Fn(&'s RpcClient) -> Fut,
        Fut: Future<Output = ClientResult<T>>,
    {
        let primary_err = match f(&self.primary).await {
            Ok(v) => return Ok(v),
            Err(e) => sanitize(&e.to_string(), &self.primary_url),
        };
        let primary = redact_url(&self.primary_url);
        let Some((fallback, fb_url)) = &self.fallback else {
            return Err(anyhow!("{op} failed on {primary}: {primary_err}"));
        };
        let fb = redact_url(fb_url);
        log::warn!(
            "RPC primary {primary} failed for {op}: {primary_err}; retrying on fallback {fb}"
        );
        match f(fallback).await {
            Ok(v) => {
                log::info!("{op} served by fallback RPC {fb}");
                Ok(v)
            }
            Err(e) => Err(anyhow!(
                "{op} failed on primary {primary} ({primary_err}) and fallback {fb} ({})",
                sanitize(&e.to_string(), fb_url)
            )),
        }
    }

    async fn get_multiple_accounts(
        &self,
        keys: &[Pubkey],
    ) -> anyhow::Result<Vec<Option<solana_sdk::account::Account>>> {
        self.call("get_multiple_accounts", |c| c.get_multiple_accounts(keys))
            .await
    }

    async fn get_version(&self) -> anyhow::Result<()> {
        self.call("get_version", |c| c.get_version())
            .await
            .map(|_| ())
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
    service_pubkey: String,  // base58
    commit_hash: String,     // hex
    liquidity_proof: String, // hex
    network: String,
    skip_fund_checks: bool,
    timestamp: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

struct AppState {
    rpc: Arc<SolanaRpc>,
    service_keypair: Arc<Keypair>,
    network_str: String,
    usdc_mint: Pubkey,
    skip_fund_checks: bool,
}

/// Derive the Associated Token Account address (same logic as spl_associated_token_account).
fn get_ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    let spl_token = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let ata_program = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
    let (ata, _bump) = Pubkey::find_program_address(
        &[owner.as_ref(), spl_token.as_ref(), mint.as_ref()],
        &ata_program,
    );
    ata
}

/// Parse the token amount from raw SPL Token account data (offset 64, 8 bytes LE u64).
/// Returns 0 if the account doesn't exist.
fn parse_token_amount(account: &Option<solana_sdk::account::Account>) -> u64 {
    match account {
        Some(acc) if acc.data.len() >= 72 => {
            u64::from_le_bytes(acc.data[64..72].try_into().unwrap())
        }
        _ => 0,
    }
}

/// Fetch both token balances in a single RPC call.
async fn get_token_balances(
    rpc: &SolanaRpc,
    owner: &Pubkey,
    mint_a: &Pubkey,
    mint_b: &Pubkey,
) -> anyhow::Result<(u64, u64)> {
    let ata_a = get_ata(owner, mint_a);
    let ata_b = get_ata(owner, mint_b);
    let accounts = rpc
        .get_multiple_accounts(&[ata_a, ata_b])
        .await
        .map_err(|e| {
            anyhow!(
                "get_multiple_accounts failed (owner: {}, mints: {}, {}): {e}",
                owner,
                mint_a,
                mint_b
            )
        })?;
    Ok((
        parse_token_amount(&accounts[0]),
        parse_token_amount(&accounts[1]),
    ))
}

/// Protocol fee uplift (floor division + min 1 when taker_fee_bps > 0).
/// Returns `(uplift, quote_amount + uplift)`.
fn compute_uplift(quote_amount: u64, taker_fee_bps: u16) -> Result<(u64, u64), String> {
    let uplift: u64 = if taker_fee_bps > 0 {
        let fee = (quote_amount as u128)
            .checked_mul(taker_fee_bps as u128)
            .ok_or_else(|| {
                format!("Overflow computing fee: quote_amount={quote_amount} * taker_fee_bps={taker_fee_bps}")
            })?
            .checked_div(10_000)
            .ok_or_else(|| "Unexpected division error in fee computation".to_string())?;
        let fee = u64::try_from(fee)
            .map_err(|_| format!("Fee uplift {fee} exceeds maximum u64 value"))?;
        if fee == 0 {
            1
        } else {
            fee
        }
    } else {
        0
    };
    let required_quote = quote_amount.checked_add(uplift).ok_or_else(|| {
        format!("Overflow computing required quote: quote_amount={quote_amount} + uplift={uplift}")
    })?;
    Ok((uplift, required_quote))
}

/// Commit hash over the 178-byte pre-image (64+32+32+32+8+8+2).
/// Must stay byte-identical to the on-chain verifier in settlement-engine.
fn commit_hash(
    salt: &[u8; 64],
    rfq: &Pubkey,
    taker: &Pubkey,
    quote_mint: &Pubkey,
    quote_amount: u64,
    bond_amount: u64,
    taker_fee_bps: u16,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt); // 64 bytes
    hasher.update(rfq.as_ref()); // 32 bytes
    hasher.update(taker.as_ref()); // 32 bytes
    hasher.update(quote_mint.as_ref()); // 32 bytes
    hasher.update(quote_amount.to_le_bytes()); // 8 bytes
    hasher.update(bond_amount.to_le_bytes()); // 8 bytes
    hasher.update(taker_fee_bps.to_le_bytes()); // 2 bytes (u16)
    hasher.finalize().into()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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
    if !salt.verify(taker.as_ref(), rfq.as_ref()) {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: format!(
                "Invalid salt {} for taker {} and rfq {}",
                data.salt, data.taker, data.rfq,
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
            error: format!("taker_fee_bps must not exceed 10000 (100%), got {taker_fee_bps}"),
        }));
    }

    let (uplift, required_quote) =
        compute_uplift(quote_amount, taker_fee_bps).map_err(actix_web::error::ErrorBadRequest)?;

    // Liquidity checks: USDC covers bond, quote token covers bid + protocol fees
    if !state.skip_fund_checks {
        let (usdc_balance, quote_balance) =
            get_token_balances(&state.rpc, &taker, &state.usdc_mint, &quote_mint)
                .await
                .map_err(|e| {
                    log::error!("RPC error during liquidity check: {e}");
                    actix_web::error::ErrorInternalServerError("Internal server error")
                })?;

        if usdc_balance < bond_amount {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: format!("Insufficient USDC: has {usdc_balance} needs {bond_amount} (bond)"),
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

    // Salt is exactly 64 bytes here: Signature::try_from rejected any other length.
    let salt_arr: [u8; 64] = salt.into();
    let commit_hash = commit_hash(
        &salt_arr,
        &rfq,
        &taker,
        &quote_mint,
        quote_amount,
        bond_amount,
        taker_fee_bps,
    );

    // Sign with solana_sdk Keypair
    let signature = state.service_keypair.sign_message(&commit_hash);
    let service_pubkey_b58 = state.service_keypair.pubkey().to_string();

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
        timestamp: now_secs(),
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
        skip_fund_checks: bool,
    }
    Ok(HttpResponse::Ok().json(Health {
        status: "healthy",
        network: state.network_str.clone(),
        service_pubkey: state.service_keypair.pubkey().to_string(),
        timestamp: now_secs(),
        skip_fund_checks: state.skip_fund_checks,
    }))
}

async fn ready(state: web::Data<AppState>) -> Result<HttpResponse> {
    #[derive(Serialize)]
    struct Ready {
        status: &'static str,
    }
    match state.rpc.get_version().await {
        Ok(()) => Ok(HttpResponse::Ok().json(Ready { status: "ready" })),
        Err(e) => {
            log::error!("Readiness check failed: {e}");
            Ok(HttpResponse::ServiceUnavailable().json(ErrorResponse {
                error: "Service not ready".to_string(),
            }))
        }
    }
}

type RateLimitConfig = GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>;

/// Per-IP rate limiter: 2 req/s sustained, burst of 5.
fn rate_limit_config() -> RateLimitConfig {
    GovernorConfigBuilder::default()
        .seconds_per_request(2)
        .burst_size(5)
        .finish()
        .expect("invalid governor config")
}

/// Register the JSON body limit and the routes. `/ready` and `/check` are
/// wrapped with the rate limiter when `governor` is set.
fn routes(cfg: &mut web::ServiceConfig, governor: Option<&RateLimitConfig>) {
    cfg.app_data(
        web::JsonConfig::default()
            .limit(1024)
            .error_handler(|err, _req| actix_web::error::ErrorPayloadTooLarge(format!("{err}"))),
    )
    .route("/health", web::get().to(health));

    match governor {
        Some(conf) => {
            cfg.service(
                web::resource("/ready")
                    .wrap(Governor::new(conf))
                    .route(web::get().to(ready)),
            )
            .service(
                web::resource("/check")
                    .wrap(Governor::new(conf))
                    .route(web::post().to(check)),
            );
        }
        None => {
            cfg.route("/ready", web::get().to(ready))
                .route("/check", web::post().to(check));
        }
    }
}

/// Permissive CORS when enabled: any origin/method/header, wildcard response.
/// send_wildcard() emits `Access-Control-Allow-Origin: *` instead of echoing
/// the request Origin; no credentials are allowed (spec forbids * + creds).
/// When disabled, Cors::default() is restrictive (blocks cross-origin), same
/// observable behavior as not wrapping at all.
fn build_cors(enabled: bool, max_age: usize) -> Cors {
    if enabled {
        Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .expose_any_header()
            .send_wildcard()
            .max_age(max_age)
    } else {
        Cors::default()
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let filter = "info,actix_web=info,actix_http=info,actix_server=info";
    env_logger::Builder::from_env(env_logger::Env::default())
        .filter_level(log::LevelFilter::Info)
        .parse_filters(filter)
        .init();

    let config = Config::from_lookup(|k| std::env::var(k).ok());

    // SIGNING_KEY is base58 keypair string
    let keypair_b58 =
        std::env::var("SIGNING_KEY").expect("SIGNING_KEY env var required (base58 Keypair)");
    let service_keypair = Arc::new(Keypair::from_base58_string(&keypair_b58));

    let usdc_mint_str =
        std::env::var("USDC_MINT").expect("USDC_MINT env var is required (base58 Pubkey)");
    let usdc_mint =
        Pubkey::from_str(&usdc_mint_str).expect("USDC_MINT must be a valid base58 Pubkey");

    let rpc = Arc::new(
        SolanaRpc::connect(
            &config.network,
            &config.rpc_url,
            config.fallback_url.as_deref(),
            &config.rpc,
        )
        .await,
    );

    let state = web::Data::new(AppState {
        rpc,
        service_keypair,
        network_str: format!("{:?}", config.network),
        usdc_mint,
        skip_fund_checks: config.skip_fund_checks,
    });

    let bind = format!("0.0.0.0:{}", config.port);

    // Built once so every worker shares the same per-IP quota.
    let governor_conf = config.rate_limit.then(rate_limit_config);
    let cors_enabled = config.cors_enabled;
    let cors_max_age = config.cors_max_age;

    HttpServer::new(move || {
        let cors = build_cors(cors_enabled, cors_max_age);

        App::new()
            // Registration order: the LAST .wrap() is outermost.
            // CORS is inner so it short-circuits OPTIONS preflights before Governor;
            // Logger is outer so every response (including preflights) is logged.
            .wrap(cors)
            .wrap(Logger::new(r#"%a "%r" %s %b %Dms"#))
            .app_data(state.clone())
            .configure(|cfg| routes(cfg, governor_conf.as_ref()))
    })
    .shutdown_timeout(15)
    .bind(&bind)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test as atest};
    use base64::Engine;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    // ---------- mock JSON-RPC server ----------

    #[derive(Clone, Copy)]
    enum Mode {
        Ok,
        Status(u16),
        Delay(u64),
    }

    struct Mock {
        mode: Mutex<Mode>,
        hits: AtomicUsize,
        /// ATA address -> token amount served by getMultipleAccounts.
        balances: Mutex<HashMap<String, u64>>,
        genesis: Mutex<String>,
        /// Distinct client sockets seen, to observe connection pooling.
        peers: Mutex<std::collections::HashSet<std::net::SocketAddr>>,
    }

    impl Mock {
        fn new(mode: Mode) -> Arc<Self> {
            Arc::new(Self {
                mode: Mutex::new(mode),
                hits: AtomicUsize::new(0),
                balances: Mutex::new(HashMap::new()),
                genesis: Mutex::new(Network::Devnet.genesis_hash().unwrap().to_string()),
                peers: Mutex::new(Default::default()),
            })
        }
        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
        fn set_balance(&self, owner: &Pubkey, mint: &Pubkey, amount: u64) {
            self.balances
                .lock()
                .unwrap()
                .insert(get_ata(owner, mint).to_string(), amount);
        }
    }

    fn token_account(amount: u64) -> Value {
        let mut data = vec![0u8; 165];
        data[64..72].copy_from_slice(&amount.to_le_bytes());
        json!({
            "data": [base64::engine::general_purpose::STANDARD.encode(&data), "base64"],
            "executable": false,
            "lamports": 2_039_280u64,
            "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "rentEpoch": 0,
            "space": 165
        })
    }

    async fn mock_rpc(
        req: actix_web::HttpRequest,
        body: web::Json<Value>,
        mock: web::Data<Arc<Mock>>,
    ) -> HttpResponse {
        mock.hits.fetch_add(1, Ordering::SeqCst);
        if let Some(peer) = req.peer_addr() {
            mock.peers.lock().unwrap().insert(peer);
        }
        let mode = *mock.mode.lock().unwrap();
        match mode {
            Mode::Status(code) => {
                return HttpResponse::build(StatusCode::from_u16(code).unwrap()).body("down")
            }
            Mode::Delay(ms) => actix_web::rt::time::sleep(Duration::from_millis(ms)).await,
            Mode::Ok => {}
        }
        let id = body["id"].clone();
        let result = match body["method"].as_str().unwrap_or_default() {
            "getVersion" => json!({"solana-core": "2.3.13", "feature-set": 1}),
            "getGenesisHash" => json!(mock.genesis.lock().unwrap().clone()),
            "getMultipleAccounts" => {
                let balances = mock.balances.lock().unwrap();
                let value: Vec<Value> = body["params"][0]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|k| match balances.get(k.as_str().unwrap()) {
                        Some(amount) => token_account(*amount),
                        None => Value::Null,
                    })
                    .collect();
                json!({"context": {"slot": 1}, "value": value})
            }
            other => panic!("unexpected RPC method {other}"),
        };
        HttpResponse::Ok().json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }

    fn start_mock(mock: Arc<Mock>) -> String {
        let data = web::Data::new(mock);
        let server = HttpServer::new(move || {
            App::new()
                .app_data(data.clone())
                .default_service(web::to(mock_rpc))
        })
        .workers(1)
        .disable_signals()
        .bind(("127.0.0.1", 0))
        .unwrap();
        let addr = server.addrs()[0];
        actix_web::rt::spawn(server.run());
        format!("http://{addr}")
    }

    /// URL of a local port nobody listens on (connection refused).
    fn dead_url() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{addr}")
    }

    fn fast_settings() -> RpcSettings {
        RpcSettings {
            timeout: Duration::from_millis(500),
            pool_max_idle_per_host: 2,
        }
    }

    // ---------- helpers for /check ----------

    struct Fixture {
        taker: Keypair,
        rfq: Pubkey,
        quote_mint: Pubkey,
        usdc_mint: Pubkey,
        service: Arc<Keypair>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                taker: Keypair::new(),
                rfq: Pubkey::new_unique(),
                quote_mint: Pubkey::new_unique(),
                usdc_mint: Pubkey::new_unique(),
                service: Arc::new(Keypair::new()),
            }
        }
        fn salt(&self) -> String {
            hex::encode(self.taker.sign_message(self.rfq.as_ref()).as_ref())
        }
        fn body(&self, quote: u64, bond: u64, bps: &str) -> Value {
            json!({
                "rfq": self.rfq.to_string(),
                "salt": self.salt(),
                "taker": self.taker.pubkey().to_string(),
                "quote_mint": self.quote_mint.to_string(),
                "quote_amount": quote.to_string(),
                "bond_amount_usdc": bond.to_string(),
                "taker_fee_bps": bps,
            })
        }
        fn state(&self, rpc: SolanaRpc, skip_fund_checks: bool) -> web::Data<AppState> {
            web::Data::new(AppState {
                rpc: Arc::new(rpc),
                service_keypair: self.service.clone(),
                network_str: "Devnet".into(),
                usdc_mint: self.usdc_mint,
                skip_fund_checks,
            })
        }
    }

    macro_rules! app {
        ($state:expr) => {
            app!($state, None)
        };
        ($state:expr, $gov:expr) => {
            atest::init_service(
                App::new()
                    .app_data($state.clone())
                    .configure(|cfg| routes(cfg, $gov)),
            )
            .await
        };
    }

    async fn post_check<B: actix_web::body::MessageBody>(
        app: &impl actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
        body: &Value,
    ) -> (StatusCode, String) {
        let req = atest::TestRequest::post()
            .uri("/check")
            .peer_addr("10.0.0.1:1234".parse().unwrap())
            .set_json(body)
            .to_request();
        let resp = atest::call_service(app, req).await;
        let status = resp.status();
        let bytes = atest::read_body(resp).await;
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    // ---------- pure functions ----------

    #[test]
    fn uplift_zero_bps_is_zero() {
        assert_eq!(compute_uplift(1_000, 0), Ok((0, 1_000)));
        assert_eq!(compute_uplift(u64::MAX, 0), Ok((0, u64::MAX)));
    }

    #[test]
    fn uplift_floor_rounds_up_to_one() {
        assert_eq!(compute_uplift(1, 1), Ok((1, 2)));
        assert_eq!(compute_uplift(0, 50), Ok((1, 1)));
        assert_eq!(compute_uplift(199, 50), Ok((1, 200)));
    }

    #[test]
    fn uplift_floor_division() {
        assert_eq!(compute_uplift(100_000_000, 50), Ok((500_000, 100_500_000)));
        assert_eq!(compute_uplift(399, 50), Ok((1, 400)));
        assert_eq!(compute_uplift(400, 50), Ok((2, 402)));
        assert_eq!(compute_uplift(1_000, 10_000), Ok((1_000, 2_000)));
    }

    #[test]
    fn uplift_overflow_on_required_quote() {
        let err = compute_uplift(u64::MAX, 1).unwrap_err();
        assert!(
            err.starts_with("Overflow computing required quote"),
            "{err}"
        );
    }

    /// Known-answer vector shared with unleaktrade/app `commit-hash.test.ts`:
    /// locks the 178-byte pre-image layout verified by settlement-engine.
    #[test]
    fn commit_hash_known_answer() {
        let salt: [u8; 64] = std::array::from_fn(|i| i as u8);
        let rfq = Pubkey::new_from_array([0xaa; 32]);
        let taker = Pubkey::new_from_array([0xbb; 32]);
        let quote_mint = Pubkey::new_from_array([0xcc; 32]);
        let hash = commit_hash(
            &salt,
            &rfq,
            &taker,
            &quote_mint,
            0x1122_3344_5566_7788,
            1,
            0x0102,
        );
        assert_eq!(
            hex::encode(hash),
            "656e5b183aea7915d097e3428d6dd2cd074c0d56359840509d1f64a387ed4588"
        );
    }

    #[test]
    fn commit_hash_matches_manual_preimage() {
        let salt = [7u8; 64];
        let (rfq, taker, mint) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let mut pre = Vec::new();
        pre.extend_from_slice(&salt);
        pre.extend_from_slice(rfq.as_ref());
        pre.extend_from_slice(taker.as_ref());
        pre.extend_from_slice(mint.as_ref());
        pre.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        pre.extend_from_slice(&42u64.to_le_bytes());
        pre.extend_from_slice(&9_999u16.to_le_bytes());
        assert_eq!(pre.len(), 178);
        let expected: [u8; 32] = Sha256::digest(&pre).into();
        assert_eq!(
            commit_hash(&salt, &rfq, &taker, &mint, 0x0102_0304_0506_0708, 42, 9_999),
            expected
        );
    }

    #[test]
    fn ata_derivation_matches_known_address() {
        // Seeds/program must match the ATA program: [owner, token_program, mint].
        let owner = Pubkey::from_str("8GAt381fturbi53tXBKubeKgXAdjKvu4fV7H9sn3z4pZ").unwrap();
        let mint = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let ata = get_ata(&owner, &mint);
        let spl_token = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let ata_program = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let (expected, _) = Pubkey::find_program_address(
            &[owner.as_ref(), spl_token.as_ref(), mint.as_ref()],
            &ata_program,
        );
        assert_eq!(ata, expected);
        assert!(!ata.is_on_curve());
        assert_ne!(ata, get_ata(&owner, &Pubkey::new_unique()));
    }

    #[test]
    fn token_amount_parsing() {
        use solana_sdk::account::Account;
        assert_eq!(parse_token_amount(&None), 0);
        let short = Account {
            data: vec![1; 71],
            ..Account::default()
        };
        assert_eq!(parse_token_amount(&Some(short)), 0);
        let mut data = vec![0u8; 165];
        data[64..72].copy_from_slice(&123_456_789u64.to_le_bytes());
        let acc = Account {
            data,
            ..Account::default()
        };
        assert_eq!(parse_token_amount(&Some(acc)), 123_456_789);
        let exact = Account {
            data: [vec![0u8; 64], u64::MAX.to_le_bytes().to_vec()].concat(),
            ..Account::default()
        };
        assert_eq!(parse_token_amount(&Some(exact)), u64::MAX);
    }

    // ---------- configuration ----------

    fn config(vars: &[(&str, &str)]) -> Config {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn config_defaults() {
        let c = config(&[]);
        assert_eq!(
            c,
            Config {
                network: Network::Devnet,
                rpc_url: "https://api.devnet.solana.com".into(),
                fallback_url: None,
                rpc: RpcSettings::default(),
                skip_fund_checks: false,
                rate_limit: false,
                cors_enabled: true,
                cors_max_age: 3600,
                port: "8080".into(),
            }
        );
        assert_eq!(c.rpc.timeout, Duration::from_secs(10));
        assert_eq!(c.rpc.pool_max_idle_per_host, 32);
    }

    #[test]
    fn network_parsing() {
        assert_eq!(Network::parse(None), Network::Devnet);
        assert_eq!(Network::parse(Some("devnet")), Network::Devnet);
        assert_eq!(Network::parse(Some("MAINNET")), Network::Mainnet);
        assert_eq!(Network::parse(Some("mainnet-beta")), Network::Mainnet);
        assert_eq!(Network::parse(Some("localnet")), Network::Localnet);
        assert_eq!(Network::parse(Some("testnet")), Network::Devnet);
        assert_eq!(Network::Localnet.rpc_url(), "http://127.0.0.1:8899");
        assert_eq!(
            Network::Mainnet.rpc_url(),
            "https://api.mainnet-beta.solana.com"
        );
        assert_eq!(Network::Localnet.genesis_hash(), None);
    }

    #[test]
    fn config_full_override() {
        let c = config(&[
            ("SOLANA_NETWORK", "mainnet"),
            ("SOLANA_RPC_URL", "https://rpc.example.com/?api-key=secret"),
            ("SOLANA_RPC_TIMEOUT_SECS", "7"),
            ("SOLANA_RPC_POOL_MAX_IDLE", "4"),
            ("SKIP_FUND_CHECKS", "TRUE"),
            ("RATE_LIMIT", "1"),
            ("CORS", "0"),
            ("CORS_MAX_AGE", "77"),
            ("PORT", "9000"),
        ]);
        assert_eq!(c.network, Network::Mainnet);
        assert_eq!(c.rpc_url, "https://rpc.example.com/?api-key=secret");
        assert_eq!(
            c.fallback_url.as_deref(),
            Some("https://api.mainnet-beta.solana.com")
        );
        assert_eq!(c.rpc.timeout, Duration::from_secs(7));
        assert_eq!(c.rpc.pool_max_idle_per_host, 4);
        assert!(c.skip_fund_checks && c.rate_limit && !c.cors_enabled);
        assert_eq!(c.cors_max_age, 77);
        assert_eq!(c.port, "9000");
    }

    #[test]
    fn config_invalid_numbers_use_defaults() {
        for bad in ["0", "-1", "abc", ""] {
            let c = config(&[
                ("SOLANA_RPC_TIMEOUT_SECS", bad),
                ("SOLANA_RPC_POOL_MAX_IDLE", bad),
                ("CORS_MAX_AGE", bad),
            ]);
            assert_eq!(c.rpc, RpcSettings::default(), "input {bad:?}");
        }
        // CORS_MAX_AGE keeps its original semantics: any u64-parsable value, else 3600.
        assert_eq!(config(&[("CORS_MAX_AGE", "abc")]).cors_max_age, 3600);
        assert_eq!(config(&[("CORS_MAX_AGE", "0")]).cors_max_age, 0);
        assert_eq!(
            config(&[("SOLANA_RPC_TIMEOUT_SECS", " 3 ")]).rpc.timeout,
            Duration::from_secs(3)
        );
    }

    #[test]
    fn flag_semantics() {
        for (v, on) in [
            ("true", true),
            ("TRUE", true),
            ("1", true),
            ("yes", false),
            ("0", false),
            ("", false),
        ] {
            assert_eq!(flag_on(Some(v)), on, "flag_on({v:?})");
        }
        assert!(!flag_on(None));
        for (v, on) in [
            ("false", false),
            ("FALSE", false),
            ("0", false),
            ("true", true),
            ("no", true),
            ("", true),
        ] {
            assert_eq!(flag_not_off(Some(v)), on, "flag_not_off({v:?})");
        }
        assert!(flag_not_off(None));
    }

    #[test]
    fn fallback_resolution() {
        let custom = Some("https://my-rpc.example.com");
        assert_eq!(resolve_fallback(&Network::Devnet, None, true), None);
        assert_eq!(
            resolve_fallback(&Network::Devnet, custom, true).as_deref(),
            Some("https://api.devnet.solana.com")
        );
        assert_eq!(
            resolve_fallback(&Network::Mainnet, custom, true).as_deref(),
            Some("https://api.mainnet-beta.solana.com")
        );
        assert_eq!(resolve_fallback(&Network::Devnet, custom, false), None);
        assert_eq!(resolve_fallback(&Network::Localnet, custom, true), None);
        // Custom URL equal to the default (docker-compose) → no pointless retry.
        assert_eq!(
            resolve_fallback(
                &Network::Devnet,
                Some("https://api.devnet.solana.com/"),
                true
            ),
            None
        );
        let c = config(&[
            ("SOLANA_RPC_URL", "https://my-rpc.example.com"),
            ("SOLANA_RPC_FALLBACK", "false"),
        ]);
        assert_eq!(c.fallback_url, None);
    }

    #[test]
    fn fallback_allowed_by_genesis() {
        let devnet = Hash::from_str(Network::Devnet.genesis_hash().unwrap()).unwrap();
        let mainnet = Hash::from_str(Network::Mainnet.genesis_hash().unwrap()).unwrap();
        assert!(fallback_allowed(&Network::Devnet, Ok(devnet)));
        assert!(fallback_allowed(&Network::Mainnet, Ok(mainnet)));
        assert!(!fallback_allowed(&Network::Devnet, Ok(mainnet)));
        assert!(!fallback_allowed(&Network::Mainnet, Ok(devnet)));
        assert!(fallback_allowed(
            &Network::Devnet,
            Err("unreachable".into())
        ));
        assert!(!fallback_allowed(&Network::Localnet, Ok(devnet)));
    }

    #[test]
    fn url_redaction() {
        assert_eq!(
            redact_url("https://mainnet.helius-rpc.com/?api-key=SECRET"),
            "https://mainnet.helius-rpc.com"
        );
        assert_eq!(
            redact_url("https://x.solana-mainnet.quiknode.pro/SECRET/"),
            "https://x.solana-mainnet.quiknode.pro"
        );
        assert_eq!(
            redact_url("https://user:SECRET@rpc.example.com:8899/path#frag"),
            "https://rpc.example.com:8899"
        );
        assert_eq!(redact_url("127.0.0.1:8899/x"), "127.0.0.1:8899");
        let url = "https://x.quiknode.pro/SECRET/";
        let msg = format!(
            "error sending request for url ({url}) and ({})",
            "https://x.quiknode.pro/SECRET"
        );
        let clean = sanitize(&msg, url);
        assert!(!clean.contains("SECRET"), "{clean}");
        assert_eq!(sanitize("no url here", "https://a/"), "no url here");
    }

    // ---------- SolanaRpc against a mock server ----------

    #[actix_web::test]
    async fn rpc_primary_ok_never_touches_fallback() {
        let (p, f) = (Mock::new(Mode::Ok), Mock::new(Mode::Ok));
        let rpc = SolanaRpc::new(
            &start_mock(p.clone()),
            Some(&start_mock(f.clone())),
            &fast_settings(),
        );
        rpc.get_version().await.unwrap();
        assert_eq!((p.hits(), f.hits()), (1, 0));
    }

    #[actix_web::test]
    async fn rpc_primary_http_error_retries_once_on_fallback() {
        let (p, f) = (Mock::new(Mode::Status(503)), Mock::new(Mode::Ok));
        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        f.set_balance(&owner, &mint, 55);
        let rpc = SolanaRpc::new(
            &start_mock(p.clone()),
            Some(&start_mock(f.clone())),
            &fast_settings(),
        );
        let accounts = rpc
            .get_multiple_accounts(&[get_ata(&owner, &mint), Pubkey::new_unique()])
            .await
            .unwrap();
        assert_eq!(parse_token_amount(&accounts[0]), 55);
        assert!(accounts[1].is_none());
        assert_eq!((p.hits(), f.hits()), (1, 1));
    }

    #[actix_web::test]
    async fn rpc_primary_timeout_falls_back() {
        let (p, f) = (Mock::new(Mode::Delay(3_000)), Mock::new(Mode::Ok));
        let rpc = SolanaRpc::new(
            &start_mock(p.clone()),
            Some(&start_mock(f.clone())),
            &fast_settings(),
        );
        let started = std::time::Instant::now();
        rpc.get_version().await.unwrap();
        assert!(started.elapsed() < Duration::from_millis(2_500));
        assert_eq!(f.hits(), 1);
    }

    #[actix_web::test]
    async fn rpc_connection_refused_falls_back() {
        let f = Mock::new(Mode::Ok);
        let rpc = SolanaRpc::new(&dead_url(), Some(&start_mock(f.clone())), &fast_settings());
        rpc.get_version().await.unwrap();
        assert_eq!(f.hits(), 1);
    }

    #[actix_web::test]
    async fn rpc_both_fail_reports_both() {
        let (p, f) = (Mock::new(Mode::Status(500)), Mock::new(Mode::Status(502)));
        let (pu, fu) = (start_mock(p.clone()), start_mock(f.clone()));
        let rpc = SolanaRpc::new(&pu, Some(&fu), &fast_settings());
        let err = rpc.get_version().await.unwrap_err().to_string();
        assert!(err.contains(&format!("primary {pu}")), "{err}");
        assert!(err.contains(&format!("fallback {fu}")), "{err}");
        assert_eq!((p.hits(), f.hits()), (1, 1));
    }

    #[actix_web::test]
    async fn rpc_without_fallback_makes_single_attempt() {
        let p = Mock::new(Mode::Status(500));
        let pu = start_mock(p.clone());
        let rpc = SolanaRpc::new(&pu, None, &fast_settings());
        let err = rpc.get_version().await.unwrap_err().to_string();
        assert!(
            err.starts_with(&format!("get_version failed on {pu}")),
            "{err}"
        );
        assert_eq!(p.hits(), 1);
    }

    #[actix_web::test]
    async fn rpc_errors_do_not_leak_url_secrets() {
        let url = format!("{}/SECRET-TOKEN/?api-key=SECRET", dead_url());
        let rpc = SolanaRpc::new(&url, None, &fast_settings());
        let err = rpc.get_version().await.unwrap_err().to_string();
        assert!(!err.contains("SECRET"), "{err}");
    }

    #[actix_web::test]
    async fn rpc_pool_reuses_connections() {
        let p = Mock::new(Mode::Ok);
        let rpc = SolanaRpc::new(&start_mock(p.clone()), None, &fast_settings());
        for _ in 0..5 {
            rpc.get_version().await.unwrap();
        }
        assert_eq!(p.hits(), 5);
        // Sequential calls reuse the single pooled keep-alive connection.
        assert_eq!(p.peers.lock().unwrap().len(), 1);
    }

    #[actix_web::test]
    async fn connect_keeps_fallback_when_genesis_matches() {
        let (p, f) = (Mock::new(Mode::Ok), Mock::new(Mode::Ok));
        let rpc = SolanaRpc::connect(
            &Network::Devnet,
            &start_mock(p.clone()),
            Some(&start_mock(f)),
            &fast_settings(),
        )
        .await;
        assert!(rpc.fallback.is_some());
        assert_eq!(p.hits(), 1);
    }

    #[actix_web::test]
    async fn connect_drops_fallback_on_genesis_mismatch() {
        let (p, f) = (Mock::new(Mode::Ok), Mock::new(Mode::Ok));
        *p.genesis.lock().unwrap() = Network::Mainnet.genesis_hash().unwrap().into();
        let rpc = SolanaRpc::connect(
            &Network::Devnet,
            &start_mock(p),
            Some(&start_mock(f)),
            &fast_settings(),
        )
        .await;
        assert!(rpc.fallback.is_none());
    }

    #[actix_web::test]
    async fn connect_keeps_fallback_when_primary_unreachable() {
        let f = Mock::new(Mode::Ok);
        let rpc = SolanaRpc::connect(
            &Network::Mainnet,
            &dead_url(),
            Some(&start_mock(f)),
            &fast_settings(),
        )
        .await;
        assert!(rpc.fallback.is_some());
    }

    #[actix_web::test]
    async fn connect_without_fallback_skips_genesis_probe() {
        let p = Mock::new(Mode::Ok);
        let rpc = SolanaRpc::connect(
            &Network::Devnet,
            &start_mock(p.clone()),
            None,
            &fast_settings(),
        )
        .await;
        assert!(rpc.fallback.is_none());
        assert_eq!(p.hits(), 0);
    }

    // ---------- HTTP handlers ----------

    #[actix_web::test]
    async fn health_endpoint() {
        let fx = Fixture::new();
        let state = fx.state(SolanaRpc::new(&dead_url(), None, &fast_settings()), true);
        let app = app!(state);
        let resp: Value = atest::call_and_read_body_json(
            &app,
            atest::TestRequest::get().uri("/health").to_request(),
        )
        .await;
        assert_eq!(resp["status"], "healthy");
        assert_eq!(resp["network"], "Devnet");
        assert_eq!(resp["service_pubkey"], fx.service.pubkey().to_string());
        assert_eq!(resp["skip_fund_checks"], true);
        assert!(resp["timestamp"].as_u64().unwrap() > 1_700_000_000);
    }

    async fn ready_status(primary: Mode, fallback: Option<Mode>) -> StatusCode {
        let fx = Fixture::new();
        let fb = fallback.map(|m| start_mock(Mock::new(m)));
        let rpc = SolanaRpc::new(
            &start_mock(Mock::new(primary)),
            fb.as_deref(),
            &fast_settings(),
        );
        let state = fx.state(rpc, false);
        let app = app!(state);
        atest::call_service(&app, atest::TestRequest::get().uri("/ready").to_request())
            .await
            .status()
    }

    #[actix_web::test]
    async fn ready_endpoint() {
        assert_eq!(ready_status(Mode::Ok, None).await, StatusCode::OK);
        assert_eq!(
            ready_status(Mode::Status(500), Some(Mode::Ok)).await,
            StatusCode::OK
        );
        assert_eq!(
            ready_status(Mode::Status(500), Some(Mode::Status(500))).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            ready_status(Mode::Status(500), None).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[actix_web::test]
    async fn check_skip_fund_checks_happy_path() {
        let fx = Fixture::new();
        let rpc_mock = Mock::new(Mode::Ok);
        let state = fx.state(
            SolanaRpc::new(&start_mock(rpc_mock.clone()), None, &fast_settings()),
            true,
        );
        let app = app!(state);
        let body = fx.body(100_000_000, 100_000, "50");
        let (status, text) = post_check(&app, &body).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let resp: Value = serde_json::from_str(&text).unwrap();
        let salt: [u8; 64] = hex::decode(fx.salt()).unwrap().try_into().unwrap();
        let expected = commit_hash(
            &salt,
            &fx.rfq,
            &fx.taker.pubkey(),
            &fx.quote_mint,
            100_000_000,
            100_000,
            50,
        );
        assert_eq!(resp["commit_hash"], hex::encode(expected));
        let sig = Signature::try_from(
            hex::decode(resp["liquidity_proof"].as_str().unwrap())
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        assert!(sig.verify(fx.service.pubkey().as_ref(), &expected));
        assert_eq!(resp["service_pubkey"], fx.service.pubkey().to_string());
        assert_eq!(resp["usdc_mint"], fx.usdc_mint.to_string());
        assert_eq!(resp["skip_fund_checks"], true);
        assert_eq!(resp["network"], "Devnet");
        for k in [
            "rfq",
            "salt",
            "taker",
            "quote_mint",
            "quote_amount",
            "bond_amount_usdc",
            "taker_fee_bps",
        ] {
            assert_eq!(resp[k], body[k], "echoed {k}");
        }
        assert_eq!(rpc_mock.hits(), 0, "no RPC when fund checks are skipped");
    }

    #[actix_web::test]
    async fn check_rejects_bad_input() {
        let fx = Fixture::new();
        let state = fx.state(SolanaRpc::new(&dead_url(), None, &fast_settings()), true);
        let app = app!(state);
        let good = fx.body(1_000, 10, "50");
        let cases: Vec<(&str, Value, &str)> = vec![
            ("rfq", json!("not-a-key"), "Invalid rfq"),
            ("taker", json!("not-a-key"), "Invalid taker"),
            ("quote_mint", json!("xx"), "Invalid quote_mint"),
            ("salt", json!("zz"), "Invalid salt hex format"),
            ("salt", json!("abcd"), "Invalid salt format"),
            ("salt", json!(hex::encode([1u8; 64])), "Invalid salt "),
            ("quote_amount", json!("-1"), "Invalid quote_amount"),
            ("bond_amount_usdc", json!("1.5"), "Invalid bond_amount_usdc"),
            ("taker_fee_bps", json!("70000"), "Invalid taker_fee_bps"),
            ("taker_fee_bps", json!("10001"), "must not exceed 10000"),
        ];
        for (field, value, expected) in cases {
            let mut body = good.clone();
            body[field] = value;
            let (status, text) = post_check(&app, &body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{field}: {text}");
            assert!(text.contains(expected), "{field}: {text}");
        }
        // Salt signed by someone else than the taker.
        let mut body = good.clone();
        body["salt"] = json!(hex::encode(
            Keypair::new().sign_message(fx.rfq.as_ref()).as_ref()
        ));
        let (status, _) = post_check(&app, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Fee overflow is a 400 too.
        let (status, text) = post_check(&app, &fx.body(u64::MAX, 0, "1")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(text.contains("Overflow computing required quote"), "{text}");
    }

    #[actix_web::test]
    async fn check_payload_too_large() {
        let fx = Fixture::new();
        let state = fx.state(SolanaRpc::new(&dead_url(), None, &fast_settings()), true);
        let app = app!(state);
        let mut body = fx.body(1, 1, "0");
        body["padding"] = json!("x".repeat(2048));
        let (status, _) = post_check(&app, &body).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    async fn check_with_balances(
        usdc: Option<u64>,
        quote: Option<u64>,
        primary: Mode,
        fallback: Option<Mode>,
    ) -> (StatusCode, String, usize, usize) {
        let fx = Fixture::new();
        let taker = fx.taker.pubkey();
        let p = Mock::new(primary);
        let f = Mock::new(fallback.unwrap_or(Mode::Ok));
        for m in [&p, &f] {
            if let Some(v) = usdc {
                m.set_balance(&taker, &fx.usdc_mint, v);
            }
            if let Some(v) = quote {
                m.set_balance(&taker, &fx.quote_mint, v);
            }
        }
        let fu = fallback.map(|_| start_mock(f.clone()));
        let state = fx.state(
            SolanaRpc::new(&start_mock(p.clone()), fu.as_deref(), &fast_settings()),
            false,
        );
        let app = app!(state);
        let (status, text) = post_check(&app, &fx.body(1_000, 500, "100")).await;
        (status, text, p.hits(), f.hits())
    }

    #[actix_web::test]
    async fn check_fund_checks() {
        // Required: USDC >= 500, quote >= 1_000 + 10.
        let (s, t, ..) = check_with_balances(Some(500), Some(1_010), Mode::Ok, None).await;
        assert_eq!(s, StatusCode::OK, "{t}");

        let (s, t, ..) = check_with_balances(Some(499), Some(1_010), Mode::Ok, None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(
            t.contains("Insufficient USDC: has 499 needs 500 (bond)"),
            "{t}"
        );

        let (s, t, ..) = check_with_balances(Some(500), Some(1_009), Mode::Ok, None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(
            t.contains("Insufficient quote: has 1009 needs 1010 (quote 1000 + fee 10)"),
            "{t}"
        );

        // Missing accounts count as zero balance.
        let (s, t, ..) = check_with_balances(None, None, Mode::Ok, None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(t.contains("Insufficient USDC: has 0"), "{t}");
    }

    #[actix_web::test]
    async fn check_uses_fallback_when_primary_down() {
        let (s, t, ph, fh) =
            check_with_balances(Some(500), Some(1_010), Mode::Status(500), Some(Mode::Ok)).await;
        assert_eq!(s, StatusCode::OK, "{t}");
        assert_eq!((ph, fh), (1, 1));
    }

    #[actix_web::test]
    async fn check_rpc_down_is_500() {
        let (s, t, ..) = check_with_balances(Some(500), Some(1_010), Mode::Status(500), None).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(t, "Internal server error");
        let (s, ..) = check_with_balances(
            Some(500),
            Some(1_010),
            Mode::Status(500),
            Some(Mode::Status(500)),
        )
        .await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[actix_web::test]
    async fn rate_limit_applies_to_check_and_ready_only() {
        let fx = Fixture::new();
        let state = fx.state(SolanaRpc::new(&dead_url(), None, &fast_settings()), true);
        let gov = rate_limit_config();
        let app = app!(state, Some(&gov));
        let body = fx.body(1, 1, "0");
        for i in 0..5 {
            let (status, text) = post_check(&app, &body).await;
            assert_eq!(status, StatusCode::OK, "request {i}: {text}");
        }
        let (status, _) = post_check(&app, &body).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        // /health is never rate limited.
        for _ in 0..10 {
            let req = atest::TestRequest::get()
                .uri("/health")
                .peer_addr("10.0.0.1:1234".parse().unwrap())
                .to_request();
            assert_eq!(
                atest::call_service(&app, req).await.status(),
                StatusCode::OK
            );
        }
        // /ready shares the per-IP quota.
        let req = atest::TestRequest::get()
            .uri("/ready")
            .peer_addr("10.0.0.1:1234".parse().unwrap())
            .to_request();
        assert_eq!(
            atest::call_service(&app, req).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[actix_web::test]
    async fn cors_preflight_bypasses_rate_limiter() {
        let fx = Fixture::new();
        let state = fx.state(SolanaRpc::new(&dead_url(), None, &fast_settings()), true);
        let gov = rate_limit_config();
        let app = atest::init_service(
            App::new()
                .wrap(build_cors(true, 77))
                .app_data(state.clone())
                .configure(|cfg| routes(cfg, Some(&gov))),
        )
        .await;
        for _ in 0..10 {
            let req = atest::TestRequest::default()
                .method(actix_web::http::Method::OPTIONS)
                .uri("/check")
                .peer_addr("10.0.0.2:1234".parse().unwrap())
                .insert_header(("Origin", "https://app.example.com"))
                .insert_header(("Access-Control-Request-Method", "POST"))
                .to_request();
            let resp = atest::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let h = resp.headers();
            assert_eq!(h.get("access-control-allow-origin").unwrap(), "*");
            assert_eq!(h.get("access-control-max-age").unwrap(), "77");
        }
        // Preflights did not consume the quota: a real request still passes.
        let (status, _) = post_check(&app, &fx.body(1, 1, "0")).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[actix_web::test]
    async fn cors_disabled_sends_no_allow_origin() {
        let fx = Fixture::new();
        let state = fx.state(SolanaRpc::new(&dead_url(), None, &fast_settings()), true);
        let app = atest::init_service(
            App::new()
                .wrap(build_cors(false, 3600))
                .app_data(state.clone())
                .configure(|cfg| routes(cfg, None)),
        )
        .await;
        let req = atest::TestRequest::get()
            .uri("/health")
            .insert_header(("Origin", "https://app.example.com"))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }
}

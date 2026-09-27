use actix_cors::Cors;
use actix_governor::governor::middleware::NoOpMiddleware;
use actix_governor::{Governor, GovernorConfig, GovernorConfigBuilder, PeerIpKeyExtractor};
use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use actix_web::{web, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Result};
use actix_web_prom::{PrometheusMetrics, PrometheusMetricsBuilder};
use anyhow::anyhow;
use prometheus::{Encoder, IntCounterVec, Opts, Registry, TextEncoder};
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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, warn};
use tracing_actix_web::{RequestId, TracingLogger};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

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
    log_format: LogFormat,
    metrics_token: Option<String>,
    api_keys: ApiKeys,
}

/// Shared-secret API keys accepted on `/check` (and `/metrics`). Empty means
/// authentication is disabled. Only the SHA-256 digest of each key is kept:
/// the plaintext never stays in memory or reaches `Debug` output, and a
/// request costs one hash whatever the number of keys.
#[derive(Clone, Default, PartialEq)]
struct ApiKeys(Vec<[u8; 32]>);

impl std::fmt::Debug for ApiKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ApiKeys(<{} redacted>)", self.0.len())
    }
}

impl ApiKeys {
    /// Merge `API_KEYS` (comma-separated) and `API_KEY` (single key): trimmed,
    /// empties dropped, duplicates removed, order preserved.
    fn parse(list: Option<&str>, single: Option<&str>) -> Self {
        let mut digests: Vec<[u8; 32]> = Vec::new();
        for key in list
            .unwrap_or("")
            .split(',')
            .chain(single)
            .map(str::trim)
            .filter(|k| !k.is_empty())
        {
            let digest = Self::digest(key);
            if !digests.contains(&digest) {
                digests.push(digest);
            }
        }
        Self(digests)
    }

    fn digest(key: &str) -> [u8; 32] {
        Sha256::digest(key.as_bytes()).into()
    }

    fn is_enabled(&self) -> bool {
        !self.0.is_empty()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    /// Compare digests in constant time (fixed length, so the key length does
    /// not leak either) and scan every key without early exit.
    fn matches(&self, given: &str) -> bool {
        let given = Self::digest(given);
        self.0
            .iter()
            .fold(false, |found, key| found | constant_time_eq(key, &given))
    }
}

/// Log output format: JSON lines (default, for log aggregation) or
/// human-readable (`LOG_FORMAT=pretty`, for local development).
#[derive(Debug, Clone, Copy, PartialEq)]
enum LogFormat {
    Json,
    Pretty,
}

impl LogFormat {
    fn parse(value: Option<&str>) -> Self {
        match value.map(|v| v.trim().to_lowercase()).as_deref() {
            Some("pretty") | Some("text") => LogFormat::Pretty,
            _ => LogFormat::Json,
        }
    }
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
                warn!("Invalid {name}={raw:?}, using default {default}");
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
            log_format: LogFormat::parse(get("LOG_FORMAT").as_deref()),
            metrics_token: get("METRICS_TOKEN")
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty()),
            api_keys: ApiKeys::parse(get("API_KEYS").as_deref(), get("API_KEY").as_deref()),
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
            error!(
                "SOLANA_RPC_URL genesis hash {hash} does not match {network:?} ({expected}); \
                 RPC fallback disabled. Check SOLANA_NETWORK."
            );
            false
        }
        Err(e) => {
            warn!(
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
    /// `rpc_requests_total{op, target, outcome}`, when metrics are enabled.
    metrics: Option<IntCounterVec>,
}

impl SolanaRpc {
    fn new(primary_url: &str, fallback_url: Option<&str>, settings: &RpcSettings) -> Self {
        Self {
            primary: build_rpc_client(primary_url, settings),
            primary_url: primary_url.to_string(),
            fallback: fallback_url.map(|u| (build_rpc_client(u, settings), u.to_string())),
            metrics: None,
        }
    }

    fn with_metrics(mut self, counter: IntCounterVec) -> Self {
        self.metrics = Some(counter);
        self
    }

    fn record(&self, op: &str, target: &str, ok: bool) {
        if let Some(m) = &self.metrics {
            m.with_label_values(&[op, target, if ok { "ok" } else { "error" }])
                .inc();
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
                info!(
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
            Ok(v) => {
                self.record(op, "primary", true);
                return Ok(v);
            }
            Err(e) => {
                self.record(op, "primary", false);
                sanitize(&e.to_string(), &self.primary_url)
            }
        };
        let primary = redact_url(&self.primary_url);
        let Some((fallback, fb_url)) = &self.fallback else {
            return Err(anyhow!("{op} failed on {primary}: {primary_err}"));
        };
        let fb = redact_url(fb_url);
        warn!(
            op,
            primary = %primary,
            fallback = %fb,
            "RPC primary {primary} failed for {op}: {primary_err}; retrying on fallback {fb}"
        );
        match f(fallback).await {
            Ok(v) => {
                self.record(op, "fallback", true);
                info!(op, fallback = %fb, "{op} served by fallback RPC {fb}");
                Ok(v)
            }
            Err(e) => {
                self.record(op, "fallback", false);
                Err(anyhow!(
                    "{op} failed on primary {primary} ({primary_err}) and fallback {fb} ({})",
                    sanitize(&e.to_string(), fb_url)
                ))
            }
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
    api_keys: Arc<ApiKeys>,
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
                    error!("RPC error during liquidity check: {e}");
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
            error!("Readiness check failed: {e}");
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

/// Register the JSON body limit and the routes. `/check` requires an API key
/// (when `API_KEYS` is set); `/ready` and `/check` are wrapped with the rate
/// limiter when `governor` is set. The Governor is the outer wrap, so it runs
/// before the key check and also throttles key guessing.
fn routes(cfg: &mut web::ServiceConfig, governor: Option<&RateLimitConfig>) {
    cfg.app_data(
        web::JsonConfig::default()
            .limit(1024)
            .error_handler(|err, _req| actix_web::error::ErrorPayloadTooLarge(format!("{err}"))),
    )
    .route("/health", web::get().to(health))
    .route("/metrics", web::get().to(metrics_handler));

    let check = web::resource("/check")
        .wrap(actix_web::middleware::from_fn(require_api_key))
        .route(web::post().to(check));
    match governor {
        Some(conf) => {
            cfg.service(
                web::resource("/ready")
                    .wrap(Governor::new(conf))
                    .route(web::get().to(ready)),
            )
            .service(check.wrap(Governor::new(conf)));
        }
        None => {
            cfg.route("/ready", web::get().to(ready)).service(check);
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

/// Histogram buckets (seconds) for HTTP latency: from cached/static answers
/// up to the worst-case RPC path (primary timeout + fallback timeout).
const LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0,
];

/// Prometheus middleware (request count + latency histogram by endpoint,
/// method and status) and the RPC counter, sharing one registry.
///
/// `/metrics` is served by our own handler (see `metrics_handler`) so it can
/// be token-protected, and is excluded from the HTTP metrics. Unmatched paths
/// are recorded as `UNKNOWN` to keep label cardinality bounded.
fn build_metrics() -> (PrometheusMetrics, IntCounterVec) {
    let prometheus = PrometheusMetricsBuilder::new("liquidity_guard")
        .registry(Registry::new())
        .buckets(LATENCY_BUCKETS)
        .exclude("/metrics")
        .mask_unmatched_patterns("UNKNOWN")
        .build()
        .expect("failed to build Prometheus metrics");
    let rpc_requests = IntCounterVec::new(
        Opts::new(
            "rpc_requests_total",
            "Solana RPC calls by operation, target (primary/fallback) and outcome",
        )
        .namespace("liquidity_guard"),
        &["op", "target", "outcome"],
    )
    .expect("invalid rpc_requests_total metric");
    // Pre-create every series at 0 so dashboards and rate() see them before
    // the first failure.
    for op in ["get_multiple_accounts", "get_version"] {
        for target in ["primary", "fallback"] {
            for outcome in ["ok", "error"] {
                rpc_requests.with_label_values(&[op, target, outcome]);
            }
        }
    }
    prometheus
        .registry
        .register(Box::new(rpc_requests.clone()))
        .expect("failed to register rpc_requests_total");
    (prometheus, rpc_requests)
}

/// Registry exposed on `/metrics`, with the optional bearer token. API keys
/// are also accepted there.
#[derive(Clone)]
struct MetricsState {
    registry: Registry,
    token: Option<String>,
    api_keys: Arc<ApiKeys>,
}

/// Constant-time byte comparison, so the token check does not leak a prefix
/// match through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

static X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");

/// The credential a client presented: `X-API-Key: <key>` first, else
/// `Authorization: Bearer <key>` (scheme is case-sensitive).
fn presented_key(headers: &actix_web::http::header::HeaderMap) -> Option<&str> {
    let header = |name: &HeaderName| headers.get(name).and_then(|v| v.to_str().ok());
    header(&X_API_KEY)
        .or_else(|| header(&AUTHORIZATION).and_then(|v| v.strip_prefix("Bearer ")))
        .map(str::trim)
        .filter(|k| !k.is_empty())
}

/// `/metrics` is open when neither `METRICS_TOKEN` nor `API_KEYS` is set;
/// otherwise either credential grants access.
fn metrics_authorized(req: &HttpRequest, state: &MetricsState) -> bool {
    if state.token.is_none() && !state.api_keys.is_enabled() {
        return true;
    }
    presented_key(req.headers()).is_some_and(|given| {
        let token_ok = state.token.as_deref().is_some_and(|t| {
            constant_time_eq(
                &Sha256::digest(given.as_bytes()),
                &Sha256::digest(t.as_bytes()),
            )
        });
        token_ok | state.api_keys.matches(given)
    })
}

fn unauthorized() -> HttpResponse {
    HttpResponse::Unauthorized()
        .insert_header(("WWW-Authenticate", "Bearer"))
        .json(ErrorResponse {
            error: "Unauthorized".to_string(),
        })
}

/// Route middleware for `/check`: rejects the request with 401 before the
/// body is parsed unless it carries a valid API key. A no-op when `API_KEYS`
/// is unset. Missing and invalid keys get the same response; only the log
/// line says which (never the key itself).
async fn require_api_key(
    req: ServiceRequest,
    next: actix_web::middleware::Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<actix_web::body::EitherBody<impl MessageBody>>, actix_web::Error> {
    let keys = req
        .app_data::<web::Data<AppState>>()
        .map(|s| s.api_keys.clone())
        // Fail closed if the state is missing.
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("missing app state"))?;
    if keys.is_enabled() {
        let reason = match presented_key(req.headers()) {
            None => Some("missing"),
            Some(k) if !keys.matches(k) => Some("invalid"),
            Some(_) => None,
        };
        if let Some(reason) = reason {
            warn!(reason, path = req.path(), "API key rejected");
            return Ok(req.into_response(unauthorized()).map_into_right_body());
        }
    }
    Ok(next.call(req).await?.map_into_left_body())
}

async fn metrics_handler(req: HttpRequest, state: web::Data<MetricsState>) -> HttpResponse {
    if !metrics_authorized(&req, &state) {
        return unauthorized();
    }
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&state.registry.gather(), &mut buffer) {
        error!("Failed to encode metrics: {e}");
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok()
        .insert_header((CONTENT_TYPE, encoder.format_type()))
        .body(buffer)
}

/// Build the global subscriber: `RUST_LOG`-style filter (default `info`) and
/// JSON lines or pretty output, written to `writer`.
fn build_subscriber<W>(
    format: LogFormat,
    filter: &str,
    writer: W,
) -> Box<dyn tracing::Subscriber + Send + Sync>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(writer);
    match format {
        LogFormat::Json => Box::new(
            builder
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(false)
                .finish(),
        ),
        LogFormat::Pretty => Box::new(builder.finish()),
    }
}

static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Runs inside the `TracingLogger` span: emits one structured line per
/// request (request id, method, path, status, duration) and returns the
/// request id to the client in `X-Request-Id`.
async fn log_request(
    req: ServiceRequest,
    next: actix_web::middleware::Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    let started = Instant::now();
    let method = req.method().to_string();
    let path = req.path().to_string();
    let request_id = req.extensions().get::<RequestId>().map(|id| id.to_string());
    let outcome = next.call(req).await;
    let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
    let status = match &outcome {
        Ok(res) => res.status().as_u16(),
        Err(e) => e.as_response_error().status_code().as_u16(),
    };
    let rid = request_id.as_deref().unwrap_or("");
    if status >= 500 {
        error!(
            request_id = rid,
            method, path, status, duration_ms, "request completed"
        );
    } else if status >= 400 {
        warn!(
            request_id = rid,
            method, path, status, duration_ms, "request completed"
        );
    } else {
        info!(
            request_id = rid,
            method, path, status, duration_ms, "request completed"
        );
    }
    let mut res = outcome?;
    if let Some(value) = request_id.and_then(|id| HeaderValue::from_str(&id).ok()) {
        res.headers_mut().insert(X_REQUEST_ID.clone(), value);
    }
    Ok(res)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = Config::from_lookup(|k| std::env::var(k).ok());

    // Also bridges `log` records from dependencies (actix, solana, reqwest).
    use tracing_subscriber::util::SubscriberInitExt;
    build_subscriber(
        config.log_format,
        &std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        std::io::stdout,
    )
    .try_init()
    .expect("failed to install tracing subscriber");

    let (prometheus, rpc_requests) = build_metrics();
    let api_keys = Arc::new(config.api_keys.clone());
    if api_keys.is_enabled() {
        info!(
            keys = api_keys.len(),
            "API key authentication enabled on /check"
        );
    } else {
        warn!("API_KEYS is not set: /check is unauthenticated");
    }
    let metrics_state = web::Data::new(MetricsState {
        registry: prometheus.registry.clone(),
        token: config.metrics_token.clone(),
        api_keys: api_keys.clone(),
    });
    if config.metrics_token.is_none() && !api_keys.is_enabled() {
        warn!("METRICS_TOKEN and API_KEYS are not set: /metrics is publicly readable");
    }

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
        .await
        .with_metrics(rpc_requests),
    );

    let state = web::Data::new(AppState {
        rpc,
        service_keypair,
        network_str: format!("{:?}", config.network),
        usdc_mint,
        skip_fund_checks: config.skip_fund_checks,
        api_keys,
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
            // the request logger and TracingLogger (request id span) sit outside it
            // so every response, preflights included, is logged; Prometheus is
            // outermost so it times and counts everything.
            .wrap(cors)
            .wrap(actix_web::middleware::from_fn(log_request))
            .wrap(TracingLogger::default())
            .wrap(prometheus.clone())
            .app_data(state.clone())
            .app_data(metrics_state.clone())
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
                api_keys: Arc::new(ApiKeys::default()),
            })
        }
        fn state_with_keys(
            &self,
            rpc: SolanaRpc,
            skip_fund_checks: bool,
            keys: &[&str],
        ) -> web::Data<AppState> {
            web::Data::new(AppState {
                rpc: Arc::new(rpc),
                service_keypair: self.service.clone(),
                network_str: "Devnet".into(),
                usdc_mint: self.usdc_mint,
                skip_fund_checks,
                api_keys: Arc::new(test_keys(keys)),
            })
        }
    }

    fn test_keys(keys: &[&str]) -> ApiKeys {
        ApiKeys::parse(Some(&keys.join(",")), None)
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
        post_check_with(app, body, &[]).await
    }

    async fn post_check_with<B: actix_web::body::MessageBody>(
        app: &impl actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
        body: &Value,
        headers: &[(&str, &str)],
    ) -> (StatusCode, String) {
        let mut req = atest::TestRequest::post()
            .uri("/check")
            .peer_addr("10.0.0.1:1234".parse().unwrap())
            .set_json(body);
        for (k, v) in headers {
            req = req.insert_header((*k, *v));
        }
        let req = req.to_request();
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
                log_format: LogFormat::Json,
                metrics_token: None,
                api_keys: ApiKeys::default(),
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

    // ---------- observability ----------

    #[test]
    fn log_format_and_metrics_token_config() {
        assert_eq!(LogFormat::parse(None), LogFormat::Json);
        assert_eq!(LogFormat::parse(Some("json")), LogFormat::Json);
        assert_eq!(LogFormat::parse(Some(" Pretty ")), LogFormat::Pretty);
        assert_eq!(LogFormat::parse(Some("text")), LogFormat::Pretty);
        assert_eq!(LogFormat::parse(Some("xml")), LogFormat::Json);
        let c = config(&[("LOG_FORMAT", "pretty"), ("METRICS_TOKEN", " s3cret ")]);
        assert_eq!(c.log_format, LogFormat::Pretty);
        assert_eq!(c.metrics_token.as_deref(), Some("s3cret"));
        assert_eq!(config(&[("METRICS_TOKEN", "  ")]).metrics_token, None);
    }

    #[test]
    fn constant_time_eq_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    /// Shared in-memory log sink for `MakeWriter`.
    #[derive(Clone, Default)]
    struct LogBuf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for LogBuf {
        type Writer = LogBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl LogBuf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
        fn json_lines(&self) -> Vec<Value> {
            self.text()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
                .collect()
        }
    }

    thread_local! {
        static CAPTURE: std::cell::RefCell<Option<LogBuf>> = const { std::cell::RefCell::new(None) };
    }

    /// Writer for the process-wide test subscriber: appends to the calling
    /// thread's capture buffer, or discards when the thread captures nothing.
    struct ThreadCapture;

    impl<'a> MakeWriter<'a> for ThreadCapture {
        type Writer = Box<dyn std::io::Write>;
        fn make_writer(&'a self) -> Self::Writer {
            match CAPTURE.with(|c| c.borrow().clone()) {
                Some(buf) => Box::new(buf),
                None => Box::new(std::io::sink()),
            }
        }
    }

    struct CaptureGuard;

    impl Drop for CaptureGuard {
        fn drop(&mut self) {
            CAPTURE.with(|c| c.borrow_mut().take());
        }
    }

    /// Capture this test thread's JSON logs (`info` filter) in memory.
    ///
    /// Tests run in parallel, and `tracing` keeps callsite interest and the max
    /// level in process-wide caches that are recomputed whenever a scoped
    /// (`set_default`) subscriber comes or goes on another thread, which
    /// intermittently dropped events. One global subscriber that is never
    /// replaced, routing each thread's output to its own buffer, avoids that.
    fn capture_json_logs() -> (LogBuf, CaptureGuard) {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            tracing::subscriber::set_global_default(build_subscriber(
                LogFormat::Json,
                "info",
                ThreadCapture,
            ))
            .expect("global test subscriber");
        });
        let buf = LogBuf::default();
        CAPTURE.with(|c| *c.borrow_mut() = Some(buf.clone()));
        (buf, CaptureGuard)
    }

    struct Observed {
        metrics: web::Data<MetricsState>,
        prometheus: PrometheusMetrics,
        rpc_requests: IntCounterVec,
    }

    fn observed(token: Option<&str>) -> Observed {
        observed_with_keys(token, &[])
    }

    fn observed_with_keys(token: Option<&str>, keys: &[&str]) -> Observed {
        let (prometheus, rpc_requests) = build_metrics();
        Observed {
            metrics: web::Data::new(MetricsState {
                registry: prometheus.registry.clone(),
                token: token.map(String::from),
                api_keys: Arc::new(test_keys(keys)),
            }),
            prometheus,
            rpc_requests,
        }
    }

    /// Full middleware stack as in `main`.
    macro_rules! full_app {
        ($state:expr, $obs:expr, $gov:expr) => {
            atest::init_service(
                App::new()
                    .wrap(build_cors(true, 3600))
                    .wrap(actix_web::middleware::from_fn(log_request))
                    .wrap(TracingLogger::default())
                    .wrap($obs.prometheus.clone())
                    .app_data($state.clone())
                    .app_data($obs.metrics.clone())
                    .configure(|cfg| routes(cfg, $gov)),
            )
            .await
        };
    }

    async fn scrape<B: actix_web::body::MessageBody>(
        app: &impl actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
        auth: Option<&str>,
    ) -> (StatusCode, String) {
        let mut req = atest::TestRequest::get().uri("/metrics");
        if let Some(a) = auth {
            req = req.insert_header((AUTHORIZATION, a));
        }
        let resp = atest::call_service(app, req.to_request()).await;
        let status = resp.status();
        let body = atest::read_body(resp).await;
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    fn metric_value(body: &str, prefix: &str) -> Option<f64> {
        body.lines()
            .find(|l| l.starts_with(prefix))
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse().ok())
    }

    #[actix_web::test]
    async fn metrics_count_requests_by_endpoint_method_status() {
        let fx = Fixture::new();
        let obs = observed(None);
        let state = fx.state(SolanaRpc::new(&dead_url(), None, &fast_settings()), true);
        let app = full_app!(state, obs, None);

        let (s, _) = post_check(&app, &fx.body(1_000, 1, "50")).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = post_check(&app, &fx.body(1_000, 1, "20000")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        for _ in 0..2 {
            let req = atest::TestRequest::get().uri("/health").to_request();
            atest::call_service(&app, req).await;
        }
        let req = atest::TestRequest::get()
            .uri("/wp-admin/x.php")
            .to_request();
        assert_eq!(
            atest::call_service(&app, req).await.status(),
            StatusCode::NOT_FOUND
        );

        let (status, body) = scrape(&app, None).await;
        assert_eq!(status, StatusCode::OK);
        let total = "liquidity_guard_http_requests_total";
        assert_eq!(
            metric_value(
                &body,
                &format!(r#"{total}{{endpoint="/check",method="POST",status="200"}}"#)
            ),
            Some(1.0),
            "{body}"
        );
        assert_eq!(
            metric_value(
                &body,
                &format!(r#"{total}{{endpoint="/check",method="POST",status="400"}}"#)
            ),
            Some(1.0)
        );
        assert_eq!(
            metric_value(
                &body,
                &format!(r#"{total}{{endpoint="/health",method="GET",status="200"}}"#)
            ),
            Some(2.0)
        );
        // Unmatched paths are masked, never recorded verbatim.
        assert_eq!(
            metric_value(
                &body,
                &format!(r#"{total}{{endpoint="UNKNOWN",method="GET",status="404"}}"#)
            ),
            Some(1.0)
        );
        assert!(!body.contains("wp-admin"));
        // Latency histogram with our buckets.
        let hist = "liquidity_guard_http_requests_duration_seconds";
        assert!(body.contains(&format!(
            r#"{hist}_bucket{{endpoint="/check",method="POST",status="200",le="0.005"}}"#
        )));
        assert!(body.contains(&format!(
            r#"{hist}_bucket{{endpoint="/check",method="POST",status="200",le="30"}}"#
        )));
        assert_eq!(
            metric_value(
                &body,
                &format!(r#"{hist}_count{{endpoint="/check",method="POST",status="200"}}"#)
            ),
            Some(1.0)
        );
        // /metrics does not count itself.
        let (_, body) = scrape(&app, None).await;
        assert!(!body.contains(r#"endpoint="/metrics""#), "{body}");
        assert!(body.contains("# TYPE liquidity_guard_rpc_requests_total counter"));
        assert_eq!(
            metric_value(
                &body,
                r#"liquidity_guard_rpc_requests_total{op="get_version",outcome="error",target="fallback"}"#
            ),
            Some(0.0),
            "series are pre-created at 0"
        );
    }

    #[actix_web::test]
    async fn metrics_record_rate_limit_and_server_errors() {
        let fx = Fixture::new();
        let obs = observed(None);
        let state = fx.state(SolanaRpc::new(&dead_url(), None, &fast_settings()), false);
        let gov = rate_limit_config();
        let app = full_app!(state, obs, Some(&gov));
        let body = fx.body(1, 1, "0");
        for _ in 0..6 {
            post_check(&app, &body).await;
        }
        let (_, metrics) = scrape(&app, None).await;
        let total = "liquidity_guard_http_requests_total";
        assert_eq!(
            metric_value(
                &metrics,
                &format!(r#"{total}{{endpoint="/check",method="POST",status="500"}}"#)
            ),
            Some(5.0),
            "{metrics}"
        );
        assert_eq!(
            metric_value(
                &metrics,
                &format!(r#"{total}{{endpoint="/check",method="POST",status="429"}}"#)
            ),
            Some(1.0)
        );
    }

    #[actix_web::test]
    async fn metrics_token_protects_endpoint() {
        let fx = Fixture::new();
        let obs = observed(Some("s3cret"));
        let state = fx.state(SolanaRpc::new(&dead_url(), None, &fast_settings()), true);
        let app = full_app!(state, obs, None);
        for auth in [
            None,
            Some("Bearer wrong"),
            Some("s3cret"),
            Some("Basic s3cret"),
            Some("Bearer s3cre"),
        ] {
            let (status, body) = scrape(&app, auth).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{auth:?}");
            assert!(
                !body.contains("liquidity_guard_"),
                "{auth:?} leaked metrics"
            );
        }
        let (status, body) = scrape(&app, Some("Bearer s3cret")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("liquidity_guard_rpc_requests_total"));
        // The endpoint is not rate limited, even with the governor on.
        let gov = rate_limit_config();
        let app = full_app!(state, obs, Some(&gov));
        for _ in 0..10 {
            assert_eq!(scrape(&app, Some("Bearer s3cret")).await.0, StatusCode::OK);
        }
    }

    #[actix_web::test]
    async fn rpc_counter_tracks_primary_and_fallback() {
        let (p, f) = (Mock::new(Mode::Ok), Mock::new(Mode::Ok));
        let obs = observed(None);
        let (pu, fu) = (start_mock(p.clone()), start_mock(f.clone()));
        let rpc =
            SolanaRpc::new(&pu, Some(&fu), &fast_settings()).with_metrics(obs.rpc_requests.clone());
        let c = |op: &str, target: &str, outcome: &str| {
            obs.rpc_requests
                .with_label_values(&[op, target, outcome])
                .get()
        };
        rpc.get_version().await.unwrap();
        assert_eq!(c("get_version", "primary", "ok"), 1);

        *p.mode.lock().unwrap() = Mode::Status(500);
        rpc.get_multiple_accounts(&[Pubkey::new_unique()])
            .await
            .unwrap();
        assert_eq!(c("get_multiple_accounts", "primary", "error"), 1);
        assert_eq!(c("get_multiple_accounts", "fallback", "ok"), 1);

        *f.mode.lock().unwrap() = Mode::Status(500);
        rpc.get_version().await.unwrap_err();
        assert_eq!(c("get_version", "primary", "error"), 1);
        assert_eq!(c("get_version", "fallback", "error"), 1);
    }

    #[actix_web::test]
    async fn json_logs_carry_request_fields_and_request_id_header() {
        let (buf, _guard) = capture_json_logs();
        let fx = Fixture::new();
        let obs = observed(None);
        let state = fx.state(SolanaRpc::new(&dead_url(), None, &fast_settings()), true);
        let app = full_app!(state, obs, None);

        let mut ids = Vec::new();
        for _ in 0..2 {
            let req = atest::TestRequest::get().uri("/health?x=1").to_request();
            let resp = atest::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
            ids.push(
                resp.headers()
                    .get("x-request-id")
                    .expect("x-request-id header")
                    .to_str()
                    .unwrap()
                    .to_string(),
            );
        }
        assert_ne!(ids[0], ids[1], "request ids must be unique");
        let (s, _) = post_check(&app, &fx.body(1, 1, "20000")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        let lines = buf.json_lines();
        let done: Vec<&Value> = lines
            .iter()
            .filter(|l| l["message"] == "request completed")
            .collect();
        assert_eq!(done.len(), 3, "{}", buf.text());
        for (line, id) in done.iter().zip(&ids) {
            assert_eq!(line["request_id"], id.as_str());
            assert_eq!(line["method"], "GET");
            assert_eq!(line["path"], "/health");
            assert_eq!(line["status"], 200);
            assert_eq!(line["level"], "INFO");
            assert!(line["duration_ms"].as_f64().unwrap() >= 0.0);
            assert!(line["timestamp"].is_string());
            // Root span from TracingLogger carries the same request id.
            assert_eq!(line["span"]["request_id"], id.as_str());
        }
        assert_eq!(done[2]["status"], 400);
        assert_eq!(done[2]["level"], "WARN");
        assert_eq!(done[2]["path"], "/check");
    }

    #[actix_web::test]
    async fn json_logs_server_errors_and_fallback_warning_are_redacted() {
        let (buf, _guard) = capture_json_logs();
        let fx = Fixture::new();
        let obs = observed(None);
        let primary = format!("{}/SECRET/?api-key=SECRET", dead_url());
        let rpc = SolanaRpc::new(&primary, Some(&dead_url()), &fast_settings());
        let state = fx.state(rpc, false);
        let app = full_app!(state, obs, None);
        let (s, _) = post_check(&app, &fx.body(1, 1, "0")).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);

        let text = buf.text();
        assert!(!text.contains("SECRET"), "{text}");
        let lines = buf.json_lines();
        let fallback = lines
            .iter()
            .find(|l| l["op"] == "get_multiple_accounts" && l["level"] == "WARN")
            .unwrap_or_else(|| panic!("no fallback warning in {text}"));
        assert!(fallback["message"]
            .as_str()
            .unwrap()
            .contains("retrying on fallback"));
        // Events inside a request inherit its request id through the span.
        assert!(fallback["span"]["request_id"].is_string());
        let done = lines
            .iter()
            .find(|l| l["message"] == "request completed")
            .unwrap();
        assert_eq!(done["status"], 500);
        assert_eq!(done["level"], "ERROR");
    }

    #[test]
    fn pretty_logs_and_filter_fallback() {
        let buf = LogBuf::default();
        // An invalid filter falls back to `info`.
        let sub = build_subscriber(LogFormat::Pretty, "=[bad", buf.clone());
        tracing::subscriber::with_default(sub, || {
            info!(answer = 42, "hello pretty");
            tracing::debug!("hidden at info");
        });
        let text = buf.text();
        assert!(
            text.contains("hello pretty") && text.contains("answer=42"),
            "{text}"
        );
        assert!(!text.contains("hidden at info"));
        assert!(serde_json::from_str::<Value>(text.lines().next().unwrap()).is_err());
    }

    // ---------- API key authentication ----------

    #[test]
    fn api_keys_config() {
        assert!(!config(&[]).api_keys.is_enabled());
        let c = config(&[("API_KEYS", " k1, ,k2,k1 ,"), ("API_KEY", "k3")]);
        assert_eq!(c.api_keys, test_keys(&["k1", "k2", "k3"]));
        assert_eq!(
            config(&[("API_KEY", "solo")]).api_keys,
            test_keys(&["solo"])
        );
        assert_eq!(
            config(&[("API_KEYS", "k1"), ("API_KEY", "k1")])
                .api_keys
                .len(),
            1
        );
        assert!(!config(&[("API_KEYS", " , "), ("API_KEY", " ")])
            .api_keys
            .is_enabled());
        // Debug output (and so `{:?}` of the whole Config) never shows a key.
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ApiKeys(<3 redacted>)"), "{dbg}");
        assert!(!dbg.contains("k1") && !dbg.contains("k3"), "{dbg}");
    }

    #[test]
    fn api_keys_matching() {
        let keys = test_keys(&["alpha-key", "beta-key"]);
        assert!(keys.matches("alpha-key"));
        assert!(keys.matches("beta-key"));
        for bad in ["", "alpha", "alpha-key ", "alpha-keyX", "ALPHA-KEY", "beta"] {
            assert!(!keys.matches(bad), "{bad:?}");
        }
        assert!(!ApiKeys::default().matches(""));
    }

    #[test]
    fn presented_key_extraction() {
        let headers = |pairs: &[(&str, &str)]| {
            let mut req = atest::TestRequest::get();
            for (k, v) in pairs {
                req = req.insert_header((*k, *v));
            }
            req.to_http_request().headers().clone()
        };
        let h = headers(&[("X-API-Key", " k ")]);
        assert_eq!(presented_key(&h), Some("k"));
        let h = headers(&[("Authorization", "Bearer k")]);
        assert_eq!(presented_key(&h), Some("k"));
        // X-API-Key wins over Authorization.
        let h = headers(&[("X-API-Key", "a"), ("Authorization", "Bearer b")]);
        assert_eq!(presented_key(&h), Some("a"));
        for auth in ["bearer k", "Basic k", "k", "Bearer ", "Bearer   "] {
            let h = headers(&[("Authorization", auth)]);
            assert_eq!(presented_key(&h), None, "{auth:?}");
        }
        assert_eq!(presented_key(&headers(&[("X-API-Key", "")])), None);
        assert_eq!(presented_key(&headers(&[])), None);
    }

    #[actix_web::test]
    async fn check_requires_api_key_when_configured() {
        let fx = Fixture::new();
        let state = fx.state_with_keys(
            SolanaRpc::new(&dead_url(), None, &fast_settings()),
            true,
            &["key-one", "key-two"],
        );
        let app = app!(state);
        let body = fx.body(1, 1, "0");
        for headers in [
            vec![],
            vec![("X-API-Key", "wrong")],
            vec![("X-API-Key", "key-on")],
            vec![("X-API-Key", "key-one-")],
            vec![("Authorization", "Bearer wrong")],
            vec![("Authorization", "bearer key-one")],
            vec![("Authorization", "Basic key-one")],
            vec![("Authorization", "key-one")],
        ] {
            let (status, text) = post_check_with(&app, &body, &headers).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{headers:?}: {text}");
            let v: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(v, json!({"error": "Unauthorized"}), "{headers:?}");
            assert!(!text.contains("key-one"));
        }
        for headers in [
            vec![("X-API-Key", "key-one")],
            vec![("X-API-Key", "key-two")],
            vec![("Authorization", "Bearer key-one")],
            vec![("Authorization", "Bearer key-two")],
            // A valid X-API-Key wins even with a wrong bearer.
            vec![("X-API-Key", "key-two"), ("Authorization", "Bearer nope")],
        ] {
            let (status, text) = post_check_with(&app, &body, &headers).await;
            assert_eq!(status, StatusCode::OK, "{headers:?}: {text}");
            assert!(text.contains("commit_hash"));
        }
    }

    #[actix_web::test]
    async fn unauthorized_check_carries_bearer_challenge() {
        let fx = Fixture::new();
        let state = fx.state_with_keys(
            SolanaRpc::new(&dead_url(), None, &fast_settings()),
            true,
            &["k"],
        );
        let app = app!(state);
        let req = atest::TestRequest::post()
            .uri("/check")
            .set_json(fx.body(1, 1, "0"))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.headers().get("www-authenticate").unwrap(), "Bearer");
    }

    #[actix_web::test]
    async fn auth_runs_before_body_parsing() {
        let fx = Fixture::new();
        let state = fx.state_with_keys(
            SolanaRpc::new(&dead_url(), None, &fast_settings()),
            true,
            &["k"],
        );
        let app = app!(state);
        // Invalid body and oversized body: still 401 without a key, so an
        // unauthenticated caller learns nothing about validation.
        let mut bad = fx.body(1, 1, "0");
        bad["rfq"] = json!("nope");
        let (status, _) = post_check_with(&app, &bad, &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let huge = json!({ "rfq": "x".repeat(4096) });
        let (status, _) = post_check_with(&app, &huge, &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // With the key, the same bodies reach validation.
        let (status, _) = post_check_with(&app, &bad, &[("X-API-Key", "k")]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = post_check_with(&app, &huge, &[("X-API-Key", "k")]).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[actix_web::test]
    async fn health_and_ready_stay_open_with_api_keys() {
        let fx = Fixture::new();
        let mock = Mock::new(Mode::Ok);
        let state = fx.state_with_keys(
            SolanaRpc::new(&start_mock(mock), None, &fast_settings()),
            true,
            &["k"],
        );
        let app = app!(state);
        for uri in ["/health", "/ready"] {
            let req = atest::TestRequest::get().uri(uri).to_request();
            assert_eq!(
                atest::call_service(&app, req).await.status(),
                StatusCode::OK,
                "{uri}"
            );
        }
    }

    #[actix_web::test]
    async fn rate_limiter_runs_before_api_key_check() {
        let fx = Fixture::new();
        let state = fx.state_with_keys(
            SolanaRpc::new(&dead_url(), None, &fast_settings()),
            true,
            &["k"],
        );
        let gov = rate_limit_config();
        let app = app!(state, Some(&gov));
        let body = fx.body(1, 1, "0");
        // Unauthenticated attempts consume the per-IP quota (throttles key guessing)...
        for i in 0..5 {
            let (status, _) = post_check_with(&app, &body, &[("X-API-Key", "guess")]).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {i}");
        }
        let (status, _) = post_check_with(&app, &body, &[("X-API-Key", "guess")]).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        // ...and the limiter answers before the key is even looked at.
        let (status, _) = post_check_with(&app, &body, &[("X-API-Key", "k")]).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[actix_web::test]
    async fn cors_preflight_with_api_key_header_is_not_challenged() {
        let fx = Fixture::new();
        let obs = observed(None);
        let state = fx.state_with_keys(
            SolanaRpc::new(&dead_url(), None, &fast_settings()),
            true,
            &["k"],
        );
        let gov = rate_limit_config();
        let app = full_app!(state, obs, Some(&gov));
        let req = atest::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/check")
            .peer_addr("10.0.0.3:1234".parse().unwrap())
            .insert_header(("Origin", "https://app.unleak.trade"))
            .insert_header(("Access-Control-Request-Method", "POST"))
            .insert_header(("Access-Control-Request-Headers", "content-type,x-api-key"))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers();
        assert_eq!(h.get("access-control-allow-origin").unwrap(), "*");
        let allowed = h
            .get("access-control-allow-headers")
            .unwrap()
            .to_str()
            .unwrap()
            .to_lowercase();
        assert!(allowed.contains("x-api-key"), "{allowed}");
        // The actual cross-origin request with the key succeeds and is CORS-tagged.
        let req = atest::TestRequest::post()
            .uri("/check")
            .peer_addr("10.0.0.3:1234".parse().unwrap())
            .insert_header(("Origin", "https://app.unleak.trade"))
            .insert_header(("X-API-Key", "k"))
            .set_json(fx.body(1, 1, "0"))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
    }

    #[actix_web::test]
    async fn metrics_accepts_api_keys_and_token() {
        let fx = Fixture::new();
        let state = fx.state(SolanaRpc::new(&dead_url(), None, &fast_settings()), true);
        let scrape_with = |header: Option<(&'static str, &'static str)>| {
            let mut req = atest::TestRequest::get().uri("/metrics");
            if let Some(h) = header {
                req = req.insert_header(h);
            }
            req.to_request()
        };

        // Token + keys: either credential works, via Bearer or X-API-Key.
        let obs = observed_with_keys(Some("tok"), &["key"]);
        let app = full_app!(state, obs, None);
        for (h, ok) in [
            (None, false),
            (Some(("Authorization", "Bearer tok")), true),
            (Some(("Authorization", "Bearer key")), true),
            (Some(("X-API-Key", "key")), true),
            (Some(("X-API-Key", "tok")), true),
            (Some(("X-API-Key", "nope")), false),
            (Some(("Authorization", "Bearer nope")), false),
        ] {
            let resp = atest::call_service(&app, scrape_with(h)).await;
            let want = if ok {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            };
            assert_eq!(resp.status(), want, "{h:?}");
        }

        // Keys only (no METRICS_TOKEN): /metrics is protected by the keys.
        let obs = observed_with_keys(None, &["key"]);
        let app = full_app!(state, obs, None);
        let resp = atest::call_service(&app, scrape_with(None)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp = atest::call_service(&app, scrape_with(Some(("X-API-Key", "key")))).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Neither: open, as before.
        let obs = observed(None);
        let app = full_app!(state, obs, None);
        let resp = atest::call_service(&app, scrape_with(None)).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn rejected_api_keys_are_logged_without_the_key() {
        let (buf, _guard) = capture_json_logs();
        let fx = Fixture::new();
        let obs = observed(None);
        let state = fx.state_with_keys(
            SolanaRpc::new(&dead_url(), None, &fast_settings()),
            true,
            &["the-real-key"],
        );
        let app = full_app!(state, obs, None);
        let body = fx.body(1, 1, "0");
        assert_eq!(
            post_check_with(&app, &body, &[]).await.0,
            StatusCode::UNAUTHORIZED
        );
        let (s, _) = post_check_with(&app, &body, &[("X-API-Key", "guessed-key")]).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let (s, _) = post_check_with(&app, &body, &[("X-API-Key", "the-real-key")]).await;
        assert_eq!(s, StatusCode::OK);

        let text = buf.text();
        assert!(
            !text.contains("the-real-key") && !text.contains("guessed-key"),
            "{text}"
        );
        let lines = buf.json_lines();
        let reasons: Vec<&str> = lines
            .iter()
            .filter(|l| l["message"] == "API key rejected")
            .map(|l| l["reason"].as_str().unwrap())
            .collect();
        assert_eq!(reasons, ["missing", "invalid"], "{text}");
        let statuses: Vec<u64> = lines
            .iter()
            .filter(|l| l["message"] == "request completed")
            .map(|l| l["status"].as_u64().unwrap())
            .collect();
        assert_eq!(statuses, [401, 401, 200]);
    }
}

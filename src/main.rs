use axum::{routing::{get, post}, Router, Json};
use serde::Serialize;
use std::net::SocketAddr;
use solana_sdk::signature::{Keypair, Signer};
use bs58;
use rand::rngs::OsRng;
use axum::extract::Json as AxumJson;
use serde::Deserialize;
use solana_sdk::pubkey::Pubkey;
use spl_token::instruction as token_instruction;
use base64;
use axum::http::Method;
use tower_http::cors::{CorsLayer, Any};
use std::env;
use solana_sdk::signature::SeedDerivable;
use axum::{response::{IntoResponse, Response}, http::StatusCode, extract::rejection::JsonRejection};
use thiserror::Error;
use axum::ServiceExt;
use base64::Engine;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991; // 2^53 - 1, max safe integer in JS

#[derive(Debug, Error)]
enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("Internal server error")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
        };
        let body = serde_json::to_string(&ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(msg),
        }).unwrap();
        (status, [("content-type", "application/json")], body).into_response()
    }
}

impl From<JsonRejection> for AppError {
    fn from(rej: JsonRejection) -> Self {
        AppError::BadRequest(format!("Invalid JSON: {}", rej))
    }
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct TokenCreateRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct TokenCreateResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct TokenMintRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct TokenMintResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct MessageSignRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct MessageSignResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct MessageVerifyRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct MessageVerifyResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenAccountMeta {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<SendTokenAccountMeta>,
    instruction_data: String,
}

fn parse_pubkey(pubkey_str: &str, field_name: &str) -> Result<Pubkey, AppError> {
    if pubkey_str.is_empty() {
        return Err(AppError::BadRequest(format!("Missing required field: {}", field_name)));
    }
    let bytes = bs58::decode(pubkey_str).into_vec()
        .map_err(|_| AppError::BadRequest(format!("Invalid base58 for {}", field_name)))?;
    if bytes.len() != 32 {
        return Err(AppError::BadRequest(format!("Invalid {} pubkey length: expected 32 bytes, got {}", field_name, bytes.len())));
    }
    Pubkey::try_from(bytes.as_slice())
        .map_err(|_| AppError::BadRequest(format!("Invalid {} pubkey", field_name)))
}

fn parse_secret_key(secret_str: &str) -> Result<Keypair, AppError> {
    if secret_str.is_empty() {
        return Err(AppError::BadRequest("Missing required field: secret".to_string()));
    }
    let bytes = bs58::decode(secret_str).into_vec()
        .map_err(|_| AppError::BadRequest("Invalid base58 for secret".to_string()))?;
    if bytes.len() != 64 && bytes.len() != 32 {
        return Err(AppError::BadRequest(format!("Invalid secret key length: expected 32 or 64 bytes, got {}", bytes.len())));
    }
    if bytes.len() == 64 {
        Keypair::from_bytes(&bytes)
            .map_err(|_| AppError::BadRequest("Invalid secret key bytes".to_string()))
    } else {
        let seed: [u8; 32] = bytes.try_into().map_err(|_| AppError::BadRequest("Invalid secret key seed length".to_string()))?;
        Keypair::from_seed(&seed)
            .map_err(|_| AppError::BadRequest("Invalid secret key seed".to_string()))
    }
}

async fn health() -> Result<Json<ApiResponse<&'static str>>, AppError> {
    Ok(Json(ApiResponse {
        success: true,
        data: Some("Solana HTTP server is running!"),
        error: None,
    }))
}

async fn generate_keypair() -> Result<Json<ApiResponse<KeypairResponse>>, AppError> {
    let keypair = Keypair::generate(&mut OsRng);
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    let data = KeypairResponse { pubkey, secret };
    Ok(Json(ApiResponse {
        success: true,
        data: Some(data),
        error: None,
    }))
}

async fn token_create(
    AxumJson(req): AxumJson<TokenCreateRequest>,
) -> Result<Json<ApiResponse<TokenCreateResponse>>, AppError> {
    let mint_authority = parse_pubkey(&req.mint_authority, "mintAuthority")?;
    let mint = parse_pubkey(&req.mint, "mint")?;
    let ix = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        req.decimals,
    ).map_err(|e| AppError::BadRequest(format!("Failed to create instruction: {}", e)))?;
    let accounts = ix.accounts.iter().map(|meta| AccountMetaResponse {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    let instruction_data = base64::engine::general_purpose::STANDARD.encode(&ix.data);
    let resp = TokenCreateResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    Ok(Json(ApiResponse {
        success: true,
        data: Some(resp),
        error: None,
    }))
}

async fn token_mint(
    AxumJson(req): AxumJson<TokenMintRequest>,
) -> Result<Json<ApiResponse<TokenMintResponse>>, AppError> {
    let mint = parse_pubkey(&req.mint, "mint")?;
    let destination = parse_pubkey(&req.destination, "destination")?;
    let authority = parse_pubkey(&req.authority, "authority")?;
    if req.amount == 0 {
        return Err(AppError::BadRequest("Amount must be greater than 0".to_string()));
    }
    if req.amount > MAX_SAFE_INTEGER {
        return Err(AppError::BadRequest(format!("Amount exceeds max safe integer ({}).", MAX_SAFE_INTEGER)));
    }
    let ix = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ).map_err(|e| AppError::BadRequest(format!("Failed to create instruction: {}", e)))?;
    let accounts = ix.accounts.iter().map(|meta| AccountMetaResponse {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    let instruction_data = base64::engine::general_purpose::STANDARD.encode(&ix.data);
    let resp = TokenMintResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    Ok(Json(ApiResponse {
        success: true,
        data: Some(resp),
        error: None,
    }))
}

async fn message_sign(
    AxumJson(req): AxumJson<MessageSignRequest>,
) -> Result<Json<ApiResponse<MessageSignResponse>>, AppError> {
    if req.message.is_empty() {
        return Err(AppError::BadRequest("Missing required field: message".to_string()));
    }
    if req.secret.is_empty() {
        return Err(AppError::BadRequest("Missing required field: secret".to_string()));
    }
    let keypair = parse_secret_key(&req.secret)?;
    let signature = keypair.sign_message(req.message.as_bytes());
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.as_ref());
    let public_key = keypair.pubkey().to_string();
    let resp = MessageSignResponse {
        signature: signature_b64,
        public_key,
        message: req.message,
    };
    Ok(Json(ApiResponse {
        success: true,
        data: Some(resp),
        error: None,
    }))
}

async fn message_verify(
    AxumJson(req): AxumJson<MessageVerifyRequest>,
) -> Result<Json<ApiResponse<MessageVerifyResponse>>, AppError> {
    if req.message.is_empty() {
        return Err(AppError::BadRequest("Missing required field: message".to_string()));
    }
    if req.signature.is_empty() {
        return Err(AppError::BadRequest("Missing required field: signature".to_string()));
    }
    if req.pubkey.is_empty() {
        return Err(AppError::BadRequest("Missing required field: pubkey".to_string()));
    }
    let pubkey = parse_pubkey(&req.pubkey, "pubkey")?;
    let signature_bytes = base64::engine::general_purpose::STANDARD.decode(&req.signature)
        .map_err(|_| AppError::BadRequest("Invalid base64 for signature".to_string()))?;
    if signature_bytes.len() != 64 {
        return Err(AppError::BadRequest(format!("Invalid signature length: expected 64 bytes, got {}", signature_bytes.len())));
    }
    let signature = solana_sdk::signature::Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| AppError::BadRequest("Invalid signature bytes".to_string()))?;
    let valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());
    let resp = MessageVerifyResponse {
        valid,
        message: req.message,
        pubkey: req.pubkey,
    };
    Ok(Json(ApiResponse {
        success: true,
        data: Some(resp),
        error: None,
    }))
}

async fn send_sol(
    AxumJson(req): AxumJson<SendSolRequest>,
) -> Result<Json<ApiResponse<SendSolResponse>>, AppError> {
    let from = parse_pubkey(&req.from, "from")?;
    let to = parse_pubkey(&req.to, "to")?;
    if req.lamports == 0 {
        return Err(AppError::BadRequest("Lamports must be greater than 0".to_string()));
    }
    if req.lamports > MAX_SAFE_INTEGER {
        return Err(AppError::BadRequest(format!("Lamports exceeds max safe integer ({}).", MAX_SAFE_INTEGER)));
    }
    let ix = solana_sdk::system_instruction::transfer(&from, &to, req.lamports);
    let accounts = ix.accounts.iter().map(|meta| meta.pubkey.to_string()).collect();
    let instruction_data = base64::engine::general_purpose::STANDARD.encode(&ix.data);
    let resp = SendSolResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    Ok(Json(ApiResponse {
        success: true,
        data: Some(resp),
        error: None,
    }))
}

async fn send_token(
    AxumJson(req): AxumJson<SendTokenRequest>,
) -> Result<Json<ApiResponse<SendTokenResponse>>, AppError> {
    let destination = parse_pubkey(&req.destination, "destination")?;
    let mint = parse_pubkey(&req.mint, "mint")?;
    let owner = parse_pubkey(&req.owner, "owner")?;
    if req.amount == 0 {
        return Err(AppError::BadRequest("Amount must be greater than 0".to_string()));
    }
    if req.amount > MAX_SAFE_INTEGER {
        return Err(AppError::BadRequest(format!("Amount exceeds max safe integer ({}).", MAX_SAFE_INTEGER)));
    }
    let ix = token_instruction::transfer(
        &spl_token::id(),
        &mint,
        &destination,
        &owner,
        &[],
        req.amount,
    ).map_err(|e| AppError::BadRequest(format!("Failed to create instruction: {}", e)))?;
    let accounts = ix.accounts.iter().map(|meta| SendTokenAccountMeta {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
    }).collect();
    let instruction_data = base64::engine::general_purpose::STANDARD.encode(&ix.data);
    let resp = SendTokenResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    Ok(Json(ApiResponse {
        success: true,
        data: Some(resp),
        error: None,
    }))
}

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST]);
        
    let app = Router::new()
        .route("/health", get(health))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(token_create))
        .route("/token/mint", post(token_mint))
        .route("/message/sign", post(message_sign))
        .route("/message/verify", post(message_verify))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(cors);
        
    let port = env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app).await.unwrap();
}
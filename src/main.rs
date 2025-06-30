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

fn parse_pubkey(pubkey_str: &str, field_name: &str) -> Result<Pubkey, String> {
    // Check for empty string
    if pubkey_str.is_empty() {
        return Err(format!("Missing required field: {}", field_name));
    }
    
    // Decode base58
    let bytes = bs58::decode(pubkey_str).into_vec()
        .map_err(|_| format!("Invalid base58 for {}", field_name))?;
    
    // Validate length (Solana pubkeys are exactly 32 bytes)
    if bytes.len() != 32 {
        return Err(format!("Invalid {} pubkey length: expected 32 bytes, got {}", field_name, bytes.len()));
    }
    
    // Convert to Pubkey
    Pubkey::try_from(bytes.as_slice())
        .map_err(|_| format!("Invalid {} pubkey", field_name))
}

fn parse_secret_key(secret_str: &str) -> Result<Keypair, String> {
    // Check for empty string
    if secret_str.is_empty() {
        return Err("Missing required field: secret".to_string());
    }
    
    // Decode base58
    let bytes = bs58::decode(secret_str).into_vec()
        .map_err(|_| "Invalid base58 for secret".to_string())?;
    
    // Validate length (should be 64 bytes for full keypair or 32 bytes for seed)
    if bytes.len() != 64 && bytes.len() != 32 {
        return Err(format!("Invalid secret key length: expected 32 or 64 bytes, got {}", bytes.len()));
    }
    
    // Try to create keypair
    if bytes.len() == 64 {
        Keypair::from_bytes(&bytes)
            .map_err(|_| "Invalid secret key bytes".to_string())
    } else {
        // Handle 32-byte seed
        let seed: [u8; 32] = bytes.try_into().map_err(|_| "Invalid secret key seed length".to_string())?;
        Keypair::from_seed(&seed)
            .map_err(|_| "Invalid secret key seed".to_string())
    }
}

async fn health() -> Json<ApiResponse<&'static str>> {
    Json(ApiResponse {
        success: true,
        data: Some("Solana HTTP server is running!"),
        error: None,
    })
}

async fn generate_keypair() -> Json<ApiResponse<KeypairResponse>> {
    let keypair = Keypair::generate(&mut OsRng);
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    let data = KeypairResponse { pubkey, secret };
    Json(ApiResponse {
        success: true,
        data: Some(data),
        error: None,
    })
}

async fn token_create(
    AxumJson(req): AxumJson<TokenCreateRequest>,
) -> Json<ApiResponse<TokenCreateResponse>> {
    // Parse pubkeys with enhanced validation
    let mint_authority = match parse_pubkey(&req.mint_authority, "mintAuthority") {
        Ok(pk) => pk,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            });
        }
    };
    
    let mint = match parse_pubkey(&req.mint, "mint") {
        Ok(pk) => pk,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            });
        }
    };
    
    // Use spl_token to create instruction
    let ix = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        req.decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create instruction: {}", e)),
            });
        }
    };
    
    let accounts = ix.accounts.iter().map(|meta| AccountMetaResponse {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    
    let instruction_data = base64::encode(&ix.data);
    
    let resp = TokenCreateResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    Json(ApiResponse {
        success: true,
        data: Some(resp),
        error: None,
    })
}

async fn token_mint(
    AxumJson(req): AxumJson<TokenMintRequest>,
) -> Json<ApiResponse<TokenMintResponse>> {
    // Parse pubkeys with enhanced validation  
    let mint = match parse_pubkey(&req.mint, "mint") {
        Ok(pk) => pk,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            });
        }
    };
    
    let destination = match parse_pubkey(&req.destination, "destination") {
        Ok(pk) => pk,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            });
        }
    };
    
    let authority = match parse_pubkey(&req.authority, "authority") {
        Ok(pk) => pk,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            });
        }
    };
    
    // Use spl_token to create instruction
    let ix = match token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create instruction: {}", e)),
            });
        }
    };
    
    let accounts = ix.accounts.iter().map(|meta| AccountMetaResponse {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    
    let instruction_data = base64::encode(&ix.data);
    
    let resp = TokenMintResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    Json(ApiResponse {
        success: true,
        data: Some(resp),
        error: None,
    })
}

async fn message_sign(
    AxumJson(req): AxumJson<MessageSignRequest>,
) -> Json<ApiResponse<MessageSignResponse>> {
    // Enhanced validation for empty/missing fields
    if req.message.is_empty() {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Missing required field: message".to_string()),
        });
    }
    
    if req.secret.is_empty() {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Missing required field: secret".to_string()),
        });
    }
    
    // Parse secret key with enhanced validation
    let keypair = match parse_secret_key(&req.secret) {
        Ok(kp) => kp,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            });
        }
    };
    
    // Sign message (handles UTF-8 properly)
    let signature = keypair.sign_message(req.message.as_bytes());
    let signature_b64 = base64::encode(signature.as_ref());
    let public_key = keypair.pubkey().to_string();
    
    let resp = MessageSignResponse {
        signature: signature_b64,
        public_key,
        message: req.message,
    };
    
    Json(ApiResponse {
        success: true,
        data: Some(resp),
        error: None,
    })
}

async fn message_verify(
    AxumJson(req): AxumJson<MessageVerifyRequest>,
) -> Json<ApiResponse<MessageVerifyResponse>> {
    // Enhanced validation for empty/missing fields
    if req.message.is_empty() {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Missing required field: message".to_string()),
        });
    }
    
    if req.signature.is_empty() {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Missing required field: signature".to_string()),
        });
    }
    
    if req.pubkey.is_empty() {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Missing required field: pubkey".to_string()),
        });
    }
    
    // Parse pubkey with enhanced validation
    let pubkey = match parse_pubkey(&req.pubkey, "pubkey") {
        Ok(pk) => pk,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            });
        }
    };
    
    // Decode signature with enhanced validation
    let signature_bytes = match base64::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base64 for signature".to_string()),
            });
        }
    };
    
    // Validate signature length (Ed25519 signatures are 64 bytes)
    if signature_bytes.len() != 64 {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some(format!("Invalid signature length: expected 64 bytes, got {}", signature_bytes.len())),
        });
    }
    
    let signature = match solana_sdk::signature::Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid signature bytes".to_string()),
            });
        }
    };
    
    // Verify (handles UTF-8 properly)
    let valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());
    
    let resp = MessageVerifyResponse {
        valid,
        message: req.message,
        pubkey: req.pubkey,
    };
    
    Json(ApiResponse {
        success: true,
        data: Some(resp),
        error: None,
    })
}

async fn send_sol(
    AxumJson(req): AxumJson<SendSolRequest>,
) -> Json<ApiResponse<SendSolResponse>> {
    // Parse pubkeys with enhanced validation
    let from = match parse_pubkey(&req.from, "from") {
        Ok(pk) => pk,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            });
        }
    };
    
    let to = match parse_pubkey(&req.to, "to") {
        Ok(pk) => pk,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            });
        }
    };
    
    // Validate lamports (keep existing validation)
    if req.lamports == 0 {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Lamports must be greater than 0".to_string()),
        });
    }
    
    // Create transfer instruction
    let ix = solana_sdk::system_instruction::transfer(&from, &to, req.lamports);
    let accounts = ix.accounts.iter().map(|meta| meta.pubkey.to_string()).collect();
    let instruction_data = base64::encode(&ix.data);
    
    let resp = SendSolResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    Json(ApiResponse {
        success: true,
        data: Some(resp),
        error: None,
    })
}

async fn send_token(
    AxumJson(req): AxumJson<SendTokenRequest>,
) -> Json<ApiResponse<SendTokenResponse>> {
    // Parse pubkeys with enhanced validation
    let destination = match parse_pubkey(&req.destination, "destination") {
        Ok(pk) => pk,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            });
        }
    };
    
    let mint = match parse_pubkey(&req.mint, "mint") {
        Ok(pk) => pk,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            });
        }
    };
    
    let owner = match parse_pubkey(&req.owner, "owner") {
        Ok(pk) => pk,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e),
            });
        }
    };
    
    // Use spl_token to create transfer instruction
    let ix = match token_instruction::transfer(
        &spl_token::id(),
        &mint,
        &destination,
        &owner,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create instruction: {}", e)),
            });
        }
    };
    
    let accounts = ix.accounts.iter().map(|meta| SendTokenAccountMeta {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
    }).collect();
    
    let instruction_data = base64::encode(&ix.data);
    
    let resp = SendTokenResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    Json(ApiResponse {
        success: true,
        data: Some(resp),
        error: None,
    })
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
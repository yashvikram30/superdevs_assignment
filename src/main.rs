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
    mintAuthority: String,
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
    isSigner: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<SendTokenAccountMeta>,
    instruction_data: String,
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
    // Parse pubkeys
    let mint_authority = match bs58::decode(&req.mintAuthority).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid mintAuthority pubkey".to_string()),
                });
            }
        },
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 for mintAuthority".to_string()),
            });
        }
    };
    let mint = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid mint pubkey".to_string()),
                });
            }
        },
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 for mint".to_string()),
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
    // Parse pubkeys
    let mint = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid mint pubkey".to_string()),
                });
            }
        },
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 for mint".to_string()),
            });
        }
    };
    let destination = match bs58::decode(&req.destination).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid destination pubkey".to_string()),
                });
            }
        },
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 for destination".to_string()),
            });
        }
    };
    let authority = match bs58::decode(&req.authority).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid authority pubkey".to_string()),
                });
            }
        },
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 for authority".to_string()),
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
    // Validate fields
    if req.message.is_empty() || req.secret.is_empty() {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }
    // Decode secret key
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 for secret".to_string()),
            });
        }
    };
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid secret key bytes".to_string()),
            });
        }
    };
    // Sign message
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
    // Validate fields
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }
    // Decode pubkey
    let pubkey_bytes = match bs58::decode(&req.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 for pubkey".to_string()),
            });
        }
    };
    let pubkey = match solana_sdk::pubkey::Pubkey::try_from(pubkey_bytes.as_slice()) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid pubkey bytes".to_string()),
            });
        }
    };
    // Decode signature
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
    // Verify
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
    // Parse pubkeys
    let from = match bs58::decode(&req.from).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid from pubkey".to_string()),
                });
            }
        },
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 for from".to_string()),
            });
        }
    };
    let to = match bs58::decode(&req.to).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid to pubkey".to_string()),
                });
            }
        },
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 for to".to_string()),
            });
        }
    };
    // Validate lamports
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
    // Parse pubkeys
    let destination = match bs58::decode(&req.destination).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid destination pubkey".to_string()),
                });
            }
        },
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 for destination".to_string()),
            });
        }
    };
    let mint = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid mint pubkey".to_string()),
                });
            }
        },
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 for mint".to_string()),
            });
        }
    };
    let owner = match bs58::decode(&req.owner).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid owner pubkey".to_string()),
                });
            }
        },
        Err(_) => {
            return Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid base58 for owner".to_string()),
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
        isSigner: meta.is_signer,
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
    let app = Router::new()
        .route("/health", get(health))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(token_create))
        .route("/token/mint", post(token_mint))
        .route("/message/sign", post(message_sign))
        .route("/message/verify", post(message_verify))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));
    
    // Use PORT environment variable or default to 8080
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid number");
    
    let addr = SocketAddr::from(([0, 0, 0, 0], port)); // Listen on all interfaces
    println!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

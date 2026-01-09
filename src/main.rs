use sha2::{Sha256, Digest};
use chrono::prelude::*;
use serde::{Serialize, Deserialize};
use ed25519_dalek::{SigningKey, Signature, Signer, Verifier, VerifyingKey};
use axum::{
    routing::{get, post},
    Json, Router, extract::State,
    http::StatusCode,
};
use std::sync::{Arc, RwLock};
use tower_http::cors::CorsLayer;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub sender: String,    // 发送者的公钥 (Hex 字符串)
    pub receiver: String,  // 接收者的地址或公钥
    pub amount: f64,
    pub signature: Option<String>, // 签名 (Hex 字符串)
}

impl Transaction {
    // 计算交易的哈希，用于签名
    pub fn calculate_hash(&self) -> Vec<u8> {
        let data = format!("{}{}{}", self.sender, self.receiver, self.amount);
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.finalize().to_vec()
    }

    // 使用私钥对交易进行签名
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let message = self.calculate_hash();
        let signature = signing_key.sign(&message);
        self.signature = Some(hex::encode(signature.to_bytes()));
    }

    // 验证交易签名是否合法
    pub fn is_valid(&self) -> bool {
        // 创世区块的系统交易跳过验证
        if self.sender == "System" {
            return true;
        }

        let sig_hex = match &self.signature {
            Some(s) => s,
            None => return false,
        };

        // 1. 解析公钥
        let public_key_bytes = match hex::decode(&self.sender) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let bytes: [u8; 32] = match public_key_bytes.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let verifying_key = match VerifyingKey::from_bytes(&bytes) {
            Ok(key) => key,
            Err(_) => return false,
        };

        // 2. 解析签名
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        // 3. 验证
        let message = self.calculate_hash();
        verifying_key.verify(&message, &signature).is_ok()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockHeader {
    pub index: u32,
    pub timestamp: i64,
    pub merkle_root: String,
    pub previous_hash: String,
    pub nonce: u64,
}

impl BlockHeader {
    pub fn calculate_hash(&self) -> String {
        let data = format!(
            "{}{}{}{}{}",
            self.index, self.timestamp, self.merkle_root, self.previous_hash, self.nonce
        );
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub hash: String,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn new(index: u32, transactions: Vec<Transaction>, previous_hash: String) -> Self {
        let timestamp = Utc::now().timestamp();
        let merkle_root = Block::calculate_merkle_root(&transactions);
        
        let header = BlockHeader {
            index,
            timestamp,
            merkle_root,
            previous_hash,
            nonce: 0,
        };
        
        let hash = header.calculate_hash();
        
        Block {
            header,
            hash,
            transactions,
        }
    }

    // A real Merkle Root calculation (Simplified for now)
    fn calculate_merkle_root(transactions: &[Transaction]) -> String {
        let mut hashes: Vec<String> = transactions
            .iter()
            .map(|tx| hex::encode(tx.calculate_hash()))
            .collect();

        if hashes.is_empty() {
            return String::from("0");
        }

        while hashes.len() > 1 {
            if hashes.len() % 2 != 0 {
                let last = hashes.last().unwrap().clone();
                hashes.push(last);
            }

            let mut new_hashes = Vec::new();
            for i in (0..hashes.len()).step_by(2) {
                let mut hasher = Sha256::new();
                hasher.update(format!("{}{}", hashes[i], hashes[i+1]).as_bytes());
                new_hashes.push(format!("{:x}", hasher.finalize()));
            }
            hashes = new_hashes;
        }

        hashes[0].clone()
    }

    pub fn mine(&mut self, difficulty: usize) {
        let target = "0".repeat(difficulty);
        while &self.hash[..difficulty] != target {
            self.header.nonce += 1;
            self.hash = self.header.calculate_hash();
        }
        println!("Block Mined! Hash: {}", self.hash);
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    pub difficulty: usize,
    pub pending_transactions: Vec<Transaction>,
}

impl Blockchain {
    pub fn new(difficulty: usize) -> Self {
        let genesis_block_tx = vec![Transaction {
            sender: "System".to_string(),
            receiver: "Creator".to_string(),
            amount: 50.0,
            signature: None,
        }];
        let mut genesis_block = Block::new(0, genesis_block_tx, "0".to_string());
        genesis_block.mine(difficulty);
        Blockchain {
            chain: vec![genesis_block],
            difficulty,
            pending_transactions: Vec::new(),
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<(), &'static str> {
        if !transaction.is_valid() {
            return Err("Invalid transaction signature");
        }
        self.pending_transactions.push(transaction);
        Ok(())
    }

    pub fn mine_pending_transactions(&mut self) -> Result<(), &'static str> {
        if self.pending_transactions.is_empty() {
            return Err("No transactions to mine");
        }

        let previous_hash = self.chain.last().unwrap().hash.clone();
        let mut new_block = Block::new(
            self.chain.len() as u32,
            self.pending_transactions.clone(),
            previous_hash,
        );
        new_block.mine(self.difficulty);
        self.chain.push(new_block);
        self.pending_transactions.clear();
        Ok(())
    }
}

struct AppState {
    blockchain: RwLock<Blockchain>,
}

#[tokio::main]
async fn main() {
    let blockchain = Blockchain::new(4);
    let shared_state = Arc::new(AppState {
        blockchain: RwLock::new(blockchain),
    });

    let app = Router::new()
        .route("/blocks", get(get_blocks))
        .route("/transactions", post(add_transaction))
        .route("/mine", post(mine_block))
        .layer(CorsLayer::permissive())
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    println!("Blockchain server running on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn get_blocks(State(state): State<Arc<AppState>>) -> Json<Vec<Block>> {
    let bc = state.blockchain.read().unwrap();
    Json(bc.chain.clone())
}

async fn add_transaction(
    State(state): State<Arc<AppState>>,
    Json(tx): Json<Transaction>,
) -> Result<Json<String>, (StatusCode, String)> {
    let mut bc = state.blockchain.write().unwrap();
    match bc.add_transaction(tx) {
        Ok(_) => Ok(Json("Transaction added to mempool".to_string())),
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

async fn mine_block(State(state): State<Arc<AppState>>) -> Result<Json<Block>, (StatusCode, String)> {
    let mut bc = state.blockchain.write().unwrap();
    match bc.mine_pending_transactions() {
        Ok(_) => {
            let latest_block = bc.chain.last().unwrap().clone();
            Ok(Json(latest_block))
        },
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}
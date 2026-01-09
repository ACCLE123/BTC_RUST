use sha2::{Sha256, Digest};
use chrono::prelude::*;
use serde::{Serialize, Deserialize};
use ed25519_dalek::{SigningKey, Signature, Signer, Verifier, VerifyingKey};

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

pub struct Blockchain {
    pub chain: Vec<Block>,
    pub difficulty: usize,
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
        }
    }

    pub fn add_block(&mut self, transactions: Vec<Transaction>) {
        // 验证所有交易的签名
        for tx in &transactions {
            if !tx.is_valid() {
                println!("Transaction verification failed! Block discarded.");
                return;
            }
        }

        let previous_hash = self.chain.last().unwrap().hash.clone();
        let mut new_block = Block::new(self.chain.len() as u32, transactions, previous_hash);
        new_block.mine(self.difficulty);
        self.chain.push(new_block);
    }
}

fn main() {
    use rand::rngs::OsRng;
    
    // 1. 生成一对密钥 (模拟用户钱包)
    let mut csprng = OsRng;



    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = VerifyingKey::from(&signing_key);
    let sender_pub_key = hex::encode(verifying_key.to_bytes());

    // 2. 初始化区块链
    let mut btc_clone = Blockchain::new(4);

    // 3. 创建并签名一笔交易
    println!("Creating transaction...");
    let mut tx1 = Transaction {
        sender: sender_pub_key.clone(),
        receiver: "Bob_Address".to_string(),
        amount: 10.5,
        signature: None,
    };
    
    // 签署交易
    tx1.sign(&signing_key);
    println!("Transaction signed.");

    // 4. 将交易打包进区块
    println!("Mining block 1...");
    let txs1 = vec![tx1];
    btc_clone.add_block(txs1);

    // 5. 打印区块链信息
    for block in btc_clone.chain {
        println!("---------------------------------------");
        println!("Index: {}", block.header.index);
        println!("Hash: {}", block.hash);
        println!("Transactions: {}", block.transactions.len());
        for tx in block.transactions {
            let sender_display = if tx.sender.len() > 10 {
                format!("{}...", &tx.sender[..10])
            } else {
                tx.sender.clone()
            };
            println!("  - From: {}", sender_display);
            println!("    To: {}", tx.receiver);
            println!("    Amount: {}", tx.amount);
            println!("    Valid: {}", tx.is_valid());
        }
    }
}

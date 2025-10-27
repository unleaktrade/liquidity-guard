use sha2::{Digest, Sha256};
use solana_sdk::signature::{Keypair, Signer};
use serde::Serialize;

#[derive(Serialize)]
struct Output<'a> {
    pubkey_base58: String,
    message: &'a str,
    hash_hex: String,
    signature_hex: String,
    // Machine-friendly fields:
    message_hash_bytes: [u8; 32],   // Serde supports up to 32
    signature_bytes: Vec<u8>,       // Use Vec for 64-byte signature
}

fn main() {
    // Keypair generation (replace with persisted keypair in prod)
    let keypair = Keypair::new();

    // Message and hash (SHA-256)
    let message = "mynameisjulien";
    let digest = Sha256::digest(message.as_bytes());      // GenericArray<u8, 32>
    let digest_bytes: &[u8] = digest.as_ref();            // &[u8]
    let mut message_hash = [0u8; 32];
    message_hash.copy_from_slice(digest_bytes);           // [u8; 32]

    // Sign the 32-byte hash (returns solana_sdk::signature::Signature)
    let signature = keypair.sign_message(&message_hash);
    let sig_slice: &[u8] = signature.as_ref();            // &[u8; 64]
    let signature_hex = hex::encode(sig_slice);

    // Human-friendly
    let pubkey_b58 = keypair.pubkey().to_string();
    let hash_hex = hex::encode(message_hash);

    println!("Message: {}", message);
    println!("Public Key (base58): {}", pubkey_b58);
    println!("Secret Key (base58): {}", keypair.to_base58_string()); // modern alternative to bs58::encode(keypair.to_bytes()).into_string();
    println!("Message Hash (sha256, hex): {}", hash_hex);
    println!("Signature (ed25519, hex): {}", signature_hex);

    // Machine-friendly JSON
    let out = Output {
        pubkey_base58: pubkey_b58,
        message,
        hash_hex,
        signature_hex,
        message_hash_bytes: message_hash,
        signature_bytes: sig_slice.to_vec(), // Vec<u8> serializes with Serde
    };
    println!("JSON:");
    println!("{}", serde_json::to_string(&out).unwrap());
}

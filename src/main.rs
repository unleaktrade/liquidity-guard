use solana_sdk::signature::{Keypair, Signer};
use sha2::{Sha256, Digest};

fn main() {
    // Generate or load keypair
    let keypair = Keypair::new();
    
    // Message to sign
    let message = "mynameisjulien";
    
    // Hash the message
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let message_hash = hasher.finalize();
    
    // Sign the hash
    let signature = keypair.sign_message(&message_hash);
    
    println!("Public Key: {}", keypair.pubkey());
    println!("Signature: {}", signature);
    
    // Export for client use
    println!("\nFor test client:");
    println!("const PUBKEY = '{}'", keypair.pubkey());
    println!("const MESSAGE_HASH = {:?}", message_hash.as_slice());
    println!("const SIGNATURE = {:?}", signature.as_ref());
}

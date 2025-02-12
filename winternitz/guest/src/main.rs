use bitcoin::Witness;
use risc0_zkvm::guest::env;
use winternitz_core::{utils::hash160, verify_winternitz_and_groth16, Parameters, PublicKey};

fn main() {
    let start = env::cycle_count();
    let pub_key: PublicKey = env::read();
    let params: Parameters = env::read();
    let signature: Vec<Vec<u8>> = env::read();
    let message: Vec<u8> = env::read();
    let image_id: [u32; 8]  = env::read();
    

    verify_winternitz_and_groth16(&pub_key, &signature, &message, &params);
    let mut pub_key_concat: Vec<u8> = vec![0; pub_key.len() * 20];
    for (i, pubkey) in pub_key.iter().enumerate() {
        pub_key_concat[i * 20..(i + 1) * 20].copy_from_slice(pubkey);
    }
    env::commit(&hash160(&pub_key_concat));
    let end = env::cycle_count();
    println!("my_operation_to_measure: {}", end - start);
}

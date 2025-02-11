use ark_bn254::{g1, Fr, G1Affine};
use borsh::{self, BorshDeserialize, BorshSerialize};
use header_chain::header_chain::{
    BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use headerchain::{HEADERCHAIN_ELF, HEADERCHAIN_ID};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use risc0_groth16::{self, verifying_key, Seal};
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, guest::env, ExecutorEnv, ProverOpts,
    Receipt,
};

use std::{
    convert::TryInto,
    fs::File,
    io::{Read, Write},
};
use winternitz::{WINTERNITZ_ELF, WINTERNITZ_ID};
use winternitz_core::{g1_compress, g2_compress, generate_public_key, sign_digits, Parameters};
use work_only::{WORK_ONLY_ELF, WORK_ONLY_ID};

const HEADERS: &[u8] = include_bytes!("regtest-headers.bin");

fn le_to_be(input: [u32; 16]) -> [u32; 16] {
    let mut output = input;
    output.chunks_exact_mut(4).for_each(|chunk| {
        chunk.reverse();
        println!("{:?}", chunk)
    });
    output.reverse();
    output
}

#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
struct Groth16ProofWithMethodId {
    proof: Receipt,
    method_id: [u32; 8],
}
pub fn generate_header_chain_g16_proof(file_name: &str) -> Groth16ProofWithMethodId {
    // Try to read from file first
    if let Ok(mut file) = File::open(file_name) {
        let mut bytes = Vec::new();
        if file.read_to_end(&mut bytes).is_ok() {
            if let Ok(proof_with_method_id) = borsh::BorshDeserialize::try_from_slice(&bytes) {
                println!(
                    "Successfully read proof from file: {:?}",
                    proof_with_method_id
                );
                return proof_with_method_id;
            }
        }
    }

    // If reading fails, generate new proof
    let headerchain_proof: Receipt = generate_header_chain_proof();
    let block_header_circuit_output: BlockHeaderCircuitOutput =
        borsh::BorshDeserialize::try_from_slice(&headerchain_proof.journal.bytes[..]).unwrap();
    println!("{:?}", block_header_circuit_output.method_id);
    let work_only_groth16_proof_receipt: Receipt = call_work_only(
        headerchain_proof,
        &block_header_circuit_output,
        block_header_circuit_output.method_id,
    );

    work_only_groth16_proof_receipt
        .verify(WORK_ONLY_ID)
        .unwrap();

    println!(
        "Work Only Groth16 Proof Receipt: {:?}",
        work_only_groth16_proof_receipt
    );

    let proof_with_method_id = Groth16ProofWithMethodId {
        proof: work_only_groth16_proof_receipt,
        method_id: WORK_ONLY_ID,
    };

    // save the proof to a file borsh serialized
    let mut file = File::create("work_only_groth16_proof.bin").unwrap();
    file.write_all(&borsh::to_vec(&proof_with_method_id).unwrap())
        .unwrap();

    proof_with_method_id
}

// pub struct CompressedGroth16Proof {
//     a: [u8; 32],
//     b: [u8; 64],
//     c: [u8; 32],
// }

// impl CompressedGroth16Proof {
//     // from seal, compress the proof
//     pub fn from_seal(seal: Seal) -> Self {
//         let a_compressed = g1_compress(seal.a);
//         let b_compressed = g2_compress(seal.b);
//         let c_compressed = g1_compress(seal.c);
//         Self {
//             a: a_compressed,
//             b: b_compressed,
//             c: c_compressed,
//         }
//     }
//     pub fn to_seal(self) -> Seal {
//         let a = g1_decompress(&self.a).unwrap();
//         let b = g2_decompress(&self.b).unwrap();
//         let c = g1_decompress(&self.c).unwrap();
//         Seal { a, b, c }
//     }

// }
fn main() {
    let verifiying_key: risc0_groth16::VerifyingKey = verifying_key();
    println!("ver_key: {:#?}", verifiying_key);

    // if there is a file, read it, otherwise create it
    let proof_with_method_id = generate_header_chain_g16_proof("work_only_groth16_proof.bin");

    let g16_proof = proof_with_method_id.proof;
    let method_id = proof_with_method_id.method_id;

    let seal = Seal::from_vec(&g16_proof.inner.groth16().unwrap().seal).unwrap();

    g16_proof.verify(method_id).unwrap();

    // let g1 = G1Affine::from_vec(&seal.a).unwrap();
    // let g2 = G2Affine::from_vec(&seal.b).unwrap();
    // let g3 = G1Affine::from_vec(&seal.c).unwrap();

    // let ark_groth16_proof: ark_groth16::Proof<Bn254> =
    //     ark_groth16::Proof::<Bn254>::from_ark_groth16_proof(seal);

    let a_compressed = g1_compress(seal.a);
    let b_compressed = g2_compress(seal.b);
    let c_compressed = g1_compress(seal.c);

    let commited_total_work: [u8; 16] = g16_proof.journal.bytes.try_into().unwrap();

    // let mut compressed_proof: Vec<u8> = vec![0; 144];
    // compressed_proof[0..32].copy_from_slice(&a_compressed[..32]);
    // compressed_proof[32..96].copy_from_slice(&b_compressed[..64]);
    // compressed_proof[96..128].copy_from_slice(&c_compressed[..32]);
    // compressed_proof[128..144].copy_from_slice(&commited_total_work);

    // let n0 = compressed_proof.len();
    // let log_d = 8;
    // let params = Parameters::new(n0.try_into().unwrap(), log_d);
    // let input: u64 = 1;
    // let mut rng = SmallRng::seed_from_u64(input);
    // let secret_key: Vec<u8> = (0..n0).map(|_| rng.gen()).collect();
    // let pub_key: Vec<[u8; 20]> = generate_public_key(&params, &secret_key);

    // let signature = sign_digits(&params, &secret_key, &compressed_proof);
    // let env = ExecutorEnv::builder()
    //     .write(&pub_key)
    //     .unwrap()
    //     .write(&params)
    //     .unwrap()
    //     .write(&signature)
    //     .unwrap()
    //     .write(&compressed_proof)
    //     .unwrap()
    //     .write(&WORK_ONLY_ID)
    //     .unwrap()
    //     .build()
    //     .unwrap();
    // let executor = default_executor();

    // println!("Exec result: {:?}", executor.execute(env, WINTERNITZ_ELF));
}

fn call_work_only(
    receipt: Receipt,
    block_header_circuit_output: &BlockHeaderCircuitOutput,
    image_id: [u32; 8],
) -> Receipt {
    let env = ExecutorEnv::builder()
        .add_assumption(receipt)
        .write(&block_header_circuit_output)
        .unwrap()
        .write(&image_id)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();
    let receipt = prover
        .prove_with_opts(env, WORK_ONLY_ELF, &ProverOpts::groth16())
        .unwrap()
        .receipt;
    return receipt;
}

fn generate_header_chain_proof() -> Receipt {
    let header_chain_guest_id: [u32; 8] = compute_image_id(HEADERCHAIN_ELF)
        .unwrap()
        .as_words()
        .try_into()
        .unwrap();

    println!("Header Chain Guest ID: {:?}", header_chain_guest_id);
    println!("Header Chain ID: {:?}", HEADERCHAIN_ID);
    let batch_size: usize = 1;

    let headers = HEADERS
        .chunks(80)
        .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
        .collect::<Vec<CircuitBlockHeader>>();

    let start = 0;
    let prev_proof = HeaderChainPrevProofType::GenesisBlock;

    let input = HeaderChainCircuitInput {
        method_id: header_chain_guest_id,
        prev_proof,
        block_headers: headers[start..start + batch_size].to_vec(),
    };

    let mut binding = ExecutorEnv::builder();
    let env = binding.write_slice(&borsh::to_vec(&input).unwrap());
    let env = env.build().unwrap();

    let prover = default_prover();

    let receipt = prover
        .prove_with_opts(env, HEADERCHAIN_ELF, &ProverOpts::succinct())
        .unwrap()
        .receipt;

    return receipt;
}

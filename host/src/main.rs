use borsh::{self, BorshDeserialize};
use header_chain::header_chain::{
    BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use headerchain::HEADERCHAIN_ELF;
use rand::{rngs::SmallRng, Rng, SeedableRng};
use risc0_groth16::{self, split_digest, verifying_key, Seal};
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, sha::{Digest, Digestible}, ExecutorEnv, ProverOpts, Receipt, VerifierContext
};
use std::convert::TryInto;
use winternitz::WINTERNITZ_ELF;
use winternitz_core::{constants::create_verifying_key, generate_public_key, groth16, sign_digits, Parameters};
use work_only::{WORK_ONLY_ELF, WORK_ONLY_ID};
use winternitz_core::groth16::Groth16Seal;
use crate::risc0_groth16::fr_from_hex_string;
const HEADERS: &[u8] = include_bytes!("regtest-headers.bin");

fn main() {
    let headerchain_proof: Receipt = generate_header_chain_proof();
    let block_header_circuit_output: BlockHeaderCircuitOutput =
        borsh::BorshDeserialize::try_from_slice(&headerchain_proof.journal.bytes[..]).unwrap();
    let work_only_groth16_proof_receipt: Receipt = call_work_only(
        headerchain_proof,
        &block_header_circuit_output,
        block_header_circuit_output.method_id,
    );

    let g16_proof_receipt: &risc0_zkvm::Groth16Receipt<risc0_zkvm::ReceiptClaim> =
        work_only_groth16_proof_receipt.inner.groth16().unwrap();
    println!("g16_proof_receipt: {:#?}", g16_proof_receipt);
    g16_proof_receipt.verify_integrity().unwrap();
    let seal = Groth16Seal::from_seal(g16_proof_receipt.seal.as_slice().try_into().unwrap());

    let verifier_context = VerifierContext::default();
    let groth16_verifier_parameters = verifier_context.groth16_verifier_parameters.unwrap();

    let (a0, a1) = split_digest(groth16_verifier_parameters.control_root).unwrap();
    let (c0, c1) = split_digest(g16_proof_receipt.claim.digest()).unwrap();
    let mut id_bn554: Digest = groth16_verifier_parameters.bn254_control_id;
    id_bn554.as_mut_bytes().reverse();
    let id_bn254_fr = fr_from_hex_string(&hex::encode(id_bn554)).unwrap();

    let risc0_groth16_seal: risc0_groth16::Seal = Seal::from_vec(&g16_proof_receipt.seal).unwrap();
    // let risc0_groth16_public_inputs = g16_proof_receipt.clone().claim.value().unwrap();
    // println!("risc0_groth16_public_inputs: {:#?}", risc0_groth16_public_inputs);

    let compressed_proof = seal.get_compressed();

    let commited_total_work: [u8; 16] = work_only_groth16_proof_receipt
        .journal
        .bytes
        .try_into()
        .unwrap();

    let mut compressed_proof_and_total_work: Vec<u8> = vec![0; 144];
    compressed_proof_and_total_work[0..128].copy_from_slice(&compressed_proof);
    compressed_proof_and_total_work[128..144].copy_from_slice(&commited_total_work);

    let n0 = compressed_proof_and_total_work.len();
    let log_d = 8;
    let params = Parameters::new(n0.try_into().unwrap(), log_d);
    let input: u64 = 1;
    let mut rng = SmallRng::seed_from_u64(input);
    let secret_key: Vec<u8> = (0..n0).map(|_| rng.gen()).collect();
    let pub_key: Vec<[u8; 20]> = generate_public_key(&params, &secret_key);

    let ark_g16_vk: ark_groth16::VerifyingKey<ark_ec::bn::Bn<ark_bn254::Config>> = create_verifying_key();
    let risc0_g16_vk: risc0_groth16::VerifyingKey = verifying_key();
    println!("risc0_g16_seal: {:#?}", risc0_groth16_seal);
    println!("a0: {:#?}", a0);
    println!("a1: {:#?}", a1);
    println!("c0: {:#?}", c0);
    println!("c1: {:#?}", c1);
    println!("id_bn254_fr: {:#?}", id_bn254_fr);
    println!("ark_g16_vk: {:#?}", ark_g16_vk);
    println!("risc0_g16_vk: {:#?}", risc0_g16_vk);
    let risc0_groth16_verifier = risc0_groth16::Verifier::new(&risc0_groth16_seal, &[a0, a1, c0, c1, id_bn254_fr], &risc0_g16_vk).unwrap();
    println!("RISC0 GROTH16 VERIFY RESULT: {:?}", risc0_groth16_verifier.verify().unwrap());

    let signature = sign_digits(&params, &secret_key, &compressed_proof_and_total_work);
    let env = ExecutorEnv::builder()
        .write(&pub_key)
        .unwrap()
        .write(&params)
        .unwrap()
        .write(&signature)
        .unwrap()
        .write(&compressed_proof_and_total_work)
        .unwrap()
        .write(&WORK_ONLY_ID)
        .unwrap()
        .build()
        .unwrap();
    let executor = default_executor();

    let _ = executor.execute(env, WINTERNITZ_ELF);
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

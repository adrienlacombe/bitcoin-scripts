use super::*;
use crate::{signatures::winternitz::legacy::utils, support::execution::execute_script};
use bitcoin_script::script;

const BLAKE3_HASH_LENGTH: usize = 20;

#[test]
fn test_signing_winternitz_with_message_success() {
    let secret = WinternitzSecret::new(4);
    let public_key = WinternitzPublicKey::from(&secret);
    let start_time_block_number = 860033_u32;

    let s = script! {
      { generate_winternitz_witness(
        &WinternitzSigningInputs {
          message: &start_time_block_number.to_le_bytes(),
          signing_key: &secret,
      },
      ).to_vec() }
      { winternitz_message_checksig(&public_key) }
      { utils::digits_to_number::<{ 4 * 2}, { LOG_D as usize }>() }
      { start_time_block_number }
      OP_EQUAL
    };

    let result = execute_script(s);
    assert!(result.success);
}

#[test]
fn test_generate_winternitz_secret_length() {
    let secret = WinternitzSecret::new(1);
    assert_eq!(secret.secret_key.len(), 40);
}

#[test]
fn test_winternitz_public_key_from_secret() {
    let secret = WinternitzSecret::new(BLAKE3_HASH_LENGTH);
    let public_key = WinternitzPublicKey::from(&secret);
    let reference_public_key = generate_public_key(&secret.parameters, &secret.secret_key);

    for i in 0..secret.parameters.total_digit_len() {
        assert_eq!(
            public_key.public_key[i as usize],
            reference_public_key[i as usize]
        );
    }
}

#[test]
fn test_winternitz_public_key_from_secret_length() {
    let secret = WinternitzSecret::new(BLAKE3_HASH_LENGTH);
    let public_key = WinternitzPublicKey::from(&secret);

    assert_eq!(
        public_key.public_key.len(),
        public_key.parameters.total_digit_len() as usize
    );
    for i in 0..public_key.parameters.total_digit_len() {
        assert_eq!(public_key.public_key[i as usize].len(), 20);
    }
}

use super::*;
use crate::{signatures::winternitz::legacy::utils, support::execution::execute_script};

use std::fs::File;
use std::io;
use std::io::Read;

#[expect(unused_imports)]
use std::io::Write; // needed to generate test vectors (see below)

use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin_script::script;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json;

const TEST_VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/signatures/winternitz/legacy/tests/vectors.json"
);

#[test]
fn test_signing_winternitz_with_message_success() {
    let secret = Wots4::generate_secret_key();
    let public_key = Wots4::generate_public_key(&secret);
    let start_time_block_number = 860033_u32;
    let message = start_time_block_number.to_le_bytes();

    let s = script! {
      { Wots4::sign_to_raw_witness(&secret, &message) }
      { Wots4::checksig_verify(&public_key) }
      { utils::digits_to_number::<{ 4 * 2}, { LOG2_BASE as usize }>() }
      { start_time_block_number }
      OP_EQUAL
    };

    let result = execute_script(s);

    assert!(result.success);
}

#[test]
fn test_generate_winternitz_secret_length() {
    let secret = Wots4::generate_secret_key();
    assert_eq!(secret.len(), 20, "Secret: {0:?}", secret);
}

#[test]
fn test_winternitz_public_key_from_secret_length() {
    let secret = Wots16::generate_secret_key();
    let public_key = Wots16::generate_public_key(&secret);

    assert_eq!(
        public_key.len(),
        Wots16::PARAMETERS.total_digit_len() as usize,
    );

    for i in 0..Wots16::PARAMETERS.total_digit_len() {
        assert_eq!(
            public_key[i as usize].len(),
            20,
            "public_key[{}]: {:?}",
            i,
            public_key[i as usize]
        );
    }
}

#[test]
fn secret_key_from_string() {
    assert_eq!(
        Wots16::secret_from_str("password").to_lower_hex_string(),
        "37303631373337333737366637323634"
    );
}

/// Test vector for WOTS.
///
/// A message is signed with the WOTS implementation for the given length,
/// using the provided secret key.
///
/// The test vector records the expected signature, ranging over all possible formats:
/// - non-compact signature
/// - non-compact Bitcoin witness
/// - compact signature
/// - compact Bitcoin witness
///
/// The expected Bitcoin witness data is included to ensure compliance
/// with Bitcoin consensus rules and to track any changes to the witness
/// in future versions of BitVM.
#[derive(Serialize, Deserialize)]
struct TestVector {
    #[serde(
        serialize_with = "serialize_bytes_hex",
        deserialize_with = "deserialize_bytes_hex"
    )]
    message: Vec<u8>,
    #[serde(
        serialize_with = "serialize_bytes_hex",
        deserialize_with = "deserialize_bytes_hex",
        rename = "secretKey"
    )]
    secret_key: Vec<u8>,
    #[serde(
        serialize_with = "serialize_byte_matrix_hex",
        deserialize_with = "deserialize_byte_matrix_hex",
        rename = "publicKey"
    )]
    public_key: Vec<Vec<u8>>,
    #[serde(
        serialize_with = "serialize_byte_matrix_hex",
        deserialize_with = "deserialize_byte_matrix_hex"
    )]
    witness: Vec<Vec<u8>>,
    #[serde(
        serialize_with = "serialize_byte_matrix_hex",
        deserialize_with = "deserialize_byte_matrix_hex"
    )]
    signature: Vec<Vec<u8>>,
    #[serde(
        serialize_with = "serialize_byte_matrix_hex",
        deserialize_with = "deserialize_byte_matrix_hex"
    )]
    compact_witness: Vec<Vec<u8>>,
    #[serde(
        serialize_with = "serialize_byte_matrix_hex",
        deserialize_with = "deserialize_byte_matrix_hex"
    )]
    compact_signature: Vec<Vec<u8>>,
}

fn serialize_bytes_hex<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&bytes.to_lower_hex_string())
}

fn deserialize_bytes_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Vec::<u8>::from_hex(&s).map_err(serde::de::Error::custom)
}

fn serialize_byte_matrix_hex<S>(byte_matrix: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(byte_matrix.len()))?;
    for entry in byte_matrix {
        seq.serialize_element(&entry.to_lower_hex_string())?;
    }
    seq.end()
}

fn deserialize_byte_matrix_hex<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec_s: Vec<String> = Vec::deserialize(deserializer)?;
    vec_s
        .into_iter()
        .map(|s| Vec::<u8>::from_hex(&s).map_err(serde::de::Error::custom))
        .collect()
}

/// Creates a test vector for the given `WOTS` implementation.
///
/// The test vector stores the output of signing the given `message`
/// with the given `secret_key`.
#[allow(dead_code)]
fn create_test_vector<WOTS: Wots + CompactWots>(
    message: &WOTS::Message,
    secret_key: WinternitzSecret,
) -> TestVector {
    let public_key: Vec<Vec<u8>> = WOTS::generate_public_key(&secret_key)
        .as_ref()
        .iter()
        .map(|entry| entry.to_vec())
        .collect();
    let witness: Vec<Vec<u8>> = WOTS::sign_to_raw_witness(&secret_key, message)
        .iter()
        .map(|entry| entry.to_vec())
        .collect();
    let signature: Vec<Vec<u8>> = WOTS::sign(&secret_key, message)
        .as_ref()
        .iter()
        .map(|entry| entry.to_vec())
        .collect();
    let compact_witness: Vec<Vec<u8>> = WOTS::compact_sign_to_raw_witness(&secret_key, message)
        .iter()
        .map(|entry| entry.to_vec())
        .collect();
    let compact_signature: Vec<Vec<u8>> = WOTS::compact_sign(&secret_key, message)
        .as_ref()
        .iter()
        .map(|entry| entry.to_vec())
        .collect();

    TestVector {
        message: message.as_ref().to_vec(),
        secret_key,
        public_key,
        witness,
        signature,
        compact_witness,
        compact_signature,
    }
}

/// Creates randomized test vectors for the given `WOTS` implementation.
#[allow(dead_code)]
fn generate_test_vectors_for<WOTS: Wots + CompactWots, const MSG_BYTE_LEN: usize>(
) -> Vec<TestVector> {
    // Working around limitations of the Rust compiler
    debug_assert_eq!(WOTS::MSG_BYTE_LEN as usize, MSG_BYTE_LEN);

    let mut test_vectors = Vec::new();

    // Sign all-zeroes message
    let message = WOTS::Message::try_from(vec![0x00; MSG_BYTE_LEN]).unwrap();
    let secret_key = WOTS::generate_secret_key();
    test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));

    // Sign all-zeroes message where signature has trailing zero byte
    'grind_trailing_zero: loop {
        let secret_key = WOTS::generate_secret_key();
        let witness = WOTS::sign_to_raw_witness(&secret_key, &message);
        for entry in &witness {
            if entry.last().map(|&byte| byte == 0).unwrap_or(false) {
                test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));
                break 'grind_trailing_zero;
            }
        }
    }

    // Sign all-zeroes message where signature has leading zero byte
    'grind_leading_zero: loop {
        let secret_key = WOTS::generate_secret_key();
        let witness = WOTS::sign_to_raw_witness(&secret_key, &message);
        for entry in &witness {
            if entry.first().map(|&byte| byte == 0).unwrap_or(false) {
                test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));
                break 'grind_leading_zero;
            }
        }
    }

    // Sign all-ones message
    let message = WOTS::Message::try_from(vec![0xff; MSG_BYTE_LEN]).unwrap();
    let secret_key = WOTS::generate_secret_key();
    test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));

    // Sign random message
    let message: Vec<u8> = (0..MSG_BYTE_LEN).map(|_| rand::random()).collect();
    let message = WOTS::Message::try_from(message).unwrap();
    let secret_key = WOTS::generate_secret_key();
    test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));

    // Sign half-zeroes, half-ones message
    let message: Vec<u8> = (0..MSG_BYTE_LEN / 2)
        .map(|_| 0x00u8)
        .chain((0..MSG_BYTE_LEN / 2).map(|_| 0xffu8))
        .collect();
    let message = WOTS::Message::try_from(message).unwrap();
    let secret_key = WOTS::generate_secret_key();
    test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));

    // Sign third-zeroes, third-ones, third-random message
    let message: Vec<u8> = (0..MSG_BYTE_LEN / 3)
        .map(|_| 0x00u8)
        .chain((0..MSG_BYTE_LEN / 3).map(|_| 0xffu8))
        .chain((0..MSG_BYTE_LEN - MSG_BYTE_LEN / 3 * 2).map(|_| rand::random()))
        .collect();
    let message = WOTS::Message::try_from(message).unwrap();
    let secret_key = WOTS::generate_secret_key();
    test_vectors.push(create_test_vector::<WOTS>(&message, secret_key));

    test_vectors
}

// Uncomment and run this code to generate fresh test vectors:
// cargo test generate_and_save_test_vectors
/*
#[test]
fn generate_and_save_test_vectors() -> io::Result<()> {
    let mut test_vectors = Vec::new();
    test_vectors.extend(generate_test_vectors_for::<Wots4, 4>());
    test_vectors.extend(generate_test_vectors_for::<Wots16, 16>());
    test_vectors.extend(generate_test_vectors_for::<Wots32, 32>());

    let json = serde_json::to_string_pretty(&test_vectors)?;

    let file = File::create(TEST_VECTOR_PATH)?;
    let mut writer = io::BufWriter::new(file);
    writer.write_all(json.as_bytes())?;
    writer.flush()?;

    Ok(())
}
*/

fn load_test_vectors() -> io::Result<Vec<TestVector>> {
    let mut file = File::open(TEST_VECTOR_PATH)?;

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let test_vectors: Vec<TestVector> = serde_json::from_str(&contents)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(test_vectors)
}

/// Run the test vector and verify the expected outputs.
fn verify_test_vector<WOTS: Wots + CompactWots>(test_vector: TestVector) {
    let message =
        WOTS::Message::try_from(test_vector.message.clone()).expect("Invalid message bytes");
    let computed_public_key = WOTS::generate_public_key(&test_vector.secret_key);
    assert_eq!(
        &test_vector.public_key,
        computed_public_key.as_ref(),
        "public key mismatch"
    );
    let computed_signature = WOTS::sign(&test_vector.secret_key, &message);
    assert_eq!(
        &test_vector.signature,
        computed_signature.as_ref(),
        "signature mismatch"
    );
    let computed_witness = WOTS::sign_to_raw_witness(&test_vector.secret_key, &message);
    assert_eq!(
        &test_vector.witness,
        &computed_witness.to_vec(),
        "witness mismatch"
    );
    assert_eq!(
        WOTS::raw_witness_to_signature(&computed_witness).as_ref(),
        computed_signature.as_ref(),
        "bad conversion witness -> signature"
    );
    assert_eq!(
        &WOTS::signature_to_raw_witness(&computed_signature),
        &computed_witness,
        "bad conversion signature -> witness"
    );
    let script = script! {
        { computed_witness }
        { WOTS::checksig_verify_and_clear_stack(&computed_public_key) }
        OP_TRUE
    };
    assert!(execute_script(script).success);

    let computed_compact_signature = WOTS::compact_sign(&test_vector.secret_key, &message);
    assert_eq!(
        &test_vector.compact_signature,
        computed_compact_signature.as_ref(),
        "compact signature mismatch"
    );
    let computed_compact_witness =
        WOTS::compact_sign_to_raw_witness(&test_vector.secret_key, &message);
    assert_eq!(
        &test_vector.compact_witness,
        &computed_compact_witness.to_vec(),
        "compact witness mismatch"
    );
    assert_eq!(
        WOTS::compact_raw_witness_to_signature(&computed_compact_witness).as_ref(),
        computed_compact_signature.as_ref(),
        "bad conversion compact witness -> compact signature"
    );
    assert_eq!(
        &WOTS::compact_signature_to_raw_witness(&computed_compact_signature),
        &computed_compact_witness,
        "bad conversion compact signature -> compact witness"
    );
    let compact_script = script! {
        { computed_compact_witness }
        { WOTS::compact_checksig_verify_and_clear_stack(&computed_public_key) }
        OP_TRUE
    };
    assert!(execute_script(compact_script).success);
}

#[test]
fn verify_test_vectors() -> io::Result<()> {
    let test_vectors = load_test_vectors()?;

    for test_vector in test_vectors {
        match test_vector.message.len() {
            4 => verify_test_vector::<Wots4>(test_vector),
            16 => verify_test_vector::<Wots16>(test_vector),
            32 => verify_test_vector::<Wots32>(test_vector),
            _ => panic!("Unexpected message length: {}", test_vector.message.len()),
        }
    }

    Ok(())
}

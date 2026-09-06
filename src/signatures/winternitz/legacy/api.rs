use bitcoin::hex::DisplayHex;
use bitcoin::script::read_scriptint;
use bitcoin_script::Script;

use super::{
    BruteforceVerifier, Converter, ListpickVerifier, Parameters, VoidConverter, Winternitz,
};
use crate::signatures::winternitz::legacy as winternitz;
use crate::signatures::winternitz::legacy::utils::bitcoin_representation;

/// Secret key for Winternitz signatures.
///
/// The same key type is used for all message lengths.
pub type WinternitzSecret = winternitz::SecretKey;

/// Public key for some Winternitz signature verification algorithm.
///
/// The key has to be converted into the right length before it can be used
/// in any algorithm. The conversion might fail.
pub type GenericWinternitzPublicKey = winternitz::PublicKey;

/// Bundles a message with a secret key for signing.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WinternitzSigningInputs<'a, 'b, WOTS: Wots + ?Sized> {
    pub message: &'a WOTS::Message,
    pub signing_key: &'b WinternitzSecret,
}

/// Number of bits per digit.
///
/// We hardcode the base to be 16. Therefore, there are 4 bits.
pub const LOG2_BASE: u32 = 4;

/// High-level functionality for working with Winternitz signatures.
///
/// Signatures contain the signature of each digit as well as the digit itself.
///
/// ## See
///
/// [`CompactWots`]
pub trait Wots {
    type Converter: Converter;
    type PublicKey: AsRef<[[u8; 20]]> + TryFrom<Vec<[u8; 20]>, Error: std::fmt::Debug>;
    type Message: AsRef<[u8]> + TryFrom<Vec<u8>, Error: std::fmt::Debug>;
    type Signature: AsRef<[[u8; 21]]> + TryFrom<Vec<[u8; 21]>, Error: std::fmt::Debug>;

    const ALGORITHM: Winternitz<ListpickVerifier, Self::Converter> = Winternitz::new();
    const MSG_BYTE_LEN: u32;
    const PARAMETERS: Parameters = Parameters::new_by_bit_length(Self::MSG_BYTE_LEN * 8, LOG2_BASE);
    const TOTAL_DIGIT_LEN: u32 = Self::PARAMETERS.total_digit_len();

    /// Generates a random secret key.
    fn generate_secret_key() -> WinternitzSecret {
        let mut buffer = [0u8; 20];
        let mut rng = rand::rngs::OsRng;
        rand::RngCore::fill_bytes(&mut rng, &mut buffer);
        Vec::from(buffer)
    }

    /// Creates a secret key from the given `secret` string.
    ///
    /// ## Warning
    ///
    /// For backwards compatibility, the original conversion function is used.
    /// The `secret` string is converted into ASCII bytes,
    /// which are in turn converted into lower hex ASCII bytes.
    #[deprecated(note = "It is safer to use Vec<u8> directly")]
    fn secret_from_str(secret: &str) -> WinternitzSecret {
        secret.as_bytes().to_lower_hex_string().into_bytes()
    }

    /// Generates a public key for the given `secret_key`.
    fn generate_public_key(secret_key: &WinternitzSecret) -> Self::PublicKey {
        let pubkey_vec = winternitz::generate_public_key(&Self::PARAMETERS, secret_key);
        match Self::PublicKey::try_from(pubkey_vec) {
            Ok(public_key) => public_key,
            _ => unreachable!(),
        }
    }

    /// Generates a signature for the given `secret_key` and `message`,
    /// in form of a Bitcoin witness.
    fn sign_to_raw_witness(
        secret_key: &WinternitzSecret,
        message: &Self::Message,
    ) -> bitcoin::Witness {
        let witness = Self::ALGORITHM.sign(&Self::PARAMETERS, secret_key, message.as_ref());
        debug_assert_eq!(witness.len(), 2 * Self::TOTAL_DIGIT_LEN as usize);
        witness
    }

    /// Generates a signature for the given `secret_key` and `message`.
    fn sign(secret_key: &WinternitzSecret, message: &Self::Message) -> Self::Signature {
        let witness = Self::sign_to_raw_witness(secret_key, message);
        Self::raw_witness_to_signature(&witness)
    }

    /// Generates a signature for the given `inputs`.
    fn sign_inputs(inputs: WinternitzSigningInputs<Self>) -> Self::Signature {
        let witness = Self::sign_inputs_to_raw_witness(inputs);
        Self::raw_witness_to_signature(&witness)
    }

    /// Generates a signature for the given `inputs` in form of a Bitcoin witness.
    fn sign_inputs_to_raw_witness(inputs: WinternitzSigningInputs<Self>) -> bitcoin::Witness {
        Self::sign_to_raw_witness(inputs.signing_key, inputs.message)
    }

    /// Parses the given bitcoin `witness` as a Winternitz signature.
    ///
    /// The `witness` must be in the format that is returned by [`Wots::sign`].
    ///
    /// ## Panics
    ///
    /// This method panics if the `witness` is ill-formatted.
    fn raw_witness_to_signature(witness: &bitcoin::Witness) -> Self::Signature {
        assert_eq!(witness.len(), 2 * Self::TOTAL_DIGIT_LEN as usize);
        let mut digit_signatures: Vec<[u8; 21]> =
            Vec::with_capacity(Self::TOTAL_DIGIT_LEN as usize);

        for i in (0..witness.len()).step_by(2) {
            assert_eq!(
                witness[i].len(),
                20,
                "the digit signature should be constant 20 bytes"
            );
            assert!(
                witness[i + 1].len() <= 2,
                "the digit should be in compressed bytes, which is equal the empty vector for digit = 0"
            );
            let digit_value = read_scriptint(&witness[i + 1]).unwrap();
            assert!(
                (0..(1 << LOG2_BASE)).contains(&digit_value),
                "the digit should be in the valid range"
            );
            let mut digit_signature: [u8; 21] = [0; 21];
            digit_signature[0..20].copy_from_slice(&witness[i]);
            digit_signature[20] = digit_value as u8;
            digit_signatures.push(digit_signature);
        }

        debug_assert_eq!(digit_signatures.len(), Self::TOTAL_DIGIT_LEN as usize);
        match Self::Signature::try_from(digit_signatures) {
            Ok(signature) => signature,
            _ => unreachable!(),
        }
    }

    /// Encodes the given Winternitz `signature` as a bitcoin witness.
    fn signature_to_raw_witness(signature: &Self::Signature) -> bitcoin::Witness {
        let mut witness = bitcoin::Witness::new();

        for digit_signature in signature.as_ref().iter() {
            witness.push(&digit_signature[0..20]);
            witness.push(bitcoin_representation(i32::from(digit_signature[20])));
        }

        witness
    }

    /// Extracts the message bytes from the given Winternitz `signature`.
    fn signature_to_message(signature: &Self::Signature) -> Self::Message {
        let digits: Vec<u8> = signature
            .as_ref()
            .iter()
            .map(|digit_sig| digit_sig[20])
            // Remove the checksum at the end
            .take(Self::PARAMETERS.message_digit_len as usize)
            // Un-reverse digits
            .rev()
            .collect();
        // Convert little endian digits [LSD, MSD] to big endian [MSD, LSD].
        // "LSD" means "least significant digit" and
        // "MSD" means "most significant digit".
        let bytes = digits
            .chunks(2)
            .map(|bn| (bn[1] << 4) + bn[0])
            .collect::<Vec<u8>>();
        debug_assert_eq!(bytes.len(), Self::MSG_BYTE_LEN as usize);
        Self::Message::try_from(bytes).unwrap()
    }

    /// Returns a Bitcoin script that verifies a Winternitz signature for the given `public_key`.
    ///
    /// ## Precondition
    ///
    /// Signature is at the stack top.
    ///
    /// ## Postcondition
    ///
    /// The converted message is on the stack top.
    /// The checksum is consumed.
    fn checksig_verify(public_key: &Self::PublicKey) -> Script {
        Self::ALGORITHM.checksig_verify(&Self::PARAMETERS, &public_key.as_ref().to_vec())
    }

    /// Returns a Bitcoin script that verifies a Winternitz signature for the given `public_key`.
    ///
    /// ## Precondition
    ///
    /// Signature (in the verifier's format) is at the stack top.
    ///
    /// ## Postcondition
    ///
    /// The message and checksum are consumed.
    fn checksig_verify_and_clear_stack(public_key: &Self::PublicKey) -> Script {
        Self::ALGORITHM
            .checksig_verify_and_clear_stack(&Self::PARAMETERS, &public_key.as_ref().to_vec())
    }
}

/// High-level functionality for working with compact Winternitz signatures.
///
/// Compact signatures contain the signature of each digit, but not the digit itself.
///
/// ## See
///
/// [`Wots`]
pub trait CompactWots: Wots {
    type CompactSignature: AsRef<[[u8; 20]]> + TryFrom<Vec<[u8; 20]>, Error: std::fmt::Debug>;
    const COMPACT_ALGORITHM: Winternitz<BruteforceVerifier, Self::Converter> = Winternitz::new();

    /// Generates a compact signature for the given `secret_key` and `message`,
    /// in form of a Bitcoin witness.
    fn compact_sign_to_raw_witness(
        secret_key: &WinternitzSecret,
        message: &Self::Message,
    ) -> bitcoin::Witness {
        let witness = Self::COMPACT_ALGORITHM.sign(&Self::PARAMETERS, secret_key, message.as_ref());
        debug_assert_eq!(witness.len(), Self::TOTAL_DIGIT_LEN as usize);
        witness
    }

    /// Generates a compact signature for the given `secret_key` and `message`.
    fn compact_sign(
        secret_key: &WinternitzSecret,
        message: &Self::Message,
    ) -> Self::CompactSignature {
        let witness = Self::compact_sign_to_raw_witness(secret_key, message);
        Self::compact_raw_witness_to_signature(&witness)
    }

    /// Parses the given bitcoin `witness` as a Winternitz signature.
    ///
    /// The `witness` must be in the format that is returned by [`CompactWots::compact_sign`].
    ///
    /// ## Panics
    ///
    /// This method panics if the `witness` is ill-formatted.
    fn compact_raw_witness_to_signature(witness: &bitcoin::Witness) -> Self::CompactSignature {
        assert_eq!(witness.len(), Self::TOTAL_DIGIT_LEN as usize);
        let mut digit_signatures: Vec<[u8; 20]> =
            Vec::with_capacity(Self::TOTAL_DIGIT_LEN as usize);

        for i in 0..witness.len() {
            assert_eq!(
                witness[i].len(),
                20,
                "the digit signature should be constant 20 bytes"
            );

            let digit_signature: [u8; 20] = witness[i].try_into().unwrap();
            digit_signatures.push(digit_signature);
        }

        debug_assert_eq!(digit_signatures.len(), Self::TOTAL_DIGIT_LEN as usize);
        match Self::CompactSignature::try_from(digit_signatures) {
            Ok(signature) => signature,
            _ => unreachable!(),
        }
    }

    /// Encodes the given Winternitz `signature` as a bitcoin witness.
    fn compact_signature_to_raw_witness(signature: &Self::CompactSignature) -> bitcoin::Witness {
        let mut witness = bitcoin::Witness::new();

        for digit_signature in signature.as_ref().iter() {
            witness.push(digit_signature);
        }

        witness
    }

    /// Converts the given Winternitz `signature` into the compact format.
    fn signature_to_compact_signature(signature: &Self::Signature) -> Self::CompactSignature {
        let digit_signatures: Vec<[u8; 20]> = signature
            .as_ref()
            .iter()
            .map(|digit_sig| std::array::from_fn(|i| digit_sig[i]))
            .collect();
        Self::CompactSignature::try_from(digit_signatures).unwrap()
    }

    /// Returns a Bitcoin script that verifies a Winternitz signature for the given `public_key`.
    ///
    /// ## Precondition
    ///
    /// Signature is at the stack top.
    ///
    /// ## Postcondition
    ///
    /// The converted message is on the stack top.
    /// The checksum is consumed.
    fn compact_checksig_verify(public_key: &Self::PublicKey) -> Script {
        Self::COMPACT_ALGORITHM.checksig_verify(&Self::PARAMETERS, &public_key.as_ref().to_vec())
    }

    /// Returns a Bitcoin script that verifies a Winternitz signature for the given `public_key`.
    ///
    /// ## Precondition
    ///
    /// Signature (in the verifier's format) is at the stack top.
    ///
    /// ## Postcondition
    ///
    /// The message and checksum are consumed.
    fn compact_checksig_verify_and_clear_stack(public_key: &Self::PublicKey) -> Script {
        Self::COMPACT_ALGORITHM
            .checksig_verify_and_clear_stack(&Self::PARAMETERS, &public_key.as_ref().to_vec())
    }
}

/// Winternitz signatures for 4-byte messages.
pub struct Wots4;
/// Winternitz signatures for 16-byte messages.
pub struct Wots16;
/// Winternitz signatures for 32-byte messages.
pub struct Wots32;
/// Winternitz signatures for 64-byte messages.
pub struct Wots64;
/// Winternitz signatures for 80-byte messages.
pub struct Wots80;

/// Implements the [`Wots`] and [`CompactWots`] traits for the given type.
///
/// ## Parameters
///
/// - `name`: name of the implementing type
/// - `msg_byte_len`: message length in bytes
/// - `converter`: a type that implements the [`Converter`] trait
#[macro_export]
macro_rules! impl_wots {
    ($name:ident, $msg_byte_len:expr, $converter:ty) => {
        impl Wots for $name {
            /// Converts the message on the stack after signature verification has finished.
            type Converter = $converter;
            /// The public key type for this Winternitz signing algorithm.
            type PublicKey = [[u8; 20]; Self::TOTAL_DIGIT_LEN as usize];
            /// The message type for this Winternitz signing algorithm.
            ///
            /// All messages have the same fixed length.
            type Message = [u8; Self::MSG_BYTE_LEN as usize];
            /// The signature type of this Winternitz signing algorithm.
            type Signature = [[u8; 21]; Self::TOTAL_DIGIT_LEN as usize];

            /// The number of bytes in a message.
            const MSG_BYTE_LEN: u32 = $msg_byte_len;
        }

        impl CompactWots for $name {
            /// The compact signature type of this Winternitz signing algorithm.
            type CompactSignature = [[u8; 20]; Self::TOTAL_DIGIT_LEN as usize];
        }
    };
}

impl_wots!(Wots4, 4, VoidConverter);
impl_wots!(Wots16, 16, VoidConverter);
impl_wots!(Wots32, 32, VoidConverter);
impl_wots!(Wots64, 64, VoidConverter);
impl_wots!(Wots80, 80, VoidConverter);

#[cfg(test)]
#[path = "tests/api.rs"]
mod tests;

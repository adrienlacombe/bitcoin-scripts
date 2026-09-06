use bitcoin::hex::DisplayHex;
use bitcoin::Witness;
use serde::{Deserialize, Serialize};

use crate::support::script::{script, Script};
use crate::{
    arithmetic::u32::stack::u32_compress,
    signatures::winternitz::legacy::{
        generate_public_key, BruteforceVerifier, ListpickVerifier, Parameters, PublicKey,
        SecretKey, ToBytesConverter, VoidConverter, Winternitz,
    },
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct WinternitzSecret {
    pub secret_key: SecretKey,
    parameters: Parameters,
}

pub const LOG_D: u32 = 4;

pub const WINTERNITZ_MESSAGE_VERIFIER: Winternitz<ListpickVerifier, VoidConverter> =
    Winternitz::new();

pub const WINTERNITZ_VARIABLE_VERIFIER: Winternitz<ListpickVerifier, ToBytesConverter> =
    Winternitz::new();

pub const WINTERNITZ_MESSAGE_COMPACT_VERIFIER: Winternitz<BruteforceVerifier, VoidConverter> =
    Winternitz::new();

impl WinternitzSecret {
    pub fn new(message_len: usize) -> Self {
        let mut buffer = [0u8; 20];
        let mut rng = rand::rngs::OsRng;
        rand::RngCore::fill_bytes(&mut rng, &mut buffer);

        Self::from_bytes(message_len, buffer.to_lower_hex_string().into())
    }

    pub fn from_bytes(message_len: usize, secret_bytes: Vec<u8>) -> Self {
        let parameters = Parameters::new_by_bit_length(message_len as u32 * 8, LOG_D);
        Self {
            secret_key: secret_bytes,
            parameters,
        }
    }

    #[deprecated(note = "It is safer to use WinternitzSecret::from_bytes")]
    pub fn from_string(secret: &str, parameters: &Parameters) -> Self {
        WinternitzSecret {
            secret_key: secret.as_bytes().to_lower_hex_string().into(),
            parameters: *parameters,
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct WinternitzPublicKey {
    pub public_key: PublicKey,
    pub parameters: Parameters,
}

impl From<&WinternitzSecret> for WinternitzPublicKey {
    fn from(secret: &WinternitzSecret) -> Self {
        WinternitzPublicKey {
            public_key: generate_public_key(&secret.parameters, &secret.secret_key),
            parameters: secret.parameters,
        }
    }
}

pub struct WinternitzSigningInputs<'a, 'b> {
    pub message: &'a [u8],
    pub signing_key: &'b WinternitzSecret,
}

pub fn generate_winternitz_checksig_leave_hash(
    public_key: &WinternitzPublicKey,
    message_size: usize,
) -> Script {
    script! {
        {WINTERNITZ_VARIABLE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key)}
        for i in 1..message_size {
            {i} OP_ROLL
        }
    }
}

pub fn generate_winternitz_checksig_leave_variable(
    public_key: &WinternitzPublicKey,
    message_size: usize,
) -> Script {
    assert_eq!(message_size % 4, 0, "message should be u32s");
    let u32s_size = message_size / 4;
    script! {
        {WINTERNITZ_VARIABLE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key)}
        for _ in 0..u32s_size {
            {u32_compress()}
            OP_TOALTSTACK
        }
        for _ in 0..u32s_size {
            OP_FROMALTSTACK
        }
        for i in 1..u32s_size {
            {i} OP_ROLL
        }
    }
}

pub fn generate_winternitz_witness(signing_inputs: &WinternitzSigningInputs) -> Witness {
    WINTERNITZ_MESSAGE_VERIFIER.sign(
        &signing_inputs.signing_key.parameters,
        &signing_inputs.signing_key.secret_key,
        signing_inputs.message,
    )
}

pub fn winternitz_message_checksig(public_key: &WinternitzPublicKey) -> Script {
    WINTERNITZ_MESSAGE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key)
}

pub fn winternitz_message_checksig_verify(
    public_key: &WinternitzPublicKey,
    message_size: usize,
) -> Script {
    script! {
        { WINTERNITZ_MESSAGE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key) }
        for _ in 0..message_size {
            OP_DROP
        }
    }
}

#[cfg(test)]
#[path = "tests/signing.rs"]
mod tests;

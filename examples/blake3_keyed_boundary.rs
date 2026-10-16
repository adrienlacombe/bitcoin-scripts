use bitcoin_lab::{
    hashes::blake3::{
        blake3_short_compute_script, blake3_short_message_witness,
        blake3_short_mode_compute_script, blake3_verify_output_script, Blake3Mode,
    },
    support::{
        execution::execute_script_with_inputs_strict,
        script::{script, ScriptCompilation},
    },
};

fn main() {
    let message: Vec<u8> = (0..32).collect();
    let key = [0x42u8; 32];
    let unkeyed = blake3::hash(&message);
    let keyed = blake3::keyed_hash(&key, &message);
    assert_ne!(unkeyed, keyed);

    let compute = blake3_short_mode_compute_script(message.len(), Blake3Mode::KeyedHash(key), 32);
    let keyed_bytes = compute.clone().compile_with_policy().len();
    let result = execute_script_with_inputs_strict(
        script! {
            { compute }
            { blake3_verify_output_script(*keyed.as_bytes()) }
        },
        blake3_short_message_witness(&message),
    );
    assert!(result.success, "keyed script rejected the reference digest");

    println!(
        "message_bytes={} key_bytes={} unkeyed_compute_script_bytes={} keyed_compute_script_bytes={} keyed_strict_peak={}",
        message.len(),
        key.len(),
        blake3_short_compute_script(message.len())
            .compile_with_policy()
            .len(),
        keyed_bytes,
        result.stats.max_nb_stack_items
    );
}

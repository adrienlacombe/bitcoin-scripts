use bitcoin_lab::{
    hashes::blake3::{
        blake3_compute_script, blake3_short_compute_script, blake3_short_message_witness,
        blake3_short_mode_compute_script, blake3_verify_extended_output_script, Blake3Mode,
    },
    support::{
        execution::execute_script_with_inputs_strict,
        script::{script, ScriptCompilation},
    },
};

fn main() {
    let message: Vec<u8> = (0..32).collect();
    let mut xof = blake3::Hasher::new().update(&message).finalize_xof();
    let mut output = [0u8; 64];
    xof.fill(&mut output);
    assert_eq!(&output[..32], blake3::hash(&message).as_bytes());

    let compute = blake3_short_mode_compute_script(message.len(), Blake3Mode::Hash, 64);
    let xof_bytes = compute.clone().compile_with_policy().len();
    let result = execute_script_with_inputs_strict(
        script! {
            { compute }
            { blake3_verify_extended_output_script(output) }
        },
        blake3_short_message_witness(&message),
    );
    assert!(result.success, "XOF script rejected the reference output");

    println!(
        "message_bytes=32 xof_output_bytes={} short_digest_compute_script_bytes={} short_xof64_compute_script_bytes={} short_xof64_strict_peak={} limb29_digest_compute_script_bytes={}",
        output.len(),
        blake3_short_compute_script(32).compile_with_policy().len(),
        xof_bytes,
        result.stats.max_nb_stack_items,
        blake3_compute_script(32).compile_with_policy().len()
    );
}

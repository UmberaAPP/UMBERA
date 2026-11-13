#![no_main]
// Real coverage-guided fuzzing of the AMF parse/verify surface. Arbitrary attacker-controlled bytes
// must NEVER panic the crypto layer — every function must reject bad input with Err/false, never
// crash (a panic in the .so would be an FFI abort on-device). libFuzzer mutates `data`.
use libfuzzer_sys::fuzz_target;
use umbera_core::amf::{amf_commit, amf_judge, amf_keypair_from_seed, amf_public_of, amf_verify};

fuzz_target!(|data: &[u8]| {
    // carve deterministic, wrapping slices out of the fuzz input
    let part = |i: usize, n: usize| -> Vec<u8> {
        let len = data.len().max(1);
        let start = (i * 32) % len;
        data.iter().cycle().skip(start).take(n).cloned().collect()
    };
    let a = part(0, 32);
    let b = part(1, 32);
    let c = part(2, 32);
    let msg = data.to_vec();
    let sig = if data.len() >= 256 { data[..256].to_vec() } else { part(3, 256) };

    // None of these may panic on arbitrary input.
    let _ = amf_verify(a.clone(), b.clone(), c.clone(), msg.clone(), sig.clone());
    let _ = amf_judge(a.clone(), b.clone(), c.clone(), msg.clone(), sig.clone());
    let _ = amf_commit(a.clone(), msg.clone());
    let _ = amf_public_of(a.clone());
    let _ = amf_keypair_from_seed(a);
});

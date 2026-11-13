#![no_main]
// PDF metadata stripping: lopdf parses a file sent by anyone (a primary attack surface).
// No panic, no infinite loop, no memory blow-up (libFuzzer: -rss_limit_mb, -timeout).
use libfuzzer_sys::fuzz_target;
use umbera_core::pdf::pdf_strip_metadata;

fuzz_target!(|data: &[u8]| {
    let _ = pdf_strip_metadata(data.to_vec());
});

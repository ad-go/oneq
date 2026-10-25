#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| oneq_core::fuzzing::registry_json(data));

// The fuzzing harness fuzz test some of the the
// unicode string normalization processing

#![no_main]

#[macro_use]
extern crate libfuzzer_sys;
extern crate unicode_normalization;

use unicode_normalization::{
    char::{
        canonical_combining_class, compose, decompose_canonical, decompose_compatible,
        is_combining_mark,
    },
    UnicodeNormalization,
};

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let c = if let Some((char_value, remaining_data)) = data.split_first() {
        match std::char::from_u32(*char_value as u32) {
            Some(ch) => {
                data = remaining_data;
                ch
            }
            None => return,
        }
    } else {
        return;
    };

    // Generate second character for fuzzing if data is enough
    let c2 = if let Some((char_value, remaining_data)) = data.split_first() {
        data = remaining_data;
        std::char::from_u32(*char_value as u32)
    } else {
        None
    };
    let string_data: String = data
        .iter()
        .filter_map(|&b| std::char::from_u32(b as u32))
        .collect();

    // Randomly choose a function target
    match data.first().map(|&b| b % 10) {
        Some(0) => {
            if let Some(c2) = c2 {
                let _ = compose(c, c2);
            }
        }
        Some(1) => {
            let _ = canonical_combining_class(c);
        }
        Some(2) => {
            let _ = is_combining_mark(c);
        }
        Some(3) => {
            let _ = string_data.nfc().collect::<String>();
        }
        Some(4) => {
            let _ = string_data.nfkd().collect::<String>();
        }
        Some(5) => {
            let _ = string_data.nfd().collect::<String>();
        }
        Some(6) => {
            let _ = string_data.nfkc().collect::<String>();
        }
        Some(7) => {
            let _ = string_data.stream_safe().collect::<String>();
        }
        Some(8) => {
            decompose_canonical(c, |_| {});
        }
        Some(9) => {
            decompose_compatible(c, |_| {});
        }
        _ => {}
    }
});

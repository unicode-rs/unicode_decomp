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

fuzz_target!(|data: (u8, String)| {
    let (function_index, string_data) = data;

    // Create an iterator for characters
    let mut chars = string_data.chars();

    // Randomly fuzz a target function
    match function_index % 10 {
        0 => {
            // Fuzz compose with two distinct characters
            if let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
                let _ = compose(c1, c2);
            }
        }
        1 => {
            // Fuzz canonical_combining_class
            if let Some(c) = chars.next() {
                let _ = canonical_combining_class(c);
            }
        }
        2 => {
            // Fuzz is_combining_mark
            if let Some(c) = chars.next() {
                let _ = is_combining_mark(c);
            }
        }
        3 => {
            // Fuzz NFC
            let _ = string_data.nfc().collect::<String>();
        }
        4 => {
            // Fuzz NFKD
            let _ = string_data.nfkd().collect::<String>();
        }
        5 => {
            // Fuzz NFD
            let _ = string_data.nfd().collect::<String>();
        }
        6 => {
            // Fuzz NFKC
            let _ = string_data.nfkc().collect::<String>();
        }
        7 => {
            // Fuzz stream_safe
            let _ = string_data.stream_safe().collect::<String>();
        }
        8 => {
            // Fuzz decompose_canonical
            if let Some(c) = chars.next() {
                decompose_canonical(c, |_| {});
            }
        }
        9 => {
            // Fuzz decompose_compatible
            if let Some(c) = chars.next() {
                decompose_compatible(c, |_| {});
            }
        }
        _ => {}
    }
});

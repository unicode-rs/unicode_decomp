// Copyright 2012-2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.


use std::char;
use super::UnicodeNormalization;
use super::char::is_combining_mark;

fn to_codepoint_seq(s: String) -> String {
    s.chars().map(|c| format!("U+{:04X} ", c as u32)).collect::<String>()
}
macro_rules! assert_eq_strs {
    ($left: expr, $right: expr) => {
        assert_eq!(to_codepoint_seq($left.to_string()), to_codepoint_seq($right.to_string()));
    }
}

#[test]
fn test_nfd() {
    macro_rules! t {
        ($input: expr, $expected: expr) => {
            assert_eq!($input.nfd().to_string(), $expected);
            // A dummy iterator that is not std::str::Chars directly;
            // note that `id_func` is used to ensure `Clone` implementation
            assert_eq!($input.chars().map(|c| c).nfd().collect::<String>(), $expected);
        }
    }
    t!("abc", "abc");
    t!("\u{1e0b}\u{1c4}", "d\u{307}\u{1c4}");
    t!("\u{2026}", "\u{2026}");
    t!("\u{2126}", "\u{3a9}");
    t!("\u{1e0b}\u{323}", "d\u{323}\u{307}");
    t!("\u{1e0d}\u{307}", "d\u{323}\u{307}");
    t!("a\u{301}", "a\u{301}");
    t!("\u{301}a", "\u{301}a");
    t!("\u{d4db}", "\u{1111}\u{1171}\u{11b6}");
    t!("\u{ac1c}", "\u{1100}\u{1162}");
    t!("\u{E1}\u{325}\u{E1}\u{325}", "a\u{325}\u{301}a\u{325}\u{301}");
    t!("\u{E1}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}",
        "a\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}");
    t!("\u{E1}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}",
        "a\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}");
}

#[test]
fn test_nfd_stream_safe() {
    macro_rules! t {
        ($input: expr, $expected: expr) => {
            assert_eq_strs!($input.nfd_stream_safe().to_string(), $expected);
            // A dummy iterator that is not std::str::Chars directly;
            // note that `id_func` is used to ensure `Clone` implementation
            assert_eq_strs!($input.chars().map(|c| c).nfd_stream_safe().collect::<String>(), $expected);
        }
    }
    t!("abc", "abc");
    t!("\u{1e0b}\u{1c4}", "d\u{307}\u{1c4}");
    t!("\u{2026}", "\u{2026}");
    t!("\u{2126}", "\u{3a9}");
    t!("\u{1e0b}\u{323}", "d\u{323}\u{307}");
    t!("\u{1e0d}\u{307}", "d\u{323}\u{307}");
    t!("a\u{301}", "a\u{301}");
    t!("\u{301}a", "\u{301}a");
    t!("\u{d4db}", "\u{1111}\u{1171}\u{11b6}");
    t!("\u{ac1c}", "\u{1100}\u{1162}");
    t!("a\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}",
        "a\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{34f}\
        \u{301}\u{301}");
    t!("\u{E1}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}",
        "a\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{34f}\
        \u{301}\u{301}");
    t!("\u{E1}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}",
        "a\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{34f}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{34f}\
        \u{301}\u{301}");
}

#[test]
fn test_nfkd() {
    macro_rules! t {
        ($input: expr, $expected: expr) => {
            assert_eq!($input.nfkd().to_string(), $expected);
        }
    }
    t!("abc", "abc");
    t!("\u{1e0b}\u{1c4}", "d\u{307}DZ\u{30c}");
    t!("\u{2026}", "...");
    t!("\u{2126}", "\u{3a9}");
    t!("\u{1e0b}\u{323}", "d\u{323}\u{307}");
    t!("\u{1e0d}\u{307}", "d\u{323}\u{307}");
    t!("a\u{301}", "a\u{301}");
    t!("\u{301}a", "\u{301}a");
    t!("\u{d4db}", "\u{1111}\u{1171}\u{11b6}");
    t!("\u{ac1c}", "\u{1100}\u{1162}");
}

#[test]
fn test_nfc() {
    macro_rules! t {
        ($input: expr, $expected: expr) => {
            assert_eq_strs!($input.nfc().to_string(), $expected);
            //assert_eq!($input.nfc().map(|c| format!("U+{:04X},", c as u32)).collect::<String>(), $expected.chars().map(|c| format!("U+{:04X},", c as u32)).collect::<String>())
            //assert_eq!($input.nfc().to_string(), $expected);
        }
    }
    t!("abc", "abc");
    t!("\u{1e0b}\u{1c4}", "\u{1e0b}\u{1c4}");
    t!("\u{2026}", "\u{2026}");
    t!("\u{2126}", "\u{3a9}");
    t!("\u{1e0b}\u{323}", "\u{1e0d}\u{307}");
    t!("\u{1e0d}\u{307}", "\u{1e0d}\u{307}");
    t!("a\u{301}", "\u{e1}");
    t!("\u{301}a", "\u{301}a");
    t!("\u{d4db}", "\u{d4db}");
    t!("\u{ac1c}", "\u{ac1c}");
    t!("a\u{300}\u{305}\u{315}\u{5ae}b", "\u{e0}\u{5ae}\u{305}\u{315}b");
    // U+0325 will get sorted to the front because it's CCC=220, and U+0301 is CCC=230, then it'll
    // canonically combine with the a to make U+1E01.
    t!("a\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{325}",
        "\u{1E01}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}");
}

#[test]
fn test_nfc_stream_safe() {
    macro_rules! t {
        ($input: expr, $expected: expr) => {
            //assert_eq!($input.nfc_stream_safe().to_string(), $expected);
            assert_eq!($input.nfc_stream_safe().map(|c| format!("U+{:04X},", c as u32)).collect::<String>(), $expected.chars().map(|c| format!("U+{:04X},", c as u32)).collect::<String>())
        }
    }
    t!("abc", "abc");
    t!("\u{1e0b}\u{1c4}", "\u{1e0b}\u{1c4}");
    t!("\u{2026}", "\u{2026}");
    t!("\u{2126}", "\u{3a9}");
    t!("\u{1e0b}\u{323}", "\u{1e0d}\u{307}");
    t!("\u{1e0d}\u{307}", "\u{1e0d}\u{307}");
    t!("a\u{301}", "\u{e1}");
    t!("\u{301}a", "\u{301}a");
    t!("\u{d4db}", "\u{d4db}");
    t!("\u{ac1c}", "\u{ac1c}");
    t!("a\u{300}\u{305}\u{315}\u{5ae}b", "\u{e0}\u{5ae}\u{305}\u{315}b");
    // In stream safe mode, COMBINING GRAPHEME JOINER (U+034F) will get inserted after 30 combining
    // characters, which breaks up the sort/recombine so the U+0325 will not get sorted next to the
    // a, so it'll combine with a U+0301 to U+00E1 instead.
    t!("a\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{325}",
        "\u{E1}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\u{301}\
        \u{34F}\
        \u{325}\u{301}\u{301}");
}

#[test]
fn test_nfkc() {
    macro_rules! t {
        ($input: expr, $expected: expr) => {
            assert_eq!($input.nfkc().to_string(), $expected);
        }
    }
    t!("abc", "abc");
    t!("\u{1e0b}\u{1c4}", "\u{1e0b}D\u{17d}");
    t!("\u{2026}", "...");
    t!("\u{2126}", "\u{3a9}");
    t!("\u{1e0b}\u{323}", "\u{1e0d}\u{307}");
    t!("\u{1e0d}\u{307}", "\u{1e0d}\u{307}");
    t!("a\u{301}", "\u{e1}");
    t!("\u{301}a", "\u{301}a");
    t!("\u{d4db}", "\u{d4db}");
    t!("\u{ac1c}", "\u{ac1c}");
    t!("a\u{300}\u{305}\u{315}\u{5ae}b", "\u{e0}\u{5ae}\u{305}\u{315}b");
}

#[test]
fn test_official() {
    use testdata::TEST_NORM;
    macro_rules! normString {
        ($method: ident, $input: expr) => { $input.$method().collect::<String>() }
    }

    for &(s1, s2, s3, s4, s5) in TEST_NORM {
        // these invariants come from the CONFORMANCE section of
        // http://www.unicode.org/Public/UNIDATA/NormalizationTest.txt
        {
            let r1 = normString!(nfc, s1);
            let r2 = normString!(nfc, s2);
            let r3 = normString!(nfc, s3);
            let r4 = normString!(nfc, s4);
            let r5 = normString!(nfc, s5);
            assert_eq_strs!(s2, &r1[..]);
            assert_eq_strs!(s2, &r2[..]);
            assert_eq_strs!(s2, &r3[..]);
            assert_eq_strs!(s4, &r4[..]);
            assert_eq_strs!(s4, &r5[..]);
        }

        {
            let r1 = normString!(nfd, s1);
            let r2 = normString!(nfd, s2);
            let r3 = normString!(nfd, s3);
            let r4 = normString!(nfd, s4);
            let r5 = normString!(nfd, s5);
            assert_eq_strs!(s3, &r1[..]);
            assert_eq_strs!(s3, &r2[..]);
            assert_eq_strs!(s3, &r3[..]);
            assert_eq_strs!(s5, &r4[..]);
            assert_eq_strs!(s5, &r5[..]);
        }

        {
            let r1 = normString!(nfkc, s1);
            let r2 = normString!(nfkc, s2);
            let r3 = normString!(nfkc, s3);
            let r4 = normString!(nfkc, s4);
            let r5 = normString!(nfkc, s5);
            assert_eq_strs!(s4, &r1[..]);
            assert_eq_strs!(s4, &r2[..]);
            assert_eq_strs!(s4, &r3[..]);
            assert_eq_strs!(s4, &r4[..]);
            assert_eq_strs!(s4, &r5[..]);
        }

        {
            let r1 = normString!(nfkd, s1);
            let r2 = normString!(nfkd, s2);
            let r3 = normString!(nfkd, s3);
            let r4 = normString!(nfkd, s4);
            let r5 = normString!(nfkd, s5);
            assert_eq_strs!(s5, &r1[..]);
            assert_eq_strs!(s5, &r2[..]);
            assert_eq_strs!(s5, &r3[..]);
            assert_eq_strs!(s5, &r4[..]);
            assert_eq_strs!(s5, &r5[..]);
        }
    }
}



#[test]
fn test_is_combining_mark_ascii() {
    for cp in 0..0x7f {
        assert!(!is_combining_mark(char::from_u32(cp).unwrap()));
    }
}

#[test]
fn test_is_combining_mark_misc() {
    // https://github.com/unicode-rs/unicode-normalization/issues/16
    // U+11C3A BHAIKSUKI VOWEL SIGN O
    // Category: Mark, Nonspacing [Mn]
    assert!(is_combining_mark('\u{11C3A}'));

    // U+11C3F BHAIKSUKI SIGN VIRAMA
    // Category: Mark, Nonspacing [Mn]
    assert!(is_combining_mark('\u{11C3F}'));
}

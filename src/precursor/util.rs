use base64::engine::{general_purpose::STANDARD, Engine};
use indicatif::{ProgressBar, ProgressStyle};
use pcre2::bytes::{Regex, RegexBuilder};
use std::path::PathBuf;
use xxhash_rust::xxh3::xxh3_64;

pub fn xxh3_64_hex(input: Vec<u8>) -> (u64, String) {
    let hash = xxh3_64(&input);
    (hash, format!("{:x}", hash))
}

pub fn remove_wrapped_quotes(input: &str) -> &str {
    input
        .trim_start_matches(|c| c == '"' || c == '\'')
        .trim_end_matches(|c| c == '"' || c == '\'')
}

pub fn get_payload(line: &str, input_mode: &str) -> Vec<u8> {
    let line_with_no_wrapped_quotes = remove_wrapped_quotes(line);
    match input_mode {
        "base64" => STANDARD.decode(line_with_no_wrapped_quotes).unwrap(),
        "string" => line_with_no_wrapped_quotes.as_bytes().to_vec(),
        "hex" => hex::decode(line_with_no_wrapped_quotes).unwrap(),
        _ => panic!("{} not a supported input mode.", input_mode),
    }
}

pub fn format_size(size: i64) -> String {
    const KILOBYTE: i64 = 1024;
    const MEGABYTE: i64 = KILOBYTE * 1024;
    const GIGABYTE: i64 = MEGABYTE * 1024;
    const TERABYTE: i64 = GIGABYTE * 1024;

    if size < KILOBYTE {
        format!("{}B", size)
    } else if size < MEGABYTE {
        format!("{:.2}KB", size / KILOBYTE)
    } else if size < GIGABYTE {
        format!("{:.2}MB", size / MEGABYTE)
    } else if size < TERABYTE {
        format!("{:.2}GB", size / GIGABYTE)
    } else {
        format!("{:.2}TB", size / TERABYTE)
    }
}

pub fn read_patterns(pattern_file: Option<&PathBuf>) -> Vec<String> {
    let mut patterns = Vec::new();
    if let Some(path) = pattern_file {
        let file_contents = std::fs::read_to_string(path).unwrap();
        for line in file_contents.lines() {
            patterns.push(line.to_owned());
        }
    }
    patterns
}

pub fn build_regex(pattern: &String) -> Result<Regex, Box<dyn std::error::Error>> {
    let re = RegexBuilder::new()
        // NOTE: We should only enable JIT if we're going to compile all patterns into one large PCRE2 statement
        // TODO: Pass CLI flags for certain REGEX settings down to the builder.
        .jit_if_available(false)
        .multi_line(true)
        .build(pattern)?;
    Ok(re)
}

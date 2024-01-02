use base64::engine::{general_purpose::STANDARD, Engine};
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
        format!("{:.2}KB", (size as f64) / (KILOBYTE as f64))
    } else if size < GIGABYTE {
        format!("{:.2}MB", (size as f64) / (MEGABYTE as f64))
    } else if size < TERABYTE {
        format!("{:.2}GB", (size as f64) / (GIGABYTE as f64))
    } else {
        format!("{:.2}TB", (size as f64) / (TERABYTE as f64))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    // Test for `xxh3_64_hex` function
    #[test]
    fn test_xxh3_64_hex() {
        let input = b"Hello, world!";
        let (hash, hex) = xxh3_64_hex(input.to_vec());
        assert_ne!(hash, 0);
        assert_eq!(hex, format!("{:x}", hash));
    }

    // Test for `remove_wrapped_quotes` function
    #[test]
    fn test_remove_wrapped_quotes() {
        // String with no quotes
        assert_eq!(remove_wrapped_quotes("Hello"), "Hello");

        // String with double quotes at the start and end
        assert_eq!(remove_wrapped_quotes("\"Hello\""), "Hello");

        // String with single quotes at the start and end
        assert_eq!(remove_wrapped_quotes("'Hello'"), "Hello");
    }

    // Test for `get_payload` function
    #[test]
    fn test_get_payload() {
        assert_eq!(get_payload("aGVsbG8=", "base64"), b"hello".to_vec());
        assert_eq!(get_payload("hello", "string"), b"hello".to_vec());
        assert_eq!(get_payload("68656c6c6f", "hex"), b"hello".to_vec());

        let result = std::panic::catch_unwind(|| get_payload("hello", "invalid_mode"));
        assert!(result.is_err());
    }

    // Test for `format_size` function
    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500B"); // Exact bytes
        assert_eq!(format_size(1023), "1023B"); // Edge case for bytes to KB
        assert_eq!(format_size(1024), "1.00KB"); // Edge case for exact KB
        assert_eq!(format_size(1536), "1.50KB"); // Middle case for KB
        assert_eq!(format_size(1048576), "1.00MB"); // Exact MB
        assert_eq!(format_size(1572864), "1.50MB"); // Middle case for MB
        assert_eq!(format_size(1073741824), "1.00GB"); // Exact GB
        assert_eq!(format_size(1610612736), "1.50GB"); // Middle case for GB
        assert_eq!(format_size(1099511627776), "1.00TB"); // Exact TB
        assert_eq!(format_size(1649267441664), "1.50TB"); // Middle case for TB
    }

    // Test for `read_patterns` function
    // Note: This requires a real or mocked file system
    #[test]
    fn test_read_patterns() {
        // Setup: Create a temporary file with some patterns
        let temp_file_path = Path::new("temp_patterns.txt");
        let mut temp_file = File::create(&temp_file_path).expect("Failed to create temp file");
        writeln!(temp_file, "pattern1\npattern2").expect("Failed to write to temp file");

        // Test: Read patterns from the file
        let patterns = read_patterns(Some(&temp_file_path.to_path_buf()));
        assert_eq!(patterns, vec!["pattern1", "pattern2"]);

        // Clean up: Remove the temporary file
        std::fs::remove_file(temp_file_path).expect("Failed to delete temp file");
    }

    // Test for `build_regex` function
    #[test]
    fn test_build_regex() {
        assert!(build_regex(&"\\d+".to_string()).is_ok());
        assert!(build_regex(&"[InvalidRegex".to_string()).is_err());
    }
}

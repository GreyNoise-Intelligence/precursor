mod precursor;

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

extern crate atomic_counter;
extern crate base64;
extern crate clap;
extern crate dashmap;
extern crate indicatif;
extern crate jaq_core;
extern crate pcre2;
extern crate rayon;
extern crate serde_json;
extern crate xxhash_rust;

use crate::precursor::tlsh::*;

use atomic_counter::{AtomicCounter, ConsistentCounter};
use base64::engine::{general_purpose::STANDARD, Engine};
use clap::{
    builder::PathBufValueParser, value_parser, Arg, ArgAction, ArgMatches, ColorChoice, Command,
};
use dashmap::DashMap;

use jaq_core::{parse, Ctx, Definitions, RcIter, Val};
use pcre2::bytes::{Regex, RegexBuilder};
use rayon::prelude::*;
use serde_json::{from_str, json, to_string, Map, Number, Value};

use xxhash_rust::xxh3::xxh3_64;

// Argument constants for CLI flags
const STATS: &str = "stats";
const TLSH: &str = "tlsh";
const TLSH_ALGORITHM: &str = "tlsh-algorithm";
const TLSH_DIFF: &str = "tlsh-diff";
const TLSH_LENGTH: &str = "tlsh-length";
const TLSH_DISTANCE: &str = "tlsh-distance";
const TLSH_SIM_ONLY: &str = "tlsh-sim-only";
const INPUT_FOLDER: &str = "input-folder";
const INPUT_MODE: &str = "input-mode";
const INPUT_BLOB: &str = "input-blob";
const INPUT_MODE_BASE64: &str = "base64";
const INPUT_MODE_STRING: &str = "string";
const INPUT_MODE_HEX: &str = "hex";
const INPUT_JSON_KEY: &str = "input-json-key";
const PATTERN_FILE: &str = "pattern-file";
const PATTERN: &str = "pattern";

fn main() {
    // Start execution timer
    let start = Instant::now();

    // Stats Variables
    let counter_inputs = Arc::new(ConsistentCounter::new(0));
    let counter_pcre_patterns = Arc::new(ConsistentCounter::new(0));
    let counter_tlsh_hashes = Arc::new(ConsistentCounter::new(0));
    let counter_tlsh_similarites = Arc::new(ConsistentCounter::new(0));
    let counter_pcre_matches = Arc::new(DashMap::new());
    let counter_pcre_matches_total = Arc::new(ConsistentCounter::new(0));
    let counter_unique_payloads = Arc::new(Mutex::new(HashSet::new()));
    let vec_payload_size_matched: Arc<Mutex<Vec<i64>>> = Arc::new(Mutex::new(Vec::new()));
    let vec_payload_size: Arc<Mutex<Vec<i64>>> = Arc::new(Mutex::new(Vec::new()));
    let vec_tlsh_disance: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));

    // Create a list to store tlsh::Tlsh objects
    let tlsh_list: Vec<TlshHashInstance> = Vec::new();

    // Create map store payload reports by xxh3_64 hash
    let payload_reports = Map::new();

    // Create map store to store tlsh_reports by tlsh
    let tlsh_reports: DashMap<String, Value> = DashMap::new();

    // Create a clap::ArgMatches object to store the CLI arguments
    let cmd = Command::new("precursor")
    .about("Precursor is a regex (PCRE2) and locality sensitive hasing (TLSH) tool for labeling and finding similairites between text, hex, or base64 encoded data.")
    .color(ColorChoice::Auto)
    .long_about("Precursor currently supports the following TLSH algorithms:\n
                  1. Tlsh48_1\n
                  2. Tlsh128_1\n
                  3. Tlsh128_3\n
                  4. Tlsh256_1\n
                  5. Tlsh256_3\n
                  \n
                  The -d flag performs TLSH distance calculations between every line of input provided. This is an expensive O(2^n) operation and can consume significant amounts of memory. You can optimize this by using appropriate PCRE2 pre-filters and chosing a smaller TLSH algorithm.")
    .arg(Arg::new(PATTERN)
        .help("Specify the PCRE2 pattern to be used, it must contain a single named capture group.")
        .required(false)
        .index(1))
    .arg(Arg::new(INPUT_FOLDER)
        .short('f')
        .long(INPUT_FOLDER)
        .value_parser(PathBufValueParser::new())
        .help("Specify the path to the input folder.")
        .action(ArgAction::Set))
    .arg(Arg::new(INPUT_BLOB)
        .short('z')
        .long(INPUT_BLOB)
        .help("NOT IMPLEMENTED! - Process input as single blob instead of splitting on newlines.")
        .action(ArgAction::SetTrue))
    .arg(Arg::new(PATTERN_FILE)
        .short('p')
        .long(PATTERN_FILE)
        .value_parser(PathBufValueParser::new())
        .help("Specify the path to the file containing PCRE2 patterns, one per line, each must contain a single named capture group.")
        .action(ArgAction::Set))
    .arg(Arg::new(TLSH)
        .short('t')
        .long(TLSH)
        .help("Calculate payload tlsh hash of the input payloads.")
        .action(ArgAction::SetTrue))
    .arg(Arg::new(TLSH_ALGORITHM)
        .short('a')
        .long(TLSH_ALGORITHM)
        .help("Specify the TLSH algorithm to use. The algorithms specify the bucket size in bytes and the checksum length in bits.")
        .value_parser(["128_1", "128_3", "256_1", "256_3", "48_1"])
        .action(ArgAction::Set)
        .default_value("48_1"))
    .arg(Arg::new(TLSH_DIFF)
        .short('d')
        .long(TLSH_DIFF)
        .help("Perform TLSH distance calculations between every line of input provided. This is an expensive O(2^n) operation and can consume significant amounts of memory. You can optimize this by using appropriate PCRE2 pre-filters and chosing a smaller TLSH algorithm.")
        .action(ArgAction::SetTrue))
    .arg(Arg::new(TLSH_SIM_ONLY)
        .short('y')
        .long(TLSH_SIM_ONLY)
        .help("Only output JSON for the payloads containing TLSH similarities.")
        .action(ArgAction::SetTrue))
    .arg(Arg::new(TLSH_DISTANCE)
        .short('x')
        .long(TLSH_DISTANCE)
        .value_parser(value_parser!(i32))
        .help("Specify the TLSH distance threshold for a match.")
        .action(ArgAction::Set)
        .default_value("100"))
    .arg(Arg::new(TLSH_LENGTH)
        .short('l')
        .long(TLSH_LENGTH)
        .help("This uses a TLSH algorithm that considered the payload length.")
        .action(ArgAction::SetTrue))
    .arg(Arg::new(INPUT_MODE)
        .short('m')
        .long(INPUT_MODE)
        .help("Specify the payload mode as base64, string, or hex for stdin.")
        .value_parser([INPUT_MODE_BASE64, INPUT_MODE_STRING, INPUT_MODE_HEX])
        .action(ArgAction::Set)
        .default_value("base64"))
    .arg(Arg::new(INPUT_JSON_KEY)
        .short('j')
        .long(INPUT_JSON_KEY)
        .help("Specify the JQ-like pattern for parsing the input from the JSON input.")
        .action(ArgAction::Set))
    .arg(Arg::new(STATS)
        .short('s')
        .long(STATS)
        .help("Output statistics report.")
        .action(ArgAction::SetTrue));

    let args = cmd.get_matches();

    let tlsh_list = Mutex::new(tlsh_list);
    let payload_reports = Mutex::new(payload_reports);

    #[allow(unused_assignments)]
    // This is valid because of the rayon usesage via the par_iter() method
    let mut patterns: Vec<String> = Vec::new();
    if args.contains_id(PATTERN_FILE) {
        let pattern_file = args
            .get_one::<std::path::PathBuf>(PATTERN_FILE)
            .expect("Unable to read pattern file");
        patterns = read_patterns(Some(pattern_file));
    } else {
        let pattern = args
            .get_one::<String>(PATTERN)
            .expect("Unable to read pattern");
        patterns = vec![pattern.to_string()];
    }

    counter_pcre_patterns.add(patterns.len());

    if args.contains_id(INPUT_FOLDER) {
        let path = args
            .get_one::<std::path::PathBuf>(INPUT_FOLDER)
            .expect("Unable to read input folder");
        if path.is_dir() {
            for entry in std::fs::read_dir(path).expect("Unable to read directory") {
                let entry = entry.expect("Unable to read entry");
                let file_path: PathBuf = entry.path();
                println!("Processing file: {}", file_path.display());
                if file_path.is_file() {
                    let file = std::fs::File::open(&file_path).expect("Unable to open file");
                    let reader = std::io::BufReader::new(file);
                    for line in reader.lines() {
                        let line = line.expect("Unable to read line");
                        handle_line(
                            &line,
                            &patterns,
                            &args,
                            &tlsh_list,
                            &payload_reports,
                            &counter_pcre_matches,
                            &counter_tlsh_hashes,
                            &vec_payload_size,
                            &vec_payload_size_matched,
                            &counter_unique_payloads,
                            &counter_pcre_matches_total,
                        );
                    }
                }
            }
        } else {
            println!("-f path must be a folder");
        }
    } else {
        let stdin = io::stdin();
        stdin
            .lock()
            .lines()
            .filter_map(Result::ok)
            .collect::<Vec<String>>()
            .par_iter()
            .for_each(|line| {
                counter_inputs.inc();
                handle_line(
                    line,
                    &patterns,
                    &args,
                    &tlsh_list,
                    &payload_reports,
                    &counter_pcre_matches,
                    &counter_tlsh_hashes,
                    &vec_payload_size,
                    &vec_payload_size_matched,
                    &counter_unique_payloads,
                    &counter_pcre_matches_total,
                );
            });
    }

    if args.get_flag(TLSH_DIFF) {
        run_hash_diffs(
            &tlsh_list,
            &args,
            &tlsh_reports,
            &counter_tlsh_similarites,
            &vec_tlsh_disance,
        );
    }

    generate_reports(&tlsh_reports, &payload_reports, &args);

    if args.get_flag(STATS) {
        // TODO: Potentially optimize so that we don't waist CPU on creation of stats (counter, incrementers, etc.) unless this flag is passed.
        let default_empty = 0;
        let end = Instant::now();
        let duration = end.duration_since(start);
        let duration_in_seconds = duration.as_secs_f32();
        let formated_duration: String = format!("{:.2}", duration_in_seconds);

        // Payloads Matched
        let payload_sizes_matched = vec_payload_size_matched.lock().unwrap();
        let avg_payload_size_matched =
            payload_sizes_matched.iter().sum::<i64>() as f64 / payload_sizes_matched.len() as f64;
        let min_payload_size_matched = payload_sizes_matched.iter().min().unwrap_or(&default_empty);
        let max_payload_size_matched = payload_sizes_matched.iter().max().unwrap_or(&default_empty);
        let mut sorted_payload_sizes_matched = payload_sizes_matched.clone();
        sorted_payload_sizes_matched.sort();
        let payload_sizes_matched_len = payload_sizes_matched.len();
        let p95_payload_size_matched = if payload_sizes_matched_len > 1 {
            sorted_payload_sizes_matched[(payload_sizes_matched_len * 95 / 100) - 1]
        } else if payload_sizes_matched_len == 1 {
            sorted_payload_sizes_matched[0]
        } else {
            default_empty
        };
        let total_payload_size_matched = payload_sizes_matched.iter().sum::<i64>();

        // Raw Payloads
        let payload_sizes = vec_payload_size.lock().unwrap();
        let avg_payload_size =
            payload_sizes.iter().sum::<i64>() as f64 / payload_sizes.len() as f64;
        let min_payload_size = payload_sizes.iter().min().unwrap_or(&default_empty);
        let max_payload_size = payload_sizes.iter().max().unwrap_or(&default_empty);
        let mut sorted_payload_sizes = payload_sizes.clone();
        sorted_payload_sizes.sort();
        let payload_sizes_len = payload_sizes.len();
        let p95_payload_size = if payload_sizes_len > 1 {
            sorted_payload_sizes[(payload_sizes_len * 95 / 100) - 1]
        } else {
            sorted_payload_sizes[0]
        };

        let total_payload_size = payload_sizes.iter().sum::<i64>();

        let processing_rate: String;
        if duration.as_secs() < 1 {
            processing_rate = format!(
                "{}/ms",
                format_size(total_payload_size / duration.as_millis() as i64)
            );
        } else {
            processing_rate = format!(
                "{}/s",
                format_size(total_payload_size / duration.as_secs() as i64)
            );
        }
        let default_empty_32 = 0_i32;
        let default_empty_str = std::string::String::new();
        // TLSH Hashes
        let mut compare_json: Value = Value::Null;
        let mut matches_json_array = Vec::new();
        for entry in counter_pcre_matches.iter() {
            let key = entry.key();
            let value = entry.value();
            let json_object: Value = json!({
                "Name": key,
                "Matches": *value
            });
            matches_json_array.push(json_object);
        }
        let matches_json = Value::Array(matches_json_array);
        let tlsh_distances: std::sync::MutexGuard<'_, Vec<i32>> = vec_tlsh_disance.lock().unwrap();
        if tlsh_distances.len() > 2 {
            let avg_tlsh_distance =
                tlsh_distances.iter().sum::<i32>() as f32 / tlsh_distances.len() as f32;
            let min_tlsh_distance = tlsh_distances.iter().min().unwrap_or(&default_empty_32);
            let max_tlsh_distance = tlsh_distances.iter().max().unwrap_or(&default_empty_32);
            let mut sorted_tlsh_distances = tlsh_distances.clone();
            sorted_tlsh_distances.sort();
            let tlsh_distances_len = tlsh_distances.len();
            let p95_tlsh_distance = if tlsh_distances_len > 1 {
                sorted_tlsh_distances[(tlsh_distances_len * 95 / 100) - 1]
            } else {
                sorted_tlsh_distances[0]
            };
            compare_json = json!({
                "Similarities": counter_tlsh_similarites.get(),
                "AvgDistance": format!("{:.0}", avg_tlsh_distance),
                "MinDistance": *min_tlsh_distance,
                "MaxDistance": *max_tlsh_distance,
                "P95Distance": p95_tlsh_distance,
            });
        }

        // Create a JSON object for the stats
        let stats = json!({
            "---PRECURSOR_STATISTICS---": "This JSON is output to STDERR so that you can parse stats seperate from the primary output.",
            "Input": {
                        "Count": counter_inputs.get(),
                        "Unique": counter_unique_payloads.lock().unwrap().len(),
                        "AvgSize": format!("{:.0}", avg_payload_size),
                        "MinSize": *min_payload_size,
                        "MaxSize": *max_payload_size,
                        "P95Size": p95_payload_size,
                        "TotalSize": format_size(total_payload_size),},
            "Match": {
                        "Patterns": counter_pcre_patterns.get(),
                        "TotalMatches": counter_pcre_matches_total.get(),
                        "Matches": matches_json,
                        "HashesGenerated": counter_tlsh_hashes.get(),
                        "AvgSize": format!("{:.0}", avg_payload_size_matched),
                        "MinSize": *min_payload_size_matched,
                        "MaxSize": *max_payload_size_matched,
                        "P95Size": p95_payload_size_matched,
                        "TotalSize": format_size(total_payload_size_matched),},
            "Compare": compare_json,
            "Environment": {
                        "Version": env!("CARGO_PKG_VERSION"),
                        "DurationSeconds": formated_duration,
                        "ProcessingRate": processing_rate,
                        "InputMode": args.get_one::<String>(INPUT_MODE).unwrap(),
                        "HashFunction": args.get_one::<String>(TLSH_ALGORITHM).unwrap(),
                        "DistanceThreshold": args.get_one::<i32>(TLSH_DISTANCE).unwrap(),
                        "DiffEnabled": args.get_flag(TLSH_DIFF),
                        "OnlyOutputSimilar": args.get_flag(TLSH_SIM_ONLY),
                        "LengthEnabled": args.get_flag(TLSH_LENGTH),
                        "InputJSONKey": args.get_one::<String>(INPUT_JSON_KEY).unwrap_or(&default_empty_str),
                        },
            }
        );

        // Serialize the JSON object as a pretty-printed String
        let pretty_json = serde_json::to_string_pretty(&stats)
            .expect("Error converting JSON object to pretty-printed String");

        // Print the pretty-printed JSON to STDERR
        let mut stderr = std::io::stderr();
        writeln!(&mut stderr, "{}", pretty_json).expect("Error printing JSON to STDERR");
        stderr.flush().expect("Error flushing STDERR buffer");
    }
}

// Unpacks the reports from the shared mutex
// and performs TLSH hash lookups for the matches from the tlsh in the payload report./
fn generate_reports(
    tlsh_reports: &DashMap<String, Value>,
    payload_reports: &Mutex<Map<String, Value>>,
    args: &ArgMatches,
) {
    for (xxh3_64_sum, report) in payload_reports
        .lock()
        .expect("unable to get payload_reports")
        .iter()
    {
        if report["tlsh"] != "" && args.get_flag(TLSH_DIFF) {
            let mut report_clone = report.clone();
            let tlsh_hash: Option<&str> = report["tlsh"].as_str();
            report_clone["xxh3_64_sum"] = json!(xxh3_64_sum.as_str());
            if let Some(tlsh_hash) = tlsh_hash {
                if let Some(tlsh_similarities) = tlsh_reports.get(tlsh_hash) {
                    report_clone["tlsh_similarities"] = tlsh_similarities.value().clone();
                    // Print reports with TLSH hash and TLSH similarities.
                    println!(
                        "{}",
                        to_string(&report_clone).expect("unable to print report to string")
                    );
                    io::stdout().flush().expect("Error flushing STDOUT buffer");
                } else if !args.get_flag(TLSH_SIM_ONLY) {
                    // Print reports with TLSH hash but no TLSH similarities.
                    println!(
                        "{}",
                        to_string(&report_clone).expect("unable to print report to string")
                    );
                    io::stdout().flush().expect("Error flushing STDOUT buffer");
                }
            }
        } else if !args.get_flag(TLSH_SIM_ONLY) {
            // Print reports empty TLSH hashes
            let mut report_clone = report.clone();
            report_clone["xxh3_64_sum"] = json!(xxh3_64_sum.as_str());
            println!(
                "{}",
                to_string(&report_clone).expect("unable to print report to string")
            );
        }
    }
}

fn run_hash_diffs(
    tlsh_list: &Mutex<Vec<TlshHashInstance>>,
    args: &ArgMatches,
    tlsh_reports: &DashMap<String, Value>,
    counter_tlsh_similarites: &Arc<ConsistentCounter>,
    vec_tlsh_disance: &std::sync::Mutex<Vec<i32>>,
) {
    let tlsh_list_guard = tlsh_list.lock().unwrap();
    tlsh_list_guard
        .par_iter()
        .enumerate()
        .for_each(|(i, tlsh_i)| {
            let mut local_tlsh_map = Map::new();
            for (_j, tlsh_j) in tlsh_list_guard.iter().enumerate().skip(i + 1) {
                let include_file_length_in_calculation = args.get_flag(TLSH_LENGTH);
                let diff = tlsh_i.diff(tlsh_j, include_file_length_in_calculation);
                vec_tlsh_disance.lock().unwrap().push(diff);
                if diff
                    <= *args
                        .get_one(TLSH_DISTANCE)
                        .expect("unable to get TLSH distance argument")
                {
                    counter_tlsh_similarites.inc();
                    let tlsh_hash_lowercase = tlsh_j.hash().to_ascii_lowercase();
                    let tlsh_hash_string = String::from_utf8(tlsh_hash_lowercase);
                    let diff_number: Number = diff.into();

                    local_tlsh_map.insert(
                        tlsh_hash_string.expect("unable to convert TLSH hash to string from UTF8"),
                        Value::Number(diff_number),
                    );
                }
            }
            let tlsh_hash_lowercase = tlsh_i.hash().to_ascii_lowercase();
            let tlsh_hash_string = String::from_utf8(tlsh_hash_lowercase);
            tlsh_reports.insert(tlsh_hash_string.unwrap(), Value::Object(local_tlsh_map));
        });
}

fn read_patterns(pattern_file: Option<&PathBuf>) -> Vec<String> {
    let mut patterns = Vec::new();
    if let Some(path) = pattern_file {
        let file_contents = std::fs::read_to_string(path).unwrap();
        for line in file_contents.lines() {
            patterns.push(line.to_owned());
        }
    }
    patterns
}

fn xxh3_64_hex(input: Vec<u8>) -> (u64, String) {
    let hash = xxh3_64(&input);
    (hash, format!("{:x}", hash))
}

fn remove_wrapped_quotes(input: &str) -> &str {
    input
        .trim_start_matches(|c| c == '"' || c == '\'')
        .trim_end_matches(|c| c == '"' || c == '\'')
}

fn get_payload(line: &str, input_mode: &str) -> Vec<u8> {
    let line_with_no_wrapped_quotes = remove_wrapped_quotes(line);
    match input_mode {
        "base64" => STANDARD.decode(line_with_no_wrapped_quotes).unwrap(),
        "string" => line_with_no_wrapped_quotes.as_bytes().to_vec(),
        "hex" => hex::decode(line_with_no_wrapped_quotes).unwrap(),
        _ => panic!("{} not a supported input mode.", input_mode),
    }
}

fn format_size(size: i64) -> String {
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

fn build_regex(pattern: &String) -> Result<Regex, Box<dyn std::error::Error>> {
    let re = RegexBuilder::new()
        // NOTE: We should only enable JIT if we're going to compile all patterns into one large PCRE2 statement
        // TODO: Pass CLI flags for certain REGEX settings down to the builder.
        .jit_if_available(false)
        .multi_line(true)
        .build(pattern)?;
    Ok(re)
}

fn handle_line(
    line: &String,
    patterns: &[String],
    args: &ArgMatches,
    tlsh_list: &Mutex<Vec<TlshHashInstance>>,
    payload_reports: &Mutex<Map<String, Value>>,
    counter_pcre_matches: &Arc<DashMap<String, i64>>,
    counter_tlsh_hashes: &Arc<ConsistentCounter>,
    vec_payload_size: &std::sync::Mutex<Vec<i64>>,
    vec_payload_size_matched: &std::sync::Mutex<Vec<i64>>,
    counter_unique_payloads: &Arc<Mutex<HashSet<u64>>>,
    counter_pcre_matches_total: &Arc<ConsistentCounter>,
) {
    #[allow(unused_assignments)]
    let mut payload: Vec<u8> = Vec::new();
    #[allow(unused_assignments)]
    let mut json_clone: Value = Value::Null;
    #[allow(unused_assignments)]
    let mut line_json = Value::Null;
    if let Some(payload_key) = args.get_one::<String>(INPUT_JSON_KEY) {
        if args.contains_id(INPUT_JSON_KEY) {
            // WARNING: This logic should probably move up so we don't have to parse the input
            // JSON twice from the line.
            line_json = from_str(line).unwrap();
        } else {
            //let json_tlsh_hash_clone  = json_tlsh_hash.clone();
            line_json = Value::Object(Map::new());
        }
        json_clone = line_json.clone();

        // JQ Like parsing
        let defs = Definitions::core();
        let mut errs = Vec::new();
        let f = parse::parse(payload_key, parse::main()).0.unwrap();
        let f = defs.finish(f, Vec::new(), &mut errs);
        assert_eq!(errs, Vec::new());
        let inputs = RcIter::new(core::iter::empty());
        let mut out = f.run(Ctx::new([], &inputs), Val::from(line_json));
        match out.next() {
            Some(Ok(v)) => {
                let v_str = v.to_string();
                if args.contains_id(INPUT_MODE) {
                    let input_mode = args.get_one::<String>(INPUT_MODE).unwrap();
                    payload = get_payload(&v_str, input_mode)
                    // This is the only path because INPUT_MODE has a clap default value of base64.
                }
            }
            Some(Err(e)) => {
                eprintln!(
                    "Unable to parse JSON pattern: {:?} with error: {:?}",
                    payload_key, e
                );
            }
            None => {
                eprintln!("No valid JSON was found for pattern: {:?}", payload_key);
            }
        }
    } else {
        #[allow(unused_assignments)] // this is used below
        if args.contains_id(INPUT_MODE) {
            let input_mode = args.get_one::<String>(INPUT_MODE).unwrap();
            payload = get_payload(line, input_mode)
            // This is the only path because INPUT_MODE has a clap default value of base64.
        }
    }
    vec_payload_size.lock().unwrap().push(payload.len() as i64);

    let (xxh3_64_sum, xxh3_64_sum_string) = xxh3_64_hex(payload.clone());
    counter_unique_payloads.lock().unwrap().insert(xxh3_64_sum);

    let matched_capture_groups = Mutex::new(Value::Array(Vec::new()));

    let match_exists = Arc::new(Mutex::new(false));

    patterns.par_iter().for_each(|pattern: &String| {
        let re =
            build_regex(pattern).unwrap_or_else(|_| panic!("invalid PCRE2 found: {}", pattern));
        let result = re
            .captures_iter(payload.as_slice())
            .filter_map(|res| res.ok())
            .any(|caps| {
                vec_payload_size_matched
                    .lock()
                    .unwrap()
                    .push(payload.len() as i64);
                counter_pcre_matches_total.inc();
                let mut found_match = false;
                for name in re.capture_names() {
                    if let Some(name) = name {
                        if caps.name(name).is_some() {
                            // Here we increment a counter for each of the capture group names from the PCRE2 patterns.
                            let mut count =
                                counter_pcre_matches.entry(name.to_string()).or_insert(0);
                            *count += 1;
                            let mut matched_capture_groups = matched_capture_groups.lock().unwrap();
                            matched_capture_groups
                                .as_array_mut()
                                .unwrap()
                                .push(Value::String(name.to_string()));
                            found_match = true;
                        }
                    }
                }
                found_match
            });
        if result {
            *match_exists.lock().unwrap() = true;
        }
    });

    let mut json_tlsh_hash: Value = Value::String(String::new());
    let tlsh_algorithm = args.get_one::<String>(TLSH_ALGORITHM).unwrap();
    if *match_exists.lock().unwrap() {
        // We only calculate TLSH hashes and push to the global TLSH list
        // If the payload passes the pattern_match gate
        // This helps us acchieve a massive reduction in work for TLSH computation
        if args.get_flag(TLSH) || args.get_flag(TLSH_DIFF) || args.get_flag(TLSH_LENGTH) {
            match calculate_tlsh_hash(payload.as_slice(), tlsh_algorithm) {
                Ok(hash) => {
                    counter_tlsh_hashes.inc();
                    let cloned_hash = hash.hash().clone();
                    tlsh_list.lock().unwrap().push(hash);
                    let tlsh_hash_lowercase = cloned_hash.to_ascii_lowercase();
                    let tlsh_hash_string = String::from_utf8(tlsh_hash_lowercase);
                    json_tlsh_hash = Value::String(tlsh_hash_string.unwrap());
                }
                Err(_err) => {
                    // Handle the error by printing an error message
                    //println!("Error calculating TLSH hash: {}", err);
                }
            };
        }

        /*
        Create JSON output for payload only when match exists
        */
        let json_tlsh_hash_clone = json_tlsh_hash.clone();
        if json_tlsh_hash_clone.as_str().is_none() {
            json_clone["tlsh"] = Value::String(String::new());
        } else {
            json_clone["tlsh"] = json_tlsh_hash.clone();
        }
        json_clone["tags"] = matched_capture_groups.lock().unwrap().clone();
        // This is where we insert the finished per-payload report
        payload_reports
            .lock()
            .unwrap()
            .insert(xxh3_64_sum_string, json_clone);
    }
}

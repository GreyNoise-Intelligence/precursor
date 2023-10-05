use std::io::{self, BufRead};
use std::path::PathBuf;
use clap::builder::PathBufValueParser;
use clap::{Arg, Command, ColorChoice, ArgMatches, ArgAction, value_parser};
use pcre2::bytes::Regex;
use serde_json::{from_str, to_string, Value, Map, Number, json};
use tlsh2;
use std::error::Error;
use std::fmt;
use base64::engine::Engine;
use base64::engine::general_purpose::STANDARD;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use dashmap::DashMap;
use atomic_counter::{AtomicCounter, ConsistentCounter};
use std::time::Instant;
use std::io::Write;
use sha2::{Sha256, Digest};
use hex;

// Argument constants for CLI flags
const STATS: &str = "stats";
const TLSH: &str = "tlsh";
const TLSH_ALGORITHM: &str = "tlsh-algorithm";
const TLSH_DIFF: &str = "tlsh-diff";
const TLSH_LENGTH: &str = "tlsh-length";
const TLSH_DISTANCE: &str = "tlsh-distance";
const TLSH_SIM_ONLY: &str = "tlsh-sim-only";
const INPUT_MODE: &str = "input-mode";
const INPUT_MODE_BASE64: &str = "base64";
const INPUT_MODE_STRING: &str = "string";
const INPUT_MODE_HEX: &str = "hex";
const INPUT_JSON_KEY: &str = "input-json-key";
const PATTERN_FILE: &str = "pattern-file";
const PATTERN: &str = "pattern";

enum TlshHashInstance {
    Tlsh48_1(tlsh2::Tlsh48_1),
    Tlsh128_1(tlsh2::Tlsh128_1),
    Tlsh128_3(tlsh2::Tlsh128_3),
    Tlsh256_1(tlsh2::Tlsh256_1),
    Tlsh256_3(tlsh2::Tlsh256_3),
}

enum TlshBuilderInstance {
    Tlsh48_1(tlsh2::TlshBuilder48_1),
    Tlsh128_1(tlsh2::TlshBuilder128_1),
    Tlsh128_3(tlsh2::TlshBuilder128_3),
    Tlsh256_1(tlsh2::TlshBuilder256_1),
    Tlsh256_3(tlsh2::TlshBuilder256_3),
}

impl TlshHashInstance {
    fn diff(&self, other: &Self, include_file_length: bool) -> i32 {
        match (self, other) {
            (TlshHashInstance::Tlsh48_1(hash1), TlshHashInstance::Tlsh48_1(hash2)) => {
                hash1.diff(hash2, include_file_length)
            }
            (TlshHashInstance::Tlsh128_1(hash1), TlshHashInstance::Tlsh128_1(hash2)) => {
                hash1.diff(hash2, include_file_length)
            }
            (TlshHashInstance::Tlsh128_3(hash1), TlshHashInstance::Tlsh128_3(hash2)) => {
                hash1.diff(hash2, include_file_length)
            }
            (TlshHashInstance::Tlsh256_1(hash1), TlshHashInstance::Tlsh256_1(hash2)) => {
                hash1.diff(hash2, include_file_length)
            }
            (TlshHashInstance::Tlsh256_3(hash1), TlshHashInstance::Tlsh256_3(hash2)) => {
                hash1.diff(hash2, include_file_length)
            }
            _ => panic!("Incompatible hash types"),
        }
    }

    fn hash(&self) -> Vec<u8> {
        match self {
            TlshHashInstance::Tlsh48_1(hash) => hash.hash().to_vec(),
            TlshHashInstance::Tlsh128_1(hash) => hash.hash().to_vec(),
            TlshHashInstance::Tlsh128_3(hash) => hash.hash().to_vec(),
            TlshHashInstance::Tlsh256_1(hash) => hash.hash().to_vec(),
            TlshHashInstance::Tlsh256_3(hash) => hash.hash().to_vec(),
        }
    }
}


impl TlshBuilderInstance {
    fn update(&mut self, data: &[u8]) {
        match self {
            TlshBuilderInstance::Tlsh48_1(builder) => builder.update(data),
            TlshBuilderInstance::Tlsh128_1(builder) => builder.update(data),
            TlshBuilderInstance::Tlsh128_3(builder) => builder.update(data),
            TlshBuilderInstance::Tlsh256_1(builder) => builder.update(data),
            TlshBuilderInstance::Tlsh256_3(builder) => builder.update(data),
        }
    }

    fn build(self) ->Option<TlshHashInstance> {
        match self {
            TlshBuilderInstance::Tlsh48_1(builder) => builder.build().map(TlshHashInstance::Tlsh48_1),
            TlshBuilderInstance::Tlsh128_1(builder) => builder.build().map(TlshHashInstance::Tlsh128_1),
            TlshBuilderInstance::Tlsh128_3(builder) => builder.build().map(TlshHashInstance::Tlsh128_3),
            TlshBuilderInstance::Tlsh256_1(builder) => builder.build().map(TlshHashInstance::Tlsh256_1),
            TlshBuilderInstance::Tlsh256_3(builder) => builder.build().map(TlshHashInstance::Tlsh256_3),
        }
    }
}


#[derive(Debug)]
struct TlshCalculationError {
    message: String,
}

impl fmt::Display for TlshCalculationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for TlshCalculationError {}

fn main() {
    // Start execution timer 
    let start = Instant::now();
    
    // Stats Variables
    let counter_inputs = Arc::new(ConsistentCounter::new(0));
    let counter_pcre_patterns = Arc::new(ConsistentCounter::new(0));
    let counter_pcre_matches = Arc::new(ConsistentCounter::new(0));
    let counter_tlsh_hashes = Arc::new(ConsistentCounter::new(0));
    let counter_tlsh_similarites = Arc::new(ConsistentCounter::new(0));
    let vec_payload_size_matched: Arc<Mutex<Vec<i64>>> = Arc::new(Mutex::new(Vec::new()));
    let vec_payload_size: Arc<Mutex<Vec<i64>>> = Arc::new(Mutex::new(Vec::new()));
    let vec_tlsh_disance: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
    
    // Create a list to store tlsh::Tlsh objects
    let tlsh_list: Vec<TlshHashInstance> = Vec::new();

    // Create map store payload reports by sha256_sum
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
    .arg(Arg::new(PATTERN_FILE)
        .short('f')
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
        .help("Specify the key for the JSON STDIN value that contains the payload.")
        .action(ArgAction::Set))
    .arg(Arg::new(STATS)
        .short('s')
        .long(STATS)
        .help("Output statistics report.")
        .action(ArgAction::SetTrue));

    let args = cmd.get_matches();

    let tlsh_list = Mutex::new(tlsh_list);
    let payload_reports = Mutex::new(payload_reports);
    let stdin = io::stdin();

    #[allow(unused_assignments)] // This is valid because of the rayon usesage via the par_iter() method
    let mut patterns: Vec<String> = Vec::new();
    if args.contains_id(PATTERN_FILE) {
        let pattern_file = args.get_one::<std::path::PathBuf>(PATTERN_FILE).unwrap();
        patterns = read_patterns(Some(pattern_file));
    } else {
        let pattern = args.get_one::<String>(PATTERN).unwrap();
        patterns = vec![pattern.to_string()];
    }

    counter_pcre_patterns.add(patterns.len());

    stdin
        .lock()
        .lines()
        .filter_map(Result::ok)
        .collect::<Vec<String>>()
        .par_iter()
        .for_each(|line| {
            counter_inputs.inc();
            vec_payload_size.lock().unwrap().push(line.len() as i64);
            handle_line(
                &line,
                &patterns,
                &args,
                &tlsh_list,
                &payload_reports,
                &counter_pcre_matches,
                &counter_tlsh_hashes,
                &vec_payload_size_matched
            );
        });

    if args.get_flag(TLSH_DIFF) {
        run_hash_diffs(&tlsh_list, &args, &tlsh_reports, &counter_tlsh_similarites, &vec_tlsh_disance);
    }


    generate_reports(&tlsh_reports, &payload_reports, &args);

    if args.get_flag(STATS){
        let end = Instant::now();
        let duration = end.duration_since(start);
        let duration_in_seconds = duration.as_secs_f32();
        let formated_duration: String = format!("{:.2}", duration_in_seconds);

        // Payloads Matched
        let payload_sizes_matched = vec_payload_size_matched.lock().unwrap();
        let avg_payload_size_matched = payload_sizes_matched.iter().sum::<i64>() as f64 / payload_sizes_matched.len() as f64;
        let min_payload_size_matched = payload_sizes_matched.iter().min().unwrap();
        let max_payload_size_matched = payload_sizes_matched.iter().max().unwrap();
        let mut sorted_payload_sizes_matched = payload_sizes_matched.clone();
        sorted_payload_sizes_matched.sort();
        let p95_payload_size_matched = sorted_payload_sizes_matched[(payload_sizes_matched.len() * 95 / 100) - 1];
        let total_payload_size_matched = payload_sizes_matched.iter().sum::<i64>();
        
        // Raw Payloads
        let payload_sizes = vec_payload_size.lock().unwrap();
        let avg_payload_size = payload_sizes.iter().sum::<i64>() as f64 / payload_sizes.len() as f64;
        let min_payload_size = payload_sizes.iter().min().unwrap();
        let max_payload_size = payload_sizes.iter().max().unwrap();
        let mut sorted_payload_sizes = payload_sizes.clone();
        sorted_payload_sizes.sort();
        let p95_payload_size = sorted_payload_sizes[(payload_sizes.len() * 95 / 100) - 1];
        let total_payload_size = payload_sizes.iter().sum::<i64>();

        // TLSH Hashes
        let tlsh_distances: std::sync::MutexGuard<'_, Vec<i32>> = vec_tlsh_disance.lock().unwrap();
        let avg_tlsh_distance = tlsh_distances.iter().sum::<i32>() as f32 / tlsh_distances.len() as f32;
        let min_tlsh_distance = tlsh_distances.iter().min().unwrap();
        let max_tlsh_distance = tlsh_distances.iter().max().unwrap();
        let mut sorted_tlsh_distances = tlsh_distances.clone();
        sorted_tlsh_distances.sort();
        let p95_tlsh_distance = sorted_tlsh_distances[(tlsh_distances.len() * 95 / 100) - 1];

        
        // Create a JSON object for the stats
        let stats = json!({
            "---PRECURSOR_STATISTICS---": "This JSON is output to STDERR so that you can parse stats seperate from the primary output.",
            "Inputs": {
                        "Count": counter_inputs.get(), 
                        "AvgSize": avg_payload_size.round(),
                        "MinSize": *min_payload_size,
                        "MaxSize": *max_payload_size,
                        "P95Size": p95_payload_size,
                        "TotalSize": format_size(total_payload_size),},
            "Match": {
                        "Patterns": counter_pcre_patterns.get(), 
                        "Matches": counter_pcre_matches.get(), 
                        "Unique": payload_reports.lock().unwrap().len(),
                        "HashesGenerated": counter_tlsh_hashes.get(),
                        "AvgSize": avg_payload_size_matched.round(),
                        "MinSize": *min_payload_size_matched,
                        "MaxSize": *max_payload_size_matched,
                        "P95Size": p95_payload_size_matched,
                        "TotalSize": format_size(total_payload_size_matched),},
            "Compare": {
                        "Similarities": counter_tlsh_similarites.get(), 
                        "AvgDistance": avg_tlsh_distance.round(),
                        "MinDistance": *min_tlsh_distance,
                        "MaxDistance": *max_tlsh_distance,
                        "P95Distance": p95_tlsh_distance,},
            "Runtime": {
                        "Version": env!("CARGO_PKG_VERSION"),
                        "DurationSeconds": formated_duration,
                        "Mode": args.get_one::<String>(INPUT_MODE).unwrap(),
            },
            }
        );

        // Serialize the JSON object as a pretty-printed String
        let pretty_json = serde_json::to_string_pretty(&stats)
        .expect("Error converting JSON object to pretty-printed String");

        // Print the pretty-printed JSON to STDERR
        let mut stderr = std::io::stderr();
        writeln!(&mut stderr, "{}", pretty_json).expect("Error printing JSON to STDERR");
    }
}

// Unpacks the reports from the shared mutex 
// and performs TLSH hash lookups for the matches from the tlsh in the payload report./
fn generate_reports(tlsh_reports: &DashMap<String, Value>, payload_reports: &Mutex<Map<String, Value>>, args: &ArgMatches) {
    for (_sha256_sum, report) in payload_reports.lock().unwrap().iter() {
        if report["tlsh"] != "" && args.get_flag(TLSH_DIFF) {
            let mut report_clone = report.clone();
            let tlsh_hash = report["tlsh"].as_str();
            if let Some(tlsh_hash) = tlsh_hash {
                if let Some(tlsh_similarities) = tlsh_reports.get(tlsh_hash) {
                    report_clone["tlsh_similarities"] = tlsh_similarities.value().clone();
                    // Print reports with TLSH hash and TLSH similarities.
                    println!("{}", to_string(&report_clone).unwrap());
                } else if !args.get_flag(TLSH_SIM_ONLY) {
                    // Print reports with TLSH hash but no TLSH similarities.
                    println!("{}", to_string(&report_clone).unwrap());
                }
            }
        } else if !args.get_flag(TLSH_SIM_ONLY) {
            // Print reports empty TLSH hashes
            println!("{}", to_string(&report).unwrap());
        }
    }
}

fn run_hash_diffs(tlsh_list: &Mutex<Vec<TlshHashInstance>>, 
                  args: &ArgMatches, 
                  tlsh_reports: &DashMap<String, Value>, 
                  counter_tlsh_similarites: &Arc<ConsistentCounter>,
                  vec_tlsh_disance: &std::sync::Mutex<Vec<i32>>,
                  ) {

    let tlsh_list_guard = tlsh_list.lock().unwrap();
    tlsh_list_guard.par_iter().enumerate().for_each(|(i, tlsh_i)| {
        let mut local_tlsh_map = Map::new();
        for (_j, tlsh_j) in tlsh_list_guard.iter().enumerate().skip(i + 1) {
            let include_file_length_in_calculation = args.get_flag(TLSH_LENGTH);
            let diff = tlsh_i.diff(tlsh_j, include_file_length_in_calculation);
            if diff <= *args.get_one(TLSH_DISTANCE).unwrap() {
                counter_tlsh_similarites.inc();
                vec_tlsh_disance.lock().unwrap().push(diff);
                let tlsh_hash_lowercase = tlsh_j.hash().to_ascii_lowercase();
                let tlsh_hash_string = String::from_utf8(tlsh_hash_lowercase);
                let diff_number: Number = diff.into();

                local_tlsh_map.insert(tlsh_hash_string.unwrap(), Value::Number(diff_number));
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
            let raw_string = r#""#.to_owned() + line + r#""#;
            patterns.push(raw_string);
        }
    }
    patterns
}

fn calculate_tlsh_hash(payload: &[u8], args: &ArgMatches) -> Result<TlshHashInstance, TlshCalculationError> {
    if payload.len() < 49 {
        return Err(TlshCalculationError {
            message: "Payload must be at least 48 bytes".to_owned(),
        });
    }
    let tlsh_algorithm = args.get_one::<String>(TLSH_ALGORITHM).unwrap();
    let mut builder: TlshBuilderInstance = match tlsh_algorithm.as_str() {
        "48_1" => TlshBuilderInstance::Tlsh48_1(tlsh2::TlshBuilder48_1::new()),
        "128_1" => TlshBuilderInstance::Tlsh128_1(tlsh2::TlshBuilder128_1::new()),
        "128_3" => TlshBuilderInstance::Tlsh128_3(tlsh2::TlshBuilder128_3::new()),
        "256_1" => TlshBuilderInstance::Tlsh256_1(tlsh2::TlshBuilder256_1::new()),
        "256_3" => TlshBuilderInstance::Tlsh256_3(tlsh2::TlshBuilder256_3::new()),
        _ => TlshBuilderInstance::Tlsh48_1(tlsh2::TlshBuilder48_1::new()),
    };
    builder.update(payload);
    if let Some(tlsh_hash) = builder.build() {
        Ok(tlsh_hash)
    } else {
        let error_message: String =format!("Failed to calculate TLSH hash for  {:?}", payload);
        Err(TlshCalculationError {
            message: error_message,
        })
    }
}


fn sha256_hex(input: Vec<u8>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&input);
    let result = hasher.finalize();
    hex::encode(result)
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

fn  handle_line(line: &String, 
               patterns: &[String], 
               args: &ArgMatches, 
               tlsh_list: &Mutex<Vec<TlshHashInstance>>,
               payload_reports: &Mutex<Map<String, Value>>,
               counter_pcre_matches: &Arc<ConsistentCounter>,
               counter_tlsh_hashes: &Arc<ConsistentCounter>,
               vec_payload_size_matched: &std::sync::Mutex<Vec<i64>>,
            ) {
    #[allow(unused_assignments)]
    let mut payload: Vec<u8> = Vec::new();
    if let Some(payload_key) = args.get_one::<String>(INPUT_JSON_KEY) {
        #[allow(unused_assignments)] // this is used below
        let line_json: Value = from_str(&line).unwrap();
        if args.contains_id(INPUT_MODE) {
            let input_mode = args.get_one::<String>(INPUT_MODE).unwrap();
            if input_mode == "base64" {
                let payloadb64: &str = line_json[payload_key].as_str().unwrap();
                payload = STANDARD.decode(payloadb64).unwrap();
            } else if input_mode == "string" {
                payload = line_json[payload_key].as_str().unwrap().as_bytes().to_vec();
            } else if input_mode == "hex" {
                let payloadhex: &str = line_json[payload_key].as_str().unwrap();
                payload = hex::decode(payloadhex).unwrap();
            } else {
                panic!("{} not a supported input mode.", input_mode);
            } 
        } else {
            let payloadb64: &str = line_json[payload_key].as_str().unwrap();
            payload = STANDARD.decode(payloadb64).unwrap();
        }
    } else {
        #[allow(unused_assignments)] // this is used below
        if args.contains_id(INPUT_MODE) {
            let input_mode = args.get_one::<String>(INPUT_MODE).unwrap();
            if input_mode == "base64" {
                let payloadb64: &str = line;
                payload = STANDARD.decode(payloadb64).unwrap();
            } else if input_mode == "string" {
                payload = line.as_bytes().to_vec();
            } else if input_mode == "hex" {
                let payloadhex: &str = line;
                payload = hex::decode(payloadhex).unwrap();
            } else {
                panic!("{} not a supported input mode.", input_mode);
            } 
        } else {
            let payloadb64: &str = line;
            payload = STANDARD.decode(payloadb64).unwrap();
        }
    }  

    let sha256_sum = sha256_hex(payload.clone());

    let matched_capture_groups = Mutex::new(Value::Array(Vec::new()));

    let match_exists = patterns
        .par_iter()
        .map(|pattern| {
            let re = Regex::new(&pattern).unwrap();
            re.captures_iter(payload.as_slice())
                .filter_map(|res| res.ok())
                .any(|caps| {
                    vec_payload_size_matched.lock().unwrap().push(payload.len() as i64);
                    for name in re.capture_names() {
                        counter_pcre_matches.inc();
                        if let Some(name) = name {
                                if caps.name(name).is_some() {
                                let mut matched_capture_groups = matched_capture_groups.lock().unwrap();
                                matched_capture_groups.as_array_mut().unwrap().push(Value::String(name.to_string()));
                                return true;
                            }
                        }
                    }
                    false
                })
        })
        .any(|result| result);

    let mut json_tlsh_hash: Value = Value::String(String::new());
    if match_exists {
        // We only calculate TLSH hashes and push to the global TLSH list 
        // If the payload passes the pattern_match gate
        // This helps us acchieve a massive reduction in work for TLSH computation
        if args.get_flag(TLSH) || args.get_flag(TLSH_DIFF) || args.get_flag(TLSH_LENGTH) {
            match calculate_tlsh_hash(payload.as_slice(), &args) {
                Ok(hash) => {
                    counter_tlsh_hashes.inc();
                    let cloned_hash = hash.hash().clone();
                    tlsh_list.lock().unwrap().push(hash);
                    let tlsh_hash_lowercase = cloned_hash.to_ascii_lowercase();
                    let tlsh_hash_string = String::from_utf8(tlsh_hash_lowercase);
                    json_tlsh_hash = Value::String(tlsh_hash_string.unwrap());
                },
                Err(_err) => {
                    // Handle the error by printing an error message
                    //println!("Error calculating TLSH hash: {}", err);
                },
            };
        }

        /*
        Create JSON output for payload only when match exists
        */

        #[allow(unused_assignments)]
        let mut json_clone = Value::Null;
        if args.contains_id(INPUT_JSON_KEY){
            // WARNING: This logic should probably move up so we don't have to parse the input
            // JSON twice from the line. 
            let line_json: Value = from_str(&line).unwrap();
            json_clone = line_json.clone();
        } else {
            //let json_tlsh_hash_clone  = json_tlsh_hash.clone();
            json_clone = Value::Object(Map::new());
        }

        let json_tlsh_hash_clone  = json_tlsh_hash.clone();
        if json_tlsh_hash_clone.as_str() == None {
            json_clone["tlsh"] = Value::String(String::new());
        } else {
            json_clone["tlsh"] = json_tlsh_hash.clone();
        }
        json_clone["tags"] = matched_capture_groups.lock().unwrap().clone();
         // This is where we insert the finished per-payload report
         payload_reports.lock().unwrap().insert(sha256_sum, json_clone);
    }
}
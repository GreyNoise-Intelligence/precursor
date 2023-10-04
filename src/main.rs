use std::io::{self, BufRead};
use std::path::PathBuf;
use clap::{Arg, Command, ArgMatches, ArgAction, value_parser};
use pcre2::bytes::Regex;
use serde_json::{from_str, to_string, Value, Map, Number};
use tlsh2;
use std::error::Error;
use std::fmt;
use base64::engine::Engine;
use base64::engine::general_purpose::STANDARD;
use rayon::prelude::*;
use std::sync::Mutex;
use dashmap::DashMap;


// TODO
// 1. Add docstrings with GPT
// 2. Add optional stats output
// 3. Add ability to specify output file so you can run w/ stats output
// 4. Add ability to specify payload as base64, string, or binary input in stdin

// Argument constants for CLI flags
const TLSH: &str = "tlsh";
const TLSH_ALGORITHM: &str = "tlsh-algorithm";
const TLSH_DIFF: &str = "tlsh-diff";
const TLSH_LENGTH: &str = "tlsh-length";
const TLSH_DISTANCE: &str = "tlsh-distance";
const INPUT_MODE: &str = "input-mode";
const INPUT_JSON_KEY: &str = "input-json-key";
const PATTERN_FILE: &str = "pattern-file";
const PATTERN: &str = "pattern";
const INPUT_JSON_KEY_BASE64: &str = "payload_b64";

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
    // Create a list to store tlsh::Tlsh objects
    let tlsh_list: Vec<TlshHashInstance> = Vec::new();

    // Create map store payload reports by sha256_sum
    let payload_reports = Map::new();

    // Create map store to store tlsh_reports by tlsh
    let tlsh_reports: DashMap<String, Value> = DashMap::new();
    //let tlsh_reports = Map::new();

    // Create a clap::ArgMatches object to store the CLI arguments
    let args = Command::new("precursor")
        .about("Precursor is a PCRE2 regex engine written in Rust to parse honeypot payloads.\n\
               Precursor takes JSONLINES from STDIN and outputs JSON on STDOUT.]\n\
               A PCRE2 patternfile to be passed as the last argument and must contain only one capturegroup per line.\n\
               The JSONLINES must contain a `payload` key or be overridden with the --payload-key flag.")
        .arg(Arg::new(PATTERN)
            .short('p')
            .long(PATTERN)
            .help("Specify the PCRE2 pattern to be used, it must contain a single named capture group.")
            .required(false)
            .index(1))
        .arg(Arg::new(PATTERN_FILE)
            .short('f')
            .long(PATTERN_FILE)
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
            .help("Measure the distance between a payload and every other payload that passed through the the PCRE2 patterns.")
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
            .help("Specify the payload mode as base64, string, or binary for stdin.")
            .action(ArgAction::Set)
            .default_value("base64"))
        .arg(Arg::new(INPUT_JSON_KEY)
            .short('k')
            .long(INPUT_JSON_KEY)
            .help("Specify the key for the JSON STDIN value that contains the payload.")
            .action(ArgAction::Set)
            .default_value(INPUT_JSON_KEY_BASE64))
        .get_matches();

    let pattern_file = PathBuf::from(args.get_one::<String>(PATTERN_FILE).unwrap());
    let patterns: Vec<String> = read_patterns(Some(pattern_file));
    let stdin = io::stdin();

    let tlsh_list = Mutex::new(tlsh_list);
    let payload_reports = Mutex::new(payload_reports);
    //let tlsh_reports  = Mutex::new(tlsh_reports);
    stdin
        .lock()
        .lines()
        .filter_map(Result::ok)
        .collect::<Vec<String>>()
        .par_iter()
        .for_each(|line| {
            let line_json: Value = from_str(&line).unwrap();
            handle_line(
                &line_json,
                &patterns,
                &args,
                &tlsh_list,
                &payload_reports,
            );
        });

    if args.get_flag(TLSH_DIFF) {
        run_hash_diffs(&tlsh_list, &args, &tlsh_reports);
    }


    generate_reports(&tlsh_reports, &payload_reports, &args)

    
}

fn generate_reports(tlsh_reports: &DashMap<String, Value>, payload_reports: &Mutex<Map<String, Value>>, args: &ArgMatches) {
    for (_sha256_sum, report) in payload_reports.lock().unwrap().iter() {
        if report["tlsh"] != "" && args.get_flag(TLSH_DIFF) {
            let mut report_clone = report.clone();
            let tlsh_hash = report["tlsh"].as_str();
            if let Some(tlsh_hash) = tlsh_hash {
                if let Some(tlsh_similarities) = tlsh_reports.get(tlsh_hash) {
                    report_clone["tlsh_similarities"] = tlsh_similarities.value().clone();
                    println!("{}", to_string(&report_clone).unwrap());
                }
            }
        } else {
            println!("{}", to_string(&report).unwrap());
        }
    }
}

fn run_hash_diffs(tlsh_list: &Mutex<Vec<TlshHashInstance>>, args: &ArgMatches, tlsh_reports: &DashMap<String, Value>) {

    let tlsh_list_guard = tlsh_list.lock().unwrap();
    tlsh_list_guard.par_iter().enumerate().for_each(|(i, tlsh_i)| {
        let mut local_tlsh_map = Map::new();
        for (_j, tlsh_j) in tlsh_list_guard.iter().enumerate().skip(i + 1) {
            let include_file_length_in_calculation = args.get_flag(TLSH_LENGTH);
            let diff = tlsh_i.diff(tlsh_j, include_file_length_in_calculation);
            if diff > *args.get_one(TLSH_DISTANCE).unwrap() {
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

fn read_patterns(pattern_file: Option<PathBuf>) -> Vec<String> {
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


fn handle_line(json_line: &Value, 
               patterns: &[String], 
               args: &ArgMatches, 
               tlsh_list: &Mutex<Vec<TlshHashInstance>>,
               payload_reports: &Mutex<Map<String, Value>>,) {
    if let Some(payload_key) = args.get_one::<String>(INPUT_JSON_KEY) {
        
        let payloadb64: &str = json_line[payload_key].as_str().unwrap();
        let payload = STANDARD.decode(payloadb64).unwrap();

        let matched_capture_groups = Value::Array(Vec::new());

        let match_exists = patterns
            .par_iter()
            .map(|pattern| {
                let re = Regex::new(&pattern).unwrap();
                re.captures_iter(payload.as_slice())
                    .filter_map(|res| res.ok())
                    .any(|caps| {
                        for name in re.capture_names() {
                            if let Some(name) = name {
                                if caps.name(name).is_some() {
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
            let mut json_clone = json_line.clone();
            let json_tlsh_hash_clone  = json_tlsh_hash.clone();
            if json_tlsh_hash_clone.as_str() == None {
                json_clone["tlsh"] = Value::String(String::new());
            } else {
                json_clone["tlsh"] = json_tlsh_hash.clone();
            }
            json_clone["tags"] = matched_capture_groups;
            let sha256_sum: &str = json_line["sha256_sum"].as_str().unwrap();
            payload_reports.lock().unwrap().insert(sha256_sum.to_string(), json_clone);
        }
        
    } else {
        println!("No payload key specified");
    }  
}
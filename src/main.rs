use std::io::{self, BufRead};
use std::path::PathBuf;
use clap::{Arg, Command, ArgMatches, ArgAction, value_parser};
use pcre2::bytes::Regex;
use serde_json::{from_str, to_string, Value, Map, Number};
use tlsh2::Tlsh48_1;
use std::error::Error;
use std::fmt;
use base64::engine::Engine;
use base64::engine::general_purpose::STANDARD;

// TODO
// 1. Add docstrings with GPT

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
    let mut tlsh_list: Vec<Tlsh48_1> = Vec::new();

    // Create map store payload reports by sha256_sum
    let mut payload_reports = Map::new();

     // Create map store to store tlsh_reports by tlsh
     let mut tlsh_reports = Map::new();

    // Create a clap::ArgMatches object to store the CLI arguments
    let args = Command::new("precursor")
        .about("Precursor is a PCRE2 regex engine written in Rust to parse honeypot payloads.\n\
               Precursor takes JSONLINES from STDIN and outputs JSON on STDOUT.]\n\
               A PCRE2 patternfile to be passed as the last argument and must contain only one capturegroup per line.\n\
               The JSONLINES must contain a `payload` key or be overridden with the --payload-key flag.")
        .arg(Arg::new("file")
            .help("File to search in")
            .required(true)
            .index(1))
        .arg(Arg::new("tlsh")
            .short('t')
            .long("tlsh")
            .help("Calculate payload tlsh values using 48 buckets and a 1 byte checksum.")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("tlshdiff")
            .short('d')
            .long("tlsh-diff")
            .help("Measure the distance between a payload and every other payload of only the payloads that pass the PCRE2 pattern matching.")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("tlshthreshold")
            .short('t')
            .long("tlsh-threshold")
            .value_parser(value_parser!(i32))
            .help("Specify the TLSH distance threshold for a match.")
            .action(ArgAction::Set)
            .default_value("100"))
        .arg(Arg::new("tlshlength")
            .short('l')
            .long("tlsh-length")
            .help("This uses a TLSH algorithm that considered the payload length.")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("payload-key")
            .short('p')
            .long("payload-key")
            .help("Specify the key for the JSON STDIN value")
            .action(ArgAction::Set)
            .default_value("payload_b64"))
        .get_matches();

    let pattern_file = PathBuf::from(args.get_one::<String>("file").unwrap());
    let patterns: Vec<String> = read_patterns(Some(pattern_file));
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut line = String::new();
    while let Ok(bytes_read) = handle.read_line(&mut line) {
        if bytes_read == 0 {
            break;
        }
        let line_json: Value = from_str(&line).unwrap();
        handle_line(&line_json, &patterns, &args, &mut tlsh_list, &mut payload_reports);

        line.clear();
    }

    if args.get_flag("tlshdiff") {
        run_hash_diffs(tlsh_list, &args, &mut tlsh_reports);
    }


    generate_reports(&mut tlsh_reports, &mut payload_reports)

    
}

fn generate_reports(tlsh_reports: &mut Map<String, Value>, payload_reports: &mut Map<String, Value>){
    for (_sha256_sum, report) in payload_reports.iter() {
        if report["tlsh"] != "" {
            let mut report_clone = report.clone();
            let tlsh_hash = report["tlsh"].as_str();
            if tlsh_hash != None {
                let tlsh_similarites = tlsh_reports.get(tlsh_hash.unwrap()).unwrap();
                report_clone["tlsh_similarities"] = tlsh_similarites.clone();
                println!("{}", to_string(&report_clone).unwrap());
            }
        } else {
            println!("{}", to_string(&report).unwrap());
        }
    }
}

fn run_hash_diffs(tlsh_list: Vec<tlsh2::Tlsh<1, 32, 12>>, args: &ArgMatches, tlsh_reports: &mut Map<String, Value>) {
    for i in 0..tlsh_list.len() {
        // Create new Map for TLSH report diffs
        let mut local_tlsh_map = Map::new();
        for j in (i + 1)..tlsh_list.len() {
            if let (Some(tlsh_i), Some(tlsh_j)) = (tlsh_list.get(i), tlsh_list.get(j)) {
                let include_file_length_in_calculation = args.get_flag("tlshlength");
                let diff = tlsh_i.diff(tlsh_j, include_file_length_in_calculation);
                if diff > *args.get_one("tlshthreshold").unwrap() {
                    let tlsh_hash_lowercase = tlsh_j.hash().to_ascii_lowercase();
                    let tlsh_hash_string = String::from_utf8(tlsh_hash_lowercase);
                    let diff_number: Number = diff.into();
                    local_tlsh_map.insert(tlsh_hash_string.unwrap(), Value::Number(diff_number));                    
                } 
            } else {
                println!("Failed to calculate TLSH diff due to index out of bounds.");
            }
        }
        if let Some(base_tlsh) = tlsh_list.get(i){
            let tlsh_hash_lowercase = base_tlsh.hash().to_ascii_lowercase();
            let tlsh_hash_string = String::from_utf8(tlsh_hash_lowercase);
            tlsh_reports.insert(tlsh_hash_string.unwrap(),  Value::Object(local_tlsh_map));
        }
    }
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

fn calculate_tlsh_hash(payload: &[u8]) -> Result<tlsh2::Tlsh48_1, TlshCalculationError> {
    if payload.len() < 49 {
        return Err(TlshCalculationError {
            message: "Payload must be at least 48 bytes".to_owned(),
        });
    }
    let mut builder = tlsh2::TlshBuilder48_1::new();
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


fn handle_line(json_line: &Value, patterns: &[String], args: &ArgMatches, tlsh_list: &mut Vec<Tlsh48_1>, payload_reports: &mut Map<String, Value>) {
    if let Some(payload_key) = args.get_one::<String>("payload-key") {
        
        let payloadb64: &str = json_line[payload_key].as_str().unwrap();
        let payload = STANDARD.decode(payloadb64).unwrap();

        let mut matched_capture_groups = Value::Array(Vec::new());

        let mut match_exists: bool = false;

        for pattern in patterns {
            let re = Regex::new(&pattern).unwrap();
            for res in re.captures_iter(payload.as_slice()) {
                let caps = res.unwrap();
                for name in re.capture_names() {
                    if let Some(name) = name {
                        if let Some(_pattern_match) = caps.name(name) {
                            // Add matched capture group names to the to a JSON Value array 
                            // So they can be appended to the payload record

                            // NOTE: We may wish to output the matching bytes to an array 
                            // in a scenario where we want a ripgrep like --only-matches.
                            match_exists = true;
                            matched_capture_groups.as_array_mut().unwrap().push(Value::String(name.to_string()));
                        }
                    }
                }
            }
        }

        let mut json_tlsh_hash: Value = Value::String(String::new());
        if match_exists {
            // We only calculate TLSH hashes and push to the global TLSH list 
            // If the payload passes the pattern_match gate
            // This helps us acchieve a massive reduction in work for TLSH computation
            if args.get_flag("tlsh") || args.get_flag("tlshdiff") || args.get_flag("tlshlength") {
                match calculate_tlsh_hash(payload.as_slice()) {
                    Ok(hash) => {
                        let cloned_hash = hash.hash().clone();
                        tlsh_list.push(hash);
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
            payload_reports.insert(sha256_sum.to_string(), json_clone);
        }
        
    } else {
        println!("No payload key specified");
    }  
}
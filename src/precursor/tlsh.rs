use std::error::Error;
use std::fmt;

pub enum TlshHashInstance {
    Tlsh48_1(tlsh2::Tlsh48_1),
    Tlsh128_1(tlsh2::Tlsh128_1),
    Tlsh128_3(tlsh2::Tlsh128_3),
    Tlsh256_1(tlsh2::Tlsh256_1),
    Tlsh256_3(tlsh2::Tlsh256_3),
}

pub enum TlshBuilderInstance {
    Tlsh48_1(tlsh2::TlshBuilder48_1),
    Tlsh128_1(tlsh2::TlshBuilder128_1),
    Tlsh128_3(tlsh2::TlshBuilder128_3),
    Tlsh256_1(tlsh2::TlshBuilder256_1),
    Tlsh256_3(tlsh2::TlshBuilder256_3),
}

impl TlshHashInstance {
    pub fn diff(&self, other: &Self, include_file_length: bool) -> i32 {
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

    pub fn hash(&self) -> Vec<u8> {
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
    pub fn update(&mut self, data: &[u8]) {
        match self {
            TlshBuilderInstance::Tlsh48_1(builder) => builder.update(data),
            TlshBuilderInstance::Tlsh128_1(builder) => builder.update(data),
            TlshBuilderInstance::Tlsh128_3(builder) => builder.update(data),
            TlshBuilderInstance::Tlsh256_1(builder) => builder.update(data),
            TlshBuilderInstance::Tlsh256_3(builder) => builder.update(data),
        }
    }

    pub fn build(self) -> Option<TlshHashInstance> {
        match self {
            TlshBuilderInstance::Tlsh48_1(builder) => {
                builder.build().map(TlshHashInstance::Tlsh48_1)
            }
            TlshBuilderInstance::Tlsh128_1(builder) => {
                builder.build().map(TlshHashInstance::Tlsh128_1)
            }
            TlshBuilderInstance::Tlsh128_3(builder) => {
                builder.build().map(TlshHashInstance::Tlsh128_3)
            }
            TlshBuilderInstance::Tlsh256_1(builder) => {
                builder.build().map(TlshHashInstance::Tlsh256_1)
            }
            TlshBuilderInstance::Tlsh256_3(builder) => {
                builder.build().map(TlshHashInstance::Tlsh256_3)
            }
        }
    }
}

#[derive(Debug)]
pub struct TlshCalculationError {
    message: String,
}

impl fmt::Display for TlshCalculationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for TlshCalculationError {}

pub fn calculate_tlsh_hash(
    payload: &[u8],
    tlsh_algorithm: &String,
) -> Result<TlshHashInstance, TlshCalculationError> {
    if payload.len() < 49 {
        return Err(TlshCalculationError {
            message: "Payload must be at least 48 bytes".to_owned(),
        });
    }
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
        let error_message: String = format!("Failed to calculate TLSH hash for  {:?}", payload);
        Err(TlshCalculationError {
            message: error_message,
        })
    }
}

//! Offline file preflight. Never connects to an ECU or changes the input.
#[path = "../src/n20_integrity.rs"]
mod n20_integrity;
use sha2::{Digest, Sha256};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("Supply a BIN path")?;
    let bytes = std::fs::read(&path)?;
    let preflight = n20_integrity::require_known_image_checks(&bytes);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "path":path,"sha256":format!("{:x}",Sha256::digest(&bytes)),
            "file_preflight_passed":preflight.is_ok(),"preflight_error":preflight.as_ref().err(),
            "observations":n20_integrity::summary(&bytes),"ecu_programming_approved":false
        }))?
    );
    preflight.map_err(Into::into)
}

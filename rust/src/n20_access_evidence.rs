//! Historical same-channel Preparation 2 observations, never a reusable grant.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};
fn read(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    if !std::fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .is_file()
    {
        return Err("Preparation evidence is not a regular file".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("Preparation evidence exceeds limit".into());
    }
    Ok(bytes)
}
fn decode(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.is_ascii() {
        return Err("Invalid evidence hex".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).map_err(|e| e.to_string()))
        .collect()
}
fn requests(value: &Value) -> Result<Vec<Vec<u8>>, String> {
    serde_json::from_value(value.clone()).map_err(|e| e.to_string())
}
fn inspect(
    folder: &Path,
    vin: &str,
    live: &crate::n20_agent_state::Identity,
) -> Result<Value, String> {
    let bytes = read(&folder.join("request.json"), 1024 * 1024)?;
    let request: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let result: Value = serde_json::from_slice(&read(&folder.join("result.json"), 1024 * 1024)?)
        .map_err(|e| e.to_string())?;
    let binding = format!("{:X}", Sha256::digest(&bytes));
    if request["schema"] != "dme-owned-preparation-v1"
        || result["schema"] != "dme-owned-preparation-result-v1"
        || request["vin"] != vin
        || result["operation_binding_sha256"] != binding
        || result["completed"] != true
        || result["security_response_accepted"] != true
        || result["outcome_unknown"] != false
    {
        return Err(
            "Preparation result is incomplete, rejected or not bound to this VIN/request".into(),
        );
    }
    let f101 = decode(
        request["f101"]
            .as_str()
            .ok_or("Preparation identity data missing")?,
    )?;
    let fingerprint = super::decode_s55_dme_identity_bundle(&f101)?;
    let identity = crate::n20_agent_state::Identity {
        hardware_id: fingerprint.hardware,
        bootloader_id: fingerprint.bootloader,
        software_id: fingerprint.software,
        calibration_id: fingerprint.calibration,
    };
    if identity != *live || request["bootloader"] != live.bootloader_id {
        return Err("Preparation identity differs from fresh DME identity".into());
    }
    let plan = requests(&request["requests"])?;
    let post = requests(&request["post_key_requests"])?;
    let prefix: Vec<u8> =
        serde_json::from_value(request["security_prefix"].clone()).map_err(|e| e.to_string())?;
    crate::dme_preparation::validate(&plan, &prefix, &post)?;
    let transcript = read(&folder.join("wire.jsonl"), 8 * 1024 * 1024)?;
    let text = std::str::from_utf8(&transcript).map_err(|e| e.to_string())?;
    if !text.ends_with('\n') {
        return Err("Preparation wire evidence is truncated".into());
    }
    let mut lines = text.lines();
    let header = lines.next().ok_or("Missing preparation wire header")?;
    let value: Value = serde_json::from_str(header).map_err(|e| e.to_string())?;
    if value["schema"] != "n20-owned-wire-v1"
        || value["manifest_sha256"] != binding.to_ascii_lowercase()
    {
        return Err("Preparation wire binding differs".into());
    }
    let mut chain = format!("{:x}", Sha256::digest(header.as_bytes()));
    let mut sequence = 0u64;
    let mut pending_request: Option<Vec<u8>> = None;
    let mut exchanges = Vec::new();
    for line in lines {
        if sequence >= 10000 {
            return Err("Preparation wire record limit exceeded".into());
        }
        let outer: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        let body = outer["record"]
            .as_str()
            .ok_or("Preparation wire body missing")?;
        let digest = format!("{:x}", Sha256::digest(body.as_bytes()));
        let row: Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
        if outer["sha256"] != digest
            || row["sequence"] != sequence
            || row["previous_sha256"] != chain
            || row["target"] != 0x12
        {
            return Err("Preparation wire chain/order/route differs".into());
        }
        chain = digest;
        sequence += 1;
        let uds = decode(
            row["uds"]
                .as_str()
                .ok_or("Preparation wire bytes missing")?,
        )?;
        match row["kind"].as_str() {
            Some("intent") if pending_request.is_none() => pending_request = Some(uds),
            Some("response") => {
                let sent = pending_request
                    .as_ref()
                    .ok_or("Preparation response has no request")?;
                if uds
                    == [
                        0x7f,
                        *sent.first().ok_or("Empty preparation request")?,
                        0x78,
                    ]
                {
                    continue;
                }
                exchanges.push((pending_request.take().unwrap(), uds));
            }
            _ => return Err("Unexpected preparation wire record".into()),
        }
    }
    if pending_request.is_some() || exchanges.len() != plan.len() + 1 + post.len() {
        return Err("Preparation transcript does not complete its exact request plan".into());
    }
    let mut session = None;
    let mut session_accepted = false;
    let mut session_verified = false;
    let mut key_accepted = false;
    let mut key_in_programming = false;
    for (index, (sent, reply)) in exchanges.iter().enumerate() {
        if index < plan.len() {
            if sent != &plan[index] {
                return Err("Preparation transcript request differs from plan".into());
            }
        } else if index == plan.len() {
            if !sent.starts_with(&[0x27, 0x12]) || sent.len() <= 2 || sent.len() > 4094 {
                return Err("Preparation security response is malformed".into());
            }
        } else if sent != &post[index - plan.len() - 1] {
            return Err("Preparation post-key request differs".into());
        }
        if index < plan.len() && crate::dme_preparation::flash_mode_refused(sent, reply) {
            continue;
        }
        match sent.as_slice() {
            [0x10, value] => {
                crate::n20_session_timing::parse(reply, *value)?;
                session = Some(*value);
                session_verified = false;
                if *value == 2 {
                    session_accepted = true;
                }
            }
            [0x27, 0x11, ..] => {
                if reply.len() != 10 || !reply.starts_with(&[0x67, 0x11]) {
                    return Err("Preparation challenge was not accepted".into());
                }
            }
            [0x27, 0x12, ..] => {
                if reply != &[0x67, 0x12] {
                    return Err("Preparation calculated key was not accepted".into());
                }
                key_accepted = true;
                key_in_programming = session == Some(2);
                // A pre-key session read does not verify the post-key state.
                session_verified = false;
            }
            [0x22, 0xf1, 0x86] => {
                let reported = crate::dme_preparation::active_session(&reply)?;
                if session.is_some_and(|expected| expected != reported) {
                    return Err(
                        "Preparation active session contradicts its accepted session request"
                            .into(),
                    );
                }
                session = Some(reported);
                session_verified = reported == 2;
            }
            _ => {
                let expected = crate::dme_preparation::response_prefix(sent)?;
                if !reply.starts_with(&expected)
                    || (sent.first() == Some(&0x22) && reply.len() <= 3)
                {
                    return Err("Preparation response did not positively match request".into());
                }
            }
        }
    }
    Ok(
        json!({"schema":"n20-programming-access-observation-v1","status":if session_accepted&&key_in_programming{"observed"}else{"security_only"},
        "vin":vin,"identity":identity,"directory":folder.to_string_lossy(),"request_sha256":binding,"wire_sha256":format!("{:x}",Sha256::digest(&transcript)),
        "programming_session_accepted":session_accepted,"security_response_accepted":key_accepted,"last_reported_session":session,"programming_session_verified_at_end":session_verified,
        "authorization_scope":"historical owned connection only","requires_fresh_owned_security":true,"live_access_authorized":false,"persistent_unlock_verified":false,"erase_transfer_acceptance_verified":false,"programming_approved":false}),
    )
}
#[flutter_rust_bridge::frb(ignore)]
pub(super) fn collect(root: &Path, vin: &str, live: &crate::n20_agent_state::Identity) -> Value {
    let result = (|| -> Result<Value, String> {
        let directory = root.join("dme_owned_preparation");
        if !directory.try_exists().map_err(|e| e.to_string())? {
            return Err("No BimmerScope programming-access observation is saved".into());
        }
        let mut entries = Vec::new();
        let mut count = 0;
        for entry in std::fs::read_dir(directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            count += 1;
            if count > 1000 || !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                return Err(
                    "Programming-access storage is incomplete or exceeds its inspection limit"
                        .into(),
                );
            }
            let path = entry.path();
            let request: Value =
                serde_json::from_slice(&read(&path.join("request.json"), 1024 * 1024)?)
                    .map_err(|e| e.to_string())?;
            if request["vin"] != vin {
                continue;
            }
            let stamp = entry
                .file_name()
                .to_str()
                .and_then(|v| v.strip_prefix("dme-owned-preparation-"))
                .and_then(|v| v.parse::<u128>().ok())
                .ok_or("Invalid preparation record name")?;
            entries.push((stamp, path));
        }
        entries.sort_by_key(|v| v.0);
        let (_, folder) = entries
            .last()
            .ok_or("No matching BimmerScope programming-access observation")?;
        inspect(folder, vin, live)
    })();
    result.unwrap_or_else(|detail|json!({"schema":"n20-programming-access-observation-v1","status":"unavailable","detail":detail,"live_access_authorized":false,"persistent_unlock_verified":false,"requires_fresh_owned_security":true,"programming_approved":false}))
}

#[cfg(test)]
mod tests {
    use super::super::n20_owned_transport::{FileWireJournal, WireJournal};
    use super::*;
    fn fixture(
        enter_session: bool,
        reject: bool,
    ) -> (std::path::PathBuf, crate::n20_agent_state::Identity) {
        let root = std::env::temp_dir().join(format!(
            "n20-access-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let folder = root.join("dme_owned_preparation/dme-owned-preparation-1");
        std::fs::create_dir_all(&folder).unwrap();
        let f101 = super::super::N20_BENCH_F101;
        let actual = super::super::decode_s55_dme_identity_bundle(&decode(f101).unwrap()).unwrap();
        let identity = crate::n20_agent_state::Identity {
            hardware_id: actual.hardware,
            bootloader_id: actual.bootloader,
            software_id: actual.software,
            calibration_id: actual.calibration,
        };
        let mut plan = if enter_session {
            vec![vec![0x10, 2], vec![0x22, 0xf1, 0x86]]
        } else {
            vec![]
        };
        plan.push(vec![0x27, 0x11, 255, 255, 255, 255]);
        let bytes=serde_json::to_vec(&json!({"schema":"dme-owned-preparation-v1","vin":"WBA3A52010F360747","bootloader":identity.bootloader_id,"f101":f101,"requests":plan,"security_prefix":[0x27,0x12],"post_key_requests":[]})).unwrap();
        std::fs::write(folder.join("request.json"), &bytes).unwrap();
        let binding = Sha256::digest(&bytes).into();
        let mut wire = FileWireJournal::create(&folder.join("wire.jsonl"), &binding).unwrap();
        for sent in plan
            .iter()
            .cloned()
            .chain(std::iter::once(vec![0x27, 0x12, 9, 9]))
        {
            wire.append("intent", 0x12, &sent).unwrap();
            let reply = match sent.as_slice() {
                [0x10, 2] => vec![0x50, 2, 0, 50, 0, 100],
                [0x22, ..] => vec![0x62, 0xf1, 0x86, 2, 1],
                [0x27, 0x11, ..] => [vec![0x67, 0x11], vec![7; 8]].concat(),
                _ if reject => vec![0x7f, 0x27, 0x35],
                _ => vec![0x67, 0x12],
            };
            wire.append("response", 0x12, &reply).unwrap();
        }
        drop(wire);
        std::fs::write(folder.join("result.json"),serde_json::to_vec(&json!({"schema":"dme-owned-preparation-result-v1","operation_binding_sha256":binding.iter().map(|b|format!("{b:02X}")).collect::<String>(),"completed":true,"security_response_accepted":true,"outcome_unknown":false})).unwrap()).unwrap();
        (root, identity)
    }
    #[test]
    fn historical_acceptance_never_becomes_a_new_connection_grant() {
        let (root, identity) = fixture(true, false);
        let report = collect(&root, "WBA3A52010F360747", &identity);
        assert_eq!(report["status"], "observed");
        assert_eq!(report["programming_session_verified_at_end"], false);
        assert_eq!(report["live_access_authorized"], false);
        assert_eq!(report["persistent_unlock_verified"], false);
        let mut different = identity.clone();
        different.calibration_id = "00001CDB029150007".into();
        assert_eq!(
            collect(&root, "WBA3A52010F360747", &different)["status"],
            "unavailable"
        );
        let path = root.join("dme_owned_preparation/dme-owned-preparation-1/wire.jsonl");
        let mut wire = std::fs::read(&path).unwrap();
        wire.truncate(wire.len() - 1);
        std::fs::write(&path, wire).unwrap();
        assert_eq!(
            collect(&root, "WBA3A52010F360747", &identity)["status"],
            "unavailable"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn seed_key_without_programming_session_and_forged_success_stay_distinct() {
        for (session, rejected, expected) in
            [(false, false, "security_only"), (true, true, "unavailable")]
        {
            let (root, identity) = fixture(session, rejected);
            assert_eq!(
                collect(&root, "WBA3A52010F360747", &identity)["status"],
                expected
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}

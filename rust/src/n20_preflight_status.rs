//! Historical ia.a(byte)/ix status interpretation. This is not a programming gate.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};
#[derive(Clone, Debug)]
pub(crate) enum Status {
    Unavailable,
    FailedQuery,
    Text(String),
}
pub(crate) struct Observation {
    pub status: Status,
    pub report: Value,
}
pub(crate) fn decode(reply: &[u8]) -> Result<Status, String> {
    if reply.len() == 3 && reply[..2] == [0x7f, 0x31] {
        return if reply[2] == 0x78 {
            Err("Condition query is still pending".into())
        } else {
            Ok(Status::FailedQuery)
        };
    }
    if !reply.starts_with(&[0x71, 1, 2, 3]) || reply.len() > 260 {
        return Err("Malformed programming-condition response".into());
    }
    // ix.g joins labels with their parenthesized code. ia.substringBefore("(")
    // therefore retains only the first label, not later HIS codes in the list.
    let Some(&code) = reply.get(4) else {
        return Ok(Status::Text(String::new()));
    };
    let labels = [
        "engine running.",
        "immobilizer system not being unlocked.",
        "gear box input speed not being zero.",
        "gear box output speed not being zero.",
        "vehicle's speed not being zero.",
        "control active.",
        "ignition needing restart. Ignition off-on is required.",
        "programming voltage being insufficient.",
        "ignition being off (clamp 15 is off).",
        "vehicle's electrical system voltage being too low.",
        "temperature being too high.",
        "temperature being too low.",
        "---",
    ];
    let label = if (1..=13).contains(&code) {
        labels[code as usize - 1]
    } else if code < 128 {
        "HIS reserved"
    } else if code <= 191 {
        "manufacturer reserved"
    } else if code == 192 {
        "unexpected"
    } else {
        "supplier reserved"
    };
    Ok(Status::Text(format!("{label} ")))
}
fn read(path: &Path) -> Result<Vec<u8>, String> {
    if !std::fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .is_file()
    {
        return Err("Condition evidence is not a regular file".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 128 * 1024 {
        return Err("Condition evidence exceeds limit".into());
    }
    Ok(bytes)
}
fn inspect(
    folder: &Path,
    vin: &str,
    identity: &crate::n20_agent_state::Identity,
    now: u128,
) -> Result<Observation, String> {
    let request_bytes = read(&folder.join("request.json"))?;
    let request: Value = serde_json::from_slice(&request_bytes).map_err(|e| e.to_string())?;
    let stamp = request["captured_unix_ns"]
        .as_str()
        .ok_or("Condition query has no bound timestamp")?
        .parse::<u128>()
        .map_err(|e| e.to_string())?;
    let age = now
        .checked_sub(stamp)
        .ok_or("Condition query timestamp is in the future")?;
    if folder.file_name().and_then(|v| v.to_str())
        != Some(format!("n20-condition-query-{stamp}").as_str())
    {
        return Err("Condition-query directory differs from bound timestamp".into());
    }
    if age > 30_000_000_000 {
        return Err("Condition query is older than 30 seconds".into());
    }
    if request["schema"] != "n20-explicit-condition-query-v1"
        || request["vin"] != vin
        || request["request"] != "31010203"
        || crate::n20_agent_state::Identity::from_operation(&request)? != *identity
    {
        return Err("Condition query identity/request differs from fresh DME".into());
    }
    let report: Value = serde_json::from_slice(&read(&folder.join("conditions.json"))?)
        .map_err(|e| e.to_string())?;
    let binding = format!("{:X}", Sha256::digest(&request_bytes));
    let text = report["response"]
        .as_str()
        .ok_or("Condition response missing")?;
    if text.len() > 520 || text.len() % 2 != 0 || !text.is_ascii() {
        return Err("Invalid condition response encoding".into());
    }
    let reply = text
        .as_bytes()
        .chunks_exact(2)
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut expected = crate::n20_preflight::conditions(&reply)?;
    expected["operation_binding_sha256"] = json!(binding);
    if expected != report {
        return Err("Condition report differs from its bound raw response".into());
    }
    let status = decode(&reply)?;
    Ok(Observation {
        report: json!({"schema":"n20-preflight-status-v1","available":true,"directory":folder.to_string_lossy(),"request_binding_sha256":binding,"age_ms":age/1_000_000,"response":text,
        "legacy_status":match &status{Status::FailedQuery=>Some("fail"),Status::Text(text)=>Some(text.as_str()),_=>None},
        "source":"recent explicit query on a separate diagnostic connection; not same-socket gate approval","programming_approved":false}),
        status,
    })
}
pub(crate) fn load(
    root: &Path,
    vin: &str,
    identity: &crate::n20_agent_state::Identity,
    now: u128,
) -> Observation {
    let result = (|| -> Result<Observation, String> {
        let dir = root.join("n20_condition_queries");
        let mut entries = Vec::new();
        if !dir.try_exists().map_err(|e| e.to_string())? {
            return Err("No explicit condition query is available".into());
        }
        for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entries.len() >= 1000 {
                return Err("Condition-query scan limit exceeded".into());
            }
            if !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                return Err("Unexpected condition-query entry".into());
            }
            let name = entry.file_name();
            let stamp = name
                .to_str()
                .and_then(|v| v.strip_prefix("n20-condition-query-"))
                .and_then(|v| v.parse::<u128>().ok())
                .ok_or("Invalid condition-query directory")?;
            entries.push((stamp, entry.path()));
        }
        entries.sort_by_key(|v| v.0);
        // Never fall back to an older, more permissive query after a new result.
        let (_, folder) = entries
            .last()
            .ok_or("No explicit condition query is available")?;
        inspect(folder, vin, identity, now)
    })();
    result.unwrap_or_else(|detail|Observation{status:Status::Unavailable,report:json!({"schema":"n20-preflight-status-v1","available":false,"detail":detail,"programming_approved":false})})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_status_preserves_legacy_first_label_and_failure_boundaries() {
        assert!(matches!(
            decode(&[0x7f, 0x31, 0x22]).unwrap(),
            Status::FailedQuery
        ));
        assert!(decode(&[0x7f, 0x31, 0x78]).is_err());
        assert!(decode(&[0x71, 1, 2, 4]).is_err());
        assert!(matches!(decode(&[0x71,1,2,3]).unwrap(),Status::Text(v)if v.is_empty()));
        for code in [0, 14, 127] {
            assert!(
                matches!(decode(&[0x71,1,2,3,code]).unwrap(),Status::Text(v)if v.contains("HIS"))
            );
        }
        assert!(matches!(decode(&[0x71,1,2,3,1,14]).unwrap(),Status::Text(v)if !v.contains("HIS")));
        for (code, label) in [
            (128, "manufacturer"),
            (191, "manufacturer"),
            (192, "unexpected"),
            (193, "supplier"),
            (255, "supplier"),
        ] {
            assert!(
                matches!(decode(&[0x71,1,2,3,code]).unwrap(),Status::Text(v)if v.contains(label))
            );
        }
    }
    #[test]
    fn saved_query_requires_fresh_exact_identity_bound_raw_result_and_latest_record() {
        let root = std::env::temp_dir().join(format!(
            "n20-status-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let folder = root.join("n20_condition_queries/n20-condition-query-100");
        std::fs::create_dir_all(&folder).unwrap();
        let identity = crate::n20_agent_state::Identity {
            hardware_id: "000019A6001019003".into(),
            bootloader_id: "00001901001049002".into(),
            software_id: "00001C9F029150001".into(),
            calibration_id: "00001CDB029150003".into(),
        };
        let request=serde_json::to_vec(&json!({"schema":"n20-explicit-condition-query-v1","vin":"WBA3A52010F360747","hardware":identity.hardware_id,"bootloader":identity.bootloader_id,"software":identity.software_id,"calibration":identity.calibration_id,"request":"31010203","captured_unix_ns":"100"})).unwrap();
        std::fs::write(folder.join("request.json"), &request).unwrap();
        let mut report = crate::n20_preflight::conditions(&[0x7f, 0x31, 0x22]).unwrap();
        report["operation_binding_sha256"] = json!(format!("{:X}", Sha256::digest(&request)));
        std::fs::write(
            folder.join("conditions.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        let vin = "WBA3A52010F360747";
        assert!(matches!(
            load(&root, vin, &identity, 1000).status,
            Status::FailedQuery
        ));
        assert!(matches!(
            load(&root, vin, &identity, 30_000_000_101).status,
            Status::Unavailable
        ));
        assert!(matches!(
            load(&root, vin, &identity, 99).status,
            Status::Unavailable
        ));
        let mut different = identity.clone();
        different.calibration_id = "00001CDB029150007".into();
        assert!(matches!(
            load(&root, vin, &different, 1000).status,
            Status::Unavailable
        ));
        assert!(matches!(
            load(&root, "WBA3A52010F360748", &identity, 1000).status,
            Status::Unavailable
        ));
        report["response"] = json!("71010203");
        std::fs::write(
            folder.join("conditions.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load(&root, vin, &identity, 1000).status,
            Status::Unavailable
        ));
        report = crate::n20_preflight::conditions(&[0x7f, 0x31, 0x22]).unwrap();
        report["operation_binding_sha256"] = json!(format!("{:X}", Sha256::digest(&request)));
        std::fs::write(
            folder.join("conditions.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        std::fs::create_dir(root.join("n20_condition_queries/n20-condition-query-101")).unwrap();
        assert!(matches!(
            load(&root, vin, &identity, 1000).status,
            Status::Unavailable
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}

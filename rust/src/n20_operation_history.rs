//! Local evidence discovery only. Never resumes writes or approves ECU state.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(crate) fn rejected_before_programming(folder: &Path, binding: &[u8; 32]) -> bool {
    let path = folder.join("wire.jsonl");
    if !std::fs::metadata(&path).is_ok_and(|meta| meta.len() <= 128 * 1024) {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    if !text.ends_with('\n') {
        return false;
    }
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<Value>(header) else {
        return false;
    };
    let expected = binding.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    if value["schema"] != "n20-owned-wire-v1" || value["manifest_sha256"] != expected {
        return false;
    }
    let mut chain = format!("{:x}", Sha256::digest(header.as_bytes()));
    let mut pending = None;
    let mut rejected = false;
    for (index, line) in lines.enumerate() {
        let Ok(outer) = serde_json::from_str::<Value>(line) else {
            return false;
        };
        let Some(body) = outer["record"].as_str() else {
            return false;
        };
        let digest = format!("{:x}", Sha256::digest(body.as_bytes()));
        let Ok(row) = serde_json::from_str::<Value>(body) else {
            return false;
        };
        if rejected || outer["sha256"] != digest || row["previous_sha256"] != chain
            || row["sequence"] != index || row["target"] != 0x12 {
            return false;
        }
        chain = digest;
        let Some(uds) = row["uds"].as_str() else {
            return false;
        };
        match row["kind"].as_str() {
            Some("intent") if pending.is_none() => {
                if !(uds.starts_with("22") || uds.starts_with("23")
                    || matches!(uds, "31010203" | "1001" | "1003" | "31010f0c03")) {
                    return false;
                }
                pending = Some(uds == "31010f0c03");
            }
            Some("response") if pending.is_some() => {
                if uds.len() == 6 && uds.starts_with("7f") && uds.ends_with("78") {
                    continue;
                }
                if pending.take() == Some(true) {
                    if uds != "7f3122" {
                        return false;
                    }
                    rejected = true;
                }
            }
            _ => return false,
        }
    }
    rejected && pending.is_none()
}
fn read_json(path: &Path) -> Result<(Vec<u8>, Value), String> {
    if std::fs::metadata(path).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
        return Err("Evidence JSON exceeds size limit".into());
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    Ok((bytes, value))
}
pub(crate) fn assess(folder: &Path, bytes: &[u8], op: &Value) -> Result<Value, String> {
    let recovery = op["schema"] == "n20-live-recovery-v1";
    let full = op["schema"] == "n20-full-operation-v1";
    let six = full || recovery;
    let kind = if full {
        "full"
    } else if recovery {
        "recovery"
    } else {
        "partial"
    };
    if full && op["operation_kind"] != "full" {
        return Err("Full-flash operation kind differs".into());
    }
    if !six && op["schema"] != "n20-operation-v1" {
        return Err("Unknown operation schema".into());
    }
    let hash = op["bin_sha256"].as_str().ok_or("Missing image hash")?;
    if std::fs::metadata(folder.join("selected.bin"))
        .map_err(|e| e.to_string())?
        .len()
        != 0x400000
    {
        return Err("Saved image has an invalid length".into());
    }
    let image = crate::n20_partial::PartialImage::from_bin(
        std::fs::read(folder.join("selected.bin")).map_err(|e| e.to_string())?,
        hash,
    )?;
    let coding = read_json(&folder.join(if recovery {
        "original-coding.json"
    } else {
        "coding.json"
    }))?
    .1;
    crate::n20_coding::CodingSnapshot::from_manifest(
        &coding,
        op["vin"].as_str().ok_or("Missing VIN")?,
    )?;
    if full {
        let sidecar = read_json(&folder.join("coding-binding.json"))?.1;
        if sidecar["operation_binding_sha256"] != format!("{:X}", Sha256::digest(bytes))
            || sidecar["coding_sha256"]
                != format!(
                    "{:x}",
                    Sha256::digest(read_json(&folder.join("coding.json"))?.0)
                )
        {
            return Err("Full-flash coding snapshot binding differs".into());
        }
    }
    if recovery {
        let (plan_bytes, plan) = read_json(&folder.join("recovery-plan.json"))?;
        let (original_bytes, original) = read_json(&folder.join("original-operation.json"))?;
        if op["plan_sha256"] != format!("{:x}", Sha256::digest(&plan_bytes))
            || op["coding_sha256"]
                != format!(
                    "{:x}",
                    Sha256::digest(read_json(&folder.join("original-coding.json"))?.0)
                )
            || plan["original_operation_sha256"] != format!("{:x}", Sha256::digest(&original_bytes))
            || original["vin"] != op["vin"]
            || plan["vin"] != op["vin"]
        {
            return Err("Saved recovery source binding differs".into());
        }
    }
    let binding: [u8; 32] = Sha256::digest(bytes).into();
    if folder.join("gate-intent.json").exists() {
        let intent = read_json(&folder.join("gate-intent.json"))?.1;
        let report = read_json(&folder.join("enforced-gate.json"))?.1;
        let expected = binding
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>();
        if intent["schema"] != "n20-enforced-gate-intent-v1"
            || intent["operation_binding"] != expected
            || report["schema"] != "n20-enforced-programming-gate-v1"
            || report["operation_binding"] != expected
            || report["outcome_unknown"] != false
        {
            return Err(
                "Programming gate was interrupted or its outcome/binding is uncertain".into(),
            );
        }
    }
    let stage_path = folder.join(if full {
        "full-stages.jsonl"
    } else if recovery {
        "recovery-stages.jsonl"
    } else {
        "stages.jsonl"
    });
    if !stage_path.exists() {
        if folder.join("prewrite-approval.json").exists() {
            return Err("Prewrite approval exists without stage evidence".into());
        }
        return Ok(
            json!({"status":"prepared","needs_review":false,"may_have_changed":false,"kind":kind,"can_load":true,"detail":"Saved preparation only; no programming stage journal. Recheck the DME before any operation."}),
        );
    }
    if std::fs::metadata(&stage_path)
        .map_err(|e| e.to_string())?
        .len()
        > 128 * 1024
    {
        return Err("Stage journal exceeds size limit".into());
    }
    let (records, complete) = if six {
        crate::n20_recovery::inspect_stages_kind(
            &stage_path,
            &binding,
            hash,
            if full {
                crate::n20_recovery::RewriteKind::Full
            } else {
                crate::n20_recovery::RewriteKind::Recovery
            },
        )?
    } else {
        let state = crate::n20_stage_journal::inspect(&stage_path, &binding, hash)?;
        (state.records, state.workflow_recorded_complete)
    };
    if !complete {
        if !six && records == 3 && rejected_before_programming(folder, &binding) {
            return Ok(json!({"status":"setup_rejected","needs_review":false,
                "may_have_changed":false,"kind":kind,"can_load":true,
                "detail":"DME rejected flash energy mode before programming session or erase."}));
        }
        return Ok(
            json!({"status":if records>=3{"interrupted_or_uncertain"}else{"preparation_incomplete"},"needs_review":true,
        "may_have_changed":records>=3,"kind":kind,"can_load":true,"detail":"Recorded workflow is incomplete. No automatic resume is allowed."}),
        );
    }
    let receipt = read_json(&folder.join("verification.json"))?.1;
    let regions: Vec<(u32, usize, usize, String)> = if six {
        crate::n20_recovery::REGIONS
            .iter()
            .enumerate()
            .map(|(i, r)| (r.address(), r.start, r.length, format!("region-{i}.jsonl")))
            .collect()
    } else {
        vec![
            (0x80180000, 0x180000, 523264, "main.jsonl".into()),
            (0x801ffd00, 0x1ffd00, 768, "tail.jsonl".into()),
        ]
    };
    let total: usize = regions.iter().map(|r| r.2).sum();
    if receipt["vin"] != op["vin"]
        || (full && receipt["operation_kind"] != "full")
        || receipt["coding_matches"] != true
        || receipt["transferred_bytes_verified"] != total
        || (six
            && (receipt["schema"]
                != if full {
                    "n20-full-verified-v1"
                } else {
                    "n20-recovery-verified-v1"
                }
                || receipt["six_regions_match"] != true))
    {
        return Err("Verification receipt is incomplete or differs from operation".into());
    }
    for (address, start, length, file) in regions {
        if std::fs::metadata(folder.join(&file))
            .map_err(|e| e.to_string())?
            .len()
            > 32 * 1024 * 1024
        {
            return Err("Transfer journal exceeds size limit".into());
        }
        let result = crate::exchange_journal::inspect_download(
            &folder.join(file),
            &binding,
            address,
            image.bytes()[start..start + length].to_vec(),
            4094,
        )?;
        if result != crate::uds_download::ReplayStatus::TransferExited {
            return Err("Transfer journal is incomplete".into());
        }
    }
    crate::n20_agent_state::validated_transition(bytes,op,&receipt,&image)?;
    Ok(
        json!({"status":"recorded_complete","needs_review":false,"may_have_changed":false,"kind":kind,"can_load":true,"identity_transition":receipt.get("identity_transition"),"agent_type":op["agent_dispatch"]["selected"],
        "detail":"Local workflow and verification receipt are complete. This does not verify the currently connected ECU."}),
    )
}
/// Global startup check: no VIN filter, no 50-row display cutoff, and no
/// silent truncation. Unattributable mutation markers also block vehicle I/O.
pub(crate) fn startup_review(root: &Path) -> Result<Value, String> {
    let mut uncertain = Vec::new();
    let mut count = 0;
    for container_name in [
        "n20_flash_operations",
        "n20_recovery_operations",
        "n20_full_operations",
        "n20_condition_queries",
        "dme_owned_preparation",
    ] {
        let container = root.join(container_name);
        if !container.try_exists().map_err(|e| e.to_string())? {
            continue;
        }
        let canonical = container.canonicalize().map_err(|e| e.to_string())?;
        if !canonical.starts_with(root.canonicalize().map_err(|e| e.to_string())?) {
            return Err("Operation container escapes application storage".into());
        }
        for entry in std::fs::read_dir(&container).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            count += 1;
            if count > 2000 {
                return Err(
                    "Startup inspection exceeded 2000 entries; complete inspection is required"
                        .into(),
                );
            }
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_symlink() {
                return Err(
                    "Linked operation entries cannot be trusted by startup inspection".into(),
                );
            }
            if !kind.is_dir() {
                continue;
            }
            let folder = entry.path();
            if container_name == "dme_owned_preparation" {
                let inspected = (|| -> Result<(), String> {
                    let (bytes, request) = read_json(&folder.join("request.json"))?;
                    let result = read_json(&folder.join("result.json"))?.1;
                    if request["schema"] != "dme-owned-preparation-v1"
                        || result["schema"] != "dme-owned-preparation-result-v1"
                        || result["operation_binding_sha256"]
                            != format!("{:X}", Sha256::digest(&bytes))
                        || result["outcome_unknown"] != false
                        || !result["completed"].is_boolean()
                        || (result["completed"] == true
                            && result["security_response_accepted"] != true)
                    {
                        return Err(
                            "Owned preparation was interrupted or its result is unbound/uncertain"
                                .into(),
                        );
                    }
                    Ok(())
                })();
                if let Err(detail) = inspected {
                    uncertain.push(json!({"directory":folder.to_string_lossy(),"detail":detail}));
                }
                continue;
            }
            if container_name == "n20_condition_queries" {
                let inspected = (|| -> Result<(), String> {
                    let (bytes, request) = read_json(&folder.join("request.json"))?;
                    let report = read_json(&folder.join("conditions.json"))?.1;
                    let binding = format!("{:X}", Sha256::digest(&bytes));
                    if request["schema"] != "n20-explicit-condition-query-v1"
                        || request["request"] != "31010203"
                        || report["operation_binding_sha256"] != binding
                    {
                        return Err("Condition-query evidence is unbound or incomplete".into());
                    }
                    let raw = report["response"]
                        .as_str()
                        .ok_or("Missing condition-query response")?;
                    if raw.len() % 2 != 0 || !raw.is_ascii() {
                        return Err("Malformed condition-query response".into());
                    }
                    let response = raw
                        .as_bytes()
                        .chunks_exact(2)
                        .map(|p| {
                            u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16)
                                .map_err(|e| e.to_string())
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    if response == [0x7f, 0x31, 0x78] {
                        return Err("Condition query still pending".into());
                    }
                    let mut expected = crate::n20_preflight::conditions(&response)?;
                    expected["operation_binding_sha256"] = json!(binding);
                    if expected != report {
                        return Err("Condition-query report differs from its raw response".into());
                    }
                    Ok(())
                })();
                if let Err(detail) = inspected {
                    uncertain.push(json!({"directory":folder.to_string_lossy(),"detail":detail}));
                }
                continue;
            }
            let markers = [
                "stages.jsonl",
                "recovery-stages.jsonl",
                "full-stages.jsonl",
                "prewrite-approval.json",
                "gate-intent.json",
            ];
            let mut marked = false;
            for marker in markers {
                marked |= folder
                    .join(marker)
                    .try_exists()
                    .map_err(|e| e.to_string())?;
            }
            if !marked {
                continue;
            }
            let result = read_json(&folder.join("operation.json"))
                .and_then(|(bytes, op)| assess(&folder, &bytes, &op));
            let detail = match result {
                Ok(row) if row["may_have_changed"] == false => None,
                Ok(row) => Some(
                    row["detail"]
                        .as_str()
                        .unwrap_or("Uncertain saved operation")
                        .to_string(),
                ),
                Err(error) => Some(error),
            };
            if let Some(detail) = detail {
                uncertain.push(json!({"directory":folder.to_string_lossy(),"detail":detail}));
            }
        }
    }
    Ok(
        json!({"schema":"vehicle-startup-safety-v1","blocked":!uncertain.is_empty(),
        "detail":if uncertain.is_empty(){"No uncertain mutation markers found in inspected local history"}else{"Uncertain flash/recovery evidence requires review"},
        "operations":uncertain,"entries_inspected":count,"programming_approved":false,
        "scope":"Local application storage; no assertion about physical ECU state or other diagnostic software"}),
    )
}

pub(crate) fn list(root: &Path, vin: &str) -> Result<Value, String> {
    if vin.len() != 17
        || !vin
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err("Expected VIN is invalid".into());
    }
    let mut folders = Vec::new();
    for name in [
        "n20_flash_operations",
        "n20_recovery_operations",
        "n20_full_operations",
    ] {
        let container = root.join(name);
        if !container.exists() {
            continue;
        }
        let canonical = container.canonicalize().map_err(|e| e.to_string())?;
        for entry in std::fs::read_dir(&container)
            .map_err(|e| e.to_string())?
            .take(1000)
        {
            let entry = entry.map_err(|e| e.to_string())?;
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if !kind.is_dir() || kind.is_symlink() {
                continue;
            }
            let path = entry.path();
            if !path
                .canonicalize()
                .map_err(|e| e.to_string())?
                .starts_with(&canonical)
            {
                continue;
            }
            folders.push(path);
        }
    }
    folders.sort_by_key(|p| {
        std::cmp::Reverse(
            p.file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| s.rsplit('-').next())
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0),
        )
    });
    let mut rows = Vec::new();
    for folder in folders {
        let parsed = read_json(&folder.join("operation.json"));
        if let Ok((_, op)) = &parsed {
            if op["vin"].as_str().is_some_and(|id| id != vin) {
                continue;
            }
        }
        let known_vin = parsed.as_ref().ok().is_some_and(|(_, op)| op["vin"] == vin);
        let result = parsed
            .as_ref()
            .map_err(|e| e.clone())
            .and_then(|(bytes, op)| assess(&folder, bytes, op));
        let mut row = match result {
            Ok(row) => row,
            Err(detail) => {
                json!({"status":"evidence_invalid","needs_review":true,"may_have_changed":known_vin && ["stages.jsonl","recovery-stages.jsonl","full-stages.jsonl","prewrite-approval.json","gate-intent.json"].iter().any(|name|folder.join(name).exists()),"can_load":false,"kind":"unknown","detail":detail})
            }
        };
        row["directory"] = json!(folder.to_string_lossy());
        row["vin_verified"] = json!(known_vin);
        row["vin"] = if known_vin { json!(vin) } else { Value::Null };
        if let Ok((_, op)) = parsed {
            row["image_sha256"] = op["bin_sha256"].clone();
            row["bin_stock"] = op["local_flash_input"]["stock_classification"].clone();
        }
        rows.push(row);
        if rows.len() == 50 {
            break;
        }
    }
    Ok(
        json!({"schema":"n20-saved-operations-v1","operations":rows,"programming_approved":false,"coverage":"up to 50 matching records; absence is not proof of ECU state"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n20_partial::{Stage, StageJournal};
    struct Fixture {
        root: std::path::PathBuf,
        folder: std::path::PathBuf,
        binding: [u8; 32],
        hash: String,
        image: Vec<u8>,
    }
    const VIN: &str = "WBA3A52010F360747";
    #[test]
    fn startup_owned_preparation_requires_bound_known_outcome() {
        let f = Fixture::new();
        let folder = f.root.join("dme_owned_preparation/preparation-1");
        std::fs::create_dir_all(&folder).unwrap();
        let request =
            serde_json::to_vec(&json!({"schema":"dme-owned-preparation-v1","vin":VIN})).unwrap();
        std::fs::write(folder.join("request.json"), &request).unwrap();
        assert_eq!(startup_review(&f.root).unwrap()["blocked"], true);
        let mut result = json!({"schema":"dme-owned-preparation-result-v1","operation_binding_sha256":format!("{:X}",Sha256::digest(&request)),"outcome_unknown":false,"completed":true,"security_response_accepted":true});
        std::fs::write(
            folder.join("result.json"),
            serde_json::to_vec(&result).unwrap(),
        )
        .unwrap();
        assert_eq!(startup_review(&f.root).unwrap()["blocked"], false);
        result["outcome_unknown"] = json!(true);
        std::fs::write(
            folder.join("result.json"),
            serde_json::to_vec(&result).unwrap(),
        )
        .unwrap();
        assert_eq!(startup_review(&f.root).unwrap()["blocked"], true);
    }
    #[test]
    fn startup_condition_queries_require_bound_final_responses() {
        let f = Fixture::new();
        let folder = f.root.join("n20_condition_queries/query-1");
        std::fs::create_dir_all(&folder).unwrap();
        let request = serde_json::to_vec(
            &json!({"schema":"n20-explicit-condition-query-v1","request":"31010203","vin":VIN}),
        )
        .unwrap();
        std::fs::write(folder.join("request.json"), &request).unwrap();
        assert_eq!(startup_review(&f.root).unwrap()["blocked"], true);
        let mut report = crate::n20_preflight::conditions(&[0x71, 1, 2, 3]).unwrap();
        report["operation_binding_sha256"] = json!(format!("{:X}", Sha256::digest(&request)));
        std::fs::write(
            folder.join("conditions.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        assert_eq!(startup_review(&f.root).unwrap()["blocked"], false);
        report["operation_binding_sha256"] = json!("wrong");
        std::fs::write(
            folder.join("conditions.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        assert_eq!(startup_review(&f.root).unwrap()["blocked"], true);
    }
    #[test]
    fn startup_preparation_does_not_block_but_unknown_owner_mutation_does() {
        let f = Fixture::new();
        assert_eq!(startup_review(&f.root).unwrap()["blocked"], false);
        let unknown = f.root.join("n20_recovery_operations/unknown-owner");
        std::fs::create_dir_all(&unknown).unwrap();
        std::fs::write(unknown.join("prewrite-approval.json"), b"{}").unwrap();
        let report = startup_review(&f.root).unwrap();
        assert_eq!(report["blocked"], true);
        assert_eq!(report["operations"].as_array().unwrap().len(), 1);
    }
    #[test]
    fn startup_checks_other_vins_and_records_beyond_the_page_limit() {
        let f = Fixture::new();
        for number in 0..60 {
            std::fs::create_dir(
                f.root
                    .join(format!("n20_flash_operations/preparation-{number}")),
            )
            .unwrap();
        }
        let mut op = read_json(&f.folder.join("operation.json")).unwrap().1;
        op["vin"] = json!("WBA3A52010F360748");
        std::fs::write(
            f.folder.join("operation.json"),
            serde_json::to_vec(&op).unwrap(),
        )
        .unwrap();
        std::fs::write(f.folder.join("stages.jsonl"), b"truncated").unwrap();
        let report = startup_review(&f.root).unwrap();
        assert_eq!(report["entries_inspected"], 61);
        assert_eq!(report["blocked"], true);
    }
    #[test]
    fn startup_truncated_gate_and_unreadable_container_fail_closed() {
        let f = Fixture::new();
        std::fs::write(f.folder.join("gate-intent.json"), b"{}").unwrap();
        assert_eq!(startup_review(&f.root).unwrap()["blocked"], true);
        std::fs::write(f.root.join("n20_recovery_operations"), b"not a directory").unwrap();
        assert!(startup_review(&f.root).is_err());
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "n20-history-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let folder = root.join("n20_flash_operations/n20-operation-1");
            std::fs::create_dir_all(&folder).unwrap();
            let mut image = vec![0; 0x400000];
            image[26..36].copy_from_slice(b"MEVD1729__");
            for (at, value) in [
                (0x18000c, 0x801ffc00u32),
                (0x180038, 0x80180000),
                (0x18003c, 0x801ffbff),
            ] {
                image[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            image[0x20024] = 8;
            image[0x20025] = 1;
            image[0x1ffd00] = 8;
            image[0x1ffd01..0x1ffd08].copy_from_slice(&[0, 0, 0x1c, 0xdb, 0x1d, 0x96, 7]);
            let hash = format!("{:x}", Sha256::digest(&image));
            let bytes = serde_json::to_vec(
                &json!({"schema":"n20-operation-v1","vin":VIN,"bin_sha256":hash}),
            )
            .unwrap();
            let binding = Sha256::digest(&bytes).into();
            std::fs::write(folder.join("operation.json"), bytes).unwrap();
            std::fs::write(folder.join("selected.bin"), &image).unwrap();
            std::fs::write(folder.join("coding.json"),serde_json::to_vec(&json!({"schema":"n20-coding-snapshot-v1","vin":VIN,"source":"ecu-read","recovery_image":false,"3320":"01","3350":"02","3351":null})).unwrap()).unwrap();
            Self {
                root,
                folder,
                binding,
                hash,
                image,
            }
        }
        fn row(&self) -> Value {
            list(&self.root, VIN).unwrap()["operations"][0].clone()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let resolved = self.root.canonicalize().unwrap();
            let parent = std::env::temp_dir().canonicalize().unwrap();
            assert_eq!(resolved.parent(), Some(parent.as_path()));
            assert!(resolved
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("n20-history-test-"));
            std::fs::remove_dir_all(resolved).unwrap();
        }
    }
    #[test]
    fn prepared_records_are_vin_scoped_and_image_corruption_is_not_loadable() {
        let f = Fixture::new();
        assert_eq!(f.row()["status"], "prepared");
        assert_eq!(f.row()["can_load"], true);
        assert_eq!(
            list(&f.root, "WBA00000000000000").unwrap()["operations"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        std::fs::write(f.folder.join("selected.bin"), [0; 5]).unwrap();
        assert_eq!(f.row()["can_load"], false);
        assert_eq!(f.row()["may_have_changed"], false);
    }
    #[test]
    fn interrupted_gate_is_not_downgraded_to_preparation_only() {
        let f = Fixture::new();
        let binding = f
            .binding
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>();
        std::fs::write(
            f.folder.join("gate-intent.json"),
            serde_json::to_vec(
                &json!({"schema":"n20-enforced-gate-intent-v1","operation_binding":binding}),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(f.row()["may_have_changed"], true);
        assert_eq!(f.row()["can_load"], false);
        let report = json!({"schema":"n20-enforced-programming-gate-v1","operation_binding":binding,"outcome_unknown":false,"passed":false});
        std::fs::write(
            f.folder.join("enforced-gate.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        assert_eq!(f.row()["status"], "prepared");
        assert_eq!(f.row()["may_have_changed"], false);
        let mut report = report;
        report["outcome_unknown"] = json!(true);
        std::fs::write(
            f.folder.join("enforced-gate.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        assert_eq!(f.row()["may_have_changed"], true);
    }
    #[test]
    fn only_a_complete_pre_programming_rejection_clears_the_pause() {
        let f = Fixture::new();
        let mut stages = crate::n20_stage_journal::FileStageJournal::create(
            &f.folder.join("stages.jsonl"), &f.binding, &f.hash,
        ).unwrap();
        for (stage, complete) in [
            (Stage::BindFreshIdentityAndValidateImage, false),
            (Stage::BindFreshIdentityAndValidateImage, true),
            (Stage::SetupAndAuthorize, false),
        ] {
            stages.record(stage, complete, &f.hash).unwrap();
        }
        let path = f.folder.join("wire.jsonl");
        let header = json!({"schema":"n20-owned-wire-v1",
            "manifest_sha256":f.binding.iter().map(|byte| format!("{byte:02x}")).collect::<String>()}).to_string();
        let mut chain = format!("{:x}", Sha256::digest(header.as_bytes()));
        let mut wire = format!("{header}\n");
        for (sequence, (kind, uds)) in [("intent", "31010f0c03"), ("response", "7f3122")].into_iter().enumerate() {
            let body = json!({"sequence":sequence,"target":18,"kind":kind,
                "uds":uds,"previous_sha256":chain}).to_string();
            chain = format!("{:x}", Sha256::digest(body.as_bytes()));
            wire.push_str(&format!("{}\n", json!({"record":body,"sha256":chain})));
        }
        std::fs::write(&path, &wire).unwrap();
        assert_eq!(f.row()["status"], "setup_rejected");
        assert_eq!(f.row()["may_have_changed"], false);
        std::fs::write(&path, wire.trim_end()).unwrap();
        assert_eq!(f.row()["may_have_changed"], true);
    }
    #[test]
    fn setup_intent_and_truncated_journals_preserve_uncertainty() {
        let f = Fixture::new();
        let path = f.folder.join("stages.jsonl");
        let mut log =
            crate::n20_stage_journal::FileStageJournal::create(&path, &f.binding, &f.hash).unwrap();
        log.record(Stage::BindFreshIdentityAndValidateImage, false, &f.hash)
            .unwrap();
        log.record(Stage::BindFreshIdentityAndValidateImage, true, &f.hash)
            .unwrap();
        assert_eq!(f.row()["may_have_changed"], false);
        log.record(Stage::SetupAndAuthorize, false, &f.hash)
            .unwrap();
        assert_eq!(f.row()["may_have_changed"], true);
        drop(log);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.pop();
        std::fs::write(path, bytes).unwrap();
        assert_eq!(f.row()["status"], "evidence_invalid");
        assert_eq!(f.row()["may_have_changed"], true);
    }
    #[test]
    fn completed_stages_need_receipt_and_valid_transfer_journals() {
        use crate::uds_download::{run_download, DownloadTransport};
        use std::time::{Duration, Instant};
        struct Wire {
            reply: Vec<u8>,
        }
        impl DownloadTransport for Wire {
            fn send(&mut self, r: &[u8], _: Instant) -> Result<(), String> {
                self.reply = match r[0] {
                    0x34 => vec![0x74, 0x20, 0x0f, 0xfe],
                    0x36 => vec![0x76, r[1]],
                    0x37 => vec![0x77],
                    _ => panic!(),
                };
                Ok(())
            }
            fn receive(&mut self, _: Instant) -> Result<Vec<u8>, String> {
                Ok(self.reply.clone())
            }
        }
        let f = Fixture::new();
        let mut log = crate::n20_stage_journal::FileStageJournal::create(
            &f.folder.join("stages.jsonl"),
            &f.binding,
            &f.hash,
        )
        .unwrap();
        for stage in crate::n20_partial::STAGES {
            log.record(stage, false, &f.hash).unwrap();
            log.record(stage, true, &f.hash).unwrap();
        }
        drop(log);
        assert_eq!(f.row()["status"], "evidence_invalid");
        std::fs::write(
            f.folder.join("verification.json"),
            serde_json::to_vec(
                &json!({"vin":VIN,"coding_matches":true,"transferred_bytes_verified":524032}),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(f.row()["status"], "evidence_invalid");
        for (file, address, start, length) in [
            ("main.jsonl", 0x80180000, 0x180000, 523264),
            ("tail.jsonl", 0x801ffd00, 0x1ffd00, 768),
        ] {
            let mut journal = crate::exchange_journal::FileExchangeJournal::create(
                &f.folder.join(file),
                &f.binding,
            )
            .unwrap();
            run_download(
                &mut Wire { reply: vec![] },
                &mut journal,
                address,
                f.image[start..start + length].to_vec(),
                4094,
                Duration::from_secs(1),
            )
            .unwrap();
        }
        assert_eq!(f.row()["status"], "recorded_complete");
        std::fs::write(f.folder.join("main.jsonl"), b"broken").unwrap();
        assert_eq!(f.row()["may_have_changed"], true);
    }
}

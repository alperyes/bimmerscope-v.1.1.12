//! Historical workflow flags, never ECU unlock evidence or programming approval.
//! Agent 0.10.082 bk: v/ud/fStat/nr/vid; ia loads VIN.coding before /ac.
use crate::n20_local_input::AgentState;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const LIMIT: u64 = 2 * 1024 * 1024;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Identity {
    pub hardware_id: String,
    pub bootloader_id: String,
    pub software_id: String,
    pub calibration_id: String,
}
impl Identity {
    pub(crate) fn from_operation(op: &Value) -> Result<Self, String> {
        let value = Self {
            hardware_id: op["hardware"]
                .as_str()
                .ok_or("Missing operation hardware")?
                .into(),
            bootloader_id: op["bootloader"]
                .as_str()
                .ok_or("Missing operation bootloader")?
                .into(),
            software_id: op["software"]
                .as_str()
                .ok_or("Missing operation software")?
                .into(),
            calibration_id: op["calibration"]
                .as_str()
                .ok_or("Missing operation calibration")?
                .into(),
        };
        check_identity(&value)?;
        Ok(value)
    }
}
pub(crate) fn transition(binding: &[u8; 32], vin: &str, from: &Identity, to: &Identity) -> Value {
    json!({"schema":"n20-identity-transition-v1","operation_binding_sha256":binding.iter().map(|b|format!("{b:02X}")).collect::<String>(),"vin":vin,"from":from,"to":to})
}
/// Optional on old receipts; required before a record may advance saved identity.
pub(crate) fn validated_transition(
    op_bytes: &[u8],
    op: &Value,
    receipt: &Value,
    image: &crate::n20_partial::PartialImage,
) -> Result<Option<(Identity, Identity)>, String> {
    let Some(value) = receipt.get("identity_transition") else {
        return Ok(None);
    };
    if value["schema"] != "n20-identity-transition-v1"
        || value["vin"] != op["vin"]
        || value["operation_binding_sha256"] != format!("{:X}", Sha256::digest(op_bytes))
    {
        return Err("Identity transition operation binding differs".into());
    }
    let from: Identity =
        serde_json::from_value(value["from"].clone()).map_err(|e| e.to_string())?;
    let to: Identity = serde_json::from_value(value["to"].clone()).map_err(|e| e.to_string())?;
    check_identity(&from)?;
    check_identity(&to)?;
    if from != Identity::from_operation(op)?
        || to.hardware_id != from.hardware_id
        || to.bootloader_id != from.bootloader_id
        || crate::n20_local_input::compact(&to.software_id).as_deref()
            != Some(image.software_token.as_str())
        || crate::n20_local_input::compact(&to.calibration_id).as_deref()
            != Some(image.calibration_token().as_str())
    {
        return Err(
            "Identity transition differs from source identity or verified BIN target".into(),
        );
    }
    if op["schema"] == "n20-operation-v1" && from.software_id != to.software_id {
        return Err("Calibration-only operation cannot advance software identity".into());
    }
    Ok(Some((from, to)))
}
#[derive(Deserialize)]
struct LegacyIdentity {
    #[serde(rename = "hardwareId")]
    hardware: String,
    #[serde(rename = "bootloaderId")]
    bootloader: String,
    #[serde(rename = "softwareId")]
    software: String,
    #[serde(rename = "calibrationId")]
    calibration: String,
}
#[derive(Deserialize)]
struct LegacyState {
    v: String,
    ud: Option<bool>,
    #[serde(rename = "fStat")]
    success: Option<bool>,
    nr: Option<bool>,
    lft: Option<String>,
    vid: LegacyIdentity,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedState {
    schema: String,
    vin: String,
    identity: Identity,
    unlock_done: bool,
    last_flash_success: bool,
    needs_recovery: bool,
    #[serde(default)]
    last_flash_type: Option<String>,
    source_sha256: String,
    imported_at_ns: u128,
}
fn valid_vin(vin: &str) -> bool {
    vin.len() == 17
        && vin.bytes().all(|b| {
            b.is_ascii_digit() || (b.is_ascii_uppercase() && !matches!(b, b'I' | b'O' | b'Q'))
        })
}
fn valid_id(id: &str) -> bool {
    id.len() == 17
        && id.is_ascii()
        && id[..8].bytes().all(|b| b.is_ascii_hexdigit())
        && [8, 11, 14].iter().all(|&p| {
            id[p..p + 3].bytes().all(|b| b.is_ascii_digit()) && id[p..p + 3].parse::<u8>().is_ok()
        })
}
fn check_identity(id: &Identity) -> Result<(), String> {
    if [
        &id.hardware_id,
        &id.bootloader_id,
        &id.software_id,
        &id.calibration_id,
    ]
    .iter()
    .all(|v| valid_id(v))
    {
        Ok(())
    } else {
        Err("Agent state requires complete decimal-version hardware, bootloader, software and calibration IDs".into())
    }
}
fn read(path: &Path) -> Result<Vec<u8>, String> {
    if fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("Agent-state evidence must not be a symbolic link".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err("Agent-state evidence exceeds size limit".into());
    }
    Ok(bytes)
}
fn exclusive(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())
}
/// Explicit import only; no server calls, automatic working-directory discovery,
/// coding restoration, boolean defaults, or physical-unlock assertions.
pub(crate) fn import(root: &Path, path: &Path, vin: &str) -> Result<Value, String> {
    if !valid_vin(vin) {
        return Err("Expected VIN is invalid".into());
    }
    let bytes = read(path)?;
    // Typed deserialization rejects duplicate known fields and wrong boolean types.
    let legacy: LegacyState = serde_json::from_slice(&bytes)
        .map_err(|e| format!("Invalid agent vehicle-data JSON: {e}"))?;
    if legacy.v != vin {
        return Err("Agent state VIN differs from selected vehicle".into());
    }
    let identity = Identity {
        hardware_id: legacy.vid.hardware,
        bootloader_id: legacy.vid.bootloader,
        software_id: legacy.vid.software,
        calibration_id: legacy.vid.calibration,
    };
    check_identity(&identity)?;
    let saved = SavedState {
        schema: "n20-agent-state-v1".into(),
        vin: vin.into(),
        identity,
        unlock_done: legacy
            .ud
            .ok_or("Agent ud field is missing/null; unlock confirmation remains unknown")?,
        last_flash_success: legacy.success.ok_or("Agent fStat field is missing/null")?,
        needs_recovery: legacy.nr.ok_or("Agent nr field is missing/null")?,
        last_flash_type: legacy.lft,
        source_sha256: format!("{:x}", Sha256::digest(&bytes)),
        imported_at_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos(),
    };
    let normalized = serde_json::to_vec_pretty(&saved).map_err(|e| e.to_string())?;
    let hash = format!("{:x}", Sha256::digest(&normalized));
    let directory = root.join("n20_agent_state").join(vin);
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    // No active pointer can be half-written; latest immutable import is selected.
    let file = directory.join(format!("{}-{hash}.json", saved.imported_at_ns));
    exclusive(&file, &normalized)?;
    Ok(
        json!({"schema":"n20-agent-state-import-v1","vin":vin,"path":file.to_string_lossy(),
        "source_sha256":saved.source_sha256,"identity":saved.identity,
        "agent_state":{"unlockDone":saved.unlock_done,"lastFlashSuccess":saved.last_flash_success,"needsRecovery":saved.needs_recovery,"lastFlashType":saved.last_flash_type},
        "programming_approved":false,"physical_unlock_verified":false,
        "detail":"Historical agent workflow state saved. Fresh identity matching is required during preparation. Imported coding is not used as a BimmerScope backup."}),
    )
}
pub(crate) struct Loaded {
    pub state: AgentState,
    pub report: Value,
}
/// Missing cache is distinct from an unreadable/malformed existing cache.
pub(crate) fn has_saved_state(root:&Path,vin:&str)->Result<bool,String>{
    if !valid_vin(vin){return Err("Expected VIN is invalid".into());}
    let directory=root.join("n20_agent_state").join(vin);
    if !directory.try_exists().map_err(|e|e.to_string())?{return Ok(false);}
    let mut entries=fs::read_dir(directory).map_err(|e|e.to_string())?;
    entries.next().transpose().map(|v|v.is_some()).map_err(|e|e.to_string())
}
fn unknown(detail: &str) -> Loaded {
    Loaded {
        state: AgentState::default(),
        report: json!({"schema":"n20-agent-state-resolution-v1","resolved":false,"detail":detail,"physical_unlock_verified":false,"programming_approved":false}),
    }
}
/// Uses persistent journals as the local result store. Replaying them after a
/// restart avoids a second mutable result flag drifting from operation evidence.
pub(crate) fn load(root: &Path, vin: &str, live: &Identity) -> Loaded {
    match resolve(root, vin, live) {
        Ok(value) => value,
        Err(error) => unknown(&error),
    }
}
fn advance_identity(
    start: &Identity,
    mut transitions: Vec<(u128, String, Identity, Identity)>,
) -> Result<(Identity, Vec<Value>), String> {
    transitions.sort_by_key(|entry| entry.0);
    let mut current = start.clone();
    let mut lineage = Vec::new();
    let mut previous_stamp = None;
    for (stamp, path, from, to) in transitions {
        if previous_stamp == Some(stamp) || from != current {
            return Err("Completed operation identity chain is ambiguous or disconnected".into());
        }
        current = to.clone();
        previous_stamp = Some(stamp);
        lineage.push(json!({"operation_directory":path,"from":from,"to":to}));
    }
    Ok((current, lineage))
}
fn resolve(root: &Path, vin: &str, live: &Identity) -> Result<Loaded, String> {
    if !valid_vin(vin) {
        return Err("Expected VIN is invalid".into());
    }
    check_identity(live)?;
    let directory = root.join("n20_agent_state").join(vin);
    let mut imports = Vec::new();
    if directory.try_exists().map_err(|e| e.to_string())? {
        for entry in fs::read_dir(&directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if imports.len() >= 1000 {
                return Err("Too many agent-state records; review storage".into());
            }
            if !entry.file_type().map_err(|e| e.to_string())?.is_file() {
                return Err("Unexpected entry in agent-state storage".into());
            }
            let name = entry
                .file_name()
                .to_str()
                .ok_or("Invalid state filename")?
                .to_string();
            let (time, _) = name.split_once('-').ok_or("Invalid state filename")?;
            imports.push((
                time.parse::<u128>()
                    .map_err(|_| "Invalid state timestamp")?,
                name,
                entry.path(),
            ));
        }
    }
    imports.sort_by_key(|v| v.0);
    let Some((time, name, path)) = imports.last() else {
        return Err("No imported agent vehicle-data state is available".into());
    };
    let bytes = read(path)?;
    let saved: SavedState = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if *name != format!("{}-{:x}.json", time, Sha256::digest(&bytes))
        || saved.imported_at_ns != *time
        || saved.schema != "n20-agent-state-v1"
        || saved.vin != vin
        || saved.source_sha256.len() != 64
        || !saved.source_sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("Imported agent-state binding is invalid".into());
    }
    if saved.identity.hardware_id != live.hardware_id
        || saved.identity.bootloader_id != live.bootloader_id
    {
        return Err(
            "Imported agent-state controller/bootloader differs from fresh DME identity".into(),
        );
    }
    let mut state = AgentState {
        unlock_done: Some(saved.unlock_done),
        last_flash_success: Some(saved.last_flash_success),
        needs_recovery: Some(saved.needs_recovery),
        last_flash_type: saved.last_flash_type.clone(),
    };
    let mut latest_complete = None;
    let mut latest_complete_type = None;
    let mut transitions = Vec::new();
    let mut uncertain = Vec::new();
    let mut count = 0;
    for container in [
        "n20_flash_operations",
        "n20_full_operations",
        "n20_recovery_operations",
    ] {
        let dir = root.join(container);
        if !dir.try_exists().map_err(|e| e.to_string())? {
            continue;
        }
        for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            count += 1;
            if count > 3000 {
                return Err("Operation-state scan limit exceeded".into());
            }
            if !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                return Err("Unexpected operation-state entry".into());
            }
            let folder = entry.path();
            let mut marked = false;
            for name in [
                "stages.jsonl",
                "full-stages.jsonl",
                "recovery-stages.jsonl",
                "prewrite-approval.json",
                "gate-intent.json",
            ] {
                marked |= folder.join(name).try_exists().map_err(|e| e.to_string())?;
            }
            if !marked {
                continue;
            }
            let outcome = (|| -> Result<Option<Value>, String> {
                let op_bytes = read(&folder.join("operation.json"))?;
                let op: Value = serde_json::from_slice(&op_bytes).map_err(|e| e.to_string())?;
                let operation_vin = op["vin"]
                    .as_str()
                    .filter(|v| valid_vin(v))
                    .ok_or("Operation VIN is unavailable")?;
                if operation_vin != vin {
                    return Ok(None);
                }
                // Another controller/bootloader's result cannot overwrite
                // this identity's cached workflow-result flags.
                if op["hardware"] != live.hardware_id || op["bootloader"] != live.bootloader_id {
                    return Err("Local operation controller binding differs".into());
                }
                Ok(Some(crate::n20_operation_history::assess(
                    &folder, &op_bytes, &op,
                )?))
            })();
            match outcome {
                Ok(None) => {}
                Ok(Some(row)) if row["status"] == "recorded_complete" => {
                    let stamp = entry
                        .file_name()
                        .to_str()
                        .and_then(|s| s.rsplit('-').next())
                        .and_then(|s| s.parse::<u128>().ok())
                        .ok_or("Invalid operation timestamp")?;
                    if stamp > *time
                        && latest_complete
                            .as_ref()
                            .is_none_or(|(previous, _)| stamp > *previous)
                    {
                        latest_complete = Some((stamp, folder.to_string_lossy().into_owned()));
                        latest_complete_type = Some(
                            row["agent_type"]
                                .as_str()
                                .filter(|v| crate::n20_local_input::Mode::parse(v).is_some())
                                .unwrap_or(if row["kind"] == "partial" { "P" } else { "F" })
                                .to_string(),
                        );
                    }
                    if stamp > *time && !row["identity_transition"].is_null() {
                        let from: Identity =
                            serde_json::from_value(row["identity_transition"]["from"].clone())
                                .map_err(|e| e.to_string())?;
                        let to: Identity =
                            serde_json::from_value(row["identity_transition"]["to"].clone())
                                .map_err(|e| e.to_string())?;
                        transitions.push((stamp, folder.to_string_lossy().into_owned(), from, to));
                    }
                }
                Ok(Some(row)) if row["may_have_changed"] == false => {}
                _ => uncertain.push(folder.to_string_lossy().into_owned()),
            }
        }
    }
    let (current, lineage) = advance_identity(&saved.identity, transitions)?;
    if current != *live {
        return Err("Fresh DME identity is not reached by the imported state and completed local operation chain".into());
    }
    // An import, even newer, cannot clear any uncertain mutation journal.
    if !uncertain.is_empty() {
        state.last_flash_success = Some(false);
        state.needs_recovery = Some(true);
    } else if latest_complete.is_some() {
        state.last_flash_success = Some(true);
        state.needs_recovery = Some(false);
        state.last_flash_type = latest_complete_type;
    }
    Ok(Loaded {
        report: json!({"schema":"n20-agent-state-resolution-v1","resolved":true,
        "import_path":path.to_string_lossy(),"source_sha256":saved.source_sha256,"imported_identity":saved.identity,"identity":current,"identity_lineage":lineage,
        "local_completed_operation":latest_complete.map(|(_,path)|path),"uncertain_operations":uncertain,
        "agent_state":{"unlockDone":state.unlock_done,"lastFlashSuccess":state.last_flash_success,"needsRecovery":state.needs_recovery,"lastFlashType":state.last_flash_type},
        "physical_unlock_verified":false,"programming_approved":false,
        "limits":"Explicit historical import plus locally inspected workflow results. No /ac or /vd service, coding import, unlock/relock success inference or automatic recovery. Missing/mismatched input remains unknown."}),
        state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const VIN: &str = "WBA3A52010F360747";
    fn identity() -> Identity {
        Identity {
            hardware_id: "000019A6001019003".into(),
            bootloader_id: "00001901001049002".into(),
            software_id: "00001C9F029150001".into(),
            calibration_id: "00001CDB029150003".into(),
        }
    }
    fn fixture() -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "n20-agent-state-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("legacy.coding");
        fs::write(&path,serde_json::to_vec(&json!({"v":VIN,"ud":true,"fStat":true,"nr":false,"vid":identity(),"cd":{"ignored":"not imported"}})).unwrap()).unwrap();
        (root, path)
    }
    #[test]
    fn import_restart_identity_and_tamper() {
        let (root, path) = fixture();
        let mut legacy:Value=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();legacy["lft"]=json!("PF");fs::write(&path,serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(load(&root, VIN, &identity()).state.unlock_done, None);
        let result = import(&root, &path, VIN).unwrap();
        assert_eq!(load(&root, VIN, &identity()).state.unlock_done, Some(true));
        assert_eq!(load(&root,VIN,&identity()).state.last_flash_type.as_deref(),Some("PF"));
        let mut other = identity();
        other.calibration_id = "00001CDB029150007".into();
        assert_eq!(load(&root, VIN, &other).state.unlock_done, None);
        let saved = result["path"].as_str().unwrap();
        let mut bytes = fs::read(saved).unwrap();
        bytes.push(b' ');
        fs::write(saved, bytes).unwrap();
        assert_eq!(load(&root, VIN, &identity()).state.unlock_done, None);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn rejects_missing_flags_wrong_types_duplicate_and_vin() {
        let (root, path) = fixture();
        let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        for field in ["ud", "fStat", "nr"] {
            let mut v = original.clone();
            v.as_object_mut().unwrap().remove(field);
            fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
            assert!(import(&root, &path, VIN).is_err());
        }
        for bad in [json!("true"), Value::Null, json!(1)] {
            let mut v = original.clone();
            v["ud"] = bad;
            fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
            assert!(import(&root, &path, VIN).is_err());
        }
        let mut text = serde_json::to_string(&original).unwrap();
        text.insert_str(1, "\"ud\":false,");
        fs::write(&path, text).unwrap();
        assert!(import(&root, &path, VIN).is_err());
        fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
        assert!(import(&root, &path, "WBA3A52010F360748").is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn import_cannot_clear_unknown_local_mutation() {
        let (root, path) = fixture();
        let folder = root.join("n20_full_operations/n20-full-operation-1");
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("full-stages.jsonl"), b"interrupted").unwrap();
        import(&root, &path, VIN).unwrap();
        let state = load(&root, VIN, &identity());
        assert_eq!(state.state.last_flash_success, Some(false));
        assert_eq!(state.state.needs_recovery, Some(true));
        assert_eq!(state.state.unlock_done, Some(true));
        assert_eq!(
            crate::n20_operation_history::startup_review(&root).unwrap()["blocked"],
            true
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn imported_state_drives_agent_dispatch_without_granting_programming() {
        use crate::n20_local_input::{select, LocalBinInput, Mode};
        let (root, path) = fixture();
        let mut bytes = vec![0u8; 0x400000];
        bytes[26..36].copy_from_slice(b"MEVD1729__");
        for (p, v) in [
            (0x18000c, 0x801ffc00u32),
            (0x180038, 0x80180000),
            (0x18003c, 0x801ffbff),
        ] {
            bytes[p..p + 4].copy_from_slice(&v.to_le_bytes());
        }
        bytes[0x20024] = 8;
        bytes[0x20025..0x2002c].copy_from_slice(&[0, 0, 0x1c, 0x9f, 0x1d, 0x96, 1]);
        bytes[0x1ffd00] = 8;
        bytes[0x1ffd01..0x1ffd08].copy_from_slice(&[0, 0, 0x1c, 0xdb, 0x1d, 0x96, 7]);
        let hash = format!("{:x}", Sha256::digest(&bytes));
        let image = crate::n20_partial::PartialImage::from_bin(bytes, &hash).unwrap();
        let mut input = LocalBinInput::new(image, VIN, Mode::P).unwrap();
        let id = identity();
        import(&root, &path, VIN).unwrap();
        let loaded = load(&root, VIN, &id);
        assert_eq!(
            select(
                &input,
                VIN,
                &id.bootloader_id,
                &id.software_id,
                &loaded.state
            )
            .selected,
            Some(Mode::P)
        );
        input.requested = Mode::F;
        assert_eq!(
            select(
                &input,
                VIN,
                &id.bootloader_id,
                &id.software_id,
                &loaded.state
            )
            .selected,
            Some(Mode::F)
        );
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["ud"] = json!(false);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        import(&root, &path, VIN).unwrap();
        let decision = select(
            &input,
            VIN,
            &id.bootloader_id,
            &id.software_id,
            &load(&root, VIN, &id).state,
        );
        assert_eq!(decision.report["candidate"], "U");
        assert!(decision.selected.is_none());
        value["ud"] = json!(true);
        value["fStat"] = json!(false);
        value["nr"] = json!(true);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        import(&root, &path, VIN).unwrap();
        input.requested = Mode::P;
        let decision = select(
            &input,
            VIN,
            &id.bootloader_id,
            &id.software_id,
            &load(&root, VIN, &id).state,
        );
        assert!(decision.selected.is_none()); // no fresh condition query supplied
        assert_eq!(decision.report["candidate"], "F");
        assert_eq!(decision.report["programming_approved"], false);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn identity_chain_requires_connected_order_and_rejects_ambiguous_forks() {
        let a = identity();
        let mut b = a.clone();
        b.calibration_id = "00001CDB029150007".into();
        let mut c = b.clone();
        c.software_id = "00001C9F029150002".into();
        let ab = (10, "first".into(), a.clone(), b.clone());
        let bc = (20, "second".into(), b.clone(), c.clone());
        let (reached, lineage) = advance_identity(&a, vec![bc.clone(), ab.clone()]).unwrap();
        assert_eq!(reached, c);
        assert_eq!(lineage.len(), 2);
        assert!(advance_identity(&a, vec![bc.clone()]).is_err());
        assert!(advance_identity(
            &a,
            vec![ab.clone(), (20, "fork".into(), a.clone(), c.clone())]
        )
        .is_err());
        assert!(advance_identity(&a, vec![ab, (10, "same-time".into(), b, c)]).is_err());
    }
}

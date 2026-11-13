//! App operation owner. Live writing remains gated by reviewed support; this
//! module must never turn static legacy evidence into an approved ECU profile.
use super::*;
use crate::n20_partial::PartialImage;
use sha2::{Digest, Sha256};

// Private execution dependencies. Public APIs always supply the native runtime
// and FRB event sink; test runtimes cannot be selected by a caller or profile.
#[flutter_rust_bridge::frb(ignore)]
trait OwnerEvents {
    #[flutter_rust_bridge::frb(ignore)]
    fn add(&self, event: N20OperationEvent) -> Result<(), String>;
}
#[flutter_rust_bridge::frb(ignore)]
impl OwnerEvents for StreamSink<N20OperationEvent> {
    fn add(&self, event: N20OperationEvent) -> Result<(), String> {
        <StreamSink<N20OperationEvent>>::add(self, event).map_err(|e| e.to_string())
    }
}
#[flutter_rust_bridge::frb(ignore)]
trait OwnerRuntime {
    #[flutter_rust_bridge::frb(ignore)]
    fn gateway(&self, host: &str) -> Result<Vec<u8>, String>;
    #[flutter_rust_bridge::frb(ignore)]
    fn reconnect(&self, host: &str) -> Result<TcpStream, String>;
    #[flutter_rust_bridge::frb(ignore)]
    fn pause(&self, duration: Duration);
}
#[flutter_rust_bridge::frb(ignore)]
struct NativeRuntime;
#[flutter_rust_bridge::frb(ignore)]
impl OwnerRuntime for NativeRuntime {
    fn gateway(&self, host: &str) -> Result<Vec<u8>, String> {
        crate::n20_preflight::probe_gateway(host, Duration::from_secs(1))
    }
    fn reconnect(&self, host: &str) -> Result<TcpStream, String> {
        fresh_diagnostic_stream(host)
    }
    fn pause(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

#[cfg(test)]
#[path = "n20_owner_simulator_tests.rs"]
mod owner_simulator_tests;

struct PendingKey {
    id: String,
    sender: mpsc::SyncSender<Result<Vec<u8>, String>>,
}
fn key_slot() -> &'static Mutex<Option<PendingKey>> {
    static SLOT: OnceLock<Mutex<Option<PendingKey>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn key_test_lock() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

#[flutter_rust_bridge::frb(ignore)]
pub fn provide_key(request_id: String, key: Vec<u8>) -> Result<(), String> {
    if key.is_empty() || key.len() > 4092 {
        return Err("Invalid security response length".into());
    }
    let mut slot = key_slot()
        .lock()
        .map_err(|_| "Security callback lock poisoned")?;
    if !slot.as_ref().is_some_and(|p| p.id == request_id) {
        return Err("Security challenge expired or belongs to another operation".into());
    }
    slot.take()
        .unwrap()
        .sender
        .send(Ok(key))
        .map_err(|_| "Security challenge is no longer waiting".into())
}

#[flutter_rust_bridge::frb(ignore)]
pub fn reject_key(request_id: String, reason: String) -> Result<(), String> {
    let mut slot = key_slot()
        .lock()
        .map_err(|_| "Security callback lock poisoned")?;
    if !slot.as_ref().is_some_and(|p| p.id == request_id) {
        return Err("Security challenge is no longer pending".into());
    }
    slot.take()
        .unwrap()
        .sender
        .send(Err(reason))
        .map_err(|_| "Security callback closed".into())
}

fn event(kind: &str, message: &str, path: &str) -> N20OperationEvent {
    N20OperationEvent {
        kind: kind.into(),
        message: message.into(),
        request_id: String::new(),
        bootloader: String::new(),
        seed: vec![],
        completed_stages: 0,
        evidence_path: path.into(),
    }
}

fn request_key(
    sink: &dyn OwnerEvents,
    operation_id: &str,
    sequence: &mut u32,
    bootloader: &str,
    seed: &[u8; 8],
    path: &str,
) -> Result<Vec<u8>, String> {
    *sequence += 1;
    let id = format!("{operation_id}-key-{sequence}");
    let (sender, receiver) = mpsc::sync_channel(1);
    {
        let mut slot = key_slot()
            .lock()
            .map_err(|_| "Security callback lock poisoned")?;
        if slot.is_some() {
            return Err("Another security challenge is pending".into());
        }
        *slot = Some(PendingKey {
            id: id.clone(),
            sender,
        });
    }
    let mut challenge = event(
        "security_challenge",
        "Calculating response for the current ECU challenge",
        path,
    );
    challenge.request_id = id.clone();
    challenge.bootloader = bootloader.into();
    challenge.seed = seed.to_vec();
    if sink.add(challenge).is_err() {
        let mut slot = key_slot()
            .lock()
            .map_err(|_| "Security callback lock poisoned")?;
        if slot.as_ref().is_some_and(|p| p.id == id) {
            *slot = None;
        }
        return Err("App disconnected before security calculation".into());
    }
    let result = receiver
        .recv_timeout(Duration::from_secs(30))
        .map_err(|_| "Security calculation timed out".to_string());
    let mut slot = key_slot()
        .lock()
        .map_err(|_| "Security callback lock poisoned")?;
    if slot.as_ref().is_some_and(|p| p.id == id) {
        *slot = None;
    }
    result?
}

fn persist(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())
}

#[flutter_rust_bridge::frb(ignore)]
struct PreparationTrace<'a, C> {
    inner: C,
    sink: &'a dyn OwnerEvents,
    unknown: &'a mut bool,
    path: &'a str,
    index: u32,
    accepted: bool,
}
#[flutter_rust_bridge::frb(ignore)]
impl<C: crate::n20_setup::ControlChannel> crate::n20_setup::ControlChannel
    for PreparationTrace<'_, C>
{
    fn exchange(
        &mut self,
        target: u8,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        *self.unknown = true;
        let mut started = event(
            "preparation_request",
            &json!({"request":request}).to_string(),
            self.path,
        );
        started.completed_stages = self.index;
        let _ = self.sink.add(started);
        let reply = self.inner.exchange(target, request, timeout)?;
        let prefix = if request.first() == Some(&0x27) {
            vec![0x67, request[1]]
        } else {
            crate::dme_preparation::response_prefix(request)?
        };
        let positive = reply.starts_with(&prefix)
            && match request {
                [0x10, session] => crate::n20_session_timing::parse(&reply, *session).is_ok(),
                [0x27, 0x11, ..] => reply.len() == 10,
                [0x27, 0x12, ..] => reply.len() == 2,
                [0x22, 0xf1, 0x86] => crate::dme_preparation::active_session(&reply).is_ok(),
                [0x22, ..] => reply.len() > 3,
                _ => true,
            };
        let rejected = reply.len() == 3 && reply[..2] == [0x7f, request[0]] && reply[2] != 0x78;
        *self.unknown = !(positive || rejected);
        if request.starts_with(&[0x27, 0x12]) && positive {
            self.accepted = true;
        }
        let mut response = event(
            "preparation_exchange",
            &json!({"request":request,"response":reply}).to_string(),
            self.path,
        );
        self.index += 1;
        response.completed_stages = self.index;
        let _ = self.sink.add(response);
        if !positive && !rejected {
            return Err("Preparation response is malformed or does not match its request".into());
        }
        Ok(reply)
    }
}

#[flutter_rust_bridge::frb(ignore)]
pub fn run_preparation(
    vin: String,
    bootloader: String,
    requests: Vec<Vec<u8>>,
    prefix: Vec<u8>,
    post: Vec<Vec<u8>>,
    output: String,
    sink: StreamSink<N20OperationEvent>,
) -> Result<(), String> {
    if vin.len() != 17
        || !vin
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        || bootloader.trim().is_empty()
    {
        let _ = sink.add(event(
            "error",
            "Selected DME VIN/bootloader is required",
            "",
        ));
        return Ok(());
    }
    if let Err(detail) = crate::dme_preparation::validate(&requests, &prefix, &post) {
        let _ = sink.add(event("error", &detail, ""));
        return Ok(());
    }
    let lease = match crate::vehicle_access::vehicle_access().programming() {
        Ok(lease) => lease,
        Err(detail) => {
            let _ = sink.add(event("error", &detail, ""));
            return Ok(());
        }
    };
    thread::spawn(move || {
        let mut path = String::new();
        let mut unknown = false;
        let result = (|| -> Result<(), String> {
            let host = last_vehicle_host().ok_or("No active vehicle endpoint")?;
            let mut stream = fresh_diagnostic_stream(&host)?;
            let actual_vin = read_ascii_data_identifier(&mut stream, 0x12, "vehicle_vin")?;
            let f101 = read_data_identifier(&mut stream, 0x12, "s55_dme_identity_bundle")?;
            let actual = decode_s55_dme_identity_bundle(&f101)?;
            if actual_vin != vin || actual.bootloader != bootloader {
                return Err("Fresh DME VIN/bootloader differs from the preparation page".into());
            }
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos();
            let id = format!("dme-owned-preparation-{stamp}");
            let folder = std::path::Path::new(&output).join(&id);
            std::fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
            path = folder.to_string_lossy().into_owned();
            let manifest=serde_json::to_vec_pretty(&json!({"schema":"dme-owned-preparation-v1","vin":vin,"bootloader":bootloader,
                "f101":hex_payload(&f101),"requests":requests,"security_prefix":prefix,"post_key_requests":post,"programming_approved":false})).map_err(|e|e.to_string())?;
            persist(&folder.join("request.json"), &manifest)?;
            let binding: [u8; 32] = Sha256::digest(&manifest).into();
            let wire =
                n20_owned_transport::FileWireJournal::create(&folder.join("wire.jsonl"), &binding)?;
            let channel = n20_owned_transport::OwnedN20Transport::new(stream, wire);
            let mut sequence = 0;
            let mut traced = PreparationTrace {
                inner: channel,
                sink: &sink,
                unknown: &mut unknown,
                path: &path,
                index: 0,
                accepted: false,
            };
            let outcome = crate::dme_preparation::run(
                &mut traced,
                &requests,
                &prefix,
                &post,
                &bootloader,
                Duration::from_secs(5),
                |btld, seed| request_key(&sink, &id, &mut sequence, btld, seed, &path),
            );
            let security_accepted = traced.accepted;
            drop(traced);
            let receipt = json!({"schema":"dme-owned-preparation-result-v1","operation_binding_sha256":hex_payload(&binding),
                "completed":outcome.is_ok(),"security_response_accepted":security_accepted,"outcome_unknown":unknown,"programming_approved":false});
            if let Err(detail) = persist(
                &folder.join("result.json"),
                &serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?,
            ) {
                unknown = true;
                return Err(detail);
            }
            outcome.map_err(|e| e.detail)?;
            Ok(())
        })();
        drop(lease);
        if let Err(detail) = result {
            let _ = sink.add(event(
                if unknown {
                    "recovery_required"
                } else {
                    "error"
                },
                &detail,
                &path,
            ));
        } else {
            let _=sink.add(event("preparation_complete","DME accepted the calculated security response on the same owned connection. No BIN was erased or transferred.",&path));
        }
    });
    Ok(())
}

/// Capture observations through the operation's durable wire journal. No
/// security access, session change, routine or write is part of this probe.
fn collect_identity_evidence(
    channel: &mut impl crate::n20_setup::ControlChannel,
    expected_vin: &str,
    expected_f101: &[u8],
    binding: &[u8; 32],
) -> Result<serde_json::Value, String> {
    let timeout = Duration::from_secs(2);
    let mut records = Vec::new();
    let mut read = |request: &[u8],
                    prefix: &[u8],
                    optional: bool|
     -> Result<Option<Vec<u8>>, String> {
        let reply = channel.exchange(0x12, request, timeout)?;
        records.push(json!({"request":hex_payload(request),"response":hex_payload(&reply)}));
        if optional && reply.len() == 3 && reply[..2] == [0x7f, request[0]] && reply[2] != 0x78 {
            return Ok(None);
        }
        if !reply.starts_with(prefix) || reply.len() <= prefix.len() {
            return Err("Identity evidence received a rejected, empty or mismatched reply".into());
        }
        Ok(Some(reply[prefix.len()..].to_vec()))
    };
    let vin = read(&[0x22, 0xf1, 0x90], &[0x62, 0xf1, 0x90], false)?.unwrap();
    let f150 = read(&[0x22, 0xf1, 0x50], &[0x62, 0xf1, 0x50], false)?.unwrap();
    let f101 = read(&[0x22, 0xf1, 0x01], &[0x62, 0xf1, 0x01], false)?.unwrap();
    if vin != expected_vin.as_bytes() || f101 != expected_f101 || f150 != [0x0f, 0x18, 0x10] {
        return Err("DME identity changed before evidence collection".into());
    }
    // Preserve supplier/factory/serial/hardware replies without treating a
    // BMW component number or arbitrary printable value as a Bosch part ID.
    for did in [0xf102u16, 0xf103, 0xf18c, 0xf191] {
        let [hi, lo] = did.to_be_bytes();
        read(&[0x22, hi, lo], &[0x62, hi, lo], true)?;
    }
    let mut reference_status = "not_applicable";
    if expected_vin == N20_BENCH_VIN && hex_payload(&f101) == N20_BENCH_F101 {
        let mut samples = Vec::new();
        for (address, length) in [(0x801f_fa40, 16u16), (0xd000_0000, 64), (0x801f_fa00, 64)] {
            let request = build_ista_memory_read_request(address, length)?;
            let payload = read(&request, &[0x63], true)?;
            if payload
                .as_ref()
                .is_some_and(|bytes| bytes.len() != length as usize)
            {
                return Err("Unlock-reference memory reply has an unexpected length".into());
            }
            samples.push(payload);
        }
        reference_status = if let (Some(short), Some(header), Some(full)) =
            (&samples[0], &samples[1], &samples[2])
        {
            if classify_n20_reference(expected_vin, short, header, full).status == "reference_match"
            {
                "reference_match"
            } else {
                "reference_differs"
            }
        } else {
            "unavailable"
        };
    }
    let final_vin = read(&[0x22, 0xf1, 0x90], &[0x62, 0xf1, 0x90], false)?.unwrap();
    let final_f101 = read(&[0x22, 0xf1, 0x01], &[0x62, 0xf1, 0x01], false)?.unwrap();
    if final_vin != vin || final_f101 != f101 {
        return Err("DME identity changed during evidence collection".into());
    }
    Ok(
        json!({"schema":"n20-identity-evidence-v1", "vin":expected_vin,
        "operation_binding_sha256":hex_payload(binding), "read_only":true,
        "collected_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_millis().to_string(),
        "bosch_hardware_status":"unverified", "unlock_status":"unverified",
        "unlock_reference_status":reference_status,
        "reference_interpretation":"Comparison with one captured bench state; does not classify general unlock state",
        "programming_approved":false, "records":records}),
    )
}

#[cfg(test)]
fn approved(identity: &crate::programming::ExactIdentity<'_>) -> bool {
    crate::programming::lookup_n20_live_policy(identity).is_some()
}

fn compatibility_evidence(
    image: &PartialImage,
    vin: &str,
    fingerprint: &EcuFingerprintValues,
    operation: crate::n20_compatibility::Operation,
    binding: &[u8; 32],
) -> crate::n20_compatibility::Assessment {
    let identity = crate::programming::ExactIdentity {
        vin,
        family: "MEVD17.2.9",
        bosch_hardware: "unverified",
        bmw_hardware: &fingerprint.hardware,
        software: &fingerprint.software,
        calibration: &fingerprint.calibration,
        bootloader: &fingerprint.bootloader,
    };
    let mut result = crate::n20_compatibility::assess(image, &identity, operation);
    result.report["operation_binding_sha256"] = json!(hex_payload(binding));
    result
}

fn compatibility_block(report: &serde_json::Value) -> String {
    let reasons = report["blocking_reasons"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_else(|| "Compatibility evidence unavailable".into());
    format!("BIN-to-DME compatibility is unsupported: {reasons}. Programming remains blocked.")
}

/// Preparation is genuinely live/read-only. No setup or mutating service is
/// sent until exact support is present in the approved registry.
#[flutter_rust_bridge::frb(ignore)]
pub fn prepare(
    expected_vin: String,
    expected_software: String,
    bin_path: String,
    bin_sha256: String,
    output_directory: String,
    stock: Option<bool>,
    sink: StreamSink<N20OperationEvent>,
) -> Result<(), String> {
    begin(
        expected_vin,
        expected_software,
        bin_path,
        bin_sha256,
        output_directory,
        false,
        stock,
        sink,
    )
}

#[flutter_rust_bridge::frb(ignore)]
pub fn begin(
    expected_vin: String,
    expected_software: String,
    bin_path: String,
    bin_sha256: String,
    output_directory: String,
    execute: bool,
    stock: Option<bool>,
    sink: StreamSink<N20OperationEvent>,
) -> Result<(), String> {
    begin_mode(
        expected_vin,
        expected_software,
        bin_path,
        bin_sha256,
        output_directory,
        execute,
        false,
        stock,
        sink,
    )
}
#[flutter_rust_bridge::frb(ignore)]
pub fn begin_full(
    expected_vin: String,
    expected_software: String,
    bin_path: String,
    bin_sha256: String,
    output_directory: String,
    execute: bool,
    stock: Option<bool>,
    sink: StreamSink<N20OperationEvent>,
) -> Result<(), String> {
    begin_mode(
        expected_vin,
        expected_software,
        bin_path,
        bin_sha256,
        output_directory,
        execute,
        true,
        stock,
        sink,
    )
}
fn begin_mode(
    expected_vin: String,
    expected_software: String,
    bin_path: String,
    bin_sha256: String,
    output_directory: String,
    execute: bool,
    full: bool,
    stock: Option<bool>,
    sink: StreamSink<N20OperationEvent>,
) -> Result<(), String> {
    if expected_vin != N20_BENCH_VIN {
        let _ = sink.add(event(
            "error",
            "Only the documented N20 bench identity is accepted",
            "",
        ));
        return Ok(());
    }
    let lease = match crate::vehicle_access::vehicle_access().programming() {
        Ok(lease) => lease,
        Err(detail) => {
            let _ = sink.add(event("error", &detail, ""));
            return Ok(());
        }
    };
    thread::spawn(move || {
        let mut evidence = String::new();
        let result = (|| -> Result<(), String> {
            let _ = sink.add(event(
                "preflight",
                "Checking BIN and fresh DME identity",
                "",
            ));
            let image = PartialImage::from_bin(
                std::fs::read(&bin_path).map_err(|e| e.to_string())?,
                &bin_sha256,
            )?;
            crate::n20_integrity::require_known_image_checks(image.bytes())?;
            let full_image = if full {
                Some(crate::n20_recovery::RecoveryImage::from_bin(
                    image.bytes().to_vec(),
                    &image.sha256,
                )?)
            } else {
                None
            };
            let host = last_vehicle_host().ok_or("No active vehicle endpoint")?;
            let mut stream = fresh_diagnostic_stream(&host)?;
            if !validate_bm3_read_vehicle(&mut stream)? {
                return Err("Expected the N20 bench DME".into());
            }
            let (vin, _, fingerprint, _, _) = identify_engine(&mut stream)?;
            if vin != expected_vin || fingerprint.software != expected_software {
                return Err("Fresh identity differs from the page snapshot".into());
            }
            let mut local_input = crate::n20_local_input::LocalBinInput::new(
                image,
                &expected_vin,
                if full {
                    crate::n20_local_input::Mode::F
                } else {
                    crate::n20_local_input::Mode::P
                },
            )?;
            local_input.stock=stock;
            let input_manifest = local_input.manifest();
            let state_root = crate::vehicle_startup_safety::storage_root()?;
            let agent_state = crate::n20_agent_state::load(&state_root,&vin,&crate::n20_agent_state::Identity {
                hardware_id:fingerprint.hardware.clone(),bootloader_id:fingerprint.bootloader.clone(),
                software_id:fingerprint.software.clone(),calibration_id:fingerprint.calibration.clone(),
            });
            let status=crate::n20_preflight_status::load(&state_root,&vin,&crate::n20_agent_state::Identity {
                hardware_id:fingerprint.hardware.clone(),bootloader_id:fingerprint.bootloader.clone(),software_id:fingerprint.software.clone(),calibration_id:fingerprint.calibration.clone()
            },SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_nanos());
            let live_identity=crate::n20_agent_state::Identity{hardware_id:fingerprint.hardware.clone(),bootloader_id:fingerprint.bootloader.clone(),software_id:fingerprint.software.clone(),calibration_id:fingerprint.calibration.clone()};
            let dispatch = crate::n20_local_input::choose_for_bin(&state_root,&local_input,&vin,&live_identity,&agent_state.state,&status.status)?;
            let access_observation=super::n20_access_evidence::collect(&state_root,&vin,&live_identity);
            let image = local_input.image;
            let f101 =
                read_data_identifier(&mut stream, ENGINE_ECU_ADDRESS, "s55_dme_identity_bundle")?;
            if decode_f101_last_flash_date(&f101).is_none() {
                return Err("Current SVK programming-date record is unavailable".into());
            }
            let date: [u8; 3] = f101[4..7]
                .try_into()
                .map_err(|_| "Missing programming date")?;
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos();
            let root = std::path::Path::new(&output_directory);
            std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
            let operation_id = format!(
                "n20-{}operation-{timestamp}",
                if full { "full-" } else { "" }
            );
            let operation = root.join(&operation_id);
            std::fs::create_dir(&operation).map_err(|e| e.to_string())?;
            evidence = operation.to_string_lossy().into_owned();
            let mut identity_reply = vec![0x62, 0xf1, 1];
            identity_reply.extend(&f101);
            let binding = json!({"schema":if full{"n20-full-operation-v1"}else{"n20-operation-v1"},"operation_kind":if full{"full"}else{"partial"},"vin":vin,"software":fingerprint.software,
                "bootloader":fingerprint.bootloader,"hardware":fingerprint.hardware,"calibration":fingerprint.calibration,
                "bin_sha256":image.sha256,"f101":hex_payload(&identity_reply),"fingerprint_date":date,
                "descriptor_integrity":crate::n20_integrity::summary(image.bytes()),
                "known_descriptor_preflight_passed":true,
                "local_flash_input":input_manifest,"agent_dispatch":dispatch.report,"agent_state_resolution":agent_state.report,"agent_preflight_status":status.report,"programming_access_evidence":access_observation,
                "profile_approval":"evaluated after fresh coding snapshot"});
            let binding_bytes = serde_json::to_vec_pretty(&binding).map_err(|e| e.to_string())?;
            persist(&operation.join("operation.json"), &binding_bytes)?;
            let binding_hash: [u8; 32] = Sha256::digest(&binding_bytes).into();
            let wire = n20_owned_transport::FileWireJournal::create(
                &operation.join("wire.jsonl"),
                &binding_hash,
            )?;
            let mut channel = n20_owned_transport::OwnedN20Transport::new(stream, wire);
            let coding = crate::n20_coding::CodingSnapshot::read(
                &mut channel,
                &expected_vin,
                Duration::from_secs(5),
            )?;
            persist(
                &operation.join("coding.json"),
                &serde_json::to_vec_pretty(&coding.manifest()).map_err(|e| e.to_string())?,
            )?;
            let coding_bytes =
                serde_json::to_vec_pretty(&coding.manifest()).map_err(|e| e.to_string())?;
            let coding_hash = format!("{:x}", Sha256::digest(&coding_bytes));
            if full {
                persist(&operation.join("coding-binding.json"),&serde_json::to_vec_pretty(&json!({"operation_binding_sha256":hex_payload(&binding_hash),"coding_sha256":coding_hash})).map_err(|e|e.to_string())?)?;
            }
            persist(&operation.join("selected.bin"), image.bytes())?;
            if let Some(full_image) = full_image.as_ref() {
                persist(&operation.join("full-regions.json"),&serde_json::to_vec_pretty(&json!({"schema":"n20-full-regions-v1","operation_kind":"full","startup_written":false,"regions":full_image.manifest()["regions"],"transferred_bytes":3931392})).map_err(|e|e.to_string())?)?;
            }
            let mut observations = crate::n20_preflight::collect(&host, &mut channel)?;
            observations["identity_evidence"] =
                collect_identity_evidence(&mut channel, &expected_vin, &f101, &binding_hash)?;
            let compatibility = compatibility_evidence(
                &image,
                &expected_vin,
                &fingerprint,
                if full {
                    crate::n20_compatibility::Operation::Full
                } else {
                    crate::n20_compatibility::Operation::Partial
                },
                &binding_hash,
            );
            observations["bin_compatibility"] = compatibility.report.clone();
            observations["local_flash_input"] = binding["local_flash_input"].clone();
            observations["agent_dispatch"] = binding["agent_dispatch"].clone();
            observations["agent_state_resolution"] = binding["agent_state_resolution"].clone();
            observations["agent_preflight_status"] = binding["agent_preflight_status"].clone();
            observations["programming_access_evidence"] = binding["programming_access_evidence"].clone();
            persist(
                &operation.join("preflight-observations.json"),
                &serde_json::to_vec_pretty(&observations).map_err(|e| e.to_string())?,
            )?;
            let _ = sink.add(event(
                "preflight_report",
                "Identity, unlock-reference, gateway and timing evidence saved; programming remains subject to profile approval",
                &evidence,
            ));

            let route_matches = if full {
                matches!(
                    dispatch.selected,
                    Some(crate::n20_local_input::Mode::F | crate::n20_local_input::Mode::FF)
                )
            } else {
                matches!(
                    dispatch.selected,
                    Some(crate::n20_local_input::Mode::P | crate::n20_local_input::Mode::PF)
                )
            };
            if !route_matches {
                let gaps = binding["agent_dispatch"]["missing_requirements"]
                    .as_array()
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .unwrap_or_default();
                let _=sink.add(event("blocked",&format!("Local BIN loaded for {}. Agent candidate {} (force={}) is unresolved or outside this entry: {gaps}. Separate compatibility/programming checks remain required.",if full{"full software/calibration"}else{"partial calibration"},binding["agent_dispatch"]["candidate"].as_str().unwrap_or("unknown"),binding["agent_dispatch"]["force"]),&evidence));
                return Ok(());
            }
            if !compatibility.approved {
                let _ = sink.add(event(
                    if !execute && compatibility.identity_checks_passed {
                        "prepared_without_write_approval"
                    } else {
                        "blocked"
                    },
                    &compatibility_block(&compatibility.report),
                    &evidence,
                ));
                return Ok(());
            }

            // A stored reference match and a working calculator are not an
            // erase/checksum/recovery specification. Never bypass this gate.
            let identity = crate::programming::ExactIdentity {
                vin: &expected_vin,
                family: "MEVD17.2.9",
                bosch_hardware: "unverified",
                bmw_hardware: &fingerprint.hardware,
                software: &fingerprint.software,
                calibration: &fingerprint.calibration,
                bootloader: &fingerprint.bootloader,
            };
            if full {
                let full_image = full_image.ok_or("Full image was not validated")?;
                let Some(policy) = crate::programming::lookup_n20_full_policy(
                    &identity,
                    &image.sha256,
                    &coding_hash,
                ) else {
                    let _=sink.add(event("blocked","Full BIN operation prepared. No reviewed ordinary full-flash profile matches; recovery-only approval cannot authorize it.",&evidence));
                    return Ok(());
                };
                if !execute {
                    let _=sink.add(event("ready","Ordinary full software/calibration operation prepared for its reviewed profile.",&evidence));
                    return Ok(());
                }
                return execute_rewrite(
                    &lease,
                    channel,
                    RewriteInputs {
                        image: full_image,
                        coding,
                    },
                    identity_reply,
                    date,
                    &fingerprint,
                    &expected_vin,
                    &host,
                    &operation_id,
                    &operation,
                    &evidence,
                    &binding_hash,
                    policy,
                    &sink,
                    &NativeRuntime,
                    crate::n20_recovery::RewriteKind::Full,
                );
            }
            let Some(policy) = crate::programming::lookup_n20_live_policy(&identity) else {
                let reference = observations["identity_evidence"]["unlock_reference_status"]
                    .as_str()
                    .unwrap_or("unavailable");
                let _=sink.add(event("blocked",
                    &format!("Operation prepared and coding saved. Unlock reference: {reference}; unlock and Bosch hardware remain unverified. Writing is blocked: no reviewed N20 erase, image-integrity and recovery profile is registered."),&evidence));
                return Ok(());
            };
            if !execute {
                let _=sink.add(event("ready","Operation preparation passed for the registered profile. Review before starting.",&evidence));
                return Ok(());
            }
            execute_approved(
                &lease,
                channel,
                coding,
                image,
                identity_reply,
                date,
                &fingerprint,
                &expected_vin,
                &host,
                &operation_id,
                &operation,
                &evidence,
                &binding_hash,
                policy,
                &sink,
                &NativeRuntime,
            )
        })();
        if let Err(detail) = result {
            let _ = sink.add(event("error", &detail, &evidence));
        }
        drop(lease);
    });
    Ok(())
}

struct ProgressJournal<'a> {
    inner: crate::n20_stage_journal::FileStageJournal,
    sink: &'a dyn OwnerEvents,
    path: &'a str,
    completed: u32,
}
impl crate::n20_partial::StageJournal for ProgressJournal<'_> {
    fn record(
        &mut self,
        stage: crate::n20_partial::Stage,
        completed: bool,
        hash: &str,
    ) -> Result<(), String> {
        self.inner.record(stage, completed, hash)?;
        if completed {
            self.completed += 1;
        }
        let mut update = event(
            "stage",
            &format!(
                "{stage:?}: {}",
                if completed { "complete" } else { "started" }
            ),
            self.path,
        );
        update.completed_stages = self.completed;
        // A lost UI must not interrupt evidence recording after a write.
        let _ = self.sink.add(update);
        Ok(())
    }
}

fn compact_component(value: &str) -> Result<String, String> {
    if value.len() != 17 || !value.is_ascii() || !value[..8].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("Unrecognized DME component identifier".into());
    }
    let mut result = value[..8].to_ascii_uppercase();
    for offset in [8, 11, 14] {
        let byte = value[offset..offset + 3]
            .parse::<u8>()
            .map_err(|_| "Invalid component version")?;
        result.push_str(&format!("{byte:02X}"));
    }
    Ok(result)
}

fn check_power(
    channel: &mut impl crate::n20_setup::ControlChannel,
    policy: &crate::programming::LiveN20Policy,
) -> Result<Vec<u32>, String> {
    if !(3..=64).contains(&policy.minimum_samples)
        || policy.minimum_voltage_mv >= policy.maximum_voltage_mv
    {
        return Err("Invalid registered power policy".into());
    }
    let mut samples = Vec::new();
    for _ in 0..policy.minimum_samples {
        let reply = channel.exchange(0x12, &[0x22, 0x58, 0x6a], Duration::from_secs(5))?;
        if reply.len() != 5 || !reply.starts_with(&[0x62, 0x58, 0x6a]) {
            return Err("Invalid DME voltage response".into());
        }
        let mv = 6000u32 + u16::from_be_bytes([reply[3], reply[4]]) as u32 / 4;
        samples.push(mv);
    }
    let min = *samples.iter().min().unwrap();
    let max = *samples.iter().max().unwrap();
    if min < u32::from(policy.minimum_voltage_mv)
        || max > u32::from(policy.maximum_voltage_mv)
        || max - min > u32::from(policy.maximum_voltage_span_mv)
    {
        return Err("DME voltage does not meet the approved profile".into());
    }
    Ok(samples)
}

fn enforce_gate(
    host: &str,
    channel: &mut impl crate::n20_setup::ControlChannel,
    policy: crate::n20_programming_gate::Policy,
    timeout: Duration,
    folder: &std::path::Path,
    binding: &[u8; 32],
    sink: &dyn OwnerEvents,
    evidence: &str,
    runtime: &dyn OwnerRuntime,
) -> Result<Option<Instant>, String> {
    policy.validate()?;
    persist(&folder.join("gate-intent.json"),&serde_json::to_vec_pretty(&json!({"schema":"n20-enforced-gate-intent-v1",
        "operation_binding":hex_payload(binding),"ignition_evidence":policy.ignition_evidence_id,"condition_evidence":policy.condition_evidence_id})).map_err(|e|e.to_string())?)?;
    let _ = sink.add(event(
        "gate_check",
        "Enforcing fresh gateway and ECU programming-condition checks before setup",
        evidence,
    ));
    let result = crate::n20_programming_gate::run(
        channel,
        policy,
        timeout,
        || runtime.gateway(host),
        |duration| runtime.pause(duration),
    );
    let (mut report, unknown) = match &result {
        Ok(proof) => (proof.report.clone(), false),
        Err(failure) => (failure.report.clone(), failure.outcome_unknown),
    };
    report["operation_binding"] = json!(hex_payload(binding));
    report["outcome_unknown"] = json!(unknown);
    let storage = persist(
        &folder.join("enforced-gate.json"),
        &serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    );
    match result {
        Ok(proof) => {
            storage?;
            if Instant::now() >= proof.valid_until {
                return Err(
                    "Programming gate expired while saving evidence; setup was not started".into(),
                );
            }
            Ok(Some(proof.valid_until))
        }
        Err(failure) => {
            let detail = match storage {
                Ok(()) => failure.detail,
                Err(e) => format!("{}; gate evidence could not be saved: {e}", failure.detail),
            };
            let _ = sink.add(event(
                if unknown {
                    "recovery_required"
                } else {
                    "blocked"
                },
                &detail,
                evidence,
            ));
            Ok(None)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_approved(
    lease: &crate::vehicle_access::Lease,
    mut channel: n20_owned_transport::OwnedN20Transport<n20_owned_transport::FileWireJournal>,
    coding: crate::n20_coding::CodingSnapshot,
    image: PartialImage,
    f101_reply: Vec<u8>,
    fingerprint_date: [u8; 3],
    fingerprint: &EcuFingerprintValues,
    vin: &str,
    host: &str,
    operation_id: &str,
    operation: &std::path::Path,
    evidence: &str,
    binding: &[u8; 32],
    policy: crate::programming::LiveN20Policy,
    sink: &dyn OwnerEvents,
    runtime: &dyn OwnerRuntime,
) -> Result<(), String> {
    use crate::n20_setup::ControlChannel;
    channel.configure_session_timing(policy.session_timing)?;
    let _ = sink.add(event("power_check", "Checking bench voltage", evidence));
    let samples = check_power(&mut channel, &policy)?;
    let Some(gate_valid_until) = enforce_gate(
        host,
        &mut channel,
        policy.gate,
        Duration::from_secs(5),
        operation,
        binding,
        sink,
        evidence,
        runtime,
    )?
    else {
        return Ok(());
    };
    persist(
        &operation.join("prewrite-approval.json"),
        &serde_json::to_vec_pretty(&json!({
            "backend":policy.backend_id,"evidence":policy.evidence_id,"recovery":policy.recovery_id,
            "erase_evidence":policy.erase_evidence_id,"erase_success_result":policy.erase_success_result,
            "operation_binding":hex_payload(binding),"voltage_mv":samples,
            "session_timing_bounds":{"max_p2_ms":policy.session_timing.max_p2_ms,"max_p2_star_ms":policy.session_timing.max_p2_star_ms,"margin_ms":policy.session_timing.margin_ms}
        }))
        .map_err(|e| e.to_string())?,
    )?;
    let mut stages = ProgressJournal {
        inner: crate::n20_stage_journal::FileStageJournal::create(
            &operation.join("stages.jsonl"),
            binding,
            &image.sha256,
        )?,
        sink,
        path: evidence,
        completed: 0,
    };
    let mut main = crate::exchange_journal::FileExchangeJournal::create(
        &operation.join("main.jsonl"),
        binding,
    )
    .map_err(|e| e.to_string())?;
    let mut tail = crate::exchange_journal::FileExchangeJournal::create(
        &operation.join("tail.jsonl"),
        binding,
    )
    .map_err(|e| e.to_string())?;
    let expected_bytes = image.bytes().to_vec();
    let expected_software = image.software_token.clone();
    let expected_calibration = image.calibration_token();
    let original_coding = coding.manifest();
    let mut sequence = 0;
    let calculate = |bootloader: &str, seed: &[u8; 8]| {
        request_key(
            sink,
            operation_id,
            &mut sequence,
            bootloader,
            seed,
            evidence,
        )
    };
    let verify = || -> Result<(), String> {
        // One fresh read-only connection after reset; never replay a write.
        runtime.pause(Duration::from_secs(2));
        let mut stream = runtime.reconnect(host)?;
        let (actual_vin, _, actual, _, _) = identify_engine(&mut stream)?;
        if actual_vin != vin
            || actual.hardware != fingerprint.hardware
            || actual.bootloader != fingerprint.bootloader
            || compact_component(&actual.software)? != expected_software
            || compact_component(&actual.calibration)? != expected_calibration
        {
            return Err("Post-reset DME identity differs from the intended result".into());
        }
        let wire = n20_owned_transport::FileWireJournal::create(
            &operation.join("verification-wire.jsonl"),
            binding,
        )?;
        let mut reader = n20_owned_transport::OwnedN20Transport::new(stream, wire);
        reader.configure_readback(n20_owned_transport::ReadbackScope::Partial, 256)?;
        for range in [0x180000usize..0x1ffc00, 0x1ffd00..0x200000] {
            for start in (range.start..range.end).step_by(256) {
                let end = (start + 256).min(range.end);
                let request = build_ista_memory_read_request(
                    0x80000000 + start as u32,
                    (end - start) as u16,
                )?;
                let response = reader.exchange(0x12, &request, Duration::from_secs(5))?;
                let actual = parse_ista_memory_read_response(&response, end - start)?;
                if actual != &expected_bytes[start..end] {
                    return Err(format!("Post-reset readback differs at 0x{start:06X}"));
                }
            }
        }
        let restored =
            crate::n20_coding::CodingSnapshot::read(&mut reader, vin, Duration::from_secs(5))?;
        if restored.manifest() != original_coding {
            return Err("Post-reset coding differs from the saved snapshot".into());
        }
        persist(
            &operation.join("verification.json"),
            &serde_json::to_vec_pretty(&json!({
                "vin":actual_vin,"software":actual.software,"calibration":actual.calibration,
                "transferred_bytes_verified":524032,"coding_matches":true,
                "identity_transition":crate::n20_agent_state::transition(binding,vin,
                    &crate::n20_agent_state::Identity{hardware_id:fingerprint.hardware.clone(),bootloader_id:fingerprint.bootloader.clone(),software_id:fingerprint.software.clone(),calibration_id:fingerprint.calibration.clone()},
                    &crate::n20_agent_state::Identity{hardware_id:actual.hardware.clone(),bootloader_id:actual.bootloader.clone(),software_id:actual.software.clone(),calibration_id:actual.calibration.clone()})
            }))
            .map_err(|e| e.to_string())?,
        )?;
        Ok(())
    };
    let inputs = crate::n20_procedure::BoundInputs {
        vin: vin.into(),
        bootloader: fingerprint.bootloader.clone(),
        software_token: image.software_token.clone(),
        f101_reply,
        fingerprint_date,
        prepare_auxiliary: vin != N20_BENCH_VIN,
        erase_success_result: policy.erase_success_result,
        setup_valid_until: Some(gate_valid_until),
    };
    let mut procedure = crate::n20_procedure::N20Procedure::new(
        channel,
        inputs,
        coding,
        calculate,
        verify,
        Duration::from_secs(30),
    )?;
    let result = crate::n20_partial::run_owned(
        lease,
        &mut procedure,
        image,
        &mut stages,
        &mut main,
        &mut tail,
        Duration::from_secs(30),
    );
    match result {
        Ok(()) => {
            let mut done = event(
                "complete",
                "Programming and independent post-reset verification completed",
                evidence,
            );
            done.completed_stages = 10;
            let _ = sink.add(done);
        }
        Err(failure) => {
            let rejected_before_programming =
                failure.stage == crate::n20_partial::Stage::SetupAndAuthorize
                    && crate::n20_operation_history::rejected_before_programming(operation, binding);
            let kind = if failure.ecu_state_may_have_changed && !rejected_before_programming {
                "recovery_required"
            } else {
                "error"
            };
            let _ = sink.add(event(
                kind,
                &format!("{:?}: {}", failure.stage, failure.detail),
                evidence,
            ));
        }
    }
    Ok(())
}

struct RecoveryInputs {
    image: crate::n20_recovery::RecoveryImage,
    coding: crate::n20_coding::CodingSnapshot,
    original: Value,
    plan_bytes: Vec<u8>,
    original_bytes: Vec<u8>,
    coding_bytes: Vec<u8>,
    coding_hash: String,
}
struct RewriteInputs {
    image: crate::n20_recovery::RecoveryImage,
    coding: crate::n20_coding::CodingSnapshot,
}
impl From<RecoveryInputs> for RewriteInputs {
    fn from(inputs: RecoveryInputs) -> Self {
        Self {
            image: inputs.image,
            coding: inputs.coding,
        }
    }
}
fn load_recovery_inputs(
    plan_path: &str,
    vin: &str,
    image_hash: &str,
) -> Result<RecoveryInputs, String> {
    let path = std::path::Path::new(plan_path);
    let folder = path.parent().ok_or("Recovery plan folder is missing")?;
    let plan_bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let plan: Value = serde_json::from_slice(&plan_bytes).map_err(|e| e.to_string())?;
    let image = crate::n20_recovery::RecoveryImage::from_bin(
        std::fs::read(folder.join("selected.bin")).map_err(|e| e.to_string())?,
        image_hash,
    )?;
    let expected = image.manifest();
    if plan["schema"] != expected["schema"]
        || plan["vin"] != vin
        || plan["bin_sha256"] != image_hash
        || plan["regions"] != expected["regions"]
        || plan["total_bytes"] != expected["total_bytes"]
    {
        return Err("Recovery plan VIN, image or six-region layout differs".into());
    }
    let original_bytes =
        std::fs::read(folder.join("original-operation.json")).map_err(|e| e.to_string())?;
    let coding_bytes =
        std::fs::read(folder.join("original-coding.json")).map_err(|e| e.to_string())?;
    let original_hash = format!("{:x}", Sha256::digest(&original_bytes));
    let coding_hash = format!("{:x}", Sha256::digest(&coding_bytes));
    if plan["original_operation_sha256"] != original_hash
        || plan["original_coding_sha256"] != coding_hash
    {
        return Err("Original recovery evidence hash differs from the saved plan".into());
    }
    let original: Value = serde_json::from_slice(&original_bytes).map_err(|e| e.to_string())?;
    if (original["schema"] != "n20-operation-v1" && original["schema"] != "n20-full-operation-v1")
        || original["vin"] != vin
        || compact_component(
            original["software"]
                .as_str()
                .ok_or("Missing original software")?,
        )? != image.partial().software_token
    {
        return Err("Original operation identity does not match recovery image".into());
    }
    let value: Value = serde_json::from_slice(&coding_bytes).map_err(|e| e.to_string())?;
    let coding = crate::n20_coding::CodingSnapshot::from_manifest(&value, vin)?;
    Ok(RecoveryInputs {
        image,
        coding,
        original,
        plan_bytes,
        original_bytes,
        coding_bytes,
        coding_hash,
    })
}

#[flutter_rust_bridge::frb(ignore)]
pub fn begin_recovery(
    expected_vin: String,
    bin_sha256: String,
    plan_path: String,
    output_directory: String,
    execute: bool,
    sink: StreamSink<N20OperationEvent>,
) -> Result<(), String> {
    if expected_vin != N20_BENCH_VIN {
        let _ = sink.add(event(
            "error",
            "Only the documented N20 bench identity is accepted",
            "",
        ));
        return Ok(());
    }
    let lease = match crate::vehicle_access::vehicle_access().programming() {
        Ok(lease) => lease,
        Err(detail) => {
            let _ = sink.add(event("error", &detail, ""));
            return Ok(());
        }
    };
    thread::spawn(move || {
        let mut evidence = String::new();
        let result = (|| -> Result<(), String> {
            let _ = sink.add(event(
                "preflight",
                "Checking original recovery evidence and fresh DME identity",
                "",
            ));
            let inputs = load_recovery_inputs(&plan_path, &expected_vin, &bin_sha256)?;
            let host = last_vehicle_host().ok_or("No active vehicle endpoint")?;
            let mut stream = fresh_diagnostic_stream(&host)?;
            if read_data_identifier(&mut stream, 0x12, "ecu_identification")? != [0x0f, 0x18, 0x10]
            {
                return Err("Expected documented N20 ECU identification".into());
            }
            let (vin, _, fingerprint, _, _) = identify_engine(&mut stream)?;
            if vin != expected_vin
                || inputs.original["hardware"] != fingerprint.hardware
                || inputs.original["bootloader"] != fingerprint.bootloader
                || inputs.original["software"] != fingerprint.software
            {
                return Err("Responding DME differs from the original recovery identity".into());
            }
            let f101 = read_data_identifier(&mut stream, 0x12, "s55_dme_identity_bundle")?;
            if decode_f101_last_flash_date(&f101).is_none() {
                return Err("Current SVK programming-date record is unavailable".into());
            }
            let date: [u8; 3] = f101[4..7]
                .try_into()
                .map_err(|_| "Missing programming date")?;
            let mut identity_reply = vec![0x62, 0xf1, 1];
            identity_reply.extend(&f101);
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos();
            let root = std::path::Path::new(&output_directory);
            std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
            let operation_id = format!("n20-recovery-operation-{stamp}");
            let folder = root.join(&operation_id);
            std::fs::create_dir(&folder).map_err(|e| e.to_string())?;
            evidence = folder.to_string_lossy().into_owned();
            let binding_bytes=serde_json::to_vec_pretty(&json!({"schema":"n20-live-recovery-v1","vin":vin,
                "hardware":fingerprint.hardware,"bootloader":fingerprint.bootloader,"software":fingerprint.software,
                "calibration":fingerprint.calibration,"f101":hex_payload(&identity_reply),"fingerprint_date":date,
                "plan_sha256":format!("{:x}",Sha256::digest(&inputs.plan_bytes)),"coding_sha256":inputs.coding_hash,
                "bin_sha256":inputs.image.partial().sha256,"regions":inputs.image.manifest()["regions"],"boot_recovery":false})).map_err(|e|e.to_string())?;
            persist(&folder.join("operation.json"), &binding_bytes)?;
            persist(&folder.join("recovery-plan.json"), &inputs.plan_bytes)?;
            persist(
                &folder.join("original-operation.json"),
                &inputs.original_bytes,
            )?;
            persist(&folder.join("original-coding.json"), &inputs.coding_bytes)?;
            persist(&folder.join("selected.bin"), inputs.image.partial().bytes())?;
            let identity = crate::programming::ExactIdentity {
                vin: &vin,
                family: "MEVD17.2.9",
                bosch_hardware: "unverified",
                bmw_hardware: &fingerprint.hardware,
                bootloader: &fingerprint.bootloader,
                software: &fingerprint.software,
                calibration: &fingerprint.calibration,
            };
            let binding: [u8; 32] = Sha256::digest(&binding_bytes).into();
            let wire =
                n20_owned_transport::FileWireJournal::create(&folder.join("wire.jsonl"), &binding)?;
            let mut channel = n20_owned_transport::OwnedN20Transport::new(stream, wire);
            let mut observations = crate::n20_preflight::collect(&host, &mut channel)?;
            observations["identity_evidence"] =
                collect_identity_evidence(&mut channel, &expected_vin, &f101, &binding)?;
            let compatibility = compatibility_evidence(
                inputs.image.partial(),
                &expected_vin,
                &fingerprint,
                crate::n20_compatibility::Operation::Recovery,
                &binding,
            );
            observations["bin_compatibility"] = compatibility.report.clone();
            persist(
                &folder.join("preflight-observations.json"),
                &serde_json::to_vec_pretty(&observations).map_err(|e| e.to_string())?,
            )?;
            let _ = sink.add(event(
                "preflight_report",
                "Recovery identity, unlock-reference, gateway and timing evidence saved",
                &evidence,
            ));
            if !compatibility.approved {
                let _ = sink.add(event(
                    "blocked",
                    &compatibility_block(&compatibility.report),
                    &evidence,
                ));
                return Ok(());
            }
            let Some(policy) = crate::programming::lookup_n20_recovery_policy(
                &identity,
                &inputs.image.partial().sha256,
                &inputs.coding_hash,
            ) else {
                let _=sink.add(event("blocked","Recovery inputs saved. No separate reviewed full-rewrite profile matches the DME, image and original coding.",&evidence));
                return Ok(());
            };
            if !execute {
                let _ = sink.add(event(
                    "ready",
                    "Recovery preflight passed for the separate full-rewrite profile.",
                    &evidence,
                ));
                return Ok(());
            }
            execute_rewrite(
                &lease,
                channel,
                inputs.into(),
                identity_reply,
                date,
                &fingerprint,
                &vin,
                &host,
                &operation_id,
                &folder,
                &evidence,
                &binding,
                policy,
                &sink,
                &NativeRuntime,
                crate::n20_recovery::RewriteKind::Recovery,
            )
        })();
        if let Err(detail) = result {
            let _ = sink.add(event("error", &detail, &evidence));
        }
        drop(lease);
    });
    Ok(())
}
struct RecoveryProgress<'a> {
    inner: crate::n20_recovery::FileStageJournal,
    sink: &'a dyn OwnerEvents,
    path: &'a str,
    completed: u32,
}
impl crate::n20_recovery::StageJournal for RecoveryProgress<'_> {
    fn record(
        &mut self,
        stage: crate::n20_recovery::Stage,
        completed: bool,
        hash: &str,
    ) -> Result<(), String> {
        self.inner.record(stage, completed, hash)?;
        if completed {
            self.completed += 1;
        }
        let mut update = event(
            "stage",
            &format!(
                "Recovery {stage:?}: {}",
                if completed { "complete" } else { "started" }
            ),
            self.path,
        );
        update.completed_stages = self.completed;
        let _ = self.sink.add(update);
        Ok(())
    }
}
#[allow(clippy::too_many_arguments)]
fn execute_rewrite(
    lease: &crate::vehicle_access::Lease,
    mut channel: n20_owned_transport::OwnedN20Transport<n20_owned_transport::FileWireJournal>,
    inputs: RewriteInputs,
    f101_reply: Vec<u8>,
    date: [u8; 3],
    fingerprint: &EcuFingerprintValues,
    vin: &str,
    host: &str,
    operation_id: &str,
    folder: &std::path::Path,
    evidence: &str,
    binding: &[u8; 32],
    policy: crate::programming::LiveN20RewritePolicy,
    sink: &dyn OwnerEvents,
    runtime: &dyn OwnerRuntime,
    kind: crate::n20_recovery::RewriteKind,
) -> Result<(), String> {
    use crate::n20_setup::ControlChannel;
    if policy.common.backend_id != kind.backend() {
        return Err("Six-region programming policy belongs to a different operation kind".into());
    }
    channel.configure_session_timing(policy.common.session_timing)?;
    let _ = sink.add(event("power_check", "Checking bench voltage", evidence));
    let samples = check_power(&mut channel, &policy.common)?;
    let Some(gate_valid_until) = enforce_gate(
        host,
        &mut channel,
        policy.common.gate,
        Duration::from_millis(policy.control_timeout_ms),
        folder,
        binding,
        sink,
        evidence,
        runtime,
    )?
    else {
        return Ok(());
    };
    persist(&folder.join("prewrite-approval.json"),&serde_json::to_vec_pretty(&json!({"operation_kind":kind.name(),"backend":policy.common.backend_id,
        "evidence":policy.common.evidence_id,"recovery":policy.common.recovery_id,"software_erase_evidence":policy.software_erase_evidence,
        "calibration_erase_evidence":policy.common.erase_evidence_id,"software_erase_result":policy.software_erase_result,
        "calibration_erase_result":policy.common.erase_success_result,"voltage_mv":samples,"operation_binding":hex_payload(binding),
            "session_timing_bounds":{"max_p2_ms":policy.common.session_timing.max_p2_ms,"max_p2_star_ms":policy.common.session_timing.max_p2_star_ms,"margin_ms":policy.common.session_timing.margin_ms}})).map_err(|e|e.to_string())?)?;
    let hash = inputs.image.partial().sha256.clone();
    let mut stages = RecoveryProgress {
        inner: crate::n20_recovery::FileStageJournal::create_kind(
            &folder.join(kind.stage_file()),
            binding,
            &hash,
            kind,
        )?,
        sink,
        path: evidence,
        completed: 0,
    };
    let mut journals = Vec::new();
    for i in 0..6 {
        journals.push(
            crate::exchange_journal::FileExchangeJournal::create(
                &folder.join(format!("region-{i}.jsonl")),
                binding,
            )
            .map_err(|e| e.to_string())?,
        );
    }
    let mut journals: [crate::exchange_journal::FileExchangeJournal; 6] = journals
        .try_into()
        .map_err(|_| "Expected six recovery journals")?;
    let expected_software = inputs.image.partial().software_token.clone();
    let expected_calibration = inputs.image.partial().calibration_token();
    let original_coding = inputs.coding.manifest();
    let mut sequence = 0;
    let calculate = |bootloader: &str, seed: &[u8; 8]| {
        request_key(
            sink,
            operation_id,
            &mut sequence,
            bootloader,
            seed,
            evidence,
        )
    };
    let readbacks = RefCell::new(None::<[Vec<u8>; 6]>);
    let verified_identity = RefCell::new(None::<crate::n20_agent_state::Identity>);
    let verify = || -> Result<(), String> {
        runtime.pause(Duration::from_millis(policy.post_reset_wait_ms));
        let mut stream = runtime.reconnect(host)?;
        let (actual_vin, _, actual, _, _) = identify_engine(&mut stream)?;
        if actual_vin != vin
            || actual.hardware != fingerprint.hardware
            || actual.bootloader != fingerprint.bootloader
            || compact_component(&actual.software)? != expected_software
            || compact_component(&actual.calibration)? != expected_calibration
        {
            return Err(format!("{} post-reset identity differs", kind.name()));
        }
        let wire = n20_owned_transport::FileWireJournal::create(
            &folder.join("verification-wire.jsonl"),
            binding,
        )?;
        let mut reader = n20_owned_transport::OwnedN20Transport::new(stream, wire);
        reader.configure_readback(
            if kind == crate::n20_recovery::RewriteKind::Full {
                n20_owned_transport::ReadbackScope::Full
            } else {
                n20_owned_transport::ReadbackScope::Recovery
            },
            policy.readback_chunk,
        )?;
        let restored = crate::n20_coding::CodingSnapshot::read(
            &mut reader,
            vin,
            Duration::from_millis(policy.control_timeout_ms),
        )?;
        if restored.manifest() != original_coding {
            return Err(format!(
                "{} post-reset coding differs from saved coding",
                kind.name()
            ));
        }
        persist(&folder.join("post-reset-identity.json"),&serde_json::to_vec_pretty(&json!({
            "operation_kind":kind.name(),"vin":actual_vin,"software":actual.software,"calibration":actual.calibration,
            "hardware":actual.hardware,"bootloader":actual.bootloader,"coding_matches":true,"six_region_verification_pending":true
        })).map_err(|e|e.to_string())?)?;
        let mut data: [Vec<u8>; 6] = std::array::from_fn(|_| Vec::new());
        for (index, region) in crate::n20_recovery::REGIONS.iter().enumerate() {
            for offset in (0..region.length).step_by(policy.readback_chunk) {
                let length = policy.readback_chunk.min(region.length - offset);
                let request = build_ista_memory_read_request(
                    region.address() + offset as u32,
                    length as u16,
                )?;
                let response = reader.exchange(
                    0x12,
                    &request,
                    Duration::from_millis(policy.control_timeout_ms),
                )?;
                data[index].extend(parse_ista_memory_read_response(&response, length)?);
            }
        }
        *readbacks.borrow_mut() = Some(data);
        *verified_identity.borrow_mut()=Some(crate::n20_agent_state::Identity{hardware_id:actual.hardware.clone(),bootloader_id:actual.bootloader.clone(),software_id:actual.software.clone(),calibration_id:actual.calibration.clone()});
        Ok(())
    };
    let bound = crate::n20_procedure::BoundInputs {
        vin: vin.into(),
        bootloader: fingerprint.bootloader.clone(),
        software_token: inputs.image.partial().software_token.clone(),
        f101_reply,
        fingerprint_date: date,
        prepare_auxiliary: true,
        erase_success_result: policy.common.erase_success_result,
        setup_valid_until: Some(gate_valid_until),
    };
    let inner = crate::n20_procedure::N20Procedure::new(
        channel,
        bound,
        inputs.coding,
        calculate,
        verify,
        Duration::from_millis(policy.control_timeout_ms),
    )?;
    let mut procedure = crate::n20_procedure::N20RecoveryProcedure::new(inner, || {
        readbacks
            .borrow_mut()
            .take()
            .ok_or("Fresh six-region readback is missing".into())
    });
    let review = crate::n20_recovery::ReviewedRecovery {
        image_sha256: hash,
        evidence_id: policy.common.evidence_id.into(),
        software_erase_result: policy.software_erase_result,
        calibration_erase_result: policy.common.erase_success_result,
    };
    let result = crate::n20_recovery::run_owned(
        lease,
        &mut procedure,
        inputs.image,
        &review,
        &mut stages,
        &mut journals,
        Duration::from_millis(policy.control_timeout_ms),
    );
    match result {
        Ok(()) => {
            let actual=verified_identity.borrow_mut().take().ok_or("Verified identity transition is unavailable")?;
            let transition=crate::n20_agent_state::transition(binding,vin,
                &crate::n20_agent_state::Identity{hardware_id:fingerprint.hardware.clone(),bootloader_id:fingerprint.bootloader.clone(),software_id:fingerprint.software.clone(),calibration_id:fingerprint.calibration.clone()},&actual);
            let receipt = json!({"schema":kind.receipt_schema(),"operation_kind":kind.name(),"vin":vin,"six_regions_match":true,"coding_matches":true,"transferred_bytes_verified":crate::n20_recovery::REGIONS.iter().map(|r|r.length).sum::<usize>(),"identity_transition":transition});
            if let Err(detail) = persist(
                &folder.join("verification.json"),
                &serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?,
            ) {
                let _ = sink.add(event(
                    "recovery_required",
                    &format!(
                        "{} verification could not be persisted: {detail}",
                        kind.name()
                    ),
                    evidence,
                ));
                return Ok(());
            }
            let mut done = event(
                "complete",
                &format!(
                    "{} completed with fresh identity, saved coding and all six regions verified",
                    kind.name()
                ),
                evidence,
            );
            done.completed_stages = 16;
            let _ = sink.add(done);
        }
        Err(failure) => {
            let _ = sink.add(event(
                if failure.ecu_state_may_have_changed {
                    "recovery_required"
                } else {
                    "error"
                },
                &format!("{} {:?}: {}", kind.name(), failure.stage, failure.detail),
                evidence,
            ));
        }
    }
    Ok(())
}

/// Explicit routine query; deliberately not part of read-only preparation.
#[flutter_rust_bridge::frb(ignore)]
pub fn query_preconditions(
    expected_vin: String,
    expected_software: String,
    output_directory: String,
    sink: StreamSink<N20OperationEvent>,
) -> Result<(), String> {
    use crate::n20_setup::ControlChannel;
    if expected_vin != N20_BENCH_VIN {
        let _ = sink.add(event(
            "error",
            "Only the documented N20 bench identity is accepted",
            "",
        ));
        return Ok(());
    }
    let lease = match crate::vehicle_access::vehicle_access().programming() {
        Ok(l) => l,
        Err(e) => {
            let _ = sink.add(event("error", &e, ""));
            return Ok(());
        }
    };
    thread::spawn(move || {
        let mut evidence = String::new();
        let mut uncertain = false;
        let result = (|| -> Result<(), String> {
            let host = last_vehicle_host().ok_or("No active vehicle endpoint")?;
            let mut stream = fresh_diagnostic_stream(&host)?;
            if !validate_bm3_read_vehicle(&mut stream)? {
                return Err("Expected the documented N20 bench DME".into());
            }
            let (vin, _, fingerprint, _, _) = identify_engine(&mut stream)?;
            if vin != expected_vin || fingerprint.software != expected_software {
                return Err("Fresh DME differs from the page identity".into());
            }
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos();
            let folder = std::path::Path::new(&output_directory)
                .join(format!("n20-condition-query-{stamp}"));
            std::fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
            evidence = folder.to_string_lossy().into_owned();
            let binding=serde_json::to_vec_pretty(&json!({"schema":"n20-explicit-condition-query-v1","vin":vin,
                "software":fingerprint.software,"hardware":fingerprint.hardware,"bootloader":fingerprint.bootloader,
                "calibration":fingerprint.calibration,"captured_unix_ns":stamp.to_string(),
                "request":"31010203","programming_approved":false})).map_err(|e|e.to_string())?;
            persist(&folder.join("request.json"), &binding)?;
            let hash: [u8; 32] = Sha256::digest(&binding).into();
            let wire =
                n20_owned_transport::FileWireJournal::create(&folder.join("wire.jsonl"), &hash)?;
            let mut channel = n20_owned_transport::OwnedN20Transport::new(stream, wire);
            let _ = sink.add(event(
                "diagnostic_query",
                "Running the explicitly requested programming-condition query",
                &evidence,
            ));
            uncertain = true;
            let reply = channel.exchange(0x12, &[0x31, 1, 2, 3], Duration::from_secs(5))?;
            let mut report = crate::n20_preflight::conditions(&reply)?;
            report["operation_binding_sha256"] = json!(hex_payload(&hash));
            persist(
                &folder.join("conditions.json"),
                &serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
            )?;
            uncertain = false;
            let summary=match report["status"].as_str(){
                Some("reported_conditions")=>report["conditions"].as_array().unwrap().iter().take(16).map(|condition|{
                    format!("{} (0x{})",condition["legacy_label"].as_str().unwrap_or("Unknown condition"),condition["hex"].as_str().unwrap_or("??"))
                }).collect::<Vec<_>>().join(", "),
                Some("rejected")=>format!("Routine rejected (NRC 0x{:02X}); the specific unmet condition is not established",report["nrc"].as_u64().unwrap_or(0)),
                _=>"No condition codes were listed".into(),
            };
            let _=sink.add(event("diagnostic_complete",&format!("{summary}. Historical labels only; no programming approval. The identity-bound report can inform agent route selection for 30 seconds; the mandatory live gate remains separate."),&evidence));
            Ok(())
        })();
        if let Err(e) = result {
            let _ = sink.add(event(
                if uncertain {
                    "diagnostic_uncertain"
                } else {
                    "error"
                },
                &e,
                &evidence,
            ));
        }
        drop(lease);
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct IdentityProbe {
        f101: Vec<u8>,
        calls: Vec<Vec<u8>>,
        optional_nrc: bool,
        fail_at: Option<usize>,
        changed_vin: bool,
    }
    impl IdentityProbe {
        fn new() -> Self {
            Self {
                f101: N20_BENCH_F101
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                    .collect(),
                calls: vec![],
                optional_nrc: false,
                fail_at: None,
                changed_vin: false,
            }
        }
    }
    impl crate::n20_setup::ControlChannel for IdentityProbe {
        fn exchange(&mut self, target: u8, request: &[u8], _: Duration) -> Result<Vec<u8>, String> {
            assert_eq!(target, 0x12);
            assert!(matches!(request[0], 0x22 | 0x23));
            self.calls.push(request.to_vec());
            if self.fail_at == Some(self.calls.len()) {
                return Err("Injected timeout".into());
            }
            let mut reply = vec![0x62];
            match request {
                [0x22, 0xf1, 0x90] => {
                    reply.extend([0xf1, 0x90]);
                    let vin = if self.changed_vin && self.calls.len() > 1 {
                        "WBA3A52010F360748"
                    } else {
                        N20_BENCH_VIN
                    };
                    reply.extend(vin.as_bytes());
                }
                [0x22, 0xf1, 0x01] => {
                    reply.extend([0xf1, 1]);
                    reply.extend(&self.f101);
                }
                [0x22, 0xf1, 0x50] => reply.extend([0xf1, 0x50, 0xf, 0x18, 0x10]),
                [0x22, hi, lo] => {
                    if self.optional_nrc {
                        return Ok(vec![0x7f, 0x22, 0x31]);
                    }
                    reply.extend([*hi, *lo, 0x41]);
                }
                [0x23, ..] => {
                    if self.optional_nrc {
                        return Ok(vec![0x7f, 0x23, 0x33]);
                    }
                    return Ok(std::iter::once(0x63)
                        .chain(vec![0xc3; request[7] as usize])
                        .collect());
                }
                _ => panic!("Unexpected request"),
            }
            Ok(reply)
        }
    }
    #[test]
    fn evidence_binds_raw_reads_without_promoting_unlock_or_bosch_identity() {
        let mut probe = IdentityProbe::new();
        let f101 = probe.f101.clone();
        let report = collect_identity_evidence(&mut probe, N20_BENCH_VIN, &f101, &[7; 32]).unwrap();
        assert_eq!(report["unlock_reference_status"], "reference_differs");
        assert_eq!(report["unlock_status"], "unverified");
        assert_eq!(report["bosch_hardware_status"], "unverified");
        assert_eq!(report["programming_approved"], false);
        assert_eq!(report["operation_binding_sha256"], "07".repeat(32));
        assert_eq!(report["records"].as_array().unwrap().len(), 12);
    }
    #[test]
    fn rejected_optional_evidence_stays_unavailable_and_raw_nrc_is_saved() {
        let mut probe = IdentityProbe::new();
        probe.optional_nrc = true;
        let f101 = probe.f101.clone();
        let report = collect_identity_evidence(&mut probe, N20_BENCH_VIN, &f101, &[0; 32]).unwrap();
        assert_eq!(report["unlock_reference_status"], "unavailable");
        assert_eq!(report["records"][7]["response"], "7F2333");
    }
    #[test]
    fn evidence_transport_failure_stops_without_retry() {
        let mut probe = IdentityProbe::new();
        probe.fail_at = Some(4);
        let f101 = probe.f101.clone();
        assert!(collect_identity_evidence(&mut probe, N20_BENCH_VIN, &f101, &[0; 32]).is_err());
        assert_eq!(probe.calls.len(), 4);
    }
    #[test]
    fn evidence_rejects_identity_change_and_skips_reference_for_other_software() {
        let mut probe = IdentityProbe::new();
        probe.changed_vin = true;
        let f101 = probe.f101.clone();
        assert!(collect_identity_evidence(&mut probe, N20_BENCH_VIN, &f101, &[0; 32]).is_err());
        let mut probe = IdentityProbe::new();
        probe.f101[0] ^= 1;
        let f101 = probe.f101.clone();
        let report = collect_identity_evidence(&mut probe, N20_BENCH_VIN, &f101, &[0; 32]).unwrap();
        assert_eq!(report["unlock_reference_status"], "not_applicable");
        assert!(probe.calls.iter().all(|request| request[0] == 0x22));
    }
    #[test]
    fn key_responses_are_single_use_and_bound_to_the_current_challenge() {
        let _serial = key_test_lock().lock().unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        *key_slot().lock().unwrap() = Some(PendingKey {
            id: "current-test-key".into(),
            sender: tx,
        });
        assert!(provide_key("stale".into(), vec![1]).is_err());
        provide_key("current-test-key".into(), vec![2, 3]).unwrap();
        assert_eq!(rx.recv().unwrap().unwrap(), vec![2, 3]);
        assert!(provide_key("current-test-key".into(), vec![4]).is_err());
    }

    #[test]
    fn power_preflight_obeys_sample_count_and_rejects_low_or_unstable_supply() {
        struct Voltage {
            raws: std::collections::VecDeque<u16>,
            calls: usize,
        }
        impl crate::n20_setup::ControlChannel for Voltage {
            fn exchange(
                &mut self,
                target: u8,
                request: &[u8],
                _: Duration,
            ) -> Result<Vec<u8>, String> {
                assert_eq!(target, 0x12);
                assert_eq!(request, [0x22, 0x58, 0x6a]);
                self.calls += 1;
                let raw = self.raws.pop_front().ok_or("Missing voltage sample")?;
                Ok([vec![0x62, 0x58, 0x6a], raw.to_be_bytes().to_vec()].concat())
            }
        }
        let mut policy = crate::programming::LiveN20Policy {
            gate: crate::n20_programming_gate::Policy {
                ignition_evidence_id: "test",
                condition_evidence_id: "test",
                query_non_mutating_verified: true,
                empty_positive_verified_clear: true,
                valid_for_ms: 10000,
            },
            session_timing: crate::n20_session_timing::Bounds {
                max_p2_ms: 1000,
                max_p2_star_ms: 30000,
                margin_ms: 100,
            },
            backend_id: "test",
            evidence_id: "test",
            recovery_id: "test",
            erase_success_result: 0,
            erase_evidence_id: "test",
            minimum_samples: 4,
            minimum_voltage_mv: 12000,
            maximum_voltage_mv: 14800,
            maximum_voltage_span_mv: 250,
        };
        let mut voltage = Voltage {
            raws: vec![32000; 4].into(),
            calls: 0,
        };
        assert_eq!(check_power(&mut voltage, &policy).unwrap(), vec![14000; 4]);
        assert_eq!(voltage.calls, 4);
        let mut voltage = Voltage {
            raws: vec![20000; 4].into(),
            calls: 0,
        };
        assert!(check_power(&mut voltage, &policy).is_err());
        let mut voltage = Voltage {
            raws: vec![32000, 32000, 34000, 32000].into(),
            calls: 0,
        };
        assert!(check_power(&mut voltage, &policy).is_err());
        policy.minimum_samples = 0;
        let mut voltage = Voltage {
            raws: vec![].into(),
            calls: 0,
        };
        assert!(check_power(&mut voltage, &policy).is_err());
        assert_eq!(voltage.calls, 0);
    }

    #[test]
    fn component_normalization_rejects_malformed_and_out_of_range_versions() {
        assert_eq!(
            compact_component("00001C9F029150001").unwrap(),
            "00001C9F1D9601"
        );
        assert_eq!(
            compact_component("00001CDB029150007").unwrap(),
            "00001CDB1D9607"
        );
        for bad in [
            "00001C9F999150001",
            "00001C9F02915X001",
            "00001C9F1D9601",
            "XXXXXXXX029150001",
        ] {
            assert!(compact_component(bad).is_err());
        }
    }

    #[test]
    fn partial_bench_policy_matches_exact_diagnostic_identity() {
        let identity = crate::programming::ExactIdentity {
            vin: N20_BENCH_VIN,
            family: "MEVD17.2.9",
            bosch_hardware: "unverified",
            bmw_hardware: "000019A6001019003",
            software: "00001C9F029150001",
            calibration: "00001CDB029150003",
            bootloader: "00001901001049002",
        };
        assert!(approved(&identity));
        let mut other = identity;
        other.bootloader = "00001901001049003";
        assert!(!approved(&other));
        let bytes: Vec<u8> = N20_BENCH_F101
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        assert!(decode_f101_last_flash_date(&bytes).is_some());
        assert_eq!(&bytes[4..7], &[0x23, 0x02, 0x07]);
    }
}

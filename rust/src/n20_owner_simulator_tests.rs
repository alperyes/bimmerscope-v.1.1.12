//! Test-only execution-owner lab. No production registry entry or API switch.
use super::*;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;

const VIN: &str = "WBA3A52010F360747";
#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    None,
    Pending,
    KeyRejected,
    Erase,
    EraseExtra,
    LostDataAck,
    LateDataAck,
    WrongDataAck,
    CheckMemory,
    CheckMemoryExtra,
    DependenciesExtra,
    Coding,
    ResetAck,
    Readback,
    ReceiptStorage,
}
fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn coding() -> crate::n20_coding::CodingSnapshot {
    crate::n20_coding::CodingSnapshot::from_manifest(&json!({"schema":"n20-coding-snapshot-v1","vin":VIN,"source":"ecu-read","recovery_image":false,"3320":"01020304","3350":"0506","3351":"090a0b0c0d"}),VIN).unwrap()
}
fn image() -> PartialImage {
    let mut bytes = vec![0u8; 0x400000];
    for region in crate::n20_recovery::REGIONS {
        for offset in region.start..region.start + region.length {
            bytes[offset] = (offset.wrapping_mul(31) % 251) as u8;
        }
    }
    bytes[26..36].copy_from_slice(b"MEVD1729__");
    for (offset, value) in [
        (0x18000c, 0x801ffc00u32),
        (0x180038, 0x80180000),
        (0x18003c, 0x801ffbff),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x20024] = 8;
    bytes[0x20025..0x2002c].copy_from_slice(&[0, 0, 0x1c, 0x9f, 0x1d, 0x96, 1]);
    bytes[0x1ffd00] = 8;
    bytes[0x1ffd01..0x1ffd08].copy_from_slice(&[0, 0, 0x1c, 0xdb, 0x1d, 0x96, 7]);
    let hash = format!("{:x}", Sha256::digest(&bytes));
    PartialImage::from_bin(bytes, &hash).unwrap()
}
fn policy() -> crate::programming::LiveN20Policy {
    crate::programming::LiveN20Policy {
        gate: crate::n20_programming_gate::Policy {
            ignition_evidence_id: "SYNTHETIC-ONLY",
            condition_evidence_id: "SYNTHETIC-ONLY",
            query_non_mutating_verified: true,
            empty_positive_verified_clear: true,
            valid_for_ms: 30000,
        },
        session_timing: crate::n20_session_timing::Bounds {
            max_p2_ms: 200,
            max_p2_star_ms: 2000,
            margin_ms: 100,
        },
        backend_id: "SYNTHETIC-ONLY",
        evidence_id: "SYNTHETIC-ONLY",
        recovery_id: "SYNTHETIC-ONLY",
        erase_success_result: 0,
        erase_evidence_id: "SYNTHETIC-ONLY",
        minimum_samples: 3,
        minimum_voltage_mv: 12000,
        maximum_voltage_mv: 15000,
        maximum_voltage_span_mv: 100,
    }
}
struct Events {
    rows: Mutex<Vec<N20OperationEvent>>,
    reject: bool,
}
impl OwnerEvents for Events {
    fn add(&self, event: N20OperationEvent) -> Result<(), String> {
        if event.kind == "security_challenge" {
            assert_eq!(event.bootloader, "00001901001049002");
            assert!(event.seed == [7; 8] || event.seed == [8; 8]);
            if self.reject {
                reject_key(
                    event.request_id.clone(),
                    "Synthetic calculator failure".into(),
                )?;
            } else {
                provide_key(event.request_id.clone(), vec![0xa5; 16])?;
            }
        }
        self.rows.lock().unwrap().push(event);
        Ok(())
    }
}
struct State {
    memory: Vec<u8>,
    requests: Vec<(bool, u8, Vec<u8>)>,
    download: Option<(usize, usize, usize, u8)>,
    written: usize,
    transfers: usize,
    connections: usize,
    fingerprint: bool,
    authorized: bool,
    pending_level: Option<u8>,
    coding_authorized: bool,
    restored: Vec<u16>,
    reset: bool,
    fault: Fault,
    injected: bool,
    session: u8,
    saw_counter_wrap: bool,
}
fn read_request(socket: &mut TcpStream) -> Result<(u8, Vec<u8>), String> {
    let mut header = [0; 8];
    socket.read_exact(&mut header).map_err(|e| e.to_string())?;
    let length = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
    if header[4..6] != [0, 1] || !(3..=65536).contains(&length) {
        return Err("Invalid test HSFZ".into());
    }
    let mut request = vec![0; length - 2];
    socket.read_exact(&mut request).map_err(|e| e.to_string())?;
    Ok((header[7], request))
}
fn respond(state: &mut State, verification: bool, target: u8, request: &[u8]) -> Option<Vec<u8>> {
    state
        .requests
        .push((verification, target, request.to_vec()));
    assert!(matches!(target, 0x12 | 0x17));
    if verification {
        assert!(state.reset);
        assert!(matches!(request[0], 0x22 | 0x23 | 0x31));
    }
    let reply = match request {
        [0x22, 0x58, 0x6a] => vec![0x62, 0x58, 0x6a, 0x7d, 0],
        [0x22, 0x10, 0x0a] => vec![0x62, 0x10, 0x0a, 0],
        [0x22, 0xf1, 0x50] => vec![0x62, 0xf1, 0x50, 0xf, 0x18, 0x10],
        [0x22, 0xf1, 0x90] => [vec![0x62, 0xf1, 0x90], VIN.as_bytes().to_vec()].concat(),
        [0x22, 0xf1, 1] => {
            let mut f101 = unhex(N20_BENCH_F101);
            if verification {
                f101[42..49].copy_from_slice(&[0, 0, 0x1c, 0xdb, 0x1d, 0x96, 7]);
            }
            [vec![0x62, 0xf1, 1], f101].concat()
        }
        [0x22, 0xf1, 0x86] => vec![0x62, 0xf1, 0x86, state.session],
        [0x22, 0x25, 0x04] => vec![0x62, 0x25, 0x04, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5],
        [0x22, 0x33, lo @ (0x20 | 0x50 | 0x51)] => {
            if verification {
                assert_eq!(state.restored, vec![0x3320, 0x3350, 0x3351]);
            }
            let data = match lo {
                0x20 => vec![1, 2, 3, 4],
                0x50 => vec![5, 6],
                _ => vec![9, 10, 11, 12, 13],
            };
            [vec![0x62, 0x33, *lo], data].concat()
        }
        [0x22, ..] => vec![0x7f, 0x22, 0x31],
        [0x10, session] => {
            state.session = *session;
            vec![0x50, *session, 0, 100, 0, 100]
        }
        [0x85, 2] => vec![0xc5, 2],
        [0x28, 1, 1] => vec![0x68, 1],
        [0x27, level @ (1 | 0x11), 255, 255, 255, 255] => {
            state.pending_level = Some(*level);
            [vec![0x67, *level], vec![if *level == 1 { 8 } else { 7 }; 8]].concat()
        }
        [0x27, level @ (2 | 0x12), key @ ..] => {
            assert_eq!(key, &[0xa5; 16]);
            assert_eq!(state.pending_level.take(), Some(level - 1));
            if *level == 2 {
                assert_eq!(
                    state.requests[state.requests.len() - 2].2,
                    [0x22, 0x25, 0x04]
                );
                state.coding_authorized = true;
            } else {
                state.authorized = true;
            }
            vec![0x67, *level]
        }
        [0x2e, 0xf1, 0x5a, ..] => {
            assert!(state.authorized);
            state.fingerprint = true;
            vec![0x6e, 0xf1, 0x5a]
        }
        [0x31, 1, 0xff, 0, ..] => {
            assert!(state.authorized && state.fingerprint);
            if state.fault == Fault::Erase {
                state.injected = true;
                return Some(vec![0x7f, 0x31, 0x22]);
            }
            let index = u32::from_be_bytes(request[6..10].try_into().unwrap());
            for region in crate::n20_recovery::REGIONS {
                if (index == 0x801ffd00 && region.start >= 0x180000 && region.start < 0x200000)
                    || (index == 0x803ffd00
                        && (region.start < 0x180000 || region.start >= 0x220000))
                {
                    state.memory[region.start..region.start + region.length].fill(255);
                }
            }
            if state.fault == Fault::EraseExtra {
                state.injected = true;
                vec![0x71, 1, 0xff, 0, 0, 0]
            } else {
                vec![0x71, 1, 0xff, 0, 0]
            }
        }
        [0x34, 0, 0x44, ..] => {
            assert!(state.download.is_none());
            assert!(state.authorized && state.fingerprint);
            let address = u32::from_be_bytes(request[3..7].try_into().unwrap());
            let length = u32::from_be_bytes(request[7..11].try_into().unwrap()) as usize;
            assert!(crate::n20_recovery::REGIONS
                .iter()
                .any(|r| r.address() == address && r.length == length));
            state.download = Some(((address - 0x80000000) as usize, length, 0, 1));
            vec![0x74, 0x20, 0x10, 0]
        }
        [0x36, counter, data @ ..] => {
            let (start, length, offset, next) =
                state.download.as_mut().expect("Download must precede data");
            assert_eq!(counter, next);
            assert!(*offset + data.len() <= *length);
            assert!(data.len() <= 4094);
            state.memory[*start + *offset..*start + *offset + data.len()].copy_from_slice(data);
            *offset += data.len();
            *next = next.wrapping_add(1);
            state.written += data.len();
            state.saw_counter_wrap |= *counter == 0;
            if !state.injected && state.fault == Fault::LostDataAck {
                state.injected = true;
                return None;
            }
            if !state.injected && state.fault == Fault::WrongDataAck {
                state.injected = true;
                vec![0x76, counter.wrapping_add(1)]
            } else {
                vec![0x76, *counter]
            }
        }
        [0x37] => {
            let (_, length, offset, _) = state.download.take().unwrap();
            assert_eq!(offset, length);
            state.transfers += 1;
            vec![0x77]
        }
        [0x31, 1, 2, 2, ..] => {
            assert!(state.download.is_none());
            if state.fault == Fault::CheckMemory {
                state.injected = true;
                vec![0x71, 1, 2, 2, 1]
            } else if state.fault == Fault::CheckMemoryExtra {
                state.injected = true;
                vec![0x71, 1, 2, 2, 0, 0]
            } else {
                vec![0x71, 1, 2, 2, 0]
            }
        }
        [0x31, 1, 0xff, 1] => {
            if state.fault == Fault::DependenciesExtra {
                state.injected = true;
                vec![0x71, 1, 0xff, 1, 1, 0]
            } else {
                vec![0x71, 1, 0xff, 1, 1]
            }
        }
        [0x31, 1, 2, 5, ..] => vec![0x7f, 0x31, 0x31],
        [0x31, sub, hi, lo, ..] => vec![0x71, *sub, *hi, *lo],
        [0x2e, 0x33, lo, data @ ..] => {
            assert_eq!(state.session, 0x41);
            assert!(state.coding_authorized);
            if state.fault == Fault::Coding {
                state.injected = true;
                return Some(vec![0x7f, 0x2e, 0x22]);
            }
            assert_eq!(
                data,
                match lo {
                    0x20 => &[1, 2, 3, 4][..],
                    0x50 => &[5, 6][..],
                    0x51 => &[12, 11, 10, 9, 13][..],
                    _ => panic!("Unexpected coding DID"),
                }
            );
            state.restored.push(0x3300 | u16::from(*lo));
            vec![0x6e, 0x33, *lo]
        }
        [0x2e, hi, lo, ..] => vec![0x6e, *hi, *lo],
        [0x11, 1] => {
            assert_eq!(state.restored, vec![0x3320, 0x3350, 0x3351]);
            state.reset = true;
            if state.fault == Fault::ResetAck {
                state.injected = true;
                return None;
            }
            vec![0x51, 1]
        }
        [0x23, 0x24, ..] => {
            assert!(verification);
            let address = u32::from_be_bytes(request[2..6].try_into().unwrap());
            let length = u16::from_be_bytes(request[6..8].try_into().unwrap()) as usize;
            let start = (address - 0x80000000) as usize;
            let mut data = state.memory[start..start + length].to_vec();
            if state.fault == Fault::Readback && !state.injected {
                state.injected = true;
                data[0] ^= 1;
            }
            [vec![0x63], data].concat()
        }
        _ => panic!("Unexpected simulator request {request:02X?}"),
    };
    Some(reply)
}
struct Lab {
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
    primary: SocketAddr,
    verification: SocketAddr,
    gateway: SocketAddr,
}
impl Lab {
    fn new(bytes: &[u8], fault: Fault) -> Self {
        let state = Arc::new(Mutex::new(State {
            memory: bytes.iter().map(|b| b ^ 0xff).collect(),
            requests: vec![],
            download: None,
            written: 0,
            transfers: 0,
            connections: 0,
            fingerprint: false,
            authorized: false,
            pending_level: None,
            coding_authorized: false,
            restored: vec![],
            reset: false,
            fault,
            injected: false,
            session: 1,
            saw_counter_wrap: false,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let mut workers = vec![];
        let mut addresses = vec![];
        for mode in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            addresses.push(listener.local_addr().unwrap());
            let state = state.clone();
            let stop = stop.clone();
            workers.push(thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let (mut socket, _) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(e) => panic!("{e}"),
                    };
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    socket.set_nodelay(true).unwrap();
                    if mode == 2 {
                        let mut request = [0; 6];
                        socket.read_exact(&mut request).unwrap();
                        assert_eq!(request, [0, 0, 0, 0, 0, 0x10]);
                        socket.write_all(&[0, 0, 0, 1, 0, 0x10, 4]).unwrap();
                        continue;
                    }
                    state.lock().unwrap().connections += 1;
                    while let Ok((target, request)) = read_request(&mut socket) {
                        let pending = {
                            let mut state = state.lock().unwrap();
                            if state.fault == Fault::Pending
                                && !state.injected
                                && request[0] == 0x36
                            {
                                state.injected = true;
                                true
                            } else {
                                false
                            }
                        };
                        if pending {
                            socket
                                .write_all(&build_hsfz(target, TESTER, &[0x7f, 0x36, 0x78]))
                                .unwrap();
                            thread::sleep(Duration::from_millis(40));
                        }
                        let reply =
                            respond(&mut state.lock().unwrap(), mode == 1, target, &request);
                        if request[0] == 0x36 && state.lock().unwrap().fault == Fault::LateDataAck {
                            state.lock().unwrap().injected = true;
                            thread::sleep(Duration::from_millis(450));
                        }
                        let Some(reply) = reply else {
                            break;
                        };
                        if socket
                            .write_all(&build_hsfz(target, TESTER, &reply))
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }));
        }
        Self {
            state,
            stop,
            workers,
            primary: addresses[0],
            verification: addresses[1],
            gateway: addresses[2],
        }
    }
    fn connect(address: SocketAddr) -> TcpStream {
        assert!(address.ip().is_loopback());
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        socket.set_nodelay(true).unwrap();
        socket
    }
}
impl OwnerRuntime for Lab {
    fn gateway(&self, host: &str) -> Result<Vec<u8>, String> {
        assert_eq!(host, "127.0.0.1");
        let mut socket = Self::connect(self.gateway);
        socket
            .write_all(&[0, 0, 0, 0, 0, 0x10])
            .map_err(|e| e.to_string())?;
        let mut frame = vec![0; 7];
        socket.read_exact(&mut frame).map_err(|e| e.to_string())?;
        Ok(frame)
    }
    fn reconnect(&self, host: &str) -> Result<TcpStream, String> {
        assert_eq!(host, "127.0.0.1");
        Ok(Self::connect(self.verification))
    }
    fn pause(&self, _: Duration) {}
}
impl Drop for Lab {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            worker.join().unwrap();
        }
    }
}

struct Fixture {
    root: PathBuf,
    folder: PathBuf,
    binding: [u8; 32],
    keep: bool,
}
impl Fixture {
    fn new(image: &PartialImage, recovery: bool, fault: Fault) -> Self {
        Self::new_mode(image, recovery, false, fault)
    }
    fn new_mode(image: &PartialImage, recovery: bool, full: bool, fault: Fault) -> Self {
        let output = std::env::var_os("BIMMERSCOPE_OWNER_SIM_REPORT_DIR").map(PathBuf::from);
        let keep = output.is_some();
        let parent = output.unwrap_or_else(std::env::temp_dir);
        std::fs::create_dir_all(&parent).unwrap();
        let root = parent.join(format!(
            "n20-owner-sim-test-{}-{fault:?}-{}",
            if full {
                "full"
            } else if recovery {
                "recovery"
            } else {
                "partial"
            },
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        if full {
            let source=root.join("historical.coding");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(&source,serde_json::to_vec(&json!({"v":VIN,"ud":true,"fStat":false,"nr":true,"vid":{
                "hardwareId":"000019A6001019003","bootloaderId":"00001901001049002","softwareId":"00001C9F029150001","calibrationId":"00001CDB029150003"
            }})).unwrap()).unwrap();
            crate::n20_agent_state::import(&root,&source,VIN).unwrap();
        }
        let full_folder=format!("n20_full_operations/n20-full-operation-{}",SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let folder = root.join(if full {
            &full_folder
        } else if recovery {
            "n20_recovery_operations/n20-operation-1"
        } else {
            "n20_flash_operations/n20-operation-1"
        });
        std::fs::create_dir_all(&folder).unwrap();
        let coding_bytes = serde_json::to_vec(&coding().manifest()).unwrap();
        let original = json!({"schema":"n20-operation-v1","vin":VIN,"bin_sha256":image.sha256,
            "hardware":"000019A6001019003","bootloader":"00001901001049002","software":"00001C9F029150001","calibration":"00001CDB029150003"});
        let original_bytes = serde_json::to_vec(&original).unwrap();
        let plan=serde_json::to_vec(&json!({"vin":VIN,"original_operation_sha256":format!("{:x}",Sha256::digest(&original_bytes))})).unwrap();
        let op = if full {
            json!({"schema":"n20-full-operation-v1","operation_kind":"full","vin":VIN,"bin_sha256":image.sha256,
                "hardware":"000019A6001019003","bootloader":"00001901001049002","software":"00001C9F029150001","calibration":"00001CDB029150003"})
        } else if recovery {
            json!({"schema":"n20-live-recovery-v1","vin":VIN,"bin_sha256":image.sha256,"plan_sha256":format!("{:x}",Sha256::digest(&plan)),"coding_sha256":format!("{:x}",Sha256::digest(&coding_bytes)),
                "hardware":"000019A6001019003","bootloader":"00001901001049002","software":"00001C9F029150001","calibration":"00001CDB029150003"})
        } else {
            original
        };
        let bytes = serde_json::to_vec(&op).unwrap();
        if full {
            std::fs::write(folder.join("coding-binding.json"),serde_json::to_vec(&json!({"operation_binding_sha256":format!("{:X}",Sha256::digest(&bytes)),"coding_sha256":format!("{:x}",Sha256::digest(&coding_bytes))})).unwrap()).unwrap();
        }
        std::fs::write(folder.join("operation.json"), &bytes).unwrap();
        std::fs::write(folder.join("selected.bin"), image.bytes()).unwrap();
        std::fs::write(
            folder.join(if recovery {
                "original-coding.json"
            } else {
                "coding.json"
            }),
            &coding_bytes,
        )
        .unwrap();
        if recovery {
            std::fs::write(folder.join("recovery-plan.json"), plan).unwrap();
            std::fs::write(folder.join("original-operation.json"), original_bytes).unwrap();
        }
        if fault == Fault::ReceiptStorage {
            std::fs::write(folder.join("verification.json"), b"{}").unwrap();
        }
        Self {
            root,
            folder,
            binding: Sha256::digest(bytes).into(),
            keep,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.keep {
            let root = self.root.canonicalize().unwrap();
            assert_eq!(
                root.parent(),
                Some(std::env::temp_dir().canonicalize().unwrap().as_path())
            );
            assert!(root
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("n20-owner-sim-test-"));
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}

fn run_case(recovery: bool, fault: Fault) {
    run_case_mode(recovery, false, fault)
}
fn run_case_mode(recovery: bool, full: bool, fault: Fault) {
    let six = recovery || full;
    let kind = if full {
        crate::n20_recovery::RewriteKind::Full
    } else {
        crate::n20_recovery::RewriteKind::Recovery
    };
    // All cases share the real single-challenge broker; serialize this lab only.
    let _serial = key_test_lock().lock().unwrap();
    let image = image();
    let fixture = Fixture::new_mode(&image, recovery, full, fault);
    let lab = Lab::new(image.bytes(), fault);
    let channel = n20_owned_transport::OwnedN20Transport::new(
        Lab::connect(lab.primary),
        n20_owned_transport::FileWireJournal::create(
            &fixture.folder.join("wire.jsonl"),
            &fixture.binding,
        )
        .unwrap(),
    );
    let events = Events {
        rows: Mutex::new(vec![]),
        reject: fault == Fault::KeyRejected,
    };
    let access = crate::vehicle_access::VehicleAccess::default();
    let lease = access.programming().unwrap();
    assert!(access.diagnostic().is_err());
    let fingerprint = decode_s55_dme_identity_bundle(&unhex(N20_BENCH_F101)).unwrap();
    let f101 = [vec![0x62, 0xf1, 1], unhex(N20_BENCH_F101)].concat();
    let evidence = fixture.folder.to_string_lossy();
    let result = if six {
        let inputs = RewriteInputs {
            image: crate::n20_recovery::RecoveryImage::synthetic(image),
            coding: coding(),
        };
        execute_rewrite(
            &lease,
            channel,
            inputs,
            f101,
            [0x23, 2, 7],
            &fingerprint,
            VIN,
            "127.0.0.1",
            "synthetic-operation",
            &fixture.folder,
            &evidence,
            &fixture.binding,
            crate::programming::LiveN20RecoveryPolicy {
                common: {
                    let mut value = policy();
                    value.backend_id = kind.backend();
                    value
                },
                software_erase_result: 0,
                software_erase_evidence: "SYNTHETIC-ONLY",
                control_timeout_ms: 5000,
                post_reset_wait_ms: 0,
                readback_chunk: 4096,
            },
            &events,
            &lab,
            kind,
        )
    } else {
        execute_approved(
            &lease,
            channel,
            coding(),
            image,
            f101,
            [0x23, 2, 7],
            &fingerprint,
            VIN,
            "127.0.0.1",
            "synthetic-operation",
            &fixture.folder,
            &evidence,
            &fixture.binding,
            policy(),
            &events,
            &lab,
        )
    };
    assert!(
        result.is_ok(),
        "Owner {recovery}/{fault:?} returned {result:?}"
    );
    let rows = events.rows.lock().unwrap();
    let terminal = rows.last().unwrap();
    let success = matches!(fault, Fault::None | Fault::Pending);
    assert_eq!(
        terminal.kind,
        if success {
            "complete"
        } else {
            "recovery_required"
        },
        "{recovery:?}/{fault:?}: {}",
        terminal.message
    );
    assert_eq!(
        rows.iter()
            .filter(|row| row.kind == "security_challenge")
            .count(),
        if fault == Fault::KeyRejected
            || matches!(
                fault,
                Fault::Erase
                    | Fault::EraseExtra
                    | Fault::LostDataAck
                    | Fault::LateDataAck
                    | Fault::WrongDataAck
                    | Fault::CheckMemory
                    | Fault::CheckMemoryExtra
                    | Fault::DependenciesExtra
            )
        {
            1
        } else {
            2
        }
    );
    let state = lab.state.lock().unwrap();
    let stages = rows.iter().filter(|row| row.kind == "stage").count();
    if success {
        assert_eq!(terminal.completed_stages, if six { 16 } else { 10 });
        assert_eq!(state.transfers, if six { 6 } else { 2 });
        assert_eq!(state.written, if six { 3_931_392 } else { 524_032 });
        assert_eq!(state.connections, 2);
        assert!(state.reset);
        if six {
            assert!(state.saw_counter_wrap);
        }
    } else {
        assert!(rows.iter().all(|row| row.kind != "complete"));
        assert!(state.connections <= 2);
    }
    if matches!(
        fault,
        Fault::LostDataAck | Fault::LateDataAck | Fault::WrongDataAck
    ) {
        assert_eq!(
            state
                .requests
                .iter()
                .filter(|(_, _, r)| r[0] == 0x36)
                .count(),
            1
        );
        assert!(!state.reset);
    }
    if !full && !recovery {
        assert!(state.requests.iter().all(|(_, target, _)| *target == 0x12));
    }
    if fault == Fault::KeyRejected {
        assert!(state
            .requests
            .iter()
            .all(|(_, _, r)| r[0] != 0x34 && r[..r.len().min(4)] != [0x31, 1, 0xff, 0]));
    }
    if matches!(fault, Fault::EraseExtra | Fault::CheckMemoryExtra | Fault::DependenciesExtra) {
        assert!(state.injected);
        assert!(!state.reset);
        assert!(!state.requests.iter().any(|(_, _, r)| r.starts_with(&[0x2e, 0xf1, 0x90]) || r.starts_with(&[0x2e, 0x33])));
        if fault == Fault::EraseExtra {
            assert_eq!(state.transfers, 0);
            assert!(!state.requests.iter().any(|(_, _, r)| r[0] == 0x34));
        }
    }
    let startup = crate::n20_operation_history::startup_review(&fixture.root).unwrap();
    assert_eq!(startup["blocked"], !success);
    let history = crate::n20_operation_history::list(&fixture.root, VIN).unwrap();
    if full {
        let loaded=crate::n20_agent_state::load(&fixture.root,VIN,&crate::n20_agent_state::Identity{
            hardware_id:"000019A6001019003".into(),bootloader_id:"00001901001049002".into(),software_id:"00001C9F029150001".into(),calibration_id:if success{"00001CDB029150007"}else{"00001CDB029150003"}.into()
        });
        assert_eq!(loaded.state.unlock_done,Some(true));
        assert_eq!(loaded.state.last_flash_success,Some(success));
        assert_eq!(loaded.state.needs_recovery,Some(!success));
        assert_eq!(loaded.report["physical_unlock_verified"],false);
        if success {
            assert_eq!(loaded.report["identity_lineage"].as_array().unwrap().len(),1);
            let stale=crate::n20_agent_state::load(&fixture.root,VIN,&crate::n20_agent_state::Identity{hardware_id:"000019A6001019003".into(),bootloader_id:"00001901001049002".into(),software_id:"00001C9F029150001".into(),calibration_id:"00001CDB029150003".into()});
            assert!(stale.state.unlock_done.is_none());
        }
    }
    if success {
        assert_eq!(history["operations"][0]["status"], "recorded_complete");
        if full {
            assert_eq!(history["operations"][0]["kind"], "full");
            assert!(!fixture.folder.join("recovery-plan.json").exists());
            assert!(crate::n20_recovery::inspect_stages(
                &fixture.folder.join("full-stages.jsonl"),
                &fixture.binding,
                &json_image_hash(&fixture)
            )
            .is_err());
            let receipt_path = fixture.folder.join("verification.json");
            let original = std::fs::read(&receipt_path).unwrap();
            let actual_identity=crate::n20_agent_state::Identity{hardware_id:"000019A6001019003".into(),bootloader_id:"00001901001049002".into(),software_id:"00001C9F029150001".into(),calibration_id:"00001CDB029150007".into()};
            let mut legacy:Value=serde_json::from_slice(&original).unwrap();legacy.as_object_mut().unwrap().remove("identity_transition");
            std::fs::write(&receipt_path,serde_json::to_vec(&legacy).unwrap()).unwrap();
            assert_eq!(crate::n20_operation_history::startup_review(&fixture.root).unwrap()["blocked"],false);
            assert!(crate::n20_agent_state::load(&fixture.root,VIN,&actual_identity).state.unlock_done.is_none());
            for field in ["operation_binding_sha256","target","source"]{
                let mut bad:Value=serde_json::from_slice(&original).unwrap();
                match field{
                    "target"=>bad["identity_transition"]["to"]["calibrationId"]=json!("00001CDB029150008"),
                    "source"=>bad["identity_transition"]["from"]["softwareId"]=json!("00001C9F029150099"),
                    _=>bad["identity_transition"][field]=json!("00".repeat(32)),
                }
                std::fs::write(&receipt_path,serde_json::to_vec(&bad).unwrap()).unwrap();
                assert_eq!(crate::n20_operation_history::startup_review(&fixture.root).unwrap()["blocked"],true);
                assert!(crate::n20_agent_state::load(&fixture.root,VIN,&actual_identity).state.unlock_done.is_none());
            }
            std::fs::write(&receipt_path,&original).unwrap();
            let mut swapped: Value = serde_json::from_slice(&original).unwrap();
            swapped["schema"] = json!("n20-recovery-verified-v1");
            std::fs::write(&receipt_path, serde_json::to_vec(&swapped).unwrap()).unwrap();
            assert_eq!(
                crate::n20_operation_history::startup_review(&fixture.root).unwrap()["blocked"],
                true
            );
            assert_eq!(
                crate::n20_operation_history::list(&fixture.root, VIN).unwrap()["operations"][0]
                    ["can_load"],
                false
            );
            std::fs::write(receipt_path, original).unwrap();
            let coding_path = fixture.folder.join("coding.json");
            let original_coding = std::fs::read(&coding_path).unwrap();
            let mut changed: Value = serde_json::from_slice(&original_coding).unwrap();
            changed["3320"] = json!("ff");
            std::fs::write(&coding_path, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert_eq!(
                crate::n20_operation_history::startup_review(&fixture.root).unwrap()["blocked"],
                true
            );
            std::fs::write(coding_path, original_coding).unwrap();
        }
    }
    if !recovery && matches!(fault, Fault::LostDataAck | Fault::Pending) {
        let path = fixture.folder.join(if six {
            kind.stage_file()
        } else {
            "stages.jsonl"
        });
        let before = std::fs::read(&path).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "api::vehicle::n20_flash_operation::owner_simulator_tests::restart_probe",
                "--ignored",
                "--nocapture",
            ])
            .env("BIMMERSCOPE_OWNER_RESTART_ROOT", &fixture.root)
            .env(
                "BIMMERSCOPE_OWNER_RESTART_BLOCKED",
                if success { "false" } else { "true" },
            )
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stdout)
        );
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
    let report = json!({"synthetic_only":true,"full":full,"recovery":recovery,"fault":format!("{fault:?}"),"terminal":terminal.kind,"message":terminal.message,"completed_stages":terminal.completed_stages,"stage_events":stages,"bytes_written":state.written,"transfers":state.transfers,"connections":state.connections,"startup_blocked":startup["blocked"],"history":history["operations"][0],"production_programming_approved":false});
    std::fs::write(
        fixture.root.join("simulation-result.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    drop(state);
    drop(rows);
    drop(lease);
    assert!(access.diagnostic().is_ok());
}

fn json_image_hash(fixture: &Fixture) -> String {
    serde_json::from_slice::<Value>(&std::fs::read(fixture.folder.join("operation.json")).unwrap())
        .unwrap()["bin_sha256"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn ordinary_full_owner_has_distinct_success_and_uncertain_failure_records() {
    for fault in [
        Fault::None,
        Fault::LostDataAck,
        Fault::Readback,
        Fault::ReceiptStorage,
    ] {
        run_case_mode(false, true, fault);
    }
}

#[test]
fn partial_owner_completes_with_pending_reply_and_verified_persistent_history() {
    run_case(false, Fault::Pending);
}

#[test]
fn preparation2_uses_one_socket_and_shared_broker_through_key_and_post_key_read() {
    let _serial = key_test_lock().lock().unwrap();
    let image = image();
    let fixture = Fixture::new(&image, false, Fault::None);
    let lab = Lab::new(image.bytes(), Fault::None);
    let events = Events {
        rows: Mutex::new(vec![]),
        reject: false,
    };
    let mut unknown = false;
    let requests = vec![
        vec![0x10, 3],
        vec![0x22, 0x10, 0x0a],
        vec![0x31, 1, 0x0f, 0x0c, 0],
        vec![0x31, 1, 0x0f, 0x0c, 3],
        vec![0x85, 2],
        vec![0x28, 1, 1],
        vec![0x31, 1, 0x10, 3, 1],
        vec![0x10, 1],
        vec![0x10, 3],
        vec![0x10, 2],
        vec![0x22, 0xf1, 0x86],
        vec![0x27, 0x11, 255, 255, 255, 255],
    ];
    let folder=fixture.root.join("dme_owned_preparation/dme-owned-preparation-1");std::fs::create_dir_all(&folder).unwrap();
    let request=serde_json::to_vec(&json!({"schema":"dme-owned-preparation-v1","vin":VIN,"bootloader":"00001901001049002","f101":N20_BENCH_F101,"requests":requests,"security_prefix":[0x27,0x12],"post_key_requests":[[0x22,0xf1,0x86]]})).unwrap();
    persist(&folder.join("request.json"),&request).unwrap();
    let binding=Sha256::digest(&request).into();
    let channel=n20_owned_transport::OwnedN20Transport::new(Lab::connect(lab.primary),n20_owned_transport::FileWireJournal::create(&folder.join("wire.jsonl"),&binding).unwrap());
    let path=folder.to_string_lossy();
    let mut traced=PreparationTrace{inner:channel,sink:&events,unknown:&mut unknown,path:&path,index:0,accepted:false};
    let mut sequence = 0;
    crate::dme_preparation::run(
        &mut traced,
        &requests,
        &[0x27, 0x12],
        &[vec![0x22, 0xf1, 0x86]],
        "00001901001049002",
        Duration::from_secs(2),
        |btld, seed| {
            request_key(
                &events,
                "preparation-test",
                &mut sequence,
                btld,
                seed,
                &path,
            )
        },
    )
    .unwrap();
    assert!(traced.accepted);
    assert_eq!(traced.index, 14);
    drop(traced);
    assert!(!unknown);
    persist(&folder.join("result.json"),&serde_json::to_vec(&json!({"schema":"dme-owned-preparation-result-v1","operation_binding_sha256":hex_payload(&binding),"completed":true,"security_response_accepted":true,"outcome_unknown":false,"programming_approved":false})).unwrap()).unwrap();
    let actual=decode_s55_dme_identity_bundle(&unhex(N20_BENCH_F101)).unwrap();
    let access=super::super::n20_access_evidence::collect(&fixture.root,VIN,&crate::n20_agent_state::Identity{hardware_id:actual.hardware,bootloader_id:actual.bootloader,software_id:actual.software,calibration_id:actual.calibration});
    assert_eq!(access["status"],"observed");assert_eq!(access["programming_session_verified_at_end"],true);assert_eq!(access["live_access_authorized"],false);assert_eq!(access["persistent_unlock_verified"],false);
    persist(&folder.join("access-observation.json"),&serde_json::to_vec_pretty(&access).unwrap()).unwrap();
    let state = lab.state.lock().unwrap();
    assert_eq!(state.connections, 1);
    assert_eq!(state.written, 0);
    assert!(!state.reset);
    assert_eq!(
        state.requests[..requests.len()]
            .iter()
            .map(|(_, _, r)| r.clone())
            .collect::<Vec<_>>(),
        requests
    );
    assert!(state.requests[12].2.starts_with(&[0x27, 0x12]));
    assert_eq!(state.requests[13].2, vec![0x22, 0xf1, 0x86]);
    assert_eq!(
        events
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.kind == "security_challenge")
            .count(),
        1
    );
}
#[test]
fn partial_owner_failures_never_complete_retry_or_clear_restart_interlock() {
    for fault in [
        Fault::KeyRejected,
        Fault::Erase,
        Fault::LostDataAck,
        Fault::LateDataAck,
        Fault::WrongDataAck,
        Fault::CheckMemory,
        Fault::Coding,
        Fault::ResetAck,
        Fault::Readback,
        Fault::ReceiptStorage,
    ] {
        run_case(false, fault);
    }
}
#[test]
fn recovery_owner_transfers_and_verifies_all_six_regions() {
    run_case(true, Fault::None);
}
#[test]
fn malformed_routine_results_preserve_uncertainty_without_followup_writes() {
    for fault in [Fault::EraseExtra, Fault::CheckMemoryExtra, Fault::DependenciesExtra] {
        run_case(false, fault);
    }
    // The shared erase parser also guards the distinct six-region owners.
    run_case_mode(false, true, Fault::EraseExtra);
    run_case(true, Fault::EraseExtra);
}
#[test]
fn recovery_owner_software_readback_mismatch_stays_uncertain() {
    run_case(true, Fault::Readback);
}

#[test]
#[ignore = "subprocess restart helper"]
fn restart_probe() {
    let root = PathBuf::from(std::env::var_os("BIMMERSCOPE_OWNER_RESTART_ROOT").unwrap());
    let report = crate::vehicle_startup_safety::initialize(&root).unwrap();
    assert_eq!(
        report["blocked"],
        std::env::var("BIMMERSCOPE_OWNER_RESTART_BLOCKED").unwrap() == "true"
    );
    assert_eq!(report["programming_approved"], false);
}

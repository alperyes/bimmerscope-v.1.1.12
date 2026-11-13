//! Same-socket adapter shared by generic-DME setup and UDS downloads.
//! Internal adapter constructed behind the approved-profile gate. The operation
//! caller must retain its exclusive programming lease throughout its lifetime.
#![allow(dead_code)]

#[cfg(test)]
use super::build_hsfz;
use super::{DownloadHsfzTransport, TESTER};
use crate::n20_setup::ControlChannel;
use crate::uds_download::DownloadTransport;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

#[flutter_rust_bridge::frb(ignore)]
pub(super) trait WireJournal {
    fn append(&mut self, kind: &str, target: u8, bytes: &[u8]) -> Result<(), String>;
}

#[flutter_rust_bridge::frb(ignore)]
pub(super) struct FileWireJournal {
    file: File,
    sequence: u64,
    chain: String,
    failed: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl FileWireJournal {
    #[flutter_rust_bridge::frb(ignore)]
    pub fn create(path: &Path, manifest_digest: &[u8; 32]) -> Result<Self, String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        let header = serde_json::json!({"schema": "n20-owned-wire-v1", "manifest_sha256": hex(manifest_digest)}).to_string();
        writeln!(file, "{header}")
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(Self {
            file,
            sequence: 0,
            chain: hex(&Sha256::digest(header.as_bytes())),
            failed: false,
        })
    }
}

impl WireJournal for FileWireJournal {
    fn append(&mut self, kind: &str, target: u8, bytes: &[u8]) -> Result<(), String> {
        if self.failed {
            return Err("Wire journal previously failed".into());
        }
        let body = serde_json::json!({"sequence": self.sequence, "kind": kind,
            "target": target, "uds": hex(bytes), "previous_sha256": self.chain})
        .to_string();
        let digest = hex(&Sha256::digest(body.as_bytes()));
        let line = serde_json::json!({"record": body, "sha256": digest}).to_string();
        if let Err(error) = writeln!(self.file, "{line}").and_then(|_| self.file.sync_all()) {
            self.failed = true;
            return Err(error.to_string());
        }
        self.sequence += 1;
        self.chain = digest;
        Ok(())
    }
}

#[flutter_rust_bridge::frb(ignore)]
pub(super) struct OwnedN20Transport<J> {
    inner: DownloadHsfzTransport,
    journal: J,
    poisoned: bool,
    timing: crate::n20_session_timing::State,
    readback: Option<(ReadbackScope, usize)>,
}

#[derive(Clone, Copy)]
#[flutter_rust_bridge::frb(ignore)]
pub(super) enum ReadbackScope {
    Partial,
    Full,
    Recovery,
}

fn readback_range_allowed(scope: ReadbackScope, maximum: usize, request: &[u8]) -> bool {
    if request.len() != 8 || request[..2] != [0x23, 0x24] {
        return false;
    }
    let address = u32::from_be_bytes(request[2..6].try_into().unwrap());
    let length = u16::from_be_bytes(request[6..8].try_into().unwrap()) as usize;
    let Some(end) = address.checked_add(length as u32) else {
        return false;
    };
    if length == 0 || length > maximum {
        return false;
    }
    match scope {
        ReadbackScope::Partial => [(0x80180000, 0x801ffc00), (0x801ffd00, 0x80200000)]
            .iter()
            .any(|(start, stop)| address >= *start && end <= *stop),
        ReadbackScope::Full | ReadbackScope::Recovery => crate::n20_recovery::REGIONS
            .iter()
            .any(|r| address >= r.address() && end <= r.address() + r.length as u32),
    }
}

impl<J: WireJournal> OwnedN20Transport<J> {
    /// Explicit physical routes: this adapter assumes response source equals
    /// selected target (12/17). It cannot infer an alternate gateway route.
    #[flutter_rust_bridge::frb(ignore)]
    pub fn new(stream: TcpStream, journal: J) -> Self {
        Self {
            inner: DownloadHsfzTransport {
                stream,
                tester: TESTER,
                response_source: 0x12,
                target: 0x12,
                buffer: vec![],
                frames: VecDeque::new(),
                sid: None,
            },
            journal,
            poisoned: false,
            timing: Default::default(),
            readback: None,
        }
    }

    /// Only post-reset verification owners configure this on a fresh socket.
    /// Such a connection becomes read-only and cannot fall back to probe mode.
    #[flutter_rust_bridge::frb(ignore)]
    pub(super) fn configure_readback(
        &mut self,
        scope: ReadbackScope,
        maximum: usize,
    ) -> Result<(), String> {
        if self.poisoned || self.readback.is_some() || maximum == 0 || maximum > u16::MAX as usize {
            self.poisoned = true;
            return Err("Invalid or repeated readback configuration".into());
        }
        self.readback = Some((scope, maximum));
        Ok(())
    }

    #[flutter_rust_bridge::frb(ignore)]
    pub(super) fn configure_session_timing(
        &mut self,
        bounds: crate::n20_session_timing::Bounds,
    ) -> Result<(), String> {
        self.timing.configure(bounds)
    }

    fn send_to(&mut self, target: u8, bytes: &[u8], deadline: Instant) -> Result<(), String> {
        if self.poisoned {
            return Err(
                "Operation connection is failed; no retry or reconnect is permitted".into(),
            );
        }
        let result = (|| {
            if !matches!(target, 0x12 | 0x17) || bytes.is_empty() {
                return Err("Unsupported physical route or empty request".into());
            }
            if self.inner.sid.is_some()
                || !self.inner.frames.is_empty()
                || !self.inner.buffer.is_empty()
            {
                return Err("Previous exchange is unresolved".into());
            }
            if Instant::now() >= deadline {
                return Err("Request deadline expired".into());
            }
            self.journal.append("intent", target, bytes)?;
            // Disk latency consumes this exchange's deadline too.
            if Instant::now() >= deadline {
                return Err("Deadline expired before send".into());
            }
            self.inner.target = target;
            self.inner.response_source = target;
            self.inner.send_packet(bytes, deadline)?;
            self.timing.begin(target, bytes, Instant::now(), deadline)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn receive_logged(&mut self, deadline: Instant) -> Result<Vec<u8>, String> {
        if self.poisoned {
            return Err("Operation connection is failed".into());
        }
        let result = (|| {
            let effective = self.timing.deadline(deadline)?;
            let reply = self.inner.receive(effective)?;
            let received_at = Instant::now();
            self.journal.append("response", self.inner.target, &reply)?;
            if Instant::now() >= self.timing.hard_deadline(deadline)? {
                return Err("Response arrived or could not be persisted before the absolute exchange deadline".into());
            }
            self.timing.received(&reply, received_at)?;
            Ok(reply)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

impl<J: WireJournal> ControlChannel for OwnedN20Transport<J> {
    fn exchange(
        &mut self,
        target: u8,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        if self.readback.is_some()
            && (target != 0x12 || !matches!(request.first(), Some(0x22 | 0x23)))
        {
            self.poisoned = true;
            return Err(
                "Verification connection permits only DME identifier and bounded memory reads"
                    .into(),
            );
        }
        // Evidence collection is limited to the three capture-derived reads;
        // it must not introduce an unrestricted memory-read control path.
        if request.first() == Some(&0x23)
            && (target != 0x12
                || !match self.readback {
                    Some((scope, maximum)) => readback_range_allowed(scope, maximum, request),
                    None => [
                        [0x23, 0x24, 0x80, 0x1f, 0xfa, 0x40, 0, 16],
                        [0x23, 0x24, 0xd0, 0, 0, 0, 0, 64],
                        [0x23, 0x24, 0x80, 0x1f, 0xfa, 0, 0, 64],
                    ]
                    .iter()
                    .any(|allowed| request == allowed),
                })
        {
            self.poisoned = true;
            return Err("Unsupported evidence memory range".into());
        }
        if !matches!(
            request.first(),
            Some(0x10 | 0x11 | 0x22 | 0x23 | 0x27 | 0x28 | 0x2e | 0x31 | 0x85)
        ) {
            self.poisoned = true;
            return Err("Unsupported control service".into());
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or("Deadline overflow")?;
        self.send_to(target, request, deadline)?;
        loop {
            let reply = self.receive_logged(deadline)?;
            if reply == [0x7f, request[0], 0x78] {
                continue;
            }
            return Ok(reply);
        }
    }
}

impl<J: WireJournal> DownloadTransport for OwnedN20Transport<J> {
    fn send(&mut self, bytes: &[u8], deadline: Instant) -> Result<(), String> {
        if self.readback.is_some() {
            self.poisoned = true;
            return Err("Verification connection cannot send downloads".into());
        }
        if !matches!(bytes.first(), Some(0x34 | 0x36 | 0x37)) {
            self.poisoned = true;
            return Err("Unsupported download service".into());
        }
        self.send_to(0x12, bytes, deadline)
    }
    fn receive(&mut self, deadline: Instant) -> Result<Vec<u8>, String> {
        self.receive_logged(deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uds_download::{ExchangeJournal, ExchangeRecord};
    use std::io::Read;
    use std::net::TcpListener;

    fn memory(address: u32, length: u16) -> Vec<u8> {
        let mut request = vec![0x23, 0x24];
        request.extend(address.to_be_bytes());
        request.extend(length.to_be_bytes());
        request
    }
    #[test]
    fn verification_reads_reach_socket_for_both_scopes_and_all_region_edges() {
        for scope in [ReadbackScope::Partial, ReadbackScope::Full, ReadbackScope::Recovery] {
            let ranges = match scope {
                ReadbackScope::Partial => vec![(0x80180000, 0x7fc00), (0x801ffd00, 0x300)],
                ReadbackScope::Full | ReadbackScope::Recovery => crate::n20_recovery::REGIONS
                    .iter()
                    .map(|r| (r.address(), r.length as u32))
                    .collect(),
            };
            let requests: Vec<_> = ranges
                .iter()
                .flat_map(|(address, length)| {
                    [memory(*address, 256), memory(address + length - 256, 256)]
                })
                .collect();
            let expected = requests.clone();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let worker = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                for request in expected {
                    assert_eq!(read_request(&mut socket), (0x12, request));
                    let reply: Vec<_> = std::iter::once(0x63).chain(vec![0x5a; 256]).collect();
                    socket.write_all(&build_hsfz(0x12, TESTER, &reply)).unwrap();
                }
            });
            let mut channel = OwnedN20Transport::new(stream, Log::default());
            channel.configure_readback(scope, 256).unwrap();
            for request in requests {
                let response = channel
                    .exchange(0x12, &request, Duration::from_secs(2))
                    .unwrap();
                assert_eq!(response.len(), 257);
                assert!(response[1..].iter().all(|b| *b == 0x5a));
            }
            worker.join().unwrap();
        }
    }
    #[test]
    fn verification_ranges_reject_gaps_startup_crossings_zero_overflow_and_oversize() {
        for scope in [ReadbackScope::Partial, ReadbackScope::Full, ReadbackScope::Recovery] {
            for request in [
                memory(0x80000000, 256),
                memory(0x801ffbff, 2),
                memory(0x801ffc00, 1),
                memory(0x801fffff, 2),
                memory(0x80180000, 0),
                memory(0x80180000, 257),
                memory(u32::MAX, 2),
            ] {
                assert!(!readback_range_allowed(scope, 256, &request));
            }
            assert!(!readback_range_allowed(scope, 256, &[0x23, 0x44]));
        }
        assert!(!readback_range_allowed(
            ReadbackScope::Partial,
            256,
            &memory(0x80020000, 256)
        ));
        assert!(readback_range_allowed(
            ReadbackScope::Recovery,
            256,
            &memory(0x80020000, 256)
        ));
    }
    #[test]
    fn verification_rejects_writes_wrong_route_and_downloads_before_journal_or_io() {
        for (target, request) in [
            (0x12, vec![0x10, 2]),
            (0x12, vec![0x2e, 0xf1, 0x90, 0]),
            (0x12, vec![0x31, 1, 0xff, 0]),
            (0x17, vec![0x22, 0xf1, 1]),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let mut channel = OwnedN20Transport::new(stream, Log::default());
            channel
                .configure_readback(ReadbackScope::Partial, 256)
                .unwrap();
            assert!(channel
                .exchange(target, &request, Duration::from_secs(1))
                .is_err());
            assert!(channel.journal.entries.is_empty());
            assert!(channel.poisoned);
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut channel = OwnedN20Transport::new(stream, Log::default());
        channel
            .configure_readback(ReadbackScope::Recovery, 256)
            .unwrap();
        assert!(channel
            .send(&[0x34, 0, 0x44], Instant::now() + Duration::from_secs(1))
            .is_err());
        assert!(channel.journal.entries.is_empty());
    }
    #[test]
    fn ordinary_operation_keeps_only_reference_probe_reads() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut channel = OwnedN20Transport::new(stream, Log::default());
        assert!(channel
            .exchange(0x12, &memory(0x80180000, 256), Duration::from_secs(1))
            .is_err());
        assert!(channel.journal.entries.is_empty());
    }
    #[derive(Default)]
    struct Log {
        entries: Vec<(String, u8, Vec<u8>)>,
        fail_at: Option<usize>,
    }
    impl WireJournal for Log {
        fn append(&mut self, kind: &str, target: u8, bytes: &[u8]) -> Result<(), String> {
            if self.fail_at == Some(self.entries.len()) {
                return Err("Injected disk failure".into());
            }
            self.entries.push((kind.into(), target, bytes.to_vec()));
            Ok(())
        }
    }
    #[derive(Default)]
    struct ExchangeLog;
    impl ExchangeJournal for ExchangeLog {
        fn append(&mut self, _: ExchangeRecord) -> Result<(), String> {
            Ok(())
        }
    }
    fn read_request(server: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut header = [0; 8];
        server.read_exact(&mut header).unwrap();
        let len = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
        let mut uds = vec![0; len - 2];
        server.read_exact(&mut uds).unwrap();
        (header[7], uds)
    }
    #[test]
    fn learned_p2_timeout_poisoning_prevents_a_second_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut server, _) = listener.accept().unwrap();
            assert_eq!(read_request(&mut server).1, [0x10, 2]);
            server
                .write_all(&build_hsfz(0x12, TESTER, &[0x50, 2, 0, 10, 0, 20]))
                .unwrap();
            assert_eq!(read_request(&mut server).1, [0x22, 0xf1, 1]);
            std::thread::sleep(Duration::from_millis(150));
            let _ = server.write_all(&build_hsfz(0x12, TESTER, &[0x62, 0xf1, 1, 1]));
        });
        let mut channel = OwnedN20Transport::new(stream, Log::default());
        channel
            .configure_session_timing(crate::n20_session_timing::Bounds {
                max_p2_ms: 1000,
                max_p2_star_ms: 30000,
                margin_ms: 20,
            })
            .unwrap();
        channel
            .exchange(0x12, &[0x10, 2], Duration::from_secs(1))
            .unwrap();
        assert!(channel
            .exchange(0x12, &[0x22, 0xf1, 1], Duration::from_secs(1))
            .is_err());
        assert!(channel
            .exchange(0x12, &[0x22, 0xf1, 1], Duration::from_secs(1))
            .is_err());
        assert_eq!(
            channel
                .journal
                .entries
                .iter()
                .filter(|(kind, _, _)| kind == "intent")
                .count(),
            2
        );
        worker.join().unwrap();
    }
    #[test]
    fn learned_p2_star_allows_pending_download_within_absolute_cap() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut server, _) = listener.accept().unwrap();
            assert_eq!(read_request(&mut server).1, [0x10, 2]);
            server
                .write_all(&build_hsfz(0x12, TESTER, &[0x50, 2, 0, 20, 0, 20]))
                .unwrap();
            assert_eq!(read_request(&mut server).1[0], 0x34);
            server
                .write_all(&build_hsfz(0x12, TESTER, &[0x7f, 0x34, 0x78]))
                .unwrap();
            std::thread::sleep(Duration::from_millis(80));
            server
                .write_all(&build_hsfz(0x12, TESTER, &[0x74, 0x10, 4]))
                .unwrap();
            let data = read_request(&mut server).1;
            assert_eq!(data, [0x36, 1, 1, 2]);
            server
                .write_all(&build_hsfz(0x12, TESTER, &[0x76, 1]))
                .unwrap();
            assert_eq!(read_request(&mut server).1, [0x37]);
            server
                .write_all(&build_hsfz(0x12, TESTER, &[0x77]))
                .unwrap();
        });
        let mut channel = OwnedN20Transport::new(stream, Log::default());
        channel
            .configure_session_timing(crate::n20_session_timing::Bounds {
                max_p2_ms: 1000,
                max_p2_star_ms: 30000,
                margin_ms: 20,
            })
            .unwrap();
        channel
            .exchange(0x12, &[0x10, 2], Duration::from_secs(1))
            .unwrap();
        crate::uds_download::run_download(
            &mut channel,
            &mut ExchangeLog,
            0x80180000,
            vec![1, 2],
            4094,
            Duration::from_secs(1),
        )
        .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn setup_and_transfer_share_one_socket_with_fragmentation_and_pending() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut server, _) = listener.accept().unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            // Sixteen setup exchanges, then download + two blocks + exit.
            for _ in 0..20 {
                let (target, request) = read_request(&mut server);
                let reply = match request.as_slice() {
                    [0x10, sub] => vec![0x50, *sub, 0, 50, 1, 244],
                    [0x31, sub, hi, lo, ..] => vec![0x71, *sub, *hi, *lo],
                    [0x85, sub] => vec![0xc5, *sub],
                    [0x28, sub, ..] => vec![0x68, *sub],
                    [0x27, 0x11, ..] => [vec![0x67, 0x11], vec![7; 8]].concat(),
                    [0x27, 0x12, ..] => vec![0x67, 0x12],
                    [0x2e, hi, lo, ..] => vec![0x6e, *hi, *lo],
                    [0x34, ..] => vec![0x74, 0x10, 4],
                    [0x36, counter, ..] => vec![0x76, *counter],
                    [0x37] => vec![0x77],
                    _ => panic!("Unexpected request"),
                };
                let mut response = build_hsfz(target, TESTER, &[0x7f, request[0], 0x78]);
                response.extend(build_hsfz(target, TESTER, &reply));
                for part in response.chunks(3) {
                    server.write_all(part).unwrap();
                }
            }
        });
        let mut channel = OwnedN20Transport::new(stream, Log::default());
        crate::n20_setup::run(
            &mut channel,
            "LIVE",
            [0x26, 0x11, 2],
            true,
            Duration::from_secs(3),
            |_, seed| {
                assert_eq!(seed, &[7; 8]);
                Ok(vec![9; 16])
            },
        )
        .unwrap();
        crate::uds_download::run_download(
            &mut channel,
            &mut ExchangeLog,
            0x80180000,
            vec![1, 2, 3],
            4094,
            Duration::from_secs(3),
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(
            channel
                .journal
                .entries
                .iter()
                .filter(|e| e.0 == "intent")
                .count(),
            20
        );
        assert_eq!(
            channel
                .journal
                .entries
                .iter()
                .filter(|e| e.0 == "response")
                .count(),
            40
        );
        assert!(!channel.poisoned);
    }
    #[test]
    fn durable_intent_failure_sends_nothing_and_permanently_stops_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let mut channel = OwnedN20Transport::new(
            stream,
            Log {
                fail_at: Some(0),
                ..Default::default()
            },
        );
        assert!(channel
            .exchange(0x12, &[0x10, 2], Duration::from_secs(1))
            .is_err());
        assert!(channel
            .exchange(0x12, &[0x10, 2], Duration::from_secs(1))
            .is_err());
        let mut bytes = [0; 8];
        assert!(server.read(&mut bytes).is_err());
        assert!(channel.journal.entries.is_empty());
    }
    #[test]
    fn lost_reply_blocks_later_requests_without_reconnecting() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let mut channel = OwnedN20Transport::new(stream, Log::default());
        assert!(channel
            .exchange(0x12, &[0x10, 2], Duration::from_millis(30))
            .is_err());
        assert_eq!(read_request(&mut server), (0x12, vec![0x10, 2]));
        assert!(channel
            .exchange(0x12, &[0x10, 2], Duration::from_secs(1))
            .is_err());
        assert_eq!(channel.journal.entries.len(), 1);
    }

    #[test]
    fn wire_file_is_bound_append_only_and_stays_failed_after_storage_error() {
        let path = std::env::temp_dir().join(format!(
            "n20-wire-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut journal = FileWireJournal::create(&path, &[0x42; 32]).unwrap();
        journal.append("intent", 0x12, &[0x10, 2]).unwrap();
        journal
            .append("response", 0x12, &[0x50, 2, 0, 50, 1, 244])
            .unwrap();
        let records: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records[0]["manifest_sha256"], "42".repeat(32));
        let body = records[1]["record"].as_str().unwrap();
        assert_eq!(records[1]["sha256"], hex(&Sha256::digest(body.as_bytes())));
        assert!(FileWireJournal::create(&path, &[0x42; 32]).is_err());
        journal.file = File::open(&path).unwrap();
        assert!(journal.append("intent", 0x12, &[0x10, 3]).is_err());
        journal.file = OpenOptions::new().append(true).open(&path).unwrap();
        assert!(journal.append("intent", 0x12, &[0x10, 3]).is_err());
        drop(journal);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
        std::fs::remove_file(path).unwrap();
    }
}

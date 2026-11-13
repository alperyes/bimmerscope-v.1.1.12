//! Legacy generic-DME P/PF ordering, separated from ECU-specific setup.
//! No live adapter or approved N20 profile exists yet. This is not an unlock
//! implementation and transfer acknowledgements do not validate image integrity.
#![allow(dead_code)]

use crate::uds_download::{run_download, DownloadTransport, ExchangeJournal};
use crate::vehicle_access::VehicleAccess;
use sha2::{Digest, Sha256};
use std::time::Duration;

const MAIN: std::ops::Range<usize> = 0x180000..0x1ffc00;
const TAIL: std::ops::Range<usize> = 0x1ffd00..0x200000;

/// Original `jc` integer-address form used by the P/PF branch. The address
/// selects an indexed operation; it does not establish physical erase scope.
pub(crate) fn legacy_indexed_erase_request() -> Vec<u8> {
    let mut request = vec![0x31, 0x01, 0xff, 0x00, 0x02, 0x40];
    request.extend(0x801ffd00u32.to_be_bytes());
    request
}

/// Original `iu` indicated-address form. The two zero bytes are fixed request
/// data from the descriptor, not a checksum calculated from the BIN.
pub(crate) fn legacy_check_memory_request() -> Vec<u8> {
    let mut request = vec![0x31, 0x01, 0x02, 0x02, 0x12, 0x40];
    request.extend(0x801ffd00u32.to_be_bytes());
    request.extend([0, 0]);
    request
}

pub(crate) fn legacy_dependency_request() -> [u8; 4] {
    [0x31, 0x01, 0xff, 0x01]
}

pub(crate) struct PartialImage {
    bytes: Vec<u8>,
    pub sha256: String,
    pub software_token: String,
}

impl PartialImage {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn calibration_token(&self) -> String {
        self.bytes[0x1ffd01..0x1ffd08]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect()
    }
    /// Own the inspected bytes so later file changes cannot alter the transfer.
    /// This establishes layout and byte identity, not ECU checksum validity.
    pub fn from_bin(bytes: Vec<u8>, expected_hash: &str) -> Result<Self, String> {
        if bytes.len() != 0x400000 || !bytes[..256].windows(10).any(|w| w == b"MEVD1729__") {
            return Err("Expected a 4 MiB MEVD17.2.9 BIN".into());
        }
        for (offset, expected) in [
            (0x18000c, 0x801ffc00u32),
            (0x180038, 0x80180000),
            (0x18003c, 0x801ffbff),
        ] {
            if bytes[offset..offset + 4] != expected.to_le_bytes() {
                return Err("N20 partial-region boundaries do not match".into());
            }
        }
        if bytes[0x1ffc00..0x1ffd00].iter().any(|b| *b != 0) {
            return Err("Nonzero skipped gap is not supported by this candidate layout".into());
        }
        let token = &bytes[0x20025..0x2002c];
        if bytes[0x20024] != 8 || token.iter().all(|b| *b == 0) || token.iter().all(|b| *b == 255) {
            return Err("File software identifier is unavailable".into());
        }
        let calibration = &bytes[0x1ffd01..0x1ffd08];
        if bytes[0x1ffd00] != 8
            || calibration.iter().all(|b| *b == 0)
            || calibration.iter().all(|b| *b == 255)
        {
            return Err("File calibration identifier is unavailable".into());
        }
        let software_token = token.iter().map(|b| format!("{b:02X}")).collect();
        let sha256: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if sha256 != expected_hash.to_ascii_lowercase() {
            return Err("Selected BIN hash changed".into());
        }
        Ok(Self {
            bytes,
            sha256,
            software_token,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    BindFreshIdentityAndValidateImage,
    SetupAndAuthorize,
    IndexedErase,
    MainTransfer,
    TailTransfer,
    CheckMemory,
    ProgrammingDependencies,
    WriteVin,
    SessionCleanup,
    CodingAndPostVerification,
}

pub(crate) const STAGES: [Stage; 10] = [
    Stage::BindFreshIdentityAndValidateImage,
    Stage::SetupAndAuthorize,
    Stage::IndexedErase,
    Stage::MainTransfer,
    Stage::TailTransfer,
    Stage::CheckMemory,
    Stage::ProgrammingDependencies,
    Stage::WriteVin,
    Stage::SessionCleanup,
    Stage::CodingAndPostVerification,
];

/// ECU-specific operations are deliberately not synthesized from session or
/// seed/key success. An implementation must bind exact identity, integrity,
/// power policy, response semantics and recovery evidence for the bench DME.
pub(crate) trait Procedure: DownloadTransport {
    fn perform(&mut self, stage: Stage, image: &PartialImage) -> Result<(), String>;
}

/// Each stage record must reach durable storage before this returns. Per-region
/// exchange journals retain the wire requests/replies independently.
pub(crate) trait StageJournal {
    fn record(&mut self, stage: Stage, completed: bool, image_sha256: &str) -> Result<(), String>;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub stage: Stage,
    pub detail: String,
    /// Conservative: setup can change ECU state even before erase is sent.
    pub ecu_state_may_have_changed: bool,
}

/// Execute the observed P/PF stage order, with strict propagation instead of
/// the historical ignored responses. No automatic U/F fallback or retries.
/// Caller must supply a reviewed Procedure; there is no production implementation.
pub(crate) fn run(
    access: &VehicleAccess,
    procedure: &mut impl Procedure,
    image: PartialImage,
    stages: &mut impl StageJournal,
    main_journal: &mut impl ExchangeJournal,
    tail_journal: &mut impl ExchangeJournal,
    timeout: Duration,
) -> Result<(), Failure> {
    let lease = access.programming().map_err(|detail| Failure {
        stage: Stage::BindFreshIdentityAndValidateImage,
        detail,
        ecu_state_may_have_changed: false,
    })?;
    run_owned(
        &lease,
        procedure,
        image,
        stages,
        main_journal,
        tail_journal,
        timeout,
    )
}

pub(crate) fn run_owned(
    lease: &crate::vehicle_access::Lease,
    procedure: &mut impl Procedure,
    image: PartialImage,
    stages: &mut impl StageJournal,
    main_journal: &mut impl ExchangeJournal,
    tail_journal: &mut impl ExchangeJournal,
    timeout: Duration,
) -> Result<(), Failure> {
    let first = Stage::BindFreshIdentityAndValidateImage;
    let failure = |stage, detail, changed| Failure {
        stage,
        detail,
        ecu_state_may_have_changed: changed,
    };
    if timeout.is_zero() {
        return Err(failure(first, "Invalid timeout".into(), false));
    }
    lease
        .require_programming()
        .map_err(|e| failure(first, e, false))?;
    for stage in STAGES {
        let changed_before = !matches!(
            stage,
            Stage::BindFreshIdentityAndValidateImage | Stage::SetupAndAuthorize
        );
        stages
            .record(stage, false, &image.sha256)
            .map_err(|e| failure(stage, e, changed_before))?;
        let result = match stage {
            Stage::MainTransfer => run_download(
                procedure,
                main_journal,
                0x80180000,
                image.bytes[MAIN].to_vec(),
                4094,
                timeout,
            ),
            Stage::TailTransfer => run_download(
                procedure,
                tail_journal,
                0x801ffd00,
                image.bytes[TAIL].to_vec(),
                4094,
                timeout,
            ),
            _ => procedure.perform(stage, &image),
        };
        // A failed setup/erase can have taken effect without its response.
        let changed = stage != first;
        result.map_err(|e| failure(stage, e, changed))?;
        stages
            .record(stage, true, &image.sha256)
            .map_err(|e| failure(stage, e, changed))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uds_download::ExchangeRecord;
    use std::collections::VecDeque;
    use std::time::Instant;

    fn bin() -> Vec<u8> {
        let mut b = vec![0; 0x400000];
        b[26..36].copy_from_slice(b"MEVD1729__");
        for (p, v) in [
            (0x18000c, 0x801ffc00u32),
            (0x180038, 0x80180000),
            (0x18003c, 0x801ffbff),
        ] {
            b[p..p + 4].copy_from_slice(&v.to_le_bytes());
        }
        b[0x20024] = 8;
        b[0x20025..0x2002c].copy_from_slice(&[0, 0, 0x1c, 0x9f, 0x1d, 0x96, 1]);
        b[MAIN.start] = 0x42;
        b[TAIL.start] = 8;
        b[TAIL.start + 1..TAIL.start + 8].copy_from_slice(&[0, 0, 0x1c, 0xdb, 0x1d, 0x96, 7]);
        b
    }
    fn image(b: Vec<u8>) -> PartialImage {
        let hash = format!("{:x}", Sha256::digest(&b));
        PartialImage::from_bin(b, &hash).unwrap()
    }
    #[derive(Default)]
    struct Bench {
        actions: Vec<Stage>,
        sent: Vec<Vec<u8>>,
        replies: VecDeque<Vec<u8>>,
        fail: Option<Stage>,
        reject_main: bool,
    }
    impl Procedure for Bench {
        fn perform(&mut self, stage: Stage, _: &PartialImage) -> Result<(), String> {
            self.actions.push(stage);
            if self.fail == Some(stage) {
                Err("Injected stage failure".into())
            } else {
                Ok(())
            }
        }
    }
    impl DownloadTransport for Bench {
        fn send(&mut self, b: &[u8], _: Instant) -> Result<(), String> {
            self.sent.push(b.to_vec());
            self.replies.push_back(match b[0] {
                0x34 if self.reject_main => vec![0x7f, 0x34, 0x70],
                // Negotiates only 1022 payload bytes; legacy cap is a ceiling.
                0x34 => vec![0x74, 0x20, 4, 0],
                0x36 => vec![0x76, b[1]],
                0x37 => vec![0x77],
                _ => panic!("Unexpected service"),
            });
            Ok(())
        }
        fn receive(&mut self, _: Instant) -> Result<Vec<u8>, String> {
            self.replies.pop_front().ok_or("Missing reply".into())
        }
    }
    #[derive(Default)]
    struct Log(Vec<ExchangeRecord>);
    impl ExchangeJournal for Log {
        fn append(&mut self, r: ExchangeRecord) -> Result<(), String> {
            self.0.push(r);
            Ok(())
        }
    }
    #[derive(Default)]
    struct Stages {
        entries: Vec<(Stage, bool)>,
        fail_at: Option<Stage>,
    }
    impl StageJournal for Stages {
        fn record(&mut self, s: Stage, done: bool, _: &str) -> Result<(), String> {
            if self.fail_at == Some(s) {
                return Err("Storage failure".into());
            }
            self.entries.push((s, done));
            Ok(())
        }
    }
    fn execute(bench: &mut Bench, stages: &mut Stages) -> Result<(), Failure> {
        run(
            &VehicleAccess::default(),
            bench,
            image(bin()),
            stages,
            &mut Log::default(),
            &mut Log::default(),
            Duration::from_secs(1),
        )
    }
    #[test]
    fn transfers_only_main_and_tail_then_checks_and_finishes() {
        let mut bench = Bench::default();
        let mut stages = Stages::default();
        execute(&mut bench, &mut stages).unwrap();
        let downloads: Vec<_> = bench.sent.iter().filter(|b| b[0] == 0x34).collect();
        assert_eq!(downloads.len(), 2);
        assert_eq!(downloads[0][3..7], 0x80180000u32.to_be_bytes());
        assert_eq!(downloads[1][3..7], 0x801ffd00u32.to_be_bytes());
        let transferred: Vec<_> = bench
            .sent
            .iter()
            .filter(|b| b[0] == 0x36)
            .flat_map(|b| b[2..].iter().copied())
            .collect();
        let b = bin();
        assert_eq!(transferred, [b[MAIN].to_vec(), b[TAIL].to_vec()].concat());
        assert!(bench
            .sent
            .iter()
            .filter(|b| b[0] == 0x36)
            .all(|b| b.len() <= 1024));
        assert_eq!(
            stages.entries.last(),
            Some(&(Stage::CodingAndPostVerification, true))
        );
        assert_eq!(
            bench.actions,
            vec![
                Stage::BindFreshIdentityAndValidateImage,
                Stage::SetupAndAuthorize,
                Stage::IndexedErase,
                Stage::CheckMemory,
                Stage::ProgrammingDependencies,
                Stage::WriteVin,
                Stage::SessionCleanup,
                Stage::CodingAndPostVerification
            ]
        );
    }
    #[test]
    fn every_stage_failure_stops_without_fallback_or_cleanup() {
        for stage in [
            Stage::BindFreshIdentityAndValidateImage,
            Stage::SetupAndAuthorize,
            Stage::IndexedErase,
            Stage::CheckMemory,
            Stage::ProgrammingDependencies,
            Stage::WriteVin,
            Stage::SessionCleanup,
            Stage::CodingAndPostVerification,
        ] {
            let mut bench = Bench {
                fail: Some(stage),
                ..Default::default()
            };
            let error = execute(&mut bench, &mut Stages::default()).unwrap_err();
            assert_eq!(error.stage, stage);
            assert_eq!(bench.actions.last(), Some(&stage));
            assert_eq!(
                error.ecu_state_may_have_changed,
                stage != Stage::BindFreshIdentityAndValidateImage
            );
            if matches!(
                stage,
                Stage::BindFreshIdentityAndValidateImage
                    | Stage::SetupAndAuthorize
                    | Stage::IndexedErase
            ) {
                assert!(bench.sent.is_empty());
            }
        }
    }
    #[test]
    fn main_rejection_prevents_tail_and_checks() {
        let mut bench = Bench {
            reject_main: true,
            ..Default::default()
        };
        let error = execute(&mut bench, &mut Stages::default()).unwrap_err();
        assert_eq!(error.stage, Stage::MainTransfer);
        assert_eq!(bench.sent.len(), 1);
        assert!(!bench.actions.contains(&Stage::CheckMemory));
    }
    #[test]
    fn storage_failure_prevents_erase() {
        let mut bench = Bench::default();
        let error = execute(
            &mut bench,
            &mut Stages {
                fail_at: Some(Stage::IndexedErase),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.stage, Stage::IndexedErase);
        assert!(!bench.actions.contains(&Stage::IndexedErase));
        assert!(bench.sent.is_empty());
    }
    #[test]
    fn rejects_bad_hash_layout_gap_and_missing_software() {
        assert!(PartialImage::from_bin(bin(), &"0".repeat(64)).is_err());
        for offset in [26, 0x18000c, 0x180038, 0x18003c, 0x1ffc00, 0x20024] {
            let mut b = bin();
            b[offset] ^= 1;
            let hash = format!("{:x}", Sha256::digest(&b));
            assert!(
                PartialImage::from_bin(b, &hash).is_err(),
                "offset {offset:x}"
            );
        }
        assert!(PartialImage::from_bin(vec![0; 3], "").is_err());
    }
    #[test]
    fn calibration_identity_requires_its_observed_type_and_present_token() {
        let valid = image(bin());
        assert_eq!(valid.calibration_token(), "00001CDB1D9607");
        // A startup type-06 record, unknown type or absent marker must not
        // expose adjacent bytes as a calibration ID, even with a valid hash.
        for record_type in [0, 6, 7, 9, 255] {
            let mut b = bin();
            b[TAIL.start] = record_type;
            let hash = format!("{:x}", Sha256::digest(&b));
            let error = PartialImage::from_bin(b, &hash).err().unwrap();
            assert!(
                error.contains("calibration identifier"),
                "type {record_type}"
            );
        }
        for empty in [0, 255] {
            let mut b = bin();
            b[TAIL.start + 1..TAIL.start + 8].fill(empty);
            let hash = format!("{:x}", Sha256::digest(&b));
            let error = PartialImage::from_bin(b, &hash).err().unwrap();
            assert!(error.contains("calibration identifier"));
        }
    }
    #[test]
    fn active_diagnostics_prevent_any_procedure_actions() {
        let access = VehicleAccess::default();
        let _diagnostic = access.diagnostic().unwrap();
        let mut bench = Bench::default();
        assert!(run(
            &access,
            &mut bench,
            image(bin()),
            &mut Stages::default(),
            &mut Log::default(),
            &mut Log::default(),
            Duration::from_secs(1)
        )
        .is_err());
        assert!(bench.actions.is_empty());
        assert!(bench.sent.is_empty());
    }
    #[test]
    fn routine_requests_match_original_integer_descriptors() {
        assert_eq!(
            legacy_indexed_erase_request(),
            vec![0x31, 1, 0xff, 0, 2, 0x40, 0x80, 0x1f, 0xfd, 0]
        );
        assert_eq!(
            legacy_check_memory_request(),
            vec![0x31, 1, 2, 2, 0x12, 0x40, 0x80, 0x1f, 0xfd, 0, 0, 0]
        );
        assert_eq!(legacy_dependency_request(), [0x31, 1, 0xff, 1]);
    }
    #[test]
    fn partial_image_owns_the_exact_inspected_bytes() {
        let mut source = bin();
        let owned = image(source.clone());
        source[MAIN.start] ^= 1;
        assert_ne!(owned.bytes[MAIN.start], source[MAIN.start]);
        assert_eq!(owned.software_token, "00001C9F1D9601");
        assert_eq!(owned.bytes[MAIN].len() + owned.bytes[TAIL].len(), 524_032);
    }

    #[test]
    fn failed_memory_check_survives_restart_without_recording_flash_completion() {
        let path = std::env::temp_dir().join(format!(
            "n20-workflow-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let selected = image(bin());
        let image_hash = selected.sha256.clone();
        let binding = [0x42; 32];
        let mut stages =
            crate::n20_stage_journal::FileStageJournal::create(&path, &binding, &image_hash)
                .unwrap();
        let mut bench = Bench {
            fail: Some(Stage::CheckMemory),
            ..Default::default()
        };
        let error = run(
            &VehicleAccess::default(),
            &mut bench,
            selected,
            &mut stages,
            &mut Log::default(),
            &mut Log::default(),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(error.stage, Stage::CheckMemory);
        drop(stages);
        let persisted = crate::n20_stage_journal::inspect(&path, &binding, &image_hash).unwrap();
        assert_eq!(persisted.last, Some((Stage::CheckMemory, false)));
        assert!(!persisted.workflow_recorded_complete);
        assert!(persisted.ecu_state_may_have_changed);
        std::fs::remove_file(path).unwrap();
    }
}

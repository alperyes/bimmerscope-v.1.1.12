//! Six-region software/calibration writer observed in FlashHandler, shared by
//! distinct ordinary-full and responding-recovery owners and approval scopes.
//! This is not boot recovery and never runs automatically after partial failure.
#![allow(dead_code)]
use crate::n20_partial::PartialImage;
use crate::uds_download::{run_download, DownloadTransport, ExchangeJournal};
use crate::vehicle_access::Lease;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RewriteKind {
    Full,
    Recovery,
}
impl RewriteKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Recovery => "recovery",
        }
    }
    pub fn stage_file(self) -> &'static str {
        match self {
            Self::Full => "full-stages.jsonl",
            Self::Recovery => "recovery-stages.jsonl",
        }
    }
    pub fn stage_schema(self) -> &'static str {
        match self {
            Self::Full => "n20-full-stages-v1",
            Self::Recovery => "n20-recovery-stages-v1",
        }
    }
    pub fn receipt_schema(self) -> &'static str {
        match self {
            Self::Full => "n20-full-verified-v1",
            Self::Recovery => "n20-recovery-verified-v1",
        }
    }
    pub fn backend(self) -> &'static str {
        match self {
            Self::Full => "n20-mevd1729-full-v1",
            Self::Recovery => "n20-mevd1729-recovery-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Region {
    pub name: &'static str,
    pub start: usize,
    pub length: usize,
}
impl Region {
    pub fn address(self) -> u32 {
        0x80000000 + self.start as u32
    }
}
// ia.java full writer's non-MEVD172 branch. MEVD1729 is not MEVD172.
pub(crate) const REGIONS: [Region; 6] = [
    Region {
        name: "software main 1",
        start: 0x20000,
        length: 0x15fc00,
    },
    Region {
        name: "software tail 1",
        start: 0x17fd00,
        length: 0x300,
    },
    Region {
        name: "software main 2",
        start: 0x220000,
        length: 0x1dfc00,
    },
    Region {
        name: "software tail 2",
        start: 0x3ffd00,
        length: 0x300,
    },
    Region {
        name: "calibration main",
        start: 0x180000,
        length: 0x7fc00,
    },
    Region {
        name: "calibration tail",
        start: 0x1ffd00,
        length: 0x300,
    },
];
pub(crate) struct RecoveryImage {
    partial: PartialImage,
}
impl RecoveryImage {
    pub fn from_bin(bytes: Vec<u8>, hash: &str) -> Result<Self, String> {
        let partial = PartialImage::from_bin(bytes, hash)?;
        crate::n20_integrity::require_known_image_checks(partial.bytes())?;
        Ok(Self { partial })
    }
    pub fn partial(&self) -> &PartialImage {
        &self.partial
    }
    #[cfg(test)]
    pub fn synthetic(partial: PartialImage) -> Self {
        Self { partial }
    }
    pub fn manifest(&self) -> serde_json::Value {
        serde_json::json!({"schema":"n20-responding-recovery-plan-v1","bin_sha256":self.partial.sha256,
            "software_token":self.partial.software_token,"total_bytes":REGIONS.iter().map(|r|r.length).sum::<usize>(),
            "regions":REGIONS.iter().map(|r|serde_json::json!({"name":r.name,"file_start":r.start,"length":r.length,"ecu_address":r.address()})).collect::<Vec<_>>(),
            "startup_written":false,"boot_recovery":false,"programming_approved":false,"live_execution_connected":true,
            "required":"separate exact full-rewrite profile, original bound coding, power checks and independent six-region post-reset verification"})
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    BindFreshIdentity,
    Setup,
    EraseSoftware,
    SoftwareMain1,
    SoftwareTail1,
    SoftwareMain2,
    SoftwareTail2,
    CheckSoftware,
    EraseCalibration,
    CalibrationMain,
    CalibrationTail,
    CheckCalibration,
    Dependencies,
    WriteVin,
    Cleanup,
    CodingAndVerification,
}
pub(crate) const STAGES: [Stage; 16] = [
    Stage::BindFreshIdentity,
    Stage::Setup,
    Stage::EraseSoftware,
    Stage::SoftwareMain1,
    Stage::SoftwareTail1,
    Stage::SoftwareMain2,
    Stage::SoftwareTail2,
    Stage::CheckSoftware,
    Stage::EraseCalibration,
    Stage::CalibrationMain,
    Stage::CalibrationTail,
    Stage::CheckCalibration,
    Stage::Dependencies,
    Stage::WriteVin,
    Stage::Cleanup,
    Stage::CodingAndVerification,
];
/// Supplied only by a separately reviewed full-rewrite owner. Partial approval
/// cannot supply these distinct software/calibration erase semantics.
pub(crate) struct ReviewedRecovery {
    pub image_sha256: String,
    pub evidence_id: String,
    pub software_erase_result: u8,
    pub calibration_erase_result: u8,
}
pub(crate) trait Procedure: DownloadTransport {
    fn perform_recovery(
        &mut self,
        stage: Stage,
        image: &RecoveryImage,
        review: &ReviewedRecovery,
    ) -> Result<(), String>;
    /// Fresh post-reset readback, in REGIONS order; partial verification is insufficient.
    fn readback_recovery(&mut self) -> Result<[Vec<u8>; 6], String>;
}
pub(crate) trait StageJournal {
    fn record(&mut self, stage: Stage, completed: bool, image_hash: &str) -> Result<(), String>;
}
#[derive(Debug)]
pub(crate) struct Failure {
    pub stage: Stage,
    pub detail: String,
    pub ecu_state_may_have_changed: bool,
}
/// Caller retains ownership from fresh preflight through independent six-region
/// verification. Never call this as an implicit retry, resume, or partial fallback.
pub(crate) fn run_owned(
    lease: &Lease,
    procedure: &mut impl Procedure,
    image: RecoveryImage,
    review: &ReviewedRecovery,
    stages: &mut impl StageJournal,
    downloads: &mut [impl ExchangeJournal; 6],
    timeout: Duration,
) -> Result<(), Failure> {
    let fail = |stage, detail, changed| Failure {
        stage,
        detail,
        ecu_state_may_have_changed: changed,
    };
    let first = Stage::BindFreshIdentity;
    lease
        .require_programming()
        .map_err(|e| fail(first, e, false))?;
    if timeout.is_zero()
        || review.evidence_id.trim().is_empty()
        || review.image_sha256 != image.partial.sha256
    {
        return Err(fail(
            first,
            "Missing or mismatched full-rewrite approval".into(),
            false,
        ));
    }
    for stage in STAGES {
        let changed_before = !matches!(stage, Stage::BindFreshIdentity | Stage::Setup);
        stages
            .record(stage, false, &image.partial.sha256)
            .map_err(|e| fail(stage, e, changed_before))?;
        let index = match stage {
            Stage::SoftwareMain1 => Some(0),
            Stage::SoftwareTail1 => Some(1),
            Stage::SoftwareMain2 => Some(2),
            Stage::SoftwareTail2 => Some(3),
            Stage::CalibrationMain => Some(4),
            Stage::CalibrationTail => Some(5),
            _ => None,
        };
        let result = if let Some(i) = index {
            let region = REGIONS[i];
            run_download(
                procedure,
                &mut downloads[i],
                region.address(),
                image.partial.bytes()[region.start..region.start + region.length].to_vec(),
                4094,
                timeout,
            )
        } else {
            procedure.perform_recovery(stage, &image, review)
        };
        let changed = stage != first;
        result.map_err(|e| fail(stage, e, changed))?;
        if stage == Stage::CodingAndVerification {
            let readback = procedure
                .readback_recovery()
                .map_err(|e| fail(stage, e, true))?;
            for (region, actual) in REGIONS.iter().zip(readback) {
                if actual != image.partial.bytes()[region.start..region.start + region.length] {
                    return Err(fail(
                        stage,
                        format!("Recovery readback differs: {}", region.name),
                        true,
                    ));
                }
            }
        }
        stages
            .record(stage, true, &image.partial.sha256)
            .map_err(|e| fail(stage, e, changed))?;
    }
    Ok(())
}

/// Operation-specific durable journal, distinct from the partial stage schema.
pub(crate) struct FileStageJournal {
    file: std::fs::File,
    sequence: usize,
    chain: String,
    failed: bool,
    image_hash: String,
}
impl FileStageJournal {
    pub fn create(
        path: &std::path::Path,
        binding: &[u8; 32],
        image_hash: &str,
    ) -> Result<Self, String> {
        Self::create_kind(path, binding, image_hash, RewriteKind::Recovery)
    }
    pub fn create_kind(
        path: &std::path::Path,
        binding: &[u8; 32],
        image_hash: &str,
        kind: RewriteKind,
    ) -> Result<Self, String> {
        use sha2::{Digest, Sha256};
        use std::io::Write;
        if image_hash.len() != 64 || !image_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid recovery image hash".into());
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        let header=serde_json::json!({"schema":kind.stage_schema(),"operation_sha256":binding.iter().map(|b|format!("{b:02x}")).collect::<String>(),"image_sha256":image_hash}).to_string();
        writeln!(file, "{header}")
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(Self {
            file,
            sequence: 0,
            chain: format!("{:x}", Sha256::digest(header.as_bytes())),
            failed: false,
            image_hash: image_hash.into(),
        })
    }
}
impl StageJournal for FileStageJournal {
    fn record(&mut self, stage: Stage, completed: bool, image_hash: &str) -> Result<(), String> {
        use sha2::{Digest, Sha256};
        use std::io::Write;
        if self.failed
            || image_hash != self.image_hash
            || STAGES.get(self.sequence / 2) != Some(&stage)
            || completed != (self.sequence % 2 == 1)
        {
            self.failed = true;
            return Err("Invalid recovery journal transition or image".into());
        }
        let body=serde_json::json!({"sequence":self.sequence,"stage":format!("{stage:?}"),"completed":completed,"previous":self.chain}).to_string();
        let hash = format!("{:x}", Sha256::digest(body.as_bytes()));
        if let Err(e) = writeln!(
            self.file,
            "{}",
            serde_json::json!({"body":body,"sha256":hash})
        )
        .and_then(|_| self.file.sync_all())
        {
            self.failed = true;
            return Err(e.to_string());
        }
        self.chain = hash;
        self.sequence += 1;
        Ok(())
    }
}

/// Validate recorded workflow order/hash chain. Completion is only a local record,
/// never a fresh ECU-state assertion.
pub(crate) fn inspect_stages(
    path: &std::path::Path,
    binding: &[u8; 32],
    image_hash: &str,
) -> Result<(usize, bool), String> {
    inspect_stages_kind(path, binding, image_hash, RewriteKind::Recovery)
}
pub(crate) fn inspect_stages_kind(
    path: &std::path::Path,
    binding: &[u8; 32],
    image_hash: &str,
    kind: RewriteKind,
) -> Result<(usize, bool), String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    if bytes.last() != Some(&b'\n') {
        return Err("Truncated recovery stage journal".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let mut lines = text[..text.len() - 1].split('\n');
    let header = lines.next().ok_or("Missing recovery journal header")?;
    let value: serde_json::Value = serde_json::from_str(header).map_err(|e| e.to_string())?;
    let expected_binding = binding
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if value["schema"] != kind.stage_schema()
        || value["operation_sha256"] != expected_binding
        || value["image_sha256"] != image_hash
    {
        return Err("Recovery journal binding differs".into());
    }
    let mut chain = format!("{:x}", Sha256::digest(header.as_bytes()));
    let mut count = 0;
    for (sequence, line) in lines.enumerate() {
        if sequence >= STAGES.len() * 2 {
            return Err("Recovery records after completion".into());
        }
        let record: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        let body = record["body"]
            .as_str()
            .ok_or("Missing recovery journal body")?;
        let hash = format!("{:x}", Sha256::digest(body.as_bytes()));
        let value: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
        if record["sha256"] != hash
            || value["sequence"] != sequence
            || value["stage"] != format!("{:?}", STAGES[sequence / 2])
            || value["completed"] != (sequence % 2 == 1)
            || value["previous"] != chain
        {
            return Err("Recovery journal chain or stage differs".into());
        }
        chain = hash;
        count += 1;
    }
    Ok((count, count == STAGES.len() * 2))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durable_recovery_journal_cannot_skip_steps_or_be_reused() {
        let path = std::env::temp_dir().join(format!(
            "n20-recovery-journal-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let hash = "0".repeat(64);
        let mut journal = FileStageJournal::create(&path, &[7; 32], &hash).unwrap();
        assert!(FileStageJournal::create(&path, &[7; 32], &hash).is_err());
        for stage in STAGES {
            journal.record(stage, false, &hash).unwrap();
            journal.record(stage, true, &hash).unwrap();
        }
        assert!(journal
            .record(Stage::BindFreshIdentity, false, &hash)
            .is_err());
        drop(journal);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 33);
        assert_eq!(inspect_stages(&path, &[7; 32], &hash).unwrap(), (32, true));
        let header: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(header["schema"], "n20-recovery-stages-v1");
        assert!(inspect_stages(&path, &[8; 32], &hash).is_err());
        std::fs::write(&path, text.trim_end_matches('\n')).unwrap();
        assert!(inspect_stages(&path, &[7; 32], &hash).is_err());
        std::fs::remove_file(&path).unwrap();
        let mut journal = FileStageJournal::create(&path, &[7; 32], &hash).unwrap();
        assert!(journal.record(Stage::Setup, false, &hash).is_err());
        assert!(journal
            .record(Stage::BindFreshIdentity, false, &hash)
            .is_err());
        drop(journal);
        std::fs::remove_file(&path).unwrap();
    }
}

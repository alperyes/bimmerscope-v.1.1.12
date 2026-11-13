//! Durable N20 workflow-stage evidence. This journal never authorizes a flash,
//! retries an operation, or interprets an ECU's memory/integrity state.
#![allow(dead_code)]

use crate::n20_partial::{Stage, StageJournal, STAGES};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

const SCHEMA: &str = "bimmerscope-n20-stages-v1";

/// Opaque digest of a separately persisted operation manifest. The future live
/// owner must bind its fresh fingerprint, procedure, payload and recovery data.
pub(crate) struct FileStageJournal {
    file: File,
    image_hash: String,
    sequence: usize,
    chain: String,
    failed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Inspection {
    pub records: usize,
    pub last: Option<(Stage, bool)>,
    /// All stages were recorded complete by the supplied Procedure; this is
    /// not independent proof of ECU validity or successful real programming.
    pub workflow_recorded_complete: bool,
    pub ecu_state_may_have_changed: bool,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn header(manifest: &[u8; 32], image: &str) -> String {
    let manifest: String = manifest.iter().map(|b| format!("{b:02x}")).collect();
    format!("{SCHEMA} {manifest} {image}")
}

impl FileStageJournal {
    pub fn create(path: &Path, manifest: &[u8; 32], image_hash: &str) -> Result<Self, String> {
        if !valid_hash(image_hash) {
            return Err("Expected a lowercase SHA-256 image digest".into());
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        let header = header(manifest, image_hash);
        writeln!(file, "{header}")
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(Self {
            file,
            image_hash: image_hash.into(),
            sequence: 0,
            chain: digest(header.as_bytes()),
            failed: false,
        })
    }
}

impl StageJournal for FileStageJournal {
    fn record(&mut self, stage: Stage, completed: bool, image_sha256: &str) -> Result<(), String> {
        if self.failed || self.sequence >= STAGES.len() * 2 {
            return Err("Stage journal is failed or complete".into());
        }
        if image_sha256 != self.image_hash
            || STAGES[self.sequence / 2] != stage
            || completed != (self.sequence % 2 == 1)
        {
            self.failed = true;
            return Err("Stage order or image binding mismatch".into());
        }
        let body = format!(
            "{} {} {} {}",
            self.sequence,
            self.sequence / 2,
            if completed { "complete" } else { "intent" },
            self.chain
        );
        let hash = digest(body.as_bytes());
        let result = writeln!(self.file, "{body} {hash}").and_then(|_| self.file.sync_all());
        if let Err(error) = result {
            self.failed = true;
            return Err(format!("Stage journal storage failed: {error}"));
        }
        self.chain = hash;
        self.sequence += 1;
        Ok(())
    }
}

pub(crate) fn inspect(
    path: &Path,
    manifest: &[u8; 32],
    image_hash: &str,
) -> Result<Inspection, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    inspect_bytes(&bytes, manifest, image_hash)
}

fn inspect_bytes(
    bytes: &[u8],
    manifest: &[u8; 32],
    image_hash: &str,
) -> Result<Inspection, String> {
    if !valid_hash(image_hash) || bytes.last() != Some(&b'\n') {
        return Err("Invalid binding or truncated stage journal".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    let mut lines = text[..text.len() - 1].split('\n');
    let expected = header(manifest, image_hash);
    if lines.next() != Some(expected.as_str()) {
        return Err("Stage journal schema or binding mismatch".into());
    }
    let mut chain = digest(expected.as_bytes());
    let mut records = 0;
    let mut last = None;
    for (sequence, line) in lines.enumerate() {
        if sequence >= STAGES.len() * 2 {
            return Err("Records after completion".into());
        }
        let body = format!(
            "{sequence} {} {} {chain}",
            sequence / 2,
            if sequence % 2 == 1 {
                "complete"
            } else {
                "intent"
            }
        );
        let hash = digest(body.as_bytes());
        if line != format!("{body} {hash}") {
            return Err("Invalid stage sequence, record or digest chain".into());
        }
        last = Some((STAGES[sequence / 2], sequence % 2 == 1));
        records += 1;
        chain = hash;
    }
    Ok(Inspection {
        records,
        last,
        workflow_recorded_complete: records == STAGES.len() * 2,
        // Setup intent alone does not establish whether a request was sent.
        ecu_state_may_have_changed: records >= 3,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "n20-stages-{}-{}.log",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    fn hash() -> String {
        "a".repeat(64)
    }

    #[test]
    fn durable_prefixes_distinguish_setup_intent_from_complete_workflow() {
        let p = Temp::new();
        let image = hash();
        let mut journal = FileStageJournal::create(&p.0, &[1; 32], &image).unwrap();
        assert_eq!(inspect(&p.0, &[1; 32], &image).unwrap().records, 0);
        for (index, stage) in STAGES.into_iter().enumerate() {
            for done in [false, true] {
                journal.record(stage, done, &image).unwrap();
                let read = inspect(&p.0, &[1; 32], &image).unwrap();
                assert_eq!(read.last, Some((stage, done)));
                assert_eq!(read.ecu_state_may_have_changed, index > 0);
                assert_eq!(read.workflow_recorded_complete, index == 9 && done);
            }
        }
        assert!(journal.record(STAGES[0], false, &image).is_err());
        assert!(FileStageJournal::create(&p.0, &[1; 32], &image).is_err());
    }
    #[test]
    fn rejects_changed_binding_torn_records_and_modified_history() {
        let p = Temp::new();
        let image = hash();
        let mut journal = FileStageJournal::create(&p.0, &[1; 32], &image).unwrap();
        journal.record(STAGES[0], false, &image).unwrap();
        let original = std::fs::read(&p.0).unwrap();
        assert!(inspect_bytes(&original, &[2; 32], &image).is_err());
        assert!(inspect_bytes(&original, &[1; 32], &"b".repeat(64)).is_err());
        assert!(inspect_bytes(&original[..original.len() - 1], &[1; 32], &image).is_err());
        let mut changed = original.clone();
        let index = changed.len() - 3;
        changed[index] ^= 1;
        assert!(inspect_bytes(&changed, &[1; 32], &image).is_err());
        let mut duplicate = original.clone();
        duplicate.extend(original.split_inclusive(|b| *b == b'\n').last().unwrap());
        assert!(inspect_bytes(&duplicate, &[1; 32], &image).is_err());
    }
    #[test]
    fn incorrect_stage_permanently_closes_writer_without_appending() {
        let p = Temp::new();
        let image = hash();
        let mut journal = FileStageJournal::create(&p.0, &[1; 32], &image).unwrap();
        assert!(journal.record(Stage::IndexedErase, false, &image).is_err());
        assert!(journal.record(STAGES[0], false, &image).is_err());
        assert_eq!(inspect(&p.0, &[1; 32], &image).unwrap().records, 0);
    }
}

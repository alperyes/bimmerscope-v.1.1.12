//! Concrete legacy P/PF stage adapter over one owned control/download channel.
//! The app operation owner constructs this only behind its approved-profile gate.
//! Caller must supply fresh fingerprint, saved coding, validated image policy,
//! regulated-power evidence and a real post-reset verification implementation.
#![allow(dead_code)]

use crate::n20_coding::CodingSnapshot;
use crate::n20_partial::{self, PartialImage, Procedure, Stage};
use crate::n20_setup::{checked, ControlChannel};
use crate::uds_download::DownloadTransport;
use std::time::{Duration, Instant};

pub(crate) struct BoundInputs {
    pub vin: String,
    pub bootloader: String,
    pub software_token: String,
    /// Exact raw F101 UDS reply captured in this operation's preflight.
    pub f101_reply: Vec<u8>,
    /// Stored record date bytes, not a substituted current-date default.
    pub fingerprint_date: [u8; 3],
    pub prepare_auxiliary: bool,
    /// Reviewed ECU result; not inferred from the legacy prefix matcher.
    pub erase_success_result: u8,
    /// In-memory proof deadline only; never restored from saved JSON.
    pub setup_valid_until: Option<Instant>,
}

pub(crate) struct N20Procedure<C, K, V> {
    channel: C,
    inputs: BoundInputs,
    coding: CodingSnapshot,
    calculate: K,
    verify_after_reset: V,
    timeout: Duration,
    failed: bool,
}

impl<C: ControlChannel + DownloadTransport, K, V> N20Procedure<C, K, V>
where
    K: FnMut(&str, &[u8; 8]) -> Result<Vec<u8>, String>,
    V: FnMut() -> Result<(), String>,
{
    pub fn new(
        channel: C,
        inputs: BoundInputs,
        coding: CodingSnapshot,
        calculate: K,
        verify_after_reset: V,
        timeout: Duration,
    ) -> Result<Self, String> {
        if inputs.vin.len() != 17
            || !inputs
                .vin
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            || inputs.bootloader.is_empty()
            || inputs.software_token.len() != 14
            || !inputs.f101_reply.starts_with(&[0x62, 0xf1, 0x01])
            || inputs.f101_reply.len() <= 3
            || timeout.is_zero()
        {
            return Err("Incomplete operation identity or timing context".into());
        }
        coding.restore_requests(&inputs.vin)?;
        Ok(Self {
            channel,
            inputs,
            coding,
            calculate,
            verify_after_reset,
            timeout,
            failed: false,
        })
    }

    fn perform_inner(&mut self, stage: Stage, image: &PartialImage) -> Result<(), String> {
        let timeout = self.timeout;
        let map = |e: crate::n20_setup::Failure| {
            format!(
                "ECU 0x{:02X}, service 0x{:02X}: {}",
                e.target, e.request_sid, e.detail
            )
        };
        match stage {
            Stage::BindFreshIdentityAndValidateImage => {
                if image.software_token != self.inputs.software_token {
                    return Err("Selected BIN software differs from the bound operation".into());
                }
                let vin = checked(
                    &mut self.channel,
                    0x12,
                    &[0x22, 0xf1, 0x90],
                    &[0x62, 0xf1, 0x90],
                    timeout,
                )
                .map_err(map)?;
                if vin.get(3..) != Some(self.inputs.vin.as_bytes()) {
                    return Err("DME VIN changed before setup".into());
                }
                let identity = checked(
                    &mut self.channel,
                    0x12,
                    &[0x22, 0xf1, 1],
                    &[0x62, 0xf1, 1],
                    timeout,
                )
                .map_err(map)?;
                if identity != self.inputs.f101_reply {
                    return Err("DME fingerprint changed before setup".into());
                }
            }
            Stage::SetupAndAuthorize => {
                if self
                    .inputs
                    .setup_valid_until
                    .is_some_and(|until| Instant::now() >= until)
                {
                    return Err("Programming precondition proof expired before setup; fresh checks are required".into());
                }
                crate::n20_setup::run(
                    &mut self.channel,
                    &self.inputs.bootloader,
                    self.inputs.fingerprint_date,
                    self.inputs.prepare_auxiliary,
                    timeout,
                    &mut self.calculate,
                )
                .map_err(map)?;
            }
            Stage::IndexedErase => {
                // Both physical extent and this result must be profile-reviewed.
                let reply = checked(
                    &mut self.channel,
                    0x12,
                    &n20_partial::legacy_indexed_erase_request(),
                    &[0x71, 1, 0xff, 0],
                    timeout,
                )
                .map_err(map)?;
                require_routine_result(&reply, self.inputs.erase_success_result)?;
            }
            Stage::CheckMemory => {
                let reply = checked(
                    &mut self.channel,
                    0x12,
                    &n20_partial::legacy_check_memory_request(),
                    &[0x71, 1, 2, 2],
                    timeout,
                )
                .map_err(map)?;
                require_routine_result(&reply, 0)?;
            }
            Stage::ProgrammingDependencies => {
                let reply = checked(
                    &mut self.channel,
                    0x12,
                    &n20_partial::legacy_dependency_request(),
                    &[0x71, 1, 0xff, 1],
                    timeout,
                )
                .map_err(map)?;
                require_routine_result(&reply, 1)?;
            }
            Stage::WriteVin => {
                let mut request = vec![0x2e, 0xf1, 0x90];
                request.extend(self.inputs.vin.as_bytes());
                checked(
                    &mut self.channel,
                    0x12,
                    &request,
                    &[0x6e, 0xf1, 0x90],
                    timeout,
                )
                .map_err(map)?;
            }
            Stage::SessionCleanup => {
                for (request, prefix) in [
                    (&[0x10, 1][..], &[0x50, 1][..]),
                    (&[0x10, 3][..], &[0x50, 3][..]),
                    (&[0x31, 1, 0x0f, 0x0c, 0][..], &[0x71, 1, 0x0f, 0x0c][..]),
                ] {
                    checked(&mut self.channel, 0x12, request, prefix, timeout).map_err(map)?;
                }
            }
            Stage::CodingAndPostVerification => {
                crate::n20_restore::run(
                    &mut self.channel,
                    &self.coding,
                    &self.inputs.vin,
                    &self.inputs.bootloader,
                    timeout,
                    &mut self.calculate,
                )
                .map_err(map)?;
                // Reset acknowledgement or coding success cannot stand in for
                // a fresh ECU identity/integrity check on the restarted DME.
                (self.verify_after_reset)()?;
            }
            Stage::MainTransfer | Stage::TailTransfer => {
                return Err("Transfer stages belong to the download runner".into())
            }
        }
        Ok(())
    }
}

impl<C: ControlChannel + DownloadTransport, K, V> N20Procedure<C, K, V>
where
    K: FnMut(&str, &[u8; 8]) -> Result<Vec<u8>, String>,
    V: FnMut() -> Result<(), String>,
{
    fn perform_recovery_control(
        &mut self,
        stage: crate::n20_recovery::Stage,
        image: &crate::n20_recovery::RecoveryImage,
        review: &crate::n20_recovery::ReviewedRecovery,
    ) -> Result<(), String> {
        use crate::n20_recovery::Stage as R;
        if self.failed {
            return Err("Procedure already failed".into());
        }
        if self.inputs.erase_success_result != review.calibration_erase_result {
            self.failed = true;
            return Err("Calibration erase policy differs from the recovery review".into());
        }
        let control = match stage {
            R::EraseSoftware => Some((true, 0x803ffd00, review.software_erase_result)),
            R::CheckSoftware => Some((false, 0x803ffd00, 0)),
            _ => None,
        };
        if let Some((erase, address, result)) = control {
            let mut request = if erase {
                n20_partial::legacy_indexed_erase_request()
            } else {
                n20_partial::legacy_check_memory_request()
            };
            request[6..10].copy_from_slice(&u32::to_be_bytes(address));
            let prefix = if erase {
                [0x71, 1, 0xff, 0]
            } else {
                [0x71, 1, 2, 2]
            };
            let outcome = checked(&mut self.channel, 0x12, &request, &prefix, self.timeout)
                .map_err(|e| e.detail)
                .and_then(|reply| require_routine_result(&reply, result));
            if outcome.is_err() {
                self.failed = true;
            }
            return outcome;
        }
        let partial = match stage {
            R::BindFreshIdentity => Stage::BindFreshIdentityAndValidateImage,
            R::Setup => Stage::SetupAndAuthorize,
            R::EraseCalibration => Stage::IndexedErase,
            R::CheckCalibration => Stage::CheckMemory,
            R::Dependencies => Stage::ProgrammingDependencies,
            R::WriteVin => Stage::WriteVin,
            R::Cleanup => Stage::SessionCleanup,
            R::CodingAndVerification => Stage::CodingAndPostVerification,
            _ => return Err("Recovery transfer belongs to the download runner".into()),
        };
        self.perform(partial, image.partial())
    }
}

/// Separate adapter requires a six-region readback provider, in addition to
/// the inner fresh identity/coding verifier. Partial completion cannot suffice.
pub(crate) struct N20RecoveryProcedure<C, K, V, R> {
    inner: N20Procedure<C, K, V>,
    readback: R,
}
impl<C, K, V, R> N20RecoveryProcedure<C, K, V, R> {
    pub(crate) fn new(inner: N20Procedure<C, K, V>, readback: R) -> Self {
        Self { inner, readback }
    }
}
impl<C: DownloadTransport, K, V, R> DownloadTransport for N20RecoveryProcedure<C, K, V, R> {
    fn send(&mut self, bytes: &[u8], deadline: Instant) -> Result<(), String> {
        self.inner.send(bytes, deadline)
    }
    fn receive(&mut self, deadline: Instant) -> Result<Vec<u8>, String> {
        self.inner.receive(deadline)
    }
}
impl<C: ControlChannel + DownloadTransport, K, V, R> crate::n20_recovery::Procedure
    for N20RecoveryProcedure<C, K, V, R>
where
    K: FnMut(&str, &[u8; 8]) -> Result<Vec<u8>, String>,
    V: FnMut() -> Result<(), String>,
    R: FnMut() -> Result<[Vec<u8>; 6], String>,
{
    fn perform_recovery(
        &mut self,
        stage: crate::n20_recovery::Stage,
        image: &crate::n20_recovery::RecoveryImage,
        review: &crate::n20_recovery::ReviewedRecovery,
    ) -> Result<(), String> {
        self.inner.perform_recovery_control(stage, image, review)
    }
    fn readback_recovery(&mut self) -> Result<[Vec<u8>; 6], String> {
        (self.readback)()
    }
}

// In the agent model dd includes two route bytes; dd[6] is UDS offset 4.
fn require_routine_result(reply: &[u8], accepted: u8) -> Result<(), String> {
    // jh requires exactly seven routed bytes through fm.a(dd,gk,7):
    // four raw UDS prefix bytes and one result. Do not ignore extra records.
    // This is source-established for erase/CheckMemory. The dependency
    // descriptor is looser; support only its modeled single-result format.
    if reply.len() != 5 {
        return Err("Routine response must contain exactly one result byte".into());
    }
    match reply.get(4) {
        Some(value) if *value == accepted => Ok(()),
        Some(value) => Err(format!("ECU routine rejected data (result {value:02X})")),
        None => Err("Routine response omitted its result byte".into()),
    }
}

impl<C: ControlChannel + DownloadTransport, K, V> Procedure for N20Procedure<C, K, V>
where
    K: FnMut(&str, &[u8; 8]) -> Result<Vec<u8>, String>,
    V: FnMut() -> Result<(), String>,
{
    fn perform(&mut self, stage: Stage, image: &PartialImage) -> Result<(), String> {
        if self.failed {
            return Err("Procedure already failed".into());
        }
        let result = self.perform_inner(stage, image);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

impl<C: DownloadTransport, K, V> DownloadTransport for N20Procedure<C, K, V> {
    fn send(&mut self, bytes: &[u8], deadline: Instant) -> Result<(), String> {
        if self.failed {
            return Err("Procedure already failed".into());
        }
        let result = self.channel.send(bytes, deadline);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn receive(&mut self, deadline: Instant) -> Result<Vec<u8>, String> {
        if self.failed {
            return Err("Procedure already failed".into());
        }
        let result = self.channel.receive(deadline);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n20_partial::{StageJournal, STAGES};
    use crate::uds_download::{ExchangeJournal, ExchangeRecord};
    use crate::vehicle_access::VehicleAccess;
    use std::collections::VecDeque;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    const VIN: &str = "WBA3A52010F360747";
    #[derive(Default)]
    struct Channel {
        sent: Vec<Vec<u8>>,
        replies: VecDeque<Vec<u8>>,
        bad_memory: bool,
        wrong_identity: bool,
        erase_reply: Option<Vec<u8>>,
        lose_download: bool,
    }
    impl ControlChannel for Channel {
        fn exchange(&mut self, _: u8, r: &[u8], _: Duration) -> Result<Vec<u8>, String> {
            self.sent.push(r.to_vec());
            Ok(match r {
                [0x10, s] => vec![0x50, *s, 0, 50, 1, 244],
                [0x22, 0xf1, 0x90] => [vec![0x62, 0xf1, 0x90], VIN.as_bytes().to_vec()].concat(),
                [0x22, 0xf1, 1] => vec![0x62, 0xf1, 1, if self.wrong_identity { 9 } else { 1 }],
                [0x22, 0x25, 0x04] => vec![0x62, 0x25, 0x04, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5],
                [0x22, hi, lo] => vec![0x62, *hi, *lo, 1, 2, 3, 4],
                [0x27, level, ..] if level % 2 == 1 => [vec![0x67, *level], vec![7; 8]].concat(),
                [0x27, level, ..] => vec![0x67, *level],
                [0x85, s] => vec![0xc5, *s],
                [0x28, s, ..] => vec![0x68, *s],
                [0x31, 1, 2, 2, ..] => vec![0x71, 1, 2, 2, u8::from(self.bad_memory)],
                [0x31, 1, 0xff, 0, ..] => self
                    .erase_reply
                    .clone()
                    .unwrap_or_else(|| vec![0x71, 1, 0xff, 0, 0]),
                [0x31, 1, 0xff, 1] => vec![0x71, 1, 0xff, 1, 1],
                [0x31, s, hi, lo, ..] => vec![0x71, *s, *hi, *lo, 0],
                [0x2e, hi, lo, ..] => vec![0x6e, *hi, *lo],
                [0x11, 1] => vec![0x51, 1],
                _ => panic!("Unexpected control request"),
            })
        }
    }
    impl DownloadTransport for Channel {
        fn send(&mut self, r: &[u8], _: Instant) -> Result<(), String> {
            self.sent.push(r.to_vec());
            self.replies.push_back(match r {
                [0x34, ..] => vec![0x74, 0x20, 0x0f, 0xfe],
                [0x36, c, ..] => vec![0x76, *c],
                [0x37] => vec![0x77],
                _ => panic!("Unexpected download request"),
            });
            Ok(())
        }
        fn receive(&mut self, _: Instant) -> Result<Vec<u8>, String> {
            if self.lose_download {
                return Err("Lost download reply".into());
            }
            self.replies.pop_front().ok_or("Missing response".into())
        }
    }
    #[derive(Default)]
    struct Stages(Vec<(Stage, bool)>);
    impl StageJournal for Stages {
        fn record(&mut self, s: Stage, c: bool, _: &str) -> Result<(), String> {
            self.0.push((s, c));
            Ok(())
        }
    }
    struct Log;
    impl ExchangeJournal for Log {
        fn append(&mut self, _: ExchangeRecord) -> Result<(), String> {
            Ok(())
        }
    }
    fn image() -> PartialImage {
        use sha2::{Digest, Sha256};
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
        b[0x1ffd00] = 8;
        b[0x1ffd01..0x1ffd08].copy_from_slice(&[0, 0, 0x1c, 0xdb, 0x1d, 0x96, 7]);
        let hash = format!("{:x}", Sha256::digest(&b));
        PartialImage::from_bin(b, &hash).unwrap()
    }
    fn inputs() -> BoundInputs {
        BoundInputs {
            vin: VIN.into(),
            bootloader: "LIVE".into(),
            software_token: "00001C9F1D9601".into(),
            f101_reply: vec![0x62, 0xf1, 1, 1],
            fingerprint_date: [0x26, 0x11, 2],
            prepare_auxiliary: true,
            erase_success_result: 0, // Synthetic test channel only.
            setup_valid_until: None,
        }
    }
    fn snapshot() -> CodingSnapshot {
        CodingSnapshot::read(&mut Channel::default(), VIN, Duration::from_secs(1)).unwrap()
    }

    #[derive(Default)]
    struct RecoveryStages(Vec<(crate::n20_recovery::Stage, bool)>);
    impl crate::n20_recovery::StageJournal for RecoveryStages {
        fn record(
            &mut self,
            s: crate::n20_recovery::Stage,
            c: bool,
            _: &str,
        ) -> Result<(), String> {
            self.0.push((s, c));
            Ok(())
        }
    }
    fn exercise_recovery(
        channel: Channel,
        bad_readback: bool,
        bad_approval: bool,
    ) -> (
        Result<(), crate::n20_recovery::Failure>,
        Vec<Vec<u8>>,
        RecoveryStages,
    ) {
        let image = crate::n20_recovery::RecoveryImage::synthetic(image());
        let readback: [Vec<u8>; 6] = std::array::from_fn(|i| {
            let r = crate::n20_recovery::REGIONS[i];
            let mut bytes = image.partial().bytes()[r.start..r.start + r.length].to_vec();
            if bad_readback && i == 0 {
                bytes[0] ^= 1;
            }
            bytes
        });
        let review = crate::n20_recovery::ReviewedRecovery {
            image_sha256: if bad_approval {
                "wrong".into()
            } else {
                image.partial().sha256.clone()
            },
            evidence_id: "synthetic-full-rewrite-only".into(),
            software_erase_result: 0,
            calibration_erase_result: 0,
        };
        let inner = N20Procedure::new(
            channel,
            inputs(),
            snapshot(),
            |_: &str, _: &[u8; 8]| Ok(vec![9; 16]),
            || Ok(()),
            Duration::from_secs(1),
        )
        .unwrap();
        let mut procedure = N20RecoveryProcedure::new(inner, move || Ok(readback.clone()));
        let access = VehicleAccess::default();
        let lease = access.programming().unwrap();
        let mut stages = RecoveryStages::default();
        let result = crate::n20_recovery::run_owned(
            &lease,
            &mut procedure,
            image,
            &review,
            &mut stages,
            &mut [Log, Log, Log, Log, Log, Log],
            Duration::from_secs(1),
        );
        (result, procedure.inner.channel.sent, stages)
    }
    #[test]
    fn recovery_writes_all_six_regions_without_startup_and_requires_readback() {
        let (result, sent, stages) = exercise_recovery(Channel::default(), false, false);
        result.unwrap();
        let addresses: Vec<u32> = sent
            .iter()
            .filter(|r| r[0] == 0x34)
            .map(|r| u32::from_be_bytes(r[3..7].try_into().unwrap()))
            .collect();
        assert_eq!(addresses, crate::n20_recovery::REGIONS.map(|r| r.address()));
        assert!(!addresses.contains(&0x80000000));
        assert_eq!(
            sent.iter()
                .filter(|r| r[0] == 0x36)
                .map(|r| r.len() - 2)
                .sum::<usize>(),
            crate::n20_recovery::REGIONS
                .iter()
                .map(|r| r.length)
                .sum::<usize>()
        );
        assert_eq!(stages.0.len(), 32);
        assert!(sent
            .iter()
            .any(|r| r == &[0x31, 1, 2, 2, 0x12, 0x40, 0x80, 0x3f, 0xfd, 0, 0, 0]));
    }
    #[test]
    fn partial_readback_success_cannot_hide_a_recovery_software_mismatch() {
        let (result, _, stages) = exercise_recovery(Channel::default(), true, false);
        let error = result.unwrap_err();
        assert!(error.ecu_state_may_have_changed);
        assert!(error.detail.contains("software main 1"));
        assert_eq!(
            stages.0.last(),
            Some(&(crate::n20_recovery::Stage::CodingAndVerification, false))
        );
    }
    #[test]
    fn recovery_software_check_failure_never_erases_calibration_or_resets() {
        let (result, sent, _) = exercise_recovery(
            Channel {
                bad_memory: true,
                ..Default::default()
            },
            false,
            false,
        );
        assert_eq!(
            result.unwrap_err().stage,
            crate::n20_recovery::Stage::CheckSoftware
        );
        assert!(!sent
            .iter()
            .any(|r| r == &n20_partial::legacy_indexed_erase_request() || r[0] == 0x11));
    }
    #[test]
    fn recovery_does_not_retry_lost_download_or_accept_wrong_image_approval() {
        let (result, sent, _) = exercise_recovery(
            Channel {
                lose_download: true,
                ..Default::default()
            },
            false,
            false,
        );
        assert_eq!(
            result.unwrap_err().stage,
            crate::n20_recovery::Stage::SoftwareMain1
        );
        assert_eq!(sent.iter().filter(|r| r[0] == 0x34).count(), 1);
        assert!(!sent.iter().any(|r| r[0] == 0x36 || r[0] == 0x11));
        let (result, sent, _) = exercise_recovery(Channel::default(), false, true);
        assert!(!result.unwrap_err().ecu_state_may_have_changed);
        assert!(sent.is_empty());
    }

    #[test]
    fn expired_gate_proof_prevents_even_first_setup_request() {
        let mut inputs = inputs();
        inputs.setup_valid_until = Some(Instant::now() - Duration::from_secs(1));
        let mut procedure = N20Procedure::new(
            Channel::default(),
            inputs,
            snapshot(),
            |_: &str, _: &[u8; 8]| panic!("No authorization after stale gate"),
            || Ok(()),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(procedure
            .perform(Stage::SetupAndAuthorize, &image())
            .unwrap_err()
            .contains("expired"));
        assert!(procedure.channel.sent.is_empty());
        assert!(procedure.perform(Stage::IndexedErase, &image()).is_err());
    }

    #[test]
    fn complete_partial_workflow_reaches_success_only_after_restore_and_verification() {
        let calls = Arc::new(AtomicUsize::new(0));
        let verified = calls.clone();
        let mut procedure = N20Procedure::new(
            Channel::default(),
            inputs(),
            snapshot(),
            |_: &str, _: &[u8; 8]| Ok(vec![9; 16]),
            move || {
                verified.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            Duration::from_secs(1),
        )
        .unwrap();
        let mut stages = Stages::default();
        n20_partial::run(
            &VehicleAccess::default(),
            &mut procedure,
            image(),
            &mut stages,
            &mut Log,
            &mut Log,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(stages.0.len(), STAGES.len() * 2);
        assert_eq!(procedure.channel.sent.last(), Some(&vec![0x11, 1]));
        let requests = &procedure.channel.sent;
        assert_eq!(requests.iter().filter(|r| r[0] == 0x34).count(), 2);
        assert_eq!(
            requests
                .iter()
                .filter(|r| r[0] == 0x36)
                .map(|r| r.len() - 2)
                .sum::<usize>(),
            524_032
        );
    }
    #[test]
    fn truncated_or_unapproved_erase_result_stops_before_any_download() {
        for reply in [
            vec![0x71, 1, 0xff, 0],
            vec![0x71, 1, 0xff, 0, 7],
            vec![0x71, 1, 0xff, 0, 0, 7],
        ] {
            let mut procedure = N20Procedure::new(
                Channel {
                    erase_reply: Some(reply),
                    ..Default::default()
                },
                inputs(),
                snapshot(),
                |_: &str, _: &[u8; 8]| Ok(vec![9; 16]),
                || panic!("Must not verify a rejected erase"),
                Duration::from_secs(1),
            )
            .unwrap();
            let failure = n20_partial::run(
                &VehicleAccess::default(),
                &mut procedure,
                image(),
                &mut Stages::default(),
                &mut Log,
                &mut Log,
                Duration::from_secs(1),
            )
            .unwrap_err();
            assert_eq!(failure.stage, Stage::IndexedErase);
            assert!(failure.ecu_state_may_have_changed);
            assert!(!procedure
                .channel
                .sent
                .iter()
                .any(|r| matches!(r[0], 0x34 | 0x36 | 0x37 | 0x11)));
            assert!(procedure.perform(Stage::WriteVin, &image()).is_err());
        }
    }

    #[test]
    fn check_memory_failure_never_reaches_vin_restore_reset_or_verification() {
        let mut procedure = N20Procedure::new(
            Channel {
                bad_memory: true,
                ..Default::default()
            },
            inputs(),
            snapshot(),
            |_: &str, _: &[u8; 8]| Ok(vec![9; 16]),
            || panic!("Must not verify a failed write"),
            Duration::from_secs(1),
        )
        .unwrap();
        let error = n20_partial::run(
            &VehicleAccess::default(),
            &mut procedure,
            image(),
            &mut Stages::default(),
            &mut Log,
            &mut Log,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(error.stage, Stage::CheckMemory);
        assert!(!procedure
            .channel
            .sent
            .iter()
            .any(|r| r.starts_with(&[0x2e, 0xf1, 0x90]) || r[0] == 0x11));
        assert!(procedure.perform(Stage::WriteVin, &image()).is_err());
    }
    #[test]
    fn failed_post_reset_verification_cannot_record_complete() {
        let mut procedure = N20Procedure::new(
            Channel::default(),
            inputs(),
            snapshot(),
            |_: &str, _: &[u8; 8]| Ok(vec![9; 16]),
            || Err("Fresh fingerprint mismatch".into()),
            Duration::from_secs(1),
        )
        .unwrap();
        let mut stages = Stages::default();
        let error = n20_partial::run(
            &VehicleAccess::default(),
            &mut procedure,
            image(),
            &mut stages,
            &mut Log,
            &mut Log,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(error.stage, Stage::CodingAndPostVerification);
        assert_eq!(
            stages.0.last(),
            Some(&(Stage::CodingAndPostVerification, false))
        );
    }
    #[test]
    fn fingerprint_change_stops_before_setup_or_download() {
        let mut procedure = N20Procedure::new(
            Channel {
                wrong_identity: true,
                ..Default::default()
            },
            inputs(),
            snapshot(),
            |_: &str, _: &[u8; 8]| panic!("Must not calculate"),
            || panic!("Must not verify"),
            Duration::from_secs(1),
        )
        .unwrap();
        let error = n20_partial::run(
            &VehicleAccess::default(),
            &mut procedure,
            image(),
            &mut Stages::default(),
            &mut Log,
            &mut Log,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(error.stage, Stage::BindFreshIdentityAndValidateImage);
        assert_eq!(procedure.channel.sent.len(), 2);
    }
    #[test]
    fn routine_result_uses_uds_offset_four_not_telegram_offset_six() {
        assert!(require_routine_result(&[0x71, 1, 2, 2, 0], 0).is_ok());
        assert!(require_routine_result(&[0x71, 1, 0xff, 1, 1], 1).is_ok());
        assert!(require_routine_result(&[0x71, 1, 2, 2, 1, 0, 0], 0).is_err());
        assert!(require_routine_result(&[0x71, 1, 2, 2], 0).is_err());
    }
    #[test]
    fn routine_results_reject_trailing_records_even_after_an_accepted_value() {
        for (prefix, accepted) in [
            ([0x71, 1, 0xff, 0], 0),
            ([0x71, 1, 2, 2], 0),
            ([0x71, 1, 0xff, 1], 1),
        ] {
            for trailing in [vec![0], vec![0xff], vec![0, 1, 2]] {
                let reply = [prefix.to_vec(), vec![accepted], trailing].concat();
                assert!(require_routine_result(&reply, accepted).is_err());
            }
        }
    }
}

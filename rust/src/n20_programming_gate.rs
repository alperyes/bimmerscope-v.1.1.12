//! Mandatory reviewed ignition/precondition gate, separate from observations.
//! No wake-up command, type switching, permissive NRC fallback or auto flash.
use crate::n20_setup::ControlChannel;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
#[derive(Clone, Copy)]
pub(crate) struct Policy {
    pub ignition_evidence_id: &'static str,
    pub condition_evidence_id: &'static str,
    pub query_non_mutating_verified: bool,
    pub empty_positive_verified_clear: bool,
    pub valid_for_ms: u64,
}
impl Policy {
    pub fn validate(self) -> Result<(), String> {
        if self.ignition_evidence_id.trim().is_empty()
            || self.condition_evidence_id.trim().is_empty()
            || !self.query_non_mutating_verified
            || !self.empty_positive_verified_clear
            || !(1000..=30000).contains(&self.valid_for_ms)
        {
            return Err(
                "Ignition/condition gate lacks reviewed exact-DME semantics or freshness policy"
                    .into(),
            );
        }
        Ok(())
    }
}
pub(crate) struct Proof {
    pub report: Value,
    pub valid_until: Instant,
}
pub(crate) struct Failure {
    pub detail: String,
    pub outcome_unknown: bool,
    pub report: Value,
}
/// Gateway value 1 is the exact historical gate. Empty CPPC is accepted only
/// when independently reviewed for this profile; no condition code is whitelisted.
pub(crate) fn run(
    channel: &mut impl ControlChannel,
    policy: Policy,
    timeout: Duration,
    mut gateway: impl FnMut() -> Result<Vec<u8>, String>,
    mut pause: impl FnMut(Duration),
) -> Result<Proof, Failure> {
    let mut report = json!({"schema":"n20-enforced-programming-gate-v1","ignition_evidence":policy.ignition_evidence_id,
        "condition_evidence":policy.condition_evidence_id,"gateway_attempts":[],"wake_command_sent":false,
        "conditions":null,"passed":false,"gate_alone_authorizes_programming":false,"valid_for_ms":policy.valid_for_ms});
    let failure = |detail: String, unknown: bool, report: Value| Failure {
        detail,
        outcome_unknown: unknown,
        report,
    };
    policy
        .validate()
        .map_err(|e| failure(e, false, report.clone()))?;
    if timeout.is_zero() {
        return Err(failure("Invalid gate timeout".into(), false, report));
    }
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02X}")).collect::<String>();
    let mut matched = false;
    let mut gateway_checked_at = None;
    for attempt in 0..2 {
        if attempt == 1 {
            pause(Duration::from_secs(3));
        }
        let result = gateway().and_then(|frame| {
            crate::n20_preflight::gateway_status(&frame).map(|status| (frame, status))
        });
        let entry = match result {
            Ok((frame, status)) => {
                matched = status == 1;
                if matched {
                    gateway_checked_at = Some(Instant::now());
                }
                json!({"response":hex(&frame),"raw_status":status,"matches_required_value":matched})
            }
            Err(detail) => json!({"unavailable":detail,"matches_required_value":false}),
        };
        report["gateway_attempts"]
            .as_array_mut()
            .unwrap()
            .push(entry);
        if matched {
            break;
        }
    }
    if !matched {
        return Err(failure("Gateway ignition/status gate did not pass after a fresh recheck; unavailable data is not an ignition-off diagnosis".into(),false,report));
    }
    let reply = channel
        .exchange(0x12, &[0x31, 1, 2, 3], timeout)
        .map_err(|e| {
            failure(
                format!("Programming-condition outcome is uncertain: {e}"),
                true,
                report.clone(),
            )
        })?;
    let decoded =
        crate::n20_preflight::conditions(&reply).map_err(|e| failure(e, true, report.clone()))?;
    report["conditions"] = decoded;
    if reply != [0x71, 1, 2, 3] {
        return Err(failure("Programming-condition gate blocked: ECU reported conditions or rejected the routine; inspect the saved raw response".into(),false,report));
    }
    let valid_until = gateway_checked_at
        .ok_or_else(|| {
            failure(
                "Gateway check timestamp is missing".into(),
                false,
                report.clone(),
            )
        })?
        .checked_add(Duration::from_millis(policy.valid_for_ms))
        .ok_or_else(|| {
            failure(
                "Gate freshness deadline overflow".into(),
                false,
                report.clone(),
            )
        })?;
    if Instant::now() >= valid_until {
        return Err(failure(
            "Gateway result expired during the condition query; fresh checks are required".into(),
            false,
            report,
        ));
    }
    report["passed"] = json!(true);
    Ok(Proof {
        report,
        valid_until,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Channel {
        reply: Result<Vec<u8>, String>,
        calls: usize,
    }
    impl ControlChannel for Channel {
        fn exchange(&mut self, target: u8, request: &[u8], _: Duration) -> Result<Vec<u8>, String> {
            assert_eq!(target, 0x12);
            assert_eq!(request, [0x31, 1, 2, 3]);
            self.calls += 1;
            self.reply.clone()
        }
    }
    fn policy() -> Policy {
        Policy {
            ignition_evidence_id: "test",
            condition_evidence_id: "test",
            query_non_mutating_verified: true,
            empty_positive_verified_clear: true,
            valid_for_ms: 10000,
        }
    }
    fn frame(status: u8) -> Vec<u8> {
        vec![0, 0, 0, 1, 0, 0x10, status << 2]
    }
    #[test]
    fn unavailable_or_nonmatching_gateway_stops_before_routine() {
        for result in [
            Err("offline".into()),
            Ok(frame(0)),
            Ok(frame(2)),
            Ok(frame(3)),
            Ok(vec![0; 2]),
        ] {
            let mut channel = Channel {
                reply: Ok(vec![0x71, 1, 2, 3]),
                calls: 0,
            };
            let mut waits = 0;
            let error = run(
                &mut channel,
                policy(),
                Duration::from_secs(1),
                || result.clone(),
                |d| {
                    assert_eq!(d, Duration::from_secs(3));
                    waits += 1;
                },
            )
            .err()
            .unwrap();
            assert!(!error.outcome_unknown);
            assert_eq!(channel.calls, 0);
            assert_eq!(waits, 1);
            assert_eq!(error.report["passed"], false);
        }
    }
    #[test]
    fn recheck_and_verified_empty_response_produce_fresh_proof_without_wake() {
        let mut responses = std::collections::VecDeque::from([Ok(frame(0)), Ok(frame(1))]);
        let mut channel = Channel {
            reply: Ok(vec![0x71, 1, 2, 3]),
            calls: 0,
        };
        let proof = run(
            &mut channel,
            policy(),
            Duration::from_secs(1),
            || responses.pop_front().unwrap(),
            |_| {},
        )
        .ok()
        .unwrap();
        assert!(proof.valid_until > Instant::now());
        assert_eq!(
            proof.report["gateway_attempts"].as_array().unwrap().len(),
            2
        );
        assert_eq!(proof.report["wake_command_sent"], false);
        assert_eq!(channel.calls, 1);
    }
    #[test]
    fn all_condition_codes_nrc_and_uncertain_outcomes_block() {
        for reply in [
            vec![0x71, 1, 2, 3, 1],
            vec![0x71, 1, 2, 3, 0],
            vec![0x71, 1, 2, 3, 255],
            vec![0x7f, 0x31, 0x22],
        ] {
            let mut channel = Channel {
                reply: Ok(reply),
                calls: 0,
            };
            let result = run(
                &mut channel,
                policy(),
                Duration::from_secs(1),
                || Ok(frame(1)),
                |_| {},
            );
            assert!(!result.err().unwrap().outcome_unknown);
            assert_eq!(channel.calls, 1);
        }
        for reply in [Err("timeout".into()), Ok(vec![0x71, 1, 2, 6])] {
            let mut channel = Channel { reply, calls: 0 };
            assert!(
                run(
                    &mut channel,
                    policy(),
                    Duration::from_secs(1),
                    || Ok(frame(1)),
                    |_| {}
                )
                .err()
                .unwrap()
                .outcome_unknown
            );
        }
    }
    #[test]
    fn slow_condition_reply_does_not_refresh_an_old_gateway_check() {
        struct Slow;
        impl ControlChannel for Slow {
            fn exchange(&mut self, _: u8, _: &[u8], _: Duration) -> Result<Vec<u8>, String> {
                std::thread::sleep(Duration::from_millis(1100));
                Ok(vec![0x71, 1, 2, 3])
            }
        }
        let mut p = policy();
        p.valid_for_ms = 1000;
        let failure = run(
            &mut Slow,
            p,
            Duration::from_secs(2),
            || Ok(frame(1)),
            |_| {},
        )
        .err()
        .unwrap();
        assert!(!failure.outcome_unknown);
        assert!(failure.detail.contains("expired"));
        assert_eq!(failure.report["passed"], false);
    }
    #[test]
    fn observation_or_unreviewed_empty_response_cannot_authorize_gate() {
        let mut policy = policy();
        policy.empty_positive_verified_clear = false;
        let mut channel = Channel {
            reply: Ok(vec![0x71, 1, 2, 3]),
            calls: 0,
        };
        assert!(run(
            &mut channel,
            policy,
            Duration::from_secs(1),
            || panic!("Must not query with unreviewed policy"),
            |_| {}
        )
        .is_err());
        assert_eq!(channel.calls, 0);
    }
}

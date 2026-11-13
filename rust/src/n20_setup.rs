//! Protocol-level implementation of FlashHandler's generic P/PF setup.
//! No socket adapter or key material is supplied here. Its caller must bind
//! identity, exclusive ownership, power and a durable coding backup first.
#![allow(dead_code)]

use std::time::Duration;

/// One owned connection throughout setup and the later transfer. Implementors
/// must durably record intent before sending, correlate the physical route,
/// consume response-pending under an absolute deadline, and return a final
/// reply only. A timeout must not silently reconnect, retry, or reset the ECU.
pub(crate) trait ControlChannel {
    fn exchange(
        &mut self,
        target: u8,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String>;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub target: u8,
    pub request_sid: u8,
    pub detail: String,
}

pub(crate) fn checked(
    channel: &mut impl ControlChannel,
    target: u8,
    request: &[u8],
    prefix: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, Failure> {
    let fail = |detail| Failure {
        target,
        request_sid: request[0],
        detail,
    };
    let reply = channel.exchange(target, request, timeout).map_err(fail)?;
    if reply.starts_with(&[0x7f, request[0]]) {
        return Err(fail(if reply.len() == 3 {
            format!(
                "ECU rejected request or pending was not resolved (NRC {:02X})",
                reply[2]
            )
        } else {
            "Malformed negative response".into()
        }));
    }
    if !reply.starts_with(prefix) {
        return Err(fail(
            "Positive response does not match the requested operation".into(),
        ));
    }
    if request[0] == 0x10 {
        crate::n20_session_timing::parse(&reply, request[1]).map_err(fail)?;
    }
    Ok(reply)
}

fn preamble(
    channel: &mut impl ControlChannel,
    target: u8,
    timeout: Duration,
) -> Result<(), Failure> {
    checked(channel, target, &[0x10, 1], &[0x50, 1], timeout)?;
    preamble_after_default(channel, target, timeout)
}

fn preamble_after_default(
    channel: &mut impl ControlChannel,
    target: u8,
    timeout: Duration,
) -> Result<(), Failure> {
    for (request, prefix) in [
        (&[0x10, 3][..], &[0x50, 3][..]),
        (&[0x31, 1, 0x0f, 0x0c, 3][..], &[0x71, 1, 0x0f, 0x0c][..]),
        (&[0x85, 2][..], &[0xc5, 2][..]),
        (&[0x28, 1, 1][..], &[0x68, 1][..]),
        (&[0x31, 1, 0x10, 3, 1][..], &[0x71, 1, 0x10, 3][..]),
    ] {
        checked(channel, target, request, prefix, timeout)?;
    }
    Ok(())
}

/// Explicit date from the VIN-bound coding/vehicle record, as in `ia`/`kw`.
/// Do not replace it with today's date (the EGS path uses different semantics).
pub(crate) fn fingerprint_request(date: [u8; 3]) -> Vec<u8> {
    let mut bytes = vec![0x2e, 0xf1, 0x5a];
    bytes.extend(date);
    bytes.extend([0x8f, 4, 0xd2, 1, 0, 0, 0x10, 0, 0, 0]);
    bytes
}

/// Mirrors the auxiliary-0x17 then selected-0x12 preambles, programming
/// session, seed/key and fingerprint. Callback can bridge the existing SK
/// calculator; a key from another seed/connection is never accepted as input.
/// Protocol acknowledgements alone do not approve the later erase operation.
pub(crate) fn run(
    channel: &mut impl ControlChannel,
    bootloader: &str,
    fingerprint_date: [u8; 3],
    prepare_auxiliary: bool,
    timeout: Duration,
    mut calculate: impl FnMut(&str, &[u8; 8]) -> Result<Vec<u8>, String>,
) -> Result<(), Failure> {
    let fail = |target, sid, detail| Failure {
        target,
        request_sid: sid,
        detail,
    };
    if timeout.is_zero() || bootloader.trim().is_empty() {
        return Err(fail(
            0x12,
            0x10,
            "Missing setup limits or live bootloader identity".into(),
        ));
    }
    // In the old o(0x17), a negative default-session reply skips this auxiliary
    // preamble. Preserve that branch, but never swallow transport uncertainty.
    if prepare_auxiliary {
        let auxiliary = channel
            .exchange(0x17, &[0x10, 1], timeout)
            .map_err(|e| fail(0x17, 0x10, e))?;
        if auxiliary.len() == 3 && auxiliary[..2] == [0x7f, 0x10] && auxiliary[2] != 0x78 {
            // No more requests to 0x17 for this branch.
        } else if auxiliary.starts_with(&[0x50, 1]) && auxiliary.len() >= 6 {
            preamble_after_default(channel, 0x17, timeout)?;
        } else {
            return Err(fail(
                0x17,
                0x10,
                "Unresolved or malformed auxiliary session response".into(),
            ));
        }
    }
    preamble(channel, 0x12, timeout)?;
    checked(channel, 0x12, &[0x10, 2], &[0x50, 2], timeout)?;
    authorize_level(channel, bootloader, 0x11, timeout, &mut calculate)?;
    checked(
        channel,
        0x12,
        &fingerprint_request(fingerprint_date),
        &[0x6e, 0xf1, 0x5a],
        timeout,
    )?;
    Ok(())
}

/// Shared calculator protocol for the distinct flash (11/12) and coding
/// (01/02) levels. The caller owns the required session and fresh identity.
pub(crate) fn authorize_level(
    channel: &mut impl ControlChannel,
    bootloader: &str,
    level: u8,
    timeout: Duration,
    mut calculate: impl FnMut(&str, &[u8; 8]) -> Result<Vec<u8>, String>,
) -> Result<(), Failure> {
    let fail = |target, sid, detail| Failure {
        target,
        request_sid: sid,
        detail,
    };
    if !matches!(level, 1 | 0x11) || bootloader.trim().is_empty() || timeout.is_zero() {
        return Err(fail(0x12, 0x27, "Unsupported authorization context".into()));
    }
    let reply = checked(
        channel,
        0x12,
        &[0x27, level, 0xff, 0xff, 0xff, 0xff],
        &[0x67, level],
        timeout,
    )?;
    let seed: [u8; 8] = reply
        .get(2..)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| fail(0x12, 0x27, "Expected exactly eight challenge bytes".into()))?;
    let key = calculate(bootloader, &seed).map_err(|e| fail(0x12, 0x27, e))?;
    if key.is_empty() || key.len() > 4092 {
        return Err(fail(
            0x12,
            0x27,
            "Invalid calculated response length".into(),
        ));
    }
    let mut request = vec![0x27, level + 1];
    request.extend(key);
    let reply = checked(channel, 0x12, &request, &[0x67, level + 1], timeout)?;
    if reply.len() != 2 {
        return Err(fail(
            0x12,
            0x27,
            "Unexpected security confirmation data".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Channel {
        sent: Vec<(u8, Vec<u8>)>,
        fail_at: Option<usize>,
        skip_auxiliary: bool,
        short_seed: bool,
    }
    impl ControlChannel for Channel {
        fn exchange(&mut self, target: u8, request: &[u8], _: Duration) -> Result<Vec<u8>, String> {
            let index = self.sent.len();
            self.sent.push((target, request.to_vec()));
            if self.fail_at == Some(index) {
                return Ok(vec![0x7f, request[0], 0x22]);
            }
            if target == 0x17 && request == [0x10, 1] && self.skip_auxiliary {
                return Ok(vec![0x7f, 0x10, 0x12]);
            }
            Ok(match request {
                [0x10, session] => vec![0x50, *session, 0, 50, 1, 244],
                [0x31, sub, hi, lo, ..] => vec![0x71, *sub, *hi, *lo],
                [0x85, sub] => vec![0xc5, *sub],
                [0x28, sub, ..] => vec![0x68, *sub],
                [0x27, 0x11, ..] => {
                    let mut v = vec![0x67, 0x11];
                    v.extend(if self.short_seed {
                        vec![7; 7]
                    } else {
                        vec![7; 8]
                    });
                    v
                }
                [0x27, 0x12, ..] => vec![0x67, 0x12],
                [0x2e, hi, lo, ..] => vec![0x6e, *hi, *lo],
                _ => panic!("Unexpected request"),
            })
        }
    }
    fn setup(channel: &mut Channel) -> Result<(), Failure> {
        run(
            channel,
            "LIVE-BTLD",
            [0x26, 0x11, 2],
            true,
            Duration::from_secs(1),
            |btld, seed| {
                assert_eq!(btld, "LIVE-BTLD");
                assert_eq!(seed, &[7; 8]);
                Ok(vec![9; 16])
            },
        )
    }
    #[test]
    fn follows_auxiliary_dme_programming_security_and_fingerprint_order() {
        let mut channel = Channel::default();
        setup(&mut channel).unwrap();
        assert_eq!(channel.sent.len(), 16);
        assert!(channel.sent[..6].iter().all(|(target, _)| *target == 0x17));
        assert!(channel.sent[6..].iter().all(|(target, _)| *target == 0x12));
        assert_eq!(channel.sent[12].1, [0x10, 2]);
        assert_eq!(channel.sent[13].1, [0x27, 0x11, 255, 255, 255, 255]);
        assert_eq!(&channel.sent[14].1[..2], &[0x27, 0x12]);
        assert_eq!(channel.sent[15].1, fingerprint_request([0x26, 0x11, 2]));
        assert_eq!(channel.sent[15].1.len(), 16);
    }
    #[test]
    fn preserves_auxiliary_default_session_rejection_branch() {
        let mut channel = Channel {
            skip_auxiliary: true,
            ..Default::default()
        };
        setup(&mut channel).unwrap();
        assert_eq!(channel.sent.iter().filter(|(t, _)| *t == 0x17).count(), 1);
        assert_eq!(channel.sent.len(), 11);
    }
    #[test]
    fn each_selected_stage_rejection_stops_without_retry_or_next_request() {
        for index in 1..16 {
            let mut channel = Channel {
                fail_at: Some(index),
                ..Default::default()
            };
            assert!(setup(&mut channel).is_err(), "index {index}");
            assert_eq!(channel.sent.len(), index + 1);
        }
    }
    #[test]
    fn malformed_seed_and_failed_calculator_prevent_key_and_fingerprint() {
        let mut channel = Channel {
            short_seed: true,
            ..Default::default()
        };
        assert!(setup(&mut channel).is_err());
        assert_eq!(channel.sent.len(), 14);
        let mut channel = Channel::default();
        assert!(run(
            &mut channel,
            "LIVE",
            [0; 3],
            true,
            Duration::from_secs(1),
            |_, _| Err("Calculator failed".into())
        )
        .is_err());
        assert_eq!(channel.sent.len(), 14);
    }
}

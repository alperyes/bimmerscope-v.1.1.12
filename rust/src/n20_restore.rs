//! FlashHandler coding continuation used by the profile-gated operation owner.
//! Protocol acknowledgements here do not replace independent ECU verification.
#![allow(dead_code)]
use crate::n20_coding::CodingSnapshot;
use crate::n20_setup::{authorize_level, checked, ControlChannel, Failure};
use std::time::Duration;

pub(crate) fn cps_request(vin: &str) -> Result<Vec<u8>, String> {
    if vin.len() != 17
        || !vin
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err("Expected a 17-character uppercase VIN".into());
    }
    let mut bytes = vec![0x2e, 0x37, 0xfe];
    bytes.extend(&vin.as_bytes()[10..]);
    Ok(bytes)
}

pub(crate) fn run(
    channel: &mut impl ControlChannel,
    snapshot: &CodingSnapshot,
    expected_vin: &str,
    bootloader: &str,
    timeout: Duration,
    calculate: impl FnMut(&str, &[u8; 8]) -> Result<Vec<u8>, String>,
) -> Result<(), Failure> {
    let fail = |detail| Failure {
        target: 0x12,
        request_sid: 0x2e,
        detail,
    };
    // Reject a wrong backup before any session or authorization requests.
    let writes = snapshot.restore_requests(expected_vin).map_err(fail)?;
    let cps = cps_request(expected_vin).map_err(fail)?;
    if bootloader.trim().is_empty() || timeout.is_zero() {
        return Err(fail("Missing live bootloader or timeout".into()));
    }
    // ia.a(byte,...,bk,Type): b(byte) then h/m then coding session.
    for (request, prefix) in [
        (&[0x10, 1][..], &[0x50, 1][..]),
        (&[0x10, 3][..], &[0x50, 3][..]),
        (&[0x31, 1, 0x0f, 0x0c, 0][..], &[0x71, 1, 0x0f, 0x0c][..]),
        (&[0x10, 1][..], &[0x50, 1][..]),
        (&[0x10, 3][..], &[0x50, 3][..]),
        (&[0x10, 0x41][..], &[0x50, 0x41][..]),
    ] {
        checked(channel, 0x12, request, prefix, timeout)?;
    }
    // ia uses in.c (jy, ReadFlashTimingParameter / 22 25 04) between seed
    // and key. F186 reports the active session and is not that timing record.
    // Keep timing values informational; only reviewed session policy sets limits.
    struct CodingChannel<'a, T> {
        inner: &'a mut T,
        timeout: Duration,
    }
    impl<T: ControlChannel> ControlChannel for CodingChannel<'_, T> {
        fn exchange(
            &mut self,
            target: u8,
            request: &[u8],
            timeout: Duration,
        ) -> Result<Vec<u8>, String> {
            let reply = self.inner.exchange(target, request, timeout)?;
            if request == [0x27, 1, 255, 255, 255, 255] && reply.starts_with(&[0x67, 1]) {
                let timing = checked(
                    self.inner,
                    0x12,
                    &[0x22, 0x25, 0x04],
                    &[0x62, 0x25, 0x04],
                    self.timeout,
                )
                .map_err(|e| e.detail)?;
                crate::n20_preflight::timings(&timing)?;
            }
            Ok(reply)
        }
    }
    authorize_level(
        &mut CodingChannel {
            inner: channel,
            timeout,
        },
        bootloader,
        1,
        timeout,
        calculate,
    )?;
    for request in writes {
        checked(
            channel,
            0x12,
            &request,
            &[0x6e, request[1], request[2]],
            timeout,
        )?;
    }
    // Historical writer logs and ignores coding-erase errors. This driver
    // requires the matching reply and stops rather than clearing recovery state.
    checked(
        channel,
        0x12,
        &[0x31, 1, 0x0f, 1],
        &[0x71, 1, 0x0f, 1],
        timeout,
    )?;
    checked(channel, 0x12, &cps, &[0x6e, 0x37, 0xfe], timeout)?;
    checked(channel, 0x12, &[0x11, 1], &[0x51, 1], timeout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const VIN: &str = "WBA3A52010F360747";
    #[derive(Default)]
    struct Channel {
        sent: Vec<Vec<u8>>,
        fail_at: Option<usize>,
        timing_reply: Option<Vec<u8>>,
    }
    impl ControlChannel for Channel {
        fn exchange(&mut self, _: u8, request: &[u8], _: Duration) -> Result<Vec<u8>, String> {
            let index = self.sent.len();
            self.sent.push(request.to_vec());
            if self.fail_at == Some(index) {
                return Ok(vec![0x7f, request[0], 0x22]);
            }
            Ok(match request {
                [0x22, 0x25, 0x04] => self
                    .timing_reply
                    .clone()
                    .unwrap_or_else(|| vec![0x62, 0x25, 0x04, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5]),
                [0x10, s] => vec![0x50, *s, 0, 50, 1, 244],
                [0x22, 0xf1, 0x90] => [vec![0x62, 0xf1, 0x90], VIN.as_bytes().to_vec()].concat(),
                [0x22, hi, lo] => vec![0x62, *hi, *lo, 1, 2, 3, 4],
                [0x31, s, hi, lo, ..] => vec![0x71, *s, *hi, *lo],
                [0x27, 1, ..] => [vec![0x67, 1], vec![7; 8]].concat(),
                [0x27, 2, ..] => vec![0x67, 2],
                [0x2e, hi, lo, ..] => vec![0x6e, *hi, *lo],
                [0x11, 1] => vec![0x51, 1],
                _ => panic!("Unexpected operation"),
            })
        }
    }
    fn snapshot() -> CodingSnapshot {
        CodingSnapshot::read(&mut Channel::default(), VIN, Duration::from_secs(1)).unwrap()
    }
    fn restore(c: &mut Channel) -> Result<(), Failure> {
        run(
            c,
            &snapshot(),
            VIN,
            "LIVE",
            Duration::from_secs(1),
            |_, _| Ok(vec![9; 16]),
        )
    }
    #[test]
    fn coding_level_section_order_cps_and_reset_match_handler() {
        let mut c = Channel::default();
        restore(&mut c).unwrap();
        assert_eq!(c.sent[5], [0x10, 0x41]);
        assert_eq!(c.sent[6], [0x27, 1, 255, 255, 255, 255]);
        assert_eq!(c.sent[7], [0x22, 0x25, 0x04]);
        assert_eq!(&c.sent[8][..2], &[0x27, 2]);
        assert_eq!(c.sent[9], [0x2e, 0x33, 0x20, 1, 2, 3, 4]);
        assert_eq!(c.sent[11], [0x2e, 0x33, 0x51, 4, 3, 2, 1]);
        assert_eq!(c.sent[12], [0x31, 1, 0x0f, 1]);
        assert_eq!(c.sent[13], cps_request(VIN).unwrap());
        assert_eq!(c.sent[14], [0x11, 1]);
    }
    #[test]
    fn every_failure_stops_without_next_write_or_reset() {
        for i in 0..15 {
            let mut c = Channel {
                fail_at: Some(i),
                ..Default::default()
            };
            assert!(restore(&mut c).is_err(), "step {i}");
            assert_eq!(c.sent.len(), i + 1);
        }
    }
    #[test]
    fn invalid_coding_timing_stops_before_calculator_key_writes_and_reset() {
        for reply in [
            vec![0x7f, 0x22, 0x31],
            vec![0x62, 0xf1, 0x86, 0x41],
            vec![0x62, 0x25, 0x04],
            vec![0x62, 0x25, 0x04, 0, 0, 0, 2, 0, 3, 0, 4, 0, 5],
        ] {
            let mut c = Channel {
                timing_reply: Some(reply),
                ..Default::default()
            };
            assert!(run(
                &mut c,
                &snapshot(),
                VIN,
                "LIVE",
                Duration::from_secs(1),
                |_, _| panic!("Invalid timing must stop before calculating a coding key"),
            )
            .is_err());
            assert_eq!(c.sent.len(), 8);
            assert_eq!(c.sent.last().unwrap(), &[0x22, 0x25, 0x04]);
            assert!(!c.sent.iter().any(|r| matches!(r[0], 0x2e | 0x11)));
        }
    }
    #[test]
    fn wrong_snapshot_vin_sends_nothing() {
        let mut c = Channel::default();
        assert!(run(
            &mut c,
            &snapshot(),
            "WBA00000000000000",
            "LIVE",
            Duration::from_secs(1),
            |_, _| Ok(vec![1])
        )
        .is_err());
        assert!(c.sent.is_empty());
        assert_eq!(&cps_request(VIN).unwrap()[3..], b"F360747");
    }
}

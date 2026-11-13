//! DME Preparation 2 on an existing owned channel. Authorization is the same
//! helper used by the flashing owner; no auth state is exported to another socket.
use crate::n20_setup::{authorize_level, checked, ControlChannel, Failure};
use std::time::Duration;

pub(crate) const REQUEST_FLASH_MODE: [u8; 5] = [0x31, 1, 0x0f, 0x0c, 3];

pub(crate) fn flash_mode_refused(request: &[u8], reply: &[u8]) -> bool {
    request == REQUEST_FLASH_MODE && reply == [0x7f, 0x31, 0x22]
}

pub(crate) fn validate(
    requests: &[Vec<u8>],
    prefix: &[u8],
    post: &[Vec<u8>],
) -> Result<(), String> {
    if requests.is_empty()
        || requests.len() > 32
        || post.len() > 32
        || prefix != [0x27, 0x12]
        || requests.last().unwrap() != &[0x27, 0x11, 255, 255, 255, 255]
    {
        return Err("Preparation must end with 27 11 FF FF FF FF and calculated 27 12; maximum 32 requests per section".into());
    }
    for request in requests.iter().take(requests.len() - 1).chain(post.iter()) {
        response_prefix(request)?;
    }
    Ok(())
}

/// This preparation entry cannot bypass the separate flashing profile with
/// editable erase/download commands. Other experimentation stays in Manual UDS.
pub(crate) fn response_prefix(request: &[u8]) -> Result<Vec<u8>, String> {
    match request {
        [0x10,session @ (1|2|3|0x41)]=>Ok(vec![0x50,*session]),
        [0x22,hi,lo]=>Ok(vec![0x62,*hi,*lo]),
        [0x3e,0]=>Ok(vec![0x7e,0]),
        [0x85,2]=>Ok(vec![0xc5,2]),
        [0x28,1,1]=>Ok(vec![0x68,1]),
        [0x31,1,0x0f,0x0c,0|3]=>Ok(vec![0x71,1,0x0f,0x0c]),
        [0x31,1,0x10,3,1]=>Ok(vec![0x71,1,0x10,3]),
        [0x2e,0xf1,0x5a,data @ ..] if data.len()==13=>Ok(vec![0x6e,0xf1,0x5a]),
        _=>Err("Unsupported preparation request. Erase/download/reset and arbitrary writes are not preparation steps; use the dedicated operation or Manual UDS entry.".into()),
    }
}
pub(crate) fn run(
    channel: &mut impl ControlChannel,
    requests: &[Vec<u8>],
    prefix: &[u8],
    post: &[Vec<u8>],
    bootloader: &str,
    timeout: Duration,
    calculate: impl FnMut(&str, &[u8; 8]) -> Result<Vec<u8>, String>,
) -> Result<(), Failure> {
    let fail = |detail| Failure {
        target: 0x12,
        request_sid: 0x27,
        detail,
    };
    validate(requests, prefix, post).map_err(fail)?;
    let mut expected_session = None;
    for request in &requests[..requests.len() - 1] {
        run_step(channel, request, timeout, &mut expected_session, true)?;
    }
    authorize_level(channel, bootloader, 0x11, timeout, calculate)?;
    for request in post {
        run_step(channel, request, timeout, &mut expected_session, false)?;
    }
    Ok(())
}
/// F-series responses may append a session status byte after the session ID.
/// See agent.jar RDBI_ADS_Service (jp), whose telegram lengths include routing.
pub(crate) fn active_session(reply: &[u8]) -> Result<u8, String> {
    match reply {
        [0x62, 0xf1, 0x86, session @ (1 | 2 | 3 | 4 | 0x41 | 0x42 | 0x43)] => Ok(*session),
        [0x62, 0xf1, 0x86, session, status] => {
            let valid = match session {
                1 => matches!(status, 0 | 0x81 | 0x82),
                2 => matches!(status, 1..=9),
                3 => matches!(status, 0 | 0x81..=0x86 | 0xff),
                0x41 => matches!(status, 1 | 2),
                4 | 0x42 | 0x43 => true,
                _ => false,
            };
            valid.then_some(*session)
                .ok_or_else(|| "Invalid DME active session or status".into())
        }
        _ => Err("Malformed DME active-session response".into()),
    }
}

fn run_step(
    channel: &mut impl ControlChannel,
    request: &[u8],
    timeout: Duration,
    expected_session: &mut Option<u8>,
    before_security: bool,
) -> Result<(), Failure> {
    let fail = |detail| Failure {
        target: 0x12,
        request_sid: request[0],
        detail,
    };
    let prefix = response_prefix(request).map_err(fail)?;
    if before_security && request == REQUEST_FLASH_MODE {
        let reply = channel.exchange(0x12, request, timeout).map_err(fail)?;
        // The legacy flash preamble continues to session entry after this reply.
        // The access check still requires positive session and security responses.
        return if reply.starts_with(&prefix) || flash_mode_refused(request, &reply) {
            Ok(())
        } else {
            Err(fail(format!("Unexpected flash-mode reply: {reply:02X?}")))
        };
    }
    let reply = checked(
        channel,
        0x12,
        request,
        &prefix,
        timeout,
    )?;
    match request {
        [0x10, session] => *expected_session = Some(*session),
        [0x22, 0xf1, 0x86] => {
            let session = active_session(&reply).map_err(fail)?;
            if expected_session.is_some_and(|expected| session != expected) {
                return Err(fail(
                    "DME active session differs from the accepted session request".into(),
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Channel {
        requests: Vec<Vec<u8>>,
        reject_key: bool,
    }
    impl ControlChannel for Channel {
        fn exchange(&mut self, target: u8, request: &[u8], _: Duration) -> Result<Vec<u8>, String> {
            assert_eq!(target, 0x12);
            self.requests.push(request.to_vec());
            Ok(match request {
                [0x10, s] => vec![0x50, *s, 0, 50, 0, 100],
                r if r == REQUEST_FLASH_MODE => vec![0x7f, 0x31, 0x22],
                [0x27, 0x11, ..] => [vec![0x67, 0x11], vec![7; 8]].concat(),
                [0x27, 0x12, ..] if self.reject_key => vec![0x7f, 0x27, 0x35],
                [0x27, 0x12, ..] => vec![0x67, 0x12],
                [0x22, 0xf1, 0x86] => vec![0x62, 0xf1, 0x86, 2, 1],
                _ => response_prefix(request).unwrap(),
            })
        }
    }
    #[test]
    fn shared_security_helper_requires_key_acceptance_before_post_key_steps() {
        for rejected in [false, true] {
            let mut channel = Channel {
                requests: vec![],
                reject_key: rejected,
            };
            let steps = vec![
                vec![0x10, 3],
                REQUEST_FLASH_MODE.to_vec(),
                vec![0x10, 2],
                vec![0x27, 0x11, 255, 255, 255, 255],
            ];
            let result = run(
                &mut channel,
                &steps,
                &[0x27, 0x12],
                &[vec![0x22, 0xf1, 0x86]],
                "BTLD",
                Duration::from_secs(1),
                |btld, seed| {
                    assert_eq!(btld, "BTLD");
                    assert_eq!(seed, &[7; 8]);
                    Ok(vec![9; 16])
                },
            );
            assert_eq!(result.is_ok(), !rejected);
            assert_eq!(channel.requests.len(), if rejected { 5 } else { 6 });
        }
    }
    #[test]
    fn editable_preparation_cannot_supply_flash_commands_or_invalid_prefix() {
        for request in [
            vec![0x34, 0, 0x44],
            vec![0x31, 1, 0xff, 0],
            vec![0x2e, 0x33, 0x20, 1],
            vec![0x11, 1],
        ] {
            assert!(validate(
                &[vec![0x27, 0x11, 255, 255, 255, 255]],
                &[0x27, 0x12],
                &[request]
            )
            .is_err());
        }
        assert!(validate(&[vec![0x27, 0x11, 255, 255, 255, 255]], &[0x34], &[]).is_err());
    }
    #[test]
    fn accepted_key_cannot_hide_wrong_active_session() {
        struct WrongSession(Channel);
        impl ControlChannel for WrongSession {
            fn exchange(
                &mut self,
                target: u8,
                request: &[u8],
                timeout: Duration,
            ) -> Result<Vec<u8>, String> {
                if request == [0x22, 0xf1, 0x86] {
                    Ok(vec![0x62, 0xf1, 0x86, 3])
                } else {
                    self.0.exchange(target, request, timeout)
                }
            }
        }
        let mut channel = WrongSession(Channel {
            requests: vec![],
            reject_key: false,
        });
        let result = run(
            &mut channel,
            &[vec![0x10, 2], vec![0x27, 0x11, 255, 255, 255, 255]],
            &[0x27, 0x12],
            &[vec![0x22, 0xf1, 0x86]],
            "BTLD",
            Duration::from_secs(1),
            |_, _| Ok(vec![9; 16]),
        );
        assert!(result.unwrap_err().detail.contains("active session"));
        assert!(channel
            .0
            .requests
            .iter()
            .any(|r| r.starts_with(&[0x27, 0x12])));
    }
}

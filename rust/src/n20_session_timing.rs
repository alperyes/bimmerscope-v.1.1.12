//! Session-response timing from retained fy: raw P2 milliseconds, P2* x10ms.
//! Reviewed bounds plus one immutable exchange cap prevent unbounded pending.
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
#[derive(Clone, Copy, Debug)]
pub(crate) struct Bounds {
    pub max_p2_ms: u64,
    pub max_p2_star_ms: u64,
    pub margin_ms: u64,
}
impl Bounds {
    pub fn validate(self) -> Result<(), String> {
        if self.max_p2_ms == 0
            || self.max_p2_ms > 65535
            || self.max_p2_star_ms == 0
            || self.max_p2_star_ms > 655350
            || self.max_p2_star_ms < self.max_p2_ms
            || self.margin_ms > 5000
        {
            return Err("Invalid reviewed session timing bounds".into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Timing {
    pub p2_ms: u64,
    pub p2_star_ms: u64,
}
pub(crate) fn parse(reply: &[u8], session: u8) -> Result<Timing, String> {
    if !matches!(session, 1 | 2 | 3 | 0x41) || reply.len() != 6 || reply[..2] != [0x50, session] {
        return Err("Session response has missing/invalid timing fields or session echo".into());
    }
    let timing = Timing {
        p2_ms: u16::from_be_bytes([reply[2], reply[3]]) as u64,
        p2_star_ms: 10 * u16::from_be_bytes([reply[4], reply[5]]) as u64,
    };
    if timing.p2_ms == 0 || timing.p2_star_ms < timing.p2_ms {
        return Err("Session timing values are zero or inconsistent".into());
    }
    Ok(timing)
}
struct Window {
    target: u8,
    sid: u8,
    session: Option<u8>,
    absolute: Instant,
    phase: Instant,
}
#[derive(Default)]
pub(crate) struct State {
    bounds: Option<Bounds>,
    timings: BTreeMap<u8, Timing>,
    window: Option<Window>,
}
impl State {
    pub fn configure(&mut self, bounds: Bounds) -> Result<(), String> {
        bounds.validate()?;
        if self.window.is_some() {
            return Err("Cannot change timing policy during an exchange".into());
        }
        self.bounds = Some(bounds);
        self.timings.clear();
        Ok(())
    }
    pub fn begin(
        &mut self,
        target: u8,
        request: &[u8],
        now: Instant,
        absolute: Instant,
    ) -> Result<(), String> {
        if self.window.is_some() || request.is_empty() || now >= absolute {
            return Err("Invalid timing exchange state or deadline".into());
        }
        let duration = self.bounds.map(|bounds| {
            Duration::from_millis(
                self.timings
                    .get(&target)
                    .map(|t| t.p2_ms)
                    .unwrap_or(bounds.max_p2_ms)
                    + bounds.margin_ms,
            )
        });
        let phase = duration
            .and_then(|d| now.checked_add(d))
            .map(|p| p.min(absolute))
            .unwrap_or(absolute);
        self.window = Some(Window {
            target,
            sid: request[0],
            session: if request[0] == 0x10 {
                request.get(1).copied()
            } else {
                None
            },
            absolute,
            phase,
        });
        Ok(())
    }
    pub fn hard_deadline(&self, caller: Instant) -> Result<Instant, String> {
        Ok(caller.min(
            self.window
                .as_ref()
                .ok_or("No timing exchange is active")?
                .absolute,
        ))
    }
    pub fn deadline(&self, caller: Instant) -> Result<Instant, String> {
        let w = self.window.as_ref().ok_or("No timing exchange is active")?;
        Ok(caller.min(w.absolute).min(w.phase))
    }
    pub fn received(&mut self, reply: &[u8], now: Instant) -> Result<(), String> {
        let w = self.window.as_mut().ok_or("No timing exchange is active")?;
        if now >= w.absolute || now >= w.phase {
            return Err("Response exceeded session timing or absolute deadline".into());
        }
        if reply == [0x7f, w.sid, 0x78] {
            if let Some(bounds) = self.bounds {
                let p2_star = self
                    .timings
                    .get(&w.target)
                    .map(|t| t.p2_star_ms)
                    .unwrap_or(bounds.max_p2_star_ms);
                w.phase = now
                    .checked_add(Duration::from_millis(p2_star + bounds.margin_ms))
                    .ok_or("Timing deadline overflow")?
                    .min(w.absolute);
            }
            return Ok(());
        }
        if let Some(bounds) = self.bounds {
            if let Some(session) = w.session {
                if reply.first() == Some(&0x50) {
                    let timing = parse(reply, session)?;
                    if timing.p2_ms > bounds.max_p2_ms || timing.p2_star_ms > bounds.max_p2_star_ms
                    {
                        return Err("ECU session timings exceed the reviewed profile bounds".into());
                    }
                    self.timings.insert(w.target, timing);
                }
            }
        }
        self.window = None;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn bounds() -> Bounds {
        Bounds {
            max_p2_ms: 1000,
            max_p2_star_ms: 30000,
            margin_ms: 10,
        }
    }
    #[test]
    fn session_values_use_correct_units_and_reject_wrong_zero_or_extra_fields() {
        assert_eq!(
            parse(&[0x50, 2, 0, 50, 1, 244], 2).unwrap(),
            Timing {
                p2_ms: 50,
                p2_star_ms: 5000
            }
        );
        for reply in [
            vec![0x50, 3, 0, 50, 1, 244],
            vec![0x50, 2, 0, 0, 1, 244],
            vec![0x50, 2, 0, 50],
            vec![0x50, 2, 0, 50, 1, 244, 0],
        ] {
            assert!(parse(&reply, 2).is_err());
        }
    }
    #[test]
    fn pending_uses_p2_star_but_cannot_extend_the_absolute_deadline() {
        let now = Instant::now();
        let cap = now + Duration::from_secs(2);
        let mut state = State::default();
        state.configure(bounds()).unwrap();
        state.begin(0x12, &[0x10, 2], now, cap).unwrap();
        state.received(&[0x50, 2, 0, 50, 0, 20], now).unwrap();
        state.begin(0x12, &[0x31, 1], now, cap).unwrap();
        assert_eq!(
            state.deadline(cap).unwrap(),
            now + Duration::from_millis(60)
        );
        state
            .received(&[0x7f, 0x31, 0x78], now + Duration::from_millis(40))
            .unwrap();
        assert_eq!(
            state.deadline(cap).unwrap(),
            now + Duration::from_millis(250)
        );
        for millis in (200..2000).step_by(150) {
            state
                .received(&[0x7f, 0x31, 0x78], now + Duration::from_millis(millis))
                .unwrap();
        }
        assert!(state.deadline(cap + Duration::from_secs(100)).unwrap() <= cap);
        assert!(state.received(&[0x71, 1], cap).is_err());
    }
    #[test]
    fn auxiliary_target_does_not_change_main_timing_and_outliers_fail() {
        let now = Instant::now();
        let cap = now + Duration::from_secs(5);
        let mut state = State::default();
        state.configure(bounds()).unwrap();
        state.begin(0x17, &[0x10, 1], now, cap).unwrap();
        state.received(&[0x50, 1, 0, 50, 1, 244], now).unwrap();
        state.begin(0x12, &[0x22, 0xf1, 1], now, cap).unwrap();
        assert_eq!(
            state.deadline(cap).unwrap(),
            now + Duration::from_millis(1010)
        );
        state.received(&[0x62, 0xf1, 1], now).unwrap();
        state.begin(0x12, &[0x10, 2], now, cap).unwrap();
        assert!(state.received(&[0x50, 2, 0xff, 0xff, 1, 244], now).is_err());
    }
}

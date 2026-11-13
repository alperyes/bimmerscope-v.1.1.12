//! Generic FlashHandler coding inputs. This reads and preserves ECU data;
//! it neither enters coding mode nor sends any coding writes.
#![allow(dead_code)]

use crate::n20_setup::ControlChannel;
use std::time::Duration;

pub(crate) struct CodingSnapshot {
    vin: String,
    sec3320: Vec<u8>,
    sec3350: Vec<u8>,
    sec3351: Option<Vec<u8>>,
}

fn vin(channel: &mut impl ControlChannel, timeout: Duration) -> Result<String, String> {
    let reply = channel.exchange(0x12, &[0x22, 0xf1, 0x90], timeout)?;
    if reply.len() != 20 || !reply.starts_with(&[0x62, 0xf1, 0x90]) {
        return Err("Missing or malformed fresh DME VIN".into());
    }
    let value = std::str::from_utf8(&reply[3..]).map_err(|_| "Invalid VIN encoding")?;
    if !value
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err("Invalid VIN characters".into());
    }
    Ok(value.into())
}

fn section(
    channel: &mut impl ControlChannel,
    did: u16,
    optional: bool,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, String> {
    let [hi, lo] = did.to_be_bytes();
    let reply = channel.exchange(0x12, &[0x22, hi, lo], timeout)?;
    // Explicit request-out-of-range is the only accepted missing-optional case.
    // Timeout, unresolved pending, access denial and malformed data are errors.
    if optional && reply == [0x7f, 0x22, 0x31] {
        return Ok(None);
    }
    if !reply.starts_with(&[0x62, hi, lo]) || !(4..=255).contains(&reply.len()) {
        return Err(format!(
            "Coding section {did:04X} is missing, rejected or malformed"
        ));
    }
    Ok(Some(reply[3..].to_vec()))
}

impl CodingSnapshot {
    /// Caller must durably persist the returned original bytes and bind the
    /// rest of the fresh ECU fingerprint before allowing programming setup.
    pub fn read(
        channel: &mut impl ControlChannel,
        expected_vin: &str,
        timeout: Duration,
    ) -> Result<Self, String> {
        if expected_vin.len() != 17 || timeout.is_zero() {
            return Err("Expected VIN and finite timeout are required".into());
        }
        let fresh_vin = vin(channel, timeout)?;
        if fresh_vin != expected_vin {
            return Err("DME VIN changed before coding snapshot".into());
        }
        let sec3320 = section(channel, 0x3320, false, timeout)?.ok_or("Missing 3320")?;
        let sec3350 = section(channel, 0x3350, false, timeout)?.ok_or("Missing 3350")?;
        let sec3351 = section(channel, 0x3351, true, timeout)?;
        if vin(channel, timeout)? != fresh_vin {
            return Err("DME VIN changed during coding snapshot".into());
        }
        Ok(Self {
            vin: fresh_vin,
            sec3320,
            sec3350,
            sec3351,
        })
    }

    /// Parse original bytes from a saved manifest. This checks structure/VIN;
    /// its enclosing operation binding and provenance must be checked by owner.
    pub(crate) fn from_manifest(
        value: &serde_json::Value,
        expected_vin: &str,
    ) -> Result<Self, String> {
        if expected_vin.len() != 17
            || !expected_vin
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            || value["schema"] != "n20-coding-snapshot-v1"
            || value["vin"] != expected_vin
            || value["source"] != "ecu-read"
            || value["recovery_image"] != false
        {
            return Err("Coding manifest identity or format differs".into());
        }
        let decode = |key: &str| -> Result<Vec<u8>, String> {
            let hex = value[key].as_str().ok_or("Missing coding section")?;
            if hex.is_empty()
                || hex.len() > 504
                || hex.len() % 2 != 0
                || !hex.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err("Invalid saved coding bytes".into());
            }
            hex.as_bytes()
                .chunks_exact(2)
                .map(|c| {
                    u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16)
                        .map_err(|e| e.to_string())
                })
                .collect()
        };
        Ok(Self {
            vin: expected_vin.into(),
            sec3320: decode("3320")?,
            sec3350: decode("3350")?,
            sec3351: if value.get("3351") == Some(&serde_json::Value::Null) {
                None
            } else {
                Some(decode("3351")?)
            },
        })
    }

    /// Original read bytes, preserved without the 3351 write transformation.
    pub fn manifest(&self) -> serde_json::Value {
        let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
        serde_json::json!({
            "schema": "n20-coding-snapshot-v1", "vin": self.vin,
            "3320": hex(&self.sec3320), "3350": hex(&self.sec3350),
            "3351": self.sec3351.as_deref().map(hex),
            "source": "ecu-read", "recovery_image": false,
        })
    }

    /// Offline construction only. A coding session, separate authorization,
    /// checked write replies, erase/CPS and reset are still required by ia.
    pub fn restore_requests(&self, expected_vin: &str) -> Result<Vec<Vec<u8>>, String> {
        if self.vin != expected_vin {
            return Err("Coding snapshot VIN mismatch".into());
        }
        let mut result = Vec::new();
        for (did, source) in [
            (0x3320u16, Some(&self.sec3320)),
            (0x3350, Some(&self.sec3350)),
            (0x3351, self.sec3351.as_ref()),
        ] {
            let Some(source) = source else {
                continue;
            };
            let mut bytes = source.clone();
            if did == 0x3351 {
                // ia.b(byte[]): reverse every group, including a short last group.
                for word in bytes.chunks_mut(4) {
                    word.reverse();
                }
            }
            let mut request = vec![0x2e];
            request.extend(did.to_be_bytes());
            request.extend(bytes);
            result.push(request);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    const VIN: &str = "WBA3A52010F360747";
    struct Wire {
        sent: Vec<Vec<u8>>,
        replies: VecDeque<Vec<u8>>,
    }
    impl ControlChannel for Wire {
        fn exchange(&mut self, target: u8, request: &[u8], _: Duration) -> Result<Vec<u8>, String> {
            assert_eq!(target, 0x12);
            self.sent.push(request.to_vec());
            self.replies.pop_front().ok_or("Lost reply".into())
        }
    }
    fn wire() -> Wire {
        let vin = [vec![0x62, 0xf1, 0x90], VIN.as_bytes().to_vec()].concat();
        Wire {
            sent: vec![],
            replies: vec![
                vin.clone(),
                vec![0x62, 0x33, 0x20, 10],
                vec![0x62, 0x33, 0x50, 20],
                vec![0x62, 0x33, 0x51, 1, 2, 3, 4, 5, 6],
                vin,
            ]
            .into(),
        }
    }
    #[test]
    fn saved_snapshot_roundtrip_requires_original_sections_and_vin() {
        let original = CodingSnapshot::read(&mut wire(), VIN, Duration::from_secs(1))
            .unwrap()
            .manifest();
        assert_eq!(
            CodingSnapshot::from_manifest(&original, VIN)
                .unwrap()
                .manifest(),
            original
        );
        assert!(CodingSnapshot::from_manifest(&original, "WBA00000000000000").is_err());
        for bad in [
            serde_json::json!(""),
            serde_json::json!("GG"),
            serde_json::json!("0"),
        ] {
            let mut value = original.clone();
            value["3320"] = bad;
            assert!(CodingSnapshot::from_manifest(&value, VIN).is_err());
        }
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove("3351");
        assert!(CodingSnapshot::from_manifest(&value, VIN).is_err());
        value["3351"] = serde_json::Value::Null;
        assert!(CodingSnapshot::from_manifest(&value, VIN).is_ok());
    }

    #[test]
    fn reads_original_sections_and_builds_3351_word_reversal_without_writes() {
        let mut w = wire();
        let snapshot = CodingSnapshot::read(&mut w, VIN, Duration::from_secs(1)).unwrap();
        assert!(w.sent.iter().all(|r| r[0] == 0x22));
        let requests = snapshot.restore_requests(VIN).unwrap();
        assert_eq!(
            requests,
            vec![
                vec![0x2e, 0x33, 0x20, 10],
                vec![0x2e, 0x33, 0x50, 20],
                vec![0x2e, 0x33, 0x51, 4, 3, 2, 1, 6, 5]
            ]
        );
        assert_eq!(snapshot.manifest()["3351"], "010203040506");
        assert!(snapshot.restore_requests("WBA00000000000000").is_err());
    }
    #[test]
    fn missing_optional_section_requires_explicit_out_of_range() {
        let mut w = wire();
        w.replies[3] = vec![0x7f, 0x22, 0x31];
        let snapshot = CodingSnapshot::read(&mut w, VIN, Duration::from_secs(1)).unwrap();
        assert_eq!(snapshot.restore_requests(VIN).unwrap().len(), 2);
        for invalid in [
            vec![0x7f, 0x22, 0x33],
            vec![0x7f, 0x22, 0x78],
            vec![0x62, 0x33, 0x51],
        ] {
            let mut w = wire();
            w.replies[3] = invalid;
            assert!(CodingSnapshot::read(&mut w, VIN, Duration::from_secs(1)).is_err());
        }
    }
    #[test]
    fn required_section_failure_and_vin_change_never_produce_snapshot() {
        for index in [0, 1, 2, 4] {
            let mut w = wire();
            w.replies[index] = vec![0x7f, 0x22, 0x31];
            assert!(CodingSnapshot::read(&mut w, VIN, Duration::from_secs(1)).is_err());
            assert_eq!(w.sent.len(), index + 1);
        }
        let mut w = wire();
        w.replies[1] = vec![0x62, 0x33, 0x50, 10];
        assert!(CodingSnapshot::read(&mut w, VIN, Duration::from_secs(1)).is_err());
    }
}

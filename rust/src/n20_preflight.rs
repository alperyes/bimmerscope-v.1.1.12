//! Retained agent dr/du and jy contracts, collected as observations only.
//! No ignition wake command, timeout override or programming approval.
use crate::n20_setup::ControlChannel;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub(crate) fn gateway_status(frame: &[u8]) -> Result<u8, String> {
    if frame.len() < 7 {
        return Err("Incomplete gateway status frame".into());
    }
    let size = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    if size == 0 || size > 256 || frame.len() != size + 6 || frame[4..6] != [0, 0x10] {
        return Err("Unexpected gateway status frame length or type".into());
    }
    Ok((frame[6] & 0x0c) >> 2)
}
pub(crate) fn probe_gateway(host: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let ip: IpAddr = host
        .parse()
        .map_err(|_| "Gateway endpoint must be an identified IP address")?;
    probe_gateway_at(SocketAddr::new(ip, 6811), timeout)
}
fn probe_gateway_at(endpoint: SocketAddr, timeout: Duration) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    let mut stream = TcpStream::connect_timeout(&endpoint, timeout).map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
        ))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&[0, 0, 0, 0, 0, 0x10])
        .map_err(|e| e.to_string())?;
    let mut frame = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("Gateway status deadline expired")?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|e| e.to_string())?;
        let mut chunk = [0; 262];
        let read = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("Gateway status socket closed before a complete reply".into());
        }
        frame.extend(&chunk[..read]);
        if frame.len() >= 4 {
            let length = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
            if !(1..=256).contains(&length) {
                return Err("Gateway status payload length is invalid".into());
            }
            if frame.len() >= length + 6 {
                gateway_status(&frame)?;
                return Ok(frame);
            }
        }
    }
}
fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}
/// Agent telegram includes two route bytes; raw UDS lengths are 13/15/18.
/// Keep raw values/format markers. They are not validated timeout settings.
pub(crate) fn timings(reply: &[u8]) -> Result<Value, String> {
    if !reply.starts_with(&[0x62, 0x25, 0x04]) || ![13, 15, 18].contains(&reply.len()) {
        return Err("Unsupported flash timing response".into());
    }
    let (erase, check, install, auth, reset, formats) = if reply.len() == 18 {
        let formats = [reply[3], reply[6], reply[9], reply[12], reply[15]];
        if formats[0] != 1
            || formats[1] != 1
            || formats[2] != 1
            || ![1, 2].contains(&formats[3])
            || ![1, 2].contains(&formats[4])
        {
            return Err("Unsupported flash timing format marker".into());
        }
        (
            word(reply, 4),
            word(reply, 7),
            word(reply, 16),
            word(reply, 10),
            word(reply, 13),
            Some(formats),
        )
    } else {
        (
            word(reply, 3),
            word(reply, 5),
            word(reply, 7),
            word(reply, 9),
            word(reply, 11),
            None,
        )
    };
    if erase == 0
        || check == 0
        || auth == 0
        || reset == 0
        || (reply.len() == 15 && word(reply, 13) == 0)
    {
        return Err("Flash timing response contains an invalid zero value".into());
    }
    Ok(
        json!({"erase_raw":erase,"check_memory_raw":check,"bootloader_install_raw":install,
        "authentication_raw":auth,"reset_raw":reset,"transfer_data_raw":if reply.len()==15 {Some(word(reply,13))}else{None},
        "format_markers_erase_check_auth_reset_install":formats,"used_to_override_timeouts":false}),
    )
}
pub(crate) fn collect(host: &str, channel: &mut impl ControlChannel) -> Result<Value, String> {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02X}")).collect::<String>();
    let gateway = match probe_gateway(host, Duration::from_secs(1)) {
        Ok(frame) => {
            let value = gateway_status(&frame)?;
            json!({"status":"observed","request":"000000000010","response":hex(&frame),"raw_status":value,"matches_legacy_gate":value==1})
        }
        Err(detail) => json!({"status":"unavailable","detail":detail}),
    };
    // Transport errors must propagate: an uncertain/poisoned channel is not usable.
    let reply = channel.exchange(0x12, &[0x22, 0x25, 0x04], Duration::from_secs(5))?;
    let timing = match timings(&reply) {
        Ok(values) => json!({"status":"observed","response":hex(&reply),"values":values}),
        Err(detail) => json!({"status":"unavailable","response":hex(&reply),"detail":detail}),
    };
    Ok(
        json!({"schema":"n20-agent-preflight-observations-v1","gateway":gateway,"flash_timing":timing,
        "programming_approved":false,"physical_ignition_verified":false,"wake_command_sent":false}),
    )
}
/// All returned condition bytes are retained. An empty list is not permission
/// to program; labels are observations from historical ix, not ECU diagnoses.
pub(crate) fn conditions(reply: &[u8]) -> Result<Value, String> {
    let raw = reply.iter().map(|b| format!("{b:02X}")).collect::<String>();
    if reply.len() == 3 && reply[..2] == [0x7f, 0x31] {
        return Ok(
            json!({"status":"rejected","nrc":reply[2],"response":raw,"conditions":[],"programming_approved":false}),
        );
    }
    if !reply.starts_with(&[0x71, 1, 2, 3]) {
        return Err("Programming-condition response does not match the routine".into());
    }
    let labels = [
        "engine running",
        "immobilizer not unlocked",
        "gearbox input speed not zero",
        "gearbox output speed not zero",
        "vehicle speed not zero",
        "control active",
        "ignition restart requested",
        "programming voltage insufficient",
        "ignition off (clamp 15)",
        "electrical-system voltage low",
        "temperature too high",
        "temperature too low",
        "unspecified legacy condition",
    ];
    let conditions=reply[4..].iter().map(|code|json!({"code":code,"hex":format!("{code:02X}"),
        "legacy_label":if (1..=13).contains(code){Some(labels[*code as usize-1])}else{None},"known_legacy_code":(1..=13).contains(code)})).collect::<Vec<_>>();
    Ok(
        json!({"status":if conditions.is_empty(){"no_conditions_listed"}else{"reported_conditions"},"response":raw,"conditions":conditions,
        "programming_approved":false,"labels_independently_verified":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn condition_query_keeps_every_code_and_never_approves_empty_or_negative_results() {
        let result = conditions(&[0x71, 1, 2, 3, 1, 8, 0xc0, 1]).unwrap();
        assert_eq!(result["conditions"].as_array().unwrap().len(), 4);
        assert_eq!(
            result["conditions"][1]["legacy_label"],
            "programming voltage insufficient"
        );
        assert_eq!(result["conditions"][2]["code"], 192);
        assert_eq!(result["conditions"][2]["legacy_label"], Value::Null);
        assert_eq!(result["programming_approved"], false);
        let empty = conditions(&[0x71, 1, 2, 3]).unwrap();
        assert_eq!(empty["status"], "no_conditions_listed");
        assert_eq!(empty["programming_approved"], false);
        assert_eq!(conditions(&[0x7f, 0x31, 0x22]).unwrap()["nrc"], 0x22);
        assert!(conditions(&[0x71, 1, 2, 6]).is_err());
        assert!(conditions(&[0x7f, 0x31]).is_err());
    }
    #[test]
    fn status_extracts_only_the_agent_bits_and_rejects_other_frames() {
        for state in 0..4 {
            let frame = [0, 0, 0, 1, 0, 0x10, 0xf3 | (state << 2)];
            assert_eq!(gateway_status(&frame).unwrap(), state);
        }
        assert!(gateway_status(&[0, 0, 0, 0, 0, 0x10]).is_err());
        assert!(gateway_status(&[0, 0, 0, 2, 0, 0x10, 4]).is_err());
        assert!(gateway_status(&[0, 0, 0, 1, 0, 1, 4]).is_err());
    }
    #[test]
    fn gateway_probe_handles_fragmented_frames_and_rejects_truncated_reply() {
        for complete in [true, false] {
            let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = server.local_addr().unwrap();
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = server.accept().unwrap();
                let mut request = [0; 6];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(request, [0, 0, 0, 0, 0, 0x10]);
                stream.write_all(&[0, 0, 0, 1]).unwrap();
                if complete {
                    stream.write_all(&[0, 0x10, 4]).unwrap();
                }
            });
            let result = probe_gateway_at(endpoint, Duration::from_secs(1));
            if complete {
                assert_eq!(gateway_status(&result.unwrap()).unwrap(), 1);
            } else {
                assert!(result.is_err());
            }
            worker.join().unwrap();
        }
    }

    #[test]
    fn timings_preserve_correct_raw_offsets_for_all_three_layouts() {
        let plain = [0x62, 0x25, 4, 0, 10, 0, 20, 0, 30, 0, 40, 0, 50];
        let v = timings(&plain).unwrap();
        assert_eq!(v["erase_raw"], 10);
        assert_eq!(v["reset_raw"], 50);
        assert_eq!(v["authentication_raw"], 40);
        let mut transfer = plain.to_vec();
        transfer.extend([0, 60]);
        assert_eq!(timings(&transfer).unwrap()["transfer_data_raw"], 60);
        let formatted = [
            0x62, 0x25, 4, 1, 0, 10, 1, 0, 20, 1, 0, 40, 2, 0, 50, 2, 0, 30,
        ];
        let v = timings(&formatted).unwrap();
        assert_eq!(v["bootloader_install_raw"], 30);
        assert_eq!(v["reset_raw"], 50);
        assert_eq!(v["used_to_override_timeouts"], false);
        let mut bad = formatted;
        bad[3] = 2;
        assert!(timings(&bad).is_err());
        let mut bad = plain;
        bad[3] = 0;
        bad[4] = 0;
        assert!(timings(&bad).is_err());
        assert!(timings(&[0x7f, 0x22, 0x31]).is_err());
    }
}

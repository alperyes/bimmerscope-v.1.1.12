//! Observed MEVD17.2.9 BIN record layout, not a general BMW metadata decoder.
use serde_json::{json, Value};

pub(crate) fn decimal(token: &str) -> Option<String> {
    if token.len() != 14
        || !token.is_ascii()
        || !token.bytes().all(|b| b.is_ascii_hexdigit())
        || token == "00000000000000"
        || token.eq_ignore_ascii_case("FFFFFFFFFFFFFF")
    {
        return None;
    }
    let mut id = token[..8].to_ascii_uppercase();
    for p in [8, 10, 12] {
        id.push_str(&format!(
            "{:03}",
            u8::from_str_radix(&token[p..p + 2], 16).ok()?
        ));
    }
    Some(id)
}
pub(crate) struct Metadata {
    pub bootloader: Option<String>,
    pub report: Value,
}
pub(crate) fn inspect(bytes: &[u8]) -> Result<Metadata, String> {
    if bytes.len() != 0x400000 {
        return Err("Expected a 4 MiB N20 BIN".into());
    }
    let locations = [
        (0x24, "startup header"),
        (0xfd00, "startup trailer"),
        (0x3ffd8e, "software bootloader dependency"),
    ];
    let mut records = Vec::new();
    let mut values = Vec::new();
    for (offset, role) in locations {
        let token = bytes[offset + 1..offset + 8]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>();
        let id = if bytes[offset] == 6 {
            decimal(&token)
        } else {
            None
        };
        records.push(json!({"record_offset":offset,"token_offset":offset+1,"role":role,"expected_type":6,"observed_type":bytes[offset],"token":token,"id":id}));
        if let Some(id) = id {
            values.push(id);
        }
    }
    let bootloader =
        if values.is_empty() && !locations.iter().any(|(offset, _)| bytes[*offset] == 6) {
            None
        } else {
            if values.len() != 3
                || values.iter().any(|v| v != &values[0])
                || &bytes[26..36] != b"MEVD1729__"
            {
                return Err(
                "Incomplete or conflicting BIN bootloader records; target bootloader is unresolved"
                    .into(),
            );
            }
            Some(values[0].clone())
        };
    Ok(Metadata {
        report: json!({"schema":"n20-bin-metadata-v1","bootloader":bootloader,"bootloader_records":records,
        "coding":Value::Null,"coding_status":"No established coding-ID record in the observed BIN layout; BM3 mp codingVersion is external metadata",
        "bootloader_meaning":"Startup image ID corroborated by software dependency; startup bytes are excluded from ordinary flashing",
        "provenance":"Observed BIN byte records, not live DME IDs or filename/package claims","programming_approved":false}),
        bootloader,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn corroborated_bootloader_missing_and_conflicting_records() {
        let mut bytes = vec![0; 0x400000];
        assert!(inspect(&bytes).unwrap().bootloader.is_none());
        bytes[0x24] = 6;
        assert!(inspect(&bytes).is_err());
        bytes[0x24] = 0;
        bytes[26..36].copy_from_slice(b"MEVD1729__");
        for p in [0x24, 0xfd00, 0x3ffd8e] {
            bytes[p] = 6;
            bytes[p + 1..p + 8].copy_from_slice(&[0, 0, 0x19, 1, 1, 49, 2]);
        }
        let metadata = inspect(&bytes).unwrap();
        assert_eq!(metadata.bootloader.as_deref(), Some("00001901001049002"));
        assert!(metadata.report["coding"].is_null());
        bytes[0x3ffd95] = 3;
        assert!(inspect(&bytes).is_err());
        bytes[0x3ffd8e] = 0;
        assert!(inspect(&bytes).is_err());
    }
    #[test]
    fn component_conversion_is_bounded_and_reversible() {
        assert_eq!(
            decimal("00001CDB1D9607").as_deref(),
            Some("00001CDB029150007")
        );
        for bad in [
            "00000000000000",
            "FFFFFFFFFFFFFF",
            "garbage",
            "00001CDB1D96ZZ",
        ] {
            assert!(decimal(bad).is_none());
        }
    }
}

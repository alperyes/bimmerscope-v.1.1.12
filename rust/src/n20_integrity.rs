//! Read-only checks of eight content descriptors and eight header CRC spans.
//! This is not ECU integrity approval: signatures, ECU validation behavior and
//! recovery remain independent. No correction, signing or CVN masking occurs.
#![allow(dead_code)]

#[derive(Debug)]
pub(crate) struct Check {
    pub descriptor: usize,
    pub start: usize,
    pub end_inclusive: usize,
    pub algorithm: u8,
    pub calculated: Option<u32>,
    pub expected: u32,
}

impl Check {
    pub fn matches(&self) -> Option<bool> {
        self.calculated.map(|v| v == self.expected)
    }
}

fn word(bytes: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap())
}

const HEADER_LAYOUT: [(usize, u32); 4] = [(0, 2), (0x20000, 3), (0x180000, 2), (0x220000, 1)];
const HEADER_CRC_SEED: u32 = 0xfadecafe;
const HEADER_CRC_TARGET: u32 = 0xcafeaffe;

#[derive(Debug)]
pub(crate) struct HeaderCheck {
    pub header: usize,
    pub kind: &'static str,
    pub end_exclusive: usize,
    pub calculated: u32,
}

/// D00064E6 calls D00060A4 from the header base through the final DWORD
/// inclusively. D000611E generates the reflected EDB88320 table. Limit this
/// interpretation to the inspected software and fixed descriptor counts.
pub(crate) fn inspect_headers(bytes: &[u8]) -> Result<Vec<HeaderCheck>, String> {
    require_known_software(bytes)?;
    let mut checks = Vec::with_capacity(8);
    for (header, count) in HEADER_LAYOUT {
        if word(bytes, header + 0x2c) != count {
            return Err(format!("Unrecognized descriptor count at 0x{header:X}"));
        }
        for (kind, end_exclusive) in [
            ("fixed_header", header + 0x34),
            (
                "header_and_descriptors",
                header + count as usize * 0x20 + 0x38,
            ),
        ] {
            checks.push(HeaderCheck {
                header,
                kind,
                end_exclusive,
                calculated: !raw_crc32(&bytes[header..end_exclusive], HEADER_CRC_SEED),
            });
        }
    }
    Ok(checks)
}

fn require_header_checks(bytes: &[u8]) -> Result<(), String> {
    for check in inspect_headers(bytes)? {
        if check.calculated != HEADER_CRC_TARGET {
            return Err(format!(
                "N20 header CRC mismatch at 0x{:X} ({}, end exclusive 0x{:X})",
                check.header, check.kind, check.end_exclusive
            ));
        }
    }
    Ok(())
}

fn header_summary(bytes: &[u8]) -> serde_json::Value {
    match inspect_headers(bytes) {
        Err(detail) => serde_json::json!({"schema":"n20-header-crc-v1", "status":"unavailable",
            "detail":detail,"ecu_integrity_approved":false}),
        Ok(checks) => serde_json::json!({"schema":"n20-header-crc-v1",
            "status":if checks.iter().all(|c|c.calculated==HEADER_CRC_TARGET){"header_crc_checks_match"}else{"header_crc_checks_differ"},
            "algorithm":"reflected_crc32_edb88320_complemented", "seed":"FADECAFE", "expected":"CAFEAFFE",
            "source":"Selected firmware D00064E6/D00060A4/D000611E; static interpretation, not live ECU acceptance",
            "ecu_integrity_approved":false,
            "checks":checks.iter().map(|c|serde_json::json!({"header_offset":c.header,"kind":c.kind,
                "file_start":c.header,"file_end_exclusive":c.end_exclusive,
                "calculated":format!("{:08X}",c.calculated),"expected":"CAFEAFFE",
                "matches":c.calculated==HEADER_CRC_TARGET})).collect::<Vec<_>>() }),
    }
}

pub(crate) fn inspect(bytes: &[u8]) -> Result<Vec<Check>, String> {
    if bytes.len() != 0x400000 || !bytes[..256].windows(10).any(|s| s == b"MEVD1729__") {
        return Err("Expected the observed 4 MiB MEVD17.2.9 image layout".into());
    }
    let mut checks = Vec::new();
    for (header, count) in HEADER_LAYOUT {
        if word(bytes, header + 0x2c) != count {
            return Err(format!("Unrecognized descriptor count at 0x{header:X}"));
        }
        for index in 0..count as usize {
            let descriptor = header + 0x34 + index * 32;
            let start = word(bytes, descriptor + 4)
                .checked_sub(0x80000000)
                .ok_or("Invalid descriptor start address")? as usize;
            let end = word(bytes, descriptor + 8)
                .checked_sub(0x80000000)
                .ok_or("Invalid descriptor end address")? as usize;
            if start > end || end >= bytes.len() || start % 4 != 0 || (end - start + 1) % 4 != 0 {
                return Err("Descriptor range is outside the image or is not word aligned".into());
            }
            let seed = word(bytes, descriptor + 12);
            let target = word(bytes, descriptor + 16);
            if seed != 0xfadecafe || target != 0xcafeaffe {
                return Err("Unrecognized descriptor seed or expected value".into());
            }
            let algorithm = bytes[descriptor + 28];
            let data = &bytes[start..=end];
            let expected = if algorithm == 0 { !target } else { target };
            let calculated =
                match algorithm {
                    0 => Some(raw_crc32(data, seed)),
                    1 => Some(data.chunks_exact(4).fold(seed, |sum, w| {
                        sum.wrapping_add(u32::from_le_bytes(w.try_into().unwrap()))
                    })),
                    0x10 => {
                        // Observed ADD16 convention: all but the final halfword
                        // contribute low; the final halfword contributes high.
                        let (prefix, last) = data.split_at(data.len() - 2);
                        let sum = prefix.chunks_exact(2).fold(seed, |sum, w| {
                            sum.wrapping_add(u16::from_le_bytes(w.try_into().unwrap()) as u32)
                        });
                        Some(sum.wrapping_add(
                            (u16::from_le_bytes(last.try_into().unwrap()) as u32) << 16,
                        ))
                    }
                    _ => None,
                };
            checks.push(Check {
                descriptor,
                start,
                end_inclusive: end,
                algorithm,
                calculated,
                expected,
            });
        }
    }
    Ok(checks)
}

// Exact descriptor set independently reproduced for the inspected software.
// A relocated/self-consistent descriptor table must not choose its own coverage.
const KNOWN_DESCRIPTORS: [(usize, usize, usize, u8); 8] = [
    (0x34, 0, 0xfbff, 0),
    (0x54, 0x78, 0x203, 0),
    (0x20034, 0x20000, 0x17fbff, 0x10),
    (0x20054, 0x5aa28, 0x6ff47, 0x10),
    (0x20074, 0x22f50, 0x266d7, 1),
    (0x180034, 0x180000, 0x1ffbff, 0x10),
    (0x180054, 0x1babc4, 0x1bbdff, 0x10),
    (0x220034, 0x220000, 0x3ffbff, 0x10),
];

fn require_known_checks(checks: &[Check]) -> Result<(), String> {
    if checks.len() != KNOWN_DESCRIPTORS.len() {
        return Err("Incomplete N20 descriptor set".into());
    }
    for (check, expected) in checks.iter().zip(KNOWN_DESCRIPTORS) {
        if (
            check.descriptor,
            check.start,
            check.end_inclusive,
            check.algorithm,
        ) != expected
        {
            return Err(format!(
                "Unreviewed descriptor coverage or algorithm at 0x{:X}",
                check.descriptor
            ));
        }
        if check.matches() != Some(true) {
            return Err(format!(
                "N20 image checksum mismatch at descriptor 0x{:X}",
                check.descriptor
            ));
        }
    }
    Ok(())
}

fn require_known_software(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != 0x400000 || bytes[0x20025..0x2002c] != [0, 0, 0x1c, 0x9f, 0x1d, 0x96, 1] {
        return Err("Image preflight is limited to the inspected N20 software".into());
    }
    Ok(())
}

/// Necessary file preflight only. Both descriptor and header checks must pass;
/// this does not approve signatures, ECU acceptance, erase or recovery.
pub(crate) fn require_known_image_checks(bytes: &[u8]) -> Result<(), String> {
    require_known_software(bytes)?;
    require_known_checks(&inspect(bytes)?)?;
    require_header_checks(bytes)
}

fn raw_crc32(bytes: &[u8], mut crc: u32) -> u32 {
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb88320
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[derive(Debug)]
pub(crate) struct CvnCheck {
    pub name: &'static str,
    pub stored_offset: usize,
    pub stored: u32,
    pub calculated: u32,
}

/// Exact observed N20 software/table only. End addresses are EXCLUSIVE,
/// unlike the inclusive checksum descriptors above. No values are patched.
pub(crate) fn inspect_cvn(bytes: &[u8]) -> Result<Vec<CvnCheck>, String> {
    if bytes.len() != 0x400000 || bytes[0x20025..0x2002c] != [0, 0, 0x1c, 0x9f, 0x1d, 0x96, 1] {
        return Err("CVN observation is limited to the inspected N20 software token".into());
    }
    let expected = [
        0x80180000u32,
        0x801ffb78,
        0x80020000,
        0x8017fb78,
        0x80220000,
        0x803ffb78,
        0x80000000,
        0x8000fb78,
        0x8000fefc,
        0x8000ff00,
        0x803ffefc,
        0x803fff00,
        0x801ffefc,
        0x801fff00,
    ];
    if expected
        .iter()
        .enumerate()
        .any(|(i, v)| word(bytes, 0x4cdd8 + i * 4) != *v)
    {
        return Err("Observed CVN address table differs".into());
    }
    let mut checks = Vec::new();
    for (name, stored_offset, regions) in [
        ("startup", 0xfefc, vec![(0, 0xfb78)]),
        (
            "software",
            0x3ffefc,
            vec![(0x20000, 0x17fb78), (0x220000, 0x3ffb78)],
        ),
        ("calibration", 0x1ffefc, vec![(0x180000, 0x1ffb78)]),
    ] {
        let state = regions.iter().fold(0xffffffff, |state, (start, end)| {
            raw_crc32(&bytes[*start..*end], state)
        });
        checks.push(CvnCheck {
            name,
            stored_offset,
            stored: word(bytes, stored_offset),
            calculated: !state,
        });
    }
    Ok(checks)
}

pub(crate) fn summary(bytes: &[u8]) -> serde_json::Value {
    let headers = header_summary(bytes);
    let cvn = match inspect_cvn(bytes) {
        Ok(checks) => {
            serde_json::json!({"status":"observed_table", "values":checks.iter().map(|c|serde_json::json!({
            "name":c.name,"stored_offset":c.stored_offset,"stored_little_endian":format!("{:08X}",c.stored),
            "calculated":format!("{:08X}",c.calculated),"matches":c.stored==c.calculated})).collect::<Vec<_>>() })
        }
        Err(detail) => serde_json::json!({"status":"unavailable","detail":detail}),
    };
    match inspect(bytes) {
        Err(detail) => {
            serde_json::json!({"status":"unavailable","detail":detail,"header_checks":headers,"ecu_integrity_approved":false})
        }
        Ok(checks) => serde_json::json!({
            "status":if checks.iter().all(|c|c.matches()==Some(true)){"descriptor_checks_match"}else{"descriptor_checks_differ_or_unavailable"},
            "ecu_integrity_approved":false,
            "candidate_cvns":cvn,
            "header_checks":headers,
            "checks":checks.iter().map(|c|serde_json::json!({"descriptor_offset":c.descriptor,
                "file_start":c.start,"file_end_inclusive":c.end_inclusive,"algorithm":c.algorithm,
                "calculated":c.calculated.map(|v|format!("{v:08X}")),"expected":format!("{:08X}",c.expected),
                "matches":c.matches()})).collect::<Vec<_>>()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Captured header-only vectors from the immutable a2b887...255b BIN.
    // Expected spans/results independently reproduced with Python binascii.
    fn header_image() -> Vec<u8> {
        let mut bytes = vec![0; 0x400000];
        for (base, hex) in [
            (0, "3000000004fc00000000028000fc008008020080000000000a004d455644313732395f5f0600001901013102020000005fca03323004020000000080fffb0080fecadefafeaffeca0000000074fb008000100000310412007800008003020080fecadefafeaffeca00000000000000000010000019ba4561"),
            (0x20000, "4000000004fc15000000228000fc1780a00002809800028004024d455644313732395f5f0800001c9f1d9601030000004533afb64004020000000280fffb1780fecadefafeaffeca78fb008074fb1780101000004104040028aa058047ff0680fecadefafeaffeca00000000000000001010000042040400502f0280d7660280fecadefafeaffeca0000000000000000011000008c4a5044"),
            (0x180000, "6000000004fc07000000000000fc1f800000000000000000000031305357303137323433afafafafafafafaf0200000026ed2ad06004000000001880fffb1f80fecadefafeaffeca78fb3f8074fb1f801010000061040400c4ab1b80ffbd1b80fecadefafeaffeca0000000000000000101000008e982162"),
            (0x220000, "5000000004fc1d000000188000fc3f80000000000000000000004d455644313732395f5f0800001c9f1d9601010000009f374d0b5004020000002280fffb3f80fecadefafeaffeca78fb178074fb3f801010000075e02d3f"),
        ] {
            for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
                bytes[base + i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
            }
        }
        bytes
    }

    #[test]
    fn captured_header_vectors_match_all_eight_source_derived_spans_without_mutation() {
        let bytes = header_image();
        let before = bytes.clone();
        let checks = inspect_headers(&bytes).unwrap();
        assert_eq!(checks.len(), 8);
        assert_eq!(
            checks.iter().map(|c| c.end_exclusive).collect::<Vec<_>>(),
            [0x34, 0x78, 0x20034, 0x20098, 0x180034, 0x180078, 0x220034, 0x220058]
        );
        assert!(checks.iter().all(|c| c.calculated == 0xcafeaffe));
        require_header_checks(&bytes).unwrap();
        assert_eq!(before, bytes);
        let report = summary(&bytes);
        assert_eq!(report["header_checks"]["status"], "header_crc_checks_match");
        assert_eq!(report["header_checks"]["ecu_integrity_approved"], false);
        assert_eq!(report["ecu_integrity_approved"], false);
    }

    #[test]
    fn header_fields_and_crc_words_fail_with_the_bound_header_and_span() {
        for (header, _) in HEADER_LAYOUT {
            for relative in [0x10, 0x30] {
                let mut bytes = header_image();
                bytes[header + relative] ^= 1;
                let error = require_header_checks(&bytes).unwrap_err();
                assert!(error.contains(&format!("0x{header:X}")));
                assert!(error.contains("fixed_header"));
                assert_eq!(header_summary(&bytes)["status"], "header_crc_checks_differ");
            }
        }
    }

    #[test]
    fn descriptor_header_crc_includes_its_last_word_and_excludes_the_next_byte() {
        for (header, count) in HEADER_LAYOUT {
            let end = header + count as usize * 0x20 + 0x38;
            let mut bytes = header_image();
            bytes[end] ^= 1;
            require_header_checks(&bytes).unwrap();
            bytes[end - 1] ^= 1;
            let checks = inspect_headers(&bytes).unwrap();
            let pair: Vec<_> = checks.iter().filter(|c| c.header == header).collect();
            assert_eq!(pair[0].calculated, HEADER_CRC_TARGET);
            assert_ne!(pair[1].calculated, HEADER_CRC_TARGET);
            assert!(require_header_checks(&bytes)
                .unwrap_err()
                .contains("header_and_descriptors"));
        }
    }

    #[test]
    fn header_checks_reject_unknown_software_and_unreviewed_counts_without_choosing_coverage() {
        assert!(inspect_headers(&[0; 4]).is_err());
        let mut bytes = header_image();
        bytes[0x2002b] ^= 1;
        assert!(inspect_headers(&bytes).unwrap_err().contains("software"));
        for (header, _) in HEADER_LAYOUT {
            for count in [0u32, 0xffff_ffff, 0x10002] {
                let mut bytes = header_image();
                bytes[header + 0x2c..header + 0x30].copy_from_slice(&count.to_le_bytes());
                assert!(inspect_headers(&bytes)
                    .unwrap_err()
                    .contains("descriptor count"));
                assert_eq!(header_summary(&bytes)["status"], "unavailable");
            }
        }
    }

    fn image() -> Vec<u8> {
        let mut b = vec![0; 0x400000];
        b[26..36].copy_from_slice(b"MEVD1729__");
        // ADD32 test vector: seed + this word == expected (mod 2^32).
        b[0x1000..0x1004].copy_from_slice(&0xcafeaffeu32.wrapping_sub(0xfadecafe).to_le_bytes());
        for (h, n) in [(0, 2u32), (0x20000, 3), (0x180000, 2), (0x220000, 1)] {
            b[h + 0x2c..h + 0x30].copy_from_slice(&n.to_le_bytes());
            for i in 0..n as usize {
                let p = h + 0x34 + i * 32;
                for (o, v) in [
                    (4, 0x80001000u32),
                    (8, 0x80001003),
                    (12, 0xfadecafe),
                    (16, 0xcafeaffe),
                ] {
                    b[p + o..p + o + 4].copy_from_slice(&v.to_le_bytes());
                }
                b[p + 28] = 1;
            }
        }
        b
    }
    #[test]
    fn verifies_records_and_detects_changed_payload_without_mutating_input() {
        let mut b = image();
        let before = b.clone();
        let checks = inspect(&b).unwrap();
        assert_eq!(checks.len(), 8);
        assert!(checks.iter().all(|c| c.matches() == Some(true)));
        assert_eq!(b, before);
        b[0x1000] ^= 1;
        assert!(inspect(&b)
            .unwrap()
            .iter()
            .all(|c| c.matches() == Some(false)));
        assert_eq!(summary(&before)["ecu_integrity_approved"], false);
    }
    #[test]
    fn malformed_ranges_and_unknown_algorithms_never_report_approval() {
        let mut b = image();
        b[0x34 + 28] = 99;
        assert_eq!(inspect(&b).unwrap()[0].matches(), None);
        b[0x34 + 8..0x34 + 12].copy_from_slice(&0x80400000u32.to_le_bytes());
        assert!(inspect(&b).is_err());
        assert!(inspect(&[0; 4]).is_err());
    }
    #[test]
    fn crc_uses_raw_seeded_state_and_add16_weights_the_last_halfword() {
        assert_eq!(raw_crc32(b"123456789", 0xffffffff), 0x340bc6d9);
        let mut b = image();
        b[0x34 + 28] = 0x10;
        b[0x1000..0x1004].copy_from_slice(&[1, 0, 2, 0]);
        assert_eq!(
            inspect(&b).unwrap()[0].calculated,
            Some(0xfadecafeu32.wrapping_add(1).wrapping_add(2 << 16))
        );
    }

    #[test]
    fn preflight_requires_exact_coverage_even_when_the_calculation_matches() {
        let mut checks: Vec<Check> = KNOWN_DESCRIPTORS
            .iter()
            .map(|&(descriptor, start, end_inclusive, algorithm)| Check {
                descriptor,
                start,
                end_inclusive,
                algorithm,
                calculated: Some(7),
                expected: 7,
            })
            .collect();
        require_known_checks(&checks).unwrap();
        checks[5].start += 4;
        assert!(require_known_checks(&checks)
            .unwrap_err()
            .contains("coverage"));
        checks[5].start -= 4;
        checks[5].calculated = Some(8);
        assert!(require_known_checks(&checks)
            .unwrap_err()
            .contains("checksum mismatch"));
        checks[5].calculated = None;
        assert!(require_known_checks(&checks).is_err());
        assert!(require_known_checks(&checks[..7]).is_err());
    }

    #[test]
    fn preflight_rejects_unknown_software_and_relocated_test_descriptors() {
        assert!(require_known_image_checks(&[0; 4]).is_err());
        let mut b = image();
        assert!(require_known_image_checks(&b).is_err());
        b[0x20025..0x2002c].copy_from_slice(&[0, 0, 0x1c, 0x9f, 0x1d, 0x96, 1]);
        // These synthetic checks all match, but cover the wrong ranges.
        assert!(inspect(&b)
            .unwrap()
            .iter()
            .all(|c| c.matches() == Some(true)));
        assert!(require_known_image_checks(&b)
            .unwrap_err()
            .contains("coverage"));
    }

    #[test]
    fn cvn_uses_exclusive_boundaries_and_keeps_stored_values_separate() {
        let mut b = image();
        b[0x20025..0x2002c].copy_from_slice(&[0, 0, 0x1c, 0x9f, 0x1d, 0x96, 1]);
        for (i, value) in [
            0x80180000u32,
            0x801ffb78,
            0x80020000,
            0x8017fb78,
            0x80220000,
            0x803ffb78,
            0x80000000,
            0x8000fb78,
            0x8000fefc,
            0x8000ff00,
            0x803ffefc,
            0x803fff00,
            0x801ffefc,
            0x801fff00,
        ]
        .iter()
        .enumerate()
        {
            b[0x4cdd8 + i * 4..0x4cddc + i * 4].copy_from_slice(&value.to_le_bytes());
        }
        let before = inspect_cvn(&b).unwrap();
        let old = before[2].calculated;
        b[0x1ffb78] ^= 1; // Signature-adjacent byte excluded by observed table.
        assert_eq!(inspect_cvn(&b).unwrap()[2].calculated, old);
        b[0x1ffb77] ^= 1;
        assert_ne!(inspect_cvn(&b).unwrap()[2].calculated, old);
        b[0x4cdd8] ^= 1;
        assert!(inspect_cvn(&b).is_err());
    }
}

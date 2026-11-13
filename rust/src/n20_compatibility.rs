//! Artifact compatibility is independent of programming-procedure approval.
//! No inferred compatibility from filenames, header markers or matching IDs.
use crate::{n20_partial::PartialImage, programming::ExactIdentity};
use serde_json::{json, Value};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Partial,
    Full,
    Recovery,
}
impl Operation {
    fn label(self) -> &'static str {
        match self {
            Self::Partial => "partial",
            Self::Full => "full",
            Self::Recovery => "recovery",
        }
    }
}

struct Rule<'a> {
    id: &'a str,
    evidence: &'a str,
    operation: Operation,
    identity: ExactIdentity<'a>,
    image_sha256: &'a str,
    image_software: &'a str,
    image_calibration: &'a str,
}

pub(crate) const BENCH_IDENTITY: ExactIdentity<'static> = ExactIdentity {
    vin: "WBA3A52010F360747",
    family: "MEVD17.2.9",
    bosch_hardware: "unverified",
    bmw_hardware: "000019A6001019003",
    software: "00001C9F029150001",
    calibration: "00001CDB029150003",
    bootloader: "00001901001049002",
};

// The captured bench identity and the exact reference image traced for
// indexed erase and CheckMemory. This entry enables an experimental partial
// write on this bench combination only.
const APPROVED: &[Rule<'static>] = &[Rule {
    id: "n20-bench-reference-partial",
    evidence: "N20_CHECKMEMORY_SIGNATURE_TRACE_2026-11-06",
    operation: Operation::Partial,
    identity: BENCH_IDENTITY,
    image_sha256: "a2b88727777c5dd01c888691f3d3eff583c690e9eb6149b8ccdeaf06834b255b",
    image_software: "00001C9F1D9601",
    image_calibration: "00001CDB1D9607",
}];

fn compact(value: &str) -> Option<String> {
    if value.len() != 17 || !value.is_ascii() || !value[..8].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let mut token = value[..8].to_ascii_uppercase();
    for offset in [8, 11, 14] {
        let field = &value[offset..offset + 3];
        if !field.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        token.push_str(&format!("{:02X}", field.parse::<u8>().ok()?));
    }
    Some(token)
}

pub(crate) struct Assessment {
    pub identity_checks_passed: bool,
    pub approved: bool,
    pub report: Value,
}
pub(crate) fn assess(
    image: &PartialImage,
    identity: &ExactIdentity<'_>,
    operation: Operation,
) -> Assessment {
    evaluate(
        &image.sha256,
        &image.software_token,
        &image.calibration_token(),
        identity,
        operation,
        APPROVED,
    )
}

fn evaluate(
    hash: &str,
    software: &str,
    calibration: &str,
    identity: &ExactIdentity<'_>,
    operation: Operation,
    rules: &[Rule<'_>],
) -> Assessment {
    let mut reasons = Vec::new();
    if identity.family != "MEVD17.2.9" {
        reasons.push("Live DME family does not match the validated BIN layout");
    }
    let live_software = compact(identity.software);
    if live_software.as_deref() != Some(software) {
        reasons.push("File software token does not match a valid live DME software identifier");
    }
    if compact(identity.calibration).is_none()
        || compact(identity.bmw_hardware).is_none()
        || compact(identity.bootloader).is_none()
    {
        reasons
            .push("Live calibration, BMW hardware or bootloader identity is missing or malformed");
    }
    let identity_checks_passed = reasons.is_empty();
    let rule = rules.iter().find(|r| {
        !r.id.trim().is_empty()
            && !r.evidence.trim().is_empty()
            && r.operation == operation
            && r.image_sha256.len() == 64
            && r.image_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            && r.image_sha256.eq_ignore_ascii_case(hash)
            && r.image_software == software
            && r.image_calibration == calibration
            && r.identity.vin == identity.vin
            && r.identity.family == identity.family
            && r.identity.bmw_hardware == identity.bmw_hardware
            && r.identity.bootloader == identity.bootloader
            && r.identity.software == identity.software
            && r.identity.calibration == identity.calibration
    });
    if rule.is_none() {
        reasons.push("No reviewed compatibility rule binds this exact BIN, calibration transition, DME identity and operation");
    }
    let approved = reasons.is_empty();
    Assessment {
        identity_checks_passed,
        approved,
        report: json!({"schema":"n20-bin-compatibility-v1",
        "status":if approved {"compatible_under_reviewed_rule"} else {"unsupported"},
        "compatible":approved,"programming_approved":false,"operation":operation.label(),
        "identity_checks_passed":identity_checks_passed,
        "bin_sha256":hash,"file_software_token":software,"file_calibration_token":calibration,
        "layout":"mevd1729-4mib-legacy-partial-v1", "layout_established_by":"PartialImage validation",
        "live_identity":{"vin":identity.vin,"family":identity.family,"bosch_hardware":identity.bosch_hardware,
            "bmw_hardware":identity.bmw_hardware,"bootloader":identity.bootloader,"software":identity.software,"calibration":identity.calibration},
        "rule_id":rule.map(|r|r.id),"evidence_id":rule.map(|r|r.evidence),"blocking_reasons":reasons,
        "limitations":"Layout and matching IDs do not authenticate file provenance or establish ECU acceptance. File hardware is not extracted; any approved association must come from reviewed evidence."}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bench_reference_only_enables_partial_for_the_exact_image_and_identity() {
        let reference = &APPROVED[0];
        let assess = |hash: &str, identity: &ExactIdentity<'_>, operation| {
            evaluate(
                hash,
                reference.image_software,
                reference.image_calibration,
                identity,
                operation,
                APPROVED,
            )
            .approved
        };
        assert!(assess(reference.image_sha256, &BENCH_IDENTITY, Operation::Partial));
        assert!(!assess(reference.image_sha256, &BENCH_IDENTITY, Operation::Full));
        assert!(!assess(reference.image_sha256, &BENCH_IDENTITY, Operation::Recovery));
        assert!(!assess(&"a".repeat(64), &BENCH_IDENTITY, Operation::Partial));
        let mut other = BENCH_IDENTITY;
        other.calibration = "00001CDB029150007";
        assert!(!assess(reference.image_sha256, &other, Operation::Partial));
    }
    fn identity() -> ExactIdentity<'static> {
        ExactIdentity {
            vin: "WBA3A52010F360747",
            family: "MEVD17.2.9",
            bosch_hardware: "test-only-bosch",
            bmw_hardware: "000019A6001019003",
            bootloader: "00001901001049002",
            software: "00001C9F029150001",
            calibration: "00001CDB029150003",
        }
    }
    fn rule() -> Rule<'static> {
        Rule {
            id: "test-only",
            evidence: "synthetic-evidence",
            operation: Operation::Partial,
            identity: identity(),
            image_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            image_software: "00001C9F1D9601",
            image_calibration: "00001CDB1D9607",
        }
    }
    fn check(id: &ExactIdentity<'_>, op: Operation, rules: &[Rule<'_>]) -> Assessment {
        evaluate(
            &"a".repeat(64),
            "00001C9F1D9601",
            "00001CDB1D9607",
            id,
            op,
            rules,
        )
    }
    #[test]
    fn matching_ids_without_reviewed_rule_do_not_approve() {
        let mut id = identity();
        id.bosch_hardware = "unverified";
        let result = check(&id, Operation::Partial, APPROVED);
        assert!(result.identity_checks_passed);
        assert!(!result.approved);
        assert_eq!(result.report["blocking_reasons"], json!([
            "No reviewed compatibility rule binds this exact BIN, calibration transition, DME identity and operation"
        ]));
        assert_eq!(result.report["programming_approved"], false);
    }
    #[test]
    fn explicit_calibration_transition_is_allowed_only_by_exact_artifact_rule() {
        let mut id = identity();
        id.bosch_hardware = "unverified";
        assert!(check(&id, Operation::Partial, &[rule()]).approved);
        let mut r = rule();
        r.image_calibration = "00001CDB1D9603";
        assert!(!check(&identity(), Operation::Partial, &[r]).approved);
        let mut r = rule();
        r.image_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert!(!check(&identity(), Operation::Partial, &[r]).approved);
    }
    #[test]
    fn rule_cannot_cross_hardware_software_bootloader_or_operation() {
        for field in 0..4 {
            let mut id = identity();
            match field {
                0 => id.bmw_hardware = "000019A6001019004",
                1 => id.bootloader = "00001901001049003",
                2 => id.software = "00001C9F029150002",
                _ => id.calibration = "00001CDB029150004",
            };
            assert!(!check(&id, Operation::Partial, &[rule()]).approved);
        }
        assert!(!check(&identity(), Operation::Recovery, &[rule()]).approved);
        assert!(!check(&identity(), Operation::Full, &[rule()]).approved);
    }
    #[test]
    fn missing_identity_or_empty_evidence_never_approves() {
        let mut id = identity();
        id.bmw_hardware = "";
        let mut r = rule();
        r.identity = id.clone();
        assert!(!check(&id, Operation::Partial, &[]).identity_checks_passed);
        assert!(!check(&id, Operation::Partial, &[r]).approved);
        let mut r = rule();
        r.evidence = " ";
        assert!(!check(&identity(), Operation::Partial, &[r]).approved);
        for bad in [
            "00001C9F999150001",
            "00001C9F+29150001",
            "é0001C9F029150001",
            "",
        ] {
            assert!(compact(bad).is_none());
        }
    }
}

"""Offline evidence inventory. Never imports profiles, connects, or grants approval."""
import argparse
import hashlib
import json
import re
from pathlib import Path

CATEGORIES = (
    "bosch_identity", "unlock_state", "artifact_compatibility", "erase_scope_and_result",
    "image_acceptance", "electrical_policy", "session_timing", "ignition_and_conditions",
    "post_write_verification", "interruption_recovery",
)
IDENTITY_FIELDS = ("vin", "hardware", "bootloader", "software", "calibration")
HASH = re.compile(r"[0-9a-fA-F]{64}\Z")


def digest(path):
    if not path.is_file() or path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("Missing file or file exceeds 256 MiB")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def confined(root, relative):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("Expected a relative evidence path")
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("Evidence path escapes its directory")
    return path


def load(path):
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("JSON exceeds 1 MiB")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def bad_constant(value):
        raise ValueError(f"Invalid JSON constant: {value}")

    value = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique,
                       parse_constant=bad_constant)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def template(operation_hash, operation):
    return {"schema": "n20-profile-evidence-v1", "operation_sha256": operation_hash,
            "operation_type": "recovery" if operation.get("schema") == "n20-live-recovery-v1" else "full" if operation.get("schema") == "n20-full-operation-v1" else "partial",
            "bin_sha256": operation.get("bin_sha256"),
            "identity": {key: operation.get(key) for key in IDENTITY_FIELDS},
            "categories": {key: {"summary": "", "attachments": []} for key in CATEGORIES}}


def validate(operation_directory, dossier_path=None):
    root = Path(operation_directory).resolve()
    issues, files, categories = [], [], []
    op, op_hash = {}, None

    def issue(code, detail):
        issues.append({"code": code, "detail": detail})

    try:
        path = confined(root, "operation.json")
        op_hash, op = digest(path), load(path)
        if op.get("schema") not in ("n20-operation-v1", "n20-live-recovery-v1", "n20-full-operation-v1"):
            issue("operation_schema", "Unknown operation schema")
        for field in IDENTITY_FIELDS:
            value = op.get(field)
            pattern = r"[A-HJ-NPR-Z0-9]{17}" if field == "vin" else r"[0-9A-Fa-f]{8}[0-9]{9}"
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                issue("identity_invalid", f"Missing or malformed {field}")
        image = confined(root, "selected.bin")
        actual = digest(image)
        files.append({"path": "selected.bin", "sha256": actual})
        if image.stat().st_size != 0x400000 or actual != str(op.get("bin_sha256", "")).lower():
            issue("image_binding", "BIN length or hash differs from operation")
        # Inventory only: Rust's image/coding/journal parsers remain authoritative.
        coding_name = "original-coding.json" if op.get("schema") == "n20-live-recovery-v1" else "coding.json"
        coding_path = confined(root, coding_name)
        coding = load(coding_path)
        files.append({"path": coding_name, "sha256": digest(coding_path)})
        if coding.get("vin") != op.get("vin"):
            issue("coding_vin", "Coding snapshot VIN differs from operation")
        if op.get("schema") == "n20-full-operation-v1":
            coding_binding = load(confined(root, "coding-binding.json"))
            if str(coding_binding.get("operation_binding_sha256", "")).lower() != op_hash or coding_binding.get("coding_sha256") != digest(coding_path):
                issue("coding_binding", "Full-flash coding binding differs from saved operation/snapshot")
    except (OSError, ValueError) as error:
        issue("operation_files", str(error))

    # New reports bind to exact operation bytes; old/missing reports are explicit gaps.
    try:
        observations_path = confined(root, "preflight-observations.json")
        observations = load(observations_path)
        files.append({"path": "preflight-observations.json", "sha256": digest(observations_path)})
        for section in ("identity_evidence", "bin_compatibility"):
            value = observations.get(section)
            if not isinstance(value, dict):
                issue("observation_missing", f"Missing {section}")
                continue
            if not op_hash or str(value.get("operation_binding_sha256", "")).lower() != op_hash:
                issue("observation_binding", f"{section} is not bound to operation.json")
            vin = value.get("vin") if section == "identity_evidence" else value.get("live_identity", {}).get("vin") if isinstance(value.get("live_identity"), dict) else None
            if vin != op.get("vin"):
                issue("observation_vin", f"{section} VIN differs from operation")
            if section == "bin_compatibility":
                if str(value.get("bin_sha256", "")).lower() != str(op.get("bin_sha256", "")).lower():
                    issue("observation_image", "Compatibility report BIN differs from operation")
                if value.get("compatible") is not True:
                    issue("compatibility_unapproved", "Compatibility report does not establish an approved artifact/DME rule")
            else:
                for key in ("bosch_hardware_status", "unlock_status"):
                    if value.get(key) != "verified":
                        issue("identity_unverified", f"{key} remains unverified; a reference match is insufficient")
    except (OSError, ValueError) as error:
        issue("observations_unavailable", str(error))

    dossier, dossier_root = {}, root
    if dossier_path:
        try:
            dossier_file = Path(dossier_path).resolve()
            dossier, dossier_root = load(dossier_file), dossier_file.parent
            files.append({"path": str(dossier_file), "sha256": digest(dossier_file)})
            expected = template(op_hash, op)
            for field in ("schema", "operation_sha256", "operation_type", "bin_sha256", "identity"):
                if dossier.get(field) != expected[field] or op_hash is None:
                    issue("dossier_binding", f"Dossier {field} does not match operation")
        except (OSError, ValueError) as error:
            issue("dossier_invalid", str(error))
    else:
        issue("dossier_missing", "No independent profile-evidence dossier supplied")

    entries = dossier.get("categories", {})
    if not isinstance(entries, dict):
        issue("dossier_categories", "Categories must be an object")
        entries = {}
    for name in CATEGORIES:
        entry, errors, attachments = entries.get(name), [], []
        if not isinstance(entry, dict):
            errors.append("Category missing")
        else:
            if not isinstance(entry.get("summary"), str) or not entry["summary"].strip():
                errors.append("Evidence interpretation missing")
            refs = entry.get("attachments")
            if not isinstance(refs, list) or not 1 <= len(refs) <= 64:
                errors.append("Expected 1..64 evidence attachments")
            else:
                for ref in refs:
                    try:
                        if not isinstance(ref, dict) or not isinstance(ref.get("sha256"), str) or not HASH.fullmatch(ref["sha256"]):
                            raise ValueError("Malformed attachment or SHA-256")
                        path = confined(dossier_root, ref.get("path"))
                        actual = digest(path)
                        if actual != ref["sha256"].lower():
                            raise ValueError("Attachment hash mismatch")
                        attachments.append({"path": ref["path"], "sha256": actual})
                    except (OSError, ValueError) as error:
                        errors.append(str(error))
        categories.append({"category": name, "status": "incomplete" if errors else "requires_independent_review",
                           "problems": errors, "attachments": attachments})

    complete = not issues and all(not item["problems"] for item in categories)
    return {"schema": "n20-profile-evidence-report-v1", "operation_directory": str(root),
            "operation_sha256": op_hash, "inventory_complete": complete,
            "status": "requires_independent_review" if complete else "incomplete",
            "profile_registration_approved": False, "ecu_programming_approved": False,
            "issues": issues, "categories": categories, "files": files,
            "limitations": "Hashes establish local byte bindings only. Claims, captures, identity, erase extent, acceptance and recovery semantics require independent expert review. This tool does not validate Rust coding/image/journal semantics or register profiles."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation_directory", type=Path)
    parser.add_argument("--dossier", type=Path)
    parser.add_argument("--output", type=Path, help="Create a new report; never overwrite")
    parser.add_argument("--template", type=Path, help="Create a blank dossier; never overwrite")
    args = parser.parse_args()
    try:
        if args.template:
            root = args.operation_directory.resolve()
            path = confined(root, "operation.json")
            blank = template(digest(path), load(path))
            with args.template.open("x", encoding="utf-8") as stream:
                json.dump(blank, stream, indent=2)
                stream.write("\n")
        report = validate(args.operation_directory, args.dossier)
        result = json.dumps(report, indent=2) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(result)
        else:
            print(result, end="")
        return 0 if report["inventory_complete"] else 2
    except (OSError, ValueError) as error:
        parser.exit(1, f"Evidence validator: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())

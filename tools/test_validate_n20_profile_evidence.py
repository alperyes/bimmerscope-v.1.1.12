import json
import tempfile
import unittest
from pathlib import Path

from validate_n20_profile_evidence import CATEGORIES, digest, load, template, validate


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "selected.bin").write_bytes(bytes(0x400000))
        self.op = {"schema": "n20-operation-v1", "vin": "WBA3A52010F360747",
                   "hardware": "000019A6001019003", "bootloader": "00001901001049002",
                   "software": "00001C9F029150001", "calibration": "00001CDB029150003",
                   "bin_sha256": digest(self.root / "selected.bin")}
        self.write("operation.json", self.op)
        self.binding = digest(self.root / "operation.json")
        self.write("coding.json", {"vin": self.op["vin"]})
        self.observations = {"identity_evidence": {"vin": self.op["vin"],
            "operation_binding_sha256": self.binding, "bosch_hardware_status": "unverified",
            "unlock_status": "unverified", "unlock_reference_status": "reference_match"},
            "bin_compatibility": {"operation_binding_sha256": self.binding,
            "live_identity": {"vin": self.op["vin"]}, "bin_sha256": self.op["bin_sha256"], "compatible": False}}
        self.write("preflight-observations.json", self.observations)

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding="utf-8")

    def dossier(self):
        value = template(self.binding, self.op)
        (self.root / "capture.bin").write_bytes(b"synthetic test evidence, not hardware proof")
        for name in CATEGORIES:
            value["categories"][name] = {"summary": "Synthetic test interpretation",
                "attachments": [{"path": "capture.bin", "sha256": digest(self.root / "capture.bin")}]}
        return value

    def test_reference_match_and_existing_files_never_establish_approval(self):
        report = validate(self.root)
        self.assertFalse(report["inventory_complete"])
        self.assertFalse(report["profile_registration_approved"])
        self.assertIn("identity_unverified", {issue["code"] for issue in report["issues"]})
        self.assertEqual(len(report["categories"]), 10)

    def test_full_operation_uses_current_coding_binding_and_full_dossier_kind(self):
        self.op["schema"] = "n20-full-operation-v1"
        self.write("operation.json", self.op)
        binding = digest(self.root / "operation.json")
        self.write("coding-binding.json", {"operation_binding_sha256": binding.upper(), "coding_sha256": digest(self.root / "coding.json")})
        report = validate(self.root)
        codes = {item["code"] for item in report["issues"]}
        self.assertNotIn("operation_schema", codes)
        self.assertNotIn("coding_binding", codes)
        self.assertEqual(template(binding, self.op)["operation_type"], "full")
        self.write("coding.json", {"vin": self.op["vin"], "changed": True})
        self.assertIn("coding_binding", {item["code"] for item in validate(self.root)["issues"]})

    def test_complete_claimed_inventory_still_requires_independent_review(self):
        self.observations["identity_evidence"].update(bosch_hardware_status="verified", unlock_status="verified")
        self.observations["bin_compatibility"]["compatible"] = True
        self.write("preflight-observations.json", self.observations)
        self.write("dossier.json", self.dossier())
        report = validate(self.root, self.root / "dossier.json")
        self.assertTrue(report["inventory_complete"])
        self.assertEqual(report["status"], "requires_independent_review")
        self.assertFalse(report["ecu_programming_approved"])
        self.assertFalse(report["profile_registration_approved"])

    def test_swapped_operation_image_and_vin_are_reported(self):
        self.observations["identity_evidence"]["operation_binding_sha256"] = "0" * 64
        self.observations["bin_compatibility"]["live_identity"]["vin"] = "OTHER"
        self.write("preflight-observations.json", self.observations)
        with (self.root / "selected.bin").open("r+b") as stream:
            stream.write(b"x")
        report = validate(self.root)
        codes = {issue["code"] for issue in report["issues"]}
        self.assertTrue({"observation_binding", "observation_vin", "image_binding"} <= codes)

    def test_dossier_binding_and_attachment_hash_fail_closed(self):
        value = self.dossier()
        value["operation_sha256"] = "0" * 64
        value["categories"]["image_acceptance"]["attachments"][0]["sha256"] = "0" * 64
        self.write("dossier.json", value)
        report = validate(self.root, self.root / "dossier.json")
        self.assertIn("dossier_binding", {item["code"] for item in report["issues"]})
        self.assertEqual(report["categories"][4]["status"], "incomplete")

    def test_path_escape_and_missing_category_are_rejected(self):
        value = self.dossier()
        value["categories"]["bosch_identity"]["attachments"][0]["path"] = "../outside.bin"
        del value["categories"]["interruption_recovery"]
        self.write("dossier.json", value)
        report = validate(self.root, self.root / "dossier.json")
        self.assertIn("escapes", " ".join(report["categories"][0]["problems"]))
        self.assertEqual(report["categories"][-1]["status"], "incomplete")

    def test_missing_malformed_and_duplicate_json_report_errors(self):
        (self.root / "operation.json").write_text('{"vin":"one","vin":"two"}', encoding="utf-8")
        report = validate(self.root)
        self.assertFalse(report["inventory_complete"])
        self.assertIn("operation_files", {item["code"] for item in report["issues"]})
        with self.assertRaises(ValueError):
            load(self.root / "operation.json")


if __name__ == "__main__":
    unittest.main()

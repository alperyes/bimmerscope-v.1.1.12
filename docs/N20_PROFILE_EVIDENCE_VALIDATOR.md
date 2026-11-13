# Offline N20 profile-evidence validator

Run with Python 3.12 or later from the project root:

```powershell
python tools/validate_n20_profile_evidence.py "C:\path\to\n20-operation-directory" --output "C:\review\report.json"
```

It reads operation.json, selected.bin, coding.json (original-coding.json for recovery), and preflight-observations.json. It checks the BIN's length/hash, identity field syntax, coding VIN and observation bindings. This is an inventory tool: Rust remains authoritative for image descriptors, coding content, stage/transfer journals and programming support.

Create a blank independent-evidence dossier:

```powershell
python tools/validate_n20_profile_evidence.py "C:\path\to\n20-operation-directory" --template "C:\review\profile-evidence.json"
```

The template binds to the exact operation bytes, BIN and live identity. For each category, supply an interpretation in `summary` and `attachments` entries with `path` and `sha256`. Attachment paths are relative to the dossier directory; escapes, missing files, invalid hashes and mismatched bytes are rejected. Attachments are capped at 64 per category and 256 MiB each. JSON inputs are capped at 1 MiB; duplicate keys are rejected. Copy or export appropriately scoped capture evidence rather than changing the saved operation files.

Validate the dossier with the saved operation:

```powershell
python tools/validate_n20_profile_evidence.py "C:\path\to\n20-operation-directory" --dossier "C:\review\profile-evidence.json" --output "C:\review\report-with-dossier.json"
```

Reports and templates are created exclusively; existing files are never overwritten. Exit code 2 means incomplete/inconsistent evidence, 1 means a command/output failure, and 0 means the inventory is complete for independent review. A complete inventory still has `profile_registration_approved=false` and `ecu_programming_approved=false`.

Required categories are Bosch identity, unlock state, artifact compatibility, erase scope/result, image acceptance, electrical policy, session timing, ignition/conditions, post-write verification and interruption recovery. Summaries and hashed attachments do not prove their claims, establish independence or validate capture semantics. The tool never registers a profile, edits application gates, connects to an ECU or sends diagnostic requests.

Tests:

```powershell
python -m unittest discover -s tools -p test_validate_n20_profile_evidence.py -v
```

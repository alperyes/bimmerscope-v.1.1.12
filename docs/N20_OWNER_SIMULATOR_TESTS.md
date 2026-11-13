# Local execution-owner integration lab

Run from the project root:

```powershell
cargo test --manifest-path rust/Cargo.toml owner_simulator_tests
```

The suite calls the actual private partial and responding-recovery execution owners, with their real setup/download/coding/verification adapters, durable journals, stage events, security challenge broker and post-reset identity/readback logic. A test-only ECU model accepts HSFZ/UDS requests over ephemeral loopback TCP sockets. Its memory changes through erase/download/data operations; readback comes from that memory rather than a prearranged successful verification callback. It checks transfer lengths, block counters (including recovery counter wrap), distinct programming/coding authorization and coding-byte transformation.

Public start APIs always supply the native runtime and Flutter event sink. The simulator can supply private runtime/event dependencies only from its cfg(test) module; no CLI, Flutter API, production registry or profile field selects it. It never connects outside loopback. It skips physical reset delays; the pending-response test uses an actual delayed TCP reply.

Thirteen cases cover partial completion with a pending reply; rejected key calculation; erase rejection; lost, late or wrong data acknowledgement; CheckMemory failure; coding rejection; lost reset acknowledgement; partial readback mismatch; inability to create the final verification receipt; six-region recovery completion; and recovery software-region mismatch. Failed cases must not emit completion and must leave startup inspection blocked. Successful cases require all bytes, identity/coding verification and recorded-complete local history. Fresh subprocesses inspect both interrupted and completed persisted history without changing stage journals or opening vehicle sockets.

The two helper tests listed as ignored by the ordinary suite are invoked explicitly by their parent tests: one for OS lock behavior, one for restart inspection. They are not skipped coverage of those scenarios.

By default test directories are created under the system temporary directory and removed after checking their resolved parent and filename prefix. To retain reports, images and raw operation journals in a new directory:

```powershell
$env:BIMMERSCOPE_OWNER_SIM_REPORT_DIR = 'C:\path\to\new-lab-output'
cargo test --manifest-path rust/Cargo.toml --lib
```

Each case has a uniquely named directory with simulation-result.json and its saved operation subtree. Keep these synthetic fixtures out of application support storage; they are lab evidence, not vehicle operation history.

This deliberately tests the execution branch after support-profile matching. It does not approve a compatibility rule, register a production profile, authenticate a BIN, test the public preparation path as an accepted hardware combination, run Flutter's real security calculator, terminate Flutter during a transfer or establish physical ECU timing/recovery. Existing tests separately cover rejected public starts, compatibility gates and detailed stage/journal failures. The owner lab injects one completion-receipt storage failure; it does not claim OS storage failure at every possible owner instruction.

Installed Windows Tune remains +125. This work adds an integration lab and private test seams; no new app control or real programming support is distributed.

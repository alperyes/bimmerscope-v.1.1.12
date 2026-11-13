# BimmerScope versioning

The source of truth is the `version:` field in `pubspec.yaml`.

The current experimental workspace is `1.1.12-experimental.1+147`. Build numbers
are never reused. This work is on the `codex/experimental-v1.1.12` branch.

Distributed APK names use:

```text
BimmerScope-v<version-name>+<build-number>-<flavor>-<build-mode>.apk
```

For the current source tree, a Tune debug build is named:

```text
BimmerScope-v1.1.12-experimental.1+147-tune-debug.apk
```

The latest local Tune Windows x64 bundle is BimmerScope-v1.1.12-experimental.1+147-tune-reconnect-windows-x64. Build 147 allows reconnecting after a verified flash energy-mode rejection before programming starts. Build 146 shows the recorded flash stages. Build 145 adds a read-only Flash diagnostics page. Build 144 skips the auxiliary address for calibration-only setup on the documented N20 bench. Build 143 enables experimental calibration-only writing for the exact reference BIN. The write sequence passed the loopback simulator. Physical erase, transfer, readback and recovery remain unverified. Android remains +109.


## Git release safety

`main` is the release baseline. Keep experimental changes on the versioned
experimental branch; do not move or rewrite existing tags.

Build 143 exposes an experimental write for one exact N20 bench combination.
Production vehicle support requires validation on the target hardware.
```

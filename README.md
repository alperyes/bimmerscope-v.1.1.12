# BimmerScope

Experimental Flutter application with a Rust protocol core for BMW F-series vehicles over ENET/HSFZ. The current workspace is **1.1.12-experimental.1+99**. Version and APK naming rules are in [VERSIONING.md](VERSIONING.md).

## Current scope

- Live vehicle connection, monitoring, logging, and diagnostics.
- Tune workspace for imported stock files, read-only review, and tuner-request preparation.
- DME identity reads, guarded DME reset, and Read DME 2 memory capture with saved BIN sharing and deletion.
- N20 bench Read DME 2 capture range: `0x80180000`–`0x801FFBFF` (511 KiB). This is a partial memory region, not a complete ECU image.
- Core and Tune Android flavors share the same Flutter and Rust codebase.

Read DME 2 and the reset flow are experimental. Bench captures do not establish compatibility with the stock 2014 F82 M4. The F82 DME software and unlock state remain unverified. The current identity and memory-read features have not been validated on that car.

The Tune workspace provides preparation and review workflows. BimmerScope does not currently expose a validated vehicle flashing or calibration-writing workflow. The DME reset is a distinct, confirmed action and may reset other ECUs when sent to the broadcast destination; review the in-app warning before use.

## Build and test

Prerequisites: Flutter 3.38 or newer, Rust, and the relevant platform toolchain.

The v1.1.12 Tune Windows x64 release bundle is checked in at
[`dist/windows-x64/BimmerScope-v1.1.12-experimental.1+99-windows-x64`](dist/windows-x64/BimmerScope-v1.1.12-experimental.1%2B99-windows-x64).
Launch `BimmerScope.exe` from that folder; keep the adjacent DLLs and `data/`
directory with it. The bundle was produced with:

```powershell
flutter build windows --release --dart-define=BIMMERSCOPE_EDITION=tune
```

The executable SHA-256 is `67B9EE9E26457B2C390F944075113427EE44F7EA2A43DAF26C8E33B98FA8343C`.

```powershell
flutter pub get
flutter_rust_bridge_codegen generate
flutter run --flavor tune --dart-define=BIMMERSCOPE_EDITION=tune
```

Use `--flavor core --dart-define=BIMMERSCOPE_EDITION=core` for the Core edition.

Run the checks from the repository root:

```powershell
cargo test --manifest-path rust/Cargo.toml
flutter analyze
flutter test
```

At the time the v1.1.11 source snapshot was created, Rust tests passed **77/77** and Flutter analysis reported no issues. Flutter tests had **75 passing and one failing**: a dashboard button width assertion differs by 2 pixels (`734` expected, `736` actual). No v1.1.12+99 APK or real-vehicle acceptance is claimed.

## Architecture

```text
Flutter UI  <--- typed event stream --->  Rust core
                                             |
                                      TCP / HSFZ / UDS
                                             |
                                      BMW gateway :6801
```

Flutter owns presentation and lifecycle. Rust handles protocol framing, transport, diagnostics, and vehicle-session operations. When changing Rust APIs, edit `rust/src/api/vehicle.rs` and regenerate the Flutter Rust bridge.

See [BIMMERSCOPE_CONTEXT.md](BIMMERSCOPE_CONTEXT.md) and [BimmerScope-review-2026-09-05.md](BimmerScope-review-2026-09-05.md) for project context, validation limits, and the product review.

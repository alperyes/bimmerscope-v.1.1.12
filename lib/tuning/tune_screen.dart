import 'dart:io';
import 'dart:convert';
import 'dart:async';
import 'dart:typed_data';
import 'package:bmw_app/diagnostics/security_response_provider.dart';
import 'package:bmw_app/diagnostics/dme_preparation_2_screen.dart';

import 'package:bmw_app/design/app_palette.dart';
import 'package:bmw_app/design/connection_status_chip.dart';
import 'package:bmw_app/vehicle/vehicle_identity.dart';
import 'package:bmw_app/vehicle/dme_identifier_format.dart';
import 'package:bmw_app/tuning/stock_file_store.dart';
import 'package:bmw_app/tuning/read_dme2_screen.dart';
import 'package:bmw_app/tuning/tune_product.dart';
import 'package:bmw_app/tuning/tune_compatibility.dart';
import 'package:bmw_app/tuning/calibration_artifact.dart';
import 'package:bmw_app/tuning/file_dme_comparison.dart';
import 'package:bmw_app/tuning/flash_map_workspace.dart';
import 'package:bmw_app/vehicle/simulator_transport.dart';
import 'package:bmw_app/src/rust/api/vehicle.dart' as rust_vehicle;
import 'package:bmw_app/vehicle/garage_screen.dart';
import 'package:bmw_app/vehicle/vehicle_garage.dart';
import 'package:flutter/material.dart';
import 'package:file_selector/file_selector.dart';
import 'package:lottie/lottie.dart';
import 'package:path_provider/path_provider.dart';

class TuneScreen extends StatefulWidget {
  const TuneScreen({
    super.key,
    required this.isDark,
    required this.vin,
    required this.mileageKm,
    required this.connectionLabel,
    this.demoMode = false,
    required this.simulatorMode,
    required this.engineEcuDetected,
    required this.engineEcuIdentity,
    required this.engineEcuHardware,
    required this.engineEcuSoftware,
    required this.engineEcuBootloader,
    required this.engineEcuCalibration,
    required this.engineEcuApplicationSoftware,
    required this.engineEcuSoftwareVersion,
    required this.engineEcuSupplierHardware,
    required this.engineEcuSupplierSoftware,
    required this.engineEcuBootloaderFingerprint,
    required this.engineEcuSoftwareFingerprint,
    required this.engineEcuCalibrationFingerprint,
    required this.engineEcuSgbdIndex,
    required this.engineEcuSerialNumber,
    required this.engineEcuManufacturingDate,
    required this.engineEcuLastFlashDate,
    required this.engineFactoryHardware,
    required this.engineFactoryBootloader,
    required this.engineFactorySoftware,
    required this.engineFactoryCalibration,
    required this.engineSupplierHardware,
    required this.engineSupplierBootloader,
    required this.engineSupplierSoftware,
    required this.engineSupplierCalibration,
    required this.engineEcuCodingId,
    required this.engineEcuCvn,
    required this.sessionId,
    required this.identityCapturedAt,
    required this.onSelectGarageVehicle,
    required this.onShowGuide,
    required this.onToggleTheme,
    required this.onBeforeVehicleCheck,
    required this.onAfterVehicleCheck,
    required this.onOpenDrawer,
  });

  final bool isDark;
  final String vin;
  final double? mileageKm;
  final String connectionLabel;
  final bool demoMode;
  final bool simulatorMode;
  final bool engineEcuDetected;
  final String? engineEcuIdentity;
  final String? engineEcuHardware;
  final String? engineEcuSoftware;
  final String? engineEcuBootloader;
  final String? engineEcuCalibration;
  final String? engineEcuApplicationSoftware;
  final String? engineEcuSoftwareVersion;
  final String? engineEcuSupplierHardware;
  final String? engineEcuSupplierSoftware;
  final String? engineEcuBootloaderFingerprint;
  final String? engineEcuSoftwareFingerprint;
  final String? engineEcuCalibrationFingerprint;
  final String? engineEcuSgbdIndex;
  final String? engineEcuSerialNumber;
  final String? engineEcuManufacturingDate;
  final String? engineEcuLastFlashDate;
  final String? engineFactoryHardware;
  final String? engineFactoryBootloader;
  final String? engineFactorySoftware;
  final String? engineFactoryCalibration;
  final String? engineSupplierHardware;
  final String? engineSupplierBootloader;
  final String? engineSupplierSoftware;
  final String? engineSupplierCalibration;
  final String? engineEcuCodingId;
  final String? engineEcuCvn;
  final String sessionId;
  final DateTime? identityCapturedAt;
  final ValueChanged<GarageVehicle> onSelectGarageVehicle;
  final VoidCallback onShowGuide;
  final VoidCallback onToggleTheme;
  final Future<void> Function() onBeforeVehicleCheck;
  final Future<void> Function() onAfterVehicleCheck;
  final VoidCallback onOpenDrawer;

  @override
  State<TuneScreen> createState() => _TuneScreenState();
}

class _TuneScreenState extends State<TuneScreen> {
  bool get _actionsAvailable => const {
    'Connected',
    'Monitoring',
    'Degraded',
  }.contains(widget.connectionLabel);

  bool get _dmeRead2Available {
    final engine = identifyVehicle(widget.vin)?.engine;
    return _actionsAvailable &&
        !widget.demoMode &&
        !widget.simulatorMode &&
        (engine == 'S55' ||
            (engine == 'N20' && widget.vin == 'WBA3A52010F360747'));
  }

  File? importedStockFile;
  int? importedStockFileSize;
  String? importedStockFileHash;
  CalibrationArtifactInspection? stockInspection;
  String? stockSource;
  bool readingEcu2 = false;
  final stockFileStore = StockFileStore();
  TuneProduct selectedProduct = s55RemapProducts.first;

  @override
  void initState() {
    super.initState();
    unawaited(loadBackup());
  }

  @override
  void dispose() {
    super.dispose();
  }

  Future<void> loadBackup() async {
    final backup = await stockFileStore.load(widget.vin);
    if (backup != null) {
      await setStockFile(backup.file);
    }
  }

  Future<void> setStockFile(File file) async {
    final inspection = await inspectCalibrationArtifact(file);
    final metadataFile = File('${file.path}.metadata.json');
    final legacyMetadataFile = File('${file.path}.json');
    final sidecar = await metadataFile.exists()
        ? metadataFile
        : legacyMetadataFile;
    String? source;
    if (await sidecar.exists()) {
      try {
        final decoded = jsonDecode(await sidecar.readAsString());
        if (decoded is Map<String, dynamic>) {
          if (decoded['sha256'] == inspection.sha256) {
            source = decoded['source'] as String?;
          }
        }
      } catch (_) {
        // Keep the file inspectable if optional metadata is damaged.
      }
    }
    if (!mounted) return;
    setState(() {
      importedStockFile = file;
      importedStockFileSize = inspection.size;
      importedStockFileHash = inspection.sha256;
      stockInspection = inspection;
      stockSource = source;
    });
  }

  Future<({rust_vehicle.N20UnlockReferenceCheck? result, String? error})>
  _readN20UnlockReference() async {
    var paused = false;
    rust_vehicle.N20UnlockReferenceCheck? result;
    String? checkError;
    try {
      await widget.onBeforeVehicleCheck();
      paused = true;
      result = await rust_vehicle.checkN20BenchUnlockReference(
        expectedVin: widget.vin,
      );
    } catch (error) {
      checkError = '$error';
    } finally {
      if (paused) {
        try {
          await widget.onAfterVehicleCheck();
        } catch (error) {
          result = null;
          checkError = 'Vehicle reconnect failed: $error';
        }
      }
    }
    return (result: result, error: checkError);
  }

  Future<String> _loadUnlockStatus() async {
    final identity = identifyVehicle(widget.vin);
    final n20Check =
        _actionsAvailable &&
            !widget.simulatorMode &&
            widget.vin == 'WBA3A52010F360747'
        ? await _readN20UnlockReference()
        : null;
    return n20Check != null
        ? n20Check.result == null
              ? 'Unable to verify N20 bench DME: ${n20Check.error}'
              : '${n20Check.result!.status == 'reference_match' ? 'N20 bench reference matched' : 'Unable to verify'}\n\n${n20Check.result!.detail}\n\nVIN: ${n20Check.result!.vin}'
        : identity == null
        ? 'Connect and identify a supported vehicle to check its DME requirements.'
        : '${identity.displayLabel}\n\nUnlock checks are informational only in this build. No ECU write or flash operation is available.';
  }

  void showUnlockStatus() {
    Navigator.of(context).push<void>(
      MaterialPageRoute<void>(
        builder: (_) => _UnlockStatusPage(
          isDark: widget.isDark,
          status: _loadUnlockStatus(),
        ),
      ),
    );
  }

  Future<void> showTuneReadiness() async {
    final identity = identifyVehicle(widget.vin);
    final report = compatibilityReport;
    final connected = widget.connectionLabel == 'Connected';
    // Simulator evidence is valid only for the active simulator session. A
    // simulator running on the desktop must never influence a real or
    // disconnected vehicle check.
    final simulatorUnlockStatus = connected && widget.simulatorMode
        ? await readSimulatorDmeUnlockStatus()
        : null;
    final n20Check =
        connected && !widget.simulatorMode && widget.vin == 'WBA3A52010F360747'
        ? await _readN20UnlockReference()
        : null;
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        scrollable: true,
        title: const Text('Tune vehicle check'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _CheckResult(
              label: 'Vehicle connection',
              passed: connected,
              detail: connected ? 'Connected' : 'Connect to the vehicle',
            ),
            _CheckResult(
              label: 'BimmerScope profile',
              passed:
                  identity != null && selectedProduct.matchesVehicle(identity),
              detail: identity?.displayLabel ?? 'Vehicle not identified',
            ),
            _CheckResult(
              label: 'Package compatibility',
              passed: report.readyForProfessionalReview,
              detail: report.label,
            ),
            _CheckResult(
              label: 'DME unlock status',
              passed: simulatorUnlockStatus == 'unlocked',
              detail: n20Check != null
                  ? n20Check.result?.status == 'reference_match'
                        ? 'N20 bench reference matched'
                        : 'Unable to verify N20 bench reference'
                  : simulatorUnlockStatus == null ||
                        simulatorUnlockStatus == 'unknown'
                  ? 'Unable to verify'
                  : simulatorUnlockStatus.replaceAll('_', ' '),
            ),
            _CheckResult(
              label: 'ECU fingerprint',
              passed: report.evidence.complete,
              detail: report.evidence.complete
                  ? report.evidence.hasPhysicalHardware
                        ? 'Core DME identifiers and physical hardware are available for review'
                        : 'Core DME identifiers are available; physical hardware is optional on some S55 software levels'
                  : widget.engineEcuIdentity == null
                  ? 'DME identity, software, boot/startup, and calibration IDs unavailable'
                  : 'DME identity read (${widget.engineEcuIdentity}); some identifiers are still unavailable',
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: () => Navigator.of(context).push(
                MaterialPageRoute<GarageVehicle>(
                  builder: (_) => GarageScreen(
                    onSelect: (vehicle) {
                      widget.onSelectGarageVehicle(vehicle);
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text(
                            'Selected ${vehicle.label} for offline review',
                          ),
                        ),
                      );
                    },
                  ),
                ),
              ),
              icon: const Icon(Icons.garage_outlined),
              label: const Text('Open vehicle garage'),
            ),
            if (n20Check == null &&
                (simulatorUnlockStatus == null ||
                    simulatorUnlockStatus == 'unknown'))
              const Text(
                'DME preflight requires a validated VIN, hardware, software, bootloader, and calibration fingerprint.',
                style: TextStyle(fontSize: 12),
              ),
            const SizedBox(height: 8),
            ...report.reasons.map(
              (reason) => Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text('• $reason', style: const TextStyle(fontSize: 12)),
              ),
            ),
            const SizedBox(height: 8),
            const Text('No ECU writing or flashing is enabled.'),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  Future<void> readEcuCalibration2() async {
    if (readingEcu2 || !_dmeRead2Available) return;
    final isN20Reference = identifyVehicle(widget.vin)?.engine == 'N20';
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Read DME?'),
        content: const Text(
          'Experimental read-only 0x23 memory reads over 0x80180000–0x801FFBFF, using up to 4,092-byte chunks. The captured BM3 flow also sends an unexplained 0x31 routine to ECU 0x40; this prototype omits that step and may not complete. It does not write to the DME.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Read DME'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    setState(() => readingEcu2 = true);
    var sessionPaused = false;
    try {
      await widget.onBeforeVehicleCheck();
      sessionPaused = true;
      final bytes = await rust_vehicle.readBm3S55Calibration();
      final backup = await stockFileStore.saveBytes(
        bytes: bytes,
        vin: widget.vin,
        sourceName: isN20Reference
            ? 'n20_bench_80180000_7fc00.bin'
            : 'ecu_read_bm3_pattern_s55.bin',
        metadata: {
          'source': 'live_enet',
          'readStatus': 'compatibility_unverified',
          'readMethod': 'bm3_pattern_prototype',
          'profile': isN20Reference
              ? 'n20_bench_00001C9F1D9601_80180000_7FC00'
              : 'bm3_s55_00001C9F029150001_80180000_7FC00',
          'dmeAddress': 0x12,
          'softwareToken': isN20Reference
              ? '00001C9F1D9601'
              : '00001C9F029150001',
          'startAddress': '0x80180000',
          'length': 0x7FC00,
          'chunkSize': 0xFFC,
          'fullCalibrationRead': false,
          'readKind': 'memory_region',
          'responseSid': '0x63',
          'vin': widget.vin,
          'sessionId': widget.sessionId,
          'identityCapturedAt': widget.identityCapturedAt?.toIso8601String(),
          'dmeIdentity': widget.engineEcuIdentity,
          'hardware': widget.engineEcuHardware,
          'software': widget.engineEcuSoftware,
          'bootloader': widget.engineEcuBootloader,
          'calibration': widget.engineEcuCalibration,
        },
      );
      await setStockFile(backup.file);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('DME read 2 saved: ${backup.fileName}')),
        );
      }
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('DME read stopped: $error')));
      }
    } finally {
      if (sessionPaused) {
        try {
          await widget.onAfterVehicleCheck();
        } catch (error) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text('Vehicle reconnect failed: $error')),
            );
          }
        }
      }
      if (mounted) setState(() => readingEcu2 = false);
    }
  }

  Future<void> openReadDme2Page() async {
    await Navigator.of(context).push<void>(
      MaterialPageRoute<void>(
        builder: (_) => ReadDme2Screen(
          vin: widget.vin,
          isN20Reference: identifyVehicle(widget.vin)?.engine == 'N20',
          canRead: () => mounted && _dmeRead2Available,
          onRead: readEcuCalibration2,
          onCancel: rust_vehicle.cancelBm3S55Calibration,
          store: stockFileStore,
        ),
      ),
    );
    final selected = importedStockFile;
    if (selected != null && !await selected.exists() && mounted) {
      setState(() {
        importedStockFile = null;
        importedStockFileSize = null;
        importedStockFileHash = null;
        stockInspection = null;
        stockSource = null;
      });
      await loadBackup();
    }
  }

  void _openFlashMap() => Navigator.of(context).push<void>(
    MaterialPageRoute<void>(
      builder: (_) => _TuneActionPage(
        isDark: widget.isDark,
        title: 'Flash a map',
        icon: Icons.map_outlined,
        vin: widget.vin,
        engine: identifyVehicle(widget.vin)?.engine,
        identity: widget.engineEcuIdentity,
        software: widget.engineEcuSoftware,
        hardware: widget.engineEcuHardware,
        bootloader: widget.engineEcuBootloader,
        calibration: widget.engineEcuCalibration,
        sessionId: widget.sessionId,
        connectionLabel: widget.connectionLabel,
        engineEcuDetected: widget.engineEcuDetected,
        action: _TuneActionKind.installMap,
        onBeforeRead: widget.onBeforeVehicleCheck,
        onAfterRead: widget.onAfterVehicleCheck,
        realVehicle:
            !widget.demoMode &&
            !widget.simulatorMode &&
            widget.engineEcuDetected &&
            widget.sessionId.isNotEmpty,
      ),
    ),
  );

  void _openFlashBackToStock() => Navigator.of(context).push<void>(
    MaterialPageRoute<void>(
      builder: (_) => _TuneActionPage(
        isDark: widget.isDark,
        title: 'Flash back to stock',
        icon: Icons.settings_backup_restore_rounded,
        vin: widget.vin,
        engine: identifyVehicle(widget.vin)?.engine,
        identity: widget.engineEcuIdentity,
        software: widget.engineEcuSoftware,
        hardware: widget.engineEcuHardware,
        bootloader: widget.engineEcuBootloader,
        calibration: widget.engineEcuCalibration,
        sessionId: widget.sessionId,
        connectionLabel: widget.connectionLabel,
        engineEcuDetected: widget.engineEcuDetected,
        action: _TuneActionKind.restoreStock,
        onBeforeRead: widget.onBeforeVehicleCheck,
        onAfterRead: widget.onAfterVehicleCheck,
        realVehicle:
            !widget.demoMode &&
            !widget.simulatorMode &&
            widget.engineEcuDetected &&
            widget.sessionId.isNotEmpty,
      ),
    ),
  );

  void _openDmeIdentity() => Navigator.of(context).push<void>(
    MaterialPageRoute<void>(
      builder: (_) => _EcuIdentityPage(
        isDark: widget.isDark,
        vin: widget.vin,
        identity: widget.engineEcuIdentity,
        serialNumber: widget.engineEcuSerialNumber,
        hardware: widget.engineEcuHardware,
        software: widget.engineEcuSoftware,
        bootloader: widget.engineEcuBootloader,
        calibration: widget.engineEcuCalibration,
        manufacturingDate: widget.engineEcuManufacturingDate,
        lastFlashDate: widget.engineEcuLastFlashDate,
        factoryHardware: widget.engineFactoryHardware,
        factoryBootloader: widget.engineFactoryBootloader,
        factorySoftware: widget.engineFactorySoftware,
        factoryCalibration: widget.engineFactoryCalibration,
        supplierHardware: widget.engineSupplierHardware,
        supplierBootloader: widget.engineSupplierBootloader,
        supplierSoftware: widget.engineSupplierSoftware,
        supplierCalibration: widget.engineSupplierCalibration,
        codingId: widget.engineEcuCodingId,
      ),
    ),
  );

  @override
  Widget build(BuildContext context) => Scaffold(
    backgroundColor: AppPalette.background(widget.isDark),
    body: SafeArea(
      top: true,
      bottom: false,
      child: ListView(
        padding: EdgeInsets.zero,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(18, 20, 10, 12),
            child: SizedBox(
              height: 52,
              child: Stack(
                alignment: Alignment.center,
                children: [
                  Center(
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        ClipOval(
                          child: Image.asset(
                            'assets/branding/bimmerscope_icon.png',
                            width: 32,
                            height: 32,
                          ),
                        ),
                        const SizedBox(width: 12),
                        const Text(
                          'BIMMERSCOPE',
                          style: TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w900,
                            letterSpacing: 1.7,
                          ),
                        ),
                      ],
                    ),
                  ),
                  Align(
                    alignment: Alignment.centerLeft,
                    child: Transform.translate(
                      offset: const Offset(-2, 0),
                      child: IconButton(
                        onPressed: widget.onOpenDrawer,
                        icon: const Icon(Icons.menu_rounded),
                        padding: EdgeInsets.zero,
                        constraints: const BoxConstraints.tightFor(
                          width: 40,
                          height: 40,
                        ),
                        visualDensity: VisualDensity.compact,
                      ),
                    ),
                  ),
                  Align(
                    alignment: Alignment.centerRight,
                    child: ConnectionStatusChip(
                      label: widget.connectionLabel,
                      isDark: widget.isDark,
                      iconOnly: true,
                      isDemo: widget.demoMode || widget.simulatorMode,
                    ),
                  ),
                ],
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _TuneReadinessPanel(
                  isDark: widget.isDark,
                  vin: widget.vin,
                  connectionLabel: widget.connectionLabel,
                  onCheckVehicle: showTuneReadiness,
                ),
                const SizedBox(height: 8),
                SizedBox(
                  height: 44,
                  child: OutlinedButton.icon(
                    key: const Key('tune-read-dme-2'),
                    onPressed: readingEcu2 ? null : openReadDme2Page,
                    icon: readingEcu2
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.memory_outlined),
                    label: Text(readingEcu2 ? 'Reading…' : 'Read DME'),
                  ),
                ),
                if (readingEcu2)
                  TextButton.icon(
                    onPressed: rust_vehicle.cancelBm3S55Calibration,
                    icon: const Icon(Icons.stop_circle_outlined),
                    label: const Text('Cancel DME read'),
                  ),
                const SizedBox(height: 8),
                _DmeStatusStrip(
                  isDark: widget.isDark,
                  softwareId: widget.engineEcuSoftware,
                  stockSource: importedStockFile == null
                      ? null
                      : stockSource ?? 'unknown',
                ),
                const SizedBox(height: 8),
                _TuneActionMenu(
                  isDark: widget.isDark,
                  enabled: true,
                  items: [
                    _TuneActionItem(
                      key: const Key('tune-dme-identity-open'),
                      title: 'DME identity',
                      subtitle: 'ECU identifiers',
                      icon: Icons.memory_rounded,
                      onTap: _openDmeIdentity,
                    ),
                    _TuneActionItem(
                      key: const Key('tune-check-unlock-open'),
                      title: 'Check unlock status',
                      subtitle: 'Read-only DME check',
                      icon: Icons.lock_open_outlined,
                      onTap: showUnlockStatus,
                    ),
                    _TuneActionItem(
                      key: const Key('tune-flash-map-open'),
                      title: 'Flash a map',
                      subtitle: 'Review a calibration file and compatibility',
                      icon: Icons.map_outlined,
                      onTap: _openFlashMap,
                    ),
                    _TuneActionItem(
                      key: const Key('tune-flash-stock-open'),
                      title: 'Flash back to stock',
                      subtitle: 'Review saved stock artifact and eligibility',
                      icon: Icons.settings_backup_restore_rounded,
                      onTap: _openFlashBackToStock,
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    ),
  );

  bool get identityAvailable =>
      widget.connectionLabel == 'Connected' &&
      widget.engineEcuDetected &&
      identifyVehicle(widget.vin) != null;

  bool get hasSupportedVehicleProfile => identifyVehicle(widget.vin) != null;

  VehicleIdentity? get connectedIdentity =>
      identityAvailable ? identifyVehicle(widget.vin) : null;

  TuneCompatibilityReport get compatibilityReport => assessTuneCompatibility(
    vehicle: connectedIdentity,
    product: selectedProduct,
    evidence: TuneDmeEvidence(
      connected: widget.connectionLabel == 'Connected',
      detected: widget.engineEcuDetected,
      identity: widget.engineEcuIdentity,
      hardware: widget.engineEcuHardware,
      software: widget.engineEcuSoftware,
      bootloader: widget.engineEcuBootloader,
      calibration: widget.engineEcuCalibration,
      codingId: widget.engineEcuCodingId,
      svk: widget.engineEcuSgbdIndex,
      serialNumber: widget.engineEcuSerialNumber,
      sessionId: widget.sessionId.isEmpty ? null : widget.sessionId,
      source: widget.simulatorMode ? 'simulator' : 'live_enet',
      capturedAt: widget.identityCapturedAt,
    ),
  );
}

class _DmeStatusStrip extends StatelessWidget {
  const _DmeStatusStrip({
    required this.isDark,
    required this.softwareId,
    required this.stockSource,
  });

  final bool isDark;
  final String? softwareId;
  final String? stockSource;

  @override
  Widget build(BuildContext context) {
    final muted = AppPalette.secondary(isDark);
    final software = softwareId?.trim();
    final displaySoftware = software != null && software.startsWith('0000')
        ? software.substring(4)
        : software;
    final backup = switch (stockSource) {
      'live_enet' => 'ECU read',
      'imported_file' => 'Imported',
      null => 'None',
      _ => 'Saved',
    };

    return Container(
      key: const Key('tune-dme-status-strip'),
      padding: const EdgeInsets.symmetric(vertical: 13, horizontal: 8),
      decoration: BoxDecoration(
        color: AppPalette.surface(isDark),
        borderRadius: BorderRadius.circular(appCardRadius),
      ),
      child: Row(
        children: [
          Expanded(
            child: _item(
              icon: Icons.memory_outlined,
              label: 'DME software',
              value: displaySoftware == null || displaySoftware.isEmpty
                  ? 'Not read'
                  : displaySoftware,
              muted: muted,
            ),
          ),
          _divider(muted),
          Expanded(
            child: _item(
              icon: Icons.lock_outline_rounded,
              label: 'Unlock status',
              value: 'Unverified',
              muted: muted,
            ),
          ),
          _divider(muted),
          Expanded(
            child: _item(
              icon: Icons.save_outlined,
              label: 'Stock backup',
              value: backup,
              valueColor: stockSource == null ? null : AppPalette.green,
              muted: muted,
            ),
          ),
        ],
      ),
    );
  }

  Widget _divider(Color muted) =>
      Container(width: 1, height: 34, color: muted.withValues(alpha: .22));

  Widget _item({
    required IconData icon,
    required String label,
    required String value,
    required Color muted,
    Color? valueColor,
  }) => Padding(
    padding: const EdgeInsets.symmetric(horizontal: 6),
    child: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 16, color: AppPalette.blue),
        const SizedBox(height: 4),
        Text(
          value,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            color: valueColor,
            fontSize: 11,
            fontWeight: FontWeight.w800,
          ),
        ),
        const SizedBox(height: 1),
        Text(
          label,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(color: muted, fontSize: 9),
        ),
      ],
    ),
  );
}

class _TuneActionItem {
  const _TuneActionItem({
    required this.key,
    required this.title,
    required this.subtitle,
    required this.icon,
    required this.onTap,
  });

  final Key key;
  final String title;
  final String subtitle;
  final IconData icon;
  final VoidCallback onTap;
}

class _TuneActionMenu extends StatelessWidget {
  const _TuneActionMenu({
    required this.isDark,
    required this.enabled,
    required this.items,
  });

  final bool isDark;
  final bool enabled;
  final List<_TuneActionItem> items;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        LayoutBuilder(
          builder: (context, constraints) {
            final columns = constraints.maxWidth >= 640 ? 4 : 2;
            return GridView.builder(
              shrinkWrap: true,
              primary: false,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: items.length,
              gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
                crossAxisCount: columns,
                crossAxisSpacing: 8,
                mainAxisSpacing: 8,
                mainAxisExtent: 100,
              ),
              itemBuilder: (context, index) => _TuneActionTile(
                isDark: isDark,
                enabled: enabled,
                item: items[index],
              ),
            );
          },
        ),
      ],
    );
  }
}

Color _tuneMenuSurface(bool isDark) =>
    AppPalette.blue.withValues(alpha: isDark ? .13 : .07);

class _TuneActionTile extends StatelessWidget {
  const _TuneActionTile({
    required this.isDark,
    required this.enabled,
    required this.item,
  });

  final bool isDark;
  final bool enabled;
  final _TuneActionItem item;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      button: true,
      enabled: enabled,
      child: Material(
        color: _tuneMenuSurface(isDark),
        borderRadius: BorderRadius.circular(appCardRadius),
        child: InkWell(
          key: item.key,
          onTap: enabled ? item.onTap : null,
          borderRadius: BorderRadius.circular(appCardRadius),
          child: Opacity(
            opacity: enabled ? 1 : .45,
            child: Padding(
              padding: const EdgeInsets.all(10),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Container(
                        width: 32,
                        height: 32,
                        decoration: BoxDecoration(
                          color: AppPalette.blue.withValues(
                            alpha: isDark ? .18 : .1,
                          ),
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Icon(
                          item.icon,
                          color: AppPalette.blue,
                          size: 18,
                        ),
                      ),
                      const Spacer(),
                      Icon(
                        Icons.chevron_right_rounded,
                        size: 19,
                        color: AppPalette.secondary(isDark),
                      ),
                    ],
                  ),
                  const Spacer(),
                  Text(
                    item.title,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                      fontSize: 13,
                      height: 1.12,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _UnlockStatusPage extends StatelessWidget {
  const _UnlockStatusPage({required this.isDark, required this.status});

  final bool isDark;
  final Future<String> status;

  @override
  Widget build(BuildContext context) => Scaffold(
    backgroundColor: AppPalette.background(isDark),
    appBar: AppBar(
      title: Row(
        children: [
          Container(
            width: 32,
            height: 32,
            decoration: BoxDecoration(
              color: AppPalette.blue.withValues(alpha: isDark ? .16 : .1),
              borderRadius: BorderRadius.circular(9),
            ),
            child: const Icon(
              Icons.lock_open_rounded,
              color: AppPalette.blue,
              size: 18,
            ),
          ),
          const SizedBox(width: 10),
          const Text('Check unlock status'),
        ],
      ),
      bottom: PreferredSize(
        preferredSize: const Size.fromHeight(1),
        child: Divider(
          height: 1,
          color: AppPalette.separator(isDark).withValues(alpha: .65),
        ),
      ),
    ),
    body: FutureBuilder<String>(
      future: status,
      builder: (context, snapshot) {
        final muted = isDark
            ? const Color(0xFF9DA8B8)
            : const Color(0xFF58677B);
        final complete = snapshot.connectionState == ConnectionState.done;
        final message = snapshot.hasError
            ? 'Unable to verify unlock status: ${snapshot.error}'
            : snapshot.data ?? 'Unable to verify unlock status.';
        final sections = message.split('\n\n');
        final positive = message.contains('reference matched');
        return ListView(
          padding: const EdgeInsets.fromLTRB(16, 20, 16, 28),
          children: [
            Container(
              padding: const EdgeInsets.fromLTRB(20, 22, 20, 20),
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [
                    AppPalette.surface(isDark),
                    AppPalette.surface(isDark).withValues(alpha: .72),
                  ],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
                borderRadius: BorderRadius.circular(22),
                border: Border.all(
                  color: (positive ? AppPalette.green : AppPalette.blue)
                      .withValues(alpha: .22),
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Container(
                        width: 48,
                        height: 48,
                        decoration: BoxDecoration(
                          color: (positive ? AppPalette.green : AppPalette.blue)
                              .withValues(alpha: .14),
                          shape: BoxShape.circle,
                        ),
                        child: Icon(
                          positive
                              ? Icons.verified_rounded
                              : Icons.search_rounded,
                          color: positive ? AppPalette.green : AppPalette.blue,
                          size: 25,
                        ),
                      ),
                      const SizedBox(width: 14),
                      Expanded(
                        child: Text(
                          complete
                              ? 'Unlock status result'
                              : 'Checking unlock status…',
                          style: Theme.of(context).textTheme.titleLarge
                              ?.copyWith(
                                fontWeight: FontWeight.w800,
                                letterSpacing: -.2,
                              ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 20),
                  if (!complete)
                    const LinearProgressIndicator()
                  else
                    for (var i = 0; i < sections.length; i++) ...[
                      if (i > 0) const SizedBox(height: 16),
                      Text(
                        sections[i],
                        style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                          color: i == 0 ? null : muted,
                          height: 1.45,
                          fontWeight: i == 0
                              ? FontWeight.w700
                              : FontWeight.w400,
                        ),
                      ),
                    ],
                ],
              ),
            ),
            const SizedBox(height: 14),
            Container(
              padding: const EdgeInsets.fromLTRB(16, 15, 16, 15),
              decoration: BoxDecoration(
                color: AppPalette.surface(isDark).withValues(alpha: .72),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: AppPalette.separator(isDark)),
              ),
              child: const Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.info_outline_rounded, color: AppPalette.blue),
                  SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      'This check is informational only. It does not unlock, write to, or flash the ECU.',
                    ),
                  ),
                ],
              ),
            ),
          ],
        );
      },
    ),
  );
}

class _EcuIdentityPage extends StatelessWidget {
  const _EcuIdentityPage({
    required this.isDark,
    required this.vin,
    required this.identity,
    required this.serialNumber,
    required this.hardware,
    required this.software,
    required this.bootloader,
    required this.calibration,
    required this.manufacturingDate,
    required this.lastFlashDate,
    required this.factoryHardware,
    required this.factoryBootloader,
    required this.factorySoftware,
    required this.factoryCalibration,
    required this.supplierHardware,
    required this.supplierBootloader,
    required this.supplierSoftware,
    required this.supplierCalibration,
    required this.codingId,
  });

  final bool isDark;
  final String vin;
  final String? identity;
  final String? serialNumber;
  final String? hardware;
  final String? software;
  final String? bootloader;
  final String? calibration;
  final String? manufacturingDate;
  final String? lastFlashDate;
  final String? factoryHardware;
  final String? factoryBootloader;
  final String? factorySoftware;
  final String? factoryCalibration;
  final String? supplierHardware;
  final String? supplierBootloader;
  final String? supplierSoftware;
  final String? supplierCalibration;
  final String? codingId;

  @override
  Widget build(BuildContext context) {
    final muted = AppPalette.secondary(isDark);
    return Scaffold(
      backgroundColor: AppPalette.background(isDark),
      appBar: AppBar(
        title: Row(
          children: [
            Container(
              width: 32,
              height: 32,
              decoration: BoxDecoration(
                color: AppPalette.blue.withValues(alpha: isDark ? .16 : .1),
                borderRadius: BorderRadius.circular(9),
              ),
              child: const Icon(
                Icons.memory_rounded,
                color: AppPalette.blue,
                size: 18,
              ),
            ),
            const SizedBox(width: 10),
            const Text('DME identity'),
          ],
        ),
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Divider(
            height: 1,
            color: AppPalette.separator(isDark).withValues(alpha: .65),
          ),
        ),
      ),
      body: SafeArea(
        top: false,
        child: LayoutBuilder(
          builder: (context, constraints) => SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _identityFields([
                  ('VIN', vin),
                  ('Diagnostic ECU ID', identity),
                  ('ECU serial number (F18C)', serialNumber),
                  ('ECU Manufactured', manufacturingDate),
                ], muted),
                const SizedBox(height: 20),
                _identityGroup(
                  title: 'Factory software',
                  accent: muted,
                  muted: muted,
                  fields: [
                    ('Hardware ID (HWEL)', factoryHardware),
                    ('Bootloader ID (BTLD)', factoryBootloader),
                    ('Software ID (SWFL)', factorySoftware),
                    ('Calibration ID (SWFL)', factoryCalibration),
                  ],
                ),
                const SizedBox(height: 16),
                _identityGroup(
                  title: 'Supplier software',
                  accent: muted,
                  muted: muted,
                  fields: [
                    ('Hardware ID (HWEL)', supplierHardware),
                    ('Bootloader ID (BTLD)', supplierBootloader),
                    ('Software ID (SWFL)', supplierSoftware),
                    ('Calibration ID (SWFL)', supplierCalibration),
                  ],
                ),
                const SizedBox(height: 16),
                _identityGroup(
                  title: 'Current software',
                  accent: AppPalette.blue,
                  muted: muted,
                  fields: [
                    ('Hardware ID (HWEL)', hardware),
                    ('Bootloader ID (BTLD)', bootloader),
                    ('Software ID (SWFL)', software),
                    ('Calibration ID (SWFL)', calibration),
                    ('Coding ID (CAFD)', codingId),
                    ('Last flash date', lastFlashDate),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _identityGroup({
    required String title,
    required Color accent,
    required Color muted,
    required List<(String, String?)> fields,
  }) => Container(
    padding: const EdgeInsets.fromLTRB(14, 14, 12, 12),
    decoration: BoxDecoration(
      color: accent.withValues(alpha: .08),
      borderRadius: BorderRadius.circular(12),
      border: Border(left: BorderSide(color: accent, width: 4)),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Semantics(
          header: true,
          child: Text(
            title,
            style: TextStyle(
              color: accent,
              fontSize: 17,
              fontWeight: FontWeight.w800,
            ),
          ),
        ),
        const SizedBox(height: 12),
        _identityFields(fields, muted),
      ],
    ),
  );

  Widget _identityFields(List<(String, String?)> fields, Color muted) =>
      LayoutBuilder(
        builder: (context, constraints) {
          final itemWidth = constraints.maxWidth < 350
              ? constraints.maxWidth
              : (constraints.maxWidth - 10) / 2;
          return Wrap(
            spacing: 10,
            runSpacing: 18,
            children: [
              for (final field in fields)
                SizedBox(
                  width: itemWidth,
                  child: _EcuIdentityField(
                    label: field.$1,
                    value: field.$2,
                    muted: muted,
                  ),
                ),
            ],
          );
        },
      );
}

class _EcuIdentityField extends StatelessWidget {
  const _EcuIdentityField({
    required this.label,
    required this.value,
    required this.muted,
  });

  final String label;
  final String? value;
  final Color muted;

  @override
  Widget build(BuildContext context) {
    final shown = value?.trim().isNotEmpty == true ? value!.trim() : 'Not read';
    final raw = rawDmeComponentId(shown);
    final valueColor = shown == 'Not read'
        ? muted.withValues(alpha: .82)
        : Theme.of(context).colorScheme.onSurface;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: muted,
              fontSize: 10,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(height: 4),
          SelectableText(
            formatDmeComponentId(shown),
            maxLines: 1,
            textAlign: TextAlign.start,
            style: TextStyle(
              color: valueColor,
              fontSize: 12,
              height: 1.1,
              fontWeight: FontWeight.w700,
              fontFamily: 'monospace',
            ),
          ),
          if (raw != null) ...[
            const SizedBox(height: 5),
            SelectableText(
              raw,
              maxLines: 1,
              style: TextStyle(
                color: muted,
                fontSize: 11,
                fontFamily: 'monospace',
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _CheckResult extends StatelessWidget {
  const _CheckResult({
    required this.label,
    required this.passed,
    required this.detail,
  });
  final String label;
  final bool passed;
  final String detail;

  @override
  Widget build(BuildContext context) => ListTile(
    contentPadding: EdgeInsets.zero,
    dense: true,
    leading: Icon(
      passed ? Icons.check_circle_outline_rounded : Icons.info_outline_rounded,
      color: passed ? AppPalette.green : AppPalette.orange,
    ),
    title: Text(label),
    subtitle: Text(detail),
  );
}

class _TuneReadinessPanel extends StatelessWidget {
  const _TuneReadinessPanel({
    required this.isDark,
    required this.vin,
    required this.connectionLabel,
    required this.onCheckVehicle,
  });
  final bool isDark;
  final String vin;
  final String connectionLabel;
  final VoidCallback onCheckVehicle;

  @override
  Widget build(BuildContext context) {
    final primary = Theme.of(context).colorScheme.primary;
    final reduceMotion = MediaQuery.disableAnimationsOf(context);
    final muted = isDark ? const Color(0xFF9DA8B8) : const Color(0xFF58677B);
    final connecting =
        connectionLabel == 'Connecting' || connectionLabel == 'Searching';
    final connected = connectionLabel == 'Connected';
    final statusColor = connected
        ? AppPalette.green
        : connecting
        ? primary
        : muted;

    final statusDetail = vin == 'Not identified'
        ? 'Connect vehicle'
        : connected
        ? 'Connected'
        : 'Waiting for a verified vehicle session';
    return Semantics(
      container: true,
      label: 'Tune. $statusDetail',
      child: Container(
        key: const Key('tune-hero-card'),
        height: appTopActionCardHeight,
        padding: const EdgeInsets.fromLTRB(16, 14, 16, 16),
        decoration: BoxDecoration(
          color: AppPalette.surface(isDark),
          borderRadius: BorderRadius.circular(appCardRadius),
        ),
        child: Column(
          children: [
            Row(
              children: [
                Container(
                  width: 44,
                  height: 44,
                  decoration: BoxDecoration(
                    color: statusColor.withValues(alpha: isDark ? .16 : .09),
                    borderRadius: BorderRadius.circular(14),
                  ),
                  child: AnimatedSwitcher(
                    duration: reduceMotion
                        ? Duration.zero
                        : const Duration(milliseconds: 220),
                    child: connecting && !reduceMotion
                        ? ExcludeSemantics(
                            key: const ValueKey('connection-pulse'),
                            child: Lottie.asset(
                              'assets/animations/connection_pulse.json',
                              width: 36,
                              height: 36,
                              repeat: true,
                            ),
                          )
                        : Icon(
                            Icons.tune_rounded,
                            key: const ValueKey('tune-icon'),
                            color: statusColor,
                            size: 22,
                          ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Tune',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        statusDetail,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(color: muted, fontSize: 11),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const Spacer(),
            const SizedBox(height: 4),
            SizedBox(
              width: double.infinity,
              height: 48,
              child: FilledButton.icon(
                key: const Key('tune-check-vehicle-button'),
                onPressed: connected ? onCheckVehicle : null,
                style: FilledButton.styleFrom(
                  foregroundColor: Colors.white,
                  disabledForegroundColor: Colors.white.withValues(alpha: .65),
                ),
                icon: const Icon(Icons.manage_search_rounded, size: 20),
                label: const Text(
                  'Check vehicle',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

enum _TuneActionKind { installMap, restoreStock }

class _TuneActionPage extends StatefulWidget {
  const _TuneActionPage({
    required this.isDark,
    required this.title,
    required this.icon,
    required this.vin,
    required this.engine,
    required this.identity,
    required this.software,
    required this.hardware,
    required this.bootloader,
    required this.calibration,
    required this.sessionId,
    required this.connectionLabel,
    required this.engineEcuDetected,
    required this.action,
    required this.realVehicle,
    required this.onBeforeRead,
    required this.onAfterRead,
  });

  final bool isDark;
  final String title;
  final IconData icon;
  final String vin;
  final String? engine;
  final String? identity;
  final String? software;
  final String? hardware;
  final String? bootloader;
  final String? calibration;
  final String sessionId;
  final String connectionLabel;
  final bool engineEcuDetected;
  final _TuneActionKind action;
  final bool realVehicle;
  final Future<void> Function() onBeforeRead;
  final Future<void> Function() onAfterRead;

  @override
  State<_TuneActionPage> createState() => _TuneActionPageState();
}

class _TuneActionPageState extends State<_TuneActionPage> {
  final _identityCapturedAt = DateTime.now();
  final _stockStore = StockFileStore();
  CalibrationArtifactInspection? _mapInspection;
  Map<String, dynamic>? _binMetadata;
  File? _mapSourceFile;
  List<StockFileBackup> _stockFiles = [];
  File? _selectedStockFile;
  CalibrationArtifactInspection? _stockInspection;
  Map<String, dynamic>? _stockMetadata;
  bool _loading = false;
  String? _error;

  String? _codingBackupPath;
  String? _preparationStatus;
  String? _operationStatus;
  String? _operationEvidence;
  String? _preflightReportPath;
  String? _recoveryPreflightReportPath;

  String? _recoveryPlanPath;
  String? _recoveryEvidence;
  bool _recoveryReady = false;
  int _totalStages = 10;
  String? _recoveryReviewStatus;

  List<Map<String, dynamic>> _savedOperations = [];
  bool _historyLoading = false;
  String? _historyError;
  String? _conditionStatus;
  String? _conditionReportPath;
  String? _agentStateStatus;
  String? _lastOperationKind;
  String? _operationBlockReason;
  Map<String, dynamic>? _programmingAccessEvidence;
  String? _programmingAccessStatus;
  bool _operationRunning = false;
  bool _operationExecuting = false;
  bool _operationRecovery = false;

  Future<void> _checkProgrammingAccess() async {
    if (_loading ||
        _historyLoading ||
        _recoveryRequired ||
        !widget.realVehicle ||
        widget.bootloader == null) {
      return;
    }
    final connection = ValueNotifier(widget.connectionLabel);
    final wasPrepared = _lastOperationKind == 'prepared_without_write_approval';
    setState(() {
      _loading = true;
      _operationReady = false;
      _recoveryReady = false;
      if (!wasPrepared) {
        _lastOperationKind = null;
        _operationStatus = null;
        _operationBlockReason = null;
      }
      _programmingAccessEvidence = null;
      _error = null;
    });
    try {
      final accessAccepted = await Navigator.of(context).push<bool>(
        MaterialPageRoute(
          builder: (_) => DmePreparation2Screen(
            vin: widget.vin,
            currentBootloader: widget.bootloader!,
            connectionStatus: connection,
            isDark: widget.isDark,
            onBeforeSend: widget.onBeforeRead,
            onAfterSend: widget.onAfterRead,
            accessCheckOnly: true,
          ),
        ),
      );
      final support = await getApplicationSupportDirectory();
      final safety =
          jsonDecode(
                await rust_vehicle.initializeVehicleSafety(
                  rootDirectory: support.path,
                ),
              )
              as Map<String, dynamic>;
      if (mounted) {
        setState(() {
          _programmingAccessStatus =
              accessAccepted == true
              ? 'Programming access accepted. Writing still requires support for this BIN and DME.'
              : null;
          if (safety['blocked'] != false) {
            _recoveryRequired = true;
            _error =
                'Programming-access result needs review. Live polling remains paused.';
            _operationStatus = jsonEncode(safety);
          }
        });
      }
    } catch (error) {
      if (mounted) {
        setState(() {
          _recoveryRequired = true;
          _error = 'Could not inspect the programming-access outcome: $error';
        });
      }
    } finally {
      connection.dispose();
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _importAgentState() async {
    if (_loading || _historyLoading) return;
    final selected = await openFile(
      acceptedTypeGroups: const [
        XTypeGroup(label: 'Agent vehicle data', extensions: ['coding', 'json']),
      ],
    );
    if (selected == null || !mounted) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Import historical agent state?'),
        content: Text(
          'Vehicle: ${widget.vin}\nFile: ${selected.name}\n\nUses the saved unlock confirmation and flash-result flags for workflow selection. These flags do not verify the DME is unlocked. Coding data from this file will not be restored. Fresh DME identity must match before the flags can be used.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Import state'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    setState(() {
      _loading = true;
      _operationReady = false;
      _recoveryReady = false;
      _lastOperationKind = null;
      _error = null;
    });
    try {
      final raw = await rust_vehicle.importN20AgentState(
        expectedVin: widget.vin,
        sourcePath: selected.path,
        confirmed: true,
      );
      final result = jsonDecode(raw) as Map<String, dynamic>;
      final state = result['agent_state'] as Map<String, dynamic>;
      if (mounted) {
        setState(() {
          _agentStateStatus =
              'Historical state saved: unlock confirmed ${state['unlockDone']}, last flash successful ${state['lastFlashSuccess']}, recovery needed ${state['needsRecovery']}, prior type ${state['lastFlashType'] ?? 'not recorded'}. Prepare a fresh operation to check identity and resolve workflow state.\n${result['path']}';
          _operationStatus =
              'Agent state changed. Prepare a fresh operation before writing.';
        });
      }
    } catch (error) {
      if (mounted) {
        setState(() => _error = 'Agent state import stopped: $error');
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _loadSavedOperations() async {
    if (_loading || _historyLoading) {
      return;
    }
    setState(() {
      _historyLoading = true;
      _historyError = null;
    });
    try {
      final support = await getApplicationSupportDirectory();
      final raw = await rust_vehicle.listN20SavedOperations(
        rootDirectory: support.path,
        expectedVin: widget.vin,
      );
      final result = jsonDecode(raw) as Map<String, dynamic>;
      final entries = (result['operations'] as List)
          .map((e) => Map<String, dynamic>.from(e as Map))
          .toList();
      final uncertain = entries.any(
        (e) => e['vin_verified'] == true && e['may_have_changed'] == true,
      );
      if (uncertain && !_recoveryRequired) {
        if (mounted) {
          setState(() => _recoveryRequired = true);
        }
        await widget.onBeforeRead();
      }
      if (mounted) {
        setState(() => _savedOperations = entries);
      }
    } catch (error) {
      if (mounted) {
        setState(
          () => _historyError = 'Saved-operation inspection failed: $error',
        );
      }
    } finally {
      if (mounted) {
        setState(() => _historyLoading = false);
      }
    }
  }

  Future<void> _loadSavedOperation(Map<String, dynamic> entry) async {
    if (_loading || _historyLoading || entry['can_load'] != true) {
      return;
    }
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final folder = entry['directory'] as String;
      final source = File('$folder${Platform.pathSeparator}selected.bin');
      final inspection = await _inspectMapArtifact(source);
      final metadata =
          widget.engine == 'N20' && inspection.partialPreview != null
          ? jsonDecode(
                  await rust_vehicle.inspectN20BinMetadata(
                    binPath: source.path,
                    binSha256: inspection.sha256,
                  ),
                )
                as Map<String, dynamic>
          : null;
      if (inspection.sha256 != entry['image_sha256']) {
        throw StateError('Saved image changed after inspection');
      }
      final recovery = entry['kind'] == 'recovery';
      if (mounted) {
        setState(() {
          _mapSourceFile = source;
          _mapInspection = inspection;
          _binMetadata = metadata;
          _fullFlash = entry['kind'] == 'full';
          _lastOperationKind = null;
          _binStock = entry['bin_stock'] as bool?;
          _operationReady = false;
          _recoveryReady = false;
          _operationEvidence = recovery ? null : folder;
          _recoveryEvidence = recovery ? folder : null;
          _recoveryPlanPath = recovery
              ? '$folder${Platform.pathSeparator}recovery-plan.json'
              : null;
          _codingBackupPath =
              '$folder${Platform.pathSeparator}${recovery ? 'original-coding.json' : 'coding.json'}';
          _preparationStatus =
              'Original saved coding loaded. Fresh DME checks are still required.';
          _operationStatus =
              'Saved evidence loaded for review. No operation was resumed.';
          _preflightReportPath = null;
          _recoveryPreflightReportPath = null;
        });
      }
    } catch (error) {
      if (mounted) {
        setState(() => _error = 'Could not load saved evidence: $error');
      }
    } finally {
      if (mounted) {
        setState(() => _loading = false);
      }
    }
  }

  Future<void> _queryProgrammingConditions() async {
    if (_loading || _historyLoading || !widget.realVehicle) {
      return;
    }
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Query programming conditions?'),
        content: const Text(
          'Runs the agent programming-condition routine on the connected bench DME. This is a separate diagnostic action and does not start flashing. Returned labels do not approve programming.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Run query'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) {
      return;
    }
    final wasUncertain = _recoveryRequired;
    var paused = false;
    setState(() {
      _loading = true;
      _error = null;
      _conditionStatus = 'Checking the bench DME identity...';
      _conditionReportPath = null;
    });
    try {
      final support = await getApplicationSupportDirectory();
      await widget.onBeforeRead();
      paused = true;
      if (mounted) {
        setState(() => _recoveryRequired = true);
      }
      await for (final event in rust_vehicle.queryN20ProgrammingPreconditions(
        expectedVin: widget.vin,
        expectedSoftware: widget.software ?? '',
        confirmed: true,
        outputDirectory:
            '${support.path}${Platform.pathSeparator}n20_condition_queries',
      )) {
        if (mounted) {
          setState(() {
            _conditionStatus = event.message;
            if (event.kind == 'diagnostic_complete') {
              _recoveryRequired = wasUncertain;
              _conditionReportPath =
                  '${event.evidencePath}${Platform.pathSeparator}conditions.json';
            }
            if (event.kind == 'diagnostic_uncertain') {
              _recoveryRequired = true;
              _error = event.message;
            }
            if (event.kind == 'error') {
              _recoveryRequired = wasUncertain;
              _error = event.message;
            }
          });
        }
      }
    } catch (error) {
      if (paused) {
        _recoveryRequired = true;
      }
      if (mounted) {
        setState(() => _error = 'Condition query stopped: $error');
      }
    } finally {
      if (paused && !wasUncertain && !_recoveryRequired) {
        try {
          await widget.onAfterRead();
        } catch (error) {
          if (mounted) {
            setState(() => _error = 'Vehicle reconnect failed: $error');
          }
        }
      }
      if (mounted) {
        setState(() => _loading = false);
      }
    }
  }

  Future<void> _prepareRecoveryPlan() async {
    final source = _mapSourceFile;
    final inspection = _mapInspection;
    final original = _operationEvidence;
    if (_loading || source == null || inspection == null || original == null) {
      return;
    }
    setState(() {
      _loading = true;
      _error = null;
      _recoveryPlanPath = null;
      _recoveryReady = false;
      _recoveryReviewStatus =
          'Reviewing the software/calibration rewrite and original coding...';
    });
    try {
      final support = await getApplicationSupportDirectory();
      final path = await rust_vehicle.prepareN20RecoveryPlan(
        expectedVin: widget.vin,
        binPath: source.path,
        binSha256: inspection.sha256,
        originalOperationDirectory: original,
        outputDirectory:
            '${support.path}${Platform.pathSeparator}n20_recovery_reviews',
      );
      if (mounted) {
        setState(() {
          _recoveryPlanPath = path;
          _recoveryReviewStatus =
              'Recovery plan saved for six software/calibration regions. Check the responding DME next. Execution requires a separate reviewed full-rewrite profile. No ECU requests were sent.';
        });
      }
    } catch (error) {
      if (mounted) {
        setState(() => _error = 'Recovery review stopped: $error');
      }
    } finally {
      if (mounted) {
        setState(() => _loading = false);
      }
    }
  }

  bool _operationReady = false;
  bool _fullFlash = false;
  bool? _binStock;
  bool _recoveryRequired = false;
  int _completedStages = 0;
  bool _flashGateStarted = false;
  bool _flashStagesStarted = false;
  bool _flashWorkflowFailed = false;

  Future<void> _prepareFlashOperation() => _runFlashOperation(execute: false);

  Future<void> _confirmFlashOperation() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(
          _fullFlash
              ? 'Write full software and calibration?'
              : 'Write the selected BIN?',
        ),
        content: Text(
          'Target: ${widget.vin}\nBIN SHA-256: ${_mapInspection?.sha256}\n\n${_fullFlash ? 'Six software/calibration regions, 3,931,392 bytes. Startup memory is excluded. This is an ordinary full flash, separate from recovery.\n\n' : ''}Confirm the bench supply and recovery equipment are ready. Programming must finish before disconnecting power.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Start writing'),
          ),
        ],
      ),
    );
    if (confirmed == true && mounted && _operationReady) {
      await _runFlashOperation(execute: true);
    }
  }

  Future<void> _prepareRecoveryOperation() =>
      _runFlashOperation(execute: false, recovery: true);

  Future<void> _confirmRecoveryOperation() async {
    if (_loading || !_recoveryReady) {
      return;
    }
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Rewrite software and calibration?'),
        content: Text(
          'Target: ${widget.vin}\nBIN SHA-256: ${_mapInspection?.sha256}\n\nThis rewrites all six software/calibration regions and restores the original saved coding. Startup memory is excluded. Keep bench power connected throughout.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Start recovery'),
          ),
        ],
      ),
    );
    if (confirmed == true && mounted && _recoveryReady) {
      await _runFlashOperation(execute: true, recovery: true);
    }
  }

  Future<void> _runFlashOperation({
    required bool execute,
    bool recovery = false,
  }) async {
    final source = _mapSourceFile;
    final inspection = _mapInspection;
    if (_loading ||
        _historyLoading ||
        (_recoveryRequired && !recovery) ||
        (recovery && _recoveryPlanPath == null) ||
        source == null ||
        inspection == null ||
        !widget.realVehicle) {
      return;
    }
    final wasRecoveryRequired = _recoveryRequired;
    final full = !recovery && _fullFlash;
    setState(() {
      _loading = true;
      _error = null;
      _operationStatus = recovery
          ? (execute
                ? 'Starting recovery...'
                : 'Checking recovery readiness...')
          : full
          ? (execute
                ? 'Starting full software/calibration flash...'
                : 'Preparing full software/calibration operation...')
          : (execute
                ? 'Starting flash operation...'
                : 'Preparing the operation...');
      _operationReady = false;
      _recoveryReady = false;
      _totalStages = recovery || full ? 16 : 10;
      _operationRunning = true;
      _operationBlockReason = null;
      _programmingAccessEvidence = null;
      _programmingAccessStatus = null;
      _operationExecuting = execute;
      _operationRecovery = recovery;
      _lastOperationKind = null;
      _completedStages = 0;
      _flashGateStarted = false;
      _flashStagesStarted = false;
      _flashWorkflowFailed = false;
      _recoveryRequired = execute || wasRecoveryRequired;
      if (recovery) {
        _recoveryEvidence = null;
        _recoveryPreflightReportPath = null;
      } else {
        _operationEvidence = null;
        _preflightReportPath = null;
        _recoveryPlanPath = null;
        _recoveryEvidence = null;
        _recoveryPreflightReportPath = null;
      }
    });
    var paused = false;
    try {
      final support = await getApplicationSupportDirectory();
      await widget.onBeforeRead();
      paused = true;
      final events = recovery
          ? (execute
                ? rust_vehicle.startN20RecoveryOperation(
                    expectedVin: widget.vin,
                    binSha256: inspection.sha256,
                    planPath: _recoveryPlanPath!,
                    confirmed: true,
                    outputDirectory:
                        '${support.path}${Platform.pathSeparator}n20_recovery_operations',
                  )
                : rust_vehicle.prepareN20RecoveryOperation(
                    expectedVin: widget.vin,
                    binSha256: inspection.sha256,
                    planPath: _recoveryPlanPath!,
                    outputDirectory:
                        '${support.path}${Platform.pathSeparator}n20_recovery_operations',
                  ))
          : full
          ? (execute
                ? rust_vehicle.startN20FullFlashOperation(
                    binStock: _binStock,
                    expectedVin: widget.vin,
                    expectedSoftware: widget.software ?? '',
                    binPath: source.path,
                    binSha256: inspection.sha256,
                    outputDirectory:
                        '${support.path}${Platform.pathSeparator}n20_full_operations',
                    confirmed: true,
                  )
                : rust_vehicle.prepareN20FullFlashOperation(
                    binStock: _binStock,
                    expectedVin: widget.vin,
                    expectedSoftware: widget.software ?? '',
                    binPath: source.path,
                    binSha256: inspection.sha256,
                    outputDirectory:
                        '${support.path}${Platform.pathSeparator}n20_full_operations',
                  ))
          : execute
          ? rust_vehicle.startN20FlashOperation(
              binStock: _binStock,
              expectedVin: widget.vin,
              expectedSoftware: widget.software ?? '',
              binPath: source.path,
              binSha256: inspection.sha256,
              outputDirectory:
                  '${support.path}${Platform.pathSeparator}n20_flash_operations',
              confirmed: true,
            )
          : rust_vehicle.prepareN20FlashOperation(
              binStock: _binStock,
              expectedVin: widget.vin,
              expectedSoftware: widget.software ?? '',
              binPath: source.path,
              binSha256: inspection.sha256,
              outputDirectory:
                  '${support.path}${Platform.pathSeparator}n20_flash_operations',
            );
      await for (final event in events) {
        String? blockReason;
        Map<String, dynamic>? accessEvidence;
        if ((event.kind == 'blocked' || event.kind == 'preflight_report') &&
            !recovery &&
            event.evidencePath.isNotEmpty) {
          try {
            final reportFile = File(
              '${event.evidencePath}${Platform.pathSeparator}preflight-observations.json',
            );
            if (await reportFile.length() <= 1024 * 1024) {
              final report =
                  jsonDecode(await reportFile.readAsString())
                      as Map<String, dynamic>;
              final dispatch =
                  report['agent_dispatch'] as Map<String, dynamic>?;
              accessEvidence =
                  report['programming_access_evidence']
                      as Map<String, dynamic>?;
              final compatibility =
                  report['bin_compatibility'] as Map<String, dynamic>?;
              final rawReasons =
                  dispatch != null && dispatch['resolved'] == false
                  ? dispatch['missing_requirements']
                  : compatibility == null
                  ? null
                  : compatibility['blocking_reasons'];
              final reasons = rawReasons is List ? rawReasons : null;
              if (reasons != null &&
                  reasons.isNotEmpty &&
                  reasons.first is String) {
                final reason = reasons.first as String;
                blockReason = reason.length > 200
                    ? '${reason.substring(0, 200)}…'
                    : reason;
              }
            }
          } catch (_) {
            // The complete native reason remains available in check details.
          }
        }
        if (event.kind == 'security_challenge') {
          try {
            final key = await SecurityResponseProvider.calculate(
              currentBootloader: event.bootloader,
              seed: event.seed,
            );
            await rust_vehicle.provideN20OperationKey(
              requestId: event.requestId,
              key: Uint8List.fromList(key),
            );
          } catch (error) {
            await rust_vehicle.rejectN20OperationKey(
              requestId: event.requestId,
              reason: 'Security calculation failed: $error',
            );
          }
        }
        if (mounted) {
          setState(() {
            _operationStatus = event.message;
            _lastOperationKind = event.kind;
            if (accessEvidence != null) {
              _programmingAccessEvidence = accessEvidence;
            }
            if (event.kind == 'blocked') _operationBlockReason = blockReason;
            if (event.kind == 'preflight_report') {
              final path =
                  '${event.evidencePath}${Platform.pathSeparator}preflight-observations.json';
              if (recovery) {
                _recoveryPreflightReportPath = path;
              } else {
                _preflightReportPath = path;
              }
            }
            if (event.kind == 'stage' || event.kind == 'complete') {
              _completedStages = event.completedStages;
              _flashStagesStarted = true;
            }
            if (event.kind == 'gate_check' || event.kind == 'power_check') {
              _flashGateStarted = true;
            }
            if (event.kind == 'error' ||
                event.kind == 'blocked' ||
                event.kind == 'recovery_required') {
              _flashWorkflowFailed = true;
            }
            _operationReady = !recovery && event.kind == 'ready';
            _recoveryReady = recovery && event.kind == 'ready';
            if (event.kind == 'complete' ||
                event.kind == 'error' ||
                event.kind == 'prepared_without_write_approval' ||
                event.kind == 'blocked') {
              _recoveryRequired = event.kind == 'complete'
                  ? false
                  : wasRecoveryRequired;
            }
            if (event.kind == 'recovery_required') {
              _recoveryRequired = true;
              _error = event.message;
            }
            if (event.evidencePath.isNotEmpty) {
              if (recovery) {
                _recoveryEvidence = event.evidencePath;
              } else {
                _operationEvidence = event.evidencePath;
              }
            }
            if (event.kind == 'error') {
              _error = event.message;
            }
          });
        }
      }
    } catch (error) {
      if (mounted) {
        setState(() {
          _error = 'Flash operation stopped: $error';
          _flashWorkflowFailed = true;
        });
      }
    } finally {
      // Resume polling only when the worker reports a known safe terminal state.
      if (paused && !_recoveryRequired) {
        try {
          await widget.onAfterRead();
        } catch (error) {
          if (mounted) {
            setState(() => _error = 'Vehicle reconnect failed: $error');
          }
        }
      }
      if (mounted) {
        setState(() {
          _loading = false;
          _operationRunning = false;
        });
      }
    }
  }

  Future<void> _readCodingBackup() async {
    final source = _mapSourceFile;
    final inspection = _mapInspection;
    if (_loading ||
        _historyLoading ||
        _recoveryRequired ||
        source == null ||
        inspection == null ||
        !widget.realVehicle) {
      return;
    }
    setState(() {
      _loading = true;
      _error = null;
      _codingBackupPath = null;
      _operationReady = false;
      _preparationStatus = 'Pausing the live session…';
    });
    var paused = false;
    try {
      final support = await getApplicationSupportDirectory();
      await widget.onBeforeRead();
      paused = true;
      if (mounted) {
        setState(
          () => _preparationStatus =
              'Checking the DME and reading coding sections…',
        );
      }
      final path = await rust_vehicle.readN20FlashCodingBackup(
        expectedVin: widget.vin,
        expectedSoftware: widget.software ?? '',
        binPath: source.path,
        binSha256: inspection.sha256,
        outputDirectory:
            '${support.path}${Platform.pathSeparator}n20_flash_preparation',
      );
      if (mounted) {
        setState(() {
          _codingBackupPath = path;
          _preparationStatus = 'Coding backup saved. No ECU data was written.';
        });
      }
    } catch (error) {
      if (mounted) {
        setState(() {
          _error = 'Coding backup stopped: $error';
          _preparationStatus = 'Preparation incomplete';
        });
      }
    } finally {
      if (paused) {
        try {
          await widget.onAfterRead();
        } catch (error) {
          if (mounted) {
            setState(() => _error = 'Vehicle reconnect failed: $error');
          }
        }
      }
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  void initState() {
    super.initState();
    if (widget.action == _TuneActionKind.restoreStock) {
      _loadStockFiles();
    } else if (widget.engine == 'N20') {
      _loadSavedOperations();
    }
  }

  Future<void> _chooseMap() async {
    final selected = await openFile(
      acceptedTypeGroups: const [
        XTypeGroup(
          label: 'Calibration files',
          extensions: ['bmap', 'bin', 'ori', 'hex', 'json'],
        ),
      ],
    );
    if (selected == null) return;
    setState(() {
      _loading = true;
      _error = null;
      _operationReady = false;
      _recoveryReady = false;
      _lastOperationKind = null;
    });
    try {
      final source = File(selected.path);
      final inspection = await _inspectMapArtifact(source);
      final metadata =
          widget.engine == 'N20' && inspection.partialPreview != null
          ? jsonDecode(
                  await rust_vehicle.inspectN20BinMetadata(
                    binPath: source.path,
                    binSha256: inspection.sha256,
                  ),
                )
                as Map<String, dynamic>
          : null;
      if (mounted) {
        setState(() {
          _mapSourceFile = source;
          _mapInspection = inspection;
          _binMetadata = metadata;
          _codingBackupPath = null;
          _binStock = null;
          _lastOperationKind = null;
          _operationReady = false;
          _preparationStatus = null;
          _operationStatus = null;
          _operationEvidence = null;
          _preflightReportPath = null;
          _recoveryPreflightReportPath = null;
          _recoveryPlanPath = null;
          _recoveryReady = false;
          _recoveryReviewStatus = null;
        });
      }
    } catch (error) {
      if (mounted) setState(() => _error = 'Could not inspect file: $error');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<CalibrationArtifactInspection> _inspectMapArtifact(File file) =>
      inspectCalibrationArtifact(
        file,
        softwareIdToken: widget.software == null
            ? null
            : rawDmeComponentId(widget.software!),
      );

  Future<void> _createBimmerScopePackage() async {
    final source = _mapSourceFile;
    if (source == null || !await source.exists()) return;
    final baseName = source.uri.pathSegments.last.replaceFirst(
      RegExp(r'\.[^.]+$'),
      '',
    );
    final location = await getSaveLocation(
      suggestedName: '$baseName.bmap',
      confirmButtonText: 'Create package',
      acceptedTypeGroups: const [
        XTypeGroup(label: 'BimmerScope map package', extensions: ['bmap']),
      ],
    );
    if (location == null || !mounted) return;
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final vehicleContext = <String, String>{
        if (widget.vin.isNotEmpty) 'vin': widget.vin,
        if (widget.engine != null) 'engine': widget.engine!,
        if (widget.identity != null) 'dme_identity': widget.identity!,
        if (widget.hardware != null) 'hardware': widget.hardware!,
        if (widget.software != null) 'software': widget.software!,
        if (widget.bootloader != null) 'bootloader': widget.bootloader!,
        if (widget.calibration != null) 'calibration': widget.calibration!,
      };
      final package = await createBimmerScopeMapPackage(
        source: source,
        target: File(location.path),
        vehicleContext: vehicleContext,
      );
      final inspection = await _inspectMapArtifact(package);
      if (mounted) {
        setState(() {
          _mapSourceFile = package;
          _binStock = null;
          _mapInspection = inspection;
          _binMetadata = null;
          _operationReady = false;
          _recoveryReady = false;
          _lastOperationKind = null;
          _operationStatus = null;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'BimmerScope package created: ${package.uri.pathSegments.last}',
            ),
          ),
        );
      }
    } catch (error) {
      if (mounted) setState(() => _error = 'Could not create package: $error');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _loadStockFiles() async {
    setState(() => _loading = true);
    try {
      final files = await _stockStore.loadAll(widget.vin);
      if (!mounted) return;
      setState(() {
        _stockFiles = files;
        _selectedStockFile ??= files.firstOrNull?.file;
      });
      if (_selectedStockFile != null) await _inspectStock(_selectedStockFile!);
    } catch (error) {
      if (mounted)
        setState(() => _error = 'Could not load saved files: $error');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _importStockFile() async {
    final selected = await openFile(
      acceptedTypeGroups: const [
        XTypeGroup(
          label: 'Stock or DME files',
          extensions: ['bin', 'ori', 'hex'],
        ),
      ],
    );
    if (selected == null) return;
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final saved = await _stockStore.importFile(
        sourcePath: selected.path,
        vin: widget.vin,
        metadata: const {
          'source': 'user_import',
          'compatibility': 'unverified',
        },
      );
      if (!mounted) return;
      setState(() {
        _stockFiles = [saved, ..._stockFiles];
        _selectedStockFile = saved.file;
      });
      await _inspectStock(saved.file);
    } catch (error) {
      if (mounted)
        setState(() => _error = 'Could not save selected file: $error');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _inspectStock(File file) async {
    try {
      final inspection = await inspectCalibrationArtifact(file);
      final metadataFile = File('${file.path}.metadata.json');
      final legacyMetadataFile = File('${file.path}.json');
      final sidecar = await metadataFile.exists()
          ? metadataFile
          : legacyMetadataFile;
      Map<String, dynamic>? metadata;
      if (await sidecar.exists()) {
        try {
          final decoded = jsonDecode(await sidecar.readAsString());
          if (decoded is Map<String, dynamic> &&
              decoded['sha256'] == inspection.sha256) {
            metadata = decoded;
          }
        } catch (_) {
          // The binary remains reviewable when its optional sidecar is bad.
        }
      }
      if (mounted) {
        setState(() {
          _stockInspection = inspection;
          _stockMetadata = metadata;
        });
      }
    } catch (error) {
      if (mounted)
        setState(() => _error = 'Could not inspect saved file: $error');
    }
  }

  Widget _artifactDetails(
    CalibrationArtifactInspection? inspection,
    String emptyMessage,
  ) {
    if (inspection == null) return Text(emptyMessage);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SelectableText(inspection.fileName),
        const SizedBox(height: 6),
        Text('${inspection.size} bytes · ${inspection.kind}'),
        if (inspection.provider != null)
          Text('Provider: ${inspection.provider}'),
        if (inspection.revision != null)
          Text('Revision: ${inspection.revision}'),
        if (inspection.packageMetadata != null &&
            inspection.kind == 'bimmerscope_map_package') ...[
          const SizedBox(height: 6),
          if (inspection.packageMetadata!['source_file'] case final value?)
            Text('Original file: $value'),
          if (inspection.packageMetadata!['payload_size'] case final value?)
            Text('Original size: $value bytes'),
          if (inspection.packageMetadata!['payload_sha256'] case final value?)
            SelectableText('Original file SHA-256: $value'),
          const Padding(
            padding: EdgeInsets.only(top: 8, bottom: 4),
            child: Text(
              'Vehicle identity recorded at packaging (context only)',
            ),
          ),
          for (final entry in inspection.packageMetadata!.entries.where(
            (entry) => !const {
              'source_file',
              'payload_size',
              'payload_sha256',
            }.contains(entry.key),
          ))
            Text('${_vehicleContextLabel(entry.key)}: ${entry.value}'),
        ],
        if (inspection.declaredCompatibility != null)
          Text(
            'Declared compatibility: ${jsonEncode(inspection.declaredCompatibility)}',
          ),
        Text('SHA-256: ${inspection.sha256}'),
        Text('Signature: ${inspection.signatureStatus}'),
        for (final note in inspection.notes) Text(note),
      ],
    );
  }

  void _changeFlashMode(bool full) {
    if (_loading || _historyLoading || _recoveryRequired) return;
    setState(() {
      _fullFlash = full;
      _completedStages = 0;
      _flashGateStarted = false;
      _flashStagesStarted = false;
      _flashWorkflowFailed = false;
      _totalStages = full ? 16 : 10;
      _error = null;
      _operationReady = false;
      _operationEvidence = null;
      _preflightReportPath = null;
      _recoveryReady = false;
      _recoveryPlanPath = null;
      _recoveryEvidence = null;
      _recoveryPreflightReportPath = null;
      _lastOperationKind = null;
      _operationStatus = null;
    });
  }

  Widget _flashTextGroup(List<Widget> children) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      for (final child in children)
        Padding(padding: const EdgeInsets.only(bottom: 12), child: child),
    ],
  );

  Widget _buildFlashPage(BuildContext context) {
    final inspection = _mapInspection;
    final validBin =
        widget.engine == 'N20' &&
        inspection?.kind == 'opaque_artifact' &&
        inspection?.partialPreview != null;
    final canPrepare =
        !_loading &&
        !_historyLoading &&
        _historyError == null &&
        !_recoveryRequired &&
        widget.realVehicle &&
        widget.software != null &&
        validBin;
    final phase = _operationRunning
        ? (_operationExecuting
              ? FlashPagePhase.writing
              : FlashPagePhase.preparing)
        : _recoveryRequired
        ? FlashPagePhase.review
        : _operationReady
        ? FlashPagePhase.ready
        : _error != null
        ? FlashPagePhase.error
        : _lastOperationKind == 'prepared_without_write_approval'
        ? FlashPagePhase.prepared
        : _lastOperationKind == 'blocked'
        ? FlashPagePhase.blocked
        : _lastOperationKind == 'complete'
        ? FlashPagePhase.completed
        : FlashPagePhase.selected;
    final reason = !widget.realVehicle
        ? 'Connect the real DME to prepare this file.'
        : widget.engine != 'N20'
        ? 'No programming profile is registered for this DME.'
        : !validBin
        ? 'Choose the original N20 BIN to prepare flashing.'
        : widget.software == null
        ? 'DME software identity is unavailable. Reconnect before preparing.'
        : _historyLoading
        ? 'Checking saved operations…'
        : null;
    final details = _flashTextGroup([
      if (inspection != null) ...[
        FileDmeComparison(
          preview: inspection.partialPreview,
          fileBootloader: _binMetadata?['bootloader'] as String?,
          software: widget.software,
          calibration: widget.calibration,
          hardware: widget.hardware,
          bootloader: widget.bootloader,
          sessionId: widget.sessionId,
          capturedAt: _identityCapturedAt,
          realVehicle: widget.realVehicle,
        ),
        const Divider(),
        if (inspection.partialPreview case final preview?) ...[
          const Text(
            'Calibration regions',
            style: TextStyle(fontWeight: FontWeight.w600),
          ),
          const SelectableText(
            'Main: 523,264 bytes · 0x180000–0x1FFBFF\nTail: 768 bytes · 0x1FFD00–0x1FFFFF',
          ),
          Text(
            'Skipped gap: ${preview.gapIsZero ? 'all zero' : 'nonzero; unsupported reference layout'}',
          ),
          SelectableText(
            'Main SHA-256: ${preview.mainHash}\nTail SHA-256: ${preview.tailHash}',
          ),
        ],
        if (_fullFlash)
          const Text(
            'Software + calibration: six regions, 3,931,392 bytes. Startup memory and skipped gaps are excluded.',
          ),
        if (inspection.filenameVin != null)
          Text('Filename VIN: ${inspection.filenameVin} (unverified claim)'),
        if (inspection.binaryMarker != null)
          Text('Header marker: ${inspection.binaryMarker} (hint only)'),
        if (inspection.comparedSoftwareToken != null)
          Text(_embeddedSoftwareIdSummary(inspection)),
        Text(_mapFileStatus(inspection)),
        _artifactDetails(inspection, ''),
      ] else
        const Text('Select a file to inspect its identity and regions.'),
    ]);
    final tools = _flashTextGroup([
      const Text(
        'BIN classification',
        style: TextStyle(fontWeight: FontWeight.w600),
      ),
      const Text(
        'Used for recovery-route selection. Your classification does not establish compatibility.',
      ),
      DropdownButton<String>(
        key: const Key('n20-bin-stock-classification'),
        value: _binStock == null
            ? 'unknown'
            : _binStock!
            ? 'stock'
            : 'modified',
        isExpanded: true,
        items: const [
          DropdownMenuItem(value: 'unknown', child: Text('Not classified')),
          DropdownMenuItem(
            value: 'stock',
            child: Text('Stock · your classification'),
          ),
          DropdownMenuItem(
            value: 'modified',
            child: Text('Modified · your classification'),
          ),
        ],
        onChanged: _loading || _historyLoading || _recoveryRequired
            ? null
            : (value) {
                if (value == null) return;
                _changeFlashMode(_fullFlash);
                setState(
                  () =>
                      _binStock = value == 'unknown' ? null : value == 'stock',
                );
              },
      ),
      const Divider(),
      const Text(
        'Programming access',
        style: TextStyle(fontWeight: FontWeight.w600),
      ),
      Text(
        _programmingAccessEvidence?['status'] == 'observed'
            ? 'A matching prior owned connection accepted programming-session and security access. This is historical evidence; writing must establish fresh access.'
            : _programmingAccessEvidence?['status'] == 'security_only'
            ? 'A security response was accepted, but programming-session access was not established by that record.'
            : 'Writing must establish programming-session and security access on its owned connection. A separate check can save an observation; it does not approve erase or transfer.',
      ),
      OutlinedButton.icon(
        key: const Key('n20-check-programming-access'),
        onPressed:
            !_loading &&
                !_historyLoading &&
                !_recoveryRequired &&
                widget.realVehicle &&
                widget.engine == 'N20' &&
                widget.bootloader != null
            ? _checkProgrammingAccess
            : null,
        icon: const Icon(Icons.key_outlined, size: 18),
        label: const Text('Check programming access'),
      ),
      if (_programmingAccessStatus != null) Text(_programmingAccessStatus!),
      if (_programmingAccessEvidence?['directory'] case final String directory)
        SelectableText(directory),
      const Divider(),
      const Text(
        'Diagnostic and file tools',
        style: TextStyle(fontWeight: FontWeight.w600),
      ),
      const Text(
        'These actions are separate from flashing. The condition query requires confirmation.',
      ),
      Wrap(
        spacing: 10,
        runSpacing: 8,
        children: [
          OutlinedButton.icon(
            key: const Key('n20-query-programming-conditions'),
            onPressed: !_loading && !_historyLoading && widget.realVehicle
                ? _queryProgrammingConditions
                : null,
            icon: const Icon(Icons.rule, size: 18),
            label: const Text('Query conditions'),
          ),
          OutlinedButton.icon(
            key: const Key('n20-import-agent-state'),
            onPressed: !_loading && !_historyLoading && widget.realVehicle
                ? _importAgentState
                : null,
            icon: const Icon(Icons.file_open_outlined, size: 18),
            label: const Text('Import agent state'),
          ),
          OutlinedButton.icon(
            key: const Key('n20-read-coding-backup'),
            onPressed: canPrepare ? _readCodingBackup : null,
            icon: const Icon(Icons.save_alt, size: 18),
            label: const Text('Read coding backup'),
          ),
          OutlinedButton.icon(
            onPressed:
                !_loading &&
                    _mapSourceFile != null &&
                    inspection?.kind != 'bimmerscope_map_package'
                ? _createBimmerScopePackage
                : null,
            icon: const Icon(Icons.inventory_2_outlined, size: 18),
            label: const Text('Save .bmap package'),
          ),
        ],
      ),
      const Text(
        'Agent-state import is optional legacy history for direct BIN preparation. It is not proof of physical unlock. A coding backup is not a complete ECU recovery image.',
      ),
      if (_conditionStatus != null) Text(_conditionStatus!),
      if (_conditionReportPath != null) SelectableText(_conditionReportPath!),
      if (_agentStateStatus != null) SelectableText(_agentStateStatus!),
      if (_preparationStatus != null) Text(_preparationStatus!),
      if (_codingBackupPath != null) SelectableText(_codingBackupPath!),
    ]);
    final history = _flashTextGroup([
      TextButton.icon(
        onPressed: !_loading && !_historyLoading ? _loadSavedOperations : null,
        icon: const Icon(Icons.refresh, size: 18),
        label: const Text('Refresh records'),
      ),
      if (_historyLoading) const LinearProgressIndicator(),
      if (_historyError != null) Text(_historyError!),
      if (_savedOperations.isEmpty && !_historyLoading)
        const Text('No matching saved operations.'),
      const Text(
        'Loading a record does not resume writing or approve the connected ECU.',
      ),
      for (final entry in _savedOperations)
        ListTile(
          contentPadding: EdgeInsets.zero,
          title: Text(entry['status'] as String? ?? 'Unknown record'),
          subtitle: Text('${entry['detail']}\n${entry['directory']}'),
          trailing: TextButton(
            onPressed:
                !_loading && !_historyLoading && entry['can_load'] == true
                ? () => _loadSavedOperation(entry)
                : null,
            child: const Text('Load'),
          ),
        ),
    ]);
    final recovery = _flashTextGroup([
      const Text(
        'Responding-DME recovery',
        style: TextStyle(fontWeight: FontWeight.w600),
      ),
      const Text(
        'Rewrites software and calibration using this BIN and the original saved coding. Startup is excluded. This cannot establish recovery after diagnostic access is lost.',
      ),
      Wrap(
        spacing: 10,
        runSpacing: 8,
        children: [
          OutlinedButton.icon(
            key: const Key('n20-prepare-recovery-plan'),
            onPressed: !_loading && _operationEvidence != null
                ? _prepareRecoveryPlan
                : null,
            icon: const Icon(Icons.restore, size: 18),
            label: const Text('Review recovery plan'),
          ),
          OutlinedButton.icon(
            key: const Key('n20-prepare-recovery-operation'),
            onPressed:
                !_loading && _recoveryPlanPath != null && widget.realVehicle
                ? _prepareRecoveryOperation
                : null,
            icon: const Icon(Icons.fact_check_outlined, size: 18),
            label: const Text('Check readiness'),
          ),
          FilledButton.icon(
            key: const Key('n20-start-recovery-operation'),
            onPressed: !_loading && _recoveryReady
                ? _confirmRecoveryOperation
                : null,
            icon: const Icon(Icons.restore, size: 18),
            label: const Text('Start recovery'),
          ),
        ],
      ),
      if (_recoveryReviewStatus != null) Text(_recoveryReviewStatus!),
      if (_recoveryPlanPath != null) SelectableText(_recoveryPlanPath!),
      if (_recoveryPreflightReportPath != null)
        SelectableText(_recoveryPreflightReportPath!),
      if (_recoveryEvidence != null) SelectableText(_recoveryEvidence!),
      const Text(
        'A reviewed recovery profile is required. A coding backup is not a full recovery image.',
      ),
    ]);
    return PopScope(
      canPop: !_loading,
      child: Scaffold(
        backgroundColor: AppPalette.background(widget.isDark),
        appBar: AppBar(
          title: const Text('Flash a map'),
          actions: [
            IconButton(
              tooltip: 'Flash diagnostics',
              onPressed: _loading || _historyLoading ? null : _openFlashDiagnostics,
              icon: const Icon(Icons.bug_report_outlined),
            ),
          ],
        ),
        body: FlashMapWorkspace(
          isDark: widget.isDark,
          vehicle: widget.engine ?? 'DME',
          vin: widget.vin,
          connection: widget.realVehicle
              ? widget.connectionLabel
              : 'Real DME not connected',
          fullFlash: _fullFlash,
          recovering: _operationRecovery,
          busy: _loading || _historyLoading,
          phase: phase,
          blockReason: _operationBlockReason,
          fileName: inspection?.fileName,
          fileSize: inspection == null
              ? null
              : _formatMapFileSize(inspection.size),
          onChoose: _loading ? null : _chooseMap,
          onPrepare: canPrepare ? _prepareFlashOperation : null,
          programmingAccessAccepted: _programmingAccessStatus != null &&
              phase == FlashPagePhase.prepared,
          onCheckProgrammingAccess: canPrepare && widget.bootloader != null
              ? _checkProgrammingAccess
              : null,
          onWrite:
              !_loading &&
                  !_historyLoading &&
                  _historyError == null &&
                  validBin &&
                  !_recoveryRequired &&
                  _operationReady
              ? _confirmFlashOperation
              : null,
          onModeChanged: _loading || _historyLoading || _recoveryRequired
              ? null
              : _changeFlashMode,
          unavailableReason: reason,
          attention: _historyError == null
              ? null
              : 'Saved operations could not be checked. Review the history details before proceeding.',
          progress: _operationExecuting && _completedStages > 0
              ? _completedStages / _totalStages
              : null,
          progressLabel: _operationExecuting
              ? '$_completedStages of $_totalStages stages completed'
              : null,
          workflow: _flashWorkflow(phase),
          checkDetails: _operationStatus == null && _error == null
              ? null
              : _flashTextGroup([
                  if (_error != null) SelectableText(_error!),
                  if (_operationStatus != null && _operationStatus != _error)
                    SelectableText(_operationStatus!),
                  if (_preflightReportPath != null)
                    SelectableText('Preflight report\n$_preflightReportPath'),
                  if (_operationEvidence != null)
                    SelectableText('Operation record\n$_operationEvidence'),
                ]),
          details: details,
          tools: tools,
          history: history,
          recovery: recovery,
          historySummary: _historyLoading
              ? 'Checking records…'
              : '${_savedOperations.length} saved records · local evidence only',
        ),
      ),
    );
  }

  Widget _flashWorkflow(FlashPagePhase phase) {
    final rewrite = _totalStages == 16;
    final steps = [
      'Receive and check BIN and DME',
      'Check power and programming conditions',
      'Confirm live DME identity',
      'Prepare session, request access and write fingerprint',
      if (rewrite) ...[
        'Erase software',
        'Transfer first software region',
        'Transfer first software tail',
        'Transfer second software region',
        'Transfer second software tail',
        'Verify software',
      ],
      'Erase calibration',
      'Transfer calibration',
      'Transfer calibration tail',
      'Verify calibration',
      'Check programming dependencies',
      'Write VIN',
      'Restore diagnostic and energy modes',
      'Restore coding and verify readback',
    ];
    final passed = _flashStagesStarted
        ? 2 + _completedStages
        : _flashGateStarted ||
              phase == FlashPagePhase.prepared ||
              phase == FlashPagePhase.ready
        ? 1
        : 0;
    final failure = _error ?? _operationStatus;
    return Padding(
      padding: const EdgeInsets.only(top: 20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Flash workflow', style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 8),
          for (final (index, step) in steps.indexed)
            ListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              leading: Icon(
                index < passed
                    ? Icons.check_circle_outline
                    : index == passed && _flashWorkflowFailed
                    ? Icons.cancel_outlined
                    : index == passed && _operationRunning
                    ? Icons.timelapse
                    : Icons.radio_button_unchecked,
                color: index < passed
                    ? AppPalette.green
                    : index == passed && _flashWorkflowFailed
                    ? Theme.of(context).colorScheme.error
                    : null,
              ),
              title: Text(step),
              subtitle: Text(
                index < passed
                    ? 'Passed'
                    : index == passed && _flashWorkflowFailed
                    ? failure ?? 'Failed'
                    : index == passed && _operationRunning
                    ? 'In progress'
                    : 'Pending',
              ),
            ),
        ],
      ),
    );
  }

  void _openFlashDiagnostics() {
    Navigator.of(context).push<void>(
      MaterialPageRoute(
        builder: (context) => Scaffold(
          appBar: AppBar(title: const Text('Flash diagnostics')),
          backgroundColor: AppPalette.background(widget.isDark),
          body: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 960),
              child: ListView(
                padding: const EdgeInsets.all(20),
                children: [
                  Text(
                    'Current operation',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  if (_error case final error?) SelectableText(error),
                  SelectableText(
                    _operationStatus ?? 'No flash result in this session.',
                  ),
                  for (final (label, path) in [
                    ('Preflight report', _preflightReportPath),
                    ('Operation folder', _operationEvidence),
                    ('Programming conditions', _conditionReportPath),
                    ('Recovery preflight report', _recoveryPreflightReportPath),
                    ('Recovery operation folder', _recoveryEvidence),
                  ])
                    if (path != null)
                      Padding(
                        padding: const EdgeInsets.only(top: 8),
                        child: SelectableText('$label\n$path'),
                      ),
                  const Divider(height: 32),
                  Text(
                    'Saved operations',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  if (_historyLoading) const LinearProgressIndicator(),
                  if (_historyError case final error?) SelectableText(error),
                  if (_savedOperations.isEmpty && !_historyLoading)
                    const Text('No matching saved operations.'),
                  for (final entry in _savedOperations)
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      title: Text(entry['status'] as String? ?? 'Unknown record'),
                      subtitle: SelectableText(
                        '${entry['detail']}\n${entry['directory']}',
                      ),
                    ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (widget.action == _TuneActionKind.installMap) {
      return _buildFlashPage(context);
    }
    final isN20 = widget.engine == 'N20';
    final isInstall = widget.action == _TuneActionKind.installMap;
    final muted = AppPalette.secondary(widget.isDark);
    final title = isInstall ? 'Choose a map file' : 'Stock restore review';
    return PopScope(
      canPop: !_loading,
      child: Scaffold(
        backgroundColor: AppPalette.background(widget.isDark),
        appBar: AppBar(title: Text(widget.title)),
        body: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Container(
              padding: const EdgeInsets.all(18),
              decoration: BoxDecoration(
                color: AppPalette.surface(widget.isDark),
                borderRadius: BorderRadius.circular(appCardRadius),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  ...[
                    Row(
                      children: [
                        Icon(widget.icon, color: AppPalette.blue),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            title,
                            style: Theme.of(context).textTheme.titleLarge,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    Text(
                      'Target: ${widget.engine ?? 'Unidentified ECU'} · VIN ${widget.vin}',
                    ),
                    Text(
                      'DME identity: ${widget.identity ?? 'Not identified'}',
                    ),
                    Text(
                      'DME hardware: ${widget.hardware ?? 'Not identified'}',
                    ),
                    Text(
                      'DME software: ${widget.software ?? 'Not identified'}',
                    ),
                    Text(
                      'Bootloader: ${widget.bootloader ?? 'Not identified'}',
                    ),
                    Text(
                      'Calibration: ${widget.calibration ?? 'Not identified'}',
                    ),
                    const SizedBox(height: 10),
                    Text(
                      isN20
                          ? 'Saved stock artifacts can be reviewed, but the N20 captures are partial probes and are not complete recovery images.'
                          : 'No validated programming and recovery backend is registered for this ECU.',
                      style: TextStyle(color: muted, height: 1.4),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 14),
            ...[
              FilledButton.icon(
                onPressed: _loading ? null : _importStockFile,
                icon: const Icon(Icons.upload_file_outlined),
                label: const Text('Import stock artifact for review'),
              ),
              const SizedBox(height: 10),
              if (_stockFiles.isEmpty && !_loading)
                const _ReviewCard(
                  title: 'Saved stock artifacts',
                  child: Text('No stock artifacts saved for this VIN.'),
                ),
              for (final backup in _stockFiles)
                Card(
                  child: RadioListTile<String>(
                    value: backup.file.path,
                    groupValue: _selectedStockFile?.path,
                    title: Text(backup.fileName),
                    subtitle: const Text(
                      'Saved artifact · compatibility unverified',
                    ),
                    onChanged: (value) {
                      if (value == null) return;
                      final file = backup.file;
                      setState(() {
                        _selectedStockFile = file;
                        _stockInspection = null;
                      });
                      _inspectStock(file);
                    },
                  ),
                ),
              _ReviewCard(
                title: 'Selected stock artifact',
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _artifactDetails(
                      _stockInspection,
                      'Select or import an artifact to inspect.',
                    ),
                    if (_stockMetadata != null) ...[
                      const SizedBox(height: 8),
                      Text(
                        'Source: ${_stockMetadata!['source'] ?? 'Not recorded'}',
                      ),
                      Text(
                        'Read status: ${_stockMetadata!['readStatus'] ?? _stockMetadata!['compatibility'] ?? 'Not recorded'}',
                      ),
                      if (_stockMetadata!.containsKey('fullCalibrationRead'))
                        Text(
                          'Full calibration read: ${_stockMetadata!['fullCalibrationRead'] == true ? 'declared yes' : 'no'}',
                        ),
                    ],
                  ],
                ),
              ),
              const _ReviewCard(
                title: 'Restore eligibility',
                child: Text(
                  'Blocked. A saved file is not automatically a complete ECU backup or recovery image. Exact DME compatibility, full-image provenance, integrity rules, and a tested recovery procedure are required.',
                ),
              ),
            ],
            if (_loading) const Center(child: CircularProgressIndicator()),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text(
                  _error!,
                  style: TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
            const SizedBox(height: 10),
            if (!isInstall)
              const _ReviewCard(
                title: 'Programming status',
                child: Text(
                  'No ECU write or flash command is available from this page.',
                ),
              ),
          ],
        ),
      ),
    );
  }

  String _vehicleContextLabel(String key) => switch (key) {
    'vin' => 'VIN',
    'engine' => 'Engine',
    'dme_identity' => 'DME identity',
    'hardware' => 'DME hardware',
    'software' => 'DME software',
    'bootloader' => 'Bootloader',
    'calibration' => 'Calibration',
    _ => key,
  };

  String _formatMapFileSize(int size) {
    if (size >= 1024 * 1024)
      return '${(size / (1024 * 1024)).toStringAsFixed(1)} MiB';
    if (size >= 1024) return '${(size / 1024).toStringAsFixed(1)} KiB';
    return '$size bytes';
  }

  String _embeddedSoftwareIdSummary(CalibrationArtifactInspection inspection) {
    final rawOffset = inspection.rawSoftwareIdOffset;
    final asciiOffset = inspection.asciiSoftwareIdOffset;
    if (rawOffset == null && asciiOffset == null) {
      return 'Live software ID bytes not found in file (not a compatibility verdict)';
    }
    final locations = <String>[
      if (rawOffset != null) 'bytes at ${_formatFileOffset(rawOffset)}',
      if (asciiOffset != null) 'text at ${_formatFileOffset(asciiOffset)}',
    ];
    return 'Live software ID found in file: ${locations.join(', ')}';
  }

  String _formatFileOffset(int offset) =>
      '0x${offset.toRadixString(16).toUpperCase().padLeft(8, '0')}';

  String _mapFileStatus(CalibrationArtifactInspection inspection) =>
      switch (inspection.kind) {
        'bimmerscope_map_package' => 'BimmerScope package integrity: passed',
        'invalid_bimmerscope_map_package' =>
          'BimmerScope package integrity: failed',
        _ => 'File opened for review',
      };
}

class _ReviewCard extends StatelessWidget {
  const _ReviewCard({required this.title, required this.child});
  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          child,
        ],
      ),
    ),
  );
}

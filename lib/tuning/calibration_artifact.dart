import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'partial_map_preview.dart';

const bimmerScopeMapPackageFormat = 'bimmerscope-map-package-v1';

/// Read-only artifact inspection, including a bounded historical layout preview.
/// Imported bytes are never patched or installed here.
class CalibrationArtifactInspection {
  const CalibrationArtifactInspection({
    required this.fileName,
    required this.sha256,
    required this.size,
    required this.kind,
    required this.provider,
    required this.revision,
    required this.declaredCompatibility,
    required this.signatureStatus,
    required this.notes,
    this.packageMetadata,
    this.filenameVin,
    this.filenameEcuId,
    this.binaryMarker,
    this.comparedSoftwareToken,
    this.rawSoftwareIdOffset,
    this.asciiSoftwareIdOffset,
    this.partialPreview,
  });

  final String fileName;
  final String sha256;
  final int size;
  final String kind;
  final String? provider;
  final String? revision;
  final Map<String, dynamic>? declaredCompatibility;
  final String signatureStatus;
  final List<String> notes;

  /// Safe summary fields from a BimmerScope-owned map package.
  final Map<String, String>? packageMetadata;

  /// Filename claims are unverified and are never treated as ECU evidence.
  final String? filenameVin;
  final String? filenameEcuId;
  final String? binaryMarker;
  final String? comparedSoftwareToken;
  final int? rawSoftwareIdOffset;
  final int? asciiSoftwareIdOffset;
  final PartialMapPreview? partialPreview;

  Map<String, dynamic> toJson() => {
    'file_name': fileName,
    'sha256': sha256,
    'size': size,
    'kind': kind,
    'provider': provider,
    'revision': revision,
    'declared_compatibility': declaredCompatibility,
    'signature_status': signatureStatus,
    'notes': notes,
    'package_metadata': packageMetadata,
    'filename_vin': filenameVin,
    'filename_ecu_id': filenameEcuId,
    'binary_marker': binaryMarker,
    'compared_software_token': comparedSoftwareToken,
    'raw_software_id_offset': rawSoftwareIdOffset,
    'ascii_software_id_offset': asciiSoftwareIdOffset,
    'partial_preview': partialPreview?.toJson(),
  };
}

Future<CalibrationArtifactInspection> inspectCalibrationArtifact(
  File file, {
  String? softwareIdToken,
}) async {
  final bytes = await file.readAsBytes();
  final digest = sha256.convert(bytes).toString();
  final fileName = file.uri.pathSegments.last;
  Map<String, dynamic>? manifest;
  try {
    final decoded = jsonDecode(utf8.decode(bytes));
    if (decoded is Map<String, dynamic> &&
        (decoded['format'] == bimmerScopeMapPackageFormat ||
            decoded['format'] == 'bimmerscope-calibration-manifest-v1')) {
      manifest = decoded;
    }
  } catch (_) {}
  if (manifest == null) {
    final nameMatch = RegExp(
      r'([A-HJ-NPR-Z0-9]{17})_([0-9A-F]{14})',
      caseSensitive: false,
    ).firstMatch(fileName);
    final marker = _binaryMarker(bytes);
    final softwareFindings = _findSoftwareId(bytes, softwareIdToken);
    return CalibrationArtifactInspection(
      fileName: fileName,
      sha256: digest,
      size: bytes.length,
      kind: 'opaque_artifact',
      partialPreview: inspectPartialMap(bytes),
      provider: null,
      revision: null,
      declaredCompatibility: null,
      signatureStatus: 'not_verifiable',
      filenameVin: nameMatch?.group(1)?.toUpperCase(),
      filenameEcuId: nameMatch?.group(2)?.toUpperCase(),
      binaryMarker: marker,
      comparedSoftwareToken: softwareFindings.token,
      rawSoftwareIdOffset: softwareFindings.rawOffset,
      asciiSoftwareIdOffset: softwareFindings.asciiOffset,
      notes: const [
        'Filename identifiers and binary markers do not verify ECU compatibility.',
      ],
    );
  }
  if (manifest['format'] == bimmerScopeMapPackageFormat) {
    final artifact = manifest['artifact'];
    // Read target_identity from early local v1 packages for compatibility;
    // current packages write vehicle_context to avoid implying approval.
    final context = manifest['vehicle_context'] ?? manifest['target_identity'];
    final payload = artifact is Map<String, dynamic>
        ? artifact['payload_base64']
        : null;
    final expectedHash = artifact is Map<String, dynamic>
        ? artifact['sha256']
        : null;
    final expectedSize = artifact is Map<String, dynamic>
        ? artifact['size']
        : null;
    try {
      if (payload is! String ||
          expectedHash is! String ||
          expectedSize is! num) {
        throw const FormatException('Incomplete package metadata.');
      }
      final payloadBytes = base64Decode(payload);
      if (payloadBytes.length != expectedSize ||
          sha256.convert(payloadBytes).toString() != expectedHash) {
        throw const FormatException('Embedded map integrity check failed.');
      }
      final recordedTarget = <String, String>{};
      final softwareFindings = _findSoftwareId(payloadBytes, softwareIdToken);
      if (context is Map<String, dynamic>) {
        for (final key in const [
          'vin',
          'engine',
          'dme_identity',
          'hardware',
          'software',
          'bootloader',
          'calibration',
        ]) {
          final value = context[key];
          if (value is String && value.isNotEmpty) recordedTarget[key] = value;
        }
      }
      return CalibrationArtifactInspection(
        fileName: fileName,
        sha256: digest,
        size: bytes.length,
        kind: 'bimmerscope_map_package',
        partialPreview: inspectPartialMap(payloadBytes),
        provider: 'BimmerScope',
        revision: 'v1',
        declaredCompatibility: null,
        signatureStatus: 'not_signed',
        notes: const [
          'Embedded file size and SHA-256 match the package manifest.',
          'Recorded vehicle identity is context only; it does not establish map compatibility.',
          'This package format does not implement ECU authorization, calibration validation, or programming.',
        ],
        packageMetadata: {
          if (artifact['file_name'] is String)
            'source_file': artifact['file_name'] as String,
          'payload_size': payloadBytes.length.toString(),
          'payload_sha256': expectedHash,
          ...recordedTarget,
        },
        comparedSoftwareToken: softwareFindings.token,
        rawSoftwareIdOffset: softwareFindings.rawOffset,
        asciiSoftwareIdOffset: softwareFindings.asciiOffset,
      );
    } catch (error) {
      return CalibrationArtifactInspection(
        fileName: fileName,
        sha256: digest,
        size: bytes.length,
        kind: 'invalid_bimmerscope_map_package',
        provider: 'BimmerScope',
        revision: 'v1',
        declaredCompatibility: null,
        signatureStatus: 'not_signed',
        notes: ['Package validation failed: $error'],
      );
    }
  }
  return CalibrationArtifactInspection(
    fileName: fileName,
    sha256: digest,
    size: bytes.length,
    kind: 'provider_manifest',
    provider: manifest['provider'] as String?,
    revision: manifest['revision'] as String?,
    declaredCompatibility: manifest['compatibility'] as Map<String, dynamic>?,
    signatureStatus: 'declared_but_not_verified',
    notes: const [
      'Manifest signatures require an approved provider public key before they can be trusted.',
    ],
  );
}

Future<File> createBimmerScopeMapPackage({
  required File source,
  required File target,
  required Map<String, String> vehicleContext,
}) async {
  final payload = await source.readAsBytes();
  final manifest = <String, dynamic>{
    'format': bimmerScopeMapPackageFormat,
    'created_at': DateTime.now().toUtc().toIso8601String(),
    'vehicle_context': vehicleContext,
    'artifact': {
      'file_name': source.uri.pathSegments.last,
      'size': payload.length,
      'sha256': sha256.convert(payload).toString(),
      'payload_encoding': 'base64',
      'payload_base64': base64Encode(payload),
    },
  };
  await target.writeAsString(jsonEncode(manifest), flush: true);
  return target;
}

String? _binaryMarker(List<int> bytes) {
  // A narrow, passive inspection of the file header. Do not interpret map
  // addresses or claim a format from arbitrary printable data elsewhere.
  final prefix = latin1.decode(bytes.take(256).toList());
  return RegExp(r'MEVD17[._0-9A-Za-z]{1,20}').firstMatch(prefix)?.group(0);
}

({String? token, int? rawOffset, int? asciiOffset}) _findSoftwareId(
  List<int> bytes,
  String? token,
) {
  final normalized = token?.trim().toUpperCase();
  if (normalized == null || !RegExp(r'^[0-9A-F]{14}$').hasMatch(normalized)) {
    return (token: null, rawOffset: null, asciiOffset: null);
  }
  final rawBytes = <int>[
    for (var index = 0; index < normalized.length; index += 2)
      int.parse(normalized.substring(index, index + 2), radix: 16),
  ];
  final upperAscii = normalized.codeUnits;
  final lowerAscii = normalized.toLowerCase().codeUnits;
  return (
    token: normalized,
    rawOffset: _firstByteSequenceOffset(bytes, rawBytes),
    asciiOffset:
        _firstByteSequenceOffset(bytes, upperAscii) ??
        _firstByteSequenceOffset(bytes, lowerAscii),
  );
}

int? _firstByteSequenceOffset(List<int> bytes, List<int> sequence) {
  if (sequence.isEmpty || sequence.length > bytes.length) return null;
  for (var offset = 0; offset <= bytes.length - sequence.length; offset++) {
    var matches = true;
    for (var index = 0; index < sequence.length; index++) {
      if (bytes[offset + index] != sequence[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return offset;
  }
  return null;
}

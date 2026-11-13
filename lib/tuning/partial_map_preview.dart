import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// Offline observations against the historical MEVD17.2.9 image layout.
/// This is not an executable programming plan or a compatibility decision.
class PartialMapPreview {
  const PartialMapPreview({
    required this.mainHash,
    required this.tailHash,
    required this.gapIsZero,
    required this.calibrationId,
    this.softwareId,
  });

  final String mainHash;
  final String tailHash;
  final bool gapIsZero;
  final String? calibrationId;
  final String? softwareId;

  Map<String, Object?> toJson() => {
    'profile': 'legacy-mevd1729-partial-observation-v1',
    'main_sha256': mainHash,
    'tail_sha256': tailHash,
    'gap_is_zero': gapIsZero,
    'file_calibration_id': calibrationId,
    'file_software_id': softwareId,
    'programming_validated': false,
  };
}

PartialMapPreview? inspectPartialMap(List<int> bytes) {
  if (bytes.length != 0x400000 ||
      !latin1.decode(bytes.sublist(0, 256)).contains('MEVD1729__')) {
    return null;
  }
  final header = ByteData.sublistView(
    Uint8List.fromList(bytes.sublist(0x180000, 0x180040)),
  );
  if (header.getUint32(0x0c, Endian.little) != 0x801ffc00 ||
      header.getUint32(0x38, Endian.little) != 0x80180000 ||
      header.getUint32(0x3c, Endian.little) != 0x801ffbff) {
    return null;
  }
  final id = bytes.sublist(0x1ffd01, 0x1ffd08);
  final hasId = id.any((b) => b != 0) && id.any((b) => b != 255);
  final component = id
      .take(4)
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();
  return PartialMapPreview(
    mainHash: sha256.convert(bytes.sublist(0x180000, 0x1ffc00)).toString(),
    tailHash: sha256.convert(bytes.sublist(0x1ffd00, 0x200000)).toString(),
    gapIsZero: bytes.sublist(0x1ffc00, 0x1ffd00).every((b) => b == 0),
    calibrationId: hasId
        ? '${component.toUpperCase()}-${id.skip(4).map((b) => b.toString().padLeft(3, '0')).join('.')}'
        : null,
    softwareId: bytes[0x20024] == 0x08
        ? bytes
              .sublist(0x20025, 0x2002c)
              .map((b) => b.toRadixString(16).padLeft(2, '0'))
              .join()
              .toUpperCase()
        : null,
  );
}

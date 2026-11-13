import 'dart:typed_data';

import 'package:bmw_app/tuning/partial_map_preview.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List fixture() {
  final bytes = Uint8List(0x400000);
  bytes.setRange(26, 36, 'MEVD1729__'.codeUnits);
  final data = ByteData.sublistView(bytes);
  data.setUint32(0x18000c, 0x801ffc00, Endian.little);
  data.setUint32(0x180038, 0x80180000, Endian.little);
  data.setUint32(0x18003c, 0x801ffbff, Endian.little);
  bytes.setRange(0x1ffd01, 0x1ffd08, [0, 0, 0x1c, 0xdb, 29, 150, 7]);
  return bytes;
}

void main() {
  test('requires size, family marker and embedded boundaries', () {
    expect(inspectPartialMap(Uint8List(64)), isNull);
    final bytes = fixture();
    expect(inspectPartialMap(bytes), isNotNull);
    bytes[26] = 0;
    expect(inspectPartialMap(bytes), isNull);
    final wrongBoundary = fixture()..[0x180038] = 1;
    expect(inspectPartialMap(wrongBoundary), isNull);
  });

  test('software ID requires the observed component record marker', () {
    final bytes = fixture();
    bytes.setRange(0x20025, 0x2002c, [0, 0, 0x1c, 0x9f, 29, 150, 1]);
    expect(inspectPartialMap(bytes)!.softwareId, isNull);
    bytes[0x20024] = 8;
    expect(inspectPartialMap(bytes)!.softwareId, '00001C9F1D9601');
  });

  test(
    'isolates region hashes, reports gap and never approves programming',
    () {
      final bytes = fixture();
      final before = inspectPartialMap(bytes)!;
      expect(before.calibrationId, '00001CDB-029.150.007');
      expect(before.gapIsZero, isTrue);
      bytes[0x1ffc00] = 1;
      final gapChanged = inspectPartialMap(bytes)!;
      expect(gapChanged.gapIsZero, isFalse);
      expect(gapChanged.mainHash, before.mainHash);
      expect(gapChanged.tailHash, before.tailHash);
      bytes[0x180100] = 1;
      final mainChanged = inspectPartialMap(bytes)!;
      expect(mainChanged.mainHash, isNot(before.mainHash));
      expect(mainChanged.tailHash, before.tailHash);
      expect(mainChanged.toJson()['programming_validated'], isFalse);
    },
  );
}

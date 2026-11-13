import 'package:flutter/material.dart';

import 'partial_map_preview.dart';
import '../vehicle/dme_identifier_format.dart';

String? normalizedComponentId(String? value) {
  if (value == null) return null;
  final text = value.trim().toUpperCase();
  if (RegExp(r'^[0-9A-F]{14}$').hasMatch(text)) {
    if (text == '00000000000000' || text == 'FFFFFFFFFFFFFF') return null;
    return text;
  }
  final compact = text.replaceAll(RegExp(r'[-.]'), '');
  final raw = rawDmeComponentId(compact);
  return raw == null ? null : normalizedComponentId(raw);
}

String compareComponentIds(String? file, String? vehicle) {
  final a = normalizedComponentId(file);
  final b = normalizedComponentId(vehicle);
  return a == null || b == null
      ? 'Unavailable'
      : a == b
      ? 'Matches'
      : 'Differs';
}

class FileDmeComparison extends StatelessWidget {
  const FileDmeComparison({
    super.key,
    required this.preview,
    required this.software,
    required this.calibration,
    required this.hardware,
    required this.bootloader,
    required this.sessionId,
    required this.capturedAt,
    required this.realVehicle,
    this.fileBootloader,
  });

  final PartialMapPreview? preview;
  final String? software, calibration, hardware, bootloader;
  final String sessionId;
  final DateTime capturedAt;
  final bool realVehicle;
  final String? fileBootloader;

  @override
  Widget build(BuildContext context) {
    Widget row(String name, String? file, String? vehicle) {
      final available = realVehicle ? vehicle : null;
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '$name · ${compareComponentIds(file, available)}',
              style: const TextStyle(fontWeight: FontWeight.w600),
            ),
            SelectableText('File: ${file ?? 'Not extracted'}'),
            SelectableText(
              'DME: ${available?.trim().isNotEmpty == true ? available : 'Unavailable'}',
            ),
          ],
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          realVehicle
              ? 'DME identity captured when this page opened: ${capturedAt.toLocal()}'
              : 'Real-vehicle DME identity unavailable. Demo and simulator values are excluded.',
        ),
        if (realVehicle) SelectableText('Session: $sessionId'),
        row('Software ID', preview?.softwareId, software),
        row('Calibration ID', preview?.calibrationId, calibration),
        row('Hardware', null, hardware),
        row('Required bootloader', fileBootloader, bootloader),
        const Text(
          'Bootloader identity is extracted only when the startup header, trailer and software dependency agree. Startup memory is excluded from ordinary flashing. Hardware and coding IDs are not established from this file. Filename and package claims are not used.',
        ),
        const SizedBox(height: 8),
        const Text(
          'A different calibration ID may be intentional. Matching IDs do not establish compatibility or approve flashing. Reopen this page after reconnecting to refresh the DME snapshot.',
        ),
      ],
    );
  }
}

import 'package:bmw_app/tuning/file_dme_comparison.dart';
import 'package:bmw_app/tuning/partial_map_preview.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test(
    'compares component encodings and rejects missing or invalid evidence',
    () {
      expect(
        compareComponentIds('00001C9F1D9601', '00001C9F029150001'),
        'Matches',
      );
      expect(
        compareComponentIds('00001cdb-029.150.007', '00001CDB029150007'),
        'Matches',
      );
      expect(
        compareComponentIds('00001CDB-029.150.007', '00001CDB029150008'),
        'Differs',
      );
      expect(compareComponentIds(null, '00001CDB029150007'), 'Unavailable');
      expect(
        compareComponentIds('00001CDB-999.150.007', '00001CDB029150007'),
        'Unavailable',
      );
      expect(
        compareComponentIds('00000000000000', '00000000000000'),
        'Unavailable',
      );
    },
  );

  testWidgets('comparison fits a phone and excludes simulator identity', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(375, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    Widget screen(bool real) => MaterialApp(
      home: Scaffold(
        body: SingleChildScrollView(
          child: FileDmeComparison(
            preview: const PartialMapPreview(
              mainHash: 'a',
              tailHash: 'b',
              gapIsZero: true,
              calibrationId: '00001CDB-029.150.007',
              softwareId: '00001C9F1D9601',
            ),
            software: '00001C9F029150001',
            calibration: '00001CDB029150008',
            hardware: 'HW-example',
            bootloader: '00001901001049002',
            fileBootloader: '00001901001049002',
            sessionId: 'session-1',
            capturedAt: DateTime(2026, 11, 1),
            realVehicle: real,
          ),
        ),
      ),
    );
    await tester.pumpWidget(screen(true));
    expect(find.text('Software ID · Matches'), findsOneWidget);
    expect(find.text('Calibration ID · Differs'), findsOneWidget);
    expect(find.text('Hardware · Unavailable'), findsOneWidget);
    expect(find.text('Required bootloader · Matches'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(screen(false));
    expect(find.text('Software ID · Unavailable'), findsOneWidget);
    expect(find.text('Required bootloader · Unavailable'), findsOneWidget);
    expect(
      find.textContaining('Demo and simulator values are excluded'),
      findsOneWidget,
    );
    expect(find.text('DME: HW-example'), findsNothing);
  });
}

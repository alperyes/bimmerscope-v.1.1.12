import 'dart:io';
import 'dart:ui' as ui;
import 'package:bmw_app/design/app_palette.dart';
import 'package:bmw_app/tuning/flash_map_workspace.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUpAll(() async {
    await (FontLoader(
          'Instrument Sans',
        )..addFont(rootBundle.load('assets/fonts/InstrumentSans-Variable.ttf')))
        .load();
    await (FontLoader(
      'MaterialIcons',
    )..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'))).load();
  });
  Widget screen({
    bool selected = true,
    FlashPagePhase phase = FlashPagePhase.selected,
    VoidCallback? prepare,
    VoidCallback? write,
    VoidCallback? checkAccess,
    bool busy = false,
    Key? capture,
  }) => MaterialApp(
    theme: ThemeData(
      brightness: Brightness.dark,
      useMaterial3: true,
      fontFamily: 'Instrument Sans',
      scaffoldBackgroundColor: AppPalette.background(true),
      colorScheme: ColorScheme.fromSeed(
        seedColor: AppPalette.blue,
        brightness: Brightness.dark,
        surface: AppPalette.surface(true),
      ).copyWith(primary: AppPalette.blue, onPrimary: const Color(0xFF031B3A)),
      appBarTheme: const AppBarTheme(backgroundColor: Colors.black),
    ),
    home: Scaffold(
      appBar: AppBar(title: const Text('Flash a map')),
      body: RepaintBoundary(
        key: capture,
        child: FlashMapWorkspace(
          isDark: true,
          vehicle: 'N20',
          vin: 'WBA3A52010F360747',
          connection: 'Connected',
          fullFlash: false,
          busy: busy,
          phase: phase,
          blockReason: phase == FlashPagePhase.blocked
              ? 'DME hardware identity is unverified.'
              : null,
          fileName: selected ? 'WBA3A52010F360747_00001C9F1D9601.bin' : null,
          fileSize: selected ? '4.0 MiB' : null,
          onChoose: busy ? null : () {},
          onPrepare: prepare,
          onWrite: write,
          onCheckProgrammingAccess: checkAccess,
          onModeChanged: busy ? null : (_) {},
          checkDetails: phase == FlashPagePhase.blocked
              ? const Text(
                  'Exact Bosch hardware identity is unverified; no reviewed programming profile.',
                )
              : null,
          details: const Text('Technical identity and hash records'),
          tools: TextButton(
            onPressed: () {},
            child: const Text('Import agent state'),
          ),
          history: const Text('Saved operation evidence'),
          historySummary: '3 saved records · local evidence only',
          recovery: const Text('Original coding and recovery review controls'),
          progress: busy ? 0.4 : null,
          progressLabel: busy ? '4 of 10 stages completed' : null,
        ),
      ),
    ),
  );
  testWidgets('empty view has one file action and tools stay collapsed', (
    tester,
  ) async {
    await tester.pumpWidget(screen(selected: false));
    await tester.pumpAndSettle();
    expect(find.text('Choose BIN'), findsOneWidget);
    expect(find.text('Prepare flash'), findsNothing);
    expect(find.text('Import agent state'), findsNothing);
    expect(find.text('Technical identity and hash records'), findsNothing);
    await tester.tap(find.text('Advanced tools'));
    await tester.pumpAndSettle();
    expect(find.text('Import agent state'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
  testWidgets(
    'blocked state keeps reason accessible without offering a write',
    (tester) async {
      var prepared = 0;
      await tester.pumpWidget(
        screen(phase: FlashPagePhase.blocked, prepare: () => prepared++),
      );
      await tester.pumpAndSettle();
      expect(find.text('Writing is blocked'), findsOneWidget);
      expect(find.text('DME hardware identity is unverified.'), findsOneWidget);
      expect(find.text('Write to ECU'), findsNothing);
      await tester.ensureVisible(find.text('Prepare again'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Prepare again'));
      expect(prepared, 1);
      expect(find.textContaining('Exact Bosch'), findsNothing);
      await tester.ensureVisible(find.text('Check details'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Check details'));
      await tester.pumpAndSettle();
      expect(find.textContaining('Exact Bosch'), findsOneWidget);
    },
  );
  testWidgets(
    'completed preparation without approval never offers a write',
    (tester) async {
      var checks = 0;
      await tester.pumpWidget(
        screen(
          phase: FlashPagePhase.prepared,
          prepare: () {},
          write: () {},
          checkAccess: () => checks++,
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('File and DME checks complete'), findsOneWidget);
      expect(find.text('Write to ECU'), findsNothing);
      final button = find.text('Check programming access');
      await tester.ensureVisible(button);
      await tester.pumpAndSettle();
      await tester.tap(button);
      expect(checks, 1);
    },
  );
  testWidgets(
    'write requires ready phase and review never offers ordinary writing',
    (tester) async {
      var writes = 0;
      await tester.pumpWidget(
        screen(phase: FlashPagePhase.ready, write: () => writes++),
      );
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Write to ECU'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Write to ECU'));
      expect(writes, 1);
      await tester.pumpWidget(
        screen(phase: FlashPagePhase.review, write: () => writes++),
      );
      await tester.pumpAndSettle();
      await tester.drag(
        find.byKey(const Key('flash-map-workspace')),
        const Offset(0, 1200),
      );
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('flash-review-warning')), findsOneWidget);
      expect(find.text('Write to ECU'), findsNothing);
      await tester.scrollUntilVisible(
        find.text('Recovery'),
        300,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.pumpAndSettle();
      expect(
        find.text('Original coding and recovery review controls'),
        findsOneWidget,
      );
    },
  );
  testWidgets('phone and desktop layout remain readable with long filenames', (
    tester,
  ) async {
    for (final size in [const Size(375, 950), const Size(1280, 960)]) {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      await tester.pumpWidget(
        screen(phase: FlashPagePhase.blocked, prepare: () {}),
      );
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull, reason: 'layout at $size');
      expect(find.text('Writing is blocked'), findsOneWidget);
    }
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
  });
  testWidgets('render workspace review images', (tester) async {
    final output = Platform.environment['BIMMERSCOPE_FLASH_UI_REVIEW'];
    if (output == null) return;
    for (final entry in [
      ('desktop', const Size(1280, 1000), FlashPagePhase.blocked),
      ('phone', const Size(375, 1050), FlashPagePhase.selected),
      ('empty', const Size(1280, 900), FlashPagePhase.selected),
    ]) {
      tester.view.physicalSize = entry.$2;
      tester.view.devicePixelRatio = 1;
      final key = GlobalKey();
      await tester.pumpWidget(
        screen(
          selected: entry.$1 != 'empty',
          phase: entry.$3,
          prepare: () {},
          capture: key,
        ),
      );
      await tester.pumpAndSettle();
      final boundary =
          key.currentContext!.findRenderObject()! as RenderRepaintBoundary;
      await tester.runAsync(() async {
        final image = await boundary.toImage();
        final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
        await Directory(output).create(recursive: true);
        await File(
          '$output/${entry.$1}.png',
        ).writeAsBytes(bytes!.buffer.asUint8List());
        image.dispose();
      });
      expect(tester.takeException(), isNull);
    }
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
  });
}

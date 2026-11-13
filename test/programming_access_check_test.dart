import 'dart:convert';
import 'package:bmw_app/diagnostics/dme_preparation_2_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  testWidgets('access check uses fixed defaults and confirms before sending', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({
      'dme_preparation_2_request_edits_v1': jsonEncode({
        'requests': ['11 01'],
        'responsePrefix': '34',
        'postKeyRequests': ['31 01 FF 00'],
      }),
    });
    final connection = ValueNotifier('Connected');
    var before = 0;
    var after = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: DmePreparation2Screen(
          vin: 'WBA3A52010F360747',
          currentBootloader: '00001901001049002',
          connectionStatus: connection,
          isDark: true,
          accessCheckOnly: true,
          onBeforeSend: () async {
            before++;
          },
          onAfterSend: () async {
            after++;
          },
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('Programming access check'), findsOneWidget);
    expect(find.text('Edit requests'), findsNothing);
    expect(find.text('Edit messages'), findsNothing);
    expect(find.text('22 F1 86'), findsOneWidget);
    final start = find.text('Start sequence');
    await tester.scrollUntilVisible(
      start,
      300,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();
    await tester.tap(start);
    await tester.pumpAndSettle();
    expect(find.text('Check programming access?'), findsOneWidget);
    expect(find.textContaining('14 UDS requests'), findsOneWidget);
    expect(before, 0);
    expect(after, 0);
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(before, 0);
    expect(after, 0);
    await tester.pumpWidget(const SizedBox());
    connection.dispose();
  });
}

import 'package:bmw_app/app.dart';
import 'package:bmw_app/dashboard/dashboard_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  testWidgets(
    'startup uncertainty is visible while offline workspace stays available',
    (tester) async {
      SharedPreferences.setMockInitialValues({});
      await tester.pumpWidget(
        const BmwEnetApp(
          previewMode: true,
          startupSafetyReport: {
            'blocked': true,
            'detail': 'Uncertain flash evidence',
            'operations': [
              {'directory': 'saved-operation-path'},
            ],
          },
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('Vehicle access paused'), findsOneWidget);
      expect(find.text('saved-operation-path'), findsOneWidget);
      expect(find.byType(DashboardScreen), findsOneWidget);
      final button = tester.widget<TextButton>(
        find.widgetWithText(TextButton, 'Recheck'),
      );
      expect(button.onPressed, isNull);
      expect(find.text('Dismiss'), findsNothing);
    },
  );
  testWidgets('clear startup inventory does not add a paused notice', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    await tester.pumpWidget(
      const BmwEnetApp(
        previewMode: true,
        startupSafetyReport: {'blocked': false},
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('Vehicle access paused'), findsNothing);
  });
}

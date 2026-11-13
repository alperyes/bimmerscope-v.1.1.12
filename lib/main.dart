import 'package:bmw_app/app.dart';
import 'package:bmw_app/src/rust/frb_generated.dart';
import 'package:flutter/widgets.dart';
import 'dart:convert';
import 'package:path_provider/path_provider.dart';
import 'package:bmw_app/src/rust/api/vehicle.dart' as vehicle;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  String? safetyRoot;
  Map<String, dynamic> report;
  try {
    safetyRoot = (await getApplicationSupportDirectory()).path;
    report =
        jsonDecode(
              await vehicle.initializeVehicleSafety(rootDirectory: safetyRoot),
            )
            as Map<String, dynamic>;
  } catch (error) {
    report = {
      'blocked': true,
      'detail': 'Startup evidence inspection failed: $error',
      'operations': <dynamic>[],
    };
  }
  runApp(BmwEnetApp(startupSafetyReport: report, safetyRoot: safetyRoot));
}

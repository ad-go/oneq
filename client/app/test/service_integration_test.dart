// Real end-to-end test against a live mesh: ONEQ_INTEGRATION=1 ONEQ_CLI=<oneqclient.exe> ONEQ_PWFILE=<file> ONEQ_CAFILE=<pem> ONEQ_RELAY=<url>
// ONEQ_COMMUNITY=<c> ONEQ_USER=<u> flutter test test/service_integration_test.dart   (needs administrator rights)
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:oneq_app/controller.dart';
import 'package:oneq_app/desktop_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  final env = Platform.environment;
  final enabled = env['ONEQ_INTEGRATION'] == '1';

  Future<void> until(bool Function() ok, String what, {int seconds = 40}) async {
    final end = DateTime.now().add(Duration(seconds: seconds));
    while (!ok()) {
      if (DateTime.now().isAfter(end)) fail('timeout waiting for: $what');
      await Future.delayed(const Duration(milliseconds: 500));
    }
  }

  Future<String> sc(String what) async => (await Process.run('sc', [what, 'oneq'])).stdout as String;

  test('connect/disconnect drive the real service; Start at boot decides the start type', () async {
    SharedPreferences.setMockInitialValues({});
    final c = OneqController();
    c.settings
      ..relays = env['ONEQ_RELAY']!
      ..community = env['ONEQ_COMMUNITY']!
      ..user = env['ONEQ_USER']!
      ..name = 'win-flutter-test'
      ..ca = File(env['ONEQ_CAFILE']!).readAsStringSync()
      ..autoStart = false;
    c.password = File(env['ONEQ_PWFILE']!).readAsStringSync().trim();

    await c.connect();
    expect(c.error, isNull);
    await until(() => c.connected && (c.snap?.peers.any((p) => p.session) ?? false), 'connected with a session');
    expect(await sc('qc'), contains('DEMAND_START')); // Start at boot off -> manual
    expect(c.snap!.ip, isNotEmpty);

    // the app's disconnect stops the service but keeps it installed
    await c.disconnect();
    await until(() => !c.active, 'inactive');
    expect(await sc('query'), contains('STOPPED'));
    expect(await sc('qc'), contains('DEMAND_START'));

    // Start at boot on -> auto start
    c.settings.autoStart = true;
    await c.connect();
    await until(() => c.connected, 'connected again');
    expect(await sc('qc'), contains('AUTO_START'));

    // a second controller (like the app restarted, or the web UI) picks up the running service
    final d = OneqController();
    await d.attach();
    expect(d.active, isTrue);
    expect(d.snap?.ip, c.snap?.ip);
    await DesktopService.control('stop');
  }, skip: enabled ? false : 'set ONEQ_INTEGRATION=1 (needs a live mesh and administrator rights)', timeout: const Timeout(Duration(minutes: 4)));
}

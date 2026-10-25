// Smoke test of the dart:ffi path used by the UI: ONEQ_CORE_LIB=<oneq_core.dll> dart run tool/ffi_smoke.dart <config.json>
import 'dart:convert';
import 'dart:io';

import 'package:oneq_app/core.dart';

Future<void> main(List<String> args) async {
  final cfg = jsonDecode(File(args[0]).readAsStringSync()) as Map<String, dynamic>;
  await OneqCore.prepare(cfg);
  final s0 = await OneqCore.status();
  stdout.writeln('prepared: ${s0.ip}/${s0.prefix} mtu ${s0.mtu}');
  await OneqCore.run(wintun: args.length > 1 ? args[1] : null);
  for (var i = 0; i < 20; i++) {
    await Future.delayed(const Duration(seconds: 1));
    final s = await OneqCore.status();
    final up = s.peers.where((p) => p.session).length;
    stdout.writeln('t=${i + 1}s state=${s.state} relay=${s.relayConnected} sessions=$up/${s.peers.length}');
  }
  final s = await OneqCore.status();
  for (final p in s.peers) {
    stdout.writeln('  ${p.name} ${p.ip} session=${p.session} path=${p.path}');
  }
  stdout.writeln('holding the tunnel for 40 s ...');
  await Future.delayed(const Duration(seconds: 40));
  await OneqCore.stop();
  stdout.writeln('stopped: ${(await OneqCore.status()).state}');
}

// Desktop (Windows/macOS/Linux): the node runs as a background service installed by `oneqclient service install`, exactly
// like the Android foreground service; this app only configures, starts/stops it and watches the status file it writes.
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'controller.dart';
import 'core.dart';

class DesktopService {
  static String get dir {
    if (Platform.isWindows) return '${Platform.environment['ProgramData'] ?? r'C:\ProgramData'}\\oneq';
    if (Platform.isMacOS) return '/Library/Application Support/oneq';
    return '/etc/oneq-client';
  }

  static String get cli {
    final o = Platform.environment['ONEQ_CLI']; // tests and unusual installs
    if (o != null && o.isNotEmpty) return o;
    final exe = Platform.resolvedExecutable;
    final d = exe.substring(0, exe.lastIndexOf(Platform.pathSeparator));
    if (Platform.isWindows) return '$d\\oneqclient.exe';
    const installed = '/usr/local/libexec/oneq/oneqclient'; // root-owned copy made by install.sh
    return File(installed).existsSync() ? installed : '$d/oneqclient';
  }

  /// The service's snapshot when it is running (status file fresh and not "stopped"), else null.
  static Future<Snapshot?> readStatus() async {
    try {
      final j = jsonDecode(await File('$dir${Platform.pathSeparator}status.json').readAsString()) as Map<String, dynamic>;
      final age = DateTime.now().millisecondsSinceEpoch / 1000 - (j['updated'] as num);
      final snap = j['snapshot'] as Map<String, dynamic>;
      if (age > 10 || snap['state'] == 'stopped') return null;
      return Snapshot(snap);
    } catch (_) {
      return null;
    }
  }

  static String _q(String s) => "'${s.replaceAll("'", "'\\''")}'";

  /// Runs `oneqclient <args>` for each command with administrator rights (one prompt for all); `(args, ignoreFailure)`.
  static Future<String> elevated(List<(List<String>, bool)> cmds) async {
    if (Platform.isWindows) {
      // the app's manifest already demands administrator rights
      final out = StringBuffer();
      for (final (args, ignore) in cmds) {
        final r = await Process.run(cli, args);
        out.write(r.stdout);
        if (r.exitCode != 0 && !ignore) throw OneqError('${r.stdout}${r.stderr}'.trim());
      }
      return out.toString().trim();
    }
    final line = cmds.map((c) {
      final s = [_q(cli), ...c.$1.map(_q)].join(' ');
      return c.$2 ? '$s || true' : s;
    }).join(' && ');
    final ProcessResult r;
    if (Platform.isMacOS) {
      final esc = line.replaceAll(r'\', r'\\').replaceAll('"', r'\"');
      r = await Process.run('osascript', ['-e', 'do shell script "$esc" with administrator privileges']);
    } else {
      r = await Process.run('pkexec', ['sh', '-c', line]);
    }
    if (r.exitCode != 0) {
      final e = '${r.stderr}'.trim();
      throw OneqError(e.contains('-128') ? 'Cancelled.' : e);
    }
    return '${r.stdout}'.trim();
  }

  static Future<File> _private(String prefix, String content) async {
    final f = File('${Directory.systemTemp.path}${Platform.pathSeparator}$prefix-${Random.secure().nextInt(1 << 32)}');
    await f.writeAsString(content);
    if (!Platform.isWindows) await Process.run('chmod', ['600', f.path]);
    return f;
  }

  /// Installs (replacing any previous one) and starts the service from the app's settings.
  static Future<void> install(Settings s, String password, String keyFile) async {
    final pw = await _private('oneq-pw', password);
    File? ca;
    try {
      final args = <String>['service', 'install'];
      for (final r in s.relayList) {
        args.addAll(['--relay', r]);
      }
      args.addAll(['--community', s.community.trim(), '--user', s.user.trim(), '--password-file', pw.path, '--key-file', keyFile]);
      if (s.name.trim().isNotEmpty) args.addAll(['--name', s.name.trim()]);
      if (s.ca.trim().isNotEmpty) {
        ca = await _private('oneq-ca', s.ca);
        args.addAll(['--cafile', ca.path]);
      }
      if (s.forceRelay) args.add('--force-relay');
      if (s.acceptRoutes) args.add('--accept-routes');
      if (s.exitNode.isNotEmpty) args.addAll(['--exit-node', s.exitNode]);
      if (!s.updateCheck) args.add('--no-update-check');
      if (!s.autoStart) args.add('--no-autostart');
      await elevated([
        (['service', 'uninstall'], true),
        (args, false),
      ]);
    } finally {
      for (final f in [pw, ca]) {
        if (f != null && await f.exists()) await f.delete();
      }
    }
  }

  static Future<void> control(String what) => elevated([
        (['service', what], false)
      ]);
}

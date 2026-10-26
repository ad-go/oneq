import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'core.dart';
import 'desktop_service.dart';

/// What the user configures. The password is never part of it unless an export explicitly asks for it.
class Settings {
  String relays = '';
  String community = '';
  String user = '';
  String name = '';
  String ca = '';
  bool forceRelay = false;
  /// use the private networks the administrator routed through a gateway member
  bool acceptRoutes = false;
  bool startHidden = false;
  /// Android: keep the (encrypted) connection config so the node starts at boot / as always-on VPN
  bool autoStart = false;
  /// check GitHub for a newer release (default yes)
  bool updateCheck = true;

  List<String> get relayList => relays.split(RegExp(r'[\s,]+')).where((s) => s.isNotEmpty).toList();

  Map<String, dynamic> toJson() => {
        'relays': relayList,
        'community': community,
        'user': user,
        'name': name,
        'ca_pem': ca,
        'force_relay': forceRelay,
        'accept_routes': acceptRoutes,
        'start_hidden': startHidden,
        'auto_start': autoStart,
        'update_check': updateCheck,
      };

  /// Validates an imported map; throws [FormatException] with a message for the user.
  static Settings fromJson(Map<String, dynamic> j) {
    final s = Settings();
    final r = j['relays'];
    if (r is! List || r.isEmpty || r.any((e) => e is! String || !e.startsWith('https://'))) {
      throw const FormatException('"relays" must be a list of https:// URLs');
    }
    s.relays = r.join('\n');
    String str(String k, {bool required = false}) {
      final v = j[k];
      if (v == null && !required) return '';
      if (v is! String || (required && v.trim().isEmpty)) throw FormatException('"$k" is missing or not text');
      return v;
    }

    s.community = str('community', required: true);
    s.user = str('user', required: true);
    s.name = str('name');
    s.ca = str('ca_pem');
    if (s.ca.isNotEmpty && !s.ca.contains('BEGIN CERTIFICATE')) throw const FormatException('"ca_pem" is not a PEM certificate');
    s.forceRelay = j['force_relay'] == true;
    s.acceptRoutes = j['accept_routes'] == true;
    s.startHidden = j['start_hidden'] == true;
    s.autoStart = j['auto_start'] == true;
    s.updateCheck = j['update_check'] != false;
    return s;
  }
}

class ExportResult {
  final String json;
  ExportResult(this.json);
}

/// State shared by the window, the tray menu and the settings page.
class OneqController extends ChangeNotifier {
  static const vpn = MethodChannel('ro.1q.oneq/vpn');
  Settings settings = Settings();
  String password = ''; // memory only
  bool busy = false;
  bool active = false;
  String? error;
  Snapshot? snap;
  Timer? _timer;

  bool get connected => active && snap?.state == 'connected';

  Future<void> load() async {
    try {
      final p = await SharedPreferences.getInstance();
      settings
        ..relays = p.getString('relays') ?? ''
        ..community = p.getString('community') ?? ''
        ..user = p.getString('user') ?? ''
        ..name = p.getString('name') ?? ''
        ..ca = p.getString('ca') ?? ''
        ..forceRelay = p.getBool('force') ?? false
        ..acceptRoutes = p.getBool('routes') ?? false
        ..startHidden = p.getBool('hidden') ?? false
        ..autoStart = p.getBool('autostart') ?? false
        ..updateCheck = p.getBool('updatecheck') ?? true;
    } catch (_) {}
    notifyListeners();
  }

  Future<void> save() async {
    try {
      final p = await SharedPreferences.getInstance();
      await p.setString('relays', settings.relays);
      await p.setString('community', settings.community);
      await p.setString('user', settings.user);
      await p.setString('name', settings.name);
      await p.setString('ca', settings.ca);
      await p.setBool('force', settings.forceRelay);
      await p.setBool('routes', settings.acceptRoutes);
      await p.setBool('hidden', settings.startHidden);
      await p.setBool('autostart', settings.autoStart);
      await p.setBool('updatecheck', settings.updateCheck);
    } catch (_) {}
    notifyListeners();
  }

  /// tests only: where the node key lives
  String? keyFileOverride;

  Future<String> keyFile() async {
    if (keyFileOverride != null) return keyFileOverride!;
    if (Platform.isAndroid) return '${await vpn.invokeMethod<String>('filesDir')}/client.key';
    final base = Platform.environment['APPDATA'] ?? '${Platform.environment['HOME'] ?? '.'}/.config';
    return '$base${Platform.pathSeparator}oneq${Platform.pathSeparator}client.key';
  }

  // ------------------------------------------------------------------ connect / disconnect
  // Same model on every platform: the node is a background service (Android foreground service, Windows service,
  // launchd daemon); this class only starts/stops it and watches its status.
  bool get _desktop => !Platform.isAndroid;
  DateTime _startedAt = DateTime.fromMillisecondsSinceEpoch(0);

  Future<void> connect() async {
    final s = settings;
    if (s.relayList.isEmpty || s.community.isEmpty || s.user.isEmpty || password.isEmpty) {
      error = 'Fill in relay, community, user and password.';
      notifyListeners();
      return;
    }
    busy = true;
    error = null;
    notifyListeners();
    await save();
    try {
      if (Platform.isAndroid) {
        final cfg = <String, dynamic>{
          'relays': s.relayList,
          'community': s.community.trim(),
          'user': s.user.trim(),
          'password': password,
          'name': s.name.trim().isEmpty ? Platform.localHostname : s.name.trim(),
          'ca_pem': s.ca,
          'key_file': await keyFile(),
          'force_relay': s.forceRelay,
          'accept_routes': s.acceptRoutes,
          'update_check': s.updateCheck,
        };
        final ok = await vpn.invokeMethod<bool>('start', {'config': jsonEncode(cfg), 'persist': s.autoStart});
        if (ok != true) throw OneqError('The VPN permission was refused.');
      } else {
        await DesktopService.install(s, password, await keyFile());
      }
      _startedAt = DateTime.now();
      active = true;
      _watch();
      await poll();
    } catch (e) {
      error = e.toString();
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  void _watch() {
    _timer?.cancel();
    _timer = Timer.periodic(Duration(seconds: _desktop ? 2 : 1), (_) => poll());
  }

  /// The node may already be running (started earlier, at boot, by the web UI, or as Android's always-on VPN): pick it up.
  Future<void> attach() async {
    try {
      if (_desktop) {
        _watch(); // keeps following the service for as long as the app lives
        await poll();
      } else {
        final st = await vpn.invokeMethod<Map>('state');
        if (st?['running'] == true) {
          active = true;
          _watch();
          await poll();
        }
      }
    } catch (_) {}
  }

  Future<void> poll() async {
    try {
      if (_desktop) {
        final st = await DesktopService.readStatus();
        if (st != null) {
          snap = st;
          _takeUpdate(st);
          active = true;
          error = st.state == 'error' ? st.message : null;
        } else if (DateTime.now().difference(_startedAt) > const Duration(seconds: 20)) {
          snap = null;
          active = false;
        }
        notifyListeners();
        return;
      }
      final st = await vpn.invokeMethod<Map>('state');
      final running = st?['running'] == true;
      final err = (st?['error'] as String?) ?? '';
      if (!running && DateTime.now().difference(_startedAt) > const Duration(seconds: 8)) {
        _timer?.cancel();
        active = false;
        snap = null;
        if (err.isNotEmpty) error = err;
        notifyListeners();
        return;
      }
      error = err.isEmpty ? null : err;
      snap = await OneqCore.status();
      _takeUpdate(snap!);
      notifyListeners();
    } catch (_) {}
  }

  // ------------------------------------------------------------------ updates (never blocks connect/disconnect)
  UpdateInfo? updateInfo;
  bool updateDismissed = false; // this session only
  bool updateBusy = false;
  String updateMessage = '';

  /// The banner shows when the last result says a newer release exists and the user has not dismissed it.
  bool get updateBanner => updateInfo?.available == true && !updateDismissed;

  void _takeUpdate(Snapshot st) {
    if (st.update != null && !updateBusy) updateInfo = st.update;
  }

  void dismissUpdate() {
    updateDismissed = true;
    notifyListeners();
  }

  /// Manual check: always works, bypasses the cache.
  Future<void> checkUpdate() async {
    if (updateBusy) return;
    updateBusy = true;
    updateMessage = 'Checking...';
    notifyListeners();
    final r = await OneqCore.updateCheck(force: true);
    updateInfo = r;
    updateBusy = false;
    if (r.available) {
      updateDismissed = false;
      updateMessage = 'Version ${r.latest} is available (you have ${r.current}).';
    } else if (r.status == 'current') {
      updateMessage = 'You have the latest version (${r.current}).';
    } else {
      updateMessage = 'Could not check for updates: ${r.error ?? 'unknown result'}';
    }
    notifyListeners();
  }

  /// tests only
  String? downloadDirOverride;

  /// Windows: the Downloads folder; Android: the app's external Downloads directory (no permission needed).
  Future<String> downloadDir() async {
    if (downloadDirOverride != null) return downloadDirOverride!;
    if (Platform.isAndroid) return (await vpn.invokeMethod<String>('downloadsDir'))!;
    final home = Platform.environment['USERPROFILE'] ?? Platform.environment['HOME'] ?? '.';
    final d = Directory('$home${Platform.pathSeparator}Downloads');
    await d.create(recursive: true);
    return d.path;
  }

  Future<void> downloadUpdate() async {
    if (updateBusy) return;
    updateBusy = true;
    updateMessage = 'Downloading and verifying...';
    notifyListeners();
    try {
      final r = await OneqCore.updateDownload(await downloadDir());
      updateMessage = r.ok ? 'Downloaded and verified: ${r.path}. Install it when you are ready.' : 'Download failed: ${r.error}';
    } catch (e) {
      updateMessage = 'Download failed: $e';
    }
    updateBusy = false;
    notifyListeners();
  }

  Future<void> disconnect() async {
    busy = true;
    error = null;
    notifyListeners();
    try {
      if (Platform.isAndroid) {
        _timer?.cancel();
        await vpn.invokeMethod('stop');
      } else {
        await DesktopService.control('stop');
      }
      active = false;
      snap = null;
    } catch (e) {
      error = e.toString();
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  // ------------------------------------------------------------------ export / import
  /// [withPassword] and [withKey] put secrets into the text; the caller has warned the user.
  Future<String> exportJson({bool withPassword = false, bool withKey = false}) async {
    final m = <String, dynamic>{'format': 'oneq-settings', 'version': 1, 'settings': settings.toJson()};
    if (withPassword && password.isNotEmpty) m['password'] = password;
    if (withKey) {
      final f = File(await keyFile());
      if (await f.exists()) m['node_key'] = (await f.readAsString()).trim();
    }
    return const JsonEncoder.withIndent('  ').convert(m);
  }

  /// Returns a human-readable summary of what was imported; throws [FormatException] for a bad file.
  Future<String> importJson(String text) async {
    if (active) throw const FormatException('Disconnect before importing settings.');
    final Object? m;
    try {
      m = jsonDecode(text);
    } on FormatException {
      throw const FormatException('Not a JSON file.');
    }
    if (m is! Map<String, dynamic> || m['format'] != 'oneq-settings') throw const FormatException('Not a oneq settings file.');
    if (m['version'] != 1) throw FormatException('Unsupported settings version ${m['version']}.');
    final s = Settings.fromJson((m['settings'] as Map).cast<String, dynamic>());
    final parts = <String>['settings'];
    if (m['password'] is String && (m['password'] as String).isNotEmpty) {
      password = m['password'] as String;
      parts.add('password (kept in memory only)');
    }
    if (m['node_key'] is String && (m['node_key'] as String).isNotEmpty) {
      final key = (m['node_key'] as String).trim();
      try {
        final raw = base64Decode(key);
        if (raw.length != 32 + 2400) throw const FormatException('bad length');
      } catch (_) {
        throw const FormatException('The node key in the file is damaged.');
      }
      final f = File(await keyFile());
      await f.parent.create(recursive: true);
      if (await f.exists()) await f.rename('${f.path}.bak');
      await f.writeAsString('$key\n');
      parts.add('node key (the old one was kept as client.key.bak)');
    }
    settings = s;
    await save();
    return 'Imported: ${parts.join(', ')}.';
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }
}

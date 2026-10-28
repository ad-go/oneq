// dart:ffi binding of the oneq Rust core (see client/core/src/ffi.rs).
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

DynamicLibrary _open() {
  final override = Platform.environment['ONEQ_CORE_LIB']; // tests and tools
  if (override != null) return DynamicLibrary.open(override);
  if (Platform.isWindows) return DynamicLibrary.open('oneq_core.dll');
  if (Platform.isAndroid) return DynamicLibrary.open('liboneq_core.so');
  if (Platform.isMacOS) return DynamicLibrary.open('liboneq_core.dylib');
  return DynamicLibrary.open('liboneq_core.so');
}

class OneqError implements Exception {
  final String message;
  OneqError(this.message);
  @override
  String toString() => message;
}

class Peer {
  final String name, ip, path, publicIp;
  final bool online, session, exitNode;
  Peer(Map<String, dynamic> j)
      : name = j['name'] ?? '',
        ip = j['ip'] ?? '',
        path = j['path'] ?? '-',
        publicIp = j['public_ip'] ?? '',
        online = j['online'] ?? false,
        session = j['session'] ?? false,
        exitNode = j['exit_node'] == true;
}

/// Result of an update check (spec: UPDATE-SPEC.md). Network work is done by the Rust core.
class UpdateInfo {
  final String current, latest, status, url, notes, assetName;
  final bool available;
  final String? error, downloadUrl;
  UpdateInfo(Map<String, dynamic> j)
      : current = '${j['current'] ?? ''}',
        latest = '${j['latest'] ?? ''}',
        status = '${j['status'] ?? 'unknown'}',
        url = '${j['url'] ?? ''}',
        notes = '${j['notes'] ?? ''}',
        available = j['update_available'] == true,
        error = j['error'] as String?,
        assetName = '${(j['asset'] is Map ? j['asset']['name'] : null) ?? ''}',
        downloadUrl = j['asset'] is Map ? j['asset']['download_url'] as String? : null;
}

class DownloadResult {
  final bool ok;
  final String path, error;
  DownloadResult(Map<String, dynamic> j)
      : ok = j['ok'] == true,
        path = '${j['path'] ?? ''}',
        error = '${j['error'] ?? 'unknown error'}';
}

class Snapshot {
  final String state, message, ip, community, relayUrl, natType, natPublic;
  final bool? natInbound;
  final int prefix, mtu, txBytes, rxBytes;
  final bool relayConnected;
  final List<Peer> peers;
  final List<String> log;
  final UpdateInfo? update;
  Snapshot(Map<String, dynamic> j)
      : state = j['state'] ?? 'idle',
        message = j['message'] ?? '',
        ip = j['ip'] ?? '',
        community = j['community'] ?? '',
        natType = j['nat_type'] ?? '',
        natPublic = j['nat_public'] ?? '',
        natInbound = j['nat_inbound'],
        relayUrl = j['relay_url'] ?? '',
        prefix = j['prefix'] ?? 0,
        mtu = j['mtu'] ?? 0,
        txBytes = j['tx_bytes'] ?? 0,
        rxBytes = j['rx_bytes'] ?? 0,
        relayConnected = j['relay_connected'] ?? false,
        peers = [for (final p in (j['peers'] ?? const [])) Peer(p)],
        log = [for (final l in (j['log'] ?? const [])) l.toString()],
        update = j['update'] is Map<String, dynamic> ? UpdateInfo(j['update']) : null;
}

String _takeString(DynamicLibrary lib, Pointer<Utf8> p) {
  final s = p.toDartString();
  lib.lookupFunction<Void Function(Pointer<Utf8>), void Function(Pointer<Utf8>)>('oneq_free_string')(p);
  return s;
}

String _lastError(DynamicLibrary lib) => _takeString(
    lib, lib.lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('oneq_last_error')());

/// Every call runs in a short-lived isolate: login and TUN creation block for seconds.
class OneqCore {
  /// Log in and join; returns normally on success.
  static Future<void> prepare(Map<String, dynamic> config) => Isolate.run(() {
        final lib = _open();
        final f = lib.lookupFunction<Int32 Function(Pointer<Utf8>), int Function(Pointer<Utf8>)>('oneq_prepare');
        final c = jsonEncode(config).toNativeUtf8();
        try {
          if (f(c) != 0) throw OneqError(_lastError(lib));
        } finally {
          malloc.free(c);
        }
      });

  /// Start the engine. [fd] >= 0 = TUN descriptor from Android's VpnService; -1 = create the interface (desktop).
  static Future<void> run({String ifname = 'oneq', String? wintun, int fd = -1}) => Isolate.run(() {
        final lib = _open();
        final f = lib.lookupFunction<Int32 Function(Pointer<Utf8>, Pointer<Utf8>, Int32),
            int Function(Pointer<Utf8>, Pointer<Utf8>, int)>('oneq_run');
        final a = ifname.toNativeUtf8();
        final w = wintun == null ? nullptr.cast<Utf8>() : wintun.toNativeUtf8();
        try {
          if (f(a, w, fd) != 0) throw OneqError(_lastError(lib));
        } finally {
          malloc.free(a);
          if (wintun != null) malloc.free(w);
        }
      });

  static Future<void> stop() => Isolate.run(() {
        _open().lookupFunction<Void Function(), void Function()>('oneq_stop')();
      });

  static Future<Snapshot> status() => Isolate.run(() {
        final lib = _open();
        final p = lib.lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('oneq_status_json')();
        return Snapshot(jsonDecode(_takeString(lib, p)) as Map<String, dynamic>);
      });

  /// Update check; [force] bypasses the core's cache (manual action). Never throws: errors come back in the result.
  static Future<UpdateInfo> updateCheck({bool force = true}) => Isolate.run(() {
        try {
          final lib = _open();
          final f = lib.lookupFunction<Pointer<Utf8> Function(Int32), Pointer<Utf8> Function(int)>('oneq_update_check_json');
          return UpdateInfo(jsonDecode(_takeString(lib, f(force ? 1 : 0))) as Map<String, dynamic>);
        } catch (e) {
          return UpdateInfo({'status': 'error', 'error': '$e'});
        }
      });

  /// Download + SHA-256 verification of the installer for this platform into [dir].
  static Future<DownloadResult> updateDownload(String dir) => Isolate.run(() {
        try {
          final lib = _open();
          final f = lib.lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>), Pointer<Utf8> Function(Pointer<Utf8>)>(
              'oneq_update_download_json');
          final d = dir.toNativeUtf8();
          try {
            return DownloadResult(jsonDecode(_takeString(lib, f(d))) as Map<String, dynamic>);
          } finally {
            malloc.free(d);
          }
        } catch (e) {
          return DownloadResult({'ok': false, 'error': '$e'});
        }
      });
}

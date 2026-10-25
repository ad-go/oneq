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
  final String name, ip, path;
  final bool online, session;
  Peer(Map<String, dynamic> j)
      : name = j['name'] ?? '',
        ip = j['ip'] ?? '',
        path = j['path'] ?? '-',
        online = j['online'] ?? false,
        session = j['session'] ?? false;
}

class Snapshot {
  final String state, message, ip, community, relayUrl, natType, natPublic;
  final bool? natInbound;
  final int prefix, mtu, txBytes, rxBytes;
  final bool relayConnected;
  final List<Peer> peers;
  final List<String> log;
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
        log = [for (final l in (j['log'] ?? const [])) l.toString()];
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
}

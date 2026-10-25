import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:oneq_app/controller.dart';
import 'package:shared_preferences/shared_preferences.dart';

const ca = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';

OneqController sample() {
  final c = OneqController();
  c.settings
    ..relays = 'https://r1.example.org:8443\nhttps://r2.example.org'
    ..community = 'lan'
    ..user = 'alice'
    ..name = 'laptop'
    ..ca = ca
    ..forceRelay = true;
  c.password = 'secret-pw';
  return c;
}

void main() {
  late Directory tmp;
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    tmp = Directory.systemTemp.createTempSync('oneq-test');
  });
  tearDown(() => tmp.deleteSync(recursive: true));

  test('export leaves secrets out by default and import restores the settings', () async {
    final a = sample();
    final text = await a.exportJson();
    expect(text.contains('secret-pw'), isFalse);
    final j = jsonDecode(text) as Map<String, dynamic>;
    expect(j.containsKey('password'), isFalse);
    expect(j.containsKey('node_key'), isFalse);
    final b = OneqController();
    final msg = await b.importJson(text);
    expect(msg, 'Imported: settings.');
    expect(b.settings.relayList, ['https://r1.example.org:8443', 'https://r2.example.org']);
    expect((b.settings.community, b.settings.user, b.settings.name, b.settings.forceRelay), ('lan', 'alice', 'laptop', true));
    expect(b.settings.ca, ca);
    expect(b.password, '');
    expect((await SharedPreferences.getInstance()).getString('community'), 'lan'); // persisted
  });

  test('password and node key are exported only when asked, and the old key is kept as .bak', () async {
    final key = base64Encode(List<int>.generate(32 + 2400, (i) => i % 251));
    final src = File('${tmp.path}/src.key')..writeAsStringSync('$key\n');
    final a = sample()..keyFileOverride = src.path;
    final text = await a.exportJson(withPassword: true, withKey: true);
    expect(jsonDecode(text)['password'], 'secret-pw');
    final dst = File('${tmp.path}/sub/dst.key');
    dst.parent.createSync();
    dst.writeAsStringSync('old\n');
    final b = OneqController()..keyFileOverride = dst.path;
    final msg = await b.importJson(text);
    expect(msg, contains('password'));
    expect(msg, contains('node key'));
    expect(b.password, 'secret-pw');
    expect(dst.readAsStringSync().trim(), key);
    expect(File('${dst.path}.bak').readAsStringSync().trim(), 'old');
  });

  test('bad files are refused with a clear message and change nothing', () async {
    final b = sample();
    Future<String> err(String t) async {
      try {
        await b.importJson(t);
      } on FormatException catch (e) {
        return e.message;
      }
      return 'ACCEPTED';
    }

    final good = jsonDecode(await sample().exportJson()) as Map<String, dynamic>;
    Map<String, dynamic> with_(void Function(Map<String, dynamic>) f) {
      final m = jsonDecode(jsonEncode(good)) as Map<String, dynamic>;
      f(m);
      return m;
    }

    expect(await err('not json'), 'Not a JSON file.');
    expect(await err('{"format":"other"}'), 'Not a oneq settings file.');
    expect(await err(jsonEncode(with_((m) => m['version'] = 2))), contains('Unsupported'));
    expect(await err(jsonEncode(with_((m) => m['settings']['relays'] = ['http://plain.example.org']))), contains('https://'));
    expect(await err(jsonEncode(with_((m) => m['settings']['relays'] = []))), contains('https://'));
    expect(await err(jsonEncode(with_((m) => m['settings']['community'] = ''))), contains('community'));
    expect(await err(jsonEncode(with_((m) => m['settings']['ca_pem'] = 'junk'))), contains('PEM'));
    expect(await err(jsonEncode(with_((m) => m['node_key'] = 'AAAA'))), contains('damaged'));
    b.active = true;
    expect(await err(jsonEncode(good)), contains('Disconnect'));
    b.active = false;
    expect(b.settings.community, 'lan'); // untouched by every failed import
  });
}

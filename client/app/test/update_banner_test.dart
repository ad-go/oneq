import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:oneq_app/controller.dart';
import 'package:oneq_app/core.dart';
import 'package:oneq_app/update_banner.dart';

void main() {
  testWidgets('banner shows the spec wording, hides when dismissed or not newer', (t) async {
    final c = OneqController();
    Future<void> pump() => t.pumpWidget(MaterialApp(home: Scaffold(body: ListenableBuilder(listenable: c, builder: (_, _) => UpdateBanner(c: c)))));
    await pump();
    expect(find.textContaining('is available'), findsNothing);

    c.updateInfo = UpdateInfo({'current': '0.0.1', 'latest': '0.0.2', 'update_available': true, 'status': 'newer', 'url': 'https://github.com/x'});
    await pump();
    expect(find.text('Version 0.0.2 is available (you have 0.0.1).'), findsOneWidget);
    expect(find.text('Download'), findsOneWidget);
    expect(find.text('Release notes'), findsOneWidget);

    c.dismissUpdate();
    await t.pump();
    expect(find.textContaining('is available'), findsNothing);
  });

  test('update_check defaults to true, is persisted in the prepare/export JSON and parsed from status', () {
    expect(Settings().updateCheck, isTrue);
    expect(Settings().toJson()['update_check'], isTrue);
    final s = Snapshot({'state': 'connected', 'update': {'current': '0.0.1', 'latest': '0.0.1', 'status': 'current', 'update_available': false}});
    expect(s.update?.status, 'current');
    expect(Snapshot({}).update, isNull);
  });
}

import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

import 'controller.dart';
import 'settings_page.dart';

final controller = OneqController();
final navigatorKey = GlobalKey<NavigatorState>();
bool get isDesktop => Platform.isWindows || Platform.isMacOS || Platform.isLinux;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await controller.load();
  await controller.attach();
  if (isDesktop) {
    await windowManager.ensureInitialized();
    await windowManager.setPreventClose(true); // the close button hides the window; the tray keeps the app alive
    final hidden = controller.settings.startHidden;
    await windowManager.waitUntilReadyToShow(const WindowOptions(size: Size(520, 760), minimumSize: Size(380, 520), title: 'oneq'), () async {
      if (!hidden) {
        await windowManager.show();
        await windowManager.focus();
      }
    });
    TrayHandler.start();
  }
  runApp(const OneqApp());
}

/// Tray icon: colour shows the state; left click opens the window, right click the menu.
class TrayHandler with TrayListener, WindowListener {
  static final TrayHandler _i = TrayHandler._();
  TrayHandler._();
  String _icon = '';
  String _menuSig = '';

  static void start() {
    trayManager.addListener(_i);
    windowManager.addListener(_i);
    controller.addListener(_i._refresh);
    _i._refresh();
  }

  String get _state {
    if (!controller.active) return 'off';
    return controller.snap?.state == 'connected' && (controller.snap?.peers.any((p) => p.session) ?? false) ? 'connected' : 'connecting';
  }

  Future<void> _refresh() async {
    final ext = Platform.isWindows ? 'ico' : 'png';
    final icon = 'assets/tray_$_state.$ext';
    if (icon != _icon) {
      _icon = icon;
      await trayManager.setIcon(icon);
    }
    final s = controller.snap;
    final sig = '${controller.active}|${controller.busy}|${s?.ip}|${s?.peers.where((p) => p.session).length}';
    if (sig != _menuSig) {
      _menuSig = sig;
      final up = s?.peers.where((p) => p.session).length ?? 0;
      await trayManager.setToolTip(controller.active ? 'oneq: ${s?.ip ?? ''} - $up peer(s) connected' : 'oneq: disconnected');
      await trayManager.setContextMenu(Menu(items: [
        MenuItem(key: 'open', label: 'Open oneq'),
        MenuItem(key: 'settings', label: 'Settings…'),
        MenuItem.separator(),
        MenuItem(key: 'toggle', label: controller.active ? 'Disconnect' : 'Connect', disabled: controller.busy),
        MenuItem.separator(),
        MenuItem(key: 'quit', label: 'Quit'),
      ]));
    }
  }

  Future<void> _show() async {
    await windowManager.show();
    await windowManager.focus();
  }

  @override
  void onTrayIconMouseDown() => _show();

  @override
  void onTrayIconRightMouseDown() => trayManager.popUpContextMenu();

  @override
  void onTrayMenuItemClick(MenuItem menuItem) async {
    switch (menuItem.key) {
      case 'open':
        await _show();
      case 'settings':
        await _show();
        navigatorKey.currentState?.push(MaterialPageRoute(builder: (_) => SettingsPage(c: controller)));
      case 'toggle':
        if (controller.active) {
          await controller.disconnect();
        } else if (controller.password.isEmpty) {
          await _show(); // the password is never stored: ask for it
        } else {
          await controller.connect();
        }
      case 'quit':
        if (controller.active) await controller.disconnect();
        await trayManager.destroy();
        await windowManager.destroy();
    }
  }

  @override
  void onWindowClose() async {
    if (await windowManager.isPreventClose()) await windowManager.hide();
  }
}

class OneqApp extends StatelessWidget {
  const OneqApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'oneq',
        navigatorKey: navigatorKey,
        theme: ThemeData(colorSchemeSeed: const Color(0xFF1B6B5A), useMaterial3: true),
        darkTheme: ThemeData(colorSchemeSeed: const Color(0xFF1B6B5A), brightness: Brightness.dark, useMaterial3: true),
        home: const HomePage(),
      );
}

String fmtBytes(int b) {
  const u = ['B', 'KB', 'MB', 'GB'];
  var v = b.toDouble(), i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return '${v.toStringAsFixed(i == 0 ? 0 : 1)} ${u[i]}';
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final _password = TextEditingController();
  OneqController get c => controller;

  @override
  void initState() {
    super.initState();
    _password.text = c.password;
    c.addListener(_changed);
  }

  @override
  void dispose() {
    c.removeListener(_changed);
    super.dispose();
  }

  void _changed() {
    if (mounted) setState(() {});
  }

  Future<void> _openSettings() async {
    await Navigator.of(context).push(MaterialPageRoute(builder: (_) => SettingsPage(c: c)));
    _password.text = c.password;
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final s = c.snap;
    final cs = Theme.of(context).colorScheme;
    final configured = c.settings.relayList.isNotEmpty && c.settings.community.isNotEmpty && c.settings.user.isNotEmpty;
    return Scaffold(
      appBar: AppBar(title: const Text('oneq'), actions: [
        if (c.active)
          Padding(
            padding: const EdgeInsets.only(right: 4),
            child: Chip(
              avatar: Icon(Icons.circle, size: 12, color: s?.state == 'connected' ? Colors.green : Colors.orange),
              label: Text(s?.state ?? 'starting'),
            ),
          ),
        IconButton(tooltip: 'Settings', icon: const Icon(Icons.settings), onPressed: _openSettings),
      ]),
      body: SafeArea(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          if (!c.active) ...[
            if (!configured)
              Card(
                child: ListTile(
                  leading: const Icon(Icons.info_outline),
                  title: const Text('Set up the connection'),
                  subtitle: const Text('Open Settings to enter the relay, community and user, or import a settings file.'),
                  onTap: _openSettings,
                ),
              )
            else
              Card(
                child: ListTile(
                  title: Text('${c.settings.user} @ ${c.settings.community}'),
                  subtitle: Text(c.settings.relayList.join('\n')),
                  isThreeLine: c.settings.relayList.length > 1,
                  trailing: IconButton(icon: const Icon(Icons.edit), onPressed: _openSettings),
                ),
              ),
            const SizedBox(height: 12),
            TextField(
              controller: _password,
              obscureText: true,
              enabled: !c.busy,
              onChanged: (v) => c.password = v,
              onSubmitted: (_) => c.connect(),
              decoration: const InputDecoration(labelText: 'Password', border: OutlineInputBorder()),
            ),
          ],
          if (c.error != null)
            Padding(padding: const EdgeInsets.symmetric(vertical: 8), child: Text(c.error!, style: TextStyle(color: cs.error))),
          const SizedBox(height: 12),
          FilledButton.icon(
            onPressed: c.busy ? null : (c.active ? c.disconnect : c.connect),
            icon: c.busy
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                : Icon(c.active ? Icons.link_off : Icons.link),
            label: Text(c.active ? 'Disconnect' : 'Connect'),
          ),
          if (c.active && s != null) ...[
            const SizedBox(height: 16),
            Card(
              child: ListTile(
                title: Text('${s.ip}/${s.prefix}', style: const TextStyle(fontWeight: FontWeight.bold)),
                subtitle: Text('${s.community} · MTU ${s.mtu} · relay ${s.relayConnected ? "connected" : "down"}\n'
                    '↑ ${fmtBytes(s.txBytes)}   ↓ ${fmtBytes(s.rxBytes)}'
                    '${s.natType.isEmpty ? "" : "\nNAT: ${s.natType}${s.natPublic.isEmpty ? "" : " · ${s.natPublic}"}"}'
                    '${s.message.isEmpty ? "" : "\n${s.message}"}'),
                isThreeLine: true,
              ),
            ),
            const SizedBox(height: 8),
            Text('Members', style: Theme.of(context).textTheme.titleMedium),
            for (final p in s.peers)
              ListTile(
                dense: true,
                leading: Icon(p.session ? Icons.lock : Icons.lock_open, color: p.session ? Colors.green : (p.online ? Colors.orange : Colors.grey)),
                title: Text(p.name),
                subtitle: Text(p.ip),
                trailing: Text(p.session ? p.path : (p.online ? 'connecting' : 'offline')),
              ),
            const SizedBox(height: 8),
            ExpansionTile(
              title: const Text('Log'),
              children: [
                SelectableText(s.log.reversed.take(60).join('\n'), style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
              ],
            ),
          ],
        ]),
      ),
    );
  }
}

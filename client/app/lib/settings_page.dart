import 'dart:async';
import 'dart:io';

import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'controller.dart';
import 'desktop_service.dart';

/// Settings window: connection details, export/import, and (Windows) the background service.
class SettingsPage extends StatefulWidget {
  final OneqController c;
  const SettingsPage({super.key, required this.c});
  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  late final TextEditingController _relays, _community, _user, _name, _ca, _password;
  bool _withPassword = false, _withKey = false;
  String? _note;
  bool _noteIsError = false;
  String _service = '';
  bool _svcBusy = false;

  OneqController get c => widget.c;
  bool get _locked => c.active || c.busy;

  @override
  void initState() {
    super.initState();
    _relays = TextEditingController(text: c.settings.relays);
    _community = TextEditingController(text: c.settings.community);
    _user = TextEditingController(text: c.settings.user);
    _name = TextEditingController(text: c.settings.name);
    _ca = TextEditingController(text: c.settings.ca);
    _password = TextEditingController(text: c.password);
    if (Platform.isWindows || Platform.isMacOS) _refreshService();
  }

  void _readForm() {
    c.settings
      ..relays = _relays.text
      ..community = _community.text.trim()
      ..user = _user.text.trim()
      ..name = _name.text.trim()
      ..ca = _ca.text;
    c.password = _password.text;
  }

  void _fillForm() {
    _relays.text = c.settings.relays;
    _community.text = c.settings.community;
    _user.text = c.settings.user;
    _name.text = c.settings.name;
    _ca.text = c.settings.ca;
    _password.text = c.password;
  }

  void _say(String m, {bool error = false}) => setState(() {
        _note = m;
        _noteIsError = error;
      });

  Future<void> _save() async {
    _readForm();
    await c.save();
    _say('Saved.');
  }

  // ------------------------------------------------------------------ export / import
  Future<bool> _confirmSecrets() async {
    if (!_withPassword && !_withKey) return true;
    final what = [if (_withPassword) 'your password in plain text', if (_withKey) 'this device\'s node key'].join(' and ');
    return await showDialog<bool>(
          context: context,
          builder: (ctx) => AlertDialog(
            title: const Text('The file will contain secrets'),
            content: Text('The exported file will contain $what. Anyone who gets the file can use it to join your '
                'network${_withKey ? ' as this device' : ''}. Store it somewhere private.'),
            actions: [
              TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
              FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Export anyway')),
            ],
          ),
        ) ??
        false;
  }

  Future<String?> _exportText() async {
    _readForm();
    if (!await _confirmSecrets()) return null;
    return c.exportJson(withPassword: _withPassword, withKey: _withKey);
  }

  Future<void> _exportFile() async {
    try {
      final text = await _exportText();
      if (text == null) return;
      final loc = await getSaveLocation(
        suggestedName: 'oneq-settings.json',
        acceptedTypeGroups: const [XTypeGroup(label: 'oneq settings', extensions: ['json'])],
      );
      if (loc == null) return;
      await File(loc.path).writeAsString(text);
      _say('Exported to ${loc.path}');
    } catch (e) {
      _say('Export failed: $e', error: true);
    }
  }

  Future<void> _exportClipboard() async {
    try {
      final text = await _exportText();
      if (text == null) return;
      await Clipboard.setData(ClipboardData(text: text));
      _say('Copied to the clipboard.');
    } catch (e) {
      _say('Export failed: $e', error: true);
    }
  }

  Future<void> _import(Future<String?> Function() source) async {
    try {
      final text = await source();
      if (text == null || text.trim().isEmpty) return;
      final msg = await c.importJson(text);
      _fillForm();
      _say(msg);
    } on FormatException catch (e) {
      _say('Import failed: ${e.message}', error: true);
    } catch (e) {
      _say('Import failed: $e', error: true);
    }
  }

  Future<String?> _readFile() async {
    final f = await openFile(acceptedTypeGroups: const [XTypeGroup(label: 'oneq settings', extensions: ['json'])]);
    if (f == null) return null;
    if (await f.length() > 1024 * 1024) throw const FormatException('The file is too large to be a settings file.');
    return f.readAsString();
  }

  Future<String?> _readClipboard() async => (await Clipboard.getData(Clipboard.kTextPlain))?.text;

  // ------------------------------------------------------------------ background service (desktop)
  Future<void> _refreshService() async {
    final st = await DesktopService.readStatus();
    if (mounted) setState(() => _service = st == null ? 'not running' : 'running (${st.state})');
  }

  Future<void> _svcAction(String what) async {
    setState(() => _svcBusy = true);
    try {
      await DesktopService.control(what);
      _say('Service: $what done.');
    } catch (e) {
      _say('Service: $e', error: true);
    } finally {
      await _refreshService();
      if (mounted) setState(() => _svcBusy = false);
    }
  }

  // ------------------------------------------------------------------ UI
  Widget _field(TextEditingController t, String label, {int lines = 1, bool secret = false}) => Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: TextField(
          controller: t,
          obscureText: secret,
          minLines: lines,
          maxLines: secret ? 1 : lines,
          enabled: !_locked,
          decoration: InputDecoration(labelText: label, border: const OutlineInputBorder()),
        ),
      );

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final desktop = Platform.isWindows || Platform.isMacOS || Platform.isLinux;
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: SafeArea(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          if (_locked)
            const Card(child: ListTile(leading: Icon(Icons.info_outline), title: Text('Disconnect to change the connection settings.'))),
          Text('Connection', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          _field(_relays, 'Relays (https://host:port, one per line)', lines: 2),
          _field(_community, 'Community'),
          _field(_user, 'User'),
          _field(_password, 'Password (not saved)', secret: true),
          _field(_name, 'Device name (optional)'),
          _field(_ca, 'Private CA certificate, PEM (empty = public CAs)', lines: 3),
          SwitchListTile(
            title: const Text('Send everything through the relay'),
            value: c.settings.forceRelay,
            onChanged: _locked ? null : (v) => setState(() => c.settings.forceRelay = v),
          ),
          SwitchListTile(
            title: const Text('Use routed networks'),
            subtitle: const Text('Reach the private networks the administrator routed through a gateway member (for example 192.168.16.0/24).'),
            value: c.settings.acceptRoutes,
            onChanged: _locked ? null : (v) => setState(() => c.settings.acceptRoutes = v),
          ),
          ListenableBuilder(
            listenable: c,
            builder: (_, _) {
              final exitPeers = (c.snap?.peers ?? []).where((p) => p.exitNode).toList();
              final options = [
                const DropdownMenuItem(value: '', child: Text('None — direct internet')),
                ...exitPeers.map((p) => DropdownMenuItem(
                  value: p.name,
                  child: Text('${p.name}${p.publicIp.isNotEmpty ? '  (${p.publicIp})' : ''}'),
                )),
                if (c.settings.exitNode.isNotEmpty && !exitPeers.any((p) => p.name == c.settings.exitNode))
                  DropdownMenuItem(value: c.settings.exitNode, child: Text(c.settings.exitNode)),
              ];
              return Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: DropdownButtonFormField<String>(
                  initialValue: c.settings.exitNode.isEmpty ? '' : c.settings.exitNode,
                  decoration: const InputDecoration(
                    labelText: 'Exit node (route internet traffic through)',
                    border: OutlineInputBorder(),
                  ),
                  items: options,
                  onChanged: _locked ? null : (v) => setState(() => c.settings.exitNode = v ?? ''),
                ),
              );
            },
          ),
          if (desktop)
            SwitchListTile(
              title: const Text('Start hidden in the tray'),
              value: c.settings.startHidden,
              onChanged: (v) => setState(() => c.settings.startHidden = v),
            ),
          SwitchListTile(
            title: const Text('Start at boot'),
            subtitle: Text(Platform.isAndroid
                ? 'Keeps the connection details, including the password, encrypted with a key in the Android Keystore, so the node '
                    'can connect without opening the app. Also used by the Android "Always-on VPN" option.'
                : 'The node runs as a background service. With this on, the service starts at boot, before anyone logs in; '
                    'otherwise it is installed but started by hand. Applies the next time you press Connect.'),
            value: c.settings.autoStart,
            onChanged: _locked ? null : (v) => setState(() => c.settings.autoStart = v),
          ),
          CheckboxListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            title: const Text('Check for updates automatically'),
            value: c.settings.updateCheck,
            onChanged: _locked ? null : (v) => setState(() => c.settings.updateCheck = v ?? true),
          ),
          ListenableBuilder(
            listenable: c,
            builder: (_, _) => Wrap(spacing: 12, crossAxisAlignment: WrapCrossAlignment.center, children: [
              OutlinedButton(onPressed: c.updateBusy ? null : c.checkUpdate, child: const Text('Check for updates')),
              if (c.updateMessage.isNotEmpty) Text(c.updateMessage),
            ]),
          ),
          const SizedBox(height: 8),
          Align(alignment: Alignment.centerLeft, child: FilledButton(onPressed: _locked ? null : _save, child: const Text('Save'))),
          const Divider(height: 40),
          Text('Export and import', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 4),
          const Text('Settings are exported as a JSON file. Secrets are left out unless you tick them.'),
          CheckboxListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            title: const Text('Include the password (plain text)'),
            value: _withPassword,
            onChanged: (v) => setState(() => _withPassword = v ?? false),
          ),
          CheckboxListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            title: const Text('Include this device\'s node key (keeps its address; moves the identity)'),
            value: _withKey,
            onChanged: (v) => setState(() => _withKey = v ?? false),
          ),
          Wrap(spacing: 8, runSpacing: 8, children: [
            if (desktop) OutlinedButton.icon(onPressed: _exportFile, icon: const Icon(Icons.file_upload_outlined), label: const Text('Export to file…')),
            OutlinedButton.icon(onPressed: _exportClipboard, icon: const Icon(Icons.copy), label: const Text('Copy to clipboard')),
            // also on Android: the system file picker (the pasted-text route is unreliable for a certificate typed on a phone)
            OutlinedButton.icon(
                onPressed: _locked ? null : () => _import(_readFile), icon: const Icon(Icons.file_download_outlined), label: const Text('Import from file…')),
            OutlinedButton.icon(
                onPressed: _locked ? null : () => _import(_readClipboard), icon: const Icon(Icons.paste), label: const Text('Paste from clipboard')),
          ]),
          if (Platform.isWindows || Platform.isMacOS) ...[
            const Divider(height: 40),
            Text('Background service', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 4),
            Text('Keeps the node connected from boot, even when nobody is logged in and this window is closed.\nStatus: $_service'),
            const SizedBox(height: 8),
            Wrap(spacing: 8, runSpacing: 8, children: [
              OutlinedButton(onPressed: _svcBusy ? null : () => _svcAction('start'), child: const Text('Start')),
              OutlinedButton(onPressed: _svcBusy ? null : () => _svcAction('stop'), child: const Text('Stop')),
              OutlinedButton(onPressed: _svcBusy ? null : () => _svcAction('uninstall'), child: const Text('Uninstall')),
            ]),
          ],
          if (_note != null)
            Padding(
              padding: const EdgeInsets.only(top: 16),
              child: SelectableText(_note!, style: TextStyle(color: _noteIsError ? cs.error : cs.primary)),
            ),
        ]),
      ),
    );
  }
}

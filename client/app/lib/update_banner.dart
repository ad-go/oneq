import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import 'controller.dart';

/// Discreet one-line update notice; shown only while a newer release is known and not dismissed this session.
class UpdateBanner extends StatelessWidget {
  final OneqController c;
  const UpdateBanner({super.key, required this.c});

  Future<void> _notes() async {
    final u = c.updateInfo?.url ?? '';
    if (u.startsWith('https://')) {
      try {
        await launchUrl(Uri.parse(u), mode: LaunchMode.externalApplication);
      } catch (_) {}
    }
  }

  @override
  Widget build(BuildContext context) {
    final i = c.updateInfo;
    if (!c.updateBanner || i == null) return const SizedBox.shrink();
    final cs = Theme.of(context).colorScheme;
    return Card(
      color: cs.secondaryContainer,
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 4, 4, 4),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Expanded(child: Text('Version ${i.latest} is available (you have ${i.current}).', style: TextStyle(color: cs.onSecondaryContainer))),
            IconButton(tooltip: 'Dismiss', visualDensity: VisualDensity.compact, icon: const Icon(Icons.close, size: 18), onPressed: c.dismissUpdate),
          ]),
          Wrap(spacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
            TextButton(onPressed: c.updateBusy ? null : c.downloadUpdate, child: const Text('Download')),
            TextButton(onPressed: _notes, child: const Text('Release notes')),
            if (c.updateMessage.isNotEmpty) Text(c.updateMessage, style: Theme.of(context).textTheme.bodySmall),
          ]),
        ]),
      ),
    );
  }
}

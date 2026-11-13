import 'package:flutter/material.dart';
import '../design/app_palette.dart';

enum FlashPagePhase {
  selected,
  preparing,
  prepared,
  ready,
  writing,
  blocked,
  completed,
  review,
  error,
}

/// Presentation only. The owner supplies readiness and all guarded actions.
class FlashMapWorkspace extends StatelessWidget {
  const FlashMapWorkspace({
    super.key,
    required this.isDark,
    required this.vehicle,
    required this.vin,
    required this.connection,
    required this.fullFlash,
    required this.busy,
    required this.phase,
    required this.onChoose,
    required this.onPrepare,
    required this.onWrite,
    required this.onModeChanged,
    required this.details,
    required this.tools,
    required this.history,
    required this.recovery,
    required this.historySummary,
    this.fileName,
    this.fileSize,
    this.unavailableReason,
    this.checkDetails,
    this.progress,
    this.progressLabel,
    this.attention,
    this.recovering = false,
    this.blockReason,
    this.onCheckProgrammingAccess,
    this.programmingAccessAccepted = false,
    this.workflow,
  });
  final bool isDark, fullFlash, busy;
  final bool recovering;
  final bool programmingAccessAccepted;
  final String? blockReason;
  final String vehicle, vin, connection, historySummary;
  final String? fileName, fileSize, unavailableReason, progressLabel, attention;
  final FlashPagePhase phase;
  final VoidCallback? onChoose, onPrepare, onWrite;
  final VoidCallback? onCheckProgrammingAccess;
  final ValueChanged<bool>? onModeChanged;
  final Widget details, tools, history, recovery;
  final Widget? checkDetails;
  final Widget? workflow;
  final double? progress;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final muted = AppPalette.secondary(isDark);
    final hasFile = fileName != null;
    final active =
        phase == FlashPagePhase.preparing || phase == FlashPagePhase.writing;
    final review = phase == FlashPagePhase.review;
    final warning =
        review ||
        phase == FlashPagePhase.blocked ||
        phase == FlashPagePhase.error;
    final statusColor = warning
        ? AppPalette.orange
        : phase == FlashPagePhase.completed
        ? AppPalette.green
        : AppPalette.blue;
    final (statusTitle, statusBody) = switch (phase) {
      FlashPagePhase.selected => (
        'Prepare the flash',
        'Checks the BIN and DME, and saves fresh coding data. Preparation does not program the ECU.',
      ),
      FlashPagePhase.preparing => (
        recovering ? 'Checking recovery readiness' : 'Preparing flash',
        'Keep the DME connected while the checks finish.',
      ),
      FlashPagePhase.prepared => (
        programmingAccessAccepted
            ? 'Programming access accepted'
            : 'File and DME checks complete',
        programmingAccessAccepted
            ? 'Writing is unavailable for this BIN and DME.'
            : 'Check whether the DME accepts the programming session and security response. This check ends before erase.',
      ),
      FlashPagePhase.ready => (
        'Ready for confirmation',
        'Review the selected file and flash mode. Writing starts only after you confirm.',
      ),
      FlashPagePhase.writing => (
        recovering ? 'Recovering ECU' : 'Writing to ECU',
        'Keep power and the diagnostic connection connected until verification finishes.',
      ),
      FlashPagePhase.blocked => (
        'Writing is blocked',
        blockReason ??
            'Preparation did not establish eligibility to write. Open the check details for the exact reason.',
      ),
      FlashPagePhase.completed => (
        'Flash completed',
        'The operation finished and verification was recorded. Review its details below.',
      ),
      FlashPagePhase.review => (
        'ECU state needs review',
        'An earlier operation may have changed the ECU. Live polling remains paused. Review the saved operation and recovery tools before proceeding.',
      ),
      FlashPagePhase.error => (
        'The operation stopped',
        'Open the check details before trying again.',
      ),
    };
    Widget surface(Widget child) => Container(
      padding: const EdgeInsets.all(22),
      decoration: BoxDecoration(
        color: AppPalette.surface(isDark),
        borderRadius: BorderRadius.circular(appCardRadius),
      ),
      child: child,
    );
    Widget label(String text) =>
        Text(text, style: theme.textTheme.labelLarge?.copyWith(color: muted));
    return Align(
      alignment: Alignment.topCenter,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 960),
        child: ListView(
          key: const Key('flash-map-workspace'),
          padding: const EdgeInsets.fromLTRB(20, 20, 20, 40),
          children: [
            Wrap(
              spacing: 16,
              runSpacing: 6,
              alignment: WrapAlignment.spaceBetween,
              children: [
                Text(
                  '$vehicle · $connection',
                  style: theme.textTheme.titleSmall,
                ),
                SelectableText(
                  vin,
                  style: theme.textTheme.bodySmall?.copyWith(color: muted),
                ),
              ],
            ),
            const SizedBox(height: 20),
            if (review || attention != null) ...[
              Container(
                key: const Key('flash-review-warning'),
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: AppPalette.orange.withValues(alpha: .10),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  attention ?? statusBody,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: AppPalette.orange,
                  ),
                ),
              ),
              const SizedBox(height: 16),
            ],
            surface(
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  label('1 · Map file'),
                  const SizedBox(height: 14),
                  if (hasFile) ...[
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Padding(
                          padding: EdgeInsets.only(top: 2),
                          child: Icon(
                            Icons.insert_drive_file_outlined,
                            color: AppPalette.blue,
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              SelectableText(
                                fileName!,
                                style: theme.textTheme.titleMedium,
                              ),
                              const SizedBox(height: 5),
                              Text(
                                '$fileSize · Compatibility checked during preparation',
                                style: theme.textTheme.bodySmall?.copyWith(
                                  color: muted,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    TextButton.icon(
                      onPressed: onChoose,
                      icon: const Icon(Icons.folder_open_outlined, size: 18),
                      label: const Text('Change file'),
                    ),
                  ] else ...[
                    Text(
                      'Choose the BIN you want to flash',
                      style: theme.textTheme.titleLarge,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Selecting a file does not write to the ECU.',
                      style: TextStyle(color: muted),
                    ),
                    const SizedBox(height: 20),
                    FilledButton.icon(
                      key: const Key('flash-choose-bin'),
                      onPressed: onChoose,
                      icon: const Icon(Icons.folder_open_outlined),
                      label: const Text('Choose BIN'),
                    ),
                  ],
                ],
              ),
            ),
            if (hasFile) ...[
              const SizedBox(height: 14),
              surface(
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    label('2 · Flash mode'),
                    const SizedBox(height: 14),
                    LayoutBuilder(
                      builder: (context, constraints) => SegmentedButton<bool>(
                        key: const Key('n20-flash-operation-mode'),
                        segments: const [
                          ButtonSegment(
                            value: false,
                            label: Text('Calibration only'),
                          ),
                          ButtonSegment(
                            value: true,
                            label: Text('Software + calibration'),
                          ),
                        ],
                        selected: {fullFlash},
                        showSelectedIcon: false,
                        onSelectionChanged: onModeChanged == null
                            ? null
                            : (value) => onModeChanged!(value.single),
                        style: ButtonStyle(
                          visualDensity: VisualDensity.standard,
                          padding: WidgetStatePropertyAll(
                            EdgeInsets.symmetric(
                              horizontal: constraints.maxWidth < 400 ? 8 : 20,
                              vertical: 14,
                            ),
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),
                    Text(
                      fullFlash
                          ? 'Writes software and calibration. Startup memory is excluded.'
                          : 'Writes calibration regions only. Software and startup memory are excluded.',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: muted,
                        height: 1.4,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 14),
              surface(
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    label('3 · Prepare and write'),
                    const SizedBox(height: 14),
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(
                          warning
                              ? Icons.info_outline
                              : phase == FlashPagePhase.completed
                              ? Icons.check_circle_outline
                              : Icons.fact_check_outlined,
                          color: statusColor,
                          size: 22,
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                statusTitle,
                                style: theme.textTheme.titleMedium?.copyWith(
                                  color: statusColor,
                                ),
                              ),
                              const SizedBox(height: 7),
                              Text(
                                statusBody,
                                style: theme.textTheme.bodyMedium?.copyWith(
                                  height: 1.45,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                    if (active) ...[
                      const SizedBox(height: 18),
                      LinearProgressIndicator(value: progress),
                      if (progressLabel != null)
                        Padding(
                          padding: const EdgeInsets.only(top: 8),
                          child: Text(
                            progressLabel!,
                            style: theme.textTheme.bodySmall,
                          ),
                        ),
                    ],
                    if (phase == FlashPagePhase.prepared &&
                        onCheckProgrammingAccess != null) ...[
                      const SizedBox(height: 20),
                      FilledButton.icon(
                        key: const Key('n20-next-check-programming-access'),
                        onPressed: busy ? null : onCheckProgrammingAccess,
                        icon: const Icon(Icons.key_outlined, size: 19),
                        label: Text(
                          programmingAccessAccepted
                              ? 'Check access again'
                              : 'Check programming access',
                        ),
                      ),
                    ] else if (!active && !review) ...[
                      const SizedBox(height: 20),
                      FilledButton.icon(
                        key: Key(
                          phase == FlashPagePhase.ready
                              ? 'n20-start-flash-operation'
                              : 'n20-prepare-flash-operation',
                        ),
                        onPressed: busy
                            ? null
                            : phase == FlashPagePhase.ready
                            ? onWrite
                            : onPrepare,
                        icon: Icon(
                          phase == FlashPagePhase.ready
                              ? Icons.bolt
                              : Icons.fact_check_outlined,
                          size: 19,
                        ),
                        label: Text(
                          phase == FlashPagePhase.ready
                              ? 'Write to ECU'
                              : phase == FlashPagePhase.selected
                              ? 'Prepare flash'
                              : 'Prepare again',
                        ),
                      ),
                      if (unavailableReason != null &&
                          onPrepare == null &&
                          phase != FlashPagePhase.ready)
                        Padding(
                          padding: const EdgeInsets.only(top: 10),
                          child: Text(
                            unavailableReason!,
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: muted,
                            ),
                          ),
                        ),
                    ],
                    if (workflow != null) workflow!,
                    if (checkDetails != null)
                      FlashDisclosure(
                        title: 'Check details',
                        child: checkDetails!,
                      ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 22),
            FlashDisclosure(
              title: 'File and DME details',
              subtitle: 'Identity comparison, regions and hashes',
              child: details,
            ),
            FlashDisclosure(
              title: 'Advanced tools',
              subtitle: 'Programming access and diagnostic tools',
              child: tools,
            ),
            FlashDisclosure(
              title: 'Saved operations',
              subtitle: historySummary,
              child: history,
            ),
            FlashDisclosure(
              key: ValueKey('recovery-$review'),
              title: 'Recovery',
              subtitle: 'For a DME that still responds',
              initiallyExpanded: review,
              child: recovery,
            ),
          ],
        ),
      ),
    );
  }
}

class FlashDisclosure extends StatelessWidget {
  const FlashDisclosure({
    super.key,
    required this.title,
    required this.child,
    this.subtitle,
    this.initiallyExpanded = false,
  });
  final String title;
  final String? subtitle;
  final Widget child;
  final bool initiallyExpanded;
  @override
  Widget build(BuildContext context) => ExpansionTile(
    tilePadding: const EdgeInsets.symmetric(horizontal: 2),
    childrenPadding: const EdgeInsets.fromLTRB(2, 8, 2, 20),
    initiallyExpanded: initiallyExpanded,
    title: Text(title, style: Theme.of(context).textTheme.titleSmall),
    subtitle: subtitle == null
        ? null
        : Text(
            subtitle!,
            style: Theme.of(
              context,
            ).textTheme.bodySmall?.copyWith(color: Theme.of(context).hintColor),
          ),
    children: [Align(alignment: Alignment.centerLeft, child: child)],
  );
}

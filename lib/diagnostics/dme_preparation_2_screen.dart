import 'dart:convert';

import 'package:bmw_app/design/connection_status_chip.dart';
import 'package:bmw_app/diagnostics/security_response_provider.dart';
import 'package:bmw_app/src/rust/api/vehicle.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:path_provider/path_provider.dart';

class DmePreparation2Screen extends StatefulWidget {
  const DmePreparation2Screen({
    super.key,
    required this.vin,
    required this.currentBootloader,
    required this.connectionStatus,
    required this.isDark,
    required this.onBeforeSend,
    required this.onAfterSend,
    this.accessCheckOnly = false,
  });

  final String vin;
  final String currentBootloader;
  final ValueListenable<String> connectionStatus;
  final bool isDark;
  final Future<void> Function() onBeforeSend;
  final Future<void> Function() onAfterSend;
  final bool accessCheckOnly;

  @override
  State<DmePreparation2Screen> createState() => _DmePreparation2ScreenState();
}

class _PreparationStep {
  const _PreparationStep(this.label, this.request);

  final String label;
  final List<int> request;
}

class _PreparationExchange {
  _PreparationExchange({required this.label, required this.request});

  final String label;
  final List<int> request;
  List<int>? response;
  String? error;
}

class _RequestSequenceEdit {
  const _RequestSequenceEdit(this.requests);

  // The final entry is the prefix before the calculated security key.
  final List<List<int>> requests;
}

class _DmePreparation2ScreenState extends State<DmePreparation2Screen> {
  static const _maxRequests = 32;
  static const _requestsPreferenceKey = 'dme_preparation_2_request_edits_v1';
  static const _defaultGuidance =
      'Runs preparation on one owned connection. SK Python calculates the response to 67 11 using the freshly checked BTLD; 27 12 must be accepted before post-key steps. This uses the flashing engine’s transport and security broker.';
  static const _defaultCompletionMessage =
      'Sequence completed and the DME accepted the security response.';
  static const _defaultSecurityResponsePrefix = [0x27, 0x12];
  static const _steps = <_PreparationStep>[
    _PreparationStep('Extended diagnostic session', [0x10, 0x03]),
    _PreparationStep('Read energy-saving mode', [0x22, 0x10, 0x0A]),
    _PreparationStep('Set normal mode', [0x31, 0x01, 0x0F, 0x0C, 0x00]),
    _PreparationStep('Request flash mode', [0x31, 0x01, 0x0F, 0x0C, 0x03]),
    _PreparationStep('Disable DTC setting', [0x85, 0x02]),
    _PreparationStep('Communication control', [0x28, 0x01, 0x01]),
    _PreparationStep('Set operating mode 01', [0x31, 0x01, 0x10, 0x03, 0x01]),
    _PreparationStep('Request default session', [0x10, 0x01]),
    _PreparationStep('Re-enter extended session', [0x10, 0x03]),
    _PreparationStep('Request programming session', [0x10, 0x02]),
    _PreparationStep('Verify active session', [0x22, 0xF1, 0x86]),
    _PreparationStep('Request Security Challenge', [
      0x27,
      0x11,
      0xFF,
      0xFF,
      0xFF,
      0xFF,
    ]),
  ];

  final List<_PreparationExchange> _exchanges = [];
  final List<List<int>> _requests =
      _steps.map((step) => List<int>.of(step.request)).toList()
        ..add(List<int>.of(_defaultSecurityResponsePrefix));
  final List<List<int>> _postKeyRequests = [];
  bool _running = false;
  bool _complete = false;
  bool _securityResponseAccepted = false;
  String? _evidencePath;
  int _stepIndex = 0;
  String? _error;
  _RequestSequenceEdit? _pendingRequestEdit;
  List<List<int>>? _pendingPostKeyEdit;

  @override
  void initState() {
    super.initState();
    if (widget.accessCheckOnly) {
      _postKeyRequests.add([0x22, 0xf1, 0x86]);
    } else {
      _restoreRequestEdits();
    }
  }

  Future<void> _restoreRequestEdits() async {
    final preferences = await SharedPreferences.getInstance();
    final encoded = preferences.getString(_requestsPreferenceKey);
    if (encoded == null) return;
    try {
      final decoded = jsonDecode(encoded);
      final List<List<int>> restored;
      final List<List<int>> restoredPostKey;
      if (decoded is List<dynamic>) {
        // Read the fixed-length format written by the first editable build.
        final legacyLines = decoded.cast<String>();
        if (legacyLines.length != _steps.length + 1) {
          throw const FormatException('Stored request list is invalid.');
        }
        restored = [
          for (var index = 0; index < _steps.length; index++)
            _parseRequestBytes(legacyLines[index], index + 1),
          _parseRequestBytes(
            legacyLines.last.replaceAll(
              RegExp(r'<\s*calculated\s+key\s*>', caseSensitive: false),
              '',
            ),
            legacyLines.length,
          ),
        ];
        restoredPostKey = [];
      } else {
        final saved = decoded as Map<String, dynamic>;
        final commandLines = (saved['requests'] as List<dynamic>)
            .cast<String>();
        if (commandLines.isEmpty || commandLines.length > _maxRequests) {
          throw const FormatException('Stored request list is invalid.');
        }
        restored = [
          for (var index = 0; index < commandLines.length; index++)
            _parseRequestBytes(commandLines[index], index + 1),
          _parseRequestBytes(
            saved['responsePrefix'] as String,
            commandLines.length + 1,
          ),
        ];
        final postKeyLines = (saved['postKeyRequests'] as List<dynamic>? ?? [])
            .cast<String>();
        if (postKeyLines.length > _maxRequests) {
          throw const FormatException(
            'Stored post-key request list is invalid.',
          );
        }
        restoredPostKey = [
          for (var index = 0; index < postKeyLines.length; index++)
            _parseRequestBytes(postKeyLines[index], index + 1),
        ];
      }
      if (!mounted) return;
      setState(() {
        _requests
          ..clear()
          ..addAll(restored);
        _postKeyRequests
          ..clear()
          ..addAll(restoredPostKey);
      });
    } catch (_) {
      await preferences.remove(_requestsPreferenceKey);
    }
  }

  List<int> _parseRequestBytes(String text, int lineNumber) {
    final bytes = text.trim().split(RegExp(r'\s+'));
    final bytePattern = RegExp(r'^[0-9a-fA-F]{2}$');
    if (bytes.isEmpty || bytes.any((byte) => !bytePattern.hasMatch(byte))) {
      throw FormatException(
        'Request $lineNumber must contain two-digit hex bytes, for example 10 03.',
      );
    }
    return bytes.map((byte) => int.parse(byte, radix: 16)).toList();
  }

  Future<void> _saveRequests() async {
    final preferences = await SharedPreferences.getInstance();
    final isDefault =
        _requests.length == _steps.length + 1 &&
        _postKeyRequests.isEmpty &&
        listEquals(
          _requests.take(_steps.length).map(_hex).toList(),
          _steps.map((step) => _hex(step.request)).toList(),
        ) &&
        listEquals(_requests.last, _defaultSecurityResponsePrefix);
    if (isDefault) {
      await preferences.remove(_requestsPreferenceKey);
      return;
    }
    await preferences.setString(
      _requestsPreferenceKey,
      jsonEncode({
        'requests': _requests.take(_requests.length - 1).map(_hex).toList(),
        'responsePrefix': _hex(_requests.last),
        'postKeyRequests': _postKeyRequests.map(_hex).toList(),
      }),
    );
  }

  Future<void> _editRequests() async {
    final requestControllers = _requests
        .take(_requests.length - 1)
        .map((request) => TextEditingController(text: _hex(request)))
        .toList();
    final prefixController = TextEditingController(text: _hex(_requests.last));
    String? validationError;
    final result = await showDialog<String>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (dialogContext, setDialogState) => AlertDialog(
          title: const Text('Edit UDS requests'),
          content: SizedBox(
            width: 520,
            height: 540,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'These requests are sent to the DME in order when you start the sequence.',
                ),
                const SizedBox(height: 8),
                Expanded(
                  child: ListView.builder(
                    itemCount: requestControllers.length,
                    itemBuilder: (context, index) => Padding(
                      padding: const EdgeInsets.only(bottom: 8),
                      child: Row(
                        children: [
                          Expanded(
                            child: TextField(
                              controller: requestControllers[index],
                              maxLength: 1200,
                              style: const TextStyle(fontFamily: 'monospace'),
                              decoration: InputDecoration(
                                labelText: 'Request ${index + 1}',
                                counterText: '',
                                errorText: validationError == 'request-$index'
                                    ? 'Use two-digit hex bytes, e.g. 10 03.'
                                    : null,
                              ),
                            ),
                          ),
                          IconButton(
                            tooltip: 'Delete request ${index + 1}',
                            onPressed: requestControllers.length <= 1
                                ? null
                                : () {
                                    setDialogState(() {
                                      requestControllers
                                          .removeAt(index)
                                          .dispose();
                                      validationError = null;
                                    });
                                  },
                            icon: const Icon(Icons.delete_outline_rounded),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
                TextButton.icon(
                  onPressed: requestControllers.length >= _maxRequests
                      ? null
                      : () => setDialogState(() {
                          requestControllers.add(TextEditingController());
                          validationError = null;
                        }),
                  icon: const Icon(Icons.add_rounded),
                  label: Text(
                    requestControllers.length >= _maxRequests
                        ? 'Request limit reached'
                        : 'Add request',
                  ),
                ),
                TextField(
                  controller: prefixController,
                  maxLength: 120,
                  style: const TextStyle(fontFamily: 'monospace'),
                  decoration: InputDecoration(
                    labelText: 'Security response prefix',
                    helperText:
                        'The calculated key is appended to these bytes.',
                    counterText: '',
                    errorText: validationError == 'prefix'
                        ? 'Use two-digit hex bytes, e.g. 27 12.'
                        : null,
                  ),
                ),
                if (validationError != null &&
                    validationError != 'prefix' &&
                    !validationError!.startsWith('request-'))
                  Text(
                    validationError!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext, 'reset'),
              child: const Text('Reset to defaults'),
            ),
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () {
                final parsedRequests = <List<int>>[];
                for (
                  var index = 0;
                  index < requestControllers.length;
                  index++
                ) {
                  try {
                    parsedRequests.add(
                      _parseRequestBytes(
                        requestControllers[index].text,
                        index + 1,
                      ),
                    );
                  } on FormatException {
                    setDialogState(() => validationError = 'request-$index');
                    return;
                  }
                }
                List<int> parsedPrefix;
                try {
                  parsedPrefix = _parseRequestBytes(
                    prefixController.text,
                    requestControllers.length + 1,
                  );
                } on FormatException {
                  setDialogState(() => validationError = 'prefix');
                  return;
                }
                _pendingRequestEdit = _RequestSequenceEdit([
                  ...parsedRequests,
                  parsedPrefix,
                ]);
                Navigator.pop(dialogContext, 'save');
              },
              child: const Text('Save requests'),
            ),
          ],
        ),
      ),
    );
    final action = result;
    var updated = action == 'save' ? _pendingRequestEdit?.requests : null;
    if (action == 'reset') {
      updated = _steps.map((step) => List<int>.of(step.request)).toList()
        ..add(List<int>.of(_defaultSecurityResponsePrefix));
    }
    for (final controller in requestControllers) {
      controller.dispose();
    }
    prefixController.dispose();
    _pendingRequestEdit = null;
    if (updated == null) return;
    setState(() {
      _requests
        ..clear()
        ..addAll(updated!);
      _complete = false;
      _securityResponseAccepted = false;
      _exchanges.clear();
      _evidencePath = null;
      _error = null;
    });
    await _saveRequests();
  }

  Future<void> _editPostKeyRequests() async {
    final controllers = _postKeyRequests
        .map((request) => TextEditingController(text: _hex(request)))
        .toList();
    String? validationError;
    final action = await showDialog<String>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (dialogContext, setDialogState) => AlertDialog(
          title: const Text('After key confirmation'),
          content: SizedBox(
            width: 520,
            height: 460,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'These messages are sent only after the DME accepts the calculated 27 12 response.',
                ),
                const SizedBox(height: 8),
                Expanded(
                  child: controllers.isEmpty
                      ? const Center(child: Text('No messages added yet.'))
                      : ListView.builder(
                          itemCount: controllers.length,
                          itemBuilder: (context, index) => Padding(
                            padding: const EdgeInsets.only(bottom: 8),
                            child: Row(
                              children: [
                                Expanded(
                                  child: TextField(
                                    controller: controllers[index],
                                    maxLength: 1200,
                                    style: const TextStyle(
                                      fontFamily: 'monospace',
                                    ),
                                    decoration: InputDecoration(
                                      labelText:
                                          'Post-key request ${index + 1}',
                                      counterText: '',
                                      errorText:
                                          validationError == 'request-$index'
                                          ? 'Use two-digit hex bytes, e.g. 2E F1 5A.'
                                          : null,
                                    ),
                                  ),
                                ),
                                IconButton(
                                  tooltip:
                                      'Delete post-key request ${index + 1}',
                                  onPressed: () => setDialogState(() {
                                    controllers.removeAt(index).dispose();
                                    validationError = null;
                                  }),
                                  icon: const Icon(
                                    Icons.delete_outline_rounded,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                ),
                TextButton.icon(
                  onPressed: controllers.length >= _maxRequests
                      ? null
                      : () => setDialogState(() {
                          controllers.add(TextEditingController());
                          validationError = null;
                        }),
                  icon: const Icon(Icons.add_rounded),
                  label: Text(
                    controllers.length >= _maxRequests
                        ? 'Post-key request limit reached'
                        : 'Add message after key',
                  ),
                ),
                if (validationError != null &&
                    !validationError!.startsWith('request-'))
                  Text(
                    validationError!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () {
                final parsed = <List<int>>[];
                for (var index = 0; index < controllers.length; index++) {
                  try {
                    parsed.add(
                      _parseRequestBytes(controllers[index].text, index + 1),
                    );
                  } on FormatException {
                    setDialogState(() => validationError = 'request-$index');
                    return;
                  }
                }
                _pendingPostKeyEdit = parsed;
                Navigator.pop(dialogContext, 'save');
              },
              child: const Text('Save messages'),
            ),
          ],
        ),
      ),
    );
    final updated = action == 'save' ? _pendingPostKeyEdit : null;
    for (final controller in controllers) {
      controller.dispose();
    }
    _pendingPostKeyEdit = null;
    if (updated == null) return;
    setState(() {
      _postKeyRequests
        ..clear()
        ..addAll(updated);
      _complete = false;
      _securityResponseAccepted = false;
      _exchanges.clear();
      _error = null;
    });
    await _saveRequests();
  }

  String _hex(List<int> bytes) => bytes
      .map((byte) => byte.toRadixString(16).toUpperCase().padLeft(2, '0'))
      .join(' ');

  Future<bool> _confirmRun() async {
    final requestCount = _requests.length + _postKeyRequests.length;
    return await showDialog<bool>(
          context: context,
          builder: (context) => AlertDialog(
            title: Text(
              widget.accessCheckOnly
                  ? 'Check programming access?'
                  : 'Start DME Preparation 2?',
            ),
            content: Text(
              'This sends $requestCount UDS requests to DME 12. After a valid 67 11 response, the app sends the calculated 27 12 response. Post-key messages run only after the DME accepts it. Some requests change ECU state.',
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('Cancel'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('Start sequence'),
              ),
            ],
          ),
        ) ??
        false;
  }

  Future<void> _runSequence() async {
    if (_running || _complete || !await _confirmRun() || !mounted) return;
    setState(() {
      _running = true;
      _error = null;
      _stepIndex = 0;
      _securityResponseAccepted = false;
      _evidencePath = null;
      _exchanges.clear();
    });

    var paused = false;
    var uncertain = false;
    try {
      await widget.onBeforeSend();
      paused = true;
      final support = await getApplicationSupportDirectory();
      uncertain = true;
      await for (final event in runOwnedDmePreparation(
        expectedVin: widget.vin,
        expectedBootloader: widget.currentBootloader,
        requests: _requests
            .take(_requests.length - 1)
            .map(Uint8List.fromList)
            .toList(),
        securityPrefix: Uint8List.fromList(_requests.last),
        postKeyRequests: _postKeyRequests.map(Uint8List.fromList).toList(),
        outputDirectory: '${support.path}/dme_owned_preparation',
        confirmed: true,
      )) {
        if (event.kind == 'security_challenge') {
          try {
            final key = await SecurityResponseProvider.calculate(
              currentBootloader: event.bootloader,
              seed: event.seed,
            );
            await provideN20OperationKey(
              requestId: event.requestId,
              key: Uint8List.fromList(key),
            );
          } catch (error) {
            await rejectN20OperationKey(
              requestId: event.requestId,
              reason: 'Security calculation failed: $error',
            );
          }
        }
        if (event.kind == 'preparation_complete' || event.kind == 'error') {
          uncertain = false;
        }
        if (event.kind == 'recovery_required') uncertain = true;
        if (!mounted) continue;
        setState(() {
          if (event.evidencePath.isNotEmpty) _evidencePath = event.evidencePath;
          if (event.kind == 'preparation_request') {
            final data = jsonDecode(event.message) as Map<String, dynamic>;
            final request = List<int>.from(data['request'] as List);
            _stepIndex = event.completedStages;
            _exchanges.add(
              _PreparationExchange(
                label:
                    request.length > 1 &&
                        request[0] == 0x27 &&
                        request[1] == 0x12
                    ? 'Send calculated Security Response'
                    : 'Owned request ${_exchanges.length + 1}',
                request: request,
              ),
            );
          }
          if (event.kind == 'preparation_exchange' && _exchanges.isNotEmpty) {
            final data = jsonDecode(event.message) as Map<String, dynamic>;
            final response = List<int>.from(data['response'] as List);
            _exchanges.last.response = response;
            if (listEquals(response, [0x67, 0x12])) {
              _securityResponseAccepted = true;
            }
          }
          if (event.kind == 'preparation_complete') _complete = true;
          if (event.kind == 'error' || event.kind == 'recovery_required') {
            _error = event.message;
          }
        });
      }
      if (uncertain && mounted) {
        setState(
          () => _error ??=
              'Preparation stream ended without a known outcome. Live polling remains paused.',
        );
      }
    } catch (error) {
      if (mounted) {
        setState(() {
          _error = error.toString();
          if (_exchanges.isNotEmpty) {
            _exchanges.last.error ??= _error;
          }
        });
      }
    } finally {
      if (paused && !uncertain) {
        try {
          await widget.onAfterSend();
        } catch (error) {
          if (mounted) setState(() => _error = 'Reconnect failed: $error');
        }
      }
      if (mounted) setState(() => _running = false);
    }
  }

  Widget _exchangeCard(_PreparationExchange exchange, int index) {
    final response = exchange.response;
    final status = exchange.error != null
        ? 'Failed'
        : response == null
        ? 'Waiting'
        : 'Received';
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text('${index + 1}. ${exchange.label} · $status'),
                ),
              ],
            ),
            const SizedBox(height: 5),
            SelectableText(
              'TX: ${_hex(exchange.request)}',
              style: const TextStyle(fontFamily: 'monospace'),
            ),
            if (response != null)
              SelectableText(
                'RX: ${_hex(response)}',
                style: const TextStyle(fontFamily: 'monospace'),
              ),
            if (exchange.error != null)
              Text(
                exchange.error!,
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) => PopScope(
    canPop: !_running,
    child: Scaffold(
      appBar: AppBar(
        title: Text(
          widget.accessCheckOnly
              ? 'Programming access check'
              : 'DME Preparation 2',
        ),
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Text('DME · ECU 12 · VIN ${widget.vin}'),
            const SizedBox(height: 4),
            Text(
              'BTLD: ${widget.currentBootloader.isEmpty ? 'Not read' : widget.currentBootloader}',
            ),
            const SizedBox(height: 8),
            ValueListenableBuilder<String>(
              valueListenable: widget.connectionStatus,
              builder: (context, status, _) => ConnectionStatusChip(
                label: status,
                isDark: widget.isDark,
                compact: true,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              widget.accessCheckOnly
                  ? 'Checks programming-session entry, calculated security-response acceptance and the active session on one owned connection. This changes diagnostic state, but does not erase or transfer a BIN. The result is historical evidence, not persistent unlock or authorization for another connection.'
                  : _defaultGuidance,
            ),
            const SizedBox(height: 12),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Expanded(
                          child: Text(
                            'UDS request sequence',
                            style: TextStyle(fontWeight: FontWeight.w700),
                          ),
                        ),
                        if (!widget.accessCheckOnly)
                          TextButton.icon(
                            onPressed: _running ? null : _editRequests,
                            icon: const Icon(Icons.edit_outlined, size: 18),
                            label: const Text('Edit requests'),
                          ),
                      ],
                    ),
                    SelectableText(
                      '${_requests.take(_requests.length - 1).map(_hex).join('\n')}\n'
                      '${_hex(_requests.last)} <calculated key>',
                      style: const TextStyle(fontFamily: 'monospace'),
                    ),
                    const Divider(height: 24),
                    Row(
                      children: [
                        const Expanded(
                          child: Text(
                            'After key confirmation',
                            style: TextStyle(fontWeight: FontWeight.w700),
                          ),
                        ),
                        if (!widget.accessCheckOnly)
                          TextButton.icon(
                            onPressed: _running ? null : _editPostKeyRequests,
                            icon: const Icon(Icons.add_rounded, size: 18),
                            label: Text(
                              _postKeyRequests.isEmpty
                                  ? 'Add message'
                                  : 'Edit messages',
                            ),
                          ),
                      ],
                    ),
                    if (_postKeyRequests.isEmpty)
                      const Text('No post-key messages')
                    else
                      SelectableText(
                        _postKeyRequests.map(_hex).join('\n'),
                        style: const TextStyle(fontFamily: 'monospace'),
                      ),
                  ],
                ),
              ),
            ),
            if (_running) ...[
              const SizedBox(height: 16),
              LinearProgressIndicator(
                value:
                    (_stepIndex + 1) /
                    (_requests.length + _postKeyRequests.length),
              ),
              const SizedBox(height: 8),
              Text(
                'Request ${_stepIndex + 1} of ${_requests.length + _postKeyRequests.length}',
              ),
            ],
            if (_error != null) ...[
              const SizedBox(height: 12),
              Text(
                _error!,
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
            ],
            if (_evidencePath != null) SelectableText(_evidencePath!),
            if (_complete) ...[
              const SizedBox(height: 12),
              Text(
                _securityResponseAccepted
                    ? widget.accessCheckOnly
                          ? 'Programming access was accepted and the active session was checked on this connection. Writing must establish access again on its own connection.'
                          : _defaultCompletionMessage
                    : 'Sequence completed without sending a calculated security response.',
              ),
            ],
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: _running
                  ? null
                  : _complete
                  ? widget.accessCheckOnly
                        ? () => Navigator.pop(context, _securityResponseAccepted)
                        : null
                  : _runSequence,
              icon: Icon(
                _complete
                    ? Icons.check_circle_outline
                    : Icons.play_arrow_rounded,
              ),
              label: Text(
                _running
                    ? 'Running sequence…'
                    : _complete
                    ? widget.accessCheckOnly
                          ? 'Return to flash'
                          : 'Completed'
                    : 'Start sequence',
              ),
            ),
            const SizedBox(height: 12),
            for (var index = 0; index < _exchanges.length; index++)
              _exchangeCard(_exchanges[index], index),
          ],
        ),
      ),
    ),
  );
}

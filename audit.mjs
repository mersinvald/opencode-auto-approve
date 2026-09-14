import { digest, redact } from './policy.mjs';
import { detailPayload, scrubAuditText } from './audit-detail.mjs';

export function safeText(value, max = 400) {
  // Scrub before truncation so a split credential cannot escape detection.
  const clean = scrubAuditText(
    String(value ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, ' '),
  )
    .replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return clean.length > max ? clean.slice(0, max - 1) + '…' : clean;
}

const explanations = {
  native_control: 'Preserved the native control permission.',
  scoped_file_allow: 'Current project scope permits this file operation.',
  native_scope_allow: 'A saved OpenCode project permission covers this directory or read.',
  native_grant_allow: 'Model-approved read with a verified saved OpenCode permission citation.',
  native_grant_mismatch:
    'The cited OpenCode permission does not cover this read or operation category.',
  native_scope_changed: 'The directory covered by the saved permission changed during review.',
  model_scope_created: 'The model derived a bounded scope from the root user task.',
  static_shell_allow: 'Static shell analysis verified all effects against current permissions.',
  static_shell_changed:
    'The shell environment, paths, or permissions changed during static review.',
  native_read: 'The native policy permits this read.',
  native_project_file: 'The native policy permits this project file operation.',
  trusted_directory: 'The directory is an installed skill or this session’s scratch directory.',
  session_scratch: 'The file is inside this session’s private scratch directory.',
  session_scratch_cleanup: 'Literal cleanup stays inside this session’s scratch directory.',
  installed_skill_read: 'Reading an installed skill is permitted.',
  agents_document_read:
    'Policy permits reading AGENTS.md at any location, including global instructions. No model review is needed.',
  ancestor_scratch_read:
    'Reading an existing scratch directory of a verified parent session is permitted.',
  missing_tool_context: 'The actual tool input is unavailable.',
  missing_resources: 'The request has no resource scope.',
  unresolved_path: 'The resource path could not be resolved safely.',
  classifier_unavailable: 'The classifier is at capacity or in a cooldown period.',
  sensitive_payload:
    'The request contains a recognized credential pattern. No model request was sent.',
  sensitive_user_context:
    'User context contains a recognized credential pattern. No model request was sent.',
  request_too_large: 'The request exceeds the review context limit.',
  review_failed: 'The review failed, timed out, or returned an invalid response.',
  helper_source_unavailable: 'The referenced helper source could not be read safely.',
  user_context_unavailable: 'The review could not load the user authorization context.',
  model_request_failed: 'The classifier request failed before it returned a valid decision.',
  classifier_response_invalid: 'The classifier did not return one completed decision tool result.',
  classifier_truncated: 'The classifier exhausted its output budget before completion.',
  classifier_format_exhausted:
    'The classifier returned no valid completed decision within the retry limit.',
  classifier_config_invalid: 'The structured classifier configuration is unavailable or invalid.',
  classifier_config_changed: 'The classifier route changed during review.',
  classifier_request_rejected: 'The classifier endpoint rejected the structured request.',
  revalidation_failed: 'The review could not recheck the latest authorization context.',
  rule_check_failed: 'A local permission rule check failed.',
  model_escalation: 'The model did not confirm permission within the authorized task.',
  read_only_role: 'This action conflicts with the agent’s role restrictions.',
  native_deny: 'A native permission rule denies an operation inside this command.',
  missing_explicit_authorization:
    'The action requires explicit user authorization with valid evidence.',
  user_context_changed:
    'User instructions changed during review. The earlier recommendation no longer applies.',
  native_permissions_unavailable:
    'The review could not verify saved OpenCode permissions and current role rules.',
  native_permissions_changed:
    'OpenCode permissions or role rules changed during review. A new review is required.',
  scoped_grant_mismatch: 'The cited scoped permission does not authorize this action.',
  tracker_configuration_changed: 'The local tracker configuration changed during review.',
  script_changed: 'A helper script changed during review.',
  policy_changed: 'The approval policy changed during review. A new approval is required.',
  policy_unavailable: 'The final policy check failed. A user approval is required.',
  preparation_failed:
    'The plugin could not obtain the session, role, tool context, or scratch directory.',
  audit_unavailable: 'The audit record could not be saved. Automatic approval is unavailable.',
  native_preflight_failed:
    'Current native rules or another permission hook did not permit automatic approval.',
  pending_changed:
    'The pending request, tool input, or working directory changed. User approval is required.',
};

export function decisionReason(result) {
  return safeText(
    result.reason ||
      explanations[result.code] ||
      result.code?.replaceAll('_', ' ') ||
      'No reason supplied.',
  );
}

export function requestPreview(event, tool) {
  const command = tool?.input?.command;
  if (event.action === 'shell' && typeof command === 'string') {
    // Avoid copying multiline programs or inline interpreter bodies into the log.
    const clean = String(redact(command).value);
    return safeText(
      clean.split(/[\r\n]/)[0].replace(/\s(?:-c|-e|--eval)\s[\s\S]*$/, ' [inline code omitted]') +
        (/[\r\n]/.test(clean) ? ' [remaining lines omitted]' : ''),
    );
  }
  if (event.action === 'shell') return '[command unavailable]';
  return safeText((event.resources ?? []).slice(0, 2).join(', '));
}

export function auditRecord({
  event,
  tool,
  request,
  original,
  result,
  mode,
  applied,
  model,
  modelDecision,
  modelResponse,
  permissionContext,
  elapsedMs,
  scope,
  config,
  diagnostics,
}) {
  const staticAnalysis = result.staticAnalysis ?? request.staticAnalysis;
  return {
    version: 2,
    time: new Date().toISOString(),
    sessionID: safeText(event.sessionID, 160),
    sourceID: event.source?.id && safeText(event.source.id, 160),
    messageID: event.source?.messageID && safeText(event.source.messageID, 160),
    action: safeText(event.action, 100),
    tool: tool?.name && safeText(tool.name, 100),
    preview: requestPreview(event, tool),
    requestHash: digest(request),
    original,
    proposed: result.effect,
    applied,
    mode,
    code: result.code,
    reason: decisionReason(result),
    stage: result.stage,
    model: model && {
      providerID: safeText(model.providerID, 100),
      id: safeText(model.id, 100),
      variant: safeText(model.variant, 40),
    },
    modelDecision: modelDecision && {
      ...modelDecision,
      reason: safeText(modelDecision.reason),
      scopeGrant: modelDecision.scopeGrant && {
        ...modelDecision.scopeGrant,
        quote: safeText(modelDecision.scopeGrant.quote),
      },
      evidence: modelDecision.evidence && {
        messageID: safeText(modelDecision.evidence.messageID, 160),
        quote: safeText(modelDecision.evidence.quote),
      },
    },
    modelResponse: modelResponse && {
      format: safeText(modelResponse.format, 40),
      finishReason: safeText(modelResponse.finishReason, 40),
    },
    permissionContext,
    grantID: result.grantID,
    elapsedMs,
    detailPayload: detailPayload({
      event,
      request: { ...request, tool: request.tool ?? tool },
      scope,
      config,
      result,
      modelDecision,
      modelResponse,
      diagnostics,
    }),
    staticAnalysis: staticAnalysis && {
      parser: safeText(staticAnalysis.parser || 'mvdan/sh@3.14.0', 80),
      complete: staticAnalysis.complete,
      elapsedMs: staticAnalysis.elapsedMs,
      reason: staticAnalysis.reason && safeText(staticAnalysis.reason, 80),
      observations: staticAnalysis.observations?.map((o) => ({
        ...o,
        target: safeText(o.target, 1000),
      })),
      terms: staticAnalysis.terms.map((t) => ({
        command: safeText(t.command, 80),
        effect: safeText(t.effect, 40),
        target: safeText(t.target, 1000),
      })),
    },
  };
}

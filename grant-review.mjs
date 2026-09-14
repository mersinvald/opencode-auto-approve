import { gate } from './grant-gate.mjs';
import {
  reviewPrompt,
  reviewContract,
  decisionProblem,
  decisionFailure,
} from './grant-decision.mjs';
import { scriptEvidence, bounded } from './review-context.mjs';
import { digest, redact } from './policy.mjs';
import { selectedRulesHash, grantDescriptor } from './grant-rules.mjs';

export async function reviewDynamic(
  prepared,
  { generate, evidence, refresh, signal, retryFeedback },
) {
  const { request, scope, config, state, permissions, runtime } = prepared;
  const diagnostics = { helpers: [], authority: { status: 'not_loaded' } };
  let stage = 'helper_source';
  try {
    return await bounded(
      async (signal) => {
        request.scripts = await scriptEvidence(request.tool, scope, config, diagnostics.helpers);
        const checked = await gate(request, { scope, config, state, permissions, runtime, signal });
        diagnostics.static = checked;
        if (checked.decision !== 'dynamic')
          return {
            result: {
              effect: checked.decision,
              code: 'grant_rule',
              binding: { fingerprint: checked.fingerprint, requestHash: digest(request) },
              reason: checked.reason ?? 'Current grant rules resolve this action.',
            },
            diagnostics,
          };
        stage = 'user_context';
        const proof = await evidence(signal);
        const context = { users: proof.users, delegation: proof.delegation };
        diagnostics.authority = { status: 'loaded', ...context, nativePermissions: permissions };
        const analysis = {
          complete: checked.analysis.complete,
          reason: checked.analysis.reason,
          unresolved: checked.analysis.unresolved,
          pathResolutions: checked.analysis.snapshots?.map(({ lexical, resolved }) => ({
            lexical,
            resolved,
          })),
          hostAttested: !!checked.analysis.host,
        };
        const data = {
          ...context,
          scope,
          request: { ...request, ...(request.action === 'shell' ? { resources: undefined } : {}) },
          projectID: permissions.projectID,
          analysis,
          grants: checked.resolution.entries.map(({ grant: item, mode, rule }) => ({
            ...grantDescriptor(item),
            id: item.id,
            mode,
            ...(item.physicalTarget
              ? { physicalTarget: item.physicalTarget, repositoryName: item.repositoryName }
              : {}),
            rule: rule
              ? { ...grantDescriptor(rule), mode: rule.mode, authority: rule.authority }
              : null,
          })),
          retryFeedback,
          candidates: checked.candidates.map((c) => ({
            ...grantDescriptor(c),
            id: c.id,
            ...(c.repositoryName ? { repositoryName: c.repositoryName } : {}),
          })),
          nativeRestrictions: {
            readOnly: !!scope.readOnly,
            deny: checked.analysis.constraints?.deny ?? [],
          },
          beadsWriters: config.staticShell?.beadsWriters ?? ['orchestrator'],
        };
        if (redact(data).changed)
          return { result: { effect: 'ask', code: 'sensitive_payload' }, diagnostics };
        stage = 'model';
        const contract = reviewContract(checked.candidates),
          prompt = reviewPrompt(data);
        diagnostics.prompt = {
          characters: prompt.length,
          omittedAstCharacters: JSON.stringify(checked.analysis.syntax ?? '').length,
          eligibleCandidates: contract.candidateIDs.length,
          retryFeedback,
        };
        const response = await generate({ model: config.model, prompt, contract }, signal);
        diagnostics.model = response;
        let decision;
        try {
          decision = JSON.parse(response.text);
        } catch {
          throw decisionFailure('invalid_json');
        }
        diagnostics.model = { ...response, decision };
        const issue = decisionProblem(decision, contract);
        if (issue) throw decisionFailure(issue);
        const modelDecision = {
          effect: decision.decision === 'escalate_once' ? 'ask' : 'allow',
          reason: decision.reason,
          decision: decision.decision,
          remember: decision.remember,
        };
        if (modelDecision.effect === 'ask')
          return {
            result: {
              effect: 'ask',
              code: 'model_escalation',
              reason: decision.reason,
              modelDecision,
            },
            diagnostics,
          };
        stage = 'revalidation';
        const latest = await refresh(signal);
        const latestScripts = await scriptEvidence(
          latest.request.tool,
          latest.scope,
          latest.config,
        );
        latest.request.scripts = latestScripts;
        const latestGate = await gate(latest.request, { ...latest, signal });
        const latestProof = await evidence(signal);
        if (
          checked.fingerprint !== latestGate.fingerprint ||
          digest(request) !== digest(latest.request) ||
          digest(context) !==
            digest({ users: latestProof.users, delegation: latestProof.delegation }) ||
          digest(config) !== digest(latest.config)
        )
          return {
            result: {
              effect: 'ask',
              code: 'review_context_changed',
              reason:
                'The request, rules, or instructions changed during review. Re-review is required.',
            },
            diagnostics,
          };
        const remember = checked.candidates.filter((c) => decision.remember.includes(c.id));
        return {
          result: {
            effect: 'allow',
            code: decision.decision === 'allow_always' ? 'model_allow_always' : 'model_allow_once',
            reason: decision.reason,
            modelDecision,
            remember,
            rememberHash: selectedRulesHash(latest.state.rules, remember),
            projectID: permissions.projectID,
            binding: {
              fingerprint: latestGate.fingerprint,
              requestHash: digest(latest.request),
              contextHash: digest(context),
            },
          },
          diagnostics,
        };
      },
      config.timeoutMs,
      signal,
    );
  } catch (error) {
    return {
      result: {
        effect: 'ask',
        code: error.approvalCode ?? (stage === 'model' ? 'model_request_failed' : 'review_failed'),
        stage,
        reason: error.approvalReason ?? error.message,
        feedback: error.approvalFeedback,
      },
      diagnostics: {
        ...diagnostics,
        failure: {
          stage,
          message: error.message,
          ...(error.auditDiagnostic ? { response: error.auditDiagnostic } : {}),
        },
      },
    };
  }
}

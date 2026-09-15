import { ruleSnapshot, savedGrantSnapshot } from './audit-grants.mjs';
import { Plugin } from '@opencode/plugin';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  loadConfig,
  scratchDirectory,
  ancestorScratchDirectories,
  sourceTool,
  loadEvidence,
  scriptEvidence,
  bounded,
} from './review-context.mjs';
import { digest } from './policy.mjs';
import {
  savedPermissionReader,
  pendingPermissionReader,
  normalizePermissionMetadata,
  permissionEvidence,
} from './native-permissions.mjs';
import { nativeTransport } from './native-transport.mjs';
import { createAsyncReview, fingerprint, pause, reviewMarker } from './async-review.mjs';
import { createStructuredClassifier } from './structured-classifier.mjs';
import { createRuleStore, legacyGrants, ruleDirectory } from './grant-store.mjs';
import { ruleKey, selectedRulesHash, grantDescriptor } from './grant-rules.mjs';
import { captureShellRuntime } from './shell-host.mjs';
import { gate, globalRules } from './grant-gate.mjs';
import { reviewDynamic } from './grant-review.mjs';
import { auditRecord, requestPreview, safeText } from './audit.mjs';
import { writeAudit } from './audit-storage.mjs';
import { extendDetail, sanitizeAudit } from './audit-detail.mjs';

export function createApprovalPlugin({ generate: override } = {}) {
  return Plugin.define({
    id: 'local.approval-review',
    async setup(ctx) {
      const policyFile = ctx.options.policyFile;
      if (!path.isAbsolute(policyFile ?? '')) throw Error('Absolute policyFile required');
      const store = createRuleStore(policyFile),
        saved = savedPermissionReader(ctx),
        call = nativeTransport();
      const captured = new Map(),
        host = captureShellRuntime(),
        probes = new Map(),
        checkedPending = new Map(),
        pendingRuntime = new Map();
      const controller = new AbortController(),
        registrations = [];
      const generate =
        override ??
        createStructuredClassifier({
          configFile: path.join(path.dirname(policyFile), 'opencode.json'),
        });
      const pendingPermission = pendingPermissionReader(ctx, { call });
      const invocation = (e) =>
        e.source?.type === 'tool' ? `${e.sessionID}:${e.source.messageID}:${e.source.id}` : null;
      const readPolicy = async () => {
        const config = await loadConfig(policyFile);
        config.protectedRoots = [
          ...new Set([
            ...config.protectedRoots,
            ruleDirectory(policyFile),
            path.join(path.dirname(policyFile), 'plugins-dev/approval-audit'),
          ]),
        ];
        return config;
      };
      if ((await readPolicy()).mode === 'off') return;
      async function prepare(event, signal, partial = {}) {
        const config = await readPolicy(),
          chain = [];
        Object.assign(partial, {
          config,
          tool: sourceTool(event, captured, []),
          scope: { directory: ctx.location.directory },
          helpers: [],
        });
        let id = event.sessionID;
        while (id && chain.length < 8) {
          if (chain.some((c) => c.info.id === id)) throw Error('Parent cycle');
          const info = await bounded(
            (s) => ctx.session.get({ sessionID: id }, { signal: s }),
            3000,
            signal,
          );
          chain.push({ info });
          id = info.parentID;
        }
        if (id) throw Error('Incomplete parent chain');
        const info = chain[0].info;
        const agent = event.agent
          ? await ctx.agent.get({ agentID: event.agent }, { signal })
          : null;
        const permissions = await permissionEvidence(chain, (p) => saved(p, signal), agent);
        let tool = sourceTool(event, captured, []);
        if (!tool && event.source)
          tool = sourceTool(
            event,
            captured,
            await ctx.session.context({ sessionID: event.sessionID }, { signal }),
          );
        partial.tool = tool;
        const scratch = await scratchDirectory(config.scratchRoot, event.sessionID);
        const readableAncestorScratch = info.parentID
          ? await ancestorScratchDirectories(ctx.session, info, config.scratchRoot, signal)
          : [];
        const readOnly =
          agent?.permissions
            ?.filter((r) => ['*', 'edit'].includes(r.action) && r.resource === '*')
            .at(-1)?.effect === 'deny';
        const scope = {
          directory: info.location.directory,
          scratch,
          readableAncestorScratch,
          readOnly,
          agent: event.agent,
        };
        const request = {
          action: event.action,
          resources: event.resources,
          effect: event.effect,
          tool,
          metadata: event.metadata,
          directory: scope.directory,
          scratch,
        };
        Object.assign(partial, { scope, request, permissions });
        const runtime =
          host.get(
            tool?.input?.command,
            tool?.input?.workdir || tool?.input?.cwd || scope.directory,
            invocation(event),
          ) ?? pendingRuntime.get(fingerprint(event));
        // Exact helper grants include source bytes before any saved rule can match.
        request.scripts = await scriptEvidence(tool, scope, config, partial.helpers, {
          runtime,
          action: event.action,
        });
        await bounded(() => queue.settleRules(info.projectID), 8000, signal);
        const state = await store.import(
          info.projectID,
          permissions.saved,
          await legacyGrants(policyFile),
        );
        return Object.assign(partial, {
          config,
          scope,
          request,
          tool,
          state,
          permissions,
          runtime,
        });
      }
      const record = (event, p, result, diagnostics, model = false, elapsedMs = 0) =>
        auditRecord({
          event,
          tool: p.tool,
          request: p.request,
          original: event.effect,
          result,
          mode: p.config.mode,
          applied: result.effect,
          elapsedMs,
          scope: p.scope,
          config: p.config,
          diagnostics,
          model: model ? p.config.model : undefined,
          modelDecision: result.modelDecision,
          permissionContext: {
            projectID: p.permissions.projectID,
            rulesHash: digest(p.state.rules),
          },
        });
      const queue = createAsyncReview({
        owner: { directory: ctx.location.directory, workspaceID: ctx.location.workspaceID ?? null },
        storage: ctx.storage,
        permission: {
          get: (x, o) => bounded((s) => pendingPermission(x, { signal: s }), 3000, o?.signal),
          reply: (x, o) => bounded((s) => ctx.permission.reply(x, { signal: s }), 5000, o?.signal),
        },
        review: async (job, signal) => {
          const p = await prepare(job.event, signal);
          p.runtime ??= pendingRuntime.get(job.meta.fingerprint);
          if (
            p.config.mode !== 'enforce' ||
            digest(p.config) !== job.meta.configHash ||
            digest(p.tool) !== job.meta.toolHash
          )
            return { result: { effect: 'ask', code: 'pending_changed' } };
          const reviewed = await reviewDynamic(p, {
            generate,
            signal,
            retryFeedback: job.meta.retryFeedback,
            evidence: (s) => loadEvidence(ctx.session, job.event.sessionID, s),
            refresh: async (s) => {
              const latest = await prepare(job.event, s);
              latest.runtime ??= p.runtime;
              return latest;
            },
          });
          if (reviewed.result.effect === 'allow') job.boundReview = reviewed.result.binding;
          return {
            result: reviewed.result,
            record: record(
              job.event,
              p,
              reviewed.result,
              reviewed.diagnostics,
              !!reviewed.diagnostics.model,
            ),
          };
        },
        preflight: async (job, signal) => {
          if (digest(await readPolicy()) !== job.meta.configHash) return false;
          if (!job.boundReview) return false;
          const latest = await prepare(job.event, signal);
          latest.runtime ??= pendingRuntime.get(job.meta.fingerprint);
          const checked = await gate(latest.request, { ...latest, signal });
          if (
            checked.fingerprint !== job.boundReview.fingerprint ||
            digest(latest.request) !== job.boundReview.requestHash
          )
            return false;
          if (job.boundReview.contextHash) {
            const proof = await loadEvidence(ctx.session, job.event.sessionID, signal);
            if (
              digest({ users: proof.users, delegation: proof.delegation }) !==
              job.boundReview.contextHash
            )
              return false;
          }
          const nonce = randomUUID(),
            probe = {
              used: false,
              fingerprint: fingerprint({
                ...job.event,
                metadata: { ...job.event.metadata, approvalReviewPreflight: nonce },
              }),
            };
          probes.set(nonce, probe);
          try {
            const result = await bounded(
              (s) =>
                call('POST', `/api/session/${job.event.sessionID}/permission`, {
                  signal: s,
                  body: {
                    id: 'per_review_' + nonce.replaceAll('-', ''),
                    action: job.event.action,
                    resources: job.event.resources,
                    source: job.event.source,
                    agent: job.event.agent,
                    metadata: { ...job.event.metadata, approvalReviewPreflight: nonce },
                  },
                }),
              5000,
              signal,
            );
            if (result.effect === 'ask')
              await ctx.permission.reply(
                { sessionID: job.event.sessionID, requestID: result.id, reply: 'reject' },
                { signal },
              );
            return result.effect === 'allow' && probe.used;
          } finally {
            probes.delete(nonce);
          }
        },
        audit: async (job, status, result, base) => {
          const config = await readPolicy();
          const row = {
            ...base,
            version: 3,
            time: new Date().toISOString(),
            sessionID: job.event.sessionID,
            sourceID: job.event.source?.id,
            action: job.event.action,
            preview: base?.preview ?? job.meta.preview,
            requestID: job.id,
            status,
            attempt: job.meta.attempt,
            original: job.meta.original,
            proposed: result.effect,
            applied:
              status === 'allow'
                ? 'allow'
                : status === 'native_reply'
                  ? result.effect
                  : status === 'ask'
                    ? 'ask'
                    : 'pending',
            mode: 'enforce',
            code: result.code,
            reason: result.reason ?? result.code,
            model: base?.model ?? job.meta.model,
            elapsedMs: Date.now() - job.meta.created,
            nextRetryAt: job.meta.next,
            detailPayload: extendDetail(
              base?.detailPayload ??
                (result.diagnostic
                  ? sanitizeAudit({
                      request: job.event,
                      diagnostics: { failure: result.diagnostic },
                    })
                  : undefined),
              {
                status,
                result,
                attempt: job.meta.attempt,
                lookupAttempt: job.meta.lookupAttempts,
                requestID: job.id,
              },
            ),
          };
          await writeAudit(config.auditRoot, row);
          if (status === 'ask' && base?.permissionContext?.projectID)
            checkedPending.set(job.id, {
              rulesHash: digest((await store.read(base.permissionContext.projectID)).rules),
              fingerprint: base.detailPayload?.data?.diagnostics?.static?.fingerprint,
            });
          if (['allow', 'native_reply', 'resolved'].includes(status))
            pendingRuntime.delete(job.meta.fingerprint);
          if (status === 'allow' && result.remember?.length) {
            let beforeRules, savedState, saveError;
            const changes = [];
            try {
              savedState = await store.update(result.projectID, (state) => {
                if (selectedRulesHash(state.rules, result.remember) !== result.rememberHash)
                  throw Error('A selected rule changed before save');
                beforeRules = [...state.rules];
                for (const item of result.remember) {
                  const previous = state.rules.find((r) => ruleKey(r) === ruleKey(item));
                  state.rules = state.rules.filter((r) => ruleKey(r) !== ruleKey(item));
                  const next = {
                    ...grantDescriptor(item),
                    ...(item.repositoryName ? { repositoryName: item.repositoryName } : {}),
                    mode: 'allow',
                    scope: 'project',
                    authority: 'model',
                    updatedAt: new Date().toISOString(),
                    provenance: {
                      model: config.model,
                      sessionID: job.event.sessionID,
                      requestID: job.id,
                      reason: result.reason,
                    },
                  };
                  state.rules.push(next);
                  changes.push({ before: ruleSnapshot(previous), after: ruleSnapshot(next) });
                }
              });
            } catch (error) {
              saveError = error.message;
            }
            let ruleUpdate = {
              status: 'failed',
              reason: saveError,
              proposed: result.remember.map(ruleSnapshot),
            };
            if (savedState) {
              ruleUpdate = { status: 'saved', changes };
              // Audit enrichment cannot prevent or undo a successful rule save.
              try {
                const data = base?.detailPayload?.data;
                const entries =
                  data?.grants?.entries ?? data?.diagnostics?.static?.resolution?.entries;
                if (!Array.isArray(entries)) throw Error('Grant states were not captured');
                Object.assign(
                  ruleUpdate,
                  savedGrantSnapshot(
                    entries.map((e) => e.grant),
                    globalRules(config, data?.scope ?? {}),
                    beforeRules,
                    savedState.rules,
                  ),
                );
              } catch (error) {
                ruleUpdate.stateError = error.message;
              }
            }
            const saveStatus = savedState ? 'scoped_grant_created' : 'scope_not_saved';
            await writeAudit(config.auditRoot, {
              ...row,
              action: savedState ? 'scoped_permission' : row.action,
              status: saveStatus,
              code: savedState ? 'model_rules_saved' : 'rule_save_failed',
              reason: savedState ? row.reason : saveError,
              preview: savedState
                ? result.remember.map((g) => g.operation + ': ' + g.target).join(', ')
                : row.preview,
              detailPayload: extendDetail(row.detailPayload ?? sanitizeAudit({}), {
                ...row.detailPayload?.data?.lifecycle,
                status: saveStatus,
                ruleUpdate,
              }),
            });
          }
        },
      });
      const events = (async () => {
        try {
          for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
            if (event.type === 'permission.asked') await queue.asked(event.data);
            if (event.type === 'permission.replied') queue.replied(event.data);
          }
        } catch {}
      })();
      registrations.push(
        await ctx.tool.hook('execute.before', (e) => {
          if (captured.size > 1000) captured.clear();
          captured.set(`${e.sessionID}:${e.messageID}:${e.id}`, {
            name: e.tool,
            input: structuredClone(e.input),
          });
          if (e.tool === 'shell')
            host.begin(
              `${e.sessionID}:${e.messageID}:${e.id}`,
              e.input?.command,
              e.input?.workdir || e.input?.cwd || ctx.location.directory,
            );
        }),
      );
      registrations.push(
        await ctx.tool.hook('execute.after', (e) => {
          if (e.tool === 'shell')
            host.release(
              e.input?.command,
              e.input?.workdir || e.input?.cwd || ctx.location.directory,
              `${e.sessionID}:${e.messageID}:${e.id}`,
            );
          captured.delete(`${e.sessionID}:${e.messageID}:${e.id}`);
        }),
      );
      if (ctx.shell?.hook)
        registrations.push(await ctx.shell.hook('create.before', (e) => host.capture(e)));
      registrations.push(
        await ctx.permission.hook('evaluate', async (event) => {
          if (event.effect === 'deny') return;
          try {
            normalizePermissionMetadata(event);
          } catch (error) {
            event.effect = 'ask';
            event.message = error.message;
            return;
          }
          const probe = probes.get(event.metadata?.approvalReviewPreflight);
          if (probe) {
            if (event.effect !== 'deny' && probe.fingerprint === fingerprint(event)) {
              probe.used = true;
              event.effect = 'allow';
            }
            return;
          }
          let p = {};
          const started = Date.now();
          try {
            p = await prepare(event, controller.signal, p);
            if (p.config.mode === 'off') return;
            const checked = await bounded(
              (s) => gate(p.request, { ...p, signal: s }),
              1500,
              controller.signal,
            );
            await store.observe(p.permissions.projectID, checked.analysis.grants, {
              sessionID: event.sessionID,
              action: event.action,
            });
            if (checked.decision === 'allow') {
              const fresh = await prepare(event, controller.signal);
              fresh.runtime ??= p.runtime;
              const current = await bounded(
                (s) => gate(fresh.request, { ...fresh, signal: s }),
                1500,
                controller.signal,
              );
              if (current.fingerprint !== checked.fingerprint)
                throw Error('The request or grant rules changed. Retry the review.');
            }
            const result = {
              effect: checked.decision === 'allow' ? 'allow' : 'ask',
              code: checked.decision === 'dynamic' ? 'review_queued' : 'grant_rule',
              reason:
                checked.reason ??
                (checked.decision === 'allow'
                  ? 'All requested grants are allowed.'
                  : 'An Always ask rule requires a user decision.'),
            };
            if (checked.decision !== 'allow' && p.config.mode === 'enforce') {
              // Keep the captured invocation while this exact native request waits.
              // Revalidation still checks its command, startup pins, and executable bytes.
              if (p.runtime && pendingRuntime.size < 256)
                pendingRuntime.set(fingerprint(event), p.runtime);
              await queue.offer(event, {
                configHash: digest(p.config),
                directory: p.scope.directory,
                toolHash: digest(p.tool),
                preview: requestPreview(event, p.tool),
                model: p.config.model,
              });
              return;
            }
            await writeAudit(
              p.config.auditRoot,
              record(event, p, result, { static: checked }, false, Date.now() - started),
            );
            if (p.config.mode === 'enforce') {
              event.effect = result.effect;
              event.message = result.reason;
            }
          } catch (error) {
            event.effect = 'ask';
            event.message = 'Approval gate: ' + safeText(error.approvalReason ?? error.message);
            try {
              const config = p?.config ?? (await readPolicy());
              const result = {
                effect: 'ask',
                code: 'preparation_failed',
                stage: 'static_gate',
                reason: event.message,
              };
              const tool = p?.tool ?? sourceTool(event, captured, []);
              const row = auditRecord({
                event,
                tool,
                request: p?.request ?? {
                  action: event.action,
                  resources: event.resources,
                  effect: event.effect,
                  tool,
                  directory: ctx.location.directory,
                },
                scope: p?.scope ?? { directory: ctx.location.directory },
                config,
                original: 'ask',
                applied: 'ask',
                mode: config.mode,
                elapsedMs: Date.now() - started,
                result,
                diagnostics: {
                  failure: {
                    stage: 'static_gate',
                    code: error.approvalCode ?? error.code,
                    message: event.message,
                  },
                  helpers: p?.helpers ?? [],
                },
              });
              await writeAudit(config.auditRoot, row);
            } catch {
              /* The native dialog remains available when audit storage is unavailable. */
            }
          }
        }),
      );
      const recovery = (async () => {
        while (!controller.signal.aborted) {
          try {
            const pending = await bounded(
              (s) =>
                call('GET', '/api/permission/request', {
                  query: { 'location[directory]': ctx.location.directory },
                  signal: s,
                }),
              5000,
              controller.signal,
            );
            for (const request of Array.isArray(pending) ? pending : []) {
              await queue.asked(request);
              const info = await ctx.session.get({ sessionID: request.sessionID });
              const state = await store.read(info.projectID),
                rulesHash = digest(state.rules);
              const previous = checkedPending.get(request.id);
              if (previous?.rulesHash === rulesHash) continue;
              if (!reviewMarker(request.message) || request.source?.type !== 'tool') continue;
              const messages = await ctx.session.context({ sessionID: request.sessionID });
              const agent = messages.find((m) => m.id === request.source.messageID)?.agent;
              const event = { ...request, agent, effect: 'ask' },
                p = await prepare(event, controller.signal);
              p.runtime ??= pendingRuntime.get(fingerprint(event));
              const checked = await gate(p.request, { ...p, signal: controller.signal });
              checkedPending.set(request.id, { rulesHash, fingerprint: checked.fingerprint });
              if (previous?.fingerprint === checked.fingerprint) continue;
              await queue.recheck(request, {
                agent,
                configHash: digest(p.config),
                directory: p.scope.directory,
                toolHash: digest(p.tool),
                preview: requestPreview(event, p.tool),
                model: p.config.model,
              });
            }
          } catch {}
          await pause(3000, controller.signal).catch(() => {});
        }
      })();
      registrations.push(
        await ctx.tool.transform((editor) =>
          editor.add({
            name: 'approval_scratch',
            description:
              'Return this session’s private scratch directory. Use it for pytest --basetemp and disposable test outputs. Each worker must request its own directory.',
            input: { type: 'object', properties: {}, additionalProperties: false },
            options: { codemode: true, permission: 'approval_scratch' },
            execute: async (_, tool) => ({
              content: JSON.stringify({
                directory: await scratchDirectory((await readPolicy()).scratchRoot, tool.sessionID),
              }),
            }),
          }),
        ),
      );
      return async () => {
        controller.abort();
        await queue.stop();
        await Promise.allSettled([events, recovery]);
        host.clear();
        for (const registration of registrations.reverse()) await registration.dispose();
      };
    },
  });
}
export default createApprovalPlugin();

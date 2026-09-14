import { randomUUID } from 'node:crypto';
import { digest } from './policy.mjs';

export const reviewMarker = (message) =>
  /^Automatic review \[([a-f0-9-]{36})\] is pending\./.exec(message ?? '')?.[1];
export const fingerprint = (event) =>
  digest({
    sessionID: event.sessionID,
    action: event.action,
    resources: event.resources,
    source: event.source ?? null,
    metadata: event.metadata ?? null,
  });
const key = (ticket) => 'approval.async.v1.' + ticket;
export const formatFailure = (result) =>
  [
    'invalid_json',
    'invalid_schema',
    'classifier_response_invalid',
    'classifier_truncated',
  ].includes(result?.code);
export const transient = (result) =>
  formatFailure(result) ||
  ['classifier_unavailable', 'model_request_failed', 'review_context_changed'].includes(
    result?.code,
  ) ||
  (result?.code === 'review_timeout' && result.stage === 'model');
export function pause(ms, signal) {
  return new Promise((resolve, reject) => {
    const cancel = () => {
      clearTimeout(timer);
      reject(Error('Cancelled'));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', cancel);
      resolve();
    }, ms);
    if (signal?.aborted) cancel();
    else signal?.addEventListener('abort', cancel, { once: true });
  });
}

// Native pending requests own execution. This queue can only send a one-use reply.
export function createAsyncReview({
  storage,
  permission,
  review,
  audit,
  preflight,
  now = Date.now,
  owner = null,
  maxConcurrent = 2,
  maxAttempts = 20,
  maxFormatAttempts = 3,
  maxAgeMs = 30 * 60000,
  retryDelay = (attempt) => Math.min(60000, [3000, 10000, 30000][attempt - 1] ?? 60000),
  sleep = pause,
}) {
  const jobs = new Map(),
    offers = new Map(),
    tasks = new Set(),
    binding = new Set();
  const awaitingReply = new Map(),
    ruleCommits = new Map();
  let active = 0,
    stopped = false;
  const persist = (job) => storage.set(key(job.ticket), job.meta);
  const track = (promise) => {
    tasks.add(promise);
    void promise.finally(() => tasks.delete(promise)).catch(() => {});
  };
  const pending = (job) =>
    permission.get(
      { sessionID: job.event.sessionID, requestID: job.id },
      { signal: job.controller.signal },
    );
  const same = (job, request) =>
    request?.id === job.id &&
    fingerprint(request) === job.meta.fingerprint &&
    reviewMarker(request.message) === job.ticket;
  async function finish(job, state, result, record) {
    if (job.done) return;
    job.done = true;
    job.controller.abort();
    jobs.delete(job.id);
    offers.delete(job.ticket);
    if (state === 'ask') {
      awaitingReply.set(job.id, job);
      if (awaitingReply.size > 512) awaitingReply.delete(awaitingReply.keys().next().value);
    }
    try {
      await audit(job, state, result, record);
    } finally {
      await storage.remove(key(job.ticket));
    }
  }
  async function retryLookup(job, error, record) {
    if (job.done || stopped || job.controller.signal.aborted) return;
    job.meta.lookupAttempts = (job.meta.lookupAttempts ?? 0) + 1;
    const diagnostic = {
      name: error?.name,
      code: error?.code ?? error?._tag,
      message: String(error?.message ?? error).slice(0, 1500),
    };
    if (
      error?.approvalCode === 'pending_lookup_invalid' ||
      [error?.name, error?._tag, error?.code].includes('SchemaError')
    )
      return finish(
        job,
        'ask',
        {
          effect: 'ask',
          code: 'pending_lookup_invalid',
          stage: 'pending_lookup',
          diagnostic,
          reason: 'The pending request has invalid data. Automatic review cannot continue.',
        },
        record,
      );
    const result = {
      effect: 'ask',
      code: 'pending_lookup_failed',
      stage: 'pending_lookup',
      diagnostic,
      reason:
        'The pending request lookup failed. Review will retry. You can answer the dialog now.',
    };
    if (job.meta.lookupAttempts >= maxAttempts || now() >= job.meta.expires)
      return finish(
        job,
        'ask',
        {
          ...result,
          code: 'pending_lookup_exhausted',
          reason: 'Pending request lookups exhausted their retry budget. Check the native dialog.',
        },
        record,
      );
    job.meta.next = now() + retryDelay(job.meta.lookupAttempts);
    await persist(job);
    await audit(job, 'retrying', result, record);
    job.waiting = true;
    track(
      sleep(Math.max(0, job.meta.next - now()), job.controller.signal)
        .then(() => {
          job.waiting = false;
          pump();
        })
        .catch(() => {}),
    );
  }
  async function run(job) {
    try {
      if (now() >= job.meta.expires || job.meta.attempt >= maxAttempts) {
        return await finish(job, 'ask', {
          effect: 'ask',
          code: 'retry_exhausted',
          reason: 'Background retries ended. The approval dialog remains available.',
        });
      }
      let request;
      try {
        request = await pending(job);
      } catch (error) {
        return await retryLookup(job, error, job.record);
      }
      if (job.done || stopped || job.controller.signal.aborted) return;
      if (request === null)
        return await finish(job, 'resolved', {
          effect: 'ask',
          code: 'pending_gone',
          reason: 'The native request is no longer pending.',
        });
      if (!same(job, request))
        return await finish(job, 'ask', { effect: 'ask', code: 'pending_changed' });
      job.meta.attempt++;
      await persist(job);
      await audit(job, 'reviewing', {
        effect: 'ask',
        code: 'review_in_progress',
        reason: 'Model review is in progress. You can answer the approval dialog now.',
      });
      const { result, record } = await review(job, job.controller.signal);
      if (job.done || stopped || job.controller.signal.aborted) return;
      job.record = record;
      if (result.effect === 'allow') {
        try {
          request = await pending(job);
        } catch (error) {
          return await retryLookup(job, error, record);
        }
        if (request === null)
          return await finish(
            job,
            'resolved',
            {
              effect: 'ask',
              code: 'pending_gone',
              reason: 'The native request is no longer pending.',
            },
            record,
          );
        if (!same(job, request))
          return await finish(job, 'ask', { effect: 'ask', code: 'pending_changed' }, record);
        if (!(await preflight(job, job.controller.signal)))
          return await finish(
            job,
            'ask',
            { effect: 'ask', code: 'native_preflight_failed' },
            record,
          );
        if (job.done || stopped || job.controller.signal.aborted) return;
        // Save the intent before replying. It is not yet an applied ALLOW.
        await audit(job, 'grant_pending', result, record);
        if (job.done || stopped || job.controller.signal.aborted) return;
        job.committing = true;
        let releaseRules;
        if (result.remember?.length)
          ruleCommits.set(job.id, {
            projectID: result.projectID,
            settled: new Promise((resolve) => {
              releaseRules = resolve;
            }),
          });
        try {
          await permission.reply(
            { sessionID: job.event.sessionID, requestID: job.id, reply: 'once' },
            { signal: job.controller.signal },
          );
          if (!job.done && !stopped) await finish(job, 'allow', result, record);
        } catch {
          if (!job.done && !stopped)
            await finish(
              job,
              'resolved',
              {
                effect: 'ask',
                code: 'reply_not_confirmed',
                reason:
                  'The automatic reply was not confirmed. A concurrent user response takes precedence.',
              },
              record,
            );
        } finally {
          job.committing = false;
          ruleCommits.delete(job.id);
          releaseRules?.();
        }
        return;
      }
      if (!transient(result)) return await finish(job, 'ask', result, record);
      if (formatFailure(result)) {
        job.meta.retryFeedback = result.feedback;
        job.meta.formatAttempts = (job.meta.formatAttempts ?? 0) + 1;
        await persist(job);
        if (job.meta.formatAttempts >= maxFormatAttempts) {
          return await finish(
            job,
            'ask',
            {
              effect: 'ask',
              code: 'classifier_format_exhausted',
              reason: `The classifier returned no valid completed decision after ${maxFormatAttempts} format attempts. User approval is required.`,
            },
            record,
          );
        }
      }
      if (job.meta.attempt >= maxAttempts || now() >= job.meta.expires) {
        return await finish(
          job,
          'ask',
          {
            effect: 'ask',
            code: 'retry_exhausted',
            reason:
              'Background retries ended after transient failures. User approval is still available.',
          },
          record,
        );
      }
      job.meta.next = now() + retryDelay(job.meta.attempt);
      await persist(job);
      await audit(
        job,
        'retrying',
        {
          ...result,
          reason: formatFailure(result)
            ? 'The classifier response was incomplete or invalid. Review will retry in the background. You can answer now.'
            : 'Temporary classifier failure. Review will retry in the background. You can answer now.',
        },
        record,
      );
      job.waiting = true;
      track(
        sleep(Math.max(0, job.meta.next - now()), job.controller.signal)
          .then(() => {
            job.waiting = false;
            pump();
          })
          .catch(() => {}),
      );
    } catch {
      if (!job.done && !stopped) {
        // Storage, audit, and context errors must not become repeated model retries.
        await finish(job, 'ask', {
          effect: 'ask',
          code: 'async_review_failed',
          reason: 'Background review could not finish safely. User approval is required.',
        }).catch(() => {});
      }
    }
  }
  function pump() {
    if (stopped) return;
    for (const job of jobs.values()) {
      if (active >= maxConcurrent) break;
      if (job.running || job.waiting || job.done) continue;
      job.running = true;
      active++;
      track(
        run(job).finally(() => {
          active--;
          job.running = false;
          pump();
        }),
      );
    }
  }
  return {
    // A native reply can resume the next tool before its model rules are saved.
    // Wait only for confirmed-reply bookkeeping, never for model inference.
    settleRules(projectID) {
      return Promise.all(
        [...ruleCommits.values()].filter((c) => c.projectID === projectID).map((c) => c.settled),
      );
    },
    async recheck(request, context) {
      const ticket = reviewMarker(request.message);
      if (
        !ticket ||
        stopped ||
        jobs.has(request.id) ||
        binding.has(request.id) ||
        jobs.size + offers.size >= 256
      )
        return false;
      const meta = {
        version: 1,
        ticket,
        reviewID: randomUUID(),
        fingerprint: fingerprint(request),
        sessionID: request.sessionID,
        original: 'ask',
        created: now(),
        expires: now() + maxAgeMs,
        attempt: 0,
        ...context,
        owner: digest(owner),
      };
      await storage.set(key(ticket), meta);
      offers.set(ticket, meta);
      await this.asked(request);
      return true;
    },
    async offer(event, context) {
      // A later native hook can suppress a prompt. Expire its unused offer.
      for (const [ticket, meta] of offers)
        if (meta.created < now() - 60000) {
          offers.delete(ticket);
          track(storage.remove(key(ticket)));
        }
      if (stopped || jobs.size + offers.size >= 256) throw Error('Review queue is full');
      const ticket = randomUUID();
      const meta = {
        version: 1,
        ticket,
        fingerprint: fingerprint(event),
        sessionID: event.sessionID,
        agent: event.agent ?? null,
        original: event.effect,
        created: now(),
        expires: now() + maxAgeMs,
        attempt: 0,
        ...context,
        owner: digest(owner),
      };
      await storage.set(key(ticket), meta);
      offers.set(ticket, meta);
      event.effect = 'ask';
      event.message = `Automatic review [${ticket}] is pending. You may approve or reject now. See /approval-audit for progress.`;
      return ticket;
    },
    async asked(request) {
      const ticket = reviewMarker(request.message);
      if (!ticket || stopped || jobs.has(request.id) || binding.has(request.id)) return;
      binding.add(request.id);
      try {
        const meta = offers.get(ticket) ?? (await storage.get(key(ticket)));
        if (
          !meta ||
          meta.version !== 1 ||
          meta.ticket !== ticket ||
          meta.sessionID !== request.sessionID ||
          meta.fingerprint !== fingerprint(request)
        )
          return;
        // Storage and event delivery span locations. A foreign instance must not
        // review, resolve, or delete this location's ticket.
        const legacyOwner =
          !meta.owner &&
          owner?.directory &&
          !owner.workspaceID &&
          meta.directory === owner.directory;
        if (meta.owner !== digest(owner) && !legacyOwner) return;
        // Only a ticket issued by this plugin can recover a pending request.
        if (meta.requestID && meta.requestID !== request.id) return;
        meta.requestID = request.id;
        const job = {
          id: request.id,
          ticket,
          meta,
          event: { ...request, agent: meta.agent ?? undefined, effect: meta.original },
          controller: new AbortController(),
          done: false,
        };
        awaitingReply.delete(job.id);
        jobs.set(job.id, job);
        offers.delete(ticket);
        try {
          await persist(job);
          await audit(job, 'queued', {
            effect: 'ask',
            code: 'review_queued',
            reason: 'Automatic review is queued. You can answer the approval dialog now.',
          });
          if (meta.next && meta.next > now()) {
            job.waiting = true;
            track(
              sleep(Math.min(meta.next - now(), 60000), job.controller.signal)
                .then(() => {
                  job.waiting = false;
                  pump();
                })
                .catch(() => {}),
            );
          }
          pump();
        } catch {
          await finish(job, 'ask', { effect: 'ask', code: 'audit_unavailable' }).catch(() => {});
        }
      } finally {
        binding.delete(request.id);
      }
    },
    replied(event) {
      const job = jobs.get(event.requestID) ?? awaitingReply.get(event.requestID);
      if (job?.done && job.event.sessionID === event.sessionID) {
        awaitingReply.delete(event.requestID);
        track(
          audit(
            job,
            'native_reply',
            {
              effect: event.reply === 'reject' ? 'deny' : 'allow',
              code: 'native_reply',
              reason: `The dialog received a native ${event.reply} response after escalation.`,
            },
            job.record,
          ),
        );
        return;
      }
      if (!job || job.event.sessionID !== event.sessionID || job.done) return;
      // While our own reply is in flight, HTTP success determines its provenance.
      if (job.committing && event.reply === 'once') return;
      track(
        finish(
          job,
          'native_reply',
          {
            effect: event.reply === 'reject' ? 'deny' : 'allow',
            code: 'native_reply',
            reason: `The dialog received a native ${event.reply} response. Background review was cancelled.`,
          },
          job.record,
        ),
      );
    },
    async stop() {
      stopped = true;
      for (const job of jobs.values()) job.controller.abort();
      await Promise.allSettled([...tasks]);
      jobs.clear();
      offers.clear();
      awaitingReply.clear();
    },
    get size() {
      return jobs.size;
    },
  };
}

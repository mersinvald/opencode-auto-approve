import { readFileSync } from 'node:fs';
import os from 'node:os';
import { createElement, insert, setProp } from '@opentui/solid';
import { createComponent, createSignal, onCleanup, untrack, For, Show } from 'solid-js';
import { auditRoot, readAudit, statusLabel } from './audit-view.mjs';
import { safeText } from './audit.mjs';
import { createGrantPanel } from './grant-tree-tui.mjs';
import { createApprovalNotifications, notifyMac } from './approval-notifications.mjs';

const { policyFile } = JSON.parse(readFileSync(new URL('./viewer.json', import.meta.url), 'utf8'));
const panelName = 'approval-audit.history';
function element(tag, props, children = []) {
  const node = createElement(tag);
  for (const [name, value] of Object.entries(props)) setProp(node, name, value);
  for (const child of children) insert(node, child);
  return node;
}

export default {
  id: 'local.approval-audit',
  setup(ctx) {
    let notificationWarningAt = 0;
    const notifications = createApprovalNotifications({
      client: ctx.client,
      policyFile,
      notify: (options) => notifyMac(ctx.attention, options, { policyFile }),
      onError: (message) => {
        if (Date.now() - notificationWarningAt < 60000) return;
        notificationWarningAt = Date.now();
        ctx.ui.toast.show({ title: 'Approval notifications', message, duration: 6000 });
      },
    });
    notifications.start();
    const grants = createGrantPanel({ ctx, policyFile });
    const color = (effect) =>
      effect === 'allow'
        ? ctx.theme.text.feedback.success.default
        : effect === 'ask'
          ? ctx.theme.text.feedback.warning.default
          : effect === 'deny'
            ? ctx.theme.text.feedback.error.default
            : ctx.theme.text.subdued;
    const text = (value, fg = ctx.theme.text.default, bold = false) =>
      element(
        'text',
        {
          fg,
          attributes: bold ? 1 : 0,
          wrapMode: 'word',
          flexShrink: 0,
        },
        [value],
      );
    const muted = (value) => text(value, ctx.theme.text.subdued);
    const open = () => {
      if (ctx.ui.panel.open(panelName)) return;
      ctx.ui.dialog.set({ size: 'large' });
      ctx.ui.dialog.show(() => content());
    };
    const content = (panel) => {
      const [records, setRecords] = createSignal([]);
      const [notice, setNotice] = createSignal('Loading local audit…');
      const [status, setStatus] = createSignal('');
      const [filter, setFilter] = createSignal('all');
      const [details, setDetails] = createSignal(false);
      let active = true,
        busy = false,
        queued = false;
      const refresh = async () => {
        if (!active) return;
        if (busy) {
          queued = true;
          return;
        }
        const selected = filter();
        busy = true;
        try {
          const result = await readAudit(await auditRoot(policyFile), {
            limit: 60,
            ...(selected === 'ask' ? { decision: 'ask' } : {}),
            modelOnly: selected === 'model',
          });
          if (active && selected === filter()) {
            // Retain existing row identities so a refresh does not rebuild the scroll contents.
            const previous = new Map();
            for (const record of records()) {
              const key = JSON.stringify(record);
              if (!previous.has(key)) previous.set(key, []);
              previous.get(key).push(record);
            }
            setRecords(
              [...result.records]
                .reverse()
                .map((record) => previous.get(JSON.stringify(record))?.shift() ?? record),
            );
            setNotice(result.records.length ? '' : 'No matching audit records.');
            setStatus(
              `${result.records.length} ${result.records.length === 1 ? 'record' : 'records'} · updated ${new Date().toLocaleTimeString([], { hour12: false })}` +
                (result.limited || result.skipped
                  ? ` · bounded tails, invalid: ${result.skipped}`
                  : ''),
            );
          }
        } catch (error) {
          if (active) setNotice(`Cannot read audit: ${safeText(error.message)}`);
        } finally {
          busy = false;
          if (queued) {
            queued = false;
            void refresh();
          }
        }
      };
      const card = (record) => {
        const decision =
          record.action === 'scoped_permission' || record.applied === 'pending'
            ? statusLabel(record.status)
            : (record.applied?.toUpperCase() ?? 'LEGACY');
        const date = new Date(record.time);
        const time = Number.isNaN(date.valueOf())
          ? record.time
          : date.toLocaleTimeString([], { hour12: false });
        const day = Number.isNaN(date.valueOf())
          ? ''
          : date.toLocaleDateString([], { month: 'short', day: 'numeric' });
        const latency =
          record.elapsedMs === null
            ? '?'
            : record.elapsedMs < 1000
              ? `${record.elapsedMs} ms`
              : `${(record.elapsedMs / 1000).toFixed(1)} s`;
        const origin = record.model
          ? `${record.model.id} · ${record.model.variant}`
          : 'Rule / system';
        const sameReason = record.modelDecision?.reason === record.reason;
        const explanation = (label, reason, effect) =>
          element('box', { flexDirection: 'column', marginTop: 1 }, [
            text(label, color(effect), true),
            text(reason),
          ]);
        const node = element(
          'box',
          {
            width: '100%',
            flexDirection: 'column',
            flexShrink: 0,
            border: ['left'],
            borderColor: color(record.applied),
            paddingLeft: 1,
            paddingRight: 1,
            marginBottom: 1,
            backgroundColor: ctx.theme.background.surface.offset,
          },
          [
            element(
              'box',
              { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'space-between', gap: 1 },
              [
                text(`${decision}  ${record.action}`, color(record.applied), true),
                muted(`${day} · ${time}`),
              ],
            ),
            text(record.preview.replaceAll(os.homedir() + '/', '~/')),
          ],
        );
        if (record.mode !== 'enforce' || !record.applied)
          insert(
            node,
            text(
              record.applied
                ? `${record.mode.toUpperCase()} · review ${record.proposed.toUpperCase()}, native ${decision}`
                : `Proposed ${record.proposed.toUpperCase()} · final decision not stored`,
              color('ask'),
            ),
          );
        insert(
          node,
          explanation(
            sameReason
              ? `Model · ${record.modelDecision.effect.toUpperCase()}`
              : record.modelDecision
                ? `Policy · ${decision}`
                : 'Reason',
            record.reason,
            sameReason ? record.modelDecision.effect : record.applied,
          ),
        );
        if (record.modelDecision && !sameReason)
          insert(
            node,
            explanation(
              `Model · ${record.modelDecision.effect.toUpperCase()}`,
              record.modelDecision.reason,
              record.modelDecision.effect,
            ),
          );
        else if (record.model && !record.modelDecision && record.version === 2)
          insert(node, muted('Model returned no structured decision.'));
        insert(
          node,
          element('box', { flexDirection: 'column', marginTop: 1 }, [
            muted(`${origin} · ${latency}`),
            ...(record.attempt
              ? [
                  muted(
                    `Attempt ${record.attempt}${record.nextRetryAt ? ' · next ' + new Date(record.nextRetryAt).toLocaleTimeString([], { hour12: false }) : ''}`,
                  ),
                ]
              : []),
            muted(`Session …${record.sessionID.slice(-12)}`),
            ...(record.grantID ? [muted(`Scoped permission ${record.grantID}`)] : []),
          ]),
        );
        insert(
          node,
          element('box', { flexDirection: 'column', flexShrink: 0 }, [
            createComponent(Show, {
              get when() {
                return details();
              },
              children: () =>
                element('box', { flexDirection: 'column', marginTop: 1 }, [
                  muted(`Code  ${record.code}${record.stage ? ' · ' + record.stage : ''}`),
                  muted(`Session  ${record.sessionID}`),
                  ...(record.sourceID ? [muted(`Source  ${record.sourceID}`)] : []),
                  ...(record.requestID ? [muted(`Request  ${record.requestID}`)] : []),
                  muted(`Time  ${record.time}`),
                ]),
            }),
          ]),
        );
        return node;
      };
      const scroll = element('scrollbox', {
        flexGrow: 1,
        minHeight: 0,
        width: '100%',
        scrollY: true,
      });
      insert(
        scroll,
        createComponent(For, {
          get each() {
            return records();
          },
          children: card,
        }),
      );
      const select = (value) => {
        setFilter(value);
        scroll.scrollTo(0);
        void refresh();
      };
      // The initial filter read must not become a dependency of the panel render.
      void untrack(refresh);
      const timer = setInterval(() => void refresh(), 3000);
      onCleanup(() => {
        active = false;
        clearInterval(timer);
      });
      ctx.keymap.layer(() => ({
        mode: panel ? 'base' : 'modal',
        commands: [
          { bind: 'r', run: () => void refresh() },
          { bind: 'a', run: () => select('all') },
          { bind: 'q', run: () => select('ask') },
          { bind: 'm', run: () => select('model') },
          { bind: 'd', run: () => setDetails((value) => !value) },
          { bind: 'down,j', run: () => scroll.scrollBy(1) },
          { bind: 'up,k', run: () => scroll.scrollBy(-1) },
          { bind: 'pagedown', run: () => scroll.scrollBy(12) },
          { bind: 'pageup', run: () => scroll.scrollBy(-12) },
          { bind: 'escape', run: () => (panel ? panel.close() : ctx.ui.dialog.clear()) },
          ...(panel ? [{ bind: 'f', run: panel.toggleFullscreen }] : []),
        ],
      }));
      const tabs = element('box', { flexDirection: 'row', flexWrap: 'wrap', gap: 2 });
      for (const [value, label] of [
        ['all', 'a All'],
        ['ask', 'q Asked'],
        ['model', 'm Model'],
      ]) {
        insert(
          tabs,
          element('box', { onMouseDown: () => select(value) }, [
            text(
              () => (filter() === value ? `[${label}]` : label),
              value === 'ask' ? color('ask') : ctx.theme.text.default,
            ),
          ]),
        );
      }
      return element(
        'box',
        { width: '100%', height: '100%', flexDirection: 'column', padding: 1 },
        [
          element('box', { flexDirection: 'column', flexShrink: 0, marginBottom: 1 }, [
            text('Approval audit', ctx.theme.text.default, true),
            tabs,
            muted(status),
            element('box', { flexDirection: 'column' }, [
              createComponent(Show, {
                get when() {
                  return notice();
                },
                children: () => text(notice, color('ask')),
              }),
            ]),
          ]),
          scroll,
          element('box', { flexDirection: 'column', flexShrink: 0, marginTop: 1 }, [
            muted(
              () =>
                `d Details ${details() ? 'on' : 'off'} · r Refresh${panel ? ' · f Fullscreen' : ''} · Esc Close`,
            ),
            muted('Review states and native replies. Command execution is not recorded.'),
          ]),
        ],
      );
    };
    const disposePanel = ctx.ui.slot({
      append: 'session.panel',
      render: (panel) =>
        createComponent(Show, {
          get when() {
            return panel.name === panelName;
          },
          children: () => content(panel),
        }),
    });
    const disposeProgress = ctx.ui.slot({
      append: 'session.composer.top',
      render: ({ sessionID }) => {
        const [lines, setLines] = createSignal([]);
        let active = true,
          busy = false;
        const refresh = async () => {
          if (!active || busy) return;
          busy = true;
          try {
            await ctx.data.session.permission.sync(sessionID);
            const pending = new Set(
              (ctx.data.session.permission.list(sessionID) ?? []).map((r) => r.id),
            );
            if (!pending.size) {
              if (active) setLines([]);
              return;
            }
            const { records } = await readAudit(await auditRoot(policyFile), {
              session: sessionID,
              limit: 60,
            });
            if (active)
              setLines(records.filter((r) => r.requestID && pending.has(r.requestID)).slice(-3));
          } catch {
            /* The native permission dialog remains available without this status view. */
          } finally {
            busy = false;
          }
        };
        void untrack(refresh);
        const timer = setInterval(() => void refresh(), 3000);
        onCleanup(() => {
          active = false;
          clearInterval(timer);
        });
        return element('box', { flexDirection: 'column', flexShrink: 0 }, [
          createComponent(For, {
            get each() {
              return lines();
            },
            children: (record) =>
              element('box', { flexDirection: 'column' }, [
                muted(`Automatic review · ${statusLabel(record.status)} · ${record.reason}`),
                ...(record.status === 'ask'
                  ? [
                      element(
                        'box',
                        { onMouseDown: () => void grants.open(sessionID, record.requestID) },
                        [text('[Project grants]  Ctrl+G', ctx.theme.text.feedback.warning.default)],
                      ),
                    ]
                  : []),
              ]),
          }),
        ]);
      },
    });
    const disposeCommands = ctx.ui.slot({
      append: 'app',
      render: () => {
        ctx.keymap.layer(() => ({
          mode: 'global',
          priority: 10,
          commands: [
            {
              id: 'approval-audit.open',
              title: 'Approval: view automatic review audit',
              group: 'Approval',
              palette: true,
              slash: { name: 'approval-audit' },
              run: open,
            },
            {
              id: 'approval-notification.test',
              title: 'Approval: test macOS notification',
              group: 'Approval',
              palette: true,
              slash: { name: 'approval-notification-test' },
              run: () => {
                void notifyMac(
                  ctx.attention,
                  {
                    title: 'OpenCode · Notification test',
                    message:
                      'Approval notifications are connected. This test does not approve an action.',
                    notification: { when: 'always' },
                    sound: { name: 'permission', when: 'always' },
                  },
                  { policyFile },
                )
                  .then((result) =>
                    ctx.ui.toast.show({
                      title: 'Approval notifications',
                      duration: 6000,
                      message: result.notification
                        ? 'Notification sent to macOS.'
                        : `Notification skipped: ${result.skipped ?? 'unavailable'}. Check attention and macOS settings.`,
                    }),
                  )
                  .catch(() =>
                    ctx.ui.toast.show({
                      title: 'Approval notifications',
                      message: 'Notification failed. Check macOS notification settings.',
                      duration: 6000,
                    }),
                  );
              },
            },
            {
              id: 'approval-grants.open',
              title: 'Approval: manage project grant tree',
              group: 'Approval',
              palette: true,
              slash: { name: 'approval-grants' },
              bind: 'ctrl+g',
              run: () => {
                const route = ctx.ui.router.current();
                void grants.open(route?.type === 'session' ? route.sessionID : null);
              },
            },
          ],
        }));
        return null;
      },
    });
    return () => {
      notifications.stop();
      disposeCommands();
      disposePanel();
      disposeProgress();
    };
  },
};

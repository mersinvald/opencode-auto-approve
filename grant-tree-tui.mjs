import { readFile } from 'node:fs/promises';
import os from 'node:os';
import { createElement, insert, setProp } from '@opentui/solid';
import { createComponent, createSignal, For, onCleanup } from 'solid-js';
import { createRuleStore } from './grant-store.mjs';
import { grantTree, modeLabels, grantLabel } from './grant-rules.mjs';
import { globalRules } from './grant-gate.mjs';
import { safeText } from './audit.mjs';
import { writeAudit } from './audit-storage.mjs';

const unwrap = (x) => {
  if (x?.error) throw Error('OpenCode request failed');
  return x?.data ?? x;
};
export function createGrantPanel({ ctx, policyFile }) {
  const store = createRuleStore(policyFile);
  let open = false;
  const panel = {
    async open(sessionID, initialFilter = '') {
      if (open) return;
      if (!sessionID) {
        ctx.ui.toast.show({ title: 'Project grants', message: 'Open a session first.' });
        return;
      }
      const session = unwrap(await ctx.client.session.get({ sessionID }));
      const config = JSON.parse(await readFile(policyFile, 'utf8'));
      open = true;
      ctx.ui.dialog.set({ size: 'large' });
      ctx.ui.dialog.show(() => {
        const [tree, setTree] = createSignal([]),
          [selected, setSelected] = createSignal(0),
          [expanded, setExpanded] = createSignal(new Set());
        const [status, setStatus] = createSignal('Loading project grants…'),
          [filter] = createSignal(initialFilter);
        let active = true,
          busy = false;
        const node = (tag, props, children = []) => {
          const n = createElement(tag);
          for (const [k, v] of Object.entries(props)) setProp(n, k, v);
          for (const c of children) insert(n, c);
          return n;
        };
        const text = (value, fg = ctx.theme.text.default) =>
          node('text', { fg, wrapMode: 'word', flexShrink: 0 }, [value]);
        const muted = (value) => text(value, ctx.theme.text.subdued);
        const rows = () => {
          const result = [],
            query = filter().toLowerCase();
          const visit = (n, depth) => {
            const visible =
              !query ||
              (n.operation + ' ' + grantLabel(n) + ' ' + (n.rule?.provenance?.reason ?? ''))
                .toLowerCase()
                .includes(query);
            if (visible) result.push({ ...n, depth });
            if (expanded().has(n.key) || query) n.children.forEach((c) => visit(c, depth + 1));
          };
          tree().forEach((n) => visit(n, 0));
          return result;
        };
        const current = () => rows()[Math.min(selected(), Math.max(0, rows().length - 1))];
        const refresh = async () => {
          try {
            const state = await store.read(session.projectID);
            if (!active) return;
            setTree(
              grantTree(state.seen, [
                ...globalRules(config, { directory: session.location.directory }),
                ...state.rules,
              ]),
            );
            setStatus(
              `${state.seen.length} seen grants · ${state.rules.length} project rules · ${session.location.directory}`,
            );
          } catch (e) {
            if (active) setStatus(safeText(e.message));
          }
        };
        const save = async (mode) => {
          const item = current();
          if (!item || busy) return;
          busy = true;
          try {
            const latest = unwrap(await ctx.client.session.get({ sessionID }));
            if (latest.projectID !== session.projectID)
              throw Error('The session project changed. Reopen grants.');
            await store.set(session.projectID, item, mode, 'user', {
              sessionID,
              source: 'grant tree',
            });
            await writeAudit(config.auditRoot, {
              version: 3,
              time: new Date().toISOString(),
              sessionID,
              action: 'scoped_permission',
              status: 'rule_changed',
              code: 'user_rule_changed',
              original: 'ask',
              proposed: mode === 'allow' ? 'allow' : 'ask',
              applied: mode === 'allow' ? 'allow' : 'ask',
              mode: 'enforce',
              elapsedMs: 0,
              preview: `${item.operation}: ${grantLabel(item)}`,
              reason: `User selected ${modeLabels[mode]}.`,
              permissionContext: { projectID: session.projectID },
            });
            await refresh();
            setStatus(
              `${modeLabels[mode]} · ${item.operation} · ${grantLabel(item)}. Pending reviews will update.`,
            );
          } catch (e) {
            setStatus(safeText(e.message));
          } finally {
            busy = false;
          }
        };
        const toggle = () => {
          const item = current();
          if (!item?.children.length) return;
          setExpanded((s) => {
            const n = new Set(s);
            n.has(item.key) ? n.delete(item.key) : n.add(item.key);
            return n;
          });
        };
        const scroll = node('scrollbox', {
          flexGrow: 1,
          minHeight: 0,
          width: '100%',
          scrollY: true,
        });
        insert(
          scroll,
          createComponent(For, {
            get each() {
              return rows();
            },
            children: (item, index) =>
              node(
                'box',
                {
                  flexDirection: 'row',
                  width: '100%',
                  flexShrink: 0,
                  paddingLeft: Math.min(item.depth * 2, 30),
                  get backgroundColor() {
                    return selected() === index() ? ctx.theme.background.surface.offset : undefined;
                  },
                  onMouseDown: () => setSelected(index()),
                },
                [
                  text(
                    () =>
                      `${selected() === index() ? '›' : ' '} ${item.children.length ? (expanded().has(item.key) ? '▾' : '▸') : '·'} `,
                  ),
                  text(
                    `${safeText(item.targetType === 'any' ? item.operation : grantLabel(item).replace(os.homedir() + '/', '~/'), 800)}  `,
                  ),
                  text(
                    modeLabels[item.mode],
                    item.mode === 'allow'
                      ? ctx.theme.text.feedback.success.default
                      : item.mode === 'ask'
                        ? ctx.theme.text.feedback.warning.default
                        : ctx.theme.text.subdued,
                  ),
                  muted(`  ${item.rule?.authority ?? 'default'}${item.seen ? ' · seen' : ''}`),
                ],
              ),
          }),
        );
        const move = (delta) => {
          setSelected((n) => Math.max(0, Math.min(rows().length - 1, n + delta)));
          scroll.scrollBy(delta);
        };
        const close = () => ctx.ui.dialog.clear();
        ctx.keymap.layer(() => ({
          mode: 'modal',
          priority: 10,
          commands: [
            { bind: 'down,j', run: () => move(1) },
            { bind: 'up,k', run: () => move(-1) },
            { bind: 'enter,right,l', run: toggle },
            {
              bind: 'left,h',
              run: () => {
                const item = current();
                if (!item) return;
                if (expanded().has(item.key)) toggle();
                else {
                  const i = rows().findIndex((n) => n.key === item.parent);
                  if (i >= 0) setSelected(i);
                }
              },
            },
            { bind: 'a', run: () => void save('allow') },
            { bind: 's', run: () => void save('ask') },
            { bind: 'd', run: () => void save('dynamic') },
            { bind: 'r', run: () => void refresh() },
            {
              bind: '/',
              run: () => {
                ctx.ui.dialog.clear();
                void ctx.ui.dialog
                  .prompt({ title: 'Filter grants', placeholder: 'Path or operation' })
                  .then((value) => panel.open(sessionID, value ?? filter()));
              },
            },
            { bind: 'escape', run: close },
          ],
        }));
        void refresh();
        const timer = setInterval(() => {
          if (!busy) void refresh();
        }, 5000);
        onCleanup(() => {
          active = false;
          open = false;
          clearInterval(timer);
        });
        return node('box', { width: '100%', height: '100%', flexDirection: 'column', padding: 1 }, [
          text('Project grants'),
          muted(status),
          muted('More specific targets override their parents. Changes apply to this project.'),
          scroll,
          node('box', { flexDirection: 'column', marginTop: 1 }, [
            text(() =>
              current() ? safeText(`${current().operation} · ${current().target}`, 1200) : '',
            ),
            muted(() =>
              current()?.rule
                ? `Source: ${current().rule.authority} · ${safeText(current().rule.provenance?.reason ?? current().rule.provenance?.source ?? 'Global defaults')}`
                : 'No rule. The model decides.',
            ),
            text('A Always allow   S Always ask   D Dynamic   ←/→ Collapse/expand'),
            muted('↑/↓ Select · / Filter · R Refresh · Esc Close'),
          ]),
        ]);
      });
    },
  };
  return panel;
}

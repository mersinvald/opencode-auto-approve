#!/usr/bin/env python3
"""Install the approval plugin and preserve the existing OpenCode profile."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import shlex
import tempfile

SOURCE = Path(__file__).resolve().parent

def link_runtime(destination):
    modules = SOURCE/'node_modules'
    target = destination/'node_modules'
    if not modules.is_dir():
        raise ValueError('Run npm ci in the plugin checkout first')
    if not target.exists():
        target.symlink_to(modules, target_is_directory=True)

PLUGIN_FILES = ['index.mjs', 'review-context.mjs', 'async-review.mjs', 'native-transport.mjs', 'native-permissions.mjs', 'policy.mjs', 'grant-decision.mjs', 'structured-classifier.mjs', 'shell-context.mjs', 'shell-host.mjs', 'shell-words.mjs', 'shell-inspection.mjs', 'sqlite-read.mjs', 'action-grants.mjs', 'grant-gate.mjs', 'grant-review.mjs', 'grant-rules.mjs', 'grant-store.mjs', 'repository-scope.mjs', 'audit.mjs', 'audit-detail.mjs', 'audit-storage.mjs', 'audit-view.mjs', 'package.json']

def private_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def install_audit_viewer(root, bin_dir=None):
    """Install audit interfaces without changing models or permission rules."""
    root = root.expanduser().resolve()
    if not (SOURCE/'node_modules').is_dir():
        raise ValueError('Run npm ci in the plugin checkout first')
    cli_file = root/'cli.json'
    if (root/'cli.jsonc').exists() or cli_file.is_symlink():
        raise ValueError('Resolve competing JSONC or symlink CLI configuration first')
    cli = json.loads(cli_file.read_text()) if cli_file.exists() else {}
    destination = root/'plugins-dev/approval-audit'
    bin_dir = bin_dir or Path.home()/'.local/bin'
    launcher = bin_dir/'oc-approvals'
    node = shutil.which('node')
    if not node:
        raise ValueError('Node is required for the audit viewer')
    backup = root/'backups'/('approval-audit-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(parents=True, mode=0o700)
    if cli_file.exists():
        shutil.copy2(cli_file, backup/'cli.json')
        (backup/'cli.json').chmod(0o600)
    if destination.exists():
        shutil.copytree(destination, backup/'viewer', symlinks=True)
    if launcher.exists():
        shutil.copy2(launcher, backup/'oc-approvals')
    destination.mkdir(parents=True, exist_ok=True)
    link_runtime(destination)
    for name in ['audit.mjs', 'audit-detail.mjs', 'audit-view.mjs', 'policy.mjs', 'shell-context.mjs', 'audit-storage.mjs', 'repository-scope.mjs', 'shell-host.mjs', 'shell-words.mjs', 'shell-inspection.mjs', 'sqlite-read.mjs', 'action-grants.mjs', 'grant-gate.mjs', 'grant-rules.mjs', 'grant-store.mjs', 'grant-tree-tui.mjs', 'approval-notifications.mjs']:
        shutil.copy2(SOURCE/name, destination/name)
    shutil.copy2(SOURCE/'audit-tui.mjs', destination/'tui.mjs')
    (destination/'index.mjs').write_text("export { default } from './tui.mjs';\n")
    private_json(destination/'package.json', {
        'name': 'opencode-auto-approve-audit', 'version': json.loads((SOURCE/'package.json').read_text())['version'], 'type': 'module',
        'exports': {'.': './index.mjs', './tui': './tui.mjs'},
    })
    policy_file = root/'approval-policy.json'
    private_json(destination/'viewer.json', {'policyFile': str(policy_file)})
    plugins = cli.setdefault('plugins', [])
    if str(destination) not in plugins:
        plugins.append(str(destination))
    attention = cli.setdefault('attention', {})
    attention.setdefault('enabled', True)
    attention.setdefault('notifications', True)
    attention.setdefault('sound', True)
    private_json(cli_file, cli)
    bin_dir.mkdir(parents=True, exist_ok=True)
    launcher.write_text('#!/bin/sh\nexec ' + shlex.quote(node) + ' ' +
                        shlex.quote(str(destination/'audit-view.mjs')) + ' --policy ' +
                        shlex.quote(str(policy_file)) + ' "$@"\n')
    launcher.chmod(0o755)
    return {'backup': str(backup), 'viewer': str(destination), 'command': str(launcher)}

def install(root, mode=None, *, provider_id=None, model_id=None, variant=None,
            bin_dir=None, audit_root=None, scratch_root=None):
    root = root.expanduser().resolve()
    if not (SOURCE/'node_modules').is_dir():
        raise ValueError('Run npm ci in the plugin checkout first')
    config_file = root/'opencode.json'
    if (root/'opencode.jsonc').exists() or config_file.is_symlink():
        raise ValueError('Resolve competing JSONC or symlink configuration first')
    config = json.loads(config_file.read_text())
    policy_file = root/'approval-policy.json'
    for target in [policy_file, root/'cli.json']:
        if target.is_symlink():
            raise ValueError('Configuration symlinks are not supported')
    if (root/'cli.jsonc').exists():
        raise ValueError('Resolve competing CLI JSONC configuration first')
    old = json.loads(policy_file.read_text()) if policy_file.exists() else {}
    selected = dict(old.get('model', {}))
    for key, value in [('providerID', provider_id), ('id', model_id), ('variant', variant)]:
        if value is not None:
            selected[key] = value
    if not all(selected.get(k) for k in ['providerID', 'id', 'variant']):
        raise ValueError('Select --provider, --model, and --variant for the first installation')
    provider = config.get('providers', {}).get(selected['providerID'], {})
    model = provider.get('models', {}).get(selected['id'], {})
    selected_variant = next((v for v in model.get('variants', []) if v['id'] == selected['variant']), {})
    if not selected_variant or {**model.get('body', {}), **selected_variant.get('body', {})}.get('reasoning_effort') != selected['variant']:
        raise ValueError('The selected model variant must set its matching reasoning_effort')
    if not provider.get('settings', {}).get('baseURL') or not provider.get('settings', {}).get('apiKey'):
        raise ValueError('The selected provider requires baseURL and apiKey settings')
    if not shutil.which('node'):
        raise ValueError('Node is required for the audit viewer')
    destination = root/'plugins-dev/approval-review'
    # State defaults belong to this profile, so isolated profiles cannot share audit data.
    audit = (audit_root or root/'approval-state/audit').resolve()
    scratch = (scratch_root or root/'approval-state/scratch').resolve()
    for target in [audit, scratch]:
        if target == Path('/') or target == Path(tempfile.gettempdir()).resolve():
            raise ValueError('Use a dedicated state directory')
    policy = {
        'version': 1, 'mode': 'shadow', 'model': selected,
        'skillRoots': [str(Path(p).expanduser().resolve()) for p in config.get('skills', []) if isinstance(p, str) and Path(p).expanduser().is_dir()],
        'protectedRoots': [], 'scratchRoot': str(scratch),
        'auditRoot': str(audit), 'timeoutMs': 45000, 'maxRequestChars': 32000,
        'modelGrants': {'enabled': True},
        **old,
    }
    policy['model'] = selected
    if mode is not None:
        policy['mode'] = mode
    if audit_root is not None:
        policy['auditRoot'] = str(audit)
    if scratch_root is not None:
        policy['scratchRoot'] = str(scratch)
    if policy['mode'] not in ['off', 'shadow', 'enforce']:
        raise ValueError('Invalid approval mode')
    grant_root = str(root/'approval-rules')
    viewer_root = str(root/'plugins-dev/approval-audit')
    for protected in [grant_root, viewer_root, str(destination), str(policy_file),
                      str(config_file), str(SOURCE), policy['auditRoot']]:
        if protected not in policy['protectedRoots']:
            policy['protectedRoots'].append(protected)
    backup = root/'backups'/('approval-review-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(parents=True, mode=0o700)
    shutil.copy2(config_file, backup/'opencode.json')
    (backup/'opencode.json').chmod(0o600)
    if policy_file.exists():
        shutil.copy2(policy_file, backup/'approval-policy.json')
    if destination.exists():
        shutil.copytree(destination, backup/'plugin', symlinks=True)
    destination.mkdir(parents=True, exist_ok=True)
    link_runtime(destination)
    for name in PLUGIN_FILES:
        shutil.copy2(SOURCE/name, destination/name)
    private_json(policy_file, policy)
    # These native gates remain when the classifier plugin is unavailable.
    gates = [{'action': 'shell', 'resource': '*', 'effect': 'ask'}]
    gates.append({'action': 'edit', 'resource': grant_root + '/*', 'effect': 'ask'})
    gates.append({'action': 'edit', 'resource': viewer_root + '/*', 'effect': 'ask'})
    import re
    gates += [{'action': re.sub(r'[^a-zA-Z0-9_-]', '_', name) + '_*', 'resource': '*', 'effect': 'ask'}
              for name in config.get('mcp', {}).get('servers', {})]
    gates += [{'action': 'edit', 'resource': p + ('/*' if Path(p).is_dir() else ''), 'effect': 'ask'}
              for p in [*policy['skillRoots'], str(destination), str(policy_file), str(root/'opencode.json'),
                        str(root/'AGENTS.md')]]
    rules = config.setdefault('permissions', [])
    for gate in gates:
        if gate not in rules:
            rules.append(gate)
    plugins = config.setdefault('plugins', [])
    plugins[:] = [p for p in plugins if (p.get('package') if isinstance(p, dict) else p) != str(destination)]
    plugins.append({'package': str(destination), 'options': {'policyFile': str(policy_file)}})
    private_json(config_file, config)
    viewer = install_audit_viewer(root, bin_dir)
    return {'backup': str(backup), 'policy': str(policy_file), 'plugin': str(destination), 'mode': policy['mode'], 'auditViewer': viewer}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config-root', type=Path,
                        default=Path(os.environ.get('XDG_CONFIG_HOME', Path.home()/'.config'))/'opencode')
    parser.add_argument('--mode', choices=['shadow', 'enforce', 'off'])
    parser.add_argument('--provider', dest='provider_id')
    parser.add_argument('--model', dest='model_id')
    parser.add_argument('--variant')
    parser.add_argument('--bin-dir', type=Path)
    parser.add_argument('--audit-root', type=Path)
    parser.add_argument('--scratch-root', type=Path)
    args = vars(parser.parse_args())
    root = args.pop('config_root')
    print(json.dumps(install(root, **args)))

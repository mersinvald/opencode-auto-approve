#!/usr/bin/env python3
"""Pin a trusted Python installation for static source analysis."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from datetime import datetime, timezone

SOURCE = Path(__file__).resolve().parent
# Setup inspects only the selected interpreter and fixed standard-library modules.
# The approval path never runs the requested interpreter or imports request code.
INSPECT = r'''
import sys, os, pathlib, subprocess, io, json, ast, hashlib, re, encodings.ascii, encodings.latin_1, encodings.utf_8
files=set()
absent=set()
modules={}
for name, module in tuple(sys.modules.items()):
    spec=getattr(module,'__spec__',None)
    origin=getattr(spec,'origin',None)
    if origin in ('built-in','frozen'):
        modules[name]=origin
    elif origin and os.path.isabs(origin):
        modules[name]=origin
        files.add(origin)
        cached=getattr(module,'__cached__',None)
        if cached:
            (files if os.path.exists(cached) else absent).add(cached)
for root in (os.path.dirname(sys.executable),os.path.dirname(os.path.dirname(sys.executable))):
    p=os.path.join(root,'pyvenv.cfg')
    (files if os.path.exists(p) else absent).add(p)
directories=[]
for p in sys.path:
    if os.path.isdir(p):directories.append({'path':p,'realpath':os.path.realpath(p)})
    elif os.path.exists(p):files.add(p)
    else:absent.add(p)
print(json.dumps({'executable':sys.executable,'prefix':sys.prefix,'version':list(sys.version_info[:2]),'defaultPath':os.defpath,
  'files':sorted(files),'absent':sorted(absent),'directories':directories,'modules':modules}))
'''


def pin(file):
    p = Path(file)
    actual = p.resolve(strict=True)
    return {'path': str(p), 'realpath': str(actual),
            'sha256': hashlib.sha256(actual.read_bytes()).hexdigest()}


def profile(interpreter):
    executable = shutil.which(interpreter) if not Path(interpreter).is_absolute() else interpreter
    if not executable:
        raise ValueError('Python interpreter not found')
    executable = str(Path(executable).absolute())
    data = json.loads(subprocess.check_output(
        [executable, '-I', '-S', '-B', '-c', INSPECT], text=True, timeout=15,
        env={'PATH': '/usr/bin:/bin'}))
    if Path(data['executable']).resolve() != Path(executable).resolve():
        raise ValueError('Interpreter wrappers are unsupported. Register the direct interpreter path')
    roots = {p['path'] for p in data['directories']}
    roots.update(str(Path(p).parent) for p in data['files'] if '__pycache__' not in Path(p).parts)
    data['directories'] = [{'path': p, 'realpath': str(Path(p).resolve()),
                            'entries': sorted(x.name for x in Path(p).iterdir())}
                           for p in sorted(roots)]
    return {**data, 'interpreter': pin(executable),
            'files': [pin(p) for p in data['files']]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interpreter', default='python3')
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument('--output', type=Path)
    destination.add_argument('--config-root', type=Path)
    args = parser.parse_args()
    runtime = profile(args.interpreter)
    result = {'enabled': True, 'parser': {**pin(SOURCE/'python-parser/parse.py'),
              'interpreter': runtime['interpreter']}, 'environments': [runtime]}
    if args.output:
        args.output.write_text(json.dumps(result, indent=2)+'\n')
        args.output.chmod(0o600)
    else:
        # Load only this repository's installer, not a module from the shell cwd.
        import importlib.util
        spec = importlib.util.spec_from_file_location('approval_install', SOURCE/'install.py')
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        root = args.config_root.expanduser().resolve()
        policy_file = root/'approval-policy.json'
        if policy_file.is_symlink():
            raise ValueError('Policy symlinks are not supported')
        policy = json.loads(policy_file.read_text())
        plugin = root/'plugins-dev/approval-review'
        if not (plugin/'python-host.mjs').is_file():
            raise ValueError('Install the current plugin before configuring Python')
        result['parser'] = {**pin(plugin/'python-parser/parse.py'), 'interpreter': runtime['interpreter']}
        backup = root/'backups'/('python-parser-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        backup.mkdir(parents=True, mode=0o700)
        shutil.copy2(policy_file, backup/'approval-policy.json')
        (backup/'approval-policy.json').chmod(0o600)
        old = policy.get('staticPython', {})
        result['environments'] = [p for p in old.get('environments', []) if p.get('interpreter', {}).get('path') != runtime['interpreter']['path']] + [runtime]
        # Keep a previously selected parser runtime when registering another venv.
        if old.get('parser'):
            result['parser']['interpreter'] = old['parser']['interpreter']
        policy['staticPython'] = result
        shell = policy.setdefault('staticShell', {})
        shell['executables'] = [p for p in shell.get('executables', []) if p.get('path') != runtime['interpreter']['path']]
        shell['executables'].append({**runtime['interpreter'], 'name': Path(runtime['interpreter']['path']).name})
        installer.private_json(policy_file, policy)
        print(json.dumps({'backup': str(backup), 'environment': runtime['prefix'], 'policy': str(policy_file)}))


if __name__ == '__main__':
    main()

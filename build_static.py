#!/usr/bin/env python3
"""Build the pinned syntax parser and optionally enable static review."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from install import private_json

SOURCE = Path(__file__).resolve().parent

def install_parser(root, binary, startup=None):
    root = root.resolve()
    plugin = root/'plugins-dev/approval-review'
    if not (plugin/'shell-host.mjs').is_file():
        raise ValueError('Install the updated approval plugin before enabling static review')
    policy_file = root/'approval-policy.json'
    policy = json.loads(policy_file.read_text())
    destination = plugin/'bin/shell-parser'
    backup = root/'backups'/('static-parser-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(parents=True, mode=0o700)
    shutil.copy2(policy_file, backup/'approval-policy.json')
    if destination.exists(): shutil.copy2(destination, backup/'shell-parser')
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.shell-parser-', dir=destination.parent)
    os.close(fd)
    try:
        shutil.copyfile(binary, temporary); os.chmod(temporary, 0o700)
        os.replace(temporary, destination)
        shutil.copy2(SOURCE/'shell-parser/LICENSE.mvdan-sh', destination.parent/'LICENSE.mvdan-sh')
        # Warm macOS executable validation before the first bounded review.
        # This parses a constant; it does not run a shell or a user command.
        subprocess.run([str(destination), 'bash'], input='true', text=True,
                       stdout=subprocess.DEVNULL, check=True, timeout=10)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    settings = {**policy.get('staticShell', {}), 'enabled': True, 'probeReadConditions': True,
                'parser': {'path': str(destination), 'sha256': hashlib.sha256(destination.read_bytes()).hexdigest()}}
    if startup is not None: settings['zshStartup'] = startup
    policy['staticShell'] = settings
    private_json(policy_file, policy)
    return {'backup': str(backup), 'parser': str(destination), 'sha256': settings['parser']['sha256']}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config-root', type=Path)
    parser.add_argument('--startup-profile', type=Path, help='Pins for a separately inspected zsh startup chain')
    args = parser.parse_args()
    binary = SOURCE/'bin/shell-parser'; binary.parent.mkdir(exist_ok=True)
    subprocess.run(['go', 'mod', 'verify'], cwd=SOURCE/'shell-parser', check=True)
    subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-o', str(binary), '.'],
                   cwd=SOURCE/'shell-parser', check=True)
    if args.config_root:
        profile = json.loads(args.startup_profile.read_text()) if args.startup_profile else None
        print(json.dumps(install_parser(args.config_root, binary, profile)))
    else: print(str(binary))

if __name__ == '__main__': main()

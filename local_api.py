"""Private local OpenCode API connection; never displays pairing credentials."""
from __future__ import annotations

import base64
import contextlib
import json
import os
from pathlib import Path
import signal
import select
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


class APIError(RuntimeError):
    def __init__(self, status, message):
        self.status = status
        super().__init__(f"OpenCode API HTTP {status}: {message}")


class LocalAPI:
    def __init__(self, url, password=None):
        self.url = url
        self.authorization = None if password is None else 'Basic ' + base64.b64encode(('opencode:' + password).encode()).decode()

    def call(self, method, path, data=None, query=None, timeout=120):
        if query:
            pairs = []
            def append(key, value):
                if isinstance(value, dict):
                    for child, item in value.items():
                        append(f'{key}[{child}]', item)
                elif isinstance(value, list):
                    for item in value:
                        append(key, item)
                else:
                    pairs.append((key, 'null' if value is None else str(value)))
            for key, value in query.items():
                append(key, value)
            path += '?' + urllib.parse.urlencode(pairs)
        body = None if data is None else json.dumps(data, ensure_ascii=False).encode()
        headers = {'Content-Type': 'application/json'}
        if self.authorization:
            headers['Authorization'] = self.authorization
        request = urllib.request.Request(self.url + path, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            # A validation response can echo imported content. Do not print it.
            detail = error.read()
            try:
                value = json.loads(detail)
                tag = value.get('_tag') or value.get('type') or 'request failed'
            except ValueError:
                tag = 'request failed'
            raise APIError(error.code, tag) from None
        if not raw:
            return None
        value = json.loads(raw)
        return value.get('data', value) if isinstance(value, dict) else value


@contextlib.contextmanager
def server(config_dir: Path, directory: Path, isolated_state: Path | None = None):
    """Start a loopback-only server and terminate only this process group."""
    password = secrets.token_urlsafe(32)
    env = dict(os.environ, HOME=str(config_dir.resolve().parent/'home'), SHELL='/bin/bash', PWD=str(directory.resolve()), OPENCODE_PASSWORD=password,
               OPENCODE_CONFIG_DIR=str(config_dir.resolve()),
               XDG_CONFIG_HOME=str(config_dir.resolve().parent))
    if isolated_state:
        env['XDG_DATA_HOME'] = str(isolated_state / 'data')
        env['XDG_STATE_HOME'] = str(isolated_state / 'state')
        env['XDG_CACHE_HOME'] = str(isolated_state / 'cache')
    Path(env['HOME']).mkdir(exist_ok=True)
    # Match the CLI's standalone bootstrap: private password passed only through
    # the child environment, loopback endpoint, lifetime tied to owning stdin.
    process = subprocess.Popen([os.environ.get('OPENCODE_TEST_BINARY', str(Path(__file__).resolve().parent/'node_modules/@opencode/cli/bin/opencode.exe')), 'serve', '--stdio'],
                               cwd=directory, env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True, text=True)
    try:
        readable, _, _ = select.select([process.stdout], [], [], 35)
        if not readable:
            raise RuntimeError('OpenCode stdio bootstrap did not return an endpoint')
        bootstrap = json.loads(process.stdout.readline())
        endpoint = urllib.parse.urlsplit(bootstrap['url'])
        if endpoint.scheme != 'http' or endpoint.hostname != '127.0.0.1' or endpoint.username:
            raise RuntimeError('Expected a private loopback OpenCode endpoint')
        api = LocalAPI(bootstrap['url'], password)
        api.pid = process.pid
        deadline = time.monotonic() + 45
        while True:
            try:
                api.call('GET', '/api/health', timeout=1)
                break
            except (OSError, APIError):
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('Private OpenCode server did not become ready') from None
                time.sleep(0.2)
        yield api
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()

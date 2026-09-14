"""Verify installation into a fresh profile without an existing OpenCode runtime."""
from pathlib import Path
import json
import tempfile

from install import install
from local_api import server
from test_install import FullInstallTest


def main():
    with tempfile.TemporaryDirectory(prefix='approval-fresh-profile-') as temp:
        root = Path(temp).resolve()
        config, repo = root/'config', root/'repo'
        config.mkdir()
        repo.mkdir()
        FullInstallTest().profile(config)
        data = json.loads((config/'opencode.json').read_text())
        data['plugins'] = []
        (config/'opencode.json').write_text(json.dumps(data))
        install(config, provider_id='custom', model_id='model', variant='medium', bin_dir=root/'bin')
        with server(config, repo, root/'state') as api:
            query = {'location': {'directory': str(repo)}}
            api.call('GET', '/api/location', query=query)
            api.call('POST', '/api/plugin/await-activation', query=query)
            plugins = api.call('GET', '/api/plugin', query=query)
            plugin = next(p for p in plugins if p['id'] == 'local.approval-review')
            assert plugin['state']['status'] == 'active', plugin['state']
        print(json.dumps({'freshProfileActivated': True, 'liveProfileRead': False}))


if __name__ == '__main__':
    main()

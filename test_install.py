"""Check that the audit viewer installation preserves the user profile."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from install import install_audit_viewer
from build_static import install_parser


class ViewerInstallTest(unittest.TestCase):
    def test_static_parser_preserves_policy_and_profile(self):
        source = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(prefix='static-install-') as temp:
            root = Path(temp); plugin = root/'plugins-dev/approval-review'; plugin.mkdir(parents=True)
            (plugin/'shell-host.mjs').write_text('// fixture\n')
            original = {'mode':'shadow','model':{'id':'keep'},'protectedRoots':['/keep'],
                        'staticShell':{'zshStartup':{'fixture':'preserve'}}}
            (root/'approval-policy.json').write_text(json.dumps(original))
            result = install_parser(root, source/'bin/shell-parser')
            policy = json.loads((root/'approval-policy.json').read_text())
            self.assertEqual({k:v for k,v in policy.items() if k != 'staticShell'},
                             {k:v for k,v in original.items() if k != 'staticShell'})
            self.assertEqual(policy['staticShell']['zshStartup'], original['staticShell']['zshStartup'])
            self.assertTrue(policy['staticShell']['enabled'])
            self.assertEqual(json.loads((Path(result['backup'])/'approval-policy.json').read_text()), original)

    def test_preserves_config_and_repeat_install(self):
        with tempfile.TemporaryDirectory(prefix='approval-install-') as temp:
            root = Path(temp)/'config'
            root.mkdir()
            cli = {'theme': {'name': 'ayu'}, 'plugins': ['existing-plugin'], 'session': {'sidebar': 'auto'}}
            (root/'cli.json').write_text(json.dumps(cli))
            (root/'opencode.json').write_text('{"model":{"id":"unchanged"}}')
            (root/'approval-policy.json').write_text(json.dumps({'auditRoot': str(Path(temp)/'audit')}))
            before = {name: (root/name).read_bytes() for name in ['opencode.json', 'approval-policy.json']}
            for _ in range(2):
                result = install_audit_viewer(root, Path(temp)/'bin')
                after = json.loads((root/'cli.json').read_text())
                self.assertEqual(after['plugins'], ['existing-plugin', result['viewer']])
                self.assertEqual({k: v for k, v in after.items() if k not in ['plugins', 'attention']},
                                 {k: v for k, v in cli.items() if k != 'plugins'})
                self.assertEqual(after['attention'], {'enabled': True, 'notifications': True, 'sound': True})
                self.assertTrue((Path(result['viewer'])/'approval-notifications.mjs').exists())
                self.assertTrue(all((root/name).read_bytes() == data for name, data in before.items()))
                output = subprocess.check_output([result['command'], '--details', '--color', 'always', '--limit', '10'], text=True)
                self.assertIn('No matching audit records', output)
                self.assertTrue((Path(result['backup'])/'cli.json').exists())
            after['attention'] = {'enabled': False, 'notifications': False, 'sound': False}
            (root/'cli.json').write_text(json.dumps(after))
            install_audit_viewer(root, Path(temp)/'bin')
            self.assertEqual(json.loads((root/'cli.json').read_text())['attention'], after['attention'])


class FullInstallTest(unittest.TestCase):
    def profile(self, root):
        config = {
            'providers': {'custom': {
                'npm': '@opencode/ai/providers/openai-compatible.js',
                'settings': {'baseURL': 'https://model.example.invalid/v1', 'apiKey': '{env:TEST_KEY}'},
                'models': {'model': {'variants': [{'id': 'medium', 'body': {'reasoning_effort': 'medium'}}]}}
            }},
            'permissions': [{'action': 'edit', 'resource': '/protected/*', 'effect': 'deny'}],
            'plugins': ['other-plugin'],
        }
        (root/'opencode.json').write_text(json.dumps(config))
        return config

    def test_explicit_model_and_preserved_policy_on_upgrade(self):
        from install import install
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            original = self.profile(root)
            first = install(root, provider_id='custom', model_id='model', variant='medium', bin_dir=root/'bin')
            policy_path = Path(first['policy'])
            policy = json.loads(policy_path.read_text())
            self.assertEqual(policy['mode'], 'shadow')
            self.assertEqual(policy['model'], {'providerID': 'custom', 'id': 'model', 'variant': 'medium'})
            policy['mode'] = 'enforce'
            policy['grantRules'] = [{'operation': 'files.read', 'target': '/fixture', 'targetType': 'directory', 'mode': 'ask'}]
            policy_path.write_text(json.dumps(policy))
            (root/'robust-options.json').write_text('{"do":"not modify"}')
            install(root, bin_dir=root/'bin')
            self.assertEqual(json.loads(policy_path.read_text()), policy)
            self.assertEqual((root/'robust-options.json').read_text(), '{"do":"not modify"}')
            config = json.loads((root/'opencode.json').read_text())
            self.assertEqual(config['providers'], original['providers'])
            self.assertIn(original['permissions'][0], config['permissions'])
            self.assertEqual(len(config['plugins']), 2)
            self.assertEqual(policy_path.stat().st_mode & 0o777, 0o600)
            self.assertTrue((Path(first['plugin'])/'node_modules/@opencode/plugin').is_dir())
            self.assertTrue((root/'approval-state').is_relative_to(root))

    def test_missing_route_and_jsonc_fail_before_mutation(self):
        from install import install
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            self.profile(root)
            before = (root/'opencode.json').read_bytes()
            with self.assertRaises(ValueError):
                install(root, bin_dir=root/'bin')
            self.assertFalse((root/'approval-policy.json').exists())
            (root/'cli.jsonc').write_text('{}')
            with self.assertRaises(ValueError):
                install(root, provider_id='custom', model_id='model', variant='medium', bin_dir=root/'bin')
            self.assertFalse((root/'plugins-dev').exists())
            self.assertEqual((root/'opencode.json').read_bytes(), before)

if __name__ == '__main__':
    unittest.main()

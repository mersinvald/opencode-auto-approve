"""Run fixture-only reads and edits through OpenCode's actual native shell tool."""
from pathlib import Path
import base64, copy, hashlib, json, shutil, sqlite3, subprocess, sys, tempfile, time
source = Path(__file__).resolve().parent
from local_api import server

def main():
    base = Path(tempfile.mkdtemp(prefix='opencode-static-native-')).resolve()
    config = base/'config'; config.mkdir()
    repo = base/'repo'; repo.mkdir()
    external = base/'external'; external.mkdir(); (external/'file').write_text('External fixture read.\n')
    (repo/'file').write_text('hello\nworld\n')
    (repo/'sed-edit').write_text('before\n')
    (repo/'files.txt').write_text('file\n')
    (repo/'tests').mkdir()
    for name in ['test_phase1_one.py','test_phase1_two.py']:(repo/'tests'/name).write_text('# Fixture selection only.\n')
    # Synthetic runner: test the native permission path and shell glob expansion,
    # without requiring pytest packages or executing any project test code.
    (repo/'pytest.py').write_text("import sys\nassert sys.argv[1:]==['-q','-p','no:cacheprovider','tests/test_phase1_one.py','tests/test_phase1_two.py']\nprint('fixture test selection verified')\n")
    with sqlite3.connect(repo/'fixture.db') as db:
        db.execute('CREATE TABLE messages (id TEXT, data TEXT)')
        db.execute('INSERT INTO messages VALUES (?, ?)',('msg_one','{"fixture":true}'))
    database_hash=hashlib.sha256((repo/'fixture.db').read_bytes()).hexdigest()
    subprocess.run(['/usr/bin/git', 'init', '-q', str(repo)], check=True)
    subprocess.run(['/usr/bin/git','-C',str(repo),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','--allow-empty','-qm','Fixture'],check=True)
    shutil.copytree(source, config/'review', ignore=shutil.ignore_patterns('__pycache__', 'node_modules', '.git', 'test-results'))
    (config/'node_modules').symlink_to(source/'node_modules', target_is_directory=True)
    parser = config/'review/bin/shell-parser'
    subprocess.run([str(parser), 'bash'], input='true', text=True, stdout=subprocess.DEVNULL, check=True, timeout=5)
    policy = {'version': 1, 'mode': 'enforce', 'model': {'providerID': 'fixture', 'id': 'classifier', 'variant': 'medium'},
      'skillRoots': [], 'protectedRoots': [str(config)], 'scratchRoot': str(base/'scratch'), 'auditRoot': str(base/'audit'),
      'timeoutMs': 20000, 'maxRequestChars': 32000,
      'grantRules': [{'operation':'files.read','target':str(external/'file'),'targetType':'file','mode':'allow'},
                     {'operation':'tests.run','target':str(repo/'tests'),'targetType':'directory','mode':'allow'}],
      'staticShell': {'enabled': True, 'probeReadConditions': True, 'parser': {'path': str(parser), 'sha256': hashlib.sha256(parser.read_bytes()).hexdigest()}}}
    policy['grantRules'] += [{'operation':'files.write','target':str(repo/name),'targetType':'file','mode':'allow'} for name in ['sed-edit','sed-edit.bak','generated-list']]
    # Linux Python aliases resolve to a versioned binary. Pin this inspected fixture interpreter.
    python = Path('/usr/bin/python3').resolve()
    policy['staticShell']['executables'] = [{'name': 'python3', 'path': '/usr/bin/python3',
        'realpath': str(python), 'sha256': hashlib.sha256(python.read_bytes()).hexdigest()}]
    # Some Linux distributions provide which as a script. Pin the fixture lookup tool.
    which = Path(shutil.which('which')).resolve()
    policy['staticShell']['executables'].append({'name': 'which', 'path': shutil.which('which'),
        'realpath': str(which), 'sha256': hashlib.sha256(which.read_bytes()).hexdigest()})
    if len(sys.argv) >= 2:
        supplied = json.loads(Path(sys.argv[1]).read_text())
        if 'staticShell' in supplied:
            policy['staticShell'] = {**supplied['staticShell'], **policy['staticShell'],
                'executables': supplied['staticShell'].get('executables', []) + policy['staticShell']['executables']}
        else:
            policy['staticShell']['zshStartup'] = supplied
    # The native test server uses a private HOME without user startup files.
    startup = policy['staticShell'].get('zshStartup')
    if startup:
        startup['environment']['HOME'] = str(base/'home')
        startup['absent'] += [str(base/'home'/name) for name in ['.zshenv', '.zshenv.zwc']]
    from build_python import profile as python_profile, pin as python_pin
    python = python_profile(sys.executable)
    python_exe = python['interpreter']['path']
    policy['staticPython'] = {'enabled': True, 'parser': {**python_pin(config/'review/python-parser/parse.py'),
                            'interpreter': python['interpreter']}, 'environments': [python]}
    policy['staticShell']['executables'].append({**python['interpreter'], 'name': Path(python_exe).name})
    lint = repo/'lint-fixture.py'
    lint.write_text("from pathlib import Path\nimport sys\nfor name in sys.argv[1:]: print(len(Path(name).read_text()))\n")
    policy['staticShell'].setdefault('helpers', []).append({'path':str(lint),'realpath':str(lint),'sha256':hashlib.sha256(lint.read_bytes()).hexdigest()})
    lint_inputs=[]
    for i in range(4):
        item=repo/f'lint-input-{i}.py';item.write_text('# data only\n'*4000);lint_inputs.append(str(item))
    large_helper=repo/'large-helper.py';large_helper.write_text('# oversized helper\n'*2000)
    worktree=base/'lint-worktree';worktree.mkdir()
    worktree_inputs=[]
    for item in lint_inputs:
        target=worktree/Path(item).name;shutil.copyfile(item,target);worktree_inputs.append(str(target))
    policy['grantRules'].extend([
        {'operation':op,'target':str(worktree),'targetType':'directory','mode':'allow'}
        for op in ['files.access','files.read']])
    policy.setdefault('grantRules', []).extend([
        {'operation': 'python.import', 'target': name, 'targetType': 'exact', 'mode': 'allow'}
        for name in ['pathlib', 'subprocess', 'hashlib']])
    (config/'policy.json').write_text(json.dumps(policy)); (config/'policy.json').chmod(0o600)
    wrapper = config/'fixture'; wrapper.mkdir()
    (wrapper/'package.json').write_text(json.dumps({'name': 'static-fixture', 'type': 'module', 'exports': './index.mjs'}))
    (wrapper/'index.mjs').write_text("""import { createApprovalPlugin } from '../review/index.mjs';
import { appendFileSync } from 'node:fs';
export default {id:'local.approval-review', async setup(ctx) {
 const log = x => appendFileSync(""" + json.dumps(str(base/'events.jsonl')) + """, JSON.stringify(x)+'\\n');
 let nativeShell;
 const registration = await ctx.tool.transform(editor => { nativeShell = editor.get('shell'); });
 const cleanup = await createApprovalPlugin({generate: async input => {
   const proof=JSON.parse(input.prompt.slice(input.prompt.lastIndexOf('\\n')+1));
   log({kind:'model',probe:input.prompt.includes('"observations":[{'),analysis:proof.request.staticAnalysis});
   if(proof.request.action==='external_directory'&&proof.request.tool.input.command.includes('/external')){
     await new Promise(r=>setTimeout(r,11000));
     return {text:JSON.stringify({decision:'allow_always',remember:[proof.candidates[0].id],reason:'Delayed directory approval for repeated fixture reads.'})};
   }
   return {text:JSON.stringify({decision:'escalate_once',remember:[],reason:'Fixture fallback.'})};
 }}).setup({...ctx, options:{policyFile:""" + json.dumps(str(config/'policy.json')) + """}});
 const runtimeHook = await ctx.shell.hook('create.before', e => { log({kind:'runtime',shell:e.shell,cwd:e.cwd}); });
 const trigger = await ctx.permission.hook('evaluate', e => {
   if (e.action !== 'execute' || !e.metadata?.fixtureRun) return;
   const name=e.metadata.fixtureRun;
   log({kind:'start',name,available:!!nativeShell});
   if (!nativeShell) return;
   void nativeShell.execute({command:e.metadata.command,workdir:e.metadata.workdir ?? """ + json.dumps(str(repo)) + """,timeout:1000},
     {sessionID:e.sessionID,agent:'build',messageID:'msg_tool_'+name,id:'call_'+name,progress:async()=>{}})
     .then(result=>log({kind:'finished',name}), error=>log({kind:'failed',name,error:String(error)}));
 });
 await ctx.tool.reload();
 return async()=>{await trigger.dispose();await runtimeHook.dispose();await registration.dispose();await cleanup();};
}};
""")
    (config/'opencode.json').write_text(json.dumps({'model': policy['model'], 'shell': sys.argv[2] if len(sys.argv) >= 3 else '/bin/zsh' if len(sys.argv) >= 2 else '/bin/bash',
      'permissions': [{'action':'shell','resource':'*','effect':'ask'}], 'plugins':[str(wrapper)]}))
    checks = []
    with server(config, repo, base/'state') as api:
        discovery = base/'state/state/opencode/service.json'; discovery.parent.mkdir(parents=True, exist_ok=True)
        discovery.write_text(json.dumps({'url':api.url,'pid':api.pid,'password':base64.b64decode(api.authorization.split(' ',1)[1]).decode().split(':',1)[1]})); discovery.chmod(0o600)
        q = {'location': {'directory':str(repo)}}
        api.call('GET','/api/location',query=q); api.call('POST','/api/plugin/await-activation',query=q)
        seed = api.call('POST','/api/session',{'location':q['location'],'title':'Static fixture'})
        template = api.call('GET',f"/api/session/{seed['id']}/export")
        def events(): return [json.loads(x) for x in (base/'events.jsonl').read_text().splitlines()] if (base/'events.jsonl').exists() else []
        def records(): return [json.loads(x) for f in (base/'audit').glob('*.jsonl') for x in f.read_text().splitlines()]
        def wait(check):
            end = time.monotonic()+25
            while time.monotonic()<end:
                if result:=check(): return result
                time.sleep(.05)
            raise AssertionError('Timeout: '+str(base))
        cases = [('reads',f"cd '{repo}' && grep -n hello file; grep -n world file"),
                 ('exit_flow', "false || exit 0; unmodeled_unreachable_fixture"),
                 ('manifest_loop', 'while read -r f; do cat "$f"; done < files.txt'),
                 ('generated_manifest', "printf '%s\\n' file > generated-list; while read -r f; do cat \"$f\"; done < generated-list"),
                 ('python_invariant_loop', f"'{python_exe}' -I -S -B - <<'PY'\nfrom pathlib import Path\nfor line in Path('file').read_text().splitlines():\n    print(Path('file').read_text())\nPY"),
                 ('invariant_loop', 'while read -r f; do cat file; done < files.txt'),
                 ('python_verification', f"'{python_exe}' -I -S -B - <<'PY'\nfrom pathlib import Path\nimport hashlib\nprint(' '.join([hashlib.sha256(p.read_bytes()).hexdigest()[:8] for p in sorted(Path('tests').glob('*.py'))]))\nPY"),
                 ('empty_echo', "echo; echo 'manifest'; echo; cat file"),
                 ('probe','if grep -q hello file; then cat file; else head -n 1 file; fi'),
                 ('env_regex','set -euo pipefail; LC_ALL=C grep -n "hello\\|world" file'),
                 ('glob_read','cat fi*'),
                 ('chained_assignment',f'cd "{repo}" && D="{repo}" && LC_ALL=C grep -n "hello\\|world" "$D/file"'),
                 ('grep_context','cat file | grep -A1 hello; cat file | grep -B 1 world; grep -C0 hello file'),
                 ('null_sink',"git status --short; find tests -type f 2>/dev/null | wc -l; cat </dev/null >/dev/null"),
                 ('git_inspection',"git -C . --no-pager status --short tests; git branch -avv; git show --stat HEAD; git ls-tree --name-only HEAD tests"),
                 ('inspection_filters',"grep -n hello file | sed 's/^/  /' | sort -u -t: -k1,1 | uniq -c; find . -path ./.git -prune -o -type f -print | head -20; test ! -d venv; echo ---; cmp file file"),
                 ('sed_reads',"sed -nE -e '1, 2 p' -e '/hello/p' file; sed 's|hello|hi|g; /world/d' file"),
                 ('sed_edits',"sed -i.bak 's/before/after/' sed-edit"),
                 ('status_path','git --no-pager status --short --untracked-files=all -- file'),
                 ('diff_path','git --no-pager diff --stat tests/test_phase1_one.py; git diff --stat -- tests/test_phase1_one.py'),
                 ('which_lookup',f"cd '{repo}' && ls .venv/bin/python 2>/dev/null; which pytest; ls tests 2>/dev/null | head; cat file | grep -A5 hello"),
                 ('pinned_lint_inputs',f"'{python_exe}' -I -S -B '{lint}' {' '.join(lint_inputs)} 2>&1 | tail -20"),
                 ('bare_lint_worktree',f"python3 -I -S -B '{lint}' {' '.join(Path(p).name for p in worktree_inputs)}"),
                 ('preparation_missing',f"'{python_exe}' -I -S -B '{repo}/missing-helper.py'"),
                 ('preparation_large',f"'{python_exe}' -I -S -B '{large_helper}'"),
                 ('preparation_directory',f"python3 -I -S -B '{large_helper}'"),
                 ('array_read','READ=(cat file); "${READ[@]}" | grep -A1 hello'),
                 ('pytest_glob','PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m pytest -q -p no:cacheprovider tests/test_phase1_*.py'),
                 ('sqlite_schema','sqlite3 -safe -readonly -init /dev/null fixture.db ".schema messages"'),
                 ('sqlite_tables','sqlite3 -safe -readonly -init /dev/null fixture.db ".tables"'),
                 ('sqlite_select',"sqlite3 -safe -readonly -init /dev/null fixture.db \"SELECT data FROM messages WHERE id='msg_one';\""),
                 ('delayed_directory',f'cd "{external}" && cat file'),
                 ('python_functions', f"'{python_exe}' -I -S -B - <<'PY'\nfrom pathlib import Path\ndef read(name):\n    return Path(name).read_text()\nfor name in ['file']:\n    print(read(name))\nPY"),
                 ('python_process', f"'{python_exe}' -I -S -B - <<'PY'\nimport subprocess\nsubprocess.run(['/bin/cat','file'],check=True)\nsubprocess.run('cat file | wc -l',shell=True,check=True)\nPY"),
                 ('pytest_missing', 'cd tests\n/usr/bin/python3 -m pytest test_phase1_one.py\nprintf done'),
                 ('fallback',"if grep -q hello file; then cat file; else unmodeled_fixture; fi")]
        if len(sys.argv) >= 2 and policy['staticShell'].get('helpers'):
            lint = policy['staticShell']['helpers'][0]['path']
            cases[2:2] = [('expanded_reads', 'head -20 file; shasum -a 256 file; git --no-pager status --short'),
                          ('pinned_lint', f"python3 -I -S -B '{lint}' file")]
            if any(p['name']=='jq' for p in policy['staticShell']['executables']):
                cases.insert(-2,('sqlite_json',"sqlite3 -safe -readonly -init /dev/null fixture.db \"SELECT data FROM messages WHERE id='msg_one';\" | jq ."))
        for name, command in cases:
            workdir=worktree if name in ('bare_lint_worktree','preparation_directory') else repo
            model_count=len([e for e in events() if e['kind']=='model'])
            data=copy.deepcopy(template); sid='ses_static_'+name; stamp=int(time.time()*1000)
            data['info'].update(id=sid,title=name)
            data['messages']=[{'id':'msg_user_'+name,'type':'user','text':'Read the fixture files for this task.','time':{'created':stamp}},
              {'id':'msg_tool_'+name,'type':'assistant','agent':'build','model':policy['model'],'time':{'created':stamp,'completed':stamp},'finish':'stop',
               'content':[{'type':'tool','id':'call_'+name,'name':'shell','state':{'status':'completed','input':{'command':command,'workdir':str(workdir)},'content':[{'type':'text','text':'Fixture source context'}]},'time':{'created':stamp,'completed':stamp}}]}]
            api.call('POST','/api/session/import',data)
            api.call('POST',f'/api/session/{sid}/permission',{'action':'execute','resources':['fixture'],'metadata':{'fixtureRun':name,'command':command,'workdir':str(workdir)}})
            if name.startswith('preparation_'):
                wait(lambda:any(r['sessionID']==sid and r['code']=='preparation_failed' for r in records()))
                row=next(r for r in records() if r['sessionID']==sid and r['code']=='preparation_failed')
                assert row['preview']!='[command unavailable]',row
                assert row['details']['status']=='stored',row
                detail=json.loads((base/'audit'/row['details']['path']).read_text())['data']
                assert detail['request']['tool']['input']['command']==command,detail['request']
                expected='helper_source_unavailable' if name=='preparation_missing' else 'helper_source_too_large'
                assert detail['diagnostics']['failure']['code']==expected,detail['diagnostics']
                assert any(h['status']=='failed' and h['path'] in command and h['code']==expected for h in detail['helpers']),detail['helpers']
                if name=='preparation_directory':
                    assert row['action']=='shell',row
                    directory=next(r for r in records() if r['sessionID']==sid and r['action']=='external_directory')
                    assert directory['code']=='grant_rule' and directory['proposed']=='allow',directory
                assert len([e for e in events() if e['kind']=='model'])==model_count
                pending=api.call('GET',f'/api/session/{sid}/permission');assert len(pending)==1
                api.call('POST',f'/api/session/{sid}/permission/{pending[0]["id"]}/reply',{'reply':'reject'})
                checks.append({'case':name,'code':row['code'],'commandAndFailureStored':True})
            elif name not in ('fallback','pytest_missing'):
                wait(lambda:any(e['kind']=='finished' and e['name']==name for e in events()))
                row=next(r for r in records() if r['sessionID']==sid and r['code']=='grant_rule' and r['action']=='shell')
                assert row['details']['status']=='stored',row.get('details')
                detail=json.loads((base/'audit'/row['details']['path']).read_text())
                assert detail['data']['request']['tool']['input']['command']==command
                assert detail['data']['diagnostics']['static']['analysis']['syntax']['Type']=='File'
                assert detail['data']['diagnostics']['static']['analysis']['grants']
                assert not api.call('GET',f'/api/session/{sid}/permission')
                assert len([e for e in events() if e['kind']=='model'])==model_count+(1 if name=='delayed_directory' else 0)
                if name=='delayed_directory':
                    directory=next(r for r in records() if r['sessionID']==sid and r['code']=='model_allow_always' and r['action']=='external_directory')
                    assert directory['elapsedMs']>=11000,directory
                if name=='sed_edits':
                    assert (repo/'sed-edit').read_text()=='after\n'
                    assert (repo/'sed-edit.bak').read_text()=='before\n'
                    grants=detail['data']['diagnostics']['static']['analysis']['grants']
                    for filename in ['sed-edit','sed-edit.bak']:
                        assert any(g['operation']=='files.write' and g['target']==str(repo/filename) for g in grants),grants
                if name=='probe': assert detail['data']['diagnostics']['static']['analysis']['complete']
                if name=='which_lookup':
                    grants=detail['data']['diagnostics']['static']['analysis']['grants']
                    assert any(g['operation']=='shell.lookup' and g['target']=='pytest' for g in grants),grants
                    assert not any(g['operation']=='tests.run' for g in grants),grants
                if name in ('pinned_lint_inputs','bare_lint_worktree'):
                    grants=detail['data']['diagnostics']['static']['analysis']['grants']
                    assert any(g['operation']=='tools.lint' for g in grants),grants
                    expected_inputs=worktree_inputs if name=='bare_lint_worktree' else lint_inputs
                    assert all(any(g['operation']=='files.read' and g['target']==p for g in grants) for p in expected_inputs),grants
                    assert [h['path'] for h in detail['data']['helpers']]==[str(repo/'lint-fixture.py')],detail['data']['helpers']
                    if name=='bare_lint_worktree':
                        directory=next(r for r in records() if r['sessionID']==sid and r['action']=='external_directory')
                        assert directory['code']=='grant_rule' and directory['proposed']=='allow',directory
                        directory_detail=json.loads((base/'audit'/directory['details']['path']).read_text())['data']
                        assert not directory_detail.get('helpers'),directory_detail.get('helpers')
                checks.append({'case':name,'code':row['code'],'elapsedMs':row['elapsedMs']})
            else:
                wait(lambda:any(r['sessionID']==sid and r['code']=='model_escalation' for r in records()))
                row=next(r for r in reversed(records()) if r['sessionID']==sid and r['code']=='model_escalation')
                detail=json.loads((base/'audit'/row['details']['path']).read_text())
                analysis=detail['data']['diagnostics']['static']['analysis']
                assert analysis['reason']==('pytest_target_missing' if name=='pytest_missing' else 'unverified_executable')
                if name=='pytest_missing':
                    assert not analysis['complete']
                    assert any(g['operation']=='tests.run' and g['target']==str(repo/'tests/test_phase1_one.py') for g in analysis['grants'])
                    assert {c['cwd'] for c in analysis['commands'] if c['argv'][0]=='printf'}=={str(repo),str(repo/'tests')}
                    assert analysis['unresolved'][0]['cdBranch']['outcome']=='failure'
                assert detail['data']['lifecycle']['status']=='ask'
                pending=api.call('GET',f'/api/session/{sid}/permission'); assert len(pending)==1
                assert any(e['kind']=='model' for e in events())
                api.call('POST',f'/api/session/{sid}/permission/{pending[0]["id"]}/reply',{'reply':'reject'})
                checks.append({'case':name,'dialog':True,'unverifiedExecutableReviewed':True})
    result={'base':str(base),'checks':checks,'commandsExecuted':'fixture reads and sed edits, pinned linter, and synthetic pytest runner; fallback rejected'}
    assert hashlib.sha256((repo/'fixture.db').read_bytes()).hexdigest()==database_hash
    (base/'report.json').write_text(json.dumps(result,indent=2)); print(json.dumps(result))

if __name__ == '__main__': main()

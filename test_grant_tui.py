"""Open the grant tree in an isolated native TUI and change one fixture rule."""
from pathlib import Path
import base64, fcntl, json, os, pty, re, select, shutil, signal, struct, subprocess, sys, tempfile, termios, time
source=Path(__file__).resolve().parent
from local_api import server
from install import install_audit_viewer

def main():
    base=Path(tempfile.mkdtemp(prefix='opencode-grant-tui-')).resolve()
    config=base/'opencode';repo=base/'repo'
    config.mkdir();repo.mkdir();subprocess.run(['/usr/bin/git','init','-q',str(repo)],check=True)
    (config/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
    (config/'opencode.json').write_text(json.dumps({}))
    (config/'approval-policy.json').write_text(json.dumps({'version':1,'mode':'enforce','skillRoots':[],'protectedRoots':[],
      'scratchRoot':str(base/'scratch'),'auditRoot':str(base/'audit'),'model':{'providerID':'fixture','id':'fixture','variant':'medium'}}))
    install_audit_viewer(config,base/'bin')
    with server(config,repo,base/'state') as api:
        password=base64.b64decode(api.authorization.split(' ',1)[1]).decode().split(':',1)[1]
        discovery=base/'state/state/opencode/service.json';discovery.parent.mkdir(parents=True,exist_ok=True)
        discovery.write_text(json.dumps({'url':api.url,'pid':api.pid,'password':password}));discovery.chmod(0o600)
        info=api.call('POST','/api/session',{'location':{'directory':str(repo)},'title':'Grant tree fixture'})
        seed=api.call('GET',f"/api/session/{info['id']}/export")
        info['id']='ses_grant_tui_fixture';seed['info']['id']=info['id']
        seed['messages']=[{'id':'msg_grant_fixture','type':'user','text':'Fixture for grant UI. Do not run a model.', 'time':{'created':int(time.time()*1000)}}]
        api.call('POST','/api/session/import',seed)
        seed_scope = 'import {createRuleStore} from ' + json.dumps(str(source/'grant-store.mjs')) + ';import {grant} from ' + json.dumps(str(source/'grant-rules.mjs')) + ';await createRuleStore(' + json.dumps(str(config/'approval-policy.json')) + ').observe(' + json.dumps(info['projectID']) + ',[grant("files.write","src","directory",{space:{repository:"a".repeat(64),modifier:"scratch"},repositoryName:"fixture-infra"})],{});'
        subprocess.run(['node','--input-type=module','-e',seed_scope],check=True)
        env=dict(os.environ,TERM='xterm-256color',OPENCODE_PASSWORD=password,OPENCODE_CONFIG_DIR=str(config),
          XDG_CONFIG_HOME=str(base),XDG_DATA_HOME=str(base/'state/data'),XDG_STATE_HOME=str(base/'state/state'),XDG_CACHE_HOME=str(base/'state/cache'))
        master,slave=pty.openpty();fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',50,140,0,0))
        proc=subprocess.Popen([str(source/'node_modules/@opencode/cli/bin/opencode.exe'),'--server',api.url,'-s',info['id'],str(repo)],
          stdin=slave,stdout=slave,stderr=slave,cwd=repo,env=env,start_new_session=True)
        os.close(slave);output=bytearray()
        def pump(seconds):
            end=time.monotonic()+seconds
            while time.monotonic()<end:
                ready,_,_=select.select([master],[],[],.1)
                if ready:
                    try:chunk=os.read(master,65536)
                    except OSError:break
                    if not chunk:break
                    output.extend(chunk)
                    if b'\x1b[6n' in chunk:os.write(master,b'\x1b[1;1R')
                    if b'\x1b[c' in chunk:os.write(master,b'\x1b[?1;2c')
                    if b'\x1b]10;?' in chunk:os.write(master,b'\x1b]10;rgb:eeee/eeee/eeee\x1b\\')
                    if b'\x1b]11;?' in chunk:os.write(master,b'\x1b]11;rgb:1111/1111/1111\x1b\\')
        try:
            pump(20);os.write(master,b'\x07');pump(5)
            os.write(master,b'\x1b[C');pump(1)
            os.write(master,b's');pump(2)
            states=list((config/'approval-rules').glob('*.json'))
            if not states:
                (base/'tui.txt').write_text(output.decode('utf8','replace'))
            assert states,'The grant tree did not create its store: '+str(base)
            state=json.loads(states[0].read_text())
            assert any(r['mode']=='ask' and r['authority']=='user' for r in state['rules']), 'The S key did not save a rule: '+str(base)
            os.write(master,b'/');pump(2);os.write(master,b'files.read');pump(1);os.write(master,b'\r');pump(3)
            os.write(master,b'd');pump(2)
            state=json.loads(states[0].read_text())
            text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',output.decode('utf8','replace'))
            (base/'tui.txt').write_text(text)
            assert any(r['operation']=='files.read' and r['mode']=='dynamic' and r['authority']=='user' for r in state['rules']), 'Filtered Dynamic edit did not persist: '+str(base)
            assert 'Project grants' in text and 'Always ask' in text, 'The tree did not render: '+str(base)
            os.write(master,b'/');pump(2);os.write(master,b'scratch');pump(1);os.write(master,b'\r');pump(3)
            os.write(master,b'a');pump(2)
            state=json.loads(states[0].read_text())
            assert any(r.get('space',{}).get('modifier')=='scratch' and r['mode']=='allow' for r in state['rules']), 'Scratch tree scope did not persist: '+str(base)
            assert b'fixture-infra' in output, 'Repository name did not render: '+str(base)
            report={'base':str(base),'checks':['native_tui_loaded','tree_rendered','expand_key','single_key_rule_edit','filter_and_dynamic_edit','scratch_filter_and_rule_edit'], 'userSessionsChanged':False}
            (base/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report),flush=True)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid,signal.SIGTERM)
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
            os.close(master)

if __name__=='__main__':main()

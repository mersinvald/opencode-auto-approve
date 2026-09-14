"""Exercise the grant gate through native OpenCode permission dialogs."""
from pathlib import Path
import base64, copy, hashlib, json, shutil, subprocess, sys, tempfile, time
source = Path(__file__).resolve().parent
from local_api import server

def main():
    base=Path(tempfile.mkdtemp(prefix='opencode-grants-native-')).resolve()
    config=base/'config'; repo=base/'repo'; other=base/'worktree'
    for p in [config,repo,other]: p.mkdir()
    subprocess.run(['/usr/bin/git','init','-q',str(repo)],check=True)
    (other/'file').write_text('Fixture only.\n')
    shutil.copytree(source,config/'review',ignore=shutil.ignore_patterns('__pycache__', 'node_modules', '.git', 'test-results'))
    (config/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
    model={'providerID':'fixture','id':'fixture','variant':'medium'}
    policy={'version':1,'mode':'enforce','model':model,'skillRoots':[],'protectedRoots':[str(config)],
      'scratchRoot':str(base/'scratch'),'auditRoot':str(base/'audit'),'timeoutMs':2000,'maxRequestChars':32000,
      'staticShell':{'enabled':True,'parser':{'path':str(config/'review/bin/shell-parser'),
        'sha256':hashlib.sha256((config/'review/bin/shell-parser').read_bytes()).hexdigest()}}}
    (config/'policy.json').write_text(json.dumps(policy));(config/'policy.json').chmod(0o600)
    wrapper=config/'fixture';wrapper.mkdir()
    (wrapper/'package.json').write_text(json.dumps({'name':'grant-native-fixture','type':'module','exports':'./index.mjs'}))
    (wrapper/'index.mjs').write_text("""import {createApprovalPlugin} from '../review/index.mjs';
import {createRuleStore} from '../review/grant-store.mjs';
import {appendFileSync} from 'node:fs';
const counts=new Map();
export default {id:'local.approval-review',async setup(ctx){
 const policyFile="""+json.dumps(str(config/'policy.json'))+""";
 let failedLookup=false;
 const permission=new Proxy(ctx.permission,{get(target,key){
  if(key==='get')return async(x,o)=>{
   if(x.sessionID==='ses_grant_lookup'&&!failedLookup){failedLookup=true;throw Object.assign(Error('Synthetic transient pending lookup'),{code:'ECONNRESET'});}
   return target.get(x,o);
  };
  const value=target[key];return typeof value==='function'?value.bind(target):value;
 }});
 const cleanup=await createApprovalPlugin({generate:async({prompt},signal)=>{
  const data=JSON.parse(prompt.slice(prompt.lastIndexOf('\\n')+1));
  const name=data.request.tool?.input?.case??'none';const n=(counts.get(name)??0)+1;counts.set(name,n);
  appendFileSync("""+json.dumps(str(base/'calls.jsonl'))+""",JSON.stringify({name,n})+'\\n');
  await new Promise(r=>setTimeout(r,name==='cancel'?1000:50));signal.throwIfAborted();
  if(name==='malformed'&&n===1)return {text:'not json'};
  if(name==='concurrent')await rules.set(data.projectID,{operation:'files.read',target:'/fixture/unrelated',targetType:'file'},'allow','user',{source:'concurrent fixture'});
  const decision=name==='escalate'?'escalate_once':['remember','cancel','concurrent'].includes(name)?'allow_always':'allow_once';
  return {text:JSON.stringify({decision,reason:'Synthetic '+name+' decision.',remember:decision==='allow_always'?[data.candidates[0].id]:[]})};
 }}).setup({...ctx,permission,options:{policyFile}});
 const rules=createRuleStore(policyFile);
 const hook=await ctx.permission.hook('evaluate',async e=>{
  if(e.action!=='fixture_set_rule')return;
  const session=await ctx.session.get({sessionID:e.sessionID});
  const state=await rules.read(session.projectID);
  const item=state.seen.find(g=>g.target.endsWith('/'+e.metadata.label));
  if(!item)throw Error('Missing seen grant');
  await rules.set(session.projectID,item,e.metadata.mode,'user',{source:'native fixture'});e.effect='allow';
 });
 return async()=>{await hook.dispose();await cleanup();};
}};
""")
    (config/'opencode.json').write_text(json.dumps({'model':model,'permissions':[{'action':'*','resource':'*','effect':'ask'}],
      'plugins':[str(wrapper)]}))
    checks=[]
    with server(config,repo,base/'state') as api:
        discovery=base/'state/state/opencode/service.json';discovery.parent.mkdir(parents=True,exist_ok=True)
        discovery.write_text(json.dumps({'url':api.url,'pid':api.pid,'password':base64.b64decode(api.authorization.split(' ',1)[1]).decode().split(':',1)[1]}));discovery.chmod(0o600)
        q={'location':{'directory':str(repo)}}
        api.call('GET','/api/location',query=q);api.call('POST','/api/plugin/await-activation',query=q)
        plugins=api.call('GET','/api/plugin',query=q)
        loaded=next(p for p in plugins if p['id']=='local.approval-review')
        assert loaded['state']['status']=='active',loaded
        seed=api.call('POST','/api/session',{'location':q['location'],'title':'Grant fixture'})
        template=api.call('GET',f"/api/session/{seed['id']}/export")
        def calls():return [json.loads(x) for x in (base/'calls.jsonl').read_text().splitlines()] if (base/'calls.jsonl').exists() else []
        def rows():return [json.loads(x) for f in (base/'audit').glob('*.jsonl') for x in f.read_text().splitlines()]
        def wait(fn,seconds=16):
            end=time.monotonic()+seconds
            while time.monotonic()<end:
                if result:=fn():return result
                time.sleep(.05)
            raise AssertionError('Timed out: '+str(base))
        def case(name,alias=None):
            sid='ses_grant_'+name;stamp=int(time.time()*1000);data=copy.deepcopy(template)
            data['info'].update(id=sid,title=name)
            data['messages']=[{'id':'msg_user_'+name,'type':'user','text':'Perform these fixture operations repeatedly. This is a synthetic permission test.', 'time':{'created':stamp}},
              {'id':'msg_tool_'+name,'type':'assistant','agent':'build','model':model,'time':{'created':stamp,'completed':stamp},'finish':'stop',
                'content':[{'type':'tool','id':'call_'+name,'name':'edit','state':{'status':'completed','input':{'case':alias or name},
                  'content':[{'type':'text','text':'Fixture only. Never executed.'}]},'time':{'created':stamp,'completed':stamp}}]}]
            api.call('POST','/api/session/import',data)
            r=api.call('POST',f'/api/session/{sid}/permission',{'action':'edit','resources':[str(other/(alias or name))],'agent':'build',
              'source':{'type':'tool','messageID':'msg_tool_'+name,'id':'call_'+name}})
            return sid,r
        def final(rid):return next((r for r in reversed(rows()) if r.get('requestID')==rid and r.get('status') in ['allow','ask','native_reply']),None)
        def set_rule(sid,label,mode):
            # The fixture hook simulates the same store mutation as the human tree UI.
            policy['mode']='off';(config/'policy.json').write_text(json.dumps(policy))
            api.call('POST',f'/api/session/{sid}/permission',{'action':'fixture_set_rule','resources':['fixture'],'metadata':{'label':label,'mode':mode}})
            policy['mode']='enforce';(config/'policy.json').write_text(json.dumps(policy))
        sid,r=case('once');assert r['effect']=='ask';assert wait(lambda:final(r['id']))['status']=='allow';checks.append('allow_once')
        sid,r=case('lookup');assert wait(lambda:final(r['id']))['status']=='allow'
        assert any(x.get('code')=='pending_lookup_failed' and x.get('sessionID')==sid for x in rows());checks.append('pending_lookup_recovers')
        sid,r=case('concurrent');assert wait(lambda:final(r['id']))['status']=='allow'
        wait(lambda:any(x.get('code')=='model_rules_saved' and x.get('sessionID')==sid for x in rows()))
        assert len([c for c in calls() if c['name']=='concurrent'])==1;checks.append('unrelated_rule_change_preserves_review_and_save')
        sid,r=case('remember');assert r['effect']=='ask';assert wait(lambda:final(r['id']))['status']=='allow'
        wait(lambda:any(x.get('code')=='model_rules_saved' and x.get('sessionID')==sid for x in rows()))
        saved_row=next(x for x in reversed(rows()) if x.get('code')=='model_rules_saved' and x.get('sessionID')==sid)
        saved_detail=json.loads((base/'audit'/saved_row['details']['path']).read_text())['data']
        update=saved_detail['lifecycle']['ruleUpdate']
        assert update['status']=='saved' and update['changes'][0]['after']['authority']=='model',update
        assert update['before'][0]['mode']=='dynamic' and update['after'][0]['mode']=='allow',update
        assert saved_detail['grants']['entries'][0]['grant']['operation']=='files.write',saved_detail
        checks.append('saved_rule_audit_has_grants_and_state_transition')
        count=len(calls());child,r2=case('reuse','remember');assert r2['effect']=='allow',r2;assert len(calls())==count;checks.append('allow_always_reused_across_sessions')
        set_rule(child,'remember','ask');_,r3=case('ask_rule','remember');assert r3['effect']=='ask';assert wait(lambda:final(r3['id']))['status']=='ask';assert len(calls())==count;checks.append('always_ask_skips_model')
        set_rule(child,'remember','dynamic');_,r4=case('dynamic','remember');assert r4['effect']=='ask';assert wait(lambda:final(r4['id']))['status']=='allow';assert len(calls())==count+1;checks.append('dynamic_calls_model')
        sid,r=case('escalate');assert wait(lambda:final(r['id']))['status']=='ask';count=len(calls())
        set_rule(sid,'concurrent','dynamic');time.sleep(4)
        assert len(calls())==count;checks.append('unrelated_rule_change_does_not_repeat_escalation')
        set_rule(sid,'escalate','allow')
        wait(lambda:not api.call('GET',f'/api/session/{sid}/permission'));assert len(calls())==count;checks.append('tree_edit_resolves_existing_dialog')
        sid,r=case('cancel');wait(lambda:any(c['name']=='cancel' for c in calls()))
        api.call('POST',f"/api/session/{sid}/permission/{r['id']}/reply",{'reply':'reject'})
        assert wait(lambda:final(r['id']))['status']=='native_reply';time.sleep(1.1)
        assert not any(x.get('code')=='model_rules_saved' and x.get('sessionID')==sid for x in rows());checks.append('human_reject_wins')
        sid,r=case('malformed');assert wait(lambda:final(r['id']))['status']=='allow';assert len([c for c in calls() if c['name']=='malformed'])==2;checks.append('malformed_retries')
        policy['mode']='off';(config/'policy.json').write_text(json.dumps(policy))
        r=api.call('POST',f'/api/session/{sid}/permission',{'action':'external_directory','resources':[str(other)+'/*'],'save':[str(other)+'/*']})
        api.call('POST',f"/api/session/{sid}/permission/{r['id']}/reply",{'reply':'always'})
        policy['mode']='enforce';(config/'policy.json').write_text(json.dumps(policy));count=len(calls())
        r=api.call('POST',f'/api/session/{sid}/permission',{'action':'external_directory','resources':[str(other)+'/*']})
        assert r['effect']=='allow',r
        r=api.call('POST',f'/api/session/{sid}/permission',{'action':'read','resources':[str(other/'file')]})
        assert r['effect']=='allow',r;assert len(calls())==count;checks.append('native_saved_directory_and_read')
    report={'base':str(base),'checks':checks,'commandsExecuted':False}
    (base/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report),flush=True)

if __name__=='__main__':main()

"""Exercise native directory reads and grep with omitted optional metadata."""
from pathlib import Path
import base64,copy,json,shutil,subprocess,sys,tempfile,time
source=Path(__file__).resolve().parent
from local_api import server

def main():
    base=Path(tempfile.mkdtemp(prefix='opencode-native-reads-')).resolve()
    config=base/'config';repo=base/'repo';outside=base/'outside'
    for p in [config,repo,outside]:p.mkdir()
    (outside/'file.txt').write_text('needle in fixture\n');(outside/'.env').write_text('needle in synthetic fixture\n')
    subprocess.run(['/usr/bin/git','init','-q',str(repo)],check=True)
    shutil.copytree(source,config/'review',ignore=shutil.ignore_patterns('__pycache__', 'node_modules', '.git', 'test-results'))
    (config/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
    policy={'version':1,'mode':'enforce','model':{'providerID':'fixture','id':'fixture','variant':'medium'},
      'skillRoots':[],'protectedRoots':[str(config)],'scratchRoot':str(base/'scratch'),'auditRoot':str(base/'audit'),
      'timeoutMs':5000,'maxRequestChars':32000,'grantRules':[{'operation':'files.access','target':str(outside),'targetType':'directory','mode':'allow'}]}
    (config/'policy.json').write_text(json.dumps(policy));(config/'policy.json').chmod(0o600)
    wrapper=config/'fixture';wrapper.mkdir()
    (wrapper/'package.json').write_text(json.dumps({'name':'native-reads-fixture','type':'module','exports':'./index.mjs'}))
    (wrapper/'index.mjs').write_text("""import {createApprovalPlugin} from '../review/index.mjs';
import {appendFileSync} from 'node:fs';
export default {id:'local.approval-review',async setup(ctx){
 const log=x=>appendFileSync("""+json.dumps(str(base/'events.jsonl'))+""",JSON.stringify(x)+'\\n');
 const native={};const registration=await ctx.tool.transform(editor=>{for(const name of ['read','grep'])native[name]=editor.get(name);});
 const permission=new Proxy(ctx.permission,{get(target,key){if(key==='get')return async(x,o)=>{
   try{return await target.get(x,o);}catch(e){log({kind:'sdk_error',name:e.name,tag:e._tag});throw e;}
 };const v=target[key];return typeof v==='function'?v.bind(target):v;}});
 const cleanup=await createApprovalPlugin({generate:async({prompt})=>{
   const data=JSON.parse(prompt.split('\\n').at(-1));log({kind:'model',action:data.request.action,grants:data.grants.map(x=>x.grant)});
   const secret=data.grants.some(x=>x.grant.operation==='secrets.read');
   const listing=data.candidates.find(c=>c.operation==='files.list');
   return {text:JSON.stringify({decision:secret?'escalate_once':listing?'allow_always':'allow_once',
     remember:!secret&&listing?[listing.id]:[],reason:secret?'Synthetic secret read requires review.':'Authorized fixture inspection.'})};
 }}).setup({...ctx,permission,options:{policyFile:"""+json.dumps(str(config/'policy.json'))+"""}});
 const hook=await ctx.permission.hook('evaluate',e=>{
  if(!e.metadata?.fixtureTool)return;
  const {fixtureTool:name,caseName,input}=e.metadata;
  void native[name].execute(input,{sessionID:e.sessionID,agent:'build',messageID:'msg_'+caseName,id:'call_'+caseName,progress:async()=>{}})
    .then(()=>log({kind:'done',caseName}),error=>log({kind:'failed',caseName,error:String(error)}));
 });
 await ctx.tool.reload();return async()=>{await hook.dispose();await registration.dispose();await cleanup();};
}};
""")
    (config/'opencode.json').write_text(json.dumps({'model':policy['model'],'plugins':[str(wrapper)],'permissions':[]}))
    checks=[]
    with server(config,repo,base/'state') as api:
        discovery=base/'state/state/opencode/service.json';discovery.parent.mkdir(parents=True,exist_ok=True)
        discovery.write_text(json.dumps({'url':api.url,'pid':api.pid,'password':base64.b64decode(api.authorization.split(' ',1)[1]).decode().split(':',1)[1]}));discovery.chmod(0o600)
        q={'location':{'directory':str(repo)}};api.call('GET','/api/location',query=q);api.call('POST','/api/plugin/await-activation',query=q)
        seed=api.call('POST','/api/session',{'location':q['location'],'title':'Native read fixture'})
        template=api.call('GET',f"/api/session/{seed['id']}/export")
        def events():return [json.loads(x) for x in (base/'events.jsonl').read_text().splitlines()] if (base/'events.jsonl').exists() else []
        def rows():return [json.loads(x) for f in (base/'audit').glob('*.jsonl') for x in f.read_text().splitlines()]
        def wait(fn):
            end=time.monotonic()+18
            while time.monotonic()<end:
                if value:=fn():return value
                time.sleep(.05)
            raise AssertionError('Timed out: '+str(base))
        cases=[('listing','read',{'path':str(outside),'limit':100}),('repeat_listing','read',{'path':str(outside),'limit':100}),
          ('grep','grep',{'path':str(outside/'file.txt'),'pattern':'needle','limit':10}),
          ('secret','grep',{'path':str(outside/'.env'),'pattern':'needle','limit':10})]
        for name,tool,input in cases:
            before=len([e for e in events() if e['kind']=='model']);sid='ses_read_'+name;stamp=int(time.time()*1000)
            data=copy.deepcopy(template);data['info'].update(id=sid,title=name)
            data['messages']=[{'id':'msg_user_'+name,'type':'user','text':'Inspect these synthetic fixture files. Repeated directory listings are authorized. Secret reads require my approval.','time':{'created':stamp}},
              {'id':'msg_'+name,'type':'assistant','agent':'build','model':policy['model'],'finish':'stop','time':{'created':stamp,'completed':stamp},
               'content':[{'type':'tool','id':'call_'+name,'name':tool,'state':{'status':'completed','input':input,'content':[{'type':'text','text':'Fixture only'}]},'time':{'created':stamp,'completed':stamp}}]}]
            api.call('POST','/api/session/import',data)
            api.call('POST',f'/api/session/{sid}/permission',{'action':'execute','resources':['fixture'],'metadata':{'fixtureTool':tool,'caseName':name,'input':input}})
            if name=='secret':
                wait(lambda:any(r.get('sessionID')==sid and r.get('code')=='model_escalation' for r in rows()))
                pending=api.call('GET',f'/api/session/{sid}/permission');assert len(pending)==1
                assert not any(e['kind']=='done' and e.get('caseName')==name for e in events())
                api.call('POST',f'/api/session/{sid}/permission/{pending[0]["id"]}/reply',{'reply':'reject'})
            else:
                wait(lambda:any(e['kind']=='done' and e.get('caseName')==name for e in events()))
                assert not api.call('GET',f'/api/session/{sid}/permission')
            calls=len([e for e in events() if e['kind']=='model'])-before
            assert calls==(0 if name=='repeat_listing' else 1),(name,calls,base)
            checks.append({'case':name,'modelCalls':calls})
        assert not any(r.get('code') in ['pending_lookup_exhausted','pending_lookup_invalid'] for r in rows())
        print(json.dumps({'base':str(base),'checks':checks,'sdkSchemaErrors':len([e for e in events() if e['kind']=='sdk_error'])}))

if __name__=='__main__':main()

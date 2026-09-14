"""Check notification decisions against native pending dialogs. Execute no tools."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parent
from local_api import server


def main():
    base = Path(tempfile.mkdtemp(prefix='opencode-notifications-native-')).resolve()
    config = base/'config'
    config.mkdir()
    repo = base/'repo'
    repo.mkdir()
    (config/'opencode.json').write_text(json.dumps({'model': {'providerID': 'fixture', 'id': 'classifier'},
        'permissions': [{'action': 'shell', 'resource': '*', 'effect': 'ask'}]}))
    (base/'node_modules').symlink_to(SOURCE/'node_modules', target_is_directory=True)
    policy = base/'policy.json'
    policy.write_text(json.dumps({'auditRoot': str(base/'audit')}))
    (base/'audit').mkdir()
    with server(config, repo, base/'state') as api:
        secret = base/'connection.json'
        secret.write_text(json.dumps({'baseUrl': api.url, 'headers': {'Authorization': api.authorization}}))
        secret.chmod(0o600)
        driver = base/'driver.mjs'
        driver.write_text("""import assert from 'node:assert/strict';
import {readFile,appendFile} from 'node:fs/promises';
import {OpenCode} from '@opencode/client';
import {createApprovalNotifications,WAIT_MS} from """ + json.dumps((SOURCE/'approval-notifications.mjs').as_uri()) + """;
const base=""" + json.dumps(str(base)) + """;
const client=OpenCode.make(JSON.parse(await readFile(base+'/connection.json','utf8')));
const permissions=[{action:'shell',resource:'*',effect:'ask'}];
const main=await client.session.create({location:{directory:base+'/repo'},agent:'build',permissions,title:'Notification fixture'});
const workerSeed=await client.session.create({location:{directory:base},agent:'build',permissions,title:'Hidden worker'});
const transfer=await client.session.export({sessionID:workerSeed.id});
transfer.info.id='ses_notification_worker';transfer.info.parentID=main.id;
const worker=await client.session.import(transfer);
assert.equal((await client.session.get({sessionID:worker.id})).parentID,main.id);
const log=base+'/audit/'+new Date().toISOString().slice(0,10)+'.jsonl';
let clock=Date.now();const sends=[];
const monitor=createApprovalNotifications({client,policyFile:base+'/policy.json',now:()=>clock,
 notify:async x=>{sends.push(x);return {notification:true};},onError:x=>{throw Error(x);}});
const create=async(session,status,code)=>{
 const request=await client.permission.create({sessionID:session.id,agent:'build',action:'shell',resources:['synthetic fixture; never execute']});
 assert.equal(request.effect,'ask');
 await appendFile(log,JSON.stringify({version:3,time:new Date(clock).toISOString(),sessionID:session.id,
 requestID:request.id,action:'shell',mode:'enforce',status,code,proposed:'ask',
 applied:status==='ask'?'ask':'pending',elapsedMs:0})+'\\n');
 return request;
};
const one=await create(worker,'ask','model_escalation');
await monitor.tick();assert.equal(sends.length,1);
assert.equal((await client.permission.list({sessionID:worker.id})).length,1);
await monitor.tick();assert.equal(sends.length,1);
await client.permission.reply({sessionID:worker.id,requestID:one.id,reply:'reject'});
await create(main,'ask','classifier_format_exhausted');await monitor.tick();assert.equal(sends.length,2);
const slow=await create(worker,'reviewing','review_in_progress');
await monitor.tick();assert.equal(sends.length,2);
clock+=WAIT_MS;await monitor.tick();assert.equal(sends.length,3);assert.match(sends[2].message,/5 minutes/);
await client.permission.reply({sessionID:worker.id,requestID:slow.id,reply:'reject'});
const cancelled=await create(worker,'ask','model_escalation');
await client.permission.reply({sessionID:worker.id,requestID:cancelled.id,reply:'reject'});
await monitor.tick();assert.equal(sends.length,3);monitor.stop();
console.log(JSON.stringify({checks:6,passed:true,commandsExecuted:false,systemNotificationsSent:false}));
""")
        result = json.loads(subprocess.check_output(['node', str(driver)], text=True))
        (base/'report.json').write_text(json.dumps(result, indent=2))
        print(json.dumps({**result, 'report': str(base/'report.json')}))


if __name__ == '__main__':
    main()

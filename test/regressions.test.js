import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { keys, makeEvent, signature, transaction, verifyEvidence } from '../src/security.js';
import { openStore, passwordHash } from '../src/store.js';
import { createApp } from '../src/server.js';

function fixture() {
  const signer=keys(), timestamp=keys();
  const events=[];
  const add=()=>events.push(makeEvent({sequence:events.length+1,previous:events.at(-1)?.hash||'0'.repeat(64),time:new Date().toISOString(),action:'TEST',data:{}},signer.privateKey,timestamp.privateKey));
  const bundle=()=>{const body={count:events.length,head:events.at(-1)?.hash||'0'.repeat(64)};return {events:structuredClone(events),checkpoint:{body,signature:signature(body,signer.privateKey)}};};
  return {add,bundle,signer,trust:{signer:signer.publicKey,timestamp:timestamp.publicKey}};
}

test('transaction schema rejects coercible non-string fields before processing',()=>{
  const input={amount:100,currency:'PKR',reference:' sample ',requestId:'sample-001'};
  for(const field of ['currency','requestId']) for(const value of [[input[field]],12345678,{},null,true]) {
    assert.throws(()=>transaction({...input,[field]:value}),{code:'INVALID_TRANSACTION'});
  }
  assert.equal(transaction(input).reference,'sample');
});

test('retained checkpoints accept journal growth but reject rollback, forks and invalid signatures',()=>{
  const f=fixture();f.add();const old=f.bundle();f.add();const current=f.bundle();
  assert.equal(verifyEvidence(current,f.trust,old.checkpoint).valid,true);
  assert.equal(verifyEvidence(current,f.trust,current.checkpoint).valid,true);
  assert(verifyEvidence(old,f.trust,current.checkpoint).issues.some(i=>i.code==='CHECKPOINT_MISMATCH'));
  const fork=structuredClone(old.checkpoint);fork.body.head='f'.repeat(64);fork.signature=signature(fork.body,f.signer.privateKey);
  assert(verifyEvidence(current,f.trust,fork).issues.some(i=>i.code==='CHECKPOINT_MISMATCH'));
  const bad=structuredClone(old.checkpoint);bad.signature='bad';
  assert(verifyEvidence(current,f.trust,bad).issues.some(i=>i.code==='BAD_CHECKPOINT'));
  const altered=structuredClone(current);altered.checkpoint.signature='bad';
  assert(verifyEvidence(altered,f.trust,old.checkpoint).issues.some(i=>i.code==='BAD_CHECKPOINT'));
});

test('malformed JSON evidence returns structured failure without throwing',()=>{
  const f=fixture();f.add();const good=f.bundle();
  for(const input of [null,undefined,[],{},true,{events:[]}, {...good,checkpoint:null}, {...good,checkpoint:{body:{count:-1,head:'bad'}}}, ...[null,{},[],{body:null},{body:[],stamp:{}}].map(event=>({...good,events:[event]}))]) {
    const result=verifyEvidence(input,f.trust);assert.equal(result.valid,false);assert(result.issues.length>0);
  }
  assert.equal(verifyEvidence(good,null).valid,false);
  assert.equal(verifyEvidence(good,f.trust,null).valid,false);
});

test('HTTP schema rejection, bounded audit writes, and durable separate auditing after revocation',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'journal-regression-')),s=openStore(dir);
  s.db.prepare('INSERT INTO users(username,password,role) VALUES(?,?,?)').run('admin',passwordHash('regression-password'),'admin');
  const server=createApp(s).listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
  const base=`http://127.0.0.1:${server.address().port}/api/`;
  const request=(path,body,headers={})=>fetch(base+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json',...headers},body:body===undefined?undefined:JSON.stringify(body)});
  try {
    const login=await request('login',{username:'admin',password:'regression-password'}), session=await login.json();
    const headers={Cookie:login.headers.get('set-cookie').split(';')[0],'X-CSRF-Token':session.csrf};
    for(const patch of [{currency:['PKR']},{requestId:12345678},{requestId:['sample-001']}]) {
      const r=await request('transactions',{amount:1,currency:'PKR',reference:'sample',requestId:'sample-001',...patch},headers);
      assert.equal(r.status,400);assert.equal((await r.json()).error,'INVALID_TRANSACTION');
    }
    assert.equal(s.events().filter(e=>e.body.action==='TRANSACTION').length,0);
    const retained=s.bundle();
    assert.equal((await request('revoke',{confirmation:'REVOKE'},headers)).status,200);
    const mainCount=s.events().length;
    assert.equal((await request('events')).status,401);
    assert.equal(s.events().length,mainCount);
    assert.equal(s.auditEvents().at(-1).body.action,'ACCESS_DENIED');
    assert.equal((await request('transactions',{amount:1,currency:'PKR',reference:'sample',requestId:'sample-002'},headers)).status,503);
    assert.equal((await request('login',{username:'admin',password:'regression-password'})).status,200);
    const history=await (await request('events',undefined,headers)).json();
    assert(history.items.some(e=>e.journal==='operational'&&e.body.action==='LOGIN'));
    const exported=await (await request('export',undefined,headers)).json();
    assert.deepEqual(verifyEvidence(exported,s.trust,retained.checkpoint).issues,[{code:'SIGNER_REVOKED'}]);
    const tampered=structuredClone(exported);tampered.auditTrail.events[0].body.actor='forged';
    assert(verifyEvidence(tampered,s.trust).issues.some(i=>i.code==='AUDIT_CONTENT_ALTERED'));
    const stripped=structuredClone(exported);delete stripped.auditTrail;
    assert(verifyEvidence(stripped,s.trust).issues.some(i=>i.code==='AUDIT_CHECKPOINT_MISMATCH'));
    assert.throws(()=>s.db.prepare('DELETE FROM audit_events').run());
    const persisted=openStore(dir);assert.equal(persisted.auditEvents().length,s.auditEvents().length);assert.deepEqual(persisted.health().issues,[{code:'SIGNER_REVOKED'}]);persisted.db.close();
    // Continue beyond the API window's budget; rejected requests must stop creating events.
    let response;
    for(let i=0;i<130;i++)response=await request('events');
    assert.equal(response.status,429);assert(response.headers.get('retry-after'));
    const count=s.auditEvents().length;
    for(let i=0;i<20;i++)assert.equal((await request('transactions',{oversized:'x'.repeat(20000)})).status,429);
    assert.equal(s.auditEvents().length,count);
    assert.equal(s.auditEvents().filter(e=>e.body.action==='API_RATE_LIMIT').length,1);
    assert.deepEqual(verifyEvidence(s.bundle(),s.trust,exported.checkpoint).issues,[{code:'SIGNER_REVOKED'}]);
    assert(verifyEvidence(exported,s.trust,s.bundle().checkpoint).issues.some(i=>i.code==='AUDIT_CHECKPOINT_MISMATCH'));
    // Non-API bodies must not bypass API throttling through parser-error audit writes.
    await fetch(new URL('/not-api',base),{method:'POST',headers:{'Content-Type':'application/json'},body:'{'});
    assert.equal(s.auditEvents().length,count);
  } finally {await new Promise(r=>server.close(r));s.db.close();rmSync(dir,{recursive:true,force:true});}
});

test('login throttle writes one summary and suppresses repeated failure records',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'journal-login-limit-')),s=openStore(dir);
  const server=createApp(s).listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
  try {
    const url=`http://127.0.0.1:${server.address().port}/api/login`;
    for(let i=0;i<15;i++) {
      const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'unknown',password:'wrong'})});
      assert.equal(r.status,i<10?401:429);
    }
    assert.equal(s.events().length,11);
    assert.equal(s.events().filter(e=>e.body.action==='LOGIN_RATE_LIMIT').length,1);
  } finally {await new Promise(r=>server.close(r));s.db.close();rmSync(dir,{recursive:true,force:true});}
});

test('independent CLI accepts retained-prefix growth and reports malformed evidence safely',()=>{
  const dir=mkdtempSync(join(tmpdir(),'journal-cli-')),f=fixture();
  try {
    f.add();const old=f.bundle();f.add();const current=f.bundle();
    for(const [name,value] of Object.entries({evidence:current,trust:f.trust,checkpoint:old.checkpoint,malformed:null})) writeFileSync(join(dir,name+'.json'),JSON.stringify(value));
    const cli=fileURLToPath(new URL('../src/verify.js',import.meta.url));
    const run=name=>spawnSync(process.execPath,[cli,join(dir,name+'.json'),join(dir,'trust.json'),join(dir,'checkpoint.json')],{encoding:'utf8'});
    const valid=run('evidence');assert.equal(valid.status,0,valid.stderr);assert.equal(JSON.parse(valid.stdout).valid,true);
    const invalid=run('malformed');assert.equal(invalid.status,1);assert.equal(JSON.parse(invalid.stdout).issues[0].code,'INVALID_EVIDENCE');assert.equal(invalid.stderr,'');
  } finally {rmSync(dir,{recursive:true,force:true});}
});

test('missing operational signing keys fail closed when audit evidence already exists',()=>{
  const dir=mkdtempSync(join(tmpdir(),'journal-audit-key-'));
  try {
    const store=openStore(dir);store.appendAudit('test','ACCESS_DENIED',{});store.db.close();
    rmSync(join(dir,'audit-keys.json'));
    assert.throws(()=>openStore(dir),/Audit signing keys missing/);
  } finally {rmSync(dir,{recursive:true,force:true});}
});

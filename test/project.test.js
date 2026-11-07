import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openStore,passwordHash } from '../src/store.js';
import { createApp } from '../src/server.js';
import { verifyEvidence,makeEvent,signature } from '../src/security.js';
import { generateKeyPairSync } from 'node:crypto';
test('T1–T6 and misuse: full authenticated workflow and persistent evidence',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'journal-'));const s=openStore(dir);
 for(const role of ['admin','operator','viewer'])s.db.prepare('INSERT INTO users(username,password,role) VALUES(?,?,?)').run(role,passwordHash('test-password-123'),role);
 const server=createApp(s).listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
 const base=`http://127.0.0.1:${server.address().port}/api/`;
 async function req(path,body,user){const r=await fetch(base+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json',...(user?{Cookie:user.cookie,'X-CSRF-Token':user.csrf}:{})},body:body?JSON.stringify(body):undefined});return {status:r.status,body:await r.json(),cookie:r.headers.get('set-cookie')?.split(';')[0]};}
 try{
  assert.equal((await req('events')).status,401);
  const admin=await req('login',{username:'admin',password:'test-password-123'});admin.csrf=admin.body.csrf;
  const operator=await req('login',{username:'operator',password:'test-password-123'});operator.csrf=operator.body.csrf;
  const viewer=await req('login',{username:'viewer',password:'test-password-123'});viewer.csrf=viewer.body.csrf;
  assert.equal((await req('events',null,viewer)).status,403);
  assert.equal((await req('settings',{amountLimit:200},operator)).status,403);
  assert.equal((await req('settings',{amountLimit:200},{...admin,csrf:'wrong'})).status,403);
  const input={amount:100,currency:'PKR',reference:'Sample',requestId:'sample-001'};
  assert.equal((await req('transactions',input,operator)).body.body.data.decision,'ALLOWED');
  assert.equal((await req('transactions',input,operator)).status,409);
  const denied=await req('transactions',{...input,amount:100001,requestId:'sample-002'},operator);
  assert.equal(denied.body.body.data.decision,'DENIED');assert.equal(denied.body.body.data.reason,'AMOUNT_LIMIT_EXCEEDED');
  assert.equal((await req('transactions',{...input,amount:-1},operator)).status,400);
  assert.equal((await req('transactions',{...input,reference:'x'.repeat(20000)},operator)).status,413);
  const malformed=await fetch(base+'transactions',{method:'POST',headers:{'Content-Type':'application/json',Cookie:operator.cookie,'X-CSRF-Token':operator.csrf},body:'{'});assert.equal(malformed.status,400);
  await req('settings',{amountLimit:50},admin);
  assert.equal((await req('transactions',{...input,requestId:'sample-003'},operator)).body.body.data.ruleVersion,2);
  assert.equal((await req('verify',{},operator)).body.valid,true);
  const bundle=(await req('export',null,operator)).body;
  assert.equal(verifyEvidence(bundle,s.trust).valid,true);
  const altered=structuredClone(bundle);altered.events.find(e=>e.body.action==='TRANSACTION').body.data.amount=42;
  assert(verifyEvidence(altered,s.trust).issues.some(i=>i.code==='CONTENT_ALTERED'));
  const removed=structuredClone(bundle);removed.events.splice(2,1);assert.equal(verifyEvidence(removed,s.trust).valid,false);
  const reordered=structuredClone(bundle);[reordered.events[0],reordered.events[1]]=[reordered.events[1],reordered.events[0]];assert.equal(verifyEvidence(reordered,s.trust).valid,false);
  const truncated=structuredClone(bundle);truncated.events.pop();assert(verifyEvidence(truncated,s.trust,bundle.checkpoint).issues.some(i=>i.code==='CHECKPOINT_MISMATCH'));
  assert.throws(()=>s.db.prepare('DELETE FROM events').run());
  const count=s.events().length;
  const second=openStore(dir);assert.equal(second.events().length,count);assert.equal(second.health().valid,true);second.db.close();
  await req('revoke',{confirmation:'REVOKE'},admin);
  assert(verifyEvidence(s.bundle(),s.trust).issues.some(i=>i.code==='SIGNER_REVOKED'));
  assert.equal((await req('transactions',{...input,requestId:'sample-004'},operator)).status,503);
 }finally{await new Promise(r=>server.close(r));s.db.close();rmSync(dir,{recursive:true,force:true});}
});
test('T5: signed future clock and invalid independent trust are detected',()=>{
 const k=generateKeyPairSync('ed25519',{publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
 const e=makeEvent({sequence:1,previous:'0'.repeat(64),time:new Date(Date.now()+3600000).toISOString(),action:'TEST'},k.privateKey,k.privateKey);
 const body={count:1,head:e.hash},b={events:[e],checkpoint:{body,signature:signature(body,k.privateKey)}};
 assert(verifyEvidence(b,{signer:k.publicKey,timestamp:k.publicKey}).issues.some(i=>i.code==='CLOCK_ANOMALY'));
 assert(verifyEvidence(b,{signer:'invalid',timestamp:'invalid'}).issues.some(i=>i.code==='BAD_SIGNATURE'));
});

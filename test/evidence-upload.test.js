import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openStore, passwordHash } from '../src/store.js';
import { createApp } from '../src/server.js';
import { keys, makeEvent, signature } from '../src/security.js';

async function setup(run) {
  const dir=mkdtempSync(join(tmpdir(),'journal-file-test-')),store=openStore(dir);
  for(const role of ['admin','operator','viewer'])store.db.prepare('INSERT INTO users(username,password,role) VALUES(?,?,?)').run(role,passwordHash('upload-test-password'),role);
  const server=createApp(store).listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
  const origin=`http://127.0.0.1:${server.address().port}`;
  const request=(path,raw,headers={})=>fetch(origin+path,{method:raw===undefined?'GET':'POST',headers:{'Content-Type':'application/json',...headers},body:raw});
  const login=async role=>{const response=await request('/api/login',JSON.stringify({username:role,password:'upload-test-password'}));const session=await response.json();return {Cookie:response.headers.get('set-cookie').split(';')[0],'X-CSRF-Token':session.csrf};};
  try {await run({store,request,login});}finally{await new Promise(r=>server.close(r));store.db.close();rmSync(dir,{recursive:true,force:true});}
}

test('uploaded original passes, changed amount identifies its sequence, and uploaded keys are never trusted',async()=>setup(async({store,request,login})=>{
  const headers=await login('operator');
  const created=await request('/api/transactions',JSON.stringify({amount:12500,currency:'PKR',reference:'Original',requestId:'upload-original-001'}),headers);
  assert.equal(created.status,201);const receipt=await created.json();
  // A realistic export must be accepted even when it exceeds ordinary request limits.
  for(let i=0;i<25;i++)store.append('test','TEST',{reference:'Synthetic size fixture '+i});
  const original=await (await request('/api/export',undefined,headers)).json();
  assert(Buffer.byteLength(JSON.stringify(original))>16384);
  const count=store.events().filter(e=>e.body.action==='TRANSACTION').length;
  const upload=evidence=>request('/api/verify-evidence',JSON.stringify(evidence),headers);
  const valid=await upload(original);assert.equal(valid.status,200);assert.equal((await valid.json()).valid,true);
  const tampered=structuredClone(original);tampered.events.find(e=>e.body.sequence===receipt.body.sequence).body.data.amount=99900;
  tampered.events.find(e=>e.body.sequence===receipt.body.sequence).body.data.reference='Uploaded-private-reference';
  const bad=await (await upload(tampered)).json();assert.equal(bad.valid,false);assert(bad.issues.some(i=>i.code==='CONTENT_ALTERED'&&i.sequence===receipt.body.sequence));
  assert.equal(store.events().filter(e=>e.body.action==='TRANSACTION').length,count);
  assert.equal(store.events().find(e=>e.body.sequence===receipt.body.sequence).body.data.amount,12500);
  const audit=store.events().at(-1);assert.equal(audit.body.action,'EVIDENCE_VERIFICATION');assert(!JSON.stringify(audit).includes('Uploaded-private-reference'));
  const attacker=keys(),event=makeEvent({sequence:1,previous:'0'.repeat(64),time:new Date().toISOString(),action:'TEST',data:{}},attacker.privateKey,attacker.privateKey);
  const body={count:1,head:event.hash};
  const forged={format:'repudiation-resolver/1',events:[event],checkpoint:{body,signature:signature(body,attacker.privateKey)},trust:{signer:attacker.publicKey,timestamp:attacker.publicKey}};
  assert((await (await upload(forged)).json()).issues.some(i=>i.code==='BAD_SIGNATURE'));
  store.atomic(()=>{store.append('admin','SIGNER_REVOKED',{});store.db.prepare('UPDATE settings SET revoked=1 WHERE id=1').run();});
  const revoked=await (await upload(original)).json();assert.equal(revoked.valid,false);assert(revoked.issues.some(i=>i.code==='SIGNER_REVOKED'));
  assert.equal(store.auditEvents().at(-1).body.action,'EVIDENCE_VERIFICATION');
}));

test('file verification enforces authentication, roles, CSRF, JSON type, size and complexity bounds',async()=>setup(async({store,request,login})=>{
  const large=JSON.stringify({padding:'x'.repeat(2*1024*1024)});
  assert.equal((await request('/api/verify-evidence',large)).status,401);
  const viewer=await login('viewer');assert.equal((await request('/api/verify-evidence',large,viewer)).status,403);
  const operator=await login('operator');assert.equal((await request('/api/verify-evidence',large,{...operator,'X-CSRF-Token':'wrong'})).status,403);
  assert.equal((await request('/api/verify-evidence','{}',{...operator,'Content-Type':'text/plain'})).status,415);
  const oversized=await request('/api/verify-evidence',large,operator);assert.equal(oversized.status,413);assert.equal((await oversized.json()).error,'PAYLOAD_TOO_LARGE');
  const broken=await request('/api/verify-evidence','{',operator);assert.equal(broken.status,400);assert.equal((await broken.json()).error,'INVALID_JSON');
  let nested={};for(let i=0;i<40;i++)nested={child:nested};
  for(const input of [null,[],{}, {...store.bundle(),extra:nested},{...store.bundle(),events:Array(2001).fill(null)}]) {
    const r=await request('/api/verify-evidence',JSON.stringify(input),operator);assert.equal(r.status,200);
    const result=await r.json();assert.equal(result.valid,false);assert(result.issues.some(i=>i.code==='INVALID_EVIDENCE'));
  }
}));

test('file-verification throttle bounds cryptographic work and repeated audit writes',async()=>setup(async({store,request,login})=>{
  const headers=await login('operator'),body=JSON.stringify(store.bundle());
  for(let i=0;i<12;i++) {
    const r=await request('/api/verify-evidence',body,headers);assert.equal(r.status,i<10?200:429);
    if(i>=10)assert(r.headers.get('retry-after'));
  }
  assert.equal(store.events().filter(e=>e.body.action==='EVIDENCE_VERIFICATION').length,10);
  assert.equal(store.events().filter(e=>e.body.action==='EVIDENCE_RATE_LIMIT').length,1);
}));

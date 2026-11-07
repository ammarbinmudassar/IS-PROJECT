import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openStore,passwordHash} from '../src/store.js';
import {createApp} from '../src/server.js';

test('event pages are bounded, stable and filtered across both journals',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'journal-history-')),store=openStore(dir);
 store.db.prepare('INSERT INTO users(username,password,role) VALUES(?,?,?)').run('analyst',passwordHash('history-test-password'),'operator');
 for(let i=0;i<32;i++)store.append(i%2?'bob':'alice','TRANSACTION',{decision:i%3?'ALLOWED':'DENIED',reference:`Invoice ${i}`,amount:i+1,currency:'PKR'});
 store.append('anonymous','FAILURE',{code:'PAYLOAD_TOO_LARGE'});
 store.appendAudit('auditor','ACCESS_DENIED',{});
 const server=createApp(store).listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
 const origin=`http://127.0.0.1:${server.address().port}`;
 try {
  const response=await fetch(origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'analyst',password:'history-test-password'})});
  const cookie=response.headers.get('set-cookie').split(';')[0];
  const get=async query=>{const r=await fetch(origin+'/api/events'+query,{headers:{Cookie:cookie}});return {status:r.status,body:await r.json()};};
  const first=(await get('')).body,second=(await get('?page=2')).body;
  assert.equal(first.total,35);assert.equal(first.items.length,10);assert.equal(first.totalPages,4);assert.equal(second.page,2);
  assert(!first.items.some(a=>second.items.some(b=>a.journal===b.journal&&a.body.sequence===b.body.sequence)));
  assert(first.actions.includes('FAILURE'));assert(first.actors.includes('auditor'));
  const filtered=(await get('?action=TRANSACTION&actor=alice&decision=DENIED&pageSize=50')).body;
  assert(filtered.total>0);assert(filtered.items.every(e=>e.body.action==='TRANSACTION'&&e.body.actor==='alice'&&e.body.data.decision==='DENIED'));
  const audit=(await get('?journal=operational')).body;assert.equal(audit.total,1);assert.equal(audit.items[0].body.actor,'auditor');
  const recorded=(await get('?decision=RECORDED')).body;assert.equal(recorded.total,3);
  const failures=(await get('?q=PAYLOAD_TOO_LARGE')).body;assert.equal(failures.total,1);assert.equal(failures.items[0].body.action,'FAILURE');
  const today=new Date().toISOString().slice(0,10);assert.equal((await get(`?from=${today}&to=${today}`)).body.total,35);
  const empty=(await get('?q=does-not-exist&page=4')).body;assert.equal(empty.total,0);assert.equal(empty.page,1);assert.equal(empty.totalPages,1);assert.deepEqual(empty.items,[]);
  assert.equal((await get('?page=99999')).body.page,4);
  assert.equal((await get('?q='+encodeURIComponent("' OR 1=1 --"))).body.total,0);
  for(const query of ['?page=0','?page=-1','?pageSize=101','?pageSize=hello','?page=1&page=2','?decision=UNKNOWN','?journal=invalid','?from=2026-02-31','?from=2026-11-08&to=2026-11-07','?actor='+('x'.repeat(41)),'?unknown=1']) {
   const r=await get(query);assert.equal(r.status,400,query);assert.equal(r.body.error,'INVALID_FILTER');
  }
  const status=await (await fetch(origin+'/api/status',{headers:{Cookie:cookie}})).json();assert.equal(status.capabilities.eventPagination,true);assert.equal(status.capabilities.evidenceUpload,true);
 }finally{await new Promise(r=>server.close(r));store.db.close();rmSync(dir,{recursive:true,force:true});}
});

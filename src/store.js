import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, existsSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { keys, makeEvent, signature, verifyEvidence } from './security.js';
export function openStore(dir=process.env.DATA_DIR||'data') {
  dir=resolve(dir); mkdirSync(dir,{recursive:true,mode:0o700}); chmodSync(dir,0o700);
  const file=resolve(dir,'keys.json');
  if (!existsSync(file)) {
    if (existsSync(resolve(dir,'journal.sqlite'))) throw new Error('Signing keys missing: restore matching backup');
    writeFileSync(file,JSON.stringify({signer:keys(),timestamp:keys()}),{mode:0o600,flag:'wx'});
  }
  const secrets=JSON.parse(readFileSync(file,'utf8'));
  const auditFile=resolve(dir,'audit-keys.json');
  if (!existsSync(auditFile)) {
    if (existsSync(resolve(dir,'journal.sqlite'))) {
      const existing=new DatabaseSync(resolve(dir,'journal.sqlite'),{readOnly:true});
      try {
        if(existing.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_events'").get() && existing.prepare('SELECT 1 FROM audit_events LIMIT 1').get()) throw new Error('Audit signing keys missing: restore matching backup');
      } finally { existing.close(); }
    }
    writeFileSync(auditFile,JSON.stringify(keys()),{mode:0o600,flag:'wx'});
  }
  const auditKeys=JSON.parse(readFileSync(auditFile,'utf8'));
  const trust={signer:secrets.signer.publicKey,timestamp:secrets.timestamp.publicKey,auditSigner:auditKeys.publicKey};
  writeFileSync(resolve(dir,'public-keys.json'),JSON.stringify(trust,null,2),{mode:0o600});
  const db=new DatabaseSync(resolve(dir,'journal.sqlite')); chmodSync(resolve(dir,'journal.sqlite'),0o600);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
  CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS events(sequence INTEGER PRIMARY KEY,event TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS audit_events(sequence INTEGER PRIMARY KEY,event TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS requests(request_id TEXT PRIMARY KEY,event_sequence INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),amount_limit INTEGER NOT NULL,version INTEGER NOT NULL,revoked INTEGER NOT NULL);
  INSERT OR IGNORE INTO settings VALUES(1,100000,1,0);
  CREATE TRIGGER IF NOT EXISTS no_event_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'append only'); END;
  CREATE TRIGGER IF NOT EXISTS no_event_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'append only'); END;
  CREATE TRIGGER IF NOT EXISTS no_audit_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'append only'); END;
  CREATE TRIGGER IF NOT EXISTS no_audit_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'append only'); END;`);
  const events=()=>db.prepare('SELECT event FROM events ORDER BY sequence').all().map(r=>JSON.parse(r.event));
  const auditEvents=()=>db.prepare('SELECT event FROM audit_events ORDER BY sequence').all().map(r=>JSON.parse(r.event));
  const setting=()=>db.prepare('SELECT amount_limit AS amountLimit,version,revoked FROM settings WHERE id=1').get();
  function append(actor,action,data) {
    if(setting().revoked) throw Object.assign(new Error('Signer revoked; restore through recovery procedure'),{status:503,code:'SIGNER_REVOKED'});
    return appendTo('events',secrets.signer.privateKey,actor,action,data);
  }
  function appendAudit(actor,action,data) { return appendTo('audit_events',auditKeys.privateKey,actor,action,data); }
  function appendTo(table,key,actor,action,data) {
    const last=db.prepare(`SELECT event FROM ${table} ORDER BY sequence DESC LIMIT 1`).get();
    const old=last?JSON.parse(last.event):null;
    const time=new Date().toISOString();
    if(old && Date.parse(time)<Date.parse(old.body.time)) throw Object.assign(new Error('Clock moved backwards'),{status:503,code:'CLOCK_ANOMALY'});
    const e=makeEvent({sequence:(old?.body.sequence||0)+1,previous:old?.hash||'0'.repeat(64),time,actor,action,data,engine:'1'},key,secrets.timestamp.privateKey);
    db.prepare(`INSERT INTO ${table} VALUES(?,?)`).run(e.body.sequence,JSON.stringify(e)); return e;
  }
  const combinedEvents="SELECT sequence,event,'transaction' AS journal FROM events UNION ALL SELECT sequence,event,'operational' AS journal FROM audit_events";
  function queryEvents({page=1,pageSize=10,action='',decision='',actor='',journal='',q='',from='',to=''}={}) {
    const clauses=[],values=[];
    const filter=(sql,value)=>{clauses.push(sql);values.push(value);};
    if(action)filter("json_extract(event,'$.body.action')=?",action);
    if(decision==='RECORDED')clauses.push("json_extract(event,'$.body.data.decision') IS NULL");
    else if(decision)filter("json_extract(event,'$.body.data.decision')=?",decision);
    if(actor)filter("json_extract(event,'$.body.actor')=?",actor);
    if(journal)filter('journal=?',journal);
    if(from)filter("substr(json_extract(event,'$.body.time'),1,10)>=?",from);
    if(to)filter("substr(json_extract(event,'$.body.time'),1,10)<=?",to);
    if(q)filter("instr(lower(CAST(sequence AS TEXT)||' '||COALESCE(json_extract(event,'$.body.actor'),'')||' '||COALESCE(json_extract(event,'$.body.action'),'')||' '||COALESCE(json_extract(event,'$.body.data.reference'),'')||' '||COALESCE(json_extract(event,'$.body.data.requestId'),'')||' '||COALESCE(json_extract(event,'$.body.data.code'),'')),lower(?))>0",q);
    const where=clauses.length?' WHERE '+clauses.join(' AND '):'';
    const source=`WITH combined AS (${combinedEvents})`;
    const total=db.prepare(`${source} SELECT COUNT(*) AS count FROM combined${where}`).get(...values).count;
    const totalPages=Math.max(1,Math.ceil(total/pageSize));page=Math.min(page,totalPages);
    const rows=db.prepare(`${source} SELECT event,journal FROM combined${where} ORDER BY json_extract(event,'$.body.time') DESC,sequence DESC,journal ASC LIMIT ? OFFSET ?`).all(...values,pageSize,(page-1)*pageSize);
    const options=field=>db.prepare(`${source} SELECT DISTINCT json_extract(event,'$.body.${field}') AS value FROM combined ORDER BY value`).all().map(r=>r.value).filter(v=>typeof v==='string');
    return {items:rows.map(r=>({...JSON.parse(r.event),journal:r.journal})),page,pageSize,total,totalPages,actions:options('action'),actors:options('actor')};
  }
  const countEvents=()=>db.prepare('SELECT (SELECT COUNT(*) FROM events)+(SELECT COUNT(*) FROM audit_events) AS count').get().count;
  function snapshot(list,key,extra={}) {
    const body={count:list.length,head:list.at(-1)?.hash||'0'.repeat(64),...extra};
    return {format:'repudiation-resolver/1',events:list,checkpoint:{body,signature:signature(body,key)}};
  }
  function bundle() {
    const audit=auditEvents();
    const auditTrail=snapshot(audit,auditKeys.privateKey);
    return {...snapshot(events(),secrets.signer.privateKey,{auditCount:auditTrail.checkpoint.body.count,auditHead:auditTrail.checkpoint.body.head}),auditTrail};
  }
  function atomic(fn) { db.exec('BEGIN IMMEDIATE'); try {const r=fn();db.exec('COMMIT');return r;}catch(e){db.exec('ROLLBACK');throw e;} }
  return {db,dir,trust,events,auditEvents,setting,append,appendAudit,queryEvents,countEvents,bundle,atomic,health:()=>verifyEvidence(bundle(),trust)};
}
export function passwordHash(password) { const salt=randomBytes(16).toString('hex');return salt+':'+scryptSync(password,salt,64).toString('hex'); }
export function passwordValid(password,stored) { const [salt,digest]=stored.split(':');return timingSafeEqual(scryptSync(password,salt,64),Buffer.from(digest,'hex')); }

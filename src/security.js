import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
export const canonical = value => JSON.stringify(value, (_, v) => v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).sort().map(k => [k,v[k]])) : v);
export const hash = value => createHash('sha256').update(canonical(value)).digest('hex');
export function keys() { return generateKeyPairSync('ed25519', {publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}}); }
export const signature = (value, key) => sign(null, Buffer.from(canonical(value)), key).toString('base64');
export function valid(value, sig, key) { try { return verify(null, Buffer.from(canonical(value)), key, Buffer.from(sig,'base64')); } catch { return false; } }
export function makeEvent(body, key, timestampKey) {
  const digest = hash(body);
  const stamp = {hash:digest,time:body.time,authority:'LOCAL_SIMULATION'};
  return {body,hash:digest,signature:signature(digest,key),stamp,stampSignature:signature(stamp,timestampKey)};
}
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const checkpointShape = cp => record(cp) && record(cp.body) && Number.isSafeInteger(cp.body.count) && cp.body.count >= 0 && typeof cp.body.head === 'string' && /^[a-f0-9]{64}$/.test(cp.body.head) && typeof cp.signature === 'string';
export function verifyEvidence(bundle, trust, retainedCheckpoint, now = Date.now()) {
  const issues=[];
  const fail=(code,sequence)=>issues.push({code,...(sequence === undefined ? {} : {sequence})});
  if (!record(bundle) || !Array.isArray(bundle.events) || !record(trust) || typeof trust.signer !== 'string' || typeof trust.timestamp !== 'string' || !checkpointShape(bundle.checkpoint) || (retainedCheckpoint !== undefined && !checkpointShape(retainedCheckpoint))) return {valid:false,issues:[{code:'INVALID_EVIDENCE'}]};
  let previous='0'.repeat(64), time=0;
  for (const [i,e] of bundle.events.entries()) {
    if (!record(e) || !record(e.body) || !record(e.stamp) || typeof e.hash !== 'string' || !/^[a-f0-9]{64}$/.test(e.hash) || typeof e.body.time !== 'string') { fail('MALFORMED_EVENT',i+1); continue; }
    const b=e.body;
    if (b.sequence!==i+1 || b.previous!==previous) fail('CHAIN_BROKEN',i+1);
    if (hash(b)!==e.hash) fail('CONTENT_ALTERED',i+1);
    if (!valid(e.hash,e.signature,trust.signer)) fail('BAD_SIGNATURE',i+1);
    if (!valid(e.stamp,e.stampSignature,trust.timestamp) || e.stamp.hash!==e.hash || e.stamp.time!==b.time || e.stamp.authority!=='LOCAL_SIMULATION') fail('BAD_TIMESTAMP',i+1);
    const t=Date.parse(b.time);
    if (!Number.isFinite(t) || t<time || t>now+60000) fail('CLOCK_ANOMALY',i+1);
    time=t; previous=e.hash;
  }
  const checkpoint=bundle.checkpoint;
  if (!valid(checkpoint.body,checkpoint.signature,trust.signer)) fail('BAD_CHECKPOINT');
  if (checkpoint.body.count!==bundle.events.length || checkpoint.body.head!==previous) fail('CHECKPOINT_MISMATCH');
  if (retainedCheckpoint !== undefined) {
    const anchor=retainedCheckpoint;
    if (!valid(anchor.body,anchor.signature,trust.signer)) fail('BAD_CHECKPOINT');
    const prefixHead=anchor.body.count===0 ? '0'.repeat(64) : bundle.events[anchor.body.count-1]?.hash;
    if (anchor.body.count>bundle.events.length || anchor.body.head!==prefixHead) fail('CHECKPOINT_MISMATCH');
    if (anchor.body.auditHead !== undefined) {
      const auditEvents=bundle.auditTrail?.events;
      const head=anchor.body.auditCount===0 ? '0'.repeat(64) : auditEvents?.[anchor.body.auditCount-1]?.hash;
      if(!Array.isArray(auditEvents) || !Number.isSafeInteger(anchor.body.auditCount) || anchor.body.auditCount<0 || anchor.body.auditCount>auditEvents.length || head!==anchor.body.auditHead) fail('AUDIT_CHECKPOINT_MISMATCH');
    }
  }
  if (bundle.events.some(e=>e?.body?.action==='SIGNER_REVOKED')) fail('SIGNER_REVOKED');
  if (checkpoint.body.auditHead !== undefined && (!record(bundle.auditTrail) || bundle.auditTrail.checkpoint?.body?.head!==checkpoint.body.auditHead || bundle.auditTrail.checkpoint?.body?.count!==checkpoint.body.auditCount)) fail('AUDIT_CHECKPOINT_MISMATCH');
  if (bundle.auditTrail !== undefined) {
    // The operational signer is separately trusted and never inherits transaction authority.
    const result=record(bundle.auditTrail) && bundle.auditTrail.auditTrail===undefined ? verifyEvidence(bundle.auditTrail,{signer:trust.auditSigner,timestamp:trust.timestamp},undefined,now) : {issues:[{code:'INVALID_EVIDENCE'}]};
    for (const issue of result.issues) fail('AUDIT_'+issue.code,issue.sequence);
  }
  return {valid:issues.length===0,issues,checked:bundle.events.length};
}
// Bound untrusted file complexity before canonicalization and cryptographic work.
export function verifyEvidenceUpload(bundle,trust) {
  const invalid=()=>({valid:false,issues:[{code:'INVALID_EVIDENCE'}]});
  if(!record(bundle) || bundle.format!=='repudiation-resolver/1' || !Array.isArray(bundle.events) || bundle.events.length>2000 || (bundle.auditTrail!==undefined && (!record(bundle.auditTrail) || bundle.auditTrail.format!=='repudiation-resolver/1' || !Array.isArray(bundle.auditTrail.events) || bundle.auditTrail.events.length>2000))) return invalid();
  const pending=[[bundle,0]];let nodes=0;
  while(pending.length) {
    const [value,depth]=pending.pop();
    if(++nodes>100000 || depth>32)return invalid();
    if(value && typeof value==='object')for(const child of Object.values(value))pending.push([child,depth+1]);
  }
  return verifyEvidence(bundle,trust);
}
export function transaction(input) {
  if (!input || typeof input!=='object' || Array.isArray(input) || Object.keys(input).some(k=>!['amount','currency','reference','requestId'].includes(k)) || !Number.isSafeInteger(input.amount) || input.amount<1 || input.amount>100000000000 || typeof input.currency!=='string' || !/^[A-Z]{3}$/.test(input.currency) || typeof input.reference!=='string' || input.reference.trim().length<1 || input.reference.length>100 || typeof input.requestId!=='string' || !/^[a-zA-Z0-9_-]{8,80}$/.test(input.requestId)) throw Object.assign(new Error('Invalid transaction fields'),{status:400,code:'INVALID_TRANSACTION'});
  return {...input,reference:input.reference.trim()};
}

import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir, cpus } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { openStore } from '../src/store.js';
import { transaction, verifyEvidence } from '../src/security.js';

const dir=mkdtempSync(join(tmpdir(),'journal-benchmark-')),store=openStore(dir);
const latencies=[];
try {
  let falsePositives=0, falseNegatives=0;
  // Equal numbers within, exactly at, and above the configured boundary.
  for(let i=0;i<120;i++) {
    const input={amount:[50000,100000,100001][i%3],currency:'PKR',reference:'Synthetic benchmark',requestId:`benchmark-${i}`};
    const expected=i%3===2?'DENIED':'ALLOWED', start=performance.now();
    store.atomic(()=>{
      const normalized=transaction(input),rule=store.setting();
      const decision=normalized.amount<=rule.amountLimit?'ALLOWED':'DENIED';
      const event=store.append('benchmark','TRANSACTION',{...normalized,decision,rule:'MAX_AMOUNT',ruleVersion:rule.version,amountLimit:rule.amountLimit});
      store.db.prepare('INSERT INTO requests VALUES(?,?)').run(input.requestId,event.body.sequence);
      if(expected==='ALLOWED'&&decision==='DENIED')falsePositives++;
      if(expected==='DENIED'&&decision==='ALLOWED')falseNegatives++;
    });
    latencies.push(performance.now()-start);
  }
  const evidence=store.bundle(),start=performance.now(),result=verifyEvidence(evidence,store.trust);
  const verificationMs=performance.now()-start;
  assert.equal(result.valid,true);assert.equal(falsePositives+falseNegatives,0);
  const sorted=[...latencies].sort((a,b)=>a-b);
  console.log(JSON.stringify({node:process.version,cpu:cpus()[0]?.model,samples:120,allowed:80,denied:40,falsePositives,falseNegatives,falsePositiveRate:falsePositives/80,falseNegativeRate:falseNegatives/40,scope:'Synthetic MAX_AMOUNT boundary fixtures; validation, policy, signing and SQLite commit. Excludes HTTP/authentication; not a real-world detection estimate.',medianMs:sorted[Math.floor(sorted.length/2)],p95Ms:sorted[Math.ceil(sorted.length*0.95)-1],verificationMs,checked:result.checked,rawLatencyMs:latencies},null,2));
} finally {store.db.close();rmSync(dir,{recursive:true,force:true});}

import { readFileSync } from 'node:fs';
import { verifyEvidence } from './security.js';
try {
  const [evidence,publicKeys,checkpoint]=process.argv.slice(2);
  if(!evidence||!publicKeys) throw new Error('Usage: npm run verify -- evidence.json trusted-public-keys.json [retained-checkpoint.json]');
  const read=p=>JSON.parse(readFileSync(p,'utf8'));
  const result=verifyEvidence(read(evidence),read(publicKeys),checkpoint?read(checkpoint):undefined);
  console.log(JSON.stringify(result,null,2));process.exitCode=result.valid?0:1;
}catch { console.error('Invalid evidence or arguments. Supply evidence and separately trusted public keys.');process.exitCode=1; }

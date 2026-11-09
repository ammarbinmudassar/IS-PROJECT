const $=id=>document.getElementById(id);
let csrf='',eventPage=1,eventTotalPages=1,eventRequest=0,serverCapabilities={};
const requestMessages={
  ACCESS_DENIED:'Sign in with an authorized account, then try again.',
  PAYLOAD_TOO_LARGE:'The request exceeded the server size limit. Evidence files allow 2 MiB; other requests allow 16 KiB. If a smaller evidence file fails, restart the server and refresh the page.',
  INVALID_FILTER:'Check the filters: dates must be valid and the from date cannot follow the to date.',
  RATE_LIMIT:'Too many requests. Wait one minute, then try again.'
};
function inspect(result){
  $('details').textContent=JSON.stringify(result,null,2);
  const body=result.body,data=body?.data||{};
  $('dialog-title').textContent=body?`${result.journal==='operational'?'Operational audit':'Transaction journal'} event ${body.sequence}`:'Journal verification';
  let message='Security activity recorded. Review the actor, time, and action below.';
  if(typeof result.valid==='boolean')message=result.valid
    ? 'Verification passed. Retain the exported evidence and trusted public keys separately.'
    : result.issues.some(i=>i.code==='SIGNER_REVOKED')
      ? 'The signer is revoked. Preserve the evidence and start a separate journal with new trusted keys before resuming transactions.'
      : 'Verification failed. Preserve the original evidence and investigate the reported issues before restoring a verified backup.';
  else if(data.decision==='DENIED')message='Transaction denied: the amount exceeds the recorded limit. Check the amount or ask an administrator to review the policy.';
  else if(data.decision==='ALLOWED')message='Transaction allowed under the recorded policy. Export its signed evidence for independent verification.';
  else if(data.code)message=requestMessages[data.code]||`The request failed (${data.code}). Review the recorded action and try again with valid input.`;
  $('recommendation').textContent=message;
  $('event-summary').replaceChildren();
  const summary=body?{Action:body.action,Actor:body.actor,'Time (UTC)':body.time,Result:data.decision||'Recorded',...(data.amount!==undefined?{Amount:`${(data.amount/100).toFixed(2)} ${data.currency} (${data.amount} minor units)`}:{}),...(data.reference?{Reference:data.reference}:{}),...(data.reason?{Reason:data.reason}:{}),...(data.code?{'Error code':data.code}:{}),...(data.route?{'Request route':data.route}:{}),...(data.amountLimit!==undefined?{'Recorded limit':`${data.amountLimit} minor units`}:{}),...(data.ruleVersion!==undefined?{'Policy version':data.ruleVersion}:{})}:{'Events checked':result.checked??0,Issues:result.issues.map(i=>i.code+(i.sequence===undefined?'':` at event ${i.sequence}`)).join(', ')||'None'};
  for(const [label,value] of Object.entries(summary)){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value;$('event-summary').append(dt,dd);}
  $('evidence-dialog').querySelector('details').open=false;
  if(!$('evidence-dialog').open)$('evidence-dialog').showModal();
}
$('dialog-close').onclick=()=>$('evidence-dialog').close();
$('evidence-dialog').onclick=event=>{if(event.target!==$('evidence-dialog'))return;const rect=event.target.getBoundingClientRect();if(event.clientX<rect.left||event.clientX>rect.right||event.clientY<rect.top||event.clientY>rect.bottom)event.target.close();};
async function api(path,body){
  const res=await fetch('/api/'+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body)});
  const data=await res.json();if(!res.ok)throw Object.assign(Error(requestMessages[data.error]||data.error),{code:data.error});return data;
}
function action(fn){return async e=>{e?.preventDefault();try{await fn(e);}catch(err){$('message').textContent=err.message;}};}
function updateOptions(id,values,label){const select=$(id),selected=select.value;select.replaceChildren();const any=document.createElement('option');any.value='';any.textContent=label;select.append(any);for(const value of values){const option=document.createElement('option');option.value=value;option.textContent=value;select.append(option);}select.value=selected;}
async function loadEvents(){
  const version=++eventRequest;
  const params=new URLSearchParams(new FormData($('event-filters')));params.set('page',eventPage);params.set('pageSize',$('page-size').value);
  $('event-list').setAttribute('aria-busy','true');$('previous-page').disabled=true;$('next-page').disabled=true;
  try{
    const data=await api('events?'+params);
    if(version!==eventRequest)return;
    if(!Array.isArray(data.items))throw Error('The backend is running older code. Stop it with Ctrl+C, run npm start again, then refresh this page.');
    eventPage=data.page;eventTotalPages=data.totalPages;
    updateOptions('event-action',data.actions,'Any action');updateOptions('event-actor',data.actors,'Any actor');
    $('events').replaceChildren();
    for(const event of data.items){
      const tr=document.createElement('tr');
      for(const value of [event.journal==='operational'?'Audit '+event.body.sequence:event.body.sequence,event.body.time,event.body.actor,event.body.action,event.body.data.decision||'Recorded']){const td=document.createElement('td');td.textContent=value;tr.append(td);}
      const td=document.createElement('td'),button=document.createElement('button');button.type='button';button.textContent='Inspect';button.setAttribute('aria-label',`Inspect ${event.journal==='operational'?'audit ':''}event ${event.body.sequence}`);button.onclick=()=>inspect(event);td.append(button);tr.append(td);$('events').append(tr);
    }
    if(!data.items.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=6;td.textContent='No events match these filters. Clear the filters or widen the date range.';tr.append(td);$('events').append(tr);}
    const first=data.total?(data.page-1)*data.pageSize+1:0,last=Math.min(data.page*data.pageSize,data.total);
    $('event-count').textContent=`Showing ${first}–${last} of ${data.total} matching events · newest first`;
    $('page-status').textContent=`Page ${data.page} of ${data.totalPages}`;
    $('previous-page').disabled=data.page<=1;$('next-page').disabled=data.page>=data.totalPages;
  }finally{if(version===eventRequest)$('event-list').setAttribute('aria-busy','false');}
}
async function refresh(){
  const status=await api('status');serverCapabilities=status.capabilities||{};
  $('status').textContent=`${status.events} journal events · Signer ${status.signerRevoked?'revoked':'active'}`;
  if($('protected').hidden)return;
  if(!serverCapabilities.evidenceUpload||!serverCapabilities.eventPagination)throw Error('The backend is running older code. Stop it with Ctrl+C, run npm start again, then refresh this page.');
  await loadEvents();
}
async function enter(me){csrf=me.csrf;$('login').hidden=true;$('dashboard').hidden=false;$('protected').hidden=me.role==='viewer';$('admin').hidden=me.role!=='admin';$('identity').textContent=me.username+' · '+me.role;await refresh();}
$('login').onsubmit=action(async()=>{const body=Object.fromEntries(new FormData($('login')));await enter(await api('login',body));$('login').reset();$('message').textContent='Signed in';});
$('logout').onclick=action(async()=>{await api('logout',{});location.reload();});
$('transaction').onsubmit=action(async()=>{const body=Object.fromEntries(new FormData($('transaction')));body.amount=Number(body.amount);body.requestId=crypto.randomUUID();const result=await api('transactions',body);inspect(result);$('message').textContent=result.body.data.decision+': '+result.body.data.reason;await refresh();});
$('settings').onsubmit=action(async()=>{if(!confirm('Change transaction limit?'))return;await api('settings',{amountLimit:Number(new FormData($('settings')).get('amountLimit'))});$('message').textContent='Limit updated';await refresh();});
$('revoke').onclick=action(async()=>{if(prompt('Revocation permanently stops new transactions. Security auditing continues. Type REVOKE to confirm.')!=='REVOKE')return;await api('revoke',{confirmation:'REVOKE'});await refresh();});
$('verify').onclick=action(async()=>{inspect(await api('verify',{}));await refresh();});
$('export').onclick=action(async()=>{const evidence=await api('export');const url=URL.createObjectURL(new Blob([JSON.stringify(evidence,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='evidence.json';a.click();URL.revokeObjectURL(url);await refresh();});
const issueMessages={
  CONTENT_ALTERED:'Signed content was changed. An amount, reference, or another signed field no longer matches its hash.',
  BAD_SIGNATURE:'The signature does not match this server’s trusted signing key.',
  BAD_TIMESTAMP:'The timestamp attestation is invalid or was changed.',
  CHAIN_BROKEN:'An event is missing, reordered, or linked to the wrong predecessor.',
  CLOCK_ANOMALY:'The event time is invalid, moves backwards, or is too far in the future.',
  BAD_CHECKPOINT:'The checkpoint signature is invalid.',
  CHECKPOINT_MISMATCH:'The event count or final hash does not match the signed checkpoint.',
  SIGNER_REVOKED:'The transaction signer has been revoked.',
  MALFORMED_EVENT:'The event is missing required evidence fields.',
  INVALID_EVIDENCE:'The file is not a supported evidence export, is too deeply nested, or exceeds the event limit.'
};
function showFileResult(result){
  $('file-result').hidden=false;
  $('file-verdict').textContent=result.valid?'Evidence verified':'Evidence verification failed';
  $('file-summary').textContent=result.valid
    ? `All checks passed for ${result.checked} transaction-journal events. Any included operational audit trail was also checked.`
    : `${result.issues.length} issue(s) found. The uploaded file has not changed the stored journal.`;
  $('file-issues').replaceChildren();
  for(const issue of result.issues){
    const li=document.createElement('li'),isAudit=issue.code.startsWith('AUDIT_'),code=isAudit?issue.code.slice(6):issue.code;
    const where=issue.sequence===undefined?'':` event ${issue.sequence}`;
    li.textContent=`${isAudit?'Operational audit':'Transaction journal'}${where}: ${issueMessages[code]||'The evidence failed an integrity check.'} (${issue.code})`;
    $('file-issues').append(li);
  }
  $('file-next').textContent=result.valid
    ? 'Retain the original export and trusted public keys separately. This result does not prove export freshness.'
    : 'Preserve the original and edited copies. Compare the flagged events. Keys from another journal also cause verification failures; use that journal’s separately trusted keys with the CLI.';
  $('file-technical').textContent=JSON.stringify(result,null,2);
}
$('evidence-file').onchange=()=>{$('file-result').hidden=true;$('message').textContent='';};
$('evidence-upload').onsubmit=action(async()=>{
  if(!serverCapabilities.evidenceUpload)throw Error('Restart the server with npm start, then refresh this page to enable evidence uploads.');
  const file=$('evidence-file').files[0];
  $('file-result').hidden=true;
  if(!file)throw Error('Choose an exported evidence JSON file first.');
  if(!/\.json$/i.test(file.name))throw Error('Choose a file with a .json extension.');
  if(file.size>2*1024*1024)throw Error('The evidence file exceeds 2 MiB. Use the independent CLI for larger exports.');
  const button=$('verify-file');$('evidence-file').disabled=true;button.disabled=true;button.textContent='Verifying evidence…';$('evidence-upload').setAttribute('aria-busy','true');
  $('message').textContent='Reading and verifying the selected evidence file…';
  try{
    let contents;
    try{contents=await file.text();JSON.parse(contents);}catch{throw Error('This file contains invalid JSON. Check its syntax and choose it again.');}
    const res=await fetch('/api/verify-evidence',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:contents});
    const result=await res.json();
    if(!res.ok){const messages={PAYLOAD_TOO_LARGE:'The evidence exceeds 2 MiB. Use the independent CLI for larger exports.',RATE_LIMIT:'Too many verification requests. Wait one minute and try again.',ACCESS_DENIED:'Sign in as an operator or administrator, then try again.',INVALID_JSON:'The file contains invalid JSON.'};throw Error(messages[result.error]||'Evidence verification could not complete. Try again or use the independent CLI.');}
    showFileResult(result);$('message').textContent=result.valid?'Selected evidence file verified.':'Selected evidence file failed verification. See the issues below.';
    await refresh();
  }finally{$('evidence-file').disabled=false;button.disabled=false;button.textContent='Verify evidence file';$('evidence-upload').setAttribute('aria-busy','false');}
});
$('event-filters').onsubmit=action(async()=>{eventPage=1;await loadEvents();});
$('clear-filters').onclick=action(async()=>{$('event-filters').reset();eventPage=1;await loadEvents();});
$('page-size').onchange=action(async()=>{eventPage=1;await loadEvents();});
$('previous-page').onclick=action(async()=>{if(eventPage>1){eventPage--;await loadEvents();}});
$('next-page').onclick=action(async()=>{if(eventPage<eventTotalPages){eventPage++;await loadEvents();}});
api('me').then(enter).catch(err=>{if(err.code!=='ACCESS_DENIED')$('message').textContent=err.message;});

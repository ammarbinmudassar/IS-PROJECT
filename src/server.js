import express from 'express';
import { getAbsoluteFSPath } from 'swagger-ui-dist';
import { spec } from './openapi.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { openStore, passwordValid, passwordHash } from './store.js';
import { transaction, verifyEvidenceUpload } from './security.js';
export function createApp(store=openStore()) {
  const app=express(), sessions=new Map();
  const dummy=passwordHash(randomBytes(24).toString('hex'));
  const error=(status,code)=>Object.assign(new Error(code),{status,code});
  app.disable('x-powered-by');
  app.use((req,res,next)=>{res.set({'Content-Security-Policy':"default-src 'self'; frame-ancestors 'none'; object-src 'none'",'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cache-Control':'no-store'});next();});
  app.get('/openapi.json', (req,res)=>res.json(spec));
  app.use('/docs', (req,res,next)=>{
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'");next();
  });
  app.use('/docs/assets', express.static(getAbsoluteFSPath(), {index:false}));
  const audit=(req,action,data={})=>{
    const append=store.setting().revoked ? store.appendAudit : store.append;
    append(req.user?.username||'anonymous',action,data);
    req.auditRecorded=true;
  };
  function throttle(limit,action) {
    const clients=new Map();
    return (req,res,next)=>{
      const now=Date.now();
      for (const [key,value] of clients) if(value.until<=now) clients.delete(key);
      for (const [token,session] of sessions) if(session.expires<=now) sessions.delete(token);
      let bucket=clients.get(req.ip);
      if(!bucket){bucket={count:0,until:now+60000};clients.set(req.ip,bucket);}
      if(++bucket.count<=limit)return next();
      // Record one summary per window, before rejecting subsequent requests without writes.
      if(bucket.count===limit+1)audit(req,action,{limit,windowSeconds:60});
      res.setHeader('Retry-After',String(Math.max(1,Math.ceil((bucket.until-now)/1000))));
      res.status(429).json({error:'RATE_LIMIT'});
    };
  }
  app.use('/api',(req,res,next)=>{req.apiRequest=true;next();},throttle(120,'API_RATE_LIMIT'));
  app.post('/api/login',throttle(10,'LOGIN_RATE_LIMIT'));
  const smallJson=express.json({limit:'16kb',strict:true});
  app.use('/api',(req,res,next)=>{
    // The larger file parser runs only after authentication, CSRF and role checks.
    if(req.method==='POST' && /^\/verify-evidence\/?$/i.test(req.path))return next();
    smallJson(req,res,next);
  });
  app.post('/api/login',(req,res)=>{
    const now=Date.now();
    const {username,password}=req.body||{};
    if(typeof username!=='string'||username.length>40||typeof password!=='string'||password.length>128)throw error(400,'INVALID_LOGIN');
    const u=store.db.prepare('SELECT * FROM users WHERE username=?').get(username);
    if(!passwordValid(password,u?.password||dummy)||!u){audit(req,'LOGIN_FAILED');throw error(401,'INVALID_LOGIN');}
    const token=randomBytes(32).toString('hex'), csrf=randomBytes(24).toString('hex');
    sessions.set(token,{id:u.id,username:u.username,role:u.role,csrf,expires:now+1800000});
    audit({user:u},'LOGIN');
    res.setHeader('Set-Cookie',`session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800${process.env.SECURE_COOKIE==='1'?'; Secure':''}`);
    res.json({username:u.username,role:u.role,csrf});
  });
  app.use('/api',(req,res,next)=>{
    const token=/\bsession=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie||'')?.[1];
    req.user=sessions.get(token);
    if(!req.user||req.user.expires<Date.now()){sessions.delete(token);audit(req,'ACCESS_DENIED');throw error(401,'ACCESS_DENIED');}
    if(req.method!=='GET' && req.headers['x-csrf-token']!==req.user.csrf){audit(req,'ACCESS_DENIED');throw error(403,'ACCESS_DENIED');}
    req.token=token;next();
  });
  const role=(...roles)=>(req,res,next)=>{if(!roles.includes(req.user.role)){audit(req,'ACCESS_DENIED');throw error(403,'ACCESS_DENIED');}next();};
  app.get('/api/me',(req,res)=>res.json({username:req.user.username,role:req.user.role,csrf:req.user.csrf}));
  app.post('/api/logout',(req,res)=>{audit(req,'LOGOUT');sessions.delete(req.token);res.setHeader('Set-Cookie','session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');res.json({ok:true});});
  app.get('/api/status',(req,res)=>res.json({events:store.countEvents(),signerRevoked:Boolean(store.setting().revoked),timestamp:'LOCAL_SIMULATION',capabilities:{evidenceUpload:true,eventPagination:true}}));
  app.get('/api/settings',role('admin','operator'),(req,res)=>res.json(store.setting()));
  app.post('/api/transactions',role('operator','admin'),(req,res)=>{
    const input=transaction(req.body);
    const e=store.atomic(()=>{
      if(store.db.prepare('SELECT 1 FROM requests WHERE request_id=?').get(input.requestId))throw error(409,'DUPLICATE_REQUEST');
      const rule=store.setting(), decision=input.amount<=rule.amountLimit?'ALLOWED':'DENIED';
      const event=store.append(req.user.username,'TRANSACTION',{id:randomUUID(),...input,decision,reason:decision==='ALLOWED'?'WITHIN_AMOUNT_LIMIT':'AMOUNT_LIMIT_EXCEEDED',rule:'MAX_AMOUNT',ruleVersion:rule.version,amountLimit:rule.amountLimit});
      store.db.prepare('INSERT INTO requests VALUES(?,?)').run(input.requestId,event.body.sequence);return event;
    });res.status(201).json(e);
  });
  app.get('/api/events',role('admin','operator'),(req,res)=>{
    const allowed=['page','pageSize','action','decision','actor','journal','q','from','to'];
    if(Object.keys(req.query).some(k=>!allowed.includes(k)) || Object.values(req.query).some(v=>typeof v!=='string'))throw error(400,'INVALID_FILTER');
    const filters={...req.query};
    const integer=(value,fallback,max)=>{if(value===undefined)return fallback;if(!/^[1-9][0-9]*$/.test(value)||Number(value)>max)throw error(400,'INVALID_FILTER');return Number(value);};
    filters.page=integer(filters.page,1,1000000);filters.pageSize=integer(filters.pageSize,10,100);
    if((filters.action && !/^[A-Z_0-9]{1,40}$/.test(filters.action)) || (filters.decision && !['ALLOWED','DENIED','RECORDED'].includes(filters.decision)) || (filters.journal && !['transaction','operational'].includes(filters.journal)) || (filters.actor?.length>40) || (filters.q?.length>120))throw error(400,'INVALID_FILTER');
    for(const key of ['from','to'])if(filters[key]){
      const value=filters[key];
      if(!/^\d{4}-\d{2}-\d{2}$/.test(value) || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString().slice(0,10)!==value)throw error(400,'INVALID_FILTER');
    }
    if(filters.from && filters.to && filters.from>filters.to)throw error(400,'INVALID_FILTER');
    if(filters.q)filters.q=filters.q.trim();
    res.json(store.queryEvents(filters));
  });
  app.get('/api/events/:sequence',role('admin','operator'),(req,res)=>{
    const e=store.events().find(e=>String(e.body.sequence)===req.params.sequence);if(!e)throw error(404,'NOT_FOUND');res.json(e);
  });
  app.post('/api/verify',role('admin','operator'),(req,res)=>{const r=store.health();audit(req,'VERIFICATION',{valid:r.valid,issues:r.issues});res.json(r);});
  app.post('/api/verify-evidence',role('admin','operator'),throttle(10,'EVIDENCE_RATE_LIMIT'),
    (req,res,next)=>{if(!req.is('application/json'))throw error(415,'JSON_REQUIRED');next();},
    express.json({limit:'2mb',strict:false}),(req,res)=>{
      const result=verifyEvidenceUpload(req.body,store.trust);
      if(store.setting().revoked && !result.issues.some(i=>i.code==='SIGNER_REVOKED')) {
        result.issues.push({code:'SIGNER_REVOKED'});result.valid=false;
      }
      // Never retain uploaded transaction data, filenames or caller-supplied keys.
      audit(req,'EVIDENCE_VERIFICATION',{valid:result.valid,checked:result.checked||0,issueCount:result.issues.length,issues:result.issues.slice(0,20)});
      res.json(result);
    });
  app.get('/api/export',role('admin','operator'),(req,res)=>{audit(req,'EXPORT');res.setHeader('Content-Disposition','attachment; filename="evidence.json"');res.json(store.bundle());});
  app.post('/api/settings',role('admin'),(req,res)=>{
    const n=req.body?.amountLimit;if(!Number.isSafeInteger(n)||n<1||n>100000000000)throw error(400,'INVALID_LIMIT');
    store.atomic(()=>{const old=store.setting();store.append(req.user.username,'CONFIG_CHANGED',{previous:old.amountLimit,amountLimit:n,version:old.version+1});store.db.prepare('UPDATE settings SET amount_limit=?,version=version+1 WHERE id=1').run(n);});res.json(store.setting());
  });
  app.post('/api/revoke',role('admin'),(req,res)=>{
    if(req.body?.confirmation!=='REVOKE')throw error(400,'CONFIRMATION_REQUIRED');
    store.atomic(()=>{store.append(req.user.username,'SIGNER_REVOKED',{reason:'Administrator revoked signer'});store.db.prepare('UPDATE settings SET revoked=1 WHERE id=1').run();});res.json({ok:true});
  });
  app.use('/api',(req,res)=>{throw error(404,'NOT_FOUND');});
  app.use(express.static(resolve(import.meta.dirname,'../public')));
  app.use((err,req,res,next)=>{
    const status=err.status||500, code=err.type==='entity.too.large'?'PAYLOAD_TOO_LARGE':err.type==='entity.parse.failed'?'INVALID_JSON':err.code||'INTERNAL_ERROR';
    try {if(req.apiRequest&&!req.auditRecorded)audit(req,'FAILURE',{code:status<500?code:'INTERNAL_ERROR',route:req.path,method:req.method});}catch{}
    res.status(status).json({error:status<500||['SIGNER_REVOKED','CLOCK_ANOMALY'].includes(code)?code:'INTERNAL_ERROR'});
  });
  return app;
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  const store=openStore();const health=store.health();
  if(health.issues.some(i=>i.code!=='SIGNER_REVOKED'))throw new Error('Journal integrity failed; restore a verified backup.');
  createApp(store).listen(Number(process.env.PORT||3000),'127.0.0.1',()=>console.log('Repudiation Resolver listening on loopback port '+(process.env.PORT||3000)));
}

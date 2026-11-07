const ref = name => ({ $ref: `#/components/schemas/${name}` });
const json = schema => ({ 'application/json': { schema } });
const response = (description, schema) => ({ description, ...(schema ? { content: json(schema) } : {}) });
const body = schema => ({ required: true, content: json(schema) });
const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required });
const string = { type: 'string' };
const integer = { type: 'integer' };
const limit = { type: 'integer', minimum: 1, maximum: 100000000000 };
const authenticated = [{ sessionCookie: [] }];
const mutation = [{ sessionCookie: [], csrfToken: [] }];
const errors = {
  400: response('Invalid input (INVALID_LOGIN, INVALID_TRANSACTION, INVALID_LIMIT, INVALID_JSON, INVALID_FILTER or CONFIRMATION_REQUIRED).', ref('Error')),
  401: response('Missing/expired session (ACCESS_DENIED) or invalid login (INVALID_LOGIN).', ref('Error')),
  403: response('Role or CSRF denial (ACCESS_DENIED).', ref('Error')),
  404: response('Record not found (NOT_FOUND).', ref('Error')),
  409: response('Request ID already used (DUPLICATE_REQUEST).', ref('Error')),
  413: response('JSON body exceeds its limit: 16 KiB normally, 2 MiB for /api/verify-evidence (PAYLOAD_TOO_LARGE).', ref('Error')),
  415: response('Uploaded evidence must use application/json (JSON_REQUIRED).', ref('Error')),
  429: response('Per IP: more than 120 API requests, ten login attempts, or ten evidence-file verifications per minute (RATE_LIMIT). Retry-After specifies the remaining wait.', ref('Error')),
  500: response('Safe internal failure (INTERNAL_ERROR). No stack traces are returned.', ref('Error')),
  503: response('Signer revoked or local clock moved backwards (SIGNER_REVOKED / CLOCK_ANOMALY).', ref('Error'))
};
function operation(summary, roles, schema, extra = {}, statuses = []) {
  return { summary, description: `Allowed roles: ${roles}.`, security: authenticated,
    responses: { 200: response('Success', schema), ...Object.fromEntries([401,403,500,...statuses].map(s => [s, errors[s]])) }, ...extra };
}
export const spec = {
  openapi: '3.0.3',
  info: {
    title: 'Repudiation Resolver API', version: '1.0.0',
    description: 'Local classroom transaction journal. Use POST /api/login first; the browser keeps the HttpOnly session cookie. Swagger automatically obtains X-CSRF-Token from /api/me for authenticated POST requests. Sessions expire after 30 minutes and on restart. Bodies are JSON, limited to 16 KiB except /api/verify-evidence (2 MiB). Amounts are integer minor units (100 PKR = PKR 1.00). Timestamps use a LOCAL_SIMULATION, not an external trusted authority. Exports contain synthetic references and actor names; do not enter sensitive data. Revocation permanently stops transaction-journal writes; a separate operational signer continues security auditing; use a disposable data directory when trying it. Independent verification requires separately trusted public keys and retained checkpoints. See docs/guide.txt for account creation, recovery and the offline CLI.'
  },
  servers: [{ url: '/', description: 'This local application' }],
  tags: [{name:'Authentication'},{name:'Journal'},{name:'Administration'}],
  paths: {
    '/api/login': { post: {
      summary: 'Sign in', tags: ['Authentication'], security: [],
      description: 'Accounts are created with the local initialization CLI. Passwords and CSRF tokens are not persisted by Swagger. The response sets an HttpOnly SameSite=Strict cookie. Ten attempts per IP per minute, including successful attempts.',
      requestBody: body(object({username:{type:'string',maxLength:40},password:{type:'string',format:'password',maxLength:128}})),
      responses: {200:{...response('Signed in',ref('Session')),headers:{'Set-Cookie':{description:'Browser-managed session cookie; not readable by JavaScript.',schema:string}}},...Object.fromEntries([400,401,413,429,500].map(s=>[s,errors[s]]))}
    } },
    '/api/me': { get: operation('Read current session','admin, operator, viewer',ref('Session'),{tags:['Authentication']}) },
    '/api/logout': { post: operation('Sign out','admin, operator, viewer',ref('Ok'),{tags:['Authentication'],security:mutation}) },
    '/api/status': { get: operation('Read aggregate status','admin, operator, viewer',ref('Status'),{tags:['Journal']}) },
    '/api/transactions': { post: {
      ...operation('Submit a transaction','admin, operator',ref('Event'),{tags:['Journal'],security:mutation,requestBody:body(ref('Transaction'))},[400,409,413,503]),
      description:'Allowed roles: admin, operator. Both ALLOWED and DENIED policy outcomes return HTTP 201 and signed evidence. Retry identifiers must be unique; duplicates return 409. The policy compares minor-unit amount to the currently configured limit.',
      responses:{201:response('Signed decision receipt',ref('Event')),...Object.fromEntries([400,401,403,409,413,500,503].map(s=>[s,errors[s]]))}
    } },
    '/api/events': { get: operation('List filtered event pages','admin, operator',ref('EventPage'),{tags:['Journal'],description:'Bounded newest-first history across both journals. Returns items plus page, pageSize, total and totalPages; action/actor options describe the complete history. Defaults to page 1 and 10 rows. Out-of-range pages clamp to the last page. Filters combine with AND. Search matches sequence, actor, action, reference, request ID and failure code. Dates are inclusive UTC calendar dates. Invalid/repeated/unknown query fields return INVALID_FILTER.',parameters:[
      {name:'page',in:'query',schema:{type:'integer',minimum:1,maximum:1000000,default:1}},
      {name:'pageSize',in:'query',schema:{type:'integer',minimum:1,maximum:100,default:10}},
      {name:'decision',in:'query',schema:{type:'string',enum:['ALLOWED','DENIED','RECORDED']}},
      {name:'action',in:'query',schema:{type:'string',maxLength:40},example:'TRANSACTION'},
      {name:'actor',in:'query',schema:{type:'string',maxLength:40}},
      {name:'journal',in:'query',schema:{type:'string',enum:['transaction','operational']}},
      {name:'q',in:'query',schema:{type:'string',maxLength:120}},
      {name:'from',in:'query',schema:{type:'string',format:'date'}},
      {name:'to',in:'query',schema:{type:'string',format:'date'}}
    ]},[400]) },
    '/api/events/{sequence}': { get: operation('Inspect dispute evidence','admin, operator',ref('Event'),{tags:['Journal'],parameters:[{name:'sequence',in:'path',required:true,schema:{type:'integer',minimum:1}}]},[404]) },
    '/api/verify': { post: operation('Verify the stored journal','admin, operator',ref('Verification'),{tags:['Journal'],security:mutation,description:'Allowed roles: admin, operator. Verifies the current stored journal; accepts no uploaded evidence. Findings return HTTP 200 with valid=false and issue codes. Offline verification of exported evidence uses the CLI. Verification is audited; after transaction-signer revocation, security actions use the separate operational audit trail.'}) },
    '/api/verify-evidence': { post: operation('Verify an uploaded evidence export','admin, operator',ref('Verification'),{tags:['Journal'],security:mutation,requestBody:body(ref('Evidence')),description:'Checks an exported JSON body against server-held public keys; uploaded keys are ignored. Authentication, role and CSRF checks run before the 2 MiB parser. Limits: 2,000 events per journal, nesting depth 32, ten verifications/IP/minute. Returns HTTP 200 with valid=false for unsupported/malformed evidence structure or failed integrity checks. Invalid JSON returns 400. Records a sanitized verification summary without retaining uploaded records. Current local signer revocation is enforced even for older exports. This does not prove freshness: use the independent CLI with a separately retained checkpoint for rollback checks.'},[400,413,415,429]) },
    '/api/export': { get: operation('Export journal and signed checkpoint','admin, operator',ref('Evidence'),{tags:['Journal'],description:'Allowed roles: admin, operator. Records an export event, then exports the transaction journal and separately signed operational audit trail. Response is an evidence.json attachment. The auditTrail is verified using the separately trusted auditSigner public key. The parent checkpoint binds its count and head. No passwords, session tokens or private keys are included. Export remains available after revocation.'}) },
    '/api/settings': {
      get: operation('Read transaction policy','admin, operator',ref('Settings'),{tags:['Administration']}),
      post: operation('Change the amount limit','admin',ref('Settings'),{tags:['Administration'],security:mutation,requestBody:body(object({amountLimit:limit})),description:'Admin only. The browser interface asks for confirmation; API callers must confirm intent themselves. Records old/new limits and advances the rule version.'},[400,413,503])
    },
    '/api/revoke': { post: operation('Permanently revoke the current signer','admin',ref('Ok'),{tags:['Administration'],security:mutation,requestBody:body(object({confirmation:{type:'string',enum:['REVOKE']}})),description:'Admin only. High impact: stops new transaction-journal writes. Security auditing continues under a separate operational key. Requires explicit REVOKE confirmation. There is no undo endpoint; preserve old evidence and initialize a separate journal for recovery. Historical signatures may remain mathematically valid while verification reports SIGNER_REVOKED.'},[400,413,503]) }
  },
  components: {
    securitySchemes: {
      sessionCookie:{type:'apiKey',in:'cookie',name:'session',description:'Obtained by POST /api/login. Browsers manage this HttpOnly cookie automatically; entering a cookie in Authorize cannot set it.'},
      csrfToken:{type:'apiKey',in:'header',name:'X-CSRF-Token',description:'Required on authenticated POST requests. Swagger obtains it automatically from /api/me; other clients use the csrf field returned by login or me.'}
    },
    schemas: {
      Error:object({error:string}), Ok:object({ok:{type:'boolean'}}),
      Session:object({username:string,role:{type:'string',enum:['admin','operator','viewer']},csrf:string}),
      Status:object({events:integer,signerRevoked:{type:'boolean'},timestamp:{type:'string',enum:['LOCAL_SIMULATION']},capabilities:object({evidenceUpload:{type:'boolean'},eventPagination:{type:'boolean'}})}),
      Settings:object({amountLimit:limit,version:integer,revoked:{type:'integer',enum:[0,1]}}),
      Transaction:{...object({amount:limit,currency:{type:'string',pattern:'^[A-Z]{3}$',example:'PKR'},reference:{type:'string',minLength:1,maxLength:100,example:'Classroom sample'},requestId:{type:'string',pattern:'^[a-zA-Z0-9_-]{8,80}$',example:'swagger-demo-001'}}),additionalProperties:false},
      EventData:{type:'object',additionalProperties:true,description:'Action-specific sanitized evidence. TRANSACTION contains UUID id, amount, currency, reference, requestId, decision (ALLOWED/DENIED), reason (WITHIN_AMOUNT_LIMIT/AMOUNT_LIMIT_EXCEEDED), rule MAX_AMOUNT, ruleVersion and amountLimit. Other actions record authentication, policy, export or revocation evidence.'},
      Event:object({body:object({sequence:integer,previous:string,time:{type:'string',format:'date-time'},actor:string,action:string,data:ref('EventData'),engine:{type:'string',example:'1'}}),hash:string,signature:{type:'string',description:'Base64 Ed25519 signature of the canonical JSON digest string.'},stamp:object({hash:string,time:{type:'string',format:'date-time'},authority:{type:'string',enum:['LOCAL_SIMULATION']}}),stampSignature:string}),
      EventPage:object({items:{type:'array',maxItems:100,items:{allOf:[ref('Event'),object({journal:{type:'string',enum:['transaction','operational']}})]}},page:integer,pageSize:integer,total:integer,totalPages:integer,actions:{type:'array',items:string},actors:{type:'array',items:string}}),
      Checkpoint:object({body:object({count:integer,head:string,auditCount:integer,auditHead:string},['count','head']),signature:string}),
      AuditTrail:object({format:{type:'string',enum:['repudiation-resolver/1']},events:{type:'array',items:ref('Event')},checkpoint:ref('Checkpoint')}),
      Evidence:object({format:{type:'string',enum:['repudiation-resolver/1']},events:{type:'array',items:ref('Event')},checkpoint:ref('Checkpoint'),auditTrail:ref('AuditTrail')}),
      Verification:object({valid:{type:'boolean'},issues:{type:'array',items:object({code:string,sequence:integer},['code'])},checked:integer},['valid','issues'])
    }
  }
};

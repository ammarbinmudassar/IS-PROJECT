import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { openStore, passwordHash } from '../src/store.js';
import { createApp } from '../src/server.js';

test('Swagger serves local docs and performs authenticated writes with CSRF', async () => {
  const dir=mkdtempSync(join(tmpdir(),'journal-docs-')), store=openStore(dir);
  store.db.prepare('INSERT INTO users(username,password,role) VALUES(?,?,?)').run('analyst',passwordHash('docs-test-password'),'operator');
  const server=createApp(store).listen(0,'127.0.0.1');
  await new Promise(resolve=>server.once('listening',resolve));
  const origin=`http://127.0.0.1:${server.address().port}`;
  try {
    const docs=await fetch(origin+'/docs/');
    assert.equal(docs.status,200);
    assert.match(await docs.text(),/swagger-ui-bundle.js/);
    assert(!docs.headers.get('content-security-policy').includes("script-src 'self' 'unsafe-inline'"));
    for (const path of ['/docs/assets/swagger-ui.css','/docs/assets/swagger-ui-bundle.js','/docs/init.js']) {
      const asset=await fetch(origin+path);assert.equal(asset.status,200);assert((await asset.text()).length>100);
    }
    const spec=await (await fetch(origin+'/openapi.json')).json();
    assert.equal(spec.openapi,'3.0.3');
    assert.equal(Object.values(spec.paths).reduce((n,p)=>n+Object.keys(p).length,0),13);
    assert.equal(spec.paths['/api/login'].post.security.length,0);
    assert.equal(spec.paths['/api/revoke'].post.requestBody.content['application/json'].schema.properties.confirmation.enum[0],'REVOKE');
    assert.equal((await fetch(origin+'/api/status')).status,401);
    const login=await fetch(origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'analyst',password:'docs-test-password'})});
    assert.equal(login.status,200);
    const cookie=login.headers.get('set-cookie').split(';')[0];
    const session=await login.json();
    let config;
    const window={addEventListener:(_,fn)=>fn()};
    runInNewContext(readFileSync(new URL('../public/docs/init.js',import.meta.url),'utf8'),{
      window, URL, location:{origin,href:origin+'/docs/'},
      SwaggerUIBundle: options=>{config=options;return {};},
      fetch:(path,options)=>fetch(new URL(path,origin),{...options,headers:{Cookie:cookie}})
    });
    assert.equal(config.validatorUrl,null);
    assert.equal(config.persistAuthorization,false);
    const request=await config.requestInterceptor({url:origin+'/api/transactions',method:'POST',headers:{'Content-Type':'application/json',Cookie:cookie}});
    assert.equal(request.headers['X-CSRF-Token'],session.csrf);
    const created=await fetch(request.url,{method:request.method,headers:request.headers,body:JSON.stringify({amount:100,currency:'PKR',reference:'Swagger test',requestId:'swagger-test-001'})});
    assert.equal(created.status,201);
    assert.equal((await created.json()).body.data.decision,'ALLOWED');
    const denied=await fetch(origin+'/api/settings',{method:'POST',headers:request.headers,body:JSON.stringify({amountLimit:1})});
    assert.equal(denied.status,403);
    const home=await fetch(origin+'/');
    assert(!home.headers.get('content-security-policy').includes('unsafe-inline'));
  } finally {
    await new Promise(resolve=>server.close(resolve));store.db.close();rmSync(dir,{recursive:true,force:true});
  }
});

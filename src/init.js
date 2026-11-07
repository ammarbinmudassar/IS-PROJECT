import { openStore, passwordHash } from './store.js';
const [username,role]=process.argv.slice(2);
const password=process.env.INIT_PASSWORD;
if (!/^[a-zA-Z0-9_-]{3,40}$/.test(username||'') || !['admin','operator','viewer'].includes(role) || !password || password.length<12 || password.length>128) {
  console.error('Usage: INIT_PASSWORD=<12–128 characters> npm run init -- username admin|operator|viewer');process.exit(1);
}
const s=openStore();
s.atomic(()=>{s.db.prepare('INSERT INTO users(username,password,role) VALUES(?,?,?)').run(username,passwordHash(password),role);s.append('local-admin','USER_CREATED',{username,role});});
s.db.close();console.log('User created.');

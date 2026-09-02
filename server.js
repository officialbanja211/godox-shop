const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || (!IS_PROD ? crypto.randomBytes(48).toString('hex') : '');
const COOKIE_SECURE = String(process.env.COOKIE_SECURE ?? (IS_PROD ? 'true' : 'false')).toLowerCase() === 'true';
const COOKIE_SAMESITE = String(process.env.COOKIE_SAMESITE || (IS_PROD ? 'none' : 'lax')).toLowerCase();
const FRONTEND_ORIGIN = String(process.env.FRONTEND_ORIGIN || '').replace(/\/$/, '');
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'godox.sqlite');
const AUTO_CONFIRM = String(process.env.DEV_AUTO_CONFIRM_PAYMENTS || 'false').toLowerCase() === 'true';

// MarzPay
const MARZPAY_BASE_URL = String(process.env.MARZPAY_BASE_URL || 'https://wallet.wearemarz.com/api/v1').replace(/\/$/, '');
const MARZPAY_API_KEY = process.env.MARZPAY_API_KEY || '';
const MARZPAY_API_SECRET = process.env.MARZPAY_API_SECRET || '';
const MARZPAY_CALLBACK_URL = String(process.env.MARZPAY_CALLBACK_URL || '').trim();
const MARZPAY_WEBHOOK_SECRET = process.env.MARZPAY_WEBHOOK_SECRET || '';
const MARZPAY_REQUIRE_SIGNATURE = String(process.env.MARZPAY_REQUIRE_WEBHOOK_SIGNATURE ?? (IS_PROD ? 'true' : 'false')).toLowerCase() === 'true';
const MARZPAY_TIMEOUT_MS = Number(process.env.MARZPAY_TIMEOUT_MS || 30000);
const MARZPAY_ENABLED = String(process.env.MARZPAY_ENABLED || 'false').toLowerCase() === 'true';
const MARZPAY_PAYOUTS_ENABLED = String(process.env.MARZPAY_PAYOUTS_ENABLED || 'false').toLowerCase() === 'true';

if (IS_PROD && (!JWT_SECRET || JWT_SECRET.length < 32)) throw new Error('JWT_SECRET must be at least 32 characters in production.');
if (IS_PROD && COOKIE_SECURE && COOKIE_SAMESITE !== 'none') throw new Error('For a Netlify frontend on another domain, COOKIE_SAMESITE must be none.');
if (IS_PROD && MARZPAY_ENABLED && (!MARZPAY_API_KEY || !MARZPAY_API_SECRET || !MARZPAY_CALLBACK_URL)) throw new Error('Production MarzPay requires API credentials and MARZPAY_CALLBACK_URL.');
if (IS_PROD && MARZPAY_ENABLED && MARZPAY_REQUIRE_SIGNATURE && !MARZPAY_WEBHOOK_SECRET) throw new Error('Production MarzPay webhook signing is required; set MARZPAY_WEBHOOK_SECRET.');

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');

const PRODUCTS = [
  {id:1,name:'Machine 1',price:20000,daily:5000,days:30},
  {id:2,name:'Machine 2',price:50000,daily:13000,days:30},
  {id:3,name:'Machine 3',price:100000,daily:28000,days:30},
  {id:4,name:'Machine 4',price:250000,daily:75000,days:30},
  {id:5,name:'Machine 5',price:500000,daily:160000,days:30}
];
const REG_BONUS=5000,CHECKIN_BONUS=500,WITHDRAWAL_MIN=5000,WITHDRAWAL_TAX=0.15,REF_RATES={1:.30,2:.15,3:.02};

function now(){return new Date().toISOString()}
function dayKey(){return new Date().toISOString().slice(0,10)}
function uuid(){return crypto.randomUUID()}
function id(prefix='TX'){return prefix+'-'+Date.now()+'-'+crypto.randomBytes(5).toString('hex').toUpperCase()}
function tel(v){return String(v||'').trim().replace(/\s+/g,'')}
function validTel(v){return /^0\d{9}$/.test(v)}
function toMarzPhone(v){const x=tel(v); return x.startsWith('0') ? '+256'+x.slice(1) : x.startsWith('+') ? x : '+'+x}
function stmt(sql){return db.prepare(sql)}
function hashPassword(p,salt=crypto.randomBytes(16).toString('hex')){return salt+':'+crypto.pbkdf2Sync(p,salt,180000,32,'sha256').toString('hex')}
function checkPassword(p,stored){const [salt,hash]=String(stored).split(':');if(!salt||!hash)return false;const actual=crypto.pbkdf2Sync(p,salt,180000,32,'sha256').toString('hex');return actual.length===hash.length&&crypto.timingSafeEqual(Buffer.from(actual),Buffer.from(hash))}
function b64(v){return Buffer.from(v).toString('base64url')}
function signJwt(payload){const h=b64(JSON.stringify({alg:'HS256',typ:'JWT'})),p=b64(JSON.stringify(payload));const s=b64(crypto.createHmac('sha256',JWT_SECRET).update(h+'.'+p).digest());return h+'.'+p+'.'+s}
function verifyJwt(token){const [h,p,s]=String(token||'').split('.');if(!h||!p||!s)throw Object.assign(Error('Invalid session.'),{status:401});const e=b64(crypto.createHmac('sha256',JWT_SECRET).update(h+'.'+p).digest());if(!crypto.timingSafeEqual(Buffer.from(e),Buffer.from(s)))throw Object.assign(Error('Invalid session.'),{status:401});const payload=JSON.parse(Buffer.from(p,'base64url').toString());if(payload.exp && Date.now()/1000>payload.exp)throw Object.assign(Error('Session expired.'),{status:401});return payload}
function appendCookie(res,value){const old=res.getHeader('Set-Cookie');res.setHeader('Set-Cookie',old?[...(Array.isArray(old)?old:[old]),value]:[value])}
function setCookie(res,name,value,maxAge){appendCookie(res,`${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=${COOKIE_SAMESITE}${COOKIE_SECURE?'; Secure':''}`)}
function clearCookie(res,name){appendCookie(res,`${name}=; Max-Age=0; Path=/; HttpOnly; SameSite=${COOKIE_SAMESITE}${COOKIE_SECURE?'; Secure':''}`)}
function csrfToken(){return crypto.randomBytes(32).toString('hex')}
function setCsrfCookie(res,value){const maxAge=value?86400:0;appendCookie(res,`godox_csrf=${value}; Max-Age=${maxAge}; Path=/; SameSite=${COOKIE_SAMESITE}${COOKIE_SECURE?'; Secure':''}`)}
function csrfOk(req){const h=String(req.headers['x-csrf-token']||'');const c=cookies(req).godox_csrf||'';return h.length===c.length&&h.length>0&&crypto.timingSafeEqual(Buffer.from(h),Buffer.from(c))}
function cookies(req){const out={};for(const x of String(req.headers.cookie||'').split(';')){const i=x.indexOf('=');if(i>0)out[x.slice(0,i).trim()]=x.slice(i+1).trim()}return out}
function currentUser(req){const token=cookies(req).godox_session;if(!token)throw Object.assign(Error('Please login first.'),{status:401});const p=verifyJwt(token);const u=stmt('SELECT * FROM users WHERE id=?').get(p.sub);if(!u)throw Object.assign(Error('Session expired. Please login again.'),{status:401});return u}
function safeUser(u){return {id:u.id,username:u.username,tel:u.tel,code:u.code,balance:+u.balance,deposited:+u.deposited,earned:+u.earned,refEarned:+u.ref_earned,withdrawn:+u.withdrawn,checkedIn:u.checked_in}}
function json(res,status,data){const body=JSON.stringify(data);res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Cache-Control','no-store');res.end(body)}
async function rawBody(req,max=64*1024){let s='';for await(const c of req){s+=c;if(Buffer.byteLength(s)>max)throw Object.assign(Error('Request body too large.'),{status:413})}return s}
async function body(req){const s=await rawBody(req);if(!s)return{};try{return JSON.parse(s)}catch{throw Object.assign(Error('Invalid JSON.'),{status:400})}}
function createCode(){let c;do{c='DG'+crypto.randomBytes(4).toString('hex').toUpperCase()}while(stmt('SELECT 1 FROM users WHERE code=?').get(c));return c}
function addLedger(uid,type,desc,amount,status='COMPLETED',reference=null){stmt('INSERT INTO ledger(user_id,type,description,amount,status,reference,created_at) VALUES(?,?,?,?,?,?,?)').run(uid,type,desc,amount,status,reference,now())}
function adjust(uid,delta){stmt('UPDATE users SET balance=balance+? WHERE id=?').run(delta,uid)}
function user(id){return stmt('SELECT * FROM users WHERE id=?').get(id)}

// Database

db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,tel TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,code TEXT UNIQUE NOT NULL,referred_by INTEGER REFERENCES users(id),balance INTEGER NOT NULL DEFAULT 0,deposited INTEGER NOT NULL DEFAULT 0,earned INTEGER NOT NULL DEFAULT 0,ref_earned INTEGER NOT NULL DEFAULT 0,withdrawn INTEGER NOT NULL DEFAULT 0,checked_in TEXT,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id),type TEXT NOT NULL,description TEXT NOT NULL,amount INTEGER NOT NULL,status TEXT NOT NULL,reference TEXT,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS purchases(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id),product_id INTEGER NOT NULL,name TEXT NOT NULL,price INTEGER NOT NULL,daily INTEGER NOT NULL,days INTEGER NOT NULL,start_day TEXT NOT NULL,earned_days INTEGER NOT NULL DEFAULT 0,earned_total INTEGER NOT NULL DEFAULT 0,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS daily_earnings(id INTEGER PRIMARY KEY AUTOINCREMENT,purchase_id INTEGER NOT NULL REFERENCES purchases(id),earning_day TEXT NOT NULL,amount INTEGER NOT NULL,UNIQUE(purchase_id,earning_day));
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id),product_id INTEGER NOT NULL,provider TEXT NOT NULL,phone TEXT NOT NULL,amount INTEGER NOT NULL,reference TEXT UNIQUE NOT NULL,provider_payment_id TEXT,status TEXT NOT NULL,created_at TEXT NOT NULL,confirmed_at TEXT);
CREATE TABLE IF NOT EXISTS withdrawals(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id),amount INTEGER NOT NULL,tax INTEGER NOT NULL,net INTEGER NOT NULL,phone TEXT NOT NULL,reference TEXT UNIQUE NOT NULL,provider_payment_id TEXT,status TEXT NOT NULL,created_at TEXT NOT NULL);`);

// Lightweight migration support for databases created by the previous build.
for (const sql of [
  "CREATE INDEX IF NOT EXISTS idx_ledger_user_created ON ledger(user_id,created_at)",
  "CREATE INDEX IF NOT EXISTS idx_payments_reference ON payments(reference)",
  "CREATE INDEX IF NOT EXISTS idx_withdrawals_reference ON withdrawals(reference)",
  "CREATE INDEX IF NOT EXISTS idx_daily_purchase_day ON daily_earnings(purchase_id,earning_day)"
]) db.exec(sql);

function accrue(uid){const ps=stmt('SELECT * FROM purchases WHERE user_id=? AND active=1').all(uid);const today=dayKey();for(const p of ps){let d=new Date(p.start_day+'T00:00:00Z');d.setUTCDate(d.getUTCDate()+1);let n=p.earned_days;while(d.toISOString().slice(0,10)<=today&&n<p.days){const k=d.toISOString().slice(0,10);if(!stmt('SELECT 1 FROM daily_earnings WHERE purchase_id=? AND earning_day=?').get(p.id,k)){stmt('INSERT INTO daily_earnings(purchase_id,earning_day,amount) VALUES(?,?,?)').run(p.id,k,p.daily);adjust(uid,p.daily);stmt('UPDATE users SET earned=earned+? WHERE id=?').run(p.daily,uid);addLedger(uid,'EARNING',`${p.name} daily earning`,p.daily,'COMPLETED',`EARN-${p.id}-${k}`);n++}d.setUTCDate(d.getUTCDate()+1)}stmt('UPDATE purchases SET earned_days=?,earned_total=?,active=? WHERE id=?').run(n,n*p.daily,n<p.days?1:0,p.id)}}
function referrals(uid){const out=[];const a=stmt('SELECT id,tel,created_at FROM users WHERE referred_by=?').all(uid);const ai=a.map(x=>x.id);const b=ai.length?stmt(`SELECT id,tel,created_at FROM users WHERE referred_by IN (${ai.map(()=>'?').join(',')})`).all(...ai):[];const bi=b.map(x=>x.id);const c=bi.length?stmt(`SELECT id,tel,created_at FROM users WHERE referred_by IN (${bi.map(()=>'?').join(',')})`).all(...bi):[];for(const [level,list] of [[1,a],[2,b],[3,c]])for(const r of list){const d=stmt("SELECT amount,created_at FROM payments WHERE user_id=? AND status='COMPLETED' ORDER BY id DESC LIMIT 1").get(r.id);out.push({tel:r.tel,level,deposit:d?+d.amount:0,date:d?d.created_at:r.created_at,bonus:d?Math.floor(d.amount*REF_RATES[level]):0})}return out.sort((x,y)=>String(y.date).localeCompare(String(x.date))).slice(0,50)}
function distribute(uid,amount,ref){let u=user(uid);for(let level=1;level<=3&&u?.referred_by;level++){const p=user(u.referred_by);if(!p)break;const bonus=Math.floor(amount*REF_RATES[level]);if(bonus){adjust(p.id,bonus);stmt('UPDATE users SET ref_earned=ref_earned+?,earned=earned+? WHERE id=?').run(bonus,bonus,p.id);addLedger(p.id,'REFERRAL',`Level ${level} referral bonus`,bonus,'COMPLETED',ref)}u=p}}
function dashboard(uid){accrue(uid);const u=user(uid);return {user:safeUser(u),purchases:stmt('SELECT id,product_id AS productId,name,price,daily,days,start_day AS startDay,earned_days AS earnedDays,earned_total AS earnedTotal,active FROM purchases WHERE user_id=? ORDER BY id DESC').all(uid),referrals:referrals(uid),ledger:stmt('SELECT type,description AS desc,amount,status,created_at AS date FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 30').all(uid)}}

function completePayment(pid,providerId){const p=stmt('SELECT * FROM payments WHERE id=?').get(pid);if(!p||p.status==='COMPLETED')return false;db.exec('BEGIN IMMEDIATE');try{const fresh=stmt('SELECT * FROM payments WHERE id=?').get(pid);if(!fresh||fresh.status==='COMPLETED'){db.exec('ROLLBACK');return false}stmt("UPDATE payments SET status='COMPLETED',provider_payment_id=?,confirmed_at=? WHERE id=?").run(providerId||'PROVIDER-CONFIRMED',now(),pid);adjust(fresh.user_id,fresh.amount);stmt('UPDATE users SET deposited=deposited+? WHERE id=?').run(fresh.amount,fresh.user_id);addLedger(fresh.user_id,'DEPOSIT','Confirmed MarzPay mobile-money deposit',fresh.amount,'COMPLETED',fresh.reference);distribute(fresh.user_id,fresh.amount,fresh.reference);db.exec('COMMIT');return true}catch(e){try{db.exec('ROLLBACK')}catch{}throw e}}
function failPayment(pid,status){const p=stmt('SELECT * FROM payments WHERE id=?').get(pid);if(!p||p.status==='COMPLETED')return;stmt('UPDATE payments SET status=? WHERE id=?').run(status,pid)}

async function marzRequest(endpoint,options={}){if(!MARZPAY_API_KEY||!MARZPAY_API_SECRET)throw Object.assign(Error('MarzPay credentials are not configured on the server.'),{status:503});const auth=Buffer.from(`${MARZPAY_API_KEY}:${MARZPAY_API_SECRET}`).toString('base64');const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),MARZPAY_TIMEOUT_MS);try{const r=await fetch(MARZPAY_BASE_URL+endpoint,{...options,headers:{Authorization:`Basic ${auth}`,'Content-Type':'application/json',Accept:'application/json',...(options.headers||{})},signal:controller.signal});const text=await r.text();let data={};try{data=JSON.parse(text)}catch{data={message:text}}if(!r.ok)throw Object.assign(Error(data.message||'MarzPay request failed.'),{status:r.status,provider:data});return data}finally{clearTimeout(timer)}}
function webhookSignatureValid(raw,req){if(!MARZPAY_WEBHOOK_SECRET)return false;const ts=String(req.headers['x-marzpay-timestamp']||'');const header=String(req.headers['x-marzpay-signature']||'');const m=header.match(/(?:^|,)v1=([a-f0-9]+)(?:,|$)/i);if(!ts||!m)return false;const age=Math.abs(Math.floor(Date.now()/1000)-Number(ts));if(!Number.isFinite(age)||age>300)return false;const expected=crypto.createHmac('sha256',MARZPAY_WEBHOOK_SECRET).update(`${ts}.${raw}`).digest('hex');const actual=m[1];return actual.length===expected.length&&crypto.timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(expected,'hex'))}
async function verifyMarzTransaction(reference,uuidHint){const id=uuidHint||reference;const data=await marzRequest('/transactions/'+encodeURIComponent(id));const tx=data?.transaction||{};return tx}

// In-memory rate limiter. Use a shared rate limiter at the edge/load balancer when horizontally scaling.
const buckets=new Map();
function rateLimit(req,key,limit,windowMs){const ip=(req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim();const k=key+':'+ip;const t=Date.now();let b=buckets.get(k);if(!b||t-b.start>=windowMs)b={start:t,count:0};b.count++;buckets.set(k,b);if(b.count>limit)throw Object.assign(Error('Too many requests. Please try again later.'),{status:429})}
setInterval(()=>{const cutoff=Date.now()-10*60*1000;for(const [k,b] of buckets)if(b.start<cutoff)buckets.delete(k)},5*60*1000).unref();

async function route(req,res){
  const u=new URL(req.url,'http://localhost');const p=u.pathname;const method=req.method;
  // Security headers.
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  const origin=req.headers.origin;
  if(origin && (!FRONTEND_ORIGIN || origin===FRONTEND_ORIGIN)){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');res.setHeader('Access-Control-Allow-Credentials','true');res.setHeader('Access-Control-Allow-Headers','Content-Type, X-CSRF-Token');res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS')}
  if(method==='OPTIONS'){res.statusCode=204;return res.end()}
  try{
    if(method==='GET'&&p==='/api/health')return json(res,200,{ok:true,time:now(),marzpay:{enabled:MARZPAY_ENABLED,payoutsEnabled:MARZPAY_PAYOUTS_ENABLED}});
    if(method==='POST'&&p==='/api/auth/register'){
      rateLimit(req,'register',10,15*60*1000);const b=await body(req),username=String(b.username||'').trim(),phone=tel(b.tel),password=String(b.password||''),code=String(b.referralCode||'').trim().toUpperCase();
      if(username.length<2||username.length>40)throw Object.assign(Error('Enter a valid username.'),{status:400});if(!validTel(phone))throw Object.assign(Error('Enter a valid 10-digit Ugandan telephone number.'),{status:400});if(password.length<8)throw Object.assign(Error('Password must be at least 8 characters.'),{status:400});if(stmt('SELECT 1 FROM users WHERE tel=?').get(phone))throw Object.assign(Error('That telephone number is already registered.'),{status:409});const parent=code?stmt('SELECT id FROM users WHERE code=?').get(code):null;if(code&&!parent)throw Object.assign(Error('Referral code not found.'),{status:400});
      const info=stmt('INSERT INTO users(username,tel,password_hash,code,referred_by,balance,created_at) VALUES(?,?,?,?,?,?,?)').run(username,phone,hashPassword(password),createCode(),parent?parent.id:null,REG_BONUS,now());addLedger(Number(info.lastInsertRowid),'BONUS','Registration bonus',REG_BONUS);const token=signJwt({sub:Number(info.lastInsertRowid),exp:Math.floor(Date.now()/1000)+7*86400,jti:uuid()});setCookie(res,'godox_session',token,7*86400);setCsrfCookie(res,csrfToken());return json(res,201,{message:'Account created successfully.'})
    }
    if(method==='POST'&&p==='/api/auth/login'){
      rateLimit(req,'login',15,15*60*1000);const b=await body(req),phone=tel(b.tel),password=String(b.password||''),u=stmt('SELECT * FROM users WHERE tel=?').get(phone);if(!u||!checkPassword(password,u.password_hash))throw Object.assign(Error('Incorrect telephone number or password.'),{status:401});setCookie(res,'godox_session',signJwt({sub:u.id,exp:Math.floor(Date.now()/1000)+7*86400,jti:uuid()}),7*86400);setCsrfCookie(res,csrfToken());return json(res,200,{message:'Login successful.'})
    }
    if(method==='POST'&&p==='/api/auth/logout'){clearCookie(res,'godox_session');setCsrfCookie(res,'');return json(res,200,{message:'Logged out.'})}
    const cu=currentUser(req);
    if(method==='GET'&&p==='/api/me'){const c=cookies(req).godox_csrf||csrfToken();if(!cookies(req).godox_csrf)setCsrfCookie(res,c);return json(res,200,{...dashboard(cu.id),csrfToken:c})}
    if(method==='GET'&&p==='/api/csrf'){const c=cookies(req).godox_csrf||csrfToken();if(!cookies(req).godox_csrf)setCsrfCookie(res,c);return json(res,200,{csrfToken:c})}
    if(method==='POST' && !p.startsWith('/api/marzpay/') && !p.endsWith('/webhook') && !csrfOk(req))throw Object.assign(Error('Invalid CSRF token.'),{status:403});
    if(method==='POST'&&p==='/api/checkin'){
      rateLimit(req,'checkin',20,60*60*1000);const u=user(cu.id);if(u.checked_in===dayKey())throw Object.assign(Error('You have already checked in today.'),{status:409});db.exec('BEGIN IMMEDIATE');try{const fresh=user(cu.id);if(fresh.checked_in===dayKey()){db.exec('ROLLBACK');throw Object.assign(Error('You have already checked in today.'),{status:409})}adjust(fresh.id,CHECKIN_BONUS);stmt('UPDATE users SET checked_in=? WHERE id=?').run(dayKey(),fresh.id);addLedger(fresh.id,'CHECKIN','Daily check-in bonus',CHECKIN_BONUS);db.exec('COMMIT')}catch(e){try{db.exec('ROLLBACK')}catch{}throw e}return json(res,200,dashboard(cu.id))
    }
    const pm=p.match(/^\/api\/products\/(\d+)\/purchase$/);if(method==='POST'&&pm){
      rateLimit(req,'purchase',20,60*60*1000);const product=PRODUCTS.find(x=>x.id===Number(pm[1]));if(!product)throw Object.assign(Error('Product not found.'),{status:404});accrue(cu.id);db.exec('BEGIN IMMEDIATE');try{const u=user(cu.id);if(u.balance<product.price)throw Object.assign(Error(`Insufficient balance. You need UGX ${product.price.toLocaleString('en-UG')}.`),{status:400});adjust(u.id,-product.price);const info=stmt('INSERT INTO purchases(user_id,product_id,name,price,daily,days,start_day,created_at) VALUES(?,?,?,?,?,?,?,?)').run(u.id,product.id,product.name,product.price,product.daily,product.days,dayKey(),now());addLedger(u.id,'PURCHASE',`${product.name} purchased`,-product.price,'COMPLETED',`PUR-${info.lastInsertRowid}`);db.exec('COMMIT')}catch(e){try{db.exec('ROLLBACK')}catch{}throw e}return json(res,200,dashboard(cu.id))}

    if(method==='POST'&&p==='/api/payments/request'){
      rateLimit(req,'payment',10,10*60*1000);if(!MARZPAY_ENABLED && !AUTO_CONFIRM)throw Object.assign(Error('MarzPay payments are not enabled on this server yet.'),{status:503});
      const b=await body(req),phone=tel(b.phone),amount=Number(b.amount),productId=Number(b.productId),product=PRODUCTS.find(x=>x.id===productId);if(!validTel(phone))throw Object.assign(Error('Enter a valid 10-digit telephone number.'),{status:400});if(!product||amount!==product.price)throw Object.assign(Error('Invalid product amount.'),{status:400});
      const reference=uuid();const info=stmt('INSERT INTO payments(user_id,product_id,provider,phone,amount,reference,status,created_at) VALUES(?,?,?,?,?,?,?,?)').run(cu.id,product.id,'MOBILE_MONEY',phone,amount,reference,'PENDING',now());const paymentId=Number(info.lastInsertRowid);
      if(AUTO_CONFIRM){completePayment(paymentId,'DEV-AUTO-CONFIRM');return json(res,200,{message:'Development payment confirmed.',paymentId:reference,status:'COMPLETED',dashboard:dashboard(cu.id)})}
      if(!MARZPAY_CALLBACK_URL) {stmt("UPDATE payments SET status='FAILED' WHERE id=?").run(paymentId);throw Object.assign(Error('MARZPAY_CALLBACK_URL is not configured.'),{status:503})}
      try{
        const result=await marzRequest('/collect-money',{method:'POST',body:JSON.stringify({amount,phone_number:toMarzPhone(phone),country:'UG',method:'mobile_money',reference,description:`GODOX-SHOP ${product.name}`,callback_url:MARZPAY_CALLBACK_URL,metadata:[{paymentId:String(paymentId)}]})});
        const tx=result?.data?.transaction||{};const providerId=tx.uuid||null;stmt('UPDATE payments SET provider_payment_id=? WHERE id=?').run(providerId,paymentId);
        return json(res,202,{message:'Payment request sent. Approve the mobile-money prompt; your balance will update only after MarzPay confirms the transaction.',paymentId:reference,status:tx.status||'PROCESSING'})
      }catch(e){stmt("UPDATE payments SET status='FAILED' WHERE id=?").run(paymentId);throw Object.assign(Error(e.message||'Unable to start MarzPay payment.'),{status:e.status>=400&&e.status<600?e.status:502})}
    }

    const psm=p.match(/^\/api\/payments\/([^/]+)\/status$/);
    if(method==='GET'&&psm){
      const reference=decodeURIComponent(psm[1]);
      const pay=stmt('SELECT id,product_id,amount,reference,status,provider_payment_id,created_at,confirmed_at FROM payments WHERE reference=? AND user_id=?').get(reference,cu.id);
      if(!pay)throw Object.assign(Error('Payment not found.'),{status:404});
      return json(res,200,{payment:pay,dashboard:pay.status==='COMPLETED'?dashboard(cu.id):undefined});
    }

    if(method==='POST'&&p==='/api/marzpay/webhook'){
      rateLimit(req,'marzpay-webhook',240,60*1000);const raw=await rawBody(req);if(MARZPAY_REQUIRE_SIGNATURE&&!webhookSignatureValid(raw,req))throw Object.assign(Error('Invalid MarzPay webhook signature.'),{status:401});let b;try{b=JSON.parse(raw)}catch{throw Object.assign(Error('Invalid webhook JSON.'),{status:400})}
      const tx=b?.transaction||{}, collection=b?.collection||{}, dis=b?.disbursement||{};const reference=String(tx.reference||b.reference||'').trim();const event=String(b?.event_type||'').toLowerCase();if(!reference)return json(res,200,{ok:true,ignored:true});
      if(event.startsWith('disbursement.') || stmt('SELECT 1 FROM withdrawals WHERE reference=?').get(reference)){
        const w=stmt('SELECT * FROM withdrawals WHERE reference=?').get(reference);if(!w)return json(res,200,{ok:true,ignored:true});const status=String(tx.status||b.status||'').toLowerCase();
        if(['completed','successful','paid','success'].includes(status)){const verified=await verifyMarzTransaction(reference,tx.uuid);if(!['completed','successful','paid','success'].includes(String(verified?.status||'').toLowerCase()))throw Object.assign(Error('MarzPay payout is not confirmed.'),{status:409});if(Number(verified?.amount?.raw)!==w.net)throw Object.assign(Error('MarzPay payout amount mismatch.'),{status:400});db.exec('BEGIN IMMEDIATE');try{const fresh=stmt('SELECT * FROM withdrawals WHERE id=?').get(w.id);if(fresh&&fresh.status!=='SUCCESS'){stmt("UPDATE withdrawals SET status='SUCCESS',provider_payment_id=? WHERE id=?").run(dis?.provider_transaction_id||tx.uuid||fresh.provider_payment_id,w.id);stmt('UPDATE users SET withdrawn=withdrawn+? WHERE id=?').run(fresh.net,fresh.user_id);stmt("UPDATE ledger SET status='COMPLETED',description='Withdrawal paid by MarzPay' WHERE reference=? AND type='WITHDRAWAL'").run(reference)}db.exec('COMMIT')}catch(e){try{db.exec('ROLLBACK')}catch{}throw e}}
        else if(['failed','cancelled','expired'].includes(status)){db.exec('BEGIN IMMEDIATE');try{const fresh=stmt('SELECT * FROM withdrawals WHERE id=?').get(w.id);if(fresh&&fresh.status!=='SUCCESS'&&fresh.status!=='FAILED'){stmt("UPDATE withdrawals SET status='FAILED' WHERE id=?").run(w.id);adjust(fresh.user_id,fresh.amount);stmt("UPDATE ledger SET status='FAILED' WHERE reference=? AND type='WITHDRAWAL'").run(reference);addLedger(fresh.user_id,'WITHDRAWAL_REVERSAL','MarzPay payout failed; amount returned',fresh.amount,'COMPLETED',reference)}db.exec('COMMIT')}catch(e){try{db.exec('ROLLBACK')}catch{}throw e}}
        return json(res,200,{ok:true});
      }
      const pay=stmt('SELECT * FROM payments WHERE reference=?').get(reference);if(!pay)return json(res,200,{ok:true,ignored:true});const status=String(tx.status||b.status||'').toLowerCase();
      if(['completed','successful','paid','success'].includes(status)){const verified=await verifyMarzTransaction(reference,tx.uuid);const verifiedStatus=String(verified?.status||'').toLowerCase();const verifiedAmount=Number(verified?.amount?.raw);const verifiedPhone=tel(verified?.phone_number||collection?.phone_number||'');if(!['completed','successful','paid','success'].includes(verifiedStatus))throw Object.assign(Error('MarzPay transaction is not confirmed.'),{status:409});if(verifiedAmount!==pay.amount)throw Object.assign(Error('MarzPay amount mismatch.'),{status:400});if(verifiedPhone&&verifiedPhone!==toMarzPhone(pay.phone)&&verifiedPhone!==pay.phone)throw Object.assign(Error('MarzPay phone mismatch.'),{status:400});completePayment(pay.id,collection?.provider_transaction_id||tx.uuid||'PROVIDER-CONFIRMED')}
      else if(['failed','cancelled','expired'].includes(status))failPayment(pay.id,status.toUpperCase());
      return json(res,200,{ok:true});
    }

    if(method==='POST'&&p==='/api/withdrawals'){
      rateLimit(req,'withdrawal',5,60*60*1000);if(!MARZPAY_PAYOUTS_ENABLED)throw Object.assign(Error('Withdrawals are not enabled for automatic MarzPay payout yet.'),{status:503});if(!MARZPAY_CALLBACK_URL)throw Object.assign(Error('MARZPAY_CALLBACK_URL is not configured.'),{status:503});
      const b=await body(req),amount=Math.floor(Number(b.amount));if(!Number.isFinite(amount)||amount<WITHDRAWAL_MIN)throw Object.assign(Error('Minimum withdrawal is UGX 5,000.'),{status:400});accrue(cu.id);const u=user(cu.id),active=stmt('SELECT 1 FROM purchases WHERE user_id=? AND active=1 LIMIT 1').get(u.id);if(!active)throw Object.assign(Error('Withdrawal is available only after purchasing an active product.'),{status:403});if(amount>u.balance)throw Object.assign(Error('Insufficient available balance.'),{status:400});
      const tax=Math.floor(amount*WITHDRAWAL_TAX),net=amount-tax,reference=uuid();let wid;
      db.exec('BEGIN IMMEDIATE');try{const fresh=user(cu.id);if(amount>fresh.balance){db.exec('ROLLBACK');throw Object.assign(Error('Insufficient available balance.'),{status:400})}const info=stmt('INSERT INTO withdrawals(user_id,amount,tax,net,phone,reference,status,created_at) VALUES(?,?,?,?,?,?,?,?)').run(fresh.id,amount,tax,net,fresh.tel,reference,'PENDING',now());wid=Number(info.lastInsertRowid);adjust(fresh.id,-amount);addLedger(fresh.id,'WITHDRAWAL','Withdrawal request (processing)',-amount,'PENDING',reference);db.exec('COMMIT')}catch(e){try{db.exec('ROLLBACK')}catch{}throw e}
      try{
        const result=await marzRequest('/send-money',{method:'POST',body:JSON.stringify({amount:net,phone_number:toMarzPhone(u.tel),country:'UG',reference,description:`GODOX-SHOP withdrawal ${reference}`,callback_url:MARZPAY_CALLBACK_URL,metadata:[{withdrawalId:String(wid)}]})});
        const tx=result?.data?.transaction||{};stmt("UPDATE withdrawals SET status='PROCESSING',provider_payment_id=? WHERE id=?").run(tx.uuid||null,wid);stmt("UPDATE ledger SET status='PROCESSING' WHERE reference=? AND type='WITHDRAWAL'").run(reference);return json(res,202,{message:'Withdrawal sent to MarzPay for processing.',tax,net,reference,dashboard:dashboard(cu.id),withdrawalId:wid,status:'PROCESSING'})
      }catch(e){db.exec('BEGIN IMMEDIATE');try{const w=stmt('SELECT * FROM withdrawals WHERE id=?').get(wid);if(w&&w.status!=='SUCCESS'){stmt("UPDATE withdrawals SET status='FAILED' WHERE id=?").run(wid);adjust(w.user_id,w.amount);addLedger(w.user_id,'WITHDRAWAL_REVERSAL','Withdrawal payout failed; amount returned',w.amount,'COMPLETED',reference)}db.exec('COMMIT')}catch(x){try{db.exec('ROLLBACK')}catch{}console.error('Withdrawal rollback failed',x)}throw Object.assign(Error(e.message||'Unable to start MarzPay payout.'),{status:e.status>=400&&e.status<600?e.status:502})}
    }

    if(method==='POST'&&p==='/api/withdrawals/webhook'){
      rateLimit(req,'payout-webhook',120,60*1000);const raw=await rawBody(req);if(MARZPAY_REQUIRE_SIGNATURE&&!webhookSignatureValid(raw,req))throw Object.assign(Error('Invalid MarzPay webhook signature.'),{status:401});let b;try{b=JSON.parse(raw)}catch{throw Object.assign(Error('Invalid webhook JSON.'),{status:400})};const tx=b?.transaction||{};const dis=b?.disbursement||{};const reference=String(tx.reference||b.reference||'').trim();if(!reference)return json(res,200,{ok:true,ignored:true});const w=stmt('SELECT * FROM withdrawals WHERE reference=?').get(reference);if(!w)return json(res,200,{ok:true,ignored:true});const status=String(tx.status||b.status||'').toLowerCase();
      if(['completed','successful','paid','success'].includes(status)){const verified=await verifyMarzTransaction(reference,tx.uuid);if(!['completed','successful','paid','success'].includes(String(verified?.status||'').toLowerCase()))throw Object.assign(Error('MarzPay payout is not confirmed.'),{status:409});if(Number(verified?.amount?.raw)!==w.net)throw Object.assign(Error('MarzPay payout amount mismatch.'),{status:400});db.exec('BEGIN IMMEDIATE');try{const fresh=stmt('SELECT * FROM withdrawals WHERE id=?').get(w.id);if(fresh&&fresh.status!=='SUCCESS'){stmt("UPDATE withdrawals SET status='SUCCESS',provider_payment_id=? WHERE id=?").run(dis?.provider_transaction_id||tx.uuid||fresh.provider_payment_id,w.id);stmt('UPDATE users SET withdrawn=withdrawn+? WHERE id=?').run(fresh.net,fresh.user_id);stmt("UPDATE ledger SET status='COMPLETED',description='Withdrawal paid by MarzPay' WHERE reference=? AND type='WITHDRAWAL'").run(reference)}db.exec('COMMIT')}catch(e){try{db.exec('ROLLBACK')}catch{}throw e}}
      else if(['failed','cancelled','expired'].includes(status)){db.exec('BEGIN IMMEDIATE');try{const fresh=stmt('SELECT * FROM withdrawals WHERE id=?').get(w.id);if(fresh&&fresh.status!=='SUCCESS'&&fresh.status!=='FAILED'){stmt("UPDATE withdrawals SET status='FAILED' WHERE id=?").run(w.id);adjust(fresh.user_id,fresh.amount);stmt("UPDATE ledger SET status='FAILED' WHERE reference=? AND type='WITHDRAWAL'").run(reference);addLedger(fresh.user_id,'WITHDRAWAL_REVERSAL','MarzPay payout failed; amount returned',fresh.amount,'COMPLETED',reference)}db.exec('COMMIT')}catch(e){try{db.exec('ROLLBACK')}catch{}throw e}}
      return json(res,200,{ok:true})
    }

    if(method==='GET'&&!p.startsWith('/api/'))return serveIndex(res);
    return json(res,404,{message:'Not found.'});
  }catch(e){console.error(e);return json(res,e.status||500,{message:e.message||'Server error.'})}
}
function serveIndex(res){const file=path.join(__dirname,'public','index.html');res.statusCode=200;res.setHeader('Content-Type','text/html; charset=utf-8');res.setHeader('Cache-Control','no-store');res.end(fs.readFileSync(file))}
const server=http.createServer(route);server.requestTimeout=35000;server.headersTimeout=40000;server.listen(PORT,()=>console.log(`GODOX-SHOP backend listening on ${PORT}`));

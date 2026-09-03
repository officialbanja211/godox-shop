import { parentPort } from 'node:worker_threads';
import { createClient } from '@libsql/client';

const client = createClient({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN });
let port=null;
let tx=null;

function splitSql(sql) {
  const out=[]; let start=0; let quote=null;
  for(let i=0;i<sql.length;i++){ const c=sql[i]; if(quote){ if(c===quote){ if(sql[i+1]===quote){i++;} else quote=null;} } else if(c==="'"||c==='"'||c==='`'){quote=c;} else if(c===';'){ const s=sql.slice(start,i).trim(); if(s)out.push(s); start=i+1; } }
  const s=sql.slice(start).trim(); if(s)out.push(s); return out;
}
function args(params){ return params ?? []; }
function target(){ return tx || client; }
async function execOne(sql, params=[]) {
  const r=await target().execute({sql, args:args(params)});
  return { rows:r.rows, rowsAffected:Number(r.rowsAffected||0), lastInsertRowid:r.lastInsertRowid==null?undefined:Number(r.lastInsertRowid) };
}

async function handle(m){
  try {
    if(m.op==='get'){ const r=await execOne(m.sql,m.params); return r.rows[0]||undefined; }
    if(m.op==='all'){ const r=await execOne(m.sql,m.params); return r.rows; }
    if(m.op==='run'){ const r=await execOne(m.sql,m.params); return { changes:r.rowsAffected, lastInsertRowid:r.lastInsertRowid }; }
    if(m.op==='exec'){
      for(const s of splitSql(m.sql)){
        const u=s.replace(/^\s+|\s+$/g,'').toUpperCase();
        if(u==='BEGIN' || u==='BEGIN TRANSACTION' || u==='BEGIN IMMEDIATE'){ if(!tx) tx=await client.transaction('write'); continue; }
        if(u==='COMMIT'){ if(tx){await tx.commit();tx=null;} continue; }
        if(u==='ROLLBACK'){ if(tx){await tx.rollback();tx=null;} continue; }
        await execOne(s);
      }
      return undefined;
    }
    if(m.op==='close'){ if(tx){await tx.rollback();tx=null;} client.close(); return undefined; }
    throw new Error('Unknown database operation: '+m.op);
  } catch(e){ if(m.op==='exec' && tx && /^(COMMIT|ROLLBACK)/i.test(String(m.sql).trim())===false){} throw e; }
}

parentPort.on('message', async (m)=>{
  if(m.type==='connect'){ port=m.port; port.on('message', async msg=>{ try { const result=await handle(msg); port.postMessage({id:msg.id,ok:true,result}); } catch(e){ port.postMessage({id:msg.id,ok:false,error:{message:e.message,stack:e.stack}}); } }); port.start(); }
});

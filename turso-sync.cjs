const { Worker, MessageChannel, receiveMessageOnPort } = require('node:worker_threads');
const { receiveMessageOnPort: recv } = require('node:worker_threads');
const originalSqlite = process.getBuiltinModule('node:sqlite');
const path = require('node:path');

function normalize(v) {
  if (typeof v === 'bigint') return Number(v);
  if (Array.isArray(v)) return v.map(normalize);
  if (v && typeof v === 'object') { const o={}; for (const [k,x] of Object.entries(v)) o[k]=normalize(x); return o; }
  return v;
}

class RemoteStatement {
  constructor(db, sql) { this.db=db; this.sql=sql; }
  get(...params) { return this.db._call('get', this.sql, params).result; }
  all(...params) { return this.db._call('all', this.sql, params).result; }
  run(...params) { return this.db._call('run', this.sql, params).result; }
}

class RemoteDatabaseSync {
  constructor() {
    this.worker = new Worker(path.join(__dirname, 'turso-worker.mjs'));
    const { port1, port2 } = new MessageChannel();
    this.port = port1;
    this.worker.postMessage({ type:'connect', port:port2 }, [port2]);
    this.nextId=1;
  }
  _call(op, sql, params=[]) {
    const id=this.nextId++;
    this.port.postMessage({id,op,sql,params});
    while (true) {
      const msg=receiveMessageOnPort(this.port);
      if (!msg) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10); continue; }
      if (msg.message.id !== id) continue;
      const m=msg.message;
      if (!m.ok) { const e=new Error(m.error?.message||'Turso database error'); if(m.error?.stack)e.stack=m.error.stack; throw e; }
      return {result:normalize(m.result)};
    }
  }
  prepare(sql) { return new RemoteStatement(this, sql); }
  exec(sql) { return this._call('exec', sql, []).result; }
  close() { try { this._call('close'); } finally { this.worker.terminate(); } }
}

function createDatabaseSync(file) {
  if (process.env.TURSO_DATABASE_URL && process.env.TURSO_AUTH_TOKEN) return new RemoteDatabaseSync();
  return new originalSqlite.DatabaseSync(file);
}

module.exports = { DatabaseSync: createDatabaseSync };

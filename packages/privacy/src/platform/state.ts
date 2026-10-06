/** Durable local control state. One SQLite database shared by processes on ONE host. DELETE journal is the default.
 * Do not put a WAL database on NFS, or interpret this as a multi-node HA service.
 * All public handles are tenant-scoped; the factory and keyring are trusted server APIs. */
import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, createHmac, randomBytes, createHash } from 'node:crypto';
import { constants, lstatSync, openSync, closeSync, chmodSync, realpathSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { canonical, id, integer, frozen, deny, hash, equalHex } from '../enterprise/util.js';
import { parseJsonStrict } from '../json.js';
export interface TenantKey { readonly id:string; readonly key:Uint8Array; }
export interface Keyring {readonly active:string;readonly keys:readonly TenantKey[];}
export interface Cell<T=unknown> {readonly value:T;readonly version:number;readonly expiresAt:number|null;}
export interface StateAnchor {readonly tenantId:string;readonly sequence:number;readonly head:string;readonly keyId:string;readonly auth:string;}
export interface StateEvent {readonly tenantId:string;readonly sequence:number;readonly at:number;readonly kind:string;readonly actorRef:string;readonly resourceRef:string;readonly previous:string;readonly keyId:string;readonly digest:string;readonly auth:string;}
interface KeySet {active:string;keys:Map<string,Buffer>;}
function digest(b:Uint8Array):string{return createHash('sha256').update(b).digest('hex');}
function checkKey(k:TenantKey):Buffer{id(k.id);if(!(k.key instanceof Uint8Array)||k.key.length!==32)deny('STATE_KEY_INVALID');return Buffer.from(k.key);}
const MAX_VALUE=1048576;
/** POSIX mode bits do not represent Windows ACLs. Check the native discretionary ACL. */
function assertPrivateAccess(path:string):void{
  if(process.platform!=='win32'){if((lstatSync(path).mode&0o077)!==0)deny('STATE_DIRECTORY_PERMISSIONS');return;}
  const script=`$ErrorActionPreference='Stop'; $path='${path.replace(/'/g,"''")}'; $acl=if([System.IO.Directory]::Exists($path)){[System.IO.Directory]::GetAccessControl($path)}else{[System.IO.File]::GetAccessControl($path)}; $allowed=@([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544'); if($allowed -notcontains $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value){exit 2}; $rules=@($acl.Access); if($rules.Count -eq 0){exit 2}; foreach($rule in $rules){if($rule.AccessControlType -eq 'Allow' -and $allowed -notcontains $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value){exit 2}}`;
  try{execFileSync(join(process.env.SystemRoot??'C:\\Windows','System32','WindowsPowerShell','v1.0','powershell.exe'),['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{stdio:'ignore',windowsHide:true,timeout:15000});}catch{deny('STATE_DIRECTORY_PERMISSIONS');}
}
export class SqliteControlStore {
  #db:DatabaseSync;#keys=new Map<string,KeySet>();#inTransaction=false;#closed=false;
  constructor(readonly path:string,tenants:ReadonlyMap<string,Keyring>,options:{requirePrivateDirectory?:boolean;journalMode?:'delete'|'wal'}={}){
    if(path!==':memory:'){
      const abs=resolve(path),parent=realpathSync(dirname(abs));
      if(parent!==dirname(abs))deny('STATE_PATH_SYMLINK');
      const dir=lstatSync(parent);
      if(!dir.isDirectory())deny('STATE_DIRECTORY_PERMISSIONS');if(options.requirePrivateDirectory!==false)assertPrivateAccess(parent);
      const fd=openSync(abs,constants.O_RDWR|constants.O_CREAT|constants.O_NOFOLLOW,0o600);closeSync(fd);
      const st=lstatSync(abs);if(!st.isFile()||st.nlink!==1||st.isSymbolicLink())deny('STATE_FILE_UNSAFE');assertPrivateAccess(abs);
      for(const suffix of ['-wal','-shm','-journal']){try{const s=lstatSync(abs+suffix);if(!s.isFile()||s.isSymbolicLink())deny('STATE_SIDECAR_UNSAFE');}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}}
    }
    for(const [tenant,ring]of tenants){id(tenant);id(ring.active);const keys=new Map<string,Buffer>();for(const k of ring.keys){if(keys.has(k.id))deny('STATE_KEY_DUPLICATE');keys.set(k.id,checkKey(k));}if(!keys.has(ring.active)||keys.size>16)deny('STATE_KEY_INVALID');this.#keys.set(tenant,{active:ring.active,keys});}
    if(!this.#keys.size)deny('STATE_TENANTS_REQUIRED');
    this.#db=new DatabaseSync(path,{enableForeignKeyConstraints:true,enableDoubleQuotedStringLiterals:false,allowExtension:false});
    // Competing processes can hold the schema lock before our first query.
    this.#db.exec('PRAGMA busy_timeout=10000');
    const version=String(this.#db.prepare('SELECT sqlite_version() AS v').get()?.v),parts=version.split('.').map(Number);const fixed=(parts[0]??0)>3||(parts[0]===3&&((parts[1]??0)>51||parts[1]===51&&(parts[2]??0)>=3||parts[1]===50&&(parts[2]??0)>=7||parts[1]===44&&(parts[2]??0)>=6));if(options.journalMode==='wal'&&!fixed){this.#db.close();deny('STATE_SQLITE_WAL_VERSION');}
    this.#db.exec(`PRAGMA journal_mode=${options.journalMode==='wal'?'WAL':'DELETE'}; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA trusted_schema=OFF;
      CREATE TABLE IF NOT EXISTS control_meta(version INTEGER NOT NULL); INSERT INTO control_meta SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM control_meta);
      CREATE TABLE IF NOT EXISTS cells(tenant TEXT NOT NULL, namespace TEXT NOT NULL, key TEXT NOT NULL, version INTEGER NOT NULL, expires INTEGER, payload TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(tenant,namespace,key)) WITHOUT ROWID;
      CREATE TABLE IF NOT EXISTS events(tenant TEXT NOT NULL, sequence INTEGER NOT NULL, at INTEGER NOT NULL, kind TEXT NOT NULL, actor TEXT NOT NULL, resource TEXT NOT NULL, previous TEXT NOT NULL, key_id TEXT NOT NULL, digest TEXT NOT NULL, auth TEXT NOT NULL, PRIMARY KEY(tenant,sequence)) WITHOUT ROWID;
      CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'AUDIT_APPEND_ONLY'); END;
      CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'AUDIT_APPEND_ONLY'); END;
      CREATE INDEX IF NOT EXISTS cell_expiry ON cells(tenant,namespace,expires);`);
    if(this.#db.prepare('SELECT version FROM control_meta').get()?.version!==1)deny('STATE_SCHEMA_UNSUPPORTED');
    if(path!==':memory:')chmodSync(path,0o600);
  }
  tenant(tenantId:string):TenantState {id(tenantId);if(!this.#keys.has(tenantId))deny('TENANT_UNCONFIGURED');return new TenantState(this,tenantId);}
  /** Internal hooks operate only with a registered tenant; do not expose the store over request JSON. */
  _atomic<T>(fn:()=>T):T{
    if(this.#closed)deny('STATE_CLOSED');if(this.#inTransaction)deny('STATE_NESTED_TRANSACTION');
    this.#db.exec('BEGIN IMMEDIATE');this.#inTransaction=true;
    try{const out=fn();if(out&&typeof(out as {then?:unknown}).then==='function')deny('STATE_ASYNC_TRANSACTION');this.#db.exec('COMMIT');return out;}catch(e){this.#db.exec('ROLLBACK');throw e;}finally{this.#inTransaction=false;}
  }
  _keyset(tenant:string):KeySet{const ring=this.#keys.get(tenant);if(!ring||this.#closed)deny('STATE_UNAVAILABLE');return ring;}
  _mac(tenant:string,keyId:string,domain:string,value:unknown):string{const k=this._keyset(tenant).keys.get(keyId);if(!k)deny('STATE_KEY_MISSING');return createHmac('sha256',k).update(canonical([domain,tenant,value])).digest('hex');}
  #seal(tenant:string,namespace:string,key:string,version:number,value:unknown,expiresAt:number|null):string{
    const ring=this._keyset(tenant),iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',ring.keys.get(ring.active)!,iv);
    cipher.setAAD(Buffer.from(canonical(['aidr-state-v2',tenant,namespace,key,version,ring.active,expiresAt])));
    const bytes=Buffer.from(canonical(value,MAX_VALUE));try{const body=Buffer.concat([cipher.update(bytes),cipher.final()]);return canonical({format:'aidr-state-v2',keyId:ring.active,iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),body:body.toString('base64')},MAX_VALUE*2);}finally{bytes.fill(0);}
  }
  #unseal(tenant:string,namespace:string,key:string,version:number,payload:string,expiresAt:number|null):unknown{
    try{const p=parseJsonStrict(payload,4,32) as Record<string,string>;if(p.format!=='aidr-state-v2')deny('STATE_LEGACY_FORMAT');const k=this._keyset(tenant).keys.get(p.keyId!);if(!k)deny('STATE_KEY_MISSING');
      const decipher=createDecipheriv('aes-256-gcm',k,Buffer.from(p.iv!,'base64'));decipher.setAAD(Buffer.from(canonical(['aidr-state-v2',tenant,namespace,key,version,p.keyId,expiresAt])));decipher.setAuthTag(Buffer.from(p.tag!,'base64'));
      const bytes=Buffer.concat([decipher.update(Buffer.from(p.body!,'base64')),decipher.final()]);try{return frozen(parseJsonStrict(bytes.toString('utf8'),32,50000));}finally{bytes.fill(0);}
    }catch{deny('STATE_INTEGRITY');}
  }
  _read<T>(tenant:string,namespace:string,key:string):Cell<T>|null{
    this._keyset(tenant);id(namespace);id(key);const r=this.#db.prepare('SELECT version,expires,payload FROM cells WHERE tenant=? AND namespace=? AND key=? AND deleted=0').get(tenant,namespace,key);
    if(!r)return null;return {value:this.#unseal(tenant,namespace,key,r.version as number,r.payload as string,r.expires as number|null) as T,version:r.version as number,expiresAt:r.expires as number|null};
  }
  _write(tenant:string,namespace:string,key:string,value:unknown,expected:number|null,expiresAt:number|null):number{
    if(!this.#inTransaction)deny('STATE_TRANSACTION_REQUIRED');id(namespace);id(key);if(expiresAt!==null)integer(expiresAt);if(expected!==null)integer(expected,1);
    const old=this._read(tenant,namespace,key);if((old?.version??null)!==expected)deny('STATE_CONFLICT');const previous=this.#db.prepare('SELECT version FROM cells WHERE tenant=? AND namespace=? AND key=?').get(tenant,namespace,key);const version=(previous?.version as number??0)+1;
    const payload=this.#seal(tenant,namespace,key,version,value,expiresAt);
    this.#db.prepare('INSERT INTO cells(tenant,namespace,key,version,expires,payload) VALUES(?,?,?,?,?,?) ON CONFLICT(tenant,namespace,key) DO UPDATE SET version=excluded.version,expires=excluded.expires,payload=excluded.payload,deleted=0').run(tenant,namespace,key,version,expiresAt,payload);return version;
  }
  _remove(tenant:string,namespace:string,key:string,expected:number):void{
    if(!this.#inTransaction)deny('STATE_TRANSACTION_REQUIRED');id(namespace);id(key);integer(expected,1);
    const r=this.#db.prepare("UPDATE cells SET deleted=1,payload='' WHERE tenant=? AND namespace=? AND key=? AND version=? AND deleted=0").run(tenant,namespace,key,expected);if(r.changes!==1)deny('STATE_CONFLICT');
  }
  _purgeExpiredTransient(tenant:string,namespace:'oidc-pending'|'portal-sessions',now:number,limit:number):number{
    if(!this.#inTransaction)deny('STATE_TRANSACTION_REQUIRED');this._keyset(tenant);if(!['oidc-pending','portal-sessions'].includes(namespace))deny('STATE_TRANSIENT_NAMESPACE');integer(now);integer(limit,1,10000);
    return Number(this.#db.prepare('DELETE FROM cells WHERE tenant=? AND namespace=? AND key IN (SELECT key FROM cells WHERE tenant=? AND namespace=? AND expires IS NOT NULL AND expires<=? ORDER BY key LIMIT ?)').run(tenant,namespace,tenant,namespace,now,limit).changes);
  }
  _count(tenant:string,namespace:string,includeDeleted=false):number{this._keyset(tenant);id(namespace);if(typeof includeDeleted!=='boolean')deny('STATE_COUNT');return Number(this.#db.prepare('SELECT COUNT(*) AS n FROM cells WHERE tenant=? AND namespace=? AND (?=1 OR deleted=0)').get(tenant,namespace,includeDeleted?1:0)?.n??0);}
  _list(tenant:string,namespace:string,limit:number,after:string):{key:string;cell:Cell}[]{
    id(namespace);integer(limit,1,10000);if(after)id(after);this._keyset(tenant);
    return this.#db.prepare('SELECT key FROM cells WHERE tenant=? AND namespace=? AND deleted=0 AND key>? ORDER BY key LIMIT ?').all(tenant,namespace,after,limit).map(r=>({key:r.key as string,cell:this._read(tenant,namespace,r.key as string)!}));
  }
  _append(tenant:string,kind:string,actor:string,resource:string,at:number):StateEvent{
    if(!this.#inTransaction)deny('STATE_TRANSACTION_REQUIRED');id(kind);id(actor);id(resource);integer(at);
    const ring=this._keyset(tenant),previous=this.#db.prepare('SELECT sequence,at,digest FROM events WHERE tenant=? ORDER BY sequence DESC LIMIT 1').get(tenant);
    if(previous&&at<(previous.at as number))deny('CLOCK_ROLLBACK');
    const body={tenantId:tenant,sequence:(previous?.sequence as number??0)+1,at,kind,actorRef:this._mac(tenant,ring.active,'actor',actor),resourceRef:this._mac(tenant,ring.active,'resource',resource),previous:previous?.digest as string??'0'.repeat(64),keyId:ring.active};
    const d=hash(body),auth=this._mac(tenant,ring.active,'event',d);
    this.#db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?)').run(tenant,body.sequence,at,kind,body.actorRef,body.resourceRef,body.previous,ring.active,d,auth);
    return frozen({...body,digest:d,auth});
  }
  _events(tenant:string):StateEvent[]{this._keyset(tenant);return this.#db.prepare('SELECT * FROM events WHERE tenant=? ORDER BY sequence').all(tenant).map(r=>({tenantId:r.tenant as string,sequence:r.sequence as number,at:r.at as number,kind:r.kind as string,actorRef:r.actor as string,resourceRef:r.resource as string,previous:r.previous as string,keyId:r.key_id as string,digest:r.digest as string,auth:r.auth as string}));}
  anchor(tenant:string):StateAnchor {const ring=this._keyset(tenant),r=this.#db.prepare('SELECT sequence,digest FROM events WHERE tenant=? ORDER BY sequence DESC LIMIT 1').get(tenant);const body={tenantId:tenant,sequence:r?.sequence as number??0,head:r?.digest as string??'0'.repeat(64),keyId:ring.active};return frozen({...body,auth:this._mac(tenant,ring.active,'anchor',body)});}
  verify(tenant:string,externalAnchor?:StateAnchor):boolean{
    try{let head='0'.repeat(64),sequence=0,at=0;for(const e of this._events(tenant)){
      const {digest:d,auth,...body}=e;if(e.previous!==head||e.sequence!==++sequence||e.at<at||hash(body)!==d||!equalHex(auth,this._mac(tenant,e.keyId,'event',d)))return false;head=d;at=e.at;
    }
    if(externalAnchor){const {auth,...body}=externalAnchor;if(body.tenantId!==tenant||body.sequence>sequence||!equalHex(auth,this._mac(tenant,body.keyId,'anchor',body)))return false;
      const match=body.sequence===0?'0'.repeat(64):this.#db.prepare('SELECT digest FROM events WHERE tenant=? AND sequence=?').get(tenant,body.sequence)?.digest;if(match!==body.head)return false;}
    return true;}catch{return false;}
  }
  /** Retain old keys until event history and approved backups no longer require them. */
  rotateKey(tenant:string,next:TenantKey):void{
    const ring=this._keyset(tenant);if(ring.keys.has(next.id))deny('STATE_KEY_DUPLICATE');const k=checkKey(next),old=ring.active;
    try {this._atomic(()=>{ring.keys.set(next.id,k);ring.active=next.id;const rows=this.#db.prepare('SELECT namespace,key FROM cells WHERE tenant=? AND deleted=0').all(tenant);for(const r of rows){const n=r.namespace as string,key=r.key as string,c=this._read(tenant,n,key)!;this._write(tenant,n,key,c.value,c.version,c.expiresAt);}});}catch(e){ring.active=old;ring.keys.delete(next.id);k.fill(0);throw e;}
  }
  /** SQLite's online snapshot operation. Destination must not exist and its directory must be private. */
  snapshot(destination:string):void{
    if(this.path===':memory:'||this.#inTransaction)deny('STATE_SNAPSHOT_UNAVAILABLE');const p=resolve(destination),dir=realpathSync(dirname(p));if(dir!==dirname(p))deny('STATE_DIRECTORY_PERMISSIONS');assertPrivateAccess(dir);
    try{lstatSync(p);deny('STATE_SNAPSHOT_EXISTS');}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
    this.#db.prepare('VACUUM INTO ?').run(p);chmodSync(p,0o600);
  }
  close():void{if(this.#closed)return;this.#closed=true;this.#db.close();for(const ring of this.#keys.values())for(const k of ring.keys.values())k.fill(0);}
}
export class StateTransaction {
  #active=true;
  constructor(private store:SqliteControlStore,readonly tenantId:string){}
  end():void{this.#active=false;}
  #check():void{if(!this.#active)deny('STATE_TRANSACTION_EXPIRED');}
  get<T=unknown>(namespace:string,key:string):Cell<T>|null{this.#check();return this.store._read<T>(this.tenantId,namespace,key);}
  put(namespace:string,key:string,value:unknown,expected:number|null,expiresAt:number|null=null):number{this.#check();return this.store._write(this.tenantId,namespace,key,value,expected,expiresAt);}
  remove(namespace:string,key:string,expected:number):void{this.#check();this.store._remove(this.tenantId,namespace,key,expected);}
  /** Only random-key transient login state may be physically purged; durable CAS tombstones remain. */
  purgeExpiredTransient(namespace:'oidc-pending'|'portal-sessions',now:number,limit=1000):number{this.#check();return this.store._purgeExpiredTransient(this.tenantId,namespace,now,limit);}
  count(namespace:string,includeDeleted=false):number{this.#check();return this.store._count(this.tenantId,namespace,includeDeleted);}
  list(namespace:string,limit=1000,after=''):{key:string;cell:Cell}[]{this.#check();return this.store._list(this.tenantId,namespace,limit,after);}
  event(kind:string,actor:string,resource:string,at=Date.now()):StateEvent{this.#check();return this.store._append(this.tenantId,kind,actor,resource,at);}
}
export class TenantState {
  constructor(private store:SqliteControlStore,readonly tenantId:string){}
  get<T=unknown>(namespace:string,key:string):Cell<T>|null{return this.store._read<T>(this.tenantId,namespace,key);}
  list(namespace:string,limit=1000,after=''):{key:string;cell:Cell}[]{return this.store._list(this.tenantId,namespace,limit,after);}
  transaction<T>(fn:(tx:StateTransaction)=>T):T{return this.store._atomic(()=>{const tx=new StateTransaction(this.store,this.tenantId);try{return fn(tx);}finally{tx.end();}});}
  events():readonly StateEvent[]{return frozen(this.store._events(this.tenantId));}
  anchor():StateAnchor{return this.store.anchor(this.tenantId);}
  /** Tenant-scoped opaque reference (changes on active-key rotation); not a plain hash of low-entropy values. */
  reference(value:unknown):string{const ring=this.store._keyset(this.tenantId);return this.store._mac(this.tenantId,ring.active,'opaque-ref',value);}
  verify(anchor?:StateAnchor):boolean{return this.store.verify(this.tenantId,anchor);}
}
export { digest as bytesDigest };

import test from 'node:test';import assert from 'node:assert/strict';
import {writeFileSync,realpathSync,unlinkSync} from 'node:fs';import{join}from'node:path';
import{fixture,NOW}from'./helpers.mjs';import{AuthorizedMcpCollector}from'../../dist/platform/collector.js';
test('authorized local collector: real config, changes and removal; no command/env leakage',()=>{const f=fixture();try{
 const path=join(f.root,'mcp.json');writeFileSync(path,JSON.stringify({mcpServers:{privateName:{command:'DO_NOT_EXECUTE',env:{TOKEN:'DO_NOT_LOG'},args:['secret-argument']}}}));
 const c=new AuthorizedMcpCollector([{id:'approved-editor',path,expectedRealPath:realpathSync(path)}],()=>NOW);const first=c.poll()[0];assert.equal(first.status,'snapshot');assert.equal(first.servers.length,1);assert(!JSON.stringify(first).includes('DO_NOT_'));assert(!JSON.stringify(first).includes('privateName'));assert.equal(first.idempotencyKey,c.poll()[0].idempotencyKey);
 writeFileSync(path,'{"mcpServers":{}}');const second=c.poll()[0];assert.equal(second.servers.length,0);assert.notEqual(first.idempotencyKey,second.idempotencyKey);unlinkSync(path);assert.equal(c.poll()[0].status,'unavailable');
 }finally{f.close();}});
test('authorized collector: watch stops on AbortSignal and never starts on import',async()=>{const f=fixture();try{const path=join(f.root,'mcp.json');writeFileSync(path,'{"mcpServers":{}}');const c=new AuthorizedMcpCollector([{id:'editor',path,expectedRealPath:realpathSync(path)}],()=>NOW),abort=new AbortController(),iterator=c.watch(abort.signal,1000);assert.equal((await iterator.next()).value.status,'snapshot');abort.abort();assert.equal((await iterator.next()).done,true);}finally{f.close();}});

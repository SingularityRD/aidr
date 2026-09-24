// Test fixture ONLY: deterministic spans, not an ML model or accuracy evaluation.
import readline from 'node:readline';
const mode=process.argv[2];
if(mode!=='no-ready')console.log(JSON.stringify({ready:true,capabilities:{local:true,offsetUnit:'utf16',languages:['tr','en'],entities:['PERSON','ADDRESS'],entitiesByLanguage:{tr:['PERSON','ADDRESS'],en:['PERSON','ADDRESS']},revision:'a'.repeat(64)}}));
const rl=readline.createInterface({input:process.stdin});
rl.on('line',line=>{
 const {id,text}=JSON.parse(line);
 if(mode==='crash')process.exit(1);if(mode==='hang'||mode==='no-ready')return;
 if(mode==='flood'){process.stdout.write('x'.repeat(1100000));return;}
 if(mode==='malformed'){console.log('NOT JSON');return;}
 const start=text.indexOf('Jane Doe');
 console.log(JSON.stringify({id:mode==='wrong-id'?id+1:id,complete:mode!=='incomplete',entities:start<0?[]:[{start,end:start+8,type:'PERSON',score:.98}]}));
});

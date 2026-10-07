/** Session authorization codes enter stdin, never argv. The registered HTTPS callback must
 * be owned by the institution and show/forward code+state only to its authenticated operator. */
import {TextGatewayClient} from '@singularityrd/aidr-privacy/platform';
import config,{saveCredentials} from './client-config.mjs';
try{
 const [action]=process.argv.slice(2);if(!['begin','complete','refresh','revoke'].includes(action))throw new Error();
 const client=new TextGatewayClient(config);let body={};
 if(action==='complete'){let raw='';for await(const b of process.stdin){raw+=b;if(raw.length>8192)throw new Error();}body=JSON.parse(raw);}
 const result=await client.session(action,body);
 if(action==='begin'){if(typeof result.location!=='string')throw new Error();process.stdout.write(JSON.stringify(result)+'\n');}
 else if(action==='revoke'){if(result.revoked!==true)throw new Error();process.stdout.write('SESSION_REVOKED\n');}
 else{saveCredentials(result);process.stdout.write('SESSION_READY\n');}
}catch{process.stderr.write('SESSION_FAILED\n');process.exitCode=1;}

/** Complete, administrator-approved text-directory snapshot over the existing mTLS client.
 * The configured group/label apply to every file; this does not discover native or cloud ACLs. */
import {readFileSync} from 'node:fs';
import {isAbsolute,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {readAuthorizedDirectory,TextGatewayClient} from '@singularityrd/aidr-privacy/platform';

export async function synchronizeDirectory(client,config){
 if(!config||Object.keys(config).sort().join(',')!=='classification,generation,groups,root,sourceId'
  ||typeof config.sourceId!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$/.test(config.sourceId)
  ||!Number.isSafeInteger(config.generation)||config.generation<1||typeof config.root!=='string'||!isAbsolute(config.root)
  ||!Array.isArray(config.groups)||!config.groups.length||config.groups.length>128||new Set(config.groups).size!==config.groups.length
  ||config.groups.some(g=>typeof g!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$/.test(g))
  ||!['public','internal','confidential','restricted'].includes(config.classification))throw new Error('SOURCE_CONFIG');
 const documents=readAuthorizedDirectory({root:config.root,groups:config.groups,classification:config.classification});
 const result=await client.synchronizeSource(config.sourceId,config.generation,documents);
 if(result?.synchronized!==true)throw new Error('SOURCE_SYNCHRONIZATION_DENIED');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  if(process.argv.length!==2||!isAbsolute(process.env.AIDR_PRIVACY_SOURCE_CONFIG??''))throw new Error('SOURCE_CONFIG');
  const config=JSON.parse(readFileSync(process.env.AIDR_PRIVACY_SOURCE_CONFIG,'utf8'));
  const {default:clientConfig}=await import('./client-config.mjs');
  await synchronizeDirectory(new TextGatewayClient(clientConfig),config);
  process.stdout.write('SOURCE_SYNCHRONIZED\n');
 }catch{process.stderr.write('SOURCE_SYNCHRONIZATION_FAILED\n');process.exitCode=1;}
}

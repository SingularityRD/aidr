/** Prepare reference-only operator files. No secrets, approval, install or live network actions. */
import {copyFileSync,mkdirSync,chmodSync,constants} from 'node:fs';
import {isAbsolute,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const packageRoot=resolve(fileURLToPath(new URL('..',import.meta.url)));
try{
 const [output,...extra]=process.argv.slice(2);
 if(!output||extra.length||!isAbsolute(output))throw new Error('PRIVATE_PREPARATION_PATH');
 mkdirSync(output,{mode:0o700}); // Existing directories are refused; never replace approved operator inputs.
 const files={
  'examples/platform/service-config.example.json':'service.json',
  'examples/platform/client-config.example.json':'client.json',
  'examples/platform/source-config.example.json':'source.json',
  'examples/platform/mcp-config.example.json':'gateway.json',
  'deployment/private-operator-inputs.example.json':'operator-inputs.json',
  'deployment/PRIVATE_INSTALL.md':'README.md',
  'deployment/text-service.nft.example':'text-service.nft.example',
  'deployment/mcp-text-service.nft.example':'mcp-text-service.nft.example',
  'deployment/aidr-text.service.example':'aidr-text.service.example',
  'deployment/aidr-text-firewall.service.example':'aidr-text-firewall.service.example',
  'deployment/aidr-privacy-mcp.service.example':'aidr-privacy-mcp.service.example',
 };
 for(const [source,name]of Object.entries(files)){
  const target=join(output,name);copyFileSync(join(packageRoot,source),target,constants.COPYFILE_EXCL);chmodSync(target,0o600);
 }
 process.stdout.write('PRIVATE_REFERENCES_PREPARED; CUSTOMER_INPUTS_AND_ACCEPTANCE_REQUIRED\n');
}catch{process.stderr.write('PRIVATE_PREPARATION_FAILED\n');process.exitCode=1;}

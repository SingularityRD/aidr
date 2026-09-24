import { canonical, deny, integer } from '../enterprise/util.js';
import { PinnedJwtVerifier } from './identity.js';
import type { TenantState } from './state.js';
/** Generates deployment CONFIGURATION, not a signed CRX, MDM enrollment or installed browser. */
export function chromeManagedPolicies(extensionId:string,updateUrl:string,managedSettings:Record<string,unknown>){
 if(!/^[a-p]{32}$/.test(extensionId))deny('EXTENSION_ID');const url=new URL(updateUrl);if(url.protocol!=='https:'||url.username||url.password||url.hash||/[\r\n"\\]/.test(updateUrl))deny('EXTENSION_UPDATE_URL');canonical(managedSettings,65536);
 return {
  linux:{ExtensionSettings:{[extensionId]:{installation_mode:'force_installed',update_url:updateUrl}},ExtensionInstallBlocklist:['*'],DeveloperToolsAvailability:2,ExtensionDeveloperModeSettings:1},
  windowsRegistry:'Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist]\r\n"1"="'+extensionId+';'+updateUrl+'"\r\n',
  extensionManaged:{[extensionId]:managedSettings},
  macOS:{PayloadType:'com.google.Chrome',ExtensionInstallForcelist:[extensionId+';'+updateUrl]},
  warning:'Configuration only. MDM profile signing, policy conflicts, platform support and real installation require organization validation.'
 };
}
/** Signed health is proof of a trusted collector's statement, not hardware-backed attestation. */
export class EndpointHealthRegistry{
 constructor(private state:TenantState,private verifier:PinnedJwtVerifier,private expected:{extensionSha256:string;nativeSha256:string;policyRevision:number},private clock:()=>number=Date.now){}
 accept(token:string):void{const now=this.clock(),c=this.verifier.verify(token,now);if(c.tenant_id!==this.state.tenantId||c.extension_sha256!==this.expected.extensionSha256||c.native_sha256!==this.expected.nativeSha256||c.policy_revision!==this.expected.policyRevision||c.force_installed!==true||c.native_healthy!==true)deny('ENDPOINT_UNHEALTHY');integer(c.sequence,1);this.state.transaction(tx=>{const old=tx.get<{sequence:number}>('endpoint-health',c.sub);if(old&&(c.sequence as number)<=old.value.sequence)deny('ENDPOINT_REPLAY');tx.put('endpoint-health',c.sub,{sequence:c.sequence,expiresAt:c.exp*1000},old?.version??null,c.exp*1000);tx.event('ENDPOINT_HEALTH_ACCEPTED',c.sub,c.sub,now);});}
 assertHealthy(deviceId:string):void{const h=this.state.get<{expiresAt:number}>('endpoint-health',deviceId);if(!h||this.clock()>=h.value.expiresAt)deny('ENDPOINT_HEALTH_REQUIRED');}
}

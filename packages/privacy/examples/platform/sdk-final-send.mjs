/** Host-owned final model-send function. No direct provider client or credential in this host.
 * The SDK generic middleware remains the separate tool/action control boundary. */
import {createGenericMiddleware,composeMiddleware} from '@singularityrd/aidr-sdk';
import {TextGatewayClient} from '@singularityrd/aidr-privacy/platform';
import config from './client-config.mjs';
const gateway=new TextGatewayClient(config);
export async function finalModelSend(text){
 const receipt=await gateway.send(text);
 if(receipt.decision!=='sent'||receipt.outputText===null)throw new Error('MODEL_OUTPUT_UNAVAILABLE');
 return receipt.outputText;
}
/** Existing SDK consumers supply their initialized AIDRClient and action context here.
 * This is an explicit host seam, not automatic interception of all SDK/network exits. */
export function toolPipeline(aidrClient){return composeMiddleware([createGenericMiddleware(aidrClient)]);}
export async function finalDocumentSend(bytes,kind){
 const receipt=await gateway.sendDocument(bytes,kind);
 if(receipt.decision!=='sent'||receipt.outputText===null)throw new Error('MODEL_OUTPUT_UNAVAILABLE');
 return receipt.outputText;
}

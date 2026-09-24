/** Integration helper, not an installed browser/endpoint hook.
 * Supply long-lived engines initialized from administrator-owned configuration.
 * Never call uploadToApprovedService with the original message or attachments. */
import { protectMultimodal } from '../../dist/visual/index.js';
export async function sendGuardedMessage({text, images, signal}, {textEngine, visualEngine, uploadToApprovedService}) {
  const result = await protectMultimodal(text, images, textEngine, visualEngine, {signal});
  if (!result.output) {
    // Do not put original text, image bytes, file names or result output into telemetry.
    return {sent: false, decision: result.decision, reasons: result.reasons};
  }
  // No earlier pre-signed upload, thumbnail upload or image-URL resolution is allowed.
  await uploadToApprovedService(result.output, {signal});
  return {sent: true, decision: result.decision};
}

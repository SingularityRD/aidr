/** Import these private dependencies from the trusted main MCP gateway host launcher.
 * Keep the main gateway's own signed tool policy/base scanner and epoch/session checks. */
import {TextGatewayClient,mcpPrivacyGuards} from '@singularity/aidr-privacy/platform';
import config from './client-config.mjs';
export const privacyDependencies=mcpPrivacyGuards(new TextGatewayClient(config));

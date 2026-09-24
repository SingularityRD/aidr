/** Integration pattern, NOT an installed AIDR interceptor.
 * Call before every external sink. Never trust tenant/policy selection from tool arguments.
 */
export function createToolGuard(engine, sendApprovedToolCall) {
  if (!engine || typeof engine.protectJson !== 'function' || typeof sendApprovedToolCall !== 'function') {
    throw new TypeError('INVALID_GUARD_CONFIGURATION');
  }
  return async function guardedToolCall(toolName, serializedArguments) {
    // The upstream caller must authenticate the tenant, authorize tool/destination,
    // bound request size and pass the COMPLETE JSON argument message.
    const result = await engine.protectJson(serializedArguments);
    if ((result.decision !== 'allow' && result.decision !== 'redact') || result.output === null) {
      throw new Error('AIDR_EGRESS_DENIED');
    }
    // Validate the masked payload against the tool schema too: masking can change scalar types.
    return sendApprovedToolCall(toolName, JSON.parse(result.output));
  };
}

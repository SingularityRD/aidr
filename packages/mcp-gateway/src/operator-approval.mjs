import { approveQuarantinedMcpToolset } from "@singularityrd/aidr-core";

/**
 * Sign and record one operator approval of a quarantined MCP toolset.
 *
 * Only the aidr-mcp-approve operator command (approve.mjs) imports this module
 * (MSC-2). It is not reachable from the importable library
 * (`@singularityrd/aidr-mcp-gateway`, dist/aidr-mcp-library.mjs) or from the
 * serving binaries, so those bundles carry no code path that signs or writes
 * an approval; library-approval.test.mjs checks the built bundles. Copying this
 * code does not help an agent either: the gateway honours only an approval
 * signed by a key in its own `approvalKeys`, and `approvalKey`
 * ({ keyId, privateKey }) is the operator's private key, which the gateway
 * never holds.
 */
export async function approveQuarantinedToolset(
	gateway,
	{ tenantId, serverId, toolsetHash, bindingSha256, approvedBy, reason, approvalKey, lifetimeMs },
) {
	if (!approvalKey) throw new Error("approval key required");
	const target = await gateway.approvalTarget({ tenantId, serverId });
	if (target.toolsetHash !== toolsetHash) return { approved: false, reason: "toolset_mismatch" };
	if (target.bindingSha256 !== bindingSha256)
		return { approved: false, reason: "binding_mismatch" };
	return approveQuarantinedMcpToolset({
		serverId: target.serverId,
		toolsetHash,
		bindingSha256,
		approvedBy,
		reason,
		store: target.store,
		approvalKey,
		approvalKeys: target.approvalKeys,
		expected: target.expected,
		now: target.now,
		...(lifetimeMs ? { expiresAt: new Date(target.now.getTime() + lifetimeMs) } : {}),
	});
}

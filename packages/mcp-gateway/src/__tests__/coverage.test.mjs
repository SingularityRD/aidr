import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { McpGatewayRefusal, makeMcpGatewayCoverageEvent, refusalPayload } from "../coverage.mjs";

describe("MCP gateway coverage contract", () => {
	it("serializes a redacted binary refusal with stable machine-readable fields", () => {
		const refusal = new McpGatewayRefusal("unsupported_binary_output", "binary output was refused");
		assert.deepEqual(refusalPayload(refusal), {
			type: "mcp_gateway_refusal",
			schemaVersion: "aidr-mcp-gateway-coverage/v1",
			category: "coverage",
			kind: "coverage_refusal",
			status: "refused",
			code: "unsupported_binary_output",
			reason: "unsupported_binary_output",
			reasonCode: "unsupported_binary_output",
			surface: "tool_output",
			outputType: "binary",
			enforcement: "inline_refusal",
		});
	});

	it("marks direct-upstream startup coverage as unobservable without claiming host routing", () => {
		const event = makeMcpGatewayCoverageEvent({
			channel: "startup",
			surface: "direct_upstream",
			status: "unobservable",
			coverageStatus: "limited",
			reasonCode: "direct_upstream_bypass_unobservable",
			decision: "unknown",
			enforcement: "not_verified",
			at: "2026-09-15T00:00:00.000Z",
		});
		assert.equal(event.event, "aidr.mcp_gateway.coverage");
		assert.equal(event.status, "unobservable");
		assert.equal(event.hostRoutingEnforced, false);
		assert.equal(event.decision, "unknown");
		assert.equal(event.tenantId, undefined);
	});
});

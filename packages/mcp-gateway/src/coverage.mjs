export const MCP_GATEWAY_COVERAGE_SCHEMA_VERSION = "aidr-mcp-gateway-coverage/v1";
export const MCP_GATEWAY_COVERAGE_EVENT = "aidr.mcp_gateway.coverage";
export const MCP_GATEWAY_REFUSAL_TYPE = "mcp_gateway_refusal";

const REFUSALS = {
	server_initiated_method: {
		surface: "server_initiated_method",
		coverageStatus: "unsupported",
		enforcement: "inline_refusal",
	},
	unsupported_binary_output: {
		surface: "tool_output",
		outputType: "binary",
		coverageStatus: "unsupported",
		enforcement: "inline_refusal",
	},
	unsupported_tool_output: {
		surface: "tool_output",
		outputType: "unsupported",
		coverageStatus: "unsupported",
		enforcement: "inline_refusal",
	},
	unsupported_structured_output: {
		surface: "tool_output",
		outputType: "structured",
		coverageStatus: "unsupported",
		enforcement: "inline_refusal",
	},
	invalid_tool_result: {
		surface: "tool_output",
		outputType: "invalid",
		coverageStatus: "limited",
		enforcement: "inline_refusal",
	},
	output_oversize: {
		surface: "tool_output",
		outputType: "oversize",
		coverageStatus: "limited",
		enforcement: "inline_refusal",
	},
	output_uninspectable: {
		surface: "tool_output",
		outputType: "uninspectable",
		coverageStatus: "limited",
		enforcement: "inline_refusal",
	},
	scanner_unavailable: {
		surface: "tool_output",
		outputType: "uninspectable",
		coverageStatus: "limited",
		enforcement: "inline_refusal",
	},
};

export const MCP_GATEWAY_COVERAGE_REFUSALS = Object.freeze(
	Object.fromEntries(
		Object.entries(REFUSALS).map(([code, descriptor]) => [code, Object.freeze({ ...descriptor })]),
	),
);

function descriptorFor(code) {
	return (
		MCP_GATEWAY_COVERAGE_REFUSALS[code] ?? {
			surface: "gateway",
			coverageStatus: "limited",
			enforcement: "inline_refusal",
		}
	);
}

/** A machine-readable refusal for a response the gateway cannot safely inspect. */
export class McpGatewayRefusal extends Error {
	constructor(code, message, details = {}) {
		super(message);
		this.name = "McpGatewayRefusal";
		this.code = code;
		this.reasonCode = code;
		const descriptor = descriptorFor(code);
		this.surface = details.surface ?? descriptor.surface;
		this.outputType = details.outputType ?? descriptor.outputType;
		this.coverageStatus = details.coverageStatus ?? descriptor.coverageStatus;
		this.enforcement = details.enforcement ?? descriptor.enforcement;
	}
}

export function coverageDescriptor(code) {
	return descriptorFor(code);
}

export function refusalPayload(refusal) {
	return {
		type: MCP_GATEWAY_REFUSAL_TYPE,
		schemaVersion: MCP_GATEWAY_COVERAGE_SCHEMA_VERSION,
		category: "coverage",
		kind: "coverage_refusal",
		status: "refused",
		code: refusal.code,
		reason: refusal.reasonCode ?? refusal.code,
		reasonCode: refusal.reasonCode ?? refusal.code,
		surface: refusal.surface,
		...(refusal.outputType ? { outputType: refusal.outputType } : {}),
		enforcement: refusal.enforcement,
	};
}

/** Create a redacted, typed coverage event; never include upstream output or URLs. */
export function makeMcpGatewayCoverageEvent(input) {
	return {
		event: MCP_GATEWAY_COVERAGE_EVENT,
		type: "mcp_gateway_coverage",
		schemaVersion: MCP_GATEWAY_COVERAGE_SCHEMA_VERSION,
		connector: "mcp-gateway",
		channel: input.channel,
		surface: input.surface,
		status: input.status,
		coverageStatus: input.coverageStatus,
		reasonCode: input.reasonCode,
		reason: input.reasonCode,
		decision: input.decision,
		enforcement: input.enforcement,
		refused: input.status === "refused",
		unsupported: input.coverageStatus === "unsupported",
		hostRoutingEnforced: false,
		at: input.at,
		...(input.tenantId ? { tenantId: input.tenantId } : {}),
		...(input.serverId ? { serverId: input.serverId } : {}),
		...(input.clientId ? { clientId: input.clientId } : {}),
		...(input.requestMethod ? { requestMethod: input.requestMethod } : {}),
		...(input.outputType ? { outputType: input.outputType } : {}),
		...(input.refusal ? { refusal: input.refusal } : {}),
	};
}

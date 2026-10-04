import { describe, expect, it } from "vitest";

import type { Incident } from "../incidents/types.js";
import { exportToSyslog, frameSyslogOctetCounting } from "../siem-export.js";

const t0 = Date.UTC(2026, 9, 5, 12, 0, 0);

const incident: Incident = {
	incident_id: "inc_001",
	opened_at_ms: t0,
	last_seen_ms: t0 + 1000,
	severity: "critical",
	status: "open",
	session_id: "sess-1",
	agent_iid: "agent-42",
	connector: "claude",
	domain: "evil.example.com",
	events: [
		{
			signal_id: "s1",
			timestamp_ms: t0,
			signal_type: "runtime_verdict",
			severity: "critical",
			summary: "deny",
		},
	],
};

describe("exportToSyslog (RFC 5424)", () => {
	it("emits a well-formed header, structured data and message", () => {
		const [line] = exportToSyslog([incident], { hostname: "aidr-host" });
		// <PRI> = local0 (16) * 8 + RFC 5424 severity 2 (critical)
		expect(line).toMatch(
			/^<130>1 2026-10-05T12:00:00\.000Z aidr-host aidr - AIDR\.critical\.DOMAIN \[aidr@32473 incident_id="inc_001" severity="critical" status="open" agent_iid="agent-42" connector="claude" session_id="sess-1" event_count="1"\] AIDR critical incident - evil\.example\.com$/,
		);
	});

	it("maps severities to syslog levels and honours facility bounds", () => {
		const sev = (severity: Incident["severity"], facility?: number) =>
			exportToSyslog([{ ...incident, severity }], { facility })[0].match(/^<(\d+)>/)?.[1];
		expect(sev("info")).toBe("134");
		expect(sev("warning")).toBe("132");
		expect(sev("high")).toBe("131");
		expect(sev("critical", 99)).toBe("186"); // clamped to facility 23
	});

	it("cannot be forced into a second record or a forged structured-data element", () => {
		const hostile: Incident = {
			...incident,
			agent_iid: 'x"] [evil@1 a="b',
			session_id: "a\r\n<13>1 forged",
			domain: "d\nforged",
		};
		const [line] = exportToSyslog([hostile], { hostname: "bad host\nname" });
		expect(line).not.toMatch(/[\r\n]/);
		expect(line).toContain("bad_host_name");
		expect(line).toContain('agent_iid="x\\"\\] [evil@1 a=\\"b"');
		expect(line).toContain('session_id="a\\r\\n<13>1 forged"');
	});

	it("applies the filter and returns no records for an empty match", () => {
		expect(exportToSyslog([incident], { severity: "info" })).toEqual([]);
	});

	it("frames with an RFC 6587 octet count in UTF-8 bytes", () => {
		expect(frameSyslogOctetCounting("abc")).toBe("3 abc");
		expect(frameSyslogOctetCounting("é")).toBe("2 é");
	});
});

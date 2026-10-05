// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import {
	buildSyslogAdapter,
	DEFAULT_SYSLOG_FORM,
	type SyslogFormValues,
} from "../lib/siem-syslog-config";
import { SiemPage } from "../ui/pages/SiemPage";

afterEach(cleanup);

const form = (overrides: Partial<SyslogFormValues> = {}): SyslogFormValues => ({
	...DEFAULT_SYSLOG_FORM,
	host: "siem.example.com",
	...overrides,
});

describe("syslog SIEM adapter builder", () => {
	it("builds a TLS adapter with CA and pins", () => {
		const result = buildSyslogAdapter(
			form({
				facility: "4",
				pinnedSha256: `${"a".repeat(64)}, ${"b".repeat(64)}`,
				caCertificatePem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
			}),
		);
		expect(result).toMatchObject({
			ok: true,
			adapter: {
				provider: "syslog",
				endpoint: "tls://siem.example.com:6514",
				facility: 4,
				tlsPinnedSha256: ["a".repeat(64), "b".repeat(64)],
			},
		});
	});

	it.each([
		["127.0.0.1", /non-routable/],
		["169.254.169.254", /non-routable/],
		["metadata.google.internal", /non-routable/],
		["::1", /non-routable/],
		["10.0.0.5", /private range/],
		["bad host!", /valid DNS name/],
		["", /Enter the collector/],
	])("refuses %s", (host, message) => {
		const result = buildSyslogAdapter(form({ host }));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.errors.join(" ")).toMatch(message);
	});

	it("allows a private collector only after the explicit confirmation", () => {
		expect(buildSyslogAdapter(form({ host: "10.0.0.5", allowPrivateNetwork: true })).ok).toBe(true);
		expect(
			buildSyslogAdapter(form({ host: "169.254.169.254", allowPrivateNetwork: true })).ok,
		).toBe(false);
	});

	it("requires the plaintext acknowledgement for tcp and udp, and warns about UDP", () => {
		expect(buildSyslogAdapter(form({ transport: "udp", port: "514" })).ok).toBe(false);
		const result = buildSyslogAdapter(
			form({ transport: "udp", port: "514", allowPlaintextTransport: true }),
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.adapter.allowPlaintextTransport).toBe(true);
			expect(result.warnings.join(" ")).toMatch(/no acknowledgement/);
		}
	});

	it("rejects bad ports, facility, pins and TLS settings on plaintext transports", () => {
		expect(buildSyslogAdapter(form({ port: "0" })).ok).toBe(false);
		expect(buildSyslogAdapter(form({ port: "70000" })).ok).toBe(false);
		expect(buildSyslogAdapter(form({ facility: "24" })).ok).toBe(false);
		expect(buildSyslogAdapter(form({ pinnedSha256: "short" })).ok).toBe(false);
		expect(
			buildSyslogAdapter(
				form({
					transport: "tcp",
					port: "514",
					allowPlaintextTransport: true,
					pinnedSha256: "a".repeat(64),
				}),
			).ok,
		).toBe(false);
		expect(buildSyslogAdapter(form({ appName: "has space" })).ok).toBe(false);
	});

	it("never emits a verification-disabling option", () => {
		const result = buildSyslogAdapter(form());
		expect(JSON.stringify(result)).not.toMatch(/rejectUnauthorized|insecure|skipVerify/i);
	});
});

describe("SIEM page", () => {
	it("shows errors for a blocked host and the config for a valid one", () => {
		render(<SiemPage />);
		const host = screen.getByLabelText("Collector host");
		fireEvent.change(host, { target: { value: "127.0.0.1" } });
		expect(screen.getByRole("alert")).toHaveTextContent(/non-routable/);
		expect(screen.queryByLabelText("Generated SIEM configuration")).toBeNull();
		fireEvent.change(host, { target: { value: "siem.example.com" } });
		expect(screen.getByLabelText("Generated SIEM configuration")).toHaveTextContent(
			"tls://siem.example.com:6514",
		);
	});

	it("switches the default port with the transport and demands the plaintext acknowledgement", () => {
		render(<SiemPage />);
		fireEvent.change(screen.getByLabelText("Collector host"), {
			target: { value: "siem.example.com" },
		});
		fireEvent.change(screen.getByLabelText("Transport"), { target: { value: "udp" } });
		expect(screen.getByLabelText("Port")).toHaveValue("514");
		expect(screen.getByRole("alert")).toHaveTextContent(/unencrypted/);
		fireEvent.click(screen.getByLabelText(/accept that incident data is sent unencrypted/));
		expect(screen.getByLabelText("Generated SIEM configuration")).toHaveTextContent(
			"udp://siem.example.com:514",
		);
	});
});

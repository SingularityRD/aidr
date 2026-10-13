// Builds the `adapter` block of the host-side SIEM config file for the syslog
// destination. Mirrors the validation in packages/core/src/siem-syslog.ts so an
// operator sees the same refusals before copying the file to the host; the
// host re-validates on every start and every send, so this is guidance, not a
// control. Nothing here is transmitted anywhere.

import { englishT, type Translate } from "../i18n/I18nProvider";

export type SyslogTransportChoice = "tls" | "tcp" | "udp";

export type SyslogFormValues = {
	transport: SyslogTransportChoice;
	host: string;
	port: string;
	facility: string;
	hostname: string;
	appName: string;
	allowPrivateNetwork: boolean;
	allowPlaintextTransport: boolean;
	caCertificatePem: string;
	pinnedSha256: string;
};

type SyslogAdapterConfig = {
	provider: "syslog";
	endpoint: string;
	facility?: number;
	hostname?: string;
	appName?: string;
	allowPrivateNetwork?: boolean;
	allowPlaintextTransport?: boolean;
	tlsCaCertificatePem?: string;
	tlsPinnedSha256?: string[];
};

export type SyslogFormResult =
	| { ok: true; adapter: SyslogAdapterConfig; warnings: string[] }
	| { ok: false; errors: string[] };

const BLOCKED_HOSTS = new Set([
	"localhost",
	"localhost.localdomain",
	"ip6-localhost",
	"ip6-loopback",
	"metadata.google.internal",
	"metadata.google.com",
	"instance-data.ec2.internal",
]);
const DNS_NAME =
	/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const PIN = /^([A-Fa-f0-9]{64}|[A-Za-z0-9+/_-]{43}={0,1})$/;

type AddressClass = "public" | "private" | "blocked";

function classifyIpv4(a: number, b: number): AddressClass {
	if (a === 127 || a === 0 || (a === 169 && b === 254) || a >= 224) return "blocked";
	if (
		a === 10 ||
		(a === 172 && b >= 16 && b <= 31) ||
		(a === 192 && b === 168) ||
		(a === 100 && b >= 64 && b <= 127) ||
		(a === 192 && b === 0) ||
		(a === 198 && (b === 18 || b === 19 || b === 51)) ||
		(a === 203 && b === 0)
	)
		return "private";
	return "public";
}

function classifyHostLiteral(host: string): AddressClass | null {
	const v4 = IPV4.exec(host);
	if (v4) {
		const parts = v4.slice(1).map(Number);
		if (parts.some((part) => part > 255)) return "blocked";
		return classifyIpv4(parts[0] as number, parts[1] as number);
	}
	if (host.includes(":")) {
		const value = host.toLowerCase();
		if (value === "::1" || value === "::" || /^fe[89ab]/.test(value) || value.startsWith("ff"))
			return "blocked";
		if (value.startsWith("::ffff:")) return "blocked"; // mapped addresses: use the IPv4 literal
		return /^f[cd]/.test(value) ? "private" : "public";
	}
	return null;
}

function parsePins(raw: string): string[] {
	return raw
		.split(/[\s,]+/)
		.map((value) => value.trim())
		.filter(Boolean);
}

function checkTls(values: SyslogFormValues, errors: string[], t: Translate): void {
	if (values.transport === "tls") {
		const pem = values.caCertificatePem.trim();
		if (pem && !/^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----$/.test(pem))
			errors.push(t("siem.err.pem"));
		if (pem.length > 65_536) errors.push(t("siem.err.pemSize"));
		const pins = parsePins(values.pinnedSha256);
		if (pins.length > 8) errors.push(t("siem.err.pinCount"));
		if (pins.some((pin) => !PIN.test(pin))) errors.push(t("siem.err.pinFormat"));
	} else if (values.caCertificatePem.trim() || values.pinnedSha256.trim()) {
		errors.push(t("siem.err.tlsOnly"));
	}
}

function checkHost(
	values: SyslogFormValues,
	errors: string[],
	warnings: string[],
	t: Translate,
): void {
	const host = values.host
		.trim()
		.toLowerCase()
		.replace(/^\[|\]$/g, "");
	const literalClass = classifyHostLiteral(host);
	if (!host) errors.push(t("siem.err.host"));
	else if (BLOCKED_HOSTS.has(host) || literalClass === "blocked")
		errors.push(t("siem.err.blocked"));
	else if (literalClass === null && !DNS_NAME.test(host)) errors.push(t("siem.err.hostInvalid"));
	else if (literalClass === "private" && !values.allowPrivateNetwork)
		errors.push(t("siem.err.private"));
	if (literalClass === null && values.allowPrivateNetwork) warnings.push(t("siem.warn.resolve"));
}

export function buildSyslogAdapter(
	values: SyslogFormValues,
	t: Translate = englishT,
): SyslogFormResult {
	const errors: string[] = [];
	const warnings: string[] = [];
	const host = values.host
		.trim()
		.toLowerCase()
		.replace(/^\[|\]$/g, "");
	checkHost(values, errors, warnings, t);
	const port = Number(values.port);
	if (!/^\d{1,5}$/.test(values.port.trim()) || port < 1 || port > 65_535)
		errors.push(t("siem.err.port"));
	const facility = values.facility.trim() === "" ? undefined : Number(values.facility);
	if (facility !== undefined && (!Number.isInteger(facility) || facility < 0 || facility > 23))
		errors.push(t("siem.err.facility"));
	if (/[^\x21-\x7e]/.test(values.hostname) || values.hostname.length > 255)
		errors.push(t("siem.err.hostname"));
	if (/[^\x21-\x7e]/.test(values.appName) || values.appName.length > 48)
		errors.push(t("siem.err.appName"));
	checkTls(values, errors, t);
	if (values.transport !== "tls" && !values.allowPlaintextTransport)
		errors.push(t("siem.err.plaintext"));
	if (errors.length > 0) return { ok: false, errors };

	if (values.transport === "udp") warnings.push(t("siem.warn.udp"));
	if (values.transport === "tcp") warnings.push(t("siem.warn.tcp"));

	const displayHost = host.includes(":") ? `[${host}]` : host;
	const pins = parsePins(values.pinnedSha256);
	const ca = values.caCertificatePem.trim();
	const adapter: SyslogAdapterConfig = {
		provider: "syslog",
		endpoint: `${values.transport}://${displayHost}:${port}`,
		...(facility !== undefined ? { facility } : {}),
		...(values.hostname ? { hostname: values.hostname } : {}),
		...(values.appName ? { appName: values.appName } : {}),
		...(values.allowPrivateNetwork ? { allowPrivateNetwork: true } : {}),
		...(values.transport !== "tls" && values.allowPlaintextTransport
			? { allowPlaintextTransport: true }
			: {}),
		...(values.transport === "tls" && ca ? { tlsCaCertificatePem: ca } : {}),
		...(values.transport === "tls" && pins.length > 0 ? { tlsPinnedSha256: pins } : {}),
	};
	return { ok: true, adapter, warnings };
}

export const DEFAULT_SYSLOG_FORM: SyslogFormValues = {
	transport: "tls",
	host: "",
	port: "6514",
	facility: "16",
	hostname: "",
	appName: "aidr",
	allowPrivateNetwork: false,
	allowPlaintextTransport: false,
	caCertificatePem: "",
	pinnedSha256: "",
};

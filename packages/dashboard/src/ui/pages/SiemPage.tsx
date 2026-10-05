import { useMemo, useState } from "react";
import {
	buildSyslogAdapter,
	DEFAULT_SYSLOG_FORM,
	type SyslogFormValues,
	type SyslogTransportChoice,
} from "../../lib/siem-syslog-config";

const PORT_DEFAULTS: Record<SyslogTransportChoice, string> = {
	tls: "6514",
	tcp: "514",
	udp: "514",
};

export function SiemPage() {
	const [values, setValues] = useState<SyslogFormValues>(DEFAULT_SYSLOG_FORM);
	const [touched, setTouched] = useState(false);
	const result = useMemo(() => buildSyslogAdapter(values), [values]);
	const update = <K extends keyof SyslogFormValues>(key: K, value: SyslogFormValues[K]) => {
		setTouched(true);
		setValues((current) => ({ ...current, [key]: value }));
	};
	const configJson = result.ok
		? JSON.stringify(
				{ state_file: "<absolute path on the host>", adapter: result.adapter },
				null,
				2,
			)
		: "";

	return (
		<div className="stack">
			<header className="card">
				<h1>SIEM syslog destination</h1>
				<p className="muted">
					Generate the <code>adapter</code> block for the host SIEM config (
					<code>SINGULARITY_AIDR_SIEM_CONFIG_PATH</code>). Delivery runs on the host from the
					durable local queue; nothing entered here is sent to the control plane, and no certificate
					check can be disabled.
				</p>
			</header>
			<section className="card" aria-labelledby="siem-syslog-heading">
				<h2 id="siem-syslog-heading">Collector</h2>
				<label className="label" htmlFor="siem-transport">
					Transport
				</label>
				<select
					id="siem-transport"
					value={values.transport}
					onChange={(event) => {
						const transport = event.target.value as SyslogTransportChoice;
						setTouched(true);
						setValues((current) => ({ ...current, transport, port: PORT_DEFAULTS[transport] }));
					}}
				>
					<option value="tls">TLS (RFC 5425 style, certificate verified)</option>
					<option value="tcp">TCP (RFC 6587 octet counting, unencrypted)</option>
					<option value="udp">UDP (unacknowledged, unencrypted)</option>
				</select>
				<label className="label" htmlFor="siem-host">
					Collector host
				</label>
				<input
					id="siem-host"
					value={values.host}
					autoComplete="off"
					onChange={(event) => update("host", event.target.value)}
				/>
				<label className="label" htmlFor="siem-port">
					Port
				</label>
				<input
					id="siem-port"
					inputMode="numeric"
					value={values.port}
					onChange={(event) => update("port", event.target.value)}
				/>
				<label className="label" htmlFor="siem-facility">
					Facility (0-23)
				</label>
				<input
					id="siem-facility"
					inputMode="numeric"
					value={values.facility}
					onChange={(event) => update("facility", event.target.value)}
				/>
				<label className="label" htmlFor="siem-app-name">
					Application name
				</label>
				<input
					id="siem-app-name"
					value={values.appName}
					onChange={(event) => update("appName", event.target.value)}
				/>
				<label className="label" htmlFor="siem-hostname">
					Reporting hostname (optional)
				</label>
				<input
					id="siem-hostname"
					value={values.hostname}
					onChange={(event) => update("hostname", event.target.value)}
				/>
				{values.transport === "tls" ? (
					<>
						<label className="label" htmlFor="siem-ca">
							Private CA certificate (PEM, optional)
						</label>
						<textarea
							id="siem-ca"
							rows={5}
							value={values.caCertificatePem}
							onChange={(event) => update("caCertificatePem", event.target.value)}
						/>
						<label className="label" htmlFor="siem-pins">
							Public-key pins, SHA-256 (optional)
						</label>
						<input
							id="siem-pins"
							value={values.pinnedSha256}
							onChange={(event) => update("pinnedSha256", event.target.value)}
						/>
					</>
				) : (
					<label className="label">
						<input
							type="checkbox"
							checked={values.allowPlaintextTransport}
							onChange={(event) => update("allowPlaintextTransport", event.target.checked)}
						/>{" "}
						I accept that incident data is sent unencrypted on this link
					</label>
				)}
				<label className="label">
					<input
						type="checkbox"
						checked={values.allowPrivateNetwork}
						onChange={(event) => update("allowPrivateNetwork", event.target.checked)}
					/>{" "}
					The collector is on a private (on-premises) network
				</label>
			</section>
			{touched && !result.ok ? (
				<div className="notice notice-danger" role="alert">
					<ul>
						{result.errors.map((message) => (
							<li key={message}>{message}</li>
						))}
					</ul>
				</div>
			) : null}
			{result.ok ? (
				<section className="card" aria-labelledby="siem-config-heading">
					<h2 id="siem-config-heading">Host configuration</h2>
					{result.warnings.map((message) => (
						<p key={message} className="notice" role="note">
							{message}
						</p>
					))}
					<pre aria-label="Generated SIEM configuration">{configJson}</pre>
					<p className="muted small">
						Save the file with owner-only permissions on the host. Loopback, link-local and
						cloud-metadata destinations are always refused by the sender.
					</p>
				</section>
			) : null}
		</div>
	);
}

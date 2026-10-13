import { useMemo, useState } from "react";
import { useRichT, useT } from "../../i18n/I18nProvider";
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
	const t = useT();
	const richT = useRichT();
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
				<h1>{t("siem.title")}</h1>
				<p className="muted">
					{richT("siem.lead", {
						adapter: <code>adapter</code>,
						path: <code>SINGULARITY_AIDR_SIEM_CONFIG_PATH</code>,
					})}
				</p>
			</header>
			<section className="card" aria-labelledby="siem-syslog-heading">
				<h2 id="siem-syslog-heading">{t("siem.collector")}</h2>
				<label className="label" htmlFor="siem-transport">
					{t("siem.transport")}
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
					<option value="tls">{t("siem.tls")}</option>
					<option value="tcp">{t("siem.tcp")}</option>
					<option value="udp">{t("siem.udp")}</option>
				</select>
				<label className="label" htmlFor="siem-host">
					{t("siem.host")}
				</label>
				<input
					id="siem-host"
					value={values.host}
					autoComplete="off"
					onChange={(event) => update("host", event.target.value)}
				/>
				<label className="label" htmlFor="siem-port">
					{t("siem.port")}
				</label>
				<input
					id="siem-port"
					inputMode="numeric"
					value={values.port}
					onChange={(event) => update("port", event.target.value)}
				/>
				<label className="label" htmlFor="siem-facility">
					{t("siem.facility")}
				</label>
				<input
					id="siem-facility"
					inputMode="numeric"
					value={values.facility}
					onChange={(event) => update("facility", event.target.value)}
				/>
				<label className="label" htmlFor="siem-app-name">
					{t("siem.appName")}
				</label>
				<input
					id="siem-app-name"
					value={values.appName}
					onChange={(event) => update("appName", event.target.value)}
				/>
				<label className="label" htmlFor="siem-hostname">
					{t("siem.hostname")}
				</label>
				<input
					id="siem-hostname"
					value={values.hostname}
					onChange={(event) => update("hostname", event.target.value)}
				/>
				{values.transport === "tls" ? (
					<>
						<label className="label" htmlFor="siem-ca">
							{t("siem.ca")}
						</label>
						<textarea
							id="siem-ca"
							rows={5}
							value={values.caCertificatePem}
							onChange={(event) => update("caCertificatePem", event.target.value)}
						/>
						<label className="label" htmlFor="siem-pins">
							{t("siem.pins")}
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
						{t("siem.plaintext")}
					</label>
				)}
				<label className="label">
					<input
						type="checkbox"
						checked={values.allowPrivateNetwork}
						onChange={(event) => update("allowPrivateNetwork", event.target.checked)}
					/>{" "}
					{t("siem.private")}
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
					<h2 id="siem-config-heading">{t("siem.config")}</h2>
					{result.warnings.map((message) => (
						<p key={message} className="notice" role="note">
							{message}
						</p>
					))}
					<pre aria-label={t("siem.configLabel")}>{configJson}</pre>
					<p className="muted small">{t("siem.saveNote")}</p>
				</section>
			) : null}
		</div>
	);
}

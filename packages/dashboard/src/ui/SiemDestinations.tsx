import { type FormEvent, type ReactNode, useCallback, useEffect, useState } from "react";
import type { DashboardMessageKey } from "../i18n/en";
import { type Translate, useT } from "../i18n/I18nProvider";
import { generateWebhookSecret } from "../lib/notification-channels";
import {
	createSiemDestination,
	DEFAULT_SIEM_FILTERS,
	loadSiemSettings,
	SIEM_DECISIONS,
	SIEM_SEVERITIES,
	type SiemDecision,
	type SiemDestination,
	type SiemFilters,
	type SiemFormat,
	type SiemProvider,
	type SiemSettings,
	type SiemSeverity,
	siemDestinationAction,
	updateSiemDestination,
} from "../lib/siem-destinations";

/** Provider names are product names in every language, except the generic webhook and syslog. */
const PROVIDER_LABELS: Record<SiemProvider, (t: Translate) => string> = {
	syslog: (t) => t("siem.central.provider.syslog"),
	splunk_hec: () => "Splunk HEC",
	elastic: () => "Elastic",
	sentinel: () => "Microsoft Sentinel",
	webhook: (t) => t("siem.central.provider.webhook"),
};

const FORMAT_LABELS: Record<SiemFormat, DashboardMessageKey> = {
	json: "siem.format.json",
	cef: "siem.format.cef",
	leef: "siem.format.leef",
};

const SEVERITY_LABELS: Record<SiemSeverity, DashboardMessageKey> = {
	info: "common.severity.info",
	warning: "common.severity.warning",
	high: "common.severity.high",
	critical: "common.severity.critical",
};

const DECISION_LABELS: Record<SiemDecision, DashboardMessageKey> = {
	deny: "siem.central.decision.deny",
	ask: "siem.central.decision.ask",
	allow: "siem.central.decision.allow",
};

const ERROR_MESSAGES: Record<string, DashboardMessageKey> = {
	mfa_required: "siem.central.error.mfa",
	siem_destinations_forbidden: "siem.central.error.forbidden",
	plan_feature_required: "siem.central.error.plan",
	siem_not_configured: "siem.central.error.notConfigured",
	siem_destination_limit: "siem.central.error.limit",
	siem_destination_name_conflict: "siem.central.error.nameConflict",
	private_network_not_allowed: "siem.central.error.private",
	plaintext_not_confirmed: "siem.central.error.plaintext",
	invalid_ca: "siem.central.error.ca",
	url_not_https: "siem.central.error.https",
	invalid_secret: "siem.central.error.secret",
	invalid_host: "siem.central.error.host",
	invalid_url: "siem.central.error.url",
};

function errorMessage(code: string, t: Translate): string {
	const key = ERROR_MESSAGES[code];
	return key ? t(key) : t("siem.central.error.generic", { code });
}

interface FormState {
	name: string;
	provider: SiemProvider;
	format: SiemFormat;
	transport: "tls" | "tcp" | "udp";
	host: string;
	port: string;
	url: string;
	token: string;
	index: string;
	apiKey: string;
	caPem: string;
	allowPlaintext: boolean;
	allowPrivate: boolean;
	endpoint: string;
	dcrId: string;
	stream: string;
	azureTenant: string;
	clientId: string;
	clientSecret: string;
	secret: string;
	filters: SiemFilters;
}

const EMPTY_FORM: FormState = {
	name: "",
	provider: "syslog",
	format: "leef",
	transport: "tls",
	host: "",
	port: "6514",
	url: "",
	token: "",
	index: "",
	apiKey: "",
	caPem: "",
	allowPlaintext: false,
	allowPrivate: false,
	endpoint: "",
	dcrId: "",
	stream: "",
	azureTenant: "",
	clientId: "",
	clientSecret: "",
	secret: "",
	filters: DEFAULT_SIEM_FILTERS,
};

/** The write-only configuration object the service validates for the chosen provider. */
function buildSiemConfig(form: FormState): Record<string, unknown> {
	const network = {
		...(form.caPem.trim() ? { ca_pem: form.caPem.trim() } : {}),
		...(form.allowPrivate ? { allow_private_network: true } : {}),
	};
	switch (form.provider) {
		case "syslog":
			return {
				transport: form.transport,
				host: form.host.trim(),
				port: Number(form.port),
				...(form.transport === "tls"
					? network
					: {
							...(form.allowPrivate ? { allow_private_network: true } : {}),
							allow_plaintext: form.allowPlaintext,
						}),
			};
		case "splunk_hec":
			return {
				url: form.url.trim(),
				token: form.token,
				...(form.index.trim() ? { index: form.index.trim() } : {}),
				...network,
			};
		case "elastic":
			return { url: form.url.trim(), index: form.index.trim(), api_key: form.apiKey, ...network };
		case "sentinel":
			return {
				endpoint: form.endpoint.trim(),
				dcr_immutable_id: form.dcrId.trim(),
				stream_name: form.stream.trim(),
				azure_tenant_id: form.azureTenant.trim(),
				client_id: form.clientId.trim(),
				client_secret: form.clientSecret,
			};
		case "webhook":
			return { url: form.url.trim(), secret: form.secret, ...network };
	}
}

function Field({ id, label, children }: { id: string; label: string; children: ReactNode }) {
	return (
		<>
			<label className="label" htmlFor={id}>
				{label}
			</label>
			{children}
		</>
	);
}

function FiltersEditor({
	filters,
	onChange,
}: {
	filters: SiemFilters;
	onChange: (filters: SiemFilters) => void;
}) {
	const t = useT();
	return (
		<fieldset>
			<legend>{t("siem.central.events")}</legend>
			<label className="label">
				<input
					type="checkbox"
					checked={filters.incidents}
					onChange={(event) => onChange({ ...filters, incidents: event.target.checked })}
				/>{" "}
				{t("siem.central.events.incidents")}
			</label>
			{SIEM_DECISIONS.map((decision) => (
				<label className="label" key={decision}>
					<input
						type="checkbox"
						checked={filters.decisions.includes(decision)}
						onChange={(event) =>
							onChange({
								...filters,
								decisions: event.target.checked
									? [...filters.decisions, decision]
									: filters.decisions.filter((item) => item !== decision),
							})
						}
					/>{" "}
					{t(DECISION_LABELS[decision])}
				</label>
			))}
			<label className="label">
				<input
					type="checkbox"
					checked={filters.browser}
					onChange={(event) => onChange({ ...filters, browser: event.target.checked })}
				/>{" "}
				{t("siem.central.events.browser")}
			</label>
			<label className="label">
				<input
					type="checkbox"
					checked={filters.adminAudit}
					onChange={(event) => onChange({ ...filters, adminAudit: event.target.checked })}
				/>{" "}
				{t("siem.central.events.adminAudit")}
			</label>
			<label className="label" htmlFor="siem-central-severity">
				{t("siem.central.minSeverity")}
			</label>
			<select
				id="siem-central-severity"
				value={filters.minSeverity}
				onChange={(event) =>
					onChange({ ...filters, minSeverity: event.target.value as SiemSeverity })
				}
			>
				{SIEM_SEVERITIES.map((severity) => (
					<option key={severity} value={severity}>
						{t(SEVERITY_LABELS[severity])}
					</option>
				))}
			</select>
		</fieldset>
	);
}

type SetField = <K extends keyof FormState>(key: K, value: FormState[K]) => void;

/** A labelled text input bound to one form field. */
function TextField({
	form,
	set,
	name,
	id,
	label,
	type = "text",
}: {
	form: FormState;
	set: SetField;
	name:
		| "host"
		| "port"
		| "url"
		| "token"
		| "index"
		| "apiKey"
		| "secret"
		| "endpoint"
		| "dcrId"
		| "stream"
		| "azureTenant"
		| "clientId"
		| "clientSecret";
	id: string;
	label: string;
	type?: "text" | "url" | "password";
}) {
	return (
		<Field id={id} label={label}>
			<input
				id={id}
				type={type}
				value={form[name]}
				autoComplete="off"
				inputMode={name === "port" ? "numeric" : undefined}
				onChange={(event) => set(name, event.target.value)}
			/>
		</Field>
	);
}

function SyslogFields({
	form,
	set,
	setForm,
}: {
	form: FormState;
	set: SetField;
	setForm: (update: (current: FormState) => FormState) => void;
}) {
	const t = useT();
	return (
		<>
			<Field id="siem-central-format" label={t("siem.central.format")}>
				<select
					id="siem-central-format"
					value={form.format}
					onChange={(event) => set("format", event.target.value as SiemFormat)}
				>
					{(Object.keys(FORMAT_LABELS) as SiemFormat[]).map((format) => (
						<option key={format} value={format}>
							{t(FORMAT_LABELS[format])}
						</option>
					))}
				</select>
			</Field>
			<Field id="siem-central-transport" label={t("siem.transport")}>
				<select
					id="siem-central-transport"
					value={form.transport}
					onChange={(event) => {
						const transport = event.target.value as FormState["transport"];
						setForm((current) => ({
							...current,
							transport,
							port: transport === "tls" ? "6514" : "514",
						}));
					}}
				>
					<option value="tls">{t("siem.tls")}</option>
					<option value="tcp">{t("siem.tcp")}</option>
					<option value="udp">{t("siem.udp")}</option>
				</select>
			</Field>
			<TextField form={form} set={set} name="host" id="siem-central-host" label={t("siem.host")} />
			<TextField form={form} set={set} name="port" id="siem-central-port" label={t("siem.port")} />
			{form.transport !== "tls" ? (
				<label className="label">
					<input
						type="checkbox"
						checked={form.allowPlaintext}
						onChange={(event) => set("allowPlaintext", event.target.checked)}
					/>{" "}
					{t("siem.plaintext")}
				</label>
			) : null}
		</>
	);
}

function HttpFields({ form, set }: { form: FormState; set: SetField }) {
	const t = useT();
	return (
		<>
			<TextField
				form={form}
				set={set}
				name="url"
				id="siem-central-url"
				label={t("siem.central.url")}
				type="url"
			/>
			{form.provider === "splunk_hec" ? (
				<TextField
					form={form}
					set={set}
					name="token"
					id="siem-central-token"
					label={t("siem.central.hecToken")}
					type="password"
				/>
			) : null}
			{form.provider === "webhook" ? null : (
				<TextField
					form={form}
					set={set}
					name="index"
					id="siem-central-index"
					label={t("siem.central.index")}
				/>
			)}
			{form.provider === "elastic" ? (
				<TextField
					form={form}
					set={set}
					name="apiKey"
					id="siem-central-apikey"
					label={t("siem.central.apiKey")}
					type="password"
				/>
			) : null}
			{form.provider === "webhook" ? (
				<>
					<TextField
						form={form}
						set={set}
						name="secret"
						id="siem-central-secret"
						label={t("siem.central.secret")}
						type="password"
					/>
					<button
						type="button"
						className="button button-secondary button-sm"
						onClick={() => set("secret", generateWebhookSecret())}
					>
						{t("siem.central.generate")}
					</button>
				</>
			) : null}
		</>
	);
}

function SentinelFields({ form, set }: { form: FormState; set: SetField }) {
	const t = useT();
	return (
		<>
			<TextField
				form={form}
				set={set}
				name="endpoint"
				id="siem-central-dce"
				label={t("siem.central.dce")}
				type="url"
			/>
			<TextField
				form={form}
				set={set}
				name="dcrId"
				id="siem-central-dcr"
				label={t("siem.central.dcr")}
			/>
			<TextField
				form={form}
				set={set}
				name="stream"
				id="siem-central-stream"
				label={t("siem.central.stream")}
			/>
			<TextField
				form={form}
				set={set}
				name="azureTenant"
				id="siem-central-azure-tenant"
				label={t("siem.central.azureTenant")}
			/>
			<TextField
				form={form}
				set={set}
				name="clientId"
				id="siem-central-client"
				label={t("siem.central.clientId")}
			/>
			<TextField
				form={form}
				set={set}
				name="clientSecret"
				id="siem-central-client-secret"
				label={t("siem.central.clientSecret")}
				type="password"
			/>
		</>
	);
}

function CreateForm({
	tenantId,
	settings,
	onCreated,
}: {
	tenantId: string;
	settings: SiemSettings;
	onCreated: (message: string) => void;
}) {
	const t = useT();
	const [form, setForm] = useState<FormState>(EMPTY_FORM);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
		setForm((current) => ({ ...current, [key]: value }));
	const syslog = form.provider === "syslog";
	const httpWithCa =
		form.provider === "splunk_hec" || form.provider === "elastic" || form.provider === "webhook";

	async function submit(event: FormEvent) {
		event.preventDefault();
		setBusy(true);
		setError(null);
		const result = await createSiemDestination(tenantId, {
			provider: form.provider,
			format: syslog ? form.format : "json",
			name: form.name,
			config: buildSiemConfig(form),
			filters: form.filters,
		});
		setBusy(false);
		if (!result.ok) {
			setError(errorMessage(result.error, t));
			return;
		}
		setForm(EMPTY_FORM);
		onCreated(t("siem.central.created", { name: result.value.name }));
	}

	return (
		<form
			className="card"
			onSubmit={(event) => void submit(event)}
			aria-labelledby="siem-central-add"
		>
			<h3 id="siem-central-add">{t("siem.central.add")}</h3>
			<Field id="siem-central-name" label={t("common.name")}>
				<input
					id="siem-central-name"
					value={form.name}
					required
					maxLength={80}
					onChange={(event) => set("name", event.target.value)}
				/>
			</Field>
			<Field id="siem-central-provider" label={t("siem.central.provider")}>
				<select
					id="siem-central-provider"
					value={form.provider}
					onChange={(event) => set("provider", event.target.value as SiemProvider)}
				>
					{(Object.keys(PROVIDER_LABELS) as SiemProvider[]).map((provider) => (
						<option key={provider} value={provider}>
							{PROVIDER_LABELS[provider](t)}
						</option>
					))}
				</select>
			</Field>
			{syslog ? <SyslogFields form={form} set={set} setForm={setForm} /> : null}
			{httpWithCa ? <HttpFields form={form} set={set} /> : null}
			{form.provider === "sentinel" ? <SentinelFields form={form} set={set} /> : null}
			{(syslog && form.transport === "tls") || httpWithCa ? (
				<Field id="siem-central-ca" label={t("siem.ca")}>
					<textarea
						id="siem-central-ca"
						rows={4}
						value={form.caPem}
						onChange={(event) => set("caPem", event.target.value)}
					/>
				</Field>
			) : null}
			{form.provider !== "sentinel" && settings.privateNetworksAllowed ? (
				<label className="label">
					<input
						type="checkbox"
						checked={form.allowPrivate}
						onChange={(event) => set("allowPrivate", event.target.checked)}
					/>{" "}
					{t("siem.private")}
				</label>
			) : null}
			<FiltersEditor filters={form.filters} onChange={(filters) => set("filters", filters)} />
			<p className="muted small">{t("siem.central.writeOnly")}</p>
			{error ? (
				<div className="notice notice-danger" role="alert">
					{error}
				</div>
			) : null}
			<button type="submit" className="button" disabled={busy || !settings.canManage}>
				{busy ? t("common.saving") : t("siem.central.save")}
			</button>
		</form>
	);
}

function DestinationRow({
	destination,
	tenantId,
	canManage,
	onChanged,
}: {
	destination: SiemDestination;
	tenantId: string;
	canManage: boolean;
	onChanged: (message: string, error?: boolean) => void;
}) {
	const t = useT();
	const [busy, setBusy] = useState(false);
	async function toggle() {
		setBusy(true);
		const result = await updateSiemDestination(tenantId, destination.id, {
			enabled: !destination.enabled,
		});
		setBusy(false);
		onChanged(result.ok ? t("siem.central.updated") : errorMessage(result.error, t), !result.ok);
	}
	async function act(action: "delete" | "test" | "requeue") {
		setBusy(true);
		const result = await siemDestinationAction(tenantId, destination.id, action);
		setBusy(false);
		if (!result.ok) return onChanged(errorMessage(result.error, t), true);
		const delivered = result.value.status === "delivered";
		const messages = {
			test: delivered
				? t("siem.central.testOk")
				: t("siem.central.testFailed", { code: result.value.error ?? t("common.unknown") }),
			requeue: t("siem.central.requeued", { count: result.value.requeued ?? 0 }),
			delete: t("siem.central.deleted"),
		};
		onChanged(messages[action], action === "test" && !delivered);
	}
	return (
		<tr>
			<td>{destination.name}</td>
			<td>
				{PROVIDER_LABELS[destination.provider](t)}
				{destination.provider === "syslog" ? ` · ${t(FORMAT_LABELS[destination.format])}` : ""}
			</td>
			<td>
				<code>{destination.targetHint}</code>
			</td>
			<td>
				{destination.enabled ? t("common.enabled") : t("common.disabled")}
				{destination.lastDeliveryStatus ? ` · ${destination.lastDeliveryStatus}` : ""}
				{destination.lastError ? ` (${destination.lastError})` : ""}
			</td>
			<td>
				{t("siem.central.queue", {
					pending: destination.pending,
					dead: destination.dead,
					dropped: destination.droppedEvents,
				})}
			</td>
			<td>
				{canManage ? (
					<span className="row">
						<button
							type="button"
							className="button button-sm"
							disabled={busy}
							onClick={() => void act("test")}
						>
							{t("siem.central.test")}
						</button>
						<button
							type="button"
							className="button button-secondary button-sm"
							disabled={busy}
							onClick={() => void toggle()}
						>
							{destination.enabled ? t("siem.central.disable") : t("siem.central.enable")}
						</button>
						{destination.dead > 0 && destination.enabled ? (
							<button
								type="button"
								className="button button-secondary button-sm"
								disabled={busy}
								onClick={() => void act("requeue")}
							>
								{t("siem.central.requeue")}
							</button>
						) : null}
						<button
							type="button"
							className="button button-danger button-sm"
							disabled={busy}
							onClick={() => void act("delete")}
						>
							{t("siem.central.delete")}
						</button>
					</span>
				) : null}
			</td>
		</tr>
	);
}

function DestinationsTable({
	tenantId,
	settings,
	onChanged,
}: {
	tenantId: string;
	settings: SiemSettings;
	onChanged: (message: string, error?: boolean) => void;
}) {
	const t = useT();
	if (settings.destinations.length === 0) return <p className="muted">{t("siem.central.empty")}</p>;
	return (
		<table>
			<caption className="sr-only">{t("siem.central.title")}</caption>
			<thead>
				<tr>
					<th scope="col">{t("common.name")}</th>
					<th scope="col">{t("siem.central.provider")}</th>
					<th scope="col">{t("siem.central.target")}</th>
					<th scope="col">{t("common.status")}</th>
					<th scope="col">{t("siem.central.queueHeading")}</th>
					<th scope="col">
						<span className="sr-only">{t("siem.central.actions")}</span>
					</th>
				</tr>
			</thead>
			<tbody>
				{settings.destinations.map((destination) => (
					<DestinationRow
						key={destination.id}
						destination={destination}
						tenantId={tenantId}
						canManage={settings.canManage}
						onChanged={onChanged}
					/>
				))}
			</tbody>
		</table>
	);
}

function DeadLetters({ settings }: { settings: SiemSettings }) {
	const t = useT();
	if (settings.deadLetters.length === 0) return null;
	const nameOf = (id: string) => settings.destinations.find((item) => item.id === id)?.name ?? id;
	return (
		<>
			<h3>{t("siem.central.deadLetters")}</h3>
			<p className="muted small">{t("siem.central.deadLettersLead")}</p>
			<table>
				<thead>
					<tr>
						<th scope="col">{t("siem.central.deadAt")}</th>
						<th scope="col">{t("siem.central.provider")}</th>
						<th scope="col">{t("siem.central.event")}</th>
						<th scope="col">{t("siem.central.lastError")}</th>
					</tr>
				</thead>
				<tbody>
					{settings.deadLetters.map((letter) => (
						<tr key={letter.id}>
							<td>{letter.deadAt ?? "—"}</td>
							<td>{nameOf(letter.destinationId)}</td>
							<td>{[letter.kind, letter.decision, letter.severity].filter(Boolean).join(" · ")}</td>
							<td>
								{letter.lastError ?? "—"}
								{letter.lastStatusCode ? ` (HTTP ${letter.lastStatusCode})` : ""}
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</>
	);
}

/** Events the server could not queue for forwarding (kept in AIDR, never sent). */
function EnqueueFailures({ count }: { count: number }) {
	const t = useT();
	if (count <= 0) return null;
	return (
		<p className="notice notice-danger" role="alert">
			{t("siem.central.enqueueFailures", { count })}
		</p>
	);
}

/** Central (control-plane) SIEM forwarding: destinations, health and dead letters. */
export function SiemDestinations({ tenantId }: { tenantId: string }) {
	const t = useT();
	const [settings, setSettings] = useState<SiemSettings | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [notice, setNotice] = useState<{ text: string; error: boolean } | null>(null);
	const reload = useCallback(async () => {
		const result = await loadSiemSettings(tenantId);
		if (result.ok) {
			setSettings(result.value);
			setLoadError(null);
		} else setLoadError(result.error);
	}, [tenantId]);
	useEffect(() => {
		void reload();
	}, [reload]);
	const changed = (text: string, error = false) => {
		setNotice({ text, error });
		void reload();
	};

	return (
		<section className="card" aria-labelledby="siem-central-heading">
			<h2 id="siem-central-heading">{t("siem.central.title")}</h2>
			<p className="muted">{t("siem.central.lead")}</p>
			{loadError ? (
				<div className="notice notice-danger" role="alert">
					{errorMessage(loadError, t)}
				</div>
			) : null}
			{notice ? (
				<div
					className={notice.error ? "notice notice-danger" : "notice"}
					role={notice.error ? "alert" : "status"}
				>
					{notice.text}
				</div>
			) : null}
			{settings && !settings.configured ? (
				<p className="notice notice-danger" role="alert">
					{t("siem.central.error.notConfigured")}
				</p>
			) : null}
			{settings ? <EnqueueFailures count={settings.enqueueFailures} /> : null}
			{settings ? (
				<>
					<DestinationsTable tenantId={tenantId} settings={settings} onChanged={changed} />
					<DeadLetters settings={settings} />
					{settings.canManage && settings.destinations.length < settings.maxDestinations ? (
						<CreateForm
							tenantId={tenantId}
							settings={settings}
							onCreated={(text) => changed(text)}
						/>
					) : null}
				</>
			) : !loadError ? (
				<p className="muted">{t("common.loading")}</p>
			) : null}
		</section>
	);
}

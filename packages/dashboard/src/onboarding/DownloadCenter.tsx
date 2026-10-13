import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useT } from "../i18n/I18nProvider";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import {
	artifactFileName,
	fetchReleaseManifest,
	formatBytes,
	type ReleaseArtifact,
	type ReleaseArtifactId,
	type ReleaseManifest,
	resolveReleaseManifestSource,
	verifyCommands,
} from "./release-manifest";
import {
	type AgentCheckIn,
	latestCheckIn,
	RUNTIME_CATALOG,
	type RuntimeCatalogEntry,
	runtimeLabel,
} from "./runtime-catalog";

export type ManifestState =
	| { state: "not-configured" }
	| { state: "loading" }
	| { state: "error"; message: string }
	| { state: "ready"; manifest: ReleaseManifest };

type CheckInState =
	| { state: "loading" }
	| { state: "unavailable" }
	| { state: "ready"; agents: AgentCheckIn[] };

function isCheckInRow(value: unknown): value is AgentCheckIn {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
	const row = value as Record<string, unknown>;
	return (
		(row.agent_runtime === null || typeof row.agent_runtime === "string") &&
		(row.agent_runtime_version === null || typeof row.agent_runtime_version === "string") &&
		typeof row.last_seen === "string"
	);
}

/**
 * The validated release manifest of this deployment (onboarding also uses it to
 * pin versions). `skip` leaves the fetch to a parent that already loads it.
 */
export function useReleaseManifest(skip = false): ManifestState {
	const t = useT();
	const source = useMemo(() => resolveReleaseManifestSource(), []);
	const [state, setState] = useState<ManifestState>(() =>
		!source.configured
			? { state: "not-configured" }
			: "error" in source
				? { state: "error", message: source.error }
				: { state: "loading" },
	);
	useEffect(() => {
		if (skip || !source.configured || "error" in source) return;
		const controller = new AbortController();
		fetchReleaseManifest(source.url, fetch, controller.signal)
			.then((manifest) => {
				if (!controller.signal.aborted) setState({ state: "ready", manifest });
			})
			.catch((cause: unknown) => {
				if (controller.signal.aborted) return;
				setState({
					state: "error",
					message: readErrorMessage(cause, t("dc.manifestFailed")),
				});
			});
		return () => controller.abort();
	}, [source, skip]);
	return state;
}

function useAgentCheckIns(teamId: string | null): CheckInState {
	const [state, setState] = useState<CheckInState>({ state: "loading" });
	useEffect(() => {
		let cancelled = false;
		setState({ state: "loading" });
		if (!teamId) {
			setState({ state: "unavailable" });
			return;
		}
		async function load(activeTeamId: string) {
			try {
				const res = await supabase
					.from("agents")
					.select("agent_runtime,agent_runtime_version,last_seen")
					.eq("tenant_id", activeTeamId)
					.order("last_seen", { ascending: false })
					.limit(1000);
				if (cancelled) return;
				if (res.error || !Array.isArray(res.data) || !res.data.every(isCheckInRow)) {
					setState({ state: "unavailable" });
					return;
				}
				setState({ state: "ready", agents: res.data });
			} catch {
				if (!cancelled) setState({ state: "unavailable" });
			}
		}
		void load(teamId);
		return () => {
			cancelled = true;
		};
	}, [teamId]);
	return state;
}

function CopyButton({ value, label }: { value: string; label: string }) {
	const t = useT();
	const [status, setStatus] = useState<"idle" | "copied" | "error">("idle");
	return (
		<>
			<button
				className="button button-secondary button-sm"
				type="button"
				aria-label={label}
				onClick={async () => {
					try {
						await navigator.clipboard.writeText(value);
						setStatus("copied");
					} catch {
						setStatus("error");
					}
				}}
			>
				{status === "copied" ? t("dc.copied") : t("dc.copy")}
			</button>
			{status === "error" ? <span className="muted small">{t("dc.copyBlocked")}</span> : null}
		</>
	);
}

function CheckInBadge({ entry, checkIns }: { entry: RuntimeCatalogEntry; checkIns: CheckInState }) {
	const t = useT();
	if (!entry.detection) {
		return <span className="pill">{t("dc.noCheckIn")}</span>;
	}
	if (checkIns.state === "loading") return <span className="muted small">{t("dc.checking")}</span>;
	if (checkIns.state === "unavailable") {
		return <span className="muted small">{t("dc.checkInUnavailable")}</span>;
	}
	const lastSeen = latestCheckIn(entry, checkIns.agents);
	return lastSeen ? (
		<span className="pill pill-success">
			{t("dc.detected", { time: new Date(lastSeen).toLocaleString() })}
		</span>
	) : (
		<span className="pill pill-warning">{t("dc.notDetected")}</span>
	);
}

function ArtifactDownload({ artifact, label }: { artifact: ReleaseArtifact; label: string }) {
	const t = useT();
	const file = artifactFileName(artifact);
	return (
		<div className="notice" style={{ marginTop: 10 }}>
			<div className="row" style={{ flexWrap: "wrap", alignItems: "center" }}>
				<a className="button" href={artifact.url} download={file} rel="noopener noreferrer">
					{t("dc.download", { file })}
				</a>
				<span className="muted small">
					v{artifact.version} · {formatBytes(artifact.size)} · {artifact.platforms.join(", ")}
				</span>
			</div>
			<div className="muted small" style={{ marginTop: 8 }}>
				SHA-256
			</div>
			<div className="row" style={{ alignItems: "center", flexWrap: "wrap" }}>
				<code
					className="mono"
					style={{ overflowWrap: "anywhere" }}
					aria-label={t("dc.shaFor", { label, file })}
				>
					{artifact.sha256}
				</code>
				<CopyButton value={artifact.sha256} label={t("dc.copySha", { file })} />
			</div>
			<details style={{ marginTop: 8 }}>
				<summary>{t("dc.verifySummary")}</summary>
				{verifyCommands(artifact).map((command) => (
					<div key={command.label} style={{ marginTop: 6 }}>
						<div className="muted small">{command.label}</div>
						<pre className="mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
							{command.command}
						</pre>
					</div>
				))}
				<p className="muted small">{t("dc.verifyFail")}</p>
			</details>
			{artifact.signature ? (
				<div className="muted small" style={{ marginTop: 8 }}>
					<a href={artifact.signature} rel="noopener noreferrer">
						{t("dc.signature", { file })}
					</a>
					{t("dc.signatureNote")}
				</div>
			) : (
				<div className="muted small" style={{ marginTop: 8 }}>
					{t("dc.noSignature")}
				</div>
			)}
		</div>
	);
}

function Enrollment({ entry, teamId }: { entry: RuntimeCatalogEntry; teamId: string | null }) {
	const t = useT();
	const label = runtimeLabel(entry, t);
	const verifyHref = teamId ? `/verify?team=${encodeURIComponent(teamId)}` : "/verify";
	if (entry.enrollment === "device") {
		return (
			<>
				<p className="small">{t("dc.device", { label })}</p>
				<div className="row" style={{ flexWrap: "wrap" }}>
					<Link className="button button-secondary button-sm" to={verifyHref}>
						{t("dc.verifyCode")}
					</Link>
				</div>
			</>
		);
	}
	if (entry.enrollment === "managed-config") {
		return <p className="small">{t("dc.managedConfig", { label })}</p>;
	}
	if (entry.enrollment === "api-key") {
		return (
			<>
				<p className="small">{t("dc.apiKey")}</p>
				<div className="row" style={{ flexWrap: "wrap" }}>
					<Link className="button button-secondary button-sm" to="/api-keys?type=browser_guard">
						{t("dc.createBgKey")}
					</Link>
				</div>
			</>
		);
	}
	return <p className="small">{t("dc.noCheckInBody", { label })}</p>;
}

function RuntimeCard({
	entry,
	manifest,
	checkIns,
	teamId,
	headingLevel,
}: {
	entry: RuntimeCatalogEntry;
	manifest: ManifestState;
	checkIns: CheckInState;
	teamId: string | null;
	headingLevel: 2 | 3;
}) {
	const t = useT();
	const label = runtimeLabel(entry, t);
	const artifacts =
		manifest.state === "ready"
			? manifest.manifest.artifacts.filter((artifact) => artifact.id === entry.id)
			: [];
	const Heading = headingLevel === 2 ? "h2" : "h3";
	const SubHeading = headingLevel === 2 ? "h3" : "h4";
	return (
		<section className="card" aria-label={label} data-runtime={entry.id}>
			<div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap" }}>
				<Heading style={{ margin: 0 }}>{label}</Heading>
				<CheckInBadge entry={entry} checkIns={checkIns} />
			</div>
			<p className="muted small">{t(entry.summary)}</p>

			<SubHeading>{t("dc.downloadTitle")}</SubHeading>
			{manifest.state === "ready" ? (
				artifacts.length > 0 ? (
					artifacts.map((artifact) => (
						<ArtifactDownload
							key={`${artifact.id}-${artifact.platforms.join("-")}`}
							artifact={artifact}
							label={label}
						/>
					))
				) : (
					<p className="muted small">
						{t("dc.noArtifact", { version: manifest.manifest.version, label })}
					</p>
				)
			) : manifest.state === "loading" ? (
				<p className="muted small">{t("dc.loadingManifest")}</p>
			) : (
				<p className="muted small">{t("dc.noDownload")}</p>
			)}

			<SubHeading>{t("dc.installTitle")}</SubHeading>
			<ol className="small">
				{entry.installSteps(artifacts[0] ?? null, t).map((step) => (
					<li key={step.text} style={{ marginBottom: 6 }}>
						{step.text}
						{step.command ? (
							<pre className="mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
								{step.command}
							</pre>
						) : null}
					</li>
				))}
			</ol>
			<p className="muted small">{t("dc.guide", { guide: entry.guide })}</p>

			<SubHeading>{t("dc.connectTitle")}</SubHeading>
			<Enrollment entry={entry} teamId={teamId} />
		</section>
	);
}

/**
 * Per-runtime download, verification, install and enrollment cards.
 *
 * Download links, digests and sizes come only from the validated release
 * manifest. With no manifest configured the cards still show install and
 * enrollment guidance but no links, and the "detected" badge reflects only real
 * check-ins in the agents table for this team.
 */
export function DownloadCenter({
	teamId,
	only,
	headingLevel = 2,
	manifestState,
}: {
	teamId: string | null;
	only?: ReleaseArtifactId[];
	headingLevel?: 2 | 3;
	/** The manifest a parent already loaded; fetched here when absent. */
	manifestState?: ManifestState;
}) {
	const t = useT();
	const ownManifest = useReleaseManifest(manifestState !== undefined);
	const manifest = manifestState ?? ownManifest;
	const checkIns = useAgentCheckIns(teamId);
	const entries = only
		? RUNTIME_CATALOG.filter((entry) => only.includes(entry.id))
		: RUNTIME_CATALOG;
	return (
		<div className="stack">
			{manifest.state === "not-configured" ? (
				<div className="notice notice-warning">
					<b>{t("dc.notConfigured")}</b> {t("dc.notConfiguredBody")}
				</div>
			) : null}
			{manifest.state === "error" ? (
				<div className="notice notice-danger" role="alert">
					<b>{t("dc.withheld")}</b> {manifest.message}
				</div>
			) : null}
			{manifest.state === "ready" ? (
				<div className="muted small">
					{t("dc.release", {
						version: manifest.manifest.version,
						time: new Date(manifest.manifest.publishedAt).toLocaleString(),
					})}
				</div>
			) : null}
			{entries.map((entry) => (
				<RuntimeCard
					key={entry.id}
					entry={entry}
					manifest={manifest}
					checkIns={checkIns}
					teamId={teamId}
					headingLevel={headingLevel}
				/>
			))}
		</div>
	);
}

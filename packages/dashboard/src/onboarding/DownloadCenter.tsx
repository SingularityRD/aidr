import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
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
} from "./runtime-catalog";

type ManifestState =
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

function useReleaseManifest(): ManifestState {
	const source = useMemo(() => resolveReleaseManifestSource(), []);
	const [state, setState] = useState<ManifestState>(() =>
		!source.configured
			? { state: "not-configured" }
			: "error" in source
				? { state: "error", message: source.error }
				: { state: "loading" },
	);
	useEffect(() => {
		if (!source.configured || "error" in source) return;
		const controller = new AbortController();
		fetchReleaseManifest(source.url, fetch, controller.signal)
			.then((manifest) => {
				if (!controller.signal.aborted) setState({ state: "ready", manifest });
			})
			.catch((cause: unknown) => {
				if (controller.signal.aborted) return;
				setState({
					state: "error",
					message: readErrorMessage(cause, "The release manifest could not be loaded."),
				});
			});
		return () => controller.abort();
	}, [source]);
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
				{status === "copied" ? "Copied" : "Copy"}
			</button>
			{status === "error" ? (
				<span className="muted small">Clipboard blocked. Select the text and copy it.</span>
			) : null}
		</>
	);
}

function CheckInBadge({ entry, checkIns }: { entry: RuntimeCatalogEntry; checkIns: CheckInState }) {
	if (!entry.detection) {
		return <span className="pill">No control-plane check-in</span>;
	}
	if (checkIns.state === "loading") return <span className="muted small">Checking check-ins…</span>;
	if (checkIns.state === "unavailable") {
		return <span className="muted small">Check-in status unavailable</span>;
	}
	const lastSeen = latestCheckIn(entry, checkIns.agents);
	return lastSeen ? (
		<span className="pill pill-success">
			Detected · last check-in {new Date(lastSeen).toLocaleString()}
		</span>
	) : (
		<span className="pill pill-warning">Not detected yet</span>
	);
}

function ArtifactDownload({ artifact, label }: { artifact: ReleaseArtifact; label: string }) {
	const file = artifactFileName(artifact);
	return (
		<div className="notice" style={{ marginTop: 10 }}>
			<div className="row" style={{ flexWrap: "wrap", alignItems: "center" }}>
				<a className="button" href={artifact.url} download={file} rel="noopener noreferrer">
					Download {file}
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
					aria-label={`SHA-256 for ${label} ${file}`}
				>
					{artifact.sha256}
				</code>
				<CopyButton value={artifact.sha256} label={`Copy SHA-256 for ${file}`} />
			</div>
			<details style={{ marginTop: 8 }}>
				<summary>Verify the download before installing</summary>
				{verifyCommands(artifact).map((command) => (
					<div key={command.label} style={{ marginTop: 6 }}>
						<div className="muted small">{command.label}</div>
						<pre className="mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
							{command.command}
						</pre>
					</div>
				))}
				<p className="muted small">Do not install the file if the check fails.</p>
			</details>
			{artifact.signature ? (
				<div className="muted small" style={{ marginTop: 8 }}>
					<a href={artifact.signature} rel="noopener noreferrer">
						Detached signature for {file}
					</a>
					. Verify it with the publisher key your release operator delivered separately.
				</div>
			) : (
				<div className="muted small" style={{ marginTop: 8 }}>
					No detached signature is published for this file. Check the SHA-256 against your approved
					release record.
				</div>
			)}
		</div>
	);
}

function Enrollment({ entry, teamId }: { entry: RuntimeCatalogEntry; teamId: string | null }) {
	const verifyHref = teamId ? `/verify?team=${encodeURIComponent(teamId)}` : "/verify";
	if (entry.enrollment === "device") {
		return (
			<>
				<p className="small">
					Start {entry.label} once after installing. In managed mode it shows a short code and a
					verification URL; approve the code for this team. Restart the agent afterwards.
				</p>
				<div className="row" style={{ flexWrap: "wrap" }}>
					<Link className="button button-secondary button-sm" to={verifyHref}>
						Verify a device code
					</Link>
				</div>
			</>
		);
	}
	if (entry.enrollment === "managed-config") {
		return (
			<p className="small">
				{entry.label} has no device-code prompt. It enrolls through the signed runtime configuration
				your operator deploys to ~/.singularity-aidr/config.json.
			</p>
		);
	}
	if (entry.enrollment === "api-key") {
		return (
			<>
				<p className="small">
					Create a Browser Guard ingest-only key, then set the managed policy keys controlPlaneUrl
					and apiKey (or enter them in the extension options). Managed policy wins. The key can only
					report counts, never prompt text, for a capped number of browsers; do not use a tenant key
					here, because users of a managed browser can read its policy.
				</p>
				<div className="row" style={{ flexWrap: "wrap" }}>
					<Link className="button button-secondary button-sm" to="/api-keys?type=browser_guard">
						Create a Browser Guard key
					</Link>
				</div>
			</>
		);
	}
	return (
		<p className="small">
			{entry.label} does not check in with the control plane, so the dashboard cannot confirm it is
			installed.
		</p>
	);
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
	const artifacts =
		manifest.state === "ready"
			? manifest.manifest.artifacts.filter((artifact) => artifact.id === entry.id)
			: [];
	const Heading = headingLevel === 2 ? "h2" : "h3";
	const SubHeading = headingLevel === 2 ? "h3" : "h4";
	return (
		<section className="card" aria-label={entry.label} data-runtime={entry.id}>
			<div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap" }}>
				<Heading style={{ margin: 0 }}>{entry.label}</Heading>
				<CheckInBadge entry={entry} checkIns={checkIns} />
			</div>
			<p className="muted small">{entry.summary}</p>

			<SubHeading>Download</SubHeading>
			{manifest.state === "ready" ? (
				artifacts.length > 0 ? (
					artifacts.map((artifact) => (
						<ArtifactDownload
							key={`${artifact.id}-${artifact.platforms.join("-")}`}
							artifact={artifact}
							label={entry.label}
						/>
					))
				) : (
					<p className="muted small">
						Release {manifest.manifest.version} does not include a {entry.label} artifact.
					</p>
				)
			) : manifest.state === "loading" ? (
				<p className="muted small">Loading the release manifest…</p>
			) : (
				<p className="muted small">No verified download is available for this deployment.</p>
			)}

			<SubHeading>Install</SubHeading>
			<ol className="small">
				{entry.installSteps(artifacts[0] ?? null).map((step) => (
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
			<p className="muted small">Full guide: {entry.guide}</p>

			<SubHeading>Connect</SubHeading>
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
}: {
	teamId: string | null;
	only?: ReleaseArtifactId[];
	headingLevel?: 2 | 3;
}) {
	const manifest = useReleaseManifest();
	const checkIns = useAgentCheckIns(teamId);
	const entries = only
		? RUNTIME_CATALOG.filter((entry) => only.includes(entry.id))
		: RUNTIME_CATALOG;
	return (
		<div className="stack">
			{manifest.state === "not-configured" ? (
				<div className="notice notice-warning">
					<b>No release manifest is published for this deployment.</b> Download links appear here
					once your release operator publishes one (AIDR_RELEASE_MANIFEST_PATH on the dashboard
					server, or VITE_AIDR_RELEASE_MANIFEST_URL). Until then, get installers from your approved
					release bundle.
				</div>
			) : null}
			{manifest.state === "error" ? (
				<div className="notice notice-danger" role="alert">
					<b>Downloads are withheld.</b> {manifest.message}
				</div>
			) : null}
			{manifest.state === "ready" ? (
				<div className="muted small">
					Release {manifest.manifest.version} · published{" "}
					{new Date(manifest.manifest.publishedAt).toLocaleString()}
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

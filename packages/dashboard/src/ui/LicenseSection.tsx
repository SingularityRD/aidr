import { useCallback, useEffect, useState } from "react";
import type { DashboardMessageKey } from "../i18n/en";
import { useT } from "../i18n/I18nProvider";
import {
	fetchLicenseStatus,
	fetchUsageReport,
	type LicenseStatus,
	licenseSubmitErrorKey,
	MAX_LICENSE_FILE_BYTES,
	parseLicenseFile,
	submitLicense,
} from "../lib/license";

const DASHBOARD_VERSION =
	(import.meta.env.VITE_AIDR_DASHBOARD_VERSION as string | undefined) || "unknown";

const REASONS: Record<string, DashboardMessageKey> = {
	bad_signature: "license.reason.bad_signature",
	expired: "license.reason.expired",
	customer_mismatch: "license.reason.customer_mismatch",
	unknown_key: "license.reason.unknown_key",
	revoked_key: "license.reason.revoked_key",
};

function reasonText(t: ReturnType<typeof useT>, reason: string | null): string {
	const key = reason && Object.hasOwn(REASONS, reason) ? REASONS[reason] : undefined;
	return key ? t(key) : t("license.reason.other", { code: reason ?? "unknown" });
}

function saveJson(name: string, value: unknown): boolean {
	if (typeof URL === "undefined" || typeof URL.createObjectURL !== "function") return false;
	const url = URL.createObjectURL(
		new Blob([`${JSON.stringify(value, null, 2)}\n`], { type: "application/json" }),
	);
	const anchor = document.createElement("a");
	anchor.href = url;
	anchor.download = name;
	document.body.appendChild(anchor);
	anchor.click();
	anchor.remove();
	URL.revokeObjectURL(url);
	return true;
}

/** Settings -> License: status, signed-license import (staged) and usage report. */
export function LicenseSection({ tenantId }: { tenantId: string }) {
	const t = useT();
	const [status, setStatus] = useState<LicenseStatus | null | "loading">("loading");
	const [file, setFile] = useState<File | null>(null);
	const [busy, setBusy] = useState(false);
	const [notice, setNotice] = useState<{ tone: "success" | "error"; text: string } | null>(null);

	const load = useCallback(async () => {
		setStatus(await fetchLicenseStatus(tenantId));
	}, [tenantId]);

	useEffect(() => {
		void load();
	}, [load]);

	async function submit() {
		if (!file) return;
		setNotice(null);
		if (file.size > MAX_LICENSE_FILE_BYTES) {
			setNotice({ tone: "error", text: t("license.err.tooLarge") });
			return;
		}
		const document = parseLicenseFile(await file.text());
		if (!document) {
			setNotice({ tone: "error", text: t("license.import.invalidFile") });
			return;
		}
		setBusy(true);
		try {
			const result = await submitLicense(tenantId, document);
			if (!result.ok) {
				const key = licenseSubmitErrorKey(result.code);
				setNotice({
					tone: "error",
					text:
						key === "license.err.rejected"
							? t(key, { reason: reasonText(t, result.reason) })
							: t(key),
				});
				return;
			}
			setNotice({
				tone: "success",
				text: t("license.import.done", {
					id: result.licenseId,
					seats: result.seats,
					date: new Date(result.expiresAt).toLocaleDateString(),
				}),
			});
			await load();
		} finally {
			setBusy(false);
		}
	}

	async function downloadReport() {
		setNotice(null);
		const report = await fetchUsageReport(tenantId, Date.now(), DASHBOARD_VERSION);
		if (
			!report ||
			!saveJson(`aidr-usage-report-${report.generated_at.slice(0, 10)}.json`, report)
		) {
			setNotice({ tone: "error", text: t("license.report.failed") });
		}
	}

	const current = status === "loading" ? null : status;
	return (
		<div className="card" id="license">
			<h2>{t("license.title")}</h2>
			<p className="muted">{t("license.intro")}</p>
			{status === "loading" ? (
				<div role="status" className="muted">
					{t("license.loading")}
				</div>
			) : status === null ? (
				<div className="notice notice-warning" role="status">
					{t("license.unavailable")}
				</div>
			) : current?.license ? (
				<dl className="kv" data-license-source="signed">
					<dt>{t("license.source.signed")}</dt>
					<dd className="mono">{current.license.licenseId}</dd>
					<dt>{t("license.field.seats")}</dt>
					<dd>{current.license.seats}</dd>
					<dt>{t("license.field.expires")}</dt>
					<dd>{new Date(current.license.expiresAt).toLocaleString()}</dd>
					<dt>{t("license.field.graceEnds")}</dt>
					<dd>{new Date(current.license.graceEndsAt).toLocaleString()}</dd>
				</dl>
			) : current?.admission && current.admission.kind === "licensed" ? (
				<dl className="kv" data-license-source="admission">
					<dt>{t("license.source.admission")}</dt>
					<dd />
					<dt>{t("license.field.seats")}</dt>
					<dd>{current.admission.seats}</dd>
					<dt>{t("license.field.graceEnds")}</dt>
					<dd>{new Date(current.admission.expiresAt).toLocaleString()}</dd>
				</dl>
			) : (
				<p className="muted">{t("license.none")}</p>
			)}

			{current?.pending ? (
				<div className="notice notice-warning" role="status" style={{ marginTop: 12 }}>
					<b>{t("license.pending.title")}</b>{" "}
					{t("license.pending.body", {
						id: current.pending.licenseId,
						seats: current.pending.seats,
						date: new Date(current.pending.expiresAt).toLocaleDateString(),
					})}
				</div>
			) : null}

			{notice ? (
				<div
					className={`notice ${notice.tone === "error" ? "notice-danger" : "notice-success"}`}
					role={notice.tone === "error" ? "alert" : "status"}
					style={{ marginTop: 12 }}
				>
					{notice.text}
				</div>
			) : null}

			{current?.canManage ? (
				<>
					<h3 style={{ marginTop: 16 }}>{t("license.import.title")}</h3>
					<p className="muted small">{t("license.import.body")}</p>
					<div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
						<label>
							<span className="sr-only">{t("license.import.file")}</span>
							<input
								type="file"
								accept="application/json,.json"
								aria-label={t("license.import.file")}
								disabled={busy}
								onChange={(event) => setFile(event.currentTarget.files?.[0] ?? null)}
							/>
						</label>
						<button
							className="button"
							type="button"
							disabled={!file || busy}
							onClick={() => void submit()}
						>
							{busy ? t("license.import.busy") : t("license.import.submit")}
						</button>
					</div>
					<h3 style={{ marginTop: 16 }}>{t("license.report.title")}</h3>
					<p className="muted small">{t("license.report.body")}</p>
					<button
						className="button button-secondary"
						type="button"
						onClick={() => void downloadReport()}
					>
						{t("license.report.download")}
					</button>
				</>
			) : current ? (
				<p className="muted small" style={{ marginTop: 12 }}>
					{t("license.import.readOnly")}
				</p>
			) : null}
		</div>
	);
}

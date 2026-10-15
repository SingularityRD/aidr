import { useState } from "react";
import { useT } from "../../i18n/I18nProvider";
import { MAX_LICENSE_FILE_BYTES, parseLicenseFile } from "../../lib/license";
import {
	appliedLicense,
	callOperatorAdmin,
	type OperatorCall,
	operatorErrorMessage,
	type PendingLicenseImport,
	parseLicenseImports,
} from "../../lib/operator-admin";

/**
 * Operator console: licences workspace admins verified and staged, and a
 * direct "apply a licence file" form for the selected tenant. Every apply goes
 * to operator-admin `apply_license`, which re-verifies the signature and uses
 * the licensed-admission grant path (admission operator, non-member actor).
 */
export function OperatorLicenseImports({
	accessToken,
	selectedTenantId,
	onApplied,
	onForbidden,
}: {
	accessToken: string;
	selectedTenantId: string | null;
	onApplied: () => Promise<unknown>;
	onForbidden: (status: number | null, code: string | null) => boolean;
}) {
	const t = useT();
	const [imports, setImports] = useState<PendingLicenseImport[] | null>(null);
	const [busy, setBusy] = useState(false);
	const [file, setFile] = useState<File | null>(null);
	const [notice, setNotice] = useState<{ tone: "success" | "error"; text: string } | null>(null);

	function failure(
		response: Extract<OperatorCall<unknown>, { ok: false }>,
		fallback: string,
	): string {
		if (response.code === "license_rejected") {
			return t("op.err.licenseRejected", { reason: response.reason ?? "unknown" });
		}
		return operatorErrorMessage(response.code, fallback, t);
	}

	async function load() {
		setBusy(true);
		setNotice(null);
		const response = await callOperatorAdmin(accessToken, { action: "list_license_imports" });
		setBusy(false);
		if (!response.ok) {
			if (!onForbidden(response.status, response.code)) {
				setNotice({ tone: "error", text: failure(response, t("op.err.unavailable")) });
			}
			return;
		}
		const parsed = parseLicenseImports(response.result);
		if (!parsed) {
			setNotice({ tone: "error", text: t("op.err.unavailable") });
			return;
		}
		setImports(parsed);
	}

	async function apply(body: Record<string, unknown>) {
		setBusy(true);
		setNotice(null);
		try {
			const response = await callOperatorAdmin(accessToken, { action: "apply_license", ...body });
			if (!response.ok) {
				if (!onForbidden(response.status, response.code)) {
					setNotice({ tone: "error", text: failure(response, t("op.licenseUnconfirmed")) });
				}
				return;
			}
			const applied = appliedLicense(response.result);
			if (!applied) {
				setNotice({ tone: "error", text: t("op.licenseUnconfirmed") });
				return;
			}
			setNotice({
				tone: "success",
				text: t("op.licenseApplied", {
					id: applied.licenseId,
					seats: applied.seats,
					date: new Date(applied.graceEndsAt).toLocaleDateString(),
				}),
			});
			setImports((rows) => rows?.filter((row) => row.licenseId !== applied.licenseId) ?? rows);
			await onApplied();
		} finally {
			setBusy(false);
		}
	}

	async function applyFile() {
		if (!file || !selectedTenantId) return;
		const document =
			file.size <= MAX_LICENSE_FILE_BYTES ? parseLicenseFile(await file.text()) : null;
		if (!document) {
			setNotice({ tone: "error", text: t("op.err.license") });
			return;
		}
		await apply({ tenant_id: selectedTenantId, license: document });
	}

	return (
		<section className="card" aria-labelledby="licence-imports-heading">
			<div className="row space-between">
				<h2 id="licence-imports-heading">{t("op.license")}</h2>
				<button
					className="button button-secondary button-sm"
					type="button"
					disabled={busy}
					onClick={() => void load()}
				>
					{t("op.licenseLoad")}
				</button>
			</div>
			<p className="muted small">{t("op.licenseLead")}</p>
			{notice ? (
				<div
					className={`notice ${notice.tone === "error" ? "notice-danger" : "notice-success"}`}
					role={notice.tone === "error" ? "alert" : "status"}
				>
					{notice.text}
				</div>
			) : null}
			{imports !== null && imports.length === 0 ? (
				<p className="muted">{t("op.licenseEmpty")}</p>
			) : null}
			{imports && imports.length > 0 ? (
				<ul className="stack" style={{ listStyle: "none", padding: 0 }}>
					{imports.map((row) => (
						<li key={row.id} className="row space-between" data-licence-import={row.id}>
							<span className="mono small">
								{t("op.licenseRow", {
									id: row.licenseId,
									seats: row.seats,
									date: new Date(row.expiresAt).toLocaleDateString(),
									tenant: row.tenantId,
								})}
							</span>
							<button
								className="button button-sm"
								type="button"
								disabled={busy}
								onClick={() =>
									void apply({ tenant_id: row.tenantId, import_id: row.id, license: row.document })
								}
							>
								{busy ? t("op.licenseApplying") : t("op.licenseApply")}
							</button>
						</li>
					))}
				</ul>
			) : null}
			<h3>{t("op.licenseUpload")}</h3>
			<p className="muted small">{t("op.licenseUploadLead")}</p>
			<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
				<input
					type="file"
					accept="application/json,.json"
					aria-label={t("op.licenseFile")}
					disabled={busy || !selectedTenantId}
					onChange={(event) => setFile(event.currentTarget.files?.[0] ?? null)}
				/>
				<button
					className="button button-sm"
					type="button"
					disabled={busy || !file || !selectedTenantId}
					onClick={() => void applyFile()}
				>
					{busy ? t("op.licenseApplying") : t("op.licenseApply")}
				</button>
			</div>
		</section>
	);
}

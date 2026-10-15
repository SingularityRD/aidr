import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../enterprise/team-provider";
import { useT } from "../i18n/I18nProvider";
import {
	fetchLicenseStatus,
	type LicenseBanner as LicenseBannerState,
	type LicenseStatus,
	licenseBanner,
} from "../lib/license";

const REFRESH_MS = 10 * 60 * 1000;

/**
 * Admission terms without a stored signed license (an unsigned pilot
 * bootstrap) have no license id, so they use the id-less wording rather than
 * rendering an empty "()".
 */
function bannerMessage(
	t: ReturnType<typeof useT>,
	banner: LicenseBannerState,
	id: string,
	date: string,
	graceDate: string,
): string {
	const days = banner.days;
	switch (banner.level) {
		case "expires_30":
			return id
				? t("license.banner.expires30", { id, days, date })
				: t("license.banner.expires30NoId", { days, date });
		case "expires_7":
			return id
				? t("license.banner.expires7", { id, days, date })
				: t("license.banner.expires7NoId", { days, date });
		case "grace":
			return t("license.banner.grace", { days, date, graceDate });
		default:
			return t("license.banner.expired", { graceDate });
	}
}

/**
 * License expiry banner: 30 and 7 days before the license end, during the
 * grace period and after it. A status that cannot be read shows nothing here
 * (Settings -> License reports it); it never renders as "licensed".
 */
export function LicenseBanner({ now = () => Date.now() }: { now?: () => number }) {
	const { currentTeam } = useTeam();
	const t = useT();
	const tenantId = currentTeam?.id ?? null;
	const [status, setStatus] = useState<{ tenantId: string; value: LicenseStatus | null } | null>(
		null,
	);

	useEffect(() => {
		let cancelled = false;
		if (!tenantId) return;
		const load = async () => {
			const value = await fetchLicenseStatus(tenantId);
			if (!cancelled) setStatus({ tenantId, value });
		};
		void load();
		const timer = setInterval(load, REFRESH_MS);
		return () => {
			cancelled = true;
			clearInterval(timer);
		};
	}, [tenantId]);

	if (!tenantId || status?.tenantId !== tenantId) return null;
	const banner = licenseBanner(status.value, now());
	if (banner.level === "none") return null;
	const date = banner.expiresAt ? new Date(banner.expiresAt).toLocaleDateString() : "";
	const graceDate = banner.graceEndsAt ? new Date(banner.graceEndsAt).toLocaleDateString() : "";
	const id = status.value?.license?.licenseId?.trim() ?? "";
	const message = bannerMessage(t, banner, id, date, graceDate);
	const tone =
		banner.level === "expires_30"
			? "notice"
			: banner.level === "expires_7"
				? "notice notice-warning"
				: "notice notice-danger";
	return (
		<div
			className={tone}
			role={banner.level === "expires_30" ? "status" : "alert"}
			data-license-banner={banner.level}
			style={{ marginBottom: 14 }}
		>
			{message} <Link to="/settings#license">{t("license.banner.action")}</Link>
		</div>
	);
}

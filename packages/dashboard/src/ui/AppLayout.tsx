import { useState } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { TeamProvider, useTeam } from "../enterprise/team-provider";
import type { DashboardMessageKey } from "../i18n/en";
import { LanguageToggle, useT } from "../i18n/I18nProvider";
import { supabaseEnvError } from "../lib/supabase";
import { signOut } from "./session";
import { ThemeToggle } from "./ThemeToggle";
import { usePendingApprovalCount } from "./use-pending-approvals";

function ManagedOutlet() {
	const { currentTeam, isLoading, error } = useTeam();
	const t = useT();
	if (isLoading) return <div role="status">{t("layout.resolvingTenant")}</div>;
	if (!currentTeam && error)
		return (
			<div role="alert">
				<p>{t("layout.teamLoadFailed")}</p>
				<p>{error}</p>
			</div>
		);
	// TeamProvider now bootstraps identity and gates BEFORE any protected table
	// read. Requiring currentTeam to discover the MFA policy deadlocked at AAL1.
	return <Outlet />;
}

interface NavAccess {
	canEditPolicy: boolean;
	currentRole: string | null;
	roleResolved: boolean;
}

interface NavItem {
	to: string;
	label: DashboardMessageKey;
	/** Omitted: shown to every signed-in member. */
	show?: (access: NavAccess) => boolean;
}

interface NavSection {
	id: string;
	label: DashboardMessageKey;
	items: readonly NavItem[];
}

const isOwner = ({ currentRole }: NavAccess) => currentRole === "owner";
const isOwnerOrAdmin = ({ currentRole }: NavAccess) =>
	currentRole === "owner" || currentRole === "admin";

/**
 * Console navigation, grouped by task. Each label is also the heading of the
 * page it opens (the page renders the same catalog key), so the link and the
 * page always use the same words.
 *
 * Visibility only declutters the menu: every page and row-level security
 * re-check the permission, so link visibility is never the control. "Team
 * policy" is hidden only once the caller's role is known to lack policy-edit
 * rights — while the role is still loading the link stays visible, because
 * hiding a capability on an unresolved role would make a slow or failed
 * lookup look like a permission decision. "Team" is shown to every
 * authenticated user because every role may read the membership list.
 */
export const NAV_SECTIONS: readonly NavSection[] = [
	{
		id: "overview",
		label: "nav.section.overview",
		items: [
			{ to: "/dashboard", label: "nav.dashboard" },
			{ to: "/events", label: "nav.events" },
			{ to: "/discovery", label: "nav.discovery" },
			{ to: "/posture", label: "nav.posture" },
		],
	},
	{
		id: "protection",
		label: "nav.section.protection",
		items: [
			{
				to: "/policies",
				label: "nav.policies",
				show: ({ canEditPolicy, roleResolved }) => !roleResolved || canEditPolicy,
			},
			{
				to: "/governance/detection-exceptions",
				label: "nav.detectionExceptions",
				show: isOwnerOrAdmin,
			},
			{ to: "/privacy-guard", label: "nav.browserGuard" },
			{ to: "/autosecops", label: "nav.autosecops" },
		],
	},
	{
		id: "response",
		label: "nav.section.response",
		items: [
			{ to: "/approvals", label: "nav.approvals" },
			{ to: "/incidents", label: "nav.incidents" },
		],
	},
	{
		id: "devices",
		label: "nav.section.devices",
		items: [
			{ to: "/onboarding", label: "nav.onboarding" },
			{ to: "/downloads", label: "nav.downloads" },
			{ to: "/agents", label: "nav.agents" },
			{ to: "/api-keys", label: "nav.apiKeys" },
		],
	},
	{
		id: "governance",
		label: "nav.section.governance",
		items: [
			{ to: "/governance", label: "nav.governance", show: isOwnerOrAdmin },
			{ to: "/governance/register", label: "nav.aiRegister" },
			{ to: "/compliance", label: "nav.compliance", show: isOwnerOrAdmin },
		],
	},
	{
		id: "admin",
		label: "nav.section.admin",
		items: [
			{ to: "/team", label: "nav.team" },
			{ to: "/settings", label: "nav.settings" },
			{ to: "/billing", label: "nav.billing" },
			{ to: "/sso", label: "nav.sso", show: isOwner },
			{ to: "/scim", label: "nav.scim", show: isOwner },
			{ to: "/retention", label: "nav.retention", show: isOwnerOrAdmin },
			{ to: "/siem", label: "nav.siem", show: ({ canEditPolicy }) => canEditPolicy },
		],
	},
];

/**
 * Dashboard approvals link. The pending-count badge is read only for roles
 * that can decide, once the role is resolved (after the identity gate).
 */
function ApprovalsNavLink() {
	const { currentTeam, currentRole, roleResolved } = useTeam();
	const canDecide = roleResolved && (currentRole === "owner" || currentRole === "admin");
	const count = usePendingApprovalCount(canDecide && currentTeam ? currentTeam.id : null);
	const t = useT();
	return (
		<NavLink to="/approvals">
			{t("nav.approvals")}
			{count ? (
				<span
					className="badge badge-warning badge-plain nav-count"
					data-testid="approvals-pending-count"
				>
					<span className="sr-only">{t("layout.pendingCount")}</span>
					{count > 99 ? "99+" : count}
				</span>
			) : null}
		</NavLink>
	);
}

function NavSections() {
	const { canEditPolicy, currentRole, roleResolved } = useTeam();
	const t = useT();
	const access: NavAccess = { canEditPolicy, currentRole, roleResolved };
	return (
		<div className="nav-sections">
			{NAV_SECTIONS.map((section) => {
				const items = section.items.filter((item) => !item.show || item.show(access));
				if (items.length === 0) return null;
				const headingId = `nav-section-${section.id}`;
				return (
					<div key={section.id} className="nav-section" role="group" aria-labelledby={headingId}>
						<p className="nav-section-title" id={headingId}>
							{t(section.label)}
						</p>
						{items.map((item) =>
							item.to === "/approvals" ? (
								<ApprovalsNavLink key={item.to} />
							) : (
								// "/governance" must not stay highlighted on its sub-pages,
								// which have their own entries.
								<NavLink key={item.to} to={item.to} end={item.to === "/governance"}>
									{t(item.label)}
								</NavLink>
							),
						)}
					</div>
				);
			})}
		</div>
	);
}

export function AppLayout() {
	const navigate = useNavigate();
	const [signingOut, setSigningOut] = useState(false);
	const t = useT();
	if (signingOut) return <div role="status">{t("layout.signingOut")}</div>;

	return (
		<TeamProvider>
			<div className="app">
				<a className="skip-link" href="#page-content">
					{t("layout.skip")}
				</a>
				<header className="console-topbar">
					<Link to="/" className="brand-link">
						<span className="brand-word" aria-hidden="true" lang="en">
							AIDR
						</span>
						<span className="brand-sub" aria-hidden="true">
							{t("layout.controlPlane")}
						</span>
						<span className="sr-only" lang="en">
							Singularity AIDR
						</span>
					</Link>
					<div className="header-actions">
						<LanguageToggle />
						<ThemeToggle />
					</div>
				</header>
				<main className="main">
					<nav className="navcard" aria-label={t("layout.navLabel")}>
						<NavSections />
						<span className="navcard-signout">
							<button
								className="button button-secondary button-sm"
								type="button"
								onClick={async () => {
									setSigningOut(true);
									try {
										const result = await signOut();
										navigate(
											result.serverRevoked ? "/login" : "/login?signout=revocation-unconfirmed",
											{ replace: true },
										);
									} catch {
										navigate("/login?signout=local-failed", { replace: true });
									}
								}}
							>
								{t("layout.signOut")}
							</button>
						</span>
					</nav>
					{supabaseEnvError ? (
						<div className="notice notice-danger" style={{ marginBottom: 14 }}>
							<b>{t("layout.envIncomplete")}</b>
							<div className="muted small" style={{ marginTop: 6 }}>
								{supabaseEnvError}
							</div>
						</div>
					) : null}
					<div id="page-content" tabIndex={-1}>
						<ManagedOutlet />
					</div>
				</main>
			</div>
		</TeamProvider>
	);
}

import { Link, NavLink, Outlet } from "react-router-dom";
import { LanguageToggle, useT } from "../i18n/I18nProvider";
import { supabaseEnvError } from "../lib/supabase";
import { ThemeToggle } from "./ThemeToggle";

export function PublicLayout() {
	const showConfigWarning = Boolean(supabaseEnvError);
	const t = useT();

	return (
		<div className="app">
			<a className="skip-link" href="#page-content">
				{t("layout.skip")}
			</a>
			<header className="nav-bar">
				<Link to="/" className="brand-link">
					<span className="brand-word" aria-hidden="true">
						AIDR
					</span>
					<span className="brand-sub" aria-hidden="true">
						Singularity
					</span>
					<span className="sr-only">Singularity AIDR</span>
				</Link>
				<nav className="nav" aria-label={t("public.navLabel")}>
					<NavLink to="/pricing">{t("public.editions")}</NavLink>
					<NavLink to="/pilot">{t("public.pilot")}</NavLink>
					<NavLink to="/login">{t("public.dashboard")}</NavLink>
				</nav>
				<div className="row">
					<Link className="button button-sm" to="/login">
						{t("public.signIn")}
					</Link>
					<LanguageToggle />
					<ThemeToggle />
				</div>
			</header>
			<main className="main">
				{showConfigWarning ? (
					<div className="notice notice-danger" style={{ marginBottom: 16 }}>
						<b>{t("public.noCredentials")}</b>
						<div className="muted small" style={{ marginTop: 6 }}>
							{supabaseEnvError}
						</div>
					</div>
				) : null}
				<div id="page-content" tabIndex={-1}>
					<Outlet />
				</div>
			</main>
			<footer className="footer">
				<div className="muted small">
					© {new Date().getFullYear()} {t("public.footer")}
				</div>
				<nav className="footer-links" aria-label={t("public.footerLabel")}>
					<Link to="/support">{t("public.support")}</Link>
					<Link to="/status">{t("public.status")}</Link>
					<Link to="/privacy">{t("public.privacy")}</Link>
					<Link to="/security">{t("public.security")}</Link>
					<Link to="/terms">{t("public.terms")}</Link>
				</nav>
			</footer>
		</div>
	);
}

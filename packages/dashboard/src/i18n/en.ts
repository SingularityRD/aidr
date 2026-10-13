/**
 * English dashboard strings: the reference key set and the default locale.
 * Values are the exact text the dashboard showed before localization.
 * `{name}` marks a parameter. Product and plan names stay untranslated.
 */
export const en = {
	"language.switchToLabel": "Switch the dashboard to Turkish",
	"theme.toDark": "Switch to dark mode",
	"theme.toLight": "Switch to light mode",

	"layout.skip": "Skip to content",
	"layout.controlPlane": "Control plane",
	"layout.navLabel": "Dashboard",
	"layout.resolvingTenant": "Resolving the managed tenant…",
	"layout.teamLoadFailed": "Your team membership could not be loaded.",
	"layout.signingOut": "Ending this browser session…",
	"layout.signOut": "Sign out",
	"layout.envIncomplete": "Dashboard environment is incomplete.",
	"layout.pendingCount": ", pending: ",
	"nav.connect": "Connect",
	"nav.downloads": "Downloads",
	"nav.dashboard": "Dashboard",
	"nav.billing": "Billing",
	"nav.apiKeys": "API Keys",
	"nav.agents": "Agents",
	"nav.events": "Events",
	"nav.discovery": "Discovery",
	"nav.posture": "Posture",
	"nav.incidents": "Incidents",
	"nav.approvals": "Approvals",
	"nav.browserPrivacy": "Browser Privacy",
	"nav.autosecops": "AutoSecOps",
	"nav.settings": "Settings",
	"nav.team": "Team",
	"nav.scim": "Directory provisioning",
	"nav.retention": "Legal holds & retention",
	"nav.sso": "Single sign-on",
	"nav.policies": "Policies",
	"nav.siem": "SIEM export",
	"nav.compliance": "Compliance",
	"nav.governance": "Governance",
	"nav.detectionExceptions": "Detection exceptions",
	"nav.aiRegister": "AI register",

	"public.navLabel": "Public",
	"public.editions": "Editions",
	"public.pilot": "Pilot",
	"public.dashboard": "Dashboard",
	"public.signIn": "Sign in",
	"public.noCredentials": "Dashboard is running without Supabase credentials.",
	"public.footer": "Singularity AIDR. Local-first AI agent detection and response.",
	"public.footerLabel": "Support and legal",
	"public.support": "Support",
	"public.status": "Status",
	"public.privacy": "Privacy",
	"public.security": "Security",
	"public.terms": "Terms",

	"notFound.title": "Page not found",
	"notFound.body": "The link may be stale or the page may have moved.",
	"common.backHome": "Back to home",
	"error.eyebrow": "Error",
	"error.title": "Something went wrong",
	"error.notFound": "This dashboard page does not exist.",
	"error.generic": "The dashboard could not complete this request.",
	"error.retry": "Retry",
	"config.eyebrow": "Configuration required",
	"config.title": "Dashboard configuration is incomplete",
	"config.body":
		"This production deployment is not connected to Supabase. Configure the required public environment variables and redeploy before inviting customers.",

	"plan.checking": "Checking your plan…",
	"plan.unavailable":
		"Plan information is unavailable, so this page is not shown. Try again shortly.",
	"plan.includedFrom":
		"{feature} is included from the {plan} edition. This workspace is on {current}{why}.",
	"plan.inactive": " because its licence or admission is not active",
	"plan.upgrade": "View plans and upgrade",

	"login.welcome": "Welcome to AIDR",
	"login.subtitleRegister": "Create an account to protect your AI agents",
	"login.subtitleSignIn": "Sign in to protect your AI agents",
	"login.revocationUnconfirmed":
		"This browser signed out, but revocation of other sessions could not be confirmed. Contact your administrator if those sessions must be ended.",
	"login.localSignOutFailed":
		"This browser sign-out could not be confirmed. Close this tab and ask your administrator to revoke active sessions.",
	"login.continueWith": "Continue with {provider}",
	"login.companySso": "company SSO",
	"login.ssoFormLabel": "Company single sign-on",
	"login.ssoEmailLabel": "Work email for single sign-on",
	"login.ssoContinue": "Continue with work email SSO",
	"login.orEmail": "or continue with email",
	"login.email": "Email address",
	"login.teamName": "Team or organization name",
	"login.password": "Password",
	"login.confirmPassword": "Confirm password",
	"login.wait": "Please wait…",
	"login.createAccount": "Create account",
	"login.signIn": "Sign in",
	"login.sendMagicLink": "Send magic link",
	"login.emailLink": "Email a sign-in link",
	"login.forgot": "Forgot password or lost your second factor?",
	"login.haveAccount": "Already have an account? Sign in",
	"login.newAccount": "New to AIDR? Create an account",
	"login.notConfigured": "Sign-in has not been configured. Contact your administrator.",
	"login.backHome": "← Back to home",
	"login.noteConfirm": "Confirm your email before setting up a workspace.",
	"login.noteAdmin": "Use the account provided by your administrator.",
	"login.sessionCheckFailed": "Unable to check your session. Please try again.",
	"login.passwordFailed":
		"Sign-in failed. Check your email and password or contact your administrator.",
	"login.emailLimited": "Email delivery is temporarily limited. Please try again later.",
	"login.linkFailed": "Unable to send a sign-in link. Contact your administrator.",
	"login.linkSent": "If this account is enabled, check your inbox for a sign-in link.",
	"login.unavailable": "Sign-in is unavailable. Please try again.",
	"login.teamNameInvalid": "Enter a team name of up to 200 characters without control characters.",
	"login.passwordMismatch": "Passwords do not match.",
	"login.registerFailed":
		"Unable to create an account. Check the password requirements or contact support.",
	"login.confirmationDisabled":
		"Email confirmation is not enabled. Account registration is unavailable.",
	"login.registerSent":
		"If this address is eligible, check your inbox for a confirmation link. Open it in this browser to continue setup.",
	"login.registerUnavailable": "Account registration is unavailable. Please try again later.",
	"login.companyUnavailable": "Company sign-in is unavailable. Contact your administrator.",
	"login.providerUnavailable": "This sign-in provider is unavailable. Contact your administrator.",

	"downloads.title": "Download",
	"downloads.intro":
		"Install AIDR for {team} in three steps: download the installer, run it, and restart your AI tools.",
	"downloads.yourTeam": "your team",
	"downloads.checkingTeam": "Checking team access…",
	"downloads.noTeam": "Select or create a workspace to download installers.",
	"downloads.backToOnboarding": "Back to onboarding",
	"downloads.viewAgents": "View agents",
	"downloads.retry": "Try again",
	"downloads.os.windows": "Windows",
	"downloads.os.linux": "Linux",
	"downloads.installer.title": "Download the AIDR installer",
	"downloads.installer.intro":
		"One installer protects every supported AI tool on this computer: Claude Code, Cursor, VS Code, Codex, OpenCode and OpenClaw.",
	"downloads.installer.loading": "Loading the installer catalog…",
	"downloads.installer.version": "Version {version} · published {date}",
	"downloads.installer.releaseNotes": "Release notes",
	"downloads.installer.recommended": "Recommended for this computer",
	"downloads.installer.other": "Other platforms",
	"downloads.installer.download": "Download {file}",
	"downloads.installer.preparing": "Preparing download…",
	"downloads.installer.started":
		"Your download has started. If it did not, {link} (valid until {time}).",
	"downloads.installer.directLink": "use this direct link",
	"downloads.installer.meta": "{size} · requires {minOs}",
	"downloads.installer.sha256": "SHA-256",
	"downloads.installer.verify": "Check the downloaded file before you run it:",
	"downloads.installer.copy": "Copy",
	"downloads.installer.copied": "Copied",
	"downloads.installer.copyChecksum": "Copy the checksum command for {file}",
	"downloads.installer.copyBlocked":
		"Clipboard access was blocked. Select the command and copy it.",
	"downloads.installer.verifyNote":
		"The command prints True on Windows or OK on Linux. Do not run the installer if it does not.",
	"downloads.installer.macos":
		"A macOS installer is not available yet. Browser Guard, below, works in Chrome, Edge and Firefox on macOS.",
	"downloads.installer.noMatch":
		"No installer is published for the operating system of this browser. Choose one of the platforms below if it applies.",
	"downloads.installer.step1":
		"Download the installer for your operating system and check its SHA-256.",
	"downloads.installer.step2":
		"Run it: double-click it on Windows, or run the script with sh on Linux.",
	"downloads.installer.step3":
		"Restart your AI tools. Running aidr status shows that protection is on.",
	"downloads.error.entitlement":
		"Downloads need an active licence or trial for this workspace. Ask your administrator, or start a trial on the onboarding page.",
	"downloads.error.unpublished":
		"No installer has been published for this deployment yet. Ask your release operator.",
	"downloads.error.integrity":
		"The installer catalog failed its signature check, so no downloads are offered. Contact support.",
	"downloads.error.forbidden": "Your account cannot download installers for this workspace.",
	"downloads.error.rateLimited": "Too many requests. Wait a minute and try again.",
	"downloads.error.generic": "Installers are unavailable right now. Try again shortly.",
	"downloads.error.download": "The download link could not be created. Try again.",
	"downloads.managed.title": "Connect this computer to your workspace (managed mode)",
	"downloads.managed.body":
		"After installing, the first start of a protected AI tool shows a short code. Approve it for this workspace on the verify page. The control plane address of this workspace is:",
	"downloads.managed.verify": "Verify a device code",
	"downloads.managed.advanced": "Manual enrollment (advanced)",
	"downloads.bg.title": "Browser Guard extension",
	"downloads.bg.body":
		"Masks personal data and secrets before prompts reach AI chat sites in Chrome, Edge and Firefox, on Windows, macOS and Linux.",
	"downloads.bg.chrome": "Add to Chrome",
	"downloads.bg.edge": "Add to Edge",
	"downloads.bg.firefox": "Add to Firefox",
	"downloads.bg.none":
		"Store links are not configured for this deployment. Ask your administrator.",
	"downloads.bg.ids": "Extension IDs for IT policy",
	"downloads.bg.chromeId": "Chrome",
	"downloads.bg.edgeId": "Edge",
	"downloads.bg.firefoxId": "Firefox",
	"downloads.it.title": "IT / MDM deployment",
	"downloads.it.body":
		"Deploy the same installers silently with Intune or Group Policy, and force-install Browser Guard by extension ID through browser policy.",
	"downloads.it.guide": "Open the administrator guide",
	"downloads.it.guideMissing":
		"The administrator guide ships with your release bundle (docs/installation/download-portal.md).",
	"downloads.advanced.title": "Individual connector packages (advanced)",
	"onboarding.install.title": "1) Download and run the installer",
	"onboarding.install.body":
		"The installer protects every supported AI tool on this computer. This is the recommended setup.",
	"onboarding.install.allDownloads": "Open the Download page",
	"onboarding.advanced.summary": "Advanced: manual setup and device authorization",
	"onboarding.advanced.body":
		"Use these steps only when you cannot run the installer, or to enroll a single connector by hand.",
} as const;

export type DashboardMessageKey = keyof typeof en;

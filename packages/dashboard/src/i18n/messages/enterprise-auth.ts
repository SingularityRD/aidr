import type { MessagePairs } from "./define";

/** Enterprise sign-in, invitation acceptance and the multi-factor step-up gate. */
export const enterpriseAuthMessages = {
	"ea.assuranceFailed": [
		"Session assurance could not be verified. No protected screen was opened.",
		"Oturum güvence düzeyi doğrulanamadı. Hiçbir korumalı ekran açılmadı.",
	],
	"ea.signInFailed": ["Sign-in could not be completed.", "Oturum açma tamamlanamadı."],
	"ea.signInNotStarted": ["Sign-in could not be started.", "Oturum açma başlatılamadı."],
	"ea.inviteNotAccepted": ["The invitation could not be accepted.", "Davet kabul edilemedi."],
	"ea.inviteAccepted": [
		"Team invitation accepted! Redirecting...",
		"Ekip daveti kabul edildi! Yönlendiriliyorsunuz...",
	],
	"ea.inviteFailed": ["Failed to accept invitation", "Davet kabul edilemedi"],
	"ea.noFactor": [
		"No verified authenticator factor is available for this account. Set one up to continue.",
		"Bu hesap için doğrulanmış bir doğrulama uygulaması yok. Devam etmek için bir tane kurun.",
	],
	"ea.addSecret": [
		"Add the secret below to your authenticator app, then enter the generated code to finish.",
		"Aşağıdaki gizli anahtarı doğrulama uygulamanıza ekleyin, sonra bitirmek için üretilen kodu girin.",
	],
	"ea.enrollFailed": [
		"Authenticator enrollment could not be started.",
		"Doğrulama uygulaması kaydı başlatılamadı.",
	],
	"ea.codeRejected": [
		"The verification code was rejected. No protected screen was opened.",
		"Doğrulama kodu reddedildi. Hiçbir korumalı ekran açılmadı.",
	],
	"ea.cancelled": [
		"Multi-factor authentication was cancelled. The session was ended and no protected screen was opened.",
		"Çok adımlı doğrulama iptal edildi. Oturum kapatıldı ve hiçbir korumalı ekran açılmadı.",
	],
	"ea.cancelledOpen": [
		"Multi-factor authentication was cancelled and this session could not be ended. Sign out to continue.",
		"Çok adımlı doğrulama iptal edildi ve bu oturum kapatılamadı. Devam etmek için oturumu kapatın.",
	],
	"ea.code": ["Authenticator code", "Doğrulama kodu"],
	"ea.verifying": ["Verifying…", "Doğrulanıyor…"],
	"ea.verify": ["Verify and continue", "Doğrula ve devam et"],
	"ea.noEnrolled": [
		"No verified authenticator factor is enrolled for this account. Enrollment is performed by the configured Supabase Auth service.",
		"Bu hesap için kayıtlı ve doğrulanmış bir doğrulama uygulaması yok. Kayıt, yapılandırılmış Supabase Auth hizmetiyle yapılır.",
	],
	"ea.starting": ["Starting…", "Başlatılıyor…"],
	"ea.setUp": ["Set up authenticator app", "Doğrulama uygulamasını kur"],
	"ea.enrollNew": ["Enroll a new authenticator app", "Yeni bir doğrulama uygulaması kaydet"],
	"ea.addThisSecret": [
		"Add this secret to your authenticator app:",
		"Bu gizli anahtarı doğrulama uygulamanıza ekleyin:",
	],
	"ea.noSecret": [
		"The Auth service returned no secret; use the enrollment URI.",
		"Auth hizmeti gizli anahtar döndürmedi; kayıt URI'sini kullanın.",
	],
	"ea.mfaRequired": ["Multi-factor authentication required", "Çok adımlı doğrulama gerekiyor"],
	"ea.actionNeedsFactor": [
		"This action requires a second factor before it can be opened.",
		"Bu işlem açılmadan önce ikinci bir doğrulama adımı gerektirir.",
	],
	"ea.tenantNeedsFactor": [
		"This tenant requires a second factor before its managed screens can be opened.",
		"Bu çalışma alanı, yönetilen ekranları açılmadan önce ikinci bir doğrulama adımı gerektirir.",
	],
	"ea.aal1": [
		"The control plane reports the session at assurance level aal1.",
		"Yönetim paneli oturumu aal1 güvence düzeyinde bildiriyor.",
	],
	"ea.cancelSignOut": ["Cancel and sign out", "Vazgeç ve oturumu kapat"],
	"ea.recoveryNote": [
		"Break-glass recovery codes and password recovery remain available from the recovery page if this factor is lost.",
		"Bu doğrulama yöntemi kaybolursa acil durum kurtarma kodları ve parola kurtarma, kurtarma sayfasında kullanılabilir.",
	],
	"ea.title": ["Enterprise Sign In", "Kurumsal oturum açma"],
	"ea.lead": [
		"Sign in with a configured method to access team features and accept invitations.",
		"Ekip özelliklerine erişmek ve davetleri kabul etmek için yapılandırılmış bir yöntemle oturum açın.",
	],
	"ea.notConfigured": [
		"Enterprise sign-in is not configured for this deployment. Ask your administrator to enable a supported sign-in method.",
		"Bu kurulumda kurumsal oturum açma yapılandırılmamış. Desteklenen bir oturum açma yöntemini açması için yöneticinize başvurun.",
	],
	"ea.configured": ["Sign in with a configured method", "Yapılandırılmış bir yöntemle oturum açın"],
	"ea.github": ["Continue with GitHub", "GitHub ile devam et"],
	"ea.gitlab": ["Continue with GitLab", "GitLab ile devam et"],
	"ea.signedIn": [
		"You are signed in. Continue to your dashboard.",
		"Oturum açtınız. Panele devam edin.",
	],
	"ea.openDashboard": ["Open dashboard", "Paneli aç"],
	"ea.invite": ["Team Invitation", "Ekip daveti"],
	"ea.inviteLead": [
		"You've been invited to join a team. Accept the invitation to continue.",
		"Bir ekibe katılmaya davet edildiniz. Devam etmek için daveti kabul edin.",
	],
	"ea.accept": ["Accept Invitation", "Daveti kabul et"],
	"ea.syncNote": [
		"By signing in, you agree to sync your organization membership. Only public organization data is accessed.",
		"Oturum açarak kuruluş üyeliğinizin eşitlenmesini kabul edersiniz. Yalnızca herkese açık kuruluş verilerine erişilir.",
	],
	"ea.verifyingAssurance": ["Verifying session assurance", "Oturum güvence düzeyi doğrulanıyor"],
	"ea.reading": [
		"Reading the signed-in session before any protected screen is rendered.",
		"Herhangi bir korumalı ekran gösterilmeden önce açık oturum okunuyor.",
	],
	"ea.notCompleted": [
		"Multi-factor authentication was not completed",
		"Çok adımlı doğrulama tamamlanmadı",
	],
	"ea.notCompletedLead": [
		"No protected screen was opened. Sign in again and satisfy the second factor before continuing.",
		"Hiçbir korumalı ekran açılmadı. Devam etmeden önce yeniden oturum açın ve ikinci doğrulama adımını tamamlayın.",
	],
	"ea.checking": [
		"Checking whether this session satisfies the tenant's multi-factor requirement. No protected screen is rendered until the control plane confirms it.",
		"Bu oturumun çalışma alanının çok adımlı doğrulama şartını karşılayıp karşılamadığı denetleniyor. Yönetim paneli bunu onaylayana kadar hiçbir korumalı ekran gösterilmez.",
	],
} as const satisfies MessagePairs<string>;

import type { MessagePairs } from "./define";

/** Settings page (workspace, profile, appearance, privacy). */
export const settingsMessages = {
	"settings.status.active": ["Active", "Etkin"],
	"settings.status.suspended": ["Suspended", "Askıya alındı"],
	"settings.status.closing": [
		"Closing (offboarding in progress)",
		"Kapatılıyor (ayrılma işlemi sürüyor)",
	],
	"settings.status.closed": ["Closed", "Kapatıldı"],

	"settings.error.mfaRequired": [
		"Multi-factor verification is required for workspace changes. Verify with your authenticator, then try again.",
		"Çalışma alanı değişiklikleri için çok faktörlü doğrulama gerekir. Doğrulama uygulamanızla doğrulayıp yeniden deneyin.",
	],
	"settings.error.role": [
		"Your role cannot make this workspace change.",
		"Rolünüz bu çalışma alanı değişikliğini yapamaz.",
	],
	"settings.error.forbidden": [
		"You no longer have access to this workspace's settings.",
		"Artık bu çalışma alanının ayarlarına erişiminiz yok.",
	],
	"settings.error.notActive": [
		"This workspace is not active, so its settings can no longer be changed.",
		"Bu çalışma alanı etkin olmadığı için ayarları artık değiştirilemez.",
	],
	"settings.error.retentionUnconfirmed": [
		"Confirm the shorter retention period before saving.",
		"Kaydetmeden önce daha kısa saklama süresini onaylayın.",
	],
	"settings.error.confirmationMismatch": [
		"The name you typed does not match the workspace name. Nothing was closed.",
		"Yazdığınız ad çalışma alanının adıyla eşleşmiyor. Hiçbir şey kapatılmadı.",
	],
	"settings.error.invalidName": [
		"Enter a workspace name of 1 to 200 characters without control characters.",
		"Denetim karakteri içermeyen, 1 ile 200 karakter arasında bir çalışma alanı adı girin.",
	],
	"settings.error.invalidRetention": [
		"Enter a whole number of retention days within the allowed range.",
		"İzin verilen aralıkta tam sayı olarak bir saklama süresi (gün) girin.",
	],
	"settings.error.rateLimited": [
		"Too many workspace changes. Wait a minute and try again.",
		"Çok fazla çalışma alanı değişikliği yapıldı. Bir dakika bekleyip yeniden deneyin.",
	],
	"settings.error.generic": [
		"The workspace service did not confirm the request.",
		"Çalışma alanı hizmeti isteği doğrulamadı.",
	],

	"settings.mfa.noTeam": [
		"Select a workspace to check this session's MFA status.",
		"Bu oturumun MFA durumunu görmek için bir çalışma alanı seçin.",
	],
	"settings.mfa.failed": [
		"MFA status could not be confirmed by the control plane.",
		"MFA durumu kontrol düzlemi tarafından doğrulanamadı.",
	],
	"settings.mfa.checking": ["Checking MFA status…", "MFA durumu denetleniyor…"],
	"settings.mfa.verified": [
		"Verified for this session (AAL2).",
		"Bu oturum için doğrulandı (AAL2).",
	],
	"settings.mfa.notVerified": [
		"Not verified for this session (AAL1).",
		"Bu oturum için doğrulanmadı (AAL1).",
	],
	"settings.mfa.workspaceRequires": [
		"This workspace requires MFA.",
		"Bu çalışma alanı MFA gerektirir.",
	],
	"settings.mfa.changesRequire": [
		"Workspace changes still require MFA.",
		"Çalışma alanı değişiklikleri yine de MFA gerektirir.",
	],
	"settings.mfa.setUp": ["Set up or verify MFA", "MFA kur ya da doğrula"],

	"settings.profile.title": ["Profile", "Profil"],
	"settings.profile.signedInAs": ["Signed in as", "Oturum açan hesap"],
	"settings.profile.mfa": ["Multi-factor authentication", "Çok faktörlü kimlik doğrulama"],
	"settings.profile.signOut": ["Sign out of this session", "Bu oturumu kapat"],

	"settings.form.name": ["Workspace name", "Çalışma alanı adı"],
	"settings.form.retention": ["Telemetry retention (days)", "Telemetri saklama süresi (gün)"],
	"settings.form.range": [
		"Allowed range: {min}–{max} days. Commercial and security audit records keep their own minimum retention.",
		"İzin verilen aralık: {min}–{max} gün. Ticari ve güvenlik denetim kayıtlarının kendi en kısa saklama süreleri vardır.",
	],
	"settings.form.ownerOnly": [
		"Telemetry retention ({days} days) can only be changed by a workspace owner, because shortening it permanently deletes older telemetry.",
		"Telemetri saklama süresini ({days} gün) yalnızca çalışma alanı sahibi değiştirebilir; çünkü süreyi kısaltmak eski telemetriyi kalıcı olarak siler.",
	],
	"settings.form.confirmReduction": [
		"I understand that shortening retention from {from} to {to} days makes older telemetry eligible for permanent deletion.",
		"Saklama süresini {from} günden {to} güne kısaltmanın eski telemetriyi kalıcı silmeye açık hâle getirdiğini anlıyorum.",
	],
	"settings.form.save": ["Save workspace settings", "Çalışma alanı ayarlarını kaydet"],
	"settings.form.note": [
		"Changes require multi-factor verification (AAL2) and are recorded in the audit log.",
		"Değişiklikler çok faktörlü doğrulama (AAL2) gerektirir ve denetim kaydına yazılır.",
	],

	"settings.close.title": ["Close workspace", "Çalışma alanını kapat"],
	"settings.close.body": [
		"Closing starts offboarding: API keys, SCIM tokens and delegated credentials are revoked immediately, members lose access, and workspace data is deleted as each retention period ends. Active legal holds pause deletion. This cannot be undone from the console.",
		"Kapatma, ayrılma sürecini başlatır: API anahtarları, SCIM belirteçleri ve devredilmiş kimlik bilgileri hemen iptal edilir, üyeler erişimini kaybeder ve çalışma alanı verileri her saklama süresi dolduğunda silinir. Etkin yasal saklama kararları silmeyi durdurur. Bu işlem konsoldan geri alınamaz.",
	],
	"settings.close.confirm": ["Type {name} to confirm", "Onaylamak için {name} yazın"],

	"settings.workspace.title": ["Workspace", "Çalışma alanı"],
	"settings.workspace.loading": [
		"Loading workspace settings…",
		"Çalışma alanı ayarları yükleniyor…",
	],
	"settings.workspace.saved": ["Workspace settings saved.", "Çalışma alanı ayarları kaydedildi."],
	"settings.workspace.closed": [
		"Workspace closure requested (offboarding status: {status}). Credentials are revoked and data is deleted as each retention period ends.",
		"Çalışma alanının kapatılması istendi (ayrılma durumu: {status}). Kimlik bilgileri iptal edildi; veriler her saklama süresi dolduğunda silinir.",
	],
	"settings.workspace.retention": ["Telemetry retention", "Telemetri saklama süresi"],
	"settings.workspace.role": ["Your role", "Rolünüz"],
	"settings.workspace.adminOnly": [
		"Only an owner or administrator can change workspace settings.",
		"Çalışma alanı ayarlarını yalnızca sahip ya da yönetici değiştirebilir.",
	],
	"settings.workspace.readOnly": ["This workspace is read-only.", "Bu çalışma alanı salt okunur."],

	"settings.sessionLoadFailed": ["Unable to load your session.", "Oturumunuz yüklenemedi."],
	"settings.intro": [
		"Workspace, notifications, profile, appearance, and privacy controls for this console.",
		"Bu konsolun çalışma alanı, bildirim, profil, görünüm ve gizlilik ayarları.",
	],
	"settings.appearance.title": ["Appearance", "Görünüm"],
	"settings.appearance.body": [
		"The console follows your stored preference, then your OS setting.",
		"Konsol önce kayıtlı tercihinizi, sonra işletim sistemi ayarınızı izler.",
	],
	"settings.appearance.light": ["Light", "Açık"],
	"settings.appearance.dark": ["Dark", "Koyu"],
	"settings.privacy.title": ["Privacy & data", "Gizlilik ve veri"],
	"settings.privacy.body": [
		"Supported connectors evaluate intercepted actions locally against the effective policy. Connector coverage, optional checks, and data sent to configured providers vary by deployment; review the canonical documents for the exact scope and retention terms.",
		"Desteklenen bağlayıcılar yakaladıkları işlemleri geçerli politikaya göre yerel olarak değerlendirir. Bağlayıcı kapsamı, isteğe bağlı denetimler ve yapılandırılmış sağlayıcılara gönderilen veriler kuruluma göre değişir; kesin kapsam ve saklama koşulları için resmi belgelere bakın.",
	],
	"settings.privacy.notice": ["Privacy notice", "Gizlilik bildirimi"],
	"settings.envIncomplete": ["Environment is incomplete.", "Ortam yapılandırması eksik."],
} as const satisfies MessagePairs<string>;

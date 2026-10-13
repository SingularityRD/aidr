import type { MessagePairs } from "./define";

/** Sign-in callbacks, account recovery, SSO break-glass and the CAPTCHA widget. */
export const authPagesMessages = {
	"captcha.notConfigured": [
		"CAPTCHA not configured. Add VITE_TURNSTILE_SITE_KEY to enable bot protection.",
		"CAPTCHA yapılandırılmamış. Bot korumasını açmak için VITE_TURNSTILE_SITE_KEY ekleyin.",
	],
	"captcha.loading": ["Loading verification...", "Doğrulama yükleniyor..."],
	"captcha.failed": [
		"Verification failed to load. Please refresh the page.",
		"Doğrulama yüklenemedi. Lütfen sayfayı yenileyin.",
	],
	"oidc.failed": [
		"Single sign-on failed. Try again.",
		"Tek oturum açma başarısız oldu. Yeniden deneyin.",
	],
	"oidc.backToSignIn": ["Back to sign-in", "Oturum açmaya dön"],
	"oidc.completing": ["Completing sign-in…", "Oturum açma tamamlanıyor…"],
	"bg.suspended": [
		"Single sign-on enforcement was suspended and the event was audited. Sign in with your password to repair the identity provider settings.",
		"Tek oturum açma zorunluluğu askıya alındı ve olay denetim kaydına yazıldı. Kimlik sağlayıcı ayarlarını düzeltmek için parolanızla oturum açın.",
	],
	"bg.rateLimited": [
		"Too many attempts. Wait ten minutes and try again.",
		"Çok fazla deneme. On dakika bekleyip yeniden deneyin.",
	],
	"bg.unavailable": [
		"Recovery is temporarily unavailable. Try again later.",
		"Kurtarma geçici olarak kullanılamıyor. Daha sonra yeniden deneyin.",
	],
	"bg.invalidCode": [
		"The recovery code is invalid or expired.",
		"Kurtarma kodu geçersiz ya da süresi dolmuş.",
	],
	"bg.title": ["Suspend SSO enforcement", "SSO zorunluluğunu askıya al"],
	"bg.subtitle": [
		"For tenant owners when the identity provider is unavailable.",
		"Kimlik sağlayıcı kullanılamadığında çalışma alanı sahipleri için.",
	],
	"bg.email": ["Owner email", "Sahip e-postası"],
	"bg.code": ["Recovery code", "Kurtarma kodu"],
	"bg.submit": ["Suspend enforcement", "Zorunluluğu askıya al"],
	"bg.note": [
		"The code is single-use and the action is audited. {link}",
		"Kod tek kullanımlıktır ve işlem denetim kaydına yazılır. {link}",
	],
	"cb.verifier": [
		"Open the sign-in link in the browser where you requested it, or request a new link.",
		"Oturum açma bağlantısını istediğiniz tarayıcıda açın ya da yeni bir bağlantı isteyin.",
	],
	"cb.fragment": [
		"This sign-in link format is not accepted. Ask your administrator for a new invitation link.",
		"Bu oturum açma bağlantısı biçimi kabul edilmiyor. Yöneticinizden yeni bir davet bağlantısı isteyin.",
	],
	"cb.failed": ["Authentication could not be completed.", "Kimlik doğrulama tamamlanamadı."],
	"cb.thisAccount": ["this account", "bu hesap"],
	"cb.confirmTitle": ["Confirm invitation", "Daveti onaylayın"],
	"cb.signingInAs": ["You are signing in as {email}.", "{email} olarak oturum açıyorsunuz."],
	"cb.access": ["Workspace access", "Çalışma alanı erişimi"],
	"cb.joining": [
		"You are joining workspace {workspace} as role {role}.",
		"{workspace} çalışma alanına {role} rolüyle katılıyorsunuz.",
	],
	"cb.noMembership": [
		"No workspace membership is attached to this account yet.",
		"Bu hesaba henüz bir çalışma alanı üyeliği bağlı değil.",
	],
	"cb.expected": [
		"Continue only if you expected this invitation. If you did not, cancel and this browser will be signed out.",
		"Yalnızca bu daveti bekliyorsanız devam edin. Beklemiyorsanız vazgeçin; bu tarayıcıda oturum kapatılır.",
	],
	"cb.continue": ["Continue", "Devam et"],
	"cb.signingIn": ["Signing in…", "Oturum açılıyor…"],
	"cb.completing": [
		"Completing Supabase authentication.",
		"Supabase kimlik doğrulaması tamamlanıyor.",
	],
	"cb.return": ["Return to sign in", "Oturum açmaya dön"],
	"rec.enterCode": [
		"Enter the one-time code from your recovery email to continue.",
		"Devam etmek için kurtarma e-postanızdaki tek kullanımlık kodu girin.",
	],
	"rec.sessionInvalid": [
		"This recovery session is invalid or expired. Request a new recovery link.",
		"Bu kurtarma oturumu geçersiz ya da süresi dolmuş. Yeni bir kurtarma bağlantısı isteyin.",
	],
	"rec.reload": [
		"Recovery is temporarily unavailable. Reload this tab to retry safely.",
		"Kurtarma geçici olarak kullanılamıyor. Güvenle yeniden denemek için bu sekmeyi yenileyin.",
	],
	"rec.notConfirmed": ["Identity operation was not confirmed.", "Kimlik işlemi onaylanmadı."],
	"rec.sent": [
		"If this account is enabled, the configured authentication provider will send a one-time recovery code. Keep this browser tab open; it can be reloaded for 10 minutes.",
		"Bu hesap etkinse, yapılandırılmış kimlik doğrulama sağlayıcısı tek kullanımlık bir kurtarma kodu gönderir. Bu tarayıcı sekmesini açık tutun; 10 dakika boyunca yenilenebilir.",
	],
	"rec.requestUnavailable": [
		"Password recovery is temporarily unavailable. Contact your administrator.",
		"Parola kurtarma geçici olarak kullanılamıyor. Yöneticinize başvurun.",
	],
	"rec.sessionExpired": [
		"The recovery session is invalid or expired.",
		"Kurtarma oturumu geçersiz ya da süresi dolmuş.",
	],
	"rec.retry": [
		"Recovery is temporarily unavailable. Retry to resume safely.",
		"Kurtarma geçici olarak kullanılamıyor. Güvenle devam etmek için yeniden deneyin.",
	],
	"rec.mismatch": ["The password confirmation does not match.", "Parola onayı eşleşmiyor."],
	"rec.updated": [
		"Password updated and sessions revoked. Sign in again with the new password.",
		"Parola güncellendi ve oturumlar kapatıldı. Yeni parolayla yeniden oturum açın.",
	],
	"rec.title": ["Recover your AIDR account", "AIDR hesabınızı kurtarın"],
	"rec.subtitle": [
		"Use provider recovery or a pre-issued break-glass code.",
		"Sağlayıcı kurtarmasını ya da önceden verilmiş acil durum kodunu kullanın.",
	],
	"rec.newPassword": ["New password", "Yeni parola"],
	"rec.confirmPassword": ["Confirm new password", "Yeni parolayı onaylayın"],
	"rec.updating": ["Updating…", "Güncelleniyor…"],
	"rec.update": ["Update password and revoke sessions", "Parolayı güncelle ve oturumları kapat"],
	"rec.emailMode": ["Email recovery", "E-postayla kurtarma"],
	"rec.breakGlassMode": ["Break-glass code", "Acil durum kodu"],
	"rec.email": ["Email address", "E-posta adresi"],
	"rec.code": ["One-time recovery code", "Tek kullanımlık kurtarma kodu"],
	"rec.wait": ["Please wait…", "Lütfen bekleyin…"],
	"rec.verify": ["Verify recovery code", "Kurtarma kodunu doğrula"],
	"rec.request": ["Request recovery", "Kurtarma iste"],
	"rec.useCode": ["Use one-time code", "Tek kullanımlık kodu kullan"],
	"rec.back": ["← Return to sign in", "← Oturum açmaya dön"],
	"rec.note": [
		"Break-glass codes are single-use and are never retrievable again.",
		"Acil durum kodları tek kullanımlıktır ve bir daha görüntülenemez.",
	],
} as const satisfies MessagePairs<string>;

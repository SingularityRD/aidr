import type { MessagePairs } from "./define";

/** API keys and enrollment tokens page. */
export const apiKeysMessages = {
	"keys.life.30": ["30 days", "30 gün"],
	"keys.life.90": ["90 days", "90 gün"],
	"keys.life.365": ["1 year (recommended)", "1 yıl (önerilen)"],
	"keys.life.730": ["2 years", "2 yıl"],
	"keys.life.never": ["Never expires (not recommended)", "Süresiz (önerilmez)"],
	"keys.label.tooLong": ["Use at most {max} characters.", "En fazla {max} karakter kullanın."],
	"keys.label.control": [
		"Remove line breaks and other control characters.",
		"Satır sonlarını ve diğer denetim karakterlerini kaldırın.",
	],
	"keys.bgNotice": [
		"Copy this Browser Guard key now (shown once) and paste it into the managed policy's telemetry.apiKey.",
		"Bu Browser Guard anahtarını şimdi kopyalayın (yalnızca bir kez gösterilir) ve yönetilen ilkedeki telemetry.apiKey alanına yapıştırın.",
	],
	"keys.type.bgLimit": [
		"Browser Guard ingest · up to {count} installs",
		"Browser Guard veri gönderimi · en fazla {count} kurulum",
	],
	"keys.type.bg": ["Browser Guard ingest", "Browser Guard veri gönderimi"],
	"keys.type.tenant": ["Tenant", "Çalışma alanı"],
	"keys.noTeam": [
		"Select a team to manage its credentials.",
		"Kimlik bilgilerini yönetmek için bir ekip seçin.",
	],
	"keys.serviceUnavailable": [
		"The dashboard service is unavailable.",
		"Panel hizmeti kullanılamıyor.",
	],
	"keys.accessInvalid": [
		"Workspace access response is invalid.",
		"Çalışma alanı erişim yanıtı geçersiz.",
	],
	"keys.listInvalid": [
		"API key list response is invalid.",
		"API anahtarı listesi yanıtı geçersiz.",
	],
	"keys.tokenListInvalid": [
		"Enrollment token list response is invalid.",
		"Kayıt belirteci listesi yanıtı geçersiz.",
	],
	"keys.rotateUnconfirmed": [
		"API key rotation was not confirmed.",
		"API anahtarı yenilemesi doğrulanmadı.",
	],
	"keys.rotatedOverlap": [
		"Copy this new key now (shown once). The previous key remains valid until {time}.",
		"Bu yeni anahtarı şimdi kopyalayın (yalnızca bir kez gösterilir). Önceki anahtar {time} saatine kadar geçerli kalır.",
	],
	"keys.rotatedNow": [
		"Copy this new key now (shown once). The previous key is no longer valid.",
		"Bu yeni anahtarı şimdi kopyalayın (yalnızca bir kez gösterilir). Önceki anahtar artık geçerli değil.",
	],
	"keys.rotateUnavailable": [
		"API key rotation is unavailable.",
		"API anahtarı yenileme kullanılamıyor.",
	],
	"keys.team": ["Team: {name}", "Ekip: {name}"],
	"keys.intro": [
		"Advanced: keys and enrollment tokens for manual setups and support.",
		"Gelişmiş: elle kurulumlar ve destek için anahtarlar ve kayıt belirteçleri.",
	],
	"keys.access": ["Workspace access", "Çalışma alanı erişimi"],
	"keys.activateFirst": [
		"Activate workspace access before creating keys or enrolling devices. Use the Onboarding flow to check availability.",
		"Anahtar oluşturmadan ya da cihaz kaydetmeden önce çalışma alanı erişimini etkinleştirin. Uygunluğu İlk kurulum sayfasından denetleyin.",
	],
	"keys.keyType": ["Key type", "Anahtar türü"],
	"keys.option.tenant": [
		"Tenant key (CLI, IDE and agent connectors)",
		"Çalışma alanı anahtarı (CLI, IDE ve yapay zekâ aracı bağlayıcıları)",
	],
	"keys.option.bg": [
		"Browser Guard ingest-only key",
		"Yalnızca veri gönderebilen Browser Guard anahtarı",
	],
	"keys.labelOptional": ["Label (optional)", "Etiket (isteğe bağlı)"],
	"keys.labelPlaceholder": ["work-laptop, build-server, etc.", "is-dizustu, derleme-sunucusu vb."],
	"keys.expiresAfter": ["Expires after", "Geçerlilik süresi"],
	"keys.neverWarning": [
		"A key that never expires stays valid until someone revokes it, even if it leaks. Prefer an expiry and rotate the key before it ends.",
		"Süresiz bir anahtar, sızsa bile biri iptal edene kadar geçerli kalır. Süreli bir anahtar seçin ve süresi dolmadan yenileyin.",
	],
	"keys.createUnconfirmed": [
		"API key creation was not confirmed.",
		"API anahtarı oluşturma doğrulanmadı.",
	],
	"keys.createFailed": ["Failed to create API key.", "API anahtarı oluşturulamadı."],
	"keys.createUnavailable": [
		"API key creation is unavailable. Please retry.",
		"API anahtarı oluşturma kullanılamıyor. Lütfen yeniden deneyin.",
	],
	"keys.generate": ["Generate key", "Anahtar oluştur"],
	"keys.copyOnce": [
		"Copy this key now (shown once):",
		"Bu anahtarı şimdi kopyalayın (yalnızca bir kez gösterilir):",
	],
	"keys.newKey": ["New API key", "Yeni API anahtarı"],
	"keys.copyBlocked": [
		"Clipboard access was blocked. Reveal the key and copy it manually.",
		"Panoya erişim engellendi. Anahtarı gösterip elle kopyalayın.",
	],
	"keys.tokens.title": ["Enrollment Tokens", "Kayıt belirteçleri"],
	"keys.tokens.intro": [
		"Enrollment tokens are one-time, short-lived credentials used to bootstrap an agent without manually copying an API key. They are stored as SHA-256 hashes only.",
		"Kayıt belirteçleri, API anahtarını elle kopyalamadan bir yapay zekâ aracını başlatmak için kullanılan tek kullanımlık, kısa ömürlü kimlik bilgileridir. Yalnızca SHA-256 özeti olarak saklanır.",
	],
	"keys.tokens.placeholder": ["workstation-1, ci-runner, etc.", "istasyon-1, ci-calistirici vb."],
	"keys.tokens.createUnconfirmed": [
		"Enrollment token creation was not confirmed.",
		"Kayıt belirteci oluşturma doğrulanmadı.",
	],
	"keys.tokens.createFailed": [
		"Failed to create enrollment token.",
		"Kayıt belirteci oluşturulamadı.",
	],
	"keys.tokens.createUnavailable": [
		"Enrollment token creation is unavailable. Please retry.",
		"Kayıt belirteci oluşturma kullanılamıyor. Lütfen yeniden deneyin.",
	],
	"keys.tokens.generate": ["Generate enrollment token", "Kayıt belirteci oluştur"],
	"keys.tokens.copyOnce": [
		"Copy this token now (shown once):",
		"Bu belirteci şimdi kopyalayın (yalnızca bir kez gösterilir):",
	],
	"keys.tokens.new": ["New enrollment token", "Yeni kayıt belirteci"],
	"keys.issued": ["Issued keys", "Verilen anahtarlar"],
	"keys.col.label": ["Label", "Etiket"],
	"keys.col.created": ["Created", "Oluşturulma"],
	"keys.col.expires": ["Expires", "Bitiş"],
	"keys.noLabel": ["(no label)", "(etiket yok)"],
	"keys.never": ["never", "süresiz"],
	"keys.rotate": ["Rotate", "Yenile"],
	"keys.revokeUnconfirmed": [
		"API key revocation was not confirmed.",
		"API anahtarı iptali doğrulanmadı.",
	],
	"keys.revokeUnavailable": [
		"API key revocation is unavailable.",
		"API anahtarı iptali kullanılamıyor.",
	],
	"keys.revoke": ["Revoke", "İptal et"],
	"keys.empty": ["No keys yet.", "Henüz anahtar yok."],
	"keys.tokens.issued": ["Issued enrollment tokens", "Verilen kayıt belirteçleri"],
	"keys.status.consumed": ["consumed", "kullanıldı"],
	"keys.status.expired": ["expired", "süresi doldu"],
	"keys.status.active": ["active", "etkin"],
	"keys.status.revoked": ["revoked", "iptal edildi"],
	"keys.tokens.deleteUnconfirmed": [
		"Enrollment token deletion was not confirmed.",
		"Kayıt belirteci silme doğrulanmadı.",
	],
	"keys.tokens.deleteUnavailable": [
		"Enrollment token deletion is unavailable.",
		"Kayıt belirteci silme kullanılamıyor.",
	],
	"keys.tokens.empty": ["No enrollment tokens yet.", "Henüz kayıt belirteci yok."],
	"keys.rotateHint": [
		"Rotate this key before it expires.",
		"Bu anahtarı süresi dolmadan yenileyin.",
	],
	"keys.expiresInDay": ["expires in 1 day", "1 gün içinde süresi doluyor"],
	"keys.expiresInDays": ["expires in {days} days", "{days} gün içinde süresi doluyor"],
	"keys.bg.body": [
		"For Browser Guard managed policy. Users of a managed browser can read this key, so it can only report counts-only privacy scans from Browser Guard, for at most the number of browser installations below. It cannot read policy, packs or reputation data. Only owners and admins can create one.",
		"Browser Guard yönetilen ilkesi içindir. Yönetilen tarayıcının kullanıcıları bu anahtarı okuyabilir; bu yüzden anahtar yalnızca Browser Guard'dan sayı içeren gizlilik taramalarını, en fazla aşağıdaki tarayıcı kurulumu sayısı kadar bildirebilir. İlke, paket ya da itibar verisi okuyamaz. Yalnızca sahipler ve yöneticiler oluşturabilir.",
	],
	"keys.bg.limit": ["Installation limit", "Kurulum sınırı"],
	"keys.bg.limitInvalid": [
		"Enter a whole number from 1 to {max}.",
		"1 ile {max} arasında bir tam sayı girin.",
	],
	"keys.bg.askAdmin": [
		"Ask a workspace owner or admin to create this key.",
		"Bu anahtarı oluşturması için bir çalışma alanı sahibine ya da yöneticisine başvurun.",
	],
} as const satisfies MessagePairs<string>;

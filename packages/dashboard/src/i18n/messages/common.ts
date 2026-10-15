import type { MessagePairs } from "./define";

/** Words and sentences shared by several console pages. */
export const commonMessages = {
	"common.role.owner": ["Owner", "Sahip"],
	"common.role.admin": ["Administrator", "Yönetici"],
	"common.role.member": ["Member", "Üye"],
	"common.role.viewer": ["Viewer", "İzleyici"],
	"common.severity.critical": ["Critical", "Kritik"],
	"common.severity.high": ["High", "Yüksek"],
	"common.severity.medium": ["Medium", "Orta"],
	"common.severity.low": ["Low", "Düşük"],
	"common.severity.warning": ["Warning", "Uyarı"],
	"common.severity.info": ["Info", "Bilgi"],
	"common.retry": ["Retry", "Yeniden dene"],
	"common.cancel": ["Cancel", "Vazgeç"],
	"common.saving": ["Saving…", "Kaydediliyor…"],
	"common.loading": ["Loading…", "Yükleniyor…"],
	"common.refresh": ["Refresh", "Yenile"],
	"common.unknown": ["unknown", "bilinmiyor"],
	"common.unavailable": ["unavailable", "kullanılamıyor"],
	"common.enabled": ["Enabled", "Açık"],
	"common.disabled": ["Disabled", "Kapalı"],
	"common.status": ["Status", "Durum"],
	"common.name": ["Name", "Ad"],
	"common.days": ["{count} days", "{count} gün"],
	"common.verifyMfa": ["Verify with authenticator", "Doğrulama uygulamasıyla doğrula"],
	"common.sessionInvalid": [
		"Your session is no longer valid. Sign in again.",
		"Oturumunuz artık geçerli değil. Yeniden oturum açın.",
	],
} as const satisfies MessagePairs<string>;

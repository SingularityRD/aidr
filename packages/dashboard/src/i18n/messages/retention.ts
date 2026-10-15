import type { MessagePairs } from "./define";

/** Legal holds and retention page. */
export const retentionMessages = {
	"ret.class.telemetry": ["Agent telemetry and incidents", "Araç telemetrisi ve güvenlik vakaları"],
	"ret.class.endpointIdentity": ["Endpoint and agent identity", "Cihaz ve araç kimliği"],
	"ret.class.securityIntelligence": ["Tenant reputation records", "Çalışma alanı itibar kayıtları"],
	"ret.class.policyConfiguration": ["Policy configuration", "Politika yapılandırması"],
	"ret.class.identityMembership": ["Membership and invitations", "Üyelik ve davetler"],
	"ret.class.commercialRecords": [
		"Commercial and billing records",
		"Ticari ve faturalama kayıtları",
	],
	"ret.class.securityAudit": [
		"Security and administrative audit",
		"Güvenlik ve yönetim denetim kayıtları",
	],
	"ret.class.temporaryExports": ["Temporary exports", "Geçici dışa aktarımlar"],
	"ret.class.accessCredentials": ["Access credentials", "Erişim kimlik bilgileri"],
	"ret.class.operationalEphemera": ["Operational ephemera", "Geçici işletim verileri"],
	"ret.err.ownerRequired": [
		"Only an active tenant owner can change legal holds or retention periods.",
		"Yasal saklama ve saklama sürelerini yalnızca etkin bir çalışma alanı sahibi değiştirebilir.",
	],
	"ret.err.adminRequired": [
		"Only an active tenant owner or admin can view legal hold and retention settings.",
		"Yasal saklama ve saklama ayarlarını yalnızca etkin bir çalışma alanı sahibi ya da yöneticisi görebilir.",
	],
	"ret.err.holdActive": [
		"This tenant already has an active legal hold. Release it before placing another.",
		"Bu çalışma alanında zaten etkin bir yasal saklama var. Yenisini koymadan önce onu kaldırın.",
	],
	"ret.err.pendingDeletion": [
		"Hold NOT placed: a Storage deletion is already in flight for this tenant. Escalate to your AIDR operator now; the tenant is unprotected.",
		"Yasal saklama KONULMADI: bu çalışma alanı için bir depolama silme işlemi zaten sürüyor. Hemen AIDR operatörünüze iletin; çalışma alanı korumasız.",
	],
	"ret.err.holdGone": [
		"That hold no longer exists or was already released. Refresh the list.",
		"Bu yasal saklama artık yok ya da zaten kaldırıldı. Listeyi yenileyin.",
	],
	"ret.err.outOfBounds": [
		"That retention period is outside the allowed range for this data class.",
		"Bu saklama süresi bu veri sınıfı için izin verilen aralığın dışında.",
	],
	"ret.err.exceedsPlan": [
		"That event retention period is longer than your plan includes. Choose a shorter period or upgrade.",
		"Bu olay saklama süresi planınızın kapsadığından uzun. Daha kısa bir süre seçin ya da planınızı yükseltin.",
	],
	"ret.err.notConfigurable": [
		"That data class is controlled by the platform and cannot be changed.",
		"Bu veri sınıfı platform tarafından yönetilir ve değiştirilemez.",
	],
	"ret.err.offboarding": [
		"Retention cannot change while tenant offboarding is in progress.",
		"Çalışma alanı kapatma işlemi sürerken saklama değiştirilemez.",
	],
	"ret.err.invalid": [
		"The request was rejected. Check each field.",
		"İstek reddedildi. Her alanı kontrol edin.",
	],
	"ret.err.unavailable": [
		"Retention management is temporarily unavailable. No change was confirmed.",
		"Saklama yönetimi geçici olarak kullanılamıyor. Hiçbir değişiklik onaylanmadı.",
	],
	"ret.err.invalidResponse": [
		"Retention management returned an invalid response.",
		"Saklama yönetimi geçersiz bir yanıt döndürdü.",
	],
	"ret.err.invalidRecord": [
		"Retention management returned an invalid record.",
		"Saklama yönetimi geçersiz bir kayıt döndürdü.",
	],
	"ret.err.invalidCursor": [
		"Retention management returned an invalid pagination cursor.",
		"Saklama yönetimi geçersiz bir sayfalama imleci döndürdü.",
	],
	"ret.selectTenant": [
		"Select a tenant to manage legal holds and retention.",
		"Yasal saklama ve saklama sürelerini yönetmek için bir çalışma alanı seçin.",
	],
	"ret.title": ["Legal holds and retention", "Yasal saklama ve saklama süreleri"],
	"ret.ownersOnly": [
		"Legal holds and retention periods are available to tenant owners and admins only.",
		"Yasal saklama ve saklama süreleri yalnızca çalışma alanı sahipleri ve yöneticileri içindir.",
	],
	"ret.loadFailed": ["Unable to load retention settings.", "Saklama ayarları yüklenemedi."],
	"ret.badCase": [
		"Enter the case ID (letters, digits and . _ : / # - only, up to 100 characters).",
		"Dosya kimliğini girin (yalnızca harf, rakam ve . _ : / # -, en fazla 100 karakter).",
	],
	"ret.badText": [
		"Owner, reason and the optional reference must be non-empty, trimmed text without control characters.",
		"Sorumlu, gerekçe ve isteğe bağlı başvuru; boş olmayan, başında ve sonunda boşluk olmayan ve kontrol karakteri içermeyen metin olmalıdır.",
	],
	"ret.holdUnconfirmed": ["The legal hold was not confirmed.", "Yasal saklama onaylanmadı."],
	"ret.holdPlaced": [
		"Legal hold placed. Retention and offboarding will not delete this tenant's data until it is released.",
		"Yasal saklama konuldu. Kaldırılana kadar saklama ve kapatma işlemleri bu çalışma alanının verilerini silmez.",
	],
	"ret.badRelease": [
		"Enter a release reason (non-empty, trimmed text).",
		"Bir kaldırma gerekçesi girin (boş olmayan, başında ve sonunda boşluk olmayan metin).",
	],
	"ret.releaseUnconfirmed": ["The release was not confirmed.", "Kaldırma onaylanmadı."],
	"ret.released": [
		"Legal hold released. Data past its retention period becomes eligible for deletion on the next scheduled run.",
		"Yasal saklama kaldırıldı. Saklama süresi geçmiş veriler bir sonraki zamanlanmış çalışmada silinebilir hale gelir.",
	],
	"ret.badDays": [
		"Enter a whole number of days between {min} and {max}.",
		"{min} ile {max} arasında tam sayı olarak gün girin.",
	],
	"ret.badChangeReason": [
		"Enter a reason for this change (non-empty, trimmed text, up to 500 characters).",
		"Bu değişiklik için bir gerekçe girin (boş olmayan, başında ve sonunda boşluk olmayan metin, en fazla 500 karakter).",
	],
	"ret.changeUnconfirmed": [
		"The retention change was not confirmed.",
		"Saklama değişikliği onaylanmadı.",
	],
	"ret.saved": [
		"Retention period saved and audited.",
		"Saklama süresi kaydedildi ve denetim kaydına yazıldı.",
	],
	"ret.unchanged": [
		"That is already the configured retention period; nothing changed.",
		"Bu zaten yapılandırılmış saklama süresi; hiçbir şey değişmedi.",
	],
	"ret.lead": [
		"Manage legal holds and data retention periods for {team}. Every change is recorded in the administrative audit log.",
		"{team} için yasal saklamaları ve veri saklama sürelerini yönetin. Her değişiklik yönetim denetim kaydına yazılır.",
	],
	"ret.adminView": [
		"Admins can view these settings. Only a tenant owner can change them.",
		"Yöneticiler bu ayarları görebilir. Yalnızca çalışma alanı sahibi değiştirebilir.",
	],
	"ret.hold": ["Legal hold", "Yasal saklama"],
	"ret.activeHoldLabel": ["Active legal hold", "Etkin yasal saklama"],
	"ret.activeHold": ["Active hold", "Etkin saklama"],
	"ret.activeHoldLine": [
		" — case {case}, owner {owner}, placed {time}.",
		" — dosya {case}, sorumlu {owner}, konulma {time}.",
	],
	"ret.notRecorded": ["not recorded", "kaydedilmedi"],
	"ret.releaseReason": ["Release reason", "Kaldırma gerekçesi"],
	"ret.confirmRelease": ["Confirm release", "Kaldırmayı onayla"],
	"ret.release": ["Release hold", "Saklamayı kaldır"],
	"ret.noHold": [
		"No active legal hold. Retention and offboarding follow the periods below.",
		"Etkin yasal saklama yok. Saklama ve kapatma işlemleri aşağıdaki süreleri izler.",
	],
	"ret.placeLabel": ["Place legal hold", "Yasal saklama koy"],
	"ret.placeTitle": ["Place a hold", "Saklama koyun"],
	"ret.caseId": ["Case ID", "Dosya kimliği"],
	"ret.holdOwner": ["Hold owner", "Saklama sorumlusu"],
	"ret.holdOwnerPlaceholder": ["Responsible counsel or custodian", "Sorumlu hukukçu ya da muhafız"],
	"ret.reason": ["Reason", "Gerekçe"],
	"ret.reference": ["Reference (optional)", "Başvuru (isteğe bağlı)"],
	"ret.holdEffect": [
		"While a hold is active, routine retention, audit export deletion and offboarding do not delete this tenant's data.",
		"Saklama etkinken olağan saklama, denetim dışa aktarımı silme ve kapatma işlemleri bu çalışma alanının verilerini silmez.",
	],
	"ret.confirmPlace": ["Confirm: place legal hold", "Onayla: yasal saklama koy"],
	"ret.periods": ["Retention periods", "Saklama süreleri"],
	"ret.periodsLead": [
		"Periods are bounded per data class. Shortening a period lets the next scheduled run delete data already older than the new period unless a legal hold is active. Backup copies follow separate backup retention.",
		"Süreler her veri sınıfı için sınırlıdır. Bir süreyi kısaltmak, yasal saklama etkin değilse bir sonraki zamanlanmış çalışmanın yeni süreden eski verileri silmesine izin verir. Yedek kopyalar ayrı yedek saklama süresini izler.",
	],
	"ret.periodsCaption": ["Retention periods by data class", "Veri sınıfına göre saklama süreleri"],
	"ret.col.class": ["Data class", "Veri sınıfı"],
	"ret.col.days": ["Days", "Gün"],
	"ret.col.effective": ["Effective", "Geçerli"],
	"ret.col.allowed": ["Allowed", "İzin verilen"],
	"ret.col.actions": ["Actions", "İşlemler"],
	"ret.planMax": [" (plan max {days})", " (plan üst sınırı {days})"],
	"ret.platform": ["Platform controlled", "Platform yönetir"],
	"ret.daysFor": ["Retention days for {class}", "{class} için saklama günü"],
	"ret.changeReason": ["Reason for change", "Değişiklik gerekçesi"],
	"ret.save": ["Save", "Kaydet"],
	"ret.change": ["Change", "Değiştir"],
	"ret.history": ["Hold history", "Saklama geçmişi"],
	"ret.noHistory": [
		"No legal holds have been recorded for this tenant.",
		"Bu çalışma alanı için kaydedilmiş yasal saklama yok.",
	],
	"ret.historyCaption": ["Legal hold history", "Yasal saklama geçmişi"],
	"ret.col.case": ["Case", "Dosya"],
	"ret.col.owner": ["Owner", "Sorumlu"],
	"ret.col.placed": ["Placed", "Konulma"],
	"ret.col.released": ["Released", "Kaldırılma"],
	"ret.active": ["Active", "Etkin"],
	"ret.loadMore": ["Load more", "Daha fazla yükle"],
} as const satisfies MessagePairs<string>;

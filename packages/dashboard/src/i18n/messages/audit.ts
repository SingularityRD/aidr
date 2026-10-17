import type { MessagePairs } from "./define";

/** Team audit panel and administrative-actions audit. */
export const auditMessages = {
	"audit.exportUnavailable": [
		"Audit export is unavailable.",
		"Denetim dışa aktarımı kullanılamıyor.",
	],
	"audit.title": ["Team audit", "Ekip denetimi"],
	"audit.intro": [
		"Recent audit entries for the selected team only. This view shows at most the latest 1,000 entries; use the paginated export API for larger history. Browser export is capped at 100,000 records or 64 MiB. No raw action input is shown here.",
		"Yalnızca seçili ekibin son denetim kayıtları. Bu görünüm en fazla son 1.000 kaydı gösterir; daha uzun geçmiş için sayfalı dışa aktarma API'sini kullanın. Tarayıcıdan dışa aktarma 100.000 kayıt ya da 64 MiB ile sınırlıdır. Burada işlemlerin ham girdisi gösterilmez.",
	],
	"audit.selectTeam": [
		"Select an accessible team to view its audit records.",
		"Denetim kayıtlarını görmek için erişebildiğiniz bir ekip seçin.",
	],
	"audit.refresh": ["Refresh audit", "Denetimi yenile"],
	"audit.prepareCsv": ["Prepare CSV export", "CSV dışa aktarımını hazırla"],
	"audit.prepareJson": ["Prepare JSON export", "JSON dışa aktarımını hazırla"],
	"audit.exportOwners": [
		"Audit export is available to team owners, admins and auditors.",
		"Denetim dışa aktarımı ekip sahipleri, yöneticileri ve denetçiler içindir.",
	],
	"audit.rangeFrom": ["From (UTC date)", "Başlangıç (UTC tarihi)"],
	"audit.rangeTo": ["To (UTC date, inclusive)", "Bitiş (UTC tarihi, dahil)"],
	"audit.rangeHint": [
		"Leave both dates empty to export the whole trail. The range applies to both audit trails.",
		"Kaydın tamamını dışa aktarmak için iki tarihi de boş bırakın. Aralık iki denetim kaydına da uygulanır.",
	],
	"audit.rangeInvalid": [
		"The start date must not be after the end date.",
		"Başlangıç tarihi bitiş tarihinden sonra olamaz.",
	],
	"audit.ready": ["Audit export is ready to download.", "Denetim dışa aktarımı indirilmeye hazır."],
	"audit.save": ["Save audit export", "Denetim dışa aktarımını kaydet"],
	"audit.loading": ["Loading audit records…", "Denetim kayıtları yükleniyor…"],
	"audit.unavailable": ["Audit records are unavailable.", "Denetim kayıtları alınamıyor."],
	"audit.empty": ["No audit records for this team.", "Bu ekip için denetim kaydı yok."],
	"audit.time": ["Time", "Zaman"],
	"audit.actor": ["Actor", "İşlemi yapan"],
	"audit.action": ["Action", "İşlem"],
	"audit.timeUnavailable": ["Time unavailable", "Zaman bilgisi yok"],
	"audit.notRecorded": ["Not recorded", "Kaydedilmedi"],
	"audit.prev": ["Previous audit page", "Önceki denetim sayfası"],
	"audit.pageOf": ["Page {page} of {count}", "Sayfa {page} / {count}"],
	"audit.next": ["Next audit page", "Sonraki denetim sayfası"],

	"adminAudit.malformed": [
		"The administrative audit response was malformed.",
		"Yönetim denetimi yanıtı hatalı.",
	],
	"adminAudit.unavailable": [
		"Administrative audit records are unavailable.",
		"Yönetim denetim kayıtları alınamıyor.",
	],
	"adminAudit.exportUnavailable": [
		"Administrative audit export is unavailable.",
		"Yönetim denetimi dışa aktarımı kullanılamıyor.",
	],
	"adminAudit.title": ["Administrative actions", "Yönetim işlemleri"],
	"adminAudit.intro": [
		"Configuration and access changes (policies, SSO, SCIM, retention, roles) for this team. Visible to owners, admins and auditors only.",
		"Bu ekibin yapılandırma ve erişim değişiklikleri (politikalar, SSO, SCIM, saklama, roller). Yalnızca sahipler, yöneticiler ve denetçiler görebilir.",
	],
	"adminAudit.refresh": ["Refresh administrative audit", "Yönetim denetimini yenile"],
	"adminAudit.csv": ["Export administrative CSV", "Yönetim CSV dışa aktar"],
	"adminAudit.json": ["Export administrative JSON", "Yönetim JSON dışa aktar"],
	"adminAudit.save": [
		"Save administrative audit export",
		"Yönetim denetimi dışa aktarımını kaydet",
	],
	"adminAudit.loading": ["Loading administrative actions…", "Yönetim işlemleri yükleniyor…"],
	"adminAudit.empty": [
		"No administrative actions recorded for this team.",
		"Bu ekip için kayıtlı yönetim işlemi yok.",
	],
	"adminAudit.target": ["Target", "Hedef"],
	"adminAudit.detail": ["Detail", "Ayrıntı"],
	"adminAudit.system": ["System", "Sistem"],
	"adminAudit.newer": ["Newer administrative actions", "Daha yeni yönetim işlemleri"],
	"adminAudit.page": ["Page {page}", "Sayfa {page}"],
	"adminAudit.older": ["Older administrative actions", "Daha eski yönetim işlemleri"],
} as const satisfies MessagePairs<string>;

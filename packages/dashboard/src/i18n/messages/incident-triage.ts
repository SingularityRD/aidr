import type { MessagePairs } from "./define";

/** Incident triage on the Security incidents page, and its hand-off to detection exceptions. */
export const incidentTriageMessages = {
	"inc.status.open": ["Open", "Açık"],
	"inc.status.acknowledged": ["Acknowledged", "Üstlenildi"],
	"inc.status.resolved": ["Resolved", "Çözüldü"],
	"inc.status.false_positive": ["False positive", "Yanlış pozitif"],
	"inc.col.status": ["Status", "Durum"],
	"inc.col.owner": ["Owner", "Sorumlu"],
	"inc.unassigned": ["Unassigned", "Atanmadı"],
	"inc.untriaged": ["new", "yeni"],
	"inc.show": ["Show", "Göster"],
	"inc.filter.active": [
		"To handle (open and acknowledged)",
		"Ele alınacaklar (açık ve üstlenilen)",
	],
	"inc.filter.snoozed": ["Snoozed", "Ertelenenler"],
	"inc.filter.closed": [
		"Closed (resolved and false positive)",
		"Kapananlar (çözülen ve yanlış pozitif)",
	],
	"inc.filter.all": ["All", "Tümü"],
	"inc.mine": ["Only incidents assigned to me", "Yalnızca bana atanan vakalar"],
	"inc.noneInFilter": [
		"No incidents match this view. Change the filter to see the others.",
		"Bu görünüme uyan vaka yok. Diğerlerini görmek için süzgeci değiştirin.",
	],
	"inc.manage": ["Manage", "Yönet"],
	"inc.details": ["Details", "Ayrıntılar"],
	"inc.manageLabel": ["Manage incident {id}", "{id} numaralı vakayı yönet"],
	"inc.panelTitle": ["Incident handling", "Vaka yönetimi"],
	"inc.close": ["Close", "Kapat"],
	"inc.formLabel": ["Change incident status", "Vaka durumunu değiştir"],
	"inc.note": ["Note (optional)", "Not (isteğe bağlı)"],
	"inc.noteRequired": ["Resolution note (required)", "Çözüm notu (zorunlu)"],
	"inc.snoozeUntil": [
		"Snooze until (hidden from the queue until this day, at most {days} days)",
		"Şu tarihe kadar ertele (bu güne kadar listede görünmez, en fazla {days} gün)",
	],
	"inc.snoozedUntil": ["snoozed until {date}", "{date} tarihine kadar ertelendi"],
	"inc.fpHint": [
		"Marking a false positive does not change what AIDR blocks. If the rule should stop firing for this agent, create a time-limited detection exception after saving.",
		"Yanlış pozitif olarak işaretlemek AIDR'nin neyi engellediğini değiştirmez. Kural bu ajan için tetiklenmemeliyse, kaydettikten sonra süreli bir algılama istisnası oluşturun.",
	],
	"inc.save": ["Save", "Kaydet"],
	"inc.saved": ["Saved. Status: {status}.", "Kaydedildi. Durum: {status}."],
	"inc.readOnly": [
		"Only workspace owners and admins can change incident status. You can follow the history below.",
		"Vaka durumunu yalnızca çalışma alanı sahipleri ve yöneticileri değiştirebilir. Aşağıdaki geçmişi izleyebilirsiniz.",
	],
	"inc.createException": ["Create a detection exception…", "Algılama istisnası oluştur…"],
	"inc.createExceptionHint": [
		"Opens the exception form filled in with this rule and agent. Review it before you submit; it lasts at most 30 days.",
		"İstisna formunu bu kural ve ajanla doldurulmuş olarak açar. Göndermeden önce gözden geçirin; en fazla 30 gün sürer.",
	],
	"inc.history": ["Audit trail", "Denetim izi"],
	"inc.loadingHistory": ["Loading the audit trail…", "Denetim izi yükleniyor…"],
	"inc.noHistory": ["No changes yet.", "Henüz değişiklik yok."],
	"inc.historyLine": [
		"{actor}: {from} → {to}, owner {owner}",
		"{actor}: {from} → {to}, sorumlu {owner}",
	],
	"inc.selfClosure": [
		"closed by the person whose agent raised it",
		"ajanı bu vakayı oluşturan kişi tarafından kapatıldı",
	],
	"inc.triageUnavailable": [
		"Incident status could not be loaded; every incident is shown as open. ({reason})",
		"Vaka durumları yüklenemedi; tüm vakalar açık gösteriliyor. ({reason})",
	],
	"inc.verifyNow": ["Verify now", "Şimdi doğrula"],
	"inc.problem.note": [
		"Write a resolution note before closing the incident.",
		"Vakayı kapatmadan önce bir çözüm notu yazın.",
	],
	"inc.problem.noteLong": [
		"The note can be at most {max} characters.",
		"Not en fazla {max} karakter olabilir.",
	],
	"inc.problem.snoozeClosed": [
		"A resolved or false-positive incident cannot be snoozed.",
		"Çözülmüş ya da yanlış pozitif bir vaka ertelenemez.",
	],
	"inc.problem.snoozeFuture": [
		"The snooze date must be in the future.",
		"Erteleme tarihi gelecekte olmalıdır.",
	],
	"inc.problem.snoozeMax": [
		"An incident can be snoozed for at most {days} days.",
		"Bir vaka en fazla {days} gün ertelenebilir.",
	],
	"inc.err.mfa": [
		"Changing incident status needs multi-factor verification in this session.",
		"Vaka durumunu değiştirmek için bu oturumda çok adımlı doğrulama gerekir.",
	],
	"inc.err.role": [
		"Only workspace owners and admins can change incident status.",
		"Vaka durumunu yalnızca çalışma alanı sahipleri ve yöneticileri değiştirebilir.",
	],
	"inc.err.conflict": [
		"Someone else changed this incident meanwhile. Reload the page and try again.",
		"Bu vaka bu arada başka biri tarafından değiştirildi. Sayfayı yenileyip yeniden deneyin.",
	],
	"inc.err.notFound": [
		"This incident no longer exists (it may have passed the retention period).",
		"Bu vaka artık yok (saklama süresi dolmuş olabilir).",
	],
	"inc.err.owner": [
		"The owner must be an active owner, admin or member of this workspace.",
		"Sorumlu, bu çalışma alanının etkin bir sahibi, yöneticisi ya da üyesi olmalıdır.",
	],
	"inc.err.unchanged": ["Nothing changed.", "Değişiklik yok."],
	"inc.err.rateLimited": [
		"Too many changes in a short time. Wait a minute and try again.",
		"Kısa sürede çok fazla değişiklik yapıldı. Bir dakika bekleyip yeniden deneyin.",
	],
	"inc.err.unavailable": [
		"The incident service is not available right now.",
		"Vaka hizmetine şu anda ulaşılamıyor.",
	],
	"dex.prefilled": [
		"Filled in from a false-positive incident. Check the rule, the agent, the end date and the reason before you add it.",
		"Yanlış pozitif bir vakadan dolduruldu. Eklemeden önce kuralı, ajanı, bitiş tarihini ve gerekçeyi kontrol edin.",
	],
} as const satisfies MessagePairs<string>;

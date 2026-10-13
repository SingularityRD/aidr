import type { MessagePairs } from "./define";

/** Settings → Notifications (alert channels). */
export const notificationsMessages = {
	"notify.type.webhook": ["Signed webhook", "İmzalı webhook"],
	"notify.type.email": ["E-mail", "E-posta"],

	"notify.event.incidentCreated": ["Incident created", "Vaka oluşturuldu"],
	"notify.event.denyCritical": ["Critical runtime deny", "Kritik çalışma zamanı engeli"],
	"notify.event.approvalRequested": ["Approval requested", "Onay istendi"],
	"notify.event.privacySpike": ["Privacy block spike", "Gizlilik engeli artışı"],
	"notify.event.test": ["Test", "Test"],
	"notify.event.agentOffline": ["Agent offline", "Ajan çevrim dışı"],
	"notify.event.agentRecovered": ["Agent back online", "Ajan yeniden çevrim içi"],
	"notify.event.reviewOverdue": ["AI reviews overdue", "Gecikmiş yapay zekâ incelemeleri"],
	"notify.event.intakeRequested": ["AI intake request", "Yapay zekâ kullanım talebi"],
	"notify.event.changePending": [
		"Policy change awaiting approval",
		"Onay bekleyen politika değişikliği",
	],
	"notify.event.exceptionExpiring": ["Exceptions expiring", "Süresi dolmak üzere olan istisnalar"],
	"notify.event.digest": ["Governance digest", "Yönetişim özeti"],

	"notify.error.mfaRequired": [
		"Multi-factor verification is required to change alert channels. Verify with your authenticator, then try again.",
		"Uyarı kanallarını değiştirmek için çok faktörlü doğrulama gerekir. Doğrulama uygulamanızla doğrulayıp yeniden deneyin.",
	],
	"notify.error.forbidden": [
		"Only workspace owners and administrators can manage alert notifications.",
		"Uyarı bildirimlerini yalnızca çalışma alanı sahipleri ve yöneticileri yönetebilir.",
	],
	"notify.error.notConfigured": [
		"Alert delivery is not configured on this deployment. Ask your operator to set AIDR_NOTIFICATION_ENCRYPTION_KEYS.",
		"Bu kurulumda uyarı gönderimi yapılandırılmamış. Operatörünüzden AIDR_NOTIFICATION_ENCRYPTION_KEYS değerini ayarlamasını isteyin.",
	],
	"notify.error.limit": [
		"This workspace already has the maximum number of alert channels.",
		"Bu çalışma alanında zaten izin verilen en fazla sayıda uyarı kanalı var.",
	],
	"notify.error.nameConflict": [
		"Another channel already uses that name.",
		"Bu adı başka bir kanal kullanıyor.",
	],
	"notify.error.notFound": [
		"That channel no longer exists. Reload the list.",
		"Bu kanal artık yok. Listeyi yeniden yükleyin.",
	],
	"notify.error.invalidName": [
		"Enter a channel name of 1 to 80 characters.",
		"1 ile 80 karakter arasında bir kanal adı girin.",
	],
	"notify.error.invalidFilters": [
		"Select at least one event, with spike, offline and expiry settings inside the allowed ranges.",
		"En az bir olay seçin; artış, çevrim dışı ve süre dolumu ayarları izin verilen aralıkta olmalıdır.",
	],
	"notify.error.notHttps": [
		"The destination must be an https:// URL.",
		"Hedef bir https:// adresi olmalıdır.",
	],
	"notify.error.credentials": [
		"The destination URL must not contain a user name or password.",
		"Hedef adres kullanıcı adı ya da parola içermemelidir.",
	],
	"notify.error.port": [
		"The destination must use the standard HTTPS port (443; 8443 is also allowed for webhooks).",
		"Hedef standart HTTPS bağlantı noktasını kullanmalıdır (443; webhook'lar için 8443 de kabul edilir).",
	],
	"notify.error.host": [
		"Private, local and IP-address destinations are not allowed.",
		"Özel, yerel ve IP adresi biçimindeki hedeflere izin verilmez.",
	],
	"notify.error.hostNotAllowed": [
		"Use the incoming-webhook URL issued by Slack (hooks.slack.com/services/…) or by a Teams workflow.",
		"Slack'in (hooks.slack.com/services/…) ya da bir Teams iş akışının verdiği gelen webhook adresini kullanın.",
	],
	"notify.error.invalidUrl": ["Enter a valid destination URL.", "Geçerli bir hedef adres girin."],
	"notify.error.secret": [
		"The signing secret must be 32 to 256 printable characters. Use Generate for a strong one.",
		"İmzalama sırrı 32 ile 256 arasında yazdırılabilir karakter olmalıdır. Güçlü bir sır için Oluştur'u kullanın.",
	],
	"notify.error.recipients": [
		"Enter 1 to 10 valid e-mail addresses.",
		"1 ile 10 arasında geçerli e-posta adresi girin.",
	],
	"notify.error.notActive": [
		"This workspace is not active, so alert channels can no longer be changed.",
		"Bu çalışma alanı etkin olmadığı için uyarı kanalları artık değiştirilemez.",
	],
	"notify.error.rateLimited": [
		"Too many changes or test sends. Wait a minute and try again.",
		"Çok fazla değişiklik ya da test gönderimi yapıldı. Bir dakika bekleyip yeniden deneyin.",
	],
	"notify.error.generic": [
		"The notification service did not confirm the request.",
		"Bildirim hizmeti isteği doğrulamadı.",
	],

	"notify.test.delivered": ["Test notification delivered.", "Test bildirimi iletildi."],
	"notify.test.deliveredHttp": [
		"Test notification delivered (HTTP {code}).",
		"Test bildirimi iletildi (HTTP {code}).",
	],
	"notify.test.pending": [
		"The test could not be delivered yet ({detail}).",
		"Test henüz iletilemedi ({detail}).",
	],
	"notify.test.failed": ["The test was not delivered ({detail}).", "Test iletilmedi ({detail})."],

	"notify.summary.incidents": ["Incidents ≥ {severity}", "Vakalar ≥ {severity}"],
	"notify.summary.denies": ["Critical denies", "Kritik engeller"],
	"notify.summary.approvals": ["Approval requests", "Onay istekleri"],
	"notify.summary.privacy": [
		"Privacy blocks ≥ {threshold}/{minutes} min",
		"Gizlilik engelleri ≥ {threshold}/{minutes} dk",
	],
	"notify.summary.offline": [
		"Agents offline ≥ {minutes} min",
		"Çevrim dışı ajanlar ≥ {minutes} dk",
	],
	"notify.summary.overdue": ["Overdue AI reviews", "Gecikmiş yapay zekâ incelemeleri"],
	"notify.summary.intake": ["AI intake requests", "Yapay zekâ kullanım talepleri"],
	"notify.summary.changes": [
		"Policy changes awaiting approval",
		"Onay bekleyen politika değişiklikleri",
	],
	"notify.summary.expiring": [
		"Exceptions expiring ≤ {days} d",
		"Süresi dolan istisnalar ≤ {days} g",
	],

	"notify.filters.legend": ["Send alerts for", "Şunlar için uyarı gönder"],
	"notify.filters.incidents": [
		"New incidents with severity at least",
		"Önem derecesi en az şu olan yeni vakalar",
	],
	"notify.filters.minSeverity": ["Minimum incident severity", "En düşük vaka önem derecesi"],
	"notify.filters.denies": ["Critical runtime denies", "Kritik çalışma zamanı engelleri"],
	"notify.filters.approvals": [
		"Actions waiting for a person's approval",
		"Bir kişinin onayını bekleyen işlemler",
	],
	"notify.filters.spikes": [
		"Spikes in blocked AI prompts:",
		"Engellenen yapay zekâ mesajlarında artış:",
	],
	"notify.filters.threshold": ["Blocked prompts threshold", "Engellenen mesaj eşiği"],
	"notify.filters.blockedWithin": ["blocked within", "engelleme, süre:"],
	"notify.filters.window": ["Spike window in minutes", "Artış penceresi (dakika)"],
	"notify.filters.minutes": ["minutes", "dakika"],
	"notify.filters.offline": ["Enrolled agent not seen for", "Kayıtlı ajan şu süredir görülmedi:"],
	"notify.filters.offlineMinutes": [
		"Agent offline threshold in minutes",
		"Ajan çevrim dışı eşiği (dakika)",
	],
	"notify.filters.offlineNote": [
		"minutes (one alert per outage, plus a notice when it reports again)",
		"dakika (her kesinti için bir uyarı; yeniden bildirim gönderdiğinde ayrıca bir bilgi)",
	],
	"notify.filters.governance": ["AI governance", "Yapay zekâ yönetişimi"],
	"notify.filters.overdue": [
		"AI register items past their review date (daily count)",
		"İnceleme tarihi geçmiş yapay zekâ envanteri kayıtları (günlük sayı)",
	],
	"notify.filters.intake": ["New AI intake requests", "Yeni yapay zekâ kullanım talepleri"],
	"notify.filters.changes": [
		"Four-eyes policy changes awaiting approval",
		"Onay bekleyen dört göz politika değişiklikleri",
	],
	"notify.filters.expiring": [
		"Approved exceptions expiring within",
		"Şu süre içinde dolacak onaylı istisnalar:",
	],
	"notify.filters.expiryWindow": [
		"Exception expiry window in days",
		"İstisna süre dolumu penceresi (gün)",
	],
	"notify.filters.daysDaily": ["days (daily count)", "gün (günlük sayı)"],
	"notify.filters.digest": [
		"Scheduled governance digest (counts only; sent when the digest schedule runs)",
		"Zamanlanmış yönetişim özeti (yalnızca sayılar; özet zamanlaması çalıştığında gönderilir)",
	],

	"notify.url.slack": ["Slack incoming-webhook URL", "Slack gelen webhook adresi"],
	"notify.url.teams": ["Teams workflow webhook URL", "Teams iş akışı webhook adresi"],
	"notify.url.webhook": ["Webhook URL (https)", "Webhook adresi (https)"],

	"notify.add.label": ["Add alert channel", "Uyarı kanalı ekle"],
	"notify.add.title": ["Add a channel", "Kanal ekle"],
	"notify.add.type": ["Channel type", "Kanal türü"],
	"notify.add.name": ["Channel name", "Kanal adı"],
	"notify.add.namePlaceholder": ["SOC on-call", "SOC nöbetçi ekibi"],
	"notify.add.recipients": ["Recipients", "Alıcılar"],
	"notify.add.mailMissing": [
		"E-mail delivery is not configured on this deployment; e-mail alerts will fail until your operator configures a mail provider.",
		"Bu kurulumda e-posta gönderimi yapılandırılmamış; operatörünüz bir e-posta sağlayıcısı yapılandırana kadar e-posta uyarıları gönderilemez.",
	],
	"notify.add.secret": ["Signing secret", "İmzalama sırrı"],
	"notify.add.generate": ["Generate", "Oluştur"],
	"notify.add.secretNote": [
		"Copy this into your receiver now: it is stored encrypted and never shown again. Requests carry {header} (HMAC-SHA256).",
		"Bunu şimdi alıcı sisteminize kopyalayın: şifreli saklanır ve bir daha gösterilmez. İstekler {header} başlığını taşır (HMAC-SHA256).",
	],
	"notify.add.submit": ["Add channel", "Kanal ekle"],
	"notify.add.note": [
		"Destinations are validated (https only, no private or internal addresses), stored encrypted, and never displayed again. Alerts carry identifiers, severities, categories and counts only — never prompts, commands or file contents.",
		"Hedefler doğrulanır (yalnızca https; özel ya da iç adres olamaz), şifreli saklanır ve bir daha gösterilmez. Uyarılar yalnızca kimlik, önem derecesi, kategori ve sayı içerir; asla mesaj, komut ya da dosya içeriği içermez.",
	],

	"notify.channel.last": ["Last: {status}", "Son durum: {status}"],
	"notify.channel.attempts": ["{count} attempts", "{count} deneme"],
	"notify.deliveries.title": ["Recent deliveries", "Son gönderimler"],
	"notify.deliveries.queued": ["Queued", "Kuyruğa alınma"],
	"notify.deliveries.channel": ["Channel", "Kanal"],
	"notify.deliveries.event": ["Event", "Olay"],
	"notify.deliveries.deleted": ["(deleted)", "(silindi)"],

	"notify.row.updated": ["Events updated for {name}.", "{name} için olaylar güncellendi."],
	"notify.row.saveEvents": ["Save events", "Olayları kaydet"],
	"notify.row.testLabel": ["Send test to {name}", "{name} kanalına test gönder"],
	"notify.row.test": ["Send test", "Test gönder"],
	"notify.row.disableLabel": ["Disable {name}", "{name} kanalını kapat"],
	"notify.row.enableLabel": ["Enable {name}", "{name} kanalını aç"],
	"notify.row.disable": ["Disable", "Kapat"],
	"notify.row.enable": ["Enable", "Aç"],
	"notify.row.editLabel": ["Edit events for {name}", "{name} için olayları düzenle"],
	"notify.row.edit": ["Edit events", "Olayları düzenle"],
	"notify.row.confirmDeleteLabel": ["Confirm delete {name}", "{name} kanalını silmeyi onayla"],
	"notify.row.confirmDelete": ["Confirm delete", "Silmeyi onayla"],
	"notify.row.deleted": ["Deleted {name}.", "{name} silindi."],
	"notify.row.deleteLabel": ["Delete {name}", "{name} kanalını sil"],
	"notify.row.delete": ["Delete", "Sil"],

	"notify.title": ["Notifications", "Bildirimler"],
	"notify.loading": ["Loading alert channels…", "Uyarı kanalları yükleniyor…"],
	"notify.intro": [
		"Alerts to Slack, Microsoft Teams, signed webhooks or e-mail when incidents open, critical actions are blocked, approvals are requested or blocked AI prompts spike. Each alert is queued when the event is recorded and sent on the dispatcher's next run, which is scheduled once a minute; failed sends are retried.",
		"Vaka açıldığında, kritik işlemler engellendiğinde, onay istendiğinde ya da engellenen yapay zekâ mesajları arttığında Slack, Microsoft Teams, imzalı webhook ya da e-postayla uyarı gönderir. Her uyarı olay kaydedildiğinde kuyruğa alınır ve dakikada bir çalışan gönderim işinin bir sonraki çalışmasında gönderilir; başarısız gönderimler yeniden denenir.",
	],
	"notify.empty": ["No alert channels yet.", "Henüz uyarı kanalı yok."],
	"notify.table.type": ["Type", "Tür"],
	"notify.table.events": ["Events", "Olaylar"],
	"notify.table.actions": ["Actions", "İşlemler"],
	"notify.added": [
		"Added {name}. Send a test to confirm delivery.",
		"{name} eklendi. Gönderimi doğrulamak için bir test gönderin.",
	],
	"notify.limit": [
		"This workspace has reached the limit of {max} alert channels.",
		"Bu çalışma alanı {max} uyarı kanalı sınırına ulaştı.",
	],
	"notify.mfaNote": [
		"Changes and test sends require multi-factor verification (AAL2) and are recorded in the audit log.",
		"Değişiklikler ve test gönderimleri çok faktörlü doğrulama (AAL2) gerektirir ve denetim kaydına yazılır.",
	],
} as const satisfies MessagePairs<string>;

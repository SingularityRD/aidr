import type { MessagePairs } from "./define";

/** Executive reports page: executive summary, team rollup, printable report, scheduled delivery. */
export const reportsMessages = {
	"rpt.selectTeam": ["Select a team to see its reports.", "Raporları görmek için bir ekip seçin."],
	"rpt.ownersOnly": [
		"Only workspace owners and admins can see executive reports.",
		"Yönetici raporlarını yalnızca çalışma alanı sahipleri ve yöneticileri görebilir.",
	],
	"rpt.lead": [
		"A short summary for management, the same figures for every workspace you administer, a printable report and the scheduled e-mail. Counts only: no prompt text, matched values, page addresses or incident notes.",
		"Yönetim için kısa bir özet, yönettiğiniz her çalışma alanı için aynı göstergeler, yazdırılabilir bir rapor ve zamanlanmış e-posta. Yalnızca sayılar: istem metni, eşleşen değer, sayfa adresi ya da vaka notu içermez.",
	],
	"rpt.window": ["Period", "Dönem"],
	"rpt.lastDays": ["Last {count} days", "Son {count} gün"],
	"rpt.language": ["Report language", "Rapor dili"],
	"rpt.verifyNow": ["Verify now", "Şimdi doğrula"],
	"rpt.executive": ["Executive summary", "Yönetici özeti"],
	"rpt.loading": ["Loading…", "Yükleniyor…"],
	"rpt.attention": ["Needs attention", "İlgilenilmesi gerekiyor"],
	"rpt.ok": ["No action needed", "İşlem gerekmiyor"],
	"rpt.period": ["{from} – {to} (UTC)", "{from} – {to} (UTC)"],
	"rpt.details": ["All figures", "Tüm göstergeler"],
	"rpt.teams": ["Team rollup", "Ekip bazında özet"],
	"rpt.teamsLead": [
		"Every workspace where you are an owner or admin, same period. A workspace whose sign-in policy (MFA or SSO) this session does not meet is listed without figures.",
		"Sahibi ya da yöneticisi olduğunuz her çalışma alanı, aynı dönem. Bu oturumun oturum açma politikasını (MFA ya da SSO) karşılamadığı çalışma alanları göstergesiz listelenir.",
	],
	"rpt.col.team": ["Workspace", "Çalışma alanı"],
	"rpt.col.agents": ["Agents active", "Etkin ajan"],
	"rpt.col.allow": ["Allowed", "İzin verilen"],
	"rpt.col.ask": ["Held for approval", "Onaya bekletilen"],
	"rpt.col.deny": ["Denied", "Engellenen"],
	"rpt.col.masked": ["AI sends masked", "Maskelenen gönderim"],
	"rpt.col.incidents": ["Incidents to handle", "Ele alınacak vaka"],
	"rpt.col.critical": ["Critical", "Kritik"],
	"rpt.col.unassigned": ["Without owner", "Sorumlusuz"],
	"rpt.col.pending": ["Approvals pending", "Bekleyen onay"],
	"rpt.restricted": [
		"Not shown: this session does not meet the workspace's sign-in policy.",
		"Gösterilmiyor: bu oturum çalışma alanının oturum açma politikasını karşılamıyor.",
	],
	"rpt.download": ["Printable report", "Yazdırılabilir rapor"],
	"rpt.downloadLead": [
		"A self-contained HTML file in the report language. Open it in a browser and print it to PDF to keep or share a copy.",
		"Rapor dilinde, tek başına açılan bir HTML dosyası. Bir kopyasını saklamak ya da paylaşmak için tarayıcıda açıp PDF olarak yazdırın.",
	],
	"rpt.includeTeams": ["Include the team rollup", "Ekip bazında özeti ekle"],
	"rpt.downloadButton": ["Download report", "Raporu indir"],
	"rpt.downloaded": ["Downloaded {file}.", "{file} indirildi."],
	"rpt.schedule": ["Scheduled e-mail", "Zamanlanmış e-posta"],
	"rpt.scheduleLead": [
		"The weekly or monthly governance summary goes to the workspace owners (and admins) with this executive summary. Choose its language and whether the printable report is attached.",
		"Haftalık ya da aylık yönetişim özeti bu yönetici özetiyle birlikte çalışma alanı sahiplerine (ve yöneticilerine) gönderilir. Dilini ve yazdırılabilir raporun eklenip eklenmeyeceğini seçin.",
	],
	"rpt.scheduleWeekly": ["Sent every week.", "Her hafta gönderilir."],
	"rpt.scheduleMonthly": ["Sent every month.", "Her ay gönderilir."],
	"rpt.scheduleOff": ["The scheduled e-mail is off.", "Zamanlanmış e-posta kapalı."],
	"rpt.scheduleLink": [
		"Turn it on or change the schedule on the AI governance page.",
		"Açmak ya da zamanlamayı değiştirmek için yapay zekâ yönetişimi sayfasına gidin.",
	],
	"rpt.mailLanguage": ["E-mail language", "E-posta dili"],
	"rpt.attach": ["Attach the printable report", "Yazdırılabilir raporu ekle"],
	"rpt.saveOptions": ["Save e-mail settings", "E-posta ayarlarını kaydet"],
	"rpt.sendTest": ["Send a test now", "Şimdi deneme gönder"],
	"rpt.optionsSaved": ["E-mail settings saved.", "E-posta ayarları kaydedildi."],
	"rpt.testSent": [
		"Test sent to {delivered} of {recipients} recipient(s).",
		"Deneme {recipients} alıcıdan {delivered} tanesine gönderildi.",
	],
	"rpt.err.mfa": [
		"Changing e-mail settings needs multi-factor verification in this session.",
		"E-posta ayarlarını değiştirmek için bu oturumda çok adımlı doğrulama gerekir.",
	],
	"rpt.err.role": [
		"Only workspace owners and admins can do this.",
		"Bunu yalnızca çalışma alanı sahipleri ve yöneticileri yapabilir.",
	],
	"rpt.err.rateLimited": [
		"Too many requests in a short time. Wait a minute and try again.",
		"Kısa sürede çok fazla istek yapıldı. Bir dakika bekleyip yeniden deneyin.",
	],
	"rpt.err.invalid": [
		"The report data could not be checked, so nothing is shown rather than wrong figures.",
		"Rapor verisi doğrulanamadı; yanlış göstergeler yerine hiçbir şey gösterilmiyor.",
	],
	"rpt.err.unavailable": [
		"The report service is not available right now.",
		"Rapor hizmetine şu anda ulaşılamıyor.",
	],
	"rpt.err.noMail": [
		"This deployment has no e-mail transport configured, so nothing was sent.",
		"Bu kurulumda e-posta gönderimi yapılandırılmamış, bu yüzden hiçbir şey gönderilmedi.",
	],
} as const satisfies MessagePairs<string>;

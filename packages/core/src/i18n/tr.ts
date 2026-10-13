import type { MessageKey } from "./en.js";

/**
 * Turkish message catalog. The `Record<MessageKey, string>` type makes a
 * missing or extra key a compile error; the key-parity test checks the same
 * thing at runtime together with the parameter names.
 *
 * Product, rule, command and configuration names (Singularity AIDR, AIDR,
 * `aidr approve`, actionId, MCP, rule ids) are not translated.
 */
export const tr: Record<MessageKey, string> = {
	"severity.critical": "kritik",
	"severity.high": "yüksek",
	"severity.medium": "orta",
	"severity.low": "düşük",
	"severity.info": "bilgi",
	"severity.warning": "uyarı",
	"common.unknown": "bilinmiyor",
	"common.none": "yok",

	"block.deny.headline": "Singularity AIDR bu eylemi engelledi.",
	"block.line.severity": "Önem: {severity}",
	"block.line.rule": "Kural: {rule}",
	"block.line.category": "Kategori: {category}",
	"block.line.reason": "Neden: {reason}",
	"block.line.artifacts": "Öğeler: {artifacts}",
	"block.line.response": "Müdahale: {response}",
	"block.response.failed": "müdahale eylemleri başarısız oldu: {failures} - hiçbir şey korunmadı",
	"block.response.rollback": "geri alma: {target}, {snapshot} anlık görüntüsünden geri yüklendi",
	"block.response.preserved":
		"{action}: {target} dosyasının bir kopyası {where} konumunda saklandı",
	"block.response.snapshot": "{snapshot} anlık görüntüsü",
	"block.response.vault": "(kasa)",
	"block.response.unknownSnapshot": "(bilinmiyor)",
	"block.configUnreadable":
		"Singularity AIDR yapılandırmasını okuyamadığı için bu eylem onaya sunulmak yerine engellendi.",
	"ask.headline":
		"Singularity AIDR bu eylemi şüpheli buldu ve kullanıcı açıkça onaylayana kadar engelledi.",
	"ask.reference": 'Onay referansı: actionId: "{actionId}"',
	"ask.agentInstructions":
		"Bu eylemi kendin onaylayamazsın ve erişebildiğin hiçbir araç da onaylayamaz.\nOnay, bant dışı ve yalnızca bir insanın verebileceği bir işlemdir. Yukarıdaki referansı kullanıcıya bildir ve\nburada dur: bu araç çağrısını yeniden DENEME ve engeli aşmaya ÇALIŞMA. Eylem, kullanıcı\nbant dışında onaylayana ya da öğeyi kalıcı olarak izin listesine ekleyene kadar engelli kalır.",
	"ask.user.dashboardOnly":
		"(Kullanıcı için: bu eylemi yalnızca AIDR panelinden verilen bir onay serbest bırakabilir.)",
	"ask.user.notRecorded":
		"(Kullanıcı için: bu onay isteği operatör onayı için KAYDEDİLEMEDİ — operatör onayları\nkapalı ya da onay deposu kullanılamıyor, bu yüzden `aidr approve` bu eylemi serbest bırakamaz.\nNedenini görmek için kendi terminalinizde `aidr doctor` komutunu çalıştırın.)",
	"ask.user.cli":
		"(Kullanıcı için: kendi terminalinizde `aidr pending` ile inceleyip `aidr approve <actionId>` ile\nonaylayın; onay, bu çağrının birebir aynısının 15 dakika içinde bir kez yeniden denenmesini kapsar.)",
	"dashboard.requested":
		"AIDR panelinde onay istendi: {requestId}\n(Kullanıcı için: bu isteği bir AIDR yöneticisinin panelden onaylaması gerekir; onay\nbu çağrının birebir aynısının bir kez yeniden denenmesini kapsar.)",
	"dashboard.denied":
		"{requestId} numaralı AIDR paneli onay isteği reddedildi; eylem engelli kalıyor.",
	"dashboard.expired":
		"{requestId} numaralı AIDR paneli onay isteğinin süresi doldu; eylem engelli kalıyor.",
	"dashboard.rejected":
		"{requestId} numaralı istek için AIDR paneli onayı doğrulanamadı ({reason}); eylem engelli kalıyor.",
	"dashboard.requestFailed":
		"Onay isteği AIDR paneline gönderilemedi ({reason}); eylem engelli kalıyor.",
	"dashboard.unavailable": "AIDR paneli onayları kullanılamıyor ({reason}); eylem engelli kalıyor.",

	"hook.label.threat": "Tehdit",
	"hook.label.severity": "Önem",
	"hook.label.rule": "Kural",
	"hook.label.artifact": "Öğe",
	"hook.label.source": "Kaynak",
	"hook.label.action": "Eylem",
	"hook.action.blocked": "Engellendi",
	"hook.action.requiresConfirmation": "Onay gerekiyor",
	"hook.ask.header": "🛡️ Singularity AIDR: Şüpheli Etkinlik Algılandı",
	"hook.reason.threatBlocked": "🛡️ Singularity AIDR: Tehdit Engellendi",
	"hook.reason.profileBlocked": "🛡️ Singularity AIDR: Ajan izin profili tarafından engellendi",
	"hook.reason.operatorHold": "🛡️ Singularity AIDR: operatör onayı bekleniyor, eylem engellendi",
	"hook.reason.dashboardRequired": "🛡️ Singularity AIDR: AIDR panelinden onay gerekiyor",
	"hook.dashboardOnlyNotice":
		"Bu eylemi yalnızca AIDR panelinden verilen bir onay serbest bırakabilir.",
	"hook.timeout.message":
		"Singularity AIDR bu araç çağrısının incelemesini zamanında bitiremedi. Eylem engellendi.",
	"hook.timeout.reason": "Singularity AIDR incelemesi zaman aşımına uğradı",
	"hook.inspectionFailed.message":
		"Singularity AIDR bu araç çağrısını inceleyemedi. Eylem engellendi.",
	"hook.inspectionFailed.reason": "Singularity AIDR incelemesi kullanılamıyor",
	"hook.tooLarge.message":
		"Singularity AIDR bu araç çağrısını inceleyemedi: girdisi {bytes} baytlık inceleme sınırını aştı. Eylem engellendi.",
	"hook.tooLarge.reason": "Singularity AIDR: girdi incelenemeyecek kadar büyük",
	"hook.malformed.message":
		"Singularity AIDR bu komutu engelledi: komut bozuk (metin ya da argv değil veya NUL ya da geçersiz UTF-8 metin içeriyor) ve güvenilir biçimde incelenemez.",
	"hook.malformed.reason": "Singularity AIDR: bozuk komut",
	"hook.redacted":
		"🛡️ Singularity AIDR bu araç çağrısı çalışmadan önce içindeki hassas verileri maskeledi. {reason}",
	"hook.sessionScanTimeout":
		"Singularity AIDR kurulu eklentileri taramayı zamanında bitiremedi; eklenti tarama sonucu yok. Araç çağrıları incelenmeye devam ediyor.",
	"hook.sessionStartFailed": "Singularity AIDR koruması başlatılamadı; oturum korunmuyor.",
	"prompt.notSent.uninspected":
		"🛡️ Singularity AIDR bu istemi gizli bilgiler açısından inceleyemediği için istem gönderilmedi. Yeniden deneyin; sorun sürerse `aidr status` komutunu çalıştırın.",
	"prompt.sent.uninspected":
		"Singularity AIDR bu istemi gizli bilgiler açısından inceleyemedi; istem, istem koruması olmadan gönderildi.",
	"prompt.notSent.timeout":
		"🛡️ Singularity AIDR bu istemin incelemesini zamanında bitiremediği için istem gönderilmedi. İstemi kısaltın ya da bölerek yeniden deneyin.",
	"prompt.sent.timeout":
		"Singularity AIDR bu istemin incelemesini zamanında bitiremedi; istem, gizli bilgiler ve kişisel veriler açısından tam incelenmeden gönderildi.",
	"prompt.notSent.policy":
		"🛡️ Singularity AIDR kuruluşunuzun veri sızıntısı önleme (DLP) politikasını doğrulayamadığı için bu istem gönderilmedi.",

	"session.updateAvailable":
		"⬆️  Güncelleme mevcut: v{current} → v{latest} (https://github.com/singularityrd/aidr)",
	"session.updateAvailableInstaller":
		"⬆️  Singularity AIDR v{latest} sürümü yayımlandı (sizdeki sürüm v{current}). Kurmak için şunu çalıştırın: aidr update",
	"session.updateInstalling":
		"⬆️  Singularity AIDR v{latest} sürümü yayımlandı (sizdeki sürüm v{current}) ve arka planda kuruluyor. Durumu görmek için: aidr update --check",
	"session.policy.cached": "{policy} önbellekte, {seconds} sn kaldı",
	"session.policy.expired": "{policy} önbelleğinin süresi doldu",
	"session.policy.expiredAge": "{policy} önbelleğinin süresi doldu, {seconds} sn önce alındı",
	"session.policy.invalid": "önbellek geçersiz",
	"session.policy.defaultName": "politika",
	"session.clean": "🛡️ Singularity AIDR v{version} ✅ Tehdit bulunamadı",
	"session.disabled": "Singularity AIDR v{version} - Devre dışı ({reason})",
	"session.localOnly":
		"Singularity AIDR v{version} - Yerel koruma ETKİN (yönetilen özellikler kullanılamıyor: {reason})",
	"session.label.policy": "Politika",
	"session.label.plugin": "Eklenti",
	"session.label.threat": "Tehdit",
	"session.label.severity": "Önem",
	"session.label.artifact": "Öğe",
	"session.label.source": "Kaynak",
	"session.label.finding": "Bulgu",
	"session.label.reason": "Neden",
	"session.label.open": "Açın",
	"session.label.code": "Kod",
	"session.label.expires": "Bitiş",
	"session.header.threatDetected": "Tehdit Algılandı",
	"session.header.reviewRequired": "İnceleme Gerekiyor",
	"session.header": "🛡️ Singularity AIDR v{version} — {label}",
	"session.finding.block": "Engelleme önerilir; bu eklentiyi inceleyin ya da devre dışı bırakın",
	"session.finding.review": "İnceleme önerilir",
	"session.moreFindings": "   ... ve {count} bulgu daha",
	"session.rulesIncompleteBanner":
		"⚠️ Tehdit kuralları eksik — koruma zayıfladı ({count} kural dosyası eksik ya da doğrulanamadı).",
	"session.check.urlReputation": "URL itibar denetimi",
	"session.check.fileReputation": "Dosya itibar denetimi",
	"session.check.pluginFiles": "Eklenti dosyası incelemesi",
	"session.check.incompletePaths": "⚠️ {label} {count} yol için tamamlanamadı.",
	"session.check.unverifiedItems": "⚠️ {label} {count} öğe için doğrulanamadı.",
	"session.mcp.unusableServers": "{count} sunucu kaydı kullanılamadı",
	"session.mcp.unreadableSources": "{count} kaynak hiç okunamadı",
	"session.mcp.coverageWarning": " Envanter kapsamı tam değil: {coverage}.",
	"session.mcp.inventory":
		"MCP envanteri: {servers} yapılandırılmış, {risky} risk göstergeli, {invalid} okunamayan kaynak, {unverified} doğrulanmamış araç bildirimli sunucu.{coverageWarning}{gapNote} Yapılandırma keşfi sunucuların güvenilirliğini doğrulamaz.",
	"session.mcp.coverageGaps": "MCP araç bildirimi kapsam boşlukları:",
	"session.mcp.moreGaps": "  ... ve {count} kapsam boşluğu daha",
	"session.rulesIncomplete": "⚠️ Tehdit kuralları eksik — koruma zayıfladı. {reason}",
	"session.infrastructure": "Yapay zekâ altyapısı politika değerlendirmesi: {assessment}.",
	"session.enrollmentRepair":
		"Kayıt yerel olarak doğrulanamadı. Bir operatörün kayıt sonucunu netleştirmesi ve etkilenen anahtarları kontrol düzleminde iptal etmesi, ardından yeni bir eşleştirme başlatıp tarayıcıda onaylaması gerekir. Kurulum kimliğini ve kiracıyı koruyun; önceki yetkilendirme kodunu yeniden kullanmayın.",
	"session.activate": "Singularity AIDR'yi etkinleştirmek için:",
};

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

	"block.deny.headline": "🛡️ Singularity AIDR bu işlemi engelledi.",
	"block.ask.headline": "🛡️ Singularity AIDR bu işlemi siz onaylayana kadar durdurdu.",
	"block.line.stopped": "Durdurulan: {what}",
	"block.line.why": "Neden: {reason} ({details}).",
	"block.line.also": "Ayrıca bulunan: {reasons}.",
	"block.detail.rule": "kural {rule}",
	"block.more": "{what} (+{count} öğe daha)",
	"block.artifact.command": "komut",
	"block.artifact.url": "URL",
	"block.artifact.file_path": "dosya",
	"block.artifact.content": "içerik",
	"block.line.response": "Singularity AIDR'nin yaptığı: {response}",
	"block.response.failed": "müdahale eylemleri başarısız oldu: {failures} - hiçbir şey korunmadı",
	"block.response.rollback": "geri alma: {target}, {snapshot} anlık görüntüsünden geri yüklendi",
	"block.response.preserved":
		"{action}: {target} dosyasının bir kopyası {where} konumunda saklandı",
	"block.response.snapshot": "{snapshot} anlık görüntüsü",
	"block.response.vault": "(kasa)",
	"block.response.unknownSnapshot": "(bilinmiyor)",
	"block.deny.next":
		"Ne yapabilirsiniz: Bunun yanlış alarm olduğunu düşünüyorsanız {rule} kuralını BT veya güvenlik ekibinize bildirin; ekip süreli bir istisna tanımlayarak izin verebilir. Ayrıntılar: `aidr audit tail`.",
	"block.deny.nextNoRule":
		"Ne yapabilirsiniz: Bunun yanlış alarm olduğunu düşünüyorsanız BT veya güvenlik ekibinize bildirin. Ayrıntılar: `aidr audit tail`.",
	"block.ask.cli":
		"Bir kez izin vermek için kendi terminalinizde şunu çalıştırın (15 dakika geçerli), sonra yapay zekâ aracından yeniden denemesini isteyin:\n  {command}",
	"block.ask.notRecorded":
		"Bu istek onay için kaydedilemedi, bu yüzden terminalden izin verilemez. Nedenini görmek için kendi terminalinizde `aidr doctor` komutunu çalıştırın.",
	"block.ask.dashboardOnly":
		"Buna yalnızca bir yönetici, Singularity AIDR panelinden izin verebilir.",
	"block.ask.hostDialog": "Bir kez izin vermek için Evet'i, engelli kalması için Hayır'ı seçin.",
	"block.ask.next":
		"Ayrıntılar: `aidr pending`. Bunun yanlış alarm olduğunu düşünüyorsanız {rule} kuralını BT veya güvenlik ekibinize bildirin.",
	"block.ask.nextNoRule":
		"Ayrıntılar: `aidr pending`. Bunun yanlış alarm olduğunu düşünüyorsanız BT veya güvenlik ekibinize bildirin.",
	"block.ask.reference": "Onay referansı: {actionId}",
	"block.agent.deny": "Yapay zekâ aracı için: Bu çağrıyı yeniden deneme ve engeli aşmaya çalışma.",
	"block.agent.ask":
		"Yapay zekâ aracı için: Bu işlemi kendin onaylayamazsın ve erişebildiğin hiçbir araç onaylayamaz. Kullanıcıya neyin durdurulduğunu ve nasıl izin verebileceğini söyle, sonra dur: bu çağrıyı yeniden deneme ve engeli aşmaya çalışma.",
	"block.agent.short":
		"🛡️ Singularity AIDR bu işlemi engelledi: {reason}. Yeniden deneme ve engeli aşmaya çalışma; ayrıntılar kullanıcıya gösterildi.",
	"block.agent.askShort":
		"🛡️ Singularity AIDR bu işlemi kullanıcı onaylayana kadar durdurdu: {reason}. Bunu kendin onaylayamazsın ve erişebildiğin hiçbir araç onaylayamaz; yeniden deneme ve engeli aşmaya çalışma. Kullanıcıya nasıl izin verebileceği gösterildi.",
	"codex.dlpRewrite":
		"Bu araç çağrısı önce maskelenmesi gereken hassas veriler içeriyor ve Codex bir araç çağrısının girdisini güvenle değiştiremediği için çağrı engellendi. Hassas değerleri çıkarıp yeniden deneyin.",
	"block.configUnreadable":
		"Singularity AIDR yapılandırmasını okuyamadığı için bu işlem onaya sunulmak yerine engellendi.",
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

	"hook.timeout.message":
		"Singularity AIDR bu araç çağrısının incelemesini zamanında bitiremediği için çağrı engellendi. Yeniden deneyin; sorun sürerse kendi terminalinizde `aidr doctor` komutunu çalıştırın.",
	"hook.timeout.reason": "Singularity AIDR incelemesi zaman aşımına uğradı",
	"hook.inspectionFailed.message":
		"Singularity AIDR bu araç çağrısını inceleyemediği için çağrı engellendi. Yeniden deneyin; sorun sürerse kendi terminalinizde `aidr doctor` komutunu çalıştırın.",
	"hook.inspectionFailed.reason": "Singularity AIDR incelemesi kullanılamıyor",
	"hook.tooLarge.message":
		"Singularity AIDR bu araç çağrısını inceleyemedi çünkü girdisi {bytes} baytlık inceleme sınırından büyük; çağrı engellendi. İşi daha küçük adımlara bölün.",
	"hook.tooLarge.reason": "Singularity AIDR: girdi incelenemeyecek kadar büyük",
	"hook.malformed.message":
		"Singularity AIDR bu komutu engelledi: komut bozuk (metin ya da argv değil veya NUL ya da geçersiz UTF-8 metin içeriyor) ve güvenilir biçimde incelenemez.",
	"hook.malformed.reason": "Singularity AIDR: bozuk komut",
	"hook.releaseKeyMissing.message":
		"Singularity AIDR bu araç çağrısını engelledi: kurulu dosyalarının orijinal olduğunu kanıtlayan sürüm anahtarı ayarlanmamış, bu yüzden kendi kurallarına güvenemiyor. Anahtar ayarlanana kadar her araç çağrısı engellenir. Bir kez 'aidr setup' çalıştırın (elle kurulumda 'aidr setup --release-key <dosya.pem>').",
	"hook.redacted":
		"🛡️ Singularity AIDR bu araç çağrısı çalışmadan önce içindeki hassas verileri maskeledi. {reason}",
	"hook.sessionScanTimeout":
		"Singularity AIDR kurulu eklentileri taramayı zamanında bitiremedi; eklenti tarama sonucu yok. Araç çağrıları incelenmeye devam ediyor.",
	"hook.sessionStartFailed": "Singularity AIDR koruması başlatılamadı; oturum korunmuyor.",
	"hook.sessionStartIntegrity":
		"Singularity AIDR kendi kurulumunu doğrulayamıyor ({cause}); bu yüzden sorun giderilene kadar bu oturumdaki tüm araç çağrıları engelleniyor. BT yöneticinizden `aidr doctor` komutunu çalıştırmasını isteyin.",
	"hook.sessionStartNoKey":
		"Singularity AIDR kendi kurulumunu doğrulayamıyor (sürüm doğrulama anahtarı eksik); bu yüzden sorun giderilene kadar bu oturumdaki tüm araç çağrıları engelleniyor. BT yöneticinizden şunu çalıştırmasını isteyin: aidr setup --release-key <anahtar.pem> (ayrıntı: aidr doctor)",

	"integrity.noKey.message":
		"Singularity AIDR kendi kurulumunu doğrulayamadığı için bu işlemi engelledi (sürüm doğrulama anahtarı eksik). Bu sorun giderilene kadar hiçbir komut çalışmaz. BT yöneticinizden şunu çalıştırmasını isteyin: aidr setup --release-key <anahtar.pem> (ayrıntı: aidr doctor)",
	"integrity.failed.message":
		"Singularity AIDR kendi kurulumunu doğrulayamadığı için bu işlemi engelledi ({cause}). Bu sorun giderilene kadar hiçbir komut çalışmaz. BT yöneticinizden Singularity AIDR'yi imzalı bir sürümden yeniden kurmasını isteyin (ayrıntı: aidr doctor)",
	"integrity.reason": "Singularity AIDR kendi kurulumunu doğrulayamıyor; tüm işlemler engelleniyor",
	"integrity.agent": "Yapay zekâ aracı için: Bunu kendin düzeltmeye çalışma; kullanıcıya bildir.",
	"integrity.cause.revoked": "bu sürüm kuruluşunuz tarafından geri çekildi",
	"integrity.cause.signature": "sürüm imzası eksik ya da geçersiz",
	"integrity.cause.files": "dosyaları değiştirilmiş ya da eksik",
	"integrity.cause.io": "dosyaları okunamadı",
	"init.failed.message":
		"Singularity AIDR başlatılamadı ({code}); bu yüzden sorun giderilene kadar tüm araç çağrıları engelleniyor. BT yöneticinizden `aidr doctor` komutunu çalıştırmasını isteyin.",
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
	"session.offline.keepLocal":
		"⚠️ Şirketin AIDR sunucusu yanıt vermedi. Bu bilgisayarda yerel koruma sürüyor; merkezden gelen politika değişiklikleri sunucuya yeniden ulaşılınca gelecek.",
	"session.offline.blockAt":
		"⚠️ Şirketin AIDR sunucusu yanıt vermedi. Sunucuya yeniden ulaşılamazsa bu bilgisayarda yapay zekâ araçlarının işlemleri {time} itibarıyla (yaklaşık {minutes} dk sonra) ENGELLENECEK: şirketiniz çevrimdışı süre dolunca engellemeyi seçti. BT ekibinize hemen haber verin.",
	"session.offline.blocked":
		"⛔ Şirketin AIDR sunucusu yanıt vermedi ve çevrimdışı süre doldu: sunucuya yeniden ulaşılana kadar bu bilgisayarda yapay zekâ araçlarının işlemleri ENGELLENİYOR (şirketinizin seçimi). BT ekibinize haber verin.",
	"session.offline.support": "Destek: {contact}",
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

	// Block-message additions, decision notices, unprotected tools, first-run privacy notice.
	"block.reportFp":
		"Yanlış alarmı bildirmek için kendi terminalinizde şunu çalıştırın: aidr report-fp {shortId}",
	"block.support": "BT veya güvenlik ekibinizden yardım: {url}",
	"dashboard.link": "Paneldeki onay sayfası: {url}",
	"dashboard.decided.approved":
		"✅ Singularity AIDR: {requestId} numaralı onay isteği panelde onaylandı. Yapay zekâ aracından aynı işlemi yeniden yapmasını isteyin; onay, sınırlı bir süre için tek bir yeniden denemeyi kapsar.",
	"dashboard.decided.denied":
		"⛔ Singularity AIDR: {requestId} numaralı onay isteği panelde reddedildi; işlem engelli kalıyor.",
	"dashboard.decided.expired":
		"Singularity AIDR: {requestId} numaralı onay isteğinin süresi karar verilmeden doldu; işlem engelli kalıyor.",
	"session.unprotectedTools":
		"⚠️ Bu bilgisayarda Singularity AIDR korumasıyla çalışmayan yapay zekâ araçları bulundu: {tools}. Bu araçların komutları, dosya değişiklikleri ve web istekleri İNCELENMİYOR. Ayrıntılar: `aidr status`.",
	"notice.title": "🛡️ Singularity AIDR bu bilgisayarda etkin. Ne yaptığı ve neyi kaydettiği:",
	"notice.guards":
		"• Neyi korur: Yapay zekâ kodlama aracınız (Claude Code, Cursor, VS Code, Codex, OpenCode veya OpenClaw) bir komut çalıştırmadan, bir dosyayı okumadan ya da değiştirmeden, bir web sayfasını açmadan veya bir MCP aracını çağırmadan önce Singularity AIDR bunu güvenlik kurallarıyla karşılaştırır ve riskli olanları engeller ya da onaya bekletir. Aracın izin verdiği yerlerde istemleriniz gizli anahtar ve kişisel veri için de denetlenir.",
	"notice.notGuarded":
		"• Neyi korumaz: Sıradan bir komutun doğru olup olmadığına karar vermez. Örneğin `kubectl delete`, `git push --force` veya `docker system prune`, kurumunuz bunlar için bir kural eklemedikçe uyarısız çalışır. Yapay zekâ aracı dışında kendi yazdığınız komutlar incelenmez; Singularity AIDR bağlayıcısı olmayan yapay zekâ araçları korunmaz.",
	"notice.unprotected": "• Bu bilgisayarda korumasız bulunan araçlar: {tools}.",
	"notice.localLog":
		"• Bu bilgisayarda kaydedilenler: engellenen ve onaya bekletilen işlemler; komutun, dosyanın veya adresin gizli bilgileri maskelenmiş kısa bir özetiyle birlikte {path} dosyasına yazılır.",
	"notice.localLogClean":
		"• Bu bilgisayarda kaydedilenler: incelenen her işlem (izin verilenler de); komutun, dosyanın veya adresin gizli bilgileri maskelenmiş kısa bir özetiyle birlikte {path} dosyasına yazılır.",
	"notice.localLogOff": "• Bu bilgisayarda kaydedilenler: hiçbir şey; karar kaydı kapalı.",
	"notice.sent.local":
		"• Bu bilgisayardan dışarı gidenler: çalışmanızla ilgili hiçbir şey. {versionCheck}",
	"notice.sent.versionCheck":
		"Yalnızca güncelleme denetimi ürün sürümünü, bir kurulum kimliğini ve temel sistem bilgilerini (işletim sistemi, yapay zekâ aracı) gönderir.",
	"notice.sent.noVersionCheck": "Güncelleme denetimi kapalı.",
	"notice.sent.managed":
		"• Bu bilgisayardan dışarı gidenler: Bu bilgisayar kurumunuz tarafından yönetiliyor. Engellenen ve onaya bekletilen kararlar{clean} kurumunuzun Singularity AIDR konsoluna ({host}) gönderilir; {redaction} Konsol ayrıca bu cihazın koruma durumunu, yapay zekâ aracı ve MCP sunucusu envanterini ve başlattığınız onay isteklerini alır.",
	"notice.sent.managedClean": " (ve izin verilen işlemler)",
	"notice.sent.managedNoAudit":
		"• Bu bilgisayardan dışarı gidenler: Bu bilgisayar kurumunuz tarafından yönetiliyor. Kararlar gönderilmez; kurumunuzun Singularity AIDR konsolu ({host}) bu cihazın koruma durumunu, yapay zekâ aracı ve MCP sunucusu envanterini ve başlattığınız onay isteklerini alır.",
	"notice.redaction.hash": "içlerindeki hassas değerler tek yönlü parmak izleriyle değiştirilir.",
	"notice.redaction.full": "komut, dosya ve adres özetleri gönderilmez.",
	"notice.redaction.none": "komut, dosya ve adres özetleri kaydedildiği gibi gönderilir.",
	"notice.privacyUrl": "• Kurumunuzun aydınlatma metni: {url}",
	"notice.privacyAsk": "• Kurumunuzun aydınlatma metni için BT veya güvenlik ekibinize başvurun.",
	"notice.support": "• Sorularınız veya hatalı olduğunu düşündüğünüz bir engel için: {url}",
	"notice.again": "Bu bilgiyi istediğiniz zaman yeniden görmek için: aidr privacy notice",
};

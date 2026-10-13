import type { MessagePairs } from "./define";

/** Runtime policy (compiled JSON controls) and four-eyes notices. */
export const policyRuntimeMessages = {
	"runtime.loadFailedPublishing": [
		"Published policy could not be loaded. Publishing is disabled until it can be read.",
		"Yayımlanmış politika yüklenemedi. Okunabilene kadar yayımlama kapalıdır.",
	],
	"runtime.loadFailed": [
		"Published policy could not be loaded.",
		"Yayımlanmış politika yüklenemedi.",
	],
	"runtime.publishFailedReload": [
		"Publication failed. Reload the page if another administrator changed the policy.",
		"Yayımlama başarısız oldu. Politikayı başka bir yönetici değiştirdiyse sayfayı yenileyin.",
	],
	"runtime.published": [
		"Version {version} published. Agents fetch it on their next policy refresh. Required-policy endpoints retain cached controls within their offline grace, then block until policy is available. Check loading receipts below.",
		"{version}. sürüm yayımlandı. Yapay zekâ araçları bunu bir sonraki politika yenilemesinde alır. Politika zorunlu uç noktalar, çevrim dışı tolerans süresi boyunca önbellekteki denetimleri korur; sonra politika alınana kadar engeller. Aşağıdaki yükleme bildirimlerini kontrol edin.",
	],
	"runtime.publishFailed": ["Publication failed.", "Yayımlama başarısız oldu."],
	"runtime.saveDraftFirst": [
		"Save a YAML draft in the Security Policy Editor first, then run the dry run.",
		"Önce güvenlik politikası düzenleyicisinde bir YAML taslağı kaydedin, sonra denemeyi çalıştırın.",
	],
	"runtime.compileFailedReview": [
		"Saved YAML could not be compiled. Review unsupported fields in the policy editor.",
		"Kaydedilen YAML derlenemedi. Politika düzenleyicisindeki desteklenmeyen alanları inceleyin.",
	],
	"runtime.revisionUnknown": [
		"The dry run did not identify the exact saved YAML revision. Try again before publishing.",
		"Deneme, kaydedilen YAML sürümünü kesin olarak belirleyemedi. Yayımlamadan önce yeniden deneyin.",
	],
	"runtime.unknownSimulation": [
		" Unknown MCP simulation: {action} ({source}).",
		" Bilinmeyen MCP benzetimi: {action} ({source}).",
	],
	"runtime.shadowed": [" {count} shadowed rule warning(s).", " {count} gölgelenmiş kural uyarısı."],
	"runtime.dryCompiled": [
		"Dry run compiled. Conflict precedence: {precedence}.",
		"Deneme derlendi. Çakışma önceliği: {precedence}.",
	],
	"runtime.compileFailed": ["Saved YAML could not be compiled.", "Kaydedilen YAML derlenemedi."],
	"runtime.publishDocFailed": [
		"Saved YAML could not be compiled and published. Run a new dry run before retrying.",
		"Kaydedilen YAML derlenip yayımlanamadı. Yeniden denemeden önce yeni bir deneme çalıştırın.",
	],
	"runtime.changedAfterReview": [
		"The saved YAML changed after review. Run a new dry run before publishing.",
		"Kaydedilen YAML incelemeden sonra değişti. Yayımlamadan önce yeni bir deneme çalıştırın.",
	],
	"runtime.notPublished": [
		"The compiled policy was not published.",
		"Derlenen politika yayımlanmadı.",
	],
	"runtime.docPublished": [
		"Saved YAML compiled and published as version {version}. Check agent loading receipts below.",
		"Kaydedilen YAML derlendi ve {version}. sürüm olarak yayımlandı. Aşağıdaki yapay zekâ aracı yükleme bildirimlerini kontrol edin.",
	],
	"runtime.docPublishFailed": [
		"Saved YAML could not be published.",
		"Kaydedilen YAML yayımlanamadı.",
	],
	"runtime.title": ["Runtime policy", "Çalışma zamanı politikası"],
	"runtime.intro": [
		"Publish controls for agents enrolled in this team. Detection rules still apply when an action defaults to allow. Use ask to require a person's approval, or deny to block.",
		"Bu ekibe kayıtlı yapay zekâ araçları için denetimleri yayımlayın. Bir işlemin varsayılanı allow olsa bile tespit kuralları uygulanmaya devam eder. Bir kişinin onayını istemek için ask, engellemek için deny kullanın.",
	],
	"runtime.versionUnavailable": ["Published version unavailable", "Yayımlanmış sürüm alınamadı"],
	"runtime.noneYet": ["No policy published", "Yayımlanmış politika yok"],
	"runtime.version": ["Published version: {version}", "Yayımlanmış sürüm: {version}"],
	"runtime.json": ["Runtime controls (JSON)", "Çalışma zamanı denetimleri (JSON)"],
	"runtime.fields": [
		"Actions: {actions}. MCP lists: {lists} and the corresponding *_tools lists. Unsupported fields are rejected.",
		"İşlemler: {actions}. MCP listeleri: {lists} ve bunlara karşılık gelen *_tools listeleri. Desteklenmeyen alanlar reddedilir.",
	],
	"runtime.compile": ["Compile saved YAML (dry run)", "Kaydedilen YAML'ı derle (deneme)"],
	"runtime.compilePublish": [
		"Compile and publish saved YAML",
		"Kaydedilen YAML'ı derle ve yayımla",
	],
	"runtime.working": ["Working…", "İşleniyor…"],
	"runtime.publishJson": [
		"Publish runtime policy JSON",
		"Çalışma zamanı politika JSON'ını yayımla",
	],
	"governance.pendingChange": [
		"Four-eyes change control is on: nothing was published. The change is waiting for a second owner or administrator under AI governance → Change control.",
		"Dört göz değişiklik denetimi açık: hiçbir şey yayımlanmadı. Değişiklik, Yapay zekâ yönetişimi → Değişiklik denetimi altında ikinci bir sahip ya da yöneticinin onayını bekliyor.",
	],
} as const satisfies MessagePairs<string>;

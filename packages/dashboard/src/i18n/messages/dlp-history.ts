import type { MessagePairs } from "./define";

/** Policy-management service errors and the DLP revision history. */
export const dlpHistoryMessages = {
	"pm.err.mfa": [
		"Multi-factor verification (AAL2) is required. Verify with your authenticator, then try again.",
		"Çok adımlı doğrulama (AAL2) gerekiyor. Doğrulama uygulamanızla doğrulayıp yeniden deneyin.",
	],
	"pm.err.forbidden": [
		"Only workspace owners and administrators can make this change.",
		"Bu değişikliği yalnızca çalışma alanı sahipleri ve yöneticileri yapabilir.",
	],
	"pm.err.conflict": [
		"Someone else changed this policy in the meantime. Reload and try again.",
		"Bu arada politikayı başka biri değiştirdi. Sayfayı yenileyip yeniden deneyin.",
	],
	"pm.err.fourEyes": [
		"Four-eyes change control is on: the change needs a second owner or administrator.",
		"Dört göz değişiklik denetimi açık: değişiklik ikinci bir sahip ya da yönetici gerektirir.",
	],
	"pm.err.quota": [
		"Too many change requests are pending. Resolve some under AI governance → Change control.",
		"Bekleyen çok fazla değişiklik talebi var. Bir kısmını Yapay zekâ yönetişimi → Değişiklik denetimi altında sonuçlandırın.",
	],
	"pm.err.revisionMissing": ["That revision no longer exists.", "Bu revizyon artık yok."],
	"pm.err.notOlder": [
		"Only an earlier revision can be restored.",
		"Yalnızca daha eski bir revizyon geri yüklenebilir.",
	],
	"pm.err.invalidDlp": [
		"That revision is no longer valid under today's rules (for example an exception has expired), so it cannot be restored as is.",
		"Bu revizyon bugünkü kurallara göre artık geçerli değil (örneğin bir istisnanın süresi dolmuş); bu yüzden olduğu gibi geri yüklenemez.",
	],
	"pm.err.invalidProfiles": ["The profile document is not valid.", "Profil belgesi geçerli değil."],
	"pm.err.noAccess": [
		"You no longer have access to this workspace.",
		"Artık bu çalışma alanına erişiminiz yok.",
	],
	"pm.err.generic": [
		"The policy service did not confirm the request.",
		"Politika hizmeti isteği onaylamadı.",
	],
	"dh.unverified": ["The revision could not be verified.", "Revizyon doğrulanamadı."],
	"dh.current": ["current", "geçerli"],
	"dh.compareLabel": [
		"Compare version {version} with current",
		"{version}. sürümü geçerli sürümle karşılaştır",
	],
	"dh.diffCurrent": ["Diff vs current", "Geçerli sürümle fark"],
	"dh.changesLabel": [
		"Show changes in version {version}",
		"{version}. sürümdeki değişiklikleri göster",
	],
	"dh.changes": ["Changes", "Değişiklikler"],
	"dh.confirmLabel": [
		"Confirm rollback to version {version}",
		"{version}. sürüme geri almayı onayla",
	],
	"dh.confirm": ["Confirm rollback", "Geri almayı onayla"],
	"dh.rollBackLabel": ["Roll back to version {version}", "{version}. sürüme geri al"],
	"dh.rollBack": ["Roll back", "Geri al"],
	"dh.historyUnverified": [
		"The revision history could not be verified.",
		"Revizyon geçmişi doğrulanamadı.",
	],
	"dh.unavailable": ["Unavailable", "Kullanılamıyor"],
	"dh.filed": [
		"Rollback to version {version} filed for approval. {pending}",
		"{version}. sürüme geri alma onaya gönderildi. {pending}",
	],
	"dh.notConfirmed": ["The rollback was not confirmed.", "Geri alma onaylanmadı."],
	"dh.restored": [
		"Version {version} restored as version {saved}. Not delivered: signed provisioning must distribute it.",
		"{version}. sürüm, {saved}. sürüm olarak geri yüklendi. Dağıtılmadı: imzalı dağıtım yolunun bunu iletmesi gerekir.",
	],
	"dh.teaser": [
		"Every saved revision is kept: compare revisions or roll back to an earlier one.",
		"Kaydedilen her revizyon saklanır: revizyonları karşılaştırın ya da eski bir revizyona geri dönün.",
	],
	"dh.show": ["Show revision history", "Revizyon geçmişini göster"],
	"dh.title": ["Revision history", "Revizyon geçmişi"],
	"dh.lead": [
		"Every saved DLP revision is kept. Compare any revision with the current one, or roll back: a rollback saves the earlier content as a new revision after re-validating it, and goes through four-eyes approval when that is on.",
		"Kaydedilen her DLP revizyonu saklanır. Herhangi bir revizyonu geçerli olanla karşılaştırın ya da geri alın: geri alma, eski içeriği yeniden doğruladıktan sonra yeni bir revizyon olarak kaydeder ve dört göz kuralı açıksa onaydan geçer.",
	],
	"dh.loading": ["Loading revisions…", "Revizyonlar yükleniyor…"],
	"dh.empty": ["No DLP revision has been saved yet.", "Henüz DLP revizyonu kaydedilmedi."],
	"dh.tableLabel": ["DLP policy revisions", "DLP politika revizyonları"],
	"dh.col.version": ["Version", "Sürüm"],
	"dh.col.saved": ["Saved", "Kaydedilme"],
	"dh.col.labels": ["Labels", "Etiketler"],
	"dh.col.rules": ["Rules", "Kurallar"],
	"dh.col.exceptions": ["Exceptions", "İstisnalar"],
	"dh.col.actions": ["Actions", "İşlemler"],
	"dh.loadOlder": ["Load older revisions", "Daha eski revizyonları yükle"],
	"dh.compareTitle": ["Version {base} → version {target}", "{base}. sürüm → {target}. sürüm"],
	"dh.lines": [" (+{added} / −{removed} lines)", " (+{added} / −{removed} satır)"],
	"dh.diffLabel": [
		"DLP diff from version {base} to version {target}",
		"{base}. sürümden {target}. sürüme DLP farkı",
	],
	"dh.loadingDiff": ["Loading diff…", "Fark yükleniyor…"],
} as const satisfies MessagePairs<string>;

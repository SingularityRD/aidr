import type { MessagePairs } from "./define";

/** AI governance: four-eyes policy change control page. */
export const governanceChangeMessages = {
	"gov.chg.kind.runtimePublish": ["Publish runtime policy", "Çalışma zamanı politikasını yayımla"],
	"gov.chg.kind.runtimePublishDocument": [
		"Publish compiled policy YAML",
		"Derlenmiş politika YAML'ını yayımla",
	],
	"gov.chg.kind.runtimeRestore": [
		"Roll back runtime policy",
		"Çalışma zamanı politikasını geri al",
	],
	"gov.chg.kind.runtimeStage": [
		"Stage runtime policy for selected agents",
		"Çalışma zamanı politikasını seçili araçlar için hazırla",
	],
	"gov.chg.kind.runtimeRollout": ["Ordered canary rollout", "Sıralı kademeli dağıtım"],
	"gov.chg.kind.dlpPublish": ["Save DLP policy", "DLP politikasını kaydet"],
	"gov.chg.kind.agentProfilesStage": [
		"Stage agent permission profiles",
		"Araç izin profillerini hazırla",
	],
	"gov.chg.kind.disableFourEyes": [
		"Turn off four-eyes change control",
		"Dört göz değişiklik denetimini kapat",
	],
	"gov.chg.filed": [
		"Filed by {member} on {time} against version {version}{restores}; expires {expires}.",
		"{member} tarafından {time} tarihinde, {version}. sürüm üzerine oluşturuldu{restores}; sona erme: {expires}.",
	],
	"gov.chg.restores": [" (restores revision {version})", " ({version}. revizyonu geri yükler)"],
	"gov.chg.diffSummary": [
		"Current version {version} → proposed: {added} line(s) added, {removed} removed.",
		"Geçerli sürüm {version} → önerilen: {added} satır eklendi, {removed} satır çıkarıldı.",
	],
	"gov.chg.targets": [" Targets {count} agent(s).", " {count} yapay zekâ aracını hedefler."],
	"gov.chg.rings": [" {count} rollout ring(s).", " {count} dağıtım halkası."],
	"gov.chg.diffFor": ["Diff for {kind}", "{kind} için fark"],
	"gov.chg.reviewDiff": ["Review diff", "Farkı incele"],
	"gov.chg.own": [
		"You filed this change, so another owner or administrator must approve it.",
		"Bu değişikliği siz oluşturdunuz; bu yüzden başka bir sahip ya da yöneticinin onaylaması gerekir.",
	],
	"gov.chg.withdraw": ["Withdraw", "Geri çek"],
	"gov.chg.approveApply": ["Approve and apply", "Onayla ve uygula"],
	"gov.chg.reviewFirst": ["Review the diff before approving.", "Onaylamadan önce farkı inceleyin."],
	"gov.chg.ownersDecide": [
		"Owners and administrators decide policy changes.",
		"Politika değişikliklerine sahipler ve yöneticiler karar verir.",
	],
	"gov.chg.historyFailed": [
		"Runtime policy history could not be loaded.",
		"Çalışma zamanı politika geçmişi yüklenemedi.",
	],
	"gov.chg.rollbackFiled": [
		"Rollback to revision {version} filed. {pending}",
		"{version}. revizyona geri alma talebi oluşturuldu. {pending}",
	],
	"gov.chg.republished": [
		"Revision {version} republished as version {next}.",
		"{version}. revizyon {next}. sürüm olarak yeniden yayımlandı.",
	],
	"gov.chg.rollbackUnconfirmed": [
		"The rollback was not confirmed. Refresh if another administrator changed the policy.",
		"Geri alma onaylanmadı. Politikayı başka bir yönetici değiştirdiyse sayfayı yenileyin.",
	],
	"gov.chg.noHistory": [
		"No runtime policy history available.",
		"Çalışma zamanı politika geçmişi yok.",
	],
	"gov.chg.nothingPublished": [
		"No runtime policy has been published yet.",
		"Henüz çalışma zamanı politikası yayımlanmadı.",
	],
	"gov.chg.version": ["Version {version}", "{version}. sürüm"],
	"gov.chg.published": [" (published)", " (yayında)"],
	"gov.chg.hideDiff": ["Hide diff", "Farkı gizle"],
	"gov.chg.diffVs": ["Diff vs version {version}", "{version}. sürümle fark"],
	"gov.chg.showContent": ["Show content", "İçeriği göster"],
	"gov.chg.rollBackTo": ["Roll back to version {version}", "{version}. sürüme geri al"],
	"gov.chg.diffOf": ["Diff of version {version}", "{version}. sürümün farkı"],
	"gov.chg.selectTeam": [
		"Select a team to view change control.",
		"Değişiklik denetimini görmek için bir ekip seçin.",
	],
	"gov.chg.title": ["Policy change control", "Politika değişiklik denetimi"],
	"gov.chg.lead": [
		"With four-eyes on, publishing runtime or DLP policy — including rollbacks, staged and canary rollouts — files a change request that a second owner or administrator must approve after reviewing the diff. The database refuses any publication that is not such an approval, and nobody can approve their own change.",
		"Dört göz kuralı açıkken çalışma zamanı ya da DLP politikası yayımlamak — geri almalar, hazırlanan ve kademeli dağıtımlar dahil — bir değişiklik talebi oluşturur; ikinci bir sahip ya da yönetici farkı inceledikten sonra bunu onaylamalıdır. Veritabanı böyle bir onay olmadan yapılan her yayımı reddeder ve kimse kendi değişikliğini onaylayamaz.",
	],
	"gov.chg.loading": ["Loading change control…", "Değişiklik denetimi yükleniyor…"],
	"gov.chg.settings": ["Settings", "Ayarlar"],
	"gov.chg.fourEyesIs": [
		"Four-eyes change control is {state}.",
		"Dört göz değişiklik denetimi {state}.",
	],
	"gov.chg.on": ["on", "açık"],
	"gov.chg.off": ["off", "kapalı"],
	"gov.chg.disablePending": [
		" A request to turn it off is waiting for a second approver.",
		" Kapatma talebi ikinci bir onaylayıcıyı bekliyor.",
	],
	"gov.chg.disableFiled": [
		"Request to turn off four-eyes filed; another owner or administrator must approve it.",
		"Dört gözü kapatma talebi oluşturuldu; başka bir sahip ya da yöneticinin onaylaması gerekir.",
	],
	"gov.chg.requestDisable": ["Request to turn off four-eyes", "Dört gözü kapatmayı iste"],
	"gov.chg.enabled": ["Four-eyes change control is on.", "Dört göz değişiklik denetimi açık."],
	"gov.chg.enable": ["Turn on four-eyes", "Dört gözü aç"],
	"gov.chg.reviewInterval": ["Review interval (days)", "Gözden geçirme aralığı (gün)"],
	"gov.chg.intervalSaved": ["Review interval saved.", "Gözden geçirme aralığı kaydedildi."],
	"gov.chg.saveInterval": ["Save interval", "Aralığı kaydet"],
	"gov.chg.settingsReadOnly": [
		"Only owners and administrators change these settings.",
		"Bu ayarları yalnızca sahipler ve yöneticiler değiştirebilir.",
	],
	"gov.chg.reviewers": [
		"Designated AI governance reviewers",
		"Atanmış yapay zekâ yönetişimi gözden geçirenleri",
	],
	"gov.chg.reviewersLead": [
		"Members you designate can decide intake requests and record periodic reviews (at AAL2). They cannot lift a ban or restriction, decide exceptions or approve policy changes.",
		"Atadığınız üyeler kullanım taleplerine karar verebilir ve dönemsel gözden geçirmeleri kaydedebilir (AAL2 doğrulamasıyla). Bir yasağı ya da kısıtlamayı kaldıramaz, istisnalara karar veremez ve politika değişikliklerini onaylayamazlar.",
	],
	"gov.chg.noMembers": ["No members with the member role.", "Üye rolünde kimse yok."],
	"gov.chg.reviewer": ["Reviewer", "Gözden geçiren"],
	"gov.chg.reviewerRemoved": [
		"Reviewer designation removed.",
		"Gözden geçiren ataması kaldırıldı.",
	],
	"gov.chg.reviewerAdded": ["Reviewer designated.", "Gözden geçiren atandı."],
	"gov.chg.remove": ["Remove", "Kaldır"],
	"gov.chg.designate": ["Designate", "Ata"],
	"gov.chg.pending": ["Pending changes", "Bekleyen değişiklikler"],
	"gov.chg.noPending": ["No changes are waiting for approval.", "Onay bekleyen değişiklik yok."],
	"gov.chg.withdrawn": ["Change withdrawn.", "Değişiklik geri çekildi."],
	"gov.chg.rejected": [
		"Change rejected; nothing was published.",
		"Değişiklik reddedildi; hiçbir şey yayımlanmadı.",
	],
	"gov.chg.applied": ["Change approved and applied.", "Değişiklik onaylandı ve uygulandı."],
	"gov.chg.appliedAs": [
		"Change approved and applied as version {version}.",
		"Değişiklik onaylandı ve {version}. sürüm olarak uygulandı.",
	],
	"gov.chg.decided": ["Decided changes", "Karara bağlanan değişiklikler"],
	"gov.chg.col.change": ["Change", "Değişiklik"],
	"gov.chg.col.author": ["Author", "Oluşturan"],
	"gov.chg.col.applied": ["Applied", "Uygulanan"],
	"gov.chg.history": ["Runtime policy history", "Çalışma zamanı politika geçmişi"],
	"gov.chg.historyLead": [
		"Every published and staged revision, with a diff against the one before it. Rolling back republishes the chosen revision through the normal publication path, so four-eyes applies to it too.",
		"Yayımlanan ve hazırlanan her revizyon, bir öncekiyle farkıyla birlikte. Geri alma, seçilen revizyonu normal yayım yolundan yeniden yayımlar; bu yüzden dört göz kuralı ona da uygulanır.",
	],
} as const satisfies MessagePairs<string>;

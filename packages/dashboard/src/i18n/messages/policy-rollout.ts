import type { MessagePairs } from "./define";

/** Policy rollout (staging, canary, rollback). */
export const policyRolloutMessages = {
	"rollout.loadFailed": [
		"Policy deployment status could not be loaded.",
		"Politika dağıtım durumu yüklenemedi.",
	],
	"rollout.loadFailedRetry": [
		"Policy deployment status could not be loaded. Refresh to retry.",
		"Politika dağıtım durumu yüklenemedi. Yeniden denemek için yenileyin.",
	],
	"rollout.changeFailedRefresh": [
		"Policy change failed. Refresh if another administrator published a version.",
		"Politika değişikliği başarısız oldu. Başka bir yönetici bir sürüm yayımladıysa sayfayı yenileyin.",
	],
	"rollout.notConfirmed": [
		"Ordered rollout was not confirmed. Refresh deployment status.",
		"Sıralı dağıtım doğrulanmadı. Dağıtım durumunu yenileyin.",
	],
	"rollout.started": [
		"Ordered rollout version {version} started. Waiting for agent-reported load receipts; host enforcement is not yet proven.",
		"{version}. sürümün sıralı dağıtımı başladı. Ajanların yükleme bildirimleri bekleniyor; bilgisayarda uygulandığı henüz kanıtlanmadı.",
	],
	"rollout.staged": [
		"Version {version} assigned to {count} selected agents. Other agents keep their current target.",
		"{version}. sürüm seçilen {count} ajana atandı. Diğer ajanlar mevcut hedeflerini korur.",
	],
	"rollout.restored": [
		"Revision {revision} republished as version {version} for all enrolled agents.",
		"{revision}. revizyon tüm kayıtlı ajanlar için {version}. sürüm olarak yeniden yayımlandı.",
	],
	"rollout.changeFailed": ["Policy change failed.", "Politika değişikliği başarısız oldu."],
	"rollout.title": ["Policy rollout", "Politika dağıtımı"],
	"rollout.intro": [
		"Select a small group to test the runtime controls above, then publish a reviewed revision to everyone. A loading receipt is reported by the agent; it does not prove the host enforced every action. Receipts older than five minutes are marked stale.",
		"Yukarıdaki çalışma zamanı denetimlerini denemek için küçük bir grup seçin, ardından incelenmiş bir revizyonu herkese yayımlayın. Yükleme bildirimi ajan tarafından gönderilir; bilgisayarın her işlemi uyguladığını kanıtlamaz. Beş dakikadan eski bildirimler eskimiş olarak işaretlenir.",
	],
	"rollout.limits": [
		"Ordered rollout plans accept up to 1,667 agents per request and must fit within 64 KB. Larger policies or many small batches can lower that limit; split larger fleets into smaller plans. This screen stages up to 200 selected agents at a time.",
		"Sıralı dağıtım planları istek başına en fazla 1.667 ajan kabul eder ve 64 KB sınırına sığmalıdır. Daha büyük politikalar ya da çok sayıda küçük grup bu sınırı düşürebilir; büyük filoları daha küçük planlara bölün. Bu ekran bir seferde en fazla 200 seçili ajanı hazırlar.",
	],
	"rollout.refresh": ["Refresh deployment status", "Dağıtım durumunu yenile"],
	"rollout.latest": [
		"Latest ordered rollout: version {version}, {status}; agent-reported loads {current}/{targeted} current, {stale} stale, {outdated} outdated, {unknown} unknown. This is not host-enforcement attestation.",
		"Son sıralı dağıtım: {version}. sürüm, {status}; ajanların bildirdiği yüklemeler {current}/{targeted} güncel, {stale} eskimiş, {outdated} eski sürüm, {unknown} bilinmiyor. Bu, bilgisayarda uygulandığına dair bir kanıt değildir.",
	],
	"rollout.unknownVersion": ["Unknown", "Bilinmiyor"],
	"rollout.status.none": ["none", "yok"],
	"rollout.status.running": ["running", "sürüyor"],
	"rollout.status.paused": ["paused", "duraklatıldı"],
	"rollout.status.completed": ["completed", "tamamlandı"],
	"rollout.status.cancelled": ["cancelled", "iptal edildi"],
	"rollout.state.unknown": ["unknown", "bilinmiyor"],
	"rollout.state.stale": ["stale", "eskimiş"],
	"rollout.state.current": ["current", "güncel"],
	"rollout.state.outdated": ["outdated", "eski sürüm"],
	"rollout.truncated": [
		"Showing up to 500 agents per page and the latest 100 revisions. Use Next agents to continue through the fleet.",
		"Sayfa başına en fazla 500 ajan ve en son 100 revizyon gösteriliyor. Filonun devamı için Sonraki ajanlar düğmesini kullanın.",
	],
	"rollout.select": ["Select", "Seç"],
	"rollout.agent": ["Agent", "Ajan"],
	"rollout.target": ["Target", "Hedef"],
	"rollout.loaded": ["Reported loaded", "Bildirilen yüklü sürüm"],
	"rollout.stageFor": ["Stage policy for {name}", "{name} için politikayı hazırla"],
	"rollout.none": ["None", "Yok"],
	"rollout.noReceipts": ["No agent loading receipts available.", "Ajan yükleme bildirimi yok."],
	"rollout.first": ["First agents", "İlk ajanlar"],
	"rollout.next": ["Next agents", "Sonraki ajanlar"],
	"rollout.stage": [
		"Stage current draft for {count} selected agents",
		"Geçerli taslağı seçilen {count} ajan için hazırla",
	],
	"rollout.canary": [
		"Start ordered canary rollout for {count} selected agents",
		"Seçilen {count} ajan için sıralı öncü dağıtımı başlat",
	],
	"rollout.canaryNote": [
		"The first selected agent is the canary. Remaining selected agents receive this revision only after its fresh load receipt.",
		"İlk seçilen ajan öncüdür. Seçilen diğer ajanlar bu revizyonu ancak öncünün yeni yükleme bildiriminden sonra alır.",
	],
	"rollout.history": ["Revision history and rollback", "Revizyon geçmişi ve geri alma"],
	"rollout.historyNote": [
		"Staging a new policy or republishing a revision cancels any active ordered rollout. Review controls before a tenant-wide publish.",
		"Yeni bir politikayı hazırlamak ya da bir revizyonu yeniden yayımlamak etkin sıralı dağıtımı iptal eder. Tüm çalışma alanına yayımlamadan önce denetimleri inceleyin.",
	],
	"rollout.revision": ["Version {version} · {time}", "{version}. sürüm · {time}"],
	"rollout.review": ["Review version {version}", "{version}. sürümü incele"],
	"rollout.publishAll": [
		"Publish version {version} to all enrolled agents",
		"{version}. sürümü tüm kayıtlı ajanlara yayımla",
	],
} as const satisfies MessagePairs<string>;

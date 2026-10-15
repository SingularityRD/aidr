import type { MessagePairs } from "./define";

/** Time-limited detection exceptions page and its validation messages. */
export const detectionExceptionsMessages = {
	"dex.subject.user": ["Member", "Üye"],
	"dex.subject.agent": ["Agent", "Yapay zekâ aracı"],
	"dex.subject.repo": ["Repository", "Depo"],
	"dex.problem.rule": [
		"Enter a rule id such as CLT-CMD-011.",
		"CLT-CMD-011 gibi bir kural kimliği girin.",
	],
	"dex.problem.protected": [
		"Self-defense rules cannot be excepted.",
		"Kendini koruma kuralları için istisna tanımlanamaz.",
	],
	"dex.problem.repo": [
		"Enter the repository (origin remote such as github.com/acme/app).",
		"Depoyu girin (github.com/acme/app gibi origin adresi).",
	],
	"dex.problem.member": ["Choose a workspace member.", "Bir çalışma alanı üyesi seçin."],
	"dex.problem.agent": ["Enter the agent id.", "Yapay zekâ aracının kimliğini girin."],
	"dex.problem.future": [
		"The end date must be in the future.",
		"Bitiş tarihi gelecekte olmalıdır.",
	],
	"dex.problem.maxDays": [
		"An exception can last at most {days} days.",
		"Bir istisna en fazla {days} gün sürebilir.",
	],
	"dex.problem.reason": [
		"A reason (up to 500 characters) is required.",
		"Bir gerekçe (en fazla 500 karakter) gereklidir.",
	],
	"dex.problem.digest": [
		"The artifact digest must be a 64-character SHA-256 hex value.",
		"Dosya özeti 64 karakterlik bir SHA-256 onaltılık değeri olmalıdır.",
	],
	"dex.err.mfa": [
		"Multi-factor verification (AAL2) is required. Verify with your authenticator, then try again.",
		"Çok adımlı doğrulama (AAL2) gerekiyor. Doğrulama uygulamanızla doğrulayıp yeniden deneyin.",
	],
	"dex.err.forbidden": [
		"Only workspace owners and admins can manage detection exceptions.",
		"Tespit istisnalarını yalnızca çalışma alanı sahipleri ve yöneticileri yönetebilir.",
	],
	"dex.err.subjectUnknown": [
		"That member or agent does not belong to this workspace.",
		"Bu üye ya da yapay zekâ aracı bu çalışma alanına ait değil.",
	],
	"dex.err.quota": [
		"At most 500 detection exceptions can be active at once.",
		"Aynı anda en fazla 500 tespit istisnası etkin olabilir.",
	],
	"dex.err.notFound": ["This exception no longer exists.", "Bu istisna artık yok."],
	"dex.err.expires": [
		"The end date must be between 5 minutes and {days} days from now.",
		"Bitiş tarihi şu andan itibaren 5 dakika ile {days} gün arasında olmalıdır.",
	],
	"dex.err.generic": [
		"The detection exception service did not confirm the request. Nothing changed.",
		"Tespit istisnası hizmeti isteği onaylamadı. Hiçbir şey değişmedi.",
	],
	"dex.selectTeam": [
		"Select a team to manage detection exceptions.",
		"Tespit istisnalarını yönetmek için bir ekip seçin.",
	],
	"dex.title": ["Detection exceptions", "Tespit istisnaları"],
	"dex.added": [
		"Exception added for {rule} until {date}.",
		"{rule} için {date} tarihine kadar istisna eklendi.",
	],
	"dex.revokePrompt": [
		"Why revoke the exception for {rule}?",
		"{rule} istisnası neden geri alınıyor?",
	],
	"dex.revoked": ["Exception for {rule} revoked.", "{rule} istisnası geri alındı."],
	"dex.lead": [
		"Lift one detection rule for one member, agent or repository until an end date at most {days} days ahead; it lifts itself when it expires. Connectors receive exceptions only inside the signed runtime policy, apply them to exactly that rule and subject, and audit every use. Self-defense rules can never be excepted. Every change requires multi-factor verification and is recorded in the audit log.",
		"Bir tespit kuralını tek bir üye, yapay zekâ aracı ya da depo için en fazla {days} gün sonrasına kadar kaldırın; süre dolunca istisna kendiliğinden biter. Bağlayıcılar istisnaları yalnızca imzalı çalışma zamanı politikasının içinde alır, yalnızca o kural ve o kişi/araç/depo için uygular ve her kullanımı denetim kaydına yazar. Kendini koruma kurallarına asla istisna tanımlanamaz. Her değişiklik çok adımlı doğrulama gerektirir ve denetim kaydına yazılır.",
	],
	"dex.verifyNow": ["Verify now", "Şimdi doğrula"],
	"dex.addLabel": ["Add a detection exception", "Tespit istisnası ekle"],
	"dex.addTitle": ["Add an exception", "İstisna ekleyin"],
	"dex.ruleId": ["Rule id", "Kural kimliği"],
	"dex.appliesTo": ["Applies to", "Kimler için geçerli"],
	"dex.member": ["Member", "Üye"],
	"dex.chooseMember": ["Choose a member…", "Bir üye seçin…"],
	"dex.agentId": ["Agent id", "Yapay zekâ aracı kimliği"],
	"dex.repo": [
		"Repository (origin remote, e.g. github.com/acme/app)",
		"Depo (origin adresi, örn. github.com/acme/app)",
	],
	"dex.endsOn": ["Ends on (UTC)", "Bitiş (UTC)"],
	"dex.reason": ["Reason", "Gerekçe"],
	"dex.artifact": [
		"Only this artifact (optional SHA-256 from {command} or the audit log)",
		"Yalnızca bu dosya ({command} çıktısından ya da denetim kaydından isteğe bağlı SHA-256)",
	],
	"dex.add": ["Add exception", "İstisna ekle"],
	"dex.list": ["Exceptions", "İstisnalar"],
	"dex.loading": ["Loading exceptions…", "İstisnalar yükleniyor…"],
	"dex.empty": ["No detection exceptions yet.", "Henüz tespit istisnası yok."],
	"dex.col.rule": ["Rule", "Kural"],
	"dex.col.ends": ["Ends", "Bitiş"],
	"dex.col.state": ["State", "Durum"],
	"dex.oneArtifact": ["one artifact ({digest}…)", "tek dosya ({digest}…)"],
	"dex.state.active": ["active", "etkin"],
	"dex.state.expired": ["expired", "süresi doldu"],
	"dex.state.revoked": ["revoked", "geri alındı"],
	"dex.revoke": ["Revoke", "Geri al"],
} as const satisfies MessagePairs<string>;

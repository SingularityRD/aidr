import type { MessagePairs } from "./define";

/** Approvals page and rule names shown on approval cards. */
export const approvalsMessages = {
	"approvals.error.mfaRequired": [
		"Multi-factor verification (AAL2) is required to decide approvals. Verify with your authenticator, then try again.",
		"Onay kararı vermek için çok faktörlü doğrulama (AAL2) gerekir. Doğrulama uygulamanızla doğrulayıp yeniden deneyin.",
	],
	"approvals.error.ssoRequired": [
		"This workspace requires single sign-on. Sign in with your identity provider, then try again.",
		"Bu çalışma alanı çoklu oturum açma (SSO) gerektirir. Kimlik sağlayıcınızla oturum açıp yeniden deneyin.",
	],
	"approvals.error.forbidden": [
		"Only owners and administrators can decide approvals.",
		"Onay kararlarını yalnızca sahipler ve yöneticiler verebilir.",
	],
	"approvals.error.selfApproval": [
		"This request was raised by your own key or agent, so another owner or administrator must approve it. You can still deny it.",
		"Bu istek sizin anahtarınız veya ajanınız tarafından oluşturuldu; bu yüzden başka bir sahip ya da yönetici onaylamalıdır. Reddetme hakkınız yine de var.",
	],
	"approvals.error.fourEyes": [
		"Four-eyes change control is on: turning off the separate-approver rule needs a second person.",
		"Dört göz değişiklik denetimi açık: ayrı onaylayıcı kuralını kapatmak için ikinci bir kişi gerekir.",
	],
	"approvals.error.settingsFailed": [
		"The approval setting was not saved. Nothing changed.",
		"Onay ayarı kaydedilmedi. Hiçbir şey değişmedi.",
	],
	"approvals.error.final": [
		"This request was already decided.",
		"Bu istek için zaten karar verildi.",
	],
	"approvals.error.expired": [
		"This request expired before it was decided. The agent's action stays blocked.",
		"Bu isteğin süresi karar verilmeden doldu. Ajanın işlemi engelli kalır.",
	],
	"approvals.error.notFound": [
		"This request is no longer available in this workspace.",
		"Bu istek artık bu çalışma alanında bulunmuyor.",
	],
	"approvals.error.keyChanged": [
		"The signing key changed while deciding. Try again.",
		"Karar verilirken imzalama anahtarı değişti. Yeniden deneyin.",
	],
	"approvals.error.signingUnavailable": [
		"The approval could not be signed. Nothing was approved; contact your platform operator.",
		"Onay imzalanamadı. Hiçbir şey onaylanmadı; platform operatörünüzle iletişime geçin.",
	],
	"approvals.error.invalidReason": [
		"Enter a reason of 1 to {max} characters without control characters.",
		"Denetim karakteri içermeyen, 1 ile {max} karakter arasında bir gerekçe girin.",
	],
	"approvals.error.rateLimited": [
		"Too many decisions. Wait a minute and try again.",
		"Çok fazla karar gönderildi. Bir dakika bekleyip yeniden deneyin.",
	],
	"approvals.error.session": [
		"Your session is no longer valid. Sign in again.",
		"Oturumunuz artık geçerli değil. Yeniden oturum açın.",
	],
	"approvals.error.unavailable": [
		"Approval requests could not be loaded.",
		"Onay istekleri yüklenemedi.",
	],
	"approvals.error.generic": [
		"The approval service did not confirm the request. Nothing changed.",
		"Onay hizmeti isteği doğrulamadı. Hiçbir şey değişmedi.",
	],

	"approvals.status.pending": ["Pending", "Bekliyor"],
	"approvals.status.approved": ["Approved", "Onaylandı"],
	"approvals.status.denied": ["Denied", "Reddedildi"],
	"approvals.status.expired": ["Expired", "Süresi doldu"],

	"approvals.card.label": ["Approval request: {title}", "Onay isteği: {title}"],
	"approvals.card.fallbackTitle": ["Action held for review", "İnceleme için bekletilen işlem"],
	"approvals.card.moreRules": ["+{count} more", "+{count} kural daha"],
	"approvals.card.expiresIn": ["Expires in {time}", "{time} içinde süresi doluyor"],
	"approvals.card.what": ["What the agent tried", "Ajanın yapmak istediği"],
	"approvals.card.noSummary": ["No summary provided.", "Özet gönderilmedi."],
	"approvals.card.summaryNote": [
		"Summary redacted by the connector before it left the computer.",
		"Özet, bilgisayardan çıkmadan önce bağlayıcı tarafından maskelendi.",
	],
	"approvals.card.why": ["Why it was held", "Neden bekletildi"],
	"approvals.card.noRules": [
		"No rule was reported with this request.",
		"Bu istekle birlikte bir kural bildirilmedi.",
	],
	"approvals.card.unknownRule": [
		"Rule not in this dashboard's catalog",
		"Bu panelin kural kataloğunda yok",
	],
	"approvals.card.next": ["What happens next", "Sonra ne olur"],
	"approvals.card.nextBody": [
		"Approve lets exactly this action run once more on {agent}, only within 15 minutes. Deny keeps it blocked. Your decision and reason are recorded in the audit log.",
		"Onaylarsanız bu işlem {agent} üzerinde yalnızca bir kez daha ve yalnızca 15 dakika içinde çalışabilir. Reddederseniz engelli kalır. Kararınız ve gerekçeniz denetim kaydına yazılır.",
	],
	"approvals.card.agent": ["Agent", "Ajan"],
	"approvals.card.requested": ["Requested", "İstenme zamanı"],
	"approvals.card.reason": [
		"Reason (recorded in the audit log)",
		"Gerekçe (denetim kaydına yazılır)",
	],
	"approvals.card.approve": ["Approve", "Onayla"],
	"approvals.card.deny": ["Deny", "Reddet"],

	"approvals.history.empty": [
		"No decided or expired requests yet.",
		"Henüz karar verilmiş ya da süresi dolmuş istek yok.",
	],
	"approvals.history.requested": ["Requested", "İstenme zamanı"],
	"approvals.history.action": ["Action", "İşlem"],
	"approvals.history.tool": ["Tool", "Araç"],
	"approvals.history.agent": ["Agent", "Ajan"],
	"approvals.history.rules": ["Rules", "Kurallar"],
	"approvals.history.outcome": ["Outcome", "Sonuç"],
	"approvals.history.decided": ["Decided", "Karar zamanı"],
	"approvals.history.reason": ["Reason", "Gerekçe"],

	"approvals.key.rotated": [
		"Approval signing key rotated. New key {keyId}; the previous key stays published only for the lifetime of tokens it already signed.",
		"Onay imzalama anahtarı yenilendi. Yeni anahtar {keyId}; önceki anahtar yalnızca daha önce imzaladığı belirteçlerin geçerlilik süresi boyunca yayımlı kalır.",
	],
	"approvals.key.title": ["Approval signing key", "Onay imzalama anahtarı"],
	"approvals.key.body": [
		"Approval tokens are signed with a per-workspace Ed25519 key held encrypted by the control plane. Connectors verify them with the public key delivered in their signed entitlement. Rotate the key if you suspect it was exposed.",
		"Onay belirteçleri, kontrol düzleminde şifreli tutulan ve her çalışma alanına özel bir Ed25519 anahtarıyla imzalanır. Bağlayıcılar bunları imzalı yetki belgelerindeki genel anahtarla doğrular. Anahtarın açığa çıktığından şüpheleniyorsanız yenileyin.",
	],
	"approvals.key.confirm": ["Confirm rotation", "Yenilemeyi onayla"],
	"approvals.key.cancel": ["Cancel", "Vazgeç"],
	"approvals.key.rotate": ["Rotate signing key", "İmzalama anahtarını yenile"],

	"approvals.separation.plan": [
		"Plan default (required on Business and Enterprise)",
		"Plan varsayılanı (Business ve Enterprise planlarında zorunlu)",
	],
	"approvals.separation.required": [
		"Always require a different approver",
		"Her zaman farklı bir onaylayıcı iste",
	],
	"approvals.separation.allowed": [
		"Allow approving your own requests (recorded as self-approved)",
		"Kendi isteklerinizi onaylamaya izin ver (kendi onayı olarak kaydedilir)",
	],
	"approvals.separation.saved": ["Approval setting saved.", "Onay ayarı kaydedildi."],
	"approvals.separation.title": ["Separation of duties", "Görevler ayrılığı"],
	"approvals.separation.body": [
		"Whether the person whose key or agent raised a request may approve it themselves. Denying your own request is always allowed.",
		"İsteği anahtarı ya da ajanı oluşturan kişinin bu isteği kendisinin onaylayıp onaylayamayacağı. Kendi isteğinizi reddetmek her zaman serbesttir.",
	],
	"approvals.separation.loadFailed": [
		"The current setting could not be loaded.",
		"Geçerli ayar yüklenemedi.",
	],
	"approvals.separation.approver": ["Approver", "Onaylayıcı"],
	"approvals.separation.effectiveRequired": [
		"In effect: a different owner or administrator must approve.",
		"Geçerli kural: farklı bir sahip ya da yönetici onaylamalıdır.",
	],
	"approvals.separation.effectiveAllowed": [
		"In effect: requesters may approve their own requests.",
		"Geçerli kural: istek sahipleri kendi isteklerini onaylayabilir.",
	],

	"approvals.verifyMfa": ["Verify with authenticator", "Doğrulama uygulamasıyla doğrula"],
	"approvals.empty": ["No pending approval requests.", "Bekleyen onay isteği yok."],
	"approvals.decided.approved": [
		"Approved {tool} on {agent}. The connector can retry the identical action until {time}.",
		"{agent} üzerindeki {tool} işlemi onaylandı. Bağlayıcı aynı işlemi {time} saatine kadar yeniden deneyebilir.",
	],
	"approvals.decided.denied": [
		"Denied {tool} on {agent}. The action stays blocked.",
		"{agent} üzerindeki {tool} işlemi reddedildi. İşlem engelli kalır.",
	],
	"approvals.noTeam": [
		"Select a team to review approval requests.",
		"Onay isteklerini incelemek için bir ekip seçin.",
	],
	"approvals.intro": [
		"In managed mode, when a protected AI tool is about to do something risky, it pauses and waits here for a person to decide. The AI tool itself can never approve: an owner or administrator decides here with multi-factor verification, and the decision is signed and sent back to that computer.",
		"Yönetilen modda, korunan bir yapay zekâ aracı riskli bir işlem yapmak üzereyken durur ve bir kişinin karar vermesi için burada bekler. Yapay zekâ aracı kendi işlemini asla onaylayamaz: kararı burada çok faktörlü doğrulamayla bir sahip ya da yönetici verir; karar imzalanıp o bilgisayara geri gönderilir.",
	],
	"approvals.tabs": ["Approval requests", "Onay istekleri"],
	"approvals.tab.pending": ["Pending ({count})", "Bekleyen ({count})"],
	"approvals.tab.history": ["History", "Geçmiş"],
	"approvals.refresh": ["Refresh", "Yenile"],
	"approvals.loading": ["Loading approval requests…", "Onay istekleri yükleniyor…"],
	"approvals.truncated.one": [
		"Showing the {shown} requests that expire soonest; {hidden} more pending request is not shown. Decide or let these expire, then refresh.",
		"Süresi en yakın dolacak {shown} istek gösteriliyor; bekleyen {hidden} istek daha gösterilmiyor. Bunlara karar verin ya da sürelerinin dolmasını bekleyin, sonra yenileyin.",
	],
	"approvals.truncated.other": [
		"Showing the {shown} requests that expire soonest; {hidden} more pending requests are not shown. Decide or let these expire, then refresh.",
		"Süresi en yakın dolacak {shown} istek gösteriliyor; bekleyen {hidden} istek daha gösterilmiyor. Bunlara karar verin ya da sürelerinin dolmasını bekleyin, sonra yenileyin.",
	],
	"approvals.historyTruncated": [
		"Showing the newest {count} decided or expired requests; older entries are not listed here.",
		"Karar verilmiş ya da süresi dolmuş en yeni {count} istek gösteriliyor; daha eski kayıtlar burada listelenmez.",
	],

	"rules.category.command": ["Dangerous command", "Tehlikeli komut"],
	"rules.category.secrets": ["Secrets and credentials", "Gizli bilgiler ve kimlik bilgileri"],
	"rules.category.irreversible": ["Irreversible action", "Geri alınamaz işlem"],
	"rules.category.exfiltration": ["Sending data out", "Dışarı veri gönderme"],
	"rules.category.persistence": ["Staying on the computer", "Bilgisayarda kalıcılık"],
	"rules.category.evasion": [
		"Disabling or hiding from security tools",
		"Güvenlik araçlarını devre dışı bırakma ya da onlardan gizlenme",
	],
	"rules.category.supplyChain": [
		"Untrusted package or download",
		"Güvenilmeyen paket ya da indirme",
	],
	"rules.category.injection": [
		"Hidden instructions for the AI tool",
		"Yapay zekâ aracına gizli talimat",
	],
	"rules.category.insecureCode": ["Insecure code", "Güvensiz kod"],
	"rules.category.resourceHijacking": [
		"Misusing computer resources",
		"Bilgisayar kaynaklarının kötüye kullanımı",
	],
	"rules.category.privilege": ["Gaining more permissions", "Daha fazla yetki edinme"],
	"rules.category.discovery": ["Scanning the system or network", "Sistemi ya da ağı tarama"],
	"rules.category.disclosure": ["Revealing private information", "Gizli bilgiyi açığa çıkarma"],
	"rules.category.rewardHacking": ["Gaming tests or checks", "Testleri ya da denetimleri atlatma"],
	"rules.category.skill": ["Unsafe skill or plugin", "Güvensiz beceri ya da eklenti"],
	"rules.category.contentSafety": ["Unsafe content", "Güvensiz içerik"],
} as const satisfies MessagePairs<string>;

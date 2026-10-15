import type { MessagePairs } from "./define";

/** Governance scorecard: derived top risks, settings validation and service errors. */
export const governanceRisksMessages = {
	"gr.critical.one": ["1 critical incident still open", "1 kritik güvenlik vakası hâlâ açık"],
	"gr.critical.many": [
		"{count} critical incidents still open",
		"{count} kritik güvenlik vakası hâlâ açık",
	],
	"gr.high.one": [
		"1 high-severity incident still open",
		"1 yüksek önemli güvenlik vakası hâlâ açık",
	],
	"gr.high.many": [
		"{count} high-severity incidents still open",
		"{count} yüksek önemli güvenlik vakası hâlâ açık",
	],
	"gr.unresolved": [
		"Reported in the last {days} days and not resolved.",
		"Son {days} günde bildirildi ve çözülmedi.",
	],
	"gr.posture.one": [
		"1 critical AI tool-chain finding",
		"1 kritik yapay zekâ araç zinciri bulgusu",
	],
	"gr.posture.many": [
		"{count} critical AI tool-chain findings",
		"{count} kritik yapay zekâ araç zinciri bulgusu",
	],
	"gr.postureDetail": [
		"Critical CVE, MCP server or skill findings uploaded in this window.",
		"Bu aralıkta yüklenen kritik CVE, MCP sunucusu ya da beceri bulguları.",
	],
	"gr.noMfa.one": ["1 owner or admin without MFA", "MFA kullanmayan 1 sahip ya da yönetici"],
	"gr.noMfa.many": [
		"{count} owners or admins without MFA",
		"MFA kullanmayan {count} sahip ya da yönetici",
	],
	"gr.noMfaDetail": [
		"The workspace does not require MFA, and these accounts can approve held agent actions.",
		"Çalışma alanı MFA zorunlu tutmuyor ve bu hesaplar bekletilen yapay zekâ aracı işlemlerini onaylayabilir.",
	],
	"gr.review.one": ["1 approver to review", "Gözden geçirilecek 1 onaylayıcı"],
	"gr.review.many": ["{count} approvers to review", "Gözden geçirilecek {count} onaylayıcı"],
	"gr.reviewDetail": [
		"Approved at least {share}% of their decisions within {seconds} s. A prompt to check for automatic approval, not a finding.",
		"Kararlarının en az %{share} kadarını {seconds} sn içinde onayladı. Bu, onayların düşünülmeden verilip verilmediğini kontrol etme uyarısıdır; bir bulgu değildir.",
	],
	"gr.expired.one": [
		"1 held action expired without a decision",
		"Bekletilen 1 işlemin süresi karar verilmeden doldu",
	],
	"gr.expired.many": [
		"{count} held actions expired without a decision",
		"Bekletilen {count} işlemin süresi karar verilmeden doldu",
	],
	"gr.expiredDetail": [
		"Nobody approved or denied these requests in time; the agent action stayed blocked.",
		"Bu isteklere zamanında kimse onay ya da ret vermedi; yapay zekâ aracının işlemi engelli kaldı.",
	],
	"gr.mcp.one": ["1 MCP server not approved", "1 MCP sunucusu onaylanmadı"],
	"gr.mcp.many": ["{count} MCP servers not approved", "{count} MCP sunucusu onaylanmadı"],
	"gr.mcpDetail": [
		"Reported by inventory scans without an approved attestation.",
		"Envanter taramalarında onaylı bir beyan olmadan bildirildi.",
	],
	"gr.noPolicy": ["No workspace runtime policy", "Çalışma alanı çalışma zamanı politikası yok"],
	"gr.noPolicyDetail": [
		"Managed agents use their local defaults; there is no versioned workspace policy to review.",
		"Yönetilen yapay zekâ araçları yerel varsayılanlarını kullanır; gözden geçirilecek sürümlü bir çalışma alanı politikası yok.",
	],
	"gr.stale.one": [
		"Runtime policy unchanged for 1 day",
		"Çalışma zamanı politikası 1 gündür değişmedi",
	],
	"gr.stale.many": [
		"Runtime policy unchanged for {count} days",
		"Çalışma zamanı politikası {count} gündür değişmedi",
	],
	"gr.staleDetail": [
		"Periodic review is expected by most AI governance frameworks.",
		"Çoğu yapay zekâ yönetişimi çerçevesi düzenli gözden geçirme bekler.",
	],
	"gr.noRetention": ["No telemetry retention policy", "Telemetri saklama politikası yok"],
	"gr.noRetentionDetail": [
		"Decision logs have no configured retention period.",
		"Karar kayıtları için yapılandırılmış bir saklama süresi yok.",
	],
	"gr.short.one": ["Decision logs kept 1 day", "Karar kayıtları 1 gün saklanıyor"],
	"gr.short.many": ["Decision logs kept {count} days", "Karar kayıtları {count} gün saklanıyor"],
	"gr.shortDetail": [
		"Shorter than six months. Deployers of high-risk AI systems keep logs for at least six months (EU AI Act Art. 26(6)).",
		"Altı aydan kısa. Yüksek riskli yapay zekâ sistemlerini kullananlar kayıtları en az altı ay saklar (AB Yapay Zekâ Yasası Md. 26(6)).",
	],
	"gr.aup": [
		"Acceptable-use notice v{version} acknowledged on {installs} of {active} active browsers",
		"Kabul edilebilir kullanım bildirimi v{version}, {active} etkin tarayıcının {installs} tanesinde onaylandı",
	],
	"gr.aupDetail": [
		"Browsers that have not visited a protected AI site since the notice was published have not seen it yet.",
		"Bildirim yayımlandığından beri korunan bir yapay zekâ sitesini ziyaret etmeyen tarayıcılar onu henüz görmedi.",
	],
	"gr.nothing": [
		"No agents or browsers reported in this window",
		"Bu aralıkta hiçbir yapay zekâ aracı ya da tarayıcı bildirim yapmadı",
	],
	"gr.nothingDetail": [
		"Enroll coding agents or Browser Guard installs to populate the scorecard.",
		"Karneyi doldurmak için kodlama araçlarını ya da Browser Guard kurulumlarını kaydedin.",
	],
	"gs.fastSeconds": [
		"Fast-approval time must be a whole number of seconds from 1 to 3600.",
		"Hızlı onay süresi 1 ile 3600 arasında tam sayı saniye olmalıdır.",
	],
	"gs.minDecisions": [
		"Minimum decisions must be a whole number from 1 to 10000.",
		"En az karar sayısı 1 ile 10000 arasında bir tam sayı olmalıdır.",
	],
	"gs.fastShare": [
		"Fast-approval share must be between 50% and 100%.",
		"Hızlı onay oranı %50 ile %100 arasında olmalıdır.",
	],
	"ge.forbidden": [
		"Only active owners and admins of this workspace can open the governance scorecard.",
		"Yönetişim karnesini yalnızca bu çalışma alanının etkin sahipleri ve yöneticileri açabilir.",
	],
	"ge.barrier": [
		"Your session does not meet this workspace's sign-in policy (MFA or single sign-on). Sign in again.",
		"Oturumunuz bu çalışma alanının oturum açma politikasını (MFA ya da tek oturum açma) karşılamıyor. Yeniden oturum açın.",
	],
	"ge.malformed": [
		"The scorecard received was incomplete, so it is not shown. Refresh to try again.",
		"Alınan karne eksikti; bu yüzden gösterilmiyor. Yeniden denemek için yenileyin.",
	],
	"ge.window": ["Choose a 7, 30 or 90 day window.", "7, 30 ya da 90 günlük bir aralık seçin."],
	"ge.settings": [
		"The settings are out of range. Check the values and try again.",
		"Ayarlar izin verilen aralığın dışında. Değerleri kontrol edip yeniden deneyin.",
	],
	"ge.mail": [
		"This deployment has no e-mail transport configured, so the summary was not sent. Ask your operator to configure mail delivery.",
		"Bu kurulumda e-posta gönderimi yapılandırılmamış; bu yüzden özet gönderilmedi. Operatörünüzden e-posta gönderimini yapılandırmasını isteyin.",
	],
	"ge.rateLimited": [
		"Too many test summaries were requested. Wait a minute and try again.",
		"Çok fazla deneme özeti istendi. Bir dakika bekleyip yeniden deneyin.",
	],
	"ge.role": [
		"Only workspace owners and admins can send a test summary.",
		"Deneme özetini yalnızca çalışma alanı sahipleri ve yöneticileri gönderebilir.",
	],
	"ge.mfa": [
		"This workspace requires a multi-factor session. Sign in again with your second factor.",
		"Bu çalışma alanı çok adımlı doğrulanmış bir oturum gerektirir. İkinci doğrulama adımınızla yeniden oturum açın.",
	],
	"ge.sso": [
		"This workspace requires single sign-on. Sign in with your organization's identity provider.",
		"Bu çalışma alanı tek oturum açma gerektirir. Kuruluşunuzun kimlik sağlayıcısıyla oturum açın.",
	],
	"ge.unavailable": [
		"The governance data is unavailable right now. Try again later.",
		"Yönetişim verileri şu anda alınamıyor. Daha sonra yeniden deneyin.",
	],
} as const satisfies MessagePairs<string>;

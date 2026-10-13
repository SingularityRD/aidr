import type { MessagePairs } from "./define";

/** Onboarding page (workspace creation, trial, manual setup and device authorization). */
export const onboardingMessages = {
	"onb.checkingTeam": ["Checking team access…", "Ekip erişimi denetleniyor…"],
	"onb.selectTeam": [
		"Select a team to enroll an agent.",
		"Yapay zekâ aracı kaydetmek için bir ekip seçin.",
	],
	"onb.create.storageFailed": [
		"Saved workspace request could not be checked.",
		"Kaydedilmiş çalışma alanı isteği denetlenemedi.",
	],
	"onb.create.title": ["Create your team workspace", "Ekip çalışma alanınızı oluşturun"],
	"onb.create.body": [
		"Create an owned team before starting your one-agent trial.",
		"Tek yapay zekâ aracı için denemenizi başlatmadan önce sahibi olduğunuz bir ekip oluşturun.",
	],
	"onb.create.unconfirmed": [
		"Workspace creation was not confirmed. Retry this saved request; it will return the same workspace rather than create another.",
		"Çalışma alanının oluşturulduğu doğrulanmadı. Kaydedilen bu isteği yeniden deneyin; yeni bir çalışma alanı oluşturmaz, aynı çalışma alanını döndürür.",
	],
	"onb.create.teamName": ["Team name", "Ekip adı"],
	"onb.create.creating": ["Creating team…", "Ekip oluşturuluyor…"],
	"onb.create.retry": ["Retry workspace creation", "Çalışma alanı oluşturmayı yeniden dene"],
	"onb.create.submit": ["Create team", "Ekip oluştur"],

	"onb.code.expired": [
		"This authorization code expired. Generate a new code to continue.",
		"Bu yetkilendirme kodunun süresi doldu. Devam etmek için yeni bir kod oluşturun.",
	],
	"onb.code.rejected": [
		"Authorization could not continue. This code was rejected or already used. Generate a new code.",
		"Yetkilendirme devam edemedi. Bu kod reddedildi ya da zaten kullanıldı. Yeni bir kod oluşturun.",
	],
	"onb.code.retrying": [
		"We could not check authorization yet. Retrying automatically.",
		"Yetkilendirme henüz denetlenemedi. Otomatik olarak yeniden deneniyor.",
	],
	"onb.code.noToken": [
		"Authorization completed, but no usable enrollment token was returned. Generate a new code.",
		"Yetkilendirme tamamlandı ancak kullanılabilir bir kayıt belirteci dönmedi. Yeni bir kod oluşturun.",
	],
	"onb.code.unknownState": [
		"The authorization service returned an unknown state. Please generate a new code.",
		"Yetkilendirme hizmeti bilinmeyen bir durum döndürdü. Lütfen yeni bir kod oluşturun.",
	],
	"onb.token.expired": [
		"The enrollment token expired. Generate a new authorization code.",
		"Kayıt belirtecinin süresi doldu. Yeni bir yetkilendirme kodu oluşturun.",
	],
	"onb.trial.unconfirmed": [
		"Trial activation was not confirmed. Refresh status or contact support.",
		"Denemenin başlatıldığı doğrulanmadı. Durumu yenileyin ya da destek ekibiyle iletişime geçin.",
	],
	"onb.trial.unavailable": ["Trial activation is unavailable.", "Deneme başlatma kullanılamıyor."],

	"onb.team": ["Team: {name}", "Ekip: {name}"],
	"onb.cannotEnroll": [
		"Your role cannot enroll agents for this team.",
		"Rolünüz bu ekip için yapay zekâ aracı kaydedemez.",
	],
	"onb.intro": [
		"Install AIDR with the installer below. The manual steps further down are only for computers where the installer cannot run.",
		"AIDR'yi aşağıdaki yükleyiciyle kurun. Daha aşağıdaki elle kurulum adımları yalnızca yükleyicinin çalıştırılamadığı bilgisayarlar içindir.",
	],
	"onb.access": ["Workspace access", "Çalışma alanı erişimi"],
	"onb.accessChecking": ["Checking workspace access…", "Çalışma alanı erişimi denetleniyor…"],
	"onb.accessUnknown": [
		"Workspace access could not be checked. Retry before generating a code.",
		"Çalışma alanı erişimi denetlenemedi. Kod oluşturmadan önce yeniden deneyin.",
	],
	"onb.legal": [
		"I have reviewed the {terms} and {privacy}.",
		"{terms} ve {privacy} belgelerini inceledim.",
	],
	"onb.legal.terms": ["Terms ({version})", "Koşullar ({version})"],
	"onb.legal.privacy": ["Privacy Notice ({version})", "Gizlilik Bildirimi ({version})"],
	"onb.trial.starting": ["Starting trial…", "Deneme başlatılıyor…"],
	"onb.trial.start": [
		"Start 14-day trial · 1 agent",
		"14 günlük denemeyi başlat · 1 yapay zekâ aracı",
	],
	"onb.trial.needsLegal": [
		"Trial activation is unavailable until Terms and Privacy are published.",
		"Koşullar ve Gizlilik belgeleri yayımlanana kadar deneme başlatılamaz.",
	],
	"onb.trial.awaitsLegal": [
		"Trial setup awaits published Terms and Privacy. Contact your administrator.",
		"Deneme kurulumu, Koşullar ve Gizlilik belgelerinin yayımlanmasını bekliyor. Yöneticinizle iletişime geçin.",
	],
	"onb.trial.none": [
		"No self-service trial is available for this workspace. Contact your administrator or sales.",
		"Bu çalışma alanı için kendi başınıza başlatabileceğiniz bir deneme yok. Yöneticinizle ya da satış ekibiyle iletişime geçin.",
	],
	"onb.retryStatus": ["Retry status", "Durumu yeniden denetle"],
	"onb.pilot": ["View / request pilot", "Pilotu görüntüle / iste"],
	"onb.trial.active": ["Trial active · {count} agent", "Deneme etkin · {count} yapay zekâ aracı"],
	"onb.trial.ends": [" · ends {time}", " · bitiş {time}"],

	"onb.manual.runtime": ["1) Choose your AI tool", "1) Yapay zekâ aracınızı seçin"],
	"onb.manual.prompt": ["Prompt to give your agent", "Yapay zekâ aracınıza verilecek mesaj"],
	"onb.manual.promptCopied": ["Prompt copied", "İstem kopyalandı"],
	"onb.manual.copyPrompt": ["Copy prompt", "İstemi kopyala"],
	"onb.manual.copyBlocked": [
		"Clipboard access was blocked. Select the prompt above and copy it manually.",
		"Panoya erişim engellendi. Yukarıdaki mesajı seçip elle kopyalayın.",
	],
	"onb.manual.promptNote": [
		"The prompt is in English on purpose: the AI tool follows it word for word. It installs the exact release version, asks you for the release verification key, and never asks you to paste API keys.",
		"İstem bilerek İngilizcedir: yapay zekâ aracı onu kelimesi kelimesine uygular. Tam sürüm numarasını kurar, sürüm doğrulama anahtarını sizden ister ve asla API anahtarı yapıştırmanızı istemez.",
	],
	"onb.manual.noVersion": [
		"The release version is not available on this dashboard yet, so the prompt tells the AI tool to stop and ask you for the approved version.",
		"Sürüm numarası bu panelde henüz yok; bu yüzden mesaj, yapay zekâ aracına durup sizden onaylı sürümü istemesini söyler.",
	],
	"onb.manual.releaseKey": [
		"Manual setup needs the release verification key. Ask your administrator for the key file and run {command} once on this computer; until then AIDR blocks every tool call. The installer above does this for you.",
		"Elle kurulum, sürüm doğrulama anahtarını gerektirir. Yöneticinizden anahtar dosyasını isteyin ve bu bilgisayarda bir kez {command} komutunu çalıştırın; o zamana kadar AIDR her araç çağrısını engeller. Yukarıdaki yükleyici bunu sizin yerinize yapar.",
	],
	"onb.manual.download": ["2) Download & connect", "2) İndirin ve bağlayın"],
	"onb.manual.downloadBody": [
		"Download the verified installer for this AI tool, check its digest, install it and connect it to this team. {link}",
		"Bu yapay zekâ aracı için doğrulanmış yükleyiciyi indirin, özetini denetleyin, kurun ve bu ekibe bağlayın. {link}",
	],
	"onb.manual.allDownloads": ["All downloads", "Tüm indirmeler"],
	"onb.manual.authorize": ["3) Authorize", "3) Yetkilendirin"],
	"onb.manual.authorizeBody": [
		"Use the verify page for a code shown by your AI tool. Generate a code here only if you need a manual enrollment token.",
		"Yapay zekâ aracınızın gösterdiği kod için doğrulama sayfasını kullanın. Burada yalnızca elle kayıt belirtecine ihtiyacınız varsa kod oluşturun.",
	],
	"onb.code.notConfirmed": [
		"The authorization service did not confirm a code.",
		"Yetkilendirme hizmeti bir kodu doğrulamadı.",
	],
	"onb.code.incomplete": [
		"The authorization service returned an incomplete code. Please retry.",
		"Yetkilendirme hizmeti eksik bir kod döndürdü. Lütfen yeniden deneyin.",
	],
	"onb.code.startFailed": [
		"Could not start authorization. Please retry.",
		"Yetkilendirme başlatılamadı. Lütfen yeniden deneyin.",
	],
	"onb.code.generating": ["Generating code…", "Kod oluşturuluyor…"],
	"onb.code.generate": ["Generate code", "Kod oluştur"],
	"onb.code.openVerify": ["Open verify page", "Doğrulama sayfasını aç"],
	"onb.code.cancel": ["Cancel authorization", "Yetkilendirmeyi iptal et"],
	"onb.code.yours": ["Your code", "Kodunuz"],
	"onb.code.url": ["Verification URL", "Doğrulama adresi"],
	"onb.code.expires": ["Expires:", "Bitiş:"],
	"onb.code.soon": ["soon", "yakında"],
	"onb.code.authorizeBrowser": ["Authorize in browser", "Tarayıcıda yetkilendir"],
	"onb.code.alreadyOpened": ["I already opened it", "Zaten açtım"],
	"onb.code.waiting": ["Waiting for authorization…", "Yetkilendirme bekleniyor…"],
	"onb.code.authorized": ["Authorized.", "Yetkilendirildi."],
	"onb.code.authorizedBody": [
		"Use the enrollment token below in your local runtime setup, then check the Agents page to confirm protection.",
		"Aşağıdaki kayıt belirtecini yerel kurulumunuzda kullanın, ardından korumayı doğrulamak için Yapay zekâ araçları sayfasına bakın.",
	],
	"onb.token.fallback": [
		"Fallback enrollment token (advanced; copy once, then clear it from this screen):",
		"Yedek kayıt belirteci (gelişmiş; bir kez kopyalayın, sonra bu ekrandan temizleyin):",
	],
	"onb.token.expiresAt": ["Expires at {time}", "Bitiş: {time}"],
	"onb.token.label": ["Enrollment token", "Kayıt belirteci"],
	"onb.token.hide": ["Hide", "Gizle"],
	"onb.token.reveal": ["Reveal", "Göster"],
	"onb.token.copyBlocked": [
		"Clipboard access was blocked. Reveal the token and copy it manually.",
		"Panoya erişim engellendi. Belirteci gösterip elle kopyalayın.",
	],
	"onb.token.copied": ["Copied", "Kopyalandı"],
	"onb.token.copy": ["Copy", "Kopyala"],
	"onb.token.clear": ["Clear", "Temizle"],
	"onb.token.cleared": [
		"The enrollment token was cleared from this screen. Generate a new code if setup still needs one.",
		"Kayıt belirteci bu ekrandan temizlendi. Kurulum hâlâ gerektiriyorsa yeni bir kod oluşturun.",
	],
	"onb.viewAgents": ["View agents", "Yapay zekâ araçlarını görüntüle"],
	"onb.viewIncidents": ["View incidents", "Vakaları görüntüle"],
	"onb.code.expiredRetry": [
		"Authorization expired. Generate a new code and try again.",
		"Yetkilendirmenin süresi doldu. Yeni bir kod oluşturup yeniden deneyin.",
	],
} as const satisfies MessagePairs<string>;

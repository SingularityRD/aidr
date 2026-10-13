import type { DashboardMessageKey } from "./en";

/** Turkish dashboard strings; the type makes a missing or extra key a compile error. */
export const tr: Record<DashboardMessageKey, string> = {
	"language.switchToLabel": "Paneli İngilizceye geçir",
	"theme.toDark": "Koyu temaya geç",
	"theme.toLight": "Açık temaya geç",

	"layout.skip": "İçeriğe geç",
	"layout.controlPlane": "Kontrol düzlemi",
	"layout.navLabel": "Panel",
	"layout.resolvingTenant": "Yönetilen kiracı belirleniyor…",
	"layout.teamLoadFailed": "Ekip üyeliğiniz yüklenemedi.",
	"layout.signingOut": "Bu tarayıcı oturumu sonlandırılıyor…",
	"layout.signOut": "Oturumu kapat",
	"layout.envIncomplete": "Panel ortam yapılandırması eksik.",
	"layout.pendingCount": ", bekleyen: ",
	"nav.connect": "Bağlan",
	"nav.downloads": "İndirmeler",
	"nav.dashboard": "Panel",
	"nav.billing": "Faturalandırma",
	"nav.apiKeys": "API Anahtarları",
	"nav.agents": "Ajanlar",
	"nav.events": "Olaylar",
	"nav.discovery": "Keşif",
	"nav.posture": "Güvenlik Duruşu",
	"nav.incidents": "Olay Kayıtları",
	"nav.approvals": "Onaylar",
	"nav.browserPrivacy": "Tarayıcı Gizliliği",
	"nav.autosecops": "AutoSecOps",
	"nav.settings": "Ayarlar",
	"nav.team": "Ekip",
	"nav.scim": "Dizin senkronizasyonu",
	"nav.retention": "Yasal saklama ve veri saklama",
	"nav.sso": "Çoklu oturum açma (SSO)",
	"nav.policies": "Politikalar",
	"nav.siem": "SIEM aktarımı",
	"nav.compliance": "Uyum",
	"nav.governance": "Yönetişim",
	"nav.detectionExceptions": "Tespit istisnaları",
	"nav.aiRegister": "Yapay zekâ envanteri",

	"public.navLabel": "Genel",
	"public.editions": "Sürümler",
	"public.pilot": "Pilot",
	"public.dashboard": "Panel",
	"public.signIn": "Oturum aç",
	"public.noCredentials": "Panel, Supabase kimlik bilgileri olmadan çalışıyor.",
	"public.footer": "Singularity AIDR. Yerel öncelikli yapay zekâ ajanı tespit ve müdahale.",
	"public.footerLabel": "Destek ve yasal bilgiler",
	"public.support": "Destek",
	"public.status": "Durum",
	"public.privacy": "Gizlilik",
	"public.security": "Güvenlik",
	"public.terms": "Koşullar",

	"notFound.title": "Sayfa bulunamadı",
	"notFound.body": "Bağlantı eskimiş ya da sayfa taşınmış olabilir.",
	"common.backHome": "Ana sayfaya dön",
	"error.eyebrow": "Hata",
	"error.title": "Bir şeyler ters gitti",
	"error.notFound": "Bu panel sayfası mevcut değil.",
	"error.generic": "Panel bu isteği tamamlayamadı.",
	"error.retry": "Yeniden dene",
	"config.eyebrow": "Yapılandırma gerekli",
	"config.title": "Panel yapılandırması eksik",
	"config.body":
		"Bu üretim dağıtımı Supabase'e bağlı değil. Müşterileri davet etmeden önce gerekli genel ortam değişkenlerini yapılandırıp yeniden dağıtın.",

	"plan.checking": "Planınız kontrol ediliyor…",
	"plan.unavailable":
		"Plan bilgisi alınamadığı için bu sayfa gösterilmiyor. Biraz sonra yeniden deneyin.",
	"plan.includedFrom":
		"{feature}, {plan} sürümünden itibaren dahildir. Bu çalışma alanı {current} sürümünde{why}.",
	"plan.inactive": ", çünkü lisansı ya da kabulü etkin değil",
	"plan.upgrade": "Planları görüntüle ve yükselt",

	"login.welcome": "AIDR'ye hoş geldiniz",
	"login.subtitleRegister": "Yapay zekâ ajanlarınızı korumak için bir hesap oluşturun",
	"login.subtitleSignIn": "Yapay zekâ ajanlarınızı korumak için oturum açın",
	"login.revocationUnconfirmed":
		"Bu tarayıcıda oturum kapatıldı ancak diğer oturumların iptali doğrulanamadı. Bu oturumların sonlandırılması gerekiyorsa yöneticinizle iletişime geçin.",
	"login.localSignOutFailed":
		"Bu tarayıcıda oturumun kapatıldığı doğrulanamadı. Bu sekmeyi kapatın ve yöneticinizden etkin oturumları iptal etmesini isteyin.",
	"login.continueWith": "{provider} ile devam et",
	"login.companySso": "şirket SSO",
	"login.ssoFormLabel": "Şirket çoklu oturum açma",
	"login.ssoEmailLabel": "Çoklu oturum açma için iş e-postası",
	"login.ssoContinue": "İş e-postası SSO ile devam et",
	"login.orEmail": "ya da e-posta ile devam edin",
	"login.email": "E-posta adresi",
	"login.teamName": "Ekip ya da kuruluş adı",
	"login.password": "Parola",
	"login.confirmPassword": "Parolayı onaylayın",
	"login.wait": "Lütfen bekleyin…",
	"login.createAccount": "Hesap oluştur",
	"login.signIn": "Oturum aç",
	"login.sendMagicLink": "Giriş bağlantısı gönder",
	"login.emailLink": "E-postayla giriş bağlantısı gönder",
	"login.forgot": "Parolanızı mı unuttunuz ya da ikinci doğrulama adımınızı mı kaybettiniz?",
	"login.haveAccount": "Zaten hesabınız var mı? Oturum açın",
	"login.newAccount": "AIDR'de yeni misiniz? Hesap oluşturun",
	"login.notConfigured": "Oturum açma yapılandırılmamış. Yöneticinizle iletişime geçin.",
	"login.backHome": "← Ana sayfaya dön",
	"login.noteConfirm": "Bir çalışma alanı kurmadan önce e-posta adresinizi doğrulayın.",
	"login.noteAdmin": "Yöneticinizin size verdiği hesabı kullanın.",
	"login.sessionCheckFailed": "Oturumunuz kontrol edilemedi. Lütfen yeniden deneyin.",
	"login.passwordFailed":
		"Oturum açılamadı. E-posta adresinizi ve parolanızı kontrol edin ya da yöneticinizle iletişime geçin.",
	"login.emailLimited":
		"E-posta gönderimi geçici olarak sınırlandırıldı. Lütfen daha sonra yeniden deneyin.",
	"login.linkFailed": "Giriş bağlantısı gönderilemedi. Yöneticinizle iletişime geçin.",
	"login.linkSent": "Bu hesap etkinse giriş bağlantısı için gelen kutunuzu kontrol edin.",
	"login.unavailable": "Oturum açma şu anda kullanılamıyor. Lütfen yeniden deneyin.",
	"login.teamNameInvalid":
		"Denetim karakteri içermeyen, en fazla 200 karakterlik bir ekip adı girin.",
	"login.passwordMismatch": "Parolalar eşleşmiyor.",
	"login.registerFailed":
		"Hesap oluşturulamadı. Parola gereksinimlerini kontrol edin ya da destek ekibiyle iletişime geçin.",
	"login.confirmationDisabled": "E-posta doğrulaması etkin değil. Hesap kaydı kullanılamıyor.",
	"login.registerSent":
		"Bu adres uygunsa doğrulama bağlantısı için gelen kutunuzu kontrol edin. Kuruluma devam etmek için bağlantıyı bu tarayıcıda açın.",
	"login.registerUnavailable":
		"Hesap kaydı şu anda kullanılamıyor. Lütfen daha sonra yeniden deneyin.",
	"login.companyUnavailable": "Şirket oturum açma kullanılamıyor. Yöneticinizle iletişime geçin.",
	"login.providerUnavailable":
		"Bu oturum açma sağlayıcısı kullanılamıyor. Yöneticinizle iletişime geçin.",

	"downloads.title": "İndir",
	"downloads.intro":
		"AIDR'yi {team} için üç adımda kurun: yükleyiciyi indirin, çalıştırın ve yapay zekâ araçlarınızı yeniden başlatın.",
	"downloads.yourTeam": "ekibiniz",
	"downloads.checkingTeam": "Ekip erişimi denetleniyor…",
	"downloads.noTeam": "Yükleyicileri indirmek için bir çalışma alanı seçin veya oluşturun.",
	"downloads.backToOnboarding": "Kuruluma dön",
	"downloads.viewAgents": "Ajanları görüntüle",
	"downloads.retry": "Yeniden dene",
	"downloads.os.windows": "Windows",
	"downloads.os.linux": "Linux",
	"downloads.installer.title": "AIDR yükleyicisini indirin",
	"downloads.installer.intro":
		"Tek bir yükleyici bu bilgisayardaki desteklenen tüm yapay zekâ araçlarını korur: Claude Code, Cursor, VS Code, Codex, OpenCode ve OpenClaw.",
	"downloads.installer.loading": "Yükleyici kataloğu yükleniyor…",
	"downloads.installer.version": "Sürüm {version} · yayın tarihi {date}",
	"downloads.installer.releaseNotes": "Sürüm notları",
	"downloads.installer.recommended": "Bu bilgisayar için önerilen",
	"downloads.installer.other": "Diğer platformlar",
	"downloads.installer.download": "{file} dosyasını indir",
	"downloads.installer.preparing": "İndirme hazırlanıyor…",
	"downloads.installer.started":
		"İndirme başladı. Başlamadıysa {link} ({time} saatine kadar geçerli).",
	"downloads.installer.directLink": "bu doğrudan bağlantıyı kullanın",
	"downloads.installer.meta": "{size} · gereksinim: {minOs}",
	"downloads.installer.sha256": "SHA-256",
	"downloads.installer.verify": "İndirilen dosyayı çalıştırmadan önce denetleyin:",
	"downloads.installer.copy": "Kopyala",
	"downloads.installer.copied": "Kopyalandı",
	"downloads.installer.copyChecksum": "{file} için sağlama toplamı komutunu kopyala",
	"downloads.installer.copyBlocked": "Panoya erişim engellendi. Komutu seçip elle kopyalayın.",
	"downloads.installer.verifyNote":
		"Komut Windows'ta True, Linux'ta OK yazar. Yazmazsa yükleyiciyi çalıştırmayın.",
	"downloads.installer.macos":
		"macOS yükleyicisi henüz sunulmuyor. Aşağıdaki Browser Guard, macOS üzerinde Chrome, Edge ve Firefox'ta çalışır.",
	"downloads.installer.noMatch":
		"Bu tarayıcının işletim sistemi için yayımlanmış bir yükleyici yok. Uygunsa aşağıdaki platformlardan birini seçin.",
	"downloads.installer.step1":
		"İşletim sisteminize uygun yükleyiciyi indirin ve SHA-256 değerini denetleyin.",
	"downloads.installer.step2":
		"Çalıştırın: Windows'ta çift tıklayın, Linux'ta betiği sh ile çalıştırın.",
	"downloads.installer.step3":
		"Yapay zekâ araçlarınızı yeniden başlatın. aidr status komutu korumanın açık olduğunu gösterir.",
	"downloads.error.entitlement":
		"İndirmek için bu çalışma alanının etkin bir lisansı veya denemesi olmalıdır. Yöneticinize danışın ya da kurulum sayfasından deneme başlatın.",
	"downloads.error.unpublished":
		"Bu kurulum için henüz bir yükleyici yayımlanmadı. Sürüm sorumlunuza danışın.",
	"downloads.error.integrity":
		"Yükleyici kataloğu imza denetiminden geçemedi; bu nedenle indirme sunulmuyor. Destek ekibiyle iletişime geçin.",
	"downloads.error.forbidden": "Hesabınız bu çalışma alanı için yükleyici indiremez.",
	"downloads.error.rateLimited": "Çok fazla istek gönderildi. Bir dakika bekleyip yeniden deneyin.",
	"downloads.error.generic": "Yükleyiciler şu anda kullanılamıyor. Biraz sonra yeniden deneyin.",
	"downloads.error.download": "İndirme bağlantısı oluşturulamadı. Yeniden deneyin.",
	"downloads.managed.title": "Bu bilgisayarı çalışma alanınıza bağlayın (yönetilen mod)",
	"downloads.managed.body":
		"Kurulumdan sonra korunan bir yapay zekâ aracı ilk açılışta kısa bir kod gösterir. Bu kodu doğrulama sayfasında bu çalışma alanı için onaylayın. Bu çalışma alanının kontrol düzlemi adresi:",
	"downloads.managed.verify": "Cihaz kodunu doğrula",
	"downloads.managed.advanced": "Elle kayıt (gelişmiş)",
	"downloads.bg.title": "Browser Guard uzantısı",
	"downloads.bg.body":
		"Windows, macOS ve Linux üzerinde Chrome, Edge ve Firefox'ta istemler yapay zekâ sohbet sitelerine ulaşmadan önce kişisel verileri ve gizli bilgileri maskeler.",
	"downloads.bg.chrome": "Chrome'a ekle",
	"downloads.bg.edge": "Edge'e ekle",
	"downloads.bg.firefox": "Firefox'a ekle",
	"downloads.bg.none":
		"Bu kurulum için mağaza bağlantıları yapılandırılmamış. Yöneticinize danışın.",
	"downloads.bg.ids": "BT ilkesi için uzantı kimlikleri",
	"downloads.bg.chromeId": "Chrome",
	"downloads.bg.edgeId": "Edge",
	"downloads.bg.firefoxId": "Firefox",
	"downloads.it.title": "BT / MDM dağıtımı",
	"downloads.it.body":
		"Aynı yükleyicileri Intune veya Grup İlkesi ile sessizce dağıtın; Browser Guard'ı tarayıcı ilkesiyle uzantı kimliği üzerinden zorunlu kurun.",
	"downloads.it.guide": "Yönetici kılavuzunu aç",
	"downloads.it.guideMissing":
		"Yönetici kılavuzu sürüm paketinizle birlikte gelir (docs/installation/download-portal.md).",
	"downloads.advanced.title": "Tek tek bağlayıcı paketleri (gelişmiş)",
	"onboarding.install.title": "1) Yükleyiciyi indirip çalıştırın",
	"onboarding.install.body":
		"Yükleyici bu bilgisayardaki desteklenen tüm yapay zekâ araçlarını korur. Önerilen kurulum budur.",
	"onboarding.install.allDownloads": "İndirme sayfasını aç",
	"onboarding.advanced.summary": "Gelişmiş: elle kurulum ve cihaz yetkilendirme",
	"onboarding.advanced.body":
		"Bu adımları yalnızca yükleyiciyi çalıştıramıyorsanız ya da tek bir bağlayıcıyı elle kaydetmek için kullanın.",
};

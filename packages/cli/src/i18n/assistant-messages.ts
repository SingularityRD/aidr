/**
 * `aidr assistant` (the Singularity AIDR Setup Assistant) texts, en/tr. The
 * terminal lines (`assistant.cli.*`) are printed by the command; every other key
 * is shown by the wizard in the browser, which receives both catalogs and lets
 * the person switch language. `{name}` marks a parameter.
 *
 * Plain words only: "AI tool" / "yapay zekâ aracı", "company" / "şirket".
 * Commands, file names and product names stay as they are in every locale.
 */
export const ASSISTANT_EN = {
	"assistant.cli.running": "Singularity AIDR Setup Assistant is open in your browser.",
	"assistant.cli.openManually": "If the browser did not open, copy this address into it:",
	"assistant.cli.noOpen": "Open this address in a browser on this computer:",
	"assistant.cli.oneUse":
		"The address works once, only on this computer. Do not share it. Press Ctrl+C to stop.",
	"assistant.cli.openFailed": "Could not open the browser ({reason}).",
	"assistant.cli.closedDone": "Setup Assistant finished. Run it again anytime: aidr assistant",
	"assistant.cli.closedIdle":
		"Setup Assistant closed after 30 minutes without activity. Run it again anytime: aidr assistant",
	"assistant.cli.closedSignal": "Setup Assistant stopped.",

	"ui.title": "Setup Assistant",
	"ui.language": "Language",
	"ui.step": "Step {current} of {total}",
	"ui.steps": "Setup steps",
	"ui.next": "Next",
	"ui.back": "Back",
	"ui.retry": "Try again",
	"ui.working": "Working…",
	"ui.details": "Details",
	"ui.copy": "Copy",
	"ui.copied": "Copied",
	"ui.preview": "Preview",
	"ui.expired":
		"This Setup Assistant link has already been used or has expired. Close this tab and run 'aidr assistant' again in a terminal.",
	"ui.connectionLost":
		"The Setup Assistant on this computer is not answering. It stops after 30 minutes without activity. Run 'aidr assistant' again.",
	"ui.error": "Something went wrong: {detail}",

	"step.welcome": "Welcome",
	"step.tools": "AI tools",
	"step.company": "Company",
	"step.protect": "Protect",
	"step.verify": "Check",
	"step.browser": "Browser",
	"step.done": "Done",

	"welcome.heading": "Protect the AI tools on this computer",
	"welcome.body":
		"Singularity AIDR checks every command, file change and web request your AI coding tools try, and stops the dangerous ones before they run.",
	"welcome.local":
		"Protection runs on this computer. It needs no account and keeps working without a network.",
	"welcome.time": "This takes about two minutes. Nothing changes until you press Protect.",
	"welcome.start": "Start",

	"tools.heading": "AI tools found on this computer",
	"tools.body": "Choose the tools Singularity AIDR should protect.",
	"tools.none":
		"No supported AI tool was found yet. Install one (Claude Code, Cursor, VS Code, Codex, OpenCode or OpenClaw), then run 'aidr assistant' again.",
	"tools.noneSelected": "Choose at least one AI tool to continue.",
	"tools.rescan": "Look again",
	"badge.installed": "AIDR set up",
	"badge.runtime_present_not_installed": "Found, not protected yet",
	"badge.not_detected": "Not installed",
	"badge.unavailable": "Could not check",
	"badge.installed_but_degraded": "Needs attention",

	"company.heading": "Company connection",
	"company.body":
		"You can use Singularity AIDR on its own, or connect it to your company's AIDR dashboard for central rules, reports and approvals.",
	"company.local": "Local protection only",
	"company.localHint": "Recommended if your IT team did not give you a company address.",
	"company.connect": "Connect to my company",
	"company.connectHint":
		"Your IT team gives you the address of your company's AIDR dashboard. Someone in your company approves this computer.",
	"company.url": "Company address (https://…)",
	"company.urlInvalid": "Enter the full https:// address your IT team gave you.",
	"company.getCode": "Get a connection code",
	"company.fromInstaller":
		"The installer saved your company address: {url}. Press 'Get a connection code' to continue.",
	"company.fromInstallerToken":
		"The installer saved your company address and a connection key: {url}. Press 'Connect now' to finish.",
	"company.connectNow": "Connect now",
	"company.pendingIgnored":
		"A saved company connection was found but it is not protected (other users could read or change it), so it was not used. Enter the address yourself.",
	"company.code": "Your connection code",
	"company.codeHelp":
		"Open the approval page, sign in with your company account and type this code. Approve only if you started this on your own computer just now.",
	"company.openPage": "Open the approval page",
	"company.waiting": "Waiting for approval… This page updates by itself.",
	"company.expiresAt": "The code is valid until {time}.",
	"company.connected": "Connected to {url}.",
	"company.already": "This computer is already connected to {url}.",
	"company.expired": "The code expired before it was approved.",
	"company.newCode": "Get a new code",
	"company.cancel": "Cancel",
	"company.denied": "The request was not approved. Ask your IT team, then try again.",
	"company.unreachable":
		"Could not reach {url}. Check the address and your network, then try again.",
	"company.notAidr":
		"{url} did not answer like a Singularity AIDR dashboard. Check the address with your IT team.",
	"company.noSeat":
		"Your company account cannot add this computer right now (no free seat or not active). Ask your IT team.",
	"company.repair":
		"Connecting needs your IT team: an earlier connection attempt did not finish cleanly. Run 'aidr doctor' in a terminal and send them the result. Local protection keeps working.",
	"company.failed": "Connecting did not work ({code}). Try again or ask your IT team.",
	"company.skipHint": "You can connect later by running 'aidr assistant' again.",

	"protect.heading": "Protect your AI tools",
	"protect.body":
		"Singularity AIDR now registers itself with the tools you chose. This is the same as running 'aidr setup'.",
	"protect.start": "Protect",
	"protect.running": "Setting up {tool}…",
	"protect.waiting": "Waiting",
	"protect.preparing": "Checking the protection rules…",
	"protect.rules": "{rules} protection rules loaded and tested.",
	"protect.protected": "Protected",
	"protect.restart": "Restart {tool} to turn protection on.",
	"protect.manual": "One step left. Run this in your own terminal:",
	"protect.failed": "Could not set up {tool}.",
	"protect.notSelected": "Not selected",
	"outcome.protected": "Protected",
	"outcome.restart": "Restart needed",
	"outcome.manual": "Manual step",
	"outcome.failed": "Failed",
	"outcome.not_selected": "Not selected",
	"protect.setupFailed": "Setup could not finish: {detail}",
	"protect.releaseKey":
		"This copy of Singularity AIDR cannot confirm it is genuine (release key problem): {detail}. Ask your IT team to reinstall it.",

	"verify.heading": "Check that protection works",
	"verify.body":
		"A harmless test command is handed to each tool's AIDR check. Nothing is run; AIDR must stop it.",
	"verify.start": "Run the check",
	"verify.again": "Check again",
	"verify.pass": "Working: AIDR stopped the test command.",
	"verify.fail": "Not working yet.",
	"verify.failHelp":
		"Restart {tool} and check again. If it still fails, run 'aidr doctor' in a terminal and send the result to your IT team. Do not uninstall Singularity AIDR to get unblocked.",
	"verify.skip":
		"This tool checks inside itself. Open {tool} once and confirm Singularity AIDR is listed there.",
	"verify.notRegistered": "Not set up",
	"verify.summaryPass": "{count} tool(s) checked and working.",
	"verify.summaryFail": "{count} tool(s) need attention.",
	"verify.summaryNone": "No tool could be checked from here yet.",

	"browser.heading": "Browser Guard",
	"browser.body":
		"Browser Guard hides personal and confidential data (ID numbers, IBANs, e-mail addresses, secrets) before a message reaches ChatGPT, Gemini, Claude, Copilot and other AI chat sites.",
	"browser.chrome": "Add to Chrome",
	"browser.edge": "Add to Edge",
	"browser.firefox": "Add to Firefox",
	"browser.dashboard": "Open the Download page of your AIDR dashboard",
	"browser.noLinks":
		"The store links are not set on this computer. You find them on the Download page of your company's AIDR dashboard, or your IT team sends them.",
	"browser.installed":
		"Already installed? Look for the Singularity AIDR Browser Guard icon in your browser toolbar (puzzle-piece menu). On a company computer your IT team may have installed it for you.",

	"done.heading": "All set",
	"done.restart": "Restart your AI tools so they load Singularity AIDR.",
	"done.summary": "Protected: {protected}. To restart: {restart}. Manual step: {manual}.",
	"done.none": "none",
	"done.dashboard": "Open your AIDR dashboard",
	"done.again": "Run again anytime: aidr assistant",
	"done.close": "Close the Setup Assistant",
	"done.closed": "The Setup Assistant has stopped. You can close this tab.",
	"done.quickstart": "Quick start",
	"done.qs1":
		"Open a new terminal and run 'aidr status'. Its last line lists protected tools, tools to restart and manual steps.",
	"done.qs2":
		"Run 'aidr verify'. It prints PASS, FAIL or SKIP per tool. SKIP means the check is inside the tool (OpenCode, OpenClaw).",
	"done.qs3":
		"When AIDR holds a risky action, the person at the keyboard runs 'aidr pending' and 'aidr approve <id>' in their own terminal. The AI tool can never approve its own action.",
	"done.qs4":
		"If something is off, run 'aidr doctor' and send its output, or the file from 'aidr support-bundle', to your IT team.",
} as const;

export type AssistantMessageKey = keyof typeof ASSISTANT_EN;

export const ASSISTANT_TR: Record<AssistantMessageKey, string> = {
	"assistant.cli.running": "Singularity AIDR Kurulum Yardımcısı tarayıcınızda açıldı.",
	"assistant.cli.openManually": "Tarayıcı açılmadıysa bu adresi tarayıcıya kopyalayın:",
	"assistant.cli.noOpen": "Bu adresi bu bilgisayardaki bir tarayıcıda açın:",
	"assistant.cli.oneUse":
		"Adres yalnızca bir kez ve yalnızca bu bilgisayarda çalışır. Kimseyle paylaşmayın. Durdurmak için Ctrl+C'ye basın.",
	"assistant.cli.openFailed": "Tarayıcı açılamadı ({reason}).",
	"assistant.cli.closedDone":
		"Kurulum Yardımcısı tamamlandı. İstediğiniz zaman yeniden çalıştırabilirsiniz: aidr assistant",
	"assistant.cli.closedIdle":
		"Kurulum Yardımcısı 30 dakika işlem yapılmadığı için kapandı. İstediğiniz zaman yeniden çalıştırabilirsiniz: aidr assistant",
	"assistant.cli.closedSignal": "Kurulum Yardımcısı durduruldu.",

	"ui.title": "Kurulum Yardımcısı",
	"ui.language": "Dil",
	"ui.step": "Adım {current} / {total}",
	"ui.steps": "Kurulum adımları",
	"ui.next": "İleri",
	"ui.back": "Geri",
	"ui.retry": "Yeniden dene",
	"ui.working": "Çalışıyor…",
	"ui.details": "Ayrıntılar",
	"ui.copy": "Kopyala",
	"ui.copied": "Kopyalandı",
	"ui.preview": "Önizleme",
	"ui.expired":
		"Bu Kurulum Yardımcısı bağlantısı zaten kullanılmış ya da süresi dolmuş. Bu sekmeyi kapatın ve bir terminalde 'aidr assistant' komutunu yeniden çalıştırın.",
	"ui.connectionLost":
		"Bu bilgisayardaki Kurulum Yardımcısı yanıt vermiyor. 30 dakika işlem yapılmazsa kapanır. 'aidr assistant' komutunu yeniden çalıştırın.",
	"ui.error": "Bir sorun oluştu: {detail}",

	"step.welcome": "Hoş geldiniz",
	"step.tools": "Yapay zekâ araçları",
	"step.company": "Şirket",
	"step.protect": "Koruma",
	"step.verify": "Denetim",
	"step.browser": "Tarayıcı",
	"step.done": "Bitti",

	"welcome.heading": "Bu bilgisayardaki yapay zekâ araçlarını koruyun",
	"welcome.body":
		"Singularity AIDR, yapay zekâ kodlama araçlarınızın denediği her komutu, dosya değişikliğini ve web isteğini denetler; tehlikeli olanları çalışmadan önce durdurur.",
	"welcome.local":
		"Koruma bu bilgisayarda çalışır. Hesap gerektirmez ve ağ bağlantısı olmadan da çalışmaya devam eder.",
	"welcome.time": "Yaklaşık iki dakika sürer. Koru düğmesine basana kadar hiçbir şey değişmez.",
	"welcome.start": "Başla",

	"tools.heading": "Bu bilgisayarda bulunan yapay zekâ araçları",
	"tools.body": "Singularity AIDR'nin koruyacağı araçları seçin.",
	"tools.none":
		"Henüz desteklenen bir yapay zekâ aracı bulunamadı. Birini kurun (Claude Code, Cursor, VS Code, Codex, OpenCode ya da OpenClaw), ardından 'aidr assistant' komutunu yeniden çalıştırın.",
	"tools.noneSelected": "Devam etmek için en az bir yapay zekâ aracı seçin.",
	"tools.rescan": "Yeniden ara",
	"badge.installed": "AIDR kurulu",
	"badge.runtime_present_not_installed": "Bulundu, henüz korunmuyor",
	"badge.not_detected": "Kurulu değil",
	"badge.unavailable": "Denetlenemedi",
	"badge.installed_but_degraded": "İlgilenilmesi gerekiyor",

	"company.heading": "Şirket bağlantısı",
	"company.body":
		"Singularity AIDR'yi tek başına kullanabilir ya da merkezi kurallar, raporlar ve onaylar için şirketinizin AIDR paneline bağlayabilirsiniz.",
	"company.local": "Yalnızca yerel koruma",
	"company.localHint": "BT ekibiniz size bir şirket adresi vermediyse önerilir.",
	"company.connect": "Şirketime bağla",
	"company.connectHint":
		"Şirketinizin AIDR panelinin adresini BT ekibiniz verir. Şirketinizden biri bu bilgisayarı onaylar.",
	"company.url": "Şirket adresi (https://…)",
	"company.urlInvalid": "BT ekibinizin verdiği tam https:// adresini girin.",
	"company.getCode": "Bağlantı kodu al",
	"company.fromInstaller":
		"Kurulum programı şirket adresinizi kaydetti: {url}. Devam etmek için 'Bağlantı kodu al' düğmesine basın.",
	"company.fromInstallerToken":
		"Kurulum programı şirket adresinizi ve bir bağlantı anahtarını kaydetti: {url}. Bitirmek için 'Şimdi bağla' düğmesine basın.",
	"company.connectNow": "Şimdi bağla",
	"company.pendingIgnored":
		"Kayıtlı bir şirket bağlantısı bulundu ancak korunmuyor (başka kullanıcılar okuyabilir ya da değiştirebilir), bu yüzden kullanılmadı. Adresi kendiniz girin.",
	"company.code": "Bağlantı kodunuz",
	"company.codeHelp":
		"Onay sayfasını açın, şirket hesabınızla oturum açın ve bu kodu yazın. Yalnızca bu işlemi az önce kendi bilgisayarınızda başlattıysanız onaylayın.",
	"company.openPage": "Onay sayfasını aç",
	"company.waiting": "Onay bekleniyor… Bu sayfa kendiliğinden güncellenir.",
	"company.expiresAt": "Kod {time} saatine kadar geçerlidir.",
	"company.connected": "{url} adresine bağlandı.",
	"company.already": "Bu bilgisayar zaten {url} adresine bağlı.",
	"company.expired": "Kodun süresi onaylanmadan doldu.",
	"company.newCode": "Yeni kod al",
	"company.cancel": "Vazgeç",
	"company.denied": "İstek onaylanmadı. BT ekibinize danışıp yeniden deneyin.",
	"company.unreachable":
		"{url} adresine ulaşılamadı. Adresi ve ağ bağlantınızı denetleyip yeniden deneyin.",
	"company.notAidr":
		"{url} bir Singularity AIDR paneli gibi yanıt vermedi. Adresi BT ekibinizle denetleyin.",
	"company.noSeat":
		"Şirket hesabınız şu anda bu bilgisayarı ekleyemiyor (boş lisans yok ya da hesap etkin değil). BT ekibinize danışın.",
	"company.repair":
		"Bağlanmak için BT ekibinizin yardımı gerekiyor: önceki bir bağlantı denemesi düzgün tamamlanmadı. Bir terminalde 'aidr doctor' komutunu çalıştırıp sonucu onlara gönderin. Yerel koruma çalışmaya devam eder.",
	"company.failed": "Bağlantı kurulamadı ({code}). Yeniden deneyin ya da BT ekibinize danışın.",
	"company.skipHint":
		"Daha sonra 'aidr assistant' komutunu yeniden çalıştırarak bağlanabilirsiniz.",

	"protect.heading": "Yapay zekâ araçlarınızı koruyun",
	"protect.body":
		"Singularity AIDR şimdi seçtiğiniz araçlara kendini kaydeder. Bu, 'aidr setup' komutunu çalıştırmakla aynıdır.",
	"protect.start": "Koru",
	"protect.running": "{tool} kuruluyor…",
	"protect.waiting": "Sırada",
	"protect.preparing": "Koruma kuralları denetleniyor…",
	"protect.rules": "{rules} koruma kuralı yüklendi ve denendi.",
	"protect.protected": "Korunuyor",
	"protect.restart": "Korumayı açmak için {tool} uygulamasını yeniden başlatın.",
	"protect.manual": "Bir adım kaldı. Bunu kendi terminalinizde çalıştırın:",
	"protect.failed": "{tool} kurulamadı.",
	"protect.notSelected": "Seçilmedi",
	"outcome.protected": "Korunuyor",
	"outcome.restart": "Yeniden başlatma gerekli",
	"outcome.manual": "Elle yapılacak adım",
	"outcome.failed": "Başarısız",
	"outcome.not_selected": "Seçilmedi",
	"protect.setupFailed": "Kurulum tamamlanamadı: {detail}",
	"protect.releaseKey":
		"Bu Singularity AIDR kopyası gerçek olduğunu doğrulayamıyor (sürüm anahtarı sorunu): {detail}. BT ekibinizden yeniden kurmasını isteyin.",

	"verify.heading": "Korumanın çalıştığını denetleyin",
	"verify.body":
		"Her aracın AIDR denetimine zararsız bir deneme komutu verilir. Hiçbir şey çalıştırılmaz; AIDR'nin bu komutu durdurması gerekir.",
	"verify.start": "Denetimi çalıştır",
	"verify.again": "Yeniden denetle",
	"verify.pass": "Çalışıyor: AIDR deneme komutunu durdurdu.",
	"verify.fail": "Henüz çalışmıyor.",
	"verify.failHelp":
		"{tool} uygulamasını yeniden başlatıp tekrar denetleyin. Hâlâ başarısızsa bir terminalde 'aidr doctor' komutunu çalıştırıp sonucu BT ekibinize gönderin. Engeli aşmak için Singularity AIDR'yi kaldırmayın.",
	"verify.skip":
		"Bu araç denetimi kendi içinde yapar. {tool} uygulamasını bir kez açın ve Singularity AIDR'nin orada listelendiğini doğrulayın.",
	"verify.notRegistered": "Kurulmadı",
	"verify.summaryPass": "{count} araç denetlendi ve çalışıyor.",
	"verify.summaryFail": "{count} araçla ilgilenilmesi gerekiyor.",
	"verify.summaryNone": "Henüz buradan denetlenebilen bir araç yok.",

	"browser.heading": "Browser Guard",
	"browser.body":
		"Browser Guard, bir mesaj ChatGPT, Gemini, Claude, Copilot ve diğer yapay zekâ sohbet sitelerine ulaşmadan önce kişisel ve gizli bilgileri (T.C. kimlik numarası, IBAN, e-posta adresi, gizli anahtarlar) gizler.",
	"browser.chrome": "Chrome'a ekle",
	"browser.edge": "Edge'e ekle",
	"browser.firefox": "Firefox'a ekle",
	"browser.dashboard": "AIDR panelinizin İndirme sayfasını açın",
	"browser.noLinks":
		"Mağaza bağlantıları bu bilgisayarda tanımlı değil. Bunları şirketinizin AIDR panelindeki İndirme sayfasında bulabilirsiniz ya da BT ekibiniz gönderir.",
	"browser.installed":
		"Zaten kurulu mu? Tarayıcınızın araç çubuğunda (yapboz parçası menüsü) Singularity AIDR Browser Guard simgesine bakın. Şirket bilgisayarlarında BT ekibiniz sizin için kurmuş olabilir.",

	"done.heading": "Hazır",
	"done.restart": "Singularity AIDR'yi yüklemeleri için yapay zekâ araçlarınızı yeniden başlatın.",
	"done.summary":
		"Korunan: {protected}. Yeniden başlatılacak: {restart}. Elle yapılacak adım: {manual}.",
	"done.none": "yok",
	"done.dashboard": "AIDR panelinizi açın",
	"done.again": "İstediğiniz zaman yeniden çalıştırabilirsiniz: aidr assistant",
	"done.close": "Kurulum Yardımcısını kapat",
	"done.closed": "Kurulum Yardımcısı durdu. Bu sekmeyi kapatabilirsiniz.",
	"done.quickstart": "Hızlı başlangıç",
	"done.qs1":
		"Yeni bir terminal açıp 'aidr status' komutunu çalıştırın. Son satırı korunan araçları, yeniden başlatılacak araçları ve elle yapılacak adımları listeler.",
	"done.qs2":
		"'aidr verify' komutunu çalıştırın. Her araç için PASS, FAIL ya da SKIP yazar. SKIP, denetimin aracın içinde yapıldığı anlamına gelir (OpenCode, OpenClaw).",
	"done.qs3":
		"AIDR riskli bir işlemi beklettiğinde, bilgisayarın başındaki kişi kendi terminalinde 'aidr pending' ve 'aidr approve <id>' komutlarını çalıştırır. Yapay zekâ aracı kendi işlemini asla onaylayamaz.",
	"done.qs4":
		"Bir sorun varsa 'aidr doctor' komutunu çalıştırıp çıktısını ya da 'aidr support-bundle' dosyasını BT ekibinize gönderin.",
};

import type { MessagePairs } from "./define";

/** Per-connector download cards and their install steps (runtime catalog). */
export const downloadCenterMessages = {
	"dc.manifestFailed": [
		"The release manifest could not be loaded.",
		"Sürüm bildirimi yüklenemedi.",
	],
	"dc.copied": ["Copied", "Kopyalandı"],
	"dc.copy": ["Copy", "Kopyala"],
	"dc.copyBlocked": [
		"Clipboard blocked. Select the text and copy it.",
		"Pano engellendi. Metni seçip kopyalayın.",
	],
	"dc.noCheckIn": ["No control-plane check-in", "Kontrol düzlemine bildirim yapmaz"],
	"dc.checking": ["Checking check-ins…", "Bildirimler denetleniyor…"],
	"dc.checkInUnavailable": ["Check-in status unavailable", "Bildirim durumu alınamadı"],
	"dc.detected": ["Detected · last check-in {time}", "Algılandı · son bildirim {time}"],
	"dc.notDetected": ["Not detected yet", "Henüz algılanmadı"],
	"dc.download": ["Download {file}", "{file} dosyasını indir"],
	"dc.shaFor": ["SHA-256 for {label} {file}", "{label} {file} için SHA-256"],
	"dc.copySha": ["Copy SHA-256 for {file}", "{file} için SHA-256 değerini kopyala"],
	"dc.verifySummary": [
		"Verify the download before installing",
		"Kurmadan önce indirilen dosyayı doğrulayın",
	],
	"dc.verifyFail": [
		"Do not install the file if the check fails.",
		"Denetim başarısız olursa dosyayı kurmayın.",
	],
	"dc.signature": ["Detached signature for {file}", "{file} için ayrık imza"],
	"dc.signatureNote": [
		". Verify it with the publisher key your release operator delivered separately.",
		". Bunu, sürüm sorumlunuzun ayrıca ilettiği yayıncı anahtarıyla doğrulayın.",
	],
	"dc.noSignature": [
		"No detached signature is published for this file. Check the SHA-256 against your approved release record.",
		"Bu dosya için ayrık imza yayımlanmadı. SHA-256 değerini onaylı sürüm kaydınızla karşılaştırın.",
	],
	"dc.device": [
		"Start {label} once after installing. In managed mode it shows a short code and a verification URL; approve the code for this team. Restart the agent afterwards.",
		"Kurduktan sonra {label} uygulamasını bir kez başlatın. Yönetilen modda kısa bir kod ve doğrulama adresi gösterir; kodu bu ekip için onaylayın. Ardından aracı yeniden başlatın.",
	],
	"dc.verifyCode": ["Verify a device code", "Cihaz kodunu doğrula"],
	"dc.managedConfig": [
		"{label} has no device-code prompt. It enrolls through the signed runtime configuration your operator deploys to ~/.singularity-aidr/config.json.",
		"{label} cihaz kodu göstermez. Operatörünüzün ~/.singularity-aidr/config.json konumuna dağıttığı imzalı çalışma yapılandırmasıyla kaydolur.",
	],
	"dc.apiKey": [
		"Create a Browser Guard ingest-only key, then set the managed policy keys controlPlaneUrl and apiKey (or enter them in the extension options). Managed policy wins. The key can only report counts, never prompt text, for a capped number of browsers; do not use a tenant key here, because users of a managed browser can read its policy.",
		"Yalnızca veri gönderebilen bir Browser Guard anahtarı oluşturun, ardından yönetilen ilkede controlPlaneUrl ve apiKey değerlerini ayarlayın (ya da uzantı seçeneklerine girin). Yönetilen ilke önceliklidir. Anahtar, sınırlı sayıda tarayıcı için yalnızca sayıları bildirebilir, asla mesaj metnini göndermez; burada çalışma alanı anahtarı kullanmayın, çünkü yönetilen tarayıcının kullanıcıları ilkesini okuyabilir.",
	],
	"dc.createBgKey": ["Create a Browser Guard key", "Browser Guard anahtarı oluştur"],
	"dc.noCheckInBody": [
		"{label} does not check in with the control plane, so the dashboard cannot confirm it is installed.",
		"{label} kontrol düzlemine bildirim yapmaz; bu yüzden panel kurulu olduğunu doğrulayamaz.",
	],
	"dc.downloadTitle": ["Download", "İndir"],
	"dc.noArtifact": [
		"Release {version} does not include a {label} artifact.",
		"{version} sürümü {label} için bir dosya içermiyor.",
	],
	"dc.loadingManifest": ["Loading the release manifest…", "Sürüm bildirimi yükleniyor…"],
	"dc.noDownload": [
		"No verified download is available for this deployment.",
		"Bu kurulum için doğrulanmış bir indirme yok.",
	],
	"dc.installTitle": ["Install", "Kurulum"],
	"dc.guide": ["Full guide: {guide}", "Ayrıntılı kılavuz: {guide}"],
	"dc.connectTitle": ["Connect", "Bağlantı"],
	"dc.notConfigured": [
		"No release manifest is published for this deployment.",
		"Bu kurulum için yayımlanmış bir sürüm bildirimi yok.",
	],
	"dc.notConfiguredBody": [
		"Download links appear here once your release operator publishes one (AIDR_RELEASE_MANIFEST_PATH on the dashboard server, or VITE_AIDR_RELEASE_MANIFEST_URL). Until then, get installers from your approved release bundle.",
		"Sürüm sorumlunuz bir bildirim yayımladığında indirme bağlantıları burada görünür (panel sunucusunda AIDR_RELEASE_MANIFEST_PATH ya da VITE_AIDR_RELEASE_MANIFEST_URL). O zamana kadar yükleyicileri onaylı sürüm paketinizden alın.",
	],
	"dc.withheld": ["Downloads are withheld.", "İndirmeler durduruldu."],
	"dc.release": ["Release {version} · published {time}", "{version} sürümü · yayın {time}"],

	"rc.registry": [
		"Your administrator configures read access to the private @singularityrd registry through a secret manager (NODE_AUTH_TOKEN). Never paste the token into a command.",
		"Yöneticiniz özel @singularityrd paket deposuna okuma erişimini bir sır yöneticisiyle (NODE_AUTH_TOKEN) yapılandırır. Belirteci asla bir komuta yapıştırmayın.",
	],
	"rc.claude.summary": [
		"Hook plugin that inspects every Claude Code tool call before it runs.",
		"Her Claude Code araç çağrısını çalışmadan önce denetleyen kanca eklentisi.",
	],
	"rc.claude.node": [
		"Requires Node.js 22.12 or later on PATH.",
		"PATH üzerinde Node.js 22.12 ya da daha yenisi gerekir.",
	],
	"rc.claude.extract": [
		"After the digest check passes, extract the plugin archive:",
		"Özet denetimi geçtikten sonra eklenti arşivini açın:",
	],
	"rc.claude.marketplace": [
		"From the Claude Code prompt, add the extracted directory as a local marketplace and install the plugin:",
		"Claude Code isteminde açtığınız klasörü yerel pazar yeri olarak ekleyin ve eklentiyi kurun:",
	],
	"rc.claude.restart": [
		"Restart Claude Code. AIDR loads automatically on every session.",
		"Claude Code'u yeniden başlatın. AIDR her oturumda otomatik yüklenir.",
	],
	"rc.cursor.summary": [
		"Cursor extension that installs and monitors AIDR's managed agent hooks.",
		"AIDR'nin yönetilen ajan kancalarını kuran ve izleyen Cursor uzantısı.",
	],
	"rc.vsix": [
		"Install the verified VSIX (or use Extensions > Install from VSIX):",
		"Doğrulanmış VSIX dosyasını kurun (ya da Uzantılar > VSIX'ten Yükle'yi kullanın):",
	],
	"rc.cursor.enable": [
		"Open the command palette and run “Singularity AIDR: Enable protection”.",
		"Komut paletini açıp “Singularity AIDR: Enable protection” komutunu çalıştırın.",
	],
	"rc.cursor.health": [
		"Run “Singularity AIDR: Show hook health” and confirm the reported extension version.",
		"“Singularity AIDR: Show hook health” komutunu çalıştırıp bildirilen uzantı sürümünü doğrulayın.",
	],
	"rc.vscode.summary": [
		"VS Code extension for local agent hooks.",
		"Yerel ajan kancaları için VS Code uzantısı.",
	],
	"rc.vscode.setting": [
		"Enable chat.useClaudeHooks in VS Code User Settings. The extension checks this prerequisite but does not change it.",
		"VS Code Kullanıcı Ayarlarında chat.useClaudeHooks seçeneğini açın. Uzantı bu ön koşulu denetler ama değiştirmez.",
	],
	"rc.vscode.enable": [
		"Run “Singularity AIDR: Enable protection”, then “Show hook health”.",
		"“Singularity AIDR: Enable protection”, ardından “Show hook health” komutunu çalıştırın.",
	],
	"rc.openclaw.summary": [
		"In-process OpenClaw plugin that blocks unsafe tool calls.",
		"Güvensiz araç çağrılarını engelleyen, OpenClaw içinde çalışan eklenti.",
	],
	"rc.openclaw.install": [
		"Install the exact release version. Its digest must match the verified package above:",
		"Tam sürüm numarasını kurun. Özeti yukarıdaki doğrulanmış paketle eşleşmelidir:",
	],
	"rc.openclaw.restart": [
		"Restart the OpenClaw gateway and confirm the installed plugin version.",
		"OpenClaw ağ geçidini yeniden başlatıp kurulu eklenti sürümünü doğrulayın.",
	],
	"rc.opencode.summary": [
		"OpenCode plugin that checks tool calls before they run.",
		"Araç çağrılarını çalışmadan önce denetleyen OpenCode eklentisi.",
	],
	"rc.opencode.pin": [
		"Pin the exact version in ~/.config/opencode/package.json:",
		"~/.config/opencode/package.json dosyasında tam sürümü sabitleyin:",
	],
	"rc.opencode.enable": [
		"Enable the plugin in ~/.config/opencode/opencode.json:",
		"Eklentiyi ~/.config/opencode/opencode.json dosyasında etkinleştirin:",
	],
	"rc.opencode.restart": [
		"Restart OpenCode and confirm the installed plugin version.",
		"OpenCode'u yeniden başlatıp kurulu eklenti sürümünü doğrulayın.",
	],
	"rc.codex.summary": [
		"Native Codex hooks for tool calls, prompts and tool output. They deny on ask and on internal errors.",
		"Araç çağrıları, istemler ve araç çıktıları için yerleşik Codex kancaları. Onay gereken durumlarda ve iç hatalarda işlemi engeller.",
	],
	"rc.exact": ["Install the exact release version:", "Tam sürüm numarasını kurun:"],
	"rc.codex.config": [
		"Deploy the operator-generated runtime configuration (scripts/deployment-prepare.mjs) as ~/.singularity-aidr/config.json. Without it the hook refuses to start.",
		"Operatörün oluşturduğu çalışma yapılandırmasını (scripts/deployment-prepare.mjs) ~/.singularity-aidr/config.json olarak dağıtın. Bu dosya olmadan kanca başlamayı reddeder.",
	],
	"rc.codex.hooks": [
		"Register the hooks (tool calls, prompt protection and tool-output inspection) in ~/.codex/config.toml:",
		"Kancaları (araç çağrıları, istem koruması ve araç çıktısı denetimi) ~/.codex/config.toml dosyasına kaydedin:",
	],
	"rc.codex.trust": [
		"In Codex, review and trust the three registered hooks with /hooks.",
		"Codex'te /hooks ile kayıtlı üç kancayı inceleyip güvenin.",
	],
	"rc.cli.label": ["AIDR CLI", "AIDR komut satırı aracı"],
	"rc.cli.summary": [
		"Local setup and diagnostics. It does not install or activate connectors.",
		"Yerel kurulum ve tanılama. Bağlayıcıları kurmaz ya da etkinleştirmez.",
	],
	"rc.cli.binary": [
		"Put the verified binary on PATH as aidr and mark it executable:",
		"Doğrulanmış ikili dosyayı PATH üzerine aidr adıyla koyup çalıştırılabilir yapın:",
	],
	"rc.cli.help": ["Inspect the available commands:", "Kullanılabilir komutlara bakın:"],
	"rc.cli.setup": [
		"Run aidr setup only after your operator supplies the approved runtime configuration.",
		"aidr setup komutunu yalnızca operatörünüz onaylı çalışma yapılandırmasını verdikten sonra çalıştırın.",
	],
	"rc.bgChrome.label": ["Browser Guard for Chrome and Edge", "Chrome ve Edge için Browser Guard"],
	"rc.bgFirefox.label": ["Browser Guard for Firefox", "Firefox için Browser Guard"],
	"rc.bg.summary": [
		"Masks sensitive data in prompts, pastes and files before they reach AI chat products.",
		"Mesajlardaki, yapıştırılan metinlerdeki ve dosyalardaki hassas verileri yapay zekâ sohbet ürünlerine ulaşmadan önce maskeler.",
	],
	"rc.bgChrome.fleet": [
		"For fleet rollout, your administrator deploys the extension through managed browser policy.",
		"Toplu dağıtımda yöneticiniz uzantıyı yönetilen tarayıcı ilkesiyle dağıtır.",
	],
	"rc.bgChrome.eval": [
		"For an evaluation on one browser, extract {file}, open chrome://extensions (or edge://extensions), turn on Developer mode, and choose Load unpacked.",
		"Tek bir tarayıcıda denemek için {file} dosyasını açın, chrome://extensions (ya da edge://extensions) sayfasını açın, Geliştirici modunu açın ve Paketlenmemiş öğe yükle'yi seçin.",
	],
	"rc.bgChrome.archive": ["the verified archive", "doğrulanmış arşiv"],
	"rc.bgFirefox.fleet": [
		"For fleet rollout, your administrator installs the signed add-on through Firefox enterprise policy (ExtensionSettings).",
		"Toplu dağıtımda yöneticiniz imzalı eklentiyi Firefox kurumsal ilkesiyle (ExtensionSettings) kurar.",
	],
	"rc.bgFirefox.eval": [
		"For an evaluation, open about:debugging, choose This Firefox, then Load Temporary Add-on and select {file}.",
		"Denemek için about:debugging sayfasını açın, Bu Firefox'u, ardından Geçici Eklenti Yükle'yi seçin ve {file} dosyasını seçin.",
	],
	"rc.package": ["the verified package", "doğrulanmış paket"],
	"rc.mcp.label": ["MCP gateway", "MCP ağ geçidi"],
	"rc.mcp.summary": [
		"Loopback gateway that inspects MCP tool results before they reach the model.",
		"MCP araç sonuçlarını modele ulaşmadan önce denetleyen yerel (loopback) ağ geçidi.",
	],
	"rc.mcp.unpack": [
		"Unpack {file} on the host that runs the MCP client.",
		"{file} dosyasını MCP istemcisinin çalıştığı bilgisayarda açın.",
	],
	"rc.mcp.config": [
		"Write the gateway configuration with the tenant, client token SHA-256, tool allowlist, signed manifest and trusted signer keys. Keep this file private.",
		"Ağ geçidi yapılandırmasını çalışma alanı, istemci belirteci SHA-256 değeri, araç izin listesi, imzalı bildirim ve güvenilen imzalayan anahtarlarıyla yazın. Bu dosyayı gizli tutun.",
	],
	"rc.mcp.start": [
		"Start the gateway. It listens on 127.0.0.1 only:",
		"Ağ geçidini başlatın. Yalnızca 127.0.0.1 üzerinde dinler:",
	],
	"rc.mcp.point": [
		"Point the MCP client at http://127.0.0.1:7789/mcp/<serverId> and send its bearer token on every request. Remove any direct route to the upstream server.",
		"MCP istemcisini http://127.0.0.1:7789/mcp/<serverId> adresine yönlendirin ve her istekte taşıyıcı belirtecini gönderin. Asıl sunucuya giden doğrudan yolları kaldırın.",
	],
} as const satisfies MessagePairs<string>;

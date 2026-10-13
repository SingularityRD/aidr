import type { MessagePairs } from "./define";

/** Public landing page. */
export const landingMessages = {
	"ld.link.start": ["Get started", "Başlayın"],
	"ld.link.startDesc": [
		"Enroll a supported agent.",
		"Desteklenen bir yapay zekâ aracını kaydedin.",
	],
	"ld.link.signIn": ["Sign in", "Oturum açın"],
	"ld.link.signInDesc": ["Open your workspace.", "Çalışma alanınızı açın."],
	"ld.link.editions": ["View Editions", "Sürümleri görün"],
	"ld.link.editionsDesc": [
		"Compare editions and request a quote.",
		"Sürümleri karşılaştırın ve teklif isteyin.",
	],
	"ld.link.pilot": ["Request Pilot", "Pilot isteyin"],
	"ld.link.pilotDesc": ["Start with an approval-gated pilot.", "Onaya bağlı bir pilotla başlayın."],
	"ld.line.agents": ["AIDR for AI coding agents", "Yapay zekâ kodlama araçları için AIDR"],
	"ld.line.agentsDesc": [
		"Connectors for {connectors} check commands, file writes and URLs against {rules} YAML threat rules before the host acts. Includes an MCP gateway, an SDK and a CLI.",
		"{connectors} bağlayıcıları; komutları, dosya yazmalarını ve adresleri, araç işlemi yapmadan önce {rules} YAML tehdit kuralına göre denetler. Bir MCP ağ geçidi, bir SDK ve bir CLI içerir.",
	],
	"ld.line.browserGuardDesc": [
		"A {browsers} extension that masks personal data and secrets before prompts, pastes and files reach AI chat products.",
		"Mesajlar, yapıştırılan metinler ve dosyalar yapay zekâ sohbet ürünlerine ulaşmadan önce kişisel verileri ve gizli bilgileri maskeleyen bir {browsers} eklentisi.",
	],
	"ld.line.privacy": ["AIDR Privacy engine", "AIDR Privacy motoru"],
	"ld.line.privacyDesc": [
		"Turkish and English detection with checksum validation and an optional enterprise gateway. NER/OCR ships without a model and is not part of the first-release scope.",
		"Sağlama toplamı doğrulamalı Türkçe ve İngilizce tespit ve isteğe bağlı kurumsal ağ geçidi. NER/OCR modelsiz gelir ve ilk sürümün kapsamında değildir.",
	],
	"ld.line.posture": ["AI Security Posture", "Yapay Zekâ Güvenlik Durumu"],
	"ld.line.postureDesc": [
		"AI infrastructure vulnerability scanning with {components} AI component fingerprints and {cves}+ CVE rules rated by severity and CVSS, MCP server risk analysis across {categories} risk categories, {first}–{last} skill and plugin scanning, and a dashboard posture view. Uploads carry identifiers and digests only.",
		"{components} yapay zekâ bileşen parmak izi ve önem derecesi ile CVSS'e göre derecelendirilmiş {cves}+ CVE kuralıyla yapay zekâ altyapısı açık taraması, {categories} risk kategorisinde MCP sunucusu risk analizi, {first}–{last} beceri ve eklenti taraması ve panelde durum görünümü. Yüklemeler yalnızca tanımlayıcı ve özet taşır.",
	],
	"ld.bg.1": [
		"TR/EN personal data: T.C. kimlik, IBAN, phone numbers, email addresses, payment cards",
		"TR/EN kişisel veriler: T.C. kimlik, IBAN, telefon numaraları, e-posta adresleri, ödeme kartları",
	],
	"ld.bg.2": [
		"Secrets and API keys, custom terms and exact-data-match fingerprints",
		"Gizli bilgiler ve API anahtarları, özel terimler ve tam veri eşleşmesi parmak izleri",
	],
	"ld.bg.3": [
		"Reversible placeholders such as [EMAIL_1]; originals are restored only on your screen",
		"[EMAIL_1] gibi geri çevrilebilir yer tutucular; asıl değerler yalnızca sizin ekranınızda geri yüklenir",
	],
	"ld.bg.4": [
		"Administrator-managed policy and counts-only telemetry, never prompt text",
		"Yönetici tarafından yönetilen politika ve yalnızca sayı içeren telemetri; asla mesaj metni değil",
	],
	"ld.dep.local": ["Local mode (free)", "Yerel mod (ücretsiz)"],
	"ld.dep.localDesc": [
		"Connectors and Browser Guard evaluate on the device. No account needed for detection.",
		"Bağlayıcılar ve Browser Guard değerlendirmeyi cihazda yapar. Tespit için hesap gerekmez.",
	],
	"ld.dep.cloud": ["Cloud", "Bulut"],
	"ld.dep.cloudDesc": [
		"Hosted dashboard, device enrollment, central policy, audit export, SSO and SCIM.",
		"Barındırılan panel, cihaz kaydı, merkezi politika, denetim dışa aktarımı, SSO ve SCIM.",
	],
	"ld.dep.onprem": ["On-premises", "Şirket içi"],
	"ld.dep.onpremDesc": [
		"Docker Compose or Kubernetes (Helm), including air-gapped installs with a signed offline license.",
		"Docker Compose ya da Kubernetes (Helm); imzalı çevrimdışı lisansla internetten yalıtılmış kurulumlar dahil.",
	],
	"ld.f.setup": ["Guided setup", "Yönlendirmeli kurulum"],
	"ld.f.setupDesc": [
		"Set up a supported runtime; managed enrollment requires a deployed control plane.",
		"Desteklenen bir aracı kurun; yönetilen kayıt için kurulmuş bir yönetim paneli gerekir.",
	],
	"ld.f.device": ["Device authorization", "Cihaz yetkilendirme"],
	"ld.f.deviceDesc": [
		"Short-lived codes support enrollment in a configured managed deployment.",
		"Kısa ömürlü kodlar, yapılandırılmış yönetilen kurulumda kaydı destekler.",
	],
	"ld.f.incidents": ["Incident correlation", "Güvenlik vakası ilişkilendirme"],
	"ld.f.incidentsDesc": [
		"Repeated denials, suspicious retries, and abuse patterns roll into one case.",
		"Tekrarlanan engellemeler, şüpheli yeniden denemeler ve kötüye kullanım örüntüleri tek bir vakada toplanır.",
	],
	"ld.f.packages": ["Package and plugin guard", "Paket ve eklenti koruması"],
	"ld.f.packagesDesc": [
		"Catch typosquats, lifecycle risk, integrity drift, and command surface exposure.",
		"Yazım taklidi paketleri, yaşam döngüsü risklerini, bütünlük kaymalarını ve komut yüzeyi açıklarını yakalayın.",
	],
	"ld.f.sync": ["Dashboard sync", "Panel eşitleme"],
	"ld.f.syncDesc": [
		"Configured managed agents can send redacted verdicts to the dashboard.",
		"Yapılandırılmış yönetilen araçlar maskelenmiş kararları panele gönderebilir.",
	],
	"ld.f.offline": ["Offline grace", "Çevrimdışı tolerans"],
	"ld.f.offlineDesc": [
		"Enrolled agents can use signed cached state during a bounded outage.",
		"Kayıtlı araçlar, sınırlı bir kesinti sırasında imzalı önbellek durumunu kullanabilir.",
	],
	"ld.hero.pill": [
		"Edge-first AI Agent Detection & Response",
		"Cihazda çalışan yapay zekâ aracı tespiti ve müdahalesi",
	],
	"ld.hero.title": [
		"Security layer for AI agents and AI chat.",
		"Yapay zekâ araçları ve yapay zekâ sohbeti için güvenlik katmanı.",
	],
	"ld.hero.lead": [
		"{brand} inspects supported agent actions on the device and masks personal data before prompts reach AI chat products. Managed visibility and device enrollment require a configured control plane. Sign in to begin onboarding or request an assisted pilot for your runtime and deployment.",
		"{brand}, desteklenen yapay zekâ aracı işlemlerini cihazda inceler ve mesajlar yapay zekâ sohbet ürünlerine ulaşmadan önce kişisel verileri maskeler. Yönetilen görünürlük ve cihaz kaydı için yapılandırılmış bir yönetim paneli gerekir. Kuruluma başlamak için oturum açın ya da aracınız ve kurulumunuz için yardımlı bir pilot isteyin.",
	],
	"ld.requestPilot": ["Request a pilot", "Pilot isteyin"],
	"ld.lines.pill": ["Product Lines", "Ürün aileleri"],
	"ld.lines.title": [
		"One policy plane for agents and people.",
		"Yapay zekâ araçları ve insanlar için tek politika katmanı.",
	],
	"ld.bg.title": [
		"Mask sensitive data before it reaches AI chat.",
		"Hassas verileri yapay zekâ sohbetine ulaşmadan maskeleyin.",
	],
	"ld.bg.lead": [
		"Works on {sites}. Detection runs in the browser; the AI provider receives placeholders.",
		"{sites} üzerinde çalışır. Tespit tarayıcıda yapılır; yapay zekâ sağlayıcısı yalnızca yer tutucuları alır.",
	],
	"ld.surface.pill": ["Product Surface", "Ürün yüzeyi"],
	"ld.surface.title": [
		"Security controls your agent can feel.",
		"Yapay zekâ aracınızın hissedeceği güvenlik denetimleri.",
	],
	"ld.surface.lead": [
		"Local detection, incident correlation, and package and plugin checks are available for supported runtimes: {connectors}. The engine ships {rules} YAML threat rules in {files} files. Device enrollment and central visibility depend on the pilot deployment.",
		"Yerel tespit, güvenlik vakası ilişkilendirme ve paket ile eklenti denetimleri desteklenen araçlarda kullanılabilir: {connectors}. Motor, {files} dosyada {rules} YAML tehdit kuralıyla gelir. Cihaz kaydı ve merkezi görünürlük pilot kurulumuna bağlıdır.",
	],
	"ld.surface.1": [
		"Guided setup for supported runtimes",
		"Desteklenen araçlar için yönlendirmeli kurulum",
	],
	"ld.surface.2": [
		"Local enforcement; optional managed visibility",
		"Yerel uygulama; isteğe bağlı yönetilen görünürlük",
	],
	"ld.surface.3": [
		"Package, plugin, and prompt abuse detection",
		"Paket, eklenti ve mesaj kötüye kullanımı tespiti",
	],
	"ld.surface.4": [
		"Managed onboarding in configured pilot environments",
		"Yapılandırılmış pilot ortamlarında yönetilen kurulum",
	],
	"ld.diagram.label": [
		"Diagram: agent tool calls pass through the AIDR policy layer before reaching commands, files, and the network",
		"Şema: yapay zekâ aracının araç çağrıları komutlara, dosyalara ve ağa ulaşmadan önce AIDR politika katmanından geçer",
	],
	"ld.diagram.agent": ["AI agent", "Yapay zekâ aracı"],
	"ld.diagram.calls": ["tool calls", "araç çağrıları"],
	"ld.diagram.layer": ["AIDR policy layer", "AIDR politika katmanı"],
	"ld.diagram.decisions": ["allow · ask · deny", "izin · onay · engel"],
	"ld.diagram.targets": ["commands · files · web", "komutlar · dosyalar · web"],
	"ld.dep.pill": ["Deployment", "Kurulum"],
	"ld.dep.title": [
		"Run it where your data has to stay.",
		"Verinizin kalması gereken yerde çalıştırın.",
	],
	"ld.features.pill": ["Core Features", "Temel özellikler"],
	"ld.cta.title": [
		"Ready to protect your AI agents?",
		"Yapay zekâ araçlarınızı korumaya hazır mısınız?",
	],
	"ld.cta.lead": [
		"Start with an assisted pilot and validate installation and data flows in your environment.",
		"Yardımlı bir pilotla başlayın ve kurulumu ve veri akışlarını kendi ortamınızda doğrulayın.",
	],
} as const satisfies MessagePairs<string>;

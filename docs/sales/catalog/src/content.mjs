/**
 * Singularity AIDR product catalog: the single bilingual source for
 * docs/sales/catalog/catalog.{tr,en}.html (built by scripts/build-catalog.mjs).
 *
 * Rules for editing (enforced by scripts/catalog-facts.test.mjs):
 * - Write every visible string as a Turkish/English pair so both editions stay identical.
 * - Countable claims use {fact-key} tokens (feature text) or h.fact("key") (templates);
 *   the test recomputes each fact from the repository.
 * - Every feature lists the repository paths that implement it; the test fails when a path
 *   is missing. There are no "pending" features: list a capability only once it has shipped.
 * - Customer-facing copy only: no prices, no internal codes, no repository paths in the
 *   visible text, no upstream vendor names, no certification or efficacy claims.
 */

/** Countable claims. Formatting (digit grouping) is applied per language at build time. */
export const FACTS = {
	"threat-rules": 519,
	"ai-components": 146,
	"cve-rules": { n: 2000, plus: true },
	"mcp-categories": 14,
	"bg-sites": 8,
	"bg-entities": 23,
	"dlp-detectors": 18,
	connectors: 6,
	"trial-days": 14,
	"plan-free-retention": 7,
	"plan-team-retention": 90,
	"plan-business-retention": 365,
	"plan-team-min": 3,
	"plan-business-min": 25,
};

/** Lifecycle stages in order, then the governance layer and the platform. */
export const STAGES = [
	{
		key: "discover",
		n: 1,
		tr: {
			name: "Keşfet",
			intro: "Döngü, neyin var olduğunu bilmekle başlar: ajanlar, MCP sunucuları, yapay zekâ servisleri ve çalışanların kullandığı araçlar.",
			gain: "Ajanların neye bağlandığını ve çalışanların hangi yapay zekâ araçlarını kullandığını görürsünüz.",
		},
		en: {
			name: "Discover",
			intro: "The loop starts with knowing what exists: agents, MCP servers, AI services and the AI tools your people use.",
			gain: "You see what your agents connect to and which AI tools your people use.",
		},
	},
	{
		key: "assess",
		n: 2,
		tr: {
			name: "Değerlendir",
			intro: "Bulunan varlıkların riski ölçülür: bilinen açıklar, riskli MCP yapılandırmaları ve tehlikeli eklentiler.",
			gain: "Açığı olan servisleri ve riskli eklentileri, ajanlar onları kullanmadan önce bilirsiniz.",
		},
		en: {
			name: "Assess",
			intro: "The risk of what was found is measured: known vulnerabilities, risky MCP configurations and dangerous plugins.",
			gain: "You know about vulnerable services and risky plugins before your agents use them.",
		},
	},
	{
		key: "protect",
		n: 3,
		tr: {
			name: "Veriyi koru",
			intro: "Yapay zekâ kullanılırken hassas veri, modele ulaşmadan önce maskelenir ya da durdurulur.",
			gain: "Tespit edilen kişisel veri ve anahtarlar içeride kalır; ekipler yapay zekâyı kullanmaya devam eder.",
		},
		en: {
			name: "Protect data",
			intro: "While AI is in use, sensitive data is masked or stopped before it reaches a model.",
			gain: "Detected personal data and keys stay inside, and people keep getting value from AI.",
		},
	},
	{
		key: "control",
		n: 4,
		tr: {
			name: "Eylemi denetle",
			intro: "Ajan harekete geçtiğinde her araç çağrısı, çalışmadan önce değerlendirilir.",
			gain: "Yıkıcı komutlar, kimlik bilgisi okuma ve veri sızdırma girişimleri çalışmadan durur.",
		},
		en: {
			name: "Control actions",
			intro: "When an agent acts, every tool call is evaluated before it runs.",
			gain: "Destructive commands, credential reads and exfiltration attempts stop before they run.",
		},
	},
	{
		key: "inspect",
		n: 5,
		tr: {
			name: "Çıktıyı incele",
			intro: "Ajanın geri okuduğu sonuçlar, bir sonraki adımı yönlendirmeden önce taranır.",
			gain: "Araç sonuçlarında tespit edilen talimatlar ve sızan anahtarlar modelden uzak tutulur.",
		},
		en: {
			name: "Inspect output",
			intro: "What the agent reads back is inspected before it can steer the next step.",
			gain: "Detected instructions and leaked keys in tool results are kept from the model.",
		},
	},
	{
		key: "respond",
		n: 6,
		tr: {
			name: "Onayla ve müdahale et",
			intro: "Şüpheli durumda karar insana kalır; olaylara kayıtlı ve kontrollü yanıt verilir.",
			gain: "Ele geçirilmiş bir ajan kendi engelini kaldıramaz; ekip olayı kendi kanalında görür.",
		},
		en: {
			name: "Approve and respond",
			intro: "When something is suspicious a person decides, and incidents get a recorded, controlled response.",
			gain: "A hijacked agent cannot lift its own block, and the team sees the incident in its own channel.",
		},
	},
	{
		key: "prove",
		n: 7,
		tr: {
			name: "Kanıtla ve iyileştir",
			intro: "Her karar kanıta dönüşür; simülasyon sonuçları politikayı güçlendirerek döngüyü kapatır.",
			gain: "Ne olduğunu denetçiye gösterir, politikayı ölçerek iyileştirirsiniz.",
		},
		en: {
			name: "Prove and improve",
			intro: "Every decision becomes evidence, and simulation results strengthen the policy to close the loop.",
			gain: "You can show auditors what happened and improve policy by measuring it.",
		},
	},
	{
		key: "govern",
		n: "G",
		tr: {
			name: "Yönet ve uyumla",
			intro: "Yönetişim katmanı tüm aşamaları kapsar: hangi yapay zekânın, kimin sorumluluğunda, hangi kurallarla kullanıldığı.",
			gain: "Yapay zekâ kullanımı sahipli, onaylı ve çerçevelere eşlenmiş olarak yönetilir.",
		},
		en: {
			name: "Govern and comply",
			intro: "The governance layer spans every stage: which AI is used, who owns it and under which rules.",
			gain: "AI use is owned, approved and mapped to the frameworks you report against.",
		},
	},
	{
		key: "platform",
		n: "+",
		tr: {
			name: "Platform ve kurulum",
			intro: "Tüm aşamalar aynı platformda çalışır: bulutta, kurum içinde ya da ağdan yalıtılmış ortamda.",
			gain: "",
		},
		en: {
			name: "Platform and deployment",
			intro: "Every stage runs on one platform: in the cloud, on-premises or air-gapped.",
			gain: "",
		},
	},
];

/**
 * The numbered feature list, in display order. [name, what it is good for] per language.
 * `evidence`: repository paths that implement the feature (checked by the facts test).
 */
export const FEATURES = [
	// 1 Discover
	{ key: "fleet-inventory", stage: "discover", evidence: ["packages/dashboard/src/ui/pages/AgentsPage.tsx"], tr: ["Filo envanteri", "hangi ajanın, hangi sürümle, en son ne zaman çalıştığı tek listede."], en: ["Fleet inventory", "which agent runs, on which version, and when it was last seen, in one list."] },
	{ key: "mcp-discovery", stage: "discover", evidence: ["packages/core/src/mcp-discovery.ts", "packages/cli/src/commands/discover.ts"], tr: ["MCP sunucu keşfi", "ajan yapılandırmalarındaki MCP sunucuları bulunur, {mcp-categories} risk kategorisine eşlenir."], en: ["MCP server discovery", "finds the MCP servers in agent configurations and maps them to {mcp-categories} risk categories."] },
	{ key: "continuous-inventory", stage: "discover", evidence: ["packages/cli/src/commands/collect.ts", "packages/dashboard/src/ui/pages/DiscoveryPage.tsx"], tr: ["Sürekli altyapı envanteri", "iç ağdaki yapay zekâ servisleri düzenli yoklanır; sessiz kalan hedef işaretlenir."], en: ["Continuous infrastructure inventory", "internal AI services are polled on a schedule; silent targets are flagged."] },
	{ key: "shadow-ai", stage: "discover", evidence: ["packages/browser-guard/src/background/shadow-ai.ts", "packages/browser-guard/src/sites/catalog.ts"], tr: ["Gölge yapay zekâ keşfi ve kontrolü", "çalışanların kullandığı yapay zekâ araçları sayılarla görülür, izin verilir ya da engellenir."], en: ["Shadow AI discovery and control", "see which AI tools employees use (counts only), then allow or block them."] },
	// 2 Assess
	{ key: "infra-cve-scan", stage: "assess", evidence: ["packages/core/src/aig-infra-scan.ts", "packages/cli/src/commands/scan.ts"], tr: ["Yapay zekâ altyapısı CVE taraması", "{ai-components} bileşen tanınır, sürümü {cve-rules} CVE kuralıyla eşlenir."], en: ["AI infrastructure CVE scan", "recognises {ai-components} components and matches versions to {cve-rules} CVE rules."] },
	{ key: "scan-to-policy", stage: "assess", evidence: ["packages/core/src/aig-policy.ts"], tr: ["Taramadan politikaya", "doğrulanmış kritik açığı olan servise ajanın isteği durdurulur."], en: ["Scan-to-policy", "agent calls to a service with a version-confirmed critical flaw are stopped."] },
	{ key: "skill-scan", stage: "assess", evidence: ["threats/skill-scan.yaml", "packages/core/src/plugin-scanner.ts"], tr: ["Skill ve eklenti taraması", "gizli talimat, uzaktan kod ve kalıcılık kalıpları T01–T09 ile bulunur."], en: ["Skill and plugin scanning", "hidden instructions, remote code and persistence found with T01–T09."] },
	{ key: "posture-dashboard", stage: "assess", evidence: ["packages/dashboard/src/ui/pages/PosturePage.tsx", "packages/core/src/posture-events.ts"], tr: ["Güvenlik duruşu paneli", "CVE, MCP ve eklenti bulguları önem derecesi ve 30 günlük eğilimle."], en: ["Posture dashboard", "CVE, MCP and plugin findings by severity, with a 30-day trend."] },
	// 3 Protect data: Browser Guard
	{ key: "bg-masking", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/engine/vault.ts", "packages/browser-guard/src/sites/index.ts"], tr: ["Geri alınabilir maskeleme", 'hassas değer, gönderimden önce <span class="ph">[EMAIL_1]</span> gibi bir yer tutucuya dönüşür.'], en: ["Reversible masking", 'a sensitive value becomes a placeholder such as <span class="ph">[EMAIL_1]</span> before sending.'] },
	{ key: "local-restore", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/background/vault-store.ts"], tr: ["Yalnızca kullanıcının ekranında geri yükleme", "yanıtta özgün değer görünür; site onu hiç görmez."], en: ["Restore on the user's screen only", "the answer shows the original value; the site never sees it."] },
	{ key: "pii-detection", stage: "protect", group: "browser", evidence: ["packages/privacy/src/detectors.ts", "packages/privacy/src/validators.ts"], tr: ["TR/EN kişisel veri tespiti", "T.C. kimlik, IBAN ve kart sağlamayla; telefon, adres, ad bağlamla."], en: ["TR/EN personal-data detection", "T.C. Kimlik, IBAN and cards by checksum; phones, addresses, names by context."] },
	{ key: "secret-detection", stage: "protect", group: "browser", evidence: ["packages/privacy/src/detectors.ts"], tr: ["Gizli anahtar tespiti", "bulut, Git ve yapay zekâ anahtarları, JWT, özel anahtarlar; hiç geri gösterilmez."], en: ["Secret detection", "cloud, Git and AI provider keys, JWTs and private keys; never shown again."] },
	{ key: "guard-modes", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/background/policy.ts"], tr: ["Dört koruma modu", "Otomatik maskele, Bana sor, Engelle, Yalnızca say (maskeleme yok); ölçümden tam korumaya."], en: ["Four protection modes", "Auto-mask, Ask me, Block, Count only (no masking); from measuring to full protection."] },
	{ key: "paste-protection", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/content"], tr: ["Yapıştırma koruması", "panodaki metin istem kutusuna girmeden maskelenir."], en: ["Paste protection", "clipboard text is masked before it enters the prompt box."] },
	{ key: "file-protection", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/engine/files.ts"], tr: ["Dosya koruması", "CSV, JSON, .env ve kodun temiz kopyası yüklenir; formül enjeksiyonu önlenir."], en: ["File protection", "clean copies of CSV, JSON, .env and code are uploaded; formula injection is defused."] },
	{ key: "office-pdf-protection", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/engine/office/ooxml.ts", "packages/browser-guard/src/engine/office/odf.ts", "packages/browser-guard/src/engine/pdf"], tr: ["Office ve PDF koruması", "Word, Excel, PowerPoint, ODF maskeli yüklenir; hassas veri içeren PDF durdurulur."], en: ["Office &amp; PDF protection", "Word, Excel, PowerPoint, ODF upload masked; PDFs with sensitive data are stopped."] },
	{ key: "custom-terms", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/engine/detect.ts"], tr: ["Kuruma özel terimler", "proje kod adları, iç sunucu adları gibi sözcükler maskelenir."], en: ["Company terms", "project code names, internal hostnames and similar words are masked."] },
	{ key: "exact-data-match", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/engine/exact-data.ts", "packages/browser-guard/scripts/fingerprint-dataset.mjs"], tr: ["Tam veri eşleştirme", "kendi müşteri kayıtlarınız yalnızca parmak iziyle tanınır."], en: ["Exact data match", "your own customer records are recognised by fingerprint only."] },
	{ key: "injection-coaching", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/engine/coaching.ts"], tr: ["Prompt injection uyarısı", "riskli metin gönderilmeden kullanıcıya Türkçe ya da İngilizce açıklanır."], en: ["Prompt-injection coaching", "risky text is explained to the user, in Turkish or English, before sending."] },
	{ key: "native-ner", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/background/native.ts"], tr: ["Yerel NER bağlantısı", "ilk sürüm kapsamı dışında; model içermez, satılmaz."], en: ["Local NER bridge", "not in the first-release scope; ships without a model, not sold."] },
	{ key: "managed-policy", stage: "protect", group: "browser", evidence: ["packages/browser-guard/static/managed_schema.json", "deploy/browser-guard"], tr: ["Kurumsal politika", "GPO, Intune, Jamf ve Firefox ile dağıtım; zayıflatan ayarlar kilitli."], en: ["Managed policy", "deploy with GPO, Intune, Jamf or Firefox; weakening settings are locked."] },
	{ key: "site-blocking", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/background/dnr.ts"], tr: ["Site engelleme ve duraklatma", "onaylanmayan siteler açılmaz; duraklatma süreli ve sayılır."], en: ["Site blocking and pause", "unapproved sites do not load; pauses are timed and still counted."] },
	{ key: "custom-ai-sites", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/background/custom-sites.ts"], tr: ["Kurum içi yapay zekâ siteleri", "kendi iç yapay zekâ portallarınız da aynı maskelemeyle korunur."], en: ["Internal AI sites", "your own internal AI portals get the same masking."] },
	{ key: "counts-telemetry", stage: "protect", group: "browser", evidence: ["packages/browser-guard/src/background/telemetry.ts"], tr: ["Yalnızca sayım telemetrisi", "panele içerik değil, tür ve site bazında sayılar gider."], en: ["Counts-only telemetry", "the console receives counts per type and site, never content."] },
	// 3 Protect data: agents and CLI
	{ key: "prompt-protection", stage: "protect", group: "agents", evidence: ["packages/core/src/prompt-protection.ts", "packages/core/src/prompt-inspection.ts"], tr: ["İstem koruması", "tüm bağlayıcılarda istem, modele gitmeden anahtar ve kişisel veri için denetlenir."], en: ["Prompt protection", "on every connector, prompts are checked for secrets and personal data first."] },
	{ key: "dlp-policies", stage: "protect", group: "agents", evidence: ["packages/core/src/dlp", "packages/core/src/local-dlp-policy.ts"], tr: ["DLP politikaları", "{dlp-detectors} TR/EN dedektör, anahtar sözcük, düzenli ifade; imzalı politika."], en: ["DLP policies", "{dlp-detectors} TR/EN detectors, keywords, regular expressions; signed policy."] },
	{ key: "dlp-redaction", stage: "protect", group: "agents", evidence: ["packages/claude-code/src/pre-tool-use.ts", "packages/opencode/src/tool-handler.ts"], tr: ["DLP girdi maskeleme", "Claude Code ve OpenCode'da değer maskelenir, araç yine çalışır."], en: ["DLP input redaction", "on Claude Code and OpenCode the value is masked and the tool still runs."] },
	{ key: "privacy-scan-cli", stage: "protect", group: "agents", evidence: ["packages/cli/src/commands/privacy.ts"], tr: ["<code>aidr privacy scan</code>", "dosya paylaşılmadan önce yerelde taranır; değer yazdırılmaz."], en: ["<code>aidr privacy scan</code>", "check a file locally before sharing it; values are never printed."] },
	{ key: "screenshot-ocr", stage: "protect", group: "agents", evidence: ["packages/privacy/src/visual"], tr: ["Ekran görüntüsü maskeleme", "yerel OCR ilk sürüm kapsamı dışında; model içermez, satılmaz."], en: ["Screenshot redaction", "local OCR is not in the first-release scope; ships without a model."] },
	{ key: "privacy-gateway", stage: "protect", group: "agents", evidence: ["packages/privacy/src/platform"], tr: ["Kurumsal gizlilik ağ geçidi", "yapay zekâ trafiğini ağ çıkışında denetleyen sunucu bileşeni."], en: ["Enterprise privacy gateway", "a server component that inspects AI traffic at your network exit."] },
	// 4 Control actions
	{ key: "connectors", stage: "control", evidence: ["packages/claude-code", "packages/extension", "packages/openclaw", "packages/opencode", "packages/codex"], tr: ["Altı bağlayıcı", "Claude Code, OpenClaw, OpenCode; Codex CLI: önizleme; Cursor, VS Code: önizleme — henüz gerçek ortam kabul kanıtı yok."], en: ["Six connectors", "Claude Code, OpenClaw, OpenCode; Codex CLI: preview; Cursor, VS Code: preview — no real-host acceptance evidence yet."] },
	{ key: "tool-call-inspection", stage: "control", evidence: ["packages/core/src/extractors.ts"], tr: ["Araç çağrısı denetimi", "kabuk, dosya, web ve MCP çağrıları çalışmadan önce değerlendirilir."], en: ["Tool-call inspection", "shell, file, web and MCP calls are evaluated before they run."] },
	{ key: "verdicts", stage: "control", evidence: ["packages/core/src/engine.ts"], tr: ["allow / ask / deny", "her kararın kuralı ve gerekçesi görünür; sıkı olan kazanır."], en: ["allow / ask / deny", "every decision shows its rule and reason; the strictest wins."] },
	{ key: "threat-rules", stage: "control", evidence: ["threats"], tr: ["{threat-rules} tespit kuralı", "Linux, macOS ve Windows için okunabilir YAML; kendi kurallarınız da."], en: ["{threat-rules} detection rules", "readable YAML for Linux, macOS and Windows; add your own."] },
	{ key: "sensitivity", stage: "control", evidence: ["packages/core/src/engine.ts"], tr: ["Duyarlılık ön ayarları", "paranoid, balanced, relaxed; ekibe uygun eşik."], en: ["Sensitivity presets", "paranoid, balanced, relaxed; the right threshold per team."] },
	{ key: "encoded-commands", stage: "control", evidence: ["packages/core/src/extractors.ts", "threats/obfuscation.yaml"], tr: ["Kodlanmış ve zincirli komutlar", "base64 ya da değişkenlerle gizlenmiş komutlar çözümlenir."], en: ["Encoded and chained commands", "commands hidden in base64 or built from variables are resolved."] },
	{ key: "package-checks", stage: "control", evidence: ["packages/core/src/package-checker.ts"], tr: ["Paket tedarik zinciri", "açıldığında var olmayan npm/PyPI paketi durur, çok yeni ve az kullanılan onaya kalır."], en: ["Package supply chain", "when enabled, non-existent npm/PyPI packages are stopped, brand-new unused ones held."] },
	{ key: "reputation-amsi", stage: "control", evidence: ["packages/core/src/clients/url-check.ts", "docs/amsi-scanning.md"], tr: ["İtibar ve AMSI", "URL, dosya ve paket itibarı; Windows'ta kötü amaçlı yazılım taraması."], en: ["Reputation and AMSI", "URL, file and package reputation; Windows antimalware scanning."] },
	{ key: "mcp-policy", stage: "control", evidence: ["packages/core/src/policy-document.ts", "packages/core/src/remote-policy.ts"], tr: ["MCP politikası", "sunucu ve araç bazında izin, onay, engel; bilinmeyen sunucuya ayrı kural."], en: ["MCP policy", "allow, approve or deny per server and tool; a rule for unknown servers."] },
	{ key: "mcp-gateway", stage: "control", evidence: ["packages/mcp-gateway/src/gateway.mjs"], tr: ["MCP Gateway", "araç çağrısı ve argümanları çalışmadan denetlenir; imzalı araç bildirimi."], en: ["MCP Gateway", "tool calls and arguments are checked before they run; signed tool manifests."] },
	{ key: "runtime-policy", stage: "control", evidence: ["supabase/functions/policy-management", "packages/dashboard/src/ui/pages/PolicyPage.tsx"], tr: ["Merkezî politika", "YAML ile yazılır, prova edilir, yayımlanır; sürüm geçmişiyle."], en: ["Central policy", "written in YAML, dry-run, published, with version history."] },
	{ key: "local-policy", stage: "control", evidence: ["packages/core/src/policy.ts", "packages/core/src/allowlist.ts"], tr: ["Yerel politika ve izin listeleri", "yazma kökleri, alan adları, özel IP; tam eşleşmeli istisnalar."], en: ["Local policy and allowlists", "write roots, domains, private IPs; exact-match exceptions."] },
	{ key: "sdk", stage: "control", evidence: ["packages/sdk/src/middleware.ts", "packages/sdk/src/client.ts"], tr: ["SDK", "kendi ajan uygulamalarınız aynı karar sözleşmesiyle korunur."], en: ["SDK", "protect your own agent applications with the same decision contract."] },
	{ key: "fail-closed", stage: "control", evidence: ["packages/core/src/init-failure.ts"], tr: ["Hata durumunda kapalı", "iç hata çağrıyı reddeder; devre dışı, güvenilmeyen ya da öldürülen hook karar vermez."], en: ["Fail-closed connectors", "internal errors deny; a disabled, untrusted or killed hook gives no verdict."] },
	{ key: "self-defense", stage: "control", evidence: ["threats/self-defense.yaml"], tr: ["Öz-savunma", "ajanın AIDR'yi kapatma ya da atlatma girişimleri yakalanır."], en: ["Self-defence", "attempts by an agent to disable or bypass AIDR are caught."] },
	{ key: "verdict-cache", stage: "control", evidence: ["packages/core/src/cache.ts", "packages/core/src/managed.ts"], tr: ["Çevrim dışı çalışma", "ağ yokken imzalı önbellekteki durumla koruma sürer."], en: ["Offline operation", "protection continues from signed cached state without a network."] },
	{ key: "toxic-flow", stage: "control", evidence: ["packages/core/src/toxic-flow.ts", "packages/core/src/toxic-flow-classify.ts"], tr: ["Zehirli akış ve saldırı zinciri tespiti", "özel veri, güvenilmeyen içerik ve dış kanal birleşince son adım onaya kalır."], en: ["Toxic-flow and attack-chain detection", "private data, untrusted content and egress in one session: the final step is held."] },
	{ key: "canary-tokens", stage: "control", evidence: ["packages/core/src/canary", "packages/cli/src/commands/canary.ts", "threats/canary.yaml"], tr: ["Tuzak kimlik bilgileri", "sahte anahtar dosyasını açan ya da değerini gönderen ajan engellenir, olay kaydedilir."], en: ["Canary credentials", "decoy key files: an agent that opens one or sends its value is blocked and the trigger recorded."] },
	{ key: "permission-profiles", stage: "control", evidence: ["packages/core/src/agent-profile.ts", "packages/core/src/agent-profile-templates.ts", "packages/cli/src/commands/profile.ts"], tr: ["Ajan yetki profilleri", "ajan ya da depo başına izinli araç, MCP, yol, alan adı ve komut; şablonlar."], en: ["Agent permission profiles", "allowed tools, MCP, paths, domains, commands per agent or repo; templates."] },
	// 4 Control actions: AI safety (risks from the agent's own behaviour)
	{ key: "runaway-guardrails", stage: "control", group: "safety", evidence: ["packages/core/src/agent-safety/runaway-guard.ts", "threats/agent-safety.yaml"], tr: ["Kaçak ajan ve bütçe sınırları", "döngü, hata tekrarı, çağrı patlaması ya da bütçe aşımında oturum insanı bekler."], en: ["Runaway and budget guardrails", "loops, failure streaks, call spikes or optional budgets pause the session."] },
	{ key: "sabotage-detection", stage: "control", group: "safety", evidence: ["packages/core/src/agent-safety/edit-views.ts", "threats/agent-safety.yaml"], tr: ["Ödül istismarı ve sabotaj tespiti", "test atlama, assert silme, kanca atlama, CI kapatma ve force-push onay ister."], en: ["Reward hacking and sabotage", "skipping tests or hooks, removing asserts, disabling CI, force-push need approval."] },
	{ key: "autonomy-escalation", stage: "control", group: "safety", evidence: ["threats/agent-safety.yaml"], tr: ["Özerklik yükseltme engeli", "ajanın başka bir ajanı izinsiz, YOLO ya da tam otomatik modda başlatması durur."], en: ["Autonomy-escalation blocking", "agents launching agents in skip-permissions, YOLO or full-auto mode are blocked."] },
	{ key: "irreversible-actions", stage: "control", group: "safety", evidence: ["threats/agent-safety.yaml"], tr: ["Geri alınamaz eylem koruması", "veritabanı ve bulut silme, terraform destroy, yayımlama ve adınıza mesaj onay ister."], en: ["Irreversible actions", "DB drops, cloud deletions, terraform destroy, publishing and messaging need approval."] },
	{ key: "safe-model-loading", stage: "control", group: "safety", evidence: ["threats/ai-supply-chain.yaml", "allowlists/model-sources/trusted-model-sources.yaml"], tr: ["Güvenli model yükleme", "pickle/torch.load, trust_remote_code, güvenilmeyen model indirme onaya kalır ya da durur."], en: ["Safe model loading", "pickle/torch.load, trust_remote_code and untrusted model downloads are held or blocked."] },
	{ key: "secure-code-guardrails", stage: "control", group: "safety", evidence: ["threats/secure-code.yaml", "packages/core/src/code-guard.ts"], tr: ["Güvenli kod korkulukları", "TLS kapatma, SQL birleştirme, eval, zayıf şifreleme yazılırken uyarılır; onay isteğe bağlı."], en: ["Secure-code guardrails", "TLS off, SQL concatenation, eval on input, weak crypto: warned as written; hold optional."] },
	{ key: "agent-env-posture", stage: "control", group: "safety", evidence: ["packages/core/src/agent-environment-posture.ts", "supabase/migrations/20260927004000_agent_environment_posture.sql"], tr: ["Ajan ortamı güvenlik duruşu", "izin atlama, kapalı kanca, sandbox yok, root, Docker soketi; çözüm önerisiyle."], en: ["Agent environment posture", "permission bypass, hooks off, no sandbox, root, Docker socket; each with a fix."] },
	{ key: "content-safety-policy", stage: "control", group: "safety", evidence: ["packages/core/src/prompt-safety.ts"], tr: ["Jailbreak ve içerik güvenliği politikası", "jailbreak ve yasak içerik temkinli kalıplarla uyarılır ya da durdurulur."], en: ["Jailbreak and content-safety policy", "conservative patterns warn on or block jailbreaks and prohibited requests."] },
	{ key: "oversight-metrics", stage: "control", group: "safety", evidence: ["supabase/migrations/20260927000060_governance_scorecard.sql", "packages/dashboard/src/ui/pages/GovernancePage.tsx"], tr: ["İnsan gözetimi ölçümleri", "onay oranı, karar süresi ve aceleci onay uyarıları yönetişim skor kartında."], en: ["Human-oversight metrics", "approval ratio, decision time and fast-approval prompts on the governance scorecard."] },
	// 5 Inspect output
	{ key: "output-scanning", stage: "inspect", evidence: ["packages/core/src/output-scanner.ts"], tr: ["Araç çıktısı taraması", "sızan anahtar, prompt injection yükü ve sistem istemi sızıntısı bulunur."], en: ["Tool-output scanning", "finds leaked keys, prompt-injection payloads and system-prompt leaks."] },
	{ key: "output-quarantine", stage: "inspect", evidence: ["packages/core/src/output-sensitive-data.ts"], tr: ["Karantina bildirimi", "riskli sonuç modele ulaşmadan değiştirilir; giden mesajlar da denetlenir."], en: ["Quarantine notice", "a risky result is replaced before the model sees it; outbound messages too."] },
	{ key: "mcp-output", stage: "inspect", evidence: ["packages/mcp-gateway/src/output-inspection.mjs"], tr: ["MCP çıktı denetimi", "MCP Gateway sonucu modele vermeden tam olarak tarar."], en: ["MCP output inspection", "the MCP Gateway scans each result in full before the model gets it."] },
	{ key: "poisoning-protection", stage: "inspect", evidence: ["packages/core/src/context-poisoning.ts", "threats/context-poisoning.yaml"], tr: ["Veri ve bağlam zehirlenmesi koruması", "talimat dosyası, okunan içerik, MCP araç tanımı ve bellek yazımı korunur."], en: ["Data and context poisoning protection", "instruction files, content read, MCP tool descriptions and memory writes are guarded."] },
	// 6 Approve and respond
	{ key: "operator-approval", stage: "respond", evidence: ["packages/core/src/operator-approvals.ts", "packages/cli/src/commands/approvals.ts"], tr: ["Bant dışı operatör onayı", "terminalden tek seferlik onay; ajan kendi engelini kaldıramaz."], en: ["Out-of-band operator approval", "a one-time approval from the terminal; the agent cannot approve itself."] },
	{ key: "dashboard-approvals", stage: "respond", evidence: ["packages/core/src/dashboard-approvals.ts", "supabase/functions/approval-requests/index.ts"], tr: ["Panelden onay", "başka bir kişi panelden imzalı, tek kullanımlık ve süreli onay verir."], en: ["Dashboard approvals", "a second person approves in the console: signed, single-use, short-lived."] },
	{ key: "alerts", stage: "respond", evidence: ["supabase/functions/notification-channels/index.ts", "supabase/functions/notification-dispatch/index.ts"], tr: ["Slack, Teams, webhook ve e-posta uyarıları", "engelleme, onay isteği ve olaylar ekibin kanalına düşer."], en: ["Slack, Teams, webhook and email alerts", "blocks, approval requests and incidents reach your team's channel."] },
	{ key: "incidents", stage: "respond", evidence: ["packages/dashboard/src/ui/pages/IncidentsPage.tsx", "packages/core/src/incidents"], tr: ["Olaylar ve kanıt zinciri", "engellenen kararlar, cihaz bazında sırasıyla tek görünümde."], en: ["Incidents and evidence chain", "blocked decisions in one view, in order, per device."] },
	{ key: "response-playbook", stage: "respond", evidence: ["supabase/functions/response-playbooks"], tr: ["Müdahale senaryosu", "ajan önce duraklatılır, sonra ağdan yalıtılır; her adım kayıtlı."], en: ["Response playbook", "the agent is paused, then network-isolated; every step is recorded."] },
	{ key: "policy-rollout", stage: "respond", evidence: ["packages/dashboard/src/ui/pages/PolicyPage.tsx"], tr: ["Aşamalı politika dağıtımı", "önce kanarya ajanlar, sonra filo; önceki sürüme dönüş."], en: ["Staged policy rollout", "canary agents first, then the fleet; roll back to a previous version."] },
	{ key: "file-quarantine-snapshot", stage: "respond", evidence: ["packages/core/src/quarantine.ts", "packages/core/src/rollback.ts"], tr: ["Dosya karantinası ve anlık görüntü", "riskli dosya ayrılır; korunan yol geri yüklenir (isteğe bağlı)."], en: ["File quarantine and snapshots", "risky files set aside; protected paths restorable (optional)."] },
	{ key: "operator-cli", stage: "respond", evidence: ["packages/cli/src/commands/allowlist.ts", "packages/cli/src/commands/audit.ts", "packages/cli/src/commands/doctor.ts"], tr: ["Operatör araçları", "<code>aidr pending</code>, <code>allowlist</code>, <code>audit</code>, <code>doctor</code>."], en: ["Operator tools", "<code>aidr pending</code>, <code>allowlist</code>, <code>audit</code>, <code>doctor</code>."] },
	// 7 Prove and improve
	{ key: "audit-export", stage: "prove", evidence: ["packages/core/src/audit-log.ts", "packages/cli/src/commands/audit.ts"], tr: ["Denetim kaydı ve dışa aktarım", "her kararın kuralı ve özeti; değer yazılmaz (JSONL, CSV)."], en: ["Audit log and export", "rule and summary of every decision; no values (JSONL, CSV)."] },
	{ key: "signed-audit-chain", stage: "prove", evidence: ["packages/core/src/response-audit.ts"], tr: ["İmzalı kayıt zinciri", "değiştirilemez kanıt için Ed25519 imzalı kayıtlar."], en: ["Signed record chain", "Ed25519-signed records for tamper-evident proof."] },
	{ key: "siem", stage: "prove", evidence: ["packages/core/src/siem-delivery.ts", "packages/core/src/siem-export.ts"], tr: ["SIEM teslimi", "Splunk, Microsoft Sentinel, Elastic ve webhook'a olaylar."], en: ["SIEM delivery", "events to Splunk, Microsoft Sentinel, Elastic and webhooks."] },
	{ key: "privacy-dashboard", stage: "prove", evidence: ["packages/dashboard/src/ui/pages/PrivacyGuardPage.tsx"], tr: ["Browser Privacy paneli", "maskelenen, uyarılan, engellenen gönderim sayıları; içerik yok."], en: ["Browser Privacy dashboard", "counts of masked, warned and blocked sends; no content."] },
	{ key: "attack-simulation", stage: "prove", evidence: ["packages/cli/src/commands/simulate.ts", "packages/cli/src/commands/simulate-corpus.ts"], tr: ["Saldırı simülasyonu ve skor kartı", "<code>aidr simulate</code> zararsız saldırıları ayarlarınıza karşı puanlar, çalıştırmaz."], en: ["Attack simulation and scorecard", "<code>aidr simulate</code> scores defanged attacks against your settings; nothing runs."] },
	// G Govern and comply
	{ key: "asset-register", stage: "govern", evidence: ["supabase/migrations/20260927000040_ai_governance_register.sql", "supabase/functions/ai-governance", "packages/dashboard/src/ui/pages/GovernanceRegisterPage.tsx"], tr: ["Yapay zekâ varlık envanteri", "ajan, MCP, site ve model; sahibi, amacı, veri kategorisi, risk seviyesi."], en: ["AI asset register", "agents, MCP, sites and models with owner, purpose, data and risk tier."] },
	{ key: "ai-bom", stage: "govern", evidence: ["packages/core/src/aibom", "packages/cli/src/commands/aibom.ts"], tr: ["AI-BOM", "ajan, MCP, model, eklenti ve bilinen açıklar; komut satırından ya da panelden CycloneDX 1.6."], en: ["AI-BOM", "agents, MCP, models, plugins and known flaws as CycloneDX 1.6, from the CLI or console."] },
	{ key: "intake-workflow", stage: "govern", evidence: ["supabase/functions/ai-governance", "packages/dashboard/src/ui/pages/GovernanceRequestsPage.tsx"], tr: ["Yeni araç talep ve onay akışı", "talebi başka biri karara bağlar; MCP yasağı ajanlara kendiliğinden ulaşır."], en: ["AI intake and approval workflow", "someone else decides each request; MCP bans reach agents automatically."] },
	{ key: "policy-change-control", stage: "govern", evidence: ["supabase/migrations/20260927000041_policy_change_control.sql", "packages/dashboard/src/ui/pages/GovernanceChangeControlPage.tsx"], tr: ["Dört göz politika değişikliği", "ikinci yönetici farkı görüp onaylar; sürüm geçmişi ve geri alma."], en: ["Four-eyes policy change", "a second admin reviews the diff and approves; version history and rollback."] },
	{ key: "timeboxed-exceptions", stage: "govern", evidence: ["supabase/migrations/20260927000040_ai_governance_register.sql", "packages/dashboard/src/ui/pages/GovernanceRequestsPage.tsx"], tr: ["Süreli istisnalar", "kişi ya da ajana özel istisna, süresi dolunca kendiliğinden kalkar."], en: ["Time-boxed exceptions", "a waiver for named people or agents expires on its own."] },
	{ key: "framework-mapping", stage: "govern", evidence: ["threats/mappings/frameworks.yaml", "packages/core/src/framework-mappings.ts", "packages/cli/src/commands/coverage.ts"], tr: ["Güvenlik çerçevesi eşlemesi", "kurallar OWASP LLM, OWASP Agentic, MITRE ATLAS ile eşlenir; madde başına kapsam."], en: ["Security framework mapping", "every rule mapped to OWASP LLM, OWASP Agentic, MITRE ATLAS; coverage per item."] },
	{ key: "governance-frameworks", stage: "govern", evidence: ["governance/frameworks", "packages/dashboard/src/lib/governance-frameworks.generated.ts"], tr: ["Yönetişim çerçeveleri", "NIST AI RMF, ISO/IEC 42001, AB Yapay Zekâ Yasası, KVKK/GDPR kontrolleri ve kanıtları."], en: ["Governance frameworks", "NIST AI RMF, ISO/IEC 42001, EU AI Act, KVKK/GDPR controls and their evidence."] },
	{ key: "compliance-report", stage: "govern", evidence: ["supabase/functions/compliance-report/index.ts"], tr: ["KVKK ve GDPR uyum raporu", "koruma kapsamı ve sayım kanıtları, imzalanabilir raporda."], en: ["KVKK and GDPR evidence report", "protection coverage and counts-only evidence in a signable report."] },
	{ key: "governance-scorecard", stage: "govern", evidence: ["supabase/migrations/20260927000060_governance_scorecard.sql", "supabase/functions/governance-digest", "packages/dashboard/src/ui/pages/GovernancePage.tsx"], tr: ["Yönetişim skor kartı", "riskler, çerçeve kapsamı, gözetim ve kullanım; haftada ya da ayda bir e-posta özeti."], en: ["Governance scorecard", "risks, framework coverage, oversight and usage; weekly or monthly e-mail summary."] },
	{ key: "acceptable-use", stage: "govern", evidence: ["packages/browser-guard/src/content/acceptable-use.ts"], tr: ["Kabul edilebilir kullanım bildirimi", "Browser Guard'da gösterilir, onaylar sayılır; AB Yapay Zekâ Yasası Madde 4 için."], en: ["Acceptable-use notice", "shown in Browser Guard, acknowledgements counted; supports EU AI Act Article 4."] },
	{ key: "team-roles", stage: "govern", evidence: ["supabase/functions/team-invite", "packages/dashboard/src/ui/pages/TeamPage.tsx"], tr: ["Ekip ve roller", "sahip, yönetici, üye, izleyici; e-posta davetleri."], en: ["Teams and roles", "owner, admin, member, viewer; email invitations."] },
	{ key: "team-audit", stage: "govern", evidence: ["supabase/functions/audit-export"], tr: ["Ekip denetim kaydı", "konsoldaki her yönetim işlemi, yapan kişiyle."], en: ["Team audit log", "every administrative action, with who did it."] },
	{ key: "retention", stage: "govern", evidence: ["supabase/migrations/20260912140000_tenant_offboarding_retention.sql"], tr: ["Saklama, yasal saklama, silme", "veri sınıfı başına süre; kayıtlı silme."], en: ["Retention, legal hold, deletion", "per data class; receipted deletion."] },
	// + Platform and deployment
	{ key: "tenancy", stage: "platform", evidence: ["supabase/migrations/20260805000000_hybrid_tenancy.sql"], tr: ["Kiracı yalıtımı", "veritabanında satır düzeyinde güvenlik."], en: ["Tenant isolation", "row-level security in the database."] },
	{ key: "identity", stage: "platform", evidence: ["supabase/functions/identity-security", "supabase/functions/scim"], tr: ["Kimlik", "Entra ID, SAML, SCIM, MFA, oturum iptali."], en: ["Identity", "Entra ID, SAML, SCIM, MFA, session revocation."] },
	{ key: "enrollment", stage: "platform", evidence: ["supabase/functions/device-start", "supabase/functions/enrollment-tokens"], tr: ["Cihaz kaydı", "kısa kodla onay; CI için tek kullanımlık belirteç."], en: ["Device enrollment", "short-code approval; one-time tokens for CI."] },
	{ key: "download-center", stage: "platform", evidence: ["packages/dashboard/src/ui/pages/DownloadsPage.tsx"], tr: ["İndirme merkezi", "her paket SHA&#8209;256 özetiyle doğrulanır."], en: ["Download center", "every package verified by SHA&#8209;256."] },
	{ key: "aidr-cli", stage: "platform", evidence: ["packages/cli/src/index.ts"], tr: ["<code>aidr</code> komut satırı", "kurulum, durum, yapılandırma, anahtar yenileme."], en: ["<code>aidr</code> command line", "setup, status, configuration, key rotation."] },
	{ key: "endpoint-installers", stage: "platform", evidence: ["scripts/endpoint-install.mjs", "deploy/fleet"], tr: ["Uç nokta dağıtımı", "yerel yükleyici; Windows, macOS, Linux betikleri."], en: ["Endpoint rollout", "local installer; Windows, macOS, Linux scripts."] },
	{ key: "local-mode", stage: "platform", evidence: ["packages/core/src/config.ts"], tr: ["Yerel mod", "hesap ve ağ olmadan, kurulumla başlayan koruma."], en: ["Local mode", "protection from install, no account or network."] },
	{ key: "integrity", stage: "platform", evidence: ["packages/core/src/integrity", "scripts/import-offline-pack.mjs"], tr: ["İmzalı bütünlük", "imzalı paket, kural ve istihbarat."], en: ["Signed integrity", "signed packages, rules and intel."] },
	{ key: "compose", stage: "platform", evidence: ["scripts/deployment-prepare.mjs", "deploy/onprem/resource-profile.json"], tr: ["Docker Compose", "kurum içi tek sunucu; üç kaynak profili."], en: ["Docker Compose", "one on-prem host; three resource profiles."] },
	{ key: "helm", stage: "platform", evidence: ["deploy/helm/aidr/Chart.yaml"], tr: ["Kubernetes Helm", "zayıf yapılandırmayla kurulmayı reddeder."], en: ["Kubernetes Helm", "refuses to install with a weak configuration."] },
	{ key: "air-gapped", stage: "platform", evidence: ["scripts/build-airgap-images.mjs", "scripts/license-verify.mjs"], tr: ["Ağdan yalıtılmış kurulum", "imzalı çevrim dışı lisans ve paketler."], en: ["Air-gapped install", "signed offline licence and packs."] },
	{ key: "tls", stage: "platform", evidence: ["scripts/deployment-tls-renew.mjs"], tr: ["TLS", "ACME ile yenileme ya da kurumun sertifikası."], en: ["TLS", "ACME renewal or your own certificate."] },
	{ key: "upgrade-backup", stage: "platform", evidence: ["scripts/deployment-upgrade.mjs", "scripts/deployment-backup.mjs"], tr: ["Yükseltme ve yedekleme", "kesintiye dayanıklı yükseltme, şifreli yedek."], en: ["Upgrades and backups", "interruption-safe upgrades, encrypted backups."] },
	{ key: "monitoring", stage: "platform", evidence: ["deploy/monitoring"], tr: ["İzleme ve uyarılar", "hazırlık denetimleri, Prometheus kuralları."], en: ["Monitoring and alerting", "readiness checks, Prometheus rules."] },
	{ key: "operator-admin", stage: "platform", evidence: ["scripts/operator-admin.mjs", "supabase/functions/operator-admin"], tr: ["Operatör yönetimi", "lisans ve kullanım, MFA ile."], en: ["Operator administration", "licences and usage, behind MFA."] },
	{ key: "version-check", stage: "platform", evidence: ["packages/core/src/version-check.ts"], tr: ["Sürüm bildirimi", "yeni sürüm çıktığında bilgilendirir."], en: ["Update notices", "tells you when a new version is out."] },
];

/**
 * Shipped safety controls that are already numbered elsewhere in the list. The safety group
 * cross-references them (`refs`) instead of listing them twice. `evidence` pairs a path with
 * a pattern its content must match (checked by the facts test).
 */
export const SAFETY_ALSO = [
	{ key: "human-approval", refs: ["verdicts", "operator-approval"], evidence: [["packages/core/src/operator-approvals.ts", "approv"]], tr: "Riskli eylemde insan onayı", en: "Human approval for risky actions" },
	{ key: "destructive-commands", refs: ["threat-rules"], evidence: [["threats/commands.yaml", "Destructive operations"]], tr: "Yıkıcı komut engelleme", en: "Destructive-command blocking" },
	{ key: "self-defense", refs: ["self-defense"], evidence: [["threats/self-defense.yaml", "- id:"]], tr: "Öz-savunma", en: "Self-defence" },
	{ key: "cryptomining", refs: ["threat-rules"], evidence: [["threats/mining.yaml", "- id:"]], tr: "Kripto madenciliği tespiti", en: "Cryptomining detection" },
	{ key: "injection-jailbreak", refs: ["threat-rules"], evidence: [["threats/llm-threats.yaml", "category: prompt_injection"], ["threats/llm-threats.yaml", "jailbreak"]], tr: "Prompt injection ve jailbreak kuralları", en: "Prompt-injection and jailbreak rules" },
	{ key: "memory-poisoning", refs: ["threat-rules"], evidence: [["threats/llm-threats.yaml", "category: memory_poisoning"]], tr: "Bellek zehirleme kuralları", en: "Memory-poisoning rules" },
	{ key: "excessive-agency", refs: ["threat-rules"], evidence: [["threats/llm-threats.yaml", "Excessive Agency"]], tr: "Aşırı yetki sınırları", en: "Excessive-agency limits" },
];

/* ------------------------------------------------------------------------------------ */
/* Page templates. `h` supplies t(), fact(), icon(), featureList(), page(), stageIntro(). */
/* ------------------------------------------------------------------------------------ */

const STAGE_NAV = [
	["Keşfet", "Discover", "envanter", "inventory"],
	["Değerlendir", "Assess", "risk ve açıklar", "risk and CVEs"],
	["Koru", "Protect", "maskeleme, DLP", "masking, DLP"],
	["Denetle", "Control", "allow · ask · deny", "allow · ask · deny"],
	["İncele", "Inspect", "araç çıktıları", "tool output"],
	["Onayla", "Approve", "onay ve müdahale", "approval, response"],
	["Kanıtla", "Prove", "kanıt ve iyileştirme", "evidence, improvement"],
];

function cover(h) {
	const { t } = h;
	return `<section class="page cover" id="p-cover" aria-label="${t("Kapak", "Cover")}">
	<div class="top"><span>${t("Ürün Kataloğu", "Product Catalog")}</span><span>2026</span></div>
	<div class="cover-logo" role="img" aria-label="Singularity"></div>
	<h1>Singularity AIDR</h1>
	<div class="kind">${t("Ürün Kataloğu", "Product Catalog")}</div>
	<div class="rule"></div>
	<p class="pos">${t("Yapay zekâ ajan güvenliğinin tüm yaşam döngüsü, tek platformda.", "The entire AI agent security lifecycle, in one platform.")}</p>
	<p class="pos2">${t("Yapay zekâ ajanları ve yapay zekâ sohbet araçları için tespit, müdahale ve veri gizliliği", "Detection, response and data privacy for AI agents and AI chat tools")}</p>
	<div class="stages">
${STAGE_NAV.map(([tr, en, str, sen], i) => `\t\t<div><b><span>${i + 1}</span>${t(tr, en)}</b>${t(str, sen)}</div>`).join("\n")}
	</div>
	<div class="contact"><span><b>singularityrd.com</b></span><span>anil@singularityrd.com</span></div>
</section>`;
}

function lifecycleSvg(h) {
	const { t } = h;
	const nodes = [
		[360, 60],
		[497.6, 102.2],
		[531.6, 196.9],
		[436.4, 272.9],
		[283.6, 272.9],
		[188.4, 196.9],
		[222.4, 102.2],
	];
	const arrows = [
		[436.4, 71.1, 17],
		[531.6, 147.1, 70.3],
		[497.6, 241.8, 141.4],
		[360, 284, 180],
		[222.4, 241.8, -141.4],
		[188.4, 147.1, -70.3],
	];
	// [x, y, anchor, title lines, sub]
	const labels = [
		[360, 25, "middle", [t("KEŞFET", "DISCOVER")], t("envanter · gölge YZ", "inventory · shadow AI")],
		[527, 99, "start", [t("DEĞERLENDİR", "ASSESS")], t("CVE · MCP riski", "CVEs · MCP risk")],
		[561, 193, "start", [t("VERİYİ KORU", "PROTECT DATA")], t("maskeleme · DLP", "masking · DLP")],
		[466, 270, "start", [t("EYLEMİ DENETLE", "CONTROL ACTIONS")], "allow · ask · deny"],
		[254, 270, "end", [t("ÇIKTIYI İNCELE", "INSPECT OUTPUT")], t("karantina · zehirlenme", "quarantine · poisoning")],
		[158, 186, "end", t(["ONAYLA VE", "MÜDAHALE ET"], ["APPROVE AND", "RESPOND"]), t("onay · olay · uyarı", "approval · alerts")],
		[192, 99, "end", [t("KANITLA VE İYİLEŞTİR", "PROVE AND IMPROVE")], t("kayıt · simülasyon", "audit · simulation")],
	];
	const labelSvg = labels
		.map(([x, y, anchor, lines, sub]) => {
			const titles = lines.map((line, i) => `<text x="${x}" y="${y + i * 14}" text-anchor="${anchor}" font-size="12.5" font-weight="700" letter-spacing="1.1" class="d-ink">${line}</text>`).join("");
			return `${titles}<text x="${x}" y="${y + lines.length * 14}" text-anchor="${anchor}" font-size="11" class="d-mute">${sub}</text>`;
		})
		.join("\n\t\t\t");
	return `<figure class="diagram" style="margin:0">
		<svg viewBox="0 0 720 345" role="img" aria-label="${t("Yedi aşamalı yaşam döngüsü ve tüm aşamaları kapsayan yönetişim katmanı", "Seven-stage lifecycle with a governance layer spanning every stage")}">
			<rect x="2" y="10" width="716" height="332" rx="18" fill="none" stroke="#3862e8" stroke-width="1.2" stroke-dasharray="5 4"/>
			<rect x="16" y="1" width="${t(150, 162)}" height="19" rx="9.5" fill="#3862e8"/>
			<text x="${t(91, 97)}" y="14.5" text-anchor="middle" font-size="9.5" font-weight="700" letter-spacing="1.2" fill="#fff">${t("YÖNET VE UYUMLA", "GOVERN AND COMPLY")}</text>
			<ellipse cx="360" cy="172" rx="176" ry="112" fill="none" stroke="#cdcdcd" stroke-width="1.2"/>
			<path d="M222.4 102.2 L231.0 95.8 L240.3 89.9 L250.3 84.4 L260.9 79.5 L272.0 75.0 L283.6 71.1 L295.7 67.7 L308.1 65.0 L320.8 62.8 L333.8 61.3 L346.8 60.3 L360.0 60.0" fill="none" stroke="#3862e8" stroke-width="2.6"/>
			<g fill="none" stroke="#3862e8" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
				${arrows.map(([x, y, a]) => `<path d="M-4 -4.5L2 0l-6 4.5" transform="translate(${x} ${y}) rotate(${a})"/>`).join("\n\t\t\t\t")}
				<path d="M-4 -4.5L2 0l-6 4.5" transform="translate(283.6 71.1) rotate(-17)"/>
			</g>
			<text x="300" y="95" text-anchor="middle" font-size="10" font-weight="700" class="d-acc">${t("politikayı günceller", "updates the policy")}</text>
			${nodes.map(([x, y], i) => `<circle cx="${x}" cy="${y}" r="19" fill="#0a0a0a"/><text x="${x}" y="${y + 5}" text-anchor="middle" font-size="14" font-weight="700" fill="#fff">${i + 1}</text>`).join("\n\t\t\t")}
			${labelSvg}
			<text x="360" y="162" text-anchor="middle" font-size="17" font-weight="700" class="d-ink">Singularity AIDR</text>
			<text x="360" y="182" text-anchor="middle" font-size="11.5" class="d-mute">${t("tek platform", "one platform")}</text>
			<text x="360" y="198" text-anchor="middle" font-size="11.5" class="d-mute">${t("uç noktada verilen tek karar modeli", "one decision model, on the endpoint")}</text>
		</svg>
	</figure>`;
}

function lifecycle(h) {
	const { t, fact, page } = h;
	const legend = [
		[1, t("Keşfet", "Discover"), t("Filo envanteri · MCP keşfi · Sürekli envanter · Gölge yapay zekâ", "Fleet inventory · MCP discovery · Continuous inventory · Shadow AI")],
		[2, t("Değerlendir", "Assess"), t("CVE taraması · Taramadan politikaya · Skill taraması · Duruş paneli", "CVE scan · Scan-to-policy · Skill scan · Posture dashboard")],
		[3, t("Veriyi koru", "Protect data"), t("Browser Guard maskeleme · İstem koruması · DLP · Tam veri eşleştirme", "Browser Guard masking · Prompt protection · DLP · Exact data match")],
		[4, t("Eylemi denetle", "Control actions"), t("allow/ask/deny · MCP Gateway · Zehirli akış · Yapay zekâ güvenliği (safety)", "allow/ask/deny · MCP Gateway · Toxic flow · AI safety")],
		[5, t("Çıktıyı incele", "Inspect output"), t("Çıktı taraması · Karantina · Zehirlenme koruması", "Output scanning · Quarantine · Poisoning protection")],
		[6, t("Onayla ve müdahale et", "Approve and respond"), t("Operatör onayı · Panelden onay · Uyarılar · Müdahale", "Operator approval · Dashboard approvals · Alerts · Response")],
		[7, t("Kanıtla ve iyileştir", "Prove and improve"), t("Denetim kaydı · SIEM · Simülasyon, politikaya geri döner", "Audit log · SIEM · Simulation feeds back into policy")],
		["G", t("Yönet ve uyumla", "Govern and comply"), t("Varlık envanteri · Talep ve onay · Dört göz · Çerçeve eşlemesi", "Asset register · Intake · Four-eyes change · Framework mapping")],
	];
	const lines = [
		["terminal", t("Kodlama ajanları için AIDR", "AIDR for coding agents"), t(`${fact("connectors")} bağlayıcı, ${fact("threat-rules")} kural, MCP Gateway, SDK`, `${fact("connectors")} connectors, ${fact("threat-rules")} rules, MCP Gateway, SDK`)],
		["browser", "AIDR Browser Guard", t(`${fact("bg-sites")} yapay zekâ sitesi, ${fact("bg-entities")} veri türü, geri alınabilir maskeleme`, `${fact("bg-sites")} AI chat sites, ${fact("bg-entities")} data types, reversible masking`)],
		["finger", t("AIDR Privacy motoru", "AIDR Privacy engine"), t("Türkçe/İngilizce tespit; tarayıcıda, ajanlarda ve komut satırında aynı kurallar", "Turkish/English detection; the same rules in the browser, in agents and on the CLI")],
		["radar", t("Yapay Zekâ Güvenlik Duruşu", "AI Security Posture"), t(`${fact("ai-components")} bileşen, ${fact("cve-rules")} CVE kuralı, ${fact("mcp-categories")} MCP risk kategorisi`, `${fact("ai-components")} components, ${fact("cve-rules")} CVE rules, ${fact("mcp-categories")} MCP risk categories`)],
	];
	const body = `	<h2 class="title">${t("Yapay zekâ ajan güvenliğinin tüm yaşam döngüsü, <em>tek platformda</em>", "The entire AI agent security lifecycle, <em>in one platform</em>")}</h2>
	<p class="lead">${t("Singularity AIDR, yapay zekâ ajanlarını ve sohbet araçlarını keşiften kanıta kadar izler: neyin var olduğunu bulur, riskini ölçer, veriyi korur, eylemi denetler, çıktıyı inceler, insan onayını ve müdahaleyi yönetir, sonucu kanıtlar. Simülasyon ve kapsam sonuçları politikaya geri döner; yönetişim katmanı tüm aşamaları kapsar.", "Singularity AIDR follows AI agents and AI chat tools from discovery to proof: it finds what exists, measures the risk, protects data, controls actions, inspects output, manages human approval and response, and proves the outcome. Simulation and coverage results feed back into policy, and a governance layer spans every stage.")}</p>
	${lifecycleSvg(h)}
	<div class="legend mt3">
${legend.map(([n, name, items]) => `\t\t<div class="it${n === "G" ? " loop" : ""}"><b><span>${n}</span>${name}</b>${items}</div>`).join("\n")}
	</div>
	<h3 class="mt3">${t("Ürün hatları", "Product lines")}</h3>
	<div class="g4 mt1">
${lines.map(([icon, name, text]) => `\t\t<div class="block"><div class="head">${h.icon(icon)}<h4>${name}</h4></div><p class="small mb0">${text}</p></div>`).join("\n")}
	</div>`;
	return page("p-lifecycle", t("Uçtan uca yaşam döngüsü", "End-to-end lifecycle"), t("Uçtan uca yaşam döngüsü", "End-to-end lifecycle"), body);
}

function coverage(h) {
	const { t, page, icon } = h;
	const Y = (text) => `<td class="y">${icon("check", "")}${text}</td>`;
	const N = `<td class="n">—</td>`;
	const rows = [
		[1, t("Keşfet", "Discover"), [Y(t("filo envanteri", "fleet inventory")), Y(t("MCP keşfi", "MCP discovery")), Y(t("gölge yapay zekâ", "shadow AI")), Y(t("sürekli envanter", "continuous inventory")), Y(t("varlık envanteri", "asset register"))]],
		[2, t("Değerlendir", "Assess"), [Y(t("skill taraması, ajan ortamı", "skill scan, agent environment")), Y(t(`${h.fact("mcp-categories")} risk kategorisi`, `${h.fact("mcp-categories")} risk categories`)), Y(t("İzle modu ölçümü", "Monitor-mode baseline")), Y(t("CVE taraması", "CVE scan")), Y(t("duruş paneli", "posture dashboard"))]],
		[3, t("Veriyi koru", "Protect data"), [Y(t("istem koruması, DLP", "prompt protection, DLP")), Y(t("argümanlarda DLP", "DLP on arguments")), Y(t("geri alınabilir maskeleme", "reversible masking")), N, Y(t("kurumsal politika", "managed policy"))]],
		[4, t("Eylemi denetle", "Control actions"), [Y("allow · ask · deny"), Y(t("MCP politikası, Gateway", "MCP policy, Gateway")), Y(t("site engelleme", "site blocking")), Y(t("taramadan politikaya", "scan-to-policy")), Y(t("dört göz politika", "four-eyes policy"))]],
		[5, t("Çıktıyı incele", "Inspect output"), [Y(t("çıktı taraması, zehirlenme", "output scan, poisoning")), Y(t("sonuç denetimi, araç zehirleme", "result inspection, tool poisoning")), N, N, N]],
		[6, t("Onayla ve müdahale et", "Approve and respond"), [Y(t("operatör onayı", "operator approval")), Y(t("araç seti onayı", "toolset approval")), Y(t("Onayla modu", "Confirm mode")), N, Y(t("panelden onay, uyarılar", "dashboard approval, alerts"))]],
		[7, t("Kanıtla ve iyileştir", "Prove and improve"), [Y(t("denetim kaydı, simülasyon", "audit log, simulation")), Y(t("bulgu kaydı", "findings record")), Y(t("sayım paneli", "counts dashboard")), Y(t("CVE bulguları", "CVE findings")), Y(t("KVKK/GDPR raporu", "KVKK/GDPR report"))]],
		["S", t('Yapay zekâ güvenliği<br>(<span lang="en">safety</span>)', "AI safety"), [Y(t("insan onayı, kaçak ajan, sabotaj", "human approval, runaway, sabotage")), Y(t("kaçak ajan sınırları", "runaway guard")), N, Y(t("güvenli model yükleme", "safe model loading")), Y(t("insan gözetimi ölçümleri", "human-oversight metrics"))]],
	];
	const why = [
		["laptop", t("Önce yerel işleme", "Local-first processing"), t("Tespit ve karar cihazda verilir; ajanlar ve Browser Guard hesap ya da ağ olmadan korur.", "Detection and decisions happen on the device; agents and Browser Guard are protected with no account or network.")],
		["mask", t("Geri alınabilir maskeleme", "Reversible masking"), t("Yapay zekâ bağlamı kaybetmez; özgün değer yalnızca kullanıcının ekranında geri gelir.", "The AI keeps its context; the original value comes back only on the user's screen.")],
		["finger", t("Türkiye'ye özgü tespit", "Turkish-specific detection"), t("T.C. kimlik ve IBAN sağlamayla; Türkçe telefon, adres, etiket ve gizlilik dereceleri.", "T.C. Kimlik and IBAN by checksum; Turkish phones, addresses, labels and classification marks.")],
		["loop", t("Ajanlar ve sohbet için aynı motor", "One engine for agents and chat"), t("Aynı TR/EN kurallar tarayıcıda, ajanların DLP'sinde ve komut satırında çalışır.", "The same TR/EN rules run in the browser, in agent DLP and on the command line.")],
		["usercheck", t("Denetlenebilir kararlar", "Auditable decisions"), t("Kurallar okunabilir veridir; onayı ajan değil, bir insan verir.", "Rules are readable data, and a person, not the agent, gives approval.")],
		["server", t("Kurulum seçeneği sizin", "Your choice of deployment"), t("Bulut, kurum içi ya da ağdan yalıtılmış; lisans bitse de yerel koruma sürer.", "Cloud, on-premises or air-gapped; local protection continues even if a licence lapses.")],
	];
	const body = `	<h2 class="title">${t("Kapsam: <em>her aşama, her yüzey</em>", "Coverage: <em>every stage, every surface</em>")}</h2>
	<p class="lead">${t("Tablo, her aşamanın hangi yüzeyde ve hangi özellikle karşılandığını gösterir; son satır ajanın kendi davranışından doğan riskleri kapsar. Boş hücreler kapsam dışıdır.", "The table shows which feature covers each stage on each surface; the last row covers risks from the agent's own behaviour. Empty cells are out of scope.")}</p>
	<table class="t cov">
		<thead><tr><th style="width:21%">${t("Aşama", "Stage")}</th><th>${t("Kodlama ajanları", "Coding agents")}</th><th>${t("MCP araçları", "MCP tools")}</th><th>${t("Yapay zekâ sohbet siteleri", "AI chat sites")}</th><th>${t("Yapay zekâ altyapısı", "AI infrastructure")}</th><th>${t("Yönetişim", "Governance")}</th></tr></thead>
		<tbody>
${rows.map(([n, name, cells]) => `\t\t\t<tr><td class="st"><span class="sn">${n}</span><span class="nm">${name}</span></td>${cells.join("")}</tr>`).join("\n")}
		</tbody>
	</table>
	<h3 class="mt4">${t("Neden Singularity AIDR?", "Why Singularity AIDR?")}</h3>
	<div class="g3 mt1">
${why.map(([icon, name, text]) => `\t\t<div class="block"><div class="head"><span class="ic k">${h.icon(icon)}</span><h4>${name}</h4></div><p class="mb0">${text}</p></div>`).join("\n")}
	</div>
	${trifectaHighlight(h)}`;
	return page("p-coverage", t("Kapsam ve farklar", "Coverage and differentiators"), t("Kapsam", "Coverage"), body);
}

function discoverAssess(h) {
	const { t, page, stageIntro, featureList, gain } = h;
	const components = ["Ollama", "vLLM", "ComfyUI", "Dify", "Langflow", "Gradio", "Jupyter", "Open WebUI", "LiteLLM", "Flowise", "MLflow", "Ray"];
	// The MCP risk taxonomy (EN names are the category names the product reports).
	const mcpCategories = [
		["Anahtar ve sır ifşası", "Token Mismanagement &amp; Secret Exposure"],
		["Kapsam genişlemesiyle yetki yükseltme", "Privilege Escalation via Scope Creep"],
		["Araç zehirleme", "Tool Poisoning"],
		["Yazılım tedarik zinciri saldırısı", "Software Supply Chain Attacks"],
		["Komut enjeksiyonu ve çalıştırma", "Command Injection &amp; Execution"],
		["Bağlamsal içerikle prompt injection", "Prompt Injection via Contextual Payloads"],
		["Yetersiz kimlik doğrulama ve yetkilendirme", "Insufficient Auth &amp; Authorization"],
		["Denetim ve telemetri eksikliği", "Lack of Audit and Telemetry"],
		["Gölge MCP sunucuları", "Shadow MCP Servers"],
		["Bağlam enjeksiyonu ve aşırı paylaşım", "Context Injection &amp; Over-Sharing"],
		["Ad karışıklığı saldırısı", "Name Confusion Attack"],
		["Rug pull saldırısı", "Rug Pull Attack"],
		["Araç gölgeleme saldırısı", "Tool Shadowing Attack"],
		["CORS yanlış yapılandırması", "CORS Misconfiguration"],
	];
	const skillTypes = [
		["T01", "Talimat ele geçirme", "Instruction hijacking"],
		["T02", "Bellek zehirleme", "Memory poisoning"],
		["T03", "Uzaktan kod çalıştırma", "Remote payload execution"],
		["T04", "Gömülü zararlı kod", "Embedded malicious code"],
		["T05", "Yetki yükseltme", "Privilege escalation"],
		["T06", "Kalıcılık", "Persistence"],
		["T07", "Araç ele geçirme", "Tool hijacking"],
		["T08", "Güvensiz bağımlılık", "Insecure dependencies"],
		["T09", "Güvensiz kodlama", "Insecure coding"],
	];
	const body = `	<div class="stage-block">
	${stageIntro("discover")}
	${featureList("discover")}
	<p class="lbl mt2">${t(`MCP risk kategorileri (${h.fact("mcp-categories")})`, `MCP risk categories (${h.fact("mcp-categories")})`)}</p>
	<div class="chips-tight">${mcpCategories.map(([tr, en]) => `<span class="chip" data-mcp-category>${t(tr, en)}</span>`).join("")}</div>
	${gain("discover")}
	</div>
	<div class="stage-block">
	${stageIntro("assess")}
	${featureList("assess")}
	<p class="lbl mt2">${t('<span lang="en">Skill</span> ve eklenti risk türleri', "Skill and plugin risk types")}</p>
	<div class="chips-tight">${skillTypes.map(([code, tr, en]) => `<span class="chip"><b>${code}</b> ${t(tr, en)}</span>`).join("")}</div>
	<div class="g2 mt3">
		<div><p class="lbl">${t("Tanınan bileşenlerden örnekler", "Examples of recognised components")}</p><div>${components.map((c) => `<span class="chip" data-component="${c}">${c}</span>`).join("")}</div></div>
		<div class="how start"><p class="lbl">${t("Panele ne gider?", "What reaches the console?")}</p><p class="mb0">${t("Yalnızca CVE kimliği, önem derecesi, bileşen ve sürüm, kural kimliği ve özetler. Hedef adresleri, dosya yolları, eşleşen metin ve kimlik bilgileri cihazda kalır. Ulaşılamayan hedef hiçbir zaman \"temiz\" sayılmaz.", "Only CVE IDs, severities, component and version, rule IDs and digests. Target addresses, file paths, matched text and credentials stay on the device. An unreachable target is never reported as clean.")}</p></div>
	</div>
	${gain("assess")}
	</div>`;
	return page("p-discover", t("Keşfet ve değerlendir", "Discover and assess"), t("Aşama 1–2", "Stages 1–2"), body);
}

function protect(h) {
	const { t, page, stageIntro, featureList, gain } = h;
	const sites = ["ChatGPT", "Gemini", "Claude", "Copilot", "Perplexity", "DeepSeek", "Mistral", "Grok"];
	const ph = (s) => `<span class="ph">[${s}]</span>`;
	const pii = (s) => `<span class="pii">${s}</span>`;
	const kept = (s) => `<span class="kept">${s}</span>`;
	const body = `	${stageIntro("protect")}
	<div class="ba">
		<div class="who">${t("Kullanıcının yazdığı", "What the user types")}</div><div>${t("Sayın", "Draft a refund letter to Mrs.")} ${pii("Ayşe Yılmaz")}${t(" için iade yazısı hazırla.", ".")} TCKN ${pii("10000000146")}, IBAN ${pii("TR33 0006 1005 1978 6457 8413 26")}, ${t("e-posta", "email")} ${pii("ayse.yilmaz@example.com")}, ${t("anahtar", "key")} ${pii("AKIAIOSFODNN7EXAMPLE")}</div>
		<div class="who alt">${t("Sitenin aldığı", "What the site receives")}</div><div class="alt">${t("Sayın", "Draft a refund letter to Mrs.")} ${ph("PERSON_1")}${t(" için iade yazısı hazırla.", ".")} TCKN ${ph("TCKN_1")}, IBAN ${ph("IBAN_1")}, ${t("e-posta", "email")} ${ph("EMAIL_1")}, ${t("anahtar", "key")} ${ph("SECRET_1")}</div>
		<div class="who scr">${t("Kullanıcının ekranında", "On the user's screen")}</div><div class="scr">${t(`Sayın ${kept("Ayşe Yılmaz")}, iadeniz ${kept("TR33 0006 1005 1978 6457 8413 26")} hesabına yapılacak; ${kept("ayse.yilmaz@example.com")} adresine bilgi verilecek. ${ph("SECRET_1")} anahtarını yenileyin.`, `Dear ${kept("Ayşe Yılmaz")}, your refund goes to ${kept("TR33 0006 1005 1978 6457 8413 26")}; we will write to ${kept("ayse.yilmaz@example.com")}. Rotate ${ph("SECRET_1")}.`)}</div>
	</div>
	<p class="tiny mt1">${t("Maskeleme ve geri yükleme bu örnekte Browser Guard'ın varsayılan ayarlarıyla üretildi; yanıt temsilîdir. Anahtar geri gösterilmez.","Masking and restore were produced with Browser Guard's default settings on this example; the answer is illustrative. The key is never shown again.")}</p>
	${featureList("protect", { groups: [{ key: "browser", lang: "en", tr: `AIDR Browser Guard · ${sites.join(" · ")} · Chrome, Edge, Firefox`, en: `AIDR Browser Guard · ${sites.join(" · ")} · Chrome, Edge, Firefox` }, { key: "agents", tr: "Kodlama ajanları ve komut satırı", en: "Coding agents and the command line" }] })}
	${gain("protect")}`;
	return page("p-protect", t("Veriyi koru", "Protect data"), t("Aşama 3", "Stage 3"), body);
}

/** Flagship callout for toxic-flow detection (feature listed under Control actions). */
function trifectaHighlight(h) {
	const { t, ref } = h;
	const venn = `<figure class="diagram" style="margin:0">
			<svg viewBox="0 0 300 214" role="img" aria-label="${t("Özel veri, güvenilmeyen içerik ve dış kanal kesiştiğinde adım onay bekler", "Where private data, untrusted content and an external channel meet, the step waits for approval")}">
				<g fill="#ffffff" fill-opacity="0.05" stroke="#ffffff" stroke-opacity="0.55" stroke-width="1.2">
					<circle cx="112" cy="80" r="64"/><circle cx="188" cy="80" r="64"/><circle cx="150" cy="144" r="64"/>
				</g>
				<g font-size="12.5" fill="#ffffff" text-anchor="middle" font-weight="700">
					<text x="86" y="62">${t("Özel veri", "Private data")}</text>
					<text x="206" y="56">${t("Güvenilmeyen", "Untrusted")}</text><text x="206" y="71">${t("içerik", "content")}</text>
					<text x="150" y="186">${t("Dış kanal", "External channel")}</text>
				</g>
				<rect x="${t(106, 101)}" y="94" width="${t(88, 98)}" height="22" rx="11" fill="#3862e8"/>
				<text x="150" y="109" text-anchor="middle" font-size="11" font-weight="700" fill="#fff">${t("onay bekler", "step held")}</text>
			</svg>
		</figure>`;
	return `<div class="highlight mt4">
		<div>
			<p class="lbl">${t("Öne çıkan · Eylemi denetle", "Highlight · Control actions")} ${ref("toxic-flow")}</p>
			<h3>${t("Zehirli akış (lethal trifecta) ve saldırı zinciri tespiti", "Toxic flow (lethal trifecta) and attack-chain detection")}</h3>
			<p class="mb0">${t("Bir ajan aynı oturumda özel veriye dokunur, güvenilmeyen içerik okur ve dış bir kanala erişebilirse veri sızdırmak için gereken her şey bir aradadır. AIDR oturum boyunca bu üç koşulu izler; zinciri tamamlayacak adımı insan onayına bırakır, en sıkı ayarda doğrudan engeller. Anahtar okunduktan sonra dışa gönderim ve güvenilmeyen içerikten sonra yıkıcı komut zincirleri de yakalanır.", "If one session lets an agent touch private data, read untrusted content and reach an external channel, everything needed to exfiltrate data is in place. AIDR tracks these three conditions across the session and holds the step that would complete the chain for a person's approval, or blocks it at the strictest setting. Sending data out after a secret was read, and destructive commands after untrusted content, are caught as well.")}</p>
		</div>
		${venn}
	</div>`;
}

function control(h) {
	const { t, page, stageIntro, featureList, gain, ref } = h;
	const also = SAFETY_ALSO.map((item) => `<span class="also" data-safety="${item.key}">${t(item.tr, item.en)} ${item.refs.map(ref).join(" ")}</span>`).join(" · ");
	const body = `	${stageIntro("control")}
	${featureList("control", { groups: [{ key: null }, { key: "safety", cls: "acc", tr: 'Yapay zekâ güvenliği (<span lang="en">safety</span>) · ajanın kendi davranışından doğan riskler', en: "AI safety · risks from the agent's own behaviour" }] })}
	<p class="xref"><span class="k">${t("Ayrıca kapsanır", "Also covered")}</span>${also}</p>
	${gain("control")}`;
	return page("p-control", t("Eylemi denetle", "Control actions"), t("Aşama 4", "Stage 4"), body);
}

function inspectRespond(h) {
	const { t, page, stageIntro, featureList, gain } = h;
	const body = `	<div class="stage-block">
	${stageIntro("inspect")}
	${featureList("inspect")}
	<div class="highlight solo">
		<div>
			<p class="lbl">${t('Öne çıkan · <span lang="en">OWASP LLM04</span> ve <span lang="en">Agentic ASI06</span>', "Highlight · OWASP LLM04 and Agentic ASI06")}</p>
			<h3>${t("Veri ve bağlam zehirlenmesi koruması", "Data and context poisoning protection")}</h3>
			<ul class="b tight">
				<li>${t("<b>Talimat ve bellek dosyaları</b> (CLAUDE.md, AGENTS.md, .cursorrules, MCP ve ajan ayarları) çalışma anında korunur: yazma onay ister, görünmez Unicode ve gizli talimatlar engellenir.", "<b>Instruction and memory files</b> (CLAUDE.md, AGENTS.md, .cursorrules, MCP and agent settings) are guarded at runtime: writes need approval; invisible Unicode and hidden instructions are blocked.")}</li>
				<li>${t("<b>Okunan içerik</b> (dosyalar, çekilen sayfalar, araç çıktısı) taranır: gizli yükler modele ulaşmaz, şüpheli talimatlar için modele uyarı eklenir.", "<b>Content the agent reads</b> (files, fetched pages, tool output) is scanned: hidden payloads are kept from the model, and suspicious directives come with a warning to it.")}</li>
				<li>${t("<b>MCP araç zehirleme ve rug pull:</b> araç tanımları gizli talimat için taranır; onaylı araç listesi sabitlenir, sonraki her değişiklik operatör yeniden onaylayana kadar engellenir.", "<b>MCP tool poisoning and rug pulls:</b> tool descriptions are scanned for hidden instructions; the approved tool list is pinned and any later change is blocked until an operator re-approves.")}</li>
				<li>${t("<b>Bellek ve vektör deposu yazımları</b> kaydedilmeden önce taranır; paket denetimi açıkken <b>uydurma paket adları</b> (slopsquatting) durdurulur.", "<b>Memory and vector-store writes</b> are scanned before they are stored; with package checks on, <b>invented package names</b> (slopsquatting) are stopped.")}</li>
			</ul>
		</div>
	</div>
	<p class="tiny mt1" data-limits="codex">${t("Codex CLI sınırları: yalnızca Bash ve apply_patch çağrıları denetlenir; araç çıktısı modelden önce incelenmez; kanca çöker ya da güvenilmezse Codex çağrıyı geçirir (bağlayıcı kendi hatalarını ve ask kararını deny'a çevirir).", "Codex CLI limits: only Bash and apply_patch calls are checked; tool output is not inspected before the model; Codex lets a call through if its hook crashes or is not trusted (the connector turns its own errors and ask into deny).")}</p>
	${gain("inspect")}
	</div>
	<div class="stage-block">
	${stageIntro("respond")}
	${featureList("respond")}
	${gain("respond")}
	</div>`;
	return page("p-inspect", t("Çıktıyı incele, onayla ve müdahale et", "Inspect output, approve and respond"), t("Aşama 5–6", "Stages 5–6"), body);
}

function proveGovern(h) {
	const { t, page, stageIntro, featureList, gain } = h;
	const frameworks = ["OWASP LLM Top 10 (2025)", "OWASP Agentic Top 10 (2026)", "MITRE ATLAS", "NIST AI RMF", "ISO/IEC 42001", t("AB Yapay Zekâ Yasası", "EU AI Act"), "KVKK", "GDPR"];
	const body = `	<div class="stage-block">
	${stageIntro("prove")}
	${featureList("prove")}
	${gain("prove")}
	</div>
	<div class="stage-block">
	${stageIntro("govern")}
	${featureList("govern")}
	<p class="lbl mt3">${t("Eşlenen çerçeveler", "Frameworks mapped")}</p>
	<div>${frameworks.map((f) => `<span class="chip">${f}</span>`).join("")}</div>
	<p class="tiny mb0">${t("KVKK ve GDPR yükümlülüklerini desteklemek üzere tasarlandı. Rapor ve eşlemeler hesap verebilirlik çalışmasını destekler; tek başına bir uyumluluk belgesi değildir. Kapsam her madde için açıkça gösterilir: örneğin ajanlar arası iletişim ve zincirleme hatalar (OWASP Agentic ASI07, ASI08) kapsam dışıdır.", "Designed to support KVKK and GDPR obligations. Reports and mappings support accountability work; they are not a compliance attestation on their own. Coverage is stated per item: for example, inter-agent communication and cascading failures (OWASP Agentic ASI07, ASI08) are not covered.")}</p>
	${gain("govern")}
	</div>`;
	return page("p-prove", t("Kanıtla, yönet ve uyumla", "Prove, govern and comply"), t("Aşama 7 · Yönetişim", "Stage 7 · Governance"), body);
}

function platformEditions(h) {
	const { t, page, stageIntro, featureList, fact, icon, plans } = h;
	const order = ["free", "team", "business", "enterprise"];
	const rows = [
		["local_detection", t("Yerel tespit motoru, ajan bağlayıcıları", "Local detection engine, agent connectors")],
		["dashboard", t("Yönetim paneli, politika, olaylar", "Management console, policy, incidents")],
		["browser_privacy_guard", "AIDR Browser Guard"],
		["entra_sso", t("Microsoft Entra ID ile tek oturum açma", "Microsoft Entra ID single sign-on")],
		["siem_export", t("SIEM dışa aktarımı", "SIEM export")],
		["scim", t("SCIM dizin eşitleme", "SCIM provisioning")],
		["ai_security_posture", t("Yapay Zekâ Güvenlik Duruşu", "AI Security Posture")],
		["air_gapped_deployment", t("Ağdan yalıtılmış kurulum", "Air-gapped deployment")],
		["dedicated_support", t("Özel destek", "Dedicated support")],
	];
	const deployName = { cloud: t("bulut", "cloud"), onprem: t("kurum içi", "on-premises"), "air-gapped": t("ağdan yalıtılmış", "air-gapped") };
	const deployment = (plan) => {
		const text = plans[plan].deployment.map((d) => deployName[d]).join(", ");
		return text.charAt(0).toLocaleUpperCase(h.lang === "tr" ? "tr-TR" : "en-GB") + text.slice(1);
	};
	const who = {
		free: t("Tek geliştirici, deneme", "One developer, evaluation"),
		team: t(`Küçük ekipler, en az ${fact("plan-team-min")} geliştirici`, `Small teams, at least ${fact("plan-team-min")} developers`),
		business: t(`Kuruluşlar, en az ${fact("plan-business-min")} geliştirici`, `Organisations, at least ${fact("plan-business-min")} developers`),
		enterprise: t("Kurum içi ve yalıtılmış ağlar", "On-premises and isolated networks"),
	};
	const retention = {
		free: `${fact("plan-free-retention")} ${t("gün", "days")}`,
		team: `${fact("plan-team-retention")} ${t("gün", "days")}`,
		business: `${fact("plan-business-retention")} ${t("gün", "days")}`,
		enterprise: t("Sözleşmeye göre", "Contractual"),
	};
	const cell = (plan, feature) =>
		plans[plan].features.includes(feature)
			? `<td class="c" data-plan-feature="${plan}:${feature}">${icon("check", "yes")}</td>`
			: `<td class="c no" data-plan-feature="${plan}:${feature}">—</td>`;
	const body = `	${stageIntro("platform")}
	${featureList("platform", { cols: true })}
	<h2 class="title mt4" id="p-editions">${t("Paketler", "Editions")}</h2>
	<table class="t matrix">
		<thead><tr><th></th>${order.map((p) => `<th class="c" lang="en">${plans[p].displayName}</th>`).join("")}</tr></thead>
		<tbody>
			<tr><td class="nm">${t("Kimin için", "Who it is for")}</td>${order.map((p) => `<td class="c small">${who[p]}</td>`).join("")}</tr>
			<tr><td class="nm">${t("Kurulum", "Deployment")}</td>${order.map((p) => `<td class="c small" data-plan-deploy="${p}">${deployment(p)}</td>`).join("")}</tr>
			<tr><td class="nm">${t("Olay saklama", "Event retention")}</td>${order.map((p) => `<td class="c small">${retention[p]}</td>`).join("")}</tr>
${rows.map(([feature, label]) => `\t\t\t<tr><td>${label}</td>${order.map((p) => cell(p, feature)).join("")}</tr>`).join("\n")}
		</tbody>
	</table>
	<p class="mt2 mb0">${t(`Yerel tespit her uç noktada plan ya da hesap olmadan çalışır. Bulut hizmeti henüz canlı değildir; açıldığında tek ajanla ${fact("trial-days")} gün denenebilecek.`, `Local detection runs on every endpoint with or without a plan. The cloud service is not live yet; once it is, it can be tried with one agent for ${fact("trial-days")} days.`)} <b>${t("Fiyatlandırma ve teklif için bizimle iletişime geçin: anil@singularityrd.com", "Contact us for pricing and a quote: anil@singularityrd.com")}</b></p>`;
	return page("p-platform", t("Platform ve paketler", "Platform and editions"), t("Platform · Paketler", "Platform · Editions"), body);
}

function backCover(h) {
	const { t, icon } = h;
	const steps = [
		["eye", t("Tanıtım", "Demo"), t("Ajan denetimini ve Browser Guard maskelemesini kendi senaryolarınız üzerinde birlikte inceleyelim; panel sentetik veriyle ve öyle belirtilerek gösterilir.", "We walk through agent control and Browser Guard masking on your own scenarios; the console is shown with synthetic data, labelled as such.")],
		["loop", "Pilot", t("Birkaç ekip ve İzle moduyla başlayan, kapsamı ve başarı ölçütleri birlikte belirlenen kontrollü bir deneme.", "A controlled trial that starts with a few teams in Monitor mode, with scope and success criteria agreed together.")],
		["doc", t("Teknik değerlendirme", "Technical evaluation"), t("Güvenlik soruları, veri akışı ve mimari belgeleri ile ayrıntılı özellik rehberi talep üzerine paylaşılır.", "Security questionnaire answers, data-flow and architecture documents and the detailed feature guide are shared on request.")],
	];
	return `<section class="page cover back" id="p-contact" aria-label="${t("Sonraki adımlar ve iletişim", "Next steps and contact")}">
	<div class="top"><span>${t("Ürün Kataloğu", "Product Catalog")}</span><span>2026</span></div>
	<p class="closing-line">${t("Keşiften kanıta — ajanlarınızın her adımı görünür, denetlenir ve kanıtlanır.", "From discovery to proof — every step your agents take is visible, controlled and proven.")}</p>
	<h2 class="back-title">${t("Sonraki adımlar", "Next steps")}</h2>
	<div class="g3">
${steps.map(([i, name, text]) => `\t\t<div class="block"><div class="head"><span class="ic">${icon(i)}</span><h4>${name}</h4></div><p class="small mb0">${text}</p></div>`).join("\n")}
	</div>
	<div class="cover-logo sm" role="img" aria-label="Singularity"></div>
	<p class="back-name">Singularity AIDR</p>
	<p class="back-contact"><span class="lbl">${t("İletişim", "Contact")}</span><b>singularityrd.com</b><br>anil@singularityrd.com</p>
	<p class="back-note">${t("Fiyatlandırma ve teklif için bizimle iletişime geçin.", "Contact us for pricing and a quote.")}</p>
</section>`;
}

export function pages(h) {
	return [cover(h), lifecycle(h), coverage(h), discoverAssess(h), protect(h), control(h), inspectRespond(h), proveGovern(h), platformEditions(h), backCover(h)];
}

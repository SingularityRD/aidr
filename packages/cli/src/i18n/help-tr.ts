/**
 * Turkish text for `aidr --help`, keyed by the English description exactly as
 * it is written in src/index.ts. The help tree is translated at display time
 * (see localizeHelp), so the command definitions keep a single English source
 * and an English locale prints them unchanged.
 *
 * The i18n test walks the real command tree and fails when a description has
 * no entry here or an entry is no longer used. Command, option, flag, rule,
 * connector and product names are not translated.
 */
export const HELP_TR: Readonly<Record<string, string>> = {
	// Commander's own texts.
	"output the version number": "sürüm numarasını göster",
	"display help for command": "komutun yardımını göster",
	"Usage:": "Kullanım:",
	"Options:": "Seçenekler:",
	"Commands:": "Komutlar:",
	"Arguments:": "Argümanlar:",
	"Global Options:": "Genel Seçenekler:",

	// `aidr --help` command groups (see HELP_GROUPS).
	"Setup:": "Kurulum:",
	"Daily use:": "Günlük kullanım:",
	"Approvals:": "Onaylar:",
	"Diagnostics:": "Tanılama:",
	"Advanced:": "Gelişmiş:",

	"Singularity AIDR command-line setup and diagnostics":
		"Singularity AIDR komut satırı kurulum ve tanılama aracı",
	"Configure AIDR and install or update the connector of every detected agent host (idempotent)":
		"AIDR'yi yapılandır ve algılanan her yapay zekâ aracının bağlayıcısını kur ya da güncelle (tekrar çalıştırmak güvenlidir)",
	"Replace an existing local configuration": "Mevcut yerel yapılandırmanın yerine yenisini yaz",
	"Credential store: windows-dpapi, macos-keychain, linux-secret-service, encrypted-file, file-acl (default: the OS vault, or the machine-bound encrypted-file store on a host without one; AIDR_SECRET_STORE=file-acl accepts the plaintext file fallback)":
		"Kimlik bilgisi deposu: windows-dpapi, macos-keychain, linux-secret-service, encrypted-file, file-acl (varsayılan: işletim sistemi kasası; kasası olmayan bir makinede makineye bağlı encrypted-file deposu; AIDR_SECRET_STORE=file-acl düz metin dosya yedeğini kabul eder)",
	"Read or update the local AIDR configuration": "Yerel AIDR yapılandırmasını oku ya da güncelle",
	"Read a dotted configuration key": "Noktalı bir yapılandırma anahtarını oku",
	"Set a dotted key/value; enter secrets at the hidden prompt, never as arguments":
		"Noktalı bir anahtar/değer ata; gizli değerleri argüman olarak değil, gizli istemde girin",
	"Print all configuration values": "Tüm yapılandırma değerlerini yazdır",
	"Rotate the CLI setup credential (not a managed endpoint API key)":
		"CLI kurulum kimlik bilgisini yenile (yönetilen uç nokta API anahtarı değildir)",
	"Emit a machine-readable rotation receipt": "Makinece okunabilir bir yenileme makbuzu üret",
	"Revoke the CLI setup credential (not a managed endpoint API key)":
		"CLI kurulum kimlik bilgisini iptal et (yönetilen uç nokta API anahtarı değildir)",
	"Emit a machine-readable revocation receipt": "Makinece okunabilir bir iptal makbuzu üret",
	"Pass a harmless canary (data only, never executed) through each registered connector's hook and report PASS/FAIL per host":
		"Zararsız bir canary'yi (yalnızca veri, asla çalıştırılmaz) kayıtlı her bağlayıcının hook'undan geçir ve yapay zekâ aracı başına BAŞARILI/BAŞARISIZ bildir",
	"Show the local AIDR configuration and hook status":
		"Yerel AIDR yapılandırmasını ve hook durumunu göster",
	"Emit measured installation state without credentials":
		"Ölçülen kurulum durumunu kimlik bilgileri olmadan çıktıla",
	"Scan AI infrastructure targets, skill packages or project code (native, no external service)":
		"Yapay zekâ altyapısı hedeflerini, skill paketlerini ya da proje kodunu tara (yerel, harici servis yok)",
	"Target base URL (repeatable). Loopback/private only unless --allow-public":
		"Hedef temel URL (tekrarlanabilir). --allow-public verilmedikçe yalnızca loopback/özel adresler",
	"Read targets from a file, one URL per line": "Hedefleri bir dosyadan oku, her satırda bir URL",
	"Scan a skill or plugin package directory with the T01-T09 skill rules (repeatable)":
		"Bir skill ya da eklenti paket dizinini T01-T09 skill kurallarıyla tara (tekrarlanabilir)",
	"Scan a project directory or file for unsafe model loading and insecure code patterns (file:line, local only)":
		"Bir proje dizinini ya da dosyasını güvensiz model yükleme ve güvensiz kod kalıpları için tara (dosya:satır, yalnızca yerel)",
	"Emit machine-readable JSON": "Makinece okunabilir JSON üret",
	"Permit non-private targets (off by default)":
		"Özel olmayan hedeflere izin ver (varsayılan olarak kapalı)",
	"Per-request timeout in milliseconds": "İstek başına zaman aşımı (milisaniye)",
	"Number of targets to scan in parallel": "Paralel taranacak hedef sayısı",
	"Persist a scan report for the configured infrastructure policy":
		"Yapılandırılmış altyapı politikası için bir tarama raporu kaydet",
	"Send findings (ids, severities, digests; no hosts, paths or secrets) to the managed control plane":
		"Bulguları (kimlikler, önem dereceleri, özetler; ana makine, yol ya da gizli bilgi olmadan) yönetilen kontrol düzlemine gönder",
	"Local TR/EN personal-data and secret checks (nothing is uploaded)":
		"Yerel TR/EN kişisel veri ve gizli bilgi denetimleri (hiçbir şey yüklenmez)",
	"Scan a file or stdin for TCKN, IBAN, phone, e-mail, card, secret and other personal data; values are never printed":
		"Bir dosyayı ya da stdin'i TCKN, IBAN, telefon, e-posta, kart, gizli bilgi ve diğer kişisel veriler için tara; değerler asla yazdırılmaz",
	"Emit findings as JSON (type, offsets, line; never the matched value)":
		"Bulguları JSON olarak üret (tür, konumlar, satır; eşleşen değer asla yok)",
	"Print the text with each finding replaced by its [TYPE] placeholder":
		"Metni, her bulgu [TÜR] yer tutucusuyla değiştirilmiş olarak yazdır",
	"Comma-separated detector names to report (default: all)":
		"Raporlanacak dedektör adları, virgülle ayrılmış (varsayılan: tümü)",
	"Findings that exit 2: none, any (default) or secret; otherwise an incomplete inspection exits 3":
		"2 koduyla çıkış yaptıran bulgular: none, any (varsayılan) ya da secret; aksi hâlde eksik bir inceleme 3 koduyla çıkar",
	"Defensive self-test: feed defanged detection fixtures to the local evaluator and report what AIDR detects (never executes anything)":
		"Savunma amaçlı öz sınama: zararsızlaştırılmış tespit örneklerini yerel değerlendiriciye ver ve AIDR'nin neleri tespit ettiğini raporla (hiçbir şey çalıştırılmaz)",
	"Comma-separated categories to run (injection, exfiltration, destructive, encoding, supply-chain, mcp, self-defense, privacy)":
		"Çalıştırılacak kategoriler, virgülle ayrılmış (injection, exfiltration, destructive, encoding, supply-chain, mcp, self-defense, privacy)",
	"Override sensitivity: paranoid, balanced or relaxed":
		"Hassasiyeti geçersiz kıl: paranoid, balanced ya da relaxed",
	"Output format: table, json or html": "Çıktı biçimi: table, json ya da html",
	"Write the report to a file instead of stdout": "Raporu stdout yerine bir dosyaya yaz",
	"Exit non-zero when the overall detection score is below N (0-100; default 90, 0 = report only)":
		"Genel tespit puanı N'nin altındaysa sıfırdan farklı kodla çık (0-100; varsayılan 90, 0 = yalnızca raporla)",
	"Drive a built connector entry point instead of the in-process evaluator (claude-code, codex, cursor, vscode)":
		"Süreç içi değerlendirici yerine derlenmiş bir bağlayıcı giriş noktasını kullan (claude-code, codex, cursor, vscode)",
	"Continuously collect tenant-scoped AI infrastructure inventory":
		"Kiracı kapsamlı yapay zekâ altyapısı envanterini sürekli topla",
	"Tenant identifier recorded in the inventory": "Envantere kaydedilen kiracı kimliği",
	"Discovery provider: local, aws, azure, gcp or intune":
		"Keşif sağlayıcısı: local, aws, azure, gcp ya da intune",
	"Tenant-bound cloud/Intune scope and credential references (JSON)":
		"Kiracıya bağlı bulut/Intune kapsamı ve kimlik bilgisi referansları (JSON)",
	"Target base URL (repeatable)": "Hedef temel URL (tekrarlanabilir)",
	"Inventory output path (tenant-isolated default under ~/.singularity-aidr)":
		"Envanter çıktı yolu (varsayılan: ~/.singularity-aidr altında kiracıya özel)",
	"Repeat without overlap every 10-86400 seconds; omitted means one run":
		"Çakışma olmadan her 10-86400 saniyede bir yinele; verilmezse tek sefer çalışır",
	"Mark last-seen evidence stale after this age": "Son görülen kanıtı bu süreden sonra eskimiş say",
	"Bounded attempts per unreachable target (1-5)":
		"Ulaşılamayan hedef başına sınırlı deneme sayısı (1-5)",
	"Initial retry backoff in milliseconds": "İlk yeniden deneme bekleme süresi (milisaniye)",
	"Maximum concurrently collected targets": "Aynı anda toplanan en fazla hedef sayısı",
	"Emit machine-readable inventory; interval mode emits JSON lines":
		"Makinece okunabilir envanter üret; aralık modunda JSON satırları üretilir",
	"Inventory local MCP servers with risk indicators and configuration fingerprints":
		"Yerel MCP sunucularını risk göstergeleri ve yapılandırma parmak izleriyle envantere al",
	"Inspect explicit JSON configuration paths": "Belirtilen JSON yapılandırma yollarını incele",
	"Emit a redacted machine-readable inventory":
		"Maskelenmiş, makinece okunabilir bir envanter üret",
	"Also check agent hosts for unsafe autonomy settings, missing AIDR hooks and environment exposure":
		"Yapay zekâ araçlarını güvensiz otonomi ayarları, eksik AIDR hook'ları ve ortam açıklığı açısından da denetle",
	"Send server names, risk categories and digests (no paths, endpoints or arguments) to the managed control plane; with --agents also host, check id, severity and count per finding":
		"Sunucu adlarını, risk kategorilerini ve özetleri (yol, uç nokta ya da argüman olmadan) yönetilen kontrol düzlemine gönder; --agents ile bulgu başına yapay zekâ aracı, denetim kimliği, önem ve sayı da gönderilir",
	"Export an AI Bill of Materials (CycloneDX 1.6): agents, MCP servers, AI packages, models, plugins and known vulnerabilities; secrets are redacted":
		"Yapay zekâ malzeme listesi (AI BOM, CycloneDX 1.6) dışa aktar: ajanlar, MCP sunucuları, yapay zekâ paketleri, modeller, eklentiler ve bilinen zafiyetler; gizli bilgiler maskelenir",
	"cyclonedx-json or json (AIDR inventory)": "cyclonedx-json ya da json (AIDR envanteri)",
	"Write to a new file (0600) instead of stdout": "stdout yerine yeni bir dosyaya (0600) yaz",
	"Project directory whose manifests and MCP configs are read":
		"Manifestoları ve MCP yapılandırmaları okunacak proje dizini",
	"Inspect explicit MCP configuration paths instead of the defaults":
		"Varsayılanlar yerine belirtilen MCP yapılandırma yollarını incele",
	"Include a saved `aidr scan --save-report` result (defaults to the configured AI infrastructure report)":
		"Kaydedilmiş bir `aidr scan --save-report` sonucunu ekle (varsayılan: yapılandırılmış yapay zekâ altyapısı raporu)",
	"Remove only the receipt-managed Claude Code hooks, preserving everything else":
		"Yalnızca kayıtla yönetilen Claude Code hook'larını kaldır; geri kalan her şey korunur",
	"Target an explicit home directory (managed fleets and verification); defaults to the current user":
		"Belirli bir ev dizinini hedefle (yönetilen filolar ve doğrulama için); varsayılan: geçerli kullanıcı",
	"Emit a machine-readable report": "Makinece okunabilir bir rapor üret",
	"Explicit, signed behavioral learning with separate execution and approval authorities":
		"Ayrı yürütme ve onay yetkilileriyle açık, imzalı davranışsal öğrenme",
	"Create one operator authority; publish only its public key and private reference":
		"Bir operatör yetkilisi oluştur; yalnızca açık anahtarını ve özel referansını yayımla",
	"Authority role: execution or approval": "Yetkili rolü: execution ya da approval",
	"New private authority-reference JSON file (never overwritten)":
		"Yeni özel yetkili-referansı JSON dosyası (asla üzerine yazılmaz)",
	"Export private signed broker policy and entitlement for an independent approval station":
		"Bağımsız bir onay istasyonu için özel, imzalı aracı politikasını ve yetkiyi dışa aktar",
	"Installed connector policy runtime": "Kurulu bağlayıcı politika çalışma zamanı",
	"New private authority-handoff JSON file (never overwritten)":
		"Yeni özel yetkili-devir JSON dosyası (asla üzerine yazılmaz)",
	"Execute one allowed foreground Bash request and issue a verified success receipt":
		"İzin verilen tek bir ön plan Bash isteğini çalıştır ve doğrulanmış bir başarı makbuzu düzenle",
	"Installed connector policy: claude-code, cursor, vscode, openclaw, opencode or codex":
		"Kurulu bağlayıcı politikası: claude-code, cursor, vscode, openclaw, opencode ya da codex",
	"Strict JSON request with sessionId, toolName Bash, command and execution_shell":
		"sessionId, toolName Bash, command ve execution_shell içeren katı JSON isteği",
	"Private execution authority-reference file": "Özel yürütme yetkilisi referans dosyası",
	"New execution-receipt JSON file (never overwritten)":
		"Yeni yürütme makbuzu JSON dosyası (asla üzerine yazılmaz)",
	"Independently confirm benign execution and consent to learning at an interactive prompt":
		"Zararsız yürütmeyi bağımsız olarak doğrula ve etkileşimli istemde öğrenmeye onay ver",
	"Signed execution-receipt JSON file": "İmzalı yürütme makbuzu JSON dosyası",
	"The exact original request for independent benign classification":
		"Bağımsız zararsızlık sınıflandırması için özgün isteğin birebir aynısı",
	"Private signed broker-authority handoff; verified against this station's fixed issuer roots":
		"Özel, imzalı aracı yetkisi devri; bu istasyonun sabit düzenleyici köklerine karşı doğrulanır",
	"Private approval authority-reference file in separate operator custody":
		"Ayrı bir operatörün gözetimindeki özel onay yetkilisi referans dosyası",
	"New approval-receipt JSON file (never overwritten)":
		"Yeni onay makbuzu JSON dosyası (asla üzerine yazılmaz)",
	"Verify both independent signatures and accept one bounded durable baseline observation":
		"Her iki bağımsız imzayı doğrula ve sınırlı, kalıcı tek bir temel gözlemi kabul et",
	"The exact original request JSON file": "Özgün isteğin birebir aynısını içeren JSON dosyası",
	"Signed benign-consent approval JSON file": "İmzalı zararsızlık-onayı JSON dosyası",
	"Check AI tools, hook registration, release key, rules, mode, DLP policy, agent profiles, approvals and the last verdict; exits non-zero on problems":
		"Yapay zekâ araçlarını, hook kaydını, sürüm doğrulama anahtarını, kuralları, modu, DLP politikasını, ajan profillerini, onayları ve son kararı denetle; sorun varsa sıfırdan farklı kodla çıkar",
	"Explain each check (paths, reasons, key storage)":
		"Her denetimi açıkla (yollar, nedenler, anahtar saklama yeri)",
	"Show how the installed detection rules map to OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026 and MITRE ATLAS":
		"Kurulu tespit kurallarının OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026 ve MITRE ATLAS ile eşleşmesini göster",
	"table, json or markdown": "table, json ya da markdown",
	"List blocked agent actions waiting for your approval (given only in your own terminal)":
		"Onayınızı bekleyen engellenmiş yapay zekâ aracı eylemlerini listele (onay yalnızca kendi terminalinizden verilir)",
	"The id from `aidr pending`, or its first 8+ characters; omit it in a terminal to pick from a list":
		"`aidr pending` çıktısındaki kimlik ya da ilk 8+ karakteri; terminalde boş bırakırsanız listeden seçersiniz",
	"Operator only: approve ONE retry of a blocked call (interactive confirmation; 15-minute default)":
		"Yalnızca operatör: engellenmiş bir çağrının TEK bir yeniden denemesini onayla (etkileşimli onay; varsayılan 15 dakika)",
	"Minutes the approval stays usable (1-1440)": "Onayın geçerli kalacağı dakika sayısı (1-1440)",
	"Also let the agent add these artifacts to the allowlist once":
		"Ajanın bu öğeleri izin listesine bir kez eklemesine de izin ver",
	"Skip the prompt; honoured only with AIDR_OPERATOR_NONINTERACTIVE=1":
		"İstemi atla; yalnızca AIDR_OPERATOR_NONINTERACTIVE=1 ile dikkate alınır",
	"Emit a machine-readable receipt": "Makinece okunabilir bir makbuz üret",
	"List, add or remove permanent allowlist entries":
		"Kalıcı izin listesi kayıtlarını listele, ekle ya da kaldır",
	"Show allowlist entries (commands are stored as hashes)":
		"İzin listesi kayıtlarını göster (komutlar özet değeri olarak saklanır)",
	"Operator only: permanently allow a url, command or file_path (interactive confirmation)":
		"Yalnızca operatör: bir url, command ya da file_path öğesine kalıcı izin ver (etkileşimli onay)",
	"Why this artifact is safe": "Bu öğenin neden güvenli olduğu",
	"Remove a url, command (text or hash) or file_path from the allowlist":
		"İzin listesinden bir url, command (metin ya da özet) veya file_path öğesini kaldır",
	"Time-limited detection exceptions per user, agent or repository":
		"Kullanıcı, ajan ya da depo başına süreli tespit istisnaları",
	"Operator only: lift one detection rule for one subject until it expires (max 30 days; interactive confirmation)":
		"Yalnızca operatör: bir tespit kuralını tek bir özne için süresi dolana kadar kaldır (en fazla 30 gün; etkileşimli onay)",
	"Subject: this OS account": "Özne: bu işletim sistemi hesabı",
	"Subject: this agent runtime (claude-code, cursor, vscode, ...)":
		"Özne: bu ajan çalışma zamanı (claude-code, cursor, vscode, ...)",
	"Subject: this repository (root path or origin remote)":
		"Özne: bu depo (kök yolu ya da origin uzak deposu)",
	"Lifetime such as 30m, 12h or 7d (required; max 30d)":
		"30m, 12h ya da 7d gibi bir süre (zorunlu; en fazla 30d)",
	"Why the exception is needed (required)": "İstisnanın neden gerektiği (zorunlu)",
	"Narrow to one exact command, URL or file path": "Tek bir komut, URL ya da dosya yoluyla sınırla",
	"Show local detection exceptions": "Yerel tespit istisnalarını göster",
	"Include expired exceptions": "Süresi dolmuş istisnaları da dahil et",
	"Revoke a local detection exception now": "Yerel bir tespit istisnasını hemen iptal et",
	"Work with compliance evidence reports from the control plane":
		"Kontrol düzleminden gelen uyum kanıtı raporlarıyla çalış",
	"Verify a compliance report offline: recompute its SHA-256 and check the Ed25519 signature":
		"Bir uyum raporunu çevrimdışı doğrula: SHA-256 değerini yeniden hesapla ve Ed25519 imzasını denetle",
	"PEM public key the report must be signed with (pins the issuer)":
		"Raporun imzalanmış olması gereken PEM açık anahtarı (düzenleyiciyi sabitler)",
	"Fail when the report is not signed": "Rapor imzalı değilse başarısız ol",
	"Emit a machine-readable result": "Makinece okunabilir bir sonuç üret",
	"Read the local verdict audit log": "Yerel karar denetim kaydını oku",
	"Show the most recent audit entries (redacted)":
		"En son denetim kayıtlarını göster (maskelenmiş)",
	"Number of entries": "Kayıt sayısı",
	"Emit JSON Lines": "JSON Lines üret",
	"Export redacted audit entries, including rotated files":
		"Döndürülmüş dosyalar dahil maskelenmiş denetim kayıtlarını dışa aktar",
	"ISO-8601 date/time or a relative age such as 24h, 7d, 30m":
		"ISO-8601 tarih/saat ya da 24h, 7d, 30m gibi göreli bir süre",
	"jsonl or csv": "jsonl ya da csv",
	"Verify the signed verdict log and the signed response-action chain; exit 0 verified, 1 broken, 2 unverifiable":
		"İmzalı karar kaydını ve imzalı müdahale eylemi zincirini doğrula; çıkış 0 doğrulandı, 1 bozuk, 2 doğrulanamıyor",
	"Pin the first root key (SHA256:<hex>)": "İlk kök anahtarı sabitle (SHA256:<hex>)",
	"Verify only this response-action chain file (exit 1 broken, 2 unverifiable)":
		"Yalnızca bu müdahale eylemi zinciri dosyasını doğrula (çıkış 1 bozuk, 2 doğrulanamıyor)",
	"Operator only: replace the verdict-log root signing key (interactive confirmation)":
		"Yalnızca operatör: karar kaydının kök imzalama anahtarını değiştir (etkileşimli onay)",
	"Inspect, release or delete files quarantined as malicious":
		"Zararlı olarak karantinaya alınan dosyaları incele, serbest bırak ya da sil",
	"List quarantined files (newest first)":
		"Karantinadaki dosyaları listele (en yeniden başlayarak)",
	"Show one quarantined file: original path, hash, reason, time":
		"Karantinadaki bir dosyayı göster: özgün yol, özet, neden, zaman",
	"Operator only: put a quarantined file back at its original path (interactive confirmation)":
		"Yalnızca operatör: karantinadaki bir dosyayı özgün yoluna geri koy (etkileşimli onay)",
	"Operator only: permanently delete a quarantined file (interactive confirmation)":
		"Yalnızca operatör: karantinadaki bir dosyayı kalıcı olarak sil (etkileşimli onay)",
	"Operator only: restore a protected path from its pre-operation snapshot (interactive confirmation), or --list them":
		"Yalnızca operatör: korunan bir yolu işlem öncesi anlık görüntüsünden geri yükle (etkileşimli onay) ya da --list ile listele",
	"List stored snapshots": "Saklanan anlık görüntüleri listele",
	"Also overwrite a target that changed after the snapshot":
		"Anlık görüntüden sonra değişmiş bir hedefin de üzerine yaz",
	"Emit machine-readable JSON (with --list)": "Makinece okunabilir JSON üret (--list ile)",
	"Inspect, validate and dry-run agent permission profiles (least privilege)":
		"Ajan izin profillerini incele, doğrula ve deneme çalıştırması yap (en az ayrıcalık)",
	"List local and managed agent permission profiles and the shipped templates":
		"Yerel ve yönetilen ajan izin profillerini ve hazır şablonları listele",
	"Print one profile (local or managed), or a shipped template with --template":
		"Bir profili (yerel ya da yönetilen) veya --template ile hazır bir şablonu yazdır",
	"Show a shipped template: read-only-reviewer, standard-developer, ci-agent, locked-down":
		"Hazır bir şablonu göster: read-only-reviewer, standard-developer, ci-agent, locked-down",
	"Validate a profile document (default: ~/.singularity-aidr/agent-profiles.json)":
		"Bir profil belgesini doğrula (varsayılan: ~/.singularity-aidr/agent-profiles.json)",
	'Dry-run a tool call (JSON or @file, e.g. \'{"tool_name":"Bash","tool_input":{"command":"ls"}}\') against the effective profiles':
		'Bir araç çağrısını (JSON ya da @dosya, ör. \'{"tool_name":"Bash","tool_input":{"command":"ls"}}\') geçerli profillere karşı deneme olarak çalıştır',
	"Connector whose profiles apply": "Profilleri uygulanacak bağlayıcı",
	"Working directory of the agent session (selects repository profiles)":
		"Ajan oturumunun çalışma dizini (depo profillerini seçer)",
	"Test against this profile document instead of the installed ones":
		"Kurulu profiller yerine bu profil belgesine karşı sına",
	"Operator only: plant and manage decoy credentials that expose an agent hunting for secrets":
		"Yalnızca operatör: gizli bilgi arayan bir ajanı açığa çıkaran tuzak kimlik bilgileri yerleştir ve yönet",
	"Create new decoy credential files (never overwrites a file); the registry stores only digests":
		"Yeni tuzak kimlik bilgisi dosyaları oluştur (hiçbir dosyanın üzerine yazmaz); kayıt defteri yalnızca özetleri saklar",
	"Directory for project decoys (env, db-url); defaults to the current one":
		"Proje tuzakları (env, db-url) için dizin; varsayılan: geçerli dizin",
	"Comma-separated kinds: aws, github, openai, env, ssh-config, db-url":
		"Türler, virgülle ayrılmış: aws, github, openai, env, ssh-config, db-url",
	"List deployed canary credentials and whether each decoy file is intact":
		"Yerleştirilmiş canary kimlik bilgilerini ve her tuzak dosyasının sağlam olup olmadığını listele",
	"Delete one decoy (by id) or all of them, and drop them from the registry":
		"Bir tuzağı (kimliğiyle) ya da hepsini sil ve kayıt defterinden çıkar",
	"Remove every deployed canary credential": "Yerleştirilmiş tüm canary kimlik bilgilerini kaldır",
	"Check the registry, the decoy files and triggers recorded in the audit log":
		"Kayıt defterini, tuzak dosyalarını ve denetim kaydına işlenmiş tetiklenmeleri denetle",
	// aidr setup connector install, uninstall and support-bundle options.
	"Show what would be installed or updated; change nothing":
		"Nelerin kurulacağını ya da güncelleneceğini göster; hiçbir şeyi değiştirme",
	"Only these hosts, comma-separated: claude-code, cursor, vscode, openclaw, opencode, codex (default: every detected host)":
		"Yalnızca bu yapay zekâ araçları, virgülle ayrılmış: claude-code, cursor, vscode, openclaw, opencode, codex (varsayılan: algılanan her araç)",
	"Configure only and print the manual connector steps":
		"Yalnızca yapılandır ve elle yapılacak bağlayıcı adımlarını yazdır",
	"Extracted, verified aidr-claude-plugin directory to install into Claude Code":
		"Claude Code'a kurulacak, açılmış ve doğrulanmış aidr-claude-plugin dizini",
	"Verified aidr-cursor.vsix to install into Cursor":
		"Cursor'a kurulacak doğrulanmış aidr-cursor.vsix",
	"Verified aidr-vscode.vsix to install into VS Code":
		"VS Code'a kurulacak doğrulanmış aidr-vscode.vsix",
	"With AIDR_OPERATOR_NONINTERACTIVE=1, confirm --force without a prompt":
		"AIDR_OPERATOR_NONINTERACTIVE=1 ile --force seçeneğini sormadan onayla",
	"Remove AIDR: the connector of every agent host, the AIDR-managed hooks, ~/.singularity-aidr and the AIDR vault items (confirmation required)":
		"AIDR'yi kaldır: her yapay zekâ aracının bağlayıcısı, AIDR'nin yönettiği hook'lar, ~/.singularity-aidr ve AIDR kasa öğeleri (onay gerekir)",
	"Keep ~/.singularity-aidr (config, audit log, approvals) and the vault items":
		"~/.singularity-aidr dizinini (yapılandırma, denetim günlüğü, onaylar) ve kasa öğelerini koru",
	"Show what would be removed; change nothing":
		"Nelerin kaldırılacağını göster; hiçbir şeyi değiştirme",
	"Only these hosts, comma-separated: claude-code, cursor, vscode, openclaw, opencode, codex (default: all)":
		"Yalnızca bu yapay zekâ araçları, virgülle ayrılmış: claude-code, cursor, vscode, openclaw, opencode, codex (varsayılan: tümü)",
	"Write a redacted diagnostic archive (versions, doctor checks, hooks, config, recent verdict metadata, rule hashes) for a support case":
		"Destek talebi için hassas verileri ayıklanmış bir tanılama arşivi yaz (sürümler, doctor denetimleri, hook'lar, yapılandırma, son karar meta verileri, kural özetleri)",
	"Archive path (.tar.gz); never overwrites an existing file":
		"Arşiv yolu (.tar.gz); var olan bir dosyanın üzerine asla yazmaz",
	"Recent audit verdicts to summarise (0-1000)": "Özetlenecek son denetim kararı sayısı (0-1000)",
	"Print the bundle summary as JSON": "Paket özetini JSON olarak yazdır",
};

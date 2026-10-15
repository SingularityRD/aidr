import type { MessagePairs } from "./define";

/** Team policy page and the YAML policy editor. */
export const policyMessages = {
	"policy.pill": ["Policy as code", "Kod olarak politika"],
	"policy.intro": [
		"Write and validate strict team policy documents, run a dry-run compilation, then publish the compiled controls to enrolled agents.",
		"Katı ekip politikası belgeleri yazıp doğrulayın, deneme derlemesi çalıştırın, ardından derlenen denetimleri kayıtlı yapay zekâ araçlarına yayımlayın.",
	],
	"policy.compiledNotice": [
		"Saved YAML is compiled before it can become runtime policy.",
		"Kaydedilen YAML, çalışma zamanı politikası olmadan önce derlenir.",
	],
	"policy.compiledBody": [
		"Unsupported fields fail compilation. Use the dry-run or compile-and-publish action below; connected agents fetch the published controls on their next refresh. Publication alone does not confirm every agent has adopted the version.",
		"Desteklenmeyen alanlar derlemeyi başarısız kılar. Aşağıdaki deneme ya da derle ve yayımla işlemini kullanın; bağlı yapay zekâ araçları yayımlanan denetimleri bir sonraki yenilemede alır. Yayımlamak, her yapay zekâ aracının bu sürümü benimsediğini tek başına doğrulamaz.",
	],
	"team.pill": ["Administration", "Yönetim"],
	"team.intro": [
		"Manage team membership and roles. Owners and administrators can invite, re-role and remove members; members and viewers get a read-only view of the same team.",
		"Ekip üyeliğini ve rolleri yönetin. Sahipler ve yöneticiler üye davet edebilir, rol değiştirebilir ve üye çıkarabilir; üyeler ve izleyiciler aynı ekibi salt okunur görür.",
	],

	"policy.v.hashUnavailable": [
		"Secure browser SHA-256 verification is unavailable; no save was attempted.",
		"Tarayıcıda güvenli SHA-256 doğrulaması kullanılamıyor; kaydetme denenmedi.",
	],
	"policy.v.notMapping": [
		'Line "{text}" is not a "key: value" mapping entry.',
		'"{text}" satırı "anahtar: değer" biçiminde bir eşleme girdisi değil.',
	],
	"policy.v.noKey": [
		'Line "{text}" has no key before ":".',
		'"{text}" satırında ":" öncesinde anahtar yok.',
	],
	"policy.v.tabs": [
		"Tabs are not supported for indentation; use spaces.",
		"Girinti için sekme desteklenmez; boşluk kullanın.",
	],
	"policy.v.invalidYaml": ["Invalid YAML", "Geçersiz YAML"],
	"policy.v.mapping": [
		"The policy must be a mapping with version, default_action and rules.",
		"Politika version, default_action ve rules alanlarını içeren bir eşleme olmalıdır.",
	],
	"policy.v.unsupportedField": [
		"Unsupported policy field: {field}.",
		"Desteklenmeyen politika alanı: {field}.",
	],
	"policy.v.version": [
		"The policy must use supported version 1.0.",
		"Politika desteklenen 1.0 sürümünü kullanmalıdır.",
	],
	"policy.v.defaultAction": [
		'The policy must set default_action to "allow", "deny" or "ask".',
		'Politika default_action değerini "allow", "deny" ya da "ask" olarak ayarlamalıdır.',
	],
	"policy.v.actionValue": [
		'{key} must be "allow", "deny" or "ask".',
		'{key} değeri "allow", "deny" ya da "ask" olmalıdır.',
	],
	"policy.v.categoryMapping": [
		"category_defaults must be a mapping.",
		"category_defaults bir eşleme olmalıdır.",
	],
	"policy.v.unsupportedCategory": [
		"Unsupported category default: {field}.",
		"Desteklenmeyen kategori varsayılanı: {field}.",
	],
	"policy.v.categoryValue": [
		'category_defaults.{key} must be "allow", "deny" or "ask".',
		'category_defaults.{key} değeri "allow", "deny" ya da "ask" olmalıdır.',
	],
	"policy.v.rules": [
		"The policy must declare a rules list.",
		"Politika bir rules listesi tanımlamalıdır.",
	],
	"policy.v.ruleMapping": ["Rule {n} must be a mapping.", "{n}. kural bir eşleme olmalıdır."],
	"policy.v.ruleField": [
		"Rule {n} has unsupported field: {field}.",
		"{n}. kuralda desteklenmeyen alan var: {field}.",
	],
	"policy.v.ruleName": ["Rule {n} must have a name.", "{n}. kuralın bir adı olmalıdır."],
	"policy.v.ruleAction": [
		'Rule {n} must set action to "allow", "deny" or "ask".',
		'{n}. kural action değerini "allow", "deny" ya da "ask" olarak ayarlamalıdır.',
	],
	"policy.v.conditionMapping": [
		"Rule {n} condition must be a mapping.",
		"{n}. kuralın condition alanı bir eşleme olmalıdır.",
	],
	"policy.v.conditionField": [
		"Rule {n} condition has unsupported field: {field}.",
		"{n}. kuralın condition alanında desteklenmeyen alan var: {field}.",
	],
	"policy.v.conditionOne": [
		"Rule {n} condition must contain exactly one of mcp_server or mcp_tool.",
		"{n}. kuralın condition alanı mcp_server ya da mcp_tool alanlarından tam olarak birini içermelidir.",
	],
	"policy.v.server": [
		"Rule {n} mcp_server must be an MCP identifier of 1 to 256 characters.",
		"{n}. kuraldaki mcp_server, 1 ile 256 karakter arasında bir MCP tanımlayıcısı olmalıdır.",
	],
	"policy.v.legacyTool": [
		"Rule {n} mcp_tool must use server.tool with no dots inside either name; use a server/tool mapping for dotted names.",
		"{n}. kuraldaki mcp_tool, adların içinde nokta olmadan server.tool biçimini kullanmalıdır; noktalı adlar için server/tool eşlemesi kullanın.",
	],
	"policy.v.toolSelector": [
		"Rule {n} mcp_tool must be a server.tool selector or a server/tool mapping.",
		"{n}. kuraldaki mcp_tool, bir server.tool seçicisi ya da server/tool eşlemesi olmalıdır.",
	],
	"policy.v.toolField": [
		"Rule {n} mcp_tool has unsupported field: {field}.",
		"{n}. kuraldaki mcp_tool alanında desteklenmeyen alan var: {field}.",
	],
	"policy.v.toolIds": [
		"Rule {n} mcp_tool server and tool must be MCP identifiers of 1 to 256 characters.",
		"{n}. kuraldaki mcp_tool server ve tool değerleri 1 ile 256 karakter arasında MCP tanımlayıcıları olmalıdır.",
	],
	"policy.v.priority": [
		"Rule {n} priority must be an integer from 0 to 1000.",
		"{n}. kuralın priority değeri 0 ile 1000 arasında bir tam sayı olmalıdır.",
	],

	"policy.dry.unsupported": [
		"the runtime compiler rejected unsupported field(s): {fields}.",
		"çalışma zamanı derleyicisi desteklenmeyen alanları reddetti: {fields}.",
	],
	"policy.dry.rejected": [
		"the runtime compiler rejected the document ({code}).",
		"çalışma zamanı derleyicisi belgeyi reddetti ({code}).",
	],
	"policy.dry.conflict": [
		"the stored policy changed (policy_document_conflict). Keep a copy of your draft, then reload and review the latest revision before saving.",
		"kayıtlı politika değişti (policy_document_conflict). Taslağınızın bir kopyasını saklayın, ardından kaydetmeden önce sayfayı yenileyip en son sürümü inceleyin.",
	],
	"policy.dry.unconfirmed": [
		"the server did not confirm the exact submitted content and revision (policy_document_save_unconfirmed). Reload and review the stored policy before retrying.",
		"sunucu gönderilen içeriği ve sürümü birebir doğrulamadı (policy_document_save_unconfirmed). Yeniden denemeden önce sayfayı yenileyip kayıtlı politikayı inceleyin.",
	],
	"policy.dry.saveFailed": [
		"the server could not save the draft ({code}).",
		"sunucu taslağı kaydedemedi ({code}).",
	],
	"policy.dry.compiled": ["the server compiled the document.", "sunucu belgeyi derledi."],

	"policy.loadFailed": ["Failed to load policy", "Politika yüklenemedi"],
	"policy.revisionInvalid": [
		"Stored policy revision is invalid; reload before saving.",
		"Kayıtlı politika sürümü geçersiz; kaydetmeden önce sayfayı yenileyin.",
	],
	"policy.notSaved": ["Policy was not saved: {reason}", "Politika kaydedilmedi: {reason}"],
	"policy.saved": ["Policy saved successfully", "Politika kaydedildi"],
	"policy.unknownError": ["unknown error", "bilinmeyen hata"],
	"policy.loading": ["Loading policy...", "Politika yükleniyor..."],
	"policy.editor.title": ["Security Policy Editor", "Güvenlik politikası düzenleyicisi"],
	"policy.teamFailed": ["Your team could not be loaded.", "Ekibiniz yüklenemedi."],
	"policy.teamFailedBody": [
		'The editor is unavailable because the team membership query failed — this is not a confirmed "no team" state.',
		'Ekip üyeliği sorgusu başarısız olduğu için düzenleyici kullanılamıyor; bu, doğrulanmış bir "ekip yok" durumu değildir.',
	],
	"policy.noTeam": [
		"You are not part of a team yet, so there is no team policy to author. {link} first.",
		"Henüz bir ekibe üye değilsiniz; bu yüzden yazılacak bir ekip politikası yok. Önce {link}.",
	],
	"policy.noTeamLink": ["Create or join a team", "bir ekip oluşturun ya da bir ekibe katılın"],
	"policy.noPermission": [
		"You don't have permission to edit team policies. A team owner, administrator or member can edit the policy for {team}; viewers have read-only access.",
		"Ekip politikalarını düzenleme izniniz yok. {team} politikasını ekip sahibi, yöneticisi ya da üyesi düzenleyebilir; izleyiciler yalnızca okuyabilir.",
	],
	"policy.editor.subtitle": [
		"Define team-level security rules as code",
		"Ekip düzeyindeki güvenlik kurallarını kod olarak tanımlayın",
	],
	"policy.reset": ["Reset to Default", "Varsayılana döndür"],
	"policy.savingDots": ["Saving...", "Kaydediliyor..."],
	"policy.save": ["Save Policy", "Politikayı kaydet"],
	"policy.storedFailed": ["Stored policy could not be loaded.", "Kayıtlı politika yüklenemedi."],
	"policy.storedFailedBody": [
		"The editor is not showing a stored policy because the query failed. Saving is disabled until the stored policy can be read, so a failed read cannot overwrite it.",
		"Sorgu başarısız olduğu için düzenleyici kayıtlı bir politika göstermiyor. Kayıtlı politika okunana kadar kaydetme kapalıdır; böylece başarısız bir okuma politikanın üzerine yazamaz.",
	],
	"policy.yaml": ["Policy (YAML)", "Politika (YAML)"],
	"policy.selectors": [
		"Supported rule selectors are exact, case-sensitive {server} and {tool} values. Use a server/tool mapping for dotted MCP names. Category defaults support command, file, url, package and output. Conflicts use priority first, then deny > ask > allow.",
		"Desteklenen kural seçicileri, büyük/küçük harfe duyarlı ve birebir {server} ile {tool} değerleridir. Noktalı MCP adları için server/tool eşlemesi kullanın. Kategori varsayılanları command, file, url, package ve output için geçerlidir. Çakışmalarda önce öncelik, sonra deny > ask > allow sırası kullanılır.",
	],
	"policy.valid": ["✓ Valid policy", "✓ Geçerli politika"],
	"policy.invalid": ["✗ Invalid policy", "✗ Geçersiz politika"],
	"policy.chars": ["{count} chars", "{count} karakter"],
	"policy.parsed": ["Parsed Policy", "Ayrıştırılan politika"],
	"policy.version": ["Version:", "Sürüm:"],
	"policy.defaultAction": ["Default Action:", "Varsayılan işlem:"],
	"policy.unknownMcp": ["Unknown MCP:", "Bilinmeyen MCP:"],
	"policy.riskyMcp": ["Risky MCP:", "Riskli MCP:"],
	"policy.rulesCount": ["Rules ({count}):", "Kurallar ({count}):"],
	"policy.ruleMeta.priority": ["Priority: {priority}", "Öncelik: {priority}"],
	"policy.ruleMeta.server": [" • MCP server: {server}", " • MCP sunucusu: {server}"],
	"policy.ruleMeta.tool": [" • MCP tool: {tool}", " • MCP aracı: {tool}"],
	"policy.noPreview": [
		"No valid policy document to preview yet.",
		"Önizlenecek geçerli bir politika belgesi henüz yok.",
	],
	"policy.dryTitle": ["Server dry run", "Sunucuda deneme"],
	"policy.dryIntro": [
		"Saving asks {fn} to compile the exact submitted draft before atomically saving it. Unsupported fields and simulation appear here; an intervening edit causes a conflict, not an overwrite.",
		"Kaydetme, gönderilen taslağı tek parça hâlinde kaydetmeden önce {fn} hizmetine birebir derletir. Desteklenmeyen alanlar ve benzetim sonucu burada görünür; arada yapılan bir düzenleme üzerine yazmaya değil, çakışmaya yol açar.",
	],
	"policy.dryCompiled": [
		"Compiled by the server compiler.",
		"Sunucu derleyicisi tarafından derlendi.",
	],
	"policy.dryNoUnsupported": ["Unsupported fields: none.", "Desteklenmeyen alan: yok."],
	"policy.dryPrecedence": ["Conflict precedence: {order}.", "Çakışma önceliği: {order}."],
	"policy.drySimulated": [
		"Simulated unknown MCP call: {action} ({source}).",
		"Bilinmeyen MCP çağrısı benzetimi: {action} ({source}).",
	],
	"policy.dryShadowed": ["{count} shadowed rule warning(s).", "{count} gölgelenmiş kural uyarısı."],
	"policy.dryRefused": [
		"The runtime compiler refused the submitted draft.",
		"Çalışma zamanı derleyicisi gönderilen taslağı reddetti.",
	],
	"policy.dryUnsupportedList": [
		"Unsupported fields reported by the server:",
		"Sunucunun bildirdiği desteklenmeyen alanlar:",
	],
	"policy.dryUnavailable": [
		"The server could not confirm the draft save ({code}).",
		"Sunucu taslağın kaydedildiğini doğrulayamadı ({code}).",
	],
	"policy.validationError": ["Policy validation error:", "Politika doğrulama hatası:"],
} as const satisfies MessagePairs<string>;

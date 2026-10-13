/**
 * CLI output catalog (en/tr) for the commands people run during an incident:
 * `aidr status`, `aidr pending` and `aidr approve`. English values are the
 * exact text these commands printed before; `{name}` marks a parameter.
 *
 * Field labels such as `actionId:` and the confirmation word `approve` stay
 * English in every locale: users copy them, and scripts parse them.
 */
export const CLI_EN = {
	"status.title": "Singularity AIDR — installation diagnostics",
	"status.passed": "passed",
	"status.failed": "FAILED",
	"status.detection": "Detection self-test: {result}; {rules} rules. {detail}",
	"status.configuration": "Configuration: {state}; mode: {mode}",
	"status.registrationDetected": "registration/package detected",
	"status.managedInactive":
		"Managed: inactive (mode: {mode}); enforcement is local and no control plane is used.",
	"status.managedEnabled": "enabled",
	"status.managedDisabled": "disabled",
	"status.endpointConfigured": "configured",
	"status.endpointMissing": "missing",
	"status.managed":
		"Managed: {state}; endpoint {endpoint}. Connectivity and fleet adoption have not been checked.",
	"status.telemetry":
		"Telemetry queue: {state}; {pending} event(s) undelivered, {lost} lost{oldest}{suffix}",
	"status.telemetryOldest": ", oldest {seconds}s",
	"status.telemetryUnreadable": " — at least one queue could not be read.",
	"status.telemetryEnd": ".",
	"status.audit":
		"Audit log: {failures} append(s) could not be written, {drops} rotation(s) dropped the oldest file.",
	"status.auditUnknownDrops": "an unknown number of",
	"status.auditLastError": " Last error: {error}.",
	"status.ready":
		"Local installation checks passed. Run an agent-host canary to confirm actual enforcement.",
	"status.attention":
		"Installation requires attention. Check configuration and connector registration above.",
	"status.disclaimer": "A package or hook registration does not prove that the host executes it.",
	"status.verdictPrefix": "Verdict:",
	"status.verdictProtected": "protected: {hosts}",
	"status.verdictRestart": "restart if open before {since}: {hosts}",
	"status.verdictManual": "needs a manual step: {steps}",
	"status.verdictNone":
		"no supported agent host is registered; install Claude Code, Cursor, VS Code, Codex, OpenCode or OpenClaw, then run 'aidr setup'",
	"status.verdictVerify": "then run 'aidr verify'",
	"verify.title":
		"Singularity AIDR — host hook canary (the canary is passed as data and never executed)",
	"verify.pass": "PASS",
	"verify.fail": "FAIL",
	"verify.skip": "SKIP",
	"verify.notRegistered": "not registered",
	"verify.summaryPass": "Every exercised AIDR hook denied the canary ({count}).",
	"verify.summaryFail":
		"{count} AIDR hook(s) did NOT deny the canary: tool calls of that host may run uninspected.",
	"verify.summaryNone":
		"No AIDR hook entry point could be exercised from here. Run 'aidr status' for the next step.",
	"verify.inProcess":
		"in-process plugin; it runs only inside the host. Restart it, then ask the agent to run a harmless command such as 'echo aidr-canary' to confirm it loads.",
	"verify.pluginOnly":
		"registered as a Claude Code plugin; its hooks run only inside Claude Code (check /plugin).",
	"verify.noEntry": "registered, but no AIDR hook command was found to exercise in {file}.",

	"approvals.artifactsTruncated":
		"artifacts:  showing {shown} of {total} (truncated); the approval covers all {total}",
	"approvals.asked": "asked:      {createdAt} (approvable until {expiresAt})",
	"approvals.integrityFailed": "integrity:  FAILED — this record cannot be approved",
	"approvals.hostDialogConnector":
		"connector:  {connector}   tool: {tool}   (answered in the host's own dialog)",
	"approvals.disabled": "Operator approvals are disabled.",
	"approvals.none": "No Singularity AIDR asks are waiting for approval.",
	"approvals.waiting": "{count} ask(s) waiting for an operator decision (newest first):",
	"approvals.howToApprove": "Approve one retry of a call with: aidr approve <actionId>",
	"approvals.hostDialogHeader":
		"{count} recent ask(s) answered in the host's own dialog (informational; not approvable here):",
	"approvals.hostDialogRoute":
		'To route these through `aidr approve` instead, set operator_approvals.mode to "operator".',
	"approvals.storeUnreadable": "Could not read the approval store: {error}",
	"approvals.answeredInHost":
		"This ask was answered in the host's own confirmation dialog (operator_approvals.mode: host_dialog). It is listed for information only and cannot be approved here.",
	"approvals.notFound":
		"No pending Singularity AIDR ask has this actionId (it may have expired or already been approved). Run `aidr pending` to list open asks.",
	"approvals.integrityRejected":
		"This pending ask failed integrity verification (the record was edited or the approval key changed). It was not approved; have the agent retry to record a fresh ask.",
	"approvals.badTtl": "--ttl must be a whole number of minutes (1-1440).",
	"approvals.notApproved": "Not approved: {reason}",
	"approvals.notApprovedCode": "Not approved ({code}): {reason}",
	"approvals.allowlistPermitted":
		"The agent will also be allowed to add these artifacts to the permanent allowlist once.",
	"approvals.allowlistNotPermitted": "The approval does not allow the agent to allowlist anything.",
	"approvals.promptTitle": "Singularity AIDR — approve a blocked agent action",
	"approvals.promptScope": "This allows ONE retry of exactly this call within {minutes} minute(s).",
	"approvals.approved": "Approved {actionId}… until {expiresAt}.",
	"approvals.retryHint":
		"Tell the agent to retry the same call; the approval is spent by that one retry.",
} as const;

export type CliMessageKey = keyof typeof CLI_EN;

export const CLI_TR: Record<CliMessageKey, string> = {
	"status.title": "Singularity AIDR — kurulum tanılaması",
	"status.passed": "başarılı",
	"status.failed": "BAŞARISIZ",
	"status.detection": "Tespit öz sınaması: {result}; {rules} kural. {detail}",
	"status.configuration": "Yapılandırma: {state}; mod: {mode}",
	"status.registrationDetected": "kayıt/paket algılandı",
	"status.managedInactive":
		"Yönetilen mod: etkin değil (mod: {mode}); koruma yerelde uygulanıyor ve kontrol düzlemi kullanılmıyor.",
	"status.managedEnabled": "etkin",
	"status.managedDisabled": "devre dışı",
	"status.endpointConfigured": "yapılandırılmış",
	"status.endpointMissing": "eksik",
	"status.managed":
		"Yönetilen mod: {state}; uç nokta {endpoint}. Bağlantı ve filo benimsemesi denetlenmedi.",
	"status.telemetry":
		"Telemetri kuyruğu: {state}; {pending} olay teslim edilmedi, {lost} olay kayboldu{oldest}{suffix}",
	"status.telemetryOldest": ", en eskisi {seconds} sn",
	"status.telemetryUnreadable": " — en az bir kuyruk okunamadı.",
	"status.telemetryEnd": ".",
	"status.audit":
		"Denetim kaydı: {failures} ekleme yazılamadı, {drops} döndürme işleminde en eski dosya silindi.",
	"status.auditUnknownDrops": "bilinmeyen sayıda",
	"status.auditLastError": " Son hata: {error}.",
	"status.ready":
		"Yerel kurulum denetimleri başarılı. Korumanın gerçekten uygulandığını doğrulamak için ajan ana makinesinde bir canary sınaması çalıştırın.",
	"status.attention":
		"Kurulum ilgi gerektiriyor. Yukarıdaki yapılandırmayı ve bağlayıcı kayıtlarını kontrol edin.",
	"status.disclaimer":
		"Bir paketin ya da hook kaydının bulunması, ana makinenin onu gerçekten çalıştırdığını kanıtlamaz.",
	"status.verdictPrefix": "Sonuç:",
	"status.verdictProtected": "korunuyor: {hosts}",
	"status.verdictRestart": "{since} öncesinde açıksa yeniden başlatın: {hosts}",
	"status.verdictManual": "elle adım gerekiyor: {steps}",
	"status.verdictNone":
		"kayıtlı desteklenen ajan ana makinesi yok; Claude Code, Cursor, VS Code, Codex, OpenCode ya da OpenClaw kurun, ardından 'aidr setup' çalıştırın",
	"status.verdictVerify": "ardından 'aidr verify' çalıştırın",
	"verify.title":
		"Singularity AIDR — ana makine hook canary sınaması (canary yalnızca veri olarak verilir, asla çalıştırılmaz)",
	"verify.pass": "BAŞARILI",
	"verify.fail": "BAŞARISIZ",
	"verify.skip": "ATLANDI",
	"verify.notRegistered": "kayıtlı değil",
	"verify.summaryPass": "Sınanan her AIDR hook'u canary'yi engelledi ({count}).",
	"verify.summaryFail":
		"{count} AIDR hook'u canary'yi ENGELLEMEDİ: bu ana makinenin araç çağrıları denetlenmeden çalışabilir.",
	"verify.summaryNone":
		"Buradan sınanabilecek bir AIDR hook giriş noktası bulunamadı. Sonraki adım için 'aidr status' çalıştırın.",
	"verify.inProcess":
		"süreç içi eklenti; yalnızca ana makinenin içinde çalışır. Ana makineyi yeniden başlatın, ardından yüklendiğini doğrulamak için ajandan 'echo aidr-canary' gibi zararsız bir komut çalıştırmasını isteyin.",
	"verify.pluginOnly":
		"Claude Code eklentisi olarak kayıtlı; hook'ları yalnızca Claude Code içinde çalışır (/plugin ile kontrol edin).",
	"verify.noEntry": "kayıtlı, ancak {file} içinde sınanacak bir AIDR hook komutu bulunamadı.",

	"approvals.artifactsTruncated":
		"artifacts:  {total} öğeden {shown} tanesi gösteriliyor (kısaltıldı); onay {total} öğenin tümünü kapsar",
	"approvals.asked": "asked:      {createdAt} ({expiresAt} tarihine kadar onaylanabilir)",
	"approvals.integrityFailed": "integrity:  BAŞARISIZ — bu kayıt onaylanamaz",
	"approvals.hostDialogConnector":
		"connector:  {connector}   tool: {tool}   (ana makinenin kendi iletişim kutusunda yanıtlandı)",
	"approvals.disabled": "Operatör onayları devre dışı.",
	"approvals.none": "Onay bekleyen bir Singularity AIDR isteği yok.",
	"approvals.waiting": "Operatör kararı bekleyen {count} istek (en yeniden başlayarak):",
	"approvals.howToApprove":
		"Bir çağrının tek bir yeniden denemesini onaylamak için: aidr approve <actionId>",
	"approvals.hostDialogHeader":
		"Ana makinenin kendi iletişim kutusunda yanıtlanan {count} yeni istek (bilgi amaçlı; buradan onaylanamaz):",
	"approvals.hostDialogRoute":
		'Bunları `aidr approve` üzerinden yönlendirmek için operator_approvals.mode değerini "operator" yapın.',
	"approvals.storeUnreadable": "Onay deposu okunamadı: {error}",
	"approvals.answeredInHost":
		"Bu istek ana makinenin kendi onay iletişim kutusunda yanıtlandı (operator_approvals.mode: host_dialog). Yalnızca bilgi amaçlı listelenir ve buradan onaylanamaz.",
	"approvals.notFound":
		"Bu actionId ile bekleyen bir Singularity AIDR isteği yok (süresi dolmuş ya da zaten onaylanmış olabilir). Açık istekleri listelemek için `aidr pending` komutunu çalıştırın.",
	"approvals.integrityRejected":
		"Bu bekleyen istek bütünlük doğrulamasından geçemedi (kayıt değiştirilmiş ya da onay anahtarı değişmiş). Onaylanmadı; yeni bir istek kaydedilmesi için ajanın çağrıyı yeniden denemesini sağlayın.",
	"approvals.badTtl": "--ttl tam sayı olarak dakika cinsinden olmalıdır (1-1440).",
	"approvals.notApproved": "Onaylanmadı: {reason}",
	"approvals.notApprovedCode": "Onaylanmadı ({code}): {reason}",
	"approvals.allowlistPermitted":
		"Ajanın bu öğeleri kalıcı izin listesine bir kez eklemesine de izin verilecek.",
	"approvals.allowlistNotPermitted":
		"Bu onay, ajanın izin listesine herhangi bir şey eklemesine izin vermez.",
	"approvals.promptTitle": "Singularity AIDR — engellenmiş bir ajan eylemini onayla",
	"approvals.promptScope":
		"Bu onay, tam olarak bu çağrının {minutes} dakika içinde TEK bir kez yeniden denenmesine izin verir.",
	"approvals.approved": "{actionId}… onaylandı, geçerlilik bitişi: {expiresAt}.",
	"approvals.retryHint":
		"Ajana aynı çağrıyı yeniden denemesini söyleyin; onay bu tek yeniden denemeyle kullanılmış olur.",
};

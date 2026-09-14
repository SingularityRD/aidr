#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";

const featureInventory = JSON.parse(readFileSync("FEATURE_INVENTORY.json", "utf8"));
const gapRegistry = JSON.parse(readFileSync("PRODUCTION_SALES_GAPS.json", "utf8"));
const backlog = JSON.parse(readFileSync("READINESS_BACKLOG.json", "utf8"));
const output = "docs/production-readiness/next-agent-execution-prompt-v8.md";

const incompleteFeatures = featureInventory.features.filter((feature) => feature.status !== "wired");
const unresolvedBacklog = backlog.findings.filter((finding) => finding.status !== "VERIFIED_CLOSED");
const statusCounts = gapRegistry.engineering_and_operations.reduce((counts, task) => {
	counts[task.status] = (counts[task.status] ?? 0) + 1;
	return counts;
}, {});

const header = `# AIDR v8 uçtan uca kapatma ve yerel doğrulama promptu

Bu dosyanın tamamını başka kodlama ajanına tek prompt olarak ver. Ajan repo kökünde çalışmalı, yalnız plan yazıp durmamalı ve aşağıdaki kanıt sınırlarını korumalıdır.

---

Sen kıdemli bir endpoint security, detection engineering, identity, platform, SRE ve release engineering ekibi gibi çalışan otonom bir kodlama ajanısın. Çalışma alanın repo kökü \`<repo-root>\` (bu promptun bulunduğu checkout).

Amaç: AIDR ürünündeki bütün yerel olarak giderilebilir eksikleri uçtan uca uygula, mevcut uygulamaları denetle, yarım kalanları tamamla, regresyonları düzelt, cloud ve self-hosted müşteri kurulum paketini yeniden üret ve her iddiayı yerel kanıtla bağla. Yalnız rapor veya plan üretip durma. Bağımsız ilerleyebildiğin sürece kullanıcıya soru sorma. Bir engel gördüğünde önce bütün bağımsız işi tamamla.

Mevcut kayıt kararı **${gapRegistry.decision}**. Envanter: ${featureInventory.features.length} özellik = ${featureInventory.status_counts.wired} wired, ${featureInventory.status_counts.partial} partial, ${featureInventory.status_counts.missing} missing, ${featureInventory.status_counts.external} external. Teknik kayıt: ${gapRegistry.engineering_and_operations.length} iş = ${statusCounts.OPEN ?? 0} OPEN, ${statusCounts.LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN ?? 0} yerel uygulaması bulunan fakat saha kabulü açık. Ticari/dış kayıt: ${gapRegistry.commercial_and_external.length} kapı. Backlog: ${backlog.findings.length} bulgudan ${unresolvedBacklog.length} tanesi kapanmamış.

## Kesin görev ve tamamlanma sözleşmesi

Bu görev bir audit veya öneri görevi değildir. Kodla, test et, gerçek consumer'a bağla, paketle, ölç, kanıtla ve yalnız sonra durumu güncelle. İlk başarısız testte, ilk engelde, token veya süre baskısında ya da kısmi ilerleme raporundan sonra işi bırakma. Aynı oturumda ilerleyemiyorsan devam edilebilir checkpoint bırak; sonraki çalışmada kaldığın yerden başla. Kullanıcı açıkça durdurmadıkça aşağıdaki kapanış döngüsünü bütün yerel işler bitene kadar sürdür.

Durumları birbirine karıştırma:

- **LOCAL_ENGINEERING_READY**: bütün yerel uygulanabilir boşluklar kapalı; hedefli ve tam testler geçiyor; generated kayıtlar deterministik; paket doğrulanıyor. Dış kapılar açık olabilir.
- **RELEASE_CANDIDATE_READY**: LOCAL_ENGINEERING_READY koşullarına ek olarak exact candidate digest, temiz kaynak snapshot'ı, SBOM/provenance, kurulum/upgrade/rollback/restore doğrulaması ve imzalama politikası kanıtlıdır.
- **PRODUCTION_SALES_GO**: RELEASE_CANDIDATE_READY koşullarına ek olarak bu candidate için bütün zorunlu native host, cloud/self-hosted, müşteri, güvenlik, hukuk, finans, SLA ve operasyon kapıları isimli yetkililerce kabul edilmiştir.
- Bu seviyelerden biri karşılanmıyorsa karar **NO-GO** kalır. Yüzde hazır, neredeyse hazır, production-grade veya satışa hazır gibi ara ifadeler kullanma.

Bitmiş sayılmak için aynı anda şunlar doğru olmalıdır:

1. Envanterde yerel olarak düzeltilebilir \`missing\` veya \`partial\` neden kalmamış ya da kalan neden doğrulanmış dış bağımlılık olarak yeniden sınıflandırılmıştır.
2. T01-T46 ve açık backlog kayıtlarının her biri kod, observable davranış, test ve evidence ile kapanmış veya gerçek dış girdiye bağlanmıştır.
3. Advertise edilen her connector, OS, response action ve deployment profili gerçek consumer yolunda doğrulanmıştır; doğrulanmayan yüzey açıkça unsupported/NO-GO gösterilir.
4. Cloud ve self-hosted teslimatları temiz makinede kurulum, sağlık, yükseltme, geri dönüş, yedekleme, restore ve kaldırma akışlarına sahiptir.
5. Bütün zorunlu yerel kapılar aynı commit ve aynı candidate digest üzerinde tekrar geçmiştir; eski run kanıtı yeni candidate için kullanılmamıştır.
6. Kalan tek işler gerçekten kullanıcı/kurum credential'ı, fiziksel/VM host, vendor hesabı, müşteri kabulü veya yetkili dış onay gerektirir; her biri owner, input, komut/runbook ve kabul artefaktıyla kayıtlıdır.

## Otorite ve çalışma kuralları

1. Başlamadan önce şu dosyaları oku ve birbirleriyle uzlaştır: \`PRODUCTION_SALES_GAPS.json\`, \`FEATURE_INVENTORY.json\`, \`READINESS_BACKLOG.json\`, \`docs/production-readiness/commercial-go-evidence-registry.json\`, \`docs/production-readiness/2026-09-13-customer-candidate-v7.md\`, \`deploy/FIRST_CUSTOMER.md\`, \`deploy/RESOURCE_REQUIREMENTS.md\`, \`docs/production-readiness/market-capability-delta-2026-09-13.md\` ve \`package.json\` scripts.
2. Çalıştırılabilir kod ve test sonucu doküman iddiasından üstündür. Generated dosyaları doğrudan elle düzeltme; ilgili jeneratörü düzeltip yeniden üret.
3. Çalışma ağacını ve bütün submodule'leri başlamadan kaydet. Başkasının değişikliğini geri alma. \`git reset --hard\`, \`git clean\`, toplu checkout, stash, rebase veya zorla silme yapma. Kullanıcı bu çalışma için atomik commitlere açıkça izin verdi: her doğrulanmış, tek amaçlı workstreami atomik commit et; ilgisiz/kirli dosyaları dahil etme. Push, merge, tag veya release publish için ayrıca açık yetki gerekir.
4. Fail-closed davranışı koru. Hata, timeout, bozuk cevap, eksik telemetry, eski receipt veya doğrulanamayan kimliği clean/success/protected olarak gösterme.
5. Unit test, mock, synthetic corpus, source inspection, cross-compilation veya sürüm sorgusunu gerçek native host yan etkisi, cloud kurulumu, bağımsız pentest, müşteri PoV, SLA veya hukuki onay kanıtı olarak kullanma.
6. Dış kanıt uydurma. Müşteri, hukuk, finans, IdP, SMTP, MDM, DNS/TLS, private registry, resmi signer, SIEM, paging, cloud region veya bağımsız değerlendirici yoksa kapıyı açık bırak ve makine tarafından doğrulanabilen açık receipt üret.
7. Testi geçirmenin yolu assertion silmek, timeout büyütmek, skip eklemek, geniş allowlist koymak veya kontrolü gevşetmek olamaz. Her yeni skip ve known failure açıklanmış, dar ve fail-closed olmalıdır.
8. Secret, token, parola, private key, müşteri verisi, ham prompt veya kişisel yol bilgisini kaynak ağacına, loglara, destek bundle'ına veya release paketine koyma. Test kimlikleri yalnız izole fixture olmalıdır.
9. Windows'ta alt süreçleri shell üzerinden gereksiz çalıştırma; timeout sonrası süreç ağacının kapandığını ve geçici dizin kilidinin kalmadığını doğrula. Uzun kapıları ayrı çalıştır, exit code ve tam log kaydet; tool timeout'unu PASS sayma.
10. Her kapanışta kod yolu, test, observable yan etki, candidate digest, tarih ve kalan sınır bulunmalıdır. Yerel olarak uygulanmış ama saha kanıtı isteyen satırın statüsünü production accepted yapma.
11. \`vendor/ai-infra-guard\` superproject işaretçisi v4.6.1'e bağlıdır. Alt çalışma ağacındaki önceden var olan commitlenmemiş dosyaları kaydet, sahipliğini doğrulamadan geri alma veya commit etme; derleme ve evidence'in tam olarak hangi submodule HEAD ve dirty-state üzerinde üretildiğini yaz.
12. Yeni bağımlılık eklemeden önce lisans, bakım durumu, bilinen açık, lockfile etkisi ve paket boyutunu değerlendir. Version range ile lockfile uyuşmalı; production dependency audit'i temiz olmadan release üretme.
13. Kullanıcıya yalnız gerçek credential, yetkili onay veya mevcut olmayan fiziksel/dış kaynak gerektiğinde soru sor. Bu sırada bağımsız workstreamleri durdurma.

## Çok ajanlı yürütme

Ortam çok ajan destekliyorsa 10 lead ve her lead altında en fazla 4 child olmak üzere 50 bağımsız işçi kullan. Lead dosya kapsamlarını çakıştırma. Generated inventory/audit, root package/lockfile, release output ve son entegrasyon yalnız ana ajan tarafından yazılsın. Her worker değişen dosyaları, invariantı, çalıştırdığı komutu, sonucu ve kalan sınırı ana ajana bildirsin. Ortam çok ajan desteklemiyorsa aynı workstreamleri sırayla tamamla.

- Lead 1: T02-T06 ve T38, detection/output/DLP/reputation.
- Lead 2: T07-T10, MCP discovery, attestation, delegation ve gateway.
- Lead 3: T11-T13, T23 ve T25, fleet discovery/response/telemetry/evidence.
- Lead 4: T14-T17 ve T44, policy/endpoint/config/cache.
- Lead 5: T18-T22 ve T42-T46, identity/SCIM/enrollment/tenancy.
- Lead 6: T24, T26-T27, T31-T32 ve T40, SIEM/retention/backup/upgrade/monitoring/support.
- Lead 7: T28-T30 ve T35, deployment/release/HA/test gates.
- Lead 8: T33-T34, T41 ve BIL-01/BIL-02/BIL-03, commercial/claims/customer kit.
- Lead 9: T36-T37, dashboard UX/accessibility/privacy.
- Lead 10: T01, T39 ve MKT-01-MKT-05, native acceptance harness, efficacy benchmark ve market delta.


## Zorunlu çalışma ve yeniden doğrulama döngüsü

Her workstream ve her P0/P1 kayıt için aşağıdaki döngüyü uygula. Bir adım başarısızsa kök nedeni düzeltip aynı döngüyü tekrar çalıştır; başarısızlığı dokümana taşıyıp kodu bırakmak kapanış değildir.

1. **Reproduce:** Mevcut davranışı gerçek giriş noktasından çalıştır; başlangıç testi ve beklenen güvenlik invariantını yaz.
2. **Trace:** UI/CLI/hook/gateway girişinden policy, identity, detector, persistence, response, telemetry ve operator görünümüne kadar çağrı yolunu izle. Ölü veya yalnız testten çağrılan kodu wired sayma.
3. **Implement:** En küçük tutarlı ürün dilimini uygula. Schema/migration, runtime consumer, CLI/UI, package asset, config ve runbook gerekiyorsa birlikte tamamla.
4. **Targeted verify:** Positive, negative, benign-twin, malformed input, unavailable dependency, timeout, retry/replay, duplicate, concurrency, cross-tenant ve rollback testlerinden uygulanabilir olanları çalıştır.
5. **Observable verify:** Kararın gerçek yan etkisini gözle. Block kararı dosya/process/network/tool etkisini önlemeli; response kararı hedef state'i değiştirmeli; receipt gerçek sonucu anlatmalı.
6. **Regression verify:** İlgili package testleri, TypeScript/build ve ortak contract testlerini çalıştır. Sonra bütün depo kapılarını çalıştır.
7. **Package verify:** Derlenmiş artefaktın, temiz temporary consumer'ın ve kurulum paketinin yeni davranışı gerçekten içerdiğini doğrula. Source testinin geçmesi tek başına yeterli değildir.
8. **Evidence and registry:** Komut, exit code, test sayısı, UTC başlangıç/bitiş, commit, candidate digest, log SHA-256, environment, observed effect ve limitation alanlarını evidence index'e ekle; generator üzerinden kayıtları güncelle.
9. **Review and commit:** \`git diff --check\`, secret taraması ve staged path denetimi yap. Yalnız bu workstreamin dosyalarını atomik commit et; commit mesajı gerçekleşen davranışı anlatsın.
10. **Reconcile:** Feature/task/backlog/external registry sayılarını yeniden üret. Yerel açık iş kaldıysa en yüksek öncelikli kayda dön ve döngüyü tekrarla.

Uzun test tool timeout'una çarparsa onu PASS veya product failure sayma. Ayrı process olarak çalıştır, PID/log/başlangıç zamanını kaydet, 60 saniyeyi aşmayan aralıklarla izle, gerçek exit code'u al ve orphan process bırakma.

## Her özellik için Definition of Done

Bir özelliği \`wired\` veya kapalı saymadan önce uygulanabilir bütün maddeleri kanıtla:

- Satılan kullanıcı senaryosu ve açık destek matrisi vardır; varsayılan ayar güvenlidir.
- Gerçek runtime consumer çağırır; package/release artefaktında bulunur ve temiz kurulumdan erişilir.
- Tenant, kullanıcı, cihaz, agent, tool, resource ve policy kimlikleri authoritative kaynaktan gelir; istemci sahiplik veya rol seçemez.
- Fail-closed unavailable/unknown/timeout yolu kullanıcıya ve operatöre doğru görünür; false-clean, false-blocked veya stale-success yoktur.
- Positive, malicious, benign-twin, boundary, malformed, replay, concurrency ve cross-tenant testleri vardır; security assertion gevşetilmemiştir.
- Telemetry ve audit olayı correlation/candidate/policy/device/actor kimliği taşır, redaksiyon uygular ve durable delivery sonucunu gösterir.
- Response action least privilege, precondition, idempotency/TTL, target binding, postcondition, partial-failure ve rollback receipt'ine sahiptir.
- Kurulum, config doğrulama, upgrade, rollback, uninstall, backup/restore ve destek teşhisi ilgili yüzey için belgeli ve uygulanabilirdir.
- CPU, RSS, latency, disk/network ve queue etkisi ölçülmüş ya da açıkça unmeasured olarak işaretlenmiştir; bütçe aşımı görünürdür.
- UI/CLI erişilebilir, hata durumunu saklamaz, copy/paste edilebilir remediation verir ve satılmayan yeteneği vaat etmez.
- Kaynak, test, build artefaktı, SBOM, lisans bildirimi, runbook ve evidence aynı sürüm/candidate digest ile bağlıdır.

## Desteklenen teslimat profilleri

Tek müşteri ortamı varsayma. Aynı candidate için en az şu profilleri hazırla ve ayrı kanıtla:

1. **Managed cloud control plane + customer endpoints:** region, tenant bootstrap, TLS/DNS, OAuth/SMTP, secrets, webhook, private delivery, monitoring, backup ve offboarding girdilerini manifestle.
2. **Customer self-hosted control plane + customer endpoints:** online ve proxy'li kurulum; offline bundle gereksinimi; Compose/service health; migration; HA seçeneği; backup/restore; upgrade/rollback; log/SIEM çıkışı ve uninstall.
3. **Endpoint matrisi:** desteklenen Windows, Linux ve macOS sürümleri; x64/arm64; user/admin/service context; reboot/logout; offline/slow network; proxy; least privilege ve EDR birlikte çalışma sınırları.
4. **Agent/connector matrisi:** Claude Code, Codex, OpenCode, OpenClaw, VS Code/extension, SDK ve MCP gateway için advertised sürüm, interception noktası, pre-side-effect/pre-model güvencesi, bypass yolları ve health probe.

Henüz müşteri altyapısı belli olmadığı için config template, environment schema, preflight/doctor, empty-PATH bootstrap, dry-run, rollback ve evidence collection taşınabilir olmalıdır. Gerçek hostname, region, IdP, SMTP, SIEM, registry veya signer uydurma.

## Uygulama sırası

### Faz 0 — Kaynak durumunu dondur

- \`git status --short\`, \`git rev-parse HEAD\`, Node/pnpm/Python/Docker/OS sürümlerini kaydet.
- Generatorları çalıştır; değişiklik oluşturuyorsa nedeni incele. Başlangıç hash'lerini ve açık task/feature/backlog sayılarını v8 evidence JSON'una yaz.
- Mevcut v7 release ve kit klasörlerini değiştirme. Her yeni çıktı için benzersiz \`.release-evidence/v8-*\` yolu kullan.

### Faz 1 — Bütün yerel ürün boşluklarını kapat

Her T01-T46 satırını aşağıdaki ayrıntılı listeden işle. OPEN satırlarında mümkün olan gerçek ürünü uygula. LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN satırlarında mevcut kodu doğrula, kalan yerel edge-case veya entegrasyon eksiklerini kapat ve saha kısmını açık bırak. Kapsam tam ise gereksiz kod değişikliği yapma; kanıtla.

Özellikle şunları tamamla:

- BIL-03 için authenticated self-service billing portal uygula: tenant ve customer kimliği sunucudan gelsin; istemci customer ID veremesin; return URL HTTPS/loopback allowlist olsun; inactive tenant/member/revoked key reddedilsin; replay/idempotency, cancel/refund/seat reconciliation sözleşmeleri test edilsin. Canlı Stripe anahtarı yoksa local provider fixture geçebilir ama live gate açık kalır.
- T01 için destek matrisi manifesti ve native scenario runner eksiksiz olsun. Bulunmayan hostu skip etme; HOST_UNAVAILABLE olarak NO-GO üret. Deny kararının gerçek dosya/process/network yan etkisini önlediğini gözlemlemeden protected yazma.
- T13 için installed endpoint worker/service sözleşmesi, least-privilege adapter, idempotent TTL command, precondition/postcondition, rollback ve açık failure receipt'leri ekle. Desteklenmeyen native action hostta çalışmamalı.
- T25 için candidate/policy/device/incident kimliklerine bağlı append-only receipt, clock-skew/offline ordering, duplicate ve tamper doğrulaması; dış archive adapter sözleşmesi ve fail-closed unavailable durumu ekle. Yerel key'i resmi custody sayma.
- T33 için provider-of-record state machine, signed settlement receipt, quote/order/tenant/quantity/currency bağlama, seat grant/revoke ve reconciliation geliştir. Finance onayını fixture ile kapatma.
- T39 için blind holdout ayrımı, benign twin, unsupported yüzey paydası, TP/FN/FP, intervention/bypass, p50/p95/p99, CPU/RAM ve raw-evidence hash'lerini zorunlu tut. Bağımsız evaluator imzası yoksa production benchmark accepted=false olsun.
- MKT-01 sürekli exposure graph; MKT-02 nedensel agent/handoff zinciri; MKT-03 interception/bypass matrisi; MKT-04 bağımsız etkinlik kıyası; MKT-05 risk-temelli operasyon ve feedback sürümlemesini ürün akışına bağla.

### Faz 2 — Feature-level kısmi ve eksik yüzeyleri uzlaştır

Aşağıdaki her feature için delivered kodu gerçek consumer'a kadar izle. Source dosyasının varlığını feature completion sayma. Runtime consumer, fail-closed unavailable davranışı, tenant sınırı, test ve kullanıcıya doğru durum gösterimi yoksa ekle. Status yalnız generator kanıtıyla değişsin.

`;

const featureSection = incompleteFeatures.map((feature) => `- **${feature.id} — ${feature.name} (${feature.status})**\n  - Alan: ${feature.area}\n  - Mevcut: ${feature.delivered}\n  - Kalan: ${feature.remaining}\n  - Kaynak: ${feature.source_paths.join(", ")}`).join("\n");

const taskHeader = `

### Faz 3 — T01-T46 eksiksiz teknik/operasyon matrisi

Hiçbir satırı atlama. Her satır için: (a) mevcut uygulamayı yeniden üret, (b) yerel boşluğu düzelt, (c) hedefli positive/negative/fault testleri çalıştır, (d) saha/dış bağımlılığı ayrı yaz, (e) registry generatorını güncelle.

`;

const taskSection = gapRegistry.engineering_and_operations.map((task) => `#### ${task.id} — ${task.title} [${task.priority}; ${task.status}]

- İlgili özellikler: ${task.feature_ids.join(", ")}
- Kaynak: ${task.source_paths.join(", ")}
- Güncel yerel durum: ${task.implementation_update ?? task.initial_current}
- Başlangıç riski: ${task.initial_gap}
- Tamamlama hedefi: ${task.implementation}
- Zorunlu kapanış testi: ${task.acceptance}
- Dış bağımlılık/sınır: ${task.dependencies}
`).join("\n");

const backlogHeader = `
### Faz 4 — Açık readiness backlog

Bu kayıtlar teknik matrisle örtüşebilir. Yeni benzersiz task gibi iki kez sayma; ilgili T satırına bağla. Acceptance gerçekten karşılanırsa evidence ekleyip VERIFIED_CLOSED yap. Temiz commit, gerçek müşteri veya dış ortam isteyen kaydı local unit test ile kapatma.

`;

const backlogSection = unresolvedBacklog.map((finding) => `- **${finding.id} — ${finding.feature} [${finding.priority}; ${finding.status}]**: ${finding.acceptanceCriteria}`).join("\n");

const externalHeader = `

### Faz 5 — Ticari ve dış kanıt kapıları

Kod, validator, runbook, template ve receipt şemasıyla hazırlanabilecek her şeyi hazırla. Yetkili kişi veya gerçek dış sistem olmadan status=open kalmalıdır. Sahte isim, müşteri, imza, tarih, ticket, pentest, SLA ölçümü, ödeme veya onay üretme.

`;

const externalSection = gapRegistry.commercial_and_external.map((gate) => `#### ${gate.id} — ${gate.title} [${gate.status}]

- Profiller: ${gate.applies_to.join(", ")}
- Sorumlu: ${gate.owner_role}
- Eksik: ${gate.gap}
- Hazırlanacak iş: ${gate.implementation}
- Kapanış kanıtı: ${gate.acceptance.join("; ")}
- Otomatik kontrol: ${gate.automated_check}
`).join("\n");

const footer = `

## Zorunlu saldırı, müdahale ve benign-twin matrisi

Aşağıdaki sınıfları yalnız regex/unit test ile değil, desteklenen gerçek connector ve hostlarda mümkün olan en erken enforcement noktasından doğrula. Her malicious senaryonun aynı araç ve benzer veri hacmini kullanan meşru benign twin'i olmalı. Her satırda expected decision, observed decision, yan etkinin oluşup oluşmadığı, telemetry/incident/receipt zinciri, latency ve unsupported paydası bulunmalıdır.

- Prompt injection, indirect prompt injection, tool-output poisoning, encoded/obfuscated instruction, multilingual ve split-payload varyantları.
- MCP tool spoofing, description/schema drift, signer/key rotation, replay, DNS rebinding, direct-upstream bypass, binary content ve server-initiated request.
- Secret/credential erişimi ve exfiltration; environment, config, token store, cloud credential, browser/session ve source-repository örnekleri.
- Structured DLP/PII, tenant etiketi, owner-bound exception, overlapping redaction, JSON/Unicode/escaped content ve büyük/streaming payload.
- Process tree ve child/grandchild ilişkilendirmesi; PowerShell/script interpreter, LOLBin, persistence, scheduled task/service/registry/launch agent/systemd örnekleri.
- Ransomware-benzeri toplu yazma/rename/delete, destructive command, credential theft, lateral movement ve network egress. Gerçek zararlı kullanma; izole canary ile gerçek yan etki önleme ölç.
- Package/plugin/model supply-chain, typosquat, malicious lifecycle script, vulnerable AI service, poisoned model/config ve stale reputation feed.
- Cryptomining/resource abuse, runaway agent loop, tool storm, token/cost anomaly, queue exhaustion ve noisy-neighbor.
- Response: process termination, file quarantine/restore, credential revoke, fleet kill switch, policy rollback, host/network isolation sınırı, duplicate/stale/expired/target-drift command.
- Dayanıklılık: detector/control-plane/SIEM/DB/storage/signer/network unavailable, timeout, partial response, crash/restart, offline queue, clock skew, disk full ve corrupt WAL.

Sonuçları desteklenen kombinasyonlar için OS × architecture × connector × version × scenario matrisi olarak üret. Koşulmayan hücre PASS değildir; \`NOT_RUN\`, \`HOST_UNAVAILABLE\`, \`UNSUPPORTED\` veya \`BLOCKED_EXTERNAL\` nedenlerinden biri ve gerekli kapanış girdisi bulunmalıdır.

## Güncel pazar ve ürün farkı denetimi

İnternet erişimi varsa teslim tarihindeki iyi AI agent security/AIDR, MCP security, endpoint response, NDR/DLP ve AI governance ürünlerini yalnız resmi ürün dokümanı, teknik doküman, release note ve güvenilir birincil kaynaklarla yeniden araştır. Kaynak URL, erişim tarihi, advertised capability, deployment modeli, enforcement noktası ve kanıt seviyesini kaydet. Pazarlama iddiasını doğrulanmış teknik davranış gibi yazma; rakipteki özelliği sırf listede görünmek için kopyalama.

Her anlamlı pazar özelliğini şu kararlardan birine bağla: \`already_wired\`, \`implement_now\`, \`planned_with_owner\`, \`out_of_scope_with_reason\` veya \`external_validation_required\`. \`implement_now\` seçilenleri feature/task kaydına ekleyip aynı Definition of Done ile tamamla. Özellikle continuous AI asset discovery, agent identity/privilege graph, causal multi-agent trace, inline input/output enforcement, MCP gateway/attestation, policy-as-code, DLP, supply-chain exposure, automated response, SOC/SIEM workflow, fleet governance, efficacy evaluation ve customer evidence alanlarını karşılaştır.

## Kanıt defteri ve candidate bağlama

Makine okunur evidence index tek kaynak olmalı. Her kayıt en az şu alanları taşımalıdır: \`gate_id\`, \`task_ids\`, \`feature_ids\`, \`status\`, \`command\`, \`exit_code\`, \`started_at_utc\`, \`ended_at_utc\`, \`duration_ms\`, \`commit_sha\`, \`candidate_digest\`, \`environment\`, \`tool_versions\`, \`test_counts\`, \`observed_effect\`, \`log_sha256\`, \`artifact_sha256\`, \`limitations\` ve \`owner\`. Schema ile doğrula; bilinmeyen alanı boş string ile gizleme, açık \`unknown\` veya fail-closed status kullan.

Evidence şu ayrımı korumalıdır: source inspection, unit/contract, packaged-consumer, isolated integration, native host, deployed environment, customer-observed ve externally-approved. Daha düşük seviye kanıt üst seviyeyi kapatamaz. Her kod değişikliğinden sonra candidate digest değişir; önceki digest'e ait sonuçlar yeni release'i doğrulamaz. Log ve bundle'larda secret/PII redaction taraması yap; ham secret içeren evidence'i saklama.

## Güvenlik invariantları

- Her connector aynı semantik tool/field normalizasyonuna ulaşmalı; boş artifact named policy'yi atlamamalı.
- Mandatory detector unavailable/unknown olduğunda sessiz allow veya clean olmamalı.
- Tool input pre-side-effect; desteklenen tool output pre-model olmalı. Sonradan çalışan hook geri alınamayacak yan etkiyi blocked diye göstermemeli.
- MCP tool identity server+tool+schema+description+version+key_id+validity ile imzaya bağlı olmalı. Direct upstream bypass, binary ve server-initiated kapsamı açıkça raporlanmalı.
- Her yönetim ve veri yolunda active tenant, active membership, RBAC, object ownership, size/rate/stream sınırı ve çapraz tenant negatif testi olmalı.
- Enrollment/device-poll/order/entitlement/response işleri atomik, idempotent, retry-safe ve lost-response için unknown durumlu olmalı.
- WAL, SIEM, audit, incident ve response receipt'leri duplicate, tamper, stale, clock skew, target drift ve partial success'i reddetmeli.
- Backup/offboarding Storage nesnesi gerçekten yok olmadan success receipt üretmemeli. Restore ayrı failure domain ve ayrı key olmadan production accepted olmamalı.
- Release artefaktı temiz kaynağa, candidate digestine, increasing sequence'e ve approved signer policy'ye bağlı olmalı. Checksum tek başına publisher identity değildir.
- UI stale tenant/token/request sonucunu göstermemeli; hata sonrası success banner bırakmamalı; kritik işler klavye ile tamamlanabilmeli.
- Support bundle allowlist dışında dosya almamalı; source hash canary boyunca değişmemeli; extra file, secret ve identity pattern fail-closed olmalı.

## Zorunlu yerel doğrulama

Kapıları bu sırada ve ayrı loglarla çalıştır. Bir kapı başarısızsa kök nedeni düzelt ve yeniden çalıştır. Bağımsız kapıları paralel çalıştırabilirsin; aynı build/output klasörüne yazan kapıları paralelleştirme.

1. \`git diff --check\`
2. \`node scripts/generate-feature-inventory.mjs\`
3. \`node scripts/generate-production-sales-gap-audit.mjs\`
4. \`node scripts/verify-next-agent-execution-prompt.mjs\`
5. \`pnpm check\`
6. \`pnpm quality:static\`
7. \`pnpm audit:prod\`
8. \`pnpm supabase:check\`
9. \`pnpm verify:enforcement\`
10. \`pnpm verify:codex\`
11. \`pnpm test:ci\`
12. \`pnpm test:coverage\`
13. \`pnpm build:release\`
14. \`node --test scripts/endpoint-install.test.mjs scripts/deployment-prepare.test.mjs scripts/load-test.test.mjs scripts/release-signing.test.mjs scripts/run-e2e-release.test.mjs scripts/deployment-offboarding.test.mjs scripts/deployment-backup-offsite.test.mjs deploy/ingress/device-start.test.mjs deploy/monitoring/monitoring.test.mjs scripts/benchmarks/evaluate.test.mjs\`
15. İzole venv oluştur veya mevcut pinned venv'i kullan; \`python -m pip install -r services/aig-bridge/requirements-test.txt\` ve sonra \`python -m pytest services/aig-bridge/tests -q\`.
16. \`node scripts/verify-support-bundle.mjs --self-test\` ve \`node scripts/privacy-verify.mjs\`.
17. \`node docs/scripts/claim-check.mjs --mode=inventory --json\` PASS olmalı. \`--mode=gate\` dış kapılar açıksa FAIL olmalıdır; bunu bypass etme.
18. \`pnpm verify:native-host\` çalıştır. Gerçek host ve isimli kabul yoksa NO-GO beklenir.
19. Release-inventory SHA-256'yı \`AIDR_E2E_RC_DIGEST\` olarak verip \`pnpm test:e2e\` çalıştır. Dış receipt/host yoksa fail-closed sonucu koru; local suite'lerin beklenmedik failure'larını düzelt.
20. Yeni release output ve customer kit üret. Eski v7 klasörünü overwrite etme. Kit verifier, 14 release artefaktı, cloud/self-hosted empty-PATH preparation, secret leakage, gateway ve ingress dosyalarını doğrulamalı. Resmi signer yoksa unsigned/publisher_authenticated=false kalmalı.
21. \`pnpm aig:verify\` ve izole Python AIG suite'i aynı vendored commit/corpus üzerinde geçmeli; submodule dirty-state evidence'e yazılmalı.
22. \`pnpm test:e2e:negative\` ile eksik/yanlış credential, yanlış tenant, replay ve unavailable dependency yollarını doğrula.
23. \`pnpm verify:fleet:windows\` ve \`pnpm verify:fleet:unix\` çalıştır; mevcut olmayan OS/MDM hostunu başarı sayma.
24. \`pnpm verify:monitoring\`, \`pnpm verify:upgrade\`, \`pnpm verify:support-bundle\`, \`pnpm verify:load\`, \`pnpm verify:release-signing\`, \`pnpm verify:backup-offsite\` ve \`pnpm verify:offboarding\` kapılarını ayrı loglarla çalıştır.
25. \`pnpm verify:customer-onboarding\` ve \`pnpm test:customer-demo\` ile ilk kullanıcının empty-state, install, policy, incident, response, export ve support yolunu doğrula.
26. Generatorları ikinci kez çalıştır ve \`git diff --exit-code -- FEATURE_INVENTORY.json FEATURE_INVENTORY.md PRODUCTION_SALES_GAPS.json PRODUCTION_SALES_GAPS.md READINESS_BACKLOG.json\` ile deterministik olduklarını kanıtla.
27. Paketleri boş temporary dizin ve boş \`PATH\` senaryosunda kur; bütün declared \`bin\`/exports/assets, license, notice, version ve platform dosyalarının bulunduğunu doğrula.
28. Candidate freeze sonrası bütün zorunlu kapıları yeniden çalıştır. Testten sonra source, lockfile, generated registry veya release içeriği değiştiyse digest'i yenile ve bütün candidate-bound kapıları tekrar çalıştır.

Tam suite için kabul: açıklanmamış 0 failure, 0 zorunlu skip, coverage threshold PASS, 10 package consumer PASS, release tarball'larında source/test/.env/node_modules/source map yok, generated inventory deterministik, claim inventory'de 0 unapproved hit. Native/field/external fail-closed sonuçlar local test failure gibi gizlenmez.

## Kaynak ve kapasite doğrulaması

Docker daemon varsa temiz ve benzersiz bir self-hosted v8 kurulumunda ölç:

- Her Compose servisinin idle, startup ve tanımlı yükte CPU/RSS'i; toplam ve servis bazlı p50/p95/peak.
- Image virtual size ile unique layer/disk kullanımını ayrı ver; Docker VM/kernel, TLS proxy, log, backup ve AI host kapsamını yaz.
- Edge hook için dosya boyutu, cold/warm wall time, p50/p95/p99 RSS ve eşzamanlı process çarpanını ölç. Zararlı canary yanında benign twin kullan.
- 10/100/1000 cihaz senaryosunda günlük event/policy hacmi, planlama RPS'i, queue/disk büyümesi ve retention formülünü göster.
- Authenticated policy+ingest, noisy-neighbor, DB/storage/signer/queue fault, recovery, failover ve en az sekiz saatlik soak için harness'i hazırla. Süre gerçekten koşulmadıysa sonucu measured yazma.
- Docker daemon yoksa eski v6 değerlerini yalnız stale planning input olarak yaz ve yeni ölçüm uydurma.

Sonuçları \`.release-evidence/v8-resource-profile-*.json\`, \`.release-evidence/v8-load-*.json\` ve insan okunur \`docs/production-readiness/resource-sizing-v8.md\` içinde candidate digest ile bağla.

## Üretilecek teslimatlar

1. Uygulama ve test değişiklikleri.
2. Güncellenmiş generatorlar ve yeniden üretilmiş \`FEATURE_INVENTORY.json/.md\`, \`PRODUCTION_SALES_GAPS.json/.md\`, \`READINESS_BACKLOG.json\`.
3. \`docs/production-readiness/2026-09-13-customer-candidate-v8.md\`: karar, değişiklikler, bütün komut/exit code/test sayıları, coverage, açık sınırlar, kaynak ölçümü ve candidate digest.
4. Güncel \`first-customer-sales-packet-v8.md\`, destek/incident/runbook bağlantıları ve market capability delta.
5. Benzersiz v8 release-output, portable customer kit ve outer envelope. Resmi key yoksa imzasız olduğu açıkça yazılmalı.
6. Makine okunur evidence index: her gate için komut, start/end UTC, exit code, log hash'i, candidate digest, status ve limitation.

## Bitiş ve raporlama biçimi

Şu koşul sağlanana kadar durma: bütün yerel olarak uygulanabilir değişiklikler tamamlanmış, ilgili testler geçmiş, generated kayıtlar güncel, package/kit doğrulanmış ve kalan her iş yalnız gerçek dış bağımlılık veya açıkça belgelenmiş ürün sınırı haline gelmiş olmalı.

Bir tur sonunda yerel OPEN/partial/backlog kaldıysa final cevap yazıp görevi bitirme; yeniden en yüksek öncelikli kayda dön. Yalnız bütün bağımsız işler tamamlandığında veya ilerleme için gerçekten kullanıcıdan alınması gereken tekil dış girdiler kaldığında final rapor üret. Dış girdiler kaldığında bile her biri için çalıştırılabilir preflight, exact input listesi, owner, runbook, evidence template ve kabul komutu hazır olmalıdır.

Finalden hemen önce \`git status --short\`, recursive submodule status, staged diff, son atomik commitler ve candidate digest'i kaydet. Kendi ürettiğin geçici dosyaları ürün ağacında bırakma. Kullanıcı değişikliklerini, özellikle dirty submodule içeriğini, temiz çalışma ağacı elde etmek amacıyla silme.

Final cevapta şu sırayı kullan:

1. Karar: LOCAL_ENGINEERING_READY veya NO-GO; production/sales GO yalnız bütün zorunlu dış kapılar gerçekten kapalıysa.
2. Kapatılan task/backlog/feature ID'leri ve önemli dosyalar.
3. Yerel doğrulama: tam komut, exit code, test/coverage/package/artefakt sayıları.
4. Fail-closed native/E2E/claim-gate sonuçları ve tam nedenleri.
5. Kalan işler: ID, owner, gerekli gerçek girdi, kabul kanıtı. Yüzde veya genel “hazır” ifadesi kullanma.
6. Customer kit, release inventory ve evidence index yolları/digestleri.
7. Kaynak tüketimi: measured ve estimated değerleri ayrı tabloyla ver.

Başarı ölçütü daha çok dosya değiştirmek değil; satılan davranışın gerçek consumer'da çalışması, hatada güvenli kalması ve her iddianın doğru kanıt sınırıyla raporlanmasıdır.
`;

writeFileSync(output, `${header}${featureSection}${taskHeader}${taskSection}${backlogHeader}${backlogSection}${externalHeader}${externalSection}${footer}`, "utf8");
console.log(`Wrote ${output}: ${incompleteFeatures.length} incomplete features, ${gapRegistry.engineering_and_operations.length} technical tasks, ${unresolvedBacklog.length} backlog findings, ${gapRegistry.commercial_and_external.length} external gates.`);

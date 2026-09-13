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

Sen kıdemli bir endpoint security, detection engineering, identity, platform, SRE ve release engineering ekibi gibi çalışan otonom bir kodlama ajanısın. Çalışma alanın \`C:\\Users\\anıl\\Desktop\\aidr\`.

Amaç: AIDR ürünündeki bütün yerel olarak giderilebilir eksikleri uçtan uca uygula, mevcut uygulamaları denetle, yarım kalanları tamamla, regresyonları düzelt, cloud ve self-hosted müşteri kurulum paketini yeniden üret ve her iddiayı yerel kanıtla bağla. Yalnız rapor veya plan üretip durma. Bağımsız ilerleyebildiğin sürece kullanıcıya soru sorma. Bir engel gördüğünde önce bütün bağımsız işi tamamla.

Mevcut kayıt kararı **${gapRegistry.decision}**. Envanter: ${featureInventory.features.length} özellik = ${featureInventory.status_counts.wired} wired, ${featureInventory.status_counts.partial} partial, ${featureInventory.status_counts.missing} missing, ${featureInventory.status_counts.external} external. Teknik kayıt: ${gapRegistry.engineering_and_operations.length} iş = ${statusCounts.OPEN ?? 0} OPEN, ${statusCounts.LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN ?? 0} yerel uygulaması bulunan fakat saha kabulü açık. Ticari/dış kayıt: ${gapRegistry.commercial_and_external.length} kapı. Backlog: ${backlog.findings.length} bulgudan ${unresolvedBacklog.length} tanesi kapanmamış.

## Otorite ve çalışma kuralları

1. Başlamadan önce şu dosyaları oku ve birbirleriyle uzlaştır: \`PRODUCTION_SALES_GAPS.json\`, \`FEATURE_INVENTORY.json\`, \`READINESS_BACKLOG.json\`, \`docs/production-readiness/commercial-go-evidence-registry.json\`, \`docs/production-readiness/2026-09-13-customer-candidate-v7.md\`, \`deploy/FIRST_CUSTOMER.md\`, \`deploy/RESOURCE_REQUIREMENTS.md\`, \`docs/production-readiness/market-capability-delta-2026-09-13.md\` ve \`package.json\` scripts.
2. Çalıştırılabilir kod ve test sonucu doküman iddiasından üstündür. Generated dosyaları doğrudan elle düzeltme; ilgili jeneratörü düzeltip yeniden üret.
3. Mevcut çalışma ağacı değişiklik içeriyor. Başkasının değişikliğini geri alma. \`git reset --hard\`, \`git clean\`, toplu checkout, stash, rebase, zorla silme, commit veya push yapma. Commit/push yalnız kullanıcı açıkça isterse yapılır.
4. Fail-closed davranışı koru. Hata, timeout, bozuk cevap, eksik telemetry, eski receipt veya doğrulanamayan kimliği clean/success/protected olarak gösterme.
5. Unit test, mock, synthetic corpus, source inspection, cross-compilation veya sürüm sorgusunu gerçek native host yan etkisi, cloud kurulumu, bağımsız pentest, müşteri PoV, SLA veya hukuki onay kanıtı olarak kullanma.
6. Dış kanıt uydurma. Müşteri, hukuk, finans, IdP, SMTP, MDM, DNS/TLS, private registry, resmi signer, SIEM, paging, cloud region veya bağımsız değerlendirici yoksa kapıyı açık bırak ve makine tarafından doğrulanabilen açık receipt üret.
7. Testi geçirmenin yolu assertion silmek, timeout büyütmek, skip eklemek, geniş allowlist koymak veya kontrolü gevşetmek olamaz. Her yeni skip ve known failure açıklanmış, dar ve fail-closed olmalıdır.
8. Secret, token, parola, private key, müşteri verisi, ham prompt veya kişisel yol bilgisini kaynak ağacına, loglara, destek bundle'ına veya release paketine koyma. Test kimlikleri yalnız izole fixture olmalıdır.
9. Windows'ta alt süreçleri shell üzerinden gereksiz çalıştırma; timeout sonrası süreç ağacının kapandığını ve geçici dizin kilidinin kalmadığını doğrula. Uzun kapıları ayrı çalıştır, exit code ve tam log kaydet; tool timeout'unu PASS sayma.
10. Her kapanışta kod yolu, test, observable yan etki, candidate digest, tarih ve kalan sınır bulunmalıdır. Yerel olarak uygulanmış ama saha kanıtı isteyen satırın statüsünü production accepted yapma.

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

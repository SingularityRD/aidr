# AIDR v8 uçtan uca kapatma ve yerel doğrulama promptu

Bu dosyanın tamamını başka kodlama ajanına tek prompt olarak ver. Ajan repo kökünde çalışmalı, yalnız plan yazıp durmamalı ve aşağıdaki kanıt sınırlarını korumalıdır.

---

Sen kıdemli bir endpoint security, detection engineering, identity, platform, SRE ve release engineering ekibi gibi çalışan otonom bir kodlama ajanısın. Çalışma alanın repo kökü `<repo-root>` (bu promptun bulunduğu checkout).

Amaç: AIDR ürünündeki bütün yerel olarak giderilebilir eksikleri uçtan uca uygula, mevcut uygulamaları denetle, yarım kalanları tamamla, regresyonları düzelt, cloud ve self-hosted müşteri kurulum paketini yeniden üret ve her iddiayı yerel kanıtla bağla. Yalnız rapor veya plan üretip durma. Bağımsız ilerleyebildiğin sürece kullanıcıya soru sorma. Bir engel gördüğünde önce bütün bağımsız işi tamamla.

Mevcut kayıt kararı **NO-GO**. Envanter: 71 özellik = 41 wired, 28 partial, 0 missing, 2 external. Teknik kayıt: 46 iş = 1 OPEN, 45 yerel uygulaması bulunan fakat saha kabulü açık. Ticari/dış kayıt: 13 kapı. Backlog: 68 bulgudan 7 tanesi kapanmamış.

## Kesin görev ve tamamlanma sözleşmesi

Bu görev bir audit veya öneri görevi değildir. Kodla, test et, gerçek consumer'a bağla, paketle, ölç, kanıtla ve yalnız sonra durumu güncelle. İlk başarısız testte, ilk engelde, token veya süre baskısında ya da kısmi ilerleme raporundan sonra işi bırakma. Aynı oturumda ilerleyemiyorsan devam edilebilir checkpoint bırak; sonraki çalışmada kaldığın yerden başla. Kullanıcı açıkça durdurmadıkça aşağıdaki kapanış döngüsünü bütün yerel işler bitene kadar sürdür.

Durumları birbirine karıştırma:

- **LOCAL_ENGINEERING_READY**: bütün yerel uygulanabilir boşluklar kapalı; hedefli ve tam testler geçiyor; generated kayıtlar deterministik; paket doğrulanıyor. Dış kapılar açık olabilir.
- **RELEASE_CANDIDATE_READY**: LOCAL_ENGINEERING_READY koşullarına ek olarak exact candidate digest, temiz kaynak snapshot'ı, SBOM/provenance, kurulum/upgrade/rollback/restore doğrulaması ve imzalama politikası kanıtlıdır.
- **PRODUCTION_SALES_GO**: RELEASE_CANDIDATE_READY koşullarına ek olarak bu candidate için bütün zorunlu native host, cloud/self-hosted, müşteri, güvenlik, hukuk, finans, SLA ve operasyon kapıları isimli yetkililerce kabul edilmiştir.
- Bu seviyelerden biri karşılanmıyorsa karar **NO-GO** kalır. Yüzde hazır, neredeyse hazır, production-grade veya satışa hazır gibi ara ifadeler kullanma.

Bitmiş sayılmak için aynı anda şunlar doğru olmalıdır:

1. Envanterde yerel olarak düzeltilebilir `missing` veya `partial` neden kalmamış ya da kalan neden doğrulanmış dış bağımlılık olarak yeniden sınıflandırılmıştır.
2. T01-T46 ve açık backlog kayıtlarının her biri kod, observable davranış, test ve evidence ile kapanmış veya gerçek dış girdiye bağlanmıştır.
3. Advertise edilen her connector, OS, response action ve deployment profili gerçek consumer yolunda doğrulanmıştır; doğrulanmayan yüzey açıkça unsupported/NO-GO gösterilir.
4. Cloud ve self-hosted teslimatları temiz makinede kurulum, sağlık, yükseltme, geri dönüş, yedekleme, restore ve kaldırma akışlarına sahiptir.
5. Bütün zorunlu yerel kapılar aynı commit ve aynı candidate digest üzerinde tekrar geçmiştir; eski run kanıtı yeni candidate için kullanılmamıştır.
6. Kalan tek işler gerçekten kullanıcı/kurum credential'ı, fiziksel/VM host, vendor hesabı, müşteri kabulü veya yetkili dış onay gerektirir; her biri owner, input, komut/runbook ve kabul artefaktıyla kayıtlıdır.

## Otorite ve çalışma kuralları

1. Başlamadan önce şu dosyaları oku ve birbirleriyle uzlaştır: `PRODUCTION_SALES_GAPS.json`, `FEATURE_INVENTORY.json`, `READINESS_BACKLOG.json`, `docs/production-readiness/commercial-go-evidence-registry.json`, `docs/production-readiness/2026-09-13-customer-candidate-v7.md`, `deploy/FIRST_CUSTOMER.md`, `deploy/RESOURCE_REQUIREMENTS.md`, `docs/production-readiness/market-capability-delta-2026-09-13.md` ve `package.json` scripts.
2. Çalıştırılabilir kod ve test sonucu doküman iddiasından üstündür. Generated dosyaları doğrudan elle düzeltme; ilgili jeneratörü düzeltip yeniden üret.
3. Çalışma ağacını ve bütün submodule'leri başlamadan kaydet. Başkasının değişikliğini geri alma. `git reset --hard`, `git clean`, toplu checkout, stash, rebase veya zorla silme yapma. Kullanıcı bu çalışma için atomik commitlere açıkça izin verdi: her doğrulanmış, tek amaçlı workstreami atomik commit et; ilgisiz/kirli dosyaları dahil etme. Push, merge, tag veya release publish için ayrıca açık yetki gerekir.
4. Fail-closed davranışı koru. Hata, timeout, bozuk cevap, eksik telemetry, eski receipt veya doğrulanamayan kimliği clean/success/protected olarak gösterme.
5. Unit test, mock, synthetic corpus, source inspection, cross-compilation veya sürüm sorgusunu gerçek native host yan etkisi, cloud kurulumu, bağımsız pentest, müşteri PoV, SLA veya hukuki onay kanıtı olarak kullanma.
6. Dış kanıt uydurma. Müşteri, hukuk, finans, IdP, SMTP, MDM, DNS/TLS, private registry, resmi signer, SIEM, paging, cloud region veya bağımsız değerlendirici yoksa kapıyı açık bırak ve makine tarafından doğrulanabilen açık receipt üret.
7. Testi geçirmenin yolu assertion silmek, timeout büyütmek, skip eklemek, geniş allowlist koymak veya kontrolü gevşetmek olamaz. Her yeni skip ve known failure açıklanmış, dar ve fail-closed olmalıdır.
8. Secret, token, parola, private key, müşteri verisi, ham prompt veya kişisel yol bilgisini kaynak ağacına, loglara, destek bundle'ına veya release paketine koyma. Test kimlikleri yalnız izole fixture olmalıdır.
9. Windows'ta alt süreçleri shell üzerinden gereksiz çalıştırma; timeout sonrası süreç ağacının kapandığını ve geçici dizin kilidinin kalmadığını doğrula. Uzun kapıları ayrı çalıştır, exit code ve tam log kaydet; tool timeout'unu PASS sayma.
10. Her kapanışta kod yolu, test, observable yan etki, candidate digest, tarih ve kalan sınır bulunmalıdır. Yerel olarak uygulanmış ama saha kanıtı isteyen satırın statüsünü production accepted yapma.
11. `vendor/ai-infra-guard` superproject işaretçisi v4.6.1'e bağlıdır. Alt çalışma ağacındaki önceden var olan commitlenmemiş dosyaları kaydet, sahipliğini doğrulamadan geri alma veya commit etme; derleme ve evidence'in tam olarak hangi submodule HEAD ve dirty-state üzerinde üretildiğini yaz.
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
9. **Review and commit:** `git diff --check`, secret taraması ve staged path denetimi yap. Yalnız bu workstreamin dosyalarını atomik commit et; commit mesajı gerçekleşen davranışı anlatsın.
10. **Reconcile:** Feature/task/backlog/external registry sayılarını yeniden üret. Yerel açık iş kaldıysa en yüksek öncelikli kayda dön ve döngüyü tekrarla.

Uzun test tool timeout'una çarparsa onu PASS veya product failure sayma. Ayrı process olarak çalıştır, PID/log/başlangıç zamanını kaydet, 60 saniyeyi aşmayan aralıklarla izle, gerçek exit code'u al ve orphan process bırakma.

## Her özellik için Definition of Done

Bir özelliği `wired` veya kapalı saymadan önce uygulanabilir bütün maddeleri kanıtla:

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

- `git status --short`, `git rev-parse HEAD`, Node/pnpm/Python/Docker/OS sürümlerini kaydet.
- Generatorları çalıştır; değişiklik oluşturuyorsa nedeni incele. Başlangıç hash'lerini ve açık task/feature/backlog sayılarını v8 evidence JSON'una yaz.
- Mevcut v7 release ve kit klasörlerini değiştirme. Her yeni çıktı için benzersiz `.release-evidence/v8-*` yolu kullan.

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

- **DET-06 — Prompt injection inspection (partial)**
  - Alan: Detection
  - Mevcut: Bounded pre-model tool-result inspection in OpenCode, VS Code and SDK; Claude/Cursor/OpenClaw use host-specific later boundaries
  - Kalan: Claude PostToolUse and OpenClaw after_tool_call cannot prove same-turn model blocking; provider streams and native host bypass need acceptance
  - Kaynak: packages/core/src/output-scanner.ts, packages/claude-code/src/output-inspection.ts, packages/extension/src/output-inspection.ts, packages/opencode/src/output-handler.ts, packages/openclaw/src/output-inspection.ts, packages/sdk/src/output-guard.ts
- **DET-07 — Structured DLP and PII (partial)**
  - Alan: Detection
  - Mevcut: Tenant labels, rules, owner-bound exceptions, redact/ask/block and signed tenant bundle verification
  - Kalan: Other connectors, trusted provisioning operations and customer label acceptance remain open
  - Kaynak: packages/core/src/dlp/scanner.ts, packages/core/src/dlp/policy.ts, packages/claude-code/src/detector-provisioning.ts
- **DET-08 — Behavioral and novelty analysis (partial)**
  - Alan: Detection
  - Mevcut: Cold start and bounded orchestrator configuration
  - Kalan: Claude one-shot hook has no persistent learning baseline; other connector and customer efficacy acceptance remain open
  - Kaynak: packages/core/src/behavioral-orchestrator.ts, packages/core/src/behavioral-analyzer.ts, packages/claude-code/src/detector-provisioning.ts
- **DET-09 — ML classification and similarity (partial)**
  - Alan: Detection
  - Mevcut: Versioned local model leg with unavailable state
  - Kalan: No independently validated production model efficacy or broad runtime adoption
  - Kaynak: packages/core/src/behavioral-orchestrator.ts, packages/core/src/ml-model.ts, packages/core/src/ml/similarity.ts
- **DET-10 — URL reputation (partial)**
  - Alan: Detection
  - Mevcut: Remote verdict lookup and unavailable state
  - Kalan: Provider feed, operational freshness and customer latency proof still required
  - Kaynak: packages/core/src/clients/url-check.ts, supabase/functions/url-check/index.ts
- **DET-11 — File reputation and AMSI (partial)**
  - Alan: Detection
  - Mevcut: File hash lookup and Windows antimalware integration
  - Kalan: AMSI requires native Windows host acceptance; no clean verdict on unavailable leg
  - Kaynak: packages/core/src/clients/file-check.ts, packages/core/src/clients/amsi.ts
- **DET-12 — Package and plugin supply chain (partial)**
  - Alan: Detection
  - Mevcut: OpenCode aliases and package-check exceptions now surface ask/unavailable instead of false-clean
  - Kalan: Registry/provider provenance and customer dependency corpus still need acceptance
  - Kaynak: packages/core/src/package-checker.ts, packages/core/src/plugin-scanner.ts, packages/core/src/evaluator.ts, packages/core/src/tool-normalization.ts
- **MCP-05 — Tool description attestation and drift (partial)**
  - Alan: MCP
  - Mevcut: Ed25519 tool manifest, signer allowlist, replay/drift quarantine and out-of-band approval
  - Kalan: Host/gateway consumer and trusted publisher provisioning remain open
  - Kaynak: packages/core/src/mcp-attestation.ts
- **MCP-06 — Identity graph and delegated privileges (partial)**
  - Alan: MCP
  - Mevcut: Bounded signed lineage, grant, introspection and revocation
  - Kalan: Real identity-provider and tool-provider integration remains external
  - Kaynak: packages/core/src/delegated-credential.ts, supabase/functions/delegated-credentials/index.ts
- **MCP-07 — MCP gateway response blocking (partial)**
  - Alan: MCP
  - Mevcut: Signed tool approval, tenant-bound auth, initialized notifications, DNS pinning and bounded inline output inspection
  - Kalan: Binary output, server-initiated requests, forced routing of direct upstream access and customer native acceptance remain open
  - Kaynak: packages/mcp-gateway/src/gateway.mjs, packages/mcp-gateway/src/stdio.mjs, packages/core/src/mcp-transport.ts
- **INF-03 — Continuous fleet discovery (partial)**
  - Alan: AI infrastructure
  - Mevcut: Authenticated operator or collector upload, sequenced cycles, dedup and stale/partial coverage reporting
  - Kalan: Cloud/MDM adapters, scheduler, dashboard alerts and customer field acceptance remain open
  - Kaynak: packages/cli/src/commands/collect.ts, supabase/functions/discovery/index.ts
- **RSP-04 — Process containment (partial)**
  - Alan: Response
  - Mevcut: Targeted process response with platform limits
  - Kalan: No enterprise endpoint isolation or universal process authority
  - Kaynak: packages/core/src/contain.ts, packages/core/src/response-actions.ts
- **RSP-06 — Fleet kill switch and credential revoke (partial)**
  - Alan: Response
  - Mevcut: Signed entitlement, operator-authorized fleet queue, bounded receipt consumer and restart-safe journal worker library
  - Kalan: No installed endpoint service, verified OS isolation adapter, device attestation or cross-provider credential revocation
  - Kaynak: supabase/functions/revocations/index.ts, packages/core/src/response-command-consumer-v6.ts, packages/core/src/response-command-worker-v6.ts
- **RSP-07 — SOAR playbook orchestration (partial)**
  - Alan: Response
  - Mevcut: External runtime bridge
  - Kalan: Customer authorization, connector matrix and success receipts need field integration
  - Kaynak: supabase/functions/autosecops-runtime/index.ts
- **CLI-04 — Enterprise fleet rollout (partial)**
  - Alan: Endpoint
  - Mevcut: Install, detect, upgrade, rollback, uninstall and health with signed artifact checks
  - Kalan: Actual Intune/SCCM/Jamf execution and publisher signing acceptance remain external
  - Kaynak: deploy/fleet/windows/README.md, deploy/fleet/linux/README.md, deploy/fleet/macos/README.md
- **CON-05 — Codex (partial)**
  - Alan: Connectors
  - Mevcut: Built connector and policy decisions
  - Kalan: Host can fail open when hook execution is unavailable; not tamper-resistant isolation
  - Kaynak: packages/codex/src/enforcement.ts, packages/codex/src/cli.ts
- **TEN-04 — SSO and directory group sync (partial)**
  - Alan: Management
  - Mevcut: Tenant token rotation, Users/Groups and immutable external-ID role mapping
  - Kalan: Real Entra/Okta configuration and tenant-wide MFA enforcement remain external/partial
  - Kaynak: supabase/functions/scim/index.ts, supabase/migrations/20260912000012_scim_directory.sql, packages/dashboard/src/enterprise/auth.tsx
- **TEN-05 — Device pairing and enrollment (partial)**
  - Alan: Management
  - Mevcut: Atomic single-use exchanges, signed entitlements, active tenant validation and spoof-resistant device-start limiter; isolated loopback HTTP smoke passed
  - Kalan: Customer TLS proxy routing and browser-to-host pairing acceptance remain pending; direct unsigned device-start is rejected
  - Kaynak: supabase/functions/device-poll/index.ts, supabase/functions/enroll/index.ts, deploy/ingress/device-start.mjs
- **OBS-04 — SIEM export and OpenTelemetry (partial)**
  - Alan: Operations
  - Mevcut: Splunk, Sentinel, Elastic and HTTPS delivery queue/receipts/retry
  - Kalan: Customer SIEM configuration, scheduled worker, native source coverage and delivery receipt remain open
  - Kaynak: packages/core/src/siem-delivery.ts, packages/core/src/siem-incident-producer.ts, scripts/siem-delivery-worker.mjs
- **OBS-06 — Retention and deletion (partial)**
  - Alan: Operations
  - Mevcut: Legal hold, bounded deletion phases and durable receipts across live data
  - Kalan: External backups and customer retention/offboarding acceptance remain outside live-data receipts
  - Kaynak: supabase/migrations/20260912140000_tenant_offboarding_retention.sql, scripts/deployment-offboarding.mjs
- **BIL-01 — Invoice-based sales model (partial)**
  - Alan: Commercial
  - Mevcut: Idempotent pending Finance request; no payment or entitlement grant
  - Kalan: Approved quote, provider receipt, reconciliation and audited paid-to-entitlement lifecycle remain open
  - Kaynak: packages/dashboard/src/ui/pages/BillingPage.tsx, supabase/functions/invoice-entitlement/index.ts, docs/billing.md
- **BIL-02 — Stripe checkout and event processing (partial)**
  - Alan: Commercial
  - Mevcut: Authenticated checkout, trusted pricing, tenant metadata, signed replay-protected webhooks
  - Kalan: Live keys/prices/webhook registration, refund/cancel/reconcile and tax acceptance remain open
  - Kaynak: supabase/functions/billing-checkout/index.ts, supabase/functions/stripe-webhook/index.ts
- **BIL-03 — Subscription self-service portal (partial)**
  - Alan: Commercial
  - Mevcut: Server-resolved tenant/customer identity, provider-of-record settlement state machine, seat grant/revoke reconciliation, cancel/refund with idempotency and TTL, portal return-URL allowlist
  - Kalan: Live provider keys, approved price/SKU catalogue, finance reconciliation and accounting approval remain external
  - Kaynak: packages/dashboard/src/billing/billing-portal.ts, packages/dashboard/src/ui/pages/BillingPage.tsx, supabase/functions/billing-portal/index.ts, supabase/functions/billing-portal/settlement.ts, supabase/functions/billing-portal/provider.ts, supabase/migrations/20260913000004_billing_settlement_portal.sql
- **DEP-02 — Cloud preparation (partial)**
  - Alan: Deployment
  - Mevcut: Same app/functions/migrations, supplied managed Supabase project
  - Kalan: Live project provisioning, per-region deployment, OAuth/SMTP and secrets installation remain external
  - Kaynak: scripts/deployment-prepare.mjs
- **DEP-05 — Authenticated signed release delivery (partial)**
  - Alan: Deployment
  - Mevcut: Exact artifact Ed25519 signature and anti-rollback state
  - Kalan: Approved publisher key custody and private registry publication remain external
  - Kaynak: scripts/release-sign.mjs, scripts/release-verify.mjs, .github/scripts/build-release-bundle.mjs
- **DEP-06 — Backup, restore and disaster recovery (partial)**
  - Alan: Deployment
  - Mevcut: Encrypted backup, remote staged commit, reread, local isolated recovery and content verification; local Windows recovery ACL probe passed
  - Kalan: Real offsite provider, independent-host recovery and agreed RPO/RTO evidence remain open
  - Kaynak: scripts/deployment-backup.mjs, scripts/deployment-backup-offsite.mjs, scripts/deployment-restore-drill.mjs
- **DEP-07 — Availability and scale (partial)**
  - Alan: Deployment
  - Mevcut: Seven fail-closed readiness legs, SLI instrumentation, generator-lag and failure-class diagnostics; v6 loopback /healthz 10 RPS for 30 seconds passed
  - Kalan: Authenticated workload, HA, capacity, noisy-neighbor and monthly SLI remain unproved
  - Kaynak: deploy/dashboard/monitoring.mjs, scripts/load-test.mjs, deploy/ha/README.md
- **EVAL-01 — Independent attack and benign benchmarks (partial)**
  - Alan: Assurance
  - Mevcut: Known attack/benign and configuration regression scenarios
  - Kalan: Blind holdout corpus, customer benign tasks, latency and evasion evaluation remain open
  - Kaynak: scripts/verify-enforcement.mjs, scripts/verify-codex-hook.mjs
- **EVAL-02 — Legal, privacy, residency and support (external)**
  - Alan: Assurance
  - Mevcut: Thirteen required evidence gates tracked
  - Kalan: Named external approvals and candidate-bound proof cannot be generated from source code
  - Kaynak: docs/production-readiness/commercial-go-evidence-registry.json
- **EVAL-03 — Customer proof of value (external)**
  - Alan: Assurance
  - Mevcut: Charter and evidence requirements exist
  - Kalan: Customer-run host matrix, observations and signed acceptance outstanding
  - Kaynak: docs/production-readiness/commercial-go-evidence-registry.json

### Faz 3 — T01-T46 eksiksiz teknik/operasyon matrisi

Hiçbir satırı atlama. Her satır için: (a) mevcut uygulamayı yeniden üret, (b) yerel boşluğu düzelt, (c) hedefli positive/negative/fault testleri çalıştır, (d) saha/dış bağımlılığı ayrı yaz, (e) registry generatorını güncelle.

#### T01 — GerÃƒÂ§ek host ve iÃ…Å¸letim sistemi kapsamÃ„Â± [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: CON-01, CON-02, CON-03, CON-04, CON-05, CON-06, DET-01, DET-02, DET-03, DET-04, DET-05, RSP-01
- Kaynak: scripts/run-e2e-release.mjs, packages/codex/README.md
- Güncel yerel durum: deploy/native/support-matrix.json satilan connector/OS/arch/context/interception matrisini ve bilinen bypass/unobserved listesini tanimliyor; deploy/native/run-support-matrix.mjs kurulu olmayan hostu HOST_UNAVAILABLE olarak NO-GO uretiyor, gercek host ve isimli kabul acik.
- Başlangıç riski: Kanca kararÃ„Â± hostun eylemi durdurduÃ„Å¸unu tek baÃ…Å¸Ã„Â±na kanÃ„Â±tlamaz. Devre dÃ„Â±Ã…Å¸Ã„Â± eklenti, sÃƒÂ¼reÃƒÂ§ ÃƒÂ§ÃƒÂ¶kmesi, timeout ve yeni host sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼ kapsam dÃ„Â±Ã…Å¸Ã„Â±nda kalabilir.
- Tamamlama hedefi: SatÃ„Â±lacak her baÃ„Å¸layÃ„Â±cÃ„Â± iÃƒÂ§in OS/sÃƒÂ¼rÃƒÂ¼m destek tablosu, gerÃƒÂ§ek host testi, kurulum/kaldÃ„Â±rma ve destek sahibi belirle; gÃƒÂ¶rÃƒÂ¼nmeyen eylemleri aÃƒÂ§Ã„Â±kÃƒÂ§a listele.
- Zorunlu kapanış testi: Her zorunlu saldÃ„Â±rÃ„Â±da yan etkinin oluÃ…Å¸madÃ„Â±Ã„Å¸Ã„Â±nÃ„Â± baÃ„Å¸Ã„Â±msÃ„Â±z kaydet; zararsÃ„Â±z iÃ…Å¸lemler geÃƒÂ§sin; kanca kapalÃ„Â±/bozuk/aÃ„Å¸sÃ„Â±z durumlarÃ„Â± ve yeniden baÃ…Å¸latma ayrÃ„Â± sÃ„Â±nansÃ„Â±n.
- Dış bağımlılık/sınır: MÃƒÂ¼Ã…Å¸teri test cihazlarÃ„Â±, runtime eriÃ…Å¸imi ve sÃƒÂ¼rÃƒÂ¼m seÃƒÂ§imi

#### T02 — BaÃ„Å¸layÃ„Â±cÃ„Â±lar arasÃ„Â±nda araÃƒÂ§ adÃ„Â± ve girdi normalizasyonu [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DET-12, DET-11, CON-04
- Kaynak: packages/core/src/evaluator.ts, packages/opencode/src/tool-handler.ts, packages/opencode/src/__tests__/aidr-contract.test.ts
- Güncel yerel durum: Ortak araÃƒÂ§/girdi normalizasyonu evaluator ÃƒÂ¶ncesinde; Codex ve OpenClaw boÃ…Å¸-artifact erken izin yolu kaldÃ„Â±rÃ„Â±ldÃ„Â±, named MCP ÃƒÂ§aÃ„Å¸rÃ„Â±larÃ„Â± politikaya ulaÃ…Å¸Ã„Â±yor.
- Başlangıç riski: Paket kurulumlarÃ„Â± ve bazÃ„Â± dosya/AMSI girdileri ilgili denetim koluna ulaÃ…Å¸mayabilir; birim testlerin yeÃ…Å¸il olmasÃ„Â± bu kapsamÃ„Â± kapatmÃ„Â±yor.
- Tamamlama hedefi: Ortak semantik araÃƒÂ§/girdi sÃƒÂ¶zleÃ…Å¸mesi tanÃ„Â±mla; tÃƒÂ¼m baÃ„Å¸layÃ„Â±cÃ„Â±larÃ„Â± eÃ…Å¸le; command, file_path/filePath, content/new_string alanlarÃ„Â±nÃ„Â± standartlaÃ…Å¸tÃ„Â±r. Bilinen boÃ…Å¸luÃ„Å¸u beklenen izin sonucu olarak sabitleyen testi deÃ„Å¸iÃ…Å¸tir.
- Zorunlu kapanış testi: AynÃ„Â± yasak paket, manifest ve dosya girdisi tÃƒÂ¼m baÃ„Å¸layÃ„Â±cÃ„Â±larda aynÃ„Â± denetime ulaÃ…Å¸sÃ„Â±n; denetleyici ÃƒÂ§aÃ„Å¸rÃ„Â±sÃ„Â± ve engellenen yan etki kanÃ„Â±tlansÃ„Â±n; boÃ…Å¸/alternatif alan adlarÃ„Â± negatif test edilsin.
- Dış bağımlılık/sınır: AIDR-060; native host matrisi

#### T03 — Paket denetiminde hatanÃ„Â±n sessiz kaybolmasÃ„Â± [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DET-10, DET-11, DET-12
- Kaynak: packages/core/src/evaluator.ts, packages/core/src/package-checker.ts
- Güncel yerel durum: Paket, registry ve file-reputation hata/bozuk-200 yollarÃ„Â± clean yerine unknown/unavailable ÃƒÂ¼retiyor; gerÃƒÂ§ek 404 ve doÃ„Å¸rulanmÃ„Â±Ã…Å¸ clean ayrÃ„Â±mÃ„Â± test edildi.
- Başlangıç riski: Paket denetleyicisi beklenmedik hata verdiÃ„Å¸inde ÃƒÂ¼st akÃ„Â±Ã…Å¸ baÃ…Å¸arÃ„Â±lÃ„Â± bir boÃ…Å¸ kontrol gibi devam edebilir; diÃ„Å¸er kurallar her vakayÃ„Â± yakalamaz.
- Tamamlama hedefi: Hata tÃƒÂ¼rlerini unavailable olarak taÃ…Å¸Ã„Â±; zorunlu denetim politikasÃ„Â±nda deny/insan onayÃ„Â± ÃƒÂ¼ret; opsiyonel kolda gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r eksik tespit kaydÃ„Â± tut. HatalÃ„Â± politika/cache/intel durumlarÃ„Â±nÃ„Â± ayÃ„Â±r.
- Zorunlu kapanış testi: Registry timeout, bozuk cevap, cache/intel ayrÃ„Â±Ã…Å¸tÃ„Â±rma hatasÃ„Â± ve denetleyici exception enjekte et; zorunlu kontrol sessiz allow ÃƒÂ¼retmesin; benign ve iptal davranÃ„Â±Ã…Å¸larÃ„Â± korunsun.
- Dış bağımlılık/sınır: AIDR-061; desteklenen araÃƒÂ§ sÃƒÂ¶zleÃ…Å¸mesi

#### T04 — Model tÃƒÂ¼ketiminden ÃƒÂ¶nce ÃƒÂ§Ã„Â±ktÃ„Â± denetimi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DET-06, DET-07, MCP-07, CON-01, CON-02, CON-03, CON-04, CON-05, CON-06
- Kaynak: packages/claude-code/src/output-inspection.ts, packages/claude-code/src/post-tool-use.ts, packages/core/src/output-scanner.ts
- Güncel yerel durum: Ãƒâ€¡Ã„Â±ktÃ„Â± tarayÃ„Â±cÃ„Â± 2 MiB UTF-8, 3000 ms best-effort ve 128 bulgu sÃ„Â±nÃ„Â±rÃ„Â±nda inspection_incomplete/critical fail-closed ÃƒÂ¼retiyor; JSON/Unicode ve sÃ„Â±nÃ„Â±r payloadlarÃ„Â± test edildi. Her hostta aynÃ„Â±-tur blok kanÃ„Â±tÃ„Â± yok.
- Başlangıç riski: Prompt injection veya sÃ„Â±r iÃƒÂ§eren ÃƒÂ§Ã„Â±ktÃ„Â± modele ulaÃ…Å¸abilir. Ã„Â°lk 262144 karakterden sonraki iÃƒÂ§erik ve desteklenmeyen biÃƒÂ§imler iÃƒÂ§in kapsam eksiktir.
- Tamamlama hedefi: Hostun izin verdiÃ„Å¸i yerlerde ÃƒÂ§Ã„Â±ktÃ„Â± tesliminden ÃƒÂ¶nce kontrol/karantina ekle; desteklenmeyen yollarda aÃƒÂ§Ã„Â±k coverage durumu gÃƒÂ¶ster; boyut sÃ„Â±nÃ„Â±rÃ„Â± aÃ…Å¸Ã„Â±mÃ„Â±nÃ„Â± sessiz temiz sayma.
- Zorunlu kapanış testi: ParÃƒÂ§alara bÃƒÂ¶lÃƒÂ¼nmÃƒÂ¼Ã…Å¸ saldÃ„Â±rÃ„Â±, sÃ„Â±nÃ„Â±rÃ„Â±n sonundaki payload, Unicode, JSON/text ve ÃƒÂ§ok bÃƒÂ¼yÃƒÂ¼k cevaplar sÃ„Â±nansÃ„Â±n; engellenen baytlar modele ulaÃ…Å¸masÃ„Â±n; zararsÃ„Â±z ÃƒÂ§ok parÃƒÂ§alÃ„Â± cevap bozulmasÃ„Â±n.
- Dış bağımlılık/sınır: Host API kabiliyeti; MCP gateway

#### T05 — DavranÃ„Â±Ã…Å¸, novelty ve ML kararlarÃ„Â±nÃ„Â±n ÃƒÂ¼rÃƒÂ¼n akÃ„Â±Ã…Å¸Ã„Â±na baÃ„Å¸lanmasÃ„Â± [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DET-08, DET-09
- Kaynak: packages/core/src/behavioral-analyzer.ts, packages/core/src/novelty-detection.ts, packages/core/src/ml-model.ts
- Güncel yerel durum: BehavioralAnalyzer adayÃ„Â± kendi baseline'Ã„Â±na katmÃ„Â±yor ve tenant/session ayrÃ„Â±mÃ„Â± korunuyor; ÃƒÂ¼retim etkinliÃ„Å¸i ve kalÃ„Â±cÃ„Â± ÃƒÂ¶Ã„Å¸renme kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Ã„Â°hracat edilen sÃ„Â±nÃ„Â±f veya demo skor, ÃƒÂ§alÃ„Â±Ã…Å¸an anomali korumasÃ„Â± sayÃ„Â±lmaz. YanlÃ„Â±Ã…Å¸ ÃƒÂ¶Ã„Å¸renme ve tenantlar arasÃ„Â± veri karÃ„Â±Ã…Å¸masÃ„Â± riski deÃ„Å¸erlendirilmemiÃ…Å¸.
- Tamamlama hedefi: GerÃƒÂ§ek olay tÃƒÂ¼keticisi, tenant bazlÃ„Â± durum, cold-start, unutma/retention, model sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼, karar aÃƒÂ§Ã„Â±klamasÃ„Â± ve insan geri bildirimi akÃ„Â±Ã…Å¸larÃ„Â±nÃ„Â± baÃ„Å¸la.
- Zorunlu kapanış testi: SoÃ„Å¸uk baÃ…Å¸langÃ„Â±ÃƒÂ§ ve model yenilemede kararlÃ„Â± sonuÃƒÂ§; tenant ayrÃ„Â±mÃ„Â±; veri zehirleme denemeleri; holdout saldÃ„Â±rÃ„Â± ve zararsÃ„Â±z iÃ…Å¸ yÃƒÂ¼kÃƒÂ¼nde yanlÃ„Â±Ã…Å¸ alarm ÃƒÂ¶lÃƒÂ§ÃƒÂ¼mÃƒÂ¼.
- Dış bağımlılık/sınır: Etiketli mÃƒÂ¼Ã…Å¸teri verisi ve baÃ„Å¸Ã„Â±msÃ„Â±z ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m seti

#### T06 — Reputation ve AI altyapÃ„Â± verisinin gÃƒÂ¼ncelliÃ„Å¸i [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DET-10, DET-11, DET-12, INF-01, INF-02
- Kaynak: supabase/functions/url-check/index.ts, supabase/functions/file-check/index.ts, packages/core/src/generated/aig-data-manifest.json, packages/core/src/aig-policy.ts
- Güncel yerel durum: Ã„Â°mzalÃ„Â± offline feed iÃƒÂ§in publisher issued_at ve yerel fetched_at birlikte yaÃ…Å¸ sÃ„Â±nÃ„Â±rÃ„Â±na baÃ„Å¸landÃ„Â±; canlÃ„Â± provider, daÃ„Å¸Ã„Â±tÃ„Â±m ve gecikme kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Feed kaynaÃ„Å¸Ã„Â±/gÃƒÂ¼ncelliÃ„Å¸i, saÃ„Å¸layÃ„Â±cÃ„Â± kesintisi, imzalÃ„Â± gÃƒÂ¼ncelleme, kapsanmayan format ve mÃƒÂ¼Ã…Å¸teri gecikme hedefleri doÃ„Å¸rulanmadÃ„Â±; canlÃ„Â± reputation testi atlanÃ„Â±yor.
- Tamamlama hedefi: Feed sÃƒÂ¶zleÃ…Å¸mesi ve gÃƒÂ¼ncelleme iÃ…Å¸i, yaÃ…Å¸ sÃ„Â±nÃ„Â±rÃ„Â±, geri alma, eksik veri durumu ve mÃƒÂ¼Ã…Å¸teri veri/URL kategorisi kalibrasyonu kur.
- Zorunlu kapanış testi: Eski/bozuk/boÃ…Å¸ feed temiz verdict ÃƒÂ¼retmesin; gÃƒÂ¼ncelleme/geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ kanÃ„Â±tlansÃ„Â±n; gerÃƒÂ§ek endpoint ve AMSI desteklenen Windows hostunda ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lsÃƒÂ¼n.
- Dış bağımlılık/sınır: SaÃ„Å¸layÃ„Â±cÃ„Â±/feed eriÃ…Å¸imi, Windows host ve mÃƒÂ¼Ã…Å¸teri corpus'u

#### T07 — MCP keÃ…Å¸fi ve kimlik normalizasyonunun kapsamÃ„Â± [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: MCP-01, MCP-02, MCP-03, MCP-04
- Kaynak: packages/core/src/mcp-discovery.ts, packages/core/src/mcp-inventory.ts, packages/core/src/policy.ts
- Güncel yerel durum: Yerel MCP keÃ…Å¸fi konum/alias bazlÃ„Â± kararlÃ„Â± inventory_id ve merkezi stale/partial kapsam raporu ÃƒÂ¼retiyor; ek host biÃƒÂ§imleri/native kabul aÃƒÂ§Ã„Â±k.
- Başlangıç riski: JSONC, yeni runtime konumlarÃ„Â±, dinamik eklenen sunucular ve belirsiz server/tool kimlikleri iÃƒÂ§in tam kapsama yok; yerel tarama kurum ÃƒÂ§apÃ„Â± keÃ…Å¸if deÃ„Å¸ildir.
- Tamamlama hedefi: Desteklenen konfigÃƒÂ¼rasyon adaptÃƒÂ¶rlerini ekle; okunamayan/kÃ„Â±smi keÃ…Å¸fi raporla; yeniden adlandÃ„Â±rma ve alias davranÃ„Â±Ã…Å¸Ã„Â±nÃ„Â± politikayla tutarlÃ„Â± yap.
- Zorunlu kapanış testi: Bozuk/izin verilmeyen dosya, JSONC, boÃ…Å¸ argÃƒÂ¼man, alias ve aynÃ„Â± isimli farklÃ„Â± sunucu testleri; eksik tarama gÃƒÂ¼venli envanter gibi gÃƒÂ¶rÃƒÂ¼nmesin.
- Dış bağımlılık/sınır: Host sÃƒÂ¼rÃƒÂ¼m ve konfigÃƒÂ¼rasyon matrisi

#### T08 — Ã„Â°mzalÃ„Â± MCP araÃƒÂ§ tanÃ„Â±mÃ„Â± ve deÃ„Å¸iÃ…Å¸iklik onayÃ„Â± [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: MCP-05
- Kaynak: packages/core/src/mcp-transport.ts, packages/core/src/mcp-discovery.ts
- Güncel yerel durum: Ã„Â°mzalÃ„Â± MCP manifest key_id'yi imzaya baÃ„Å¸lÃ„Â±yor, geÃƒÂ§ersiz saat ve legacy imza fail-closed; eski manifestler gÃƒÂ¼venilir yayÃ„Â±ncÃ„Â± tarafÃ„Â±ndan yeniden imzalanmalÃ„Â±.
- Başlangıç riski: Ã„Â°mzalÃ„Â± sunucu/araÃƒÂ§ description ve schema manifesti, kalÃ„Â±cÃ„Â± onay, sÃƒÂ¼rÃƒÂ¼m/expiry ve replay korumasÃ„Â± yok. SÃƒÂ¼reÃƒÂ§ yeniden baÃ…Å¸latÃ„Â±lmasÃ„Â± gÃƒÂ¼venilir onay deÃ„Å¸ildir.
- Tamamlama hedefi: AraÃƒÂ§ tanÃ„Â±mÃ„Â±nÃ„Â± sunucu kimliÃ„Å¸i ve sÃƒÂ¼rÃƒÂ¼me imzayla baÃ„Å¸la; deÃ„Å¸iÃ…Å¸en araÃƒÂ§larÃ„Â± karantinaya al; yalnÃ„Â±zca operatÃƒÂ¶rÃƒÂ¼n onaylayabildiÃ„Å¸i inceleme ve daÃ„Å¸Ã„Â±tÃ„Â±m akÃ„Â±Ã…Å¸Ã„Â± kur.
- Zorunlu kapanış testi: Description/schema deÃ„Å¸iÃ…Å¸imi, eski manifest, yanlÃ„Â±Ã…Å¸ signer, yeniden baÃ…Å¸latma, eÃ…Å¸ zamanlÃ„Â± deÃ„Å¸iÃ…Å¸iklik ve onaysÃ„Â±z retry reddedilsin; ajan kendi aracÃ„Â±nÃ„Â± onaylayamasÃ„Â±n.
- Dış bağımlılık/sınır: AIDR-046; signer/key custody ve yÃƒÂ¶netim UI'sÃ„Â±

#### T09 — KullanÃ„Â±cÃ„Â±Ã¢â‚¬â€œajanÃ¢â‚¬â€œaraÃƒÂ§Ã¢â‚¬â€œkaynak iliÃ…Å¸kisi ve delegasyon [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: MCP-06, TEN-06, OBS-02
- Kaynak: packages/core/src/mcp-inventory.ts, supabase/functions/enroll/index.ts, supabase/functions/api-keys/index.ts
- Güncel yerel durum: Ed25519 delegated lineage ve grant/introspection/revoke; geÃƒÂ§ersiz sayÃ„Â± ve Ed25519 olmayan EdDSA anahtarÃ„Â± reddediliyor. GerÃƒÂ§ek IdP/tool provider kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Kimin hangi ajan ÃƒÂ¼zerinden hangi kaynaÃ„Å¸a hangi yetkiyle eriÃ…Å¸tiÃ„Å¸ini gÃƒÂ¶steren tam iliÃ…Å¸ki grafiÃ„Å¸i; araÃƒÂ§ bazlÃ„Â± kÃ„Â±sa ÃƒÂ¶mÃƒÂ¼rlÃƒÂ¼ delegasyon yok.
- Tamamlama hedefi: Kaynak ve kimlik iliÃ…Å¸kileri, audience/scope/expiry taÃ…Å¸Ã„Â±yan kÃ„Â±sÃ„Â±tlÃ„Â± token, delegation depth ve credential broker uygula.
- Zorunlu kapanış testi: BaÃ…Å¸ka tool/resource/audience iÃƒÂ§in token kullanÃ„Â±mÃ„Â±, sÃƒÂ¼resi bitmiÃ…Å¸ delegasyon, kullanÃ„Â±cÃ„Â± ayrÃ„Â±lmasÃ„Â± ve zincir yetki bÃƒÂ¼yÃƒÂ¼tme reddedilsin; olaydan kaynaÃ„Å¸a iz sÃƒÂ¼rÃƒÂ¼lsÃƒÂ¼n.
- Dış bağımlılık/sınır: IdP ve araÃƒÂ§ saÃ„Å¸layÃ„Â±cÃ„Â±sÃ„Â± API'leri

#### T10 — MCP gateway ve taÃ…Å¸Ã„Â±ma gÃƒÂ¼venliÃ„Å¸i [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: MCP-07
- Kaynak: packages/core/src/mcp-transport.ts, packages/core/src/__tests__/mcp-transport.test.ts
- Güncel yerel durum: Loopback/stdio JSON-RPC geÃƒÂ§idi DNS pinleme, gerÃƒÂ§ek stream sÃ„Â±nÃ„Â±rÃ„Â±, tekil framing ve bozuk yanÃ„Â±t reddi uyguluyor; binary, server-initiated ve zorunlu routing kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: DNS rebinding, baÃ…Å¸lÃ„Â±ksÃ„Â±z/chunked bÃƒÂ¼yÃƒÂ¼k cevap, mapped IPv6 ve baÃ„Å¸lantÃ„Â± ÃƒÂ¶mrÃƒÂ¼ iÃƒÂ§in gerÃƒÂ§ek aÃ„Å¸ kabulÃƒÂ¼ eksik. Mevcut test adÃ„Â± DNS rebinding korumasÃ„Â±nÃ„Â± olduÃ„Å¸undan gÃƒÂ¼ÃƒÂ§lÃƒÂ¼ anlatÃ„Â±yor.
- Tamamlama hedefi: DoÃ„Å¸rulanan IP'yi baÃ„Å¸lantÃ„Â±ya sabitle; IP sÃ„Â±nÃ„Â±flamasÃ„Â±nÃ„Â± tamamla; gerÃƒÂ§ek okunan/decompress edilmiÃ…Å¸ baytlarÃ„Â± sÃ„Â±nÃ„Â±rla; authentication/session/stream ve bypass akÃ„Â±Ã…Å¸larÃ„Â±nÃ„Â± gateway'e baÃ„Å¸la.
- Zorunlu kapanış testi: Kontrol ile baÃ„Å¸lantÃ„Â± arasÃ„Â±nda DNS deÃ„Å¸iÃ…Å¸sin; private/mapped IPv6, redirect, baÃ…Å¸lÃ„Â±ksÃ„Â±z sonsuz stream, sÃ„Â±nÃ„Â±r aÃ…Å¸Ã„Â±mÃ„Â±, disconnect ve bozuk JSON/SSE ile gerÃƒÂ§ek aÃ„Å¸ testi ÃƒÂ§alÃ„Â±Ã…Å¸sÃ„Â±n.
- Dış bağımlılık/sınır: AIDR-062; stdio/HTTP/SSE kapsam kararÃ„Â±

#### T11 — SÃƒÂ¼rekli kurum/filo keÃ…Å¸fi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: INF-03
- Kaynak: packages/cli/src/commands/scan.ts, packages/core/src/aig-infra-scan.ts
- Güncel yerel durum: Kimlikli merkezi discovery upload var; interval modu geÃƒÂ§ici upload hatasÃ„Â±nÃ„Â± gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r tutarak sonraki ÃƒÂ§evrime devam ediyor. Cloud/MDM scheduler ve saha kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: ZamanlanmÃ„Â±Ã…Å¸ kolektÃƒÂ¶r, tenant envanteri, sahiplik, tekrar birleÃ…Å¸tirme, son gÃƒÂ¶rÃƒÂ¼lme ve stale alarmÃ„Â± yok.
- Tamamlama hedefi: Filo/cloud kolektÃƒÂ¶rleri, kapsam izinleri, zamanlama, retry, dedup, kimlik ve keÃ…Å¸if tazeliÃ„Å¸i ekranlarÃ„Â±nÃ„Â± kur.
- Zorunlu kapanış testi: Kapanan veya yeni aÃƒÂ§Ã„Â±lan ajan gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r olsun; baÃ„Å¸lantÃ„Â±sÃ„Â±z kolektÃƒÂ¶r eski veriyi gÃƒÂ¼ncel gÃƒÂ¶stermesin; tenant ayrÃ„Â±mÃ„Â± ve keÃ…Å¸if yÃƒÂ¼k sÃ„Â±nÃ„Â±rlarÃ„Â± sÃ„Â±nansÃ„Â±n.
- Dış bağımlılık/sınır: MÃƒÂ¼Ã…Å¸teri cloud/MDM API eriÃ…Å¸imi ve aÃ„Å¸ tarama kapsamÃ„Â±

#### T12 — Filo mÃƒÂ¼dahalesi ve credential iptali [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: RSP-04, RSP-06
- Kaynak: packages/core/src/contain.ts, supabase/functions/revocations/index.ts
- Güncel yerel durum: Ã„Â°mzalÃ„Â± revocation feed tenant+global kapsamÃ„Â± 5000 sÃ„Â±nÃ„Â±rÃ„Â±ndan ÃƒÂ¶nce filtreliyor ve eksik/truncated seti imzalamÃ„Â±yor; native/provider iptali aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Kurumsal endpoint izolasyonu, tÃƒÂ¼m cloud saÃ„Å¸layÃ„Â±cÃ„Â±larda credential iptali ve ajandan sonuÃƒÂ§ alan komut altyapÃ„Â±sÃ„Â± yok.
- Tamamlama hedefi: Yetkili komut kuyruÃ„Å¸u, TTL/idempotency, operatÃƒÂ¶r yetkisi, ajan sonuÃƒÂ§ bildirimi, geri alma ve saÃ„Å¸layÃ„Â±cÃ„Â± adaptÃƒÂ¶rleri ekle.
- Zorunlu kapanış testi: Offline ajana sÃƒÂ¼resi geÃƒÂ§miÃ…Å¸ komut uygulanmasÃ„Â±n; tekrar gelen komut tek etki ÃƒÂ¼retsin; baÃ…Å¸arÃ„Â±sÃ„Â±z izolasyon baÃ…Å¸arÃ„Â± gÃƒÂ¶rÃƒÂ¼nmesin; ilgili izinler ve geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ kanÃ„Â±tlansÃ„Â±n.
- Dış bağımlılık/sınır: OS yetkileri, saÃ„Å¸layÃ„Â±cÃ„Â± API'leri, mÃƒÂ¼Ã…Å¸teri mÃƒÂ¼dahale yetkisi

#### T13 — Response eylemlerinin gÃƒÂ¼venli uÃƒÂ§tan uca iÃ…Å¸letimi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: RSP-02, RSP-03, RSP-05, RSP-07
- Kaynak: packages/core/src/quarantine.ts, packages/core/src/rollback.ts, packages/core/src/response-command-worker-v6.ts, packages/core/src/response-audit.ts, supabase/functions/autosecops-runtime/index.ts
- Güncel yerel durum: Yeni response-worker-contract.ts capability/onkosul/TTL/idempotency/rollback makbuzu sozlesmesini uyguluyor; desteklenmeyen action adapter tarafindan reddediliyor ve geri alinamayan adim partial olarak raporlaniyor. Native OS/provider adapter ve kurulu servis musteri tarafinda acik. Eski: Restart-safe worker resume sÃ„Â±rasÃ„Â±nda adapter destek listesini yeniden doÃ„Å¸ruluyor ve kaldÃ„Â±rÃ„Â±lmÃ„Â±Ã…Å¸ action'Ã„Â± ÃƒÂ§alÃ„Â±Ã…Å¸tÃ„Â±rmadan unsupported_action bildiriyor. Native OS/provider adapter ve kurulu servis aÃƒÂ§Ã„Â±k.
- Başlangıç riski: GerÃƒÂ§ek mÃƒÂ¼Ã…Å¸teri dosya izinleri, aynÃ„Â± anda deÃ„Å¸iÃ…Å¸en dosya, dÃ„Â±Ã…Å¸ playbook etkileri, signer saklama ve baÃ„Å¸Ã„Â±msÃ„Â±z arÃ…Å¸iv kanÃ„Â±tÃ„Â± eksik.
- Tamamlama hedefi: Desteklenen eylem ve dosya kapsamÃ„Â±nÃ„Â± sabitle; ÃƒÂ¶nkoÃ…Å¸ul/sonuÃƒÂ§ doÃ„Å¸rulama, operatÃƒÂ¶r sÃ„Â±nÃ„Â±rlarÃ„Â±, dÃ„Â±Ã…Å¸ SOAR sonuÃƒÂ§larÃ„Â± ve baÃ„Å¸Ã„Â±msÃ„Â±z kanÃ„Â±t saklamayÃ„Â± tamamla.
- Zorunlu kapanış testi: Dosya sonradan deÃ„Å¸iÃ…Å¸miÃ…Å¸ken yanlÃ„Â±Ã…Å¸ rollback yapÃ„Â±lmasÃ„Â±n; symlink/izin/disk hatasÃ„Â± aÃƒÂ§Ã„Â±k baÃ…Å¸arÃ„Â±sÃ„Â±z olsun; eylem ve geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ aynÃ„Â± incidentten izlenebilsin.
- Dış bağımlılık/sınır: MÃƒÂ¼Ã…Å¸teri dosya sistemi/EDR/SOAR izinleri

#### T14 — YAML politika yazÃ„Â±mÃ„Â± ile gerÃƒÂ§ek runtime iliÃ…Å¸kisi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: POL-01, POL-02
- Kaynak: packages/dashboard/src/enterprise/policy-editor.tsx, packages/dashboard/src/ui/pages/PolicyPage.tsx, packages/core/src/policy.ts
- Güncel yerel durum: Core/server dry-run unknown MCP fallback kararÃ„Â± runtime evaluator ile eÃ…Å¸lendi; YAML/JSON compiler, parity ve dashboard publish akÃ„Â±Ã…Å¸Ã„Â± baÃ„Å¸lÃ„Â±.
- Başlangıç riski: Kaydedilen YAML kurallarÃ„Â± runtime tarafÃ„Â±ndan tÃƒÂ¼ketilmiyor. KullanÃ„Â±cÃ„Â± belge kaydÃ„Â±nÃ„Â± etkin gÃƒÂ¼venlik politikasÃ„Â± sanabilir.
- Tamamlama hedefi: Desteklenen YAML Ã…Å¸emasÃ„Â±nÃ„Â± runtime modeline derle veya belge akÃ„Â±Ã…Å¸Ã„Â±nÃ„Â± aÃƒÂ§Ã„Â±kÃƒÂ§a ayÃ„Â±r; desteklenmeyen alanlarÃ„Â± reddet; ÃƒÂ¶ncelik ve etki simÃƒÂ¼lasyonu sun.
- Zorunlu kapanış testi: Kaydedilen/yayÃ„Â±nlanan politika gerÃƒÂ§ek ajan kararÃ„Â±nda deÃ„Å¸iÃ…Å¸iklik ÃƒÂ¼retsin; bilinmeyen alan sessiz atÃ„Â±lmasÃ„Â±n; allowlist ile aÃƒÂ§Ã„Â±k deny ÃƒÂ¶nceliÃ„Å¸i doÃ„Å¸rulansÃ„Â±n.
- Dış bağımlılık/sınır: Politika sÃƒÂ¶zleÃ…Å¸mesi ve migration planÃ„Â±

#### T15 — Politika daÃ„Å¸Ã„Â±tÃ„Â±mÃ„Â± saha kabulÃƒÂ¼ ve ÃƒÂ¶lÃƒÂ§ek sÃ„Â±nÃ„Â±rlarÃ„Â± [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: POL-03, POL-04, POL-05
- Kaynak: supabase/functions/policy-management/index.ts, supabase/functions/policy-ack/index.ts, packages/core/src/remote-policy.ts
- Güncel yerel durum: Hedefli stage iÃ…Å¸lemi atomik revision precondition ile eski eÃ…Å¸zamanlÃ„Â± gÃƒÂ¼ncellemeyi 409 reddediyor; gerÃƒÂ§ek filo/ÃƒÂ¶lÃƒÂ§ek kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Receipt yalnÃ„Â±zca ajanÃ„Â±n yÃƒÂ¼kleme bildirimi; host enforcement attestation deÃ„Å¸il. Eski baÃ„Å¸lÃ„Â± olmayan anahtarlar, bÃƒÂ¼yÃƒÂ¼k filo batch planÃ„Â± ve gerÃƒÂ§ek offline saha kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Tamamlama hedefi: Eski ajanlarÃ„Â± yeniden kaydet; daÃ„Å¸Ã„Â±tÃ„Â±m batch/ring iÃ…Å¸letimini ve zorunlu politika sÃƒÂ¼relerini mÃƒÂ¼Ã…Å¸teriye gÃƒÂ¶re belirle; gÃƒÂ¶zlem/uyarÃ„Â± ve native canary kabulÃƒÂ¼ yap.
- Zorunlu kapanış testi: Yetkisiz/stale receipt, rollback, offline sÃƒÂ¼resi, 401/403, bozuk cache, yeniden baÃ…Å¸latma ve hedef deÃ„Å¸iÃ…Å¸tirmede yanlÃ„Â±Ã…Å¸ sÃƒÂ¼rÃƒÂ¼m uygulanmasÃ„Â±n; gerÃƒÂ§ek filoda yakÃ„Â±nsama ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lsÃƒÂ¼n.
- Dış bağımlılık/sınır: Ajan sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼, mÃƒÂ¼Ã…Å¸teri offline toleransÃ„Â±

#### T16 — Endpoint sÃ„Â±r saklama ve anahtar rotasyonu [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: CLI-02, TEN-06
- Kaynak: packages/cli/src/utils/config-manager.ts, packages/core/src/types.ts, docs/runbooks/secrets-management.md
- Güncel yerel durum: Windows config create/update/reuse yolu owner+SYSTEM+Administrators DACL kuruyor ve ACL hatasÃ„Â±nda credential yazmÃ„Â±yor; OS vault ve server-side revocation aÃƒÂ§Ã„Â±k.
- Başlangıç riski: OS credential vault entegrasyonu, kurumsal daÃ„Å¸Ã„Â±tÃ„Â±mda signer rotasyonu, kayÃ„Â±p cihaz/anahtar kurtarma ve minimum API-key kapsamÃ„Â± eksik.
- Tamamlama hedefi: Windows/macOS/Linux iÃƒÂ§in sÃ„Â±r deposu adaptÃƒÂ¶rÃƒÂ¼; anahtar rotasyonu ve iptali; config/export/support bundle redaksiyonunu tamamla.
- Zorunlu kapanış testi: Yetkisiz kullanÃ„Â±cÃ„Â± sÃ„Â±r okuyamasÃ„Â±n; eski anahtar zamanÃ„Â±nda reddedilsin; yenileme kesintisi gÃƒÂ¼venli olsun; log, argÃƒÂ¼man ve destek arÃ…Å¸ivi sÃ„Â±r sÃ„Â±zdÃ„Â±rmasÃ„Â±n.
- Dış bağımlılık/sınır: Kurum secret manager'Ã„Â± ve OS depolarÃ„Â±

#### T17 — Ã„Â°mzalÃ„Â± filo kurulumu, gÃƒÂ¼ncelleme ve kaldÃ„Â±rma [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: CLI-01, CLI-03, CLI-04
- Kaynak: scripts/endpoint-install.mjs, packages/extension/package.json, packages/cli/src/commands/setup.ts
- Güncel yerel durum: Installer ile Windows/Unix uninstall yalnÃ„Â±z AIDR iÃ…Å¸aretli nested hook'u kaldÃ„Â±rÃ„Â±yor, aynÃ„Â± entry'deki mÃƒÂ¼Ã…Å¸teri hook'larÃ„Â±nÃ„Â± koruyor; gerÃƒÂ§ek MDM/yayÃ„Â±ncÃ„Â± kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Intune/Jamf/SCCM teslimatÃ„Â±, tÃƒÂ¼m hostlarda upgrade/rollback/uninstall ve filo saÃ„Å¸lÃ„Â±k kanÃ„Â±tÃ„Â± tamam deÃ„Å¸il.
- Tamamlama hedefi: Ã„Â°mzalÃ„Â± daÃ„Å¸Ã„Â±tÃ„Â±m paketleri, detect/remediate betikleri, yÃƒÂ¶netici/kullanÃ„Â±cÃ„Â± kurulumlarÃ„Â±, policy-preserving upgrade ve uninstall kurallarÃ„Â± ÃƒÂ¼ret.
- Zorunlu kapanış testi: Temiz kurulum, yarÃ„Â±m kalan upgrade, eski sÃƒÂ¼rÃƒÂ¼me dÃƒÂ¶nÃƒÂ¼Ã…Å¸, host gÃƒÂ¼ncellemesi ve uninstall sonrasÃ„Â±nda baÃ…Å¸ka kancalar/politika bozulmasÃ„Â±n; gerÃƒÂ§ek MDM'de kanÃ„Â±t topla.
- Dış bağımlılık/sınır: MDM test tenantÃ„Â±, signer, OS paketleme araÃƒÂ§larÃ„Â±

#### T18 — Kurumsal giriÃ…Å¸, MFA ve hesap kurtarma [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-01, TEN-04, TEN-07
- Kaynak: packages/dashboard/src/ui/pages/LoginPage.tsx, packages/dashboard/src/enterprise/auth.tsx, scripts/deployment-bootstrap.mjs
- Güncel yerel durum: Recovery URL yalnÃ„Â±z hosted HTTPS/loopback HTTP kabul ediyor, credential URL'yi reddediyor ve parola deÃ„Å¸iÃ…Å¸iminden ÃƒÂ¶nce global session barrier kuruyor; canlÃ„Â± IdP aÃƒÂ§Ã„Â±k.
- Başlangıç riski: GerÃƒÂ§ek IdP/SSO, MFA, parola sÃ„Â±fÃ„Â±rlama, oturum sonlandÃ„Â±rma, break-glass ve kimlik sahipliÃ„Å¸i iÃ…Å¸letimi kabul edilmedi.
- Tamamlama hedefi: MÃƒÂ¼Ã…Å¸teri IdP'si, MFA ve kurtarma akÃ„Â±Ã…Å¸larÃ„Â±nÃ„Â± baÃ„Å¸la; bootstrap sahiplik prosedÃƒÂ¼rÃƒÂ¼, session sÃƒÂ¼releri ve acil yÃƒÂ¶netici eriÃ…Å¸imini tanÃ„Â±mla.
- Zorunlu kapanış testi: KayÃ„Â±p parola/MFA, kapatÃ„Â±lmÃ„Â±Ã…Å¸ kullanÃ„Â±cÃ„Â±, sÃƒÂ¼resi dolmuÃ…Å¸ oturum ve baÃ…Å¸arÃ„Â±sÃ„Â±z IdP durumlarÃ„Â±nÃ„Â± sÃ„Â±nayarak hesabÃ„Â±n hem geri alÃ„Â±nabilir hem yetkisiz eriÃ…Å¸ime kapalÃ„Â± olduÃ„Å¸unu kanÃ„Â±tla.
- Dış bağımlılık/sınır: IdP/SMTP/DNS ve kurum gÃƒÂ¼venlik politikasÃ„Â±

#### T19 — SCIM ve gÃƒÂ¼venilir directory grup eÃ…Å¸lemesi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-02, TEN-04
- Kaynak: packages/dashboard/src/auth/azure-ad.ts, packages/dashboard/src/enterprise/team-provider.tsx
- Güncel yerel durum: SCIM stale PATCH'i reddediyor, Remove members tÃƒÂ¼m ÃƒÂ¼yeleri kaldÃ„Â±rÃ„Â±yor ve bÃƒÂ¼yÃƒÂ¼k grup ÃƒÂ¼yeliÃ„Å¸ini sayfalÃ„Â±yor; gerÃƒÂ§ek Entra/Okta kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: YardÃ„Â±mcÃ„Â± kod user_metadata gruplarÃ„Â±nÃ„Â± ÃƒÂ¶nce okuyabiliyor ve isimde admin geÃƒÂ§mesine gÃƒÂ¶re rol eÃ…Å¸liyor. Bu, sunucu yetkilendirmesi iÃƒÂ§in gÃƒÂ¼venilir temel deÃ„Å¸ildir; aktif bir yetki yÃƒÂ¼kseltme kanÃ„Â±tÃ„Â± olarak sunulmuyor.
- Tamamlama hedefi: Sunucuda doÃ„Å¸rulanmÃ„Â±Ã…Å¸ immutable grup ID'leri, allowlist rol eÃ…Å¸lemesi ve SCIM create/update/deactivate/groups uygula; kullanÃ„Â±cÃ„Â± metadata'sÃ„Â±nÃ„Â± yetki kaynaÃ„Å¸Ã„Â± yapma.
- Zorunlu kapanış testi: Sahte metadata, benzer grup adÃ„Â±, grup kaldÃ„Â±rma, hesap pasifleÃ…Å¸tirme, pagination/replay ve tenant karÃ„Â±Ã…Å¸tÃ„Â±rma testleri; eriÃ…Å¸im belirtilen sÃƒÂ¼re iÃƒÂ§inde kesilsin.
- Dış bağımlılık/sınır: AIDR-019/048; Entra/Okta test ortamÃ„Â±

#### T20 — Davet ve cihaz kayÃ„Â±t yaÃ…Å¸am dÃƒÂ¶ngÃƒÂ¼sÃƒÂ¼ [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-03, TEN-05
- Kaynak: supabase/functions/team-invite/index.ts, supabase/functions/device-poll/index.ts, packages/dashboard/src/ui/pages/public/VerifyPage.tsx
- Güncel yerel durum: Tenant kapsamlÃ„Â± invite list/revoke/resend token rotasyonu ile device-start/exchange temeli var; SMTP, gerÃƒÂ§ek browser/IdP ve aÃ„Å¸ kesintisi kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: SMTP davet teslimi, gerÃƒÂ§ek cihaz yeniden kaydÃ„Â±, ekipten ayrÃ„Â±lan ÃƒÂ§alÃ„Â±Ã…Å¸anÃ„Â±n eriÃ…Å¸im kapanmasÃ„Â± ve mÃƒÂ¼Ã…Å¸teri mail/link akÃ„Â±Ã…Å¸Ã„Â± tam kabul edilmedi.
- Tamamlama hedefi: Davet daÃ„Å¸Ã„Â±tÃ„Â±mÃ„Â±nÃ„Â±, expiry/iptal/yeniden gÃƒÂ¶nderme, yanlÃ„Â±Ã…Å¸ ekip ve cihaz yenileme iÃ…Å¸letimini tamamla.
- Zorunlu kapanış testi: KullanÃ„Â±lmÃ„Â±Ã…Å¸/iptal edilmiÃ…Å¸ davet, rol deÃ„Å¸iÃ…Å¸imi, baÃ…Å¸ka ekip, eski device code ve kimlik deÃ„Å¸iÃ…Å¸iminde kayÃ„Â±t reddedilsin; mail linki gerÃƒÂ§ek tarayÃ„Â±cÃ„Â±da doÃ„Å¸ru ekibe dÃƒÂ¶nsÃƒÂ¼n.
- Dış bağımlılık/sınır: SMTP/IdP ve mÃƒÂ¼Ã…Å¸teri cihazlarÃ„Â±

#### T21 — Mevcut API anahtarÃ„Â±nda ekip ve ÃƒÂ¼yelik iptali [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-01, TEN-06, DET-10, DET-11
- Kaynak: supabase/functions/url-check/index.ts, supabase/functions/file-check/index.ts, scripts/audit-reputation-lifecycle.mjs
- Güncel yerel durum: Packs manifest/download dahil anahtar kullanan yollar aktif tenant, ÃƒÂ¼yelik ve revocation doÃ„Å¸ruluyor; ÃƒÂ¶nceden ÃƒÂ¼retilmiÃ…Å¸ signed URL sÃƒÂ¼re sonuna dek geÃƒÂ§erli.
- Başlangıç riski: Ã„Â°zole gerÃƒÂ§ek HTTP provasÃ„Â±nda askÃ„Â±ya alÃ„Â±nmÃ„Â±Ã…Å¸ ekip ve sÃƒÂ¼resi bitmiÃ…Å¸ ÃƒÂ¼yelikle hem URL hem dosya sorgusu 200 dÃƒÂ¶ndÃƒÂ¼; dÃƒÂ¶rt kabul yeniden ÃƒÂ¼retildi. BaÃ…Å¸ka tenant verisi okunduÃ„Å¸u gÃƒÂ¶sterilmedi.
- Tamamlama hedefi: Ortak doÃ„Å¸rulanmÃ„Â±Ã…Å¸ anahtar/aktif tenant/aktif ÃƒÂ¼yelik sÃ„Â±nÃ„Â±rÃ„Â± uygula; iptal, kapanÃ„Â±Ã…Å¸ ve deprovisioning semantiÃ„Å¸ini tÃƒÂ¼m servislerde birleÃ…Å¸tir.
- Zorunlu kapanış testi: Aktif kimlik 200; suspended/closing/closed tenant, expired/removed membership ve revoked key tÃƒÂ¼m tÃƒÂ¼keticilerde 401/403; stale cache ile eriÃ…Å¸im sÃƒÂ¼rmesin.
- Dış bağımlılık/sınır: AIDR-063; yerel yeniden ÃƒÂ¼retim kanÃ„Â±tÃ„Â±

#### T22 — Tenant izolasyonu ve kaynak tÃƒÂ¼ketim sÃ„Â±nÃ„Â±rlarÃ„Â± [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-01, OBS-01, DEP-07
- Kaynak: supabase/functions/_shared/auth.ts, supabase/migrations/20260805000000_hybrid_tenancy.sql
- Güncel yerel durum: Edge byte/rate sÃ„Â±nÃ„Â±rÃ„Â± bozuk RPC'de 503 ve stalled stream'de 413 fail-closed ÃƒÂ¼retiyor; mÃƒÂ¼Ã…Å¸teri yÃƒÂ¼k/izolasyon kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Her endpoint/rol/tenant kombinasyonu, body/stream sÃ„Â±nÃ„Â±rÃ„Â±, rate-limit kesintisi ve komÃ…Å¸u tenant kaynak tÃƒÂ¼ketimi tam ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lmedi.
- Tamamlama hedefi: TÃƒÂ¼m endpointler iÃƒÂ§in auth/RBAC/RLS sÃƒÂ¶zleÃ…Å¸mesi; servis rolÃƒÂ¼ kullanan yollarda aÃƒÂ§Ã„Â±k tenant sÃ„Â±nÃ„Â±rÃ„Â±; kuyruk/iÃ…Å¸/istek/depoma kotalarÃ„Â± ekle ve denetle.
- Zorunlu kapanış testi: FarklÃ„Â± tenant, ÃƒÂ¼yelik kaybÃ„Â±, viewer, eski anahtar, bÃƒÂ¼yÃƒÂ¼k body ve paralel isteklerle negatif matris ÃƒÂ§alÃ„Â±Ã…Å¸sÃ„Â±n; tek tenant diÃ„Å¸erinin SLO'sunu tÃƒÂ¼ketemesin.
- Dış bağımlılık/sınır: BaÃ„Å¸Ã„Â±msÃ„Â±z deÃ„Å¸erlendirme ve tanÃ„Â±mlÃ„Â± yÃƒÂ¼k profili

#### T23 — Telemetri dayanÃ„Â±klÃ„Â±lÃ„Â±Ã„Å¸Ã„Â± ve gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r veri kaybÃ„Â± [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: OBS-01
- Kaynak: supabase/functions/ingest/index.ts, packages/core/src/audit-log.ts
- Güncel yerel durum: Telemetry WAL bozuk/unknown/tampered committed kayÃ„Â±tlarÃ„Â± reddediyor, terminal drop sonrasÃ„Â± retry ve stale backlog readiness saÃ„Å¸lÃ„Â±yor; uzun kesinti saha testi aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Filo yÃƒÂ¼kÃƒÂ¼nde teslim SLO'su, disk/kuyruk sÃ„Â±nÃ„Â±rÃ„Â±, offline retry/dedup ve uÃƒÂ§tan uca kayÃ„Â±p oranÃ„Â± iÃƒÂ§in kanÃ„Â±t eksik.
- Tamamlama hedefi: Olay teslim sÃƒÂ¶zleÃ…Å¸mesi, kimlik/idempotency, retry/backpressure, kayÃ„Â±p sayaÃƒÂ§larÃ„Â± ve tenant bazlÃ„Â± retention bÃƒÂ¼tÃƒÂ§elerini doÃ„Å¸rula.
- Zorunlu kapanış testi: AÃ„Å¸/DB/storage kesintisi ve ajan yeniden baÃ…Å¸latmada kayÃ„Â±p/duplicate ÃƒÂ¶lÃƒÂ§; sessiz olay kaybÃ„Â± olmasÃ„Â±n; disk dolmasÃ„Â± ve gecikme kullanÃ„Â±cÃ„Â±ya gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r olsun.
- Dış bağımlılık/sınır: MÃƒÂ¼Ã…Å¸teri cihaz/olay hacmi ve saklama hedefi

#### T24 — SIEM ve OpenTelemetry ÃƒÂ¼retim teslimi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: OBS-04
- Kaynak: packages/core/src/siem-export.ts, packages/core/src/tracing.ts
- Güncel yerel durum: SIEM durable state provider/endpoint/index routing fingerprint'e baÃ„Å¸lÃ„Â± ve farklÃ„Â± hedefte reopen'i reddediyor; gerÃƒÂ§ek SIEM alÃ„Â±ndÃ„Â±sÃ„Â±/zamanlayÃ„Â±cÃ„Â± aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Named SIEM transport, teslim bildirimi, kesinti tamponu, Ã…Å¸ema sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼ ve mÃƒÂ¼Ã…Å¸teri SIEM alan eÃ…Å¸lemesi kabul edilmedi.
- Tamamlama hedefi: SatÃ„Â±lacak Splunk/Sentinel/Elastic vb. adaptÃƒÂ¶rleri iÃƒÂ§in gerÃƒÂ§ek endpoint entegrasyonu, retry/dedup ve saÃ„Å¸lÃ„Â±k gÃƒÂ¶stergesi tamamla.
- Zorunlu kapanış testi: SIEM kesintisi/429/401, sertifika deÃ„Å¸iÃ…Å¸imi, yeniden gÃƒÂ¶nderim ve alan eÃ…Å¸lemesi gerÃƒÂ§ek SIEM'de doÃ„Å¸rulansÃ„Â±n; yanlÃ„Â±Ã…Å¸ baÃ…Å¸arÃ„Â± bildirimi olmasÃ„Â±n.
- Dış bağımlılık/sınır: SIEM test hesabÃ„Â± ve event schema anlaÃ…Å¸masÃ„Â±

#### T25 — Olay araÃ…Å¸tÃ„Â±rmasÃ„Â± ve kanÃ„Â±t bÃƒÂ¼tÃƒÂ¼nlÃƒÂ¼Ã„Å¸ÃƒÂ¼ [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: OBS-02, RSP-05
- Kaynak: packages/core/src/incidents/correlate.ts, packages/core/src/incidents/anchor.ts, packages/core/src/response-audit.ts
- Güncel yerel durum: incidents/evidence-receipt.ts candidate/policy/device/actor/incident/action bagli append-only receipt, Lamport mantik saati ile offline/skew siralamasi, duplicate/tamper reddi ve fail-closed arsiv adapteri ekliyor. Dis arsiv sahibi ve key custody acik. Eski: Olay receipt head sÃ„Â±rasÃ„Â± deterministik UTF-16 ve legacy doÃ„Å¸rulama uyumlu; ayrÃ„Â± Ed25519 snapshot makbuzu var. DÃ„Â±Ã…Å¸ saklama, key custody ve gÃƒÂ¼venilir zaman aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Tam cross-agent nedensellik, ayrÃ„Â±calÃ„Â±klÃ„Â± deÃ„Å¸iÃ…Å¸ikliklere karÃ…Å¸Ã„Â± baÃ„Å¸Ã„Â±msÃ„Â±z kanÃ„Â±t saklama ve olayÃ¢â€ â€™araÃƒÂ§Ã¢â€ â€™credential izi eksik.
- Tamamlama hedefi: Korelasyon kimlikleri, zaman sapmasÃ„Â±, iliÃ…Å¸kili ajan/kaynak gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼mÃƒÂ¼, zincir doÃ„Å¸rulama ve baÃ„Å¸Ã„Â±msÃ„Â±z arÃ…Å¸iv kur.
- Zorunlu kapanış testi: Saat kaymasÃ„Â±/duplicate/offline sÃ„Â±ralama, silinmiÃ…Å¸ veya deÃ„Å¸iÃ…Å¸tirilmiÃ…Å¸ zincir ve ÃƒÂ§ok ajanlÃ„Â± saldÃ„Â±rÃ„Â±da kanÃ„Â±t boÃ…Å¸luklarÃ„Â± gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r olsun.
- Dış bağımlılık/sınır: Kimlik grafiÃ„Å¸i, gÃƒÂ¼venilir zaman ve arÃ…Å¸iv sahibi

#### T26 — Saklama, legal hold ve mÃƒÂ¼Ã…Å¸teri ÃƒÂ§Ã„Â±kÃ„Â±Ã…Å¸Ã„Â± [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: OBS-03, OBS-06
- Kaynak: scripts/deployment-maintenance.mjs, deploy/maintenance/aidr-export-retention.timer, supabase/functions/audit-export/index.ts
- Güncel yerel durum: Offboarding her Storage nesnesinin yokluÃ„Å¸unu doÃ„Å¸rulamadan ACK ÃƒÂ¼retmiyor; legal hold/resume var, harici backup silme kanÃ„Â±tÃ„Â± aÃƒÂ§Ã„Â±k.
- Başlangıç riski: ZamanlayÃ„Â±cÃ„Â± mÃƒÂ¼Ã…Å¸teri ortamÃ„Â±nda aktif deÃ„Å¸il; tÃƒÂ¼m veri sÃ„Â±nÃ„Â±flarÃ„Â± iÃƒÂ§in retention/deletion, legal hold ve doÃ„Å¸rulanmÃ„Â±Ã…Å¸ offboarding yok.
- Tamamlama hedefi: Tablo/nesne/log/cache/yedek bazÃ„Â±nda yaÃ…Å¸am dÃƒÂ¶ngÃƒÂ¼sÃƒÂ¼; legal hold istisnasÃ„Â±; kullanÃ„Â±cÃ„Â±/tenant kapanÃ„Â±Ã…Å¸Ã„Â± ve silme makbuzu kur.
- Zorunlu kapanış testi: SÃƒÂ¼re dolan verinin API, Storage, cache ve replikalardan yokluÃ„Å¸u; hold verisinin korunmasÃ„Â±; retry ve yarÃ„Â±m silme sonrasÃ„Â± tutarlÃ„Â±lÃ„Â±k kanÃ„Â±tlansÃ„Â±n.
- Dış bağımlılık/sınır: OnaylÃ„Â± saklama/silme politikasÃ„Â±; yedek istisnalarÃ„Â±

#### T27 — Offsite yedekleme ve RPO/RTO [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-06
- Kaynak: scripts/deployment-backup.mjs, scripts/verify-deployment-recovery.mjs
- Güncel yerel durum: Offsite commit zamanÃ„Â± authenticated manifest'e baÃ„Å¸lÃ„Â± ve S3 lookup hatasÃ„Â± fail-closed; izole restore aracÃ„Â± var. BaÃ„Å¸Ã„Â±msÃ„Â±z host/provider ve RPO/RTO aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Off-host kopya, otomatik zamanlama/retention, ayrÃ„Â± anahtar kurtarma ve gerÃƒÂ§ek felaket RPO/RTO kanÃ„Â±tÃ„Â± yok; bakÃ„Â±m duruÃ…Å¸u gerekiyor.
- Tamamlama hedefi: Yedek hedefi/anahtar custody, zamanlama, eriÃ…Å¸im ayrÃ„Â±lÃ„Â±Ã„Å¸Ã„Â±, baÃ…Å¸arÃ„Â±sÃ„Â±zlÃ„Â±k alarmÃ„Â± ve kayÃ„Â±p-host geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ iÃ…Å¸letimini kur.
- Zorunlu kapanış testi: Yeni hostta yalnÃ„Â±z offsite yedek ve ayrÃ„Â± anahtarla kurtar; tablo/nesne iÃƒÂ§erikleri eÃ…Å¸leÃ…Å¸sin; gerÃƒÂ§ek kayÃ„Â±p veri sÃƒÂ¼resi ve toparlanma sÃƒÂ¼resi ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lsÃƒÂ¼n.
- Dış bağımlılık/sınır: Offsite storage, key custodian, kabul edilmiÃ…Å¸ RPO/RTO

#### T28 — GerÃƒÂ§ek cloud ve self-hosted ÃƒÂ¼retim kurulumu [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-01, DEP-02
- Kaynak: scripts/deployment-prepare.mjs, deploy/FIRST_CUSTOMER.md
- Güncel yerel durum: 33 migrationlÃ„Â± self-hosted prova var; prepare inputlarÃ„Â± secret oluÃ…Å¸turmadan doÃ„Å¸ruluyor ve cloud public proxy/provider upstream loop'unu reddediyor. CanlÃ„Â± provider/TLS aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Cloud hesabÃ„Â±/projesi, bÃƒÂ¶lge, DNS/TLS, reverse proxy, SMTP/IdP, secret installation ve gerÃƒÂ§ek internet eriÃ…Å¸imi bilinmiyor; cloud hazÃ„Â±rlama ÃƒÂ§alÃ„Â±Ã…Å¸an cloud demek deÃ„Å¸il.
- Tamamlama hedefi: Her model iÃƒÂ§in hedef ortamÃ„Â± kur; TLS yenileme ve HTTP/WebSocket baÃ…Å¸lÃ„Â±klarÃ„Â±nÃ„Â± doÃ„Å¸rula; DB/Studio'yu ÃƒÂ¶zel aÃ„Å¸da tut; public endpoint ve onboarding'i kabul et.
- Zorunlu kapanış testi: Temiz makinede mÃƒÂ¼Ã…Å¸teri kimliÃ„Å¸iyle giriÃ…Å¸Ã¢â€ â€™cihazÃ¢â€ â€™denyÃ¢â€ â€™olayÃ¢â€ â€™exportÃ¢â€ â€™rollback akÃ„Â±Ã…Å¸Ã„Â±; dÃ„Â±Ã…Å¸ port/izin kontrolleri ve sertifika yenileme tatbikatÃ„Â±.
- Dış bağımlılık/sınır: Alan adÃ„Â±, cloud hesabÃ„Â±/bÃƒÂ¶lge ve aÃ„Å¸ bilgisi

#### T29 — KimliÃ„Å¸i doÃ„Å¸rulanan daÃ„Å¸Ã„Â±tÃ„Â±m ve release provenance [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-05, DEP-08, OBS-05
- Kaynak: scripts/customer-kit.mjs, .github/scripts/build-release-bundle.mjs, scripts/release-artifact-manifests.mjs
- Güncel yerel durum: Release verifier receipt hedefini mutation ÃƒÂ¶ncesi doÃ„Å¸ruluyor ve bundle/state/policy ÃƒÂ§akÃ„Â±Ã…Å¸masÃ„Â±nÃ„Â± reddediyor; resmi key custody/private registry aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Checksum yayÃ„Â±ncÃ„Â± kimliÃ„Å¸i deÃ„Å¸ildir. Private registry kurulumu, imza doÃ„Å¸rulama, key rotasyonu ve air-gap imaj teslimi kanÃ„Â±tÃ„Â± yok.
- Tamamlama hedefi: AynÃ„Â± candidate'Ã„Â± imzala; auth kontrollÃƒÂ¼ registry/download, provenance ve sabit imaj digestleriyle teslim et; air-gap satÃ„Â±lÃ„Â±yorsa tÃƒÂ¼m baÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k/imajlarÃ„Â± dahil et.
- Zorunlu kapanış testi: YanlÃ„Â±Ã…Å¸ signer/deÃ„Å¸iÃ…Å¸miÃ…Å¸ arÃ…Å¸iv/eski sÃƒÂ¼rÃƒÂ¼m reddedilsin; mÃƒÂ¼Ã…Å¸teri temiz makinede internetsiz veya yetkili registry ile kurabilsin; imza/anahtar iptali sÃ„Â±nansÃ„Â±n.
- Dış bağımlılık/sınır: Signer ve registry yetkisi; lisans onayÃ„Â±

#### T30 — HA, failover, kapasite ve SLA ÃƒÂ¶lÃƒÂ§ÃƒÂ¼mÃƒÂ¼ [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-07
- Kaynak: deploy/dashboard/server.mjs, deploy/README.md
- Güncel yerel durum: Load harness her fault senaryosu iÃƒÂ§in son hatadan sonra ardÃ„Â±Ã…Å¸Ã„Â±k recovery ve tam gÃƒÂ¶zlem istiyor; gerÃƒÂ§ek HA, kapasite ve aylÃ„Â±k SLA aÃƒÂ§Ã„Â±k.
- Başlangıç riski: HA topology, DB failover, tenant noisy-neighbor ve aylÃ„Â±k availability SLI kanÃ„Â±tÃ„Â± yok; 99.9 ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lmÃƒÂ¼Ã…Å¸ sonuÃƒÂ§ deÃ„Å¸il.
- Tamamlama hedefi: Desteklenen kapasite ve region topology tanÃ„Â±mla; load/soak/failover, hata bÃƒÂ¼tÃƒÂ§esi ve ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m paydasÃ„Â± kur.
- Zorunlu kapanış testi: GerÃƒÂ§ekÃƒÂ§i agent/event yÃƒÂ¼kÃƒÂ¼nde p50/p95/p99, hata/kayÃ„Â±p oranÃ„Â±, DB/servis/node arÃ„Â±zasÃ„Â± ve bakÃ„Â±m etkisi raporlansÃ„Â±n; kabul edilmiÃ…Å¸ gÃƒÂ¶zlem penceresi tamamlanmÃ„Â±Ã…Å¸ olsun.
- Dış bağımlılık/sınır: Host boyutlarÃ„Â±, filo/olay profili, SLA anlaÃ…Å¸masÃ„Â±

#### T31 — Migration, upgrade ve geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ tatbikatÃ„Â± [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-03, DEP-04
- Kaynak: scripts/deployment-migrate.mjs, scripts/deployment-doctor.mjs
- Güncel yerel durum: Kesilen rename resume yalnÃ„Â±z kaynak/staged iÃƒÂ§erik preflight hash'leriyle eÃ…Å¸leÃ…Å¸irse devam ediyor; gerÃƒÂ§ek trafik cutover/rollback kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Ãƒâ€“nceki mÃƒÂ¼Ã…Å¸teri sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼nden upgrade, sÃƒÂ¼rÃƒÂ¼m karmaÃ…Å¸asÃ„Â± ve gerÃƒÂ§ek ÃƒÂ¼retim rollback tatbikatÃ„Â± aÃƒÂ§Ã„Â±k.
- Tamamlama hedefi: Desteklenen upgrade yollarÃ„Â±, ÃƒÂ¶n kontrol/yedek, kesinti planÃ„Â±, kompatibilite ve baÃ…Å¸arÃ„Â±sÃ„Â±z migration geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ prosedÃƒÂ¼rÃƒÂ¼ hazÃ„Â±rla.
- Zorunlu kapanış testi: Eski veriyle upgrade, kesilen migration, checksum deÃ„Å¸iÃ…Å¸ikliÃ„Å¸i, uygulama/DB sÃƒÂ¼rÃƒÂ¼m uyuÃ…Å¸mazlÃ„Â±Ã„Å¸Ã„Â± ve kurtarma testi; veri kaybÃ„Â± ve sessiz schema drift olmasÃ„Â±n.
- Dış bağımlılık/sınır: Ãƒâ€“nceki sÃƒÂ¼rÃƒÂ¼m snapshotlarÃ„Â± ve bakÃ„Â±m penceresi

#### T32 — Ã„Â°zleme, alarm ve iÃ…Å¸letim sahipliÃ„Å¸i [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-01, DEP-02, OBS-01
- Kaynak: docs/runbooks/alerting.md, docs/runbooks/incident-response.md
- Güncel yerel durum: Per-instance scrape/readiness ve empty-discovery alertleri eklendi; kural YAML/testleri var. CanlÃ„Â± paging, isimli nÃƒÂ¶bet ve SLA aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Production dashboard, nÃƒÂ¶betÃƒÂ§i, gerÃƒÂ§ek paging, sertifika/disk/kuyruk/feed/backup alarmÃ„Â± ve incident tatbikatÃ„Â± tamamlanmadÃ„Â±.
- Tamamlama hedefi: SLI dashboard ve alarm eÃ…Å¸ikleri, sorumlu/nÃƒÂ¶bet takvimi, alarm sessizliÃ„Å¸i kontrolÃƒÂ¼, escalation ve olay sonrasÃ„Â± inceleme akÃ„Â±Ã…Å¸Ã„Â± kur.
- Zorunlu kapanış testi: Servis, DB, storage, signer, kuyruk ve yedek hatasÃ„Â± enjekte et; doÃ„Å¸ru kiÃ…Å¸iye zamanlÃ„Â± alarm ve ÃƒÂ§ÃƒÂ¶zÃƒÂ¼ldÃƒÂ¼ bildirimi gelsin; kayÃ„Â±tlÃ„Â± tatbikat tut.
- Dış bağımlılık/sınır: GerÃƒÂ§ek izleme/paging kanallarÃ„Â± ve isimli sorumlular

#### T33 — SatÃ„Â±lan fatura ve entitlement yaÃ…Å¸am dÃƒÂ¶ngÃƒÂ¼sÃƒÂ¼ [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: BIL-01, BIL-02, BIL-03
- Kaynak: packages/dashboard/src/ui/pages/BillingPage.tsx, supabase/functions/billing-checkout/index.ts, supabase/functions/stripe-webhook/index.ts
- Güncel yerel durum: billing-portal Edge Function provider-of-record durum makinesi, sunucu tarafi tenant/uyelik/rol/MFA cozumlemesi, istemci customer/tenant/subscription id reddi, TTL/idempotency, cancel/refund ve seat reconciliation uyguluyor; finance fixture ile test edildi, canli provider ve muhasebe onayi acik. Eski: Pending Finance sipariÃ…Å¸ sonucu tenant/request/quantity/quote alanlarÃ„Â±na fail-closed baÃ„Å¸lÃ„Â±; provider-of-record, ÃƒÂ¶deme makbuzu ve paid-to-entitlement yok.
- Başlangıç riski: OnaylÃ„Â± SKU/fiyat/teklif, tahsilat-mutabakat, quota deÃ„Å¸iÃ…Å¸imi, iptal ve ÃƒÂ§Ã„Â±kÃ„Â±Ã…Å¸ provasÃ„Â± yok. Self-service portal uygulanmamÃ„Â±Ã…Å¸; yalnÃ„Â±z satÃ„Â±lan SKU'da gerekiyorsa blocker.
- Tamamlama hedefi: Provider-of-record ve kurumsal sipariÃ…Å¸Ã¢â€ â€™quota iÃ…Å¸letimini tamamla; self-service satÃ„Â±lacaksa gerÃƒÂ§ek portal, invoice, cancel/refund/reconcile akÃ„Â±Ã…Å¸larÃ„Â±nÃ„Â± ekle.
- Zorunlu kapanış testi: SipariÃ…Å¸/ek koltuk/azaltma/yenileme/ÃƒÂ¶deme hatasÃ„Â±/iptal ve mÃƒÂ¼kerrer webhook aynÃ„Â± entitlement sonucunu versin; finans mutabakatÃ„Â± ve mÃƒÂ¼Ã…Å¸teri makbuzu eÃ…Å¸leÃ…Å¸sin.
- Dış bağımlılık/sınır: Ticari karar, canlÃ„Â± provider anahtarlarÃ„Â± ve muhasebe onayÃ„Â±

#### T34 — Readiness kayÃ„Â±tlarÃ„Â±nÃ„Â±n ve ÃƒÂ¼rÃƒÂ¼n iddialarÃ„Â±nÃ„Â±n tutarlÃ„Â±lÃ„Â±Ã„Å¸Ã„Â± [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: EVAL-02, EVAL-03, DEP-05
- Kaynak: docs/production-readiness/commercial-go-evidence-registry.json, READINESS_BACKLOG.json, README.md
- Güncel yerel durum: 71 ÃƒÂ¶zellik, 59 iÃ…Å¸ paketi, 10 release rootu ve claim candidate/expiry tutarlÃ„Â±lÃ„Â±Ã„Å¸Ã„Â± otomatik kontrol ediliyor; 13 dÃ„Â±Ã…Å¸ onay kapÃ„Â±sÃ„Â± aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Ticari registry AÃ„Å¸ustos tarihli ve artifactRoots/connector listesi mevcut dokuz paketi tam yansÃ„Â±tmÃ„Â±yor; eski checkout/default endpoint ifadeleri yeni implementasyonu anlatmÃ„Â±yor.
- Tamamlama hedefi: Tarihsel bulguyu korurken currentState alanlarÃ„Â±nÃ„Â± ayÃ„Â±r; beklenen paket/connector kapsamÃ„Â±nÃ„Â± release manifestinden tÃƒÂ¼ret; web, README, demo ve teklif metnini tek kanÃ„Â±t sÃƒÂ¶zlÃƒÂ¼Ã„Å¸ÃƒÂ¼ne baÃ„Å¸la.
- Zorunlu kapanış testi: AynÃ„Â± sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼n paket/ÃƒÂ¶zellik/claim sayÃ„Â±larÃ„Â± tutarlÃ„Â±; eksik paket zorunlu gate'i dÃƒÂ¼Ã…Å¸ÃƒÂ¼rsÃƒÂ¼n; sÃƒÂ¼resi dolmuÃ…Å¸/onaysÃ„Â±z iddia mÃƒÂ¼Ã…Å¸teri yÃƒÂ¼zÃƒÂ¼ne ÃƒÂ§Ã„Â±kmasÃ„Â±n.
- Dış bağımlılık/sınır: GÃƒÂ¼ncel release candidate ve ticari onay sahipleri

#### T35 — Test kapÃ„Â±larÃ„Â±nÃ„Â±n kapsamÃ„Â± ve baÃ…Å¸arÃ„Â±sÃ„Â±zlÃ„Â±Ã„Å¸Ã„Â±n saklanmamasÃ„Â± [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: EVAL-01, CON-05
- Kaynak: vitest.config.ts, packages/opencode/src/__tests__/aidr-contract.test.ts, scripts/verify-enforcement.mjs
- Güncel yerel durum: v7 birleÃ…Å¸ik test 237 dosya/3326 geÃƒÂ§iÃ…Å¸/2 aÃƒÂ§Ã„Â±klanmÃ„Â±Ã…Å¸ skip, coverage eÃ…Å¸ikleri ve 10 paket release consumer geÃƒÂ§ti; native kÃƒÂ¶r corpus aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Test sayÃ„Â±sÃ„Â± ÃƒÂ¶zellik tamamlanmasÃ„Â± deÃ„Å¸ildir; bazÃ„Â± gÃƒÂ¶zlem testleri bilinen boÃ…Å¸luÃ„Å¸u allow olarak kabul ediyor. Native/soak/baÃ„Å¸Ã„Â±msÃ„Â±z corpus ve coverage kapanÃ„Â±Ã…Å¸Ã„Â± eksik; 132 lint uyarÃ„Â±sÃ„Â± var.
- Tamamlama hedefi: Ãƒâ€“zellikÃ¢â€ â€™tÃƒÂ¼keticiÃ¢â€ â€™pozitif/negatifÃ¢â€ â€™artefact baÃ„Å¸Ã„Â±nÃ„Â± zorunlu kÃ„Â±l; bilinen aÃƒÂ§Ã„Â±klarÃ„Â± test hedefi yap; mandatory skip ve stale evidence gate'i dÃƒÂ¼Ã…Å¸ÃƒÂ¼rsÃƒÂ¼n; uyarÃ„Â±/dead-code borcunu sÃ„Â±nÃ„Â±flandÃ„Â±r.
- Zorunlu kapanış testi: Her satÃ„Â±lan ÃƒÂ¶zellik iÃƒÂ§in gerÃƒÂ§ek tÃƒÂ¼keticide deny/allow/outage kanÃ„Â±tÃ„Â±; aynÃ„Â± candidate checksum; 0 aÃƒÂ§Ã„Â±klanmamÃ„Â±Ã…Å¸ zorunlu skip; deÃ„Å¸iÃ…Å¸meyen timeoutlarla tekrar koÃ…Å¸u ve aÃƒÂ§Ã„Â±k borÃƒÂ§ kaydÃ„Â±.
- Dış bağımlılık/sınır: Native ortam, baÃ„Å¸Ã„Â±msÃ„Â±z corpus ve CI kapasitesi

#### T36 — OperatÃƒÂ¶r UI ve ilk mÃƒÂ¼Ã…Å¸teri kullanÃ„Â±labilirliÃ„Å¸i [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: CLI-01, TEN-07, TEN-03, POL-02, OBS-03
- Kaynak: packages/dashboard/src/main.tsx, packages/dashboard/src/ui/pages/OnboardingPage.tsx, packages/dashboard/src/enterprise/audit-view.tsx
- Güncel yerel durum: Onboarding stale token/tenant/error durumlarÃ„Â± fail-closed ve yapÃ„Â±landÃ„Â±rÃ„Â±lmÃ„Â±Ã…Å¸ Azure/Entra login gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r; gerÃƒÂ§ek browser/IdP/eriÃ…Å¸ilebilirlik kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: TÃƒÂ¼m desteklenen tarayÃ„Â±cÃ„Â±lar, klavye/eriÃ…Å¸ilebilirlik, aÃ„Å¸ hatalarÃ„Â±, ÃƒÂ§ok ekipli eÃ…Å¸ zamanlÃ„Â± kullanÃ„Â±m ve gerÃƒÂ§ek mÃƒÂ¼Ã…Å¸teri eÃ„Å¸itimi tamam deÃ„Å¸il.
- Tamamlama hedefi: Ekran bazlÃ„Â± loading/empty/error/permission sÃƒÂ¶zleÃ…Å¸mesi, eriÃ…Å¸ilebilirlik ve tarayÃ„Â±cÃ„Â± matrisi; ilk mÃƒÂ¼Ã…Å¸teri kÃ„Â±lavuzunu gerÃƒÂ§ek operatÃƒÂ¶rle uygula.
- Zorunlu kapanış testi: YanlÃ„Â±Ã…Å¸ ekipte sÃ„Â±r/politika gÃƒÂ¶rÃƒÂ¼nmesin; timeout/409/401 sonrasÃ„Â± yanlÃ„Â±Ã…Å¸ baÃ…Å¸arÃ„Â± olmasÃ„Â±n; klavye ile kritik iÃ…Å¸ler tamamlansÃ„Â±n; bÃƒÂ¼yÃƒÂ¼k liste ve uzun deÃ„Å¸erlerde UI bozulmasÃ„Â±n.
- Dış bağımlılık/sınır: Desteklenen browser ve mÃƒÂ¼Ã…Å¸teri kullanÃ„Â±cÃ„Â±larÃ„Â±

#### T37 — GerÃƒÂ§ek veri akÃ„Â±Ã…Å¸Ã„Â±, redaksiyon ve gizlilik kanÃ„Â±tÃ„Â± [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: OBS-01, OBS-03, OBS-06, TEN-01
- Kaynak: docs/privacy.md, packages/core/src/tracing.ts, supabase/functions/ingest/index.ts
- Güncel yerel durum: Privacy verifier canary boyunca source hash kararlÃ„Â±lÃ„Â±Ã„Å¸Ã„Â± ve temp support-bundle izolasyonu istiyor; 6 canary/13 bundle kontrolÃƒÂ¼ geÃƒÂ§ti, hukuk/saha aÃƒÂ§Ã„Â±k.
- Başlangıç riski: TÃƒÂ¼m outbound alan/domain listesi, browser tracing, managed olaylar, AIG payloadlarÃ„Â±, region, subprocessors ve silme kanÃ„Â±tÃ„Â± mÃƒÂ¼Ã…Å¸teri metinleriyle onaylanmadÃ„Â±.
- Tamamlama hedefi: Alan bazlÃ„Â± data-flow ve egress envanteri ÃƒÂ§Ã„Â±kar; ham prompt/komut/secret canary'leriyle paket/log/export/support bundle sÃƒÂ¶zleÃ…Å¸mesi kur; metinleri gerÃƒÂ§ek iÃ…Å¸leyiÃ…Å¸e eÃ…Å¸le.
- Zorunlu kapanış testi: Canary sÃ„Â±rlar izinsiz kanalda bulunmasÃ„Â±n; opt-out ve retention davranÃ„Â±Ã…Å¸Ã„Â± ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lsÃƒÂ¼n; bÃƒÂ¼tÃƒÂ¼n veri sÃ„Â±nÃ„Â±flarÃ„Â± iÃƒÂ§in bÃƒÂ¶lge/eriÃ…Å¸im/silme sahibi belli olsun.
- Dış bağımlılık/sınır: DPA ve mÃƒÂ¼Ã…Å¸teri veri sÃ„Â±nÃ„Â±flandÃ„Â±rmasÃ„Â±; hukuk incelemesi

#### T38 — Kuruma ÃƒÂ¶zel DLP ve veri etiketleri [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DET-07
- Kaynak: packages/core/src/dlp/index.ts, packages/core/src/pii-detector.ts
- Güncel yerel durum: DLP overlapping ve JSON Unicode-escaped secret spanlarÃ„Â±nÃ„Â± tam redact ediyor; malformed/mapping/oversize fail-closed. Attachment/diÃ„Å¸er connector/mÃƒÂ¼Ã…Å¸teri label kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: MÃƒÂ¼Ã…Å¸teri etiketleri, belge/attachment tÃƒÂ¼rleri, her baÃ„Å¸layÃ„Â±cÃ„Â±daki giriÃ…Å¸/ÃƒÂ§Ã„Â±kÃ„Â±Ã…Å¸ yolu ve dÃƒÂ¼Ã…Å¸ÃƒÂ¼k yanlÃ„Â±Ã…Å¸ alarm kabulÃƒÂ¼ tamam deÃ„Å¸il.
- Tamamlama hedefi: Kural/etiket yÃƒÂ¶netimi, kapsam hedefleri, maskeleme/engelleme/approval eylemleri ve exception yaÃ…Å¸am dÃƒÂ¶ngÃƒÂ¼sÃƒÂ¼nÃƒÂ¼ baÃ„Å¸la.
- Zorunlu kapanış testi: Sentetik ve kuruma ÃƒÂ¶zgÃƒÂ¼ sÃ„Â±rlar tÃƒÂ¼m kapsanan giriÃ…Å¸/ÃƒÂ§Ã„Â±kÃ„Â±Ã…Å¸larda yakalansÃ„Â±n; yetkili benign iÃ…Å¸lem geÃƒÂ§sin; ÃƒÂ¶rnek dÃ„Â±Ã…Å¸Ã„Â± format unavailable olarak raporlansÃ„Â±n.
- Dış bağımlılık/sınır: Etiket/kural sÃƒÂ¶zlÃƒÂ¼Ã„Å¸ÃƒÂ¼ ve maskelenmiÃ…Å¸ test verisi

#### T39 — BaÃ„Å¸Ã„Â±msÃ„Â±z etkinlik, performans ve rakip kÃ„Â±yaslamasÃ„Â± [P1; OPEN]

- İlgili özellikler: EVAL-01, EVAL-02, EVAL-03
- Kaynak: docs/production-readiness/agent-security-market-and-release-plan.md, docs/production-readiness/customer-investor-validation-master-plan.md
- Güncel yerel durum: Pazar yetenek kategorileri ve ÃƒÂ¶nerilen benchmark protokolÃƒÂ¼ belgeli.
- Başlangıç riski: En iyi ÃƒÂ¼rÃƒÂ¼n, sÃ„Â±fÃ„Â±r false-positive, evasion dayanÃ„Â±klÃ„Â±lÃ„Â±Ã„Å¸Ã„Â± veya latency ÃƒÂ¼stÃƒÂ¼nlÃƒÂ¼Ã„Å¸ÃƒÂ¼nÃƒÂ¼ gÃƒÂ¶steren baÃ„Å¸Ã„Â±msÃ„Â±z kanÃ„Â±t yok.
- Tamamlama hedefi: GeliÃ…Å¸tirme ve blind holdout setlerini ayÃ„Â±r; saldÃ„Â±rÃ„Â± ailesi/baÃ„Å¸layÃ„Â±cÃ„Â± bazÃ„Â±nda coverage, false block/approval, p50/p95/p99 ve limitations ÃƒÂ¶lÃƒÂ§; eÃ…Å¸it koÃ…Å¸ullu karÃ…Å¸Ã„Â±laÃ…Å¸tÃ„Â±rma yap.
- Zorunlu kapanış testi: AynÃ„Â± workload/ortamda ham ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m, payda, sÃƒÂ¼rÃƒÂ¼m, ÃƒÂ¶rneklem ve baÃ„Å¸Ã„Â±msÃ„Â±z deÃ„Å¸erlendirici imzasÃ„Â±; gÃƒÂ¶rÃƒÂ¼nmeyen yÃƒÂ¼zeyler baÃ…Å¸arÃ„Â± ortalamasÃ„Â±na katÃ„Â±lmasÃ„Â±n.
- Dış bağımlılık/sınır: MÃƒÂ¼Ã…Å¸teri benign corpus'u, rakip deÃ„Å¸erlendirme eriÃ…Å¸imi, ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m bÃƒÂ¼tÃƒÂ§esi

#### T40 — GÃƒÂ¼venlik gÃƒÂ¼ncellemesi ve mÃƒÂ¼Ã…Å¸teri destek iÃ…Å¸letimi [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-05, OBS-05
- Kaynak: docs/runbooks/incident-response.md, docs/production-readiness/support-sla-template.md
- Güncel yerel durum: Support v7 runbook, izinli/hashli bundle, escalation ve emergency update akÃ„Â±Ã…Å¸Ã„Â± hazÃ„Â±r; gerÃƒÂ§ek kanal, nÃƒÂ¶bet ve ticket tatbikatÃ„Â± aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Ãƒâ€¡alÃ„Â±Ã…Å¸an ticket/security contact, nÃƒÂ¶bet, CVE/incident bildirimi, imzalÃ„Â± acil gÃƒÂ¼ncelleme, EOL ve tanÃ„Â±lama izni iÃ…Å¸letimi onaylÃ„Â± deÃ„Å¸il.
- Tamamlama hedefi: Destek planÃ„Â±, severity/response hedefi, escalation, PSIRT/sorumlu, patch daÃ„Å¸Ã„Â±tÃ„Â±mÃ„Â±, EOL ve redakte tanÃ„Â±lama prosedÃƒÂ¼rÃƒÂ¼ kur.
- Zorunlu kapanış testi: GerÃƒÂ§ek ticket aÃƒÂ§/kapat, kritik incident ve imza anahtarÃ„Â± kaybÃ„Â± tatbikatÃ„Â±; mÃƒÂ¼Ã…Å¸teri bildirim sÃƒÂ¼resi, rollback ve sÃ„Â±r iÃƒÂ§ermeyen tanÃ„Â±lama kanÃ„Â±tlansÃ„Â±n.
- Dış bağımlılık/sınır: Ã„Â°simli ekip, iletiÃ…Å¸im kanallarÃ„Â±, sÃƒÂ¶zleÃ…Å¸me ve ÃƒÂ§alÃ„Â±Ã…Å¸ma saatleri

#### T41 — Ã„Â°lk mÃƒÂ¼Ã…Å¸teri satÃ„Â±Ã…Å¸ ve satÃ„Â±n alma deÃ„Å¸erlendirme paketi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: EVAL-02, EVAL-03, BIL-01
- Kaynak: docs/production-readiness/controlled-demo-runbook.md, docs/production-readiness/customer-investor-validation-master-plan.md, docs/production-readiness/enterprise-order-entitlement-template.md
- Güncel yerel durum: GÃƒÂ¼ncel ilk mÃƒÂ¼Ã…Å¸teri satÃ„Â±Ã…Å¸ paketi ve portable kit ÃƒÂ¼reticisi var; yeni v7 kit imzasÃ„Â± ile onaylÃ„Â± teklif/satÃ„Â±n alma kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: MÃƒÂ¼Ã…Å¸terinin satÃ„Â±n alma sÃƒÂ¼recine uygun onaylÃ„Â± ÃƒÂ¼rÃƒÂ¼n ÃƒÂ¶zeti, mimari/veri akÃ„Â±Ã…Å¸Ã„Â±, destek matrisi, gÃƒÂ¼venlik soru formu, kapsamlÃ„Â± teklif ve kanÃ„Â±ta dayalÃ„Â± demo/PoV paketi tek sÃƒÂ¼rÃƒÂ¼mde birleÃ…Å¸tirilmedi. Bu ÃƒÂ§alÃ„Â±Ã…Å¸ma ortamÃ„Â±ndaki static preflight satÃ„Â±Ã…Å¸ URL/e-posta ayarÃ„Â± bulamadÃ„Â±; ÃƒÂ¼retim satÃ„Â±Ã…Å¸ CTA hedefi ayrÃ„Â±ca doÃ„Å¸rulanmalÃ„Â±.
- Tamamlama hedefi: ÃƒÅ“rÃƒÂ¼n ÃƒÂ¶zeti, gereksinimler, deployment seÃƒÂ§enekleri, desteklenen araÃƒÂ§lar, aÃƒÂ§Ã„Â±k sÃ„Â±nÃ„Â±rlar, gÃƒÂ¼venlik/tedarikÃƒÂ§i soru yanÃ„Â±tlarÃ„Â±, teklif ve PoV baÃ…Å¸arÃ„Â± ÃƒÂ¶lÃƒÂ§ÃƒÂ¼tlerini satÃ„Â±Ã…Å¸ kitinde topla; ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lmemiÃ…Å¸ ROI veya sertifikasyon iddiasÃ„Â± ekleme.
- Zorunlu kapanış testi: Bir operatÃƒÂ¶r kÃ„Â±lavuzdan demoyu tekrar edebilsin; procurement sorularÃ„Â± kaynak/kanÃ„Â±t/owner'a baÃ„Å¸lÃ„Â± olsun; teklif kapsamÃ„Â± ile kurulan ÃƒÂ¶zellik ve destek koÃ…Å¸ullarÃ„Â± eÃ…Å¸leÃ…Å¸sin; mÃƒÂ¼Ã…Å¸teri adÃ„Â± olmadan referans/baÃ…Å¸arÃ„Â± hikayesi uydurulmasÃ„Â±n.
- Dış bağımlılık/sınır: MÃƒÂ¼Ã…Å¸teri satÃ„Â±n alma formu, teklif sahibi, onaylÃ„Â± ÃƒÂ¼rÃƒÂ¼n kapsamÃ„Â±

#### T42 — Legacy RLS tenant yaÃ…Å¸am dÃƒÂ¶ngÃƒÂ¼sÃƒÂ¼ ve itibar satÃ„Â±rÃ„Â± sahteciliÃ„Å¸i [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-01, DET-10, DET-11
- Kaynak: supabase/migrations/20260912000019_tenant_lifecycle_rls.sql, scripts/tenant-lifecycle-rls-postgres.test.mjs
- Güncel yerel durum: Eski izin verici RLS kaldÃ„Â±rÃ„Â±ldÃ„Â±; forged claim, expired member, suspended tenant ve service-role kontrolleri yerel PostgreSQL'de geÃƒÂ§ti. Saha migrationÃ„Â± aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Yeni migration yetkiyi kapatÃ„Â±r; ÃƒÂ¶nceden yazÃ„Â±lmÃ„Â±Ã…Å¸ olabilecek sahte satÃ„Â±rlar otomatik temizlenmez ve kurulu mÃƒÂ¼Ã…Å¸teri verisi denetlenmedi.
- Tamamlama hedefi: MigrationÃ„Â± uygulamadan ÃƒÂ¶nce tenant itibar satÃ„Â±rlarÃ„Â±nÃ„Â± denetle; migrationÃ„Â± kontrollÃƒÂ¼ uygula, kalÃ„Â±cÃ„Â± rol matrisi ve PostgREST negatif testini ÃƒÂ§alÃ„Â±Ã…Å¸tÃ„Â±r.
- Zorunlu kapanış testi: Eski ÃƒÂ¼ye veya askÃ„Â±ya alÃ„Â±nmÃ„Â±Ã…Å¸ tenant okuyamasÃ„Â±n; baÃ…Å¸ka tenant iÃƒÂ§in insert reddedilsin; mevcut veride sahte kayÃ„Â±t kalmasÃ„Â±n ve servis rolÃƒÂ¼ iÃ…Å¸lemleri ÃƒÂ§alÃ„Â±Ã…Å¸sÃ„Â±n.
- Dış bağımlılık/sınır: Mevcut deployment verisi ve migration penceresi

#### T43 — Enrollment exchange iÃ…Å¸lem bÃƒÂ¼tÃƒÂ¼nlÃƒÂ¼Ã„Å¸ÃƒÂ¼ [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-05, TEN-06
- Kaynak: supabase/migrations/20260912000017_enrollment_exchange_atomic.sql, supabase/functions/enroll/index.ts
- Güncel yerel durum: Atomik token/seat/key RPC ve lost-response sonucu unknown sÃƒÂ¶zleÃ…Å¸mesi var; plaintext-key recovery protokolÃƒÂ¼ ve canlÃ„Â± HTTP kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Yeni RPC atomik yazÃ„Â±yor; mÃƒÂ¼Ã…Å¸teri HTTP akÃ„Â±Ã…Å¸Ã„Â±nda kayÃ„Â±p yanÃ„Â±t, eski kayÃ„Â±t ve eÃ…Å¸zamanlÃ„Â± seat yarÃ„Â±Ã…Å¸Ã„Â± henÃƒÂ¼z sÃ„Â±nanmadÃ„Â±.
- Tamamlama hedefi: MigrationÃ„Â± daÃ„Å¸Ã„Â±t, canlÃ„Â± HTTP hata enjeksiyonuyla token/seat/key durumunu doÃ„Å¸rula, belirsiz commit sonrasÃ„Â± yeniden kayÃ„Â±t operatÃƒÂ¶r prosedÃƒÂ¼rÃƒÂ¼nÃƒÂ¼ hazÃ„Â±rla.
- Zorunlu kapanış testi: Hata rollback yaparken token yeniden kullanÃ„Â±labilsin; baÃ…Å¸arÃ„Â±da yalnÃ„Â±z bir kimlik oluÃ…Å¸sun; kayÃ„Â±p yanÃ„Â±t aÃƒÂ§Ã„Â±k unknown durumuna dÃƒÂ¼Ã…Å¸sÃƒÂ¼n.
- Dış bağımlılık/sınır: MÃƒÂ¼Ã…Å¸teri kurulum ortamÃ„Â± ve canlÃ„Â± DB

#### T44 — Entitlement grace ve eski imzalÃ„Â± ÃƒÂ¶nbellek geÃƒÂ§iÃ…Å¸i [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-05, POL-04
- Kaynak: supabase/functions/enroll/index.ts, supabase/functions/ingest/index.ts, packages/core/src/managed.ts
- Güncel yerel durum: Cache unsigned/unknown/schema-invalid entitlement'Ã„Â± atÃ„Â±yor; kesin invalid_api_key signed state'i temizliyor, geÃƒÂ§ici hata grace'i koruyor. CanlÃ„Â± kabul aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Kod dÃƒÂ¼zeltildi; ÃƒÂ¶nceki yanlÃ„Â±Ã…Å¸ imzalÃ„Â± snapshotlar ÃƒÂ§evrimdÃ„Â±Ã…Å¸Ã„Â± iken dÃƒÂ¼zelmez, canlÃ„Â± Deno ve zaman geÃƒÂ§iÃ…Å¸i kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Tamamlama hedefi: Yeni entitlementlarÃ„Â± daÃ„Å¸Ã„Â±tÃ„Â±p ÃƒÂ¶nbelleÃ„Å¸i gÃƒÂ¼venli yenile; saat sÃ„Â±nÃ„Â±rÃ„Â± ve eski istemci geÃƒÂ§iÃ…Å¸i tatbikatÃ„Â± yap.
- Zorunlu kapanış testi: 168 saat sonrasÃ„Â±nda 72 saat grace, ardÃ„Â±ndan deny; iptal edilen/bozuk anahtar her aÃ…Å¸amada reddedilsin.
- Dış bağımlılık/sınır: Ã„Â°mzalÃ„Â± eski kayÃ„Â±tlar ve mÃƒÂ¼Ã…Å¸teri aÃ„Å¸ takvimi

#### T45 — Device-start gÃƒÂ¼venilir IP ve giriÃ…Å¸ yÃƒÂ¶nlendirmesi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-05, DEP-01, DEP-02
- Kaynak: supabase/functions/device-start/index.ts, deploy/ingress/device-start.mjs
- Güncel yerel durum: Device-start signer placeholder/reused secret'i reddediyor; HMAC ingress/rate limit var. GerÃƒÂ§ek public proxy/TLS routing ve mÃƒÂ¼Ã…Å¸teri yÃƒÂ¼kÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Ã„Â°mzalÃ„Â± ingress ve kÃƒÂ¼resel sÃ„Â±nÃ„Â±r kodlandÃ„Â±; Nginx/TLS yÃƒÂ¶nlendirmesi ve iki ÃƒÂ¶zel anahtarÃ„Â±n mÃƒÂ¼Ã…Å¸teri ortamÃ„Â±nda kurulumu henÃƒÂ¼z kanÃ„Â±tlanmadÃ„Â±.
- Tamamlama hedefi: Cloud ve self-hosted giriÃ…Å¸ini signer ÃƒÂ¼zerinden geÃƒÂ§ir; proxy baÃ…Å¸lÃ„Â±klarÃ„Â±nÃ„Â± temizle, doÃ„Å¸rudan Edge yolunu engelle ve yÃƒÂ¼k testini ÃƒÂ§alÃ„Â±Ã…Å¸tÃ„Â±r.
- Zorunlu kapanış testi: Sahte baÃ…Å¸lÃ„Â±klar oranÃ„Â± deÃ„Å¸iÃ…Å¸tirmesin; imzasÃ„Â±z istek 401; meÃ…Å¸ru kayÃ„Â±t akÃ„Â±Ã…Å¸Ã„Â± iki daÃ„Å¸Ã„Â±tÃ„Â±m modelinde ÃƒÂ§alÃ„Â±Ã…Å¸sÃ„Â±n.
- Dış bağımlılık/sınır: TLS proxy, sÃ„Â±r yÃƒÂ¶netimi ve mÃƒÂ¼Ã…Å¸teri aÃ„Å¸Ã„Â±

#### T46 — Device-poll onaydan kayda atomik geÃƒÂ§iÃ…Å¸ [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-05
- Kaynak: supabase/functions/device-poll/index.ts, supabase/migrations/20260912000017_enrollment_exchange_atomic.sql
- Güncel yerel durum: Device-poll kayÃ„Â±p yanÃ„Â±t/eÃ…Å¸zamanlÃ„Â± poll'da aynÃ„Â± hash-only tokenÃ„Â± geri buluyor, lookup hatasÃ„Â±nda 503 unknown dÃƒÂ¶nÃƒÂ¼yor; canlÃ„Â± yarÃ„Â±Ã…Å¸ kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Başlangıç riski: Yeni RPC atomik; canlÃ„Â± HTTP retry, yarÃ„Â±Ã…Å¸ ve mÃƒÂ¼Ã…Å¸teri tarayÃ„Â±cÃ„Â±sÃ„Â±/CLI kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.
- Tamamlama hedefi: MigrationÃ„Â± daÃ„Å¸Ã„Â±tÃ„Â±p onay, poll ve enroll tam akÃ„Â±Ã…Å¸Ã„Â±nÃ„Â± hata enjeksiyonu ile ÃƒÂ§alÃ„Â±Ã…Å¸tÃ„Â±r; eÃ…Å¸zamanlÃ„Â± poll ve kayÃ„Â±p yanÃ„Â±tÃ„Â± ÃƒÂ¶lÃƒÂ§.
- Zorunlu kapanış testi: Bir onay en ÃƒÂ§ok bir token ÃƒÂ¼retir; insert hatasÃ„Â± oturumu tÃƒÂ¼ketmez; tekrar poll belirsiz durum olarak raporlanÃ„Â±r.
- Dış bağımlılık/sınır: CanlÃ„Â± kurulum ve gerÃƒÂ§ek cihaz

### Faz 4 — Açık readiness backlog

Bu kayıtlar teknik matrisle örtüşebilir. Yeni benzersiz task gibi iki kez sayma; ilgili T satırına bağla. Acceptance gerçekten karşılanırsa evidence ekleyip VERIFIED_CLOSED yap. Temiz commit, gerçek müşteri veya dış ortam isteyen kaydı local unit test ile kapatma.

- **AIDR-016 — Enrollment / control-plane connectivity (default endpoint) [P0; BLOCKED_EXTERNAL]**: A fresh install either completes device enrollment against a reachable endpoint and shows the verification URL+code, or clearly reports local-only protection. No silent 'auth_required' dead end.
- **AIDR-019 — Dashboard/Edge-Function contract completeness [P1; BLOCKED_EXTERNAL]**: No UI code invokes a non-existent function; device enrollment completes end-to-end from the browser; every invoked function has a contract test in the release manifest.
- **AIDR-044 — Encrypted backup and validated restore [P0; BLOCKED_EXTERNAL]**: Restore database and objects to an independent environment; prove retention, key recovery and agreed RPO/RTO.
- **AIDR-049 — Production deployment and native host acceptance [P0; BLOCKED_EXTERNAL]**: Customer/cloud HTTPS onboarding, SMTP/IdP, supported host/OS canaries and failover evidence for the sold candidate.
- **AIDR-050 — Enterprise fleet installers and updates [P1; BLOCKED_EXTERNAL]**: MDM distribution, signed updates, policy-preserving rollback and uninstall across supported hosts.
- **AIDR-051 — Continuous agent discovery and delegated credential scope [P1; BLOCKED_EXTERNAL]**: Scheduled fleet/cloud collectors with freshness and identity; short-lived least-privilege tool credentials.
- **AIDR-052 — Measured availability, scale and isolation under load [P0; IN_PROGRESS]**: Defined workload and observation window, HA/failover, tenant noisy-neighbor tests and agreed availability evidence.

### Faz 5 — Ticari ve dış kanıt kapıları

Kod, validator, runbook, template ve receipt şemasıyla hazırlanabilecek her şeyi hazırla. Yetkili kişi veya gerçek dış sistem olmadan status=open kalmalıdır. Sahte isim, müşteri, imza, tarih, ticket, pentest, SLA ölçümü, ödeme veya onay üretme.

#### COM-001 — OnaylÃ„Â± SKU, fiyat, teklif ve ticari sÃƒÂ¼rÃƒÂ¼m manifesti [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Commercial/Sales + Finance/Billing
- Eksik: AynÃ„Â± sÃƒÂ¼rÃƒÂ¼me baÃ„Å¸lÃ„Â± SKU, fiyat, ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m birimi, para birimi/vergi, kurulum modeli, bÃƒÂ¶lge, saklama, SLA, destek, lisans hakkÃ„Â±, yenileme, iptal ve ÃƒÂ§Ã„Â±kÃ„Â±Ã…Å¸ koÃ…Å¸ullarÃ„Â± onaylanmamÃ„Â±Ã…Å¸.
- Hazırlanacak iş: SatÃ„Â±Ã…Å¸ ve finans tek ticari manifesti onaylasÃ„Â±n; ÃƒÂ¶rnek teklif/sipariÃ…Å¸ten mÃƒÂ¼Ã…Å¸teri ÃƒÂ§Ã„Â±kÃ„Â±Ã…Å¸Ã„Â±na kadar prova yapÃ„Â±lsÃ„Â±n.
- Kapanış kanıtı: Ã„Â°simli onaylÃ„Â± ticari manifest; Ãƒâ€“rnek teklif ve sipariÃ…Å¸; SipariÃ…Å¸ten offboarding'e prova; SÃƒÂ¼rÃƒÂ¼m ve deÃ„Å¸iÃ…Å¸tirilemeyen kanÃ„Â±t ÃƒÂ¶zeti
- Otomatik kontrol: claim-check --mode=gate plus signed-manifest verification

#### COM-002 — Lisans, fikri mÃƒÂ¼lkiyet ve ÃƒÂ¼ÃƒÂ§ÃƒÂ¼ncÃƒÂ¼ taraf haklarÃ„Â± [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Legal + Engineering
- Eksik: Lisans dosyasÃ„Â± bulunmasÃ„Â± yeterli deÃ„Å¸il: daÃ„Å¸Ã„Â±tÃ„Â±lan kod/veri/model/ÃƒÂ¼ÃƒÂ§ÃƒÂ¼ncÃƒÂ¼ taraf bileÃ…Å¸en haklarÃ„Â±, atÃ„Â±flar ve fikri mÃƒÂ¼lkiyet zinciri hukukÃƒÂ§a onaylanmamÃ„Â±Ã…Å¸.
- Hazırlanacak iş: SBOM ve kaynak kÃƒÂ¶kenini lisans/NOTICE/package metadata ile uzlaÃ…Å¸tÃ„Â±r; daÃ„Å¸Ã„Â±tÃ„Â±m haklarÃ„Â±nÃ„Â± ve sÃƒÂ¼reli istisnalarÃ„Â± yetkili hukuk incelemesine sun.
- Kapanış kanıtı: Hukuk onayÃ„Â±; Eksiksiz LICENSE/NOTICE ve ÃƒÂ¼ÃƒÂ§ÃƒÂ¼ncÃƒÂ¼ taraf lisans paketi; Paket lisanslarÃ„Â±nÃ„Â±n uzlaÃ…Å¸tÃ„Â±rÃ„Â±lmasÃ„Â±; Kaynak/vendor kÃƒÂ¶keni ve sÃƒÂ¼reli istisna kaydÃ„Â±
- Otomatik kontrol: claim-check --mode=gate (license/NOTICE/package metadata check) plus licence inventory

#### COM-003 — Veri iÃ…Å¸leme, DPA ve gizlilik onayÃ„Â± [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Privacy/DPO + Legal + Security
- Eksik: GerÃƒÂ§ek telemetri, browser tracing, managed olaylar, AIG payloadlarÃ„Â±, retention/silme, veri bÃƒÂ¶lgesi, alt iÃ…Å¸leyenler ve transferler mÃƒÂ¼Ã…Å¸teri belgeleriyle onaylÃ„Â± biÃƒÂ§imde eÃ…Å¸leÃ…Å¸tirilmemiÃ…Å¸.
- Hazırlanacak iş: Alan bazlÃ„Â± veri akÃ„Â±Ã…Å¸Ã„Â±nÃ„Â± ÃƒÂ¶lÃƒÂ§; mÃƒÂ¼Ã…Å¸teri bildirimi ve gerekli veri iÃ…Å¸leme/gÃƒÂ¼venlik eklerini Privacy/Legal sahipleriyle tamamla.
- Kapanış kanıtı: Alan bazlÃ„Â± veri akÃ„Â±Ã…Å¸ matrisi ve payload testleri; DPA/TOM/SCC kapsam inceleme ve onayÃ„Â±; Alt iÃ…Å¸leyen/bÃƒÂ¶lge listesi; GerÃƒÂ§ek export ve silme makbuzu
- Otomatik kontrol: privacy-payload-contract and outbound-domain/redaction gates

#### COM-004 — FaturaÃ¢â‚¬â€œÃƒÂ¶demeÃ¢â‚¬â€œentitlement mutabakatÃ„Â± [open]

- Profiller: assisted-sale, production-ga, investor
- Sorumlu: Finance/Billing + Product
- Eksik: SipariÃ…Å¸, koltuk deÃ„Å¸iÃ…Å¸imi, fatura/mutabakat, iptal, eriÃ…Å¸im iptali ve mÃƒÂ¼Ã…Å¸teri silme tek kayÃ„Â±t sistemine gÃƒÂ¶re uÃƒÂ§tan uca kabul edilmemiÃ…Å¸.
- Hazırlanacak iş: Tek provider-of-record belirle; finans iÃ…Å¸lemlerini sunucudaki entitlement ile baÃ„Å¸la; baÃ…Å¸arÃ„Â±sÃ„Â±z/tekrarlanan olay ve manuel mÃƒÂ¼dahale iÃ…Å¸letimini tanÃ„Â±mla.
- Kapanış kanıtı: Provider ve SKU kararÃ„Â±; Quota/entitlement senaryolarÃ„Â±; Fatura ve mutabakat ÃƒÂ¶rneÃ„Å¸i; Ã„Â°ptal, eriÃ…Å¸im kesme ve silme makbuzu
- Otomatik kontrol: billing contract suite and quote-to-offboarding rehearsal

#### COM-005 — Ãƒâ€¡alÃ„Â±Ã…Å¸an destek ve mÃƒÂ¼Ã…Å¸teri iletiÃ…Å¸im yollarÃ„Â± [open]

- Profiller: evaluation, assisted-sale, production-ga
- Sorumlu: Support/Customer Success + Operations
- Eksik: MÃƒÂ¼Ã…Å¸terinin gerÃƒÂ§ekten ulaÃ…Å¸abildiÃ„Å¸i destek, durum sayfasÃ„Â±, gÃƒÂ¼venlik iletiÃ…Å¸imi, privacy/terms, escalation, severity hedefi ve tanÃ„Â±lama izni iÃ…Å¸letimi kanÃ„Â±tlanmamÃ„Â±Ã…Å¸.
- Hazırlanacak iş: KanallarÃ„Â± yayÃ„Â±nla; ÃƒÂ§alÃ„Â±Ã…Å¸ma saatleri ve isimli nÃƒÂ¶bet/escalation sorumlularÃ„Â±nÃ„Â± ata; gerÃƒÂ§ek ticket tatbikatÃ„Â± yap.
- Kapanış kanıtı: YayÃ„Â±nlanmÃ„Â±Ã…Å¸ destek/SLA planÃ„Â±; Zaman damgalÃ„Â± ticket tatbikatÃ„Â±; Ãƒâ€¡alÃ„Â±Ã…Å¸an status/security/privacy baÃ„Å¸lantÃ„Â±larÃ„Â±; NÃƒÂ¶bet ve escalation kaydÃ„Â±
- Otomatik kontrol: deployed route/link crawl; ticket drill is manual evidence

#### COM-010 — ReklamÃ„Â± yapÃ„Â±lan tÃƒÂ¼m baÃ„Å¸layÃ„Â±cÃ„Â±larÃ„Â±n kabulÃƒÂ¼ [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Product + QA + Engineering + Support
- Eksik: ReklamÃ„Â± yapÃ„Â±lan baÃ„Å¸layÃ„Â±cÃ„Â±larÃ„Â±n her biri iÃƒÂ§in gerÃƒÂ§ek host desteÃ„Å¸i, imzalÃ„Â± paket, ÃƒÂ¶zel registry kurulumu, geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ ve destek sahibi tamam deÃ„Å¸il. Registry'nin kapsam listesi ayrÃ„Â±ca gÃƒÂ¼ncellenmeli.
- Hazırlanacak iş: SatÃ„Â±lan connector manifestini sabitle; her connector/host/OS sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼nde aynÃ„Â± imzalÃ„Â± candidate iÃƒÂ§in kurulum, native E2E, rollback ve disable kabulÃƒÂ¼ topla.
- Kapanış kanıtı: Tam destek matrisi; GerÃƒÂ§ek host test raporlarÃ„Â±; Private registry kurulum kayÃ„Â±tlarÃ„Â±; Rollback/disable tatbikatÃ„Â±; Ã„Â°simli sahip ve sÃ„Â±nÃ„Â±rlar
- Otomatik kontrol: expected connector manifest, package consumer tests, real-host E2E and claim-check

#### COM-011 — BÃƒÂ¶lge ve veri yerleÃ…Å¸imi kanÃ„Â±tÃ„Â± [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Operations + Privacy/DPO + Legal
- Eksik: Registry'deki EU/US/APAC hedefleri ÃƒÂ§alÃ„Â±Ã…Å¸an ve onaylÃ„Â± bÃƒÂ¶lge hizmeti kanÃ„Â±tÃ„Â± deÃ„Å¸ildir; tenant yerleÃ…Å¸imi, routing, yedek/silme ve transfer modeli aÃƒÂ§Ã„Â±k.
- Hazırlanacak iş: SatÃ„Â±lacak bÃƒÂ¶lgeleri provider ve veri iÃ…Å¸leme modeliyle eÃ…Å¸le; her bÃƒÂ¶lgede tenant yerleÃ…Å¸imi ve sÃ„Â±nÃ„Â±r dÃ„Â±Ã…Å¸Ã„Â± eriÃ…Å¸im negatif testlerini tamamla.
- Kapanış kanıtı: BÃƒÂ¶lge/provider matrisi; Tenant yerleÃ…Å¸im testi; Cross-region negatif test; Veri iÃ…Å¸leme onaylarÃ„Â±; BÃƒÂ¶lgeye baÃ„Å¸lÃ„Â± yedek/silme makbuzlarÃ„Â±
- Otomatik kontrol: region manifest, outbound-domain/data-flow assertions and deployment smoke per region

#### COM-012 — FaturalÃ„Â± ve kimliÃ„Å¸i doÃ„Å¸rulanan ÃƒÂ¶zel daÃ„Å¸Ã„Â±tÃ„Â±m [open]

- Profiller: assisted-sale, production-ga, investor
- Sorumlu: Finance/Billing + Release Engineering + Support
- Eksik: Kurumsal fatura ile verilen eriÃ…Å¸imin kimliÃ„Å¸i doÃ„Å¸rulanan private registry ve imzalÃ„Â± artefact teslimiyle ÃƒÂ§alÃ„Â±Ã…Å¸tÃ„Â±Ã„Å¸Ã„Â± kanÃ„Â±tlanmamÃ„Â±Ã…Å¸; air-gap prosedÃƒÂ¼rÃƒÂ¼ de tamam deÃ„Å¸il.
- Hazırlanacak iş: SipariÃ…Å¸Ã¢â€ â€™entitlementÃ¢â€ â€™downloadÃ¢â€ â€™installÃ¢â€ â€™revoke/offboard zincirini gerÃƒÂ§ek mÃƒÂ¼Ã…Å¸teri eriÃ…Å¸im modeliyle tamamla; offline satÃ„Â±lÃ„Â±yorsa imaj/baÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k teslimini ekle.
- Kapanış kanıtı: Provider ve registry kararÃ„Â±; Faturadan entitlement'a test; Ã„Â°mzalÃ„Â± paket kurulumu; Ã„Â°ptal/offboarding testi; DoÃ„Å¸rulanmÃ„Â±Ã…Å¸ air-gap prosedÃƒÂ¼rÃƒÂ¼
- Otomatik kontrol: private-registry consumer install and entitlement contract suite

#### COM-013 — 99.9% SLA iÃƒÂ§in ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m ve sÃƒÂ¶zleÃ…Å¸me [open]

- Profiller: assisted-sale, production-ga, investor
- Sorumlu: Operations + Legal + Support + Finance
- Eksik: 99.9% aylÃ„Â±k availability bir hedef; ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lmÃƒÂ¼Ã…Å¸ SLI, payda, kapsam dÃ„Â±Ã…Å¸Ã„Â± durumlar, bakÃ„Â±m politikasÃ„Â±, servis kredisi ve incident kanÃ„Â±tÃ„Â± tamam deÃ„Å¸il.
- Hazırlanacak iş: SRE/Legal/Support/Finance ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m ve sÃƒÂ¶zleÃ…Å¸me kapsamÃ„Â±nÃ„Â± onaylasÃ„Â±n; kabul edilen gÃƒÂ¶zlem penceresinde veriyi topla ve incident tatbikatÃ„Â± yap.
- Kapanış kanıtı: OnaylÃ„Â± SLA ve destek planÃ„Â±; SLI tanÃ„Â±mÃ„Â±, payda ve gÃƒÂ¶zlem penceresi; BakÃ„Â±m ve kapsam dÃ„Â±Ã…Å¸Ã„Â± durumlar; Servis kredisi koÃ…Å¸ullarÃ„Â±; Incident kanÃ„Â±tÃ„Â±
- Otomatik kontrol: monthly SLI/error-budget report and SLA manifest check

#### SEC-EXT-001 — BaÃ„Å¸Ã„Â±msÃ„Â±z gÃƒÂ¼venlik deÃ„Å¸erlendirmesi ve yeniden test [open]

- Profiller: assisted-sale, production-ga, investor
- Sorumlu: Security Lead + independent assessor
- Eksik: SatÃ„Â±lan candidate iÃƒÂ§in baÃ„Å¸Ã„Â±msÃ„Â±z gÃƒÂ¼venlik deÃ„Å¸erlendirmesi, bulgu giderme ve yeniden test raporu yok.
- Hazırlanacak iş: BaÃ„Å¸Ã„Â±msÃ„Â±z deÃ„Å¸erlendiriciyle scope/tarih belirle; tenant, kimlik, runtime, daÃ„Å¸Ã„Â±tÃ„Â±m ve sÃ„Â±r sÃ„Â±nÃ„Â±rlarÃ„Â±nÃ„Â± kapsa; bulgularÃ„Â± kapat ve yeniden test ettir.
- Kapanış kanıtı: Ã„Â°mzalÃ„Â± baÃ„Å¸Ã„Â±msÃ„Â±z rapor ve kapsam; Remediation/retest mektubu; Ãƒâ€¡ÃƒÂ¶zÃƒÂ¼lmemiÃ…Å¸ kritik bulgu olmamasÃ„Â±; YÃƒÂ¼ksek bulgularda registry'nin gerektirdiÃ„Å¸i gerekÃƒÂ§eli isimli ve sÃƒÂ¼reli kabul
- Otomatik kontrol: assessment evidence expiry/RC match check

#### POV-001 — Ã„Â°simli mÃƒÂ¼Ã…Å¸teri PoV ve kabul kaydÃ„Â± [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Customer Success + Product + evaluator
- Eksik: Ã„Â°simli mÃƒÂ¼Ã…Å¸teri/deÃ„Å¸erlendirici aynÃ„Â± candidate ÃƒÂ¼zerinde zorunlu senaryolarÃ„Â± ve sÃ„Â±nÃ„Â±rlarÃ„Â± inceleyerek kabul vermedi.
- Hazırlanacak iş: DeÃ„Å¸erlendirme sÃƒÂ¶zleÃ…Å¸mesi/charter, baÃ„Å¸Ã„Â±msÃ„Â±z sandbox, zorunlu testler ve mÃƒÂ¼dahale/sapma kaydÃ„Â±nÃ„Â± tamamla; mÃƒÂ¼Ã…Å¸terinin kabul/ÃƒÂ§ekincelerini kaydet.
- Kapanış kanıtı: Ã„Â°mzalÃ„Â± charter; BaÃ„Å¸Ã„Â±msÃ„Â±z koÃ…Å¸u raporu; MÃƒÂ¼dahale ve sapma gÃƒÂ¼nlÃƒÂ¼Ã„Å¸ÃƒÂ¼; MÃƒÂ¼Ã…Å¸terinin kabul/ÃƒÂ§ekinceleri; DeÃ„Å¸iÃ…Å¸tirilemeyen kanÃ„Â±t indeksi
- Otomatik kontrol: expected-suite manifest and evidence-index completeness; acceptance is manual

#### INV-001 — YatÃ„Â±rÃ„Â±mcÃ„Â± metriklerinin kanÃ„Â±t ve onay sÃƒÂ¶zlÃƒÂ¼Ã„Å¸ÃƒÂ¼ [open]

- Profiller: investor
- Sorumlu: Product + Finance + Legal
- Eksik: YatÃ„Â±rÃ„Â±mcÃ„Â±ya sunulan teknik baÃ…Å¸arÃ„Â±, mÃƒÂ¼Ã…Å¸teri, gÃƒÂ¼venlik, uyum, traction ve finans ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lerinin tamamÃ„Â± formÃƒÂ¼l/payda/kaynak/dÃƒÂ¶nem/sÃƒÂ¼rÃƒÂ¼m/onay sahibiyle kayÃ„Â±tlÃ„Â± deÃ„Å¸il. Bu kapÃ„Â± yatÃ„Â±rÃ„Â±mcÃ„Â± profili iÃƒÂ§indir.
- Hazırlanacak iş: Her metriÃ„Å¸i veri sorgusuna veya imzalÃ„Â± kaynaÃ„Å¸a baÃ„Å¸la; ÃƒÂ¶rneklem, dÃƒÂ¶nem, sÃ„Â±nÃ„Â±r ve belirsizliÃ„Å¸i yaz; Product/Finance/Legal incelemesi al.
- Kapanış kanıtı: OnaylÃ„Â± metrik sÃƒÂ¶zlÃƒÂ¼Ã„Å¸ÃƒÂ¼; Kaynak sorgu veya imzalÃ„Â± belge; DÃƒÂ¶nem/ÃƒÂ¶rneklem/payda; Ã„Â°nceleyen kiÃ…Å¸i onayÃ„Â±
- Otomatik kontrol: metric dictionary/evidence-index completeness

#### CLM-001 — MÃƒÂ¼Ã…Å¸teri ve satÃ„Â±Ã…Å¸ iddialarÃ„Â±nÃ„Â±n kanÃ„Â±t onayÃ„Â± [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Product/Marketing + Commercial + Legal
- Eksik: Landing, README, plugin, teklif, procurement ve yatÃ„Â±rÃ„Â±mcÃ„Â± metinlerinin tamamÃ„Â± onaylÃ„Â±, gÃƒÂ¼ncel ve aynÃ„Â± sÃƒÂ¼rÃƒÂ¼me baÃ„Å¸lÃ„Â± iddia kanÃ„Â±tÃ„Â±yla eÃ…Å¸lenmiÃ…Å¸ deÃ„Å¸il.
- Hazırlanacak iş: Her iddiayÃ„Â± Claim Registry'ye baÃ„Å¸la; kaynak ve derlenmiÃ…Å¸ yÃƒÂ¼zeyleri tara; yalnÃ„Â±z sÃƒÂ¼resi geÃƒÂ§memiÃ…Å¸ Sales Approved ifadeleri yayÃ„Â±nla.
- Kapanış kanıtı: Registry snapshot; DerlenmiÃ…Å¸ ÃƒÂ§Ã„Â±ktÃ„Â± tarama JSON'u; Ã„Â°ddiaÃ¢â€ â€™kanÃ„Â±t baÃ„Å¸lantÃ„Â±larÃ„Â±; Sales Approved incelemesi
- Otomatik kontrol: node docs/scripts/claim-check.mjs --mode=gate


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

Sonuçları desteklenen kombinasyonlar için OS × architecture × connector × version × scenario matrisi olarak üret. Koşulmayan hücre PASS değildir; `NOT_RUN`, `HOST_UNAVAILABLE`, `UNSUPPORTED` veya `BLOCKED_EXTERNAL` nedenlerinden biri ve gerekli kapanış girdisi bulunmalıdır.

## Güncel pazar ve ürün farkı denetimi

İnternet erişimi varsa teslim tarihindeki iyi AI agent security/AIDR, MCP security, endpoint response, NDR/DLP ve AI governance ürünlerini yalnız resmi ürün dokümanı, teknik doküman, release note ve güvenilir birincil kaynaklarla yeniden araştır. Kaynak URL, erişim tarihi, advertised capability, deployment modeli, enforcement noktası ve kanıt seviyesini kaydet. Pazarlama iddiasını doğrulanmış teknik davranış gibi yazma; rakipteki özelliği sırf listede görünmek için kopyalama.

Her anlamlı pazar özelliğini şu kararlardan birine bağla: `already_wired`, `implement_now`, `planned_with_owner`, `out_of_scope_with_reason` veya `external_validation_required`. `implement_now` seçilenleri feature/task kaydına ekleyip aynı Definition of Done ile tamamla. Özellikle continuous AI asset discovery, agent identity/privilege graph, causal multi-agent trace, inline input/output enforcement, MCP gateway/attestation, policy-as-code, DLP, supply-chain exposure, automated response, SOC/SIEM workflow, fleet governance, efficacy evaluation ve customer evidence alanlarını karşılaştır.

## Kanıt defteri ve candidate bağlama

Makine okunur evidence index tek kaynak olmalı. Her kayıt en az şu alanları taşımalıdır: `gate_id`, `task_ids`, `feature_ids`, `status`, `command`, `exit_code`, `started_at_utc`, `ended_at_utc`, `duration_ms`, `commit_sha`, `candidate_digest`, `environment`, `tool_versions`, `test_counts`, `observed_effect`, `log_sha256`, `artifact_sha256`, `limitations` ve `owner`. Schema ile doğrula; bilinmeyen alanı boş string ile gizleme, açık `unknown` veya fail-closed status kullan.

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

1. `git diff --check`
2. `node scripts/generate-feature-inventory.mjs`
3. `node scripts/generate-production-sales-gap-audit.mjs`
4. `node scripts/verify-next-agent-execution-prompt.mjs`
5. `pnpm check`
6. `pnpm quality:static`
7. `pnpm audit:prod`
8. `pnpm supabase:check`
9. `pnpm verify:enforcement`
10. `pnpm verify:codex`
11. `pnpm test:ci`
12. `pnpm test:coverage`
13. `pnpm build:release`
14. `node --test scripts/endpoint-install.test.mjs scripts/deployment-prepare.test.mjs scripts/load-test.test.mjs scripts/release-signing.test.mjs scripts/run-e2e-release.test.mjs scripts/deployment-offboarding.test.mjs scripts/deployment-backup-offsite.test.mjs deploy/ingress/device-start.test.mjs deploy/monitoring/monitoring.test.mjs scripts/benchmarks/evaluate.test.mjs`
15. İzole venv oluştur veya mevcut pinned venv'i kullan; `python -m pip install -r services/aig-bridge/requirements-test.txt` ve sonra `python -m pytest services/aig-bridge/tests -q`.
16. `node scripts/verify-support-bundle.mjs --self-test` ve `node scripts/privacy-verify.mjs`.
17. `node docs/scripts/claim-check.mjs --mode=inventory --json` PASS olmalı. `--mode=gate` dış kapılar açıksa FAIL olmalıdır; bunu bypass etme.
18. `pnpm verify:native-host` çalıştır. Gerçek host ve isimli kabul yoksa NO-GO beklenir.
19. Release-inventory SHA-256'yı `AIDR_E2E_RC_DIGEST` olarak verip `pnpm test:e2e` çalıştır. Dış receipt/host yoksa fail-closed sonucu koru; local suite'lerin beklenmedik failure'larını düzelt.
20. Yeni release output ve customer kit üret. Eski v7 klasörünü overwrite etme. Kit verifier, 14 release artefaktı, cloud/self-hosted empty-PATH preparation, secret leakage, gateway ve ingress dosyalarını doğrulamalı. Resmi signer yoksa unsigned/publisher_authenticated=false kalmalı.
21. `pnpm aig:verify` ve izole Python AIG suite'i aynı vendored commit/corpus üzerinde geçmeli; submodule dirty-state evidence'e yazılmalı.
22. `pnpm test:e2e:negative` ile eksik/yanlış credential, yanlış tenant, replay ve unavailable dependency yollarını doğrula.
23. `pnpm verify:fleet:windows` ve `pnpm verify:fleet:unix` çalıştır; mevcut olmayan OS/MDM hostunu başarı sayma.
24. `pnpm verify:monitoring`, `pnpm verify:upgrade`, `pnpm verify:support-bundle`, `pnpm verify:load`, `pnpm verify:release-signing`, `pnpm verify:backup-offsite` ve `pnpm verify:offboarding` kapılarını ayrı loglarla çalıştır.
25. `pnpm verify:customer-onboarding` ve `pnpm test:customer-demo` ile ilk kullanıcının empty-state, install, policy, incident, response, export ve support yolunu doğrula.
26. Generatorları ikinci kez çalıştır ve `git diff --exit-code -- FEATURE_INVENTORY.json FEATURE_INVENTORY.md PRODUCTION_SALES_GAPS.json PRODUCTION_SALES_GAPS.md READINESS_BACKLOG.json` ile deterministik olduklarını kanıtla.
27. Paketleri boş temporary dizin ve boş `PATH` senaryosunda kur; bütün declared `bin`/exports/assets, license, notice, version ve platform dosyalarının bulunduğunu doğrula.
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

Sonuçları `.release-evidence/v8-resource-profile-*.json`, `.release-evidence/v8-load-*.json` ve insan okunur `docs/production-readiness/resource-sizing-v8.md` içinde candidate digest ile bağla.

## Üretilecek teslimatlar

1. Uygulama ve test değişiklikleri.
2. Güncellenmiş generatorlar ve yeniden üretilmiş `FEATURE_INVENTORY.json/.md`, `PRODUCTION_SALES_GAPS.json/.md`, `READINESS_BACKLOG.json`.
3. `docs/production-readiness/2026-09-13-customer-candidate-v8.md`: karar, değişiklikler, bütün komut/exit code/test sayıları, coverage, açık sınırlar, kaynak ölçümü ve candidate digest.
4. Güncel `first-customer-sales-packet-v8.md`, destek/incident/runbook bağlantıları ve market capability delta.
5. Benzersiz v8 release-output, portable customer kit ve outer envelope. Resmi key yoksa imzasız olduğu açıkça yazılmalı.
6. Makine okunur evidence index: her gate için komut, start/end UTC, exit code, log hash'i, candidate digest, status ve limitation.

## Bitiş ve raporlama biçimi

Şu koşul sağlanana kadar durma: bütün yerel olarak uygulanabilir değişiklikler tamamlanmış, ilgili testler geçmiş, generated kayıtlar güncel, package/kit doğrulanmış ve kalan her iş yalnız gerçek dış bağımlılık veya açıkça belgelenmiş ürün sınırı haline gelmiş olmalı.

Bir tur sonunda yerel OPEN/partial/backlog kaldıysa final cevap yazıp görevi bitirme; yeniden en yüksek öncelikli kayda dön. Yalnız bütün bağımsız işler tamamlandığında veya ilerleme için gerçekten kullanıcıdan alınması gereken tekil dış girdiler kaldığında final rapor üret. Dış girdiler kaldığında bile her biri için çalıştırılabilir preflight, exact input listesi, owner, runbook, evidence template ve kabul komutu hazır olmalıdır.

Finalden hemen önce `git status --short`, recursive submodule status, staged diff, son atomik commitler ve candidate digest'i kaydet. Kendi ürettiğin geçici dosyaları ürün ağacında bırakma. Kullanıcı değişikliklerini, özellikle dirty submodule içeriğini, temiz çalışma ağacı elde etmek amacıyla silme.

Final cevapta şu sırayı kullan:

1. Karar: LOCAL_ENGINEERING_READY veya NO-GO; production/sales GO yalnız bütün zorunlu dış kapılar gerçekten kapalıysa.
2. Kapatılan task/backlog/feature ID'leri ve önemli dosyalar.
3. Yerel doğrulama: tam komut, exit code, test/coverage/package/artefakt sayıları.
4. Fail-closed native/E2E/claim-gate sonuçları ve tam nedenleri.
5. Kalan işler: ID, owner, gerekli gerçek girdi, kabul kanıtı. Yüzde veya genel “hazır” ifadesi kullanma.
6. Customer kit, release inventory ve evidence index yolları/digestleri.
7. Kaynak tüketimi: measured ve estimated değerleri ayrı tabloyla ver.

Başarı ölçütü daha çok dosya değiştirmek değil; satılan davranışın gerçek consumer'da çalışması, hatada güvenli kalması ve her iddianın doğru kanıt sınırıyla raporlanmasıdır.

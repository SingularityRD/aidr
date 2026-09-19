# AIDR v8 uçtan uca kapatma ve yerel doğrulama promptu

Bu dosyanın tamamını başka kodlama ajanına tek prompt olarak ver. Ajan repo kökünde çalışmalı, yalnız plan yazıp durmamalı ve aşağıdaki kanıt sınırlarını korumalıdır.

---

Sen kıdemli bir endpoint security, detection engineering, identity, platform, SRE ve release engineering ekibi gibi çalışan otonom bir kodlama ajanısın. Çalışma alanın repo kökü `<repo-root>` (bu promptun bulunduğu checkout).

Amaç: AIDR ürünündeki bütün yerel olarak giderilebilir eksikleri uçtan uca uygula, mevcut uygulamaları denetle, yarım kalanları tamamla, regresyonları düzelt, cloud ve self-hosted müşteri kurulum paketini yeniden üret ve her iddiayı yerel kanıtla bağla. Yalnız rapor veya plan üretip durma. Bağımsız ilerleyebildiğin sürece kullanıcıya soru sorma. Bir engel gördüğünde önce bütün bağımsız işi tamamla.

Mevcut kayıt kararı **NO-GO**. Envanter: 71 özellik = 41 wired, 28 partial, 0 missing, 2 external. Teknik kayıt: 46 iş = 0 OPEN, 46 yerel uygulaması bulunan fakat saha kabulü açık. Ticari/dış kayıt: 13 kapı. Backlog: 69 bulgudan 7 tanesi kapanmamış.

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

#### T01 — Gerçek host ve işletim sistemi kapsamı [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: CON-01, CON-02, CON-03, CON-04, CON-05, CON-06, DET-01, DET-02, DET-03, DET-04, DET-05, RSP-01
- Kaynak: scripts/run-e2e-release.mjs, packages/codex/README.md
- Güncel yerel durum: deploy/native/support-matrix.json satilan connector/OS/arch/context/interception matrisini ve bilinen bypass/unobserved listesini tanimliyor; deploy/native/run-support-matrix.mjs kurulu olmayan hostu HOST_UNAVAILABLE olarak NO-GO uretiyor, gercek host ve isimli kabul acik.
- Başlangıç riski: Kanca kararı hostun eylemi durdurduğunu tek başına kanıtlamaz. Devre dışı eklenti, süreç çökmesi, timeout ve yeni host sürümü kapsam dışında kalabilir.
- Tamamlama hedefi: Satılacak her bağlayıcı için OS/sürüm destek tablosu, gerçek host testi, kurulum/kaldırma ve destek sahibi belirle; görünmeyen eylemleri açıkça listele.
- Zorunlu kapanış testi: Her zorunlu saldırıda yan etkinin oluşmadığını bağımsız kaydet; zararsız işlemler geçsin; kanca kapalı/bozuk/ağsız durumları ve yeniden başlatma ayrı sınansın.
- Dış bağımlılık/sınır: Müşteri test cihazları, runtime erişimi ve sürüm seçimi

#### T02 — Bağlayıcılar arasında araç adı ve girdi normalizasyonu [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DET-12, DET-11, CON-04
- Kaynak: packages/core/src/evaluator.ts, packages/opencode/src/tool-handler.ts, packages/opencode/src/__tests__/aidr-contract.test.ts
- Güncel yerel durum: Ortak araç/girdi normalizasyonu evaluator öncesinde; Codex ve OpenClaw boş-artifact erken izin yolu kaldırıldı, named MCP çağrıları politikaya ulaşıyor.
- Başlangıç riski: Paket kurulumları ve bazı dosya/AMSI girdileri ilgili denetim koluna ulaşmayabilir; birim testlerin yeşil olması bu kapsamı kapatmıyor.
- Tamamlama hedefi: Ortak semantik araç/girdi sözleşmesi tanımla; tüm bağlayıcıları eşle; command, file_path/filePath, content/new_string alanlarını standartlaştır. Bilinen boşluğu beklenen izin sonucu olarak sabitleyen testi değiştir.
- Zorunlu kapanış testi: Aynı yasak paket, manifest ve dosya girdisi tüm bağlayıcılarda aynı denetime ulaşsın; denetleyici çağrısı ve engellenen yan etki kanıtlansın; boş/alternatif alan adları negatif test edilsin.
- Dış bağımlılık/sınır: AIDR-060; native host matrisi

#### T03 — Paket denetiminde hatanın sessiz kaybolması [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DET-10, DET-11, DET-12
- Kaynak: packages/core/src/evaluator.ts, packages/core/src/package-checker.ts
- Güncel yerel durum: Paket, registry ve file-reputation hata/bozuk-200 yolları clean yerine unknown/unavailable üretiyor; gerçek 404 ve doğrulanmış clean ayrımı test edildi.
- Başlangıç riski: Paket denetleyicisi beklenmedik hata verdiğinde üst akış başarılı bir boş kontrol gibi devam edebilir; diğer kurallar her vakayı yakalamaz.
- Tamamlama hedefi: Hata türlerini unavailable olarak taşı; zorunlu denetim politikasında deny/insan onayı üret; opsiyonel kolda görünür eksik tespit kaydı tut. Hatalı politika/cache/intel durumlarını ayır.
- Zorunlu kapanış testi: Registry timeout, bozuk cevap, cache/intel ayrıştırma hatası ve denetleyici exception enjekte et; zorunlu kontrol sessiz allow üretmesin; benign ve iptal davranışları korunsun.
- Dış bağımlılık/sınır: AIDR-061; desteklenen araç sözleşmesi

#### T04 — Model tüketiminden önce çıktı denetimi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DET-06, DET-07, MCP-07, CON-01, CON-02, CON-03, CON-04, CON-05, CON-06
- Kaynak: packages/claude-code/src/output-inspection.ts, packages/claude-code/src/post-tool-use.ts, packages/core/src/output-scanner.ts
- Güncel yerel durum: Çıktı tarayıcı 2 MiB UTF-8, 3000 ms best-effort ve 128 bulgu sınırında inspection_incomplete/critical fail-closed üretiyor; JSON/Unicode ve sınır payloadları test edildi. Her hostta aynı-tur blok kanıtı yok.
- Başlangıç riski: Prompt injection veya sır içeren çıktı modele ulaşabilir. İlk 262144 karakterden sonraki içerik ve desteklenmeyen biçimler için kapsam eksiktir.
- Tamamlama hedefi: Hostun izin verdiği yerlerde çıktı tesliminden önce kontrol/karantina ekle; desteklenmeyen yollarda açık coverage durumu göster; boyut sınırı aşımını sessiz temiz sayma.
- Zorunlu kapanış testi: Parçalara bölünmüş saldırı, sınırın sonundaki payload, Unicode, JSON/text ve çok büyük cevaplar sınansın; engellenen baytlar modele ulaşmasın; zararsız çok parçalı cevap bozulmasın.
- Dış bağımlılık/sınır: Host API kabiliyeti; MCP gateway

#### T05 — Davranış, novelty ve ML kararlarının ürün akışına bağlanması [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DET-08, DET-09
- Kaynak: packages/core/src/behavioral-analyzer.ts, packages/core/src/novelty-detection.ts, packages/core/src/ml-model.ts
- Güncel yerel durum: BehavioralAnalyzer adayı kendi baseline'ına katmıyor ve tenant/session ayrımı korunuyor; üretim etkinliği ve kalıcı öğrenme kabulü açık.
- Başlangıç riski: İhracat edilen sınıf veya demo skor, çalışan anomali koruması sayılmaz. Yanlış öğrenme ve tenantlar arası veri karışması riski değerlendirilmemiş.
- Tamamlama hedefi: Gerçek olay tüketicisi, tenant bazlı durum, cold-start, unutma/retention, model sürümü, karar açıklaması ve insan geri bildirimi akışlarını bağla.
- Zorunlu kapanış testi: Soğuk başlangıç ve model yenilemede kararlı sonuç; tenant ayrımı; veri zehirleme denemeleri; holdout saldırı ve zararsız iş yükünde yanlış alarm ölçümü.
- Dış bağımlılık/sınır: Etiketli müşteri verisi ve bağımsız ölçüm seti

#### T06 — Reputation ve AI altyapı verisinin güncelliği [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DET-10, DET-11, DET-12, INF-01, INF-02
- Kaynak: supabase/functions/url-check/index.ts, supabase/functions/file-check/index.ts, packages/core/src/generated/aig-data-manifest.json, packages/core/src/aig-policy.ts
- Güncel yerel durum: İmzalı offline feed için publisher issued_at ve yerel fetched_at birlikte yaş sınırına bağlandı; canlı provider, dağıtım ve gecikme kabulü açık.
- Başlangıç riski: Feed kaynağı/güncelliği, sağlayıcı kesintisi, imzalı güncelleme, kapsanmayan format ve müşteri gecikme hedefleri doğrulanmadı; canlı reputation testi atlanıyor.
- Tamamlama hedefi: Feed sözleşmesi ve güncelleme işi, yaş sınırı, geri alma, eksik veri durumu ve müşteri veri/URL kategorisi kalibrasyonu kur.
- Zorunlu kapanış testi: Eski/bozuk/boş feed temiz verdict üretmesin; güncelleme/geri dönüş kanıtlansın; gerçek endpoint ve AMSI desteklenen Windows hostunda ölçülsün.
- Dış bağımlılık/sınır: Sağlayıcı/feed erişimi, Windows host ve müşteri corpus'u

#### T07 — MCP keşfi ve kimlik normalizasyonunun kapsamı [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: MCP-01, MCP-02, MCP-03, MCP-04
- Kaynak: packages/core/src/mcp-discovery.ts, packages/core/src/mcp-inventory.ts, packages/core/src/policy.ts
- Güncel yerel durum: Yerel MCP keşfi konum/alias bazlı kararlı inventory_id ve merkezi stale/partial kapsam raporu üretiyor; ek host biçimleri/native kabul açık.
- Başlangıç riski: JSONC, yeni runtime konumları, dinamik eklenen sunucular ve belirsiz server/tool kimlikleri için tam kapsama yok; yerel tarama kurum çapı keşif değildir.
- Tamamlama hedefi: Desteklenen konfigürasyon adaptörlerini ekle; okunamayan/kısmi keşfi raporla; yeniden adlandırma ve alias davranışını politikayla tutarlı yap.
- Zorunlu kapanış testi: Bozuk/izin verilmeyen dosya, JSONC, boş argüman, alias ve aynı isimli farklı sunucu testleri; eksik tarama güvenli envanter gibi görünmesin.
- Dış bağımlılık/sınır: Host sürüm ve konfigürasyon matrisi

#### T08 — İmzalı MCP araç tanımı ve değişiklik onayı [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: MCP-05
- Kaynak: packages/core/src/mcp-transport.ts, packages/core/src/mcp-discovery.ts
- Güncel yerel durum: İmzalı MCP manifest key_id'yi imzaya bağlıyor, geçersiz saat ve legacy imza fail-closed; eski manifestler güvenilir yayıncı tarafından yeniden imzalanmalı.
- Başlangıç riski: İmzalı sunucu/araç description ve schema manifesti, kalıcı onay, sürüm/expiry ve replay koruması yok. Süreç yeniden başlatılması güvenilir onay değildir.
- Tamamlama hedefi: Araç tanımını sunucu kimliği ve sürüme imzayla bağla; değişen araçları karantinaya al; yalnızca operatörün onaylayabildiği inceleme ve dağıtım akışı kur.
- Zorunlu kapanış testi: Description/schema değişimi, eski manifest, yanlış signer, yeniden başlatma, eş zamanlı değişiklik ve onaysız retry reddedilsin; ajan kendi aracını onaylayamasın.
- Dış bağımlılık/sınır: AIDR-046; signer/key custody ve yönetim UI'sı

#### T09 — Kullanıcı–ajan–araç–kaynak ilişkisi ve delegasyon [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: MCP-06, TEN-06, OBS-02
- Kaynak: packages/core/src/mcp-inventory.ts, supabase/functions/enroll/index.ts, supabase/functions/api-keys/index.ts
- Güncel yerel durum: Ed25519 delegated lineage ve grant/introspection/revoke; geçersiz sayı ve Ed25519 olmayan EdDSA anahtarı reddediliyor. Gerçek IdP/tool provider kabulü açık.
- Başlangıç riski: Kimin hangi ajan üzerinden hangi kaynağa hangi yetkiyle eriştiğini gösteren tam ilişki grafiği; araç bazlı kısa ömürlü delegasyon yok.
- Tamamlama hedefi: Kaynak ve kimlik ilişkileri, audience/scope/expiry taşıyan kısıtlı token, delegation depth ve credential broker uygula.
- Zorunlu kapanış testi: Başka tool/resource/audience için token kullanımı, süresi bitmiş delegasyon, kullanıcı ayrılması ve zincir yetki büyütme reddedilsin; olaydan kaynağa iz sürülsün.
- Dış bağımlılık/sınır: IdP ve araç sağlayıcısı API'leri

#### T10 — MCP gateway ve taşıma güvenliği [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: MCP-07
- Kaynak: packages/core/src/mcp-transport.ts, packages/core/src/__tests__/mcp-transport.test.ts
- Güncel yerel durum: Loopback/stdio JSON-RPC geçidi DNS pinleme, gerçek stream sınırı, tekil framing ve bozuk yanıt reddi uyguluyor; binary, server-initiated ve zorunlu routing kabulü açık.
- Başlangıç riski: DNS rebinding, başlıksız/chunked büyük cevap, mapped IPv6 ve bağlantı ömrü için gerçek ağ kabulü eksik. Mevcut test adı DNS rebinding korumasını olduğundan güçlü anlatıyor.
- Tamamlama hedefi: Doğrulanan IP'yi bağlantıya sabitle; IP sınıflamasını tamamla; gerçek okunan/decompress edilmiş baytları sınırla; authentication/session/stream ve bypass akışlarını gateway'e bağla.
- Zorunlu kapanış testi: Kontrol ile bağlantı arasında DNS değişsin; private/mapped IPv6, redirect, başlıksız sonsuz stream, sınır aşımı, disconnect ve bozuk JSON/SSE ile gerçek ağ testi çalışsın.
- Dış bağımlılık/sınır: AIDR-062; stdio/HTTP/SSE kapsam kararı

#### T11 — Sürekli kurum/filo keşfi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: INF-03
- Kaynak: packages/cli/src/commands/scan.ts, packages/core/src/aig-infra-scan.ts
- Güncel yerel durum: Kimlikli merkezi discovery upload var; interval modu geçici upload hatasını görünür tutarak sonraki çevrime devam ediyor. Cloud/MDM scheduler ve saha kabulü açık.
- Başlangıç riski: Zamanlanmış kolektör, tenant envanteri, sahiplik, tekrar birleştirme, son görülme ve stale alarmı yok.
- Tamamlama hedefi: Filo/cloud kolektörleri, kapsam izinleri, zamanlama, retry, dedup, kimlik ve keşif tazeliği ekranlarını kur.
- Zorunlu kapanış testi: Kapanan veya yeni açılan ajan görünür olsun; bağlantısız kolektör eski veriyi güncel göstermesin; tenant ayrımı ve keşif yük sınırları sınansın.
- Dış bağımlılık/sınır: Müşteri cloud/MDM API erişimi ve ağ tarama kapsamı

#### T12 — Filo müdahalesi ve credential iptali [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: RSP-04, RSP-06
- Kaynak: packages/core/src/contain.ts, supabase/functions/revocations/index.ts
- Güncel yerel durum: İmzalı revocation feed tenant+global kapsamı 5000 sınırından önce filtreliyor ve eksik/truncated seti imzalamıyor; native/provider iptali açık.
- Başlangıç riski: Kurumsal endpoint izolasyonu, tüm cloud sağlayıcılarda credential iptali ve ajandan sonuç alan komut altyapısı yok.
- Tamamlama hedefi: Yetkili komut kuyruğu, TTL/idempotency, operatör yetkisi, ajan sonuç bildirimi, geri alma ve sağlayıcı adaptörleri ekle.
- Zorunlu kapanış testi: Offline ajana süresi geçmiş komut uygulanmasın; tekrar gelen komut tek etki üretsin; başarısız izolasyon başarı görünmesin; ilgili izinler ve geri dönüş kanıtlansın.
- Dış bağımlılık/sınır: OS yetkileri, sağlayıcı API'leri, müşteri müdahale yetkisi

#### T13 — Response eylemlerinin güvenli uçtan uca işletimi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: RSP-02, RSP-03, RSP-05, RSP-07
- Kaynak: packages/core/src/quarantine.ts, packages/core/src/rollback.ts, packages/core/src/response-command-worker-v6.ts, packages/core/src/response-audit.ts, supabase/functions/autosecops-runtime/index.ts
- Güncel yerel durum: Yeni response-worker-contract.ts capability/onkosul/TTL/idempotency/rollback makbuzu sozlesmesini uyguluyor; desteklenmeyen action adapter tarafindan reddediliyor ve geri alinamayan adim partial olarak raporlaniyor. Native OS/provider adapter ve kurulu servis musteri tarafinda acik. Eski: Restart-safe worker resume sırasında adapter destek listesini yeniden doğruluyor ve kaldırılmış action'ı çalıştırmadan unsupported_action bildiriyor. Native OS/provider adapter ve kurulu servis açık.
- Başlangıç riski: Gerçek müşteri dosya izinleri, aynı anda değişen dosya, dış playbook etkileri, signer saklama ve bağımsız arşiv kanıtı eksik.
- Tamamlama hedefi: Desteklenen eylem ve dosya kapsamını sabitle; önkoşul/sonuç doğrulama, operatör sınırları, dış SOAR sonuçları ve bağımsız kanıt saklamayı tamamla.
- Zorunlu kapanış testi: Dosya sonradan değişmişken yanlış rollback yapılmasın; symlink/izin/disk hatası açık başarısız olsun; eylem ve geri dönüş aynı incidentten izlenebilsin.
- Dış bağımlılık/sınır: Müşteri dosya sistemi/EDR/SOAR izinleri

#### T14 — YAML politika yazımı ile gerçek runtime ilişkisi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: POL-01, POL-02
- Kaynak: packages/dashboard/src/enterprise/policy-editor.tsx, packages/dashboard/src/ui/pages/PolicyPage.tsx, packages/core/src/policy.ts
- Güncel yerel durum: Core/server dry-run unknown MCP fallback kararı runtime evaluator ile eşlendi; YAML/JSON compiler, parity ve dashboard publish akışı bağlı.
- Başlangıç riski: Kaydedilen YAML kuralları runtime tarafından tüketilmiyor. Kullanıcı belge kaydını etkin güvenlik politikası sanabilir.
- Tamamlama hedefi: Desteklenen YAML şemasını runtime modeline derle veya belge akışını açıkça ayır; desteklenmeyen alanları reddet; öncelik ve etki simülasyonu sun.
- Zorunlu kapanış testi: Kaydedilen/yayınlanan politika gerçek ajan kararında değişiklik üretsin; bilinmeyen alan sessiz atılmasın; allowlist ile açık deny önceliği doğrulansın.
- Dış bağımlılık/sınır: Politika sözleşmesi ve migration planı

#### T15 — Politika dağıtımı saha kabulü ve ölçek sınırları [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: POL-03, POL-04, POL-05
- Kaynak: supabase/functions/policy-management/index.ts, supabase/functions/policy-ack/index.ts, packages/core/src/remote-policy.ts
- Güncel yerel durum: Hedefli stage işlemi atomik revision precondition ile eski eşzamanlı güncellemeyi 409 reddediyor; gerçek filo/ölçek kabulü açık.
- Başlangıç riski: Receipt yalnızca ajanın yükleme bildirimi; host enforcement attestation değil. Eski bağlı olmayan anahtarlar, büyük filo batch planı ve gerçek offline saha kabulü açık.
- Tamamlama hedefi: Eski ajanları yeniden kaydet; dağıtım batch/ring işletimini ve zorunlu politika sürelerini müşteriye göre belirle; gözlem/uyarı ve native canary kabulü yap.
- Zorunlu kapanış testi: Yetkisiz/stale receipt, rollback, offline süresi, 401/403, bozuk cache, yeniden başlatma ve hedef değiştirmede yanlış sürüm uygulanmasın; gerçek filoda yakınsama ölçülsün.
- Dış bağımlılık/sınır: Ajan sürümü, müşteri offline toleransı

#### T16 — Endpoint sır saklama ve anahtar rotasyonu [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: CLI-02, TEN-06
- Kaynak: packages/cli/src/utils/config-manager.ts, packages/core/src/types.ts, docs/runbooks/secrets-management.md
- Güncel yerel durum: Windows config create/update/reuse yolu owner+SYSTEM+Administrators DACL kuruyor ve ACL hatasında credential yazmıyor; OS vault ve server-side revocation açık.
- Başlangıç riski: OS credential vault entegrasyonu, kurumsal dağıtımda signer rotasyonu, kayıp cihaz/anahtar kurtarma ve minimum API-key kapsamı eksik.
- Tamamlama hedefi: Windows/macOS/Linux için sır deposu adaptörü; anahtar rotasyonu ve iptali; config/export/support bundle redaksiyonunu tamamla.
- Zorunlu kapanış testi: Yetkisiz kullanıcı sır okuyamasın; eski anahtar zamanında reddedilsin; yenileme kesintisi güvenli olsun; log, argüman ve destek arşivi sır sızdırmasın.
- Dış bağımlılık/sınır: Kurum secret manager'ı ve OS depoları

#### T17 — İmzalı filo kurulumu, güncelleme ve kaldırma [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: CLI-01, CLI-03, CLI-04
- Kaynak: scripts/endpoint-install.mjs, packages/extension/package.json, packages/cli/src/commands/setup.ts
- Güncel yerel durum: Installer ile Windows/Unix uninstall yalnız AIDR işaretli nested hook'u kaldırıyor, aynı entry'deki müşteri hook'larını koruyor; gerçek MDM/yayıncı kabulü açık.
- Başlangıç riski: Intune/Jamf/SCCM teslimatı, tüm hostlarda upgrade/rollback/uninstall ve filo sağlık kanıtı tamam değil.
- Tamamlama hedefi: İmzalı dağıtım paketleri, detect/remediate betikleri, yönetici/kullanıcı kurulumları, policy-preserving upgrade ve uninstall kuralları üret.
- Zorunlu kapanış testi: Temiz kurulum, yarım kalan upgrade, eski sürüme dönüş, host güncellemesi ve uninstall sonrasında başka kancalar/politika bozulmasın; gerçek MDM'de kanıt topla.
- Dış bağımlılık/sınır: MDM test tenantı, signer, OS paketleme araçları

#### T18 — Kurumsal giriş, MFA ve hesap kurtarma [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-01, TEN-04, TEN-07
- Kaynak: packages/dashboard/src/ui/pages/LoginPage.tsx, packages/dashboard/src/enterprise/auth.tsx, scripts/deployment-bootstrap.mjs
- Güncel yerel durum: Recovery URL yalnız hosted HTTPS/loopback HTTP kabul ediyor, credential URL'yi reddediyor ve parola değişiminden önce global session barrier kuruyor; canlı IdP açık.
- Başlangıç riski: Gerçek IdP/SSO, MFA, parola sıfırlama, oturum sonlandırma, break-glass ve kimlik sahipliği işletimi kabul edilmedi.
- Tamamlama hedefi: Müşteri IdP'si, MFA ve kurtarma akışlarını bağla; bootstrap sahiplik prosedürü, session süreleri ve acil yönetici erişimini tanımla.
- Zorunlu kapanış testi: Kayıp parola/MFA, kapatılmış kullanıcı, süresi dolmuş oturum ve başarısız IdP durumlarını sınayarak hesabın hem geri alınabilir hem yetkisiz erişime kapalı olduğunu kanıtla.
- Dış bağımlılık/sınır: IdP/SMTP/DNS ve kurum güvenlik politikası

#### T19 — SCIM ve güvenilir directory grup eşlemesi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-02, TEN-04
- Kaynak: packages/dashboard/src/auth/azure-ad.ts, packages/dashboard/src/enterprise/team-provider.tsx
- Güncel yerel durum: SCIM stale PATCH'i reddediyor, Remove members tüm üyeleri kaldırıyor ve büyük grup üyeliğini sayfalıyor; gerçek Entra/Okta kabulü açık.
- Başlangıç riski: Yardımcı kod user_metadata gruplarını önce okuyabiliyor ve isimde admin geçmesine göre rol eşliyor. Bu, sunucu yetkilendirmesi için güvenilir temel değildir; aktif bir yetki yükseltme kanıtı olarak sunulmuyor.
- Tamamlama hedefi: Sunucuda doğrulanmış immutable grup ID'leri, allowlist rol eşlemesi ve SCIM create/update/deactivate/groups uygula; kullanıcı metadata'sını yetki kaynağı yapma.
- Zorunlu kapanış testi: Sahte metadata, benzer grup adı, grup kaldırma, hesap pasifleştirme, pagination/replay ve tenant karıştırma testleri; erişim belirtilen süre içinde kesilsin.
- Dış bağımlılık/sınır: AIDR-019/048; Entra/Okta test ortamı

#### T20 — Davet ve cihaz kayıt yaşam döngüsü [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-03, TEN-05
- Kaynak: supabase/functions/team-invite/index.ts, supabase/functions/device-poll/index.ts, packages/dashboard/src/ui/pages/public/VerifyPage.tsx
- Güncel yerel durum: Tenant kapsamlı invite list/revoke/resend token rotasyonu ile device-start/exchange temeli var; SMTP, gerçek browser/IdP ve ağ kesintisi kabulü açık.
- Başlangıç riski: SMTP davet teslimi, gerçek cihaz yeniden kaydı, ekipten ayrılan çalışanın erişim kapanması ve müşteri mail/link akışı tam kabul edilmedi.
- Tamamlama hedefi: Davet dağıtımını, expiry/iptal/yeniden gönderme, yanlış ekip ve cihaz yenileme işletimini tamamla.
- Zorunlu kapanış testi: Kullanılmış/iptal edilmiş davet, rol değişimi, başka ekip, eski device code ve kimlik değişiminde kayıt reddedilsin; mail linki gerçek tarayıcıda doğru ekibe dönsün.
- Dış bağımlılık/sınır: SMTP/IdP ve müşteri cihazları

#### T21 — Mevcut API anahtarında ekip ve üyelik iptali [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-01, TEN-06, DET-10, DET-11
- Kaynak: supabase/functions/url-check/index.ts, supabase/functions/file-check/index.ts, scripts/audit-reputation-lifecycle.mjs
- Güncel yerel durum: Packs manifest/download dahil anahtar kullanan yollar aktif tenant, üyelik ve revocation doğruluyor; önceden üretilmiş signed URL süre sonuna dek geçerli.
- Başlangıç riski: İzole gerçek HTTP provasında askıya alınmış ekip ve süresi bitmiş üyelikle hem URL hem dosya sorgusu 200 döndü; dört kabul yeniden üretildi. Başka tenant verisi okunduğu gösterilmedi.
- Tamamlama hedefi: Ortak doğrulanmış anahtar/aktif tenant/aktif üyelik sınırı uygula; iptal, kapanış ve deprovisioning semantiğini tüm servislerde birleştir.
- Zorunlu kapanış testi: Aktif kimlik 200; suspended/closing/closed tenant, expired/removed membership ve revoked key tüm tüketicilerde 401/403; stale cache ile erişim sürmesin.
- Dış bağımlılık/sınır: AIDR-063; yerel yeniden üretim kanıtı

#### T22 — Tenant izolasyonu ve kaynak tüketim sınırları [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-01, OBS-01, DEP-07
- Kaynak: supabase/functions/_shared/auth.ts, supabase/migrations/20260805000000_hybrid_tenancy.sql
- Güncel yerel durum: Edge byte/rate sınırı bozuk RPC'de 503 ve stalled stream'de 413 fail-closed üretiyor; müşteri yük/izolasyon kabulü açık.
- Başlangıç riski: Her endpoint/rol/tenant kombinasyonu, body/stream sınırı, rate-limit kesintisi ve komşu tenant kaynak tüketimi tam ölçülmedi.
- Tamamlama hedefi: Tüm endpointler için auth/RBAC/RLS sözleşmesi; servis rolü kullanan yollarda açık tenant sınırı; kuyruk/iş/istek/depoma kotaları ekle ve denetle.
- Zorunlu kapanış testi: Farklı tenant, üyelik kaybı, viewer, eski anahtar, büyük body ve paralel isteklerle negatif matris çalışsın; tek tenant diğerinin SLO'sunu tüketemesin.
- Dış bağımlılık/sınır: Bağımsız değerlendirme ve tanımlı yük profili

#### T23 — Telemetri dayanıklılığı ve görünür veri kaybı [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: OBS-01
- Kaynak: supabase/functions/ingest/index.ts, packages/core/src/audit-log.ts
- Güncel yerel durum: Telemetry WAL bozuk/unknown/tampered committed kayıtları reddediyor, terminal drop sonrası retry ve stale backlog readiness sağlıyor; uzun kesinti saha testi açık.
- Başlangıç riski: Filo yükünde teslim SLO'su, disk/kuyruk sınırı, offline retry/dedup ve uçtan uca kayıp oranı için kanıt eksik.
- Tamamlama hedefi: Olay teslim sözleşmesi, kimlik/idempotency, retry/backpressure, kayıp sayaçları ve tenant bazlı retention bütçelerini doğrula.
- Zorunlu kapanış testi: Ağ/DB/storage kesintisi ve ajan yeniden başlatmada kayıp/duplicate ölç; sessiz olay kaybı olmasın; disk dolması ve gecikme kullanıcıya görünür olsun.
- Dış bağımlılık/sınır: Müşteri cihaz/olay hacmi ve saklama hedefi

#### T24 — SIEM ve OpenTelemetry üretim teslimi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: OBS-04
- Kaynak: packages/core/src/siem-export.ts, packages/core/src/tracing.ts
- Güncel yerel durum: SIEM durable state provider/endpoint/index routing fingerprint'e bağlı ve farklı hedefte reopen'i reddediyor; gerçek SIEM alındısı/zamanlayıcı açık.
- Başlangıç riski: Named SIEM transport, teslim bildirimi, kesinti tamponu, şema sürümü ve müşteri SIEM alan eşlemesi kabul edilmedi.
- Tamamlama hedefi: Satılacak Splunk/Sentinel/Elastic vb. adaptörleri için gerçek endpoint entegrasyonu, retry/dedup ve sağlık göstergesi tamamla.
- Zorunlu kapanış testi: SIEM kesintisi/429/401, sertifika değişimi, yeniden gönderim ve alan eşlemesi gerçek SIEM'de doğrulansın; yanlış başarı bildirimi olmasın.
- Dış bağımlılık/sınır: SIEM test hesabı ve event schema anlaşması

#### T25 — Olay araştırması ve kanıt bütünlüğü [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: OBS-02, RSP-05
- Kaynak: packages/core/src/incidents/correlate.ts, packages/core/src/incidents/anchor.ts, packages/core/src/response-audit.ts
- Güncel yerel durum: incidents/evidence-receipt.ts candidate/policy/device/actor/incident/action bagli append-only receipt, Lamport mantik saati ile offline/skew siralamasi, duplicate/tamper reddi ve fail-closed arsiv adapteri ekliyor. Dis arsiv sahibi ve key custody acik. Eski: Olay receipt head sırası deterministik UTF-16 ve legacy doğrulama uyumlu; ayrı Ed25519 snapshot makbuzu var. Dış saklama, key custody ve güvenilir zaman açık.
- Başlangıç riski: Tam cross-agent nedensellik, ayrıcalıklı değişikliklere karşı bağımsız kanıt saklama ve olay→araç→credential izi eksik.
- Tamamlama hedefi: Korelasyon kimlikleri, zaman sapması, ilişkili ajan/kaynak görünümü, zincir doğrulama ve bağımsız arşiv kur.
- Zorunlu kapanış testi: Saat kayması/duplicate/offline sıralama, silinmiş veya değiştirilmiş zincir ve çok ajanlı saldırıda kanıt boşlukları görünür olsun.
- Dış bağımlılık/sınır: Kimlik grafiği, güvenilir zaman ve arşiv sahibi

#### T26 — Saklama, legal hold ve müşteri çıkışı [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: OBS-03, OBS-06
- Kaynak: scripts/deployment-maintenance.mjs, deploy/maintenance/aidr-export-retention.timer, supabase/functions/audit-export/index.ts
- Güncel yerel durum: Offboarding her Storage nesnesinin yokluğunu doğrulamadan ACK üretmiyor; legal hold/resume var, harici backup silme kanıtı açık.
- Başlangıç riski: Zamanlayıcı müşteri ortamında aktif değil; tüm veri sınıfları için retention/deletion, legal hold ve doğrulanmış offboarding yok.
- Tamamlama hedefi: Tablo/nesne/log/cache/yedek bazında yaşam döngüsü; legal hold istisnası; kullanıcı/tenant kapanışı ve silme makbuzu kur.
- Zorunlu kapanış testi: Süre dolan verinin API, Storage, cache ve replikalardan yokluğu; hold verisinin korunması; retry ve yarım silme sonrası tutarlılık kanıtlansın.
- Dış bağımlılık/sınır: Onaylı saklama/silme politikası; yedek istisnaları

#### T27 — Offsite yedekleme ve RPO/RTO [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-06
- Kaynak: scripts/deployment-backup.mjs, scripts/verify-deployment-recovery.mjs
- Güncel yerel durum: Offsite commit zamanı authenticated manifest'e bağlı ve S3 lookup hatası fail-closed; izole restore aracı var. Bağımsız host/provider ve RPO/RTO açık.
- Başlangıç riski: Off-host kopya, otomatik zamanlama/retention, ayrı anahtar kurtarma ve gerçek felaket RPO/RTO kanıtı yok; bakım duruşu gerekiyor.
- Tamamlama hedefi: Yedek hedefi/anahtar custody, zamanlama, erişim ayrılığı, başarısızlık alarmı ve kayıp-host geri dönüş işletimini kur.
- Zorunlu kapanış testi: Yeni hostta yalnız offsite yedek ve ayrı anahtarla kurtar; tablo/nesne içerikleri eşleşsin; gerçek kayıp veri süresi ve toparlanma süresi ölçülsün.
- Dış bağımlılık/sınır: Offsite storage, key custodian, kabul edilmiş RPO/RTO

#### T28 — Gerçek cloud ve self-hosted üretim kurulumu [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-01, DEP-02
- Kaynak: scripts/deployment-prepare.mjs, deploy/FIRST_CUSTOMER.md
- Güncel yerel durum: 33 migrationlı self-hosted prova var; prepare inputları secret oluşturmadan doğruluyor ve cloud public proxy/provider upstream loop'unu reddediyor. Canlı provider/TLS açık.
- Başlangıç riski: Cloud hesabı/projesi, bölge, DNS/TLS, reverse proxy, SMTP/IdP, secret installation ve gerçek internet erişimi bilinmiyor; cloud hazırlama çalışan cloud demek değil.
- Tamamlama hedefi: Her model için hedef ortamı kur; TLS yenileme ve HTTP/WebSocket başlıklarını doğrula; DB/Studio'yu özel ağda tut; public endpoint ve onboarding'i kabul et.
- Zorunlu kapanış testi: Temiz makinede müşteri kimliğiyle giriş→cihaz→deny→olay→export→rollback akışı; dış port/izin kontrolleri ve sertifika yenileme tatbikatı.
- Dış bağımlılık/sınır: Alan adı, cloud hesabı/bölge ve ağ bilgisi

#### T29 — Kimliği doğrulanan dağıtım ve release provenance [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-05, DEP-08, OBS-05
- Kaynak: scripts/customer-kit.mjs, .github/scripts/build-release-bundle.mjs, scripts/release-artifact-manifests.mjs
- Güncel yerel durum: Release verifier receipt hedefini mutation öncesi doğruluyor ve bundle/state/policy çakışmasını reddediyor; resmi key custody/private registry açık.
- Başlangıç riski: Checksum yayıncı kimliği değildir. Private registry kurulumu, imza doğrulama, key rotasyonu ve air-gap imaj teslimi kanıtı yok.
- Tamamlama hedefi: Aynı candidate'ı imzala; auth kontrollü registry/download, provenance ve sabit imaj digestleriyle teslim et; air-gap satılıyorsa tüm bağımlılık/imajları dahil et.
- Zorunlu kapanış testi: Yanlış signer/değişmiş arşiv/eski sürüm reddedilsin; müşteri temiz makinede internetsiz veya yetkili registry ile kurabilsin; imza/anahtar iptali sınansın.
- Dış bağımlılık/sınır: Signer ve registry yetkisi; lisans onayı

#### T30 — HA, failover, kapasite ve SLA ölçümü [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-07
- Kaynak: deploy/dashboard/server.mjs, deploy/README.md
- Güncel yerel durum: Load harness her fault senaryosu için son hatadan sonra ardışık recovery ve tam gözlem istiyor; gerçek HA, kapasite ve aylık SLA açık.
- Başlangıç riski: HA topology, DB failover, tenant noisy-neighbor ve aylık availability SLI kanıtı yok; 99.9 ölçülmüş sonuç değil.
- Tamamlama hedefi: Desteklenen kapasite ve region topology tanımla; load/soak/failover, hata bütçesi ve ölçüm paydası kur.
- Zorunlu kapanış testi: Gerçekçi agent/event yükünde p50/p95/p99, hata/kayıp oranı, DB/servis/node arızası ve bakım etkisi raporlansın; kabul edilmiş gözlem penceresi tamamlanmış olsun.
- Dış bağımlılık/sınır: Host boyutları, filo/olay profili, SLA anlaşması

#### T31 — Migration, upgrade ve geri dönüş tatbikatı [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-03, DEP-04
- Kaynak: scripts/deployment-migrate.mjs, scripts/deployment-doctor.mjs
- Güncel yerel durum: Kesilen rename resume yalnız kaynak/staged içerik preflight hash'leriyle eşleşirse devam ediyor; gerçek trafik cutover/rollback kabulü açık.
- Başlangıç riski: Önceki müşteri sürümünden upgrade, sürüm karmaşası ve gerçek üretim rollback tatbikatı açık.
- Tamamlama hedefi: Desteklenen upgrade yolları, ön kontrol/yedek, kesinti planı, kompatibilite ve başarısız migration geri dönüş prosedürü hazırla.
- Zorunlu kapanış testi: Eski veriyle upgrade, kesilen migration, checksum değişikliği, uygulama/DB sürüm uyuşmazlığı ve kurtarma testi; veri kaybı ve sessiz schema drift olmasın.
- Dış bağımlılık/sınır: Önceki sürüm snapshotları ve bakım penceresi

#### T32 — İzleme, alarm ve işletim sahipliği [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-01, DEP-02, OBS-01
- Kaynak: docs/runbooks/alerting.md, docs/runbooks/incident-response.md
- Güncel yerel durum: Per-instance scrape/readiness ve empty-discovery alertleri eklendi; kural YAML/testleri var. Canlı paging, isimli nöbet ve SLA açık.
- Başlangıç riski: Production dashboard, nöbetçi, gerçek paging, sertifika/disk/kuyruk/feed/backup alarmı ve incident tatbikatı tamamlanmadı.
- Tamamlama hedefi: SLI dashboard ve alarm eşikleri, sorumlu/nöbet takvimi, alarm sessizliği kontrolü, escalation ve olay sonrası inceleme akışı kur.
- Zorunlu kapanış testi: Servis, DB, storage, signer, kuyruk ve yedek hatası enjekte et; doğru kişiye zamanlı alarm ve çözüldü bildirimi gelsin; kayıtlı tatbikat tut.
- Dış bağımlılık/sınır: Gerçek izleme/paging kanalları ve isimli sorumlular

#### T33 — Satılan fatura ve entitlement yaşam döngüsü [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: BIL-01, BIL-02, BIL-03
- Kaynak: packages/dashboard/src/ui/pages/BillingPage.tsx, supabase/functions/billing-checkout/index.ts, supabase/functions/stripe-webhook/index.ts
- Güncel yerel durum: billing-portal Edge Function provider-of-record durum makinesi, sunucu tarafi tenant/uyelik/rol/MFA cozumlemesi, istemci customer/tenant/subscription id reddi, TTL/idempotency, cancel/refund ve seat reconciliation uyguluyor; finance fixture ile test edildi, canli provider ve muhasebe onayi acik. Eski: Pending Finance sipariş sonucu tenant/request/quantity/quote alanlarına fail-closed bağlı; provider-of-record, ödeme makbuzu ve paid-to-entitlement yok.
- Başlangıç riski: Onaylı SKU/fiyat/teklif, tahsilat-mutabakat, quota değişimi, iptal ve çıkış provası yok. Self-service portal uygulanmamış; yalnız satılan SKU'da gerekiyorsa blocker.
- Tamamlama hedefi: Provider-of-record ve kurumsal sipariş→quota işletimini tamamla; self-service satılacaksa gerçek portal, invoice, cancel/refund/reconcile akışlarını ekle.
- Zorunlu kapanış testi: Sipariş/ek koltuk/azaltma/yenileme/ödeme hatası/iptal ve mükerrer webhook aynı entitlement sonucunu versin; finans mutabakatı ve müşteri makbuzu eşleşsin.
- Dış bağımlılık/sınır: Ticari karar, canlı provider anahtarları ve muhasebe onayı

#### T34 — Readiness kayıtlarının ve ürün iddialarının tutarlılığı [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: EVAL-02, EVAL-03, DEP-05
- Kaynak: docs/production-readiness/commercial-go-evidence-registry.json, READINESS_BACKLOG.json, README.md
- Güncel yerel durum: 71 özellik, 59 iş paketi, 10 release rootu ve claim candidate/expiry tutarlılığı otomatik kontrol ediliyor; 13 dış onay kapısı açık.
- Başlangıç riski: Ticari registry Ağustos tarihli ve artifactRoots/connector listesi mevcut dokuz paketi tam yansıtmıyor; eski checkout/default endpoint ifadeleri yeni implementasyonu anlatmıyor.
- Tamamlama hedefi: Tarihsel bulguyu korurken currentState alanlarını ayır; beklenen paket/connector kapsamını release manifestinden türet; web, README, demo ve teklif metnini tek kanıt sözlüğüne bağla.
- Zorunlu kapanış testi: Aynı sürümün paket/özellik/claim sayıları tutarlı; eksik paket zorunlu gate'i düşürsün; süresi dolmuş/onaysız iddia müşteri yüzüne çıkmasın.
- Dış bağımlılık/sınır: Güncel release candidate ve ticari onay sahipleri

#### T35 — Test kapılarının kapsamı ve başarısızlığın saklanmaması [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: EVAL-01, CON-05
- Kaynak: vitest.config.ts, packages/opencode/src/__tests__/aidr-contract.test.ts, scripts/verify-enforcement.mjs
- Güncel yerel durum: v7 birleşik test 237 dosya/3326 geçiş/2 açıklanmış skip, coverage eşikleri ve 10 paket release consumer geçti; native kör corpus açık.
- Başlangıç riski: Test sayısı özellik tamamlanması değildir; bazı gözlem testleri bilinen boşluğu allow olarak kabul ediyor. Native/soak/bağımsız corpus ve coverage kapanışı eksik; 132 lint uyarısı var.
- Tamamlama hedefi: Özellik→tüketici→pozitif/negatif→artefact bağını zorunlu kıl; bilinen açıkları test hedefi yap; mandatory skip ve stale evidence gate'i düşürsün; uyarı/dead-code borcunu sınıflandır.
- Zorunlu kapanış testi: Her satılan özellik için gerçek tüketicide deny/allow/outage kanıtı; aynı candidate checksum; 0 açıklanmamış zorunlu skip; değişmeyen timeoutlarla tekrar koşu ve açık borç kaydı.
- Dış bağımlılık/sınır: Native ortam, bağımsız corpus ve CI kapasitesi

#### T36 — Operatör UI ve ilk müşteri kullanılabilirliği [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: CLI-01, TEN-07, TEN-03, POL-02, OBS-03
- Kaynak: packages/dashboard/src/main.tsx, packages/dashboard/src/ui/pages/OnboardingPage.tsx, packages/dashboard/src/enterprise/audit-view.tsx
- Güncel yerel durum: Onboarding stale token/tenant/error durumları fail-closed ve yapılandırılmış Azure/Entra login görünür; gerçek browser/IdP/erişilebilirlik kabulü açık.
- Başlangıç riski: Tüm desteklenen tarayıcılar, klavye/erişilebilirlik, ağ hataları, çok ekipli eş zamanlı kullanım ve gerçek müşteri eğitimi tamam değil.
- Tamamlama hedefi: Ekran bazlı loading/empty/error/permission sözleşmesi, erişilebilirlik ve tarayıcı matrisi; ilk müşteri kılavuzunu gerçek operatörle uygula.
- Zorunlu kapanış testi: Yanlış ekipte sır/politika görünmesin; timeout/409/401 sonrası yanlış başarı olmasın; klavye ile kritik işler tamamlansın; büyük liste ve uzun değerlerde UI bozulmasın.
- Dış bağımlılık/sınır: Desteklenen browser ve müşteri kullanıcıları

#### T37 — Gerçek veri akışı, redaksiyon ve gizlilik kanıtı [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: OBS-01, OBS-03, OBS-06, TEN-01
- Kaynak: docs/privacy.md, packages/core/src/tracing.ts, supabase/functions/ingest/index.ts
- Güncel yerel durum: Privacy verifier canary boyunca source hash kararlılığı ve temp support-bundle izolasyonu istiyor; 6 canary/13 bundle kontrolü geçti, hukuk/saha açık.
- Başlangıç riski: Tüm outbound alan/domain listesi, browser tracing, managed olaylar, AIG payloadları, region, subprocessors ve silme kanıtı müşteri metinleriyle onaylanmadı.
- Tamamlama hedefi: Alan bazlı data-flow ve egress envanteri çıkar; ham prompt/komut/secret canary'leriyle paket/log/export/support bundle sözleşmesi kur; metinleri gerçek işleyişe eşle.
- Zorunlu kapanış testi: Canary sırlar izinsiz kanalda bulunmasın; opt-out ve retention davranışı ölçülsün; bütün veri sınıfları için bölge/erişim/silme sahibi belli olsun.
- Dış bağımlılık/sınır: DPA ve müşteri veri sınıflandırması; hukuk incelemesi

#### T38 — Kuruma özel DLP ve veri etiketleri [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DET-07
- Kaynak: packages/core/src/dlp/index.ts, packages/core/src/pii-detector.ts
- Güncel yerel durum: DLP overlapping ve JSON Unicode-escaped secret spanlarını tam redact ediyor; malformed/mapping/oversize fail-closed. Versioned CAS storage/history/audit/offboarding ve owner/admin+MFA publish sınırı uygulandı; imzalı agent delivery ve müşteri label kabulü açık.
- Başlangıç riski: Müşteri etiketleri, belge/attachment türleri, her bağlayıcıdaki giriş/çıkış yolu ve düşük yanlış alarm kabulü tamam değil.
- Tamamlama hedefi: Kural/etiket yönetimi, kapsam hedefleri, maskeleme/engelleme/approval eylemleri ve exception yaşam döngüsünü bağla.
- Zorunlu kapanış testi: Sentetik ve kuruma özgü sırlar tüm kapsanan giriş/çıkışlarda yakalansın; yetkili benign işlem geçsin; örnek dışı format unavailable olarak raporlansın.
- Dış bağımlılık/sınır: Etiket/kural sözlüğü ve maskelenmiş test verisi

#### T39 — Bağımsız etkinlik, performans ve rakip kıyaslaması [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: EVAL-01, EVAL-02, EVAL-03
- Kaynak: docs/production-readiness/agent-security-market-and-release-plan.md, docs/production-readiness/customer-investor-validation-master-plan.md
- Güncel yerel durum: Deterministik sentetik corpus, içerik-digest holdout manifesti, sold-scope coverage, confusion/P-R-F1/ROC-AUC, reason-coded unknown competitor hücreleri, trusted-key/duty-separation binding, ölçüm bütçesi, canonical digest ve byte-exact reproduce harness'ı uygulanıp test edildi. Gerçek müşteri benign corpus'u, competitor erişimi, bağımsız evaluator/trust kaydı ve bütçe onayı dış kanıt olarak açık.
- Başlangıç riski: En iyi ürün, sıfır false-positive, evasion dayanıklılığı veya latency üstünlüğünü gösteren bağımsız kanıt yok.
- Tamamlama hedefi: Geliştirme ve blind holdout setlerini ayır; saldırı ailesi/bağlayıcı bazında coverage, false block/approval, p50/p95/p99 ve limitations ölç; eşit koşullu karşılaştırma yap.
- Zorunlu kapanış testi: Aynı workload/ortamda ham ölçüm, payda, sürüm, örneklem ve bağımsız değerlendirici imzası; görünmeyen yüzeyler başarı ortalamasına katılmasın.
- Dış bağımlılık/sınır: Müşteri benign corpus'u, rakip değerlendirme erişimi, ölçüm bütçesi

#### T40 — Güvenlik güncellemesi ve müşteri destek işletimi [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: DEP-05, OBS-05
- Kaynak: docs/runbooks/incident-response.md, docs/production-readiness/support-sla-template.md
- Güncel yerel durum: Support v7 runbook, izinli/hashli bundle, escalation ve emergency update akışı hazır; gerçek kanal, nöbet ve ticket tatbikatı açık.
- Başlangıç riski: Çalışan ticket/security contact, nöbet, CVE/incident bildirimi, imzalı acil güncelleme, EOL ve tanılama izni işletimi onaylı değil.
- Tamamlama hedefi: Destek planı, severity/response hedefi, escalation, PSIRT/sorumlu, patch dağıtımı, EOL ve redakte tanılama prosedürü kur.
- Zorunlu kapanış testi: Gerçek ticket aç/kapat, kritik incident ve imza anahtarı kaybı tatbikatı; müşteri bildirim süresi, rollback ve sır içermeyen tanılama kanıtlansın.
- Dış bağımlılık/sınır: İsimli ekip, iletişim kanalları, sözleşme ve çalışma saatleri

#### T41 — İlk müşteri satış ve satın alma değerlendirme paketi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: EVAL-02, EVAL-03, BIL-01
- Kaynak: docs/production-readiness/controlled-demo-runbook.md, docs/production-readiness/customer-investor-validation-master-plan.md, docs/production-readiness/enterprise-order-entitlement-template.md
- Güncel yerel durum: Güncel ilk müşteri satış paketi ve portable kit üreticisi var; yeni v7 kit imzası ile onaylı teklif/satın alma kabulü açık.
- Başlangıç riski: Müşterinin satın alma sürecine uygun onaylı ürün özeti, mimari/veri akışı, destek matrisi, güvenlik soru formu, kapsamlı teklif ve kanıta dayalı demo/PoV paketi tek sürümde birleştirilmedi. Bu çalışma ortamındaki static preflight satış URL/e-posta ayarı bulamadı; üretim satış CTA hedefi ayrıca doğrulanmalı.
- Tamamlama hedefi: Ürün özeti, gereksinimler, deployment seçenekleri, desteklenen araçlar, açık sınırlar, güvenlik/tedarikçi soru yanıtları, teklif ve PoV başarı ölçütlerini satış kitinde topla; ölçülmemiş ROI veya sertifikasyon iddiası ekleme.
- Zorunlu kapanış testi: Bir operatör kılavuzdan demoyu tekrar edebilsin; procurement soruları kaynak/kanıt/owner'a bağlı olsun; teklif kapsamı ile kurulan özellik ve destek koşulları eşleşsin; müşteri adı olmadan referans/başarı hikayesi uydurulmasın.
- Dış bağımlılık/sınır: Müşteri satın alma formu, teklif sahibi, onaylı ürün kapsamı

#### T42 — Legacy RLS tenant yaşam döngüsü ve itibar satırı sahteciliği [P0; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-01, DET-10, DET-11
- Kaynak: supabase/migrations/20260912000019_tenant_lifecycle_rls.sql, scripts/tenant-lifecycle-rls-postgres.test.mjs
- Güncel yerel durum: Eski izin verici RLS kaldırıldı; forged claim, expired member, suspended tenant ve service-role kontrolleri yerel PostgreSQL'de geçti. Saha migrationı açık.
- Başlangıç riski: Yeni migration yetkiyi kapatır; önceden yazılmış olabilecek sahte satırlar otomatik temizlenmez ve kurulu müşteri verisi denetlenmedi.
- Tamamlama hedefi: Migrationı uygulamadan önce tenant itibar satırlarını denetle; migrationı kontrollü uygula, kalıcı rol matrisi ve PostgREST negatif testini çalıştır.
- Zorunlu kapanış testi: Eski üye veya askıya alınmış tenant okuyamasın; başka tenant için insert reddedilsin; mevcut veride sahte kayıt kalmasın ve servis rolü işlemleri çalışsın.
- Dış bağımlılık/sınır: Mevcut deployment verisi ve migration penceresi

#### T43 — Enrollment exchange işlem bütünlüğü [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-05, TEN-06
- Kaynak: supabase/migrations/20260912000017_enrollment_exchange_atomic.sql, supabase/functions/enroll/index.ts
- Güncel yerel durum: Atomik token/seat/key RPC ve lost-response sonucu unknown sözleşmesi var; plaintext-key recovery protokolü ve canlı HTTP kabulü açık.
- Başlangıç riski: Yeni RPC atomik yazıyor; müşteri HTTP akışında kayıp yanıt, eski kayıt ve eşzamanlı seat yarışı henüz sınanmadı.
- Tamamlama hedefi: Migrationı dağıt, canlı HTTP hata enjeksiyonuyla token/seat/key durumunu doğrula, belirsiz commit sonrası yeniden kayıt operatör prosedürünü hazırla.
- Zorunlu kapanış testi: Hata rollback yaparken token yeniden kullanılabilsin; başarıda yalnız bir kimlik oluşsun; kayıp yanıt açık unknown durumuna düşsün.
- Dış bağımlılık/sınır: Müşteri kurulum ortamı ve canlı DB

#### T44 — Entitlement grace ve eski imzalı önbellek geçişi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-05, POL-04
- Kaynak: supabase/functions/enroll/index.ts, supabase/functions/ingest/index.ts, packages/core/src/managed.ts
- Güncel yerel durum: Cache unsigned/unknown/schema-invalid entitlement'ı atıyor; kesin invalid_api_key signed state'i temizliyor, geçici hata grace'i koruyor. Canlı kabul açık.
- Başlangıç riski: Kod düzeltildi; önceki yanlış imzalı snapshotlar çevrimdışı iken düzelmez, canlı Deno ve zaman geçişi kabulü açık.
- Tamamlama hedefi: Yeni entitlementları dağıtıp önbelleği güvenli yenile; saat sınırı ve eski istemci geçişi tatbikatı yap.
- Zorunlu kapanış testi: 168 saat sonrasında 72 saat grace, ardından deny; iptal edilen/bozuk anahtar her aşamada reddedilsin.
- Dış bağımlılık/sınır: İmzalı eski kayıtlar ve müşteri ağ takvimi

#### T45 — Device-start güvenilir IP ve giriş yönlendirmesi [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-05, DEP-01, DEP-02
- Kaynak: supabase/functions/device-start/index.ts, deploy/ingress/device-start.mjs
- Güncel yerel durum: Device-start signer placeholder/reused secret'i reddediyor; HMAC ingress/rate limit var. Gerçek public proxy/TLS routing ve müşteri yükü açık.
- Başlangıç riski: İmzalı ingress ve küresel sınır kodlandı; Nginx/TLS yönlendirmesi ve iki özel anahtarın müşteri ortamında kurulumu henüz kanıtlanmadı.
- Tamamlama hedefi: Cloud ve self-hosted girişini signer üzerinden geçir; proxy başlıklarını temizle, doğrudan Edge yolunu engelle ve yük testini çalıştır.
- Zorunlu kapanış testi: Sahte başlıklar oranı değiştirmesin; imzasız istek 401; meşru kayıt akışı iki dağıtım modelinde çalışsın.
- Dış bağımlılık/sınır: TLS proxy, sır yönetimi ve müşteri ağı

#### T46 — Device-poll onaydan kayda atomik geçiş [P1; LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN]

- İlgili özellikler: TEN-05
- Kaynak: supabase/functions/device-poll/index.ts, supabase/migrations/20260912000017_enrollment_exchange_atomic.sql
- Güncel yerel durum: Device-poll kayıp yanıt/eşzamanlı poll'da aynı hash-only tokenı geri buluyor, lookup hatasında 503 unknown dönüyor; canlı yarış kabulü açık.
- Başlangıç riski: Yeni RPC atomik; canlı HTTP retry, yarış ve müşteri tarayıcısı/CLI kabulü açık.
- Tamamlama hedefi: Migrationı dağıtıp onay, poll ve enroll tam akışını hata enjeksiyonu ile çalıştır; eşzamanlı poll ve kayıp yanıtı ölç.
- Zorunlu kapanış testi: Bir onay en çok bir token üretir; insert hatası oturumu tüketmez; tekrar poll belirsiz durum olarak raporlanır.
- Dış bağımlılık/sınır: Canlı kurulum ve gerçek cihaz

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

#### COM-001 — Onaylı SKU, fiyat, teklif ve ticari sürüm manifesti [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Commercial/Sales + Finance/Billing
- Eksik: Aynı sürüme bağlı SKU, fiyat, ölçüm birimi, para birimi/vergi, kurulum modeli, bölge, saklama, SLA, destek, lisans hakkı, yenileme, iptal ve çıkış koşulları onaylanmamış.
- Hazırlanacak iş: Satış ve finans tek ticari manifesti onaylasın; örnek teklif/siparişten müşteri çıkışına kadar prova yapılsın.
- Kapanış kanıtı: İsimli onaylı ticari manifest; Örnek teklif ve sipariş; Siparişten offboarding'e prova; Sürüm ve değiştirilemeyen kanıt özeti
- Otomatik kontrol: claim-check --mode=gate plus signed-manifest verification

#### COM-002 — Lisans, fikri mülkiyet ve üçüncü taraf hakları [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Legal + Engineering
- Eksik: Lisans dosyası bulunması yeterli değil: dağıtılan kod/veri/model/üçüncü taraf bileşen hakları, atıflar ve fikri mülkiyet zinciri hukukça onaylanmamış.
- Hazırlanacak iş: SBOM ve kaynak kökenini lisans/NOTICE/package metadata ile uzlaştır; dağıtım haklarını ve süreli istisnaları yetkili hukuk incelemesine sun.
- Kapanış kanıtı: Hukuk onayı; Eksiksiz LICENSE/NOTICE ve üçüncü taraf lisans paketi; Paket lisanslarının uzlaştırılması; Kaynak/vendor kökeni ve süreli istisna kaydı
- Otomatik kontrol: claim-check --mode=gate (license/NOTICE/package metadata check) plus licence inventory

#### COM-003 — Veri işleme, DPA ve gizlilik onayı [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Privacy/DPO + Legal + Security
- Eksik: Gerçek telemetri, browser tracing, managed olaylar, AIG payloadları, retention/silme, veri bölgesi, alt işleyenler ve transferler müşteri belgeleriyle onaylı biçimde eşleştirilmemiş.
- Hazırlanacak iş: Alan bazlı veri akışını ölç; müşteri bildirimi ve gerekli veri işleme/güvenlik eklerini Privacy/Legal sahipleriyle tamamla.
- Kapanış kanıtı: Alan bazlı veri akış matrisi ve payload testleri; DPA/TOM/SCC kapsam inceleme ve onayı; Alt işleyen/bölge listesi; Gerçek export ve silme makbuzu
- Otomatik kontrol: privacy-payload-contract and outbound-domain/redaction gates

#### COM-004 — Fatura–ödeme–entitlement mutabakatı [open]

- Profiller: assisted-sale, production-ga, investor
- Sorumlu: Finance/Billing + Product
- Eksik: Sipariş, koltuk değişimi, fatura/mutabakat, iptal, erişim iptali ve müşteri silme tek kayıt sistemine göre uçtan uca kabul edilmemiş.
- Hazırlanacak iş: Tek provider-of-record belirle; finans işlemlerini sunucudaki entitlement ile bağla; başarısız/tekrarlanan olay ve manuel müdahale işletimini tanımla.
- Kapanış kanıtı: Provider ve SKU kararı; Quota/entitlement senaryoları; Fatura ve mutabakat örneği; İptal, erişim kesme ve silme makbuzu
- Otomatik kontrol: billing contract suite and quote-to-offboarding rehearsal

#### COM-005 — Çalışan destek ve müşteri iletişim yolları [open]

- Profiller: evaluation, assisted-sale, production-ga
- Sorumlu: Support/Customer Success + Operations
- Eksik: Müşterinin gerçekten ulaşabildiği destek, durum sayfası, güvenlik iletişimi, privacy/terms, escalation, severity hedefi ve tanılama izni işletimi kanıtlanmamış.
- Hazırlanacak iş: Kanalları yayınla; çalışma saatleri ve isimli nöbet/escalation sorumlularını ata; gerçek ticket tatbikatı yap.
- Kapanış kanıtı: Yayınlanmış destek/SLA planı; Zaman damgalı ticket tatbikatı; Çalışan status/security/privacy bağlantıları; Nöbet ve escalation kaydı
- Otomatik kontrol: deployed route/link crawl; ticket drill is manual evidence

#### COM-010 — Reklamı yapılan tüm bağlayıcıların kabulü [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Product + QA + Engineering + Support
- Eksik: Reklamı yapılan bağlayıcıların her biri için gerçek host desteği, imzalı paket, özel registry kurulumu, geri dönüş ve destek sahibi tamam değil. Registry'nin kapsam listesi ayrıca güncellenmeli.
- Hazırlanacak iş: Satılan connector manifestini sabitle; her connector/host/OS sürümünde aynı imzalı candidate için kurulum, native E2E, rollback ve disable kabulü topla.
- Kapanış kanıtı: Tam destek matrisi; Gerçek host test raporları; Private registry kurulum kayıtları; Rollback/disable tatbikatı; İsimli sahip ve sınırlar
- Otomatik kontrol: expected connector manifest, package consumer tests, real-host E2E and claim-check

#### COM-011 — Bölge ve veri yerleşimi kanıtı [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Operations + Privacy/DPO + Legal
- Eksik: Registry'deki EU/US/APAC hedefleri çalışan ve onaylı bölge hizmeti kanıtı değildir; tenant yerleşimi, routing, yedek/silme ve transfer modeli açık.
- Hazırlanacak iş: Satılacak bölgeleri provider ve veri işleme modeliyle eşle; her bölgede tenant yerleşimi ve sınır dışı erişim negatif testlerini tamamla.
- Kapanış kanıtı: Bölge/provider matrisi; Tenant yerleşim testi; Cross-region negatif test; Veri işleme onayları; Bölgeye bağlı yedek/silme makbuzları
- Otomatik kontrol: region manifest, outbound-domain/data-flow assertions and deployment smoke per region

#### COM-012 — Faturalı ve kimliği doğrulanan özel dağıtım [open]

- Profiller: assisted-sale, production-ga, investor
- Sorumlu: Finance/Billing + Release Engineering + Support
- Eksik: Kurumsal fatura ile verilen erişimin kimliği doğrulanan private registry ve imzalı artefact teslimiyle çalıştığı kanıtlanmamış; air-gap prosedürü de tamam değil.
- Hazırlanacak iş: Sipariş→entitlement→download→install→revoke/offboard zincirini gerçek müşteri erişim modeliyle tamamla; offline satılıyorsa imaj/bağımlılık teslimini ekle.
- Kapanış kanıtı: Provider ve registry kararı; Faturadan entitlement'a test; İmzalı paket kurulumu; İptal/offboarding testi; Doğrulanmış air-gap prosedürü
- Otomatik kontrol: private-registry consumer install and entitlement contract suite

#### COM-013 — 99.9% SLA için ölçüm ve sözleşme [open]

- Profiller: assisted-sale, production-ga, investor
- Sorumlu: Operations + Legal + Support + Finance
- Eksik: 99.9% aylık availability bir hedef; ölçülmüş SLI, payda, kapsam dışı durumlar, bakım politikası, servis kredisi ve incident kanıtı tamam değil.
- Hazırlanacak iş: SRE/Legal/Support/Finance ölçüm ve sözleşme kapsamını onaylasın; kabul edilen gözlem penceresinde veriyi topla ve incident tatbikatı yap.
- Kapanış kanıtı: Onaylı SLA ve destek planı; SLI tanımı, payda ve gözlem penceresi; Bakım ve kapsam dışı durumlar; Servis kredisi koşulları; Incident kanıtı
- Otomatik kontrol: monthly SLI/error-budget report and SLA manifest check

#### SEC-EXT-001 — Bağımsız güvenlik değerlendirmesi ve yeniden test [open]

- Profiller: assisted-sale, production-ga, investor
- Sorumlu: Security Lead + independent assessor
- Eksik: Satılan candidate için bağımsız güvenlik değerlendirmesi, bulgu giderme ve yeniden test raporu yok.
- Hazırlanacak iş: Bağımsız değerlendiriciyle scope/tarih belirle; tenant, kimlik, runtime, dağıtım ve sır sınırlarını kapsa; bulguları kapat ve yeniden test ettir.
- Kapanış kanıtı: İmzalı bağımsız rapor ve kapsam; Remediation/retest mektubu; Çözülmemiş kritik bulgu olmaması; Yüksek bulgularda registry'nin gerektirdiği gerekçeli isimli ve süreli kabul
- Otomatik kontrol: assessment evidence expiry/RC match check

#### POV-001 — İsimli müşteri PoV ve kabul kaydı [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Customer Success + Product + evaluator
- Eksik: İsimli müşteri/değerlendirici aynı candidate üzerinde zorunlu senaryoları ve sınırları inceleyerek kabul vermedi.
- Hazırlanacak iş: Değerlendirme sözleşmesi/charter, bağımsız sandbox, zorunlu testler ve müdahale/sapma kaydını tamamla; müşterinin kabul/çekincelerini kaydet.
- Kapanış kanıtı: İmzalı charter; Bağımsız koşu raporu; Müdahale ve sapma günlüğü; Müşterinin kabul/çekinceleri; Değiştirilemeyen kanıt indeksi
- Otomatik kontrol: expected-suite manifest and evidence-index completeness; acceptance is manual

#### INV-001 — Yatırımcı metriklerinin kanıt ve onay sözlüğü [open]

- Profiller: investor
- Sorumlu: Product + Finance + Legal
- Eksik: Yatırımcıya sunulan teknik başarı, müşteri, güvenlik, uyum, traction ve finans ölçülerinin tamamı formül/payda/kaynak/dönem/sürüm/onay sahibiyle kayıtlı değil. Bu kapı yatırımcı profili içindir.
- Hazırlanacak iş: Her metriği veri sorgusuna veya imzalı kaynağa bağla; örneklem, dönem, sınır ve belirsizliği yaz; Product/Finance/Legal incelemesi al.
- Kapanış kanıtı: Onaylı metrik sözlüğü; Kaynak sorgu veya imzalı belge; Dönem/örneklem/payda; İnceleyen kişi onayı
- Otomatik kontrol: metric dictionary/evidence-index completeness

#### CLM-001 — Müşteri ve satış iddialarının kanıt onayı [open]

- Profiller: evaluation, assisted-sale, production-ga, investor
- Sorumlu: Product/Marketing + Commercial + Legal
- Eksik: Landing, README, plugin, teklif, procurement ve yatırımcı metinlerinin tamamı onaylı, güncel ve aynı sürüme bağlı iddia kanıtıyla eşlenmiş değil.
- Hazırlanacak iş: Her iddiayı Claim Registry'ye bağla; kaynak ve derlenmiş yüzeyleri tara; yalnız süresi geçmemiş Sales Approved ifadeleri yayınla.
- Kapanış kanıtı: Registry snapshot; Derlenmiş çıktı tarama JSON'u; İddia→kanıt bağlantıları; Sales Approved incelemesi
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

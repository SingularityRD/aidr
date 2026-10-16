# Production'a hazırlık — kalan eksikler promptu (11 Ekim 2026 sonrası)

Bu dosyanın **PROMPT** bölümünü, kalan eksikleri kapatacak ajana ya da ekibe tek prompt olarak ver.

Bu prompt [PRODUCTION_READY_PROMPT-2026-10-10.md](./PRODUCTION_READY_PROMPT-2026-10-10.md) dosyasının devamıdır. O prompttaki kod bulgularının tamamı kapandı ve merge edildi ([SingularityRD/aidr#145](https://github.com/SingularityRD/aidr/pull/145), `master` @ `eca71088`; [SingularityRD/aidr-landing#1](https://github.com/SingularityRD/aidr-landing/pull/1)).

Geriye kalanların çoğu kod işi değil. Bunlar gerçek ortam, yetkili kişi ya da ürün sahibi kararı gerektiriyor. Bu yüzden prompt, ajanın tek başına yapabileceği işi, ortam verildiğinde yapacağı işi ve yalnız insanların kapatabileceği kapıları ayrı ayrı tanımlar.

Kaynak kayıtlar:
- [production-gaps-closure-2026-10-11.md](../audit/production-gaps-closure-2026-10-11.md): ana kayıt ve ek
- [production-gaps-2026-10-10.md](../audit/production-gaps-2026-10-10.md)
- `READINESS_BACKLOG.json`
- `docs/production-readiness/commercial-go-evidence-registry.json`
- `docs/production-readiness/commercial-gate-receipts.json`

---

## PROMPT

Sen otonom bir kodlama ajanısın ve kıdemli bir güvenlik, platform, SRE ve release ekibi gibi çalışıyorsun. Çalışma alanın `SingularityRD/aidr` repo kökü (gerektiğinde `SingularityRD/aidr-landing`). Ürün **Singularity AIDR**; mimari ve kurallar `CLAUDE.md` dosyasında.

### Hedef

Kararı **NO-GO**'dan **PRODUCTION_SALES_GO**'ya taşı. Bunun için kalan her eksik kapanmalı:
- Kod gerektirenler kod, test ve kanıtla kapanır.
- Ortam gerektirenler gerçek ortamda koşturulup kanıtlanır.
- İnsan kararı gerektirenler isimli sahibin imzalı makbuzuyla kapanır.

Kapanmayan madde için uydurma kanıt üretme. Maddeyi açık bırak ve sahibine tam olarak neyin gerektiğini yaz.

### Doğruluk sözleşmesi (ihlal edilemez)

1. Karar yalnız `commercial-go-evidence-registry.json` ve `commercial-gate-receipts.json` ile değişir. Bu iki dosyayı yalnız şu koşullarda değiştir:
   - aynı aday digest'ine bağlı gerçek kanıt var;
   - isimli bir sahip onaylamış;
   - kanıtın tarihi ve hash'i kayıtta.
2. Aşağıdakiler gerçek host, bulut, pentest, PoV, SLA veya hukuk kanıtı **değildir**: unit test, mock, sentetik korpus, scripted mock-model, tek host üzerinde yapılan yerel prova, developer build.
3. Testi geçirmek için assertion silme, timeout veya bütçe büyütme, skip ekleme, allowlist genişletme yasak.
4. Secret, token, private key, müşteri verisi veya ham prompt; kaynağa, loga, kanıta ya da release'e girmez. Kanıtta yalnız fingerprint ve hash kullan.
5. Ortam ya da yetki yoksa dur. Kalan bağımsız işleri bitir. Raporuna eksik olanla başla: hangi ortam, kimin yetkisi, hangi komut.
6. "Yüzde X hazır", "neredeyse hazır", "production-grade" gibi ifadeler kullanma.

### Çalışma kuralları

- **Başlangıç kaydı:** başlarken şunları not et: `git status`, HEAD, OS/arch, Node/pnpm/Python/Docker sürümleri.
- **Dal ve PR:** `master`'a doğrudan push yapma. Her iş paketi ayrı bir dalda, atomik commit'lerle ve taslak PR olarak gider. Kullanıcı açıkça istemedikçe merge, tag ya da publish yapma.
- **PR öncesi:** değişen dosyalarda `code-simplifier` alt ajanını çalıştır.
- **Kapanış kaydı:** her kapanışta kod yolu, test, gözlenen gerçek yan etki, aday digest, sahip ve tarih yer alır. Kayıt `docs/production-readiness/` altında yeni tarihli bir belgeye ve `READINESS_BACKLOG.json`'a yazılır. Tarihli kayıtlar yeniden yazılmaz; yeni kayıt eklenir.
- **Üretilmiş dosyalar:** `FEATURE_INVENTORY.*`, `PRODUCTION_SALES_GAPS.*` ve evidence index elle değil, jeneratörle güncellenir.
- **Her PR'dan önce yerel kapı:**
  - `pnpm check && pnpm build && pnpm lint && pnpm test`
  - `pnpm test:privacy`
  - `pnpm ci:local --keep-going --fetch-tools`
  - Docker varsa Postgres adımları dahil.
  - Ortamsal SKIP'leri gerekçesiyle listele.

### Başlangıç durumu (11 Ekim 2026, `master` @ `eca71088`) — işe başlarken yeniden ölç

**Yerel kapılar**

| Kontrol | Sonuç |
| --- | --- |
| `check`, `build`, `lint` | Yeşil |
| Unit test | 11.699 geçti, 0 başarısız |
| Privacy | 1.535 geçti |
| Real-host E2E | 4/4 host, tüm senaryolar PASS (linux/x64, mock model) |
| Interception matrisi | 0 hata |

Bunlardan biri kırmızıya döndüyse önce onu düzelt.

**Kurumsal kapılar:** 13 kapının hepsi açık.
- COM-001…005, COM-010…013
- SEC-EXT-001, POV-001, INV-001, CLM-001

**Kapanmamış backlog maddeleri:**

| Madde | Durum | Konu |
| --- | --- | --- |
| AIDR-016 | `BLOCKED_EXTERNAL` | Control-plane erişimi |
| AIDR-019 | `IN_PROGRESS` | Canlı enrollment ve SCIM |
| AIDR-044 | `BLOCKED_EXTERNAL` | Offsite yedek ve ayrı hata alanı |
| AIDR-049 | `BLOCKED_EXTERNAL` | Production deployment ve native host |
| AIDR-050 | `BLOCKED_EXTERNAL` | Fleet installer ve update |
| AIDR-051 | `BLOCKED_EXTERNAL` | Sürekli keşif ve delegasyon |
| AIDR-052 | `BLOCKED_EXTERNAL` | HA, 8 saat soak, SLA |
| AIDR-070 | `BLOCKED_EXTERNAL` | Secret geçmişi, owner kararı |
| AIDR-079 | `IMPLEMENTED_UNVERIFIED` | Landing imajı |
| AIDR-080 | `BLOCKED_EXTERNAL` | Upstream Supabase imajları |

### A. Ajanın tek başına yapabilecekleri (önce bunları bitir)

1. **AIDR-079 kapanışı.**
   - Landing [PR #1](https://github.com/SingularityRD/aidr-landing/pull/1) merge edildi. Trivy 0.73.0 taraması (ignore yok) 0 CRITICAL / 0 HIGH verdi.
   - Merge edilmiş `main`'den imajı yeniden kur, tara ve runtime kontrollerini koş: read-only rootfs, `cap-drop ALL`, nonroot, `/api/health` ve `/api/ready` için JSON + `no-store`.
   - Kanıtı tarihli kayda yaz. Backlog'da `localEvidence` ile `VERIFIED_CLOSED` yap.
   - Firebase grpc-js override'ının (`@grpc/grpc-js@<1.14.5 → ^1.14.5`) Firestore emülatör smoke'unu yeniden koş.
2. **Satış PDF'leri ve feature guide.**
   - Brochure/catalog PDF ve PNG önizlemeleri eski NER/OCR ifadelerini taşıyor; layout kontrolü önceki ortamda kırıldığı için render edilemediler.
   - `docs/product/features` bölüm 16 ve 20 hâlâ NER/OCR'ı opsiyonel özellik gibi anlatıyor.
   - Yapılacaklar: layout kontrolünün neden kırıldığını bul, render'ı düzelt, `first_release_scope` ile uyumlu içeriği yeniden üret. Ardından `node docs/scripts/claim-check.mjs --mode=gate` ve commercial adımları yeşil olmalı.
3. **Kayıt temizliği.**
   - `production-gaps-closure-2026-10-11.md` içindeki "uncommitted working tree" ifadeleri bayat: o değişiklikler `a455f355` ile commit edildi. Tarihli kaydı yeniden yazma; düzeltmeyi yeni tarihli bir ek olarak yaz.
   - `RELEASE_READINESS_REPORT.md` ve `FEATURE_ACCEPTANCE.json` jeneratörsüz ve bayat: kaynaktan güncelle.
4. **Kod artıkları.** Her biri ayrı PR, test ile.
   - **VS Code native araç listesi elle sayılmış.** Listede olmayan native shell/file araçları politika katmanını atlıyor; sezgisel kurallar yine çalışıyor.
     - Yapılacak: VS Code'un güncel araç referansıyla listeyi doğrula ve eksikleri ekle.
     - Bilinmeyen ama shell/file alanı taşıyan araçları (`command`, `filePath`, `content` gibi) canonical işleme eşleyen bir yedek kural ekle.
     - Yapılamıyorsa bu bir ürün kararıdır: bilinmeyen native araç için `ask` mı verilecek? Sahibine sor.
   - **PostgREST yeniden bağlanma gecikmesi.** Ağ kesintisinden sonra toparlanma hâlâ 11–24 saniye sürüyor. Kaynak, PostgREST v14'ün ayarlanamayan backoff'u.
     - Yapılacak: upstream'de ayar ya da sürüm var mı araştır.
     - İstemci tarafında request deadline ve ilgili ayarları değerlendir. Request timeout'larını kısaltarak testi "geçirme".
   - **Paket ve imaj yenilemeleri.** Supabase upstream'de yeni tag'ler çıktığında AIDR-080 triage'ını tekrarla (Trivy, aynı yöntem). Uyumlu fix'leri pinle ve etkilenen servislerin native kabulünü koş.
   - **GO zinciri provası.** Sahte bir GO kaydıyla (yalnız test fixture'ında, gerçek registry'de değil) promote → rollback yolunu `release-promote.yml`'in dry-run job'u üzerinden uçtan uca kanıtla. Actions kapalıysa `act` ya da yerel simülasyon kullan ve bunu açıkça etiketle.

### B. Ortam verildiğinde ajanın yapacakları (her biri için ortamı/erişimi sahibinden iste)

Her maddede önce ortam envanterini kaydet: OS build, host sürümü, donanım, AV/EDR. Sonra komutları koş. Başarısızlıkları, atlamaları ve elle müdahaleleri olduğu gibi sakla.

1. **Native host matrisi** (madde 27, T01-NATIVE-SCENARIOS, T01-OS-VERSION-MATRIX, COM-010, AIDR-049).
   - **Ortam:** satılacak her host (Claude Code, Codex, OpenCode, OpenClaw, Cursor, VS Code) için Windows, macOS ve Linux tek kullanımlık makineler; desteklenen sürüm listesi Endpoint Engineering'den gelir.
   - **Komutlar:** `pnpm test:e2e:real-host --evidence-dir docs/evidence/real-host`, `pnpm test:e2e:cursor`, `pnpm test:e2e:vscode`, `deploy/native/scenarios/` senaryoları.
   - **Senaryolar:** denied side effect, benign twin, disabled hook, crash, timeout, offline, restart, upgrade, uninstall.
   - **Windows:** compile cache'i `AIDR_ENABLE_COMPILE_CACHE=1` ile ölç. Hook gecikmesini Defender açıkken ve ACL yolu dahilken ölç (madde 30).
   - **Kabul:** hook verdict'inin yanında gerçek kalıcı yan etkinin gözlenmesi; imzalı artefakt hash'i; isimli QA/Endpoint onayı. `support-matrix.json` sha pinlerini güncelle ve `pnpm verify:interception-matrix` 0 hata vermeli.
2. **Windows NER lock yükseltmesi** (madde 22, CVE-2025-47273).
   - **Ortam:** `download.pytorch.org`'a erişebilen bir host.
   - **Yapılacaklar:**
     - setuptools'u en az 78.1.1'e yükselterek koordineli re-lock yap.
     - Evidence'ı `scripts/extract-pypi-license-metadata.py` ile final lock'tan yeniden üret.
     - Binding verifier 0 sorun vermeli.
     - Windows'ta offline hash'li kurulum, `pip check` ve gerçek inference.
   - **Prosedür:** `packages/privacy/ner/DEPENDENCIES.md`.
3. **Canlı deployment** (madde 32, AIDR-016, AIDR-049).
   - **Erişim:** DNS, Cloudflare Worker ve hosting hesabı.
   - **Kabul edilecekler:**
     - doğru DNS ve TLS;
     - Worker route;
     - `readyz`/`version` için JSON + `no-store`;
     - deploy edilen revision'ın aday digest'iyle eşleşmesi;
     - gerçek login ve enrollment.
   - **Operatör adımları** (`NO_GO_TO_GO_GAP_LIST.md` I.2'ye ek olarak):
     - `AIDR_OIDC_CLIENT_SECRET_BINDINGS` tanımlı olmalı. Tanımlanmazsa secret kullanan SSO girişleri çalışmaz.
     - PostgreSQL 17.11 yükseltmesi `deploy/backup/README.md` prosedürüyle yapılır: önce yedek, sonra restore provası.
     - Yeni migration'lar uygulanır.
     - Studio'ya yalnız SSH tüneliyle erişilir.
4. **Kimlik** (madde 28, AIDR-019).
   - **Ortam:** gerçek Entra, Okta ve Clerk tenant'ları.
   - **Senaryolar:** değişmez grup ID eşlemesi, grup kaldırma, deaktivasyon, başka directory'den üyelik, sayfalama/replay, tenant karışması, erişimin tanımlı sürede kesilmesi.
   - **Ek kabul:** canlı SCIM provisioning ve tarayıcıdan uçtan uca device enrollment.
5. **HA, yük ve SLA** (madde 37, AIDR-052, COM-013).
   - **Ortam:** satılan topolojide gerçek altyapı: en az iki hata alanı, yönetilen ya da self-hosted HA.
   - **Yapılacaklar:**
     - Kalibre, ayrı bir load-generator ile en az 8 saatlik authenticated soak koş.
     - İki tenant'lı noisy-neighbour senaryosu koş.
     - Node, DB, ağ ve hata alanı kesintilerini enjekte et, toparlanmayı ölç.
   - **Araç:** `scripts/load-test.mjs`'in `--timeseries-interval-seconds` ve `--request-ledger` seçenekleri ile olay mutabakatı.
   - **SLA:** aylık SLI için tam bir ay gözlem penceresi gerekir. 8 saatlik soak SLA kanıtı değildir.
6. **Yedek ve legal hold** (madde 34, AIDR-044).
   - **Ortam:** ayrı bir host, gerçek offsite depolama, ayrı recovery-key emanetçisi.
   - **Yapılacaklar:**
     - Aday sürümün yedeğini başka bir hosta restore et.
     - Login, tenant, policy, audit, object ve agent işlevlerini doğrula.
     - Gerçek trafik cutover süresini ölç.
     - Onaylı RPO/RTO hedeflerini kayda al.
     - Offsite prune'un `tenant_legal_holds`'u okuması için hold-aware workflow'u uygula ve test et (şu an okumuyor).
7. **Kurum çıkış kapsamı** (madde 29).
   - **Ortam:** MDM, ağ, broker, CA ve vault.
   - **Yapılacak:** canary hassas veriyle izin verilmeyen kanallarda gerçek egress capture yap.
   - Browser Guard'ı ağ filtresi diye satma.
8. **Saha kabulleri** (madde 36, AIDR-050, AIDR-051).
   - **Kapsam:** fleet installer, update, rollback ve uninstall (MDM ile); sürekli keşif collector'ları; delegasyon.
   - **Kabul:** her biri gerçek tüketicide malicious, benign ve outage senaryolarıyla.
9. **İmzalı aday** (madde 35).
   - **Yetki:** onaylı yayıncı anahtarı.
   - **Yapılacaklar:**
     - Temiz snapshot'tan `pnpm build:release` al; SBOM, provenance ve imza üret.
     - `pnpm quality:gate`, `pnpm evidence:index` ve `node scripts/run-evidence-gates.mjs --profile first-customer-local` aynı aday digest üzerinde koşmalı.
     - Bütün B maddelerinin kanıtları bu digest'e bağlanır. Eski kanıt yeni aday için kullanılmaz.

### C. Yalnız insanların kapatabileceği kapılar (ajan sahip paketini hazırlar, kapatmaz)

Her kapı için tek bir sahip paketi hazırla. Pakette şunlar olsun:
- sahip rolü;
- gereken girdiler;
- doldurulmuş şablon;
- çalıştırılacak doğrulama komutu: `node scripts/verify-commercial-gate-receipts.mjs --candidate-digest <digest>`;
- kabul çıktısı ve hash bağlama biçimi;
- ret durumunda ne olacağı.

Mevcut ön doldurmalar `docs/production-readiness/commercial-gates-prefill-and-owner-actions-2026-10-05.md` içinde.

| Kapı | Sahip | Kapanış için gereken |
| --- | --- | --- |
| COM-001 Ticari manifest | Commercial/Product + Finance | Onaylı fiyat, SKU, vergi, dönem, SLA hakkı; teklif → entitlement → iptal → offboarding provası |
| COM-002 Lisans ve IP zinciri | Legal | Aday SBOM'una göre notice'lar ve kaynak yükümlülükleri, certifi MPL-2.0 ve psycopg LGPL kararları, katkıcı IP devirleri |
| COM-003 Veri akışı ve gizlilik | Privacy/Legal | Gerçek egress ölçümü, DPA/TOM/SCC, subprocessor listesi, silme makbuzları |
| COM-004 Billing ve entitlement | Finance | Gerçek sağlayıcı hesabı; duplicate, gecikmiş ve sırası bozuk webhook testleri; mutabakat |
| COM-005 Destek | Support/Ops | Çalışan ticket sistemi, security mailbox ve status feed; Sev1/Sev3 drill zaman damgaları |
| COM-010 Beş direct-GA connector | QA/Endpoint | B.1 makbuzları. Codex preview kapsamında kalır |
| COM-011 Bölge ve yerleşim | Privacy/Legal + Ops | Gerçek bölge projeleri, yanlış bölge erişim testleri |
| COM-012 Private registry ve offline teslim | Ops + Finance | Kimlik doğrulamalı registry, imzalı air-gap manifest, internetsiz host provası |
| COM-013 Aylık %99,9 SLA | SRE + Legal/Finance | Tam ay SLI gözlemi, credit kuralları |
| SEC-EXT-001 Bağımsız güvenlik incelemesi | Security | Bağımsız assessor, aynı aday digest'i için pentest, fix ve retest mektubu. Dahili inceleme yerine geçmez |
| POV-001 Müşteri kabulü | Sales + müşteri | İmzalı Evaluation Charter, bağımsız koşu, yazılı kabul |
| INV-001 Yatırımcı metrikleri | Product/Finance + Legal | Onaylı formül, gerçek kaynak veri |
| CLM-001 Satış iddiaları | Sales + Legal | Final artefakt ve canlı landing byte'larına bağlı claim scan, "Sales Approved" kararı |

### D. Ürün sahibinden beklenen kararlar (sorma; seçenek ve öneri hazırla)

1. **Aşırı yük politikası.** Kapasite aşıldığında hangi isteklerin düşürüleceği:
   - tenant başına eşzamanlı istek sınırı mı;
   - adil paylaşım mı;
   - plan önceliği mi?

   Bugün yük atma (load shedding) yok. Kırılma noktasının üstünde başarılı yanıtlar sıfıra iniyor (`load-soak-drill-2026-10-11.md` O1). Karar verilince uygula ve aynı provayı tekrar koş.
2. **Upstream Supabase imajlarının kalıntı CVE'leri** (AIDR-080). Risk kabulü mü, vendor eskalasyonu mu, alternatif imaj mı?
3. **Direct-GA connector seti:** 5 mi 6 mı? Codex preview mi kalacak? README, registry ve `support-matrix.json` buna göre hizalanmalı.
4. **NER ve OCR** (madde 21).
   - Kurumsal TR/EN korpusla kalite kabulü yapılıp satılacak mı, ilk sürüm dışında mı kalacak?
   - Kabul eşikleri: recall ≥ 0,95; precision ≥ 0,90; temiz belgede müdahale oranı ≤ 0,05.
   - Kabul geçmezse `not-sold` kalır.
5. **Bölge vaadi, SLA zamanlaması, satış kademesi.** Kontrollü değerlendirme → destekli satış → GA.
6. **Repo ayarları.**
   - GitHub "automated security fixes" açılmalı; repo sahibinin işi.
   - Dependabot limitleri qualification sonrası geri açılmalı: npm 10, Actions/Python/Docker 5. NER limiti 0 kalır.

### Bitti tanımı

| Seviye | Koşul |
| --- | --- |
| **LOCAL_ENGINEERING_READY** | A bölümü tamam; yerel kapılar yeşil |
| **RELEASE_CANDIDATE_READY** | Ek olarak B.9 tamam: imzalı aday, SBOM, provenance; B.1–B.8 kanıtları bu digest'e bağlı ya da açıkça kapsam dışı |
| **PRODUCTION_SALES_GO** | Ek olarak seçilen satış profilinin (production-ga: 12 kapı) bütün C kapıları isimli sahiplerin makbuzlarıyla kapalı; registry `decision: GO`, `releaseCandidate` = aday digest. `scripts/verify-production-go.mjs --profile production-ga` aynı digest için 0 ile çıkıyor |

Bir seviye karşılanmıyorsa karar bir alt seviyede kalır.

### Rapor biçimi (her çalışmanın sonunda)

1. **En üstte:** tıkanan her şey. Hangi ortam, yetki ya da karar eksik; kimden bekleniyor; hangi komut koşulacak.
2. Kapanan maddeler: madde no, commit/PR, kanıt dosyası ve hash, kanıt seviyesi (yerel / gerçek ortam / isimli onay).
3. Kapı durum tablosu: kapı → eksik → sahip.
4. Karar bekleyenler, her biri için öneri ile.
5. Karar: **NO-GO** / LOCAL_ENGINEERING_READY / RELEASE_CANDIDATE_READY / PRODUCTION_SALES_GO.

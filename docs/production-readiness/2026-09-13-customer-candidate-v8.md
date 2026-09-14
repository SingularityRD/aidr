# AIDR ilk müşteri adayı v8 — birleşik mühendislik ve kabul kaydı

**Karar: NO-GO (production ve destekli satış).** Bu kayıt `07a4fc4ad3b0cad1c2ff84c93082e66a27bf3fa0` tabanındaki **değişiklik içeren çalışma ağacını** değerlendirir. Yerel uygulama tarafında v7'ye göre kapanan işler vardır; resmi yayıncı imzası, temiz immutable kaynak adayı, gerçek müşteri host/OS/IdP/ağ ortamı, bağımsız güvenlik değerlendirmesi, bağımsız etkinlik ölçümü ve isimli müşteri kabulü yoktur.

Bu belge yalnızca **gerçekten çalıştırılan** komutların sonucunu taşır. Koşulmayan hiçbir hücre PASS sayılmaz.

## 1. Ürün kapsamı ve karar

`FEATURE_INVENTORY.json/.md` içindeki 71 alt özellik: **41 wired, 28 partial, 0 missing, 2 external**.
`PRODUCTION_SALES_GAPS.json/.md`: **59 iş paketi** (46 teknik/operasyon + 13 ticari/dış kapı). Teknik işlerin **45'i** yerel uygulaması bulunan fakat saha kabulü açık durumdadır; **1 iş (T39)** uygulama/entegrasyon olarak açıktır. Production-GA ve assisted-sale profillerinde **12 zorunlu dış kapı** açıktır. Bu sayılar tamamlanma yüzdesi değildir.

v7 → v8 kapanan yerel uygulama boşlukları:

| v7 durumu | v8 durumu | Ne değişti |
| --- | --- | --- |
| `BIL-03` missing | `partial` | Gerçek self-service abonelik portalı: `supabase/functions/billing-portal/` (settlement durum makinesi, provider adapteri, handler) + `20260913000004_billing_settlement_portal.sql` + dashboard istemcisi ve UI kartı |
| `T01` OPEN | yerel uygulama hazır, saha açık | `deploy/native/support-matrix.json` satılan connector/OS/arch/context/interception matrisi; `deploy/native/run-support-matrix.mjs` kurulu olmayan hostu `HOST_UNAVAILABLE` + NO-GO üretiyor |
| `T13` OPEN | yerel uygulama hazır, saha açık | `packages/core/src/response-worker-contract.ts`: capability beyanı, önkoşul, TTL/idempotency, geri dönüş makbuzu, `partial` raporu |
| `T25` OPEN | yerel uygulama hazır, saha açık | `packages/core/src/incidents/evidence-receipt.ts`: candidate/policy/device/actor/incident/action bağlı append-only makbuz, Lamport sıralaması, duplicate/tamper reddi, fail-closed arşiv adapteri |
| `T33` OPEN | yerel uygulama hazır, saha açık | provider-of-record durum makinesi, sunucu tarafı kimlik çözümlemesi, seat reconciliation, cancel/refund (BIL-03 ile aynı dilim) |
| `T39` OPEN | uygulama açık | bağımsız kör holdout ölçümü hâlâ bağımsız değerlendirici ve müşteri benign corpus'u gerektiriyor |

Ek olarak `AIDR-019` çerçevesinde, dashboard'un tarayıcıdan çağırdığı **16 Edge Function'ın tamamı** için makine tarafından doğrulanan bir sözleşme testi beyanı ve varlığı zorunlu hale getirildi (`docs/production-readiness/edge-function-contract-manifest.json` + `scripts/check-supabase-edge-contracts.mjs`). v7'de 6 fonksiyonun beyan edilen testi yoktu; v8'de **0**.

## 2. Kapatılan task/backlog/feature kimlikleri

- **Feature:** `BIL-03` (missing → partial).
- **Teknik iş:** `T01`, `T13`, `T25`, `T33` yerel uygulama + hedefli test kazandı; statüleri `LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN` olarak yeniden üretildi. `T39` `OPEN` kaldı.
- **Backlog:** `AIDR-019` beyan edilen sözleşme testi boşluğu kapandı (16/16 fonksiyon, 0 açıklanmamış). Diğer yedi kayıt (`AIDR-012`, `AIDR-016`, `AIDR-044`, `AIDR-049`, `AIDR-050`, `AIDR-051`, `AIDR-052`) gerçek dış girdi (immutable commit, saha hostu, MDM tenantı, offsite storage, müşteri kabulü) gerektirdiği için açık kaldı.
- **Güvenlik düzeltmeleri (sözleşme testleri sırasında bulunan gerçek açıklar):**
  - `oauth-callback` (davet kabul yolu): RPC'nin *herhangi* hatalı sonucu `200 {ok:true}` olarak dönüyordu; artık sonuç davetin kendi tenant kimliği olmak zorunda, aksi halde `503 invitation_unavailable`.
  - `team-invite`: aynı istek tekrarı ikinci bir canlı davet linki üretiyordu; artık bekleyen satır yeniden kullanılıp token döndürülüyor, önceki link ölüyor. `23505` artık `409 invitation_conflict`.
  - `pilot-apply`: sınırsız `req.json()` ve sessiz boş-gövde kabulü vardı; artık sınırlı gövde, katı şema ve `400/413`.
  - `policy-management`: Redis/RPC kaydı olmayan bir yayın `200 {ok:true, version: undefined}` dönebiliyordu; artık `503 policy_publish_failed`.
  - `autosecops-runtime`: dizi/`null` gövde `exception` üretip `500`'e düşüyordu; artık `400 invalid_query`.

## 3. Yerel doğrulama (aynı çalışma ağacı)

| Kapı | Komut | Exit | Sonuç |
| --- | --- | --- | --- |
| Whitespace | `git diff --check` | 0 | temiz |
| Envanter | `node scripts/generate-feature-inventory.mjs` | 0 | 71 kayıt: 41/28/0/2 |
| Gap audit | `node scripts/generate-production-sales-gap-audit.mjs` | 0 | 59 iş paketi, 13 dış kapı, T39 dışında OPEN yok |
| Prompt | `node scripts/verify-next-agent-execution-prompt.mjs` | 0 | 19 bölüm, 46 teknik iş, 8 açık backlog, 13 dış kapı |
| Tip | `pnpm check` | 0 | TypeScript + workspace sözleşmeleri |
| Static | `pnpm quality:static` | 0 | lint 156 uyarı, Knip review debt files=220/exports=131/duplicates=1, ticari yüzey + 16/16 Edge sözleşmesi + demo preflight PASS |
| Bağımlılık | `pnpm audit:prod` | 0 | 0 advisory |
| Migration | `pnpm supabase:check` | 0 | 34 migration, benzersiz/sıralı (v7: 33) |
| Enforcement | `pnpm verify:enforcement` | 0 | 72/72 |
| Codex | `pnpm verify:codex` | 0 | 11/11 |
| Test | `pnpm test:ci` | 0 | **250 dosya, 3.661 geçti, 2 açıklanmış skip, 0 hata** (v7: 237/3.326) |
| Coverage | `pnpm test:coverage` | 0 | statements **%77,66**, branches **%70,09**, functions **%81,11**, lines **%81,17**; eşikler %70/%60/%70/%70 |
| Release build | `pnpm build:release` | 0 | 10 paket release manifesti + 10/10 consumer smoke |
| Node sözleşmeleri | `node --test scripts/endpoint-install.test.mjs … scripts/benchmarks/evaluate.test.mjs` | 0 | tümü geçti |
| Release bundle | `.github/scripts/build-release-bundle.mjs` | 0 | **14 artefakt** |
| Customer kit | `node scripts/customer-kit.mjs --output … --upstream-dir … --release-dir … --envelope-output …` | 0 | **342 dosyalı portable aday**, imzasız dış zarf |
| Kit verifier | `node scripts/verify-customer-kit.mjs <kit>` | 0 | 6 kontrol PASS |
| Native host matrisi | `node deploy/native/run-support-matrix.mjs --probe-only` | 1 (beklenen) | **NO-GO**: yalnız opencode 1.18.30 ve codex-cli 0.141.0 sürüm olarak bulundu |
| Support bundle | `pnpm verify:support-bundle` | 0 | self-test geçti |
| Monitoring | `pnpm verify:monitoring` | 0 | kurallar ve testleri geçti |
| Upgrade | `pnpm verify:upgrade` | 0 | geçti |
| Release signing | `pnpm verify:release-signing` | 0 | geçti |
| Offsite backup | `pnpm verify:backup-offsite` | 0 | geçti |
| Offboarding | `pnpm verify:offboarding` | 0 | geçti |
| Load harness | `pnpm verify:load` | 0 | geçti |
| Fleet (Windows) | `pnpm verify:fleet:windows` | 0 | manifest digest, imzasız/yanlış imzalı CMS reddi, path traversal reddi, dosya sistemi kökü reddi, log redaksiyonu, uninstall'ın yalnız yönetilen hook'ları kaldırması |
| Fleet (Unix) | `pnpm verify:fleet:unix` | 0 | 25 kontrol; MDM/Jamf kabulü kapsam dışı olarak işaretli |
| Privacy | `node scripts/privacy-verify.mjs` | 0 | canary ve bundle izolasyonu geçti |
| Claim inventory | `node docs/scripts/claim-check.mjs --mode=inventory --json` | 0 | PASS; onaysız iddia yok |

### v8 sırasında bulunan ve düzeltilen ortam/kapı kusurları

Bu turda, kapıların kendisinde üç gerçek kusur bulundu ve düzeltildi; hiçbiri assertion gevşetilerek geçirilmedi:

1. **`config-contract.test.ts` fabrika düzenini izlemiyordu.** Handler üretimini `Deno.serve(` konumundan kırpıyordu; fabrika kalıbı kullanan fonksiyonlarda istek yolu neredeyse boş kalıyordu. `handlerBody` artık `export function create...` ile `Deno.serve(` arasındaki bölgeyi kapsıyor ve bağımlılık enjeksiyonlu istemci kurucusu için istemci bağlayıcısının *bağlandığı* noktayı esas alıyor.
2. **Filo fixture'ları gerçek AMSI yükünü taşımıyordu.** `endpoint-install.mjs` Windows'ta paketli native AMSI eklentisi yoksa hook kaydını reddeder; Windows ve Unix filo kapıları ise sentetik paketlerine bu yükü koymuyordu. Kontrolü atlamak yerine fixture artık `pnpm build` ile üretilen gerçek `packages/claude-code/dist/vendor/koffi` içeriğini taşıyor ve yük yoksa kapı açık bir hata veriyor.
3. **`device-start` kota testi saat sınırına bağlıydı.** Aynı 31 istek 60 saniyelik pencere sınırını geçerse 31. istek meşru olarak 200 dönüyordu; bu, yavaş bir yük altında aralıklı hata üretiyordu. Test artık handler'ın okuduğu saati sabitliyor ve ayrıca pencerenin bir sonraki dakikada sıfırlandığını doğruluyor.

Ayrıca `check-commercial-readiness.mjs` sıfır üyeli bir durum kategorisini "beyan edilmemiş" sayıp başarısız oluyordu; eksik anahtar ile açık `0` artık aynı kabul ediliyor. `run-knip-gate.mjs` Deno'nun `npm:` belirteci için dosya bazlı izin listesini genişletti; liste hâlâ dosya bazlı, yani yeni bir dosya kendiliğinden muafiyet kazanmıyor.

Yeni test dosyaları (v8): `supabase/functions/__tests__/billing-portal.test.ts` (37), `billing-invoice-entitlement.test.ts` (28), `oauth-callback-contract.test.ts` (24), `pilot-intake-contract.test.ts` (49), `policy-management-contract.test.ts` (39), `team-invite-contract.test.ts` (34), `autosecops-runtime-contract.test.ts` (16), `packages/core/src/__tests__/evidence-receipt.test.ts` (20), `response-worker-contract.test.ts` (18), `exposure-graph.test.ts` (22), `exposure-sources.test.ts` (8), `causal-chain.test.ts` (17), `false-positive-feedback.test.ts` (17).

### Makine okunur kanıt indeksi

`docs/production-readiness/v8-evidence-index.json` (28 kapı, şema `v8-evidence-index.schema.json`, doğrulayıcı `node scripts/generate-v8-evidence-index.mjs --verify`) her kapı için komut, exit code, UTC başlangıç/bitiş, süre, commit, candidate digest, ortam, araç sürümleri, test sayıları, gözlenen etki, log SHA-256, artefakt SHA-256, sınırlar, sahip ve kanıt seviyesi taşır. Türetilemeyen her alan açıkça `"unknown"`, logu olmayan her kapı `NOT_RUN`'dır; hiçbir kapı atlanmaz. Bu turda: **17 PASS, 6 FAIL, 3 NOT_RUN, 2 unknown**. FAIL'lerin tamamı fail-closed dış bağımlılıktır (§4); hiçbiri yerel test hatası değildir.

## 4. Fail-closed native / E2E / claim-gate sonuçları ve tam nedenleri

- **Native host matrisi — NO-GO (beklenen fail-closed).** `deploy/native/support-matrix.json` altı satılan connector tanımlar; bu makinede yalnız `opencode` ve `codex` var, dördü `HOST_UNAVAILABLE`. Hiçbir satırda isimli kabul kanıtı (`acceptanceEvidence`) yoktur, bu yüzden her satır `acceptance: open`. Kaynak: `.release-evidence/v8-native-probe.json`.
- **Native senaryo manifestleri — açık.** `deploy/native/scenarios/<connector>.json` bu turda üretilmedi, çünkü host başına gerçek CLI sözdizimi doğrulanmadan yazılacak bir manifest uydurma olurdu. `run-support-matrix.mjs` bu durumu `SCENARIO_MANIFEST_MISSING`/`NATIVE_SCENARIOS_OPEN` olarak raporlar ve NO-GO üretir.
- **Release E2E — bu turda çalıştırılmadı.** `pnpm test:e2e` `AIDR_E2E_RC_DIGEST` ve dış host/kimlik makbuzu ister; ikisi de yoktur. Sonuç yok, dolayısıyla PASS da yoktur.
- **Claim gate — FAIL (beklenen).** `node docs/scripts/claim-check.mjs --mode=gate` 13 dış onay kapısı açık olduğu için başarısız olur; bu turda bypass edilmedi. `--mode=inventory` PASS'tir.
- **AIG bridge Python suite — PASS, yalnız pinlenmiş venv ile.** `AIDR_AIG_PYTHON` izole `.release-evidence/aig-bridge-venv`'e işaret edince **31/31** geçti. Sistem Python'unda `tenacity` yoktur ve suite collection aşamasında durur; bu bir eksik önkoşuldur, ürün hatası değildir. E2E manifesti artık `{python}` yer tutucusunu `AIDR_AIG_PYTHON` üzerinden çözer; varsayılan `python` olarak kalır, böylece CI davranışı değişmez.
- **`pnpm aig:verify` — FAIL (açık, sahipli).** Doğrulayıcı `31c72a97… (v4.5.1)` bekliyor; `vendor/ai-infra-guard` submodule'i süper proje kaydıyla tutarlı biçimde **`e68bc5d0… (v4.6.1)`** üzerinde duruyor ve çalışma ağacında 10 adet önceden var olan silinmiş CVE YAML dosyası var. Sahibi: AI Infrastructure Engineering. Gereken girdi: submodule'ün kirli durumunun sahibince doğrulanması, beklenen commit ile `aig-data-manifest.json`'ın aynı corpus üzerinde yeniden üretilmesi. Bu kanıt sınırı korunmuştur; submodule içeriği bu turda geri alınmadı veya commit edilmedi.
- **`pnpm test:e2e:negative` — exit 0, NO-GO.** 6 senaryonun 2'si kesin sonuç (`opencode-missing-cli`, `release-preflight` PASS), 3'ü `HOST_UNAVAILABLE` (Claude CLI, Cursor, VS Code kurulu değil), 1'i `BLOCKED_EXTERNAL` (OpenClaw gateway token / chatCompletions). Ürün hatası 0. Yanlış-kabul koruması JSON **ve** JUnit kanıtı üzerinde çalışır ve geliştirme sırasında canlı olarak tetiklenmiştir.

## 5. Kalan işler (ID, sahip, gereken gerçek girdi, kabul kanıtı)

| ID | Sahip | Gereken gerçek girdi | Kabul kanıtı / komut |
| --- | --- | --- | --- |
| T39 | Detection Research + QA + bağımsız değerlendirici | Müşteri benign corpus'u, rakip erişimi, ölçüm bütçesi, **bağımsız imzalı attestation** | `node scripts/benchmarks/evaluate.mjs --corpus … --observations … --attestation … --public-key …`; `production_accepted:false` bağımsız imza gelene kadar |
| T01 / AIDR-049 | QA + Endpoint Engineering | Altı satılan hostun lisanslı kurulumu, disposable Windows/Linux/macOS makineleri, OS build listesi | `node deploy/native/run-support-matrix.mjs --scenario-file deploy/native/scenarios/<host>.json` her satırda `SCENARIOS_PASSED` |
| AIDR-016 | Product + Infrastructure | Ulaşılabilir control-plane endpoint'i, DNS, TLS | Taze kurulumda `device-start` → `user_code`/`verification_url`, poll tamamlanıp `managed.json` yazılır |
| AIDR-044 / T27 | SRE + müşteri operasyonları | Offsite storage, ayrı anahtar custodian'ı, kabul edilmiş RPO/RTO | Bağımsız hostta yalnız offsite yedekten kurtarma; tablo/nesne karşılaştırması |
| AIDR-050 | Release + Endpoint Engineering | MDM test tenantı (Intune/Jamf/SCCM), resmi imzalayan | MDM dağıtım kaydı + policy koruyan upgrade/rollback/uninstall |
| AIDR-051 | Discovery + Backend | Müşteri cloud/MDM API erişimi | Zamanlanmış kolektör + tazelik alarmı + kısa ömürlü delegasyon |
| AIDR-052 / T30 | SRE | Host boyutları, filo/olay profili, SLA anlaşması | Kimlikli yük, noisy-neighbor, failover, ≥8 saat soak, aylık SLI |
| T37 / T40 / COM-003 / COM-005 | Privacy/DPO + Support | DPA, isimli nöbet, gerçek ticket/paging kanalı | Alan bazlı veri akışı onayı + zaman damgalı ticket tatbikatı |
| SEC-EXT-001 / POV-001 | Security Lead + müşteri | Bağımsız değerlendirici, isimli müşteri | İmzalı rapor + imzalı charter ve kabul kaydı |
| T33 canlı kısım / COM-004 / COM-012 | Finance + Release Engineering | Canlı provider anahtarları, onaylı SKU/fiyat, muhasebe onayı, private registry | Fatura→entitlement→indirme→iptal provası; **yerelde fixture ile geçildi**, canlı kapı açık |
| T29 / DEP-05 | Release Engineering + Security | Onaylı yayıncı anahtarı (key custody), private registry | Aynı candidate için imzalı paket + registry kurulum kaydı; `publisher_authenticated=false` açık kalır |
| T01 native senaryolar | QA + Endpoint Engineering | Altı hostun kurulu olduğu makineler | `deploy/native/scenarios/<connector>.json` gerçek host koşusuyla doldurulur; `TEMPLATE.json` asla kabul kanıtı değildir (kapı bunu bloke eder) |
| MKT-01/02/05 saha kabulü | Product + Detection + SOC | Gerçek IdP/cloud/MDM kaynakları, iki tenantlı müşteri testi, kalıcı store ve analist UI | Maruziyet grafiği, nedensel zincir ve geri bildirim kaydı yerelde uygulandı ve test edildi; müşteri kaynağı ve UI açık |

## 6. Teslimat yolları ve digestler

- Aday kaydı: bu dosya. Donmuş kaynak commit: `fd95c91f0e5cdc07408a089d49d5e8ab4380cf6e`.
- Release çıktısı: `.release-evidence/customer-release-v8-local-20260913-r3/` (14 artefakt, `release-metadata.json` `git_sha=fd95c91f…`, `release_version=0.6.0-rc.8`).
- Release-inventory SHA-256 (candidate digest): `0d78abdece256237805792ca6b5339fba53e7018001eaa4a81ba73ae262539f4`.
- Portable customer kit: `.release-evidence/aidr-customer-kit-v8-local-20260913-r3/` (344 dosya, kit verifier 6/6).
- İmzasız dış zarf: `.release-evidence/aidr-envelope-v8-local-20260913-r3/` (`publisher_authenticated=false`).
- Native matris kaydı: `.release-evidence/v8-native-probe.json`, girdi `deploy/native/support-matrix.json`.
- Ölçülen kaynak profili: `.release-evidence/v8-resource-profile-aidr-v6-local.json`, insan okunur özet `resource-sizing-v8.md`.
- Makine okunur kanıt indeksi: `v8-evidence-index.json` + `v8-evidence-index.schema.json`.
- Ticari kapı makbuzları: `commercial-gate-receipts.json` + `.schema.json` (13 kapının tamamı `open`).
- Komut logları: `.release-evidence/v8-logs/`.
- v7 klasörleri (`customer-release-v7-local-20260913`, `aidr-customer-kit-v7-local-20260913*`, `aidr-envelope-v7-local-20260913*`) değiştirilmedi. Önceki v8 paketleme denemeleri (`…-20260913`, `…-r2`) silinmedi; `…-r3` bunları supersede eder. `r2` ile aynı digest'e sahiptir çünkü aradaki commit yalnızca üretilmiş kayıtları yeniden pinler; paketlenen baytlar değişmez.

> **Kendine referans notu.** Üretici kayıtlar (`FEATURE_INVENTORY.json`, `PRODUCTION_SALES_GAPS.json`, `v8-evidence-index.json`) üretildikleri commit'i `source_commit` alanında taşır. Bu alanı içeren bir commit atıldığında değer bir sonraki commit'e kayar; bu yüzden "generator determinizmi" kapısı, commit edilmiş dosyayı değil **iki ardışık üretici koşusunun bayt-eşitliğini** esas alır. Kanıt: iki ardışık koşu 6 üretilmiş dosyada da aynı SHA-256'yı verir; `source_commit` dışındaki hiçbir satır değişmez.

## 7. Kaynak ve kapasite

**Bu turda yeni bir canlı self-hosted ölçüm üretilmedi**; Docker daemon durumu doğrulanmadı ve v6 değerleri v8 kanıtı olarak yükseltilmedi. Ölçülmüş sayılan tek şey yerel test/paketleme süreleridir:

| Ölçüm | Değer | Kanıt |
| --- | --- | --- |
| Tam test süresi | 239,1 s (246 dosya, Win32 seri) | `11-test-ci-final.log` |
| Release bundle üretimi | 14 artefakt, exit 0 | `20-release-bundle.log` |
| Customer kit | 342 dosya, exit 0 | `20-customer-kit.log` |
| Enforcement | 72/72 | `09-verify-enforcement.log` |
| Node sözleşmeleri | 57/57 | `14-node-contracts.log` |

Tahsis (ölçülmemiş, v6 ölçümünden türetilmiş planlama girdisi): pilot/100 cihaz **4 vCPU / 8 GiB / 100 GiB SSD**; 1.000 cihaz yük testi **8 vCPU / 16 GiB / 250 GiB SSD**; uç cihaz başına **512 MiB disk**. Bunlar ölçüm değil tahsistir.

İlk müşteri öncesi zorunlu kapanış sırası v7'deki gibidir; v8'de yerel tarafta kalan tek uygulama işi `T39`'un bağımsız ölçüm altyapısıdır.

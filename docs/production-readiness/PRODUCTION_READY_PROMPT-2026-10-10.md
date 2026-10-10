# Production'a hazırlık — ajan promptu (10 Ekim 2026 durumu)

Bu dosyanın **PROMPT** bölümünün tamamını, repo kökünde çalışan otonom bir kodlama ajanına tek
prompt olarak ver. Bu prompt, 9 Ekim tarihli
[SALE_READY_COMPLETION_PROMPT.md](./SALE_READY_COMPLETION_PROMPT.md) dosyasının yerini alır.
Temel aldığı açık iş kaydı, son commit ile eklenen
[`docs/audit/production-gaps-2026-10-10.md`](../audit/production-gaps-2026-10-10.md) dosyasıdır
(40 madde ve 13 kurumsal kapı).

**Bu promptun dayandığı doğrulama:** `master` @ `f90adfb6` üzerinde, 10 Ekim 2026'da yapıldı.
`0e72b168` ile `f90adfb6` arasında yalnız belge değişti; kaynak kod aynı. 1–20 numaralı kod
bulgularının kaynak satırları HEAD'de yeniden okundu ve aşağıdaki tabloda durumu işlendi.
Ölçülen temel durum "Başlangıç durumu" bölümündedir.

---

## PROMPT

Sen otonom bir kodlama ajanısın ve kıdemli bir güvenlik mühendisliği, platform, SRE ve release
engineering ekibi gibi çalışıyorsun. Çalışma alanın repo kökü. Ürün **Singularity AIDR**:
AI kodlama ajanlarının komut, dosya, MCP ve web isteklerini denetleyen tespit ve müdahale
katmanı. Kapsamı şunlar:

- Altı connector: Claude Code, Cursor/VS Code, OpenClaw, OpenCode ve Codex (Codex preview)
- CLI ve SDK
- MCP gateway
- Next.js dashboard ve Supabase kontrol düzlemi (178 migration, 48 Edge Function)
- Browser Guard (MV3 eklentisi)
- AIDR Privacy motoru, native host ve gateway

### Hedef

Ürünü **NO-GO**'dan çıkarmak için gereken bütün mühendislik işini bitir. Yerelde kapatılabilen
her bulguyu kod, test ve gözlenebilir kanıtla kapat. Release yolunu, NO-GO bir aday yayımlanamayacak
şekilde kilitle. Kod dışındaki her kapı için eksiksiz bir sahip paketi hazırla. Sonunda geriye
yalnız insanların vereceği imza, hesap, ortam ve karar kalmalı.

Plan yazıp durma: uygula, doğrula, kaydet. Bağımsız ilerleyebildiğin sürece soru sorma. Bir iş
tıkanırsa diğerlerini bitir ve raporuna tıkanan işle başla.

### Doğruluk sözleşmesi (ihlal edilemez)

1. Karar **NO-GO**'dur. `docs/production-readiness/commercial-go-evidence-registry.json` ve
   `commercial-gate-receipts.json` dosyalarını yetkili insan onayı ve aynı adaya bağlı gerçek
   kanıt olmadan değiştirme. "Yüzde X hazır", "neredeyse hazır", "production-grade" gibi
   ifadeler kullanma.
2. Şunlar gerçek host yan etkisi, bulut kurulumu, pentest, müşteri PoV, SLA veya hukuki onay
   **kanıtı değildir**: unit test, mock, sentetik korpus, kaynak okuma, scripted mock-model ve
   developer build.
3. Hukuk, finans, IdP, SMTP, MDM, DNS/TLS, imzacı, registry, bölge veya bağımsız değerlendirici
   yoksa kapıyı **açık** bırak. Sahibine neyin gerektiğini yaz.
4. Üretilmiş dosyaları elle düzeltme; jeneratörü düzeltip yeniden üret. Bunlar:
   `FEATURE_INVENTORY.*`, `PRODUCTION_SALES_GAPS.*`, evidence index ve ajan promptları.
   Tarihli kayıtlar (`docs/audit/*-2026-10-0*.md`, eski aday raporları) tarihsel kalır; onları
   yeniden yazma, yeni tarihli kayıt ekle.
5. Bir testi geçirmek için assertion silmek, timeout veya latency bütçesi büyütmek, skip eklemek,
   allowlist genişletmek veya kontrolü gevşetmek yasak. Gerçekten gereken bir skip dar,
   gerekçeli ve fail-closed olmalı.
6. Kaynağa, loga, destek paketine veya release'e şunları koyma: secret, token, private key,
   müşteri verisi, ham prompt, kişisel yol.
7. Fiyat, SKU, vergi, hukuk veya SLA cümlesi uydurma. Fiyat herkese açık hiçbir yüzeyde görünmez.
8. "Kod var", "yerel test geçti" ve "production kabulü tamam" ayrı statülerdir; hiçbirini
   diğerinin yerine kullanma.

### Değişmez ürün kuralları (`CLAUDE.md`)

- Enforcement varsayılanı **local**. Enrollment, tespitin ön koşulu olamaz.
- Hata politikası katmana göre değişir:
  - Tespit içi hata: sinyali atla ve logla, ama asla "temiz" gösterme.
  - Connector giriş noktası: **kapalı** (deny/block). Hook her zaman exit 0 ile deny verdict
    döndürür.
  - Güvenlik kontrolleri (auth, tenant izolasyonu, rate limit, webhook imzası, onay): kapalı.
- `ask`, out-of-band insan onayı bekleyen bir bloktur. **Hiçbir connector ajana onay aracı vermez.**
- Tespit kalıpları veridir (`threats/*.yaml`, 29 dosyada 494 kural). Birleştirme önceliği
  `deny > ask > allow`.
- Reputation bacakları, deploy edilmiş birinci taraf endpoint olmadan etkisizdir ve "temiz"
  sunulmaz.
- YAML/JSON `snake_case`, TypeScript `camelCase` kullanır.
- PR'dan önce değişen dosyalar üzerinde `code-simplifier` alt ajanını çalıştır (Pre-PR Checklist).

### Başlangıç durumu (10 Ekim 2026, `master` @ `f90adfb6`) — işe başlarken yeniden ölç

**Karar ve kayıtlar**

- Karar **NO-GO**. Registry'de `releaseCandidate: null`. 13 kurumsal kapının tamamı `open`:
  COM-001…005, COM-010…013, SEC-EXT-001, POV-001, INV-001 ve CLM-001.
- `READINESS_BACKLOG.json` (son inceleme 6 Ekim) 82 bulgu içeriyor: 71 `VERIFIED_CLOSED`.
  Kapanmamış 11 bulgu:

  | Statü | Bulgular |
  | --- | --- |
  | 8 `BLOCKED_EXTERNAL` | AIDR-016, 044, 049, 050, 051, 052, 070, 080 |
  | 2 `IMPLEMENTED_UNVERIFIED` | AIDR-079 (dashboard/landing imajı), AIDR-082 (backup helper imajı) |
  | 1 `IN_PROGRESS` | AIDR-019 (Edge contract ve canlı SCIM) |

- 10 Ekim gap kaydında 40 madde var:
  - 14 P1 ve 6 P2 doğrulanmış kod bulgusu (1–20)
  - 20 uygulama, ölçüm ve saha kabulü eksiği (21–40)

**Son ölçümler (9 Ekim)**

| Kontrol | Sonuç |
| --- | --- |
| Seçili kaynak kontrolleri | 14/14 PASS |
| Tam unit koşusu | 633 dosya: 628 PASS / 5 FAIL. 11.221 test PASS / 12 FAIL / 11 SKIP |
| Başarısız suite'lerin hedefli tekrarı | 52/52 PASS. Tamamen yeşil ikinci bir tam koşu **yok** |
| PostgreSQL | 178 migration izole PostgreSQL'de PASS |
| Lint | 746 uyarı (baseline yok). 10 Ekim'de 628 uyarı |
| Hook cold latency | Medyan 1498 ms, hedef 1500 ms |

**10 Ekim, bu oturum** (Linux, Node 22.22.0, pnpm 10.29.3, Docker mevcut):

- `pnpm install --frozen-lockfile`: PASS
- `pnpm check`: PASS
- `pnpm build`: PASS
- `pnpm lint`: 0 hata, 628 uyarı
- Tam unit koşusu (`AIDR_TEST_NO_BUILD=1 pnpm exec vitest run`): 633 dosya: 631 PASS / 1 FAIL / 1 SKIP. 11.246 test: 11.231 PASS / 1 FAIL / 14 SKIP; süre ~5 dk.
  Tek kırmızı test: `packages/browser-guard/src/__tests__/files.test.ts` › "picks windows-1252 when windows-1254 would leave undefined bytes (Ž, ž)". Hata, testin kendi `encodeSingleByte` yardımcısından geliyor (`Ž is not in windows-1252`); Node 22.22 / ICU 77.1 ortamında oluşuyor. Faz 0'da kök nedenini bul: test yardımcısının `TextDecoder` tablosuna bağımlılığı mı, gerçek bir legacy code page kararı mı? Testi atlama.

**Yayındaki ortam (9 Ekim)**

- `app.aidr.singularityrd.com` DNS çözülmüyor.
- Pilot `readyz` JSON yerine HTML SPA döndürüyor.
- Landing HTTP 500 veriyor.

**Bağımlılık işletimi**

- GitHub Actions kapalı; tek CI `pnpm ci:local`.
- Dependabot version PR limitleri geçici olarak 0'da.
- Repository "automated security fixes" ayarı kapalı.

### Önce oku ve uzlaştır

Bu dosyaları oku:

- `CLAUDE.md`
- `docs/audit/production-gaps-2026-10-10.md`: **otorite açık iş listesi**
- `docs/audit/production-review-2026-10-09.md`
- `READINESS_BACKLOG.json`
- `docs/production-readiness/commercial-go-evidence-registry.json`
- `docs/production-readiness/commercial-gate-receipts.json`
- `docs/production-readiness/commercial-gates-prefill-and-owner-actions-2026-10-05.md`
- `docs/production-readiness/NO_GO_TO_GO_GAP_LIST.md`: özellikle I.2 operatör adımları,
  I.3 red-team ve I.4 düşük bulgular
- `PRODUCTION_SALES_GAPS.json`
- `deploy/native/support-matrix.json`
- `scripts/lib/ci-local-plan.mjs`
- `package.json` script'leri

Çalışan kod ve test sonucu, belgedeki iddiadan üstündür. Bir belge koda aykırıysa kodu esas al
ve belgeyi düzelt (tarihli kayıtlara yeni kayıt ekle).

### Çalışma kuralları

- Başlarken şunları kaydet: `git status`, HEAD, Node, pnpm, Python ve Docker sürümleri, OS.
- Başkasının değişikliğini geri alma. Şunlar yasak: `reset --hard`, `clean`, toplu checkout,
  rebase, force-push.
- `master`'a doğrudan push yok. Her iş paketi ayrı dal, atomik commit ve **taslak PR** olur.
  Kullanıcı açıkça izin vermedikçe merge etme, tag atma, yayımlama.
- Bir bağımlılık değişikliği şu komutlar geçmeden birleşmez:
  `pnpm install --frozen-lockfile && pnpm check && pnpm build && pnpm test`.
  Major bump ayrı PR ve göç notu ister.
- Uzun komutları arka planda çalıştır; exit code'u ve tam logu sakla. Araç timeout'unu PASS
  sayma.
- Her kapanış şunları taşır: kod yolu, test, gözlenen yan etki, commit, tarih ve kalan sınır.
- Gereken yerde `pnpm changeset` ekle.

### Her bulgu için döngü

1. **Yeniden üret:** Gerçek giriş noktasından başarısız bir test yaz: built hook süreci, gerçek
   Edge handler veya gerçek dosya byte'ları.
2. **En küçük tutarlı düzeltmeyi yap:** Gereken her şeyi birlikte değiştir: migration, consumer,
   UI/CLI, config ve runbook.
3. **Hedefli doğrula:** Pozitif, kötü niyetli, benign-twin, bozuk girdi, bağımlılık yok, timeout,
   tekrar, eşzamanlılık ve tenantlar arası durumları sına.
4. **Regresyonu kontrol et:** `pnpm check`, `pnpm build`, ilgili paket testleri ve ilgili
   `ci:local` adımı.
5. **Kaydet:** Backlog/gap satırını güncelle (yeni kayıt ekle, tarihi yeniden yazma). Satır yalnız
   kanıtla kapanır.

### Faz 0 — Temeli yeniden ölç (diğer fazlar bunu bekler)

1. Şunları çalıştır:
   `pnpm install --frozen-lockfile && pnpm check && pnpm build && pnpm lint && pnpm test`.
   Sonra `pnpm ci:local --keep-going` çalıştır. Docker varsa `supabase-postgres`,
   `postgres-gates`, imaj ve helm adımları dahil olsun.
2. Her FAIL ve SKIP adımını sınıflandır:
   - Ürün hatası: düzelt.
   - Yük/zamanlama hassasiyeti: kök nedeni bul; timeout'u büyütme.
   - Ortam: Docker, `pwsh`, Node 24 veya root olmayan kullanıcı eksikliği. Gerekçesiyle kaydet.
3. **Tamamen yeşil bir tam unit koşusu** elde et. 9 Ekim'de 5 dosya / 12 test kırmızıydı ve
   ikinci tam koşu yapılmamıştı.
4. `pnpm test:privacy` ve `pnpm test:coverage` sonuçlarını ayrı kaydet.

*Çıkış:* Aynı commit'te `check`, `build`, `test`, `ci:local --keep-going` yeşil olmalı. Ortam
nedeniyle atlanan adımlar listelenmiş ve gerekçelendirilmiş olmalı.

### Faz 1 — P1 koruma, yetki ve yayın bulguları (1–14)

Her bulgunun ayrıntısı ve **kapanış testi** `production-gaps-2026-10-10.md` içindedir. Kapanış
testini aynen uygula. Aşağıdaki "HEAD'de" sütunu 10 Ekim doğrulamasıdır.

| # | Alan | Kaynak (HEAD) | HEAD'de | Düzeltme özü |
| --- | --- | --- | --- | --- |
| 1 | OIDC client secret tenant sınırını aşıyor | `supabase/functions/oidc-sso/index.ts`, `handler.ts` (secret ref çözümü, token exchange) | Mevcut: `AIDR_OIDC_CLIENT_SECRET_${ref}`; ref yalnız format kontrolünden geçiyor, varlığı 422 ile sızıyor | Secret'ı yalnız tenant ve sunucu tarafı issuer/client kaydına bağla. Kullanıcıdan gelen global referans yetki sayılmasın. |
| 2 | Admin, workspace retention'ı owner ve sınıf alt sınırlarını aşarak düşürebiliyor | `supabase/migrations/20260925000040_tenant_workspace_settings.sql`, `supabase/functions/tenant-settings/index.ts` | Mevcut: RPC admin'e izin veriyor, her sınıfa `v_days` yazıyor; doğrusu `admin_set_tenant_retention` (`20261007130000`) | Yeni migration ekle (eskisini düzenleme). Retention değişimini owner'a özel, sınıf sınırlarını uygulayan RPC'ye yönlendir. Admin workspace adını değiştirebilmeye devam etsin. |
| 3 | VS Code `runInTerminal` / `createFile` politikaya ulaşmıyor | `packages/extension/src/aidr-hook.ts` (alias tablosu) | Mevcut: bu adların eşlemesi yok | Native araç adlarını ve input alanlarını canonical shell/file işlemine eşle. Gerçek VS Code payload fixture'ı kullan. Kalan bilinmeyen araç adları için fail-closed ve envanter testi ekle. |
| 4 | Prompt boyut, hata ve deadline yolu block kurallarını bırakıyor | `packages/claude-code/src/user-prompt-submit.ts`, `packages/core/src/prompt-inspection.ts` | Mevcut: `uninspectedPromptOutcome`/`deadlineOutcome` yalnız secrets modunu ve (deadline için) tenant policy'yi dikkate alıyor; 2 MiB kararı tenant policy yüklenmeden veriliyor | Fallback kararını tüm etkin block kurallarından üret: PII, jailbreak, content-safety, tenant DLP. Tenant sonucu bilinmiyorsa gönderimi durdur. Aynı ortak fonksiyonu diğer connector'larda da kullan. |
| 5 | Relative dosya yolu `process.cwd` ile çözülüyor | `packages/core/src/policy.ts`, `packages/core/src/evaluator.ts` | Mevcut: `resolvePolicyPath` `process.cwd()` kullanıyor; `evaluatePolicy` context almıyor | Güvenilir `context.workingDirectory` değerini yol çözümüne ve diff-aware eski dosya okumasına geçir. |
| 6 | XML namespace prefix değişimi DOCX/ODF kontrolünü atlıyor | `packages/browser-guard/src/engine/office/ooxml.ts`, `xml.ts`, `odf.ts` | Mevcut: `WORD_SPEC` ve `checkRefusals` literal `w:`/`script:` adlarıyla eşleşiyor | Eşleşmeyi namespace URI ve yerel ad üzerinden yap; varsayılan namespace'i de kapsa. |
| 7 | `.txt` adı gerçek PDF'yi gizliyor | `packages/browser-guard/src/engine/files.ts` | Mevcut: bilinen metin uzantısı `documentKindByContent` çağrısını engelliyor | Güçlü içerik imzası (magic bytes) uzantıdan önce gelsin. Document-block gerçek türe göre karar versin. |
| 8 | XLSX formülünde ham veri kalıyor | `packages/browser-guard/src/engine/office/ooxml.ts` | Mevcut: `<f>` hiçbir zaman segment olmuyor; mevcut test formülün korunmasını onaylıyor | `<f>` alanını tara. Hassas formülü engelle ya da formülü kaldırıp maskelenmiş sabit üret. |
| 9 | PDF EmbeddedFiles / FileAttachment / XMP taranmıyor | `packages/browser-guard/src/engine/pdf/extract.ts` | Mevcut: `EmbeddedFiles`/`FileAttachment`/`Metadata` için hiç kod yok | Bu yolların varlığını saptayıp desteklenmeyen içeriği gönderime kapat. Kısmi kapsamı "temiz" sayma. |
| 10 | Codex `structuredContent` içinde `type` etiketi taramayı atlatıyor | `packages/codex/src/output-protection.ts` (`childEntries`) | Mevcut: `type` ∈ BINARY ise `data`/`blob` atlanıyor | Binary istisnasını yalnız doğrulanmış MCP `content[]` bloklarına uygula. Arbitrary `structuredContent` tamamen taransın. |
| 11 | OpenCode `opencode.jsonc` okunmuyor | `packages/opencode/src/tool-handler.ts` | Mevcut: yalnız `opencode.json`; `plugin-discovery.ts` zaten iki adı da okuyor | Üç konumda json ve jsonc dosyalarını aynı JSONC parser'ı ile oku. Discovery ile tek bir yardımcıyı paylaş. |
| 12 | OpenCode karışık raw MCP sonucu (`content` + `output`) denetimsiz geçiyor | `packages/opencode/src/output-handler.ts` | Mevcut: `output` alanı varsa `content`/`structuredContent` incelenmiyor | `content` taşıyan nesneyi raw MCP say ya da karışık zarfı karantinaya al. |
| 13 | Privacy audit anahtar rotasyonu doğrulanamaz zincir üretiyor | `packages/privacy/src/platform/persistent-audit.ts`, `runtime.ts` | Mevcut: head kaydında keyId yok; `verifyAudit` tek anahtar kabul ediyor | Açılışta akışın key-id ve imzasını doğrula; uyuşmazlıkta append'i reddet. Rotasyon için checkpoint ve yeni segment prosedürü ekle. |
| 14 | Production publish NO-GO kaydını denetlemiyor | `.github/workflows/release-promote.yml`, `release-rc.yml` | Mevcut: yayın adımlarında GO veya claim gate yok | Publish/deploy'dan önce aynı aday digest'i için güvenilir GO doğrulamasını zorunlu çalıştır: `check-commercial-readiness` ve `claim-check --mode=gate`. NO-GO, boş aday, yanlış digest ve eski kanıt durumlarında yayının durduğunu test et (workflow testleri `scripts/` altında). |

Sıra:

1. Önce **14**: yayın kilidi, diğer her şeyden bağımsızdır.
2. Ardından **1, 2**: tenant ve yetki.
3. Sonra **3, 4, 5, 10, 11, 12**: connector bypass'ları.
4. En son **6–9**: Browser Guard dosya motoru.

Faz 1'deki her düzeltme, ilgili **gerçek** tüketicide de doğrulanmalı:

| Bulgu | Gerçek tüketici |
| --- | --- |
| 3 | Built extension hook süreci |
| 10 | Codex hook |
| 11, 12 | OpenCode plugin |
| 1, 2, 15 | Edge handler ve izole PostgreSQL |
| 6–9 | Gerçek dosya byte'ları ve Browser Guard Playwright E2E (`pnpm test:e2e:browser-guard`) |

Mümkün olduğunda `pnpm test:e2e:real-host` ile scripted mock-model üzerinden gerçek yan etkinin
oluşmadığını göster. Bu kanıt seviyesi production kabulü değildir; öyle etiketle.

### Faz 2 — P2 ve işletim bulguları

Bu tablodaki sekiz bulgunun sekizi de 10 Ekim'de HEAD'de hâlâ mevcut.

| # | Bulgu | Kaynak | Düzeltme özü |
| --- | --- | --- | --- |
| 15 | OIDC ayarı, owner kontrolü ve audit aynı transaction'da değil | `supabase/functions/oidc-sso/handler.ts`, `store.ts` Yeni bir security-definer RPC ekle (`oidc_set_enforcement` örneğini izle). Owner'ı kilit altında yeniden kontrol etsin; upsert ve audit tek transaction'da olsun. `store.saveProvider` bu RPC'yi çağırsın. |
| 16 | Kesilen diff-aware girdi temiz `allow` sayılıyor | `packages/core/src/agent-safety/edit-views.ts`, `evaluator.ts` Satır kesildiğinde de `truncated` set edilsin. `evaluator.ts` `truncated` sonucunu okuyup temiz `allow` yerine `ask`/deny üretsin. |
| 17 | Privacy audit export 100 bin kayıtta duruyor | `persistent-audit.ts` (`AUDIT_EXPORT_LIMIT`) | Sıra numarasıyla sayfalı export ve önceki hash'ten devam eden doğrulama ekle. |
| 18 | Receipt verifier ve evidence generator farklı varsayılan aday kullanıyor | `scripts/verify-commercial-gate-receipts.mjs`, `scripts/generate-v8-evidence-index.mjs` Varsayılanlar farklı: `…-20260913` ve `…-20260916-r9`. `CANDIDATE_DIGEST_SOURCE` değerini generator'dan import et (`check-claim-evidence-freshness.mjs` bunu zaten yapıyor). Farklı aday açıkça reddedilsin. |
| 19 | Restore drill kanıtı retention ile silinmiyor | `scripts/deployment-restore-drill.mjs` Marker olmasa da her `RESTORE_RUN` dizinine retention/mtime kontrolü uygula (ya da kalıcı bir sahiplik marker'ı kullan). Operatörün yabancı klasörleri korunsun. |
| 20 | Wrapper ve bitişik kısa flag secret'ları maskelenmiyor | `packages/core/src/mcp-launch-redaction.ts` `resolveOwner` içinde wrapper'ların değer alan seçeneklerini atla (sudo: `-u -g -C -h -p -r -t -U`; env: `-u -C -S`). `SECRET_SHORT_FLAGS` için bitişik biçimi de maskele. Kapsanacak örnekler: `sudo -u root curl -u x:y`, `env -u N redis-cli -a x`, `curl -uuser:pass`. |
| 23 | Privacy quota satırları hiç temizlenmiyor | `packages/privacy/src/platform/durable.ts`, `state.ts` `purgeExpiredTransient` yalnız `oidc-pending` ve `portal-sessions` kabul ediyor. `quotas` namespace'ini ekle ve `consume` transaction'ı içinde sınırlı purge yap. Replay, clock ve audit kayıtlarına genel TTL uygulanmasın. |
| 31 | Windows CI timeout süreç ağacını kapatmıyor | `scripts/ci-local.mjs` Bugün win32'de `child.kill` yalnız bash'i öldürüyor. `taskkill /pid <pid> /T /F` veya Job Object kullan. POSIX `process.kill(-pid)` davranışı korunsun. |

Ayrıca `NO_GO_TO_GO_GAP_LIST.md` I.4 tablosundaki düşük bulguları HEAD'de yeniden doğrula ve
hâlâ duranları düzelt:

- MCP gateway global kota oranı
- IPv6 origin ayrıştırması
- `audit verify` çıkış kodları
- U+FFFD yanlış pozitifi
- `a__b` MCP sunucu adı
- İki ayrı canonical JSON uygulaması
- `mcp-gateway package.test.mjs` içindeki 2 kırmızı test

Repo-remote istisnası artık `trustedRepoRoots` gerektiriyor. Kapandığını bir testle kayda geçir.

### Faz 3 — Tedarik zinciri ve bağımlılık sağlığı

1. **Python lock'ları (madde 22):** Her OS/Python platformu için koordineli resolver kullanarak
   hash lock'ları yeniden üret. Ardından:
   - Temiz offline wheel kurulumu ve `pip check` yap.
   - Gerçek NER inference çalıştır.
   - Final lock'tan lisans ve SBOM'u yeniden çıkar.
   - `bindPypiLicenseEvidence` 0 sorun vermeli.

   Bilinen uyumsuzluklar:
   - Linux py3.11 + networkx 3.7
   - Hub 2.x ve transformers `hub<2`
   - mpmath 1.4 ve SymPy 1.14
   - pytest 9 ve pytest-asyncio 1.1
   - Pydantic 2.13 ve pydantic-core

   AIG bridge (`services/aig-bridge`) için de aynı koordineli kabulü yap.
2. **Ertelenen JS göçleri:** zod 4 ve koffi 3 durumunu doğrula; açık kalanlar ayrı PR olsun.
   jsdom 30, pino 10, @vscode/test-electron 3 ve @opencode-ai/plugin 1.18 bump'larını
   ilgili paket ve E2E ile tek tek doğrula.
3. **Lint:** 628 uyarı (10 Ekim) için baseline koy ve yeni uyarıyı CI'da reddet.
4. **Konteyner imajları:**
   - AIDR-079 (dashboard/landing) ve AIDR-082 (backup helper): OS/dil taramasını ignore
     kullanmadan tekrarla, nonroot runtime kontrolünü çalıştır, sonra `VERIFIED_CLOSED` yap.
   - AIDR-080 / madde 33: 33 CRITICAL / 709 HIGH upstream bulgusu için vendor-fix ve
     reachability sınıflandırması yap, uyumlu sabit sürümleri seç ve etkilenen servislerde
     native kabul betiklerini hazırla. Pinlenmiş upstream kaynağını sessizce değiştirme.
5. **Secret geçmişi (madde 39, AIDR-070):** Resmi gitleaks ile final adayda nonshallow full-history
   taraması yap. 2 owner-confirm kaydı için Security'ye karar paketi hazırla. Geçmişi yeniden
   yazma.
6. **Dependabot (madde 40):** Qualification bittikten sonra limitleri geri açan değişikliği hazırla:
   npm 10, Actions/Python/Docker 5. NER limiti 0 kalsın. "Automated security fixes" ayarı repo
   sahibinin işi; bunu sahip listesine yaz.

### Faz 4 — Kapsam, iddia ve kayıt uzlaştırması

1. **Browser Guard native NER zorunluluğu (madde 24):** Tenant yönetimli
   `requireNativeNer` politikası ekle. Host yoksa, çöktüyse, timeout olduysa, sonuç rules-only
   kaldıysa veya limit aşıldıysa paste/upload/send engellensin. Bugün
   `packages/browser-guard/src/content/guard.ts` içindeki `nativeScan`, her hatada `unavailable`
   döndürüp rules-only devam ediyor.
2. **Satılmayacak kapsamı güvenli reddet (madde 25, 26):** İlk sürüm dışında kalanlar:
   - Video, ses ASR, CAD
   - Taranmış PDF OCR
   - Uzak SharePoint/Drive/S3 fetch

   Bunları destek matrisinden çıkar ve kodda açıkça reddedilir hâle getir. Fingerprint
   kapasitesine aşılınca güvenli red ekle.
3. **Connector kapsamı:** Registry 5 direct-GA connector, depo ve native matrix 6 connector
   söylüyor (Codex preview). README, `support-matrix.json`, registry ve plugin manifest'lerini
   hizala.
4. **Kayıt uzlaştırması (madde 38):** Bayat statüleri düzelt (`FEATURE_ACCEPTANCE.json`,
   `RELEASE_READINESS_REPORT.md`) ve inventory/gap/evidence jeneratörlerini aynı aday için
   çalıştır. `pnpm features:inventory`, `scripts/generate-production-sales-gap-audit.mjs` ve
   `scripts/check-generator-determinism.mjs` deterministik geçmeli.
5. **İddia taraması:** Landing kaynağını depoya al. Sonra şunları çalıştır:
   `node docs/scripts/claim-check.mjs --mode=gate`. Kanıtsız iddiaları kaldır
   ("launch-ready", "fully supported", "real-time" vb.). Satış kataloğu madde 30'u da düzelt:
   "ağ çıkışını denetler" iddiası doğru değil.
6. **Red-team regresyonu (I.3):** 114 vakada 22 kaçak ölçülmüştü ve vakalar depoda yok.
   Vakaları depo içinde, zararsız fixture biçiminde yeniden üret. Kuralları `threats/` altında ve
   extractor'larda düzelt. `regex-performance.test.ts` ile doğrula; iki yanlış pozitifi de gider.

### Faz 5 — Aday dondurma ve release kanıtı

1. Kaynağı dondur ve temiz snapshot'tan çalıştır: `pnpm build:release`, SBOM, provenance ve
   `customer-kit`. Onaylı yayıncı anahtarı yoksa çıktıyı **"unsigned mühendislik adayı"** diye
   etiketle.
2. Aynı digest üzerinde çalıştır:
   - `pnpm quality:gate`
   - `pnpm ci:local --keep-going`
   - `pnpm verify:release-signing`
   - `pnpm verify:provenance`
   - `pnpm evidence:index` ve `pnpm evidence:index:verify`
   - `node scripts/run-evidence-gates.mjs --profile first-customer-local`

   Eski kanıtı yeni aday için kullanma.
3. Faz 1 #14'ün çalıştığını göster: bu NO-GO adayla promote dry-run **reddedilmeli**.
4. Hook latency (madde 30): Kurulu artifact üzerinde ≥30 cold ve ≥100 warm örnekle P50/P95/P99
   ölç; eşzamanlı agent ve DLP/NER açık senaryoları dahil olsun. Bütçeyi büyütme. Gerekirse cold
   path'i optimize et: lazy import, threat cache, ACL.

### Faz 6 — Saha kabulü için hazırlık (ajan hazırlar, insan ortamı sağlar)

Aşağıdakilerin her biri için betik, senaryo manifesti, çalıştırma sırası ve receipt şablonu
hazırla. Ortam sağlanırsa çalıştır ve başarısızlıkları, atlamaları ve müdahaleleri sakla.
Ortam yoksa iş açık kalır.

| Madde | Hazırlanacak kabul |
| --- | --- |
| 27 | Native host matrisi: `deploy/native/scenarios/`, T01-NATIVE-SCENARIOS, T01-OS-VERSION-MATRIX. Her host için denied-side-effect, benign-twin, disabled-hook, crash, timeout, offline, restart, upgrade ve uninstall. Cursor/VS Code satırları da dahil. |
| 32 | Canlı deployment: DNS/TLS, Worker route, `readyz`/`version` için JSON + `no-store` kontratı, deployed revision ve login/enrollment smoke (`deploy/cloudflare`). |
| 34, AIDR-044 | Ayrı hosta restore, RPO/RTO, legal-hold-aware prune (`tenant_legal_holds` okunmalı) ve offsite durability. |
| 37, AIDR-052 | 8 saatlik authenticated soak, iki tenant noisy-neighbour, failover (`deploy/ha`, `scripts/load-test*`). |
| 28, AIDR-019 | Gerçek Entra/Okta SCIM: grup kaldırma, deaktivasyon, başka directory, replay. |
| 29 | Kurum çıkış (egress) envanteri ve canary capture planı. Browser Guard'ı ağ filtresi diye satma. |
| 36 | `PRODUCTION_SALES_GAPS.json` içindeki 44 saha kabul paketinin her biri için malicious/benign/outage senaryosu. |
| I.2 | Operatör deployment adımlarını tek bir sıralı runbook'a dönüştür. |

### Faz 7 — Kurumsal kapılar için sahip paketleri

Kapılar: COM-001…005, COM-010…013, SEC-EXT-001, POV-001, INV-001 ve CLM-001.

Her kapı için şunları yaz:

- Sahip rolü
- Gereken girdi
- Doldurulmuş şablon (önceden doldurulabilenleri doldur)
- Çalıştırılacak komut
- Kabul çıktısı ve hash bağlama biçimi
- Ret durumunda ne olacağı

Ayrıca adım adım bir hesap/yetki talep listesi üret:

- Kod imzalama (Authenticode, notarization)
- Mağaza hesapları
- Yayıncı anahtarı
- Private registry
- DNS/TLS
- SMTP
- IdP
- Billing sağlayıcısı
- Bağımsız pentest firması
- PoV değerlendiricisi

### Sahibinden beklenecek kararlar (sorma; seçenek ve öneri hazırla)

- Satış kademesi: kontrollü değerlendirme → destekli satış → GA
- Direct-GA connector seti: 5 mi 6 mı
- Bölge vaadi
- SLA zamanlaması
- T18 SAML zorlama semantiği
- Billing sağlayıcısı ve SKU
- Kayıtsız ticari build davranışı: yerel tespit mi, başlamayı reddetme mi
- Plan kuralları: deneme, downgrade, retention
- Yönetilen istisnalarda dört göz
- NER modeli: madde 21. Hiçbir aday kalite eşiğini geçmedi (recall ≥0,95, precision ≥0,90,
  clean disruption ≤0,05). Satılabilmesi için ya kurumsal korpusla kabul ya da kapsamdan
  çıkarma kararı gerekiyor.

### Paralel çalışma (çok ajan destekliyorsa)

Dosya kapsamları çakışmayan lead'ler kullan:

| Lead | Kapsam |
| --- | --- |
| A | Supabase/OIDC/retention: 1, 2, 15 |
| B | Core ve connector'lar: 3, 4, 5, 10, 11, 12, 16, 20 |
| C | Browser Guard: 6–9, 24 |
| D | Privacy: 13, 17, 23, 25 |
| E | Release/CI: 14, 18, 19, 31, Faz 5 |
| F | Tedarik zinciri: Faz 3 |
| G | Kapsam, iddia ve kayıtlar: Faz 4, 7 |

Root `package.json`, lockfile, generated kayıtlar ve son entegrasyon yalnız ana ajan tarafından
yazılır.

### Bitti tanımı

| Seviye | Koşul |
| --- | --- |
| **LOCAL_ENGINEERING_READY** | 1–20, 23, 24 ve 31 kodda kapalı, gerçek tüketicide testli. Faz 0 yeşil. Faz 3 kod kısmı ve Faz 4 tamam. Generated kayıtlar deterministik. |
| **RELEASE_CANDIDATE_READY** | Yukarıdakilere ek olarak Faz 5'in tamamı tek bir immutable digest'e bağlı. NO-GO publish kilidi kanıtlı (imza hariç). |
| **PRODUCTION_SALES_GO** | Yukarıdakilere ek olarak aynı digest için Faz 6 saha receipt'leri ve seçilen profilin kurumsal kapıları isimli yetkililerce kabul edilmiş. |

Bir seviye karşılanmıyorsa karar bir alt seviyede kalır.

### Rapor biçimi (her çalışmanın sonunda)

1. **En üstte:** Tıkanan veya başarısız olan her şey: komut, exit code, log yolu.
2. Kapanan bulgular: numara, commit, test, kanıt seviyesi.
3. Yeşil kontroller: komut, sonuç, commit, aday digest.
4. Açık kapılar: kapı → eksik → sahip.
5. Karar bekleyenler.
6. Karar: **NO-GO** / LOCAL_ENGINEERING_READY / RELEASE_CANDIDATE_READY / PRODUCTION_SALES_GO.

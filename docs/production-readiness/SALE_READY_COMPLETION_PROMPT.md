# Satışa hazır olma — ajan promptu

Bu dosyanın "PROMPT" bölümünün tamamını, repo kökünde çalışan otonom bir kodlama ajanına tek
prompt olarak ver. Plan: [SALE_READY_COMPLETION_PLAN.md](./SALE_READY_COMPLETION_PLAN.md).
Önceki ajan promptu (`next-agent-execution-prompt-v8.md`) bir jeneratör çıktısı olabilir; bu
dosya onun yerine geçmez, ondan sonraki durumu (8 Ekim 2026) esas alır.

---

## PROMPT

Sen kıdemli bir platform, güvenlik, SRE ve release mühendisliği ekibi gibi çalışan otonom bir
kodlama ajanısın. Çalışma alanın repo kökü. Ürün: **Singularity AIDR** — AI kodlama ajanlarının
komut, dosya ve web isteklerini koruyan tespit/müdahale katmanı (connector'lar, CLI, SDK, MCP
gateway, dashboard + Supabase kontrol düzlemi, Browser Guard, AIDR Privacy).

### Hedef

Ürünü, **yalnızca insanlara imza, hesap ve karar kalacak** hâle getir: yerel olarak kapatılabilen
her boşluğu kod, test ve kanıtla kapat; dış kapıların her biri için eksiksiz "sahip paketi"
hazırla; hiçbir kanıtı uydurma. Plan yazıp durma — uygula, doğrula, kaydet. Bağımsız ilerleyebildiğin
sürece kullanıcıya soru sorma; bir parça tıkandığında diğerlerini bitir ve raporuna tıkanan
parçayla başla.

### Doğruluk sözleşmesi (ihlal edilemez)

1. Karar **NO-GO**'dur ve yalnızca `commercial-go-evidence-registry.json` ile
   `commercial-gate-receipts.json` değişebilir; onları **yetkili insan onayı ve gerçek, aynı
   adaya bağlı kanıt olmadan** değiştirme. Yüzde, "neredeyse hazır", "production-grade" gibi ifadeler yok.
2. Unit test, mock, sentetik korpus, kaynak okuma, çapraz derleme, sürüm sorgusu; gerçek host
   yan etkisi, gerçek bulut kurulumu, bağımsız pentest, müşteri PoV, SLA veya hukuki onay
   **kanıtı değildir**.
3. Hukuk, finans, IdP, SMTP, MDM, DNS/TLS, private registry, resmi imzacı, bölge, bağımsız
   değerlendirici veya müşteri yoksa kapıyı **açık** bırak; sahibine ne gerektiğini yaz.
4. Üretilmiş dosyaları (`FEATURE_INVENTORY.*`, `PRODUCTION_SALES_GAPS.*`, kanıt indeksi, ajan
   promptları) elle düzenleme; jeneratörü düzelt, yeniden üret. `FEATURE_ACCEPTANCE.json` ve
   `RELEASE_READINESS_REPORT.md` jeneratörsüzdür ve bayattır (hâlâ "90 yetenek" diyor): elle,
   kaynağa bakarak güncelle.
5. Testi geçirmek için assertion silme, timeout büyütme, skip ekleme, geniş allowlist veya
   kontrol gevşetme yasak. Yeni skip dar, gerekçeli, kapalı-kapalı olmalı.
6. Sır, token, parola, özel anahtar, müşteri verisi, ham prompt veya kişisel yol bilgisini
   kaynağa, loga, destek paketine veya release'e koyma.
7. Fiyat herkese açık hiçbir sayfada görünmez (bir test bunu zorlar). Fiyat/SKU/vergi/hukuk
   cümlesi uydurma.

### Değişmez ürün kuralları (`CLAUDE.md`)

- Varsayılan zorlama **yerel**tir; kayıt/hesap tespitin ön koşulu olamaz.
- Hata politikası katmana göredir: tespit içi → sinyali atla + logla (asla "temiz" gösterme);
  connector giriş noktaları → **kapalı** (deny/block); güvenlik kontrolleri → kapalı.
- `ask` = insan onayı bekleyen blok; **hiçbir connector ajana onay aracı vermez**.
- Tehdit kuralları veridir (`threats/*.yaml`), koda gömülmez. Kural çakışmasında `deny > ask > allow`.
- URL/dosya/paket itibar bacakları dağıtılmış bir birinci taraf uç nokta olmadan **etkisizdir** ve "temiz" sunulmaz.
- Adlandırma: YAML/JSON `snake_case`, TypeScript `camelCase`.

### Başlangıç durumu (8 Ekim 2026, `master` @ `847bee80`) — önce bunu yeniden ölç

- Kayıt: 109 yetenek (66 bağlı / 41 kısmi / 2 dış), 47 teknik iş (3 OPEN: **T19, T37, T38**), 13 dış kapı.
- **`master` kırık**, bugünkü toplu Dependabot birleşiminden (üç ayrı PR):
  - `pnpm check` → `packages/core` içinde 42 TS hatası: **zod 3→4** (#75). `.default({})` iç içe şema
    çağrıları, kaldırılan `invalid_enum_value` kodu, `z.record` argüman sayısı vb.
  - `pnpm build` → **koffi 2→3** (#95): `koffi/build/koffi/<plat>/koffi.node` yok;
    `scripts/stage-windows-koffi.mjs` ve `scripts/verify-package-install.mjs` bu yola bağlı.
  - `pnpm test` → **react-dom 19.3.0 / react 19.2.4** uyuşmazlığı (#80): 66 dashboard test dosyası düşüyor.
  - zod ve koffi geri alınınca `check` ve `build` geçti; tam test 10.291 geçti / 30 başarısız /
    13 atlama (69 dosya). Bu 30'un: react uyuşmazlığı (dosya düzeyi), `deploy/upstream` submodule'ü
    başlatılmamış olduğu için `discovery-cloud` testleri (ortamsal), ve **merge öncesi `dc56701c`'de de
    kırmızı olan** 9 SCIM admin contract + 1 browser-guard windows-1252 testi (önceden var) olduğunu
    ayırt et; hepsini yeniden ölç. jsdom 30, pino 10, @vscode/test-electron 3, @opencode-ai/plugin,
    Node 26 ve Python 3.14 Docker imajlarının etkisi **doğrulanmadı** (dashboard testleri koşmadığı için görünmüyor).
  - Yerel (push edilmemiş) `local/revert-zod4-koffi3-candidate` dalı iki geri almayı taşıyabilir;
    ajan oturumunda bulunmayabilir — yeniden üretmek için `git revert 80d7e76c 3dff546d`.
- `pnpm ci:local --list` kendi başına hata veriyor (`ci.yml` ile `scripts/lib/ci-local-plan.mjs`
  arasında "MCP gateway and dashboard auth callback tests" adım kayması). GitHub Actions bu
  depoda kapalı; **`ci:local` tek CI'dır**.
- `pnpm lint` çıkış 0 ama ~746 uyarı.
- Gerçek host kanıtı: yalnızca linux/x64, geliştirme build'i, betikli sahte model; Cursor/VS Code hiç
  çalışmadı; Windows/macOS yok.
- Kayıtlı son tam test (6 Eki): 6.857 geçti, 6 POSIX atlama.

### Önce şunları oku ve uzlaştır

`CLAUDE.md`, `docs/production-readiness/SALE_READY_COMPLETION_PLAN.md`, `HANDOFF.md`,
`first-customer-ready.md`, `external-gates-runbook.md`, `go-preparation-2026-10-06.md`,
`commercial-go-evidence-registry.json`, `commercial-gate-receipts.json`, `PRODUCTION_SALES_GAPS.json`,
`FEATURE_INVENTORY.json`, `READINESS_BACKLOG.json`, `deploy/FIRST_CUSTOMER.md`,
`deploy/native/support-matrix.json`, `package.json` script'leri. Çalışan kod ve test sonucu,
doküman iddiasından üstündür.

### Çalışma kuralları

- `git status`, `HEAD`, Node/pnpm/Python/Docker/OS sürümlerini kaydederek başla. Başkasının
  değişikliğini geri alma; `reset --hard`, `clean`, toplu checkout, rebase, zorla silme yok.
- **`master`'a doğrudan push yok.** Her iş ayrı dal + atomik commit(ler) + **taslak PR**. PR açmadan
  önce değişen dosyalar üzerinde `code-simplifier` alt ajanını çalıştır ve önerileri uygula
  (`CLAUDE.md` Pre-PR Checklist). Kullanıcı açıkça izin vermedikçe PR'ı **merge etme**, tag atma, yayın yapma.
- **Hiçbir bağımlılık güncellemesi (özellikle major) `pnpm install --frozen-lockfile && pnpm check
  && pnpm build && pnpm test` geçmeden birleşmez.** Major bump = ayrı PR + göç notu.
- Yeni bağımlılık eklemeden önce lisans, bakım, bilinen açık, lockfile ve boyut etkisini değerlendir.
- Uzun komutları arka planda çalıştır, çıkış kodunu ve tam logu sakla; araç zaman aşımını PASS sayma.
- Her kapanışta: kod yolu + test + gözlenebilir yan etki + commit + aday digest + tarih + kalan sınır.
- Değişiklik için `pnpm changeset` gerektiğinde ekle.

### Döngü (her iş için)

Çoğalt (gerçek giriş noktasından) → izle (UI/CLI/hook'tan politika, kimlik, dedektör, kalıcılık,
müdahale, telemetri, operatör görünümüne) → uygula (en küçük tutarlı dilim; migration, tüketici,
CLI/UI, paket varlığı, config, runbook birlikte) → hedefli doğrula (pozitif, kötü niyetli,
benign-twin, bozuk girdi, bağımlılık yok, zaman aşımı, tekrar, eşzamanlılık, tenantlar arası,
geri alma) → gözlenebilir etkiyi doğrula (blok gerçekten yan etkiyi önlüyor mu) → regresyon
(`pnpm check`, `build`, `test`, ilgili paket) → **paketlenmiş artefakt ve temiz tüketicide
doğrula** → kayıt/jeneratör → commit.

### Fazlar

**Faz 0 — `master`'ı yeşile döndür (ilk iş, diğerleri bunu bekler).**
1. `master`'dan dal aç. zod 4 (#75) ve koffi 3 (#95) birleşimlerini `git revert` ile geri al
   (öneri) **veya** tam göç yap; hangisini seçtiğini gerekçeyle raporla. Geri almada lockfile'ın
   tutarlı kaldığını doğrula. react-dom (#80) için `react`'i aynı sürüme hizala (veya geri al) ve
   dashboard testlerini yeniden koştur; jsdom 30 etkisi ancak bundan sonra görünür.
   Merge öncesi de kırmızı olan testleri (SCIM admin contract, windows-1252) ayrıca sınıflandır;
   `deploy/upstream` submodule'ünü başlatmadan `discovery-cloud` testleri koşamaz.
2. Doğrulama: `pnpm install --frozen-lockfile && pnpm check && pnpm build && pnpm test`, sonra
   `pnpm ci:local --keep-going --fetch-tools`. Atlamaları (Docker, `pwsh`, kök olmayan kullanıcı,
   aday envanteri) nedenleriyle listele.
3. Kalan major bump'ları tek tek doğrula; Docker taban imajlarını (Node 26, Python 3.14) gerçekten
   derle, imaj güvenlik taramasını yeniden çalıştır; sorunluysa geri al ve ayrı iş aç.
4. `ci:local` ↔ `ci.yml` kaymasını onar; `scripts/ci-local.test.mjs` yakalasın.
5. Dependabot: major sürümler ayrı grup / otomatik merge dışı; PR şablonuna doğrulama komutları.
6. Lint uyarı tabanı (baseline) koy; yeni uyarı eklenemesin.

*Çıkış:* temiz `master`'da `check`, `build`, `test`, `ci:local --keep-going` yeşil.

**Faz 1 — Yerel kod boşlukları** (öncelik sırasıyla; her biri döngüyle kapanır):
1. **T19** SCIM / Azure AD grup eşlemesi, **T37** gerçek veri akışı + redaksiyon + gizlilik kanıtı,
   **T38** kuruma özel DLP ve etiketler.
2. Tespit: hostname'de DNS sızdırma; ters/bölünmüş canary; AI-BOM'da `-p <parola>` maskeleme;
   iki MCP sunucusuna yayılan zincirler; MCP doğrudan upstream bypass (zorunlu yönlendirme).
3. Browser Guard: PDF içi görsel OCR; eski `.doc/.xls/.ppt` taraması; OCR doğruluğu ve ODF/LibreOffice doğrulaması.
4. Sınama kapsamı: Docker gerektiren 15 Postgres paketi ve `ci:local` Docker adımları (Docker varsa);
   yoksa açık "çalıştırılmadı" kaydı.
5. **T18 SAML zorlama:** ürün kararı olmadan **uygulama**. Seçenekleri (kim onaylar, AAL2, geri dönüş
   hedefi, oturum iptali, süre/tekrar kuralları) ve önerini yaz; kararı sahibinden iste.

*Çıkış:* LOCAL_ENGINEERING_READY — yerel giderilebilir "partial" yok; kalanlar jeneratörle
doğrulanmış dış bağımlılık olarak yeniden sınıflanmış.

**Faz 2 — Aday dondurma ve sahip paketleri**
1. Yalıtılmış temiz snapshot'tan release, müşteri kiti, SBOM, provenance üret
   (`scripts/customer-kit.mjs`, `release-sign.mjs`, `generate-provenance.mjs`); aday digest'i bağla.
   Onaylı yayıncı anahtarı yoksa çıktıyı **"unsigned mühendislik adayı"** etiketle; test anahtarını yayıncı gibi sunma.
2. `node scripts/run-evidence-gates.mjs --profile first-customer-local`, `pnpm evidence:index:verify`.
   Eski kanıtı yeni aday için kullanma; kaynak değişirse etkilenen kanıtı yeniden üret.
3. İddia temizliği: `node docs/scripts/claim-check.mjs --mode=gate`; "launch-ready", "go live in
   minutes", "fully supported", "comprehensive … platform", "real-time" gibi kalıpları kaldır.
   Yayındaki landing kaynağını (kayıtlara göre depoda yok) depoya al.
4. **Her dış kapı için sahip paketi** (COM-001…005, 010…013, SEC-EXT-001, POV-001, INV-001, CLM-001):
   sahip rolü, gereken girdi, doldurulmuş şablon, çalıştırılacak komut, kabul çıktısı, hata
   durumunda ne olur. Önceden doldurulabilenleri doldur
   (`commercial-gates-prefill-and-owner-actions-2026-10-05.md`).
5. Kod imzalama, mağaza hesapları, yayıncı anahtarı, özel registry, DNS/TLS, SMTP, IdP, fatura
   sağlayıcısı için **adım adım hesap/yetki talep listesi** üret.

*Çıkış:* RELEASE_CANDIDATE_READY (imza hariç) + 12 kapı için eksiksiz sahip paketi.

**Faz 3 — Gerçek ortam kabulleri (ajan hazırlar, gerçek ortamı insan sağlar).**
Gerçek host/bulut/DNS/yedek/yük kabulü için betikleri, senaryo manifestlerini ve çalıştırma
sırasını hazırla; ortam sağlanınca çalıştır ve **başarısızlıkları, atlamaları, müdahaleleri
saklayarak** kaydet. Eksik host = kapsam dışı. Sekiz saatlik soak, off-host geri yükleme,
ikinci makinede bağımsız imza doğrulaması (tamper/expiry/yanlış imzacı/rollback reddi) için
komutlar `deploy/native`, `deploy/ha`, `deploy/backup`, `scripts/` altındadır.

**Faz 4 — Kapanış raporu.** Registry/receipt'lere dokunmadan: durum tablosu (kapı → kanıt
seviyesi → eksik girdi → sahip), açık risk listesi, sahibinden beklenen kararlar.

### Sahibinden bekleyeceğin kararlar (sorma; seçenek + öneri hazırla)

Satış kademesi (kontrollü değerlendirme → destekli satış → GA); connector kapsamı (registry beş,
native matrix altı — hizala); bölge vaadi (EU/US/APAC vs tek bölge); SLA zamanlaması; T18 SAML
semantiği; faturalama sağlayıcısı ve SKU; mağaza/imza yayıncı kimliği; zod 4 / koffi 3 göçü.

### Rapor biçimi (her çalışma sonunda)

1. **En üstte:** tıkanan veya başarısız olan her şey (komut, çıkış kodu, ilgili log yolu).
2. Yeşil olanlar: komut, sonuç, commit, aday digest.
3. Açık kapılar: kapı → ne eksik → kim sağlayacak.
4. Karar bekleyenler.
5. Karar: **NO-GO** / LOCAL_ENGINEERING_READY / RELEASE_CANDIDATE_READY / FCR GO / PRODUCTION_SALES_GO — kanıt seviyesiyle.

Bir seviye karşılanmıyorsa karar bir alt seviyede kalır; ara ifade kullanma.

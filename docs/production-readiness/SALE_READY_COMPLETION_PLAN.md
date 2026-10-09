# Satışa hazır olma planı — Singularity AIDR

Hazırlanma tarihi: 8 Ekim 2026. Kaynak: depodaki hazırlık kayıtları (`READINESS_BACKLOG.json`,
`PRODUCTION_SALES_GAPS.json`, `FEATURE_INVENTORY.json`, `commercial-go-evidence-registry.json`,
`first-customer-ready.md`, `HANDOFF.md`) ve bu oturumda yapılan yerel ölçümler. Bu plan
**yeni bir kabul defteri değildir**; karar kaydı `commercial-go-evidence-registry.json` ve
`commercial-gate-receipts.json` olarak kalır. Bu belgeyle birlikte verilen ajan promptu:
[SALE_READY_COMPLETION_PROMPT.md](./SALE_READY_COMPLETION_PROMPT.md).
NO-GO'dan GO'ya geçmek için **kapanması gereken her maddenin eksiksiz listesi**:
[NO_GO_TO_GO_GAP_LIST.md](./NO_GO_TO_GO_GAP_LIST.md).

## 1. Dürüst çerçeve: "%100 hazır" ne demek, kim bitirir?

Ürünün kodu büyük ölçüde yazılmış durumda. Kayıtlara göre karar **NO-GO** ve bunun nedeni
çoğunlukla kod değil, **dışarıdan gelmesi gereken kanıt ve onaylar**:

| Parça | Bir kodlama ajanı tek başına bitirebilir mi? |
|---|---|
| Kırık derleme, regresyon, test ve lint borcu, belge/kayıt tutarlılığı | **Evet** |
| Açık kod işleri (T19, T37, T38, tespit boşlukları, Browser Guard boşlukları) | **Evet**, ürün kararı gerektirenler hariç (bkz. bölüm 7) |
| Aday dondurma, SBOM/provenance, kurulum paketi, kanıt indeksi, sahiplere hazır paketler | **Evet** |
| Gerçek DNS/TLS, bulut hesapları, canlı faturalama, e-posta/SMTP, IdP (Entra/Okta) | **Hayır** — hesap ve yetki sahibi gerekir |
| Kod imzalama sertifikaları, mağaza hesapları (Chrome/Edge/AMO/Marketplace), yayıncı anahtarı | **Hayır** |
| Bağımsız sızma testi, hukuki/gizlilik/lisans onayı, SLA sözleşmesi, fiyat/SKU kararı | **Hayır** — üçüncü taraf veya yetkili insan |
| Gerçek host (Windows/macOS/Linux, Cursor/VS Code) kabulü, 8 saatlik yük testi, off-host geri yükleme | **Kısmen** — betikler hazır, gerçek makine ve hesap gerekir |
| İsimli müşteri PoV ve imzalı kabul | **Hayır** |

Bu yüzden hedef şöyle tanımlanır: ajan işi **"insanlara yalnızca imza, hesap ve karar kalacak
hâle"** getirir; dış kapılar paralel yürütülür; her kapı için kanıt, mevcut receipt şemasıyla
(`commercial-gate-receipts.schema.json`) kapanır. Kanıt uydurulmaz, hiçbir kapı "yüzde" ile
raporlanmaz.

Depo kendi kabul seviyelerini zaten tanımlıyor; bu plan onları kullanır:

1. **LOCAL_ENGINEERING_READY** — yerel olarak kapatılabilir her boşluk kapalı, testler/derleme/kayıtlar yeşil.
2. **RELEASE_CANDIDATE_READY** — kesin aday özeti (digest), temiz kaynak, SBOM/provenance, kurulum/yükseltme/geri dönüş doğrulaması.
3. **FCR GO (kontrollü değerlendirme)** — `first-customer-ready.md` FCR-01…08, AIDR'ın kendi hesap/altyapısıyla; 8 zorunlu kapı.
4. **Destekli satış / Production-GA** — 12 zorunlu dış kapı (COM-001…005, 010…013, SEC-EXT-001, POV-001, CLM-001).

**Önerilen yol: kademeli satış.** Önce kontrollü değerlendirme (en az dış bağımlılık), sonra
destekli satış, en son GA. Üçünü aynı anda hedeflemek kritik yolu gereksiz uzatır.

## 2. Bugünkü ölçülmüş durum (8 Ekim 2026, `master` @ `847bee80`)

Aşağıdakiler bu oturumda yerelde ölçüldü; kayıtlardan alınanlar ayrıca işaretli.

| Konu | Durum |
|---|---|
| Karar kaydı | **NO-GO** (registry, 23 Eyl 2026; FCR 24 Eyl; native matrix 30 Eyl) |
| Özellik envanteri (kayıt) | 109 yetenek: 66 bağlı, 41 kısmi, 2 dış kabule bağlı |
| Teknik iş paketleri (kayıt) | 47: 44 "yerel uygulandı, saha kabulü açık", **3 OPEN (T19, T37, T38)** |
| Dış kapılar (kayıt) | 13 kapı açık; değerlendirme profili 8, destekli satış / GA / yatırımcı 12 |
| Backlog (kayıt) | 82 bulgu: 73 kapalı, 9 `BLOCKED_EXTERNAL` |
| Son tam test (kayıt, 6 Eki) | 6.857 geçti / 0 kalan / 6 POSIX atlama; kapsam %81 ifade, %76 dal |
| **`pnpm check` (ölçüldü)** | **BAŞARISIZ** — `packages/core` içinde 42 TypeScript hatası; kaynak: zod 3→4 bump'ı (#75). `core` derlenmediği için tüm paketler zincirleme kırık |
| **`pnpm build` (ölçüldü)** | **BAŞARISIZ** (zod geri alınsa bile) — `koffi` 2→3 bump'ı (#95): `koffi/build/koffi/win32_x64/koffi.node` yok, Windows AMSI hazırlama ve paket doğrulama betikleri bu yola bağlı |
| **`react-dom` bump'ı (ölçüldü)** | `react-dom` ^19.3.0 yükseltilmiş ama `react` 19.2.4'te kaldı (#80): "Incompatible React versions" → **66 dashboard test dosyası** düşüyor |
| zod + koffi bump'ları geri alınmış yerel dalda (`local/revert-zod4-koffi3-candidate`, push edilmedi) | `pnpm check` **geçti**, `pnpm build` **geçti**; tam test: **10.291 geçti / 30 başarısız / 13 atlama** (628 dosyanın 69'u başarısız) |
| Bu başarısızlıkların kaynağı | 66 dosya: react/react-dom uyuşmazlığı (#80). `discovery-cloud` testleri: `deploy/upstream` submodule'ü bu checkout'ta başlatılmamış (ortamsal, `git submodule update --init`). **9 SCIM admin contract testi + 1 browser-guard windows-1252 testi merge öncesi `dc56701c`'de de başarısız** (bugünkü merge'lerden bağımsız, önceden var; ortam Node 22.22, depo kayıtları Node 24 diyor). Dashboard düzeldikten sonra jsdom 30'un etkisi **henüz görünmüyor** (testler hiç koşmadı), yeniden ölçülmeli |
| `pnpm lint` (ölçüldü) | çıkış 0; **746 uyarı** (çoğu karmaşıklık/biome) — kalıcı borç |
| `pnpm ci:local --list` (ölçüldü) | **hata**: `ci.yml` içinde "MCP gateway and dashboard auth callback tests" adımı yok (bugünkü merge'lerden önce de vardı). CI devre dışı olduğu için `ci:local` tek kapı — bu kayma onu kısmen kör ediyor |
| Canlı pilot (kayıt, 24 Eyl) | `app.aidr…` DNS yok; yayındaki landing "launch-ready / go live in minutes" diyor (claim kaydı bunu yasaklıyor); destek, durum, gizlilik, şartlar sayfaları yapılandırılmamış; `/readyz` 503 |
| Gerçek host kanıtı | Claude Code, Codex, OpenCode, OpenClaw: linux/x64, **geliştirme build'i + betikli sahte model**. Cursor ve VS Code **hiç çalıştırılmadı**; Windows/macOS yok |

> **Bugünkü merge'ler hakkında not.** 8 Ekim'de 22 Dependabot PR'ı toplu merge edildi. Bunlardan
> üçü `master`'ı kırdı: #75 (zod 4: derleme), #95 (koffi 3: build) ve #80 (react-dom: dashboard
> testleri). Merge öncesi CI/test olmadığı için fark edilmedi; merge'ler yalnızca GitHub'ın
> "mergeable" durumuna dayanıyordu. Diğer major bump'lar (jsdom 30, pino 10, vb.) ayrıca
> doğrulanmalı. Faz 0 bunu onarır ve tekrarını önler.

## 3. Ürün haritası (kısa)

TypeScript monorepo; ortak tespit çekirdeği (`packages/core`) üzerine connector'lar (Claude Code,
Codex, OpenCode, OpenClaw, Cursor/VS Code), CLI, SDK, MCP gateway, dashboard + Supabase kontrol
düzlemi (150+ migration, Edge Functions), Browser Guard (Chrome/Edge/Firefox MV3) + AIDR Privacy
motoru (TR/EN PII, isteğe bağlı yerel NER), AIG köprüsü (Python/FastAPI), Helm/Compose
dağıtımı, 494 tehdit kuralı (YAML). Varsayılan mod **yerel**: hesapsız çalışır; "managed" katmanı
isteğe bağlıdır. Hata politikası katmana göre (tespit içi: sinyali atla ve logla; connector giriş
noktası: kapalı-kapalı/deny; güvenlik kontrolleri: kapalı). Satılan kapsam kararı (registry):
direct-GA, hibrit dağıtım (EU/US/APAC), çevrimiçi + faturalı satış, 14 gün / 1 ajan deneme, özel
registry dağıtımı, %99,9 SLA hedefi.

## 4. Fazlar

Süreler **tahmindir**; dış taraf süreleri özellikle belirsizdir ve kritik yolu onlar belirler.

### Faz 0 — `master`'ı yeşile döndür (ajan, 0,5–2 gün)

Bu faz her şeyin ön koşuludur; bitmeden başka iş yapılmaz.

1. `master`'daki üç kırık birleşimi onar: **zod 4 (#75)** ve **koffi 3 (#95)** için geri al (hızlı, düşük risk) veya gerçek göç yap; **react-dom (#80)** için `react`'i aynı sürüme (19.3.0) hizala ya da geri al.
   Öneri: zod ve koffi'yi geri al, her birini ayrı iş olarak planla (Faz 1). Çünkü zod 4 göçü 42 hata + davranış farkı, koffi 3 ise yerel ikili dosya yerleşimi ve Windows imzalı AMSI hattı demek. Yerel `local/revert-zod4-koffi3-candidate` dalı iki geri almayı içerir (doğrulandı: check + build geçer); react düzeltmesi eklenmeli.
2. Geri aldıktan sonra tam doğrulama: `pnpm install --frozen-lockfile && pnpm check && pnpm build && pnpm test`, ardından `pnpm ci:local --keep-going`.
3. Diğer major bump'ları (jsdom 30, pino 10, @vscode/test-electron 3, Node 26 ve Python 3.14 Docker taban imajları, @opencode-ai/plugin) **tek tek** test et; Docker imajlarını gerçekten derle ve imaj güvenlik taramasını yeniden çalıştır (`bridge-*-security-2026-10-06.md` kanıtları eski taban imajlara bağlı).
3b. Merge öncesi de kırmızı olan testleri çöz: 9 SCIM admin contract testi (`supabase/functions/__tests__/scim-admin-contract.test.ts`, T19 ile ilişkili olabilir) ve `browser-guard` windows-1252 testi (Node 22 vs 24 farkı mı gerçek hata mı belirle). `deploy/upstream` submodule'ünü başlatıp `discovery-cloud` testlerini koştur.
4. `ci:local` kaymasını onar (`scripts/lib/ci-local-plan.mjs` ↔ `.github/workflows/ci.yml`); `ci-local.test.mjs` bunu yakalamalı.
5. Dependabot politikası: major sürümleri otomatik açma/ayrı grupla, "merge öncesi `pnpm check && pnpm build && pnpm test` zorunlu" kuralı (dallanma koruması veya `ci:local` ön-merge kontrolü).
6. Lint borcu: 746 uyarıyı sınıflandır; yeni uyarı eklenmesini engelle (baseline), karmaşıklık uyarılarını hedefli azalt.

**Çıkış kriteri:** `check`, `build`, `test`, `ci:local --keep-going` temiz `master` üzerinde yeşil; atlamalar nedenleriyle listeli.

### Faz 1 — Yerel kod boşlukları (ajan, 1–4 hafta)

Öncelik sırası; her biri "gerçek tüketici + test + paket + kanıt" döngüsüyle kapanır.

1. **Üç OPEN iş:** T19 (SCIM/Azure AD grup eşlemesi), T37 (gerçek veri akışı/redaksiyon/gizlilik kanıtı), T38 (kuruma özel DLP/etiketler).
2. **Bilinen tespit boşlukları:** hostname'de DNS sızdırma; ters/bölünmüş canary token; AI-BOM başlatma argümanında `-p <parola>` maskeleme; iki MCP sunucusuna yayılan zincirler için gateway birleştirmesi; MCP doğrudan upstream bypass (zorunlu yönlendirme).
3. **Browser Guard:** PDF içi görseller için OCR yolu eklendi (doğruluk ölçülmedi); eski `.doc/.xls/.ppt` içerik taraması; OCR doğruluğu ve ODF dosyalarının LibreOffice'te açılması doğrulaması.
4. **Sınama kapsamı:** Docker gerektiren 15 Postgres paketi ve `ci:local` Docker imaj adımları (Docker'lı ortamda); Windows `pwsh` adımı; kök olmayan kullanıcı adımı.
5. **Zod 4 ve koffi 3 göçleri** (isteğe bağlı, satışı geciktirmez): ayrı dal, ayrı PR, tam kapı.
6. **Ürün kararı gerektirenler — ajan karar vermez:** T18 kurumsal SAML zorlama semantiği (kim onaylar, geri dönüş, oturum iptali, süre/tekrar kuralları). Bkz. bölüm 7.

**Çıkış kriteri:** `LOCAL_ENGINEERING_READY`; envanterde yerel olarak giderilebilir "partial" kalmaz, kalanlar doğrulanmış dış bağımlılık olarak yeniden sınıflanır (jeneratörlerle, elle düzenlemeyle değil).

### Faz 2 — Aday dondurma ve "sahiplere hazır paketler" (ajan, 1 hafta)

1. Kaynak ve konfigürasyonu dondur; temiz, yalıtılmış snapshot'tan release çıktısı + müşteri kiti + SBOM/provenance üret (`scripts/customer-kit.mjs`, `release-sign.mjs`, `generate-provenance.mjs`). Aday digest'ini bağla. **İmza yoksa çıktı "unsigned mühendislik adayı" olarak etiketlenir.**
2. Kanıt indeksini üret ve doğrula (`node scripts/run-evidence-gates.mjs --profile first-customer-local`, `pnpm evidence:index:verify`).
3. İddia temizliği: landing ve README taraması (`node docs/scripts/claim-check.mjs --mode=gate`); "launch-ready", "go live in minutes", "fully supported", "real-time" gibi yasaklı kalıpları kaldır; yayındaki landing kaynağını depoya al (24 Eyl bulgusu).
4. **Her dış kapı için sahip paketi** üret: kim, ne verecek, hangi şablon, hangi komut, kabul çıktısı ne. Mevcut şablonları önceden doldur (`commercial-gates-prefill-and-owner-actions-2026-10-05.md`, `external-gates-runbook.md`). İmza, hesap, fiyat, hukuki cümle **uydurulmaz**.
5. Fiyat politikası: fiyatlar herkese açık sayfada yok (test bunu zorluyor); iç dokümanlardaki fiyatları depo paylaşılmadan önce kaldırma kararı sahibe sorulur.

**Çıkış kriteri:** `RELEASE_CANDIDATE_READY` (imza hariç); 12 dış kapının her biri için eksiksiz sahip paketi.

### Faz 3 — Dış kapılar (insanlar, **hemen paralel başlat**, 4–12+ hafta)

Aşağıdaki işlerin hepsinin bekleme süresi var; bu yüzden Faz 0'dan itibaren başlatılır.

| Kapı | Ne gerekiyor | Sahibi | Tahmini bekleme (belirsiz) |
|---|---|---|---|
| COM-001 | SKU, fiyat, ölçüm, vergi, teklif/sipariş şablonu, imzalı manifest | Ticari + Finans | 1–3 hf |
| COM-002 | Lisans/NOTICE/IP incelemesi (vendored AI Infra Guard dahil) | Hukuk + Mühendislik | 2–6 hf |
| COM-003 | DPA/TOM/alt işleyen listesi, saklama ve veri akışı onayı | Gizlilik/DPO + Hukuk + Güvenlik | 3–8 hf |
| COM-004 | Gerçek fatura sağlayıcısı hesabı, sipariş→ödeme→entitlement uçtan uca | Finans + Ürün | 2–4 hf |
| COM-005 | Destek kanalı, durum sayfası, güvenlik iletişimi, gizlilik/şartlar yayını, on-call | Destek + Operasyon | 1–3 hf |
| COM-010 | Her satılan connector için gerçek host kabulü (Win/Linux/macOS) | Ürün + QA + Mühendislik | 2–4 hf |
| COM-011 | EU/US/APAC yerleşim, rota, yedek, silme kanıtı — **kapsam daraltma kararı önerilir** | Operasyon + Gizlilik + Hukuk | 4–12 hf |
| COM-012 | Kimlik doğrulamalı özel registry, imzalı kurulum, iptal, air-gap prosedürü | Finans + Release + Destek | 2–4 hf |
| COM-013 | SLI/SLA/kredi sözleşmesi + tam aylık gerçek izleme penceresi | Operasyon + Hukuk + Destek + Finans | **≥ 5–6 hf** (tam ay ölçüm) |
| SEC-EXT-001 | Bağımsız sızma testi + düzeltme + yeniden test | Güvenlik + bağımsız değerlendirici | 4–8 hf (planlama dahil) |
| POV-001 | İsimli müşteri/değerlendirici, imzalı charter, bağımsız koşu | Müşteri Başarısı + Ürün | 4–8 hf |
| CLM-001 | Tüm satış iddialarının kanıtla onayı | Pazarlama + Ticari + Hukuk | 1–2 hf (Faz 2 sonrası) |
| Altyapı | Kod imzalama (Windows Authenticode, Apple notarization), mağaza hesapları (Chrome, Edge, AMO, VS Code Marketplace/Open VSX, npm), yayıncı anahtarı | Release + Yönetim | 1–4 hf (sertifika/doğrulama süreleri) |

### Faz 4 — Gerçek ortam kabulleri (insanlar + ajan, 3–6 hafta)

Aynı **değişmez aday** üzerinde, AIDR'ın kendi hesapları ve cihazlarıyla:

1. **FCR-03:** hem self-hosted hem managed-cloud topolojisini gerçek DNS/TLS ile kur; tenant → giriş → taze cihaz kaydı → politika → olay → dışa aktarma → yükseltme → kaldırma → başarısız yükseltme.
2. **FCR-04 / COM-010:** satılan her host/OS/mimari için gerçek ikili ile benign-twin, deny-canary, yan etki gözlemi, devre dışı/çökme/zaman aşımı/çevrimdışı/yeniden başlatma/güncelleme/geri dönüş. **Eksik host kapsam dışıdır, geçmiş sayılmaz.**
3. **FCR-06:** iki yol için off-host yedek + bağımsız kurtarma anahtarı erişimi; ayrı arıza alanına geri yükleme; ölçülmüş RPO/RTO; başarısız yedek alarmı.
4. **FCR-07:** kimlikli temsilî yük, ≥ 8 saat soak, iki tenant gürültülü komşu, node/DB/ağ arızası. (Bu SLA onayı değildir.)
5. **FCR-05:** tam geçmiş sır taraması triyajı (AIDR-070), canlı sırların döndürülmesi, iki tenant negatifleri, günlük/destek paketi redaksiyonu.

### Faz 5 — Bağımsız doğrulama (3. taraf, 4–8 hafta, Faz 4 ile örtüşebilir)

Sızma testi ve yeniden test; bağımsız etkinlik/rakip kıyaslaması (T39 harness'i hazır); NER doğruluk kabulü (600 örnekli PERSON/ADDRESS testi **hâlâ başarısız** — model onaysız, satış vaadine eklenmez).

### Faz 6 — GO kararı ve çıkış (insanlar, 1–2 hafta)

`first-customer-ready.md` imza kayıtları; `commercial-gate-receipts.json` receipt'leri (isim, aday, immutable kanıt yolu + SHA-256, bağımsız gözden geçiren, tarih); `pnpm evidence:index:verify`; kontrollü değerlendirme teklifi → destekli satış → GA geçişi.

## 5. Kritik yol ve takvim (tahmini)

```
Hf 0      Faz 0  ──┐
Hf 0-2    Dış kapıları BAŞLAT (hukuk, fiyat, sertifika, pentest sözleşmesi, mağaza hesapları)
Hf 1-4    Faz 1 (kod) ─ Faz 2 (aday, paketler)
Hf 4-10   Faz 4 (gerçek ortam kabulü)  ‖  Faz 5 (pentest, benchmark)
Hf 5-6+   COM-013 tam aylık SLI penceresi (ancak gerçek izleme açıldıktan sonra)
Hf 8-12   Faz 6: FCR GO → kontrollü değerlendirme
Hf 12-20  Destekli satış (12 kapı) → GA
```

Kritik yol **dış kapılar**dır: hukuk onayları, sertifika/mağaza süreleri, pentest penceresi,
tam aylık SLA ölçümü ve isimli müşteri. Kod tarafı bunları geciktirmemeli; tersine, ajan işi
sahiplere mümkün olan en erken günde "hazır paket" olarak teslim etmelidir.

## 6. Risk kaydı

| Risk | Etki | Önlem |
|---|---|---|
| Toplu bağımlılık birleştirmesiyle `master` kırılması (bugün yaşandı) | Tüm hazırlık kanıtı geçersizleşir | Faz 0; major bump'larda ayrı PR + `check/build/test` zorunlu |
| CI devre dışı, `ci:local` kaymış | Gerilemeler fark edilmez | `ci-local` kayma testi; ön-merge zorunlu |
| Yayındaki landing/pilot ile depo kaynağı uyuşmuyor | Onaysız iddia, güven kaybı | Landing kaynağını depoya al; claim-check; yayını imzalı adaya bağla |
| Kapsam şişmesi (EU/US/APAC + 5-6 connector + air-gap + SLA aynı anda) | Takvim uzar | Kademeli satış; kapsam daraltma kararları (bölüm 7) |
| Cursor/VS Code hiç gerçek host'ta çalışmadı | COM-010 kapanmaz | Gerçek host edinimi; sağlanamazsa kapsamdan çıkar |
| Learned-behavior (T05) ve NER modeli onaysız | Yanlış vaat | Satış katalogundan hariç; doğruluk kabulü olmadan iddia yok |
| Aynı kullanıcı OS yetkisiyle çalışan kod yerel kontrolleri aşabilir (belgelenmiş artık risk) | Güvenlik algısı | `docs/configuration.md` artık riskini satış dilinde dürüstçe belirt |
| Gizli bilgi / geçmiş sır bulguları | Hukuki ve itibar | AIDR-070 triyajı + döndürme, Faz 4 |

## 7. Sahibinden gelmesi gereken kararlar

Ajan bu kararları **vermez**; her biri için seçenekler ve öneri hazırlar:

1. **Satış kademesi:** önce kontrollü değerlendirme (8 kapı), sonra destekli satış (12 kapı), sonra GA. *Öneri: kademeli.*
2. **Connector kapsamı:** registry "beş direct-GA connector" (Claude Code, Cursor, VS Code, OpenClaw, OpenCode) diyor; native matrix ve depo altı satıyor (Codex dahil). Birini seç ve tüm yüzeyleri (README, matrix, registry) hizala.
3. **Bölge vaadi:** EU/US/APAC ilk günden mi, yoksa tek bölge + yol haritası mı? *Öneri: tek bölgeyle başla; COM-011'i daralt.*
4. **SLA:** %99,9 sözleşmesi GA'ya mı bağlanır, ilk satışlarda "hedef" olarak mı sunulur?
5. **T18 SAML zorlama semantiği** (onaylayan, geri dönüş hedefi, oturum iptali, süre/tekrar).
6. **Faturalama sağlayıcısı** ve fiyat/SKU yapısı; iç dokümanlardaki fiyatların akıbeti.
7. **Mağaza ve imza hesapları:** hangi yayıncı kimliği (tüzel kişi) adına?
8. **Zod 4 / koffi 3 göçü:** şimdi mi, satıştan sonra mı?

## 8. "Satışa hazır" kontrol listesi (bu planın bitiş tanımı)

- [ ] `master`: `check`, `build`, `test`, `ci:local --keep-going` yeşil; kanıt aday digest'ine bağlı.
- [ ] Envanterde yerel olarak giderilebilir "partial" kalmadı; T19/T37/T38 kapalı veya gerekçeli olarak kapsam dışı.
- [ ] İmzalı release adayı (onaylı yayıncı anahtarı), ikinci makinede bağımsız doğrulama ve tamper/expiry/yanlış imzacı/rollback reddi.
- [ ] Satılan her connector × host × OS × mimari için gerçek host kabulü; eksikler açıkça kapsam dışı.
- [ ] İki dağıtım yolu (self-hosted, managed-cloud) gerçek DNS/TLS ile uçtan uca, geri yükleme ve ≥ 8 saat soak kanıtlı.
- [ ] Bağımsız sızma testi: kritik/yüksek bulgu yok veya kayıt izin veriyorsa isimli/süreli istisna; yeniden test mektubu.
- [ ] Hukuk/gizlilik/lisans onayları, DPA, alt işleyen listesi; canlı destek, durum, güvenlik iletişimi, gizlilik ve şartlar sayfaları.
- [ ] Fatura sağlayıcısı: sipariş → ödeme → entitlement → iptal/iade/mutabakat kanıtı.
- [ ] Tüm satış iddiaları claim registry'de onaylı; yayındaki landing = depo kaynağı = taranmış build.
- [ ] 12 receipt (`commercial-gate-receipts.json`) gerçek, immutable kanıt ve bağımsız gözden geçirenle kapalı; isimli müşteri PoV kabulü.
- [ ] Yetkili sahiplerin aday-özgü GO kararı kayıtlı.

Bunlardan biri eksikse karar **NO-GO** kalır; ara ifadeler ("neredeyse hazır", "%90") kullanılmaz.

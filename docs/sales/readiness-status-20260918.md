# Satışa hazırlık durumu — 18 Eylül 2026

**Karar: `RELEASE_CANDIDATE_READY`, `PRODUCTION_SALES_GO` değil.**

Bu belge, "satışa hazır mı?" sorusunun kanıta dayalı cevabıdır. Her satır ya
çalıştırılmış bir komuta ya da açıkça "yapılmadı" beyanına dayanır.

---

## 1. Bu oturumda kapatılan gerçek hatalar

Bunların hepsi, ürünü satmadan önce mutlaka düzeltilmesi gereken ve **daha önce
hiç çalışmamış** şeylerdi.

### 1.1 Control plane hiç ayağa kalkamıyordu

`20260913000005_tenant_storage_queue_quotas.sql` migration'ı
`alter table storage.objects enable row level security` çalıştırıyordu. Bu tablo
`supabase_storage_admin`'e ait, migration'ı çalıştıran role değil. Sonuç:
`SQLSTATE 42501 (must be owner of table objects)` ve **tüm migration zincirinin
iptali**. Yani `supabase start` veya `db reset` hiçbir zaman tamamlanamıyordu.

Düzeltildi (`d489d561`). Doğrulama: 47 migration uygulanıyor, 11 servis ayağa
kalkıyor.

### 1.2 Deployment kendi API portuyla çelişiyordu

`deployment-prepare.mjs` gateway'i `127.0.0.1:8000`'de yayınlıyor ama
`deployment.json` ve `.env` içine `--supabase-url` ile verilen URL'i yazıyor.
Standalone Supabase CLI'ın portuyla (`54321`) hazırlandığında, hiçbir şeyin
dinlemediği bir porta işaret eden bir kurulum oluşuyordu.

Rehearsal artık `--supabase-url http://127.0.0.1:8000` ile hazırlanıyor.

### 1.3 Release candidate üretimi tekrarlanabilir değildi

r5 ve r8 aday paketleri **elle** üretilmişti; nasıl yeniden üretileceğinin tek
kaydı onları üreten oturumdu. Tek kişilik bir şirkette bu, her sürümde insan
hatası demek.

`scripts/build-release-candidate.mjs` eklendi (`226348af`): on paketi artı Claude
plugin arşivini ve dashboard dist'ini paketler, `release-inventory.json`'ı
`release-signing-lib`'in doğruladığı şekilde yazar, sonucu kaydettiği commit'e
bağlar. Kirli worktree'yi `--allow-dirty` olmadan reddeder. 7 regresyon testi.

### 1.4 Customer kit'in bağımlı olduğu dizin repoda yoktu

`customer-kit.mjs`, `deploy/upstream`'i sabitlenmiş bir checkout olarak okuyor ve
`8c7a4d9d` commit'inde olmadıkça kit üretmeyi reddediyor — ama bu yol
`.gitmodules`'da hiç tanımlanmamıştı. r8 kit'i o commit'ten 63 dosya gömüyor,
yani **kit bir makinada üretilmiş ve kimse yeniden üretemiyordu**.

`deploy/upstream` Supabase submodule'ü olarak tanımlandı ve incelenen commit'e
sabitlendi (`f80134a9`). Doğrulama: gate 20 ilk kez geçti, 394 dosyalık kit
üretildi.

### 1.5 Release build geçerli durumdan başarısız oluyordu

Source-map koruması core build'inden **hemen sonra** tüm paketleri kontrol
ediyordu — diğerleri henüz derlenmemişken. Her test koşusundan sonra (globalSetup
normal build yapar) bu, hiç ulaşılmamış 7 paket için "contaminated" hatası
veriyordu.

Düzeltildi (`295f87c1`). İki eksik regresyon eklendi: önceden var olan connector
map'leri build'i durdurmamalı, ama connector kendi rebuild'inden sonra map
bırakırsa durdurmalı.

### 1.6 Diğer düzeltmeler

| Hata | Etki | Commit |
|---|---|---|
| OpenClaw gate 120s sabit timeout | Bu makinede ~200s süren CLI'ı ETIMEDOUT yapıyordu; gate kullanılamazdı | `b69c1255` |
| Knip Supabase monorepo'sunu tarıyordu | `quality:static` yüzlerce çözülemeyen path alias'ında düşüyordu | `78a74083` |
| Gate 20/25 argümansız çalışıyordu | Gate'ler depo durumundan bağımsız olarak asla geçemezdi | `86e47249`, `9d502ebe` |
| Claim kayıtları her commit'te eskiyordu | `quality:static` gerçek ihlal yerine bayatlıkta düşüyordu | `refresh-claim-evidence` |
| Candidate assurance alanı bundle şemasını bozuyordu | Her aday kit tarafından yüklenemez hale geliyordu | `1e5300a2` |

---

## 2. Kanıtlanan yetenekler

### 2.1 Gerçek IDE host'ları

| Host | Sürüm | Sonuç |
|---|---|---|
| Cursor | 3.19.7 | **8/8 geçti**, exit 0 |
| VS Code | 1.137.0 | **8/8 geçti**, exit 0 |

Sekiz vaka: workspace scope ayarı, aktivasyon, komut kaydı, hook yazımı, hook
health, **tehlikeli write bloğu**, hook yanıt şekli, hook kaldırma.

### 2.2 Diğer host'lar

| Host | Sonuç |
|---|---|
| OpenClaw 2026.9.4 | Packed contract, offline install, runtime inspect, gateway startup + health — **shim olmadan** |
| OpenCode 1.18.30 | Plugin gerçek host'ta yüklendi ve çalıştı (host logları) |
| Claude Code 2.1.273 | Plugin keşfedildi (`aidr@inline`), 3 hook, MCP bağlı, strict validation 0 hata |
| Codex 0.141.0 | `rm -rf /` → deny (critical), `ls -la` → allow |

### 2.3 Müşteri onboarding — canlı control plane

Gate 25 **ilk kez geçti**. 9 kontrol, 11 container üzerinde:

1. İlk owner ayrı bir enterprise tenant ile provision edildi
2. Resume idempotent; mükerrer ve değişik konfigürasyon reddedildi
3. Owner SMTP/OAuth olmadan giriş yaptı
4. Browser onboarding enterprise enrollment onayını gördü
5. Normal oturum provision veya seat artıramadı
6. Onay ve seat tahsisi enterprise tenant'a bağlı
7. Device flow agent'ı müşterinin tenant'ına kaydetti
8. Yeni müşteri ilk tool call'dan **önce** merkezi policy aldı
9. Kayıtlı API key enterprise takımının policy'sini aldı

Artı: 289 test dosyası / 4249 test geçti, dashboard route smoke PASS.

**Sınıflandırma: izole yerel rehearsal, müşteri saha kabulü değil.**

---

## 3. Satışa engel olan açık işler

### 3.1 Senin kararın gereken (teknik değil)

Bunlar `docs/sales/commercial-decision-packet.md` içinde seçenekleriyle listeli:

| Gate | Ne gerekiyor |
|---|---|
| COM-001 | SKU, fiyat, metraj, lisans hakları, yenileme, iptal |
| COM-002 | Lisans/atıf dosyaları, hukuk onayı |
| COM-003 | Gizlilik bildirimi, DPA, alt-işleyici listesi |
| COM-004 | Fiyat ve yetkilerin tek bir provider-of-record ile uygulanması |
| COM-005 | Destek, durum sayfası, güvenlik iletişimi, eskalasyon |
| COM-011 | Bölge/data residency modeli (şu an tek bölge önerilir) |
| COM-013 | SLA hedefi (99.9% önerilmez — on-call rotasyonu yok) |

### 3.2 Dış kanıt gereken

| Gate | Neden kapanamaz |
|---|---|
| 18-native-host | Yedi senaryonun gerçek host'ta koşması + **isimli** QA/Endpoint/Support kabulü. Gate'in gözlem değişkenlerini (`AIDR_NATIVE_TEST_*`) hiçbir connector okumuyor — mekanizma fixture host'lar için bağlı, gerçek host'lar için değil. Bu bir mühendislik işi, digest doldurma değil. |
| 19-release-e2e | Provider auth ve canlı servis makbuzları |
| SEC-EXT-001 | Bağımsız sızma testi |
| POV-001 | İsimli müşteri değerlendirmesi |
| INV-001 | Yatırımcı metrikleri (formül, kaynak, sahip) |
| CLM-001 | 42 onaysız iddia, claim registry'ye eşlenmeli |

### 3.3 Kod imzalama

`docs/sales/code-signing-guide.md`. Özet:

- **Azure Artifact Signing Türkiye'ye kapalı** (coğrafi kısıt) — ucuz bulut seçeneği yok
- **Türkiye engel değil**: SSL.com kabul listesinde, MERSIS/Ticaret Sicil Gazetesi geçerli doğrulama kaynağı
- **Asıl ayrım şirket tipi**: DigiCert/Sectigo sadece organizasyonlara, GlobalSign bireysel ürünü kaldırdı, SSL.com IV (~$129/yıl) şirketsiz geliştirici için
- **EV almayın**: Microsoft'un kendi beyanına göre EV'nin SmartScreen avantajı kalmadı
- **İmzalama SmartScreen uyarısını kaldırmaz** — "Unknown Publisher"ı kaldırır ve publisher itibarını sürümler arası taşır; asıl ROI bu

---

## 4. Dürüst sınırlar

- **Hiç müşteri yok.** Hiçbir vaka çalışması, referans veya logo yok.
- **Hiç sertifika yok.** SOC 2, ISO 27001, sızma testi yapılmadı.
- **Etkinlik ölçümü yok.** "Saldırıların %99'unu engeller" gibi bir iddia ölçülmedi; satış belgelerinde sadece "351 kural" deniyor, o sayılabilir.
- **Model-driven interception kanıtlanmadı.** Tüm host sonuçları hook seviyesinde. Gerçek ajan turunun yan etkisini engellediği gösterilmedi — provider auth gerekiyor.
- **İmzasız yayın.** Kurumsal alıcı SmartScreen uyarısı görür.

Bu maddelerin hiçbiri satış belgelerinde iddia olarak geçmiyor; hepsi açık
beyan olarak yer alıyor.

---

## 5. Sıradaki en değerli üç iş

1. **Provider auth ver** → model-driven interception'ı gerçek turla kanıtlarım. Ürünün en önemli iddiası şu an kanıtsız.
2. **Karar paketini doldur** (`docs/sales/commercial-decision-packet.md`) → 7 ticari gate senin kararına bağlı.
3. **Native host gözlem mekanizmasını bağla** → altı connector'ın `AIDR_NATIVE_TEST_*` değişkenlerini yazması, yedi senaryonun gerçek host'ta koşabilmesi için ön koşul.

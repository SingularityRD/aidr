# AIDR satış hazırlığı: uygulama ve doğrulama

> Tarihsel ara kayıt. Güncel çalışma ve doğrulama için [12 Eylül müşteri adayı raporuna](2026-09-12-customer-candidate.md) bakın.

11 Eylül 2026. Değişiklikler mevcut çalışma ağacına uygulanmıştır; ticari üretim
adayı imzalanmış veya müşteri tarafından kabul edilmiş değildir. **Karar: NO-GO.**

## Envanter ve açık işler

[Alt özellik envanteri](../../FEATURE_INVENTORY.md) 69 özellik/teslimat gereksinimini
kapsar: 38 çalışan kod akışına bağlı, 20 kısmi, 9 eksik, 2 dış kabul gerektiren
kategori. Her satırın kaynağı, tüketen bileşeni ve kalan sınırı
[JSON kaydında](../../FEATURE_INVENTORY.json) bulunur. Bunlar etkinlik veya üretim
kabul oranları değildir.

[Bulgu kaydı](../../READINESS_BACKLOG.json) 52 bulgu içerir: 38 yerel doğrulamayla
kapatıldı; 11 doğrulanmış açık, 2 dış bağımlılıkla bloklu, 1 devam ediyor.
Önceden kapatılan bulgular korunmuştur. Buna ek olarak mevcut ticari kanıt
sicilindeki 13 dış kabul kapısı açıktır. Alt özellik, hata bulgusu ve ticari
kabul kapısı farklı ölçümlerdir; sayıları birleştirilmemelidir.

## Bu çalışmada tamamlanan akışlar

- Her iki dağıtım modeli için hazırlama komutu; kendine ait rastgele sırlar ve
  Ed25519 anahtarları, doğru DER kodlaması, ayrı Compose ad alanları, runtime
  dashboard ayarları ve kaynak/paket özetleri.
- Gerçek self-hosted Docker kurulumu ve 13 migration'ın atomik, checksum
  kontrollü uygulanması; tekrar çalıştırıldığında aynı migration'lar atlanır.
- Tenant ve rol denetimli runtime politika yayınlama, değişiklik geçmişi,
  sürüm çatışmasında 409, yerel ajan anahtarıyla çekme ve gerçek derlenmiş
  Claude hook'unda yayınlanan MCP politikasının uygulanması.
- MCP envanteri, kaynak okuma hataları ve redakte edilmiş konfigürasyon
  parmak izleri; boş parametreli MCP çağrılarının denetimi atlamasının giderilmesi.
- AI altyapı tarama raporunun isteğe bağlı, hedef kapsamlı runtime politikaya
  bağlanması; eksik/eski/yarım taramanın temiz sonuç gibi sunulmaması.
- Claude araç çıktılarında sınırlı injection/secret incelemesi. Bu kontrol
  işlemden sonra çalışır; yapılmış işlemi geri aldığı veya model tüketimini
  kesin olarak engellediği iddia edilmez.
- Ekip daveti oluşturma ve tek kullanımlık kabul, e-posta sahipliği ve rol
  sınırları; yetkili özel audit indirme ve CSV formül kaçışı.
- Cihaz kodunun tarayıcı JWT'siyle karıştırılmasının giderilmesi; tam eşleştirme,
  kayıt, dağıtılan public key ile imza doğrulama ve kayıt token'ı replay reddi.
- Yetkili sunucu tarafı Stripe checkout; invoice varsayılanı korunur. Canlı
  ödeme kabulü tamamlanmış değildir.
- Tipli/redakte CLI config, gerçeği ölçen JSON status, müşteri hook'larını
  koruyan ve yerel deny canary çalıştıran Claude kurulum komutu.
- Codex'in release girişleri, ESM kaynak çözümü, runtime bağımlılığı ve SBOM/
  manifest kapsamı; Claude arşivine hook ve kaynak dosyalarının dahil edilmesi.
- Windows üzerinde 9 paket ve 13 teslimat dosyasının arşivlenmesi. Bu çıktı
  geliştirme doğrulama paketidir; imzalı ticari aday olarak sunulmaz.

## Son doğrulama sonuçları

| Kontrol | Sonuç | Kanıt / kapsam |
|---|---|---|
| `pnpm build:release` | PASS | 9 paket; geliştirme release modu, ticari imza gereksinimleri kaldırılmadı |
| Paket sözleşmesi ve tüketici testleri | 9/9 PASS | Core, Claude, editor, OpenClaw, OpenCode, CLI, SDK, dashboard, Codex |
| `pnpm -r exec tsc --noEmit` | PASS | Çalışma alanı TypeScript denetimi |
| Son release çıktıları üzerinde Vitest | 169 dosya, 2721 PASS, 1 SKIP | Gerçek reputation endpoint'i isteyen mevcut test atlandı |
| `verify-enforcement.mjs` | 72/72 PASS | Zararlı/iyi huylu komutlar ve yerel/managed yapılandırma matrisi |
| `verify-codex-hook.mjs` | 11/11 PASS | Derlenmiş hook davranışı; yerel hostun çağırdığının kanıtı değildir |
| `verify-installation-tools.mjs` | 8/8 PASS | Cloud hazırlama, sırları koruma, DER anahtar, HTTPS, ayrı ad alanı, idempotent endpoint kurulumu |
| Self-hosted gerçek HTTP/SQL smoke | 29/29 PASS | [Sanitize edilmiş kanıt](evidence/2026-09-11-self-hosted-smoke.json) |
| Migration statik sözleşmesi ve tekrar uygulama | PASS | 13 sıralı migration ve checksum defteri |
| `pnpm quality:static` | PASS, uyarılar var | Lint, kullanılmayan kod, tekrar oranı, ticari yüzey, 25 Edge config ve 12 browser CORS sözleşmesi |
| `pnpm audit:prod` | 0 advisory | Güncel bağımlılık taraması; yeni istisna eklenmedi |
| Geliştirme teslimat arşivi | PASS | 9 npm paketi, 2 ürün arşivi ve SBOM/checksum; toplam 13 dosya |
| `git diff --check` | PASS | Mevcut çalışma ağacı korunarak |

Bağımlılık düzeltmeleri `qs 6.16.0`, `fast-uri 3.1.7`, `hono 4.13.5` sürümlerine
uygulandı. Paket sahiplerinin
[qs bildirimi](https://github.com/ljharb/qs/security/advisories/GHSA-4mjr-xmp4-gh2g),
[fast-uri bildirimi](https://github.com/fastify/fast-uri/security/advisories/GHSA-qw65-cvwx-89v3)
ve [Hono release kaydı](https://github.com/honojs/hono/releases/tag/v4.13.5)
incelendi. Başlangıçtaki üretim taraması dört yüksek ve beş orta advisory
bildiriyordu; güncelleme sonrası aynı kapı sıfır bildirdi.

Tam loglar çalışma alanındaki `.aidr-*.log` dosyalarında, geliştirme teslimat
dosyaları `.release-evidence/customer-bundle-development-v3/` altında bulunur.
Çalışan yerel Docker projesinin hazırlama dizini
`.release-evidence/aidr-install-v3/` ve dashboard adresi `http://localhost:8080`.
Bu özel dizin sırlar içerir; kaynak depoya veya müşteriye aynen kopyalanmaz.
JSON smoke kanıtı hassas değer içermez ve test edilen hook/fonksiyon özetlerini
kaydeder.

## Satış için kalan somut engeller

Öncelikli ürün işleri: yedekleme/geri yükleme otomasyonu ve tatbikatı, HA/yük
ölçümü, ajanların politika sürümünü uyguladığına dair kayıt, büyük audit
çıktılarının sayfalanması ve saklama süresi, merkezi ajan/MCP keşfi, tool
description/schema güveni, directory/SCIM yaşam döngüsü ve filo kurulum/güncelleme
paketleri. Claude çıktı kontrolünün diğer bağlayıcılar ve uygun inline sınırlar
için genişletilmesi de açık kalır.

Dış ortam işleri: seçilmiş cloud projesi/bölge, müşteri HTTPS alanları, SMTP/SSO,
satış iletişim hedefi, özel registry ve ticari imza anahtarı yönetimi, canlı
ödeme/entitlement kabulü, bağımsız güvenlik testi, müşteri native host/OS
senaryoları ve sözleşme/veri yerleşimi/SLA onayları. Statik demo kapısı satış
URL/e-postası ve kimlik doğrulamalı demo bilgilerinin eksik olduğunu hâlâ
bildirir. Cloud hazırlığı gerçek cloud dağıtımı anlamına gelmez.

Her kalan işin kabul ölçütü ve rakip kaynakları
[teslimat planında](agent-security-market-and-release-plan.md), çalıştırılabilir
kurulum adımları [kurulum belgesinde](../../deploy/README.md) bulunur.

# İlk müşteri v4 mühendislik adayı — 12 Eylül 2026

**Karar: NO-GO (genel production/satış).** Her iki kurulum modelini hazırlayan taşınabilir bir paket ve taze self-hosted yerel prova var. Müşteri ortamı, resmi yayıncı imzası, bağımsız güvenlik, SLA ve ticari kabul henüz yoktur. Bu kayıt [v3 tarihçesini](2026-09-12-customer-candidate.md) güncel kodla karıştırmadan v4 sonucunu bildirir. Makine kanıtı [candidate-v4-verification.json](evidence/2026-09-12-candidate-v4-verification.json) içindedir.

## Bu turda kapanan kod boşlukları

- OpenCode `bash/write/edit` ve alan adları evaluator öncesinde normalize edildi. Paket denetimi exception/eksik sonuçta false-clean yerine `ask/unavailable` üretiyor. `AIDR-060/061` yerel regresyonla kapandı.
- Reputation URL/file API'si aktif tenant ve aktif/süresi dolmamış üyeliği ortak hash-only anahtar sınırında doğruluyor. Önceki dört 200 yanıtı [tarihsel bulgu](evidence/2026-09-12-reputation-lifecycle-audit.json) olarak korunur; taze v4 [HTTP tekrarında](evidence/2026-09-12-reputation-lifecycle-fix.json) dört yanıtın tamamı 403 oldu. `AIDR-063` yerel olarak kapandı.
- MCP taşıma DNS pinning, IP yeniden doğrulama ve akış/decode bayt limitleriyle sertleşti. İmzalı tool manifest, replay önleme, drift karantinası ve insan onayı API'si eklendi. Inline gateway ve host consumer henüz yok.
- Ed25519 delegated credential broker, SCIM v2 Users/Groups, strict YAML policy compiler, hesap kurtarma ve tenant/user kaynak kotası kanonik Edge/migration akışlarına eklendi. MFA/session barrier bütün eski service-role Edge uçlarına bağlanmadığı için tenant çapında tam MFA iddia edilmez.
- WAL telemetri/idempotent ingest, dayanıklı SIEM teslim API'si, tenant bazlı DLP, davranış/novelty/model orkestrasyonu, imzalı offline reputation feed ve scheduler dostu yerel keşif API'si eklendi. Bunların gerçek provider, connector veya merkezi yönetim tüketimi satılan kapsamda ayrıca tamamlanmalıdır.
- Windows Intune/SCCM ve Unix/Jamf filo betikleri; offsite yedek, legal hold/offboarding, sürüm yükseltme/geri alma, imza doğrulayıcı, yedi kontrollü readiness, alert/on-call ve izin bağlı destek paketi teslimata eklendi. Gerçek MDM, sağlayıcı, signer ve nöbet kabulü dış kanıttır.

## Birleşik doğrulama

Temiz birleşik build, release build, TypeScript, statik kapı, üretim bağımlılığı denetimi ve `git diff --check` geçti. Dokuz paket tüketici sözleşmesi ve 13 release artefaktı doğrulandı. Tam seri Vitest: **202 dosya, 3.010 başarılı, 0 hata, 1 atlanan canlı reputation testi**. İlk geniş koşu evaluator testinde zaman aşımı ve bir worker başlatma hatası verdi; başarısız kayıt `.aidr-v4-tests.log` içinde saklandı. İlgili iki dosya 33/33 ve aynı zaman sınırlarıyla ikinci tam koşu geçti.

Bağımsız kapılar: 24 migration sırası, 29 Edge config, 72 enforcement, 11 Codex hook, 9 kurulum, Windows filo 17, Unix filo 25, izleme 9, upgrade 21, destek paketi 13, yük harness 6, release signing 9, offsite yedek 5 ve offboarding 9. Statik kapı geçse de **133 lint uyarısı ve knip 207 dosya/120 export/1 duplicate** inceleme borcu vardır. Üretim bağımlılığı taraması 0 advisory verdi.

Yeni `.release-evidence/aidr-install-v4` loopback self-hosted provasında **11 servis sağlıklı, 24 migration atomik uygulandı, doctor 40 kontrol geçti**. Gerçek yerel HTTP/veritabanı akışlarında smoke 29, onboarding 9, politika 11, enterprise 8 ve pagination 4 kontrol geçti. Bu, müşteri TLS/cloud/host kabulü değildir. Cloud modu Git/pnpm olmadan hazırlama ve 24 migration manifestiyle sınandı; gerçek cloud projesi açılmadı.

## Taşınabilir teslim

`aidr-customer-kit-20260912-v4` **278 dosya** içerir: kanonik fonksiyon/migration, dashboard, dokuz paketlik release, Claude uç kurucusu, Windows/Unix filo şablonları, izleme/HA, offsite yedek, yükseltme, offboarding, destek ve imza doğrulama araçları. Kit doğrulayıcısı yedi kontrolle dosya özetlerini, ek dosya/symlink yokluğunu, özel prova sırlarının düz ve açılmış release arşivlerinde bulunmadığını ve her iki modun boş PATH ile hazırlanmasını sınadı.

Arşiv: [aidr-customer-kit-20260912-v4.tar.gz](../../.release-evidence/aidr-customer-kit-20260912-v4.tar.gz). SHA-256: `f416da495d2c771d7ceb1102973ce9cac75f4d23b054897e06828b724b57fa0a`. [SHA dosyası](../../.release-evidence/aidr-customer-kit-20260912-v4.tar.gz.sha256). Paket **resmi yayıncı imzası taşımıyor**; SHA özetleri kimlik doğrulamaz. `release-verify` yalnız bağımsız signer policy ve kalıcı anti-rollback state verildiğinde üretim kabul zincirinde kullanılabilir. Özel `.release-evidence/aidr-install-v4` sırları müşteri paketinde bulunmaz.

## Kalan karar kapıları

[71 alt özellik envanteri](../../FEATURE_INVENTORY.md): **42 bağlı, 25 kısmi, 2 eksik, 2 dış kabul**. Eksikler inline MCP gateway ve teklif edilen self-service abonelik portalıdır; sonuncusu faturalı SKU için şu anda sunulmuyor. [63 bulguluk defterde](../../READINESS_BACKLOG.json) **50 yerel doğrulanmış kapanış, 13 açık/kısmi/dış bağımlı** bulunur. [54 iş paketlik ayrıntılı kayıtta](../../PRODUCTION_SALES_GAPS.md) 41 teknik/operasyon ve 13 ticari/dış kanıt kapısı, her biri sorumlu ve kabul ölçütüyle açıklanır. 12 zorunlu dış kapı hem assisted-sale hem GA için açıktır.

Öncelikli gerçek iş: native host ve MDM matrisi, cloud/HTTPS/IdP/SMTP konfigürasyonu, bütün service-role Edge uçlarında MFA/session barrier, MCP gateway ve core DLP/behavior/feed/SIEM tüketicileri, onaylı publisher key/özel registry, müşteri offsite RPO/RTO ve failover, çalışan alarm/destek kanalı, bağımsız pentest, sözleşme/veri işleme ve isimli müşteri PoV. Yük aracı altı testle geçse de tek-host **10 RPS/30 saniye** denemesi eşzamanlı ajan yükünde 144 düşen istek ve 47 taşıma hatasıyla **başarısız**; bu sonuç `.release-evidence/load-dashboard-local-20260912.json` içinde korunur ve kapasite/SLA vaadi değildir.

Kurulum adımları [ilk müşteri kılavuzunda](../../deploy/FIRST_CUSTOMER.md). Aynı candidate için müşteri kabulü ve resmi dağıtım kanıtı alınana dek “production ready” veya “sales approved” işareti verilmez.

# AIDR ilk müşteri aday v5 — doğrulama ve kalan işler

**Karar: NO-GO (production ve assisted sale).** Bu kayıt, 12 Eylül 2026 tarihli kirli çalışma ağacı üzerindeki yerel adayı anlatır. Resmi yayımlanmış, müşteri ortamında kabul edilmiş veya imzalı sürüm değildir. Müşteri altyapısı, bölge, AI host/OS matrisi ve ticari SKU henüz belirtilmedi; hem cloud hem self-hosted teslim hedefleniyor.

## Güncel kapsam

71 alt özellikten 41'i çağrılabilir kod akışına bağlı, 27'si kısmi, 1'i eksik ve 2'si dış kanıta bağlıdır. Tek eksik özellik, yalnız satılırsa zorunlu olacak self-service abonelik portalıdır (BIL-03); mevcut varsayılan model kurumsal faturadır. Kısmi özellikler arasında MCP gateway, cihaz eşleme, filo izolasyonu/credential iptali, merkezi keşif, SIEM, DLP/behavior/reputation etkinleştirmesi ve yönetilen cloud kurulumu bulunur. `wired` üretim kabulü anlamına gelmez. Tam envanter kökteki `FEATURE_INVENTORY.json` ve `FEATURE_INVENTORY.md` içindedir.

**46 teknik/operasyon iş paketinin 39'unda yerel kod ilerlemesi var ve saha kabulü açık; 7'si uygulama/entegrasyon olarak açık.** Ayrıca 13 ticari/dış kanıt kapısı açık; destekli satış ve production-GA profillerinin her birinde 12 zorunlu dış kapı kapanmadı. Her işin başlangıç boşluğu, güncel uygulaması, kabul testi, sorumlusu ve bağımlılığı `PRODUCTION_SALES_GAPS.json/.md` içinde ayrıntılıdır. Bu sayılar benzersiz bug veya tamamlanma yüzdesi değildir.

## Bu adayda yapılan önemli düzeltmeler

- Legacy RLS izin verici yolları kapatıldı. Gerçek PostgreSQL `authenticated` rolüyle migration öncesi yabancı tenant reputation yazımı yeniden üretildi; migration sonrası 11 tablo için eski/sona ermiş üyelik, askıya alınmış tenant, yabancı yazım ve meşru erişim matrisi geçti. Test transaction'ı geri alındı. Daha önce kurulu veride sahte satır denetimi ve gerçek migration uygulanması açık.
- Enrollment token, seat, API key ve device-poll exchange işlemleri atomik RPC'ye alındı; entitlement süresi 168 saat ve ardından 72 saat grace olarak düzeltildi. Eski imzalı snapshotların yenilenmesi ve canlı HTTP yarış/hata provası açık.
- Anonymous `device-start` yalnız HMAC imzalı ingress IP'sini kabul ediyor; istemci başına ve toplam oran sınırlı. Self-hosted ve cloud kurulumunda gerçek TLS proxy/sidecar route, anahtar yerleşimi ve uçtan uca cihaz eşleme kabulü açık. Doğrudan imzasız Edge çağrısı reddedilir.
- MCP için tenant kimlikli, imzalı manifest onaylı, sınırlı JSON-RPC inline gateway paketlendi. Stdio, notification, binary içerik ve doğrudan upstream bypass engeli yok. İmzalı reputation feed URL/file/package tüketimine, DLP/behavior kararları güvenilir evaluator bağlamına, incident üretimi dayanıklı SIEM kuyruğu/worker'a bağlandı; connector provisioning ve müşteri teslim makbuzu açık.
- JWT Edge oturum iptali/MFA bariyeri 12 insan rotasına ve delegated credential JWT işlemlerine eklendi; servis rolü ve farklı auth modellerinin tam negatif matrisi ile gerçek IdP kabulü açık. Filo komut kuyruğu operatör MFA'sı ve cihaza bağlı API anahtarıyla var; endpoint OS uygulayıcısı ve fiziksel izolasyon kanıtı yok.
- Claude Code Windows release paketi native Koffi AMSI dosyalarını ve MIT lisansını içeriyor. Çıkarılmış paket `node_modules` olmadan native backend açtı; eksik native yükte kurucu fail-closed. Bozuk hook girdisi deny üretir. Gerçek müşteri host sürümü ve hook devre dışı/timeout davranışı hâlâ test edilmeli.

## Yerel doğrulama

| Kontrol | Sonuç / kanıt sınırı |
| --- | --- |
| 30 Supabase migration sırası ve 30 Edge function sözleşmesi | PASS; statik sözleşme, canlı dağıtım değil |
| PostgreSQL tenant RLS önce/sonra regresyonu | PASS; 11 tablo ve yabancı reputation/API key/enrollment yazımı, rollback transaction |
| `pnpm build:release` | PASS; 10 paket consumer kontrolü ve SBOM. Paketler geliştirici çalışma ağacından üretildi, resmi imza yok |
| `pnpm check` | PASS; 9 TS paketi ve MCP JS syntax; yeni JS paketi TypeScript kontrolüne yanlış dahil etme hatası düzeltildi |
| Tam Vitest kümesi | PASS: 215 dosya, 3.094 geçti, 2 atlandı, 0 hata. Atlananlar canlı reputation sağlayıcısı ve Windows'ta POSIX izin testi; `.release-evidence/v5-full-test.log` |
| Statik kalite | PASS; 131 lint uyarısı ve Knip inceleme borcu kayıtlı. Canlı satış CTA adresi ve tarayıcı onboarding kimlik bilgisi bu ortamda yok |
| Native Claude ayrı paket | 10 benign çağrıda native AMSI, PowerShell yok; deny ve malformed deny geçti; `claude-native-standalone-20260912.json` |
| Temiz self-hosted v5 | 11/11 servis sağlıklı; 30 migration atomik uygulandı; 30 HTTP smoke ve 9 müşteri bootstrap kontrolü PASS. Loopback fixture; gerçek Nginx/TLS ve bağımsız müşteri makinesi bekliyor |
| Taşınabilir müşteri kiti | 295 dosyanın hash/manifest doğrulaması PASS; çıkarılmış kitten cloud ve self-hosted hazırlık PASS. Resmi yayıncı imzası yok; `publisher_authenticated=false` |

V4'teki tek-host 10 RPS/30 saniye dashboard sağlık yük denemesi başarısızdı. Bu adayın tam test geçişi bile kapasite veya SLA kabulü değildir. Claude'un v4 ve v5 hafif süre örnekleri farklı paylaşılan host yükünde alındı; karşılaştırmalı p95 taahhüdü olarak kullanılamaz.

## Kalan işi hangi sırayla kapatacağız?

1. **P0 güvenlik/çalışırlık:** v5 migration ve endpoint imza route'unu izole cloud/self-hosted kurulumda uygula; tam cihaz eşleme, kiracı ayrımı ve mevcut reputation verisi denetimi yap. T01, T18, T21–T23, T28, T42–T46.
2. **Gerçek koruma kapsamı:** Satılacak Claude/Cursor/VS Code/OpenCode/OpenClaw/Codex/SDK sürümlerinin native host/OS kabulünü yap; MCP stdio ve bypass, DLP/behavior/feed connector provisioning, output sınırları ve OS filo müdahalesini tamamla. T01, T04–T13, T15–T20, T24–T25, T38.
3. **Kurumsal işletim:** Offsite bağımsız host restore, upgrade/rollback, yük/failover/noisy-neighbor, alarm/paging, SIEM makbuzu, SLA ve destek on-call tatbikatlarını aynı release hash'iyle kaydet. T26–T32, T35, T39–T40.
4. **Satış ve hukuk:** SKU/teklif, lisans/üçüncü taraf bildirimleri, DPA, bölge/veri akışı, fatura-entitlement mutabakatı, özel imzalı dağıtım, onaylı iddialar, bağımsız pentest/retest ve isimli müşteri PoV. T33–T34, T37, T41 ve COM/SEC-EXT/POV/CLM kapıları.

Kaynak hesabı ve 10/100/1.000 cihaz varsayımları `docs/production-readiness/resource-sizing-v5.md` içindedir. V5 yerel 11-servis tek anlık ölçümü **1.169,3 MiB RAM**, **%2,23 tek çekirdek CPU**; son kit Claude dosyaları **28,12 MiB**, üç hafif hook sürecinde tanılama dahil p95 RSS **88,1 MiB** ve ilk süreç **384 ms** gösterdi. V4 ölçümü farklı koşullarda 1.312,8 MiB RAM idi; fark kapasite kazanımı kanıtı değildir. 1.000 cihaz modeli 400.000 policy+ingest Edge çağrısı/gün ve 47 RPS planlama zirvesi üretir; bu, başarısız 10 RPS yerel testin üstündedir ve kabul edilmiş kapasite değildir. Hosted Edge işçi bellek/CPU limitleri sağlayıcı sınırlarıdır; AIDR istek başı kaynak tüketimi ölçülmedi.

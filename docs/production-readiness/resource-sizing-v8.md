# AIDR v8 kaynak ve kapasite ölçümü

Bu belge, 13 Eylül 2026'da `07a4fc4ad3b0cad1c2ff84c93082e66a27bf3fa0` çalışma ağacında **gerçekten çalıştırılan** ölçümleri ve bunlardan türetilen **tahsisleri** ayrı ayrı taşır. Ölçülmüş bir sayı hiçbir yerde tahsis gibi sunulmaz.

Bu tarihsel ölçümün ham `.release-evidence` makine kaydı artık tutulmuyor; aşağıdaki özet mevcut tek izlenen kayıttır ve güncel adaya yeniden bağlanamaz.

## 1. Ölçülmüş değerler

Kapsam: tek Windows Docker Desktop geliştirme hostu, artık tutulmayan izole loopback self-hosted fixture, 11 servis çalışır durumda, başka 1 container paylaşımlı hostta koşuyor. Müşteri yükü, TLS, ters proxy, HA ve yedek **dahil değildir**.

| Ölçüm | Değer | Not |
| --- | --- | --- |
| Container bellek (idle, 3 örnek) | p50 **1.501,4 MiB**, min 1.500,4 MiB, max 1.502,3 MiB | 11 servisin toplamı; rezervasyon veya tepe değer değil |
| Container CPU (idle, 3 örnek) | p50 **%13,05**, min %8,39, p95/max %24,60 (tek çekirdek yüzdesi) | Paylaşımlı geliştirici hostu; throughput kanıtı değildir |
| Hook ilk süreç wall time | **668,3 ms** | Zararsız yerel Bash değerlendirmesi, kontrol düzlemi isteği yok |
| Hook sonraki süreç wall time | p50 **828,5 ms**, p95/max **1.360,8 ms** (10 koşu) | Aynı koşul |
| Hook tanılama peak RSS | p50 **98,6 MiB**, p95/max **99,4 MiB** (103.419.904 bayt) | Diagnostik preload dahil; aktif hook süreci başına, boşta duran bellek değil |
| Kurulu connector dosya boyutu | **41.346.450 bayt (39,43 MiB)** | Hook çıktı digesti `604972e0…20be` |
| Edge HTTP (kimliksiz ret yolu) | 5 istek, 0 transport hatası, hepsi 401 | İş yolu maliyeti değil, reddetme maliyeti |
| Edge HTTP wall time | p50 **10,6 ms**, p95 **447,0 ms** | Küçük örneklem; p95 tek bir soğuk çağrıdan etkilenir |

Görüntü boyutları servis bazında kayıtta `images.by_service` altındadır (örneğin `db` sanal açılmış 367.224.458 bayt, `functions` 391.296.005 bayt). Bunlar **sanal açılmış** boyutlardır; ortak katmanlar birden çok servis için tekrar sayılır, bu yüzden toplamları disk kullanımı olarak okunamaz.

Bu 13 Eylül kaynak ölçümüne dahil olmayanlar: Docker Desktop VM/kernel/cache, ters proxy, TLS, otomatik yedek ve offsite transfer, HA/failover, noisy-neighbor, kimlikli policy+ingest yükü, uzun soak, native host yan etkisi ve müşteri kabulü. Sonraki tarihsel noisy-neighbor koşusu ayrı bir başarısız yerel sinyaldir; bu kaynak ölçümünü veya aday bağını geriye dönük değiştirmez.

## 2. Tahsis (ölçüm değil)

`scripts/resource-profile.mjs` içindeki planlama modeli, ölçülen tek nokta ile müşteri profili bilinmeden üretilmiş bir tahsistir. Varsayımlar (kayıtta `planning_model.assumptions`): olay yükü 2.048 bayt, policy değişimi 4.096 bayt, optimize ingest partisi 20 olay, indeksli DB/WAL çarpanı 3, saklama 90 gün, tepe/ortalama oranı 10, policy cache 30 saniye.

| Senaryo | Uç nokta | Kayıtlı olay/gün | Edge çağrısı/gün | Ortalama RPS | Planlama zirvesi RPS | Canlı DB tahmini |
| --- | --- | --- | --- | --- | --- | --- |
| Pilot | 10 | 100 | ~700 | 0,01 | 1 | 0,05 GiB |
| Departman | 100 | 2.000 | ~14.000 | 0,16 | 2 | 1,03 GiB |
| Kurum | 1.000 | 40.000 | ~400.000 | 4,63 | 47 | 20,6 GiB |

Bu tablo, v7'de yazılan "1.000 cihaz → günlük ~400.000 policy+ingest çağrısı, 47 RPS zirvesi" ifadesiyle tutarlıdır ve hâlâ **tahsistir**: müşteri olay profili, batching davranışı ve gerçek olay boyutu ölçülmeden kesinleşmez. Not: mevcut uç akışı çoğu zaman verdict başına tek olay gönderir; "optimize edilmiş batching" yalnızca alt sınırdır.

Başlangıç donanım tahsisi (ölçüm değil): pilot/100 cihaz **4 vCPU / 8 GiB RAM / 100 GiB SSD**; 1.000 cihazlık ilk yük testi **8 vCPU / 16 GiB RAM / 250 GiB SSD**; uç cihaz başına **512 MiB disk rezervi**. Eşzamanlı hook süreçleri için süreç RSS'i ayrıca bütçelenir (yukarıdaki ~99 MiB/aktif süreç bu bütçenin girdisidir).

## 3. Bu ölçümle kapanmayan kapılar

- **T30 / AIDR-052:** yerel yük harness'i geçti ve tek-host noisy-neighbor koşusu kuyruk gecikmesi/erişilebilirlik eşiğini başarısız kıldı; HA/failover, bağımsız çok-host izolasyon, aday-bağlı aylık SLI ve en az 8 saatlik soak hâlâ koşulmadı. Yukarıdaki idle ölçümü bunların yerine geçmez.
- **T27 / AIDR-044:** offsite storage, bağımsız host kurtarma ve kabul edilmiş RPO/RTO yok.
- **T01:** gerçek host ve OS matrisi ile isimli kabul hâlâ açık (bkz. `docs/evidence/native-host-status-20260916.md`).
- **T39:** bağımsız imzalı etkinlik ölçümü yok.

Kapasite iddiası içeren hiçbir satış metni bu belgeye dayandırılamaz; ölçüm tek bir geliştirici hostunda, tek bir izole fixture üzerinde alınmıştır.

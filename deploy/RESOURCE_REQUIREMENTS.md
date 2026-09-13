# AIDR kaynak ve kapasite başlangıç rehberi

Bu değerler ilk kurulum bütçesi içindir; kapasite, SLA veya müşteri cihazı kabulü değildir. 13 Eylül 2026 tarihli yerel Windows Docker Desktop v6 provasında 11 self-hosted servis tek anlık örnekte **1.165,1 MiB RAM** kullandı. Aynı anın yaklaşık **%66,52 tek çekirdek CPU** değeri kurulumdan kısa süre sonra alındı; idle veya tepe CPU kabulü değildir. Konteyner imajlarının açılmış sanal boyutları toplamı, paylaşılan katmanlar çift sayılarak **1,69 GiB üst sınırdır**. Host ters proxy, cihaz kayıt imzalayıcısı, Docker VM/kernel, log, yedek ve TLS bu ölçümde yoktur. v6 yerel dashboard `/healthz` sağlık rotasında 10 RPS/30 saniye denemesi 300/300 başarılı ve p95 7,2 ms oldu; önceki başarısız prova da korunur. Bu kısa sağlık denemesi kimlikli Edge veya kurumsal kapasiteyi onaylamaz.

| Kurulum noktası | İlk tahsis / ölçüm | Bütçeye ayrıca ekleyin |
| --- | --- | --- |
| Korunan Windows uç cihaz | v6 Claude paket dosyaları 28,17 MiB; üç hafif çağrıda ayrı Node süreci için tanılama dahil p95 RSS 88,9 MiB | Claude/AI host ve Node gereksinimi, eşzamanlı kanca süreçleri, 64 MiB varsayılan olay kuyruğu, en çok 32 MiB feed, günlükler, eski sürümler. Başlangıç disk rezervi: cihaz başına 512 MiB |
| Self-hosted pilot/100 cihaz | Prova başlangıç VM'si: 4 vCPU, 8 GiB RAM, 100 GiB SSD | Ters proxy ve imzalı `device-start` sidecar, TLS, kalıcı PostgreSQL/Storage, log, en az iki yedek ve ayrı offsite hedef |
| Self-hosted 1.000 cihaz | Yük testine başlanacak tahsis: 8 vCPU, 16 GiB RAM, 250 GiB SSD | Bu satır 1.000 cihaz kapasite vaadi değildir; yük, HA, DB IOPS ve büyüme ölçümüne göre artırın |
| Yönetilen cloud | Endpoint gereksinimi aynı; Edge Function, yönetilen DB, Storage, dashboard ve güvenilir ingress ayrı faturalanır | Gerçek proje/region/plan seçimi, Edge CPU/bellek/invocation, DB IOPS, egress ve yedek metrikleri olmadan fiyat veya tier hesaplanamaz |

Trafik modelinde varsayılan 2 KiB olay, 4 KiB politika alışverişi, 90 gün saklama, olay alanının 3 katı DB+indeks/WAL alanı ve günlük ortalamanın 10 katı zirve kullanıldı. Bunlar gerçek müşteri telemetrisiyle değiştirilmelidir.

| Cihaz sayısı | Policy + ingest Edge çağrısı/gün | Tahmini uygulama payload/gün | 90 gün olay DB alanı | Planlama zirvesi |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 700 | 2,5 MiB | 0,05 GiB | 1 RPS |
| 100 | 14.000 | 50,8 MiB | 1,03 GiB | 2 RPS |
| 1.000 | 400.000 | 1,45 GiB | 20,6 GiB | 47 RPS |

Bu model URL/dosya reputation sorgusu, enrollment, dashboard, SIEM, tekrar deneme, HTTP/TLS başlıkları, yedek ve sürüm indirmelerini saymaz. Gerçek kullanıcı dağılımı mesai başlangıcında yoğunlaşırsa zirve daha yüksek olabilir. 1.000 cihaz için 47 RPS, yalnız dashboard sağlık rotasında geçen 10 RPS yerel denemesinin çok üstündedir.

Ölçüm kanıtları mühendislik adayında `resource-profile-v6-local-20260913.json`, `resource-images-v6-local-20260913.json` ve `load-dashboard-v6-local-20260913.json` olarak tutulur; bunlar müşterinin sahadaki ölçümünün yerini almaz. Yerel kanca ölçümünde ilk süreç 1.014 ms, sonraki iki süreç 1.020–1.127 ms sürdü; tanılama preload'u RSS'e dahildir. Bu örneklerin hiçbirinde gerçek müşteri politikası, tam reputation feed veya eşzamanlı AI host iş yükü yoktur.

Satışta cihaz sayısı veya SLA sınırı vermeden önce aynı imzalı adayla hedef host/region üzerinde 1→10→100→hedef cihaz yük adımları, en az 8 saat soak, p50/p95/p99 kanca ve API gecikmeleri, CPU/RAM tepe, DB IOPS, disk büyümesi, kuyruk kaybı, offsite restore, failover ve gerçek cloud fatura metrikleri kaydedilmelidir. Özel feed, DLP, model ve SIEM ayarları bu yükte etkin olmalıdır.

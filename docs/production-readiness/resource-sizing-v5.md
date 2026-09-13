# AIDR kaynak ve kapasite boyutlandırması — yerel ölçüm / planlama modeli

Bu belge ilk müşteri için **kurulum bütçesi** çıkarır. Ölçümler, `.release-evidence/aidr-install-v4` ve `.release-evidence/aidr-install-v5` içindeki 11 servisli, loopback'e bağlı self-hosted geliştirme kurulumları ve Claude Code bağlayıcıları üzerindedir. Docker Desktop başka konteynerlerle ve eşzamanlı geliştirme işleriyle paylaşıldı. Aşağıdaki sayılar ne müşteri sunucusu, ne yönetilen bulut, ne de kapasite/SLA kabulüdür. Daha önceki 10 RPS/30 saniye dashboard sağlık yük denemesi başarısızdı; kanıt `.release-evidence/load-dashboard-local-20260912.json` olarak korunur.

## Kaynağın nerede tüketildiği

| Konum | Tüketim nedeni | Operatörün ayıracağı kaynak |
| --- | --- | --- |
| Korunan uç cihaz | Claude Code PreToolUse için ayrı Node süreci, yerel kural/DLP/reputation taraması, imzalı politika ve telemetri kuyruk dosyaları | Her eşzamanlı kanca süreci için CPU ve geçici RAM; bağlayıcı, feed, günlük ve kuyruk için kullanıcı diski |
| Self-hosted yönetim sunucusu | 11 Compose servisi: dashboard, API gateway, Auth, REST, Realtime, Edge runtime, PostgreSQL, Storage, Imgproxy, Meta, Studio; ayrıca cihaz başlangıcı için host ingress signer ve TLS proxy | VM/host vCPU ve RAM; DB/Storage/Deno cache ve imajlar için hızlı kalıcı disk; ayrı yedek alanı |
| Cloud yönetim modeli | Statik dashboard/barındırma, Edge Function çağrıları, yönetilen PostgreSQL ve nesne deposu; ayrıca cihaz başlangıcını imzalayan güvenilir ingress | Sağlayıcıdaki compute/DB/storage/egress faturası ve limitleri; gerçek proje metrikleriyle seçilecek kapasite |
| Uç cihaz ↔ yönetim katmanı | Politika yenileme, olay ingest, enrollment, durum, güncelleme ve isteğe bağlı reputation sorguları | Eşzamanlı istek kapasitesi, TLS/WAF/proxy ve outbound bant genişliği |

Claude bağlayıcısının kurucusu `dist`, `resources` ve `package.json` dosyalarını digest adresli dizine kopyalar (`scripts/endpoint-install.mjs`). Bağlayıcının disk ayak izi güncellemelerde eski digest paketleri tutulursa sürüm sayısıyla büyür. Telemetri kuyruğu varsayılan olarak 64 MiB pending bayt sınırı kullanır (`packages/core/src/telemetry-queue.ts`); WAL compact öncesi geçici disk gereksinimi daha yüksek olabilir. İmzalı reputation feed payload üst sınırı 32 MiB'dir (`packages/core/src/reputation-feed.ts`) ve mevcut tüketiciler URL/dosya/paket sorgularında feed'i yeniden yükleyip doğrular. Büyük feed veya yoğun sorgu için uç cihaz CPU/RAM/gecikme ayrı ölçülmelidir; aşağıdaki hafif Bash canary ölçümü bunu kapsamaz.

## Ölçüm yöntemi ve sınırı

`node scripts/resource-profile.mjs --deployment .release-evidence/aidr-install-v4 --connector-package .release-evidence/aidr-customer-kit-20260912-v4/packages/claude-code --output .release-evidence/resource-profile-local-20260912.json --samples 1 --hook-iterations 3 --edge-iterations 1 --skip-image-size`

Son v5 kit ölçümü aynı komutun deployment, connector-package ve output yolları sırasıyla `.release-evidence/aidr-install-v5`, `.release-evidence/aidr-customer-kit-20260912-v5-final/packages/claude-code` ve `.release-evidence/resource-profile-v5-local-20260912.json` yapılarak alındı. Son 295 dosyalık teslim kitindeki Claude hook SHA-256 aynı olduğundan bu ölçüm kanca baytlarına bağlıdır.

İmaj boyutlarını uç cihaz/Edge yükü üretmeden ayrıca alın: `node scripts/resource-profile.mjs --deployment .release-evidence/aidr-install-v4 --output .release-evidence/resource-images-local-20260912.json --image-inventory-only`. Bu iki kanıt aynı `compose_sha256` değerine bağlıdır. Kanıt dosyaları kaynak ağacındaki `.release-evidence/` altında kalır; kullanıcı paketi içine özel kurulum verisi koyulmaz.

Araç yalnız `development: true`, self-hosted ve loopback adresli kurulumda çalışır. `docker stats` ile servis başına anlık CPU, bellek, ağ/blok I/O; `du` ile DB/Storage/cache volume boyutu; Docker image inspect ile sanal açılmış imaj boyutu; ayrı Node süreçleriyle hafif Bash kanca süresi ve tanılama RSS; loopback Edge `url-check` kimliksiz ret ve dashboard `/healthz` yanıt süresi/baytını alır. Çıktıda credential, istek gövdesi, hostname, URL, raw Docker inspect veya kullanıcı yolu yoktur; kaynak SHA-256 ile bağlanır. Ölçüm ilk kanca sürecini ve sonraki süreçleri ayırır. RSS örneklemesi bir tanılama preload'u içerdiğinden ölçülen aktif süreç belleği üretim kancasının salt belleği değildir.

Docker `MemUsage` anlık kullanım, CPU% yaklaşık **bir çekirdeğin yüzdesi**, NetIO/BlockIO ise konteyner başlatıldığından beri kümülatif sayaçtır. Bu sayaçlardan tek istek maliyeti veya kalıcı disk boyutu çıkarılmaz. Sanal açılmış imaj boyutlarının toplamı ortak katmanları tekrar sayar; fiziksel image disk tüketimi değildir. Docker Desktop VM/kernel, host ingress signer ve ters proxy, container logları, yedekler, TLS ve müşteri tarayıcısı bu 11 servis toplamında yoktur.

## Ölçülen yerel değerler

12 Eylül 2026 tek anlık örneği: Windows host **12 mantıksal CPU, 31,35 GiB RAM**; Docker Desktop içinde 11 AIDR konteynerine ek **3 başka konteyner** çalışıyordu. AIDR konteynerleri toplam **1.312,8 MiB RAM** ve anlık **%19,88 tek çekirdek CPU** gösterdi. Bu bir idle tabanı veya tepe kullanım ölçümü değildir. Image sanal açılmış boyut toplamı **1,69 GiB üst sınır**; katman paylaşımı nedeniyle fiziksel tüketim bundan doğrudan hesaplanmaz. Taze prova veri alanı: PostgreSQL **70,5 MiB**, Storage **0,4 MiB**, Deno cache **16,0 MiB**, DB config **0,1 MiB**. Yedek, log, image metadata ve büyüme rezervi ayrı tutulur.

| Servis | RAM MiB | CPU % tek çekirdek | Net Rx/Tx MiB kümülatif | Blok oku/yaz MiB kümülatif | İmaj sanal MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| API gateway | 35,3 | 1,31 | 36,24 / 3,38 | 0,95 / 0,05 | 70 |
| Auth | 16,2 | 4,13 | 1,14 / 1,02 | 1,07 / 0,00 | 28 |
| Dashboard | 19,1 | 0,01 | 0,01 / 0,64 | 0,88 / 0,00 | 54 |
| PostgreSQL | 134,8 | 0,16 | 5,81 / 5,18 | 0,49 / 104,90 | 350 |
| Edge Functions | 350,3 | 4,99 | 5,53 / 1,19 | 0,26 / 16,78 | 373 |
| Imgproxy | 14,7 | 0,00 | 0,00 / 0,00 | 0,00 / 0,00 | 77 |
| Meta | 106,2 | 2,70 | 0,01 / 0,01 | 0,00 / 0,00 | 109 |
| Realtime | 229,5 | 0,50 | 0,67 / 0,99 | 0,00 / 0,04 | 119 |
| REST | 74,5 | 2,04 | 4,81 / 37,38 | 1,44 / 0,00 | 6 |
| Storage | 115,4 | 4,04 | 0,56 / 0,67 | 0,34 / 0,34 | 229 |
| Studio | 216,8 | 0,00 | 0,02 / 0,36 | 0,00 / 0,00 | 318 |

V4 Claude bağlayıcısının kurulan dosyaları **20,19 MiB**. Boş HOME ile zararsız `Bash: ls -la` değerlendirmesinde ilk ayrı Node süreç **4.348 ms**, sonraki iki süreç **2.460–3.431 ms** sürdü. Tanılama preload'uyla ölçülen tepe RSS p95 **92,0 MiB** (3 örnek); preload'un payı ayrıştırılmadı. Bu, kancanın doğal üst sınırı ya da tüm konektörlerin belleği değildir. İş istasyonundaki eşzamanlı build/test yükü gecikmeyi etkilemiş olabilir. Kanca input gövdesi ve stdout baytları kanıt JSON'dadır.

V5 Claude ön paketinde ayrıca [izole Windows native AMSI provası](../../.release-evidence/claude-native-standalone-20260912.json) yapıldı. `node_modules` bulunmayan çıkarılmış pakette 10 zararsız ayrı hook süreci **native Koffi** kullandı ve PowerShell açmadı: medyan **1.156 ms**, p95 **2.594 ms**; bozuk girdi ve saldırı canary'si deny döndü. V4 örneğinin medyanı **3.183 ms**, p95'i **5.046 ms** idi. Bu ön paketin hook hash'i son kitinkinden farklıdır; örneklem, iş yükü ve eşzamanlı host koşulları da eşitlenmediği için karşılaştırmalı performans/latency SLO kanıtı değildir. Native yük eksikse kurucu hook kaydı yapmadan durur.

Son 295 dosyalık v5 teslim kitiyle aynı hook hash'ine bağlı [yerel kaynak profili](../../.release-evidence/resource-profile-v5-local-20260912.json) üç hafif süreç ölçtü: kurulan Claude dosyaları **28,12 MiB**, ilk süreç **384 ms**, sonraki iki süreç **340–375 ms**, tanılama dahil p95 RSS **88,1 MiB**. Bunlar yerel boş HOME ve zararsız Bash canary'sidir; kayıtlı müşteri politikası, gerçek AI host yükü ve tam reputation feed içermez. Aynı v5 kurulumunun 11 Compose servisi tek anlık ölçümde **1.169,3 MiB RAM** ve **%2,23 tek çekirdek CPU** gösterdi; başka bir konteyner de çalışıyordu. [V5 imaj envanteri](../../.release-evidence/resource-images-v5-local-20260912.json) açılmış sanal imaj boyutlarını ortak katmanları çift sayarak **1,69 GiB üst sınır** olarak topladı; fiziksel disk kullanımı değildir. Bu değerler idle rezervi, tepe kullanım veya throughput kanıtı değildir. V4 ile farkı AIDR sürüm kazancı diye yorumlamayın: v4/v5 anlık ölçüm zamanı, süreç durumu ve paylaşılan host yükü farklıdır.

Loopback Edge `url-check` ret yolu (anon gateway anahtarı, **ajan bearer yok**) tek istekte HTTP 401, **2.408 ms** ve **27 B** yanıt gövdesi verdi; 58 B istek gövdesi kullanıldı. Dashboard `/healthz` tek istekte HTTP 200, **90 ms/39 B** verdi. Önceki daha uzun Edge örneği 10 saniyede zaman aşımına uğradı ve sonuç üretmedi. Bu örnekler authenticated URL reputation, gerçek Edge CPU süresi, istek başı RAM veya bulut Edge maliyeti ölçmez; Edge runtime'ın 350,3 MiB değeri konteynerin toplam anlık belleğidir.

## 10, 100 ve 1.000 uç cihaz için talep modeli

Bu **trafik senaryoları ölçüm değildir**. Varsayımlar: olay gövdesi ortalama 2 KiB, politika istek/yanıt gövdeleri toplam 4 KiB, 90 gün saklama, PostgreSQL indeks+WAL için olay gövdesinin 3 katı canlı disk, zirve/saatlik ortalama oranı 10. Bunlar saha örnekleriyle değiştirilmelidir. Varsayılan `send_clean_verdicts=false`; olay/gün bağımsız bir girdi olarak verilir. Policy Function `cache_seconds: 30` döndürür (`supabase/functions/policy/index.ts`); politika sorgusu üst sınırı, günlük araç çağrısı ile aktif dakika başına iki sorgunun küçük olanıdır. Mevcut telemetri gönderimi normalde olay başına `ingest` çağrısı yapar; kuyruk backlog'unun 20'li batch'e dönüşmesi yalnız daha düşük bir istek sayısı sınırıdır.

Formüller: `P = N × min(T, 2 × M)` politika isteği/gün; `E = N × F` olay/gün; tipik iki Edge rotası çağrısı `P + E`; optimize toplu gönderim alt sınırı `P + ceil(E/20)`; uygulama payload baytı/gün `4.096 × P + 2.048 × E`; 90 günlük DB olay alanı yaklaşık `E × 2.048 × 3 × 90`. Buradaki ağ baytı HTTP başlığı, TLS, tekrar deneme, diğer Edge uçları, SIEM ve sürüm indirmesini **içermez**. Canlı veritabanı alanı PostgreSQL başlangıç imajı/cluster, tablo bloat, vakum rezervi, dosya nesneleri ve yedeği **içermez**.

| Profil | Uç cihaz | Araç çağrısı/cihaz/gün | Aktif dakika/cihaz/gün | Olay/cihaz/gün | Politika istek/gün üst sınırı | Tipik iki rota Edge çağrısı/gün | Ortalama → ×10 planlama zirvesi | App payload/gün | 90 gün olay DB alanı |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Pilot | 10 | 100 | 30 | 10 | 600 | 700 | 0,01 → 1 RPS | 2,5 MiB | 0,05 GiB |
| Departman | 100 | 200 | 60 | 20 | 12.000 | 14.000 | 0,16 → 2 RPS | 50,8 MiB | 1,03 GiB |
| Kurumsal | 1.000 | 400 | 180 | 40 | 360.000 | 400.000 | 4,63 → 47 RPS | 1,45 GiB | 20,6 GiB |

Bu rota sayıları yalnız `policy` ve `ingest` içindir. `url-check`, `file-check`, enroll, dashboard, audit-export, SCIM ve bildirim trafiği ayrıca eklenir. Her müşteri için N/T/M/F dağılımı, p95 olay boyutu, aynı anda aktif kullanıcı ve politika yenileme korelasyonu ölçülür. Örneğin herkes mesai başlangıcında oturum açarsa ×10 faktörü yetersiz kalabilir. 1.000 cihaz satırındaki 47 RPS, başarısız 10 RPS yerel denemesinin üzerinde olduğundan mevcut tek-host Compose üzerinde kabul edilmiş kapasite değildir.

## İlk kurulum bütçesi ve kabul ölçümü

Pilot/100 cihaz için **yalnız prova başlangıç tahsisi**: tek self-hosted VM'de en az 4 vCPU, 8 GiB RAM ve 100 GiB SSD; 1.000 cihaz için 8 vCPU, 16 GiB RAM ve 250 GiB SSD ile başlatıp yük adımlarında büyütün. Bu değerler SLA, minimum teknik gereksinim veya 1.000 cihazın çalışacağı garantisi değildir; 11 servis, image/DB/backup alanı ve test başlığı için temkinli rezervdir. [Supabase'in Docker self-hosting rehberi](https://supabase.com/docs/guides/self-hosting/docker) tüm bileşenler için asgari 2 çekirdek/4 GB/40 GB SSD ve önerilen 4+ çekirdek/8+ GB/80+ GB SSD verir; AIDR başlangıç tahsisi buna ek uygulama ve işletim rezervi koyar. Gerçek üretimde ters proxy, yedek hedefi, ayrı failure domain ve DB/Storage ayrımı eklenir. İki yerel yedek ve en az %30 boş alan isteniyorsa alan hesabı `imaj+kurulum+DB+Storage+cache+log+2×yedek + %30 rezerv` üzerinden yeniden yapılır. Offsite kopya aynı sunucu diskine sayılmaz.

Uç cihazda ayrı Node kanca süreci için ölçülen tepe RSS üzerine eşzamanlılık payı konur: `aktif_kanca_sayısı × ölçülen_RSS`; bunu Claude host'unun kendi RAM ihtiyacına ekleyin. Başlangıç disk rezervi olarak **cihaz başına 512 MiB** ayırmak 20,19 MiB bağlayıcı, varsayılan 64 MiB pending kuyruk, geçici WAL/kompakt, 32 MiB feed ve log/rollback için bir planlama tamponudur; kural paketi, audit retention ve sürüm sayısıyla yeniden hesaplayın. Kullanıcı uygulamasının/Node runtime'ının kendisi buna dahil değildir.

Cloud modelinde endpoint gereksinimi aynıdır. 11 servisli self-hosted bellek toplamını Supabase Edge için ayrılması gereken RAM diye çevirmeyin; sağlayıcıya göre izole Edge yürütümü, managed PostgreSQL, Storage ve dashboard ayrı ürünlerdir. [Supabase hosted Edge sınırları](https://supabase.com/docs/guides/functions/limits) 12 Eylül 2026 itibarıyla işçi başına 256 MB bellek ve istek başına 2 saniye etkin CPU zamanı bildirir; bunlar AIDR'nin ölçülen tüketimi veya seçilmiş planın kapasitesi değildir. Bu proje için gerçek cloud hesabı/region/plan seçilmedi; Edge CPU zamanı, memory, invocations, DB IOPS ve egress sağlayıcı metrikleriyle ölçülmeden bir tier veya fiyat yazılamaz. Yüksek kullanılabilirlik için iki/üç failure domain ve DB replika kararı `deploy/ha/` saha provası ile bağlanır.

Müşteri kabulünde aynı aday hash'iyle 1, 10, 100 ve hedef cihaz eşzamanlılığında en az 8 saat soak, p50/p95/p99, container/Edge CPU ve bellek zirvesi, DB IOPS/bağlantı/bloat, kuyruk doluluğu ve kayıp, gerçek Edge invocation ve egress, disk büyüme eğrisi, policy invalidation yükü, 32 MiB feed canary'si, cloud fatura metriği ve başarısız 10 RPS senaryosunun düzeltilmiş tekrarını kaydedin. Eşikler müşteri sözleşmesi ve gerçek host/region için onaylanmadan satışta kapasite veya SLA vaadi verilmez.

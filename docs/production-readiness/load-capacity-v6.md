# Kapasite ve yük kanıtı — v6 mühendislik incelemesi

**Durum: AIDR-052 açık.** Bu kayıt, yük aracının yerel doğruluğunu iyileştirir; tek host, yüksek erişilebilirlik, 100/1.000 uç cihaz veya müşteri SLA kabulü değildir. Mevcut paylaşılan Docker kurulumuna bu incelemede yük verilmedi.

## Tarihsel 10 RPS sonucu ve ne anlattığı

12 Eylül'de kaydedilen 30 saniyelik dashboard sağlık yükü 300 istek planladı, 156'sını başlattı, 144'ünü istemci tarafında düşürdü, 47'sinde taşıma hatası aldı ve 109 HTTP 200 gördü. Başlayan isteklerin p95 süresi 5.407 ms, beklenen yanıtların planlanan isteklere oranı %36,3 idi. Sonuç **FAIL**. Ham `.release-evidence/load-dashboard-local-20260912.json` türetilmiş dosyası artık tutulmadığından bu özet tarihsel bağlamdır, güncel aday kanıtı değildir. Profil 20 eşzamanlı istek sınırı ve 5 saniye istek zaman aşımı kullanıyordu. Test, diğer ajan işleriyle paylaşılan Windows Docker Desktop hostunda çalıştı; host CPU/bellek/IO, Docker VM, Node istemci kuyruğu ve bağlantı havuzu o koşuyla eşzamanlı olarak ayrıştırılmadı.

`deploy/dashboard/server.mjs` içindeki `/healthz` yolu sabit JSON döndürür ve DB sorgusu yapmaz. Bu nedenle eski sonuç tek başına dashboard uygulamasının 10 RPS'de doyduğunu veya Edge ingest kapasitesini göstermez. 47 hatanın ağ, zaman aşımı veya gövde okuma nedeni eski sonuçta kayıtlı değildir. 144 düşüş `max_in_flight` sınırına çarpan yük üreticisini de içerir. Kök neden belirsiz kalır; satışta bu denemeyi başarılı kapasite delili diye kullanmayın.

## Araç doğruluğunda kapatılan boşluklar

- Senaryo yolunun WHATWG URL çözümlemesinden sonra tam olarak izinli origin'de kaldığı denetlenir. Önceden `"/\\example.invalid/escape"` yolu metin kontrolünden geçip başka hosta çözülebiliyordu. Yönlendirmeler zaten `manual` olarak işlenir.
- Sonuçtaki yeni `diagnostics` alanı yük üreticisinin p50/p95/p99/en büyük planlama gecikmesini, en yüksek eşzamanlılığı, planlama/drenaj bitişini ve tamamlanan istek hızını kaydeder. Güncel şema eski sonuçları da kabul eder; eski katı şemayı kullanan doğrulayıcı yeni sonuçlar için güncellenmelidir. Hata sınıfları senaryo ve cohort bazında `unexpected_status`, `timeout`, `network`, `response_body_limit`, `client_error`, `other` olarak ayrılır. Ham URL, credential, gövde veya hata mesajı yazılmaz.
- Yük üreticisi geç kalan istekleri bir anda gönderip servis eşiklerini yalancı biçimde geçemesin diye her sonuçta iki iç geçerlilik eşiği uygulanır: p95 planlama gecikmesi `max(100 ms, 2 × planlanan istek aralığı)`, en büyük gecikme `max(1.000 ms, 10 × aralık)`. İkisi de `threshold_checks` içinde görünür ve aşılırsa `passed: false` olur. Bu eşikler müşteri latency SLO'su değildir; üretici zamanlaması bozulmuş koşunun kapasite kanıtı olmasını engeller.
- Başlık alınmış olsa bile gövde okuma/zaman aşımı hatası `transport_errors` sayılır. `status_counts` görülen HTTP kodlarını, `failure_classes` ise işlenen sonucun neden başarısız olduğunu gösterir. Rezervuar örneklemesinde `latency_ms.max` artık örneklem maksimumu değil gerçek gözlenen maksimumdur.

## İzole fixture sonucu

`node scripts/verify-load-test.mjs` dokuz kontrolü geçti. 4 saniyelik loopback fixture 5 RPS hedefinde 20/20 isteği başlatıp tamamladı; ilk dört yanıt kasıtlı 503, sonraki 16 yanıt 200 idi. p95 istemci isteği 7,9 ms, p95 yük üretici planlama gecikmesi 189,4 ms, tepe uçuşta istek 2 idi. Bu sadece izole sentetik HTTP fixture'ıdır, AIDR servisi ölçümü değildir. Ayrı timeout fixture 3/3 zaman aşımını `timeout` ve `transport_errors` olarak saydı ve eşiği beklenen şekilde başarısız kıldı. Gövde limiti fixture HTTP 200 alınsa bile aşırı gövdeyi başarısız saydı. Doğrulama kaydı credential sızdırmama, URL origin kaçışı ve schema sözleşmesini de kontrol etti. Bu dosyalar her çalıştırmada `.release-evidence/load-harness-*` altında yeniden üretilir ve kalıcı aday kanıtı sayılmaz; fixture zamanlamaları aynı paylaşılan geliştirme hostunun o andaki durumuna özgüdür.

## AIDR-052'yi kapatmak için kalan ölçüm

Sabit aday digest'i, host donanımı, Docker/OS sürümü ve diğer host yükü ile izole bir test ortamı hazırlayın. Aynı profili en az üç kez 1→5→10→25→hedef RPS basamaklarında çalıştırın; önce `/healthz` üreticisini ayrı makinede kalibre edin, ardından gerçek imzalı policy, ingest, URL/file reputation, dashboard sorgusu ve SIEM teslim karışımını gerçek olay boyutlarıyla ölçün. Her basamakta sonuç JSON'una container CPU/bellek, Docker VM/host CPU, DB bağlantı/IOPS, Edge runtime, kuyruk derinliği, ağ retransmit ve sunucu erişim günlüğünün zaman serisini aday kimliği ve saat eşlemesiyle bağlayın. Eski 10 RPS kaybının hangi katmanda oluştuğu ancak bu ayrımla belirlenebilir.

Ardından sözleşmeye göre sürekli yükte en az sekiz saat soak, farklı tenant için noisy-neighbor ve operatör kontrollü replika/DB/failure-domain kesintileri yapın. Sonuç `passed: true` olsa bile aracın `production_accepted`, `production_sla_proven`, `ha_proven` alanları `false` kalır; müşteri ortamında bağımsız kabul ve onay gereklidir.

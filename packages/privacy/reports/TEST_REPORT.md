# AIDR Privacy — Test ve ölçüm raporu

**Sürüm:** 0.1.0-rc.1  
**Tarih:** 23 Eylül 2026  
**Durum:** Test edilmiş üretime hazırlık adayı; gerçek NER / kurum kabul testleri tamamlanmadı.

## 1. Çalıştırılan testler

| Kontrol | Sonuç |
|---|---:|
| Node testleri | **330/330 geçti** |
| Python artefakt / offset / manifest CLI testleri | **38/38 geçti** |
| Toplam test girdisi | **368 geçti; 0 başarısız** |
| Ek property-test üretimleri | **10.000 deterministik vaka** |
| Satır kapsamı, derlenmiş çekirdek | **%99.10** |
| Dal kapsamı, derlenmiş çekirdek | **%93.93** |
| Fonksiyon kapsamı, derlenmiş çekirdek | **%97.12** |
| TypeScript typecheck / build | Geçti |
| CLI / AIDR guard / atomic streaming | Testlerde çalıştırıldı |
| Gerçek alt süreç protokolü | Açıkça sahte NER worker ile çalıştırıldı |
| Değerlendirme CLI, yerel provider yolu | Tek sentetik belge + sahte worker ile smoke test geçti |
| Python worker sözdizimi | Derleme kontrolü geçti |
| Gerçek pretrained NER çıkarımı | **Çalıştırılmadı** |

10.000 property vakası Node test girdilerinin içinde döngülerle çalışır; bunları 10.000 ayrı Node testi olarak sunmuyoruz. Kapsama ölçümü Node'un deneysel built-in coverage özelliğiyle `dist/*.js` üzerinde yapıldı. Kod kapsamı; kusursuz güvenlik, eksiksiz PII tespiti veya model doğruluğu demek değildir.

Kanıt dosyaları: `tests.tap`, `python-tests.txt`, `coverage.txt`, `typecheck.txt`, `build.txt`, `evaluator-smoke.json`.

## 2. Geliştirici üretimi regresyon değerlendirmesi

107 belge: 78 pozitif, 29 negatif. Geliştirme sırasında kullanılan fixture'lardır; **bağımsız/held-out gerçek dünya test kümesi değildir**. Varsayılan fixture'lar dil başına kalite iddiasına uygun şekilde ayrı etiketlenmemiştir.

| Ölçüm | Sonuç |
|---|---:|
| Doğru tam aralık + tür | 77 / 78 |
| Tam aralık precision / recall / F1 | %98,7179 / %98,7179 / %98,7179 |
| İşaretlenmiş hassas karakterlerin maskelenme kapsamı | 1.442 / 1.442 |
| Pozitif belge içinde gönderilmiş eksik maskeleme | 0 / 78 |
| Negatif belgede yanlış pozitif karar | 0 / 29 |
| Block / review | 0 / 0 |

Bir URI kimlik bilgisi örneğinde, e-posta biçimiyle örtüşen host son eki de maskelendiğinden aralık altın etiketin sınırından geniştir. Bu, tam eşleşme skorunu düşürür ama bu örnekte hassas kısmı açık bırakmaz. Sonuçlar yalnızca bu tanımlı 107 kayda aittir; “%100 PII yakalama” iddiasına dönüştürülemez.

Ham metinler rapor dosyalarına yazılmadı. Fixture kaynakları sentetiktir. Ayrıntı: `evaluation.json`.

## 3. Gerçek çekirdek gecikme ölçümü

**Yalnızca TypeScript kuralları, tek süreç, sıralı ve ısınmış çağrılar. Gerçek NER, HTTP/TLS, JSON iş yükü, çok kiracılı trafik veya müşteri donanımı dahil değildir.** Her mixed-pii girdisinde üç bulgu vardır.

| Girdi | Tekrar | Medyan | p95 | p99 |
|---|---:|---:|---:|---:|
| 256 B | 300 | 0.103 ms | 0.369 ms | 0.976 ms |
| 1,024 B | 300 | 0.226 ms | 0.436 ms | 0.678 ms |
| 4,096 B | 300 | 0.794 ms | 1.712 ms | 2.994 ms |
| 16,384 B | 100 | 3.169 ms | 4.859 ms | 5.294 ms |

Toplam Node süreç RSS başlangıcı **29.95 MiB**, çağrı sonlarında örneklenen en yüksek RSS **50.41 MiB**. Bu sayı sadece kütüphanenin ek belleği değil; Node/V8 ve benchmark tahsisleri dahil toplam süreç belleğidir. Sürekli örneklenen gerçek tepe bellek de değildir.

64 KiB temiz/uzun token/ayırıcı/etiket-benzeri girdiler ile 65.537 byte limit aşımı ayrıca çalıştırıldı. Uzun opak token `OPAQUE_ENCODING`, limit aşımı `INPUT_LIMIT` ile engellendi. Süreler `benchmark.json` içindedir.

Ortam: v22.16.0, linux/x64, INTEL(R) XEON(R) PLATINUM 8573C. Görünür CPU sayısı garanti edilmiş CPU kotası değildir. Bu ölçümden üretim SLA'sı veya NER kapasitesi çıkarılamaz.

## 4. Doğrulanmayan ve dağıtımdan önce gerekli olanlar

Gerçek TR/EN modellerinin çıkarımı/kalitesi, gerçek model bağımlılıklarının pin/hash/CVE kontrolleri, bağımsız kurum verisi üzerinde kaçırma ve yanlış-pozitif oranları, AIDR'nin bütün gönderim kanallarına bağlanma, gerçek host egress izolasyonu, hedef OS testleri, yük/soak/kaos testleri, üçüncü taraf pentest ve müşteri kabulü tamamlanmadı.

Npm geliştirme bağımlılıkları için registry-backed lock oluşturma denemesi çevrimdışı cache eksikliğiyle başarısız oldu; başarılmış gibi gösterilmedi. Paket sürümleri sabit, derlenmiş çekirdek hazırdır; onaylı yeniden üretilebilir build ve tam deployment SBOM/CVE taraması kalan release kapılarıdır.

`defense` profilinde NER yoksa veya Türkçe/İngilizce PERSON + ADDRESS yetenekleri dil bazında eksikse motor **ham metni geçirmez**. Bu teslimi gerçek NER kapsamı tamamlanmadan savunma kurumuna “production ready” diye sunmak doğru olmaz.

Model incelemesi: `../docs/MODEL_REVIEW.md`  
Kabul/dağıtım kapıları: `../docs/DEPLOYMENT.md`  
Tehdit modeli: `../SECURITY.md` ve `../docs/ARCHITECTURE.md`

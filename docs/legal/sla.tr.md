# Destek ve hizmet düzeyi eki (SLA)

> **TASLAK — hukuk/iş onayı gerekir.** Bugün onaylı ya da personeli atanmış
> destek saati, yanıt süresi, nöbet ya da hizmet kredisi yoktur
> ([destek şablonu](../production-readiness/support-sla-template.md)). Köşeli
> parantezdeki sayılar pazarlık için öneridir, taahhüt değildir; bu ek
> onaylanmadan ve nöbet listesi kurulmadan teklife, sözleşmeye ya da durum
> sayfasına kopyalamayın. İngilizce sürüm: [sla.en.md](sla.en.md).
> Sürüm: taslak 0.1, 14.10.2026.
>
> **Yürürlükte bir SLA yoktur.** §4'teki aylık %99,9 erişilebilirlik rakamı
> ticari kararın taslak hedefidir; sözleşme kanıtı açıktır (COM-013, CLAIM-014,
> [iddia kaydı](../production-readiness/commercial-go-evidence-registry.json)) ve
> ölçülecek canlı bir barındırılan hizmet yoktur. Satış metinleri bunu yalnız
> sözleşmeye bağlı bir taslak hedef olarak anabilir.

## 1. Kapsam

Bu ek, Singularity AIDR Son Kullanıcı Lisans Sözleşmesinin ekidir ve Sipariş
Formundaki destek düzeyine (`AIDR-SUP-STD`, `AIDR-SUP-ADV` ya da
`AIDR-SUP-CRT`) uygulanır. [Desteklenen sürümler politikasında](../security/supported-versions.md)
desteklenen olarak listelenen sürümleri, [uyumluluk matrisindeki](../compatibility-matrix.md)
platform ve AI ajan aracı sürümleri üzerinde kapsar.

## 2. Önem dereceleri

Müşteri talebi açarken bir önem derecesi önerir; SingularityRD bunu yazılı
gerekçeyle onaylar ya da değiştirir. Kanıt değiştikçe derece değişebilir.

| Derece | Tanım | Örnekler |
|---|---|---|
| **1 — Kritik** | Üretimde koruma kaybedildi ya da kontrol sunucusu kullanıcıların çoğu için çalışmıyor, veya ürünle ilgili bir güvenlik olayından şüpheleniliyor; geçici çözüm yok | Bir güncellemeden sonra tüm filoda her araç çağrısı reddediliyor; imzalı politika yüklenemiyor ve `remote_policy_required` kayıtlı her ajanı durduruyor; imza anahtarının ele geçirildiği şüphesi; bir kiracının verisi başka kiracıya görünüyor |
| **2 — Yüksek** | Önemli bir işlev çalışmıyor ya da ciddi biçimde bozuk; geçici çözüm var ama sürdürmesi zor | Yeni cihazlar kaydolamıyor; onaylar panelde karara bağlanamıyor; SIEM iletimi durdu |
| **3 — Orta** | Bir işlev yanlış çalışıyor, makul bir geçici çözüm var | Yaygın bir geliştirici komutunda yanlış pozitif; bir panel raporu yanlış sayı gösteriyor |
| **4 — Düşük** | Soru, belge hatası, özellik isteği | Nasıl yapılır soruları; bir mesajın ifadesi |

## 3. Yanıt hedefleri (öneri)

"Yanıt", yetkin bir mühendisin talebi aldığını bildirip çalışmaya başlamasıdır;
çözüm değildir. Süreler yalnız destek düzeyinin kapsama saatlerinde işler;
`CRT` düzeyinde Derece 1 bunun dışındadır.

| Derece | Standart (`STD`) | Gelişmiş (`ADV`) | Kritik (`CRT`) |
|---|---|---|---|
| 1 | [4] iş saati | [2] saat, uzatılmış saatler | [1] saat, 7/24 |
| 2 | [1] iş günü | [4] iş saati | [4] iş saati |
| 3 | [2] iş günü | [1] iş günü | [1] iş günü |
| 4 | [5] iş günü | [3] iş günü | [3] iş günü |

| Kapsama | Standart | Gelişmiş | Kritik |
|---|---|---|---|
| Saatler | İş günleri 09:00–18:00 (TSİ), resmî tatiller hariç | İş günleri 08:00–20:00 TSİ | Gelişmiş + Derece 1 için 7/24 |
| Kanallar | Bilet portalı, e-posta | + adlandırılmış destek sorumlusu, mesai içinde telefon | + Derece 1 için nöbet telefonu |
| Dil | Türkçe, İngilizce | Türkçe, İngilizce | Türkçe, İngilizce |
| Açık Derece 1'de güncelleme | Her [iş günü] | Her [4] saatte | Her [2] saatte |
| Gözden geçirme | — | Üç ayda bir hizmet toplantısı | Üç ayda bir hizmet toplantısı |

Çözüm süresi garantisi yoktur. Derece 1'de SingularityRD, bir düzeltme,
geçici çözüm ya da geri alma korumayı yeniden sağlayana kadar (kapsama
saatlerinde) kesintisiz çalışır.

## 4. Erişilebilirlik (yalnız barındırılan hizmet)

Şirket içi ve internetsiz kurulumları müşteri işletir; erişilebilirlikleri
müşterinin altyapısına bağlıdır ve bir erişilebilirlik hedefine tabi değildir.
Kontrol sunucusu çalışmazken uç noktalardaki tespit devam eder.

Barındırılan kontrol sunucusu için panel ve API'nin aylık **[%99,9]**
erişilebilirlik hedefi önerilir: `(uygun dakika − erişilemeyen dakika) / uygun
dakika`; duyurulmuş bakım (en az [5] iş günü önceden, ayda en çok [8] saat, TSİ
mesai dışında) ve SingularityRD'nin kontrolü dışındaki nedenler hariç. Hizmet
kredisi: hedefin altında aylık bedelin [%10]'u, [%99,0] altında [%25]'i; aylık
üst sınır [%25]; [30] gün içinde yazılı talep üzerine. Barındırılan hizmet bugün
müşteri kullanımı için kabul edilmemiştir ([SaaS kurulumu](../deployment/saas.md));
bu bölüm ancak kabulden sonra uygulanır.

## 5. Müşterinin yükümlülükleri

- En fazla [3] (STD) / [5] (ADV, CRT) yetkili irtibat kişisi bildirmek.
- Desteklenen sürümleri kullanmak ve güvenlik güncellemelerini makul sürede
  uygulamak.
- Tanılamayı onaylı destek paketiyle vermek ([destek süreci](../runbooks/support-process.md));
  talepte asla kimlik bilgisi, istem ya da müşteri verisi göndermemek.
- Şirket içi kurulumda: [on-prem runbook'unda](../operations/onprem-runbook.md)
  anlatılan yedekleme, saat eşitleme (NTP) ve izlemeyi sürdürmek; anlaşıldığında
  uzaktan ya da yerinde erişim sağlamak.

## 6. Kapsam dışı

Desteklenmeyen sürüm ya da platformlar; uyumluluk matrisinde olmayan araç
sürümleri; müşterinin ürüne, veritabanına ya da üretilen yapılandırmaya yaptığı
değişiklikler; üçüncü taraf AI ajan araçlarından ya da AI sağlayıcılarından
kaynaklanan sorunlar; deneme (POC) lisansları (yalnız makul çaba ile destek).

## 7. Üst kademeye taşıma

Bir talep beklendiği gibi ilerlemezse müşteri önce destek yöneticisine, sonra
[CTO / kurucuya] başvurabilir. İrtibat bilgileri Sipariş Formundadır. Güvenlik
olayları olay müdahale runbook'una göre yürütülür ve müşteriye olay
komutanının kim olduğu bildirilir.

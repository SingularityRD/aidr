# Şirket içi (on-prem) teklif şablonu ve SKU yapısı (TRY)

> **TASLAK — hukuk/iş onayı gerekir.** İç kullanım içindir, müşteriye bu hâliyle
> gönderilmez. Tutarların hepsi yer tutucudur (`₺[____]`); hiçbir rakam onaylı
> fiyat değildir. Fiyatlar yayımlanmaz
> ([edisyonlar ve teklif esaslı fiyatlama](pricing.md), 25.09.2026 kararı); bir
> teklif yalnız tek bir müşteriye, yazılı ve imzalı olarak verilir. Finans
> onayı (COM-001) ve hukuk onayı olmadan teklif çıkmaz.
>
> Sahibi: Kurucu (iş) · Onaylayacaklar: Finans, Hukuk · Son güncelleme: 14.10.2026

Bu belge üç şey içerir: (1) şirket içi satış için SKU yapısı, (2) müşteriye
gidecek TRY teklif şablonu, (3) teklif onayından tahsilata kadar iç akış. e-Fatura
ve e-Arşiv adımları ayrı listededir:
[e-Fatura / e-Arşiv kontrol listesi](e-fatura-kontrol-listesi.tr.md).

## 1. SKU yapısı

Kod biçimi: `AIDR-<EDİSYON>-<KURULUM>-<SÜRE>-<KADEME>`. Ek ürünler `AIDR-ADD-...`,
hizmetler `AIDR-SVC-...` ile başlar. Lisans birimi **koltuktur** (bir kişi; tanım
[EULA taslağı](../legal/eula.tr.md) madde 3). Lisans her zaman süreli
(abonelik) verilir; süresiz (perpetual) lisans bu yapıda yoktur.

### Edisyonlar

| Kod | Edisyon | Kapsam (özet, [pricing.md](pricing.md) ile aynı) | Asgari koltuk |
|---|---|---|---|
| `BUS` | Business | Şirket içi kontrol sunucusu (Docker Compose), SIEM iletimi, SCIM, AI güvenlik duruşu, 365 gün olay saklama | 25 |
| `ENT` | Enterprise | Business + Kubernetes (Helm), sözleşmeye bağlı saklama, özel destek, özel koşullar | Anlaşmaya göre (öneri: 100) |

### Kurulum türü

| Kod | Anlamı |
|---|---|
| `ONP` | Müşterinin sunucusunda, internete çıkabilen kontrol sunucusu |
| `AGP` | İnternetsiz (air-gapped) kurulum. Yalnız `ENT` ile; hava boşluğu ek ürünü (`AIDR-ADD-AIRGAP`) zorunludur |

### Süre

| Kod | Süre | Not |
|---|---|---|
| `12M` | 12 ay | Varsayılan |
| `24M` | 24 ay | İndirim kaldıracı yalnız taahhüt süresidir ([pricing.md](pricing.md) §5) |
| `36M` | 36 ay | Kamu ve savunmada bütçe dönemine göre |
| `POC30` | 30 gün deneme | Ücretsiz, üretim dışı; [POC kiti](poc-kiti.tr.md) |

### Koltuk kademeleri

Birim fiyat kademeye göre düşer; kademe, toplam koltuk sayısına göre seçilir
(tümü o kademenin birim fiyatıyla).

| Kademe kodu | Koltuk | Birim fiyat (koltuk / yıl, KDV hariç) |
|---|---|---|
| `T025` | 25–99 | `₺[____]` |
| `T100` | 100–249 | `₺[____]` |
| `T250` | 250–499 | `₺[____]` |
| `T500` | 500–999 | `₺[____]` |
| `T1K` | 1.000 ve üzeri | Proje bazlı, `₺[____]` |

Örnek SKU: `AIDR-ENT-AGP-12M-T250` = Enterprise, internetsiz, 12 ay, 250–499 koltuk kademesi.

### Destek düzeyleri

Tanımlar ve hedef süreler [destek SLA taslağındadır](../legal/sla.tr.md); hiçbiri
onaylı taahhüt değildir.

| Kod | Düzey | Kapsam | Fiyatlama |
|---|---|---|---|
| `AIDR-SUP-STD` | Standart | İş günleri 09:00–18:00 (TSİ), e-posta + bilet; Business'a dahil | Lisansa dahil |
| `AIDR-SUP-ADV` | Gelişmiş | Standart + uzatılmış saatler, adlandırılmış destek sorumlusu, çeyreklik gözden geçirme | Lisans bedelinin `%[__]`'i |
| `AIDR-SUP-CRT` | Kritik | Gelişmiş + yalnız Derece 1 (kritik) için 7/24 ulaşılabilirlik | Lisans bedelinin `%[__]`'i |

`CRT`, nöbet listesi gerçekten kurulmadan satılmaz ([destek süreci](../runbooks/support-process.md)).

### Ek ürünler

| Kod | Ad | Not | Birim | Fiyat |
|---|---|---|---|---|
| `AIDR-ADD-AIRGAP` | Hava boşluğu (air-gap) paketi | İmzalı çevrimdışı güncelleme paketlerinin (kurallar, istihbarat, kurulum dosyaları, Browser Guard) taşınabilir ortamla düzenli teslimi; teslim takvimi siparişte yazılır | Yıllık, kurulum başına | `₺[____]` |
| `AIDR-ADD-POSTURE` | AI güvenlik duruşu tarayıcısı | Business ve üstünde kapsamda; ayrı sunucu kaynağı gerekir | Dahil / `₺[____]` | — |
| `AIDR-ADD-PRIVGW` | Gizlilik ağ geçidi (privacy gateway) | NER modeli kabulü kapanana kadar satılmaz ([pricing.md](pricing.md)) | — | Satışta değil |
| `AIDR-ADD-BGONLY` | Yalnız Browser Guard koltuğu | Açık soru ([pricing.md](pricing.md) §7 soru 1); onaylanmadan teklife girmez | — | Karar bekliyor |
| `AIDR-ADD-ESCROW` | Kaynak kod emaneti | [Emanet teklif şablonu](../legal/kaynak-kod-emaneti-teklif.md) | Yıllık | `₺[____]` + emanetçi ücreti |

### Hizmetler

| Kod | Ad | Birim | Fiyat |
|---|---|---|---|
| `AIDR-SVC-INSTALL` | Kurulum ve devreye alma (uzaktan ya da yerinde) | Adam/gün | `₺[____]` |
| `AIDR-SVC-POC` | Ücretli POC desteği (30 günü aşan ya da yerinde POC) | Adam/gün | `₺[____]` |
| `AIDR-SVC-TRAIN` | Yönetici / SOC eğitimi (TR) | Oturum | `₺[____]` |
| `AIDR-SVC-HC` | Yıllık sağlık kontrolü ve sürüm yükseltme desteği | Yıllık | `₺[____]` |

Yol, konaklama ve yerinde çalışma giderleri ayrıca faturalanır ya da teklife
götürü olarak yazılır.

## 2. Teklif şablonu (müşteriye giden metin)

Aşağıdaki metin müşteriye gönderilecek teklifin iskeletidir. Köşeli parantezleri
doldurun; hiçbir alanı boş bırakmayın. Teklifi PDF olarak ve imzalı (ıslak imza
ya da e-imza) gönderin.

```text
SingularityRD [tam unvan]                         TEKLİF No: AIDR-Q-[YYYY]-[NNNN]
[Adres] · [Vergi dairesi / VKN] · [MERSİS]        Tarih: [GG.AA.YYYY]
[KEP adresi] · [e-posta] · [telefon]              Geçerlilik: [GG.AA.YYYY] (30 gün)

Sayın [Müşteri tam unvanı]
[Adres] · [Vergi dairesi / VKN] · [KEP adresi]
İlgili kişi: [Ad Soyad, unvan]

Konu: Singularity AIDR şirket içi lisans ve hizmet teklifi

Kalem  SKU                        Açıklama                              Miktar  Birim fiyat   Tutar
1      AIDR-ENT-ONP-12M-T250      Enterprise, şirket içi, 12 ay          300 koltuk  ₺[____]   ₺[____]
2      AIDR-SUP-ADV               Gelişmiş destek, 12 ay                 1       ₺[____]       ₺[____]
3      AIDR-ADD-AIRGAP            Hava boşluğu paketi, 12 ay             1       ₺[____]       ₺[____]
4      AIDR-SVC-INSTALL           Kurulum ve devreye alma                [3] gün ₺[____]       ₺[____]
                                                                         Ara toplam             ₺[____]
                                                                         KDV (%[20])            ₺[____]
                                                                         GENEL TOPLAM           ₺[____]

Koşullar
1. Lisans süresi: lisans dosyasının düzenlendiği tarihten itibaren [12] ay.
   Başlangıç: [GG.AA.YYYY]  Bitiş: [GG.AA.YYYY]  Lisans ek süresi (grace): [__] gün.
2. Fiyatlar Türk lirasıdır ve KDV hariçtir. [Seçenek A: Sabit TRY.]
   [Seçenek B: Fiyatlar USD/EUR bazlıdır; fatura tarihindeki TCMB döviz satış
   kuru ile TRY'ye çevrilerek faturalanır.]
3. Ödeme: faturanın tebliğinden itibaren [30] gün içinde [IBAN: TR__ ____ ...] hesabına.
4. Fatura: e-Fatura (alıcı GİB'e kayıtlıysa) ya da e-Arşiv fatura olarak
   [lisans dosyasının tesliminde / siparişte] düzenlenir.
5. Teslim: imzalı lisans dosyası, müşteri kurulum paketi ve imza doğrulama
   anahtarı [güvenli teslim kanalı] üzerinden; internetsiz kurulumda
   [taşınabilir ortam / yerinde teslim].
6. Kullanım koşulları: Singularity AIDR Son Kullanıcı Lisans Sözleşmesi
   [sürüm], Veri İşleme Sözleşmesi [sürüm], Destek Eki [sürüm].
7. Koltuk artışı: dönem içinde eklenen koltuklar dönem sonuna kadar kıst
   (pro-rata) faturalanır. Yenilemede koltuk sayısı müşteri kullanım
   raporuna (aidr-usage-report-v1) göre güncellenir.
8. Lisans süresi bittiğinde yönetilen özellikler ek süreden sonra durur;
   uç noktalardaki yerel tespit çalışmaya devam eder. Güncellemeler yalnız
   lisans süresi boyunca verilir.
9. Bu teklif [Müşteri] tarafından imzalanıp iade edildiğinde ya da teklife
   atıf yapan bir satın alma siparişi gönderildiğinde sipariş yerine geçer.

SingularityRD adına                               [Müşteri] adına (kabul)
[Ad Soyad, unvan, imza]                           [Ad Soyad, unvan, imza, tarih]
```

### Kamu ve savunma alıcıları için ek notlar

- Doğrudan temin ya da ihale (4734 sayılı Kamu İhale Kanunu) yoluna alıcı karar
  verir; teklif, alıcının yaklaşık maliyet çalışmasına girdi olarak
  istenebilir. EKAP kaydı, teminat mektubu ve ihale belgeleri ayrı iş
  kalemidir.
- Yerli Malı Belgesi (yazılım için) kamu ihalelerinde fiyat avantajı
  sağlayabilir; başvuru ve uygunluk değerlendirilecek. Belge alınmadan
  teklifte "yerli malı" ifadesi kullanılmaz.
- Kamu alıcılarında KDV tevkifatı uygulanıp uygulanmayacağı ve oranı muhasebe
  ve mali müşavir tarafından fatura öncesinde teyit edilir.
- Gizlilik dereceli projelerde personel güvenlik soruşturması, tesis güvenlik
  belgesi ve yerinde çalışma kuralları teklif öncesinde sorulur.

## 3. İç akış: teklif → sipariş → lisans → fatura → tahsilat

| Adım | Sorumlu | Kayıt / çıktı |
|---|---|---|
| 1. Kapsam: koltuk sayısı, kurulum türü (ONP/AGP), edisyon, destek, ek ürünler | Satış | Keşif notu, [ideal müşteri profili](ideal-customer-profile.md) kontrolü |
| 2. Teklif taslağı bu şablondan; indirim yalnız taahhüt süresiyle | Satış | `AIDR-Q-YYYY-NNNN` |
| 3. Finans onayı (fiyat, ödeme vadesi, kur seçeneği) | Finans | Onay e-postası teklif kaydına eklenir |
| 4. Hukuk onayı (EULA/DPA/SLA sürümleri, sapmalar) | Hukuk | Sapma listesi |
| 5. İmzalı teklif ya da satın alma siparişi | Müşteri | PO no. |
| 6. Müşteri kaydı ve lisans: koltuk, bitiş, plan, müşteri kimliği | Operasyon | /admin müşteri kaydı; imzalı `aidr-license-v1` ([lisanslama](../operations/licensing.md), [müşteri derlemeleri](../operations/customer-builds.md)) |
| 7. Fatura (e-Fatura / e-Arşiv) | Muhasebe | [Kontrol listesi](e-fatura-kontrol-listesi.tr.md); ETTN teklif kaydına yazılır |
| 8. Teslim: lisans dosyası, kurulum paketi, doğrulama talimatı | Operasyon | Teslim makbuzu (SHA-256 değerleri) |
| 9. Tahsilat takibi; vadesi geçen alacakta yalnız yönetilen özellikler etkilenir, yerel tespit kapatılmaz | Finans | Tahsilat kaydı |
| 10. Yenileme: bitişten 60 ve 30 gün önce hatırlatma, kullanım raporu talebi | Satış | Yenileme teklifi |

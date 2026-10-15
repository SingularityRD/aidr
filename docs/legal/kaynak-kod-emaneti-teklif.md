# Kaynak kod emaneti (escrow) teklif şablonu / Source-code escrow offer template

> **TASLAK — hukuk/iş onayı gerekir. DRAFT — legal/business approval
> required.** Emanetçi (escrow agent) seçilmemiştir; bu şablondaki emanetçi,
> ücret ve süreler yer tutucudur. No escrow agent has been engaged; names, fees
> and timelines are placeholders. Sürüm: taslak 0.1, 14.10.2026.

Kamu, savunma ve kritik altyapı müşterileri, satıcının faaliyetini sürdürememesi
hâlinde ürünü bakımını kendileri ya da bir üçüncü tarafla yapabilmek için
kaynak kod emaneti ister. Bu şablon, Enterprise teklifine ek ürün
(`AIDR-ADD-ESCROW`) olarak eklenir ([teklif şablonu](../sales/onprem-teklif-sablonu.tr.md)).

## 1. Teklif metni (TR)

**Konu:** Singularity AIDR kaynak kod emaneti

1. **Emanetçi.** Kaynak kod, taraflardan bağımsız bir emanetçide tutulur:
   [Emanetçi kuruluşun unvanı — ör. bir noter, bir teknoloji emanet şirketi ya
   da bir TÜBİTAK/üniversite teknoloji transfer ofisi; hukuk seçecek].
   Sözleşme üç taraflıdır: SingularityRD, Müşteri, Emanetçi.
2. **Emanete konan malzeme.** Müşterinin lisanslı sürümüne karşılık gelen:
   - kaynak kod deposunun tam anlık görüntüsü (git paketi, imzalı etiket ve
     commit SHA'sı ile),
   - derleme talimatları, sabitlenmiş bağımlılık kilit dosyası ve çevrimdışı
     derleme için bağımlılık arşivi,
   - kurulum ve işletim belgeleri, tehdit kuralları (YAML) ve veritabanı
     taşıma (migration) dosyaları,
   - üçüncü taraf bileşen listesi ve lisansları (SBOM).
   Üretim imza anahtarları ve diğer müşterilere ait veriler emanete **konmaz**.
3. **Güncelleme.** Her ana ya da küçük sürümde ve en az [6] ayda bir
   emanetteki malzeme yenilenir. Emanetçi her teslimde bir teslim tutanağı
   (dosya özetleri ile) düzenler.
4. **Doğrulama (isteğe bağlı).** Müşteri, ücretini ödeyerek emanetçiden ya da
   bağımsız bir uzmandan malzemenin derlenebildiğinin doğrulanmasını
   isteyebilir ("derleme doğrulaması"). Doğrulama SingularityRD'nin
   gözetiminde ve gizlilik taahhüdüyle yapılır.
5. **Teslim koşulları (release conditions).** Emanetçi malzemeyi yalnız
   şu hâllerde ve belgelendirildiğinde Müşteriye teslim eder:
   - SingularityRD'nin iflası, tasfiyesi ya da konkordato ile faaliyetini
     durdurması,
   - SingularityRD'nin ürünü sürdürmeyi yazılı olarak bırakması ve bir halef
     göstermemesi,
   - destek ekindeki Derece 1 (kritik) yükümlülüklerin, yazılı ihtara rağmen
     [60] gün boyunca esaslı olarak yerine getirilmemesi.
   SingularityRD'nin teslim talebine [15] gün içinde itiraz hakkı vardır;
   uyuşmazlık [hakem / mahkeme — hukuk] tarafından çözülür.
6. **Kullanım hakkı.** Teslim hâlinde Müşteri, kaynak kodu yalnız kendi iç
   kullanımı için, lisanslı koltuk ve kapsamla sınırlı olarak bakım, hata
   düzeltme ve güvenlik güncellemesi amacıyla kullanabilir; üçüncü kişilere
   satamaz ve dağıtamaz. Bu iş için tutacağı yükleniciler gizlilik taahhüdü
   altında olur. EULA'daki tersine mühendislik yasağı bu kullanım için
   kaldırılmış sayılır.
7. **Ücret.** Emanet hizmeti yıllık `₺[____]` (emanetçi ücreti dahil /
   hariç); derleme doğrulaması `₺[____]` / gün.
8. **Süre.** Emanet, lisans süresi ve yenilemeleri boyunca devam eder;
   lisans sona ererse emanet de sona erer ve malzeme SingularityRD'ye iade
   edilir ya da imha edilir (tutanakla).

## 2. Offer text (EN, short form)

SingularityRD offers to deposit the Singularity AIDR source code for the
customer's licensed version with an independent escrow agent [to be selected]
under a three-party agreement. The deposit (full repository snapshot with
signed tag, build instructions, pinned lock file and offline dependency
archive, operating documentation, threat rules, database migrations and SBOM;
never production signing keys or other customers' data) is refreshed on every
major or minor release and at least every [6] months. Release to the customer
only on documented insolvency or liquidation, written discontinuation without a
successor, or a material failure of critical support obligations not cured
within [60] days of notice; SingularityRD may object within [15] days. On
release the customer may use the code internally, within its licensed scope,
only to maintain, fix and secure the product. Fee: `TRY [____]` per year, plus
optional build verification at `TRY [____]` per day.

## 3. Hazırlık kontrol listesi (iç)

- [ ] Emanetçi seçildi, üç taraflı sözleşme şablonu hukukça onaylandı.
- [ ] Emanet paketi üreten tekrarlanabilir bir komut (git bundle + kilit
      dosyası + bağımlılık arşivi + SBOM + özet listesi) hazırlandı ve bir
      temiz makinede derleme denendi.
- [ ] Paket özetleri teslim tutanağına ve müşteri kaydına yazılıyor.
- [ ] Yenileme takvimi sürüm takvimine bağlandı.

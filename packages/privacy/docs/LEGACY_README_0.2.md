# Singularity AIDR Privacy — 0.2.0-rc.1

Türkçe/İngilizce metin DLP çekirdeğine **ekran görüntüsü / görsel ek kontrolü** eklendi.

**[Görsel modülünü kurma ve API](VISUAL.md)** · **[Gerçek test raporu](../reports/visual/TEST_REPORT.md)** · **[Güven modeli](VISUAL_THREAT_MODEL.md)** · **[Üretime alma kapıları](VISUAL_DEPLOYMENT.md)**

Yeni subpath: `@singularityrd/aidr-privacy/visual`. Yeni CLI: `aidr-visual`. Yerel Tesseract eng+tur, PNG/JPEG/WebP, siyah piksel maskelemesi, bağımsız PNG doğrulaması ve atomic multimodal gönderim. Yerel Python/native bağımlılıkları ayrıca kurulur; OCR ağırlıkları/fontlar pakete dahil değildir.

**628 birim/entegrasyon testi + ayrı 8 gerçek OCR pipeline testi geçti.** Beş sentetik PII görselindeki 29 hassas satırın glif sınırları piksel düzeyinde kontrol edildi. Bu sayılar genel OCR/NER başarım yüzdesi değildir. `release:'manual'` varsayılanı hiçbir görsel yayımlamaz; otomatik modu açıkça seçmek gerekir. Gerçek NER değerlendirmesi, kurumsal egress entegrasyonu ve üretim kabulü tamamlanmış değildir.

Aşağıdaki bölüm önceki metin modülünün kullanım ve kapsam bilgisidir. Buradaki 0.1.0 rapor/benchmark sayıları tarihsel baseline'dır; 0.2.0 test sonucu için yukarıdaki görsel test raporunu kullanın.

---

# Singularity AIDR Privacy

**Türkçe / İngilizce, yerel çalışan PII ve sır maskeleme çekirdeği**  
Sürüm: `0.1.0-rc.1` · TypeScript / Node.js · Üretim çalışma zamanı bağımlılığı: **0**

> Durum: çalıştırılmış ve test edilmiş **üretime hazırlık adayı**. BMC veya başka bir savunma kurumunda doğrulanmış, sertifikalı ya da bağımsız benchmark ile piyasadan üstün olduğu kanıtlanmış bir ürün değildir. Serbest metindeki kişi/adres kapsamı, onaylı gerçek NER modelleri eklenmeden tamamlanmış sayılmaz. Bu teslimde gerçek model çıkarımı çalıştırılmadı; ağırlıklar dahil değildir.

## Hemen çalıştır

Teslim bütünlüğünü, raporları yeniden üretmeden önce `node scripts/verify-release.mjs` ile kontrol edebilirsin. Benchmark/evaluation raporlarını yeniden çalıştırmak tarih ve ölçümleri değiştirir; bundan sonra eski teslim hash'leriyle fark görülmesi beklenir.

Tam kaynak ZIP'inde derlenmiş `dist/` dizini bulunur. Node.js 22.16.0 ile test edilmiştir. Aşağıdaki komutlar, çekirdek için paket veya model indirmeden çalışır:

```sh
node examples/demo.mjs
node --test tests/*.test.mjs
python3 -m unittest discover -s ner -p 'test_*.py' -v
node scripts/benchmark.mjs
node scripts/evaluate.mjs
```

Python komutu yalnızca Python standart kütüphanesini kullanır; model çalıştırmaz. Windows'ta `python3` yerine kurulumuna göre `python` kullanılabilir. Windows üzerinde bu teslimin testleri çalıştırılmamıştır.

CLI girdiyi komut argümanından değil standart girdiden alır:

```sh
node dist/cli.js < input.txt
node dist/cli.js --redact < input.txt
node dist/cli.js --json < tool-arguments.json
```

`0`: geçerli, gönderilebilir karar. `2`: block/review veya girdi hatası. `64`: hatalı CLI seçeneği. CLI JSON çıktısındaki yalnızca izin verilen `output` gönderilebilir; bütün sonuç nesnesi bir modele gönderilmemelidir.

Kaynağı yeniden derlemek için onaylı geliştirme ortamında `npm install --ignore-scripts`, ardından `npm run build` gerekir. Testte kullanılan derleyici `typescript@5.8.3`, tip tanımları `@types/node@22.19.7` idi. Paket sürümleri sabitlenmiştir; bu ortamda registry erişimi olmadığından yeniden üretilebilir bağımlılık kilidi/CVE taraması tamamlanmamıştır. Üretim release kapısı için `docs/DEPLOYMENT.md` dosyasına bak.

## AIDR entegrasyonu

Tam kaynak paketten doğrudan:

```ts
import { PrivacyEngine } from './dist/index.js';

const privacy = new PrivacyEngine({
  profile: 'strict',
  mask: 'label',
  policyId: 'aidr-egress-v1',
  literals: [{ value: 'PROJECT-ORION-TEST', type: 'INTERNAL' }],
  actions: { INTERNAL: 'block', PRIVATE_KEY: 'block' },
});

const result = await privacy.protect(
  'Ad Soyad: Ahmet Yılmaz; E-posta: ahmet@example.com; Telefon: 0532 123 45 67',
);

if (result.output === null || !['allow', 'redact'].includes(result.decision)) {
  throw new Error('AIDR_EGRESS_DENIED');
}

// Dış servise yalnızca result.output gönderilir. Ham metne geri dönüş YOKTUR.
console.log(result.output);
// Ad Soyad: [PERSON]; E-posta: [EMAIL]; Telefon: [PHONE]

privacy.dispose();
```

Dağıtım `.tgz` paketinden monorepoya yerel bağımlılık olarak eklenebilir. Ardından import yolu `@singularityrd/aidr-privacy` olur. `examples/aidr-tool-guard.mjs` örneği JSON tool çağrılarının gönderim öncesi denetimini gösterir; mevcut AIDR interceptörlerine kendiliğinden bağlanmaz.

## Gerçekte neler var?

| Alan | Dahil edilen davranış | Kapsam sınırı |
|---|---|---|
| E-posta | Türkçe karakterler, yaygın uluslararası alan adları, açık `[at]`/`[dot]`, seçili kodlamalar | Tam RFC e-posta doğrulayıcısı değildir |
| Telefon | TR mobil/sabit, `+90`/`0090`, ABD yaygın biçimleri, uluslararası `+` biçimi | Bütün ülkelerin numaralandırma planları doğrulanmaz |
| T.C. kimlik | Biçim + kontrol basamakları + açık alan bağlamı | Kayıt/kişiye aidiyet sorgulamaz |
| IBAN | 44 ülkelik açık uzunluk listesi + mod-97; TR/DE için ek karakter yapısı | Tüm ülkeler/BBAN kuralları/banka varlığı doğrulanmaz |
| Kart | 13–19 hane, Luhn, açık alan bağlamı | Kartın gerçek/aktif olduğunu doğrulamaz |
| SSN | ABD 3-2-4 biçimi ve yapısal aralık kontrolleri | Kimlik doğrulaması yapmaz; etiketsiz tüm biçimleri yakalamaz |
| Kişi / adres | TR/EN alan etiketleri, bazı tanıtım/unvan/sokak kalıpları, hassas JSON anahtarları | Bunlar **NER değil**; serbest metin eksiksizliği yok |
| Ek PII | Doğum tarihi, pasaport, vergi/ulusal kimlik, hesap numarası için bağlam/şema | Her ülkenin belge biçimi için ayrı doğrulayıcı yok |
| Sırlar | API anahtarı biçimleri, password/token alanları, Bearer/Basic, JWT, URI kimlik bilgisi, PEM özel anahtar | Her sağlayıcı/özel token biçimini kapsamaz |
| Kurum verisi | IP/MAC, yönetici tanımlı literal sözlük; belirli sınıflandırma işaretleri | Genel kaynak kodu veya askeri gizlilik sınıflandırıcısı değil |
| Maskeleme | Tür etiketi, sabit redaksiyon, tenant ayrımlı HMAC token | Geri döndürülebilir kasa ve sahte kişi üretimi yok |
| Politika | allow / redact / review / block | review çıktısı `null`; onay iş akışı üst üründe |
| JSON | Anahtar ve değer taraması, hassas alan/subtree maskeleme, duplicate-key/prototype/depth kontrolleri | Maskeleme sayı/nesne tipini marker string'e çevirebilir |
| Akış | Tam mesajı tamponlayan, inceleme öncesi **hiçbir byte salmayan** kapı | Gerçek zamanlı parça parça temiz metin yayını değil |
| NER bağlama | Yerel süreç protokolü, hata/zaman aşımı, artefakt SHA-256 doğrulama, Python worker kaynağı | Gerçek model ağırlıkları/çalıştırılmış NER kalite sonucu yok |

`ENTITY_TYPES` 23 sınıf içerir. **23 sınıf = 23 eksiksiz öğrenilmiş dedektör değildir.** `USERNAME`, `HEALTH_ID`, `LICENSE_PLATE` ağırlıklı olarak şema/custom/NER kanalıyla; `LOCATION` NER/custom kanalından desteklenir.

## Profiller

**balanced:** Kurallar ve yapılandırılmış NER çalışır. Açık kodlamalar çözülür; bazı opak-kodlama/bidi politikaları strict kadar kısıtlayıcı değildir. Kısıt ihlali veya takılı NER yine block üretir.

**strict (varsayılan):** Ek olarak seçili bidi kontrolleri, belirgin base64/hex işaretleri ve uzun opak token biçimleri engellenir. Hatalı/tamamlanmamış girdiler sessizce geçirilemez. Kuralsız serbest kişi/adres alanında NER yoksa kapsam sınırlıdır.

**defense:** Türkçe ve İngilizce için PERSON + ADDRESS yeteneklerini **dil bazında** bildiren yerel NER zorunludur. NER yoksa `NER_REQUIRED`; eksik kapsam varsa `NER_CAPABILITY_MISSING`. SECRET / PRIVATE_KEY / INTERNAL da bloklanır. CLASSIFIED bütün profillerde bloklanır. Modelde düşük güvenli pozitif bulgu varsa review/null üretilir. Modelin kaçırdığı varlıkları bu mekanizma kendiliğinden bulamaz.

Modelin dil/etiket beyanı ölçülmüş kalite garantisi değildir. Sırf profile `defense` yazmak, savunma kurumu dağıtımını güvenli veya mevzuata uyumlu yapmaz.

## Token modu

```ts
import { readFileSync } from 'node:fs';
import { PrivacyEngine } from './dist/index.js';

const privacy = new PrivacyEngine({
  profile: 'strict',
  mask: 'token',
  tenantId: 'tenant-bound-by-authentication',
  keyId: 'k2026a',
  tokenKey: readFileSync('/run/secrets/aidr-pii-hmac'), // 32–128 byte
});
```

Biçim: `[EMAIL~k2026a~24_karakterlik_token]`. Anahtar, tenant, tür ve key ID HMAC girdisine bağlanır. Ham SHA-256 kullanılmaz. Aynı tenant/anahtar/tür/kanonik değer aynı token'ı üretir; farklı tenant ayrıştırılır. Çıktı 144 bit HMAC kısmı taşır. Bu **takma adlandırmadır (pseudonymization)**, otomatik hukuki anonimleştirme değildir. Eşitlik bilgisi sızdırır; erişim kontrolü ve anahtar yaşam döngüsü gerekir. Tokenlar orijinal değere çevrilemez; vault verilmez. Zaten maskelenmiş alanların tekrar maskelemede birebir aynı kalacağı genel olarak garanti edilmez.

## Yerel NER

`ner/ner_worker.py` yalnızca incelenmiş yerel token-classification modelleriyle kullanılacak bir adaptördür. Otomatik model indirmez; `local_files_only`, `trust_remote_code=False`, safetensors ve manifest envanteri kullanır. CPU yolu vardır. Worker kodu verilir fakat bu ortamda Transformers/tokenizer ve gerçek model ağırlıkları bulunmadığından gerçek çıkarımı **test edilmedi**.

`ner/model-config.example.json` ve `ner/local-provider.example.json` çalışır varsayılanlar değil, açıkça işaretli kurum onayı gerektiren şablonlardır. GLiNER modeli, standart `AutoModelForTokenClassification` worker'ına doğrudan takılamaz; ayrı adaptör gerekir ve bu teslimde yoktur.

İncelenen modeller: `docs/MODEL_REVIEW.md`. Yerel kurulum ve süreç yalıtımı: `docs/DEPLOYMENT.md`.

## Varsayılan sınırlar

64 KiB UTF-8 girdi, 2.048 bulgu, 32 JSON derinliği, 4.096 JSON düğümü, 1.000 ms senkron tarama bütçesi, 5.000 ms NER süresi, motor başına 4 etkin text çağrısı. Atomic gate 30 saniye tutma süresi kullanır. Yerel NER sağlayıcı **tek uçuşlu**dur; üretim havuzu/kuyruğu dahil değildir. JSON isteklerinin üst katmanda ayrıca sınırlandırılması gerekir.

Senkron JS tarama bütçesi kooperatif kontrol edilir; bloke olmuş event loop'u durdurmaz. Güvenilmeyen ağır girdilere karşı worker/process izolasyonu, CPU/bellek sınırı ve upstream hız sınırı zorunludur.

## Testler ve raporlar

- `reports/TEST_REPORT.md`: doğrulanmış sonuçlar ve doğrulanmayanlar.
- `reports/tests.tap`, `reports/coverage.txt`, `reports/python-tests.txt`: gerçek test çıktıları.
- `reports/benchmark.json`: çekirdek gecikme / toplam süreç RSS ölçümü.
- `reports/evaluation.json`: **geliştirici üretimi** regresyon veri kümesinde ölçüm; bağımsız gerçek dünya başarısı değildir.
- `docs/VALIDATION.md`: bağımsız değerlendirme biçimi ve üretim kabul kapıları.

## Dahil olmayan ürün katmanları

Tarayıcı eklentisi, endpoint agent kurulumu, TLS gateway, masaüstü uygulama interception, SSO/RBAC/mTLS, dashboard, SIEM/webhook gönderimi, PDF/OCR/dosya parser'ları, otomatik bütün agent/tool interceptörleri ve imzalı merkezi politika dağıtımı bu paketin parçası değildir. Mevcut AIDR bunları sağlamalıdır. Sağlanmayan kanalı korunan kanal gibi göstermek veri kaybına yol açar.

`SECURITY.md`, `docs/ARCHITECTURE.md` ve `docs/DEPLOYMENT.md` dağıtımdan önce okunmalıdır.

# AIDR Browser Privacy 0.3.0-rc.1 — kurulum ve kullanım

## Teslimin sınırı

Bu sürüm; 0.2.0 metin/görsel motoru üzerine Chrome Manifest V3 eklentisi, tarayıcıya uygun ortak PII çekirdeği, güvenli yazım alanı, yönetilen politikalar, yapılandırılmış dosya temizleme ve yerel Native Messaging köprüsü ekler. Kaynak ve derlenmiş eklenti dosyaları dahildir. Chrome Web Store'da yayımlanmış, imzalanmış bir kurumsal dağıtım değildir.

Gerçek Chromium DOM testleri ve gerçek yerel host/OCR testleri çalıştırıldı. Bu çalışma ortamında kurumsal Chrome politikası eklenti kurulumunu engellediği için **kurulu MV3 eklentisinin kendisi, işletim sistemi native-host kaydı ve oturum açılmış canlı ChatGPT/Gemini/Claude sayfaları doğrulanmadı**. Politikalar değiştirilmedi. Windows/macOS native çalışma zamanı da ayrıca test edilmelidir.

## 1. Yalnız Chrome eklentisini kurma

`extension/chrome` dizini doğrudan yüklenebilir derlenmiş eklenti dizinidir. Ayrı Chrome ZIP'i açıldığında `manifest.json` doğrudan köktedir. JavaScript, CSS ve HTML hazırdır; tarayıcıdaki metin kuralları için Node.js, Python, GPU veya bulut API anahtarı gerekmez.

Yönetici izinli geliştirme/test profilinde Chrome'un eklenti yönetim ekranını aç, **Geliştirici modu → Paketlenmemiş öğe yükle** ile `manifest.json` bulunan klasörü seç. Eklentiyi araç çubuğuna sabitle. Daha önce açık ChatGPT/Gemini/Claude sekmelerini yenile. Kurumsal politika kurulumu yasaklıyorsa bunu değiştirmeye çalışma; BT ekibinin onaylı dağıtımı gerekir.

Geliştirme paketi kimliği: `hmcbdjjldiobifmolecnmalilknnapcb`. Bu yalnız paketle gelen açık anahtarın belirlediği geliştirme kimliğidir. Yayınlanan imzalı paket farklı kimlik kullanırsa host `allowed_origins`, host yapılandırması ve kurum politikaları aynı kimliğe güncellenmelidir. Özel imzalama anahtarı teslimde yoktur.

### Desteklenen adaptörler

| Sağlayıcı | Tam ana makine adları | Bu sürümde doğrulama |
|---|---|---|
| ChatGPT | `chatgpt.com`, `chat.openai.com` | textarea / prompt-textarea sentetik Chromium DOM |
| Gemini | `gemini.google.com` | rich-textarea / contenteditable sentetik Chromium DOM |
| Claude | `claude.ai` | ProseMirror / contenteditable sentetik Chromium DOM |

Bunlar üç sağlayıcı için yazılmış adaptörlerdir; “300+ uygulama desteği” veya tüm A/B arayüz sürümlerini kapsama iddiası değildir. Alan adını taklit eden adresler, kullanıcı bilgili URL'ler, HTTP, ek portlar ve alt çerçeveden gelen ayrıcalıklı mesajlar kabul edilmez. Bilinen gönder düğmesinde yazım alanı yoksa/çok anlamlıysa gönderim durur. Hem editör hem gönderim yolu bilinmeyen biçimde değişirse ağ seviyesinde genel koruma garantisi yoktur.

## 2. İki kullanım biçimi

### Guard — yerel ön tarama ve gönderim kontrolü

Yönetilmemiş ilk kurulumun varsayılanıdır. Site editöründeki değişiklikten sonra 250 ms debounce ile yerel kurallar çalışır. PII bulunursa durum kartı uyarır. İlk gönderme girişimi durdurulur; temiz metin kontrol edildikten sonra ikinci, açık kullanıcı gönderimi gerekir. Hassas içerikte **Maskele** ile editör güncellenir. Sistem kendiliğinden mesaj göndermez.

Metin yapıştırma olayı sayfa dinleyicilerine bırakılmadan yakalanır; aday metnin tamamı taranır ve yalnız temizlenmiş düz metin editöre konur. Zengin HTML doğrudan kullanılmaz. Görsel/dosya yapıştırma, sürükleme ve normal dosya seçimi durdurulur; dosya güvenli yazım alanından işlenir. Tanınmayan alandaki yapıştırma da durdurulur. Enter, bilinen gönder düğmeleri ve ilgili form submit yolu kontrol edilir; Shift+Enter ve IME düzenleme olarak korunur.

**Guard bir gizli yazım alanı değildir.** Siteye ait editöre yazılan ham metin ortak DOM'da bulunur; site veya başka sayfa kodu gönderimden önce onu okuyabilir. Sayfanın programatik ağ istekleri, farklı yükleme API'leri veya başka uygulamalar bu DOM kontrolüyle tam olarak denetlenmez.

### Güvenli Yaz / secure-compose — ham içeriği site editöründen ayrı tutma

Araç çubuğundaki eklenti düğmesi veya AIDR kartındaki **Güvenli yaz** ayrı `chrome-extension://` sayfasını açar. Ham metni burada yaz, hedef sekmeyi seç, **Tara ve maskele** ile önizlemeyi incele. **Yalnız bu çıktıyı sekmeye aktar** yalnız sunucu-worker belleğindeki taranmış çıktıyı aktarır; sayfa tarafından sağlanan ham metni veya sonradan değiştirilmiş önizlemeyi kullanmaz.

`mode: "secure-compose"` politikasında normal site editörüne ham yazma/yapıştırma da engellenir. Hassas işletim için bu kontrollü akış, guard kipinden daha uygun başlangıçtır; tek başına cihaz genelindeki tüm çıkış yollarını kapatmaz.

Aktarım yetkisi tek kullanımlıktır; sekme, sağlayıcı kökeni, doküman kimliği ve politika sürümüne bağlıdır. En fazla 120 saniye yaşar. Eklenti worker'ı daha erken durur/yeniden başlarsa da geçersizleşir. Metin veya hedef değişince arayüz yeniden tarama ister. Sekme gezinmesi, politika değişimi, başka sekmeye aktarım veya tekrar kullanım reddedilir. Kuyruk en fazla 8 bekleyen güvenli çıktı tutar; tıkanırsa süresinin dolmasını bekleyip yeniden tara. Bu bellek kalıcı depolamaya yazılmaz.

## 3. Dosyalar

| Biçim | Yol | Davranış |
|---|---|---|
| TXT | Yerel tarayıcı kuralları; gerekiyorsa native NER | UTF-8 ve boyut kontrolü; düz metin maskelemesi |
| JSON | Yapısal tarayıcı/native tarama | Yinelenen/tehlikeli anahtar reddi, alan adına göre hassas değer maskelemesi |
| CSV/TSV | Yapısal tarayıcı/native tarama | Başlık duyarlı maskeleme, katı tablo ayrıştırma, formül başlangıçlarını engelleme |
| PNG/JPEG/WebP | Ayrı yerel native host + OCR | Önceki görsel motoru, gerçek piksel maskelemesi, yeniden tarama, metadata'sız yeni PNG |
| PDF, DOCX, XLSX, arşiv, SVG, GIF/video ve diğerleri | Bu eklentide uygulanmadı | Doğrudan ek yollarında engellenir; güvenli yazım alanı kabul etmez |

CSV'de `=`, `+`, `-`, `@` ile başlayan hücreler ihtiyatlı biçimde engellenir. Bu, bazı meşru negatif sayıları da engelleyebilir. Hücre boyutu/satır/sütun limitleri vardır; ayrıştırılamayan dosyada orijinale geri dönülmez. Maskeleme sayı/nesne tipini marker string'e çevirebilir; downstream şemayı yeniden doğrula.

Varsayılan metin sınırı 64 KiB, görsel kaynak dosya sınırı 8 MiB, metin dosyası sınırı en fazla 1 MiB'dir. İşlenmiş dosyanın adı yalnız `aidr-sanitized.*` olur. Orijinal ad hedef siteye taşınmaz. Dosya aktarımı hedef sitenin yüklemesini başlatabilir; o noktada yalnız temizlenmiş byte'lar verilir. Tek uygun file input bulunmayan adaptörde aktarım reddedilir.

**OCR bağlı değilse görüntü serbest bırakılmaz.** Native örnek yapılandırmasının `release:"manual"` ayarı yalnız karar üretir; aktarılabilir görüntü üretmez. Bu sürümde ayrıca bir insan onay kuyruğu/override uygulaması bulunmaz. Otomatik görüntü yayını ayrı bir yönetici kararıdır.

## 4. Yerel OCR / NER host'unu hazırlama

Tam kaynak veya npm paketini yönetici kontrolündeki kalıcı bir dizine yerleştir. Node.js 22.16.0 veya daha yeni, onaylanmış bir sürüm gerekir. OCR için ayrıca onaylı Python/Pillow/pyzbar/libzbar/Tesseract ve `eng`/`tur` modellerini kur. OCR ağırlıkları, NER ağırlıkları ve fontlar pakette yoktur. `vision/requirements.txt` Python bileşenlerini belirtir; Tesseract/libzbar işletim sistemi paketleri ayrı tedarik edilir.

`native/config.example.json` dosyasını kopyala, gerçek mutlak yolları ve izinli eklenti kimliğini düzenle. OCR envanterini **önceden onaylanmış** kurulumdan üret:

```sh
python3 vision/build_manifest.py \
  --tesseract /usr/bin/tesseract \
  --tessdata /usr/share/tesseract-ocr/5/tessdata \
  --output /etc/aidr/ocr-manifest.json
```

Bir dosyanın hash'ini kendi kurulumundan üretmek onun kaynağının güvenilirliğini kanıtlamaz. Dosya/klasörler çalışan kullanıcı tarafından değiştirilebiliyorsa kurumsal bütünlük sağlanmış sayılmaz.

Host dosyalarını oluştur (bu komut kayıt/kurum politikası değiştirmez):

```sh
node native/prepare-host.mjs \
  --config /opt/aidr/native-config.json \
  --out /opt/aidr/native-host-stage
```

Çıktı dizini yeni olmalıdır. Linux/macOS için mutlak yollu launcher ve `com.singularity.aidr_privacy.json` üretilir. İncelemeden sonra manifesti BT dağıtım süreciyle ilgili Chrome NativeMessagingHosts dizinine yerleştir. Varsayılan kullanıcı dizinleri Linux Chrome'da `~/.config/google-chrome/NativeMessagingHosts/`, macOS Chrome'da `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` biçimindedir; kurumsal/sistem-geneli veya Chromium kurulumlarının yolları farklıdır. [R2]

### Windows

Eklentinin tarayıcıdaki metin kuralları Windows'ta ayrı Node/Python host'u gerektirmez. Yerel OCR için Windows native host kurulumu ayrıca yapılır:

```powershell
node .\native\prepare-host.mjs --config "C:\AIDR\native-config.json" --out "C:\AIDR\native-host-stage" --platform win32
powershell.exe -NoProfile -File "C:\AIDR\native-host-stage\build-windows.ps1"
```

Hazırlayıcı C# launcher kaynağı ve Windows PowerShell 5.1 derleme betiği üretir. Üretilen EXE **imzasızdır**. Kurumun kod imzalama ve uygulama izin süreçlerinden geçmelidir. Derleme politikaları engelliyorsa bypass etme. Manifestin mutlak yolu Chrome'un `HKCU` veya `HKLM\Software\Google\Chrome\NativeMessagingHosts\com.singularity.aidr_privacy` kaydının varsayılan değerine BT tarafından kaydedilir. [R2]

**Windows launcher derleme/çalıştırma, Windows alt süreç sonlandırması ve macOS çalışma zamanı bu Linux ortamında test edilmedi.** Örnek launcher süreç izolasyonu veya Windows Job Object/cgroup katmanı sağlamaz; üretim paketine OS seviyesinde kaynak ve süreç ağacı sınırlandırması eklenmelidir.

### Yerel NER zorunluluğu

`requireNativeText:true`, gönderimde host'un gerçek motor kapsamını `rules-and-ner` olarak bildirmesini ister; rules-only host yetmez. Onaylı `LocalNerProcess` yapılandırmasını host `ner` alanına ekle. Şeması ve protokolü `docs/DEPLOYMENT.md` ve `ner/DEPENDENCIES.md` ve `ner/local-provider.example.json` içinde açıklanır. Gerçek modeli yükleyip dil/tür kapsamını bağımsız doğrulamak kurumun kabul kapısıdır. Bu teslim NER ağırlığı veya onun kalite kanıtını içermez.

## 5. Yönetici politikası

Politika yalnız `chrome.storage.managed` içindeki **PolicyJSON** string'inden alınır. Son kullanıcı ayar ekranı politikayı gevşetemez. `native/policy.enterprise.example.json` bir başlangıç örneğidir. Bu JSON'un string karşılığını kurumun Chrome eklenti politikası olarak yayımla. Host `browserPolicyJSON` aynı etkin politikayı temsil etmelidir. Tarayıcı ve host kanonik politikanın SHA-256 değerini karşılaştırır; uyuşmazlıkta içerik native taramaya verilmez.

İlk yönetilmemiş kullanımda varsayılan guard politikası vardır. Yönetilen politika bir kez görülmüşse sonradan kaybolması varsayılana düşmez; siteler karantinaya alınır. Yeniden izin vermek için yönetici geçerli bir PolicyJSON yayımlamalıdır. `{}` açıkça varsayılan politikayı seçer. Politika hatası, geçersiz alan, çakışan JSON anahtarı veya okunamayan yönetilen depolama gönderimi kapatır.

```json
{
  "version": 1,
  "id": "aidr-enterprise-v1",
  "mode": "secure-compose",
  "textAction": "redact",
  "requireNativeText": true,
  "fileHandling": "sanitize",
  "blockSites": [],
  "retentionDays": 7,
  "literals": [{ "value": "PROJECT-ORION-TEST", "type": "INTERNAL" }]
}
```

`mode:"block"` bütün desteklenen sağlayıcıları URL/isteği başlatan köken kurallarıyla engeller. `blockSites:["gemini"]` gibi seçimler sağlayıcı bazında uygulanır. Bu DNR kuralları istek gövdesini PII taramasıyla yeniden yazmaz. Eklenti devre dışı bırakılabiliyorsa koruma da kaldırılabilir; savunma kurumu dağıtımında zorunlu kurulum ve yönetilen profil gerekir. Buradaki geliştirme ZIP'i bu politikaları kendiliğinden kurmaz. [R3, R4]

## 6. Kayıtlar, gizlilik ve arıza davranışı

Kalıcı kayıt yalnız gün/sağlayıcı/karar ve PII türü sayaçlarıdır. Ham metin, OCR metni, görüntü, dosya adı, sayfa başlığı, tam URL, kullanıcı kimliği ve içerik hash'i audit'e yazılmaz. Literal politikalar ve `managedPolicyRequired` yönetim durumu istisna olarak yapılandırma/bellek alanlarıdır; veri içeriği kaydı değildir. Chrome Sync kullanılmaz.

Saklama 0–30 gün ayarlanabilir. Süresi geçen sayaçlar yeni olay, politika yükleme veya audit dışa aktarma sırasında ayıklanır; kapalı tarayıcıda kesin saniyelik silme garantisi yoktur. JavaScript/Python heap'i ve işletim sistemi swap/crash dump'ları için kriptografik bellek silme garantisi verilmez. Yönetilen disk şifrelemesi/dump politikası ayrıca gerekir.

Native bağlantı localhost HTTP açmaz. Chrome'un length-prefixed UTF-8 JSON stdio kanalı kullanılır. Veriler 192 KiB parçalara bölünür, sıralı offset, toplam uzunluk, kaynak/çıktı SHA-256, yanıt kimliği ve politika hash'i kontrol edilir. Bu hash'ler geçici protokol/bellek içindir, audit değildir. Başarısızlıkta orijinal içerik gönderilmez. [R2]

## 7. Yeniden derleme ve test

Tam kaynak ZIP'i geliştirme bağımlılıklarını `tools/vendor` içinde içerir. Bunlar runtime Chrome ZIP'inde yoktur.

```sh
npm install --offline --ignore-scripts --no-audit --no-fund
npm run build:all
npm run test:all
npm run test:python
npm run test:vision-python
npm run test:extension:e2e
```

Son komut Python Playwright ve bir Chromium kurulumu ister. Fixture testi gerçek Chromium DOM'unda çalışır fakat Chrome API'leri açıkça taklittir. NER/OCR modelleri olmadan geçmesi görsel model başarımı kanıtı değildir. Gerçek native/OCR testi ayrıca:

```sh
# JSON burada yalnız LocalImageOptions backend nesnesidir, visual politika sarmalı değildir.
AIDR_VISION_CONFIG=/absolute/local-vision.config.json npm run test:native:e2e
```

İzinli test makinesinde kurulu eklenti kontrolü için `scripts/extension/installed-e2e.py` vardır. `AIDR_RUN_INSTALLED_EXTENSION=1` açık opt-in ister; kurumsal politikaları değiştirmez. Bu script de gerçek hesap yerine sentetik sağlayıcı cevapları kullanır. Canlı arayüzlerin güncel sürümlerini ayrıca test et.

## Resmî platform dayanakları

R1 — Chrome content scripts; izole JavaScript dünyası ile ortak DOM ayrımı: `https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts`

R2 — Chrome Native Messaging; protokol, boyutlar, izinli kökenler ve OS kayıt yolları: `https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging`

R3 — Chrome declarativeNetRequest; deklaratif istek kontrolü: `https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest`

R4 — Chrome storage; yönetilen depolama ve TRUSTED_CONTEXTS: `https://developer.chrome.com/docs/extensions/reference/api/storage`

Bu kaynaklar platform davranışını açıklar; AIDR'nin kurumsal kabulü veya başarım sertifikası değildir.

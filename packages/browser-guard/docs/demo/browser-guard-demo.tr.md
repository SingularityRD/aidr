# Singularity AIDR Browser Guard: müşteri demosu

Bu rehber Browser Guard'ı bir müşteri sunumunda (PoC öncesi) göstermek içindir: Chrome veya
Edge'e geliştirici modunda kurulum, hangi sayfanın açılacağı, ne yazılacağı ve izleyicinin ne
görmesi gerektiği. En sonda nelerin **doğrulanmadığı** açıkça yazılıdır; sunumdan önce okuyun.

Browser Guard, ChatGPT, Gemini, Claude, Copilot, Perplexity, DeepSeek, Mistral ve Grok'a
yazılan metindeki kişisel ve gizli verileri **tarayıcıdan çıkmadan önce** `[EMAIL_1_k3f9]`
gibi etiketlerle değiştirir; yanıtta bu etiketler geldiğinde gerçek değerleri **yalnızca bu
bilgisayarda** geri gösterir. Algılama tarayıcının içinde, ağ bağlantısı olmadan çalışır.

## 1. Hazırlık (sunumdan önce, bir kez)

Depo kökünde (Windows 11, Node 24, pnpm 10):

```powershell
pnpm install --frozen-lockfile
pnpm --filter @singularityrd/aidr-browser-guard demo:package
```

Çıktı:

| Dosya | Ne işe yarar |
|---|---|
| `packages/browser-guard/dist/demo/aidr-browser-guard-demo-1.0.0.zip` | Demo paketi: içinde yüklenecek `aidr-browser-guard-chrome-1.0.0/` klasörü ve kısa `DEMO-KURULUM.txt` |
| `packages/browser-guard/dist/demo/SHA256SUMS` | Zip'in SHA-256 özeti |
| `packages/browser-guard/dist/chrome/` | Aynı eklentinin açılmış hâli (doğrudan da yüklenebilir) |

Zip'teki eklenti dosyaları mağaza paketiyle (`dist/aidr-browser-guard-chrome-1.0.0.zip`)
bayt bayt aynıdır; küçültülmüş (release) derlemedir, kaynak haritası içermez.

Çevrimdışı canlı demo (bölüm 4) için ayrıca bir kez Playwright'ın sabitlenmiş Chromium'unu
indirin (yaklaşık 200 MB, `%LOCALAPPDATA%\ms-playwright\chromium-1243`):

```powershell
node packages/browser-guard/node_modules/playwright-core/cli.js install --no-shell chromium
```

## 2. Chrome veya Edge'e kurulum (geliştirici modu)

1. `aidr-browser-guard-demo-1.0.0.zip` dosyasını kalıcı bir klasöre çıkarın, örneğin
   `C:\AIDR-Demo`. (Tarayıcı eklentiyi bu klasörden çalıştırır; sunum bitene kadar taşımayın.)
2. Adres çubuğuna yazın:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
3. **Geliştirici modu** anahtarını açın (Chrome'da sağ üstte, Edge'de sol menünün altında).
4. **Paketlenmemiş öğe yükle** (*Load unpacked*) düğmesine basın ve
   `C:\AIDR-Demo\aidr-browser-guard-chrome-1.0.0` klasörünü seçin (içinde `manifest.json` olan klasör).
5. Kartta "Singularity AIDR Browser Guard 1.0.0" görünmelidir; hata yoksa kart kırmızı uyarı göstermez.
6. Araç çubuğundaki yapboz simgesine tıklayıp Browser Guard'ı **sabitleyin**. Simge, mavi
   yuvarlak Singularity işaretidir.
7. Eklentinin **Ayrıntılar → Uzantı seçenekleri** sayfasında dil olarak **Türkçe** seçin
   (veya tarayıcı dili Türkçe ise "Otomatik" kalabilir). Koruma modu: **Otomatik maskele**.

"Paketlenmemiş öğe yükle" ile kurulumda izin penceresi çıkmaz (mağazadan kurulumda tarayıcı,
desteklenen yapay zekâ sitelerine erişim iznini gösterir). Eklenti yalnızca desteklenen yapay
zekâ sitelerinde çalışır; gizli pencerede çalışmaz.

Sunumdan sonra kaldırmak için: `chrome://extensions` (veya `edge://extensions`) → Kaldır.

## 3. Gerçek sitede demo (hesap gerekir)

Demo için şirketin **kendi test hesabını** kullanın; kişisel hesap ve gerçek müşteri verisi
kullanmayın. Aşağıdaki metin tamamen sentetiktir (geçerli sağlama toplamlı ama kimseye ait olmayan
TCKN, IBAN ve kart numarası; `example.com` e-postası; sahte anahtarlar).

1. `https://chatgpt.com` (veya `https://gemini.google.com/app`, `https://claude.ai/new`) açın.
   Eklenti, kurulumdan önce açık olan sekmelere de kendini ekler; araç çubuğu penceresi
   "Korunmuyor — bu sekmeyi yenileyin" derse sekmeyi yenileyin.
2. Araç çubuğundaki Browser Guard simgesine tıklayın: yeşil **"Korunuyor"** kutusu ve
   "ChatGPT hizmetine gönderdiğiniz hassas veriler tarayıcıdan çıkmadan önce denetlenir."
   yazısı görünmelidir.
3. İstem kutusuna şunu yazın veya yapıştırın:

   ```text
   Müşteri Ayşe Yılmaz için iade yazısı hazırla. E-posta ayse.yilmaz@example.com, telefon +90 532 123 45 67, TCKN 10000000146, IBAN TR33 0006 1005 1978 6457 8413 26, kart 4539 1488 0343 6467. Deploy anahtarları: sk-proj-Q7vX2mN9pL4kR8tW1yB6cD3fG5hJ0sAaZe ghp_R4nd0mF4k3T0k3nF0rDem0Purp0s3s0nly12 AKIAZ7QX3EXAMPLE4DMO
   ```

4. **Enter**'a basın.

İzleyicinin görmesi gerekenler:

| Adım | Ekranda |
|---|---|
| Yapıştırınca | Metin editöre zaten etiketli girer (`[EMAIL_1_…]`, `[PHONE_1_…]`, `[TCKN_1_…]`, `[IBAN_1_…]`, `[CARD_1_…]`, üç ayrı `[SECRET_n_…]`) ve sağ altta "Yapıştırılan metin maskelendi: …" bildirimi çıkar. Elle yazınca maskeleme Enter'da olur. |
| Gönderince | Sağ altta "Gönderilmeden önce maskelendi: 1 e-posta adresi, 1 telefon numarası, 1 T.C. kimlik numarası, 1 IBAN, 1 kredi kartı numarası, 3 API anahtarı, belirteç veya parola." Yapay zekâ hizmetine yalnızca etiketler gider. |
| Kendi mesajınız ve yanıt | Etiketlerin yerinde gerçek değerler açık mavi kutucuklarda görünür (yalnızca bu tarayıcıda). Kutucuk genişliği sabittir; uzun değerler (IBAN) `…` ile kısaltılır; bu, sitenin değerin uzunluğunu ölçememesi içindir. **API anahtarları geri açılmaz**, `[SECRET_…]` olarak kalır (varsayılan politika). |
| Araç çubuğu penceresi | "Bu oturum": korunan mesaj, maskelenen öğe sayısı ve en sık bulunan türler. |

Gösterilebilecek ek noktalar:

- **Bana sor modu:** Ayarlar → Koruma modu → **Bana sor**. Enter'da bir pencere bulunanları
  listeler: **Maskeli gönder**, **Düzenle** veya **Orijinali gönder** (yönetici kapatabilir).
- **Engelle modu:** Koruma modu → **Engelle**. Hassas veri varken Enter "Gönderim engellendi"
  der ve hiçbir şey gönderilmez; metin editörde kalır.
- **Yalnızca say:** maskelemeden gönderir, sadece sayar (izleme/pilot dönemi için).
- **Kişisel / kurumsal hesap:** yönetici politikası (`workAccounts`) ile, örneğin Gemini'ye
  kişisel gmail hesabıyla girildiğinde gönderim engellenir veya uyarı verilir. Bu yalnızca
  kurumsal politika (GPO/Intune/MDM) ile açılır; geliştirici modunda kurulan demo eklentisinde
  ayar sayfasından açılamaz. Kanıtı için bölüm 4'teki ekran görüntüsüne bakın.

## 4. Çevrimdışı garantili demo (hesap ve internet gerekmez)

Gerçek sitelere giriş yapılamıyorsa veya ağ güvenilir değilse, aynı eklentiyi gerçek
sitelerin istem kutusu yapısını taklit eden **yerel simülasyon sayfalarında** gösterin. Bunlar
otomatik testlerde kullanılan sayfalardır; adres çubuğunda `https://chatgpt.com` görünür ama
istekler bilgisayardan çıkmaz, yanıtları bir test modeli üretir. Sayfanın üstünde bunu söyleyen
bir şerit vardır, izleyiciye de söyleyin.

```powershell
pnpm --filter @singularityrd/aidr-browser-guard demo:live
```

Görünür bir Chromium penceresi ChatGPT, Claude ve Gemini simülasyonlarıyla açılır (eklenti
yüklü, arayüz Türkçe, mod "Otomatik maskele"). Bölüm 3'teki metni yazın veya yapıştırın ve
Enter'a basın. Üstteki koyu **"Yapay zekâ servisine giden metin"** paneli, sayfanın servise
gönderdiği metni gösterir: izleyici orada yalnızca etiketleri görür, sohbette ise gerçek
değerleri. Bitirmek için pencereyi kapatın.

Kaydedilmiş adımlar (ekran görüntüleri, `node e2e/demo.mjs --record` ile her adımda aynı
denetimlerle üretildi):

| | |
|---|---|
| ![İstem yazıldı](../screenshots/01-istem-yazildi.png) | 1. Gerçek verilerle yazılan istem |
| ![Maskelendi](../screenshots/02-gonderimden-once-maskelendi.png) | 2. Gönderimden önce maskelendi; üst panel servise gideni gösterir |
| ![Geri yüklendi](../screenshots/03-yanit-yerelde-geri-yuklendi.png) | 3. Yanıt yerelde geri açıldı, anahtarlar maskeli kaldı |
| ![Yapıştırma](../screenshots/04-yapistirma-maskelendi.png) | 4. Yapıştırılan metin editöre maskeli girdi |
| ![Bana sor](../screenshots/05-bana-sor-modu.png) | 5. "Bana sor" modu |
| ![Engelle](../screenshots/06-engelle-modu.png) | 6. "Engelle" modu |
| ![Pencere](../screenshots/07-acilir-pencere.png) | 7. Araç çubuğu penceresi |
| ![Ayarlar](../screenshots/08-ayarlar.png) | 8. Ayarlar sayfası |
| ![Gemini](../screenshots/09-gemini.png) | 9. Gemini simülasyonu |
| ![Claude](../screenshots/10-claude.png) | 10. Claude simülasyonu |
| ![Kişisel hesap](../screenshots/11-kisisel-hesap-engellendi.png) | 11. Kurumsal politika: kişisel Gemini hesabıyla gönderim engellendi |

Animasyon: [`../screenshots/browser-guard-demo.apng.png`](../screenshots/browser-guard-demo.apng.png)
(tarayıcıda açın). Video (WebM, yaklaşık 35 sn, depoda değil, üretilir):
`pnpm --filter @singularityrd/aidr-browser-guard demo:record` → `dist/demo/browser-guard-demo.webm`.
Her adımda servise gidenler `docs/screenshots/demo-evidence.json` dosyasındadır (yalnızca etiketler).

## 5. Sık sorulanlar (sunum sırasında)

- **Veriler nereye gidiyor?** Hiçbir yere. Algılama, maskeleme ve geri açma tarayıcının
  içinde olur. Etiket → değer eşlemesi yalnızca o sekmenin belleğinde (ve tarayıcının oturum
  belleğinde) tutulur; sekme kapanınca veya tarayıcı kapanınca silinir. Yönetici bir kontrol
  düzlemi bağlarsa yalnızca **sayılar** gider (ör. "2 e-posta maskelendi"), metin asla.
- **Yapay zekâ cevabı bozulmuyor mu?** Model `[EMAIL_1_…]` gibi etiketlerle çalışır ve cevabında
  onları kullanır; kullanıcı ekranda gerçek değerleri görür.
- **İsim ve adres?** "Ad Soyad:", "Adres:" gibi etiketli alanlar tarayıcıda yakalanır. Etiketsiz
  serbest metindeki isim/adres için isteğe bağlı yerel yardımcı uygulama (native host, NER)
  gerekir; bu demo paketinde yoktur ve NER modeli ürünle gelmez.
- **Dosyalar?** CSV/TXT/JSON, Word/Excel/PowerPoint, OpenDocument maskelenir; PDF ve eski .doc/.xls
  taranır, bulgu varsa engellenir (otomatik testlerde doğrulandı; bu rehberde gösterilmiyor).

## 6. Neler doğrulandı, neler doğrulanmadı

Doğrulandı (Windows 11, Chrome for Testing 153.0.8010.12, Playwright 1.63.0, 15 Ekim 2026):

- Demo zip'inden çıkarılan klasör, "Load unpacked" ile aynı şekilde yüklenerek tam gerçek
  tarayıcı test paketinden geçti: 49 senaryodan 47'si başarılı, 2'si bilinçli atlandı
  (genel site yok; native host senaryosu isteğe bağlı), 0 hata.
- Sekiz sitenin simülasyonunda (ChatGPT, Gemini, Claude, Copilot, Perplexity, DeepSeek, Mistral,
  Grok): e-posta, telefon, TCKN, boşluklu IBAN, kart (Luhn) ve üç anahtar türü gönderimden önce
  maskeleniyor, yanıt yerelde geri açılıyor, anahtarlar açılmıyor, sayfa betikleri gerçek değeri
  okuyamıyor, ağa hiçbir gerçek değer çıkmıyor.
- Yapıştırma, Bana sor, Engelle, Yalnızca say, kişisel/kurumsal hesap (engelle, uyar, yalnızca
  maskele), yerel yardımcı uygulama yokken kurallarla devam edip kullanıcıya söyleme.
- Yerel yardımcı uygulama (native host): kullanıcı başına (HKCU, yönetici yetkisi olmadan)
  kayıt betiği ile Chromium için kaydedildi, eklenti "bağlı" raporladı, tarama ondan geçti,
  kayıt sonra silindi (`BG_E2E_NATIVE_HOST=1`, isteğe bağlı senaryo).

**Doğrulanmadı** (sunumda söz vermeyin):

- **Gerçek ChatGPT, Gemini, Claude, Copilot, Perplexity, DeepSeek, Mistral ve Grok siteleri.**
  Bunlar hesap ister ve bu çalışmada hiçbir siteye giriş yapılmadı. Testler, sitelerin istem
  kutusu yapısını taklit eden yerel sayfalarla yapıldı; siteler arayüzlerini değiştirdiyse gerçek
  sitede yakalama çalışmayabilir. Sunumdan önce, demo hesabıyla bölüm 3'ü bir kez deneyin. Çalışmazsa
  bölüm 4'e geçin.
- Kurulu Google Chrome ve Microsoft Edge (testler Chrome for Testing ile yapıldı; aynı
  Chromium motoru ve aynı "Load unpacked" yolu). Edge'de elle deneme yapılmadı.
- Microsoft 365 Copilot'un Office içi paneli, canlı kiracıda.
- Yerel yardımcı uygulamanın imzalı Windows başlatıcısı, kurulu Chrome/Edge için kaydı ve NER
  doğruluğu (NER modeli ürünle gelmez). Bilinen durum: yardımcı uygulama açıkken istemde bir
  API anahtarı varsa yardımcı uygulama metni kendi politikası gereği reddeder; maskeleme yine de
  yapılır ama sayfa "yalnızca yerleşik kurallarla denetlendi" der.
- Firefox derlemesi bu demo için denenmedi.

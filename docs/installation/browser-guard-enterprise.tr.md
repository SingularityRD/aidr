# Browser Guard'ı kurumda dağıtma

[English](browser-guard-enterprise.md)

Bu kılavuz Singularity AIDR Browser Guard'ı yönetilen bilgisayarlara tarayıcı
mağazalarından kurar, ayarlarını kilitler ve dağıtımın nasıl doğrulanıp geri
alınacağını gösterir. Söz edilen politika dosyaları
[`deploy/browser-guard/`](../../deploy/browser-guard/README.md) klasöründedir; her
yönetilen ayarın anlamı oradaki ["Managed keys"](../../deploy/browser-guard/README.md#managed-keys)
tablosundadır. Tek bir kullanıcının kendi kurulumu için [browser-guard.tr.md](browser-guard.tr.md).

## 1. Ne dağıtılır

| Tarayıcı | Kaynak | Uzantı kimliği | Güncelleme URL'si |
|---|---|---|---|
| Google Chrome | Chrome Web Store (liste dışı / unlisted kayıt) | `<CHROME_WEB_STORE_ID>` | `https://clients2.google.com/service/update2/crx` |
| Microsoft Edge | Microsoft Edge Add-ons (liste dışı kayıt) | `<EDGE_ADDONS_ID>` | `https://edge.microsoft.com/extensionwebstorebase/v1/crx` |
| Mozilla Firefox 140+ | Mozilla imzalı XPI (addons.mozilla.org, liste dışı, kendi sunucunuzda) | `browser-guard@singularityrd.com` | XPI'yi barındırdığınız HTTPS adresi |

`<CHROME_WEB_STORE_ID>` ve `<EDGE_ADDONS_ID>`, yayımlanmış mağaza kayıtlarının
kimlikleridir (`a`-`p` arası 32 harf; kayıt adresinin son bölümü). Singularity
irtibat kişiniz veya kayıt bağlantısı bunları verir. Tüm örnek dosyalar tam olarak bu
yer tutucuları kullanır: dağıtmadan önce değiştirin. Değiştirilmemiş bir yer tutucu
geçerli bir uzantı kimliği değildir; tarayıcı hiçbir şey kurmaz (güvenli tarafta kalır).

Liste dışı (unlisted) bir kayıt mağaza aramasında görünmez; bağlantısından veya
politikayla kurulur. Politikayla kurulum herkese açık bir kayıttaki gibi çalışır.

Her ortamda iki bölüm dağıtılır:

1. **Kurulum politikası**: uzantıyı zorunlu kur ve araç çubuğuna sabitle
   (`ExtensionInstallForcelist` / `ExtensionSettings`, Firefox'ta `ExtensionSettings`).
2. **Yönetilen yapılandırma**: uzantının `chrome.storage.managed` üzerinden okuduğu
   Browser Guard ayarları (`3rdparty` politika dalı). Belirlediğiniz anahtarlar
   kullanıcı için kilitlenir. Şema, uzantıdaki `static/managed_schema.json` dosyasıdır.

Her örnek önerilen tarayıcı sıkılaştırmasını da içerir (gizli/InPrivate pencere,
Misafir profili, geliştirici araçları ve başka uzantılar kapalı). Dağıtmadan önce
["Hardening the browser"](../../deploy/browser-guard/README.md#hardening-the-browser)
bölümünü okuyun: bu ayarlar tarayıcının tamamını etkiler.

## 2. Başlamadan önce

1. Mağaza kimliklerini yukarıdaki gibi ve örnek değerleri (`policyId`, `literals`,
   `exactData` yer tutucusu, `telemetry.controlPlaneUrl`, `telemetry.apiKey`)
   değiştirin. Bir AIDR kontrol düzlemine raporlamıyorsanız `telemetry` anahtarını silin.
2. Küçük bir grupla `"mode": "monitor"` ile pilot yapın: hiçbir şey maskelenmez veya
   engellenmez ama her denetim sayılır; ne olacağını görürsünüz.
3. Kullanıcılara Chrome, Edge ve Firefox'un `declarativeNetRequest` iznini "Herhangi
   bir sayfadaki içeriği engelleme" olarak gösterdiğini söyleyin. İzin yalnızca
   engellediğiniz yapay zekâ siteleri için kullanılır. Zorunlu kurulan kopyalar
   soru sormadan kurulur.

## 3. Microsoft Intune (Windows)

**Edge.** [`edge-intune.example.json`](../../deploy/browser-guard/edge-intune.example.json) dosyasını kullanın:

1. **Cihazlar > Yapılandırma > Oluştur > Yeni ilke**, platform *Windows 10 ve üzeri*,
   profil türü *Ayarlar kataloğu*.
2. **Microsoft Edge > Uzantılar > Sessizce yüklenen uzantıları denetle** ayarını
   `<EDGE_ADDONS_ID>;https://edge.microsoft.com/extensionwebstorebase/v1/crx`
   değeriyle ekleyin; isterseniz örnekteki `ExtensionSettings` JSON'u ile **Uzantı
   yönetimi ayarlarını yapılandır** ayarını da ekleyin (araç çubuğu düğmesini sabitler).
3. Örneğin `settingsCatalog` bölümündeki sıkılaştırma ayarlarını ekleyip profili bir
   cihaz grubuna atayın (önce pilot grup).
4. Yönetilen yapılandırma: Intune'da uzantıya özel politika için katalog girdisi
   yoktur. `managedConfiguration` kayıt defteri değerlerini **Cihazlar > Betikler ve
   düzeltmeler > Platform betikleri** altında bir PowerShell betiğiyle dağıtın
   (sistem olarak, 64 bit):

   ```powershell
   $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<EDGE_ADDONS_ID>\policy'
   New-Item -Path $key -Force | Out-Null
   New-ItemProperty -Path $key -Name mode -PropertyType String -Value 'auto' -Force | Out-Null
   New-ItemProperty -Path $key -Name allowUserPause -PropertyType DWord -Value 0 -Force | Out-Null
   New-ItemProperty -Path $key -Name neverRestore -PropertyType String -Value '["SECRET","PRIVATE_KEY"]' -Force | Out-Null
   # ...managedConfiguration.values içindeki her değer için bir satır (metinler REG_SZ,
   # boolean/tam sayılar DWord, listeler ve nesneler REG_SZ içinde JSON metni)
   ```

   Ya da [`windows-registry.example.reg`](../../deploy/browser-guard/windows-registry.example.reg)
   dosyasını (Chrome ve Edge) bir Win32 uygulamasından `reg import` ile içe aktarın.

**Chrome.** Aynı adımlar; Ayarlar kataloğundaki Google Chrome girdileri (**Google >
Google Chrome > Uzantılar**) veya özel profil olarak alınmış Chrome ADMX, Google
güncelleme URL'siyle `<CHROME_WEB_STORE_ID>` kimliği ve
`HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<CHROME_WEB_STORE_ID>\policy`
kayıt defteri anahtarı.

## 4. Google Yönetici Konsolu (Chrome Enterprise Core)

Chrome Enterprise Core'a (eski adıyla Chrome Browser Cloud Management) kayıtlı veya
yönetilen Google hesaplarıyla oturum açılmış tarayıcılar için:

1. **Cihazlar > Chrome > Uygulamalar ve uzantılar > Kullanıcılar ve tarayıcılar**,
   kuruluş birimini seçin (önce pilot birim).
2. **+ > Kimliğe göre Chrome uygulaması veya uzantısı ekle**, `<CHROME_WEB_STORE_ID>`
   girin, kaynak *Chrome Web Store'dan*.
3. **Yükleme politikası**: *Zorunlu yükle + tarayıcı araç çubuğuna sabitle*.
4. **Uzantılar için politika**: yönetilen yapılandırmayı JSON olarak yapıştırın.
   Konsol her değeri `{"Value": ...}` içinde bekler. Başvuru kopyasını şöyle dönüştürün:

   ```bash
   node -e 'const p=require("./deploy/browser-guard/chrome-managed-policy.example.json")["3rdparty"].extensions["<CHROME_WEB_STORE_ID>"];console.log(JSON.stringify(Object.fromEntries(Object.entries(p).map(([k,v])=>[k,{Value:v}])),null,2))'
   ```

5. **Cihazlar > Chrome > Ayarlar > Kullanıcılar ve tarayıcılar** altında
   sıkılaştırma: *Gizli mod* izin verilmez, *Tarayıcı misafir modu* kapalı,
   *Geliştirici araçları* hiçbir zaman; **Uygulamalar ve uzantılar > Ek ayarlar**
   altında diğer tüm uzantıları engelleyin (yalnızca onayladıklarınıza izin verin).
6. **Kaydet**. Tarayıcılar değişikliği bir sonraki politika yenilemesinde alır (veya
   `chrome://policy` > *Politikaları yeniden yükle*).

## 5. Jamf Pro (macOS)

1. [`macos-jamf.example.mobileconfig`](../../deploy/browser-guard/macos-jamf.example.mobileconfig)
   dosyasını bir metin düzenleyicide açın. `&lt;CHROME_WEB_STORE_ID&gt;` ve
   `&lt;EDGE_ADDONS_ID&gt;` (XML'de kaçışlı yer tutucular) değerlerini hem yük
   türlerinde hem zorunlu kurulum girdilerinde mağaza kimlikleriyle, örnek değerleri de
   kendi değerlerinizle değiştirin.
2. **Bilgisayarlar > Yapılandırma Profilleri > Karşıya Yükle** ile dosyayı seçin. Jamf
   profili yüklerken imzalar.
3. Profili kullanıcılara değil bilgisayarlara atayın; önce pilot grup.
4. Profilde dört yük vardır: `com.google.Chrome` ve `com.microsoft.Edge` (kurulum ve
   sıkılaştırma), `com.google.Chrome.extensions.<id>` / `com.microsoft.Edge.extensions.<id>`
   (yönetilen yapılandırma, yerel plist türleri).

macOS'ta Firefox: `EnterprisePoliciesEnabled` ile `org.mozilla.firefox` tercih alanını
ve `policies.json` ile aynı içeriği (bölüm 7) kullanın ya da `policies.json` dosyasını
`Firefox.app/Contents/Resources/distribution/` klasörüne koyun.

## 6. Grup İlkesi (Windows, Active Directory)

1. Google Chrome ve Microsoft Edge ADMX şablonlarını Merkezi Depo'ya alın.
2. Bilgisayarların kuruluş birimine bağlı bir GPO'da: **Bilgisayar Yapılandırması >
   İlkeler > Yönetim Şablonları > Google > Google Chrome > Uzantılar > Zorunlu yüklenen
   uygulama ve uzantıların listesini yapılandır**:
   `<CHROME_WEB_STORE_ID>;https://clients2.google.com/service/update2/crx`. Edge:
   **Microsoft Edge > Uzantılar > Sessizce yüklenen uzantıları denetle**:
   `<EDGE_ADDONS_ID>;https://edge.microsoft.com/extensionwebstorebase/v1/crx`.
3. Sıkılaştırma ilkelerini ayarlayın (*Gizli mod kullanılabilirliği*, *InPrivate mod
   kullanılabilirliği*, *Misafir modunu etkinleştir*, *Geliştirici araçlarının
   kullanılabileceği yerler*, uzantı engelleme/izin listeleri).
4. Yönetilen yapılandırma ADMX şablonlarında yoktur: **Bilgisayar Yapılandırması >
   Tercihler > Windows Ayarları > Kayıt Defteri** öğeleriyle
   `HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<CHROME_WEB_STORE_ID>\policy`
   ve `HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<EDGE_ADDONS_ID>\policy`
   altına ekleyin (türler `windows-registry.example.reg` dosyasındaki gibi) ya da bu
   dosyayı bir başlangıç betiğiyle `reg import` edin.
5. Pilot bir makinede `gpupdate /force` çalıştırın, sonra bölüm 8'i uygulayın.

## 7. Firefox (`policies.json`, tüm platformlar)

1. Sürümün Mozilla imzalı XPI dosyasını alın (addons.mozilla.org'da liste dışı
   eklenti olarak imzalanır; yayıncı imzadan sonra AMO Developer Hub'dan indirir,
   Singularity irtibat kişiniz sağlar) ve bilgisayarlarınızın erişebildiği bir HTTPS
   sunucusunda barındırın. Firefox imzasız eklentileri reddeder.
2. [`firefox-policies.example.json`](../../deploy/browser-guard/firefox-policies.example.json)
   dosyasında `install_url` değerini bu dosyaya ayarlayın (`<FIREFOX_XPI_HOST>`
   yerine), `3rdparty.Extensions["browser-guard@singularityrd.com"]` içindeki örnek
   değerleri değiştirin.
3. Dosyayı Firefox kurulumunun `distribution` klasörüne `policies.json` adıyla kaydedin
   (Windows `C:\Program Files\Mozilla Firefox\distribution\`; macOS
   `Firefox.app/Contents/Resources/distribution/`; Linux `/etc/firefox/policies/`) ya da
   Firefox ADMX şablonlarını (Windows) veya `org.mozilla.firefox` alanını (macOS) kullanın.

**Güncellemeler.** Bu derleme `update_url` bildirmez; Firefox kendi sunucunuzdaki
kopyayı kendiliğinden güncellemez. Yeni sürümü, imzalı yeni XPI'yi yeni bir dosya
adıyla yayımlayıp `install_url` değerini değiştirerek dağıtın; Firefox politikayı bir
sonraki okuyuşunda yeni adresten kurar. Genişletmeden önce pilot makinede doğrulayın
(`about:addons` sürümü gösterir). Eklenti addons.mozilla.org'da herkese açık
listelenirse `https://addons.mozilla.org/firefox/downloads/latest/<AMO_SLUG>/latest.xpi`
kullanın; Firefox oradan günceller.

## 8. Dağıtımı doğrulama

Pilot bir bilgisayarda, tarayıcı yeniden başlatıldıktan veya politikaları yeniden
yüklendikten sonra:

1. `chrome://policy`, `edge://policy` veya `about:policies`: `ExtensionInstallForcelist`
   (Firefox'ta `ExtensionSettings`) durum OK ile listelenir; uzantının kendi politikası
   kimliğinin altında hatasız görünür.
2. `chrome://extensions` / `edge://extensions` / `about:addons`: Browser Guard kurulu,
   etkin ve kuruluşunuz tarafından kurulmuş olarak işaretlidir (kullanıcı kaldıramaz).
3. Araç çubuğu penceresi modu kilit simgesiyle ve "Kuruluşunuz tarafından yönetiliyor"
   ifadesiyle gösterir; "geçersiz ayar" uyarısı yoktur. Oradaki politika hata sayısı
   bir değerin doğrulanmadığını gösterir; o ayar en katı değeriyle çalışır.
4. Desteklenen bir yapay zekâ sitesinde `jane.doe@example.com` gibi bir deneme adresi
   yazıp gönderin: `auto` modunda siteye `[EMAIL_1_xxxx]` gider.
5. Telemetri açıksa `privacy_scan` sayıları yaklaşık bir dakika içinde AIDR panosunda
   görünür.

Komut satırından: Windows `reg query "HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"`;
macOS `sudo profiles show -type configuration | grep -i browser-guard`; Linux
`cat /etc/opt/chrome/policies/managed/*.json`.

## 9. Sürüm sabitleme, aşamalı dağıtım ve geri alma

- **Mağazalar yalnızca yayımlanmış son sürümü sunar.** Chrome ve Edge mağazadan
  kurulan uzantıyı kendiliğinden günceller; politika ile eski bir mağaza sürümünde
  tutulamaz. Değişiklikleri kendi halkalarınızla aşamalandırın: kurulum politikasını
  önce pilot gruba atayın, sonra genişletin.
- **Yapılandırmayı geri almak** anında olur: yönetilen değerleri değiştirin veya silin,
  tarayıcılar politikayı yenilesin. Yönetilen bir politika varken sildiğiniz ayarlar
  kullanıcının değerine değil, kilitli yerleşik değere döner.
- **Uzantıyı geri almak** yayıncının işidir: önceki kod yeni ve daha yüksek bir sürüm
  numarasıyla yeniden yayımlanır (mağazalar düşük sürümü kabul etmez). Her sürüm imzalı
  etiketinden yeniden üretilebilir.
- **Acil durdurma:** kimliği zorunlu kurulum politikasından çıkarın (tarayıcı uzantıyı
  kaldırır) veya `ExtensionInstallBlocklist` listesine ekleyin. Bunun korumayı da
  kaldırdığını unutmayın.
- **Belirli bir sürüme sabitleme** yalnızca kendi barındırmanızla mümkündür: kendi
  anahtarınızla paketlenip kendi `update.xml` dosyanızdan sunulan bir Chromium derlemesi
  (farklı uzantı kimliği; yönetilen yapılandırma o kimliğe taşınır) veya sabit bir
  `install_url` adresindeki belirli bir imzalı Firefox XPI.

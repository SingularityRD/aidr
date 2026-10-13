# Masaüstü yükleyicileri (Windows ve Linux)

[English](desktop-installers.md)

Masaüstü yükleyicileri AIDR'yi bir iş istasyonuna kendi kendine yeterli olarak
kurar: Node.js ya da paket deposu gerekmez. Her yükleyici bağımsız paketin
sürüm derlemesini (hem komut satırı aracı hem her hook olan tek bir `aidr`
programı, yanında tehdit kuralları, Cursor ve VS Code eklentileri; hepsi sürüm
anahtarıyla imzalı bildirim dosyalarında listelenir) ve sürüm ortak anahtarını
içerir; ardından oturum açmış kullanıcı için `aidr setup` çalıştırır.

| İşletim sistemi | Dosya | Kurulum konumu |
|---|---|---|
| Windows 10/11 x64 | `singularity-aidr-<sürüm>-windows-x64.msi` (Authenticode imzalı) | `C:\Program Files\Singularity AIDR\` (kullanıcı başına: `%LOCALAPPDATA%\Programs\Singularity AIDR\`) |
| Debian / Ubuntu | `singularity-aidr_<sürüm>_amd64.deb` (+ `.asc`) | `/opt/singularity-aidr/`, `/usr/bin/aidr` |
| RHEL / Fedora / SUSE | `singularity-aidr-<sürüm>-1.x86_64.rpm` (GPG imzalı) | `/opt/singularity-aidr/`, `/usr/bin/aidr` |
| Her Linux | `singularity-aidr-<sürüm>-linux-x64.tar.gz` (+ `.asc`) | `/opt/singularity-aidr/`, `/usr/local/bin/aidr` |

**macOS yükleyicisi henüz sunulmuyor.** macOS'ta [Başlarken](../getting-started.md)
belgesindeki bağlayıcı paketlerini kullanın.

> **Sürüm durumu.** Yükleyiciler sürüm adayı iş akışında
> (`.github/workflows/release-rc.yml`, `installers-*` işleri) üretilir ve taslak
> RC sürümüne eklenir. [Başlarken](../getting-started.md#current-customer-installation-status)
> belgesindeki sürüm kararı onay verene kadar müşteriye onaylı bir sürüm
> değildir. Yayımlanan her yükleyici imzalıdır; imzalama sırrı olmayan bir
> derleme imzasız yayımlanmak yerine başarısız olur.

## Kurulum her ana makinede ne yapar

`aidr setup`, kurulumu yapan kullanıcı için çalışır (`root` ya da
`LocalSystem` için asla) ve:

- **Sürüm anahtarı** — yükleyicinin `config/release-public.pem` dosyasına
  koyduğu sürüm ortak anahtarını `~/.singularity-aidr/config.json` içindeki
  `integrity.public_keys_pem` alanına kopyalar ve parmak izini yazdırır. Sürüm
  derlemesi kendi kurallarına ancak bu anahtar ayarlandıktan sonra güvenir; o
  zamana kadar her araç çağrısı, bunu ve çözümünü söyleyen bir mesajla
  engellenir. Yöneticinin daha önce ayarladığı farklı bir anahtar korunur
  (kurulum bunu söyler); `aidr setup --force` operatör onayından sonra onu
  değiştirir. Elle kurulumda `aidr setup --release-key <dosya.pem>` bir Ed25519
  ortak anahtarını (PEM) operatör onayından sonra ayarlar ve parmak izini yazdırır.
- **Claude Code** — `"<paket>/bin/aidr" hook pre-tool-use` (ve `post-tool-use`,
  `session-start`) komutlarını `~/.claude/settings.json` dosyasına kaydeder
  (yalnızca AIDR işaretli girdiler değişir; sizin hook'larınız kalır). Öncesinde
  paketteki her dosyayı ve iki bildirim imzasını sürüm anahtarıyla denetler,
  hook'tan zararsız bir engelleme canary'si ve zararsız bir `ls` geçirir;
  canary engellenmez ya da `ls` engellenirse hiçbir şey kaydetmez. Etkin bir
  AIDR Claude Code eklentisine dokunulmaz.
- **Codex** — aynı canary denetiminden sonra `"<paket>/bin/aidr" hook
  aidr-codex-hook` komutunu PreToolUse, UserPromptSubmit ve PostToolUse için
  `~/.codex/hooks.json` dosyasına kaydeder. Ardından Codex'te `/hooks` ile
  hook'lara bir kez güvenin.
- **Cursor, VS Code** — editör kuruluysa yükleyicinin taşıdığı eklentiyi
  (`bundle/extensions/aidr-cursor.vsix`, `aidr-vscode.vsix`) editörün kendi
  komut satırıyla kurar. Ardından komut paletinden "Singularity AIDR: Enable
  protection" komutunu çalıştırın.
- **OpenCode** — `@singularityrd/aidr-opencode` paketini kaydeder (OpenCode bir
  sonraki açılışta özel depodan kurar).
- **OpenClaw** — `openclaw` komutu `PATH` üzerindeyse `openclaw plugins install`
  çalıştırır.

O kullanıcı için henüz desteklenen bir yapay zekâ aracı kurulu değilse kurulum
hiçbir aracı değiştirmez, 3 koduyla çıkar ve paket yine de kurulur; Linux
paketi "No AI tool … was found for <kullanıcı> yet" iletisini ve bir araç
kurduktan sonra çalıştırılacak komutu (`aidr setup`) yazdırır. Sıfırdan farklı
başka her kod gerçek bir kurulum sorunudur.

## Hızlı başlangıç

### Windows

1. AIDR panelindeki **İndirmeler** sayfasından `singularity-aidr-<sürüm>-windows-x64.msi`
   dosyasını indirin.
2. Çift tıklayın ve sihirbazı izleyin ([sayfalar aşağıda](#windows-kurulum-sihirbazı)).
   Kurulum sonunda sizin için `aidr setup` çalışır.
3. Yapay zekâ araçlarınızı (Claude Code, Cursor, VS Code, ...) yeniden başlatın.
   Yeni bir terminal açıp `aidr status`, ardından `aidr verify` çalıştırın.

#### Windows kurulum sihirbazı

Windows görüntüleme dili Türkçe ise sihirbaz Türkçe, değilse İngilizce açılır;
iki dil de tek MSI dosyasındadır. Ekran görüntüleri henüz yayımlanmadı: aşağıdaki
her yer tutucu, ekran görüntüsünün neyi göstereceğini anlatır.

1. **Hoş geldiniz**: ürün adı, ne yaptığını anlatan tek satır ve sürüm.
   *Ekran görüntüsü yer tutucusu: solda kalkan işaretli lacivert panel; sağda
   "Singularity AIDR'ye hoş geldiniz", tek satırlık açıklama ve "Sürüm 0.6.0".*
2. **Lisans sözleşmesi**: okuyun ve devam etmek için "kabul ediyorum"u işaretleyin.
   *Ekran görüntüsü yer tutucusu: lisans metni kutusu ve altında onay kutusu.*
3. **Kimler korunsun?**
   - *Yalnızca benim için*: `%LOCALAPPDATA%\Programs\Singularity AIDR\`
     konumuna sizin hesabınız için kurar; yönetici yetkisi gerekmez.
   - *Bu bilgisayarın tüm kullanıcıları için* (varsayılan):
     `C:\Program Files\Singularity AIDR\` konumuna kurar; Windows yönetici
     onayı ister (Kur düğmesinde kalkan simgesi vardır). Diğer kullanıcılar bir
     sonraki oturum açışlarında hazırlanır.
   Mevcut bir "Yalnızca benim için" kurulumu önceden seçili gelir; böylece
   yükseltme kapsamını korur. Kapsamı değiştirmek için önce kaldırın.
   *Ekran görüntüsü yer tutucusu: her biri tek satır açıklamalı iki seçenek.*
4. **Şirket bağlantısı (isteğe bağlı)**:
   - *Yalnızca yerel koruma (hesap gerekmez)* (varsayılan): koruma bu
     bilgisayarda çalışır; başka bir şey girmeniz gerekmez.
   - *Şirketime bağlan*: BT ekibinizin verdiği şirket adresi (yalnızca
     `https://`; Singularity AIDR hizmetiyle önceden doldurulur, şirket içi
     konsol için değiştirin) ve isteğe bağlı olarak konsoldan alınan kayıt kodu
     (`aidr_enroll_…`, 55 karakter, yazarken gizlenir). Devam etmeden önce
     biçim denetlenir. Bkz.
     [Yükleyiciden şirket bağlantısı](#yükleyiciden-şirket-bağlantısı).
   *Ekran görüntüsü yer tutucusu: iki seçenek; "Şirketime bağlan" seçilene kadar
   adres ve kod alanları soluk görünür.*
5. **Kuruluma hazır**: kimlerin korunacağı, klasör, şirket bağlantısı ve
   kurulumun ne yapacağı. Ardından ilerleme sayfası.
6. **Son**: işaretli gelen "Singularity AIDR Kurulum Yardımcısını aç" sizin
   için `aidr assistant` komutunu kendi hesabınızla, yönetici yetkisi olmadan
   başlatır; kurulum onu beklemeden kapanır. "Hızlı başlangıç kılavuzunu
   görüntüle", kurulum klasörünün `docs\quick-start.<dil>.html` dosyasındaki
   çevrim dışı kılavuzu açar. Yükleyiciyi yönetici olarak açılmış bir komut
   isteminden başlattıysanız yardımcı oradan başlatılmaz; sayfa, `aidr assistant`
   komutunu normal bir terminalde çalıştırmanızı söyler.
   *Ekran görüntüsü yer tutucusu: "Singularity AIDR kuruldu", sonraki adım
   (`aidr status`), işaretli yardımcı kutusu ve hızlı başlangıç bağlantısı.*

Onarma ve kaldırma (Ayarlar > Uygulamalar ya da MSI'yi yeniden çalıştırmak)
standart Windows Installer sayfalarını kullanır ve aynı Son sayfasıyla biter.

#### Yükleyiciden şirket bağlantısı

Kayıt kodu tek kullanımlık bir gizli bilgidir; yükleyici onu hiçbir zaman komut
satırına ya da günlüğüne yazmaz: alan gizlenir, `ENROLLMENT_CODE` gizli bir
özelliktir ve sizin hesabınızla çalışan bir özel eylem onu adresle birlikte
yalnızca sizin hesabınızın açabildiği
`%USERPROFILE%\.singularity-aidr\installer-enrollment.json` dosyasına yazar.
Yükleyicinin çalıştırdığı `aidr setup` bunu uygular:
`~/.singularity-aidr/config.json` içinde `mode: "managed"`,
`control_plane.endpoint` ve `auth.enrollment_token` (ticari derleme belirteci
Windows kimlik bilgisi kasasında tutar); ardından dosyayı siler. Kayıt, bir
yapay zekâ aracı bir sonraki açılışında tamamlanır; kod yoksa yapay zekâ aracı
bu bilgisayarı şirketinizin konsolunda onaylamanız için kısa bir kod ve bir
bağlantı gösterir.

- Singularity AIDR'yi bir şirket konsoluna bağlamak yalnızca operatörün
  yapabileceği bir işlemdir: setup dosyayı yalnızca yükleyici çalıştırdığında ya
  da siz bir terminalde `aidr setup` çalıştırıp `connect` yazdığınızda uygular.
  Onaysız bir çalıştırma (örneğin bir yapay zekâ aracından) hiçbir şeyi
  değiştirmez ve dosyayı yerinde bırakır.
- 3 günden eski ya da beklenen biçimde olmayan bir dosya kullanılmadan silinir;
  güncel bilgilerle yeniden kurun.
- Zaten kayıtlı bir bilgisayar bağlantısını korur; yükleyicideki bilgiler
  kullanılmadan silinir.
- `AIDR_SKIP_SETUP=1` ile dosya kullanıcının ilk `aidr setup` çalıştırmasını bekler.
- Yerel koruma bağlantıya bağlı değildir: bağlantı kaydedilemezse setup bunu
  söyler ve koruma açık kalır.

### Debian / Ubuntu

1. `singularity-aidr_<sürüm>_amd64.deb` dosyasını indirin.
2. `sudo apt install ./singularity-aidr_<sürüm>_amd64.deb` — kurulum `sudo`
   çalıştıran kullanıcı için yapılır.
3. Yapay zekâ araçlarınızı yeniden başlatın; `aidr status` ve `aidr verify`
   çalıştırın.

### RHEL / Fedora

1. `.rpm` dosyasını indirin ve paket imzalama anahtarını bir kez içe aktarın:
   `sudo rpm --import linux-package-signing-key.asc`.
2. `sudo dnf install ./singularity-aidr-<sürüm>-1.x86_64.rpm`.
3. Yapay zekâ araçlarınızı yeniden başlatın; `aidr status` ve `aidr verify`
   çalıştırın.

### Tar arşivi (her Linux)

1. `tar -xzf singularity-aidr-<sürüm>-linux-x64.tar.gz`
2. `sudo ./singularity-aidr-<sürüm>-linux-x64/install.sh`
3. Yapay zekâ araçlarınızı yeniden başlatın; `aidr status` ve `aidr verify`
   çalıştırın.

Paket yöneticisi bir kullanıcının `sudo` komutu olmadan çalıştığında (örneğin
imaj derlemesi ya da yapılandırma yönetimi aracısı) paket yalnızca
`aidr setup` komutunu yazdırır; her kullanıcı bunu kendi hesabıyla bir kez
çalıştırır.

## Kurulum Yardımcısı (`aidr assistant`)

Kurulum Yardımcısı, aynı kurulumu tarayıcınızda Türkçe ya da İngilizce adım
adım yapan bir sayfadır. Uygulamalar menüsünden (**Singularity AIDR Kurulum
Yardımcısı**, .deb ve .rpm), Windows yükleyicisinin son sayfasından ya da bir
terminalden açın:

```sh
aidr assistant            # varsayılan tarayıcınızı açar
aidr assistant --no-open  # bunun yerine adresi yazdırır (ekransız, SSH)
```

Yedi adımı vardır: AIDR'nin ne yaptığı; bu bilgisayarda bulunan yapay zekâ
araçları (kurulu olmayanlar soluk gösterilir); şirket bağlantısı; **Koru**
(seçtiğiniz araçlar için `aidr setup` ile aynı iş; her araç için sonuç: korunuyor,
yeniden başlatma gerekli ya da elle çalıştırılacak tam komut); her araç için
`aidr verify` denetimi; Browser Guard; ve bir özet. İstediğiniz zaman yeniden
çalıştırabilirsiniz; zaten kurulu olanı değiştirmez.

**Şirket bağlantısı.** Varsayılan "Yalnızca yerel koruma"dır ve hesap gerektirmez.
"Şirketime bağla", şirketinizin AIDR panelinin adresini sorar; kısa bir bağlantı
kodu ve onay sayfasını açan bir düğme gösterir. Biri bilgisayarı onayladığında
sayfa kendiliğinden güncellenir. `mode: "managed"` ve adres ancak o zaman
`~/.singularity-aidr/config.json` dosyasına yazılır. Windows yükleyicisi bir şirket
adresini (ve isteğe bağlı tek kullanımlık bir bağlantı anahtarını)
`%USERPROFILE%\.singularity-aidr\installer-enrollment.json` dosyasına kaydettiyse,
yardımcı bunu doldurur ve kullandıktan sonra dosyayı siler. Dosyayı yalnızca o
kullanıcı okuyabiliyorsa kullanılır; aksi halde yok sayılır.

**Browser Guard bağlantıları**, panelin İndirme sayfasının kullandığı ayarlardan
gelir (`VITE_BROWSER_GUARD_CHROME_URL`, `VITE_BROWSER_GUARD_EDGE_URL`,
`VITE_BROWSER_GUARD_FIREFOX_URL`; yalnızca https, ortam değişkenlerinden okunur).
Bilgisayarda tanımlı değilse yardımcı panelin İndirme sayfasına bağlantı verir.

**Nasıl gizli kalır.** Sayfayı `aidr` kendisi `127.0.0.1` üzerinde rastgele bir
porttan sunar; ağdan erişilemez. Adres, `#` işaretinden sonra tek kullanımlık
256 bitlik bir anahtar taşır; sayfa bunu bir kez yalnızca tarayıcının gördüğü bir
oturum çerezine (HttpOnly, SameSite=Strict) çevirir; kopyalanan ya da yeniden
kullanılan adres reddedilir. Başka bir ana bilgisayar adıyla ya da başka bir web
sayfasından gelen istekler reddedilir, sayfa ikili dosyanın dışından hiçbir şey
yüklemez (`Content-Security-Policy: default-src 'self'`) ve yardımcı son sayfada
kapattığınızda ya da 30 dakika işlem yapılmadığında durur. Yalnızca algılama,
kurulum (asla `--force` ya da `--release-key` ile değil), denetim, durum gösterme
ve şirkete bağlanma yapabilir; kaldıramaz, hiçbir şeyi onaylayamaz ve başka
ayarları değiştiremez. Bir yapay zekâ aracı onu başlatamaz: bir aracın çalıştırdığı
`aidr assistant`, `aidr setup --force` gibi engellenir (`CLT-SELF-007` kuralı).
Sayfa imzalı `aidr` ikili dosyasının parçasıdır.

## Korumayı denetleme

`aidr status` tek satırlık bir sonuçla biter, örneğin:

```
Sonuç: korunuyor: Claude Code | 2026-10-13T09:00:00.000Z öncesinde açıksa yeniden başlatın: OpenCode | elle adım gerekiyor: Codex → ... | ardından 'aidr verify' çalıştırın
```

- **korunuyor** — bağlayıcı kayıtlı;
- **… öncesinde açıksa yeniden başlatın** — kurulum onu o anda kaydetti; zaten
  açık olan bir ana makine onu ancak yeniden başlatıldıktan sonra yükler;
- **elle adım gerekiyor** — o ana makine için tam komut.

`aidr verify`, zararsız bir canary'yi (ayrılmış `.invalid` alan adına yönelik bir
`curl … | bash` komutu) kayıtlı her bağlayıcının gerçek hook giriş noktasına
yalnızca veri olarak verir — hiçbir şey çalıştırılmaz — ve ana makine başına
bildirir:

- **BAŞARILI** — hook canary'yi engelledi ve zararsız `ls` ikizine izin verdi;
- **BAŞARISIZ** — engellemedi ya da her şeyi engelliyor (iç hata); o ana
  makinenin araç çağrıları denetlenmeden çalışabilir;
- **ATLANDI** — bağlayıcı yalnızca kendi ana makinesinde çalışır (OpenCode,
  OpenClaw, Claude Code eklenti kurulumu): ana makineyi yeniden başlatıp orada
  doğrulayın.

Bu komutların hiçbiri ana makinenin hook'u gerçekten çalıştırdığını kanıtlamaz;
bunun için ana makinenin kendisi gerekir ([ilk müşteri çalışma kitabı](../../deploy/FIRST_CUSTOMER.md)).

`aidr doctor` her denetim için bir satır yazar (yapılandırma, sürüm anahtarı,
tespit, bağlayıcılar, DLP, profiller, onaylar, son karar) ve biri başarısızsa
sıfırdan farklı kodla çıkar; `aidr doctor --verbose` her satırın altına nedeni,
yolu ve çözümü ekler.

## Engellenen bir işlemi onaylama

Bazı işlemler bir kişi onaylayana kadar bekletilir (örneğin `terraform destroy`
ya da `.env` dosyasını okumak). Codex, OpenCode ve OpenClaw'da (ve
`operator_approvals.mode: "operator"` olan her ana makinede) engelleme mesajı,
kendi terminalinizde çalıştıracağınız komutla başlar, örneğin:

```sh
aidr approve 3f9c2a7b   # kimliğin ilk 8 karakteri yeterlidir; "approve" yazın
aidr approve            # kimlik yok: bekleyen işlemlerin numaralı listesinden seçin
aidr pending            # bekleyen her şeyi listeler
```

AIDR ardından "Onaylandı. Yapay zekâ aracından 15 dakika içinde yeniden
denemesini isteyin." yazar; onay o tek çağrıya bir kez izin verir. Yapay zekâ
aracı hiçbir zaman kendisi onaylayamaz. Claude Code varsayılan olarak bunun
yerine kendi Evet / Hayır penceresini gösterir.

## Sessiz ve yönetilen dağıtım

### Windows: Intune, SCCM/ConfigMgr, GPO

```bat
msiexec /i singularity-aidr-<sürüm>-windows-x64.msi /qn /l*v aidr-install.log
```

- **Sistem bağlamında** makine başına kurulum (Intune Win32 uygulaması
  "Install behavior: System", SCCM, GPO yazılım kurulumu) `aidr setup`
  komutunu `LocalSystem` olarak çalıştırmaz. Bir Active Setup girdisi kaydeder;
  böylece `aidr setup` **her kullanıcı için bir sonraki oturum açışında** bir
  kez çalışır.
- Kullanıcı bağlamındaki kurulum sonunda o kullanıcı için kurulumu çalıştırır.
- `AIDR_SKIP_SETUP=1` yalnızca dosyaları kurar (ana imajlar, aşamalı dağıtım):
  `msiexec /i … /qn AIDR_SKIP_SETUP=1`.
- `AIDR_MDM_MANAGED=1` güncellemeyi MDM'nize bırakır: uç noktalar kendini
  güncellemez ([Cihaz yönetimiyle yönetilen makineler](#cihaz-yönetimiyle-yönetilen-makineler-intune-sccm-gpo-yapılandırma-yönetimi)).
- Sessiz kurulum yeni bir özellik gerektirmez: sihirbaz eklenmeden önceki gibi
  davranır. Sihirbazın şirket sayfasının iki isteğe bağlı genel özelliği vardır;
  yalnızca **kullanıcı bağlamındaki** kurulumlar içindir:
  `ENROLLMENT_URL=https://aidr.example.com` ve `ENROLLMENT_CODE=aidr_enroll_…`
  (biri yeterlidir; yalnızca `ENROLLMENT_CODE` verilirse Singularity AIDR hizmeti
  kullanılır). Biçimi bozuk bir değer kurulumu başarısız kılar ve günlüğe
  değerini değil, özelliğin adını yazar. `ENROLLMENT_CODE` msiexec günlüğünde
  gizlenir; ancak komut satırındaki bir değer msiexec çalışırken diğer
  programlarca görülebilir ve dağıtım aracınızca saklanabilir: kısa ömürlü
  kodlar kullanın. Sistem bağlamındaki kurulumda bağlanacak etkileşimli kullanıcı
  yoktur ve iki özellik de yok sayılır; bu kullanıcıları yönetilen yapılandırmayla
  kaydedin ([`mode`](../configuration.md#mode), [`auth`](../configuration.md#auth)).
- **Dil:** görüntüleme dili Türkçe olduğunda MSI Türkçe görünür.
  `TRANSFORMS=:1055` Türkçe sihirbazı zorlar; sessiz kurulum iki dilde de aynıdır.
- **Yönetici hakkı olmadan kullanıcı başına kurulum:**
  `msiexec /i … MSIINSTALLPERUSER=1 ALLUSERS=2`
  `%LOCALAPPDATA%\Programs\Singularity AIDR\` konumuna kurar ve `bundle\bin`
  klasörünü kullanıcının `PATH` değişkenine ekler.
- Intune algılama kuralı: MSI ürün kodu ya da
  `C:\Program Files\Singularity AIDR\bundle\bin\aidr.exe` dosyası.
- Yüklemeden önce imzayı doğrulayın: `signtool verify /pa /v <msi>`.

### Linux: apt / yum / dnf / yapılandırma yönetimi

```sh
sudo apt-get install -y ./singularity-aidr_<sürüm>_amd64.deb      # Debian/Ubuntu
sudo dnf install -y ./singularity-aidr-<sürüm>-1.x86_64.rpm        # RHEL/Fedora
```

Paketleri iç apt/yum deponuzda her zamanki gibi barındırın. Çağıran kullanıcı
(`SUDO_USER`) olmadan yapılan kurulum yalnızca dosyaları kurar ve `aidr setup`
yazdırır; bunu kullanıcı başına çalıştırın, örneğin bir oturum açma betiğinden:
`sudo -u alice -H aidr setup`. `AIDR_INSTALL_SKIP_SETUP=1`, `SUDO_USER`
ayarlıyken bile yalnızca dosyaları kurar.

Dağıtmadan önce indirilenleri doğrulayın:

```sh
gpg --import linux-package-signing-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS && sha256sum --check --ignore-missing SHA256SUMS
rpm -K singularity-aidr-<sürüm>-1.x86_64.rpm
```

## Güncelleme

`aidr update`, bir iş istasyonunu kurumunuzun indirme portalında yayımladığı
sürüme getirir:

```sh
aidr update --check     # daha yeni bir sürüm var mı? hiçbir şeyi değiştirmez
aidr update             # indirir, doğrular, kurar, 'aidr verify' çalıştırır; başarısız olursa eski sürümü geri koyar
```

Komutu kendi kullanıcınızla çalıştırın. Linux'ta `sudo` **kullanmayın**:
kurulum sırasında sudo parolanızı kendisi sorar. Windows'ta makine geneli bir
kurulum, **Yönetici olarak çalıştır** ile açılmış bir terminal ister; kullanıcıya
özel kurulum istemez. Kurulum korumayı değiştirdiği için `aidr update` sizden
`update` yazmanızı ister; otomasyon için `--yes` ile birlikte
`AIDR_OPERATOR_NONINTERACTIVE=1` verin.

### Güncelleme nereden gelir

| Durum | Kaynak |
|---|---|
| Yönetilen (kaydı yapılmış) cihaz | kurumunuzun portalı: `control_plane.endpoint` içindeki SaaS ya da kurum içi kontrol düzlemi; cihazın kendi API anahtarıyla (Edge Function `installer-update`) |
| Yöneticinizin verdiği kurulum dosyası | `aidr update --from <kurulum dosyası ya da https adresi>`; imzalı `manifest.json` ve `manifest.json.sig` dosyası yanında (ya da portal düzenindeki gibi üst klasörde, `<sürüm>/manifest.json`) olmalı ya da `--catalog <dosya ya da adres>` ile verilmeli |
| Kurum içi kopya | `aidr update --from <latest.json içeren klasör ya da https adresi>` ya da `update.source` ayarı |

Kopya, portal deposundaki dosya ağacının aynısıdır;
`scripts/publish-installers.mjs --dry-run --out <dizin>` tam olarak bu ağacı
hazırlar. Yalnızca `https` üzerinden indirilir.

### Kurulumdan önce ne denetlenir

1. **İmzalı katalog.** `latest.json` ve kataloğun Ed25519 imzaları ile
   `latest.json` içindeki katalog SHA-256 değeri, sabitlenmiş kurulum kataloğu
   anahtarıyla denetlenir. Anahtar yoksa hiçbir şey indirilmez.
2. **Kurulum dosyası.** İndirilen dosyanın boyutu ve SHA-256 değeri imzalı
   katalogdakiyle birebir aynı olmalıdır; değilse dosya silinir.
3. **Sürüm.** Daha eski bir sürüm, `--allow-downgrade` verilmedikçe (yöneticinizin
   istediği bir geri dönüş) reddedilir.
4. **Biçim.** `aidr update`, AIDR'nin kurulduğu biçime uyan kurulum dosyasını
   kendisi seçer: Windows'ta `.msi`; `singularity-aidr` paketi dpkg'de kayıtlıysa
   `.deb`, rpm'de kayıtlıysa `.rpm`, değilse `.tar.gz`. Portal bir platformun
   bütün biçimlerini yayımladığı için bu otomatiktir. Yalnızca katalogda o
   biçimde kurulum dosyası yoksa durur ve katalogdaki biçimleri listeler;
   yöneticinizden sizin biçiminizi yayımlamasını isteyin. Bir kurulumu bir
   biçimden diğerine geçirmez; `--from` ile verdiğiniz kurulum dosyası da aynı
   biçimde olmalıdır.

**Kurulum kataloğu anahtarı**, portal kataloğunu imzalayan anahtarın açık
kısmıdır (base64 biçimi portaldaki `AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64`
değeridir). Bunu her uç noktada, kurulum klasöründe `release-public.pem`
dosyasının yanına `config/installer-catalog-public.pem` olarak koyun
(`/opt/singularity-aidr/config/`, `C:\Program Files\Singularity AIDR\config\`;
sahibi root/Administrators olsun) ya da `update.catalog_public_keys` içinde
listeleyin. İkisi birden varsa dosya geçerlidir:

```sh
openssl pkey -in installer-catalog-key.pem -pubout -out installer-catalog-public.pem
```

### Nasıl kurar ve nasıl geri alır

| Kurulum | Komut |
|---|---|
| Windows | `msiexec /i <msi> /qn /norestart /l*v <kayıt>` (kullanıcıya özel kurulumda ayrıca `MSIINSTALLPERUSER=1 ALLUSERS=2`) |
| Debian / Ubuntu | `sudo dpkg -i <deb>` |
| RHEL / Fedora / SUSE | `sudo rpm -U <rpm>` (`--allow-downgrade` ile `--oldpackage`) |
| Tar arşivi | yeni `bundle`, zaten kurulu olan sürüm anahtarına göre denetlenir, sonra `sudo` ile yerine konur (`install.sh` kullanılmaz) |

`aidr update` kurmadan önce kurulum dosyasını ve kurulu paketi yalnızca root
ya da yöneticilerin değiştirebildiği bir klasöre kopyalar (sudo ile
`/var/cache/singularity-aidr/`; makine geneli Windows kurulumunda kurulum
klasöründeki `update-staging`), kurulum dosyasının SHA-256 değerini orada
yeniden denetler ve paket kopyasını denetler: bu kopya yedektir. Böylece aynı
kullanıcının başka bir programı, denetim ile kurulum arasında dosyayı
değiştiremez. Bozuk bir kurulumun üzerine yazılmaz (onu kurulum dosyasından
yeniden kurun). Kurulumdan sonra yeni paket, kurulu
sürüm anahtarına göre bütünlük denetiminden geçmeli, beklenen sürümü taşımalı
ve `aidr verify`, güncellemeden önce geçen bir ana makine için FAIL
bildirmemelidir. Aksi hâlde önceki paket geri konur, `aidr setup` ile yeniden
kaydedilir ve denetlenir. MSI, `.deb` ve `.rpm` kurulumlarında paket yöneticisi
bundan sonra hâlâ yeni sürümü gösterir: önceki kurulum dosyasını yeniden kurun
ya da sorun giderildikten sonra `aidr update` komutunu yeniden çalıştırın.
Başarısız bir Windows kurulumu `msiexec.log` dosyasını
`~/.singularity-aidr/updates/` altında bırakır.

### Otomatik denetim: `update.auto`

| Değer | Davranış |
|---|---|
| `notify` (varsayılan) | Bir yapay zekâ aracı oturum başlattığında, en fazla `update.check_interval_hours` (24) saatte bir, AIDR aynı imzalı kataloğu denetler ve "Singularity AIDR v… sürümü yayımlandı … Kurmak için şunu çalıştırın: aidr update" mesajını gösterir. |
| `install` | Ayrıca arka planda `aidr update --auto` başlatır. Yalnızca yapılandırılmış kaynaktan gelen, doğrulanmış daha yeni bir sürümü kurar (asla eski sürüme dönmez, asla `--from` kullanmaz) ve aynı şekilde geri alır. Linux'ta parolasız sudo, Windows'ta kullanıcıya özel kurulum gerekir (makine geneli MSI yönetici ister); yoksa yalnızca bildirmeye devam eder. |
| `off` | Otomatik denetim yok. |

Otomatik denetim yalnızca bu kurulum dosyalarıyla kurulmuş uç noktalarda
çalışır ve yalnızca kiracının kontrol düzlemine (yönetilen mod) ya da
`update.source` adresine bağlanır. Ayarlar:
[configuration.md](../configuration.md#update).

### Cihaz yönetimiyle yönetilen makineler (Intune, SCCM, GPO, yapılandırma yönetimi)

**Dağıtımı cihaz yönetimiyle (MDM) yapan müşteriler güncellemeyi de MDM
üzerinden yapar**: yeni MSI'yı ya da paketi ilk kurulumdaki gibi orada
yayımlayın. Uç noktaların kendini güncellememesi için bu kurulumları işaretleyin:

- **Windows:** makine geneli kuruluma `AIDR_MDM_MANAGED=1` ekleyin
  (`msiexec /i … /qn AIDR_MDM_MANAGED=1`). Bu,
  `HKLM\SOFTWARE\Policies\Singularity AIDR` altına `MdmManaged = 1` (DWORD)
  yazar; aynı değeri bir GPO ya da Intune yapılandırma profiliyle de
  ayarlayabilir ya da `%ProgramData%\Singularity AIDR\mdm-managed` dosyasını
  oluşturabilirsiniz.
- **Linux:** paket kurulumunda `AIDR_MDM_MANAGED=1` verin (bu,
  `/etc/singularity-aidr/mdm-managed` dosyasını yazar; paket tamamen
  kaldırılınca silinir) ya da bu dosyayı yapılandırma yönetiminizle oluşturun.

İşaretli bir makinede `update.auto` ne olursa olsun otomatik denetim kapalıdır,
`aidr update` işareti göstererek kurmayı reddeder ve `aidr update --check`
yine de yayımlanan sürümü bildirir.

## Kaldırma

| İşletim sistemi | Komut |
|---|---|
| Windows | Ayarlar → Uygulamalar → Singularity AIDR → Kaldır ya da `msiexec /x singularity-aidr-<sürüm>-windows-x64.msi /qn` |
| Debian/Ubuntu | `sudo apt remove singularity-aidr` |
| RHEL/Fedora | `sudo dnf remove singularity-aidr` |
| Tar arşivi | `sudo /yol/singularity-aidr-<sürüm>-linux-x64/uninstall.sh` |

Dosyalar silinmeden önce kaldırıcı, kaldırmayı yapan kullanıcı için
`aidr uninstall --yes --keep-data` (`AIDR_OPERATOR_NONINTERACTIVE=1` ile)
çalıştırır: her AIDR bağlayıcı kaydı kaldırılır, sizin hook'larınız kalır ve
`~/.singularity-aidr` (yapılandırma, denetim kaydı) korunur. Bu verileri ve
AIDR kasa öğelerini de silmek için paketi kaldırmadan **önce** `aidr uninstall`
komutunu kendiniz çalıştırın.

Makinede `aidr setup` çalıştırmış diğer kullanıcılar, paket kaldırılmadan önce
`aidr uninstall` çalıştırmalıdır. Aksi hâlde `~/.claude/settings.json`
dosyalarında silinmiş çalıştırılabiliri gösteren `Singularity AIDR managed
installation` işaretli hook girdileri kalır; bu girdileri silin. (Windows'ta
Active Setup kaldırmada çalışmaz.)

Yükseltmeler (daha yeni `.deb` için `apt install`, `dnf upgrade`, daha yeni MSI)
tüm kayıtları korur ve kurulumu yapan kullanıcı için kurulumu yeniden çalıştırır.

## Sorun giderme

- **Kurulumdan sonra `aidr` bulunamıyor (Windows)** — yeni bir terminal açın;
  `PATH` değişikliği yeni oturumlarda geçerlidir.
- **Kurulum Claude Code için "manual step needed" dedi** — `disableAllHooks`
  ayarlı ya da `~/.claude/settings.json` geçerli JSON değil; düzeltip
  `aidr setup` komutunu yeniden çalıştırın.
- **"the installed AIDR bundle … failed verification"** — paketteki bir dosya
  değişmiş. Paketi yeniden kurun; paketi düzenlemeyin.
- **`aidr verify` Claude Code için BAŞARISIZ diyor** — `aidr status` çalıştırıp
  tespit öz sınaması satırına bakın; başarısızsa yeniden kurun.
- **`aidr uninstall`, `receipt_connector_missing` ile reddediyor** — paket
  `aidr uninstall` çalışmadan kaldırılmış; aynı sürümü yeniden kurun,
  `aidr uninstall` çalıştırın, sonra paketi kaldırın.
- **Her araç çağrısı "sürüm anahtarı ayarlanmamış" ("the release key … is not set
  up") ile engelleniyor** — o kullanıcı olarak `aidr setup` çalıştırın
  (yükleyicinin getirdiği anahtarı ayarlar); elle kurulumda
  `aidr setup --release-key <dosya.pem>`.
- **Diğer her şey** — `aidr doctor --verbose` başarısız her denetimin nedenini ve
  çözümünü gösterir; bunu ya da `aidr support-bundle` arşivini desteğe gönderin.
- **Yükleyici boyutu** — komut satırı aracını ve her hook'u tek bir bağımsız
  program sunar; kurulu paket yaklaşık 150 MB'tır (her hook ayrı programken
  yaklaşık 900 MB'tı).
- Kayıtlar: Windows `msiexec /l*v`; Linux paket yöneticisi çıktısı.

## Yükleyicileri derleme

Komutlar ve gerekli imzalama sırları için İngilizce belgenin
[Building the installers](desktop-installers.md#building-the-installers)
bölümüne bakın. Yükleyiciler yalnızca sürüm anahtarıyla imzalanmış sürüm
derlemesini paketler; isteğe bağlı katalog anahtarı (`--catalog-key`,
`-CatalogKey`) `aidr update` için `config/installer-catalog-public.pem` olarak
kurulur. Sertifikasız yerel bir MSI `-Unsigned` gerektirir ve adı
`…-UNSIGNED.msi` ile biter; sürüm iş akışı eksik bir sırda başarısız olur.

Windows derlemesi sihirbazı (`windows/ui/AidrUI.wxs`, metinler
`windows/ui/aidr.en-US.wxl` ve `aidr.tr-TR.wxl` içinde) her dil için aynı
ProductCode ve aynı içerikle bir kez derler, Türkçe derlemeyi İngilizce MSI'ye
dil dönüşümü olarak gömer (`1055` adlı depolama, özet dilleri `1033,1055`) ve
dönüşümün yalnızca dili değiştirdiğini denetler. **Her sürüm ve mimari için tek
bir MSI yayımlanır.** Derleme için WiX 5 ve `WixToolset.UI.wixext` 5.0.2
(betik kendisi ekler), şirket sayfasının özel eylemleri (`windows/ca/`, C#,
net472) için .NET SDK gerekir. Sihirbaz görselleri (`windows/ui/banner.bmp`
493×58, `dialog.bmp` 493×312) `banner.svg` ve `dialog.svg` dosyalarından
`node deploy/installers/windows/ui/render-bitmaps.mjs` ile üretilir; güncel
değillerse derleme durur. Lisans sayfası, incelenmiş metin gelene kadar bir yer
tutucudur (`<EULA TEXT — legal review required>`, `windows/ui/eula.*.rtf`).

`pnpm test:installers` sihirbaz kaynaklarını her işletim sisteminde yapısal
olarak denetler. Bir sürümden önce gerçek bir Windows makinesinde şunlar
doğrulanmalıdır: sihirbaz İngilizce ve Türkçe görüntüleme dilinde Türkçe
(ve `TRANSFORMS=:1055` ile) görünür; "Yalnızca benim için" UAC sormadan
`%LOCALAPPDATA%\Programs` altına kurar, "tüm kullanıcılar için" onay ister;
şirket sayfası bozuk adresi ya da kodu reddeder, aktarım dosyasının erişim
listesi yalnızca kullanıcıyı içerir, `aidr setup` onu uygulayıp siler ve
`msiexec /l*v` günlüğünde kayıt kodu görünmez; Son sayfası yardımcıyı
kullanıcı olarak yükseltilmemiş başlatır (Görev Yöneticisi, "Yükseltilmiş:
Hayır") ve yönetici komut isteminden başlatılan kurulumda başlatmaz;
`msiexec /qn` `AIDR_SKIP_SETUP`/`AIDR_MDM_MANAGED` ile ve onlarsız, sistem
bağlamında da önceki gibi davranır; onarma, kaldırma ve ana sürüm yükseltmesi.

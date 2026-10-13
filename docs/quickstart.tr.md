# Hızlı başlangıç: sıfırdan korumaya

[English](quickstart.md)

Singularity AIDR'yi kuran her kişi için tek sayfa: dizüstü bilgisayarındaki geliştirici,
tarayıcıyı kullanan ofis çalışanı ve kurulumu dağıtan BT yöneticisi. Her bölüm,
kurulumun çalıştığını gösteren bir denetimle biter.

> **Kullanılabilirlik.** Singularity AIDR henüz müşteri kullanımı için yayımlanmadı
> ([Sürüm durumu](../README.md#release-status)). Aşağıdaki adımlar bir sürüm onaylandıktan
> ve kurumunuz yükleyicilerini ve Browser Guard mağaza bağlantılarını yayımladıktan sonra
> geçerlidir; o zamana kadar İndirmeler sayfası ve mağaza bağlantıları boştur.

İki şey aynı anda doğrudur ve birbiriyle çelişmez:

- **Koruma bilgisayarınızda çalışır ve hesap gerektirmez.** Yapay zekâ aracınızın denediği
  her komut, dosya ve web isteği bilgisayarın kendisinde denetlenir; ağ yokken ve kimse
  oturum açmadan önce de.
- **Yayımlanan sürüm önce kendisinin gerçek olduğunu denetler.** İçinde bir sürüm
  anahtarı vardır; kendi dosyaları veya bu anahtar doğrulanamazsa çalışmaya başlamaz
  (her işlemi engeller ve bunu söyler). Masaüstü yükleyicileri bu anahtarı zaten içerir;
  sizin ek bir şey yapmanız gerekmez. Şirketinizin AIDR paneline bağlanmak yalnızca
  merkezi özellikleri (panel, merkezi kurallar, tarayıcıdan onay) ekler; bağlanmasanız da
  yerel koruma çalışmaya devam eder.

## A. Geliştirici bilgisayarı (Windows veya Linux)

Desteklenen yapay zekâ araçları: Claude Code, OpenCode ve OpenClaw'u yükleyici kurar.
Codex, Cursor ve VS Code (Cursor ve VS Code: önizleme — henüz gerçek ortam kabul kanıtı
yok) için `aidr status` komutunun yazdırdığı bir ek adım gerekir.

1. **İndirin.** Şirketinizin AIDR paneline giriş yapın ve **Cihazlar ve indirmeler**
   altındaki **İndirmeler** sayfasını açın.
   Sayfa sisteminize uygun yükleyiciyi seçer. Her dosyanın SHA-256 değerini ve bunu
   karşılaştırmak için bir komutu da gösterir; şirketiniz isterse kullanın.
2. **Kurun.**
   - Windows 10/11: `singularity-aidr-<sürüm>-windows-x64.msi` dosyasına çift tıklayın
     ve onay penceresini kabul edin.
   - Debian / Ubuntu:

     ```sh
     sudo apt install ./singularity-aidr_<sürüm>_amd64.deb
     ```

   - RHEL / Fedora:

     ```sh
     sudo rpm --import linux-package-signing-key.asc
     sudo dnf install ./singularity-aidr-<sürüm>-1.x86_64.rpm
     ```

   - Diğer Linux dağıtımları:

     ```sh
     tar -xzf singularity-aidr-<sürüm>-linux-x64.tar.gz
     sudo ./singularity-aidr-<sürüm>-linux-x64/install.sh
     ```

   Yükleyici, sonunda AIDR'yi sizin için (yükleyiciyi çalıştıran kullanıcı) ayarlar;
   sürüm anahtarı da buna dahildir, yapılandırmanız gereken bir şey yoktur. Yapay zekâ
   araçlarınızdan hiçbiri henüz kurulu değilse "No AI tool … was found" yazar ve kurulum
   yine tamamlanır (kurulum çıkış kodu `3`; hata değildir): yapay zekâ aracınızı kurun,
   ardından bir kez `aidr setup` çalıştırın.
3. **Yapay zekâ araçlarınızı yeniden başlatın.** Zaten açık olan bir araç AIDR'yi ancak
   yeniden başlatıldıktan sonra kullanır.
4. **Denetleyin.** Yeni bir terminal açıp şunları çalıştırın:

   ```sh
   aidr status
   aidr verify
   ```

   `aidr status` tek bir satırla biter: korunan araçlar, yeniden başlatılması gereken
   araçlar ve elle bir adım gerektiren araçlar (komutuyla birlikte). `aidr verify`, her
   korunan aracın AIDR denetiminden zararsız bir deneme komutu geçirir (hiçbir şey
   çalıştırılmaz) ve her biri için **BAŞARILI**, **BAŞARISIZ** veya **ATLANDI** yazar
   (İngilizce sistemde PASS, FAIL, SKIP). Araçlarınız BAŞARILI gösteriyorsa işlem
   tamamdır. ATLANDI, denetimin aracın içinde yapıldığı anlamına gelir (OpenCode,
   OpenClaw): aracı bir kez açın ve AIDR'nin orada listelendiğini görün.
5. **Güncel kalın.** Bir yapay zekâ aracı başladığında AIDR, şirketinizin portalında (ya
   da BT'nin belirlediği güncelleme kaynağında) daha yeni bir sürüm olup olmadığını en
   fazla günde bir kez denetler ve varsa söyler ("… sürümü yayımlandı … Kurmak için şunu
   çalıştırın: aidr update"). Ardından:

   ```sh
   aidr update --check   # daha yeni sürüm var mı? hiçbir şeyi değiştirmez
   aidr update           # doğrular, kurar, 'aidr verify' çalıştırır; sorun çıkarsa eski sürümü geri koyar
   ```

   Linux'ta komutu `sudo` ile değil kendi kullanıcınızla çalıştırın (kurarken parolanızı
   kendisi sorar); Windows'ta makine geneli kurulum, **Yönetici olarak çalıştır** ile
   açılmış bir terminal ister. `update.auto` (varsayılan `notify`) `install` (arka planda
   kurar) ya da `off` da olabilir. BT'nin cihaz yönetimiyle işaretlediği bilgisayarlarda
   güncellemeler BT'den gelir; `aidr update` yalnızca denetler.

Bir sorun varsa:

- **`aidr` bulunamadı (Windows):** yeni bir terminal açın.
- **BAŞARISIZ çıkıyor veya her işlem engelleniyor:** `aidr doctor` çalıştırın (her denetim
  için bir satır; `aidr doctor --verbose` her satırın altına nedenini ve çözümünü ekler)
  ve çıktısını ya da `aidr support-bundle` komutunun ürettiği dosyayı BT ekibinize
  gönderin. Engeli kaldırmak için AIDR'yi kaldırmayın.
- **Sürüm anahtarı eksik olduğu için her işlem engelleniyor** ("sürüm anahtarı
  ayarlanmamış" ya da "sürüm doğrulama anahtarı eksik"): bir kez `aidr setup` çalıştırın;
  yükleyicinin getirdiği anahtarı ayarlar. Yükleyici olmadan elle yapılan kurulumda BT
  ekibinizden sürüm anahtarı dosyasını isteyin ve
  `aidr setup --release-key <anahtar.pem>` çalıştırın.
- **"… desteklenen bir yapay zekâ aracı bulunamadı" ya da "No AI tool … was found":**
  yapay zekâ aracınızı (Claude Code, Cursor, VS Code, Codex, OpenCode ya da OpenClaw)
  kurun, ardından `aidr setup` çalıştırın.
- **macOS:** masaüstü yükleyicisi henüz sunulmuyor. Browser Guard (B bölümü) macOS'ta
  Chrome, Edge ve Firefox ile çalışır.

Ayrıntılar: [Masaüstü yükleyicileri](installation/desktop-installers.tr.md).

## B. Ofis çalışanı (Browser Guard)

Browser Guard; ChatGPT, Gemini, Claude, Microsoft Copilot, Perplexity, DeepSeek, Mistral
Le Chat ve Grok'a yazdığınız, yapıştırdığınız veya yüklediğiniz içeriği denetler; kişisel
ve gizli bilgileri mesajınız tarayıcınızdan çıkmadan önce maskeler. Windows, Linux ve
macOS'ta çalışır.

1. **Bilgisayarınızı şirketiniz mi yönetiyor?** O zaman BT ekibiniz kurar; 4. adıma
   geçin.
2. **Kurulum bağlantısını açın.** Bağlantıyı BT ekibinizden, Singularity irtibat
   kişinizden veya paneldeki **İndirmeler** sayfasından alırsınız. Mağaza kayıtları liste
   dışıdır; mağazada arayarak bulunmazlar.
   - Chrome 120+: **Chrome'a ekle**, ardından **Uzantı ekle**.
   - Edge 120+: **Al**, ardından **Uzantı ekle**.
   - Firefox 140+: `.xpi` bağlantısını açın ve **Ekle**'ye tıklayın.
3. **Sabitleyin.** Yapboz simgesine tıklayıp **Singularity AIDR Browser Guard**'ı araç
   çubuğuna sabitleyin.
4. **Denetleyin.** Desteklenen bir yapay zekâ sitesini açın, bir mesaja
   `jane.doe@example.com` yazıp gönderin. Site adres yerine `[EMAIL_1_xxxx]` gibi bir
   etiket alır; yanıtta gerçek adresiniz yalnızca sizin bilgisayarınızda yeniden
   görünür. Araç çubuğu penceresi sekmenin korunmadığını söylüyorsa sekmeyi yenileyin.

Ayrıntılar: [Browser Guard'ı kurma](installation/browser-guard.tr.md).

## C. BT yöneticisi

### Masaüstü yükleyicisini dağıtın

Windows (Intune Win32 uygulaması, SCCM/ConfigMgr veya GPO ile yazılım dağıtımı):

```bat
msiexec /i singularity-aidr-<sürüm>-windows-x64.msi /qn /l*v aidr-install.log
```

Sistem bağlamında yapılan makine geneli kurulum, AIDR'yi **her kullanıcı için bir sonraki
oturum açışında** ayarlar. Intune algılama kuralı: MSI ürün kodu veya
`C:\Program Files\Singularity AIDR\bundle\bin\aidr.exe` dosyası. Yüklemeden önce imzayı
denetleyin: `signtool verify /pa /v <msi>`.

Linux (kurum içi apt/yum deponuz veya yapılandırma yönetimi):

```sh
sudo apt-get install -y ./singularity-aidr_<sürüm>_amd64.deb   # Debian/Ubuntu
sudo dnf install -y ./singularity-aidr-<sürüm>-1.x86_64.rpm     # RHEL/Fedora
sudo -u ayse -H aidr setup                                     # kullanıcının kendi sudo'su olmadan kurulduysa, her kullanıcı için bir kez
```

Betikler ve algılama kuralları için kurulum çıkış kodları: `0` korunuyor, `3` o
kullanıcıda henüz desteklenen bir yapay zekâ aracı kurulu değil (hata değildir; paket ve
MSI yine kurulur), `1` gerçek bir kurulum sorunu. Yükleyici olmadan elle yapılan kurulum
önce sürüm anahtarını ister: `aidr setup --release-key <anahtar.pem>`.

Güncelleme: yeni yükleyiciyi aynı yolla dağıtın; kayıtlar korunur. Uç noktaların
güncellemeyi size bırakması için kuruluma `AIDR_MDM_MANAGED=1` ekleyin; bu olmadan uç
noktalar portalınızdan `aidr update` ile kendilerini güncelleyebilir (`update.auto`).
Ayrıntılar, kaldırma ve paket imzası denetimi:
[Masaüstü yükleyicileri](installation/desktop-installers.tr.md).

### Browser Guard'ı zorunlu kurun

Uzantıyı tarayıcının zorunlu kurulum listesine ekleyin (Intune Ayarlar kataloğu, GPO
ADMX, Google Yönetici Konsolu veya Firefox `policies.json`):

| Tarayıcı | Değer |
|---|---|
| Chrome | `<CHROME_WEB_STORE_ID>;https://clients2.google.com/service/update2/crx` |
| Edge | `<EDGE_ADDONS_ID>;https://edge.microsoft.com/extensionwebstorebase/v1/crx` |
| Firefox | Kimlik `browser-guard@singularityrd.com`, kurulum adresi imzalı `.xpi` dosyasını barındırdığınız adres |

İki mağaza kimliği ancak Singularity mağaza kayıtlarını yayımladıktan sonra oluşur;
bunları Singularity irtibat kişiniz verir, panelin İndirmeler sayfası da bu kimliklerle
yapılandırıldıysa gösterir. Önce bir pilot grupla `"mode": "monitor"` kullanın (hiçbir
şey maskelenmez, her şey sayılır). Intune, Google Yönetici Konsolu, GPO ve Firefox için
adım adım anlatım, kilitlenebilen ayarlar ve geri alma:
[Browser Guard'ı kurumda dağıtma](installation/browser-guard-enterprise.tr.md).

### Kısaca onaylar

Bazı işlemler risklidir ama bazen gereklidir (örneğin `terraform destroy` veya `.env`
dosyasını okumak). AIDR bu işlemi bekletir ve kararı bir **kişi** verir; yapay zekâ aracı
kendi işlemini hiçbir zaman onaylayamaz.

- **Claude Code** varsayılan olarak kendi onay penceresini gösterir; kararı kullanıcı
  orada verir.
- **Codex, OpenCode, OpenClaw** (ve `operator_approvals.mode` değeri `"operator"` olduğunda
  Claude Code, Cursor ve VS Code): işlem engellenir ve mesaj tam komutu gösterir.
  Bilgisayarın başındaki kişi onu kendi terminalinde çalıştırır:

  ```sh
  aidr approve 3f9c2a7b        # kimliğin ilk 8 karakteri yeterlidir; onaylamak için "approve" yazın
  aidr approve                 # ya da: bekleyenlerin numaralı listesinden seçin
  aidr pending                 # bekleyen her şeyi görün
  ```

  AIDR "Onaylandı. Yapay zekâ aracından 15 dakika içinde yeniden denemesini isteyin."
  yazar. Onay o tek işleme bir kez izin verir; varsayılan süre 15 dakikadır.
- **AIDR paneli kullanılıyorsa** (yönetilen mod), sahipler ve yöneticiler iki adımlı
  doğrulamayla giriş yapıp **Onaylar** sayfasından da onay verebilir.

Ayrıntılar (İngilizce): [Operator approvals](configuration.md#operator-approvals).

## D. AIDR'yi kendi sunucularınızda çalıştırma (on-prem)

Dizüstü bilgisayarlar ve tarayıcılar yukarıdakiyle aynı şekilde kurulur; yalnızca
bağlandıkları panel sizin ortamınızda çalışır. Bu belgeler İngilizcedir:

- Docker Compose ile tek Linux sunucusu: [AIDR on-prem installation](../deploy/onprem/README.md)
- Helm ile Kubernetes: [Running AIDR on Kubernetes](operations/kubernetes.md)
- Genel bakış, internetsiz (air-gapped) kurulum ve topolojiler: [On-premises deployment](deployment/onprem.md)
- Güncellemeler: tek komut, `pnpm onprem:upgrade --to <yeni sürüm dizini>` (yedek,
  denetimler, yükseltme, sağlık denetimi; bir adım başarısız olursa durur ve ne
  yapılacağını söyler): [On-prem kurulumu yükseltme](operations/onprem-upgrade.tr.md)
  (Türkçe); sözleşmeler: [Upgrade runbook](../deploy/UPGRADE.md)
- İlk müşteri kurulum ve kabul kılavuzu (Türkçe): [FIRST_CUSTOMER.md](../deploy/FIRST_CUSTOMER.md)

Role göre tüm kurulum ve dağıtım belgeleri: [Kurulum belgeleri](installation/README.tr.md).

# Masaüstü yükleyicileri (Windows ve Linux)

[English](desktop-installers.md)

Masaüstü yükleyicileri AIDR'yi bir iş istasyonuna kendi kendine yeterli olarak
kurar: Node.js ya da paket deposu gerekmez. Her yükleyici `pnpm build:sea` ile
üretilen bağımsız paketi (`aidr` komut satırı aracı ve Claude Code hook
çalıştırılabilirleri, yanlarında tehdit kurallarıyla) ve sürüm güven açık
anahtarını içerir; ardından oturum açmış kullanıcı için `aidr setup` çalıştırır.

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

- **Claude Code** — paketin hook çalıştırılabilirlerini `~/.claude/settings.json`
  dosyasına kaydeder (yalnızca AIDR işaretli girdiler değişir; sizin hook'larınız
  kalır). Öncesinde paketteki her dosyayı bildirim dosyasıyla karşılaştırır ve
  PreToolUse çalıştırılabilirinden zararsız bir engelleme canary'si geçirir;
  biri başarısız olursa hiçbir şey kaydetmez. Etkin bir AIDR Claude Code
  eklentisine dokunulmaz.
- **OpenCode** — `@singularityrd/aidr-opencode` paketini kaydeder (OpenCode bir
  sonraki açılışta özel depodan kurar).
- **OpenClaw** — `openclaw` komutu `PATH` üzerindeyse `openclaw plugins install`
  çalıştırır.
- **Codex, Cursor, VS Code** — pakette yok. `aidr status` gereken adımı tam
  komutuyla yazdırır (Codex: `aidr-codex-hook` paketi; Cursor/VS Code: imzalı VSIX).

## Hızlı başlangıç

### Windows

1. AIDR panelindeki İndirme sayfasından `singularity-aidr-<sürüm>-windows-x64.msi`
   dosyasını indirin.
2. Çift tıklayın ve onay penceresini kabul edin. Kurulum sonunda sizin için
   `aidr setup` çalışır.
3. Yapay zekâ araçlarınızı (Claude Code, Cursor, VS Code, ...) yeniden başlatın.
   Yeni bir terminal açıp `aidr status`, ardından `aidr verify` çalıştırın.

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
- **Yükleyici boyutu** — her yükleyici yaklaşık 200–300 MB'tır: her hook ayrı,
  kendi kendine yeterli bir çalıştırılabilirdir.
- Kayıtlar: Windows `msiexec /l*v`; Linux paket yöneticisi çıktısı.

## Yükleyicileri derleme

Komutlar ve gerekli imzalama sırları için İngilizce belgenin
[Building the installers](desktop-installers.md#building-the-installers)
bölümüne bakın. Sertifikasız yerel bir MSI `-Unsigned` gerektirir ve adı
`…-UNSIGNED.msi` ile biter; sürüm iş akışı eksik bir sırda başarısız olur.

# Yükleyici indirme portalı (işletmeciler için)

English: [download-portal.md](download-portal.md)

Müşteriler AIDR yükleyicisini panelin **İndir** sayfasından (`/downloads`,
ayrıca kurulumun 1. adımı) indirir. Sayfa ziyaretçinin işletim sistemini
algılar, uygun platformu öne çıkarır, diğer platformları boyut, SHA-256 ve
kopyalanabilir sağlama toplamı komutuyla listeler; Browser Guard mağaza
bağlantılarını ve BT / MDM dağıtım notlarını gösterir.

Bir platform birden çok **biçimde** yayımlanabilir: Windows `.msi`; Linux
`.deb`, `.rpm` ve `.tar.gz`. Her platformda önce önerilen biçim, altında
diğerleri gösterilir: Windows'ta `.msi`; Linux'ta Debian/Ubuntu için `.deb`,
RHEL/Fedora için `.rpm`, diğer dağıtımlar için (ve tarayıcı dağıtımı
belirtmiyorsa) `.tar.gz` arşivi. Her biçimin hangi dağıtımlar için olduğu
yanında yazar.

Yükleyiciler **Windows ve Linux** için sunulur. macOS yükleyicisi yoktur; macOS
ziyaretçisi bunu belirten kısa bir not görür, Browser Guard (Chrome, Edge,
Firefox) macOS'ta yine çalışır. Platform listesi veridir
(`supabase/functions/_shared/installer-catalog.ts` içindeki
`INSTALLER_PLATFORMS`, `scripts/publish-installers.mjs` içindeki `PLATFORMS` ve
`public.record_installer_download` içindeki platform denetimi); yeni bir
platform sayfa değiştirilmeden eklenebilir. Biçim listesi de veridir
(`_shared/installer-catalog.ts` içindeki `INSTALLER_FORMATS`,
`scripts/publish-installers.mjs` içindeki `FORMATS`; `aidr update` yeni bir
biçimi kurabilsin diye `packages/cli/src/utils/update-installer.ts` içindeki
`KIND_FORMATS`).

## İşleyiş

- **Kapalı başarısızlık.** Oturum yoksa 401. Etkin bir kiracının etkin üyesi
  değilse 403. Süresi dolmuş, iptal edilmiş veya hakkı olmayan kiracı: 403
  `entitlement_required`. Okunamayan kabul durumu, depolama hatası ya da imzası
  veya özeti doğrulanmayan katalog: 503, hiçbir şey listelenmez. Bağlantı ancak
  denetim kaydı yazıldıktan sonra döner.
- **Denetim.** Her bağlantı `admin_audit_logs` tablosuna `installer.download`
  eylemiyle kiracı, kullanıcı, sürüm, platform, biçim, dosya adı ve SHA-256 yazar. IP
  adresi veya tarayıcı bilgisi saklanmaz. Sahipler ve yöneticiler bu kayıtları
  denetim izinde ve dışa aktarımda görür.
- **Hız sınırları.** Kullanıcı ve kiracı başına dakikada: katalog 60 / 3000,
  indirme bağlantısı 20 / 600 (kapalı başarısızlık).
- **Yönetilen kayıt.** Sahip, yönetici ve üyeler için katalog kontrol düzleminin
  genel adresini içerir; sayfa mevcut cihaz kodu akışını gösterir (kodu
  `/verify` sayfasında onaylayın). Tarayıcıda gizli bilgi üretilmez.

- **Uç nokta güncellemeleri.** Kaydı yapılmış uç noktalar aynı kataloğa,
  tarayıcı oturumu olmadan, kiracı API anahtarlarıyla `installer-update` Edge
  Function üzerinden ulaşır: etkin bir kiracının etkin sahip/yönetici/üye
  anahtarı ve ETKİN bir kabul gerekir. İşlev imzalı `latest.json` ve katalog
  baytlarını olduğu gibi döndürür; `aidr update` bunları sabitlenmiş katalog
  anahtarıyla yeniden doğrular, ardından güncel sürüm için, uç noktanın
  kurulduğu biçimde (`.msi`, `.deb`, `.rpm` veya `.tar.gz`) tek bir imzalı
  adres alır ve aynı `installer.download` denetim kaydı yazılır (işlemi yapan:
  anahtarın sahibi). Anahtar ve kiracı başına dakikada: katalog 30 / 6000,
  indirme bağlantısı 10 / 3000. Bkz. [Güncelleme](desktop-installers.tr.md#güncelleme).

## Depolama sözleşmesi

Özel kova, varsayılan adı `aidr-installers` (göç
`20261013000600_installer_download_portal.sql` oluşturur; başka bir ad için
`AIDR_INSTALLERS_BUCKET` ayarlayın ve o kovayı istemci ilkesi olmadan özel
oluşturun). Denetim işlevi isteğe bağlı `p_format` bağımsız değişkenini
`20261013000610_installer_download_format.sql` göçüyle kazandı; özgün altı
bağımsız değişkenle çağıran eski sürüm de çalışmaya devam eder.

| Nesne | İçerik | Yazılma |
|---|---|---|
| `<sürüm>/<platform>/<dosya>` | yükleyici baytları, imzalı sürüm yapıtının aynısı; platform ve biçim başına bir dosya | bir kez, asla değiştirilmez |
| `<sürüm>/SHA256SUMS` | her yükleyici için `<sha256>  <platform>/<dosya>` | bir kez |
| `<sürüm>/release/aidr-release.manifest.json` / `.sig` | yükleyicilerin geldiği imzalı sürüm bildirimi (güven zinciri) | bir kez |
| `<sürüm>/manifest.json` | yükleyici kataloğu: sürüm, kanal, `published_at`, `release_notes_url`, sürüm etiketi/commit/sıra numarası, imzalı bildirimin özeti ve imzalayanı; dosya başına `platform`, `os`, `arch`, `file`, `path`, `size`, `sha256`, `minimum_os`, `format` | bir kez |
| `<sürüm>/manifest.json.sig` | `manifest.json` baytları üzerinde Ed25519 imzası | bir kez |
| `latest.json` / `latest.json.sig` | güncel sürüme imzalı işaretçi | her yayında, en son |

Platformlar: `windows-x64`, `windows-arm64`, `linux-x64`, `linux-arm64`.
Biçimler: `msi` (Windows); `deb`, `rpm`, `tar.gz` (Linux). Dosya uzantısı
biçimi belirler.

### Katalog şema sürümleri

| `schema_version` | Dosyalar | Ne zaman yazılır |
|---|---|---|
| `1` | platform başına en fazla bir | her platformun tek dosyası varsa (biçimlerden önceki gibi) |
| `2` | platform **ve** biçim başına bir; her dosya adı `.<biçim>` ile biter | en az bir platformun birden çok biçimi varsa |

İşaretçi (`latest.json`, `schema_version` 1) ve imza zarfı değişmedi; daha önce
yayımlanmış şema 1 katalog doğrulanmaya ve okunmaya devam eder. Şema 2'yi
`installer-download` / `installer-update` işlevleri ve bu sürümden itibaren
`aidr update` okur. Daha eski `aidr` kullanan uç noktalar yalnızca şema 1
okur: onlar güncellenene kadar ya platform başına tek dosya yayımlayın
(`--installer` seçeneğini platform başına bir kez verin; şema 1 yazılır) ya da
onları bir kez paket yöneticisi veya yükleyiciyle güncelleyin (`apt install
./….deb`, `dnf install ./….rpm`, MSI). İlk şema 2 yayınından önce göçleri ve
Edge Function'ları dağıtın; eski bir işlev şema 2 kataloğu reddeder ve hiçbir
şey listelemez.

### Biçim seçimi

İndirme isteği (`POST`) isteğe bağlı `format` alanı alır. Bu, katalogda o
platform için listelenen bir biçim olmalıdır; değilse yanıt 404
`installer_not_found` olur ve adres üretilmez; bozuk bir değer 400
`invalid_request` döner. `format` içermeyen istek (biçimlerden önceki biçim)
platformun tek dosyasını, yoksa varsayılan biçimini (Windows'ta `msi`,
Linux'ta `tar.gz`) alır. Denetim kaydı verilen biçimi yazar.

İmzalar `scripts/release-signing-lib.mjs` içindeki sürüm imza zarfını kullanır;
anahtar, sürüm imzalama anahtarı değil, **ayrı bir yükleyici kataloğu
anahtarıdır**.

## Yayınlama

`scripts/publish-installers.mjs`, yükseltilmiş (promote edilmiş) bir sürümün
yükleyicilerini yeniden yayımlar: sürüm paketini güvenilir imzalayan ilkesiyle
doğrular, yükleyicileri uzantıya göre seçer (paketteki her
`installers/<platform>/<dosya>`, uzantısı o platformun bir biçimiyse: `.msi`;
`.deb`, `.rpm`, `.tar.gz`; oradaki diğer dosyalar atlanır ve `skipped` olarak
bildirilir; ya da biçim başına bir kez verilen `--installer <platform>=<yol>`),
aynı platform ve biçimde iki dosya varsa durur, her yükleyicinin imzalı bir
yapıt olduğunu ve `SHA256SUMS` içinde aynı özetle yer aldığını denetler,
kataloğu (şema 1 veya 2) imzalar ve hizmet rolü anahtarıyla
yükler. Sürümlü nesneler üzerine yazılmaz; `latest.json` en son yazılır ve daha
düşük bir sıra numarasına geri alınmaz. İmzalama anahtarı, anahtar kimliği,
`SUPABASE_URL` veya `SUPABASE_SERVICE_ROLE_KEY` yoksa hiçbir şey yüklenmez.

Sürüm yükseltme iş akışına eklenecek adım ve yerel deneme (`--dry-run`) için
İngilizce belgeye bakın: [download-portal.md](download-portal.md#publishing-release-promotion).

## Yapılandırma

Edge Function `installer-download` ve `installer-update` (aynı değişkenler): `SUPABASE_URL`,
`SUPABASE_SERVICE_ROLE_KEY`, `AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64` (zorunlu),
`AIDR_INSTALLERS_BUCKET` (varsayılan `aidr-installers`),
`AIDR_INSTALLER_URL_TTL_SECONDS` (varsayılan 300, 30..900),
`AIDR_PUBLIC_API_ORIGIN` (`SUPABASE_URL` iç adresse zorunlu).

Panel derlemesi (isteğe bağlı; ayarlanmamış veya https olmayan bağlantı
gizlenir): `VITE_BROWSER_GUARD_CHROME_URL`, `VITE_BROWSER_GUARD_EDGE_URL`,
`VITE_BROWSER_GUARD_FIREFOX_URL`, `VITE_BROWSER_GUARD_CHROME_EXTENSION_ID`,
`VITE_BROWSER_GUARD_EDGE_EXTENSION_ID`, `VITE_AIDR_ADMIN_GUIDE_URL`. Firefox
uzantı kimliği her zaman `browser-guard@singularityrd.com` olur.

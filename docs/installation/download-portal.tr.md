# Yükleyici indirme portalı (işletmeciler için)

English: [download-portal.md](download-portal.md)

Müşteriler AIDR yükleyicisini panelin **İndir** sayfasından (`/downloads`,
ayrıca kurulumun 1. adımı) indirir. Sayfa ziyaretçinin işletim sistemini
algılar, uygun yükleyiciyi öne çıkarır, diğer platformları boyut, SHA-256 ve
kopyalanabilir sağlama toplamı komutuyla listeler; Browser Guard mağaza
bağlantılarını ve BT / MDM dağıtım notlarını gösterir.

Yükleyiciler **Windows ve Linux** için sunulur. macOS yükleyicisi yoktur; macOS
ziyaretçisi bunu belirten kısa bir not görür, Browser Guard (Chrome, Edge,
Firefox) macOS'ta yine çalışır. Platform listesi veridir
(`supabase/functions/_shared/installer-catalog.ts` içindeki
`INSTALLER_PLATFORMS`, `scripts/publish-installers.mjs` içindeki `PLATFORMS` ve
`public.record_installer_download` içindeki platform denetimi); yeni bir
platform sayfa değiştirilmeden eklenebilir.

## İşleyiş

- **Kapalı başarısızlık.** Oturum yoksa 401. Etkin bir kiracının etkin üyesi
  değilse 403. Süresi dolmuş, iptal edilmiş veya hakkı olmayan kiracı: 403
  `entitlement_required`. Okunamayan kabul durumu, depolama hatası ya da imzası
  veya özeti doğrulanmayan katalog: 503, hiçbir şey listelenmez. Bağlantı ancak
  denetim kaydı yazıldıktan sonra döner.
- **Denetim.** Her bağlantı `admin_audit_logs` tablosuna `installer.download`
  eylemiyle kiracı, kullanıcı, sürüm, platform, dosya adı ve SHA-256 yazar. IP
  adresi veya tarayıcı bilgisi saklanmaz. Sahipler ve yöneticiler bu kayıtları
  denetim izinde ve dışa aktarımda görür.
- **Hız sınırları.** Kullanıcı ve kiracı başına dakikada: katalog 60 / 3000,
  indirme bağlantısı 20 / 600 (kapalı başarısızlık).
- **Yönetilen kayıt.** Sahip, yönetici ve üyeler için katalog kontrol düzleminin
  genel adresini içerir; sayfa mevcut cihaz kodu akışını gösterir (kodu
  `/verify` sayfasında onaylayın). Tarayıcıda gizli bilgi üretilmez.

## Depolama sözleşmesi

Özel kova, varsayılan adı `aidr-installers` (göç
`20261013000600_installer_download_portal.sql` oluşturur; başka bir ad için
`AIDR_INSTALLERS_BUCKET` ayarlayın ve o kovayı istemci ilkesi olmadan özel
oluşturun).

| Nesne | İçerik | Yazılma |
|---|---|---|
| `<sürüm>/<platform>/<dosya>` | yükleyici baytları, imzalı sürüm yapıtının aynısı | bir kez, asla değiştirilmez |
| `<sürüm>/SHA256SUMS` | her yükleyici için `<sha256>  <platform>/<dosya>` | bir kez |
| `<sürüm>/release/aidr-release.manifest.json` / `.sig` | yükleyicilerin geldiği imzalı sürüm bildirimi (güven zinciri) | bir kez |
| `<sürüm>/manifest.json` | yükleyici kataloğu: sürüm, kanal, `published_at`, `release_notes_url`, sürüm etiketi/commit/sıra numarası, imzalı bildirimin özeti ve imzalayanı; dosya başına `platform`, `os`, `arch`, `file`, `path`, `size`, `sha256`, `minimum_os`, `format` | bir kez |
| `<sürüm>/manifest.json.sig` | `manifest.json` baytları üzerinde Ed25519 imzası | bir kez |
| `latest.json` / `latest.json.sig` | güncel sürüme imzalı işaretçi | her yayında, en son |

Platformlar: `windows-x64`, `windows-arm64`, `linux-x64`, `linux-arm64`.

İmzalar `scripts/release-signing-lib.mjs` içindeki sürüm imza zarfını kullanır;
anahtar, sürüm imzalama anahtarı değil, **ayrı bir yükleyici kataloğu
anahtarıdır**.

## Yayınlama

`scripts/publish-installers.mjs`, yükseltilmiş (promote edilmiş) bir sürümün
yükleyicilerini yeniden yayımlar: sürüm paketini güvenilir imzalayan ilkesiyle
doğrular, her yükleyicinin imzalı bir yapıt olduğunu ve `SHA256SUMS` içinde aynı
özetle yer aldığını denetler, kataloğu imzalar ve hizmet rolü anahtarıyla
yükler. Sürümlü nesneler üzerine yazılmaz; `latest.json` en son yazılır ve daha
düşük bir sıra numarasına geri alınmaz. İmzalama anahtarı, anahtar kimliği,
`SUPABASE_URL` veya `SUPABASE_SERVICE_ROLE_KEY` yoksa hiçbir şey yüklenmez.

Sürüm yükseltme iş akışına eklenecek adım ve yerel deneme (`--dry-run`) için
İngilizce belgeye bakın: [download-portal.md](download-portal.md#publishing-release-promotion).

## Yapılandırma

Edge Function `installer-download`: `SUPABASE_URL`,
`SUPABASE_SERVICE_ROLE_KEY`, `AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64` (zorunlu),
`AIDR_INSTALLERS_BUCKET` (varsayılan `aidr-installers`),
`AIDR_INSTALLER_URL_TTL_SECONDS` (varsayılan 300, 30..900),
`AIDR_PUBLIC_API_ORIGIN` (`SUPABASE_URL` iç adresse zorunlu).

Panel derlemesi (isteğe bağlı; ayarlanmamış veya https olmayan bağlantı
gizlenir): `VITE_BROWSER_GUARD_CHROME_URL`, `VITE_BROWSER_GUARD_EDGE_URL`,
`VITE_BROWSER_GUARD_FIREFOX_URL`, `VITE_BROWSER_GUARD_CHROME_EXTENSION_ID`,
`VITE_BROWSER_GUARD_EDGE_EXTENSION_ID`, `VITE_AIDR_ADMIN_GUIDE_URL`. Firefox
uzantı kimliği her zaman `browser-guard@singularityrd.com` olur.

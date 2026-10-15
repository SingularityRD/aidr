# Kurum içi kurulumu güncelleme

[English](onprem-upgrade.md)

Bu rehber, kendi sunucularında Singularity AIDR yönetim katmanını çalıştıran
yöneticiler içindir. Docker Compose kurulumunun tek komutla güncellenmesini, Helm ile üç
komutluk güncellemeyi, internete kapalı (air-gapped) sunucular için tek imzalı paketi ve
bir güncelleme durduğunda ne yapılacağını anlatır. Her adımın ayrıntılı kuralları
[güncelleme runbook'unda](../../deploy/UPGRADE.md) ve
[kurum içi kurulum rehberinde](../../deploy/onprem/README.md) yer alır.

Uç nokta koruması buna bağlı değildir: yönetim katmanı güncellenirken bağlayıcılar
yerel olarak korumaya devam eder.

## Docker Compose: tek komut

Başlamadan önce üç şeye ihtiyacınız var:

1. **Kendi dizininde hazırlanmış yeni sürüm.** Çalışan kurulumun üzerine asla
   hazırlamayın. Yeni sürümün doğrulanmış kitinden:

   ```sh
   node scripts/deployment-prepare.mjs --mode self-hosted --output /srv/aidr-target ...
   ```

   Çalışan kurulumla aynı `--dashboard-url`, `--supabase-url`, `--region` ve
   `--tenant-region` değerlerini kullanın.
2. **Sürüm sorumlusunun uyumluluk sözleşmesi**, varsayılan olarak
   `/secure/aidr-upgrade/upgrade-compatibility.json` konumunda ve deneme kanıtıyla yan
   yana ([biçim](../../deploy/UPGRADE.md#required-release-evidence)).
3. **Yedek anahtarı**, varsayılan olarak `/secure/aidr-recovery.key`; kurulumdan ve
   yedeklerden ayrı tutulur.

Ardından onaylı bakım penceresinde, yeni sürümün kitinden:

```sh
pnpm onprem:upgrade --to /srv/aidr-target --dry-run   # planı gösterir, hiçbir şeyi değiştirmez
pnpm onprem:upgrade --to /srv/aidr-target             # güncellemeyi çalıştırır
```

pnpm yoksa aynı seçeneklerle `node scripts/onprem-upgrade.mjs` kullanın. Kurulum,
`--current` verilmedikçe (veya `AIDR_DEPLOYMENT_DIR` ayarlanmadıkça) `/srv/aidr`'dir.
Sistem dili Türkçe olduğunda veya `--lang tr` ile mesajlar Türkçe gelir.

Komut şu adımları sırayla çalıştırır ve ilk başarısız adımda durur:

| Adım | Ne olur | Çalıştırdığı araç |
|---|---|---|
| 1. Kontrol | Yeni sürüm bu kuruluma uyuyor: aynı platform temeli ve adresler, veritabanı değişiklikleri yalnızca sona eklenmiş, sözleşme tam bu iki sürüm için onaylanmış, imza anahtarları değişmemiş. Yalnızca okur. | `deployment-upgrade.mjs check` |
| 2. Yedek | `/backups/aidr-pre-upgrade-<zaman>` içine şifreli soğuk yedek (`--backup-root` ile değiştirilir). Yedek sırasında servisler durur ve yeniden başlar. | `deployment-backup.mjs backup` |
| 3. Doğrulama | Yedek açılabiliyor ve eksiksiz. | `deployment-backup.mjs verify` |
| 4. Son kontroller | İki sürümün her dosyası kayıtlı özetiyle eşleşiyor; yedek bu kuruluma ait ve güncel. | `deployment-upgrade.mjs preflight` |
| 5. Uygulama | Yazan servisler durur, veritabanı değişiklikleri önce denenir sonra tek işlemde uygulanır, yeni dosyalar kurulur. | `deployment-upgrade.mjs apply` |
| 6. Yeniden başlatma | Yeni sürüm başlar (5. adımın parçası). | |
| 7. Sağlık kontrolü | Çevrim içi sağlık kontrolü (doctor) geçer (5. adımda ve burada yeniden çalışır). | `deployment-doctor.mjs --online` |
| 8. Güncelleme sonrası kontroller | Kurulu sürüm güncelleme kaydıyla eşleşiyor, sağlık kaydı bu çalıştırmaya ait ve başarılı, panel yanıt veriyor. | yalnızca okur |

`--to` çalışan dizinin kendisiyse (veya onun içindeyse), hedef daha önce çalışan bir
kurulum olarak kullanılmışsa ya da sözleşme, yedek anahtarı veya yedek klasörü yoksa
başlamayı reddeder. Tamamlanmamış önceki bir güncellemenin üzerine asla yazmaz: ona
`--resume` ile devam etmenizi söyler. Tamamlanmış olanı
`/srv/aidr/.aidr-upgrade/history/` altına taşır.

Kendi aldığınız ve doğruladığınız bir yedeği kullanmak için `--backup <dizin>` verin
(24 saatten yeni olmalı; `--max-backup-age-hours` ile en fazla 168).

Her çalıştırma, her adımın sonucunu ve zamanını
`/srv/aidr/.aidr-upgrade/onprem-upgrade-receipt.json` dosyasına yazar; güncelleme
aracının kendi kaydı `/srv/aidr/.aidr-upgrade/upgrade-receipt.json` dosyasıdır. İkisi de
müşteri kabulü değildir: başarılı bir çalıştırmadan sonra yönetici olarak giriş yapın,
bir deneme cihazı kaydedin, engellenmesi gereken bir işlemin engellendiğini görün ve
denetim kaydını dışa aktarın.

Kurulum Yapay Zekâ Güvenlik Duruşu tarayıcısını veya gizlilik ağ geçidini çalıştırıyorsa,
çalıştırmadan önce hazırlanmış dizinlerini
[kurum içi rehberde](../../deploy/onprem/README.md#upgrade) anlatıldığı gibi kopyalayın.

<a id="guncelleme-basarisiz-olursa"></a>

## Güncelleme başarısız olursa

Komut hangi adımda durduğunu, nedenini, kurulumun durumunu ve sıradaki komutun tam
halini yazar. Kısaca:

| Durduğu yer | Kurulumunuz | Ne yapmalı |
|---|---|---|
| 1. Kontrol, 3. Doğrulama, 4. Son kontroller | Değişmedi; mevcut sürüm çalışmaya devam ediyor. | Nedeni giderin ve aynı komutu yeniden çalıştırın. Son kontroller başarısız olursa az önce doğrulanan yedeği yeniden kullanmak için `--backup <dizin>` önerir. |
| 2. Yedek | Değişmedi. Yedek aracı durdurduğu servisleri yeniden başlatır. | Bazıları duruyorsa: `node scripts/deployment-backup.mjs recover-services --deployment /srv/aidr --recovery-journal /var/lib/aidr-backup/recovery-journal.json`, sonra yeniden çalıştırın. |
| 5. Uygulama, veritabanı değişikliğinden önce | Veritabanı değişmedi ve önceki sürüm yeniden başlatıldı. | Nedeni giderin, sonra `pnpm onprem:upgrade --to /srv/aidr-target --resume`. |
| 5–7, veritabanı değişikliğinden sonra | Veritabanı zaten yeni sürümde. Kullanıcıları sistemden uzak tutun. | `docker compose ... logs` ile bakın, nedeni giderin ve `--resume` ile devam edin. Giderilemiyorsa geri yükleyin (aşağıda). |
| 8. Güncelleme sonrası kontroller | Yeni sürüm kurulu ve çalışıyor. | Başarısız kontrolü giderin, `node scripts/deployment-doctor.mjs --deployment /srv/aidr --online` komutunu yeniden çalıştırın, sonra doğrulamak için `--resume`. |
| Ctrl+C veya durdurma sinyali | Güvenli bir noktada durdu. | `--resume` ile devam edin. |

**Otomatik geri yükleme yapılmaz.** Veritabanı değişikliğinden önce güncelleme aracı
önceki sürümü zaten kendisi geri getirir. Sonrasında geri dönmek, doğrulanmış yedeği
yeni ve ayrı bir kuruluma geri yüklemek demektir ve kullanıcılar taşınmadan önce sizin
kararınızı gerektirir:

```sh
node scripts/deployment-upgrade.mjs recover \
  --current /srv/aidr --target /srv/aidr-target \
  --backup /backups/aidr-pre-upgrade-<zaman> --key-file /secure/aidr-recovery.key \
  --contract /secure/aidr-upgrade/upgrade-compatibility.json \
  --recovery-runtime /srv/aidr-reviewed-current --maintenance
```

`--recovery-runtime`, **mevcut** (eski) sürümden hazırlanmış temiz bir dizindir. Tam
komutu içeren plan ayrıca `/srv/aidr/.aidr-upgrade/rollback-plan.json` dosyasına
yazılır. Geri yüklenen kurulumu tek başına başlatın, orada doctor'ı çalıştırın; giriş,
cihaz kaydı, engellenen işlem ve denetim kaydı dışa aktarımını kontrol edin ve
kullanıcıları ancak bundan sonra taşıyın. Ayrıntılar:
[Failure and recovery](../../deploy/UPGRADE.md#failure-and-recovery).

## Kubernetes (Helm): üç komut

Yedekleme açıkken chart önce yedek alır, sonra veritabanını günceller, sonra yeni
pod'ları başlatır; yedek başarısız olursa veritabanı değişmeden durur.
[`values.example.yaml`](../../deploy/helm/aidr/values.example.yaml) dosyasından başlayın
ve [Upgrade in 3 commands](../../deploy/helm/aidr/README.md#upgrade-in-3-commands)
bölümünü izleyin:

```bash
node deploy/helm/build-images.mjs --output .aidr-images-<sürüm> --registry <kayıt-defteri> --build --push
helm upgrade aidr deploy/helm/aidr -n aidr -f my-values.yaml --wait --timeout 30m
kubectl -n aidr wait --for=condition=Available deployment -l app.kubernetes.io/instance=aidr --timeout=10m
```

## İnternete kapalı sunucular: tek paket

Aynı sürüme sahip, internete bağlı bir hazırlık sunucusunda, kapalı ortamın ihtiyaç
duyduğu her şeyi içeren tek bir imzalı paket oluşturun:

```sh
node scripts/onprem-offline-bundle.mjs build --output /media/aidr-offline-0.6.1 \
  --signing-key /secure/offline-bundle-signing.pem --key-id site-operator-2026 \
  --compose .aidr-deploy/compose.yml --platform linux/amd64 \
  --intel-pack /releases/intel/aidr-intel-2.0.0 --intel-trusted-keys /secure/intel-trusted-keys.json \
  --installers /releases/installers-staged --installer-catalog-public-key /secure/installer-catalog.pub.pem \
  --browser-guard-feed /releases/browser-guard-feed \
  --tar
```

`scripts/build-airgap-images.mjs` ile daha önce oluşturulmuş bir imaj paketini kullanmak
için `--compose` yerine `--images <dizin>` verin. Her parça isteğe bağlıdır ama en az
biri gerekir. Sonuç tek bir dizin (`--tar` ile ayrıca tek bir `.tar` dosyası) olur:

| Parça | İçerik | Pakete girmeden önce ve içe aktarmadan önce yeniden kontrol edilen |
|---|---|---|
| `images/` | Sistemin ihtiyaç duyduğu tüm konteyner imajları (`docker save` arşivleri) | Her arşivin boyutu ve SHA-256 özeti |
| `intel-packs/` | İmzalı tehdit bilgisi paketleri | Güvenilen bir anahtardan Ed25519 imzası, geçerlilik süresi, her dosyanın özeti |
| `installers/` | Masaüstü kurulum dosyaları ve imzalı katalogları | Katalog ve işaretçi imzaları, her kurulum dosyasının özeti |
| `browser-guard/` | Verildiyse Browser Guard güncelleme dosyaları | Her `.crx` dosyasında imzalı CRX3 başlığı, her `.xpi` dosyasında Mozilla imzası |
| `aidr-offline-bundle.manifest.json` (+ `.sig`) | İçerik listesi ve her dosyanın SHA-256 özeti | Paket anahtarınızla imzalanır |
| `SHA256SUMS` | Her dosyanın SHA-256 özeti | |

İmza anahtarı yoksa, bir tehdit bilgisi paketinin veya kurulum kataloğunun imzası
doğrulanmazsa, güvenilen anahtar veya katalog anahtarı eksikse ya da bir Browser Guard
paketi imzasızsa paket reddedilir ve hiçbir şey yazılmaz.

İnternete kapalı sunucuda, paket açık anahtarı ayrı bir yoldan (paketin içinde değil)
iletilmiş olarak:

```sh
node scripts/onprem-offline-bundle.mjs verify --bundle /media/aidr-offline-0.6.1.tar \
  --public-key /secure/offline-bundle-signing.pub.pem \
  --intel-trusted-keys /secure/intel-trusted-keys.json --installer-catalog-public-key /secure/installer-catalog.pub.pem

node scripts/onprem-offline-bundle.mjs import --bundle /media/aidr-offline-0.6.1.tar \
  --public-key /secure/offline-bundle-signing.pub.pem \
  --intel-trusted-keys /secure/intel-trusted-keys.json --installer-catalog-public-key /secure/installer-catalog.pub.pem \
  --load-images --intel-target storage --deployment /srv/aidr \
  --installers-out /srv/aidr-downloads/0.6.1 --browser-guard-out /srv/aidr-browser-guard --lang tr
```

`import` önce her şeyi yeniden doğrular; bir kontrol bile başarısız olursa hiçbir şey
içe aktarılmaz. İmajları `docker load` ile yükler, tehdit bilgisi paketlerini
`scripts/import-offline-pack.mjs` ile kurar (uç nokta paket klasörü için
`--intel-target local --packs-dir <dizin>`), kurulum dosyalarını ve Browser Guard
dosyalarını kurum içi indirme portalınız ve güncelleme adresiniz için yeni dizinlere
kopyalar. Ardından yeni sürümü hazırlayın ve yukarıdaki tek komutlu güncellemeyi
çalıştırın.

İmaj arşivleri bir yayıncı imzasıyla değil, paket imzası ve özetleriyle korunur:
üretici imajlarını paketlemeden önce
[Kubernetes rehberindeki](kubernetes.md#vendor-built-signed-images-and-chart) gibi
`cosign` ile doğrulayın.

## Bu rehberin kapsamı dışında kalanlar

- Müşteri kabulü, trafiğin yeni sisteme geçirilmesi, yüksek erişilebilirlik ve kurtarma
  süresi hedefleri sizin değişiklik ve kabul kayıtlarınızda tutulur.
- Platform temelinin (paketlenmiş Supabase sürümü) veya genel adreslerin değişmesi ayrı
  bir platform geçişidir; 1. adım bunu reddeder.

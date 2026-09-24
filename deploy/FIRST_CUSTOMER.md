# İlk müşteri kurulum ve kabul kılavuzu

Bu paket bir kurulum adayıdır. Her müşteride aşağıdaki akışı aynı sürüm üzerinde tamamlayın. Alan adı, çalışma ortamı ve sözleşme henüz seçilmediği için yerel prova sonuçları müşteri kabulü sayılmaz.

## Görüşmeden önce

Bir kurulum sorumlusu ve müşteri güvenlik sorumlusu belirleyin. Yönetim katmanı için cloud veya müşteri sunucusunu; korunacak cihazlar için işletim sistemi, AI araçları ve sürümlerini kaydedin. Veri bölgesi, saklama süresi, cihaz sayısı, izin verilen MCP sunucuları ve başlangıç politikası üzerinde anlaşın. Destek kanalı, müdahale saatleri, lisans/kota, veri işleme ve SLA maddelerini sözleşmede netleştirin; ölçülmemiş performans veya engelleme kapsamı vaat etmeyin.

## Taşınabilir paket ve yayıncı doğrulaması

Teslim sorumlusu, derlenmiş release dizini ve sabit upstream commit'ten kiti oluşturur. `--envelope-output`, tüm kit dosyalarını içeren tek tar artefaktı ve mevcut `release-sign.mjs` ile imzalanmaya hazır metadata/inventory üretir:

```sh
node scripts/customer-kit.mjs --output /release/aidr-kit-1 --upstream-dir /release/supabase-upstream --release-dir /release/aidr-artifacts --envelope-output /release/aidr-envelope-1
node scripts/verify-customer-kit.mjs /release/aidr-kit-1
node scripts/release-sign.mjs --bundle /release/aidr-envelope-1 --private-key /secure/publisher-ed25519.pem --key-id APPROVED_KEY_ID --sequence APPROVED_SEQUENCE --expires-at APPROVED_UTC_EXPIRY --channel customer-kit
```

İlk komut, release'e bağlı kit için kirli kaynak ağacını reddeder; release artefaktları da aynı temiz source commit'ten yeniden üretilmelidir. İkinci komut sahte uç noktalarla çevrimdışı hazırlama provasını yapar ve yalnız sır içermeyen bir kanıt dosyasını işletim sisteminin geçici dizininde bırakır; gerçek kurulum ve imza doğrulaması değildir. Üçüncü komut yalnız kurumun onaylı çevrimdışı yayıncı anahtarı, sürüm sırası ve geçerlilik süresiyle yayın sorumlusu tarafından çalıştırılır. İmzalanan dış zarf tar artefaktını, dolayısıyla kurulum betiklerini, belgeleri, dashboard'u ve iç release artefaktlarını bağlar. İç `artifacts/` imzası varsa o imza yalnız o alt dizindeki release dosyalarını bağlar. Paketin `SHA256SUMS` dosyası değişikliği tespit eder, yayıncı kimliğini doğrulamaz. İmzalama olmadan hazırlanan zarf mühendislik adayıdır; müşteri üretim yayını olarak kabul edilmez.

Müşteri, **paketten bağımsız ve önceden güvenilir kanaldan alınmış** `release-verify.mjs` ile `release-signing-lib.mjs` kopyasını, yayıncı public-key policy dosyasını ve kurulumdan ayrı kalıcı anti-rollback state yolunu kullanır. Paket içindeki doğrulayıcıyı dış imzayı doğrulamak için güven kökü olarak kullanmayın. Policy `customer-kit` kanalına ve onaylı signer fingerprint'ine açıkça izin vermelidir; private key hiçbir zaman pakete veya müşteri sunucusuna girmez.

Doğrulanmış arşivi yeni bir staging alanına çıkarın; aşağıdaki `mkdir` hedefi
önceden varsa durur, böylece eski dosyalarla karışık bir kit doğrulanmaz.

```sh
node /opt/aidr-trust/release-verify.mjs --bundle /delivery/aidr-envelope-1 --policy /etc/aidr/signer-policy.json --state /var/lib/aidr/release-state.json --receipt /var/log/aidr/release-verification.json
mkdir -m 0700 /srv/aidr-staging && \
  tar -xzf /delivery/aidr-envelope-1/aidr-customer-kit.tar.gz -C /srv/aidr-staging && \
  cd /srv/aidr-staging/aidr-kit-1 && \
  node scripts/customer-kit-verify.mjs --kit .
```

İlk doğrulama imzayı, signer yetkisini, geçerlilik süresini, sürüm geri dönüşünü ve tar özetini denetler; `--record` verilmediği için state'i ilerletmez. Açılmış kit denetimi tüm dosya özetlerini, fazladan dosya/symlink bulunmamasını ve iç release envanterini denetler. İç release ayrı imzalıysa `node scripts/customer-kit-verify.mjs --kit . --release-policy /etc/aidr/release-policy.json --release-state /var/lib/aidr/inner-release-state.json` ile iç imzayı da doğrulayın. Dış imzanın geçmesi, müşterideki kurulum/host kabulü yerine geçmez. Kurulum ve kabul başarılı olduktan sonra dış zarfı aynı policy/state ile yeniden doğrulayıp `--record` kullanın; bu adım olmadan anti-rollback state ileri alınmaz. Zarf değişirse ikinci doğrulama başarısız olur.

Bu mühendislik adayında kurumun resmi yayıncı anahtarı ve bağımsız policy dağıtımı henüz bulunmadığından imzalı üretim yayını diye sunmayın. Kurulum makinesinde Node.js 24, Docker Engine + Compose v2 ve tar bulunmalıdır. Git, pnpm veya kaynak kod derlemesi gerekmez. İlk çevrimiçi kurulumda konteyner imajları çekilir; air-gap teslim için ayrıca imaj arşivi gerekir. İmaj digestleri ve registry erişimi onaylı release kayıtlarına bağlanmalıdır.

Komutları paketin kökünde çalıştırın. Yeni kurulum dizini seçin; mevcut bir kurulumda yeniden hazırlama çalıştırmayın.

```sh
node scripts/deployment-prepare.mjs --mode self-hosted --output /srv/aidr --region self-hosted --tenant-region self-hosted --dashboard-url https://console.customer.example --supabase-url https://api.customer.example --artifact-verification-public-key-file /secure-delivery/aidr-artifact-signing-public.pem --telemetry-queue-root /var/lib/aidr-telemetry
docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml up -d --build
node scripts/deployment-migrate.mjs /srv/aidr
```

`--telemetry-queue-root` boş bir klasör oluşturma talimatı değildir. Kimliği
doğrulanmış filo toplayıcısı bu hedefi gerçekten beslemeli ve systemd kurulumu
öncesinde altında 64 haneli en az bir kuyruk namespace'i bulunmalıdır; canlı
filo toplayıcısı yoksa kurulum readiness'i yeşile çevirmeyi reddeder.

Windows'ta dizinleri uygun mutlak yollarla değiştirin. Üretilen portlar yalnızca loopback'e bağlanır. Kurulum yöneticisi TLS ters proxy üzerinden console adresini 8080, api adresindeki genel rotaları 8000 portuna yönlendirir. **`/functions/v1/device-start` rotası yalnız 127.0.0.1:8191 üzerindeki güvenilir ingress signer'a gitmelidir.** Hazırlanan self-hosted dizindeki gizli `.env.ingress` ile `node --env-file=/srv/aidr/.env.ingress /srv/aidr/ingress/device-start.mjs` komutunu ayrı hizmet olarak başlatın. `deploy/ingress/nginx.device-start.reference.conf` içindeki TLS adını ve özel proxy token'ını uyarlayın; bu token, `AIDR_DEVICE_START_INGRESS_SECRET` değerinden farklıdır. Doğrudan 8000 erişimini yalnız yerel/özel ağa sınırlayın, veritabanı/Studio servislerini internete açmayın ve gerçek rotayı test edin.

İlk TLS sertifikasını Nginx'in sertifika gerektiren yapılandırmasını başlatmadan önce alın; Certbot'un `/etc/letsencrypt/live/<alan adı>/` zincirini Nginx ve yenileme betiği birlikte kullanır. HTTP-01 için port 80 ve `/var/www/aidr-acme` yolu dışarıdan erişilebilir olmalıdır. Hazırlanan `/srv/aidr/ingress/aidr-tls-renew.service` ve `.timer` dosyalarını systemd dizinine kurup `daemon-reload` çalıştırmadan timer'ı etkinleştirmeyin. Ayrıntılı ilk sertifika, özel `/etc/aidr/tls-renew.env`, kurulum ve test adımları `deploy/ingress/README.md` içindedir. Yenileme makbuzu varsayılan olarak `/var/lib/aidr/tls-renewal-receipt.json` konumundadır; gerçek ACME, DNS ve dış TLS doğrulaması müşteri hostunda yapılmalıdır. Cloud modunda aynı güvenilir signer müşteri kontrolündeki TLS ingress üzerinde çalışmalı ve sabit upstream'i seçilen projenin HTTPS device-start rotasına yönlendirmelidir; sağlayıcı rotasının önüne kontrollü ingress konulamıyorsa bu kurulum akışı kabul edilmiş sayılmaz.

Kurucu, S3 protokol erişim anahtarı ve parolası dahil kurulum sırlarını rastgele üretir. Doctor örnek upstream S3 parolasını reddeder. Daha eski bir prova taşınıyorsa bu alanları kurumun secret manager'ından ayrı yeni değerlerle değiştirin ve Storage servisini yeniden oluşturup doctor'u tekrar çalıştırın; sırları `.env.example` dosyasından kopyalamayın.

Cloud için `--mode cloud` kullanın; müşteriye ayrılmış Supabase projesini seçin, paketteki `supabase/config.toml` ayarlarıyla kanonik migration ve fonksiyonları o projeye dağıtın. Discovery kolektörünün makine kimliği için `verify_jwt=false` gereklidir; fonksiyon insan JWT'sini ve dar yetkili kolektör anahtarını kendi içinde doğrular. `.env` içindeki yer tutucuları projenin anahtarlarıyla doldurun ve `.env.functions` değerlerini sunucu gizli değerleri olarak tanımlayın. Proje bölgesi ve yönetilen yedekleme müşterinin veri gereksinimlerine uymalıdır. `deploy/regions.manifest.json` içinde seçilen bölgeyi gerçek sağlayıcı bölgesi ve projenin HTTPS kaynağıyla beyan edip kurulumu `--region` ve `--tenant-region` ile hazırlayın; beyan edilmemiş bir bölge veya kiracı bölgesiyle uyuşmayan bir kurulum reddedilir ve doctor bu alanlar olmadan geçmez. Bu alanlar operatör beyanıdır; hukuki yerleşim, sağlayıcı yerleşimi veya canlı bölgesel hizmet kanıtı değildir. Bu paket bulut hesabını kendiliğinden oluşturmaz. Hazırlık ve migration ayrıntıları için [deployment kılavuzuna](README.md) ve [Supabase dağıtım rehberine](../supabase/README.md) bakın.

Pack delivery kullanılıyorsa `deployment-prepare` ayrı ve rastgele `AIDR_PACK_DOWNLOAD_GRANT_SECRET` üretir. Self-hosted kurulumda değer yalnızca erişimi kısıtlı `.env.functions` dosyasına yazılır ve Edge Functions konteynerine aktarılır; dosyayı tarayıcıya/agent'a kopyalamayın ve yükseltmede koruyun. Managed Supabase'te `.env.functions` uzaktaki projeyi kendiliğinden yapılandırmaz: aynı gizli değeri seçilen projenin Supabase Edge Function secrets alanında hem `packs-manifest` hem `packs-download` için güvenli secret-entry yöntemiyle ayarlayın. Değeri komut argümanına, ticket'a veya log'a yazdırmayın. Secret iki fonksiyonda da yoksa premium pack URL üretimi ve indirme fail-closed kalır. `SERVICE_ROLE_KEY` de yalnız sunucu tarafında kalmalı; `deployment-prepare` bunu self-hosted `.env`/Compose ayarına bağlar, cloud dağıtımında projeden alınan service-role anahtarı Supabase'in server-side Edge Function ortamında tutulur.

Pack bağlantıları iç `api-gw` adresiyle üretilemez. Self-hosted hazırlık `AIDR_PUBLIC_API_ORIGIN` değerini müşterinin erişebildiği `--supabase-url` kaynağına yazar. Managed Supabase'te aynı değişkeni seçilen projenin dış HTTPS API kaynağına ayarlayın veya `SUPABASE_URL` zaten dış HTTPS proje kaynağıysa varsayılanı doğrulayın. Kanonik migration özel `aidr-packs` deposunu oluşturur; sentetik bir paketi ajan ağından indirip önceden verilmiş bağlantının anahtar iptalinde 401 döndüğünü doğrulayın.

Bulut kayıt ekranı varsayılan olarak kapalıdır. `AIDR_SIGNUP_MODE=cloud` yalnız arayüzde kayıt seçeneğini gösterir; Supabase Auth kaydı, veritabanının cloud admission modu ve hukukça onaylanmış, gerçekten yayınlanmış Terms/Privacy sürüm ve SHA-256 özetleri ayrı ayrı doğrulanmadan deneme erişimi açılmaz. Migration `20260923000041` ile eski iki parametreli deneme RPC'si kaldırılır; ilgili migration, yeni `pilot-status` fonksiyonu ve onay kutulu dashboard aynı sürümde dağıtılıp birlikte test edilmelidir. Hukuki metinlerin bağlantıları, özetleri ve onay referansı henüz gerçek sahipler tarafından sağlanmadıysa bu kapıyı açmayın. Şirket içi ilk yönetici kaydı bundan bağımsız, sonlu süreli lisans bootstrap'ı ile yapılır.

## İlk yönetici

Şirket içi kurulumda kullanıcı kaydı kapalıdır. İlk hesabı yönetici aracı oluşturur; parola stdin üzerinden alınır, komut argümanına veya günlük dosyasına yazılmaz. Müşterinin seçtiği 16–128 karakter parolayı gizli bir terminal isteminden ya da secret manager'dan aktarın. Aşağıdaki lisans bitiş tarihi yalnız örnektir: gerçek, gelecekteki UTC tarihi ve sözleşme referansını onaylı müşteri anlaşmasından alın; bunlar olmadan kurulum erişimi açılmaz.

```sh
node scripts/deployment-bootstrap.mjs --deployment /srv/aidr --email owner@customer.example --name "Customer" --seats 5 --license-expires-at 2027-09-23T00:00:00Z --license-reference '<approved-contract-reference>'
```

Komut TTY'de açık parola istemez; parola 16–128 karakterlik tek satır UTF-8 olarak stdin'den verilmelidir. POSIX örneği: `read -r -s AIDR_PASSWORD; printf '%s' "$AIDR_PASSWORD" | node scripts/deployment-bootstrap.mjs ...; unset AIDR_PASSWORD`. Tercihen kurumsal secret manager'ın secret'ı doğrudan stdout'a yazan stdin entegrasyonunu kullanın. PowerShell 7.4+ ile gizli etkileşimli örnek:

```powershell
$securePassword = Read-Host -Prompt "Bootstrap password" -AsSecureString
$savedEncoding = $OutputEncoding
$passwordBuffer = [IntPtr]::Zero
$plainPassword = $null
try {
    $OutputEncoding = [Text.UTF8Encoding]::new($false)
    $passwordBuffer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordBuffer)
    $plainPassword | & node scripts/deployment-bootstrap.mjs --deployment C:\aidr --email owner@customer.example --name "Customer" --seats 5 --license-expires-at 2027-09-23T00:00:00Z --license-reference '<approved-contract-reference>'
    if ($LASTEXITCODE -ne 0) { throw "Customer bootstrap failed." }
} finally {
    $plainPassword = $null
    if ($passwordBuffer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordBuffer)
    }
    $securePassword.Dispose()
    $OutputEncoding = $savedEncoding
}
```

PowerShell bu aktarım sırasında kısa süreliğine düz metin değeri süreç belleğinde tutar; daha sıkı bellek politikalarında secret manager kullanın. `Read-Host -AsSecureString` tek başına Node aracına parola aktarmaz. Parolayı sohbet veya e-posta ile göndermeyin. Araç mevcut hesabın parolasını değiştirmez. Kesinti sonrası aynı parametrelerle `--resume` kullanın; işlem sunucudaki işleme özel kimlik ile eşleşmelidir.

Araç kurumsal ekibi, yönetici üyeliğini, kayıt iznini ve cihaz kotasını hazırlar. `/login` üzerinden giriş yapın. Varsayılan yöntem paroladır. Google/GitHub veya e-posta bağlantısı kullanılacaksa önce sağlayıcı/SMTP yapılandırmasını tamamlayın; sonra `.env` içine `AIDR_AUTH_METHODS=password,google` gibi yalnızca çalışan yöntemleri ekleyip dashboard'u yeniden oluşturun. Parola kurtarma için hazırlanan `auth-templates/recovery.html` şablonunu Auth sağlayıcısına yükleyin; şablon bağlantıya sır eklemez, tek kullanımlık kodu gösterir ve yalnız allowlist'teki `/auth/recover` sayfasını açar. Canlı kabulde kodun tek kullanımını, süresini ve dönen JWT'nin `amr` alanındaki `otp` yöntemini, ardından sunucuya bağlı kurtarma iznini doğrulayın. İlk hesabı oluştururken e-posta sahipliği kurulum operatörü tarafından doğrulanmalıdır; araç gönderim yapmaz.

## Uç cihaz ve demo

Uç cihaz paketini yalnızca onaylı imzalı sürümden kurun. Private GitHub
Packages erişimi, sürüm doğrulama ve OpenClaw/OpenCode/Codex kurulum adımları
[paket kurulum kılavuzunda](../docs/package-installation.md) yer alır. Bu
çalışma ağacındaki kaynak derlemeleri müşteri kurulumu için dağıtım paketi
sayılmaz.

Claude Code için ayrı kontrol düzlemi/uç cihaz kurulumunda, `deployment-prepare` tarafından
üretilen `agent-config.json` dosyasını imzalama anahtarıyla bağımsız doğrulanmış
güvenli bir kanaldan her uç cihaza aktarın. Uç cihazda örnekteki
`/srv/aidr/agent-config.json` yoluna koyun; dosya yalnızca uç nokta ve herkese açık
doğrulama anahtarlarını içerir. Bu dosya hazırlama ana makinesinden otomatik
aktarılmaz. Uç cihazda hedef kullanıcıya özel, erişimi kısıtlı bir kopya tutun.
Mevcut `~/.singularity-aidr/config.json` varsa üzerine yazmayın; yönetilen alanları
inceleyip açıkça birleştirin. Aynı makinede hazırlama ve uç cihaz kullanılıyorsa
aktarımı atlayıp üretilen dosyanın yerel yolunu kullanabilirsiniz.

Önce yukarıdaki gibi dış müşteri-kit zarfını bağımsız doğrulayıcıyla doğrulayın,
kiti yeni bir dizine çıkarın ve kit kökünde `node scripts/customer-kit-verify.mjs --kit .`
çalıştırın. Ardından yalnızca onay
kaydındaki sürüme karşılık gelen `artifacts/aidr-claude-plugin-VERSION.tar.gz`
arşivini kullanın; kaynak çalışma ağacındaki `packages/claude-code` yolu müşteri
kitinde bulunmaz. Arşivi boş, yeni bir uç cihaz staging dizinine çıkarın; aşağıdaki
PowerShell değişkenlerindeki kit kökü, sürüm ve güvenli yapılandırma yolunu kendi
doğrulanmış tesliminizle değiştirin:

```powershell
$kitRoot = (Resolve-Path 'C:\path\to\verified-kit').Path
$version = '<exact-approved-version>'
$stage = Join-Path $env:TEMP "aidr-claude-$version"
if (Test-Path $stage) { throw 'Choose a new staging directory; do not extract over existing files.' }
New-Item -ItemType Directory -Path $stage | Out-Null
$archive = Join-Path $kitRoot "artifacts\aidr-claude-plugin-$version.tar.gz"
tar -xzf $archive -C $stage
if ($LASTEXITCODE -ne 0) { throw 'Claude archive extraction failed.' }
$packageDir = Join-Path $stage 'packages\claude-code'
node (Join-Path $kitRoot 'scripts\endpoint-install.mjs') --package-dir $packageDir --config 'C:\secure-delivery\agent-config.json'
if ($LASTEXITCODE -ne 0) { throw 'AIDR endpoint installation failed.' }
```

`--config` yalnız ilk kurulumda, bağımsız olarak doğrulanıp güvenli kanaldan
aktarılmış public-key yapılandırmasını kopyalamak için kullanılır. Güncellemede
yeni onaylı arşivi yeni bir staging dizinine çıkarıp aynı kurucuyu, mevcut
`~/.singularity-aidr/config.json` dosyasını kullanması için `--config` olmadan
çalıştırın. Kurucu sürüm içeriğinin özetine göre yeni bir dizin kurar, yalnız
yönetilen hook kayıtlarını yeni sürüme geçirir ve önceki digest dizinini silmez;
aynı hostta zaten etkin bir AIDR marketplace plug-in'i varsa çift çalıştırmayı
önlemek için bu yolu kullanmayın. İmza anahtarı değişmişse mevcut trust ayarını
değiştirmeden önce onaylı anahtar rotasyonunu tamamlayın.

Kurucu `--config` kaynağını `~/.singularity-aidr/config.json` konumuna yalnızca dosya yoksa kopyalar; mevcut dosyayı korur. `.env` veya `.env.functions` dosyalarını uç cihaza dağıtmayın. Kurucu kancayı yerel bir deny canary ile sınar ve kullanıcının diğer kancalarını korur. Claude'u yeniden başlatın, gösterilen cihaz kodunu yetkili hesapla onaylayın; kurucu başarısı gerçek host yürütmesi kanıtı değildir.

İlk müşteri akışı:

1. Yönetici gerçek panelde giriş yapar; doğru ekip ve kota görünür.
2. Yeni ajan kayıt olur; Agents ekranında aynı ekipte görünür.
3. Normal dosya okuma gibi zararsız işlem geçer.
4. Tehlikeli komut yalnızca değerlendirme canary'si olarak gönderilir; gerçekten çalıştırılmaz. Host deny kararını uygular.
5. Runtime Policy ekranında deneme MCP aracı yasaklanır; yeni sürüm aynı ajana ulaşıp isteği engeller.
6. Yetkisiz başka bir ekip aynı politikayı veya olayları okuyamaz/değiştiremez.
7. Olay/denetim kaydı görünür, özel dışa aktarım indirilir. Politika geri alınır ve sonuç tekrar sınanır.
8. Ağ kesintisi, ajan yeniden başlatma ve host kancasının çalışmaması gözlemlenir; görünürlük/koruma sınırları kabul formuna yazılır.

Cursor, VS Code, OpenClaw, OpenCode, Codex ve SDK için o hosta ait paket ve kabul matrisi kullanılır. `deploy/fleet/windows`, `deploy/fleet/linux` ve `deploy/fleet/macos` altındaki lifecycle ve MDM şablonları imzalı manifest/artefakt gerektirir; gerçek Intune/SCCM/Jamf dağıtımını ve işletim sistemi kabulünü ayrıca yapın. Codex host kancası süreç hatasında fail-open davranabilir. Claude PostToolUse ve OpenClaw `after_tool_call` aynı tur model tüketimini engellediği iddiası taşımaz; desteklenen pre-model sınırlar için ilgili connector kılavuzunu kullanın.

Paket `release-source.json` içinde `inline_mcp_gateway_bundled: true` bildiriyorsa, `deploy/gateway/aidr-mcp-gateway.mjs`, `aidr-mcp-stdio.mjs` ve `aidr-mcp-approve.mjs` bağımsız Node 24 çalışma dosyaları teslim edilmiştir; paket yöneticisi veya kaynak derlemesi gerektirmez. Aynı dizindeki `aidr-artifact.manifest.json` ve `aidr-artifact.manifest.sig` dosyalarını ayırmayın. `deployment-prepare` tarafından doğrulanan artefakt public key'ini içeren `agent-config.json` dosyasını gateway servis hesabının `~/.singularity-aidr/config.json` dosyasına kurun veya mevcut yapılandırmaya `integrity` bloğunu birleştirin; eksik imza veya public key ticari binary başlangıcını reddeder. Özel gateway yapılandırmasını kit dışında hazırlayıp HTTP için `node deploy/gateway/aidr-mcp-gateway.mjs /secure/aidr-mcp-gateway.json` komutuyla yalnız loopback'te çalıştırın. Stdio köprüsü ve desteklenen yöntemler için `deploy/gateway/README.md` içindeki örneği izleyin. İmzalı tool manifest, tenant'a özel allowlist, güçlü client token hash'leri ve onay durumunu aynı kılavuza göre kurun. Uzak istemciler için TLS/mTLS proxy ve doğrudan upstream erişimini kapatma gereklidir. Gerçek MCP istemci/sunucu çiftiyle `tools/list`, `tools/call`, bildirim ve stdio kabulünü sınayın; tüm MCP yöntemleri ve zorunlu doğrudan upstream yönlendirmesi kanıtlanmış değildir. Alan yoksa veya `false` ise gateway bu pakette teslim edilmiş sayılmaz.

## Politika dağıtımı ve ağ kesintisi

Yeni müşteri için başlangıç politikası ilk yönetici işlemiyle yayınlanır. Policies ekranında bir taslağı seçili ajanlara dağıtın; hedef sürüm ve ajanın yüklediğini bildirdiği sürümü kontrol edin. Bildirim gelmeyen ajan Unknown, beş dakikadan eski bildirim Stale görünür. Bu bildirim, hostun her eylemi engellediğine dair bağımsız kanıt değildir. Review ile eski sürümü inceleyin; Publish version to all agents geçmiş içeriği yeni sürüm olarak yayınlar ve deneme atamalarını kaldırır. Büyük filolar Next agents ile sayfalanır.

Dağıtımın agent-config.json dosyası kayıtlı ajan için merkezi politikayı zorunlu tutar. Son geçerli önbellek normal süresi bittikten sonra varsayılan 3.600 saniye kullanılabilir; bu süre sabittir, dosyanın yeniden okunması süreyi uzatmaz. Ağ kesintisi bu süreyi aşarsa işlemler engellenir. 401/403, bozuk politika veya farklı anahtara ait önbellek eski politikaya dönüş izni vermez. Kuruma ait süreyi `control_plane.remote_policy_offline_grace_seconds` ile seçin; sahada çevrimdışı ve yeniden bağlantı denemesi yapın. Kayıtsız uç cihaz yerel tespitle çalışır.

## Denetim dışa aktarımı ve geçici dosyaların temizliği

CSV/JSON dışa aktarımı başlangıç anındaki ekip kayıtlarını 500 satırlık sayfalarla alır. Aynı zaman damgasındaki kayıtlar kimlikle sıralanır; sayfa imleci kullanıcı/ekip/format ve 15 dakikalık oturuma bağlıdır. Tarayıcı 100.000 kayıt veya 64 MB sınırını aşarsa eksik dosyayı tamamlanmış gibi indirmez. Daha büyük işler için `audit-export` API yanıtındaki `next_cursor` ile devam edin. Her indirme bağlantısı 60 saniye geçerlidir; geçici dosya 24 saat sonra silinmeye uygundur.

```sh
node scripts/deployment-maintenance.mjs /srv/aidr
node scripts/deployment-maintenance.mjs /srv/aidr --apply
```

İlk komut yalnızca ölçer. İkinci komut süresi dolmuş geçici dışa aktarım dosyalarını Storage API ile, tamamlanmış webhook kayıtlarını ve saklama süresi dolmuş olayları kendi güvenlik sınırları içinde, deneme hakkına ait yalnız HMAC e-posta özetlerini ise özgün 14 günlük süre sonunda siler; kaynak audit kayıtlarını değiştirmez. Özellikle deneme özetlerinin fiziksel temizliği saatlik işin çalışmasına bağlıdır; iş durursa `maintenance-evidence.json` eksik/başarısız kalmalı ve operatöre alarm gitmelidir. Kesintide dışa aktarım kayıt defteri tekrar denemeye izin verir. Linux için `deploy/maintenance/aidr-export-retention.*` service/timer dosyalarında Node, kit ve kurulum yollarını doğrulayın; sonra kurumun sistem servisi yönetimiyle kurup saatlik timer'ı etkinleştirin. Windows'ta aynı komutu kurumun zamanlanmış görev sisteminde saatlik çalıştırın. Sonucun `maintenance-evidence.json` dosyasına ve başarısız işlem çıkış kodunun operasyon izlemesine ulaştığını doğrulayın. Zamanlayıcının müşteride etkinleştirilmesi ayrıca gereklidir. Kaynak audit/olay saklama ve yasal muhafaza politikaları bu geçici dosya temizliğinden ayrıdır.

## Yedekleme ve geri dönüş

Self-hosted yedekleme soğuk yedektir: yalnızca bu AIDR projesini bakım penceresinde durdurur, veritabanının temiz kapandığını doğrular, veritabanı ve nesne depolama disklerini ve yapılandırmayı AES-256-GCM ile şifreler, önce çalışan servisleri geri başlatır. Bakım süresi ölçülmelidir; yüksek erişilebilirlik yerine geçmez.

```sh
node scripts/deployment-backup.mjs keygen --key-file /secure/aidr-recovery.key
node scripts/deployment-backup.mjs backup --deployment /srv/aidr --output /backups/aidr-2026-09-11 --key-file /secure/aidr-recovery.key --recovery-journal /var/lib/aidr-backup/recovery-journal.json --maintenance
node scripts/deployment-backup.mjs verify --backup /backups/aidr-2026-09-11 --key-file /secure/aidr-recovery.key
node scripts/deployment-backup.mjs recover --backup /backups/aidr-2026-09-11 --output /srv/aidr-recovery --key-file /secure/aidr-recovery.key --runtime /srv/aidr-reviewed-runtime
```

Yedek komutu servisleri durdurmadan önce kaydedilmiş çalışan servis listesini `/var/lib/aidr-backup/recovery-journal.json` dosyasına yazar. Beklenmeyen bir kesintiden sonra boot kurtarma birimi yalnızca bu kayıttaki servisleri başlatır; yeni yedekten önce journal temizliğini ve servis sağlığını doğrulayın.

Anahtarı kurulum/yedek dizininin dışında saklayın; kurumsal secret manager ve ayrı erişim yetkisi kullanın. `--runtime`, yedekle aynı temiz kaynak commit'ine bağlı, ayrıca incelenmiş bir deployment dizini olmalıdır; arşiv içindeki Compose ve yapılandırma çalıştırılmaz. `scripts/deployment-backup-offsite.mjs` ve `deploy/backup/README.md` ile ayrı dosya sistemi veya scoped S3 Object Lock hedefini kurun; yükleme ancak kopya yeniden okunup doğrulandığında `COMMITTED.json` ve readiness makbuzu üretir. Günlük timer ve saklama politikası müşteri ortamında etkinleştirilmelidir. Yedeği aynı makinede bırakmak felaket kurtarma sağlamaz. Dosyaları değiştirmek veya yanlış anahtar kullanmak kurtarma başlamadan reddedilir. Kurtarma her zaman yeni dizin ve yeni Docker volume'ları oluşturur; mevcut veritabanını silmez. Fiziksel yedek için aynı mimari ve aynı PostgreSQL imajı gerekir.

Kurtarılan servisler durur durumda bırakılır. Önce izole ortamda `docker compose ... up -d db` ile veritabanını ve kayıtları doğrulayın. Tam başlatma öncesi port/alan adı çakışmasını çözün; bütün servisler, giriş, imzalı ajan kaydı, politika ve dosya indirme kontrollerini tamamlayın. Sonra yönlendirmeyi değiştirin. Eski sistemi başarı kanıtlanana kadar koruyun. Hedef RPO, backup sıklığıdır; RTO ise bu müşteri ortamındaki gerçek kurtarma provasından ölçülür.

## Yükseltme, izleme ve destek

Sürüm değişiminde `UPGRADE.md` ve `scripts/deployment-upgrade.mjs` izlenir. Tam manifest/hash eşleşmesi, append-only migration, doğrulanmış yedek, uyumluluk ve yeni-volume recovery koşulları olmadan yükseltme başarılı sayılmaz. Canlı trafik yönlendirmesi ve rollback müşteri provasında ölçülür.

`deploy/monitoring/` Prometheus scrape/alert ve on-call şablonlarını kurun. Dashboard `/livez`, `/readyz` ve `/metrics` uçlarını yayınlar; readiness DB, storage, function, imza, yedek, kuyruk ve TLS kanıtı eksik veya bayatsa başarısızdır. Monitoring kanıt dosyalarını gerçek operasyonlara bağlayın, alarmı gerçek nöbetçiye ulaştırıp test edin. `deploy/ha/` içindeki yük/failover profillerini gerçek boyutlandırma ve tenant izolasyonu için kullanın; eski 10 RPS başarısız prova korunur, v6 10 RPS kısa `/healthz` provası geçmiştir. Kimlikli trafik, filo yükü, soak ve failover ölçülmeden kapasite veya SLA vaadi çıkarmayın.

SIEM teslimatı kullanılacaksa olay kuyruğunu yazan hostta `SINGULARITY_AIDR_SIEM_CONFIG_PATH` değerini kit dışındaki erişimi sınırlı JSON dosyasına bağlayın; dosyada `/var/lib/aidr-siem` altındaki mutlak `state_file` yolu, seçilen adapter/HTTPS endpoint ve gerekli kimlik bilgisi bulunur. Üretilen kurulumda `sudo sh /srv/aidr/maintenance/install-systemd.sh` komutu imza, dayanıklı kuyruk kanıtı ve SIEM yeniden denemesini aynı dakikalık `aidr-siem-delivery.timer` altında etkinleştirir; ikinci bir SIEM/readiness zamanlayıcısı kurmayın. Birim başarısızlığını operasyon alarmına bağlayın. **Zamanlayıcı kurulmazsa hem readiness kanıtı bayatlar hem de yeni olay gelmediğinde başarısız teslimatlar yeniden denenmez.** Gerçek müşteri SIEM endpoint'i, makbuz/ack ve yeniden deneme-kesinti kabulü sahada doğrulanmadan SIEM teslimi tamamlanmış sayılmaz. Kuyruk state dosyasını kilit çözmek için silmeyin.

TLS, kimliği doğrulanmış filo kuyruğu, signer, off-site yedek/timer, izleme ve gerektiğinde SIEM yapılandırması tamamlandıktan sonra online doctor'ı çalıştırın. Doctor'ı bu önkoşullar oluşmadan çalıştırmak readiness'i beklenen şekilde başarısız kılar:

```sh
node scripts/deployment-doctor.mjs --deployment /srv/aidr --online
```

Müşteriden açık izin ve destek ticket referansı alındıktan sonra `scripts/support-bundle.mjs` ile sınırlı tanılama paketi üretin; `scripts/verify-support-bundle.mjs` ile bütünlüğünü doğrulayın. Sır, ham log, veritabanı veya host kimliği pakete alınmaz. `SUPPORT-BUNDLE.md` prosedürü kullanılır; aktarım ayrıca kurum onayına bağlıdır. Tenant çıkışında `scripts/deployment-offboarding.mjs` önce dry-run, sonra yetkili operatör ve aktif legal hold kontrolüyle `--apply` çalıştırır. Tenant'ın önbellek katmanı (edge/CDN yanıt önbelleği ve tenant'a özel geçici önbellekler) ayrı bir aşamadır: sürücü harici bir önbelleği temizleyemez, bu yüzden çıkış `ack_tenant_offboarding_cache` makbuzu kaydedilene kadar tamamlanmış sayılmaz ve sürücü bu aşamada durup exit 2 verir. Canlı veri makbuzu harici yedeklerin silindiği anlamına gelmez.

## Teslim kaydı

Paket SHA-256, sunucu/host sürümleri, kurulum modu, tenant kimliği, kabul adımlarının zamanı/sonucu, bilinen sınırlamalar, yedek konumu, kurtarma süresi ve müşteri/satıcı sorumlularını kaydedin. Erişim anahtarı, ham kullanıcı komutu veya parola eklemeyin. Yerel başarı, bağımsız güvenlik testi, gerçek TLS kurulumu, native host kabulü, yük/uzun süre testi veya sözleşme onayının yerini tutmaz.

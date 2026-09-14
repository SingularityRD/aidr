# İlk müşteri kurulum ve kabul kılavuzu

Bu paket bir kurulum adayıdır. Her müşteride aşağıdaki akışı aynı sürüm üzerinde tamamlayın. Alan adı, çalışma ortamı ve sözleşme henüz seçilmediği için yerel prova sonuçları müşteri kabulü sayılmaz.

## Görüşmeden önce

Bir kurulum sorumlusu ve müşteri güvenlik sorumlusu belirleyin. Yönetim katmanı için cloud veya müşteri sunucusunu; korunacak cihazlar için işletim sistemi, AI araçları ve sürümlerini kaydedin. Veri bölgesi, saklama süresi, cihaz sayısı, izin verilen MCP sunucuları ve başlangıç politikası üzerinde anlaşın. Destek kanalı, müdahale saatleri, lisans/kota, veri işleme ve SLA maddelerini sözleşmede netleştirin; ölçülmemiş performans veya engelleme kapsamı vaat etmeyin.

## Taşınabilir paket ve yayıncı doğrulaması

Teslim sorumlusu, derlenmiş release dizini ve sabit upstream commit'ten kiti oluşturur. `--envelope-output`, tüm kit dosyalarını içeren tek tar artefaktı ve mevcut `release-sign.mjs` ile imzalanmaya hazır metadata/inventory üretir:

```sh
node scripts/customer-kit.mjs --output /release/aidr-kit-1 --upstream-dir /release/supabase-upstream --release-dir /release/aidr-artifacts --envelope-output /release/aidr-envelope-1
node scripts/release-sign.mjs --bundle /release/aidr-envelope-1 --private-key /secure/publisher-ed25519.pem --key-id APPROVED_KEY_ID --sequence APPROVED_SEQUENCE --expires-at APPROVED_UTC_EXPIRY --channel customer-kit
```

İkinci komut yalnız kurumun onaylı çevrimdışı yayıncı anahtarı, sürüm sırası ve geçerlilik süresiyle yayın sorumlusu tarafından çalıştırılır. Resmi imzadan önce `release-source.json` içindeki `dirty` alanı false olmalı ve release artefaktları aynı temiz source commit'ten yeniden üretilmelidir. İmzalanan dış zarf tar artefaktını, dolayısıyla kurulum betiklerini, belgeleri, dashboard'u ve iç release artefaktlarını bağlar. İç `artifacts/` imzası varsa o imza yalnız o alt dizindeki release dosyalarını bağlar. Paketin `SHA256SUMS` dosyası değişikliği tespit eder, yayıncı kimliğini doğrulamaz. İmzalama olmadan hazırlanan zarf mühendislik adayıdır; müşteri üretim yayını olarak kabul edilmez.

Müşteri, **paketten bağımsız ve önceden güvenilir kanaldan alınmış** `release-verify.mjs` ile `release-signing-lib.mjs` kopyasını, yayıncı public-key policy dosyasını ve kurulumdan ayrı kalıcı anti-rollback state yolunu kullanır. Paket içindeki doğrulayıcıyı dış imzayı doğrulamak için güven kökü olarak kullanmayın. Policy `customer-kit` kanalına ve onaylı signer fingerprint'ine açıkça izin vermelidir; private key hiçbir zaman pakete veya müşteri sunucusuna girmez.

```sh
node /opt/aidr-trust/release-verify.mjs --bundle /delivery/aidr-envelope-1 --policy /etc/aidr/signer-policy.json --state /var/lib/aidr/release-state.json --receipt /var/log/aidr/release-verification.json
tar -xzf /delivery/aidr-envelope-1/aidr-customer-kit.tar.gz -C /srv/aidr-staging
cd /srv/aidr-staging/aidr-kit-1
node scripts/customer-kit-verify.mjs --kit .
```

İlk doğrulama imzayı, signer yetkisini, geçerlilik süresini, sürüm geri dönüşünü ve tar özetini denetler; `--record` verilmediği için state'i ilerletmez. Açılmış kit denetimi tüm dosya özetlerini, fazladan dosya/symlink bulunmamasını ve iç release envanterini denetler. İç release ayrı imzalıysa `node scripts/customer-kit-verify.mjs --kit . --release-policy /etc/aidr/release-policy.json --release-state /var/lib/aidr/inner-release-state.json` ile iç imzayı da doğrulayın. Dış imzanın geçmesi, müşterideki kurulum/host kabulü yerine geçmez. Kurulum ve kabul başarılı olduktan sonra dış zarfı aynı policy/state ile yeniden doğrulayıp `--record` kullanın; bu adım olmadan anti-rollback state ileri alınmaz. Zarf değişirse ikinci doğrulama başarısız olur.

Bu mühendislik adayında kurumun resmi yayıncı anahtarı ve bağımsız policy dağıtımı henüz bulunmadığından imzalı üretim yayını diye sunmayın. Kurulum makinesinde Node.js 24, Docker Engine + Compose v2 ve tar bulunmalıdır. Git, pnpm veya kaynak kod derlemesi gerekmez. İlk çevrimiçi kurulumda konteyner imajları çekilir; air-gap teslim için ayrıca imaj arşivi gerekir. İmaj digestleri ve registry erişimi onaylı release kayıtlarına bağlanmalıdır.

Komutları paketin kökünde çalıştırın. Yeni kurulum dizini seçin; mevcut bir kurulumda yeniden hazırlama çalıştırmayın.

```sh
node scripts/deployment-prepare.mjs --mode self-hosted --output /srv/aidr --region self-hosted --tenant-region self-hosted --dashboard-url https://console.customer.example --supabase-url https://api.customer.example
docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml up -d --build
node scripts/deployment-migrate.mjs /srv/aidr
node scripts/deployment-doctor.mjs --deployment /srv/aidr --online
```

Windows'ta dizinleri uygun mutlak yollarla değiştirin. Üretilen portlar yalnızca loopback'e bağlanır. Kurulum yöneticisi TLS ters proxy üzerinden console adresini 8080, api adresindeki genel rotaları 8000 portuna yönlendirir. **`/functions/v1/device-start` rotası yalnız 127.0.0.1:8191 üzerindeki güvenilir ingress signer'a gitmelidir.** Hazırlanan self-hosted dizindeki gizli `.env.ingress` ile `node --env-file=/srv/aidr/.env.ingress /srv/aidr/ingress/device-start.mjs` komutunu ayrı hizmet olarak başlatın. `deploy/ingress/nginx.device-start.reference.conf` içindeki TLS adı, sertifika yolları ve özel proxy token'ı müşteri ortamına göre düzenleyin; `nginx -t` ve gerçek rota testinden sonra etkinleştirin. Bu token, signer ile Edge Function arasında paylaşılan `AIDR_DEVICE_START_INGRESS_SECRET` değerinden farklıdır. Doğrudan 8000 erişimini yalnız yerel/özel ağa sınırlayın; imzasız device-start çağrısı fonksiyon tarafından reddedilmelidir. Veritabanı/Studio servislerini internete açmayın. Proxy için WebSocket ve başlık iletimini doğrulayın. Sertifika, DNS ve yenileme sahibi müşteri ortamına göre belirlenmelidir. Hazırlanan dizine `ingress/aidr-tls-renew.service` ve `ingress/aidr-tls-renew.timer` birimleri kopyalanır; kurulum bunları kendiliğinden etkinleştirmez. TLS ana makinesinde `/etc/aidr/tls-renew.env` özel dosyasını (alan adı, e-posta, sertifika dizini, ACME webroot'u, ACME istemcisi ve Nginx yolu) oluşturup `systemctl enable --now aidr-tls-renew.timer` ile etkinleştirin. Betik ACME istemcisi kurulu değilse, sunulan zincir eksikse, sertifika başka bir alan adına aitse veya sorgu başarısızsa Nginx'i yeniden yüklemez; sertifika zincirinin yanına `renewal-receipt.json` içine `refused`/`failed` sonucu ve nedenini yazıp sıfırdan farklı çıkış kodu verir. Başarılı yenilemede makbuz zaman damgasını, alan adını, SHA-256 sertifika parmak izini, son kullanma tarihini, sorgunun başarılı olduğunu ve Nginx'in yeniden yüklendiğini kaydeder. Gerçek ACME sorgusu, alan adı ve sertifika müşteri ortamında doğrulanmalıdır; makbuz yerel bir deneme kaydıdır. Cloud modunda aynı güvenilir signer müşteri kontrolündeki TLS ingress üzerinde çalışmalı ve sabit upstream'i seçilen projenin HTTPS device-start rotasına yönlendirmelidir; sağlayıcı rotasının önüne kontrollü ingress konulamıyorsa bu kurulum akışı kabul edilmiş sayılmaz.

Kurucu, S3 protokol erişim anahtarı ve parolası dahil kurulum sırlarını rastgele üretir. Doctor örnek upstream S3 parolasını reddeder. Daha eski bir prova taşınıyorsa bu alanları kurumun secret manager'ından ayrı yeni değerlerle değiştirin ve Storage servisini yeniden oluşturup doctor'u tekrar çalıştırın; sırları `.env.example` dosyasından kopyalamayın.

Cloud için `--mode cloud` kullanın; müşteriye ayrılmış Supabase projesini seçin, paketteki `supabase/config.toml` ayarlarıyla kanonik migration ve fonksiyonları o projeye dağıtın. Discovery kolektörünün makine kimliği için `verify_jwt=false` gereklidir; fonksiyon insan JWT'sini ve dar yetkili kolektör anahtarını kendi içinde doğrular. `.env` içindeki yer tutucuları projenin anahtarlarıyla doldurun ve `.env.functions` değerlerini sunucu gizli değerleri olarak tanımlayın. Proje bölgesi ve yönetilen yedekleme müşterinin veri gereksinimlerine uymalıdır. `deploy/regions.manifest.json` içinde seçilen bölgeyi gerçek sağlayıcı bölgesi ve projenin HTTPS kaynağıyla beyan edip kurulumu `--region` ve `--tenant-region` ile hazırlayın; beyan edilmemiş bir bölge veya kiracı bölgesiyle uyuşmayan bir kurulum reddedilir ve doctor bu alanlar olmadan geçmez. Bu alanlar operatör beyanıdır; hukuki yerleşim, sağlayıcı yerleşimi veya canlı bölgesel hizmet kanıtı değildir. Bu paket bulut hesabını kendiliğinden oluşturmaz. Ayrıntılar INSTALLATION.md dosyasındadır.

## İlk yönetici

Kullanıcı kaydı kapalıdır. İlk hesabı yönetici aracı oluşturur; parola stdin üzerinden alınır, komut argümanına veya günlük dosyasına yazılmaz. Müşterinin seçtiği 16–128 karakter parolayı gizli bir terminal isteminden ya da secret manager'dan aktarın:

```sh
node scripts/deployment-bootstrap.mjs --deployment /srv/aidr --email owner@customer.example --name "Customer" --seats 5
```

Komut TTY'de açık parola istemez; yukarıdaki komuta gizli kaynaktan stdin sağlayın. POSIX örneği: `read -r -s AIDR_PASSWORD; printf '%s' "$AIDR_PASSWORD" | node scripts/deployment-bootstrap.mjs ...; unset AIDR_PASSWORD`. PowerShell'de `Read-Host -AsSecureString` veya kurumun secret manager'ını kullanın. Parolayı sohbet veya e-posta ile göndermeyin. Araç mevcut hesabın parolasını değiştirmez. Kesinti sonrası aynı parametrelerle `--resume` kullanın; işlem sunucudaki işleme özel kimlik ile eşleşmelidir.

Araç kurumsal ekibi, yönetici üyeliğini, kayıt iznini ve cihaz kotasını hazırlar. `/login` üzerinden giriş yapın. Varsayılan yöntem paroladır. Google/GitHub veya e-posta bağlantısı kullanılacaksa önce sağlayıcı/SMTP yapılandırmasını tamamlayın; sonra `.env` içine `AIDR_AUTH_METHODS=password,google` gibi yalnızca çalışan yöntemleri ekleyip dashboard'u yeniden oluşturun. İlk hesabı oluştururken e-posta sahipliği kurulum operatörü tarafından doğrulanmalıdır; araç gönderim yapmaz.

## Uç cihaz ve demo

Claude Code için müşterinin hesabında:

```sh
node scripts/endpoint-install.mjs --package-dir packages/claude-code --config /srv/aidr/agent-config.json
```

Kopyalanan konfigürasyon yalnızca herkese açık uç noktayı ve doğrulama anahtarını içerir. `.env` veya `.env.functions` dosyalarını uç cihaza dağıtmayın. Var olan ajan konfigürasyonu üzerine yazılmaz. Kurucu kancayı yerel bir deny canary ile sınar ve kullanıcının diğer kancalarını korur. Claude'u yeniden başlatın, gösterilen cihaz kodunu yetkili hesapla onaylayın; kurucu başarısı gerçek host yürütmesi kanıtı değildir.

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

Paket `release-source.json` içinde `inline_mcp_gateway_bundled: true` bildiriyorsa, `deploy/gateway/aidr-mcp-gateway.mjs`, `aidr-mcp-stdio.mjs` ve `aidr-mcp-approve.mjs` bağımsız Node 24 çalışma dosyaları teslim edilmiştir; paket yöneticisi veya kaynak derlemesi gerektirmez. Özel yapılandırmayı kit dışında hazırlayıp HTTP için `node deploy/gateway/aidr-mcp-gateway.mjs /secure/aidr-mcp-gateway.json` komutuyla yalnız loopback'te çalıştırın. Stdio köprüsü ve desteklenen yöntemler için `deploy/gateway/README.md` içindeki örneği izleyin. İmzalı tool manifest, tenant'a özel allowlist, güçlü client token hash'leri ve onay durumunu aynı kılavuza göre kurun. Uzak istemciler için TLS/mTLS proxy ve doğrudan upstream erişimini kapatma gereklidir. Gerçek MCP istemci/sunucu çiftiyle `tools/list`, `tools/call`, bildirim ve stdio kabulünü sınayın; tüm MCP yöntemleri ve zorunlu doğrudan upstream yönlendirmesi kanıtlanmış değildir. Alan yoksa veya `false` ise gateway bu pakette teslim edilmiş sayılmaz.

## Politika dağıtımı ve ağ kesintisi

Yeni müşteri için başlangıç politikası ilk yönetici işlemiyle yayınlanır. Policies ekranında bir taslağı seçili ajanlara dağıtın; hedef sürüm ve ajanın yüklediğini bildirdiği sürümü kontrol edin. Bildirim gelmeyen ajan Unknown, beş dakikadan eski bildirim Stale görünür. Bu bildirim, hostun her eylemi engellediğine dair bağımsız kanıt değildir. Review ile eski sürümü inceleyin; Publish version to all agents geçmiş içeriği yeni sürüm olarak yayınlar ve deneme atamalarını kaldırır. Büyük filolar Next agents ile sayfalanır.

Dağıtımın agent-config.json dosyası kayıtlı ajan için merkezi politikayı zorunlu tutar. Son geçerli önbellek normal süresi bittikten sonra varsayılan 3.600 saniye kullanılabilir; bu süre sabittir, dosyanın yeniden okunması süreyi uzatmaz. Ağ kesintisi bu süreyi aşarsa işlemler engellenir. 401/403, bozuk politika veya farklı anahtara ait önbellek eski politikaya dönüş izni vermez. Kuruma ait süreyi `control_plane.remote_policy_offline_grace_seconds` ile seçin; sahada çevrimdışı ve yeniden bağlantı denemesi yapın. Kayıtsız uç cihaz yerel tespitle çalışır.

## Denetim dışa aktarımı ve geçici dosyaların temizliği

CSV/JSON dışa aktarımı başlangıç anındaki ekip kayıtlarını 500 satırlık sayfalarla alır. Aynı zaman damgasındaki kayıtlar kimlikle sıralanır; sayfa imleci kullanıcı/ekip/format ve 15 dakikalık oturuma bağlıdır. Tarayıcı 100.000 kayıt veya 64 MB sınırını aşarsa eksik dosyayı tamamlanmış gibi indirmez. Daha büyük işler için `audit-export` API yanıtındaki `next_cursor` ile devam edin. Her indirme bağlantısı 60 saniye geçerlidir; geçici dosya 24 saat sonra silinmeye uygundur.

```sh
node scripts/deployment-maintenance.mjs /srv/aidr
node scripts/deployment-maintenance.mjs /srv/aidr --apply
```

İlk komut yalnızca ölçer. İkinci komut süresi dolmuş geçici dışa aktarım dosyalarının baytlarını Storage API ile siler; kaynak audit kayıtlarını değiştirmez. Kesintide kayıt defteri tekrar denemeye izin verir. Linux için `deploy/maintenance/` altındaki service/timer dosyalarında Node, kit ve kurulum yollarını doğrulayın; sonra kurumun sistem servisi yönetimiyle kurup saatlik timer'ı etkinleştirin. Windows'ta aynı komutu kurumun zamanlanmış görev sisteminde saatlik çalıştırın. Sonucun `maintenance-evidence.json` dosyasına ve başarısız işlem çıkış kodunun operasyon izlemesine ulaştığını doğrulayın. Zamanlayıcının müşteride etkinleştirilmesi ayrıca gereklidir. Kaynak audit/olay saklama ve yasal muhafaza politikaları bu geçici dosya temizliğinden ayrıdır.

## Yedekleme ve geri dönüş

Self-hosted yedekleme soğuk yedektir: yalnızca bu AIDR projesini bakım penceresinde durdurur, veritabanının temiz kapandığını doğrular, veritabanı ve nesne depolama disklerini ve yapılandırmayı AES-256-GCM ile şifreler, önce çalışan servisleri geri başlatır. Bakım süresi ölçülmelidir; yüksek erişilebilirlik yerine geçmez.

```sh
node scripts/deployment-backup.mjs keygen --key-file /secure/aidr-recovery.key
node scripts/deployment-backup.mjs backup --deployment /srv/aidr --output /backups/aidr-2026-09-11 --key-file /secure/aidr-recovery.key --maintenance
node scripts/deployment-backup.mjs verify --backup /backups/aidr-2026-09-11 --key-file /secure/aidr-recovery.key
node scripts/deployment-backup.mjs recover --backup /backups/aidr-2026-09-11 --output /srv/aidr-recovery --key-file /secure/aidr-recovery.key
```

Anahtarı kurulum/yedek dizininin dışında saklayın; kurumsal secret manager ve ayrı erişim yetkisi kullanın. `scripts/deployment-backup-offsite.mjs` ve `deploy/backup/README.md` ile ayrı dosya sistemi veya scoped S3 Object Lock hedefini kurun; yükleme ancak kopya yeniden okunup doğrulandığında `COMMITTED.json` ve readiness makbuzu üretir. Günlük timer ve saklama politikası müşteri ortamında etkinleştirilmelidir. Yedeği aynı makinede bırakmak felaket kurtarma sağlamaz. Dosyaları değiştirmek veya yanlış anahtar kullanmak kurtarma başlamadan reddedilir. Kurtarma her zaman yeni dizin ve yeni Docker volume'ları oluşturur; mevcut veritabanını silmez. Fiziksel yedek için aynı mimari ve aynı PostgreSQL imajı gerekir.

Kurtarılan servisler durur durumda bırakılır. Önce izole ortamda `docker compose ... up -d db` ile veritabanını ve kayıtları doğrulayın. Tam başlatma öncesi port/alan adı çakışmasını çözün; bütün servisler, giriş, imzalı ajan kaydı, politika ve dosya indirme kontrollerini tamamlayın. Sonra yönlendirmeyi değiştirin. Eski sistemi başarı kanıtlanana kadar koruyun. Hedef RPO, backup sıklığıdır; RTO ise bu müşteri ortamındaki gerçek kurtarma provasından ölçülür.

## Yükseltme, izleme ve destek

Sürüm değişiminde `UPGRADE.md` ve `scripts/deployment-upgrade.mjs` izlenir. Tam manifest/hash eşleşmesi, append-only migration, doğrulanmış yedek, uyumluluk ve yeni-volume recovery koşulları olmadan yükseltme başarılı sayılmaz. Canlı trafik yönlendirmesi ve rollback müşteri provasında ölçülür.

`deploy/monitoring/` Prometheus scrape/alert ve on-call şablonlarını kurun. Dashboard `/livez`, `/readyz` ve `/metrics` uçlarını yayınlar; readiness DB, storage, function, imza, yedek, kuyruk ve TLS kanıtı eksik veya bayatsa başarısızdır. Monitoring kanıt dosyalarını gerçek operasyonlara bağlayın, alarmı gerçek nöbetçiye ulaştırıp test edin. `deploy/ha/` içindeki yük/failover profillerini gerçek boyutlandırma ve tenant izolasyonu için kullanın; eski 10 RPS başarısız prova korunur, v6 10 RPS kısa `/healthz` provası geçmiştir. Kimlikli trafik, filo yükü, soak ve failover ölçülmeden kapasite veya SLA vaadi çıkarmayın.

SIEM teslimatı kullanılacaksa olay kuyruğunu yazan hostta `SINGULARITY_AIDR_SIEM_CONFIG_PATH` değerini kit dışındaki erişimi sınırlı JSON dosyasına bağlayın; dosyada mutlak `state_file` yolu, seçilen adapter/HTTPS endpoint ve gerekli kimlik bilgisi bulunur. `node scripts/siem-delivery-worker.mjs --max-items 25` komutunu Task Scheduler, cron veya systemd timer ile düzenli çalıştırın; `--status` kilit yaşını ve PID'yi raporlar. Çıkış 0 sağlıklı/boş, 2 kuyrukta tekrar deneme/dead-letter/eski kilit, 3 yapılandırma veya çalışma hatasıdır; 2 ve 3'ü operasyon alarmına bağlayın. **Zamanlayıcı kurulmazsa yeni olay gelmediğinde başarısız teslimatlar yeniden denenmez.** Gerçek müşteri SIEM endpoint'i, makbuz/ack ve yeniden deneme-kesinti kabulü sahada doğrulanmadan SIEM teslimi tamamlanmış sayılmaz. Kuyruk state dosyasını kilit çözmek için silmeyin.

Müşteriden açık izin ve destek ticket referansı alındıktan sonra `scripts/support-bundle.mjs` ile sınırlı tanılama paketi üretin; `scripts/verify-support-bundle.mjs` ile bütünlüğünü doğrulayın. Sır, ham log, veritabanı veya host kimliği pakete alınmaz. `SUPPORT-BUNDLE.md` prosedürü kullanılır; aktarım ayrıca kurum onayına bağlıdır. Tenant çıkışında `scripts/deployment-offboarding.mjs` önce dry-run, sonra yetkili operatör ve aktif legal hold kontrolüyle `--apply` çalıştırır. Canlı veri makbuzu harici yedeklerin silindiği anlamına gelmez.

## Teslim kaydı

Paket SHA-256, sunucu/host sürümleri, kurulum modu, tenant kimliği, kabul adımlarının zamanı/sonucu, bilinen sınırlamalar, yedek konumu, kurtarma süresi ve müşteri/satıcı sorumlularını kaydedin. Erişim anahtarı, ham kullanıcı komutu veya parola eklemeyin. Yerel başarı, bağımsız güvenlik testi, gerçek TLS kurulumu, native host kabulü, yük/uzun süre testi veya sözleşme onayının yerini tutmaz.

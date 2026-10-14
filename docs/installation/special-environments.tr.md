# Kurulum tarifleri: VDI, devcontainer, Remote-SSH, WSL ve CI çalıştırıcıları

[English](special-environments.md)

AIDR, yapay zekâ ajanını **ajanın araç çağrılarının çalıştığı ortamın içinden**
korur: kanca, o makinedeki o kullanıcının ajan aracı yapılandırmasına kaydedilir.
Aşağıdaki her ortam için soru aynıdır: "ajan nerede, hangi kullanıcıyla
çalışıyor?" AIDR'ı oraya kurun. Komut ve dosya örneklerinin tamamı İngilizce
sayfadadır.

| Ortam | Ajanın araçları nerede çalışır | AIDR nereye kurulur |
|---|---|---|
| VDI / Citrix (Windows masaüstü) | Sanal masaüstü oturumu | Altın imaj (makine geneli MSI); her kullanıcı için kurulum oturum açılışında |
| Dev container | Konteyner | Konteyner imajı; kurulum konteyner kullanıcısıyla |
| VS Code Remote-SSH | Uzak sunucu | Uzak sunucu, her uzak kullanıcı için |
| WSL | Linux dağıtımı | Her WSL dağıtımı, WSL kullanıcısıyla |
| CI çalıştırıcısı | İşin çalıştırıcısı (VM ya da konteyner) | İşin içinde, ajan adımından önce |

> **Destek durumu.** Gerçek ortam kabul kanıtı yalnız [uyumluluk
> matrisindeki](../compatibility-matrix.md) araç ve platformlarda vardır (bugün
> Linux x64). Bu sayfadaki ortamların hiçbirinin kendi kabul kaydı yoktur; her
> tarifi müşterinin pilot halkasında doğrulanacak bir tasarım olarak ele alın.
> Cursor / VS Code eklentisi önizlemedir — henüz gerçek ortam kabul kanıtı yok.
> Windows Server çok oturumlu sunucular test edilmemiştir.

## VDI ve Citrix (kalıcı olmayan masaüstleri)

1. **Altın imaj:** MSI'ı imaja makine geneli kurun:
   `msiexec /i singularity-aidr-<sürüm>-windows-x64.msi /qn AIDR_MDM_MANAGED=1`.
   Güncelleme imaj yenilenerek yapılır. Active Setup her oturum açılışında
   `aidr setup` çalıştırır; kurulum tekrar çalıştırılmaya uygundur.
2. **AI araçlarını da imaja kurun**, ki kurulum onları bulup kancayı kaydetsin.
3. **Kullanıcı durumunu profil kapsayıcısında saklayın** (FSLogix, Citrix Profile
   Management): `%USERPROFILE%\.singularity-aidr` ve AI araçlarının yapılandırma
   klasörleri. Saklanmazsa: her oturumda yeni kurulum kimliği oluşur ve yönetilen
   modda **her oturum yeni bir cihaz olarak kaydolup yeni koltuk kullanır**; onay
   anahtarı ve bekleyen onaylar kaybolur (bekleyen işlemler engelli kalır, asla
   kendiliğinden onaylanmaz); yerel denetim kaydı oturum kapanınca silinir.
4. **Kayıt:** imajda yönetilen yapılandırmayı kullanın (sürümünüz destekliyorsa
   makine politikası). Her oturumda etkileşimli kayıt pratik değildir.
5. **Merkezi kayıt:** yönetilen telemetri ya da SIEM iletimini açın.
6. **Saat:** VDI sunucuları etki alanı saat hiyerarşisini izlemelidir.
7. **Kontrol:** test oturumunda `aidr doctor`, `aidr verify`; oturumu kapatıp
   açın, `aidr status` aynı kurulum kimliğini göstermelidir.

## Dev container

Ana makinedeki AIDR konteyner içindeki araç çağrılarını görmez; tersi de
geçerlidir. Ajan konteynerde çalışıyorsa AIDR'ı imaja kurun (`.deb` ya da iç
apt deposu), `postCreateCommand` içinde konteyner kullanıcısıyla
`aidr setup --host claude-code && aidr doctor` çalıştırın ve
`~/.singularity-aidr` klasörünü adlandırılmış bir birimde saklayın (aksi hâlde
her yeniden derleme yeni cihaz kaydı demektir). Yönetilen modda makine politika
dosyasını (`/etc/singularity-aidr/managed.json`) salt okunur bağlayın; kayıt
kimlik bilgisini imaja gömmeyin. İç CA kullanılıyorsa konteynere kök
sertifikayı verin (`NODE_EXTRA_CA_CERTS` ya da destekleniyorsa `ca_file`).

## VS Code Remote-SSH

Remote-SSH'de VS Code sunucusu, eklentileri ve tümleşik terminalde başlatılan
ajan komut satırı araçları **uzak** sunucuda çalışır; dizüstündeki AIDR onları
korumaz. Linux paketini uzak sunucuya kurun ve her geliştirici bir kez
`aidr setup` çalıştırsın (ya da yönetici `sudo -u <kullanıcı> -H aidr setup`).
VS Code eklentisi olarak çalışan ajanlar için AIDR eklentisi de uzak tarafa
kurulmalıdır ("Install in SSH: <sunucu>"); bu yol Cursor / VS Code önizlemesinin
parçasıdır. Ortak derleme sunucularında her kullanıcının kurulumu bir cihaz
sayılır.

## WSL

WSL dağıtımı ayrı bir Linux sistemidir. Windows MSI'ı Windows'ta başlatılan
ajanları korur; WSL içinde kurulup başlatılan ajanları **korumaz**. Ajan çalışan
her dağıtıma Linux paketini kurun ve WSL kullanıcısıyla `aidr setup`
çalıştırın. WSL kurulumunun kendi kurulum kimliği vardır ve yönetilen modda ayrı
cihaz olarak kaydolur; bir kişinin Windows ve WSL kurulumlarının tek koltukta
sayılıp sayılmayacağı siparişte belirlenir. İç CA'yı dağıtımın güven deposuna ve
`NODE_EXTRA_CA_CERTS`'e ekleyin. Uykudan sonra eski WSL sürümlerinde saat
kayabilir; `aidr doctor` bunu bildirir, `sudo hwclock -s` düzeltir.

## CI çalıştırıcıları

İşte ajan adımından önce tarball'ı kurun, `aidr setup --host claude-code`,
`aidr doctor --json` ve `aidr verify` çalıştırın; biri başarısızsa iş dursun.
Geçici çalıştırıcılarda **yerel mod** tercih edin (kayıt yok, iş başına koltuk
kullanılmaz); merkezi görünürlük gerekiyorsa denetim kaydını (`audit.jsonl`)
iş çıktısı olarak SIEM'e aktarın. CI'da `ask` kararını onaylayacak kimse yoktur;
engelleme olarak kalır ve adım başarısız olur. Bu bilinçli bir davranıştır:
istisnayı (dar izin listesi ya da tespit istisnası) bant dışında kararlaştırın,
AIDR'ı hatta kapatmayın. AIDR sürümünü sabitleyin ve tarball imzasını işte
doğrulayın.

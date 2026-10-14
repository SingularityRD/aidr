# Filo kayıt anahtarları (çok makine, tek anahtar)

[English](fleet-enrollment.md)

Tek kullanımlık kayıt kodu bir bilgisayarı bağlar. MSI dağıtımı, Intune, GPO ya
da Ansible ile yüzlerce Windows ve Linux makineyi bağlamak için bir **filo kayıt
anahtarı** oluşturun ve makine ilkesine koyun. Her makine, AIDR ilk kez
çalıştığında tarayıcı adımı ve makineye özel kod olmadan kendini kaydeder.

| | Tek kullanımlık kayıt kodu | Filo kayıt anahtarı |
|---|---|---|
| Önek | `aidr_enroll_` | `aidr_fleet_` |
| Kullanım | tek bilgisayar | anahtarın makine sınırına kadar |
| Geçerlilik | saatler (varsayılan 24) | 30, 90, 180 ya da 365 gün |
| Kim oluşturur | sahip, yönetici ya da üye | yalnızca sahip ya da yönetici |
| İptal | kullanılmadan silinir | her an iptal edilebilir |
| Kayıt hız sınırı | kişi başına dakikada 30 | anahtar başına dakikada 600 (ayarlanabilir) |

Kayıt uç noktası (`/v1/enroll`), kayıt kodunu kabul ettiği her yerde filo
anahtarını da kabul eder. Lisanslı koltuk sınırınız her makine için yine
geçerlidir.

## Anahtar oluşturma

1. Panele **sahip ya da yönetici** olarak girin ve ekibi seçin.
2. **API anahtarları** sayfasında **Filo kayıt anahtarları** bölümünü açın.
3. Bir etiket (örneğin `finans-dizustu`), bu anahtarın kaydedebileceği **en
   fazla yeni makine sayısını** (1 ile 100.000 arası) ve geçerlilik süresini
   girin.
4. **Filo anahtarı oluştur** düğmesine basın ve anahtarı kopyalayın. Anahtar
   **yalnızca bir kez** gösterilir; sistemde yalnızca SHA-256 özeti ve son dört
   karakteri saklanır.

Listede her anahtar için son dört karakter, sınıra göre kaydedilen makine
sayısı, toplam kullanım, bitiş tarihi ve durum (`etkin`, `sınıra ulaşıldı`,
`süresi doldu`, `iptal edildi`) görünür. **İptal et** ikinci bir onay ister.

## Anahtarı makine ilkesine koyma

Uç noktalar makine ilkesinden iki değer okur. Kullanıcılar makine ilkesini
değiştiremez ve bu değerler kullanıcının kendi ayarlarından önce gelir.

| Değer | Anlamı |
|---|---|
| `control_plane_url` | Kontrol sunucunuz, örneğin `https://aidr.example.com` |
| `enrollment_key` | Filo anahtarı, `aidr_fleet_…` |

Makine ilkesi ayrıca `ca_file`, `https_proxy`, `no_proxy` ve yapılandırma
başvurusunda anlatılan diğer alanları taşır.

### Windows: kayıt defteri (`HKLM\SOFTWARE\Policies\Singularity AIDR`)

İki değer de metindir (`REG_SZ`). Yönetici ya da SYSTEM olarak çalıştırın:

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Singularity AIDR'
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name control_plane_url -Value 'https://aidr.example.com'
Set-ItemProperty -Path $path -Name enrollment_key -Value $env:AIDR_FLEET_KEY
```

- **MSI dağıtımı (SCCM/ConfigMgr, PDQ, betikler):** ilkeyi aynı dağıtım
  adımında, `msiexec /i singularity-aidr-<sürüm>-windows-x64.msi /qn`
  komutundan önce ya da sonra yazın. Kurulum paketi anahtarı komut satırında
  istemez; anahtar msiexec günlüğüne hiç düşmez.
- **Intune:** yukarıdaki betiği platform betiği olarak (sistem bağlamında,
  64 bit PowerShell) ya da Win32 uygulamasının kurulum komutunun parçası olarak
  dağıtın; anahtarı uygulamanın görünen komut satırına değil betiğin içine
  koyun. AIDR uygulamasıyla aynı cihaz grubuna atayın.
- **GPO:** Bilgisayar Yapılandırması → Tercihler → Windows Ayarları → Kayıt
  Defteri; eylem *Güncelleştir*, kovan `HKEY_LOCAL_MACHINE`, anahtar
  `SOFTWARE\Policies\Singularity AIDR`, iki `REG_SZ` değeri.

### Linux: `/etc/singularity-aidr/managed.json`

Dosyanın sahibi root olmalı ve kullanıcılar yazamamalıdır:

```json
{
  "control_plane_url": "https://aidr.example.com",
  "enrollment_key": "aidr_fleet_…"
}
```

Ansible örneği (anahtarı Ansible Vault içinde tutun):

```yaml
- name: Singularity AIDR makine ilkesi
  hosts: developer_workstations
  become: true
  tasks:
    - name: İlke dizini
      ansible.builtin.file:
        path: /etc/singularity-aidr
        state: directory
        owner: root
        group: root
        mode: "0755"
    - name: Filo kayıt anahtarlı makine ilkesi
      ansible.builtin.copy:
        dest: /etc/singularity-aidr/managed.json
        owner: root
        group: root
        mode: "0644"
        content: "{{ {'control_plane_url': aidr_control_plane_url, 'enrollment_key': aidr_fleet_key} | to_nice_json }}"
      no_log: true
    - name: AIDR paketi
      ansible.builtin.package:
        name: singularity-aidr
        state: present
```

## Sınırdan ne düşer

- Her kayıt bir **AIDR kurulum kimliği** kaydeder (bugün bir makinedeki her
  kullanıcı profilinin kendi kimliği vardır). Yeni bir kurulum, anahtarın
  sınırından bir yer ve bir koltuk kullanır.
- Ekibin zaten tanıdığı bir kurulumun yeniden kaydı (yeniden deneme, dağıtımın
  tekrar çalışması) ikisini de kullanmaz; yalnızca anahtarın kullanım sayısını
  artırır.
- Anahtarın sınırı dolunca yeni makineler `409 fleet_key_exhausted` alır; yeni
  bir anahtar oluşturun. Ekibin koltukları dolunca, anahtarın sınırı ne olursa
  olsun `402 agent_limit_exceeded` alırlar.
- Tek anahtarla dakikada 600'den fazla kayıt `retry_after_seconds` içeren
  `429 rate_limited` yanıtı alır; uç nokta daha sonra yeniden dener.

## Güvenlik notları

- **Makine ilkesini okuyabilen herkes anahtarı da okuyabilir.** Kayıt defteri
  ilkeleri ve `managed.json` yerel kullanıcılar tarafından okunabilir. Anahtar
  veri okuyamaz ve bir kullanıcı gibi davranamaz; yalnızca sınırı ve süresi
  içinde ekibinize yeni kurulum kaydedebilir. Sınırı filo büyüklüğüne yakın
  tutun, dağıtım dönemi için kısa süre seçin, bölüm ya da yerleşke başına ayrı
  anahtar kullanın ve dağıtım bitince anahtarı iptal edin.
- **Anahtarı iptal etmek yalnızca yeni kayıtları durdurur.** Daha önce
  kaydedilen makineler, siz kendi API anahtarlarını iptal edene kadar
  çalışmaya devam eder.
- **Anahtar, onu oluşturan yönetici adına çalışır.** Bu kişi ekipten
  çıkarılırsa anahtar çalışmaz ve anahtarın verdiği makine API anahtarları da
  kişinin diğer anahtarlarıyla birlikte iptal edilir. Kişi sahip/yönetici
  rolünü kaybederse anahtar çalışmaz. Filo anahtarlarını personel
  değişikliklerinden etkilenmeyecek bir yönetici hesabıyla oluşturun.
- Her oluşturma, iptal ve kayıt aynı işlem içinde bir denetim kaydı yazar
  (`fleet_key.create`, `fleet_key.revoke`, `fleet_key.enroll`); denetim kaydı
  yazılamazsa hiçbir şey değişmez.

## Operatörler için

`/v1/enroll`, anahtar başına hız sınırı için `AIDR_ENROLL_FLEET_RL_PER_MIN`
değerini okur (varsayılan `600`, aralık `1..100000`); geçersiz bir değer sınırı
kapatmaz, `503 enrollment_rate_limit_config_invalid` yanıtı verir.
`/v1/fleet-keys`, yönetici başına dakikadaki anahtar oluşturma sayısı için
`AIDR_FLEETKEY_CREATE_RL_PER_MIN` değerini okur (varsayılan `10`). Her ekip en
fazla 50 etkin filo anahtarı tutabilir. Şema:
`supabase/migrations/20261014000210_fleet_enrollment_keys.sql`.

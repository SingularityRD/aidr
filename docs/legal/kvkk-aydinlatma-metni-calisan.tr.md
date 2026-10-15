# Çalışan aydınlatma metni şablonu — Singularity AIDR

> **TASLAK — hukuk/iş onayı gerekir.** Bu bir şablondur. Singularity AIDR'ı
> kuran **müşteri kurum** veri sorumlusudur ve bu metni kendi hukuk birimi ve
> veri koruma sorumlusuyla gözden geçirip, köşeli parantezleri doldurup, kendi
> çalışanlarına duyurmakla yükümlüdür. SingularityRD bu metnin hukuki
> yeterliliğini garanti etmez. Son güncelleme: 14.10.2026.
>
> Nasıl kullanılır: doldurulmuş metni kurum içi bir HTTPS adresinde yayımlayın
> ve bu adresi makine politikasındaki `privacy_notice_url` anahtarına yazın
> (Windows: `HKLM\SOFTWARE\Policies\Singularity AIDR`, Linux:
> `/etc/singularity-aidr/managed.json`); uç noktalar ilk çalıştırmadaki
> bildirimde bu bağlantıyı gösterir. Hangi bileşenin ne kaydettiğinin ayrıntısı
> için [operatör KVKK rehberine](../operations/kvkk.md) bakın; metni kurumunuzda
> açık olan bileşenlere göre kısaltın.

---

## [Kurum unvanı] — Yapay zekâ araçlarının güvenli kullanımı kapsamında kişisel verilerin işlenmesine ilişkin aydınlatma metni

6698 sayılı Kişisel Verilerin Korunması Kanunu ("KVKK") madde 10 ve Aydınlatma
Yükümlülüğünün Yerine Getirilmesinde Uyulacak Usul ve Esaslar Hakkında Tebliğ
uyarınca, veri sorumlusu sıfatıyla [Kurum unvanı] ("Kurum") olarak sizi
aşağıdaki konularda bilgilendiririz.

### 1. Veri sorumlusu

[Kurum unvanı], [adres], [MERSİS no], [KEP adresi]. Veri koruma irtibat
kişisi: [ad / birim, e-posta].

### 2. Hangi araç, neden kullanılıyor?

Kurum, yapay zekâ destekli kodlama araçlarının (örneğin Claude Code, Codex,
Cursor, VS Code eklentileri) ve tarayıcıdaki yapay zekâ sohbet hizmetlerinin
kurum bilgisayarlarında güvenli kullanımı için **Singularity AIDR** yazılımını
kullanır. Yazılım, yapay zekâ aracının çalıştırmak istediği komutları, eriştiği
dosya yollarını ve web adreslerini çalıştırılmadan önce değerlendirir; zararlı
görünenleri engeller ya da bir yöneticinin onayına bırakır. Tarayıcı eklentisi
(Browser Guard), yapay zekâ sohbetlerine gönderilen metindeki kişisel verileri
ve gizli bilgileri göndermeden önce maskeler.

Amaç çalışanların performansını ya da içeriğini izlemek değildir; amaç,
kurumun bilgi güvenliğini ve kişisel verilerin güvenliğini (KVKK madde 12)
sağlamak, yapay zekâ araçları aracılığıyla oluşabilecek veri sızıntısını,
kötü amaçlı komut çalıştırılmasını ve yetkisiz erişimi önlemektir.

### 3. İşlenen kişisel veriler

[Kurumunuzda açık olan satırları bırakın.]

| Veri | Nerede tutulur | Ne zaman |
|---|---|---|
| Bilgisayarınızın ve kullanıcı hesabınızın teknik kimliği (kurulum kimliği, cihaz adı, işletim sistemi ve sürüm bilgisi) | Bilgisayarınızda ve Kurumun yönetim sunucusunda | Kurulum ve kayıt sırasında |
| Yapay zekâ aracının yapmak istediği işlemle ilgili karar kaydı: araç adı, karar (izin / engelle / onay iste), eşleşen kural, zaman | Bilgisayarınızda (yerel denetim kaydı) ve [yönetilen modda] yönetim sunucusunda | Her değerlendirmede |
| İşlemin özeti (komut, dosya yolu, web adresi) | Bilgisayarınızda yerel kayıtta açık metin olarak; yönetim sunucusunda **yalnız SHA-256 özeti** olarak [kurum `redact_mode` ayarını değiştirdiyse burayı güncelleyin] | Her değerlendirmede |
| Onay talepleri: talep eden kişi/cihaz, istenen işlem özeti, onaylayan yönetici ve zaman | Yönetim sunucusunda | Bir işlem onaya düştüğünde |
| Tarayıcı eklentisi sayaçları: hangi yapay zekâ sitesi, ne tür veri kaç kez maskelendi (ör. "2 e-posta, 1 TCKN") | Yönetim sunucusunda | Gönderim sırasında |
| Yönetim paneli kullanıcısıysanız: ad, e-posta, rol, oturum ve giriş kayıtları | Yönetim sunucusunda | Panel kullanımında |

**İşlenmeyenler:** Yazılım yapay zekâya yazdığınız istemlerin tam metnini,
kaynak kodunuzu ve dosyalarınızın içeriğini yönetim sunucusuna göndermez.
Browser Guard, maskelediği değerleri (ör. bir TCKN'nin kendisini) ve sayfa
adreslerini göndermez; maskeleme eşleştirmesi yalnız o tarayıcı sekmesinin
belleğinde tutulur.

### 4. İşlemenin hukuki sebebi

Kişisel verileriniz KVKK madde 5/2 kapsamında;
- (ç) veri sorumlusunun hukuki yükümlülüğünü yerine getirmesi için zorunlu
  olması (KVKK madde 12 uyarınca veri güvenliğine ilişkin teknik ve idari
  tedbirlerin alınması [ve sektörünüzdeki düzenlemeler, ör. BDDK, Cumhurbaşkanlığı
  Bilgi ve İletişim Güvenliği Rehberi]),
- (f) ilgili kişinin temel hak ve özgürlüklerine zarar vermemek kaydıyla
  Kurumun bilgi sistemlerinin güvenliğini sağlamaya yönelik meşru menfaati,
- [(c) iş sözleşmesinin ifası — hukuk birimi değerlendirecek]

hukuki sebeplerine dayanılarak, otomatik yollarla işlenir.

### 5. Kimlere aktarılır?

- Kurumun bilgi güvenliği, BT ve [SOC] ekiplerindeki yetkili kişiler
  (görev gereği ve rol bazlı erişimle),
- [Kurumun güvenlik olay yönetimi (SIEM) sistemi — açıksa],
- Yasal zorunluluk halinde yetkili kamu kurum ve kuruluşları,
- [Yönetim sunucusu Kurum içinde çalışıyorsa:] Verileriniz yazılım üreticisine
  (SingularityRD) **gönderilmez**. Bir destek talebinde, yalnız Kurumun
  onayladığı ve kişisel veri içermeyecek şekilde tasarlanmış tanılama özeti
  paylaşılabilir.
- [Barındırılan hizmet kullanılıyorsa:] Hizmeti barındıran SingularityRD ve
  alt işleyenleri, veri işleme sözleşmesi kapsamında; yurt dışına aktarım
  varsa KVKK madde 9 uyarınca [aktarım aracı].

### 6. Saklama süresi

Bilgisayarınızdaki yerel kayıt boyuta göre döner (varsayılan en fazla yaklaşık
20 MiB). Yönetim sunucusundaki karar kayıtları [__] gün, yönetici denetim
kayıtları [__] gün saklanır ve süre sonunda otomatik olarak silinir. Bir hukuki
uyuşmazlık ya da olay incelemesi nedeniyle saklama süresi, yalnız ilgili
kayıtlar için ve gerekçesi kayda geçirilerek uzatılabilir.

### 7. Haklarınız

KVKK madde 11 uyarınca; kişisel verilerinizin işlenip işlenmediğini öğrenme,
işlenmişse bilgi talep etme, işlenme amacını ve amacına uygun kullanılıp
kullanılmadığını öğrenme, yurt içinde veya yurt dışında aktarıldığı üçüncü
kişileri bilme, eksik veya yanlış işlenmişse düzeltilmesini, KVKK madde 7
koşullarıyla silinmesini veya yok edilmesini isteme ve bu işlemlerin aktarılan
üçüncü kişilere bildirilmesini isteme, münhasıran otomatik sistemlerle analiz
edilmesi suretiyle aleyhinize bir sonucun ortaya çıkmasına itiraz etme ve
kanuna aykırı işleme nedeniyle zarara uğramanız halinde zararın giderilmesini
talep etme haklarına sahipsiniz.

Bir işlemin yazılım tarafından engellenmesi ya da onaya düşmesi bir
**otomatik karardır**; engelleme mesajında nedeni ve kural kimliği yazar.
Kararın yanlış olduğunu düşünüyorsanız [BT destek adresi / `support_contact_url`]
üzerinden itiraz edebilirsiniz; itiraz bir kişi tarafından incelenir.

Başvurularınızı Veri Sorumlusuna Başvuru Usul ve Esasları Hakkında Tebliğ'e
uygun olarak [yazılı başvuru adresi], [KEP adresi] ya da [kayıtlı e-posta]
üzerinden iletebilirsiniz. Başvurular en geç 30 gün içinde ücretsiz
sonuçlandırılır.

---

Bu metni okudum ve bilgilendirildim. (İmza ya da elektronik onay **gerekmez**;
aydınlatma yükümlülüğü açık rıza değildir. Kurum yalnız duyurunun yapıldığını
kayda geçirir.)

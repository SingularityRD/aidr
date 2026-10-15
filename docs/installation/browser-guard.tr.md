# Browser Guard'ı kurma

[English](browser-guard.md)

Singularity AIDR Browser Guard, yapay zekâ sohbet araçlarına (ChatGPT, Gemini,
Claude, Microsoft Copilot, Perplexity, DeepSeek, Mistral Le Chat, Grok)
gönderdiklerinizi denetler ve kişisel ve gizli verileri tarayıcınızdan çıkmadan önce
yer tutucularla değiştirir. Özgün değerler yanıtlarda yalnızca sizin bilgisayarınızda
geri gelir.

**Bilgisayarınızı şirketiniz mi yönetiyor?** O zaman Browser Guard'ı BT ekibiniz
kurar; sizin bir şey yapmanız gerekmez. Uzantı araç çubuğunda "Kuruluşunuz tarafından
yönetiliyor" olarak görünür. Yöneticiler için:
[browser-guard-enterprise.tr.md](browser-guard-enterprise.tr.md).

## Kurulum

> **Kullanılabilirlik.** Browser Guard henüz Chrome Web Store'da, Edge Add-ons'ta ya
> da Mozilla imzalı XPI olarak yayımlanmadı; bu yüzden bugün bir kurulum bağlantısı
> yoktur ve değerlendirmelerde derlenmiş uzantı paketlenmemiş olarak yüklenir. AI
> sitelerinin kapalı test kopyalarında doğrulandı, canlı sitelerde henüz değil.
> Aşağıdaki adımlar kayıtlar yayımlandıktan sonra geçerlidir.

Kurulum bağlantısını Singularity irtibat kişinizden veya kurumunuzdan alırsınız.
Kayıtlar liste dışıdır (unlisted): mağaza aramasında görünmez ama diğer uzantılar gibi
kurulur.

| Tarayıcı | Adımlar |
|---|---|
| Google Chrome 120+ | Chrome Web Store bağlantısını açın, **Chrome'a ekle**'ye, ardından **Uzantı ekle**'ye tıklayın. |
| Microsoft Edge 120+ | Edge Eklentileri bağlantısını açın, **Al**'a, ardından **Uzantı ekle**'ye tıklayın. |
| Mozilla Firefox 140+ | Kurumunuzun verdiği `.xpi` bağlantısını açın ve **Ekle** ile onaylayın. |

Tarayıcı, uzantının listelenen yapay zekâ sitelerinde "verilerinizi okuyup
değiştirebileceği" ve "herhangi bir sayfadaki içeriği engelleyebileceği" uyarısını
gösterir. Birincisi istemlerinizi o sitelerde nasıl denetlediğidir; ikincisi yalnızca
kurumunuzun izin vermediği yapay zekâ sitelerini engellemek için kullanılır.

Kurulumdan sonra yapboz simgesine tıklayıp **Singularity AIDR Browser Guard**'ı araç
çubuğuna sabitleyin. Zaten açık olan yapay zekâ sekmeleri yeniden yüklenmeden korunur;
açılır pencere **Korunmuyor — bu sekmeyi yenileyin** diyorsa sekmeyi yenileyin.

## Çalıştığını denetleme

1. Desteklenen yapay zekâ sitelerinden birini açın.
2. İsteme `jane.doe@example.com` gibi bir deneme adresi yazıp gönderin.
3. Siteye adres yerine `[EMAIL_1_xxxx]` gider; küçük bir "Gönderilmeden önce maskelendi:
   1 e-posta adresi." notu görünür ve yanıt özgün adresi yeniden gösterir.

Araç çubuğu penceresi geçerli sekmenin korunup korunmadığını ve bu oturumda kaç öğenin
maskelendiğini gösterir.

## Bilmeniz gerekenler

- Tüm denetimler tarayıcınızda çalışır. Singularity'ye hiçbir şey gönderilmez.
  Kurumunuz AIDR kontrol düzlemini bağlarsa yalnızca sayılar bildirilir (ör.
  "ChatGPT'de 2 e-posta adresi maskelendi"), yazdıklarınız asla. Gizlilik politikası:
  [store/privacy-policy.tr.html](../../packages/browser-guard/store/privacy-policy.tr.html).
- Gizli veya misafir pencerelerde, diğer tarayıcılarda, masaüstü yapay zekâ
  uygulamalarında ve sesli girişte çalışmaz.
- Etiketsiz yazılan ad ve adresler ("Ad:", "Adres:" olmadan) için BT ekibinizin ayrıca
  kurduğu isteğe bağlı AIDR Privacy yardımcı programı gerekir.
- Kaldırmak için: araç çubuğu simgesine sağ tıklayın > **Chrome'dan kaldır** /
  **Microsoft Edge'den kaldır**, Firefox'ta `about:addons`. Kurumunuzun kurduğu bir
  kopyayı yalnızca BT ekibiniz kaldırabilir.

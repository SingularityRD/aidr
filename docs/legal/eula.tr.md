# Singularity AIDR Son Kullanıcı Lisans Sözleşmesi

> TASLAK - HUKUK/İŞ ONAYI GEREKİR. Bu metin hukuk danışmanı ve iş sahibi tarafından onaylanmamıştır; henüz bir teklif ya da bağlayıcı bir sözleşme değildir. Onaylı metin, kurulum programı değişmeden bunun yerine konabilsin diye kurulumda gösterilir. Onaylı sürüm yayımlanana kadar bu metne dayanmayın.

Sürüm: taslak 0.1 (14 Ekim 2026). İngilizce sürüm: docs/legal/eula.en.md. İki sürüm arasında fark olursa Sipariş Formunda belirtilen sürüm geçerlidir; Sipariş Formu bir sürüm belirtmiyorsa Türkiye'de yerleşik müşteriler için Türkçe sürüm geçerlidir.

## 1. Taraflar ve kapsam

Bu Son Kullanıcı Lisans Sözleşmesi ("Sözleşme"), SingularityRD [tam unvan, ticaret sicil ve MERSİS numarası hukuk tarafından doldurulacak] ("Lisans Veren") ile Yazılımı bir Sipariş Formu, teklif kabulü ya da deneme onayıyla edinen kuruluş ("Müşteri") arasındadır. Yazılımı Müşteri adına kuran kişi, bu Sözleşmeyi Müşteri adına kabul etmeye yetkili olduğunu beyan eder.

Sözleşme, Müşteriye teslim edilen Singularity AIDR yazılımını kapsar: uç nokta komut satırı aracı ve ajan bağlayıcıları, masaüstü kurulum paketleri, tarayıcı eklentisi (Browser Guard), MCP ağ geçidi, şirket içi kontrol sunucusu (yönetim paneli, veritabanı şeması ve sunucu fonksiyonları) ile bunlarla birlikte ya da güncelleme olarak teslim edilen tehdit kuralları, istihbarat paketleri, politikalar ve belgeler (birlikte "Yazılım").

Yazılımın içerdiği üçüncü taraf bileşenler kendi lisanslarına tabi kalır. Bunlar kurulum klasöründeki docs klasöründe bulunan THIRD_PARTY_NOTICES.txt dosyasında listelenir (örneğin C:\Program Files\Singularity AIDR\docs\THIRD_PARTY_NOTICES.txt). Bu Sözleşmedeki hiçbir hüküm Müşterinin o lisanslardan doğan haklarını kısıtlamaz.

## 2. Lisans

Bu Sözleşmeye ve ilgili bedellerin ödenmesine bağlı olarak Lisans Veren, Müşteriye Lisans Süresi boyunca, Yazılımı nesne kodu biçiminde, Müşterinin kendi iç işleri için, Sipariş Formunda ve imzalı lisans dosyasında belirtilen Koltuk sayısına kadar ve belirtilen sürüm, modül ve kurulum türü içinde kurma ve kullanma hakkı verir. Bu hak münhasır değildir, devredilemez ve alt lisansa konu edilemez.

Müşteri, Yazılımı kendi yararına kullanmaları için çalışanlarına ve yüklenicilerine kullandırabilir. Bu kişilerin Sözleşmeye uymasından Müşteri sorumludur.

Müşteri yedekleme, felaket kurtarma, test ve hazırlık ortamları için makul sayıda kopya oluşturabilir; ancak test ve hazırlık kurulumları lisanslı Koltuk sayısını aşan sayıda gerçek kullanıcıyı korumak için kullanılamaz.

## 3. Koltuklar ve kullanım bildirimi

"Koltuk", yapay zekâ ajan araçları ya da tarayıcısı Müşteri politikası altında Yazılımla korunan bir kişidir. Sipariş Formunda aksi yazılmadıkça bir Koltuk, o kişinin tarayıcısını ve kayıtlı bir ajan kurulumunu kapsar.

Kontrol sunucusu kayıtlı kurulumları lisanslı Koltuklara karşı sayar. Müşteri bu sayımı, örneğin veritabanını değiştirerek, bir kaydı birden fazla kişi için kullanarak ya da lisans dosyasını değiştirerek aşmaya çalışmaz.

Lisans Verenin makul yazılı talebi üzerine ve yılda en fazla bir kez (ya da yenilemede) Müşteri, Yazılımın ürettiği kullanım raporunu (aidr-usage-report-v1) ya da kullanılan Koltuk sayısını gösteren eşdeğer bir yazılı beyanı verir. Rapor Müşteri tarafından hazırlanır ve beyan edilir; değiştirilemez bir ölçüm değildir. Müşteri lisanslı sayıdan fazla Koltuk kullanıyorsa, fazla Koltukları Lisans Süresinin kalanı için Sipariş Formundaki fiyatlarla, fiyat yoksa Lisans Verenin o tarihteki teklifiyle satın alır.

## 4. Lisans Süresi ve deneme lisansları

"Lisans Süresi", Sipariş Formunda ve imzalı lisans dosyasında belirtilen süredir. Yazılı olarak yenilenmedikçe bitiş tarihinde sona erer.

Deneme ya da kavram kanıtlama (POC) lisansı, deneme onayında belirtilen süre için (olağan olarak 30 gün) ücretsiz ve yalnız değerlendirme amacıyla verilir; üretim kullanımı için değildir. Koltuk ve özellik bakımından sınırlı olabilir, destek taahhüdü olmadan "olduğu gibi" sağlanır ve ücretli lisansa çevrilmezse süre sonunda kendiliğinden sona erer.

Lisans Süresi bittiğinde Yazılımın yönetilen özellikleri (koltuk kabulü, cihaz kaydı, olay alımı ve diğer kontrol sunucusu özellikleri) lisans dosyasında belirtilen ek süreden sonra durur. Uç noktalardaki yerel tespit, son kurulan sürüm, kurallar ve politikayla çalışmaya devam eder; çünkü kaçırılmış bir yenileme yüzünden korumanın kapanması Müşterinin kullanıcılarını açıkta bırakır. Müşteri, Lisans Süresinden sonra Güncelleme alma hakkına sahip değildir ve Sözleşme yenilenmezse sona ermeden sonra makul bir süre içinde Yazılımı kaldırır.

## 5. Güncellemeler lisansı izler

"Güncellemeler", Lisans Verenin Müşterinin sürümü için genel olarak sunduğu yeni sürümler, düzeltmeler, tehdit kuralları, istihbarat paketleri ve imzalı politika içeriğidir. Müşteri Güncellemelere yalnız ücretli bir Lisans Süresi boyunca (deneme lisanslarında deneme süresi boyunca) hak kazanır. Güncellemeler, farklı koşullarla gelmedikçe bu Sözleşmeye tabidir.

Lisans Veren Güncellemeleri kontrol sunucusu üzerinden, internet bağlantısı olmayan kurulumlar için imzalı çevrimdışı paketlerle ya da tarayıcı eklenti mağazaları üzerinden teslim edebilir. Bir Güncellemenin kendi ortamına ne zaman kurulacağına Müşteri karar verir. Lisans Verenin destek yükümlülükleri, varsa, yalnız Lisans Verenin desteklenen sürümler politikasında desteklenen olarak adlandırılan sürümler için geçerlidir.

## 6. Kısıtlamalar

Bu Sözleşmenin açıkça izin verdiği ya da emredici hukukun öngördüğü durumlar dışında Müşteri:

- Yazılımı kopyalayamaz, değiştiremez, çeviremez ya da ondan türev eser oluşturamaz; Yazılımın Müşterinin yazmasına izin vermek üzere tasarlandığı yapılandırma, politika, izin listesi ve kurallar bunun dışındadır;
- Yazılımı tersine mühendisliğe tabi tutamaz, kaynak koda dönüştüremez (decompile), çözümleyemez (disassemble) ya da başka bir yolla kaynak kodunu elde etmeye çalışamaz; emredici hukukun (birlikte çalışabilirlik için 5846 sayılı Fikir ve Sanat Eserleri Kanunu madde 38 dahil) bu kısıtlamaya rağmen açıkça izin verdiği ölçü bunun dışındadır ve bu durumda da önce birlikte çalışabilirlik bilgisini Lisans Verenden yazılı olarak istemesi gerekir;
- lisans denetimlerini, imza ve bütünlük doğrulamasını, koltuk sayımını ya da Yazılımın güvenlik denetimlerini kaldıramaz, devre dışı bırakamaz ya da atlatamaz;
- Sipariş Formu açıkça izin vermedikçe Yazılımı kiralayamaz, ödünç veremez, satamaz, alt lisans veremez ya da üçüncü kişilere barındırılan veya yönetilen hizmet olarak sunamaz;
- mülkiyet bildirimlerini kaldıramaz ya da değiştiremez; emredici hukukun izin verdiği haller dışında Lisans Verenin önceden yazılı izni olmadan Yazılımın kıyaslama ya da test sonuçlarını yayımlayamaz;
- Yazılımı ihracat denetimi ve yaptırım mevzuatı dahil yürürlükteki hukuka aykırı biçimde kullanamaz.

## 7. Müşteri verileri ve veri işleme

Yazılım, Müşterinin uç noktalarındaki komutları, dosyaları ve web isteklerini değerlendirir ve varsayılan olarak bunu yerel olarak, Lisans Verene göndermeden yapar. Uç noktaların bir kontrol sunucusuna bağlanıp bağlanmayacağına, hangi kontrol sunucusunu kullanacağına (Müşterinin kendi şirket içi kurulumu ya da Lisans Verenin barındırdığı hizmet) ve hangi isteğe bağlı özelliklerin (örneğin itibar sorguları, tanılama ya da SIEM iletimi) açık olacağına Müşteri karar verir.

Lisans Verenin Müşteri adına kişisel veri işlediği ölçüde (örneğin kontrol sunucusunu barındırırken ya da bir destek talebini yürütürken) taraflar arasındaki Veri İşleme Sözleşmesi uygulanır (taslak: docs/legal/dpa.tr.md ve docs/legal/dpa.en.md). Müşterinin işlettiği şirket içi kurulumlarda Lisans Veren Müşterinin telemetrisini almaz ve Yazılımın kaydettiği veriler bakımından veri sorumlusu Müşteridir. Çalışanlarını Yazılım hakkında hukukun gerektirdiği biçimde bilgilendirmekten Müşteri sorumludur (şablon aydınlatma metni: docs/legal/kvkk-aydinlatma-metni-calisan.tr.md).

## 8. Mülkiyet ve geri bildirim

Yazılım satılmaz, lisanslanır. Yazılım üzerindeki fikri mülkiyet hakları dahil tüm haklar Lisans Verende ve lisans verenlerinde kalır. Müşterinin verileri, yapılandırması ve politikaları üzerindeki haklar Müşteride kalır. Lisans Veren, Müşterinin kendi isteğiyle verdiği öneri ve geri bildirimleri, Müşterinin gizli bilgilerini açıklamamak ve Müşteriyi tanımlamamak koşuluyla, herhangi bir yükümlülük doğmadan kullanabilir.

## 9. Gizlilik

Her taraf diğerinin kamuya açık olmayan bilgilerini gizli tutar, yalnız bu Sözleşmenin ifası için kullanır ve en az makul özenle korur. Yazılım, Lisans Verenin yayımlamadığı belgeleri, lisans dosyası ve fiyatlar Lisans Verenin gizli bilgisidir.

## 10. Garanti

Lisans Veren, ücretli bir sürümün ilk tesliminden itibaren 90 gün boyunca Yazılımın belgelerinde anlatıldığı şekilde esas itibarıyla çalışacağını garanti eder. Bu garantinin ihlali halinde Müşterinin tek talep hakkı, Lisans Verenin seçimine göre, uygunsuzluğun giderilmesi ya da ilgili lisansın sona erdirilerek kalan Lisans Süresi için ödenen bedelin iadesidir.

Yazılım bir tespit ve müdahale katmanıdır. Riski azaltır; her zararlı ya da istenmeyen eylemin tespit edileceğini veya engelleneceğini garanti etmez ve Müşterinin diğer güvenlik denetimlerinin, yedeklerinin ya da inceleme süreçlerinin yerini tutmaz. Davranış, yapay zekâ ajan aracına bağlıdır: araç bir kancayı devre dışı bıraktığında, ona güvenmediğinde, zaman aşımına uğrattığında ya da sonlandırdığında çağrıya ne olacağına araç karar verir. Bu maddede yazılanlar dışında ve hukukun izin verdiği ölçüde Yazılım, belirli bir amaca uygunluk dahil açık ya da örtülü başka bir garanti olmaksızın sağlanır. Deneme lisansları "olduğu gibi" sağlanır.

## 11. Sorumluluğun sınırlandırılması

Hukukun izin verdiği ölçüde taraflardan hiçbiri dolaylı zararlardan, kâr ya da gelir kaybından veya veri kaybından sorumlu değildir ve her tarafın bu Sözleşme kapsamındaki toplam sorumluluğu, talebe yol açan olaydan önceki 12 ayda Müşterinin Yazılım için ödediği ya da ödemesi gereken bedelle sınırlıdır. Bu sınırlar, ağır kusur ya da kast nedeniyle sorumluluk (Türk Borçlar Kanunu madde 115) dahil hukuken sınırlandırılamayan sorumluluğa, 6. madde ihlallerine ve Müşterinin ödeme yükümlülüklerine uygulanmaz.

## 12. Süre ve fesih

Bu Sözleşme, Müşterinin kabulüyle ya da Yazılımın ilk kurulumuyla başlar ve Lisans Süresi boyunca devam eder. Taraflardan biri Sözleşmeyi esaslı olarak ihlal eder ve bildirimden itibaren 30 gün içinde ihlali gidermezse diğer taraf yazılı bildirimle feshedebilir. Sona ermede lisanslar biter, Müşteri Yazılımı kullanmayı bırakır ve kaldırır; 6, 8, 9, 11 ve 13. maddeler yürürlükte kalır.

## 13. Uygulanacak hukuk ve uyuşmazlıklar

Bu Sözleşmeye Türkiye Cumhuriyeti hukuku uygulanır. [İstanbul (Çağlayan) - hukuk tarafından teyit edilecek] mahkemeleri ve icra daireleri münhasıran yetkilidir. Müşteriye uygulanan emredici tüketici ya da kamu ihale kuralları bu maddeyle çeliştiği ölçüde önceliklidir.

## 14. Çeşitli hükümler

Sipariş Formu, bu Sözleşme, Veri İşleme Sözleşmesi ve varsa destek eki, Yazılım hakkındaki sözleşmenin tamamını oluşturur. Çelişki halinde önce Sipariş Formu, veri koruma konularında ardından Veri İşleme Sözleşmesi, sonra bu Sözleşme uygulanır. Taraflardan hiçbiri diğerinin yazılı onayı olmadan bu Sözleşmeyi devredemez; işletmesinin tamamını devralan halefe devir bunun dışındadır. Geçersiz sayılan bir hüküm, amacına en yakın geçerli hükümle değiştirilir ve Sözleşmenin kalanı yürürlükte kalır. Bildirimler, kayıtlı elektronik posta (KEP) ya da Sipariş Formundaki e-posta adresleri dahil, yazılı olarak yapılır.

"Kabul ediyorum" seçeneğini işaretleyen ya da Yazılımı kuran kişi, yukarıdakileri Müşteri adına onaylamış olur.

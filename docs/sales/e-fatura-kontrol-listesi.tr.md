# e-Fatura / e-Arşiv kontrol listesi (muhasebe sağlayıcısıyla)

> **TASLAK — hukuk/iş onayı gerekir.** Bu liste vergi danışmanlığı değildir.
> Oranlar, senaryolar ve süreler mali müşavir / muhasebe sağlayıcısı tarafından
> teyit edilmeden uygulanmaz. Son güncelleme: 14.10.2026 · Sahibi: Finans

Singularity AIDR faturaları ürün içinden kesilmez: ürünün kendi ödeme
sağlayıcıları (Stripe/Polar, USD) kapalıdır ve Türkiye'deki satışlar yazılı
teklif + muhasebe sağlayıcısının e-belge sistemi üzerinden faturalanır
([teklif şablonu](onprem-teklif-sablonu.tr.md)). Bu liste, muhasebe sağlayıcısı
(mali müşavir ve kullandığı özel entegratör / GİB portalı) ile birlikte bir kez
kurulacak düzeni ve her faturada yapılacak kontrolleri sıralar.

## A. Bir kez: kurulum

- [ ] **e-Fatura mükellefiyeti.** Şirketin GİB e-Fatura sistemine kayıtlı olduğu
      ve hangi kanalın (özel entegratör ya da GİB portalı) kullanıldığı
      yazılı. Kayıtlı değilse kayıt süreci ve tarihi mali müşavirle planlanır.
- [ ] **e-Arşiv.** e-Fatura'ya kayıtlı olmayan alıcılar için e-Arşiv fatura
      düzenleme yetkisi aynı kanalda açık.
- [ ] **Ürün/hizmet kartları.** Muhasebe sisteminde SKU başına kalem kartı:
      `AIDR-<EDİSYON>-<KURULUM>-<SÜRE>-<KADEME>` lisans kalemleri, `AIDR-SUP-*`
      destek, `AIDR-ADD-*` ek ürünler, `AIDR-SVC-*` hizmetler. Her kartın KDV
      oranı mali müşavirce teyit edildi (yazılım lisansı ve hizmetlerde
      genel oran beklenir; teyit edilmeden varsayılmaz).
- [ ] **Kamu alıcıları.** Kamu idarelerine kesilecek faturalar için kullanılacak
      senaryo/profil ve IBAN bilgisi zorunluluğu ile KDV tevkifatının
      uygulanıp uygulanmayacağı ve oranı mali müşavirce yazılı olarak
      belirlendi.
- [ ] **Yurt dışı alıcılar.** Yurt dışındaki bir müşteriye satışta hizmet
      ihracatı istisnası ve belge düzeni (e-Arşiv / e-Fatura ihracat
      senaryosu, döviz) mali müşavirce belirlendi.
- [ ] **Döviz bazlı teklifler.** Teklif "döviz bazlı, TCMB kuruyla TRY" ise hangi
      kurun (fatura tarihindeki TCMB döviz satış kuru) ve kur farkı
      faturasının nasıl düzenleneceği yazılı.
- [ ] **Saklama.** e-Faturaların ve eklerinin saklanma süresi ve yeri (Vergi
      Usul Kanunu ve Türk Ticaret Kanunu süreleri; mali müşavir teyit eder)
      ve kimin erişebileceği yazılı.
- [ ] **Yetki.** Fatura onaylama/gönderme yetkisi olan kişiler (en az iki kişi)
      ve kanal hesaplarında çok adımlı doğrulama açık.

## B. Her fatura: düzenlemeden önce

- [ ] İmzalı teklif ya da müşterinin satın alma siparişi (PO) var; PO numarası
      faturaya yazılacak.
- [ ] Alıcının **GİB e-Fatura kayıtlı kullanıcılar** listesinde olup olmadığı
      fatura günü kontrol edildi: kayıtlıysa e-Fatura, değilse e-Arşiv.
- [ ] Alıcının unvanı, vergi dairesi, VKN/TCKN, adresi ve (varsa) e-Fatura
      posta kutusu etiketi siparişteki bilgilerle aynı.
- [ ] Senaryo seçildi: temel / ticari (ticari faturada alıcının kabul/ret
      süresi işler) ya da kamu senaryosu. Kamuda tevkifat uygulanacaksa oran
      mali müşavir teyidiyle girildi.
- [ ] Kalemler teklifle birebir: SKU, koltuk sayısı, birim fiyat, süre.
      Açıklama alanı: `Singularity AIDR lisansı, [başlangıç]–[bitiş], [N]
      koltuk, lisans no [license_id], teklif [AIDR-Q-...]`.
- [ ] Döviz bazlı teklifte kur ve kur tarihi açıklamaya yazıldı.
- [ ] Fatura tarihi, teslim (lisans dosyası teslimi) ya da hizmetin
      tamamlanmasıyla ilişkilendirildi ve yasal düzenleme süresi içinde
      (mali müşavirin belirlediği gün sınırı) kalıyor.
- [ ] Fiziksel teslim (internetsiz kurulum için taşınabilir ortam ya da donanım)
      varsa e-İrsaliye gerekip gerekmediği mali müşavirle teyit edildi.

## C. Her fatura: düzenledikten sonra

- [ ] ETTN (fatura evrensel tekil numarası) teklif/müşteri kaydına ve /admin
      müşteri kaydının notuna yazıldı.
- [ ] Ticari faturada alıcının kabul/ret yanıtı izlendi; ret halinde düzeltme
      süreci (iade faturası / yeni fatura) mali müşavirle yürütüldü.
- [ ] Vade takvimi Finans'ın tahsilat listesinde; vade + 7 günde hatırlatma.
- [ ] Tahsil edilmeyen alacakta yalnız yönetilen özellikler (lisans
      yenilenmez, ek koltuk verilmez) etkilenir; uç noktalardaki yerel tespit
      hiçbir koşulda uzaktan kapatılmaz ([pricing.md](pricing.md)).

## D. Yenileme ve değişiklikler

- [ ] Dönem içi koltuk artışı: ek koltuklar için kıst (pro-rata) ek fatura;
      yeni imzalı lisans dosyası aynı gün teslim edilir.
- [ ] İade / iptal: iade faturası ya da gider pusulası gerekliliği mali
      müşavirce belirlenir; lisans sonlandırma kaydı /admin'e yazılır.
- [ ] Yenileme faturası, yeni lisans dosyasıyla aynı lisans dönemine bağlanır.

## Muhasebe sağlayıcısından istenecekler

| İstek | Neden |
|---|---|
| e-Fatura / e-Arşiv kanalının adı, erişim yöntemi ve yetkili kullanıcıları | Faturayı kimin, nereden kestiği belli olsun |
| Ürün kartları için KDV oranı ve kamu tevkifatı görüşü (yazılı) | Yanlış oranla fatura iadesi önlenir |
| Fatura düzenleme süresi ve teslim tarihi ilişkisi (yazılı) | Lisans teslimi ile fatura tarihi uyumu |
| Döviz bazlı teklifte kur ve kur farkı düzeni | TCMB kuru ve kur farkı faturası |
| Saklama süresi ve arşiv yeri | Denetimde belgeye erişim |
| Aylık mutabakat: kesilen faturalar ↔ /admin'deki lisanslar | Lisanssız fatura ya da faturasız lisans kalmasın |

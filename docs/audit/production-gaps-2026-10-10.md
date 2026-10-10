# AIDR production eksikleri ve kabul koşulları

10 Ekim 2026 kayıt güncellemesi. **Karar: NO-GO. Durum: OPEN. Ürün müşteri production kurulumu veya genel satış için kabul edilmiş değildir.**

Bu kayıt, dal birleştirmesinden sonraki açık işleri ve kapanış koşullarını içerir. İlk 20 madde 9 Ekim incelemesinde doğrulanmış kod bulgularıdır: 14 P1 ve 6 P2. 21–40 numaraları ek uygulama sınırlarını, ölçüm ve saha kabulü eksiklerini içerir; 40 maddenin tamamı ayrı doğrulanmış exploit değildir. Kurumsal kayıtlarda 13 kapı open; production profili 12 kapıyı, yatırımcı profili ayrıca INV-001’i kullanır.

Kaynak davranışı 0e72b1681480078de582ba08a0737ce5450f0de9 üzerinde incelendi. Bu belgenin kayıt tabanı e5250905c29908556b48df570707f4a6b1e2c0af. 10 Ekim’de bu bulgular için kod düzeltmesi, yeni tam test koşusu veya canlı deployment kabulü yapılmış değildir. Her madde, tarihli kanıtı veya kaynak sınırını belirtir; düzeltme ve kapanış testleri yapılacak işlerdir.

Dal birleştirme ve test geçmişi [9 Ekim incelemesinde](production-review-2026-10-09.md), ref SHA ve koruma kayıtları [dal envanterinde](branch-consolidation-2026-10-09.json) bulunur. Merge, push ve temiz çalışma ağacı production onayı değildir. P1 yüksek etkili güvenlik/yetki/veri/yayın sorunu; P2 daha dar koşullu işlev veya sürekli kullanım sorunudur.

## Production öncesi düzeltilmesi gerekenler

P1: Güvenlik, hassas veri, yetki veya yayın kontrolünde yüksek etkili hata. P2: Daha dar koşullarda hata veya sürekli kullanımda operasyon sorunu. Bulgular düzeltme uygulanmış iddiası taşımaz; entegrasyon için yapılan Koffi ve ACL düzeltmeleri ayrı kaydedilmiştir.

### 1 P1 OIDC secret seçimi tenant sınırını aşabiliyor

Kaynak: [index.ts satır 101](../../supabase/functions/oidc-sso/index.ts#L101), [handler.ts satır 602](../../supabase/functions/oidc-sso/handler.ts#L602), [token exchange satır 239](../../supabase/functions/oidc-sso/handler.ts#L239).

- İşlev: Kurum sahibi OIDC sağlayıcısı ve client secret referansı tanımlıyor.
- Sorun ve kanıt: Referans global ortam değişkeninden tenant bağı olmadan çözülüyor. A tenant sahibi başka referansı kendi HTTPS token endpoint'iyle tanımlayınca callback başarısız olsa bile seçilen secret token isteğinde gönderildi; gerçek handler ve sahte IdP fixture'ıyla doğrulandı.
- En küçük düzeltme: Secret çözümlemesini tenant ve sunucu tarafından yönetilen issuer/client kaydına bağlayın; kullanıcıdan gelen global referansı yetki kabul etmeyin.
- Ertelenirse: Bir tenant başka kurumun yapılandırılmış OIDC kimlik bilgisini öğrenebilir.
- Kapanış testi: Başka tenant referansı, yanlış issuer ve saldırgan token endpoint testlerinde secret hiçbir ağ isteğine eklenmemeli; meşru kurum bağlantısı çalışmalı.

### 2 P1 Workspace saklama güncellemesi owner ve alt süre sınırlarını aşıyor

Kaynak: [workspace SQL satır 83](../../supabase/migrations/20260925000040_tenant_workspace_settings.sql#L83), [tenant-settings satır 259](../../supabase/functions/tenant-settings/index.ts#L259).

- İşlev: Workspace ayarı verinin kaç gün saklanacağını güncelliyor.
- Sorun ve kanıt: Tüm 178 migration izole PostgreSQL'e uygulandı. Admin workspace RPC'siyle süreyi 1 güne düşürebildi; 30 günlük alt sınırı olan identity/config sınıfları ve 7 günlük telemetry sınıfları 1 oldu. Owner'ın yeni bounded retention RPC'si aynı isteği reddediyor.
- En küçük düzeltme: Retention değişimini yalnız owner ve sınıf sınırlarını uygulayan ortak RPC'ye yönlendirin. Admin'in workspace adı değiştirme yetkisini koruyun.
- Ertelenirse: Yetkisiz süre azaltımı ve reaper/offboarding ile beklenenden erken veri kaybı oluşur.
- Kapanış testi: Admin retention değiştirememeli; owner sınıf alt sınırlarını aşamamalı. Reaper ve offboarding yalnız geçerli sürelerle çalışmalı.

### 3 P1 VS Code native araç adları politikaya ulaşmıyor

Kaynak: [aidr-hook.ts satır 1081](../../packages/extension/src/aidr-hook.ts#L1081). Host adları: [VS Code araç referansı](https://code.visualstudio.com/docs/agents/reference/tools-reference).

- İşlev: Host araçları canonical shell/file işlemlerine dönüştürülüyor.
- Sorun ve kanıt: Gerçek built hook sürecinde yasak komut Bash ile deny, runInTerminal ile boş izin yanıtı verdi. Yasak dosya yolu Write ile deny, createFile ile boş yanıt verdi. Native adlar/alanlar alias tablosunda yok.
- En küçük düzeltme: runInTerminal/createFile adlarını ve input alanlarını canonical işlemlere eşleyip gerçek payload testleri ekleyin.
- Ertelenirse: Desteklenen editörde shell ve filesystem engellemesi aşılır.
- Kapanış testi: Gerçek VS Code payload’larında yasak komut çalışmamalı, yasak dosya oluşmamalı; meşru karşılıkları çalışmalı. Hook verdict’i yanında gerçek yan etki gözlenmeli.

### 4 P1 Prompt hata ve deadline yolu block kurallarını bırakıyor

Kaynak: [Claude giriş satır 100](../../packages/claude-code/src/user-prompt-submit.ts#L100), [fallback satır 222](../../packages/claude-code/src/user-prompt-submit.ts#L222), [ortak prompt-inspection satır 134](../../packages/core/src/prompt-inspection.ts#L134).

- İşlev: Prompt gönderilmeden PII, secret, tenant DLP ve safety kontrolü yapılıyor.
- Sorun ve kanıt: secrets=warn ve pii=block ile normal e-posta engellenirken 2 MiB üstü aynı içerik yalnız uyarıyla geçti. Kurulu tenant detector hatası da büyük girdi yolunda değerlendirilmedi. Ortak deadline fallback PII/jailbreak/content-safety ve yalnız promptSafety ile gelen tenant block tabanını hesaba katmıyor. Yüklenmiş etkin tenant DLP deadline yolunda engelleniyor; büyük girdi veya tenant DLP yüklenmeden oluşan hata yolunda tenant kuralı öğrenilmeden karar veriliyor.
- En küçük düzeltme: Hata kararını tüm etkin block kurallarından üretin; tenant politikasının sonucu bilinmiyorsa gönderimi durdurun.
- Ertelenirse: Boyut veya timeout durumunda yapılandırılmış hassas veri engeli çalışmaz.
- Kapanış testi: Boyut aşımı, detector exception, tenant yükleme hatası ve timeout ayrı sınanmalı. Zorunlu denetim tamamlanmadığında orijinal prompt dış sağlayıcıya ulaşmamalı.

### 5 P1 Relative dosya policy yanlış çalışma dizinini kullanıyor

Kaynak: [policy.ts satır 54](../../packages/core/src/policy.ts#L54), [evaluator.ts satır 2149](../../packages/core/src/evaluator.ts#L2149).

- İşlev: Dosya hedefinin izinli kökte olup olmadığı hesaplanıyor.
- Sorun ve kanıt: Hook cwd izinli klasörde, context.workingDirectory dışarıdayken Write relative.txt allow verdi. Policy yolu process.cwd üzerinden çözüyor; tool'un gerçek hedefi izinli kökün dışında kalıyor.
- En küçük düzeltme: Güvenilir workingDirectory bağlamını ortak path çözümlemesine ve diff-aware eski dosya okumasına aktarın.
- Ertelenirse: Relative hedefler filesystem kapsamını aşabilir veya yanlış engellenebilir.
- Kapanış testi: Relative ve absolute yollar güvenilir host workingDirectory üzerinden gerçek hedefe çözülmeli; hook process.cwd değişimi kararı bozmamalı.

### 6 P1 XML namespace prefix değişimi DOCX ve ODF kontrolünü atlıyor

Kaynak: [ooxml.ts satır 226](../../packages/browser-guard/src/engine/office/ooxml.ts#L226), [xml.ts satır 452](../../packages/browser-guard/src/engine/office/xml.ts#L452), [odf.ts satır 284](../../packages/browser-guard/src/engine/office/odf.ts#L284).

- İşlev: Office/ODF XML metni ve macro işaretleri inceleniyor.
- Sorun ve kanıt: Aynı namespace URI ile w:p/w:t e-postayı maskeledi, geçerli x:p/x:t allow verdi. ODF script:event-listener engellenirken aynı URI'li s:event-listener geçti.
- En küçük düzeltme: Eleman ve nitelikleri prefix metni yerine namespace URI ve yerel adla eşleştirin.
- Ertelenirse: Geçerli dosyalar ham hassas veri veya macro kontrolü atlamasıyla geçer.
- Kapanış testi: Aynı namespace URI ile farklı prefix ve varsayılan namespace kullanan eşdeğer belgeler aynı masking/macro sonucunu üretmeli.

### 7 P1 Metin dosyası adı gerçek PDF türünü gizliyor

Kaynak: [files.ts satır 1130](../../packages/browser-guard/src/engine/files.ts#L1130).

- İşlev: Dosya uzantısı ve içerik türü tarayıcıyı seçiyor.
- Sorun ve kanıt: Hex e-posta içeren PDF report.pdf olarak engellendi. Aynı byte dizisi report.txt/text/plain olarak allow döndü; bilinen uzantı içerik sniff kontrolünü erken kesiyor.
- En küçük düzeltme: Güçlü içerik imzalarını uzantı kararından önce uygulayın; document-block politikasını da gerçek tür üzerinden değerlendirin.
- Ertelenirse: Yalnız yeniden adlandırılan dosya hassas veri taramasını aşar.
- Kapanış testi: Aynı PDF byte’ları farklı ad ve MIME değerlerinde aynı sonuca ulaşmalı; çelişkili içerik türü güvenli değerlendirilmelidir.

### 8 P1 XLSX maskeleme formülde ham veriyi bırakıyor

Kaynak: [ooxml.ts satır 518](../../packages/browser-guard/src/engine/office/ooxml.ts#L518).

- İşlev: Hücre değerleri maskelenerek yeni ZIP üretiliyor.
- Sorun ve kanıt: E-posta içeren f formülü ile aynı v cache değeri mask kararı verdi, fakat sonuç ZIP'in f alanında ham e-posta kaldı. Cache değeri yokken aynı formül allow verdi.
- En küçük düzeltme: Formülü tarayın; hassas formülü engelleyin veya formülü kaldırıp maskelenmiş sabit hücre üretin.
- Ertelenirse: Maskelendiği bildirilen dosya hâlâ ham veriyi içerir ve yeniden hesaplamada gösterir.
- Kapanış testi: Çıktı ZIP’inde formula/cache dahil ilgili alanlarda ham veri kalmamalı; belge yeniden açılıp hesaplandığında hassas veri geri gelmemeli.

### 9 P1 PDF ek dosyaları eksik tarama uyarısı olmadan geçiyor

Kaynak: [extract.ts satır 246](../../packages/browser-guard/src/engine/pdf/extract.ts#L246).

- İşlev: PDF görünür metni, form ve bilgi alanları taranıyor.
- Sorun ve kanıt: Görünür sayfası temiz PDF'ye Names/EmbeddedFiles üzerinden e-postalı secret.txt eklendi. Gerçek PDF taraması allow verdi; eksik kapsama işareti üretmedi.
- En küçük düzeltme: EmbeddedFiles/FileAttachment/XMP yollarının varlığını saptayın; desteklenmeyen ek içeriği gönderime kapatın.
- Ertelenirse: Tam PDF yüklemesiyle ek dosyadaki hassas veri sağlayıcıya gider.
- Kapanış testi: Temiz görünür sayfa ve hassas EmbeddedFiles eki birlikte taranmalı veya reddedilmeli; desteklenmeyen içerik temiz sayılmamalı.

### 10 P1 Codex structuredContent içindeki binary etiketi metin taramasını atlıyor

Kaynak: [output-protection.ts satır 128](../../packages/codex/src/output-protection.ts#L128).

- İşlev: MCP çıktısı modele ulaşmadan prompt injection için kontrol ediliyor.
- Sorun ve kanıt: structuredContent nesnesi type=image/audio/blob deyince data/blob atlanıyor. Gerçek hook'ta data içindeki zararlı yönerge geçti; aynı içerik type=text ile OUT-INJ-001 engeli aldı.
- En küçük düzeltme: Arbitrary structuredContent'i bütünüyle tarayın; binary istisnasını yalnız doğrulanmış MCP content bloklarına uygulayın.
- Ertelenirse: Untrusted çıktı kendi etiketini seçerek denetimden çıkar.
- Kapanış testi: Untrusted structuredContent’in yalnız type alanını değiştirmek denetimi atlatmamalı; nested ve karışık envelope’lar sınanmalı.

### 11 P1 OpenCode JSONC config MCP deny kuralını atlıyor

Kaynak: [tool-handler.ts satır 48](../../packages/opencode/src/tool-handler.ts#L48), [OpenCode config referansı](https://docs.opencode.ai/docs/config/).

- İşlev: Config'teki sunucu isimleri canonical MCP araç adını kuruyor.
- Sorun ve kanıt: Keşif yalnız opencode.json okuyor. Desteklenen opencode.jsonc'deki sunucu adı tanınmayınca default_action=block ve unknown_server_action=block politikasında host adı null, doğru canonical ad deny/POL-MCP-005 üretti.
- En küçük düzeltme: Üç config konumunda json ve jsonc dosyalarını aynı parser ile okuyun.
- Ertelenirse: Geçerli kullanıcı config'i varsayılan MCP engellemesini devre dışı bırakır.
- Kapanış testi: JSON/JSONC, yorumlar, üç config konumu ve okunamayan dosyalar aynı kimlik ve blocking sözleşmesini korumalı.

### 12 P1 OpenCode karışık raw MCP sonucu zararlı content alanını bırakıyor

Kaynak: [output-handler.ts satır 168](../../packages/opencode/src/output-handler.ts#L168).

- İşlev: Desteklenen raw MCP hook yolu çıktıdaki metni inceliyor.
- Sorun ve kanıt: content içinde zararlı metin, ek output alanında temiz metin olduğunda gerçek handler inspected_clean/rawMcpResult=false kaydetti; content değişmeden kaldı. Bulgu raw MCP hook yoluna bağlıdır; gerçek OpenCode binary/model E2E bu alt incelemede çalışmadı.
- En küçük düzeltme: content bulunan nesneyi raw MCP olarak ele alın veya karışık envelope'u karantinaya alın.
- Ertelenirse: Desteklenen bu yolda saldırgan içerik modele denetlenmeden ulaşabilir.
- Kapanış testi: Gerçek OpenCode sürecinde zararlı content modele ulaşmamalı. Handler kanıtı, eksik gerçek host/model E2E kabulüyle tamamlanmalı.

### 13 P1 Privacy audit anahtar yenilemesi doğrulanamayan zincir üretiyor

Kaynak: [persistent-audit.ts satır 11](../../packages/privacy/src/platform/persistent-audit.ts#L11), [runtime.ts satır 37](../../packages/privacy/src/platform/runtime.ts#L37).

- İşlev: Kararlar imzalı ve hash bağlı audit akışına yazılıyor.
- Sorun ve kanıt: Aynı DB önce a1 sonra a2 anahtarıyla açıldı, iki karar da allow oldu. Akış iki anahtarı içeriyor; mevcut verifyAudit eski ve yeni anahtarın ikisiyle de false verdi.
- En küçük düzeltme: Başlangıçta mevcut akışın anahtar kimliği ve imzasını doğrulayın; uyuşmazlıkta append'i reddedin. Rotation için checkpoint ve yeni akış prosedürü sağlayın.
- Ertelenirse: Rutin anahtar yenilemesi ürünün kendi audit geçmişini doğrulanamaz yapar.
- Kapanış testi: Normal restart, yanlış anahtar ve meşru rotation ayrı sınanmalı; eski/yeni audit segmentleri ve checkpoint bağlantısı bağımsız doğrulanmalı.

### 14 P1 Production publish NO-GO kaydını zorunlu denetlemiyor

Kaynak: [release-promote.yml satır 197](../../.github/workflows/release-promote.yml#L197).

- İşlev: İmzalı RC doğrulandıktan sonra paketler, dashboard ve latest yayımlanıyor.
- Sorun ve kanıt: Yayın/RC workflow'ları candidate-bound production GO kontrolünü veya claim-check --mode=gate çağrısını zorunlu çalıştırmıyor. Mevcut ticari tutarlılık kontrolleri tüm kapılar open/NO-GO iken geçebiliyor. Workflow production environment seçiyor; ortamın zorunlu reviewer koruması API ile doğrulanamadı (404), bu nedenle manuel onay bariyeri varsayılmıyor.
- En küçük düzeltme: Güvenilir doğrulayıcıyla aynı adayın GO kararını publish/deploy öncesine ekleyin ve NO-GO adayın yayımlanamadığını test edin.
- Ertelenirse: İmzalı fakat güvenlik/ticari kabulü eksik aday production'a çıkabilir.
- Kapanış testi: NO-GO, boş aday, yanlış digest ve eski kanıtla yayın durmalı; yalnız aynı adayın güvenilir GO kaydı publish/deploy’u açmalı.

## Ayrıca düzeltilmesi gerekenler

### 15 P2 OIDC ayarı yetki ve audit ile tek transaction değil

Kaynak: [handler.ts satır 668](../../supabase/functions/oidc-sso/handler.ts#L668), [store.ts satır 115](../../supabase/functions/oidc-sso/store.ts#L115).

- İşlev: Sağlayıcı ayarı kaydediliyor ve admin audit yazılıyor.
- Sorun ve kanıt: Audit insert hatasında handler 503 döndü fakat enabled sağlayıcı DB'de kaldı. Discovery beklerken owner üyeliği kaldırılınca da kayıt başarılı oldu; service-role upsert actor üyeliğini transaction içinde kontrol etmiyor.
- En küçük düzeltme: Provider/domain write, güncel owner kontrolü ve audit'i tek RPC transaction'ında yapın.
- Ertelenirse: Yetkisi kaldırılan aktör değişiklik yapabilir; başarısız görünen güvenlik ayarı gerçekte uygulanmış ve auditi eksik olabilir.
- Kapanış testi: Audit insert hatasında bütün ayarlar rollback olmalı; transaction commit öncesi yetkisi kaldırılan aktörün yazımı reddedilmeli.

### 16 P2 Kesilen diff aware girdi temiz allow sayılıyor

Kaynak: [edit-views.ts satır 141](../../packages/core/src/agent-safety/edit-views.ts#L141), [evaluator.ts satır 2247](../../packages/core/src/evaluator.ts#L2247).

- İşlev: Test/guardrail değişiklikleri satır ve diff görünümünde inceleniyor.
- Sorun ve kanıt: Normal it.skip yazımı ask verdi. Önüne 4097 boşluk eklenince uzun satır kesildi, truncated=false ve allow oldu. 20001 newline ile 20.037 karakterlik örnekte truncated=true olsa da allow döndü.
- En küçük düzeltme: Uzun satırları kayıpsız tarayın; partial inspection sonucunu belirsiz/blocking karara katın.
- Ertelenirse: Düşük boyutlu değişiklikler agent-safety kuralını aşabilir.
- Kapanış testi: Uzun boşluk/satır/newline güvenlik kararını değiştirmemeli; kısmi inceleme temiz allow yerine belirsiz veya blocking karar üretmeli.

### 17 P2 Privacy audit export 100 bin kararda duruyor

Kaynak: [persistent-audit.ts satır 16](../../packages/privacy/src/platform/persistent-audit.ts#L16).

- İşlev: Olay incelemesi için karar geçmişi dışa aktarılıyor.
- Sorun ve kanıt: records sıra numarası 100001 olunca AUDIT_EXPORT_LIMIT veriyor; sayfalı export yok. Saniyede bir karar için yaklaşık 27,8 saat, input/output ayrı karar olduğunda yaklaşık 13,9 saat yeterli.
- En küçük düzeltme: Sıra numarasıyla sayfalı export ve önceki hash'ten devam eden doğrulama ekleyin.
- Ertelenirse: Sürekli çalışan kurulumun olay geçmişi alınamaz.
- Kapanış testi: 100 bin üzeri kayıt eksiksiz ve sıra/hash doğrulamalı export edilmeli; page gap, tekrar ve eşzamanlı append sınanmalı.

### 18 P2 Release kanıtı varsayılanları farklı adayları gösteriyor

Kaynak: [receipt verifier satır 45](../../scripts/verify-commercial-gate-receipts.mjs#L45), [evidence generator satır 36](../../scripts/generate-v8-evidence-index.mjs#L36).

- İşlev: Receipt ve index aynı release adayı için doğrulanmalı.
- Sorun ve kanıt: Import edilmiş varsayılanlar farklı: biri 20260913, diğeri 20260916-r9 inventory dosyası. Generator'ın adayı için hazırlanmış receipt varsayılan verifier'da reddedilir; override farklı adayı seçebilir.
- En küçük düzeltme: Tek ortak candidate kaynağını veya zorunlu aynı candidate parametresini kullanın.
- Ertelenirse: Release kararında yanlış adayın kanıtı değerlendirilir veya doğru kanıt reddedilir.
- Kapanış testi: Generator, verifier, signer ve publisher aynı inventory digest’ini kullanmalı; farklı adaylar açıkça reddedilmeli.

### 19 P2 Restore drill kanıtları retention ile silinmiyor

Kaynak: [deployment-restore-drill.mjs satır 319](../../scripts/deployment-restore-drill.mjs#L319), [temizlik satır 334](../../scripts/deployment-restore-drill.mjs#L334).

- İşlev: Tamamlanan recovery denemeleri ve kanıt dosyaları temizleniyor.
- Sorun ve kanıt: İşlem recovery-project marker'ını kaldırıyor; sonraki retention temizliği marker olmayan klasörü atlıyor. 2020 tarihli, 1 günlük retention fixture'da expired=0 ve kanıt dosyası kaldı.
- En küçük düzeltme: Aktif recovery marker'ından ayrı kalıcı sahiplik marker'ı kullanın; operator klasörü korumasını sürdürün.
- Ertelenirse: Hassas recovery kanıtı ve disk kullanımı süresiz birikir.
- Kapanış testi: Tamamlanmış expired AIDR drill kanıtları temizlenmeli; aktif recovery ve operatörün yabancı klasörleri korunmalı.

### 20 P2 Yeni kısa flag redaction wrapper durumlarında secret bırakıyor

Kaynak: [mcp-launch-redaction.ts](../../packages/core/src/mcp-launch-redaction.ts).

- İşlev: AI-BOM ve MCP launch argument çıktıları kimlik bilgilerini maskeliyor.
- Sorun ve kanıt: Doğrudan curl kısa flag'i maskelenirken sudo -u root curl -u ve env -u NAME redis-cli -a wrapper option değerleri command owner keşfini bozuyor. Attached curl -uuser:password biçimi de kapsanmıyor; gerçek modül üzerinde tekrarlandı.
- En küçük düzeltme: Wrapper seçeneklerinin değerlerini parse edin ve attached kısa flag biçimini ortak secret redaction'a alın.
- Ertelenirse: Envanter ve destek çıktıları kısa kimlik bilgilerini açık metinle taşıyabilir.
- Kapanış testi: Doğrudan/wrapper/ayrı/bitişik flag biçimlerinin hiçbirinde secret log, envanter veya support export içinde kalmamalı.


## Ek teknik ve saha kabul eksikleri

### 21 Gerçek NER modelleri kalite kabulünü geçememiş

Kaynak: [model ölçümleri](../../packages/privacy/docs/MODEL_PROVIDER.md#L64), [örnek qualification politikası](../../packages/privacy/ner/qualification-policy.example.json).

Gerçek CPU modelleri Windows ve Linux’ta çalıştırılmıştır; eksik yalnız kurulum değildir. Kamuya açık sentetik 600 belge karşılaştırmasının kayıtlı sonuçları ve sonraki source diagnosis, adayların kalite kabulünü geçmediğini gösteriyor. Aşağıdaki değerler doğru type/boundary ile raw entity true-positive sayılarıdır. DeBERTa satırı whitespace düzeltmesinin cached prediction replay sonucudur; yeni tam defense benchmark değildir.

| Model veya ölçüm | TR kişi | TR adres | EN kişi | EN adres | Temiz belgede müdahale |
| --- | ---: | ---: | ---: | ---: | --- |
| KVKK + PrivyShield başlangıç raw NER | 78/100 | 1/100 | 33/108 | 36/107 | TR 100/100, EN 100/100 |
| KVKK + DeBERTa whitespace düzeltmesi replay | 82/100 | 0/100 | 63/108 | 8/107 | TR 98/100, EN 94/100 |
| COSMOS düzeltilmiş profil | 43/100 | 72/100 | TR kapsamı | TR kapsamı | TR 4/100 |
| OpenAI native aday | 48/100 | 7/100 | 85/108 | 51/107 | TR 87/100, EN 41/100 |

Başlangıç full-defense ölçümünde forwardable output içinde eksik gold maskeleme ilk çiftte TR 3/EN 1, alternatif çiftte TR 11/EN 0 belgede kaydedildi. Offline evaluator gerçek ağ gönderimi yapmaz. Block veya aşırı masking doğru entity recognition yerine geçmez. Son source fixes geçmiş kalite başarısızlıklarını kapatmıyor; adayların approved/qualified kararı yok.

- Gereken iş: Eğitimden bağımsız, tam annotated kurumsal TR/EN corpus ve overlap kontrolü; dil/type bazında raw model ve full defense recall/precision; false-positive iş akışı kabulü; son worker/model/tokenizer/environment hash’leri ve kurum onayı.
- Kapanış: Mevcut örnek engineering policy’nin Wilson recall alt sınırı 0,95, precision alt sınırı 0,90 ve clean disruption üst sınırı 0,05 ölçülmeli. Bunlar resmi sertifika değildir. Onay ancak gerçek kabulden sonra trusted digest ile dağıtılmalı; manifest’e elle approved:true yazılmamalı.

### 22 Python lock ve wheel kanıtları eşleşmiyor

Kaynak: [Linux lock](../../packages/privacy/ner/requirements.linux-py311.lock.txt), [Windows lock](../../packages/privacy/ner/requirements.windows-py312.lock.txt), [Linux metadata](../../packages/privacy/sbom/ner-linux.pypi-licenses.json), [Windows metadata](../../packages/privacy/sbom/ner-windows.pypi-licenses.json).

9 Ekim’de mevcut locklarla repository’nin bindPypiLicenseEvidence doğrulayıcısı toplam 8 binding sorunu bildirdi:

- Linux source_lock_sha256 eski lock’a ait; filelock 4.0.11 ve networkx 3.7 wheel evidence lock hash’leriyle eşleşmiyor: 3 sorun.
- Windows source_lock_sha256 eski lock’a ait; filelock 4.0.11, markupsafe 3.0.4, networkx 3.7 ve setuptools 84.0.0 evidence pinlenmiş wheel’lerle eşleşmiyor: 5 sorun.

Linux Python 3.11 lock’undaki networkx 3.7 Python 3.12 ister. Eski stack’i korumak tek başına sağlıklı kurulum anlamına gelmez. Merge sırasında bazı öneriler uygulanmadı: Hub 2.1.1 mevcut Transformers’ın hub<2 sözleşmesini aşar; mpmath 1.4.1 SymPy 1.14.0’ın mpmath<1.4 sınırını aşar; pytest 9.1.1 pytest-asyncio 1.1.0’ın pytest<9 şartına uymaz; Pydantic 2.13.5 farklı pydantic-core ister. Requirements satırını değiştirmek runtime/CI hash lockunu yükseltmez.

- Gereken iş: Her OS/Python platformunda koordineli resolver ve hash lock; temiz offline wheel kurulumu; bağımlılık tutarlılık kontrolü, gerçek inference ve final locktan yeniden çıkarılmış lisans/SBOM.
- Kapanış: Son platform kurulumları, wheel hash’leri, source_lock_sha256, metadata ve aday inventory birebir eşleşmeli; approved runtime kabulü eklenmeli.

### 23 Privacy quota kayıtları fiziksel olarak birikiyor

Kaynak: [quota kayıtları](../../packages/privacy/src/platform/durable.ts#L39), [purge](../../packages/privacy/src/platform/state.ts#L88).

Her subject/window yeni kayıt üretir. Expiry olmasına rağmen purge yalnız oidc-pending/portal-sessions namespace’lerini kabul eder; quotas temizlenmez. Kayıtlı 120-window denemesinde expired 120 satır kaldı. Bir dakikalık window, 1000 kullanıcı ve günde 480 aktif dakika varsayımı yaklaşık 480.000 yeni satır/gündür; production kapasite ölçümü değildir.

- Etki: SQLite, backup ve bakım maliyeti büyür; quota hesabının doğru olması fiziksel retention sorununu kapatmaz.
- Düzeltme ve kapanış: Yalnız expired quota satırlarına bounded bakım uygulanmalı; çok günlük yükte satır sayısı sınırlı kalmalı. Eşzamanlı tüketim, restart ve tenant izolasyonu korunmalı; replay/clock/audit kayıtlarına genel TTL uygulanmamalı.

### 24 Browser Guard native NER zorunluluğu eksik

Kaynak: [native akış](../../packages/browser-guard/src/content/guard.ts#L402), [ayrı Privacy eklentisi](../../packages/privacy/extension/src/service-worker.ts#L80).

Browser Guard host yokluğu, timeout, büyük metin veya unavailable yanıtında rules-only devam edebilir. Rule scan temizse uyarı ile akış sürebilir. Ayrı Privacy eklentisi requireNativeText etkinse rules-and-ner ister; bütün ürün yolları aynı fail-open davranışta değildir.

- Gereken iş: Browser Guard’da tenant yönetimli native NER zorunlu politikası; ilgili PERSON/ADDRESS denetimi tamamlanmazsa paste/upload/send engeli.
- Kapanış: Host kapalı, crash, timeout, rules-only ve limit aşımı zorunlu politikada durmalı; opsiyonel devam yalnız açık kapsamla yapılmalı.

### 25 Fingerprint algılama ve kapasite sınırları

Kaynak: [index](../../packages/privacy/src/enterprise/data-index.ts#L26), [data policy](../../packages/privacy/src/platform/data-policy.ts#L13), [kapsam](../../packages/privacy/docs/DATA_OPERATIONS.md#L11).

Uzun kaynaklarda en az dört eşleşme ve benzersiz beş-token fragment hash’lerinin yüzde 20’si varsayılan eşiktir; karakterlerin yüzde 20’si değildir. Daha küçük alıntı bu mekanizmadan kaçabilir; ayrı PII/secret kuralları yine yakalayabilir. Toplam 1.000 kaynak belgesi, varsayılan 100.000 fingerprint, kaynakta 8.192 normalize token ve 65.536 scan operation sınırı vardır.

- Gereken iş: Satılan corpus büyüklüğü ve en küçük korunacak alıntı için gerçek recall/false-positive kabulü; gerektiğinde ölçümlü kapasite artışı.
- Kapanış: Kısa/uzun alıntı, benign ortak ifade, normalizasyon ve kapasite sınırları test edilmeli. Unsupported boyut güvenli reddedilmeli; arbitrary paraphrase/OCR veya complete lineage iddiası yapılmamalı.

### 26 Belge medya ve uzak kaynak kapsamı tamam değil

Kaynak: [private Privacy veri işlemleri](../../packages/privacy/docs/DATA_OPERATIONS.md).

Bu sınırlar private servis profilinindir; Browser Guard’ın ayrı parser kapsamıyla karıştırılmamalı:

- PDF/Office yolu temiz UTF-8 TXT üretir; format-preserving redaction değildir. Linux seccomp ister; Windows/macOS document istekleri reddedilir.
- Input 8 MiB ve extracted text 512 KiB ile sınırlıdır; signed politika daha küçük sınır koyabilir. Scanned PDF/legacy Office/unsupported media orijinal olarak gönderilmez.
- Scanned PDF için bounded rasterizer ve bütün sayfaların OCR/visual kabulü açık.
- Local source repository gerçek SharePoint/Drive/S3 içerik fetch, ACL sync ve remote deletion sağlamaz; kurum connector’ı gerekir.
- Audio yolu en fazla 1 MiB, PCM16 WAV, 8–48 kHz ve 120 s için bütün ses örneklerini sıfırlar. ASR/selective masking veya MP3/M4A/Opus desteği değildir.
- Selective audio onaylı TR/EN ASR, orijinal hash’e bağlı kelime timestamp’leri ve residual voice identity incelemesi ister.
- Video için gerçek bounded decoder/transcoder ve bütün frame’lerde bağımsız kabul edilmiş OCR/face/handwriting/signature/audio taraması eksik. CAD/steganografi ayrı uzman detector kabulü ister.

- Kapanış: Satılacak formatlar gerçek artifact üzerinde kabul edilmeli. İlk sürümün dışında kalan özellikler destek kapsamından çıkarılmalı ve güvenli reddedilmelidir; hepsini implement etmek zorunlu bir ilk-sürüm koşulu değildir.

### 27 Gerçek host OS ve sürüm kabulü tamam değil

Kaynak: [support matrix](../../deploy/native/support-matrix.json), [önceki release sonuçları](../../RELEASE_READINESS_REPORT.md).

Matrix Claude Code/OpenClaw/OpenCode/Codex için linux/x64 development build ve scripted mock-model binary kanıtı taşır. Matrix’te Cursor/VS Code receipt alanları boştur. Ayrı 6 Ekim release kaydı Cursor extension-host 8/8, Codex 2/2 ve OpenCode 6/6 developer denemelerini içerir; Cursor agent dispatch/model-output ve tam production matrix’i kabul etmez. Dolayısıyla hiç native test yapılmadı denemez; eksik son imzalı adayın bütün satılan host/OS/arch/version kabulüdür.

Her host için denied-side-effect, benign twin, disabled-hook, crash, timeout, offline ve restart ayrı yürütülmeli. Kurulum/update/rollback/uninstall, binary hash, OS build ve isimli QA/Endpoint/Support kabulü eklenmeli.

Bilinen sınırlar: Claude hook verdict öncesi öldürülürse host devam edebilir; OpenClaw plugin/embedded-runner koşullarına bağlı; OpenCode kaldırılmış/override plugin ve provider stream sınırı ayrıca kabul ister; Codex output-side interception yoktur, hook matcher Bash/apply_patch ile sınırlıdır ve başka MCP/tool yolları hook’a uğramayabilir.

- Kapanış: Hook verdict’i yanında gerçek kalıcı yan etki gözlenmeli; unobserved yollar ürün sınırına yazılmalı. T01-NATIVE-SCENARIOS ve T01-OS-VERSION-MATRIX production receipt’leri tamamlanmalı.

### 28 Kurumsal directory yetkilendirme kabulü eksik

Kaynak: [T19 scope kaydı](../../PRODUCTION_SALES_GAPS.json), [provider kabul işleri](../production-readiness/commercial-gates-prefill-and-owner-actions-2026-10-05.md).

Self-hosted SCIM lifecycle kodu var. Ayrı managed Clerk yolu seçili directory-active durumunu her grant için kanıtlayamıyor; manual/başka-directory grant’in strict deny garantisi için provider kabiliyeti veya kurum kontrolü gerekiyor. Bu source-scope kaydı canlı exploit kanıtı değildir.

- Kapanış: Gerçek Entra/Okta/Clerk’te immutable grup ID mapping, group removal, deactivate, başka-directory üyeliği, pagination/replay, tenant karıştırma ve erişimin tanımlı sürede kesilmesi kabul edilmeli.

### 29 Kurum genelinde bütün alternatif çıkışları kapatan dağıtım eksik

Kaynak: [T37 kaydı](../../PRODUCTION_SALES_GAPS.json), [private servis sınırları](../../packages/privacy/docs/DATA_OPERATIONS.md).

Broker/MCP/seçili CLI gönderimleri bağlıdır. Bütün native/browser/model-provider alternatiflerini zorunlu privacy rotasına alan kurum MDM/OS/network deployment ve gerçek authority materyali tamamlanmış değildir. MV3 eklentisi cihaz genelinde ağ filtresi değildir.

- Gereken iş: Gerçek kurum broker/CA/vault, yönetilen cihaz ve hesap bağlamı, kişisel/kurumsal hesap değişimi, ayrı profil/private window/logout, izinli provider ve alternatif çıkış envanteri.
- Kapanış: Canary hassas veri izin verilmeyen kanallarda görünmemeli; son byte, retry/stream/upload/telemetry yolları gerçek egress capture ile doğrulanmalı. Seçili integration bütün endpoint kapsamı diye satılmamalı.

### 30 Hook gecikmesinin production marjı dar

Kaynak: [hook test bütçesi](../../packages/claude-code/src/__tests__/pre-tool-use-latency.test.ts#L61), [9 Ekim sonuçları](production-review-2026-10-09.md).

Son cold örnekler 1426/1428/1498/1549/1726 ms; medyan 1498 ms, test hedefi 1500 ms. Medyan PASS fakat nominal marj 2 ms ve bazı örnekler hedef üstünde. Persistent HOME ile ilk çağrı 2053 ms, sonraki 745 ms; bu uzun yaşayan daemon ölçümü değildir. Beş örnek production P95/P99 kanıtı sağlamaz.

- Kapanış: Final kurulu/imzalı artifact, müşteri donanımı, AV/Defender, gerçek politika/DLP/NER, yoğun IO/CPU ve eşzamanlı agent yüküyle latency/error dağılımı ölçülmeli. ACL koruması kaldırılmamalı; yalnız testi geçirmek için bütçe artırılmamalı.

### 31 Windows CI timeout bütün süreç ağacını kapatmıyor

Kaynak: [runner](../../scripts/ci-local.mjs#L437).

Windows’ta dış Bash kill sonrası child/grandchild Node süreçleri devam edip pipe’ları açık tutabilir. Önceki 3 dakika hygiene timeout’ı yaklaşık 5 dakika 38 saniye sürdü. Final 14 seçili kontrol ve sonraki 5 belge gate’i geçti; eski timeout final FAIL olarak sunulmamalı.

- Düzeltme: Runner’ın sahip olduğu Windows process tree Job Object veya güvenli PID-bound yöntemle kapatılmalı; POSIX process-group korunmalı.
- Kapanış: Timeout sonrası torun süreç yazma/CPU işi sürdürmemeli, dönüş bounded olmalı, ilgisiz kullanıcı/agent süreçleri çalışmaya devam etmeli.

### 32 Canlı deployment kabulü eksik

Kaynak: [9 Ekim gözlemi](production-review-2026-10-09.md).

9 Ekim read-only ölçümünde app.aidr.singularityrd.com/login DNS çözülmedi; pilot readyz/version JSON yerine 200 HTML SPA ve public cache verdi; landing status 500 verdi. Bunlar 10 Ekim yeniden canlı test sonuçları değildir.

- Kapanış: Doğru DNS/TLS, Worker route/deployment, JSON/no-store sağlık kontratı, deployed revision ve gerçek login/enrollment son adayla kabul edilmeli. Kaynak testinin PASS olması yayındaki revision’ı kanıtlamaz.

### 33 Runtime image güvenliği ve native servis kabulü açık

Kaynak: [7 Ekim scan raporu](../production-readiness/runtime-image-security-2026-10-07.md).

Seçili upstream image setinin aynı scanner/DB koşusunda 33 CRITICAL / 709 HIGH paket-target occurrence bulgusu kaldı. Aynı CVE farklı paketlerde tekrar sayılır; sayı otomatik sömürülebilirlik kanıtı değildir.

| Servis | CRITICAL | HIGH |
| --- | ---: | ---: |
| Studio | 17 | 318 |
| Auth | 0 | 5 |
| Storage | 1 | 57 |
| Postgres Meta | 8 | 87 |
| Edge Runtime | 4 | 56 |
| Realtime | 3 | 141 |
| PostgreSQL | 0 | 45 |

- Gereken iş: Vendor-fix/reachability değerlendirmesi; final digest/SBOM scan ve isimli Security kararı. Bazı image scan’leri OS-layer ile sınırlı, runtime binary dependency clearance’i değildir.
- Kapanış: Yükseltilen Auth schema/login/recovery/JWT; Storage schema/RLS/signedURL; Studio login/editor; Meta endpoint/type-generation; Edge dispatch/JWKS/secrets/signing gerçek stack’te geçmeli. Stateful PostgreSQL image değişimi ayrı migration/backup/restore drill ister.

### 34 Restore ve backup legal hold kabulü açık

Kaynak: [offsite işletimi](../../deploy/backup/README.md#L64), [restore kabulü](../production-readiness/backup-restore-v6.md).

Ayrı failure-domain host, ayrı recovery-key custody, gerçek offsite durability, schedule/freshness/failure alarmı, onaylı veri kaybı hedefi(RPO) ve hizmet geri dönüş hedefi(RTO) eksik. DB backup tek başına Storage object byte’larını, secrets/config, release artifact, DNS/TLS ve jobs’u kurtarmaz. Teknik restore süresi gerçek trafik cutover süresi değildir.

tenant_legal_holds offsite prune tarafından okunmaz; S3 Object Lock ile tenant hold aynı mekanizma değildir. Hold-aware workflow kabul edilene kadar aktif/incelemedeki tenant hold varken olağan pruning uygulanmamalı; operator change-freeze ve ayrı yetkili hold-copy süreci gerekir.

- Kapanış: Son signed adaya bağlı backup ayrı hostta restore edilmeli; login/tenant/policy/audit/object/agent işlevleri ve traffic cutover ölçülmeli. Gerçek provider hold/retention/deletion ve failure alert receipt’leri eklenmeli.

### 35 Final adayın bütün zorunlu testleri ve kanıtları tamam değil

Kaynak: [test kapsamı](production-review-2026-10-09.md), [merge kayıtları](branch-consolidation-2026-10-09.json).

| Kontrol | Kayıtlı sonuç |
| --- | --- |
| Seçili kaynak kontrolleri | 9649037b üzerinde 14/14 PASS, 0 FAIL, 0 SKIP |
| Son belge hygiene/secret/guard kontrolü | e5250905 üzerinde 5/5 PASS |
| İlk full unit | 633 dosya: 628 PASS / 5 FAIL; 11.221 test PASS / 12 FAIL / 11 SKIP |
| Başarısız suite hedefli tekrarları | 52/52 PASS; ikinci tamamen yeşil full unit koşulmadı |
| Canonical PostgreSQL | İzole DB’de 178 migration uygulandı; blocking SQL gate adımı PASS |
| Son workspace/built-hook | Build PASS; hook 4/4 PASS |
| npm production/build audit | 0 advisory; Docker/Python kapsamı değil |
| Release build | b8d7a231 developer build PASS; 11 manifest / 281 SBOM component / 10 consumer smoke |

- Gereken iş: Final source dondurulmalı; full unit ve coverage, gerekli platformlarda skip/TODO olmadan zorunlu gate’ler; final artifact seti için inventory/SBOM/provenance/signature; Python/native/browser/customer kabulü.
- Kapanış: Bütün kabul kayıtları aynı immutable candidate digest’ine bağlanmalı. Daha önceki source/unsigned developer build final publisher/production clearance’i yerine geçmez.

### 36 Kaynakta uygulanmış akışların saha kapanışları açık

Kaynak: [teknik iş paketleri](../../PRODUCTION_SALES_GAPS.json).

Bu inventory daha önceki c6561173 tabanı ve değişmiş worktree’ye ait 47 teknik / 13 kurumsal paket snapshot’ıdır; 44 teknik paket local implementation/field acceptance open, T19 / T37 / T38 kapsamları ayrıca open kaydedilmiştir. İlk gap metinleri yeni doğrulanmış exploit veya final candidate sonucu değildir.

| Akış | Gereken final saha kanıtı |
| --- | --- |
| Paket/reputation | Registry timeout, bozuk yanıt, stale intel/cache ve exception’da zorunlu kontrolün sessiz allow vermemesi |
| Davranış/novelty | Kurum baseline, benign iş yükü, değişim ve gerçek learning authority |
| MCP discovery/tool | Config drift, signed definition değişimi, gerçek transport ve yeniden onay |
| Delegasyon | User-agent-tool-resource, expiry, revoke ve gerçek session bağları |
| Fleet discovery/response | Sürekli keşif, stale cihaz, offline agent, kuyruk, durable sonuç/revoke receipt |
| Response | Doğru dosyada rollback/quarantine, başarısızlığın görünür olması |
| Politika | Editor yayınının gerçek agent kararını değiştirmesi; eski/bilinmeyen alan ve rollout |
| Secret store | Gerçek OS vault, kullanıcı sınırı, rotation ve uninstall |
| Identity/enrollment | MFA/recovery/invite/exchange/poll; role removal’ın mevcut credential’a etkisi |
| Tenant quota | İki tenant gerçek noisy-neighbour, kaynak sınırı ve izolasyon |
| Telemetry/SIEM | Kesinti/retry/duplicate, durable queue ve collector teslim receipt |
| Olay kanıtı | Correlation/export/hash integrity, yetki ve retention |
| Upgrade/migration | Eski kurulumu upgrade, yarım/failed update ve gerçek rollback |
| Operator UI | Enrollment/policy/incident/billing/offboarding görevi gerçek kullanıcıda |
| Etkinlik kıyası | Bağımsız holdout, ölçüm bütçesi, veri kaynağı ve gerçek karşılaştırma |

- Kapanış: Satılan her akış için malicious/benign/outage sonucu gerçek tüketicide gözlenmeli; görünmeyen/unsupported kapsam destek metnine yazılmalı.

### 37 Kapasite HA ve SLA yük kabulü eksik

Kaynak: [yük kabul profili](../production-readiness/load-capacity-v6.md).

Kısa yerel testler final kapasite/HA ölçümü değildir. Exact digest/hardware/OS/runtime, kalibre ayrı load-generator, artan RPS seviyelerinde tekrarlar ve gerçek policy/ingest/reputation/dashboard/SIEM boyutları gerekir. p50/p95/p99/errors/loss, CPU/RAM/IOPS/DB connection/queue/network zaman serisi toplanmalı.

- Kapanış: Her satılan topolojide en az 8 saat temsilî authenticated soak; iki tenant noisy-neighbour; node/DB/network/failure-domain kesintisi ve toparlanma; managed HA ve gerçek aylık SLI. Sekiz saat soak tek başına yüzde 99,9 aylık SLA kanıtı değildir.

### 38 Güncel readiness kayıtları final adayla uzlaştırılmalı

Kaynak: [eski paket snapshot’ı](../../PRODUCTION_SALES_GAPS.json), [tarihsel release kayıtları](../../RELEASE_READINESS_REPORT.md), [9 Ekim incelemesi](production-review-2026-10-09.md).

Eski checklist’lerde Koffi 3, PostgreSQL hiç çalışmadı, SAML UI yok gibi son merge/incelemeyle kapanmış veya kapsamı değişmiş tarihsel iddialar vardır. Son 178 migration/test ve source kayıtları korunmalı; eski sonuç final source’a taşınmış sayılmamalı. Inventory/feature/support/claim/evidence dosyaları tek final candidate’a bağlanmış değildir.

- Kapanış: Tarihsel kayıtlar tarihsel tutulmalı; current feature/support/gap/evidence index aynı aday için üretilmeli. Kod var, yerel test geçti ve production kabulü tamam statüleri ayrı kalmalı; 5 direct-GA connector ve Codex preview kapsamı doğru gösterilmeli.

### 39 Secret history owner kararları açık

Kaynak: [tarihsel triage](../production-readiness/secret-history-triage-2026-10-05.md).

Pinned resmi scanner’ın tarihsel koşusu 132 detection; engineering 130 false-positive/invalid-fixture ve 2 owner-confirm bildirdi. Doğrulanmış canlı credential iddiası yok. İki kayıt aynı örnek dataset fingerprint key’in Chrome/Firefox örneklerine ait; gerçek dataset için kullanılmadığını sahibi doğrulamalı. Emin olunamazsa compromised kabulü, regenerate/refingerprint/deploy ve Security incelemesi gerekir.

- Kapanış: İsimli owner/Security disposition; gereken provider rotation ve kullanım logu kararı; final signed adayın nonshallow full-clone history/current taraması, redacted evidence/hash. Current scan PASS tarihsel owner kararlarını kapatmaz; yayımlanmış history rastgele yeniden yazılmamalı.

### 40 Güvenlik güncelleme işletimi tamam değil

Kaynak: [Dependabot geçici durdurma](../../.github/dependabot.yml), [API setting kaydı](branch-consolidation-2026-10-09.json).

Version PR limitleri botun tekrar dal açmasını durdurmak ve koordineli qualification için geçici 0 yapıldı. Security PR’ları bu limite tabi değildir. 9 Ekim 15:15:40 UTC repository automated security fixes enabled=false bulundu; inceleme bu hesap ayarını değiştirmedi. 10 Ekim yeni API kontrolü yapıldığı iddiası yok.

- Kapanış: Otomatik security fix repo ayarı açılmalı ve işlediği doğrulanmalı. Qualification sonrası npm 10, Actions/diğer Python/Docker 5 limitleri geri açılmalı; NER resolver/hash-lock/wheel/inference kabulüne kadar 0 kalmalı. Müşteri update/disclosure/support ve emergency rollback publisher trust zinciriyle kabul edilmeli.


## Kurumsal kabul kapıları

Kaynak: [commercial receipts](../production-readiness/commercial-gate-receipts.json), [GO registry](../production-readiness/commercial-go-evidence-registry.json), [owner action listesi](../production-readiness/commercial-gates-prefill-and-owner-actions-2026-10-05.md).

13 kaydın tamamı open; releaseCandidate null. Her kapanışta değişmez aday digest’i, kanıt dosyası ve hash’i, isimli sorumlu, gözden geçiren veya onaylayan ve tarih gerekir. Sadece dosya oluşturmak veya yapısal validator geçirmek kabul değildir. Production-ga ve assisted-sale profilleri 12 kapıyı kullanır; INV-001 yatırımcı profilinde ek kapıdır. Aşağıdaki roller gereken kabul rolleridir; atanmış veya onay vermiş kişiler değildir.

### COM-001 Ticari ürün ve sürüm manifesti

- Eksik: Onaylı fiyat, vergi ve para birimi, SKU ve sağlayıcı fiyat kimliği, miktar sınırı, dönem, yenileme ve iptal koşulları; deployment, bölge, retention, destek, SLA ve lisans hakkı. Şablonlar taslaktır.
- Kapanış: Commercial/Product ve Finance isimli karar vermeli. Aynı aday için imzalı katalog, sipariş ve manifest; teklif → entitlement → koltuk değişimi → iptal/revoke → export → offboarding provası; yayıncı imzası ve bağımsız doğrulama makbuzu gerekir.

### COM-002 Lisans notices ve mülkiyet zinciri

- Eksik: Legal kararı, çalışan/taşeron/contributor IP hak zinciri, vendor provenance ve gerçekten dağıtılan npm/PyPI/native/container/upstream notice ve kaynak yükümlülükleri. Certifi MPL-2.0 ve saf psycopg LGPLv3 için iki değerlendirme açık; sorumlu, onaylayan ve süre bilinmiyor. Wheel/native notice arşivi dağıtım hakkı onayı değildir.
- Kapanış: Aday SBOM ve hash’i, notice ve kaynak yükümlülükleri, isimli Legal kararı ve hak devirleri gerekir. İstisna gerekiyorsa kapsamı, sahibi ve süresi onaylanmalı. Eski UNKNOWN licence veya kaldırılan binary-wheel kayıtları güncel listeye taşınmamalı.

### COM-003 Gerçek veri akışı ve gizlilik

- Eksik: 25 kaynak envanteri akışı için gerçek domain, sağlayıcı ve hukuki kuruluş; işlem/backup bölgesi, erişim sahibi, amaç, hukuki temel, sayısal saklama süresi, hold/deletion ve sözleşme onayı. Kaynak açıklaması deployment değerlerini kanıtlamaz.
- Kapanış: Son build'in egress request/response ölçümü ve opt-out testi; etkin akış listesi; DPA/TOM/SCC, subprocessor ve notice sürüm/hash'i; gerçek tenant export/offboarding ile sağlayıcı ve backup silme/expiry makbuzları gerekir. Supabase ile ayrı Clerk/Firestore/Polar yolunun kabulü ayrıdır.

### COM-004 Billing ve entitlement

- Eksik: Provider-of-record ve SKU onayı; ödeme/fatura/settlement-to-entitlement; mutabakat, dunning, refund, cancel, expiry ve revoke; sağlayıcı retention/deletion kanıtı.
- Kapanış: Finance yetkisi, gerçek sağlayıcı hesabı ve güvenli webhook ayarları gerekir. Satılan yolda duplicate, gecikmiş ve sırası değişmiş webhook; koltuk sınırı/değişimi; expiry/refund/revoke sınanmalı. Muhasebe mutabakatı ve sağlayıcı kayıtlarının export/deletion süreci onaylanmalı.

### COM-005 Destek ve iletişim işletimi

- Eksik: İşletilen ticket sistemi, security mailbox ve status feed; çalışma saati/dil/kapsam, primary ve backup rota, zaman damgalı drill. Runbook ve şablon işletim kanıtı değildir.
- Kapanış: Support/Operations sahipleri; önem derecesine göre acknowledgement, update ve restoration hedefleri; Sev1/Sev3 ticket kimlikleri ile submitted/ack/escalated/updated/closed zamanları gerekir. Gerçek production rotaları ve render edilmiş link hedefleri, diagnostic rızası, dar erişim yetkisi ve silme süreci kabul edilmeli.

### COM-010 Beş direct GA connector kabulü

- Eksik: Claude Code, Cursor, VS Code, OpenClaw ve OpenCode için desteklenen host/OS/sürüm; yayıncı imzalı artifact, kimlik doğrulamalı registry kurulumu, gerçek host E2E, rollback/disable ve destek sahibi. Codex altıncı shipped connector olarak preview/engineering kapsamındadır; direct-GA kapsamı dışındadır.
- Kapanış: Her satılan satırda final artifact ve host hash'i ile saldırgan/meşru işlem, kesinti, restart, upgrade ve uninstall sınanmalı. Bağımsız yan etki kanıtı ve destek sınırları eklenmeli. Developer/mock veya package-consumer testleri bu makbuz yerine geçmez.

### COM-011 Bölge ve veri yerleşimi

- Eksik: Production EU/US/APAC projeleri; tenant placement, cross-region negatif test, Edge region pinning makbuzu; bölgesel sağlayıcı DPA/SCC/TOM kabulü, backup/deletion. Region manifest'i deklarasyondur.
- Kapanış: Gerçek sağlayıcının işlem/backup/onward-transfer coğrafyası ve bölge sahibi; sipariş placement ve yanlış bölge erişim/yönlendirme testleri; bölgesel backup/silme ve Privacy/Legal kararı gerekir.

### COM-012 Private registry ve offline teslim

- Eksik: İşletilen ve kimlik doğrulamalı private registry; fatura → entitlement → download → imzalı kurulum; gerçek revoke/offboarding ve disconnected-host kabulü. İmzasız air-gap digest manifest'i yayıncı kimliği sağlamaz.
- Kapanış: Registry/provider ve Finance kararı; gerçek erişim politikası ve credential süreci; bağımsız trust/public-key teslimi; müşteri download/install/revoke audit'i; production publisher imzalı air-gap manifest ve internetsiz host provası gerekir.

### COM-013 Aylık yüzde 99,9 availability ve SLA

- Eksik: Yayındaki servis için SLI sorgusu/payda/probe konumu/gözlem aralığı, tam aylık gözlemler, eksik aralık/maintenance/exclusion kuralları, service credit ve incident drill onayı. Hedef ölçülmüş sonuç değildir.
- Kapanış: Gerçek endpoint ve bölge monitoring export'u, tam ay paydası, giriş/rapor hash'leri, isimli Operations/SRE; Legal/Finance credit ve Support SLA kabulü gerekir. Yerel hesaplama testi veya sekiz saatlik soak aylık SLA'yı kapatmaz.

### SEC-EXT-001 Bağımsız güvenlik incelemesi

- Eksik: Bağımsız assessor engagement/scope, rapor, remediation ve retest letter.
- Kapanış: Aynı source/artifact digest'i için tenant/RLS/identity/recovery, connector, cloud/on-prem, update provenance ve operator trust incelenmeli. Secret-history owner maddeleri ve yüksek etkili bulgular fix/retest ile kapanmalı; isimli Security kabulü alınmalı. İç review, dependency audit veya static check bağımsız assessment değildir.

### POV-001 Bağımsız evaluator ve müşteri kabulü

- Eksik: İsimli evaluator, imzalı Evaluation Charter, bağımsız run, müdahale/sapma günlüğü, yazılı kabul veya rezervasyon.
- Kapanış: Gerçek müşteri kabul yetkilisi, kesin host/provider/kapsam, saldırgan/meşru işlem ve kesinti/rollback gözlemleri, değişmez evidence index gerekir. Sentetik loopback demo müşteri PoV'si değildir.

### INV-001 Yatırımcı metrikleri

- Eksik: Onaylı formül, payda, kaynak, dönem, örneklem, ortam, aday, sorumlu, gözden geçiren ve sınırlamalar; gerçek traction/finans kaynak verisi repository'de sağlanmış değil.
- Kapanış: Product/Finance kaynak ve reviewer sağlamalı; Legal sınırlama metnini onaylamalı. Yalnız dictionary ve gerçek kaynak destekli metrikler yayımlanmalı. Bu yatırımcı profili kapısıdır; production'ın 12 kapısına dahil değildir.

### CLM-001 Satış pazarlama ve ürün iddiaları

- Eksik: Final artifact ve gerçek landing deployment byte'larına bağlı claim scan JSON'u ve registry hash'i; Sales Approved kararı ve Legal metin incelemesi. Açık kapıya bağlı iddia engelli kalır.
- Kapanış: README/plugin/landing/sales/customer/investor/procurement iddiaları aday/hash/expiry ve isimli kabule bağlanmalı. Unit PASS müşteri kabulü, SLA hedefi ölçülmüş availability diye sunulmamalı; claim gate'i kaldırmak düzeltme değildir.

## Kapanış sırası ve sorumluluk

Önce 1–14 P1 koruma/yetki/yayın bulguları; ardından 15–20 ve quota/audit/lock sorunları kapanmalı. Son kaynak ve artifact seti dondurulup zorunlu testler, native/browser/model/deployment kabulü, bağımsız Security, restore/load ve seçilmiş release profilinin kurumsal kapıları aynı digest üzerinde tamamlanmalı. Her kapanış issue, kod commit'i, test kanıtı, candidate digest'i, sorumlu, reviewer ve tarih içermeli; yalnız belge değişimi OPEN durumunu kapatmaz.

Ön-müşteri first-customer-ready kabulü AIDR'nin kendi host, altyapı ve hesabıyla bağımsız reviewer kullanabilir; isimli müşterinin bütün materyali bu aşamada zorunlu değildir. Gerçek müşteri pilot/GA için müşteri host/IdP/MDM/bölge/retention/hukuki kuruluş/SLA, charter, PoV ve ilgili 12 production kapısı ayrıca gerekir. İlk sürüm kapsamı dışında kalan özellikler destek matrisinden çıkarılmalı; kapatma davranışı ve sınırlama açıkça yayımlanmalıdır.

Tam müşteri dağıtımı, gerçek paid-model/browser/OS matrisi, bağımsız pentest ve final signed production acceptance tamamlanmış değildir. Vendor/generated data satır satır ayrı audit edilmedi. Bu kayıt mevcut incelemeyi ve açık kanıtları tanımlar; yeni kabul olmadan NO-GO kararı sürer.

# AIDR kod incelemesi ve production hazırlığı

9 Ekim 2026. Karar: **NO-GO**. AIDR; AI agent araç çağrılarını yerel politikalarla denetleyen, tarayıcıdaki AI gönderimlerinden hassas veriyi maskeleyen ve merkezi yönetim sağlayan bir güvenlik ürünüdür. Birleşmiş kodda doğrulanmış koruma atlamaları, tenant yetki sorunları ve yayın kapısı eksikleri bulunuyor. Dalların birleştirilmesi ürünün production onayı anlamına gelmez.

İnceleme, sürekli çalışan çok kullanıcılı kurum kurulumunu ve merkezi politikayla yönetilen birden fazla agent oturumunu varsayar. Core, CLI, altı connector, MCP Gateway, Browser Guard, Privacy, dashboard, Supabase Edge/SQL, CI, yayın ve operasyon akışları incelendi. Bulgular gerçek handler/hook denemeleri, tarama motoru örnekleri veya izole PostgreSQL üzerinde doğrulandı. Gerçek müşteri host kabulü ayrıca gerekir.

## Dal birleştirme kararları

Başlangıç envanteri 112 yerel ve remote ref ile 53 çalışma klasörü içeriyordu. Yerel master 52a5daff iken güncel origin/master 03ffe20a idi. İncelenen 28 ref güncel ana dalın dışında kalıyordu; bunlardan go-preparation, remaining-fixes dalının atası olduğu için ayrıca merge commit gerektirmedi. Yeni entegrasyon codex/all-branches-review-2026-10-09 üzerinde hazırlandı.

| Dal grubu | Birleştirme kararı |
| --- | --- |
| DNS hostname ve kısa flag secret redaction | Benzersiz kod ve testler normal merge ile alındı. Redaction kenar durumları aşağıda açık bulgu olarak kaydedildi. |
| Koffi 3 | Native paket geçişi alındı. Staged payload dışındaki komşu paket ve Electron fallback yolları ek regresyon testleriyle kapatıldı. |
| Koffi 2.16 yükseltmesi | Koffi 3 tarafından karşılanan eski yükseltme geçmişe alındı; sürüm geri düşürülmedi. |
| React ve React DOM | İkisi ve ilgili tip paketleri birlikte 19.3'e hizalandı. Kilit dosyası yeniden üretildi. |
| Node tip güncellemesi | Node 22 kullanan paketler Node 20 tiplerine geri düşürülmedi. |
| Zod migration adlı dal | Dal yalnız schema parity snapshot testi içeriyordu; testler alındı, Zod 3 korundu. Commit edilmemiş Zod 4 çalışması çalışma klasöründe kaldı. |
| Lint baseline | Gereksiz tanımların silinmesi ve lint kurallarının sıkılaştırılması alındı. |
| Diğer npm ve GitHub Actions güncellemeleri | Manifest değişiklikleri alındı; çakışan lock içeriği nihai manifestlerden yeniden üretildi. |
| Python güncellemeleri | Geçmiş birleştirildi, uygulanması uyumsuz yükseltmeler geri alınarak önceki platform lock dosyaları korundu. Linux Python 3.11, önerilen NumPy 2.5.3'ü çalıştıramıyor; Transformers/Hub yükseltmeleri yeni tokenizer/httpx2 bağımlılıkları istiyor. mpmath 1.4.1 de mevcut SymPy 1.14.0 ile uyumsuzdur (mpmath<1.4 gerekiyor). Bu stack ayrıca yeniden doğrulanmalı. |
| Eski portable preparation | remaining-fixes tipinin ağacı f3f7f7e9 squash commit'i ile birebir aynıydı. Güncel içerik korunup eski ancestry birleştirildi. |
| Eski sale-ready plan ve discovery çalışmaları | Plan dosyaları 19d9aef5 ile aynıydı; discovery değişiklikleri sonraki commit'lerde zaten vardı. Güncel auth sırası ve belgeler korundu. |
| Eski detection robustness | Sonraki uygulama korundu. Eksik kalan Windows cache-key ACL koruması ayrıca taşındı; gerçek NTFS testi eklendi. Güncel commercial enforcement sözleşmesi geri alınmadı. |

Ana dal güncellenince Dependabot toplam 14 ek ref açtı. Beş NER ve beş AIG bridge önerisinin geçmişi birleştirildi; bazı yükseltmeler uyumsuz, diğerleri shipped hash lock ve runtime/SBOM kabulünü güncellemiyordu. AIG Pydantic 2.13.5 mevcut pydantic-core 2.27.2 yerine 2.46.5 ister; pytest 9.1.1 mevcut pytest-asyncio 1.1.0 sınırlamasını (pytest<9) aşar. Yalnız requirements satırını değiştirmek Docker/CI locklarını yükseltmez. Mevcut pinler tutuldu; koordineli doğrulama açık iş olarak kaydedildi.

Vite 6.4.4, CLI Node 20 tip patch’i ve esbuild 0.28.2 alındı. Esbuild root override ile birlikte hizalandı ve lock yeniden üretildi; diğer Node 22 sözleşmeleri ve Sentry 10.76.2 korundu. CodeQL 4.38.2 tag nesnesi resmi GitHub commitine açılarak doğrulandı; init/autobuild/analyze/upload-sarif birlikte aynı immutable SHA ile güncellendi.

Version PR’ları merge sonrası sürekli yeni dal açtığı için Dependabot sürüm önerileri koordineli dependency kabulü tamamlanana kadar geçici durduruldu. Güvenlik güncellemeleri bu limite tabi değildir. Kabulden sonra npm limiti 10, Actions/diğer Python/Docker limitleri 5 olarak geri açılmalı; NER kendi resolver/hash-lock/wheel/inference kabulü tamamlanana kadar 0 kalmalı. [GitHub seçenek referansı](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#open-pull-requests-limit).

Dal envanterindeki SHA değerleri silinen ref'lerin geri bulunmasını sağlar. Birleşmiş geçmişte tüm commit'ler erişilebilir kalır. Çalışma klasörleri silinmez; commit edilmemiş değişiklikler korunarak dallar detached HEAD durumuna alınır. Son sayılar ve doğrulamalar raporun sonunda yer alır.

## Production öncesi düzeltilmesi gerekenler

P1: Güvenlik, hassas veri, yetki veya yayın kontrolünde yüksek etkili hata. P2: Daha dar koşullarda hata veya sürekli kullanımda operasyon sorunu. Bulgular düzeltme uygulanmış iddiası taşımaz; entegrasyon için yapılan Koffi ve ACL düzeltmeleri ayrı kaydedilmiştir.

### 1 P1 OIDC secret seçimi tenant sınırını aşabiliyor

Kaynak: [index.ts satır 101](../../supabase/functions/oidc-sso/index.ts#L101), [handler.ts satır 602](../../supabase/functions/oidc-sso/handler.ts#L602), [token exchange satır 239](../../supabase/functions/oidc-sso/handler.ts#L239).

- İşlev: Kurum sahibi OIDC sağlayıcısı ve client secret referansı tanımlıyor.
- Sorun ve kanıt: Referans global ortam değişkeninden tenant bağı olmadan çözülüyor. A tenant sahibi başka referansı kendi HTTPS token endpoint'iyle tanımlayınca callback başarısız olsa bile seçilen secret token isteğinde gönderildi; gerçek handler ve sahte IdP fixture'ıyla doğrulandı.
- En küçük düzeltme: Secret çözümlemesini tenant ve sunucu tarafından yönetilen issuer/client kaydına bağlayın; kullanıcıdan gelen global referansı yetki kabul etmeyin.
- Ertelenirse: Bir tenant başka kurumun yapılandırılmış OIDC kimlik bilgisini öğrenebilir.

### 2 P1 Workspace saklama güncellemesi owner ve alt süre sınırlarını aşıyor

Kaynak: [workspace SQL satır 83](../../supabase/migrations/20260925000040_tenant_workspace_settings.sql#L83), [tenant-settings satır 259](../../supabase/functions/tenant-settings/index.ts#L259).

- İşlev: Workspace ayarı verinin kaç gün saklanacağını güncelliyor.
- Sorun ve kanıt: Tüm 178 migration izole PostgreSQL'e uygulandı. Admin workspace RPC'siyle süreyi 1 güne düşürebildi; 30 günlük alt sınırı olan identity/config sınıfları ve 7 günlük telemetry sınıfları 1 oldu. Owner'ın yeni bounded retention RPC'si aynı isteği reddediyor.
- En küçük düzeltme: Retention değişimini yalnız owner ve sınıf sınırlarını uygulayan ortak RPC'ye yönlendirin. Admin'in workspace adı değiştirme yetkisini koruyun.
- Ertelenirse: Yetkisiz süre azaltımı ve reaper/offboarding ile beklenenden erken veri kaybı oluşur.

### 3 P1 VS Code native araç adları politikaya ulaşmıyor

Kaynak: [aidr-hook.ts satır 1081](../../packages/extension/src/aidr-hook.ts#L1081). Host adları: [VS Code araç referansı](https://code.visualstudio.com/docs/agents/reference/tools-reference).

- İşlev: Host araçları canonical shell/file işlemlerine dönüştürülüyor.
- Sorun ve kanıt: Gerçek built hook sürecinde yasak komut Bash ile deny, runInTerminal ile boş izin yanıtı verdi. Yasak dosya yolu Write ile deny, createFile ile boş yanıt verdi. Native adlar/alanlar alias tablosunda yok.
- En küçük düzeltme: runInTerminal/createFile adlarını ve input alanlarını canonical işlemlere eşleyip gerçek payload testleri ekleyin.
- Ertelenirse: Desteklenen editörde shell ve filesystem engellemesi aşılır.

### 4 P1 Prompt hata ve deadline yolu block kurallarını bırakıyor

Kaynak: [Claude giriş satır 100](../../packages/claude-code/src/user-prompt-submit.ts#L100), [fallback satır 222](../../packages/claude-code/src/user-prompt-submit.ts#L222), [ortak prompt-inspection satır 134](../../packages/core/src/prompt-inspection.ts#L134).

- İşlev: Prompt gönderilmeden PII, secret, tenant DLP ve safety kontrolü yapılıyor.
- Sorun ve kanıt: secrets=warn ve pii=block ile normal e-posta engellenirken 2 MiB üstü aynı içerik yalnız uyarıyla geçti. Kurulu tenant detector hatası da büyük girdi yolunda değerlendirilmedi. Ortak deadline fallback PII/jailbreak/content-safety ve yalnız promptSafety ile gelen tenant block tabanını hesaba katmıyor. Yüklenmiş etkin tenant DLP deadline yolunda engelleniyor; büyük girdi veya tenant DLP yüklenmeden oluşan hata yolunda tenant kuralı öğrenilmeden karar veriliyor.
- En küçük düzeltme: Hata kararını tüm etkin block kurallarından üretin; tenant politikasının sonucu bilinmiyorsa gönderimi durdurun.
- Ertelenirse: Boyut veya timeout durumunda yapılandırılmış hassas veri engeli çalışmaz.

### 5 P1 Relative dosya policy yanlış çalışma dizinini kullanıyor

Kaynak: [policy.ts satır 54](../../packages/core/src/policy.ts#L54), [evaluator.ts satır 2149](../../packages/core/src/evaluator.ts#L2149).

- İşlev: Dosya hedefinin izinli kökte olup olmadığı hesaplanıyor.
- Sorun ve kanıt: Hook cwd izinli klasörde, context.workingDirectory dışarıdayken Write relative.txt allow verdi. Policy yolu process.cwd üzerinden çözüyor; tool'un gerçek hedefi izinli kökün dışında kalıyor.
- En küçük düzeltme: Güvenilir workingDirectory bağlamını ortak path çözümlemesine ve diff-aware eski dosya okumasına aktarın.
- Ertelenirse: Relative hedefler filesystem kapsamını aşabilir veya yanlış engellenebilir.

### 6 P1 XML namespace prefix değişimi DOCX ve ODF kontrolünü atlıyor

Kaynak: [ooxml.ts satır 226](../../packages/browser-guard/src/engine/office/ooxml.ts#L226), [xml.ts satır 452](../../packages/browser-guard/src/engine/office/xml.ts#L452), [odf.ts satır 284](../../packages/browser-guard/src/engine/office/odf.ts#L284).

- İşlev: Office/ODF XML metni ve macro işaretleri inceleniyor.
- Sorun ve kanıt: Aynı namespace URI ile w:p/w:t e-postayı maskeledi, geçerli x:p/x:t allow verdi. ODF script:event-listener engellenirken aynı URI'li s:event-listener geçti.
- En küçük düzeltme: Eleman ve nitelikleri prefix metni yerine namespace URI ve yerel adla eşleştirin.
- Ertelenirse: Geçerli dosyalar ham hassas veri veya macro kontrolü atlamasıyla geçer.

### 7 P1 Metin dosyası adı gerçek PDF türünü gizliyor

Kaynak: [files.ts satır 1130](../../packages/browser-guard/src/engine/files.ts#L1130).

- İşlev: Dosya uzantısı ve içerik türü tarayıcıyı seçiyor.
- Sorun ve kanıt: Hex e-posta içeren PDF report.pdf olarak engellendi. Aynı byte dizisi report.txt/text/plain olarak allow döndü; bilinen uzantı içerik sniff kontrolünü erken kesiyor.
- En küçük düzeltme: Güçlü içerik imzalarını uzantı kararından önce uygulayın; document-block politikasını da gerçek tür üzerinden değerlendirin.
- Ertelenirse: Yalnız yeniden adlandırılan dosya hassas veri taramasını aşar.

### 8 P1 XLSX maskeleme formülde ham veriyi bırakıyor

Kaynak: [ooxml.ts satır 518](../../packages/browser-guard/src/engine/office/ooxml.ts#L518).

- İşlev: Hücre değerleri maskelenerek yeni ZIP üretiliyor.
- Sorun ve kanıt: E-posta içeren f formülü ile aynı v cache değeri mask kararı verdi, fakat sonuç ZIP'in f alanında ham e-posta kaldı. Cache değeri yokken aynı formül allow verdi.
- En küçük düzeltme: Formülü tarayın; hassas formülü engelleyin veya formülü kaldırıp maskelenmiş sabit hücre üretin.
- Ertelenirse: Maskelendiği bildirilen dosya hâlâ ham veriyi içerir ve yeniden hesaplamada gösterir.

### 9 P1 PDF ek dosyaları eksik tarama uyarısı olmadan geçiyor

Kaynak: [extract.ts satır 246](../../packages/browser-guard/src/engine/pdf/extract.ts#L246).

- İşlev: PDF görünür metni, form ve bilgi alanları taranıyor.
- Sorun ve kanıt: Görünür sayfası temiz PDF'ye Names/EmbeddedFiles üzerinden e-postalı secret.txt eklendi. Gerçek PDF taraması allow verdi; eksik kapsama işareti üretmedi.
- En küçük düzeltme: EmbeddedFiles/FileAttachment/XMP yollarının varlığını saptayın; desteklenmeyen ek içeriği gönderime kapatın.
- Ertelenirse: Tam PDF yüklemesiyle ek dosyadaki hassas veri sağlayıcıya gider.

### 10 P1 Codex structuredContent içindeki binary etiketi metin taramasını atlıyor

Kaynak: [output-protection.ts satır 128](../../packages/codex/src/output-protection.ts#L128).

- İşlev: MCP çıktısı modele ulaşmadan prompt injection için kontrol ediliyor.
- Sorun ve kanıt: structuredContent nesnesi type=image/audio/blob deyince data/blob atlanıyor. Gerçek hook'ta data içindeki zararlı yönerge geçti; aynı içerik type=text ile OUT-INJ-001 engeli aldı.
- En küçük düzeltme: Arbitrary structuredContent'i bütünüyle tarayın; binary istisnasını yalnız doğrulanmış MCP content bloklarına uygulayın.
- Ertelenirse: Untrusted çıktı kendi etiketini seçerek denetimden çıkar.

### 11 P1 OpenCode JSONC config MCP deny kuralını atlıyor

Kaynak: [tool-handler.ts satır 48](../../packages/opencode/src/tool-handler.ts#L48), [OpenCode config referansı](https://docs.opencode.ai/docs/config/).

- İşlev: Config'teki sunucu isimleri canonical MCP araç adını kuruyor.
- Sorun ve kanıt: Keşif yalnız opencode.json okuyor. Desteklenen opencode.jsonc'deki sunucu adı tanınmayınca default_action=block ve unknown_server_action=block politikasında host adı null, doğru canonical ad deny/POL-MCP-005 üretti.
- En küçük düzeltme: Üç config konumunda json ve jsonc dosyalarını aynı parser ile okuyun.
- Ertelenirse: Geçerli kullanıcı config'i varsayılan MCP engellemesini devre dışı bırakır.

### 12 P1 OpenCode karışık raw MCP sonucu zararlı content alanını bırakıyor

Kaynak: [output-handler.ts satır 168](../../packages/opencode/src/output-handler.ts#L168).

- İşlev: Desteklenen raw MCP hook yolu çıktıdaki metni inceliyor.
- Sorun ve kanıt: content içinde zararlı metin, ek output alanında temiz metin olduğunda gerçek handler inspected_clean/rawMcpResult=false kaydetti; content değişmeden kaldı. Bulgu raw MCP hook yoluna bağlıdır; gerçek OpenCode binary/model E2E bu alt incelemede çalışmadı.
- En küçük düzeltme: content bulunan nesneyi raw MCP olarak ele alın veya karışık envelope'u karantinaya alın.
- Ertelenirse: Desteklenen bu yolda saldırgan içerik modele denetlenmeden ulaşabilir.

### 13 P1 Privacy audit anahtar yenilemesi doğrulanamayan zincir üretiyor

Kaynak: [persistent-audit.ts satır 11](../../packages/privacy/src/platform/persistent-audit.ts#L11), [runtime.ts satır 37](../../packages/privacy/src/platform/runtime.ts#L37).

- İşlev: Kararlar imzalı ve hash bağlı audit akışına yazılıyor.
- Sorun ve kanıt: Aynı DB önce a1 sonra a2 anahtarıyla açıldı, iki karar da allow oldu. Akış iki anahtarı içeriyor; mevcut verifyAudit eski ve yeni anahtarın ikisiyle de false verdi.
- En küçük düzeltme: Başlangıçta mevcut akışın anahtar kimliği ve imzasını doğrulayın; uyuşmazlıkta append'i reddedin. Rotation için checkpoint ve yeni akış prosedürü sağlayın.
- Ertelenirse: Rutin anahtar yenilemesi ürünün kendi audit geçmişini doğrulanamaz yapar.

### 14 P1 Production publish NO-GO kaydını zorunlu denetlemiyor

Kaynak: [release-promote.yml satır 197](../../.github/workflows/release-promote.yml#L197).

- İşlev: İmzalı RC doğrulandıktan sonra paketler, dashboard ve latest yayımlanıyor.
- Sorun ve kanıt: Yayın/RC workflow'ları candidate-bound production GO kontrolünü veya claim-check --mode=gate çağrısını zorunlu çalıştırmıyor. Mevcut ticari tutarlılık kontrolleri tüm kapılar open/NO-GO iken geçebiliyor. Workflow production environment seçiyor; ortamın zorunlu reviewer koruması API ile doğrulanamadı (404), bu nedenle manuel onay bariyeri varsayılmıyor.
- En küçük düzeltme: Güvenilir doğrulayıcıyla aynı adayın GO kararını publish/deploy öncesine ekleyin ve NO-GO adayın yayımlanamadığını test edin.
- Ertelenirse: İmzalı fakat güvenlik/ticari kabulü eksik aday production'a çıkabilir.

## Ayrıca düzeltilmesi gerekenler

### 15 P2 OIDC ayarı yetki ve audit ile tek transaction değil

Kaynak: [handler.ts satır 668](../../supabase/functions/oidc-sso/handler.ts#L668), [store.ts satır 115](../../supabase/functions/oidc-sso/store.ts#L115).

- İşlev: Sağlayıcı ayarı kaydediliyor ve admin audit yazılıyor.
- Sorun ve kanıt: Audit insert hatasında handler 503 döndü fakat enabled sağlayıcı DB'de kaldı. Discovery beklerken owner üyeliği kaldırılınca da kayıt başarılı oldu; service-role upsert actor üyeliğini transaction içinde kontrol etmiyor.
- En küçük düzeltme: Provider/domain write, güncel owner kontrolü ve audit'i tek RPC transaction'ında yapın.
- Ertelenirse: Yetkisi kaldırılan aktör değişiklik yapabilir; başarısız görünen güvenlik ayarı gerçekte uygulanmış ve auditi eksik olabilir.

### 16 P2 Kesilen diff aware girdi temiz allow sayılıyor

Kaynak: [edit-views.ts satır 141](../../packages/core/src/agent-safety/edit-views.ts#L141), [evaluator.ts satır 2247](../../packages/core/src/evaluator.ts#L2247).

- İşlev: Test/guardrail değişiklikleri satır ve diff görünümünde inceleniyor.
- Sorun ve kanıt: Normal it.skip yazımı ask verdi. Önüne 4097 boşluk eklenince uzun satır kesildi, truncated=false ve allow oldu. 20001 newline ile 20.037 karakterlik örnekte truncated=true olsa da allow döndü.
- En küçük düzeltme: Uzun satırları kayıpsız tarayın; partial inspection sonucunu belirsiz/blocking karara katın.
- Ertelenirse: Düşük boyutlu değişiklikler agent-safety kuralını aşabilir.

### 17 P2 Privacy audit export 100 bin kararda duruyor

Kaynak: [persistent-audit.ts satır 16](../../packages/privacy/src/platform/persistent-audit.ts#L16).

- İşlev: Olay incelemesi için karar geçmişi dışa aktarılıyor.
- Sorun ve kanıt: records sıra numarası 100001 olunca AUDIT_EXPORT_LIMIT veriyor; sayfalı export yok. Saniyede bir karar için yaklaşık 27,8 saat, input/output ayrı karar olduğunda yaklaşık 13,9 saat yeterli.
- En küçük düzeltme: Sıra numarasıyla sayfalı export ve önceki hash'ten devam eden doğrulama ekleyin.
- Ertelenirse: Sürekli çalışan kurulumun olay geçmişi alınamaz.

### 18 P2 Release kanıtı varsayılanları farklı adayları gösteriyor

Kaynak: [receipt verifier satır 45](../../scripts/verify-commercial-gate-receipts.mjs#L45), [evidence generator satır 36](../../scripts/generate-v8-evidence-index.mjs#L36).

- İşlev: Receipt ve index aynı release adayı için doğrulanmalı.
- Sorun ve kanıt: Import edilmiş varsayılanlar farklı: biri 20260913, diğeri 20260916-r9 inventory dosyası. Generator'ın adayı için hazırlanmış receipt varsayılan verifier'da reddedilir; override farklı adayı seçebilir.
- En küçük düzeltme: Tek ortak candidate kaynağını veya zorunlu aynı candidate parametresini kullanın.
- Ertelenirse: Release kararında yanlış adayın kanıtı değerlendirilir veya doğru kanıt reddedilir.

### 19 P2 Restore drill kanıtları retention ile silinmiyor

Kaynak: [deployment-restore-drill.mjs satır 319](../../scripts/deployment-restore-drill.mjs#L319), [temizlik satır 334](../../scripts/deployment-restore-drill.mjs#L334).

- İşlev: Tamamlanan recovery denemeleri ve kanıt dosyaları temizleniyor.
- Sorun ve kanıt: İşlem recovery-project marker'ını kaldırıyor; sonraki retention temizliği marker olmayan klasörü atlıyor. 2020 tarihli, 1 günlük retention fixture'da expired=0 ve kanıt dosyası kaldı.
- En küçük düzeltme: Aktif recovery marker'ından ayrı kalıcı sahiplik marker'ı kullanın; operator klasörü korumasını sürdürün.
- Ertelenirse: Hassas recovery kanıtı ve disk kullanımı süresiz birikir.

### 20 P2 Yeni kısa flag redaction wrapper durumlarında secret bırakıyor

Kaynak: [mcp-launch-redaction.ts](../../packages/core/src/mcp-launch-redaction.ts).

- İşlev: AI-BOM ve MCP launch argument çıktıları kimlik bilgilerini maskeliyor.
- Sorun ve kanıt: Doğrudan curl kısa flag'i maskelenirken sudo -u root curl -u ve env -u NAME redis-cli -a wrapper option değerleri command owner keşfini bozuyor. Attached curl -uuser:password biçimi de kapsanmıyor; gerçek modül üzerinde tekrarlandı.
- En küçük düzeltme: Wrapper seçeneklerinin değerlerini parse edin ve attached kısa flag biçimini ortak secret redaction'a alın.
- Ertelenirse: Envanter ve destek çıktıları kısa kimlik bilgilerini açık metinle taşıyabilir.

## Kod dışındaki production kabul eksikleri

| Alan | Güncel engel | Kabul ölçütü |
| --- | --- | --- |
| Release kararı | Commercial registry NO-GO, releaseCandidate null; 13 receipt open. Yapısal validator PASS release onayı değildir. | Tek immutable aday SHA/digest, imza, kapalı gate receipt'leri ve aynı adaya bağlı GO. |
| Yayındaki uygulama | 9 Ekim read-only ölçümünde app.aidr.singularityrd.com/login DNS çözülmedi; pilot readyz/version HTTP200 HTML SPA ve public cache verdi; landing status HTTP500. | Kaynak Worker'ın JSON/no-store kontratı, doğru DNS/TLS ve deployed revision doğrulaması. |
| Runtime imajları | 7 Ekim raporundaki dağıtım seti 33 CRITICAL ve 709 HIGH scanner bulgusu taşıyor; beş yeni imajın native kabulü çalışmadı. Scanner severity sömürülebilirlik kanıtı değildir. | Reachability/vendor-fix değerlendirmesi, güvenli pinler, final image/SBOM taraması ve gerçek hizmet kabulü. |
| Python NER stack | Yükseltmelerin geri alınması tek başına eski stack'i sağlıklı yapmaz. Linux Python 3.11 lock'undaki networkx 3.7 de Python 3.12 ister; Repository verifier mevcut iki lock ve wheel kanıtında 8 bağlama sorunu buldu; her iki source_lock_sha256 farklı, filelock/networkx ve bazı Windows paket kanıtları pinlerle eşleşmiyor. | Platform bazında resolver ve hash-verified wheel kurulumu, pip check, NER inference; eşleşen SBOM ve aday kanıtı. |
| Host ve browser kabulü | Native support matrix NO-GO; müşteri imzalı adaya bağlı tam OS/architecture/host/version ve gerçek browser/site matrisi yok. | Satılacak kapsamın gerçek host E2E testleri, MDM/notarization ve signed artifact kabulü. |
| Güvenlik | Historical secret triage 132 detection ve iki owner-confirm kaydı açık; doğrulanmış canlı credential iddiası yok. Bağımsız assessment/retest eksik. | Owner triage/rotation kararı, final secret taraması, pentest ve bulgu kapanışı. |
| Operasyon | Bağımsız hata alanına restore, kabul edilmiş RPO/RTO, çalışan on-call alarmı ve sekiz saat soak/failover kanıtı eksik. | Authenticated load/noisy-neighbour/failover, restore ve aylık SLI/SLA kanıtları. |
| Ticari ve hukuki kabul | Finans/entitlement/provider anahtarları, IP/privacy/residency, private registry ve müşteri PoV gate'leri açık. | İlgili sahiplerin aday bağlı kabul receipt'leri. |

Dayanaklar: [commercial gate receipts](../../docs/production-readiness/commercial-gate-receipts.json), [runtime image raporu](../../docs/production-readiness/runtime-image-security-2026-10-07.md), [native support matrix](../../deploy/native/support-matrix.json), [secret geçmişi triage](../../docs/production-readiness/secret-history-triage-2026-10-05.md).

Ek ölçek sınırları: Privacy quota state kullanıcı/dakika başına satır ekliyor ve mevcut purge yolu bu namespace'i kabul etmiyor; 120 dakikalık denemede süresi geçmiş 120 kayıt kaldı. 1000 kullanıcı ve 480 aktif dakika/gün yaklaşık 480 bin ek satır/gün eder. Native NER gerektiğinde rules-only devamını durduran politika gerekir. Belgelenmiş kaynak fingerprint yüzde 20 kapsam eşiği daha küçük kopyalar için genel DLP garantisi değildir.

Eski belgelerdeki tüm migration'ların hiç PostgreSQL'de çalışmadığı iddiası güncel değildir: 9 Ekim'de 6dafe898 üzerinde beş PostgreSQL gate'i geçmişti; bu inceleme de 178 migration'ı isolated DB'ye uyguladı. Bu sonuçlar final release'in tüm gate'lerini kapatmaz.

## Doğrulama ve son işlem kaydı

İncelenen kaynak commit: 0e72b1681480078de582ba08a0737ce5450f0de9. Rapor ve envanter bu kaynağın ardından ayrı bir belge commit’i olarak kaydedildi.

- Ana dal fast-forward ile güncellendi; ana dal güncellemesi ve uzak dal silmeleri iki atomic push ile yapıldı. Her silme, son incelenen uzak uç SHA için lease kullandı.
- Başlangıçtaki 112 ref ve sonradan açılan 14 ref’in commitleri master geçmişinde bulunuyor. 73 yerel dal ve 47 farklı uzak dal silindi; otomasyonun yeniden açtığı dallarla toplam 51 uzak silme işlemi yapıldı. Yerelde ve uzakta yalnız master kaldı.
- İncelenen 28 PR GitHub’da MERGED durumunda. 53 çalışma klasörü korundu. Diğer 52 klasör aynı HEAD’de detached durumuna alındı; öncesi ve sonrası tracked/staged/untracked içerik parmak izleri birebir eşleşti. Başlangıçta 11 klasördeki commit edilmemiş değişiklikler korundu.
- Tüm ref SHA’ları, merge kararları, PR sonuçları ve içerik koruma parmak izleri branch-consolidation-2026-10-09.json içinde kayıtlı. Ref silinmesi commit geçmişini silmedi.

| Kontrol | Sonuç ve kapsam |
| --- | --- |
| Temiz kurulum, tip kontrolü, lint, Knip ve duplicate gate | Son kaynakta PASS. Node 22 sözleşmeleri ve CLI’nin kendi Node 20 tip patch’i doğrulandı. |
| npm production ve build dependency audit | Son kaynakta PASS, tüm severity düzeylerinde 0 advisory. Docker/Python taraması bu sonuca dahil değil. |
| Current-worktree secret scan | Resmi checksum doğrulanmış Gitleaks 8.30.1 ile PASS. Historical owner triage ayrıca açık. |
| Hızlı 39 adımlı kontrol | 38 PASS, 1 yeni fixture yanlış alarmı. Dar ve gerekçeli fixture allowlist düzeltmesinden sonra hygiene 27/27 test ve aynı süre sınırıyla tekrar edilen 4/4 gate PASS. |
| Tam birim test koşusu | 633 dosya: 628 PASS, 5 FAIL. 11.221 test PASS, 12 FAIL, 11 SKIP; 23 dakika. Başarısız dosyaların hedefli tekrarında 52/52 PASS. İkinci tamamen yeşil tam koşu çalıştırılmadı. |
| Birim test hata ayrımı | 9 eski auth-budget fixture beklentisi düzeltildi; 2 fail-closed bütçe testi eklendi. 1 ACL işlem bütçesi yeni key korumasına uyarlandı; warm çağrı sıfır PowerShell. 2 yerel timeout aynı eşiklerle tekrarda geçti. |
| Windows key ve native payload koruması | Cache 33/33; Koffi staging 3/3; sızan yol scanner 7/7 regresyon testi PASS. Key byte’ları yazılmadan ACL onarımı ve native fallback kapatma doğrulandı. |
| PDF görüntü değişikliği | 53/53 hedefli PDF test, scoped type check ve Knip PASS. Bulgulardaki farklı PDF/Office kapsam atlamaları açık. |
| Dashboard | Vite 6.4.4 ile yeni build PASS; bundle boyutu uyarısı var. |
| Son esbuild paketi | 0.28.2 ile tüm workspace build ve gerçek built-hook 4/4 PASS. Son Windows cold medyanı 1498 ms, persistent warm 745 ms; 1500 ms cold hedefinin çok yakını, production yük kabulü ayrıca gerekir. |
| Release build | b8d7a231 üzerinde PASS: 11 manifest, 281 SBOM bileşeni ve 10 consumer smoke. İmzalı müşteri adayı ve final host matrisi değildir. |
| Supabase | Canonical 178 migration gerçek izole PostgreSQL’de PASS. Blocking reputation/identity/OIDC/SAML/discovery/fleet/delegation/offboarding/retention/quota gate adımı 15 dakika 38 saniyede PASS. |
| Cloudflare ve monitoring | Worker kontratı, Git Bash ile 40/40 staging-deploy testi, promtool rule/test kontrolleri PASS. Yayındaki deployment gözlemi ayrı NO-GO engeli olarak üstte kayıtlı. |
| CI workflow bütünlüğü | Son CodeQL değişikliğinin ardından 5/5 seçili workflow/drift/guard adımı PASS. Resmi tag SHA doğrulandı. |
| HOME ve dosya koruması | Gerçek HOME’a yazılmadığı ve final temiz ağacın değişmediği bağımsız kontroller PASS. |

Koşu sınırları: PostgreSQL test adımı geçti fakat eşzamanlı yetkili test düzeltmeleri sırasında aynı koşunun unchanged-tree guard’ı başarısız oldu; güncel temiz ağaç sonraki bağımsız guard’larla doğrulandı. Son 14 adımlı kaynak kontrolünde 13 PASS ve hygiene timeout vardı; 27 assertion geçmişti. Aynı deadline ile hygiene tekrarı 4/4 PASS verdi. Windows runner dış Bash’i kapatınca alt süreçler devam edebildiği için bu timeout’ın gerçek duvar süresi 3 dakika yerine 5 dakika 38 saniye oldu; süreç ağacı sonlandırma davranışı ayrıca iyileştirilmeli.

Yerel koşu JSON ve günlükleri .ci-local/merge-review altında tutuldu. Coverage, tam gerçek host/browser/OS matrisi, Python model kurulumu ve signed production acceptance çalıştırılmadı. Bu kayıtlar release GO receipt’i değildir.

Production yolu: Önce P1 koruma ve yetki bulguları kapanmalı, ardından birleşmiş commit'te zorunlu gate'ler atlamasız geçmeli. Aynı immutable signed aday üzerinde gerçek host/deployment ve operasyon/security/commercial kabulü tamamlanmalı; ancak bundan sonra candidate-bound GO ile yayımlanmalı.

Kontrol sınırı: Gerçek müşteri Office/browser/model davranışı, tam OS matrisi, yeni Python model kurulumu, bağımsız pentest ve production dağıtımı bu incelemenin tamamlandığı iddiasına dahil değildir. Repository'deki vendor ve generated data dosyaları satır satır ayrı kod incelemesine tabi tutulmadı.

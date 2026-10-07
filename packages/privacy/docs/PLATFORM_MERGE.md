# AIDR platform katmanı — birleştirme rehberi

Bu rehberin teknik sınırları geçerlidir; ancak bağımsız ZIP'e ait eski npm kurulum adımı çalışma alanı içe aktarımında kullanılmaz. Güncel pnpm komutları için [paket README'sine](../README.md) bakın. Aşağıdaki paket testleri Linux ortamında çalıştırılır.

## Başlangıç

Node 22.16.0 üzerinde derlendi/test edildi; kullanılan `node:sqlite` bu sürümde deneysel uyarı veriyor. Üretimde kurumun onaylı ve yamalı Node/native dağıtımıyla yeniden test edin. Python belge parser'ı Linux ve libseccomp gerektirir. Tam test kümesi Python parser bağımlılıklarını da ister; özel virtualenv için `AIDR_PYTHON=/absolute/venv/bin/python3` verin. Görsel uçtan uca denemelerde `AIDR_VISION_CONFIG` ile kendi onaylı yerel OCR yapılandırmanızı belirtin; `reports/platform/vision-local-config.json` bu ortamda kullanılan konfigürasyon kaydıdır, taşınabilir üretim ayarı değildir. Python modelleri/OCR/derleyici tarayıcıda çalışmaz.

```bash
pnpm install --frozen-lockfile --ignore-scripts
pnpm --filter @singularityrd/aidr-privacy build
pnpm --filter @singularityrd/aidr-privacy test:all
pnpm --filter @singularityrd/aidr-privacy test:python
pnpm --filter @singularityrd/aidr-privacy test:vision-python
pnpm --filter @singularityrd/aidr-privacy test:parser
pnpm --filter @singularityrd/aidr-privacy demo:platform
```

Özgün tam kaynak ZIP'i geliştirme tarball'larını içeriyordu; bu çalışma alanı içe aktarımı onları ve derlenmiş çıktıları taşımaz. Derleme gerekli çıktıları üretir, ancak henüz bir müşteri npm paketi yayımlanmaz. Python/native ortam, Tesseract ve gerçek NER ağırlıkları ayrıca kurulmalıdır. `parsers/requirements.lock.txt` parser bağımlılıklarını (pypdf, defusedxml, pypdfium2, Pillow) PyPI wheel SHA-256 değerleriyle kilitler ve `--require-hashes` ile kurulur; CVE/lisans onayı değildir.

## 1. Kimlik ve cihazı güvenilir sunucu katmanında kurun

`PinnedJwtVerifier` ve `ContextResolver` giriş metninden hesap rolü üretmez. Kullanıcı IdP'si, MDM/device broker'ı ve provider-account broker'ı ayrı imzalama anahtarları kullanmalıdır. JWT tokenları kısa ömürlüdür; issuer/audience/purpose/tenant/sub/sid/session_version/device_id bağlanır. Provider iddiası açıkça enterprise, verified ve logged_in olmalı, doğru kökeni belirtmelidir.

`provisionSession()` yalnız güvenilir broker tarafından çağrılır. Bir IdP login'i, ChatGPT veya Gemini hesabının kurumsal olduğunu tek başına kanıtlamaz. Provider hesabını broker gerçekten gözlemlemiyor/doğrulamıyorsa token üretmeyin.

Varsayılan cihaz bağlama aktiftir. TLS peer sertifikasının SHA-256 değeri, device tokenındaki `cnf['x5t#S256']` ile eşleşmelidir. `bindTlsCredentials()` gerçek yetkili TLSSocket kullanır; HTTP JSON'dan `authorized:true` kabul etmez. `requireTransportBinding:false` sadece izole birim testlerinde kullanılan kaçış seçeneğidir; normal dağıtım ayarı değildir. Aynı süreçte keyfi JavaScript çalıştırabilen kötü amaçlı kod bu SDK'nın güven sınırının dışındadır.

## 2. Tek tenant runtime fabrikası

```ts
import { createPlatformRuntime, listenPlatform } from '@singularityrd/aidr-privacy/platform';

// options: onaylı veritabanı yolu, KMS'ten alınan tenant/audit anahtarları,
// sabit issuer/public keys, imzalı politika ve sabit provider konfigürasyonları.
const runtime = await createPlatformRuntime(options);
await listenPlatform(runtime, {
  key: serverPrivateKey,
  cert: serverCertificate,
  clientCa: enrolledDeviceCA,
}, 8443, '127.0.0.1');
```

`RuntimeOptions` tam şeması `dist/platform/runtime.d.ts` içindedir. Çalışan, gizli bilgi gerektirmeyen örnek `examples/platform/demo.mjs`'dir; açıkça sentetik ve doğrudan SDK örneğidir, gerçek oturum kanıtı değildir.

Fabrika varsayılan `defense` profilini kullanır. Onaylı TR/EN PERSON+ADDRESS NER yeteneği yoksa metin dışarı verilmez. `profile:'strict'` yalnız kurallı pilot seçeneğidir; NER boşluğunu kapatmaz. Baseline semantik sınıflandırıcı NER yerine geçmez. Görsel yolu fabrikada varsayılan açık değildir; güvenilir `VisualPrivacyEngine` factory'sini `EnforcedEgress` içine bağlamadan görüntü reddedilir.

Tek tenant/tek sağlayıcı metin-only kurulum için [servis launcher rehberi](TEXT_SERVICE.md) kullanılabilir. `aidr-privacy-service` gerçek model/broker/oturum/TLS hazır olmadan dinlemeye başlamaz; SDK'nin strict pilot seçeneğini bu servis açmaz. Diğer ürün/browser/native çıkışlarına otomatik bağlandığı iddia edilmez.

## 3. Son çıkışı değiştirin; yalnız önce taramakla yetinmeyin

Provider çağrıları `/v1/egress` handler'ından geçmelidir. İstek `requestId`, sabit `destinationId`, `text`, opsiyonel base64 `images` ve onaylı yeniden denemede `reviewCaseId` taşır. Model, endpoint, API key veya tenant kullanıcının gövdesinden alınmaz. User/device/provider tokenları ayrı header'lardadır; mTLS bağlantısı gerekir. Provider credentials sadece bu serviste tutulmalıdır.

`EnforcedEgress` metin ve bütün görselleri tarar; ilk upload ancak tarama tamamlandıktan sonra başlar. Girdi byte'ları snapshot alınır; kimlik/iptal/politika asenkron aralıktan sonra yeniden denetlenir. Dönen nesne, tekrar kullanılabilir “temiz dosya izni” değil, dispatch makbuzudur. Network sınırını bunun dışında kalan provider URL'lerini kapatacak şekilde uygulayın.

Sabit HTTPS taşıyıcısı DNS çözümü ve TLS bağlantısından sonra, gövdeyi göndermeden hemen önce kimlik ve politikayı tekrar doğrular. Özel `ByteTransport` adapter'ları da verilen `beforeDispatch` callback'ini asenkron hazırlıktan sonra, byte çıkışından önce çağırmalıdır.

`unknown` ağ sonucunda aynı `requestId` otomatik tekrar gönderilmez. Uzak sağlayıcı işlemi tamamlamış olabilir. Başarılı dış gönderimden sonra yanıtın engellenmesi `sent / RESPONSE_WITHHELD` olarak raporlanır, gönderim hiç olmadı denmez. `output` ve `response` null olduğunda orijinal metin/görsele fallback yasaktır.

MCP için `EnforcedMcpCall.callOnTls()` aynı cihaz sınırını kullanır. Bu dar `tools/call` JSON-RPC yürütücüsüdür; MCP OAuth, tam oturum/stream protokolü veya OS tool sandbox değildir. Güvenilir tool registry ve sabit upstream taşınır, modelden URL alınmaz.

Desteklenen MCP yanıtı yalnız metin `content` blokları ve opsiyonel JSON `structuredContent`, `_meta`, `isError` alanlarıdır. Görsel/audio/resource ve bilinmeyen içerik alanları reddedilir. Bitişik metin blokları birleştirilerek, ardından anahtarlar ve metadata dahil bütün sonuç `ToolCallGuard`'ın yapılandırılmış gizlilik tarayıcısıyla denetlenir. Varsayılan tarayıcı strict kurallıdır; verilen defense/NER tarayıcı daha zayıf bir varsayılanla değiştirilmez. Yalnız tamamen `allow` ve null olmayan taranmış çıktı döner; redact/review/block veya tarayıcı hatasında bütün sonuç saklanır. Araç çalışmış olduğu için dispatch kaydı `completed` kalır ve hata `MCP_RESPONSE_WITHHELD` olur; onay iade edilmez, ham yanıta fallback veya aynı requestId ile yeniden gönderim yapılamaz. Tarama sonrasında oturum ve politika tekrar doğrulanır. Bu sınır EnterprisePrivacyGate provenance/ACL/taint denetimi eklemez; arbitrary encoded JSON, öğrenilmiş model doğruluğu veya bütün MCP yollarının kapsandığı iddia edilmez.

## 4. Kalıcı durum ve restore

`SqliteControlStore` çok tenant destekler; hazır factory her runtime için tek kurum kabul eder. Aynı makinedeki süreçler aynı özel dizindeki DB'yi paylaşabilir. NFS, ayrı host'lar ve HA için uygun dağıtık/transactional adapter eklenmeden genişletmeyin.

POSIX dizin 0700, dosya 0600 olmalıdır. Windows'ta yerel ACL sahibi ve izinli kimlikler yalnız çalışan kullanıcı, SYSTEM ve Administrators olmalıdır; geniş erişim izinleri reddedilir. Hücre payload'ları tenant bazlı AES-256-GCM ile şifrelidir; v2 formatında son geçerlilik zamanı da doğrulanan metadata'ya bağlanır. Namespace/key/metadata tamamının gizlendiği iddia edilmez. Eski RC veritabanlarını yükseltmeden önce [durum kurtarma rehberini](STATE_RECOVERY.md) uygulayın. Varsayılan `journal_mode=DELETE`, `synchronous=FULL` kullanılır. WAL yalnız kodun sürüm kontrolünden geçen SQLite ile açılır.

`DurableApprovalLedger`, `DurableBudget`, `DurablePolicyCheckpoint`, `DurableDispatchLedger` ve `PersistentAuditJournal` mevcut 0.4 adapter noktalarıyla çalışır. Onay talebinin ham JSON'undan bir admin principal üretmeyin; identity resolver'ın gerçek rol doğrulamasını kullanın.

Harici anchor/checkpoint bağımsız bir yerde saklanmalıdır. Tam eski veritabanı snapshot'ı, yeni harici anchor ile testte tespit edildi. Bu, DB sahibi eski geçerli tek bir hücreyi seçerek geri yüklediğinde otomatik koruma veya WORM depolama anlamına gelmez. Ayrı anahtarlar, yedek erişim kontrolü ve kurum restore tatbikatı gerekir. Silme/tombstone eski yedekleri fiziksel olarak yok etmez; rotation sonrası eski anahtarlar eski history/backuplar için korunur. Retention/GC ve uzun dönem kapasite kurumdaki işletim sürecine bağlanmalıdır.

## 5. Portal ve dört-göz

`OidcSessionManager` gerçek protocol kontrol kodudur; `exchange()` sabit HTTPS token endpoint taşıyıcısı ve `establishLocalSession()` doğrulanmış claim -> kurumsal yerel oturum eşlemesi sizin IdP/broker adapter'ınızdır. Bu callback'lerin birim testlerinde taklidi kullanıldı. Canlı IdP bağlantısı yapılmadı.

`createReviewHandler()` + `portal/` gerçek HTTPS API/arayüz oluşturur. Cookie HttpOnly/Secure/SameSite, POST Origin+CSRF, RBAC, sequence kontrolü ve gerekçe uygulanır. İstisna exact action digest/policy/session/TTL/kullanım sayısına bağlıdır. `consumeApproved()` yalnız reviewable bir eylem için çağrılmalıdır; secret, auth veya sert block'u override etmez. Otomatik bütün gate block'larını istisnaya dönüştüren yol yoktur.

Runtime, `runtime.reviews` üzerinden portalın kullanacağı workflow'u sağlar. Yalnız semantik sezgi nedeniyle incelemeye alınan istek, HTTP 409 yanıtında `reviewCaseId` alır. Başka bir yetkili incelemeci bu kaydı onayladıktan sonra aynı kullanıcı ve oturum, aynı metin/görseller/hedef/model ile yeni `requestId` ve bu `reviewCaseId` gönderir. Gateway onayı atomik olarak tüketir; bütün gizlilik kontrollerini tekrar çalıştırır ve yalnız temizlenmiş çıktıyı iletir. Değişmiş içerik, oturum, politika veya tüketilmiş/süresi geçmiş onay reddedilir. Secret, provenance taint, tarayıcı belirsizliği ve sert engeller bu akışla aşılmaz.

OIDC başlangıç kayıtları silinmiş kayıtlar dahil 1.000, portal oturum kayıtları 10.000 ile sınırlıdır. Süresi geçmiş bu iki geçici namespace temizlenir; kapasite doluyken giriş HTTP 503 ve `Retry-After` döndürür. Kalıcı dispatch/audit/onay geçmişi bu temizlik kapsamına girmez.

## 6. Belge, keşif, DSPM ve model

`DocumentCdr` varsayılan olarak yalnız yeni `aidr-sanitized.txt` üretir. DOCX/XLSX/PPTX için `protect(input, kind, {output:'office'})` açıkça istenirse biçim koruyan `aidr-redacted.<kind>` üretilir (bkz. PLATFORM_FEATURE_STATUS.md, "Biçim koruyan Office redaction"); PDF için `protect(input, 'pdf', {output:'pdf'})` metin katmanı ve metadata içermeyen, span'leri siyah kutuyla kapatılmış yalnız görüntü `aidr-redacted.pdf` üretir ("Biçim koruyan PDF redaction"); worker değiştiği için `workerSha256` pinini güncelleyin. PDF/Office arkasındaki gizli/aktif container'ı taşımayın. Kaynak dosya, thumbnail, attachment veya orijinal filename'i temiz TXT yanında iletmeyin. Linux libseccomp sonradan filesystem open/network/exec çağrılarını engeller; yine de readonly/no-network container ve native güncelleme disiplini gerekir. Desteklenmeyen içerik bloktur.

`AuthorizedMcpCollector.watch(signal, intervalMs)` yalnız açıkça onaylı dosya yollarını izler ve metadata üretir; uygulama başlatmalıdır. Çıktı imzalı kurumsal collector ingest'e adapter ile bağlanır. Yeniden başlatma full snapshot üretir; sink `idempotencyKey` ile tekrarları ele almalıdır. Eksik/okunamayan kaynak “boş” kabul edilmez.

`DspmRepository.replace(..., complete=true)` eksiksiz yetkili snapshot gerektirir. Canlı cloud ACL yerine varsayımsal herkese erişim vermeyin. Yerel örnek grup ACL/classification'ı yönetici konfigürasyonundan alır.

`LinearRiskClassifier` ek review sinyalidir; `no-additional-signal` -> allow olarak çevrilmez. `inspectSafetensors` format kontrolü ve hash pin model davranışının güvenli olduğunu kanıtlamaz. `COMPONENT-INVENTORY.json` CVE clearance değildir.

## 7. Chrome paketini birlikte yükseltin

Chrome/native 0.4 davranışı korunur ve 0.5 olarak yeniden derlenir. Yeni gateway/SSO, bu bundle içindeki bütün site yollarına otomatik bağlanmadı. Mevcut native protokolünü gerçek token broker/gateway'e bağlayın veya güvenli kurum UI/gateway yoluna yönlendirin. Doğrudan site kullanımında `guard` modu sayfanın DOM'a yazılan ham metni önceden okumasını engelleyemez; `secure-compose` kullanın. İlk upload ve alternatif app/CLI rotalarını ağda da kapatın.

`deployment/` politika parçaları üretim MDM dağıtımı değildir. Geliştirme extension public ID'nin CRX signing private key'i pakette yoktur; kendi yayıncı kimliğinizle değiştirin. Ana AIDR deposuna merge öncesinde bu rehberdeki gerçek entegrasyon testleri uygulanmalıdır.

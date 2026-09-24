# AIDR 0.4.0-rc.1 — Birleştirme ve çalıştırma rehberi

Bu kaynak, önceki 0.3.0-rc.1 modülünün devamıdır. Ana Singularity AIDR uygulama deposu bu çalışmada bulunmadığı için o depoda gerçek bir merge yapılmadı. Mevcut API'ler korundu; kurumsal kontroller `@singularity/aidr-privacy/enterprise` altında eklendi. Eklentiye de yeni tarama/koçluk kontrolleri bağlandı.

## Mimari sınırlar

```text
Tarayıcıdaki Güvenli Yaz / AIDR uygulaması / agent runtime
                         |
             AIDR authenticated enforcement boundary
      kimlik + tenant + cihaz + sağlayıcı hesabı + hedef
                         |
        imzalı politika + kurumsal indeks + kaynak makbuzu
                         |
             EnterprisePrivacyGate / ToolCallGuard
                         |
             kalıcı içeriksiz denetim ve onay
                         |
              yalnız izin verilen yeni byte'lar
                         |
                 gerçek provider / tool executor
```

Eklentinin tek başına bağlam girdisindeki `account:'enterprise'` değerini doğruladığı iddia edilmez. Eklenti gönderim deneyimidir; hesap/cihaz yetkisini sayfadaki bir DOM etiketiyle kanıtlamayın. Girdinin “tenant-1” demesi tenant yetkilendirmesi değildir.

## Hızlı yerel çalışma

Önceden derlenmiş `.tgz` için:

```bash
npm install ./singularity-aidr-privacy-0.4.0-rc.1.tgz
```

Tam kaynak kökünde:

```bash
npm ci --offline --ignore-scripts
npm run build:all
npm run test:all
npm run test:python
npm run test:vision-python
npm run demo:enterprise
npm run benchmark:enterprise
```

TypeScript derleyici ve tip paketleri tam kaynakta geliştirme bağımlılığı olarak vendor edilmiştir. Node çalışma zamanında yeni üçüncü taraf npm bağımlılığı eklenmedi. Python/native OCR/NER çalışma ortamı ayrı kurulur. Test edilen Node sürümü v22.16.0; üretimde kurumun güncel yamalı ve test edilmiş runtime imajı kullanılmalıdır.

`examples/enterprise/demo.mjs`, gerçek Ed25519 imzalama, senkron disk denetimi, PII maskeleme, kurumsal kayıt engeli, kişisel hesap engeli, talimat sinyali, kaynak sınıfı mirası ve dört-göz araç onayı çalıştırır. Hiçbir dış sağlayıcıya veya gerçek iş sistemine istek göndermez. Örnek kimlikler sentetiktir; production kimlik doğrulaması değildir. Demo anahtarları her çalışmada bellekte üretilir, dosyaya yazılmaz.

## Ana uygulamada birleştirilecek noktalar

### 1. Tenant ve güven köklerini uygulama katmanında ayırın

Her tenant için ayrı `PolicyRegistry`, `AuditJournal`, `SensitiveDataIndex`, `ProvenanceLedger` ve gerekli kotalar oluşturun. Tenant dışı kaynağın bağlanması reddedilir. Özel politika imzalama anahtarını browser bundle'a veya native kullanıcı ayarına koymayın; yönetici kontrol alanında tutun. Doğrulama tarafına yalnız onaylı açık anahtar map'i verin.

```ts
import {
  PolicyRegistry, EnterprisePrivacyGate,
  SensitiveDataIndex, AuditJournal, createFileAuditSink,
} from '@singularity/aidr-privacy/enterprise';
```

`PolicyRegistry(tenantId, trustedPublicKeys, persistedCheckpoint?)`, sabitlenmiş Ed25519 anahtarlarını alır. `installDurable(envelope, writeCheckpoint)` kullanın. `writeCheckpoint` atomik ve kalıcı yazı tamamlanınca resolve etmelidir. O sırada politika uygulanabilir hale gelmez; gecikme, hata veya süre aşımı aktarımı kapalı bırakır. Aynı süreçte sürüm geriye gidemez. Yeniden başlatmada yüksek sürüm checkpoint'ini güvenilir depodan yüklemek zorunludur.

Düz `install()` yalnız kalıcı checkpoint'in ayrıca güvenceye alındığı tek süreçli/laboratuvar akışlarında uygundur. Saldırganın eski disk snapshot'ını geri getirebildiği yerde yalnız bellekte sürüm numarası saklamak yeterli değildir.

### 2. Onaylı kayıtları veri sınırında indeksleyin

```ts
const index = new SensitiveDataIndex(
  tenantId, 'restricted-project-records', 'index-key-v1', tenantIndexKey,
);
index.enrollRecord(
  'opaque-record-1',
  { part: 'PART-ALPHA', facility: 'FACILITY-BRAVO' },
  'restricted',
  2,
);
```

Bu girdiler örnektir. Gerçek kaynağın okunması, silinmesi, güncellenmesi, erişim kontrolü ve eşik seçimi size ait ingestion işinde yapılmalı. İndeks anahtarları tenant başına ve diğer HMAC amaçlarından ayrı yönetilmeli. Anahtar değiştiğinde indeks yeniden kurulmalı. `snapshot()` kaynak metni veya anahtarı içermez; ancak snapshot yine hassas kabul edilmelidir. Bu sürümde kalıcı indeks import/senkronizasyon servisi yoktur.

### 3. Denetim yazısını gerçek ve kalıcı hale getirin

```ts
const sink = await createFileAuditSink('/var/lib/aidr/audit/new-segment.jsonl');
const journal = new AuditJournal(
  tenantId, 'unique-log-id', 'audit-key-v1', auditKey, sink.write,
);
```

Dizin yönetici tarafından önceden güvenli biçimde hazırlanmalı. Dosya mutlaka yeni olmalı; var olan dosya/symlink üzerine yazılmaz. Varsayılan segment sınırı 64 MiB'dir; sınırda eski kayıtlar sessizce silinmez. Bu adaptör Linux'ta test edildi. Rotation, saklama süresi, off-host checkpoint ve erişim kontrolü ayrı işletim görevleridir. Fsync çağrısının güç kaybına dayanıklılığı fiziksel depolamanın semantiğine bağlıdır.

Alternatif olarak `AuditJournal` yazıcısını AIDR'nin dayanıklı olay deposuna bağlayın. Bir array'e `push()` edip resolve etmek yalnız testtir, production kalıcılığı değildir. Yazıcı, içeriksiz kaydı kalıcı onaydan önce başarılı saymamalı. `AuditJournal` tek süreçte sıralar; aynı `logId` için birbirinden habersiz birkaç süreç kullanmayın.

Zincir `verifyAudit(records, checkpoint, auditKey)` ile doğrulanabilir. Checkpoint'i bağımsız güven kökünde saklamadan zincirin sonunun silinmesini kesin fark etme iddiasında bulunmayın. Kayıt, karar niyetini gösterir; sağlayıcıya gerçek teslimin kanıtı değildir. Ayrı gönderim/yanıt kaydı ve uygulama idempotency'si gerekir.

### 4. Son provider çağrısını koruyun

```ts
const gate = new EnterprisePrivacyGate({
  registry, audit: journal, indexes: [index], provenance, budget,
  textEngine: approvedPrivacyEngine,
});

const result = await gate.protect(rawText, trustedContext);
if (result.output === null) {
  // block veya review: orijinal metne fallback YOK.
  throw new Error('AIDR_EGRESS_DENIED');
}
// Buraya yalnız result.output verilmelidir.
await providerSend(result.output);
```

`trustedContext` alanları: `tenantId`, `subjectId`, `sessionId`, `groups`, `scopes`, `device`, `account`, `accountVerified`, `destination`, `channel`, `assetIds`. Gerçek oturumdan, tenant yetkisinden, yönetilen cihaz bilgisinden ve sağlayıcı hesabına ilişkin güvenilir kayıttan türetilmelidir. Modelin tool argümanı, HTTP'deki bir `X-Tenant` değeri veya kullanıcının gönderdiği JSON güven kaynağı değildir.

`destination` tam HTTPS kökenidir; suffix eşleştirmesi yapılmaz. Bu sürüm bazı intranet/IP/punycode biçimlerini bilinçli reddeder. İç ağ sağlayıcısı desteği, gerekçeli ayrı taşıma politikasıyla genişletilmelidir; `endsWith()` gibi gevşek denetimle açılmamalıdır.

`output` kontrolünden sonra orijinal promptu başka alana, loga, thumbnail'e, analytics'e veya retry kuyruğuna koymayın. Telemetri ve retry payload'ları da çıkış sınırının parçasıdır. Çok mesajlı konuşmada yalnız son kullanıcı metnini değil, gerçekten dışarı gidecek bütün mesajları ve ekleri kontrol edin. Büyük konuşmayı bağımsız küçük parçalar halinde taramak, parçalar arası eşleştirme kapsamını azaltabilir.

### 5. Görsel motoruna aynı kararı bağlayın

```ts
import { VisualPrivacyEngine } from '@singularity/aidr-privacy/visual';

const visual = new VisualPrivacyEngine({
  backend: localImageBackend,
  textEngine: gate.textAdapter(trustedContext),
  release: 'automatic',
  uncertainText: 'review',
});
```

`textAdapter`, orijinal UTF-16 PII aralıklarını korur; görsel motorunun koordinat eşleştirmesi değiştirilmez. Kurumsal engel, görselin de gönderilebilir byte üretmemesine yol açar. Bu bağlantı gerçek Türkçe OCR, piksel doğrulaması ve kalıcı denetimle test edildi.

Buradaki `release:'automatic'` bir entegrasyon örneğidir, bütün kurumlar için güvenli varsayılan değildir. Kritik ortamlarda manuel inceleme veya görsel engeliyle başlayın. `assetIds` metnin kendisine bağlı makbuzlardır; kaynak dosya makbuzunu farklı OCR metnine aynen geçirmek eşleşme hatası verir. Dosya → OCR → özet türetmelerini güvenilir entegrasyonun açıkça kaydetmesi gerekir. OCR aynı görseli birden fazla görünüm/kalıntı için kontrol edebilir ve birkaç denetim kaydı oluşabilir.

### 6. Agent runtime'da en son araç sınırını koruyun

`ToolCallGuard`, SDK seviyesinde çağrı doğrulamasıdır. MCP taşıma, OAuth veya uzak sunucu kimliği uygulaması değildir. Registry'den gelen isim/açıklama/annotations dahil tanımın hash'ini yönetici incelemesinden sonra sabitleyin. `ToolRule.effect` modelin self-report'undan değil gerçek adapter incelemesinden gelmelidir.

```ts
const preview = await tools.inspect(request, trustedToolContext);
// review.approval yalnız doğrulanmış ayrı approver ekranına gider.
// Principal bilgisi kullanıcı JSON'undan değil mevcut SSO/RBAC'den çözülür.
const token = approvals.approve(preview.approval, verifiedSecondPerson);
await tools.execute(request, trustedToolContext, executeRealTool, token);
```

Tam akış için çalıştırılabilir demo kullanın; `preview.approval` yalnız `review` kararında doludur. `inspect()` çıktısı yeniden kullanılabilir bir yürütme yetkisi değildir. Son çağrı `execute()` üzerinden yapılmalı. Parametreler değişirse eski onay geçersizdir. Kurallar güncellenince eski onaylar iptal olur. Onayı daha sonra yeniden kullanmayın; executor hatası bile onayı geri kazandırmaz.

`executeRealTool` için ayrıca süre/kaynak sınırı, gerçek DNS/redirect kontrolü, ağ sandbox'ı, hedef yetkilendirmesi, iş idempotency'si ve içeriksiz işlem denetimi gerekir. `ToolCallGuard` bu callback'i tam bir OS sandbox'a dönüştürmez. Dört-göz arayüzü, onay gerekçesi depolama ve tool olaylarını AIDR olay deposuna aktarma bu örnek tarafından otomatik kurulmaz.

### 7. Browser ve native host'u beraber yükseltin

`extension/chrome/` yeni derlenmiş MV3 eklentisidir; kimliği önceki paketle korunur. Eklenti manifest sürümü `0.4.0`, sürüm adı `0.4.0-rc.1`.

`PolicyJSON` yeni alanlar:

```json
{
  "id": "aidr-managed-v04",
  "mode": "secure-compose",
  "injectionAction": "review",
  "sourceCodeAction": "block",
  "textAction": "redact",
  "requireNativeText": false,
  "fileHandling": "sanitize"
}
```

Bu örnek kural tabanlı pilot içindir; öğrenilmiş NER kapsamı iddia etmez. Onaylı TR/EN NER bağlandıktan sonra `requireNativeText:true` kullanılabilir; bağlı değilse aktarım kapanır. Yüksek hassasiyette `mode:'block'` veya dosya engeli başlangıç seçeneğidir.

Browser `PolicyJSON` ile enterprise Ed25519 politikası aynı şema veya otomatik senkronize sistem değildir. Güvenilir AIDR politika dağıtıcısı bunları eşleştirmelidir. Yeni alanlar varsayılan politika digest'ine girdiğinden eski native host ile yeni eklentiyi eşleştirmeyin; uyuşmazlık engellenir. Anahtarlar, EDM kayıtları ve kurumsal kimlik verisi eklentiye gömülmez. Yeni enterprise SDK'nın varlığı, bütün browser isteklerinin kendiliğinden ona yönlendirildiği anlamına gelmez.

## Diğer API'ler ve sınırları

| API | Kullanım | Önemli sınır |
|---|---|---|
| `ActivityBudget.consume()` | Çağrı/byte penceresi | Süreç içi atomiklik; dağıtık Redis/SQL katmanı ayrıca gerekir. |
| `ProvenanceLedger.registerRoot/derive/resolve()` | Sınıf ve taint mirası | Yalnız bildirilmiş dönüşümler; otomatik OS lineage değil. |
| `ApplicationInventory.observe()` | Köken/onaylı durum gözlemi | Gözlem girdisi gerekir; gizli tarayıcı izleme sensörü yok. |
| `signWebhook/verifyWebhook()` | Metadata zarfı bütünlüğü | Ağ göndericisi ve alıcı tarafı atomik deliveryId tekrar deposu yok. |
| `inspectSignals()` | TR/EN kalıp triajı | Semantik ML modeli veya garantili injection savunması değil. |

## Değişen dosyalar

Yeni çekirdek `src/enterprise/`, testler `tests/enterprise/`, örnek `examples/enterprise/`, gerçek çalışma scriptleri `scripts/enterprise/`. Browser politika/engine dosyaları ve extension service-worker/compose/build scriptleri değişti. `MERGE-0.3-to-0.4.patch` metin kaynak farkını içerir; binary görselleri, derlenmiş dağıtımı ve eski raporları içermez. Patch uygulandıktan sonra `npm ci --offline --ignore-scripts && npm run build:all` çalıştırın. Tam kaynak ZIP'i esas teslimdir.

## Güvenli geçiş sırası

Önce offline demo ve testleri kendi runtime'ınızda tekrarlayın. Sonra policy/audit/identity adapterlarını kurum sınırında kurup shadow değerlendirme sonuçlarını insan incelemesiyle karşılaştırın. İnceleme/engelleme kipinden yalnız doğrulanmış kanalları otomatik maskelemeye açın. İlk dış upload'u atlayan yolları, retry ve timeout davranışlarını, tenant geçişini ve policy rollback'i müşteri ortamında test edin. Canlı sağlayıcı arayüzleri değiştiğinde adaptör regresyonunu CI'da çalıştırın. Eski sürüme dönüşte politika/metadata şeması uyumsuzluğunu güvenliği azaltarak gidermeyin; gerekiyorsa kanalı kapalı tutun.

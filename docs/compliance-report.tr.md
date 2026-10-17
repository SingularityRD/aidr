# Uyum kanıt raporu

[English](compliance-report.md) · Bu sayfa İngilizce
[compliance-report.md](compliance-report.md) belgesinin Türkçesidir; iki metin
ayrışırsa önce İngilizce sürüm güncellenir.

Uyum kanıt raporu, kiracıya özel ve dönemle sınırlı bir JSON belgesidir; güvenlik
ya da veri koruma (DPO) ekibinin iç veya dış denetçiye verebileceği bir
belgedir. Singularity AIDR'ın zaten tuttuğu kayıtlardan, KVKK ve GDPR hesap
verebilirlik çalışmalarında genellikle istenen kanıtları toplar: neyin
korunduğu, ürünün kişisel verilerle ve gizli bilgilerle ne yaptığı, hangi
politikaların yürürlükte olduğu, çalışma alanını kimin yönetebildiği, hangi
olayların yaşandığı ve saklama ile silmenin nasıl uygulandığı.

> **Ne değildir.** Rapor KVKK ve GDPR hesap verebilirliğini *desteklemek* için
> tasarlanmıştır. Bir sertifika, denetim görüşü ya da hukuki danışmanlık
> değildir. Kurumunuzun, kurulumunuzun ya da Singularity AIDR'ın herhangi bir
> yasa veya standarda uyumlu olduğunu söylemez. Uyuma ilişkin sonuçlar DPO'nuza,
> hukuk danışmanınıza ve denetçilerinize aittir.

- Edge Function: `supabase/functions/compliance-report/index.ts`
- Ortak şema ve bütünlük kodu: `supabase/functions/_shared/compliance-report.ts`
- SQL: `supabase/migrations/20260926000030_compliance_report.sql`
  (`public.compliance_report_evidence`, `public.record_compliance_report`)
- Panel: **Uyum** (`/compliance`), yalnız sahipler, yöneticiler ve denetçiler
- Çevrimdışı doğrulama: `aidr compliance verify <rapor.json>`

## Raporu kim oluşturabilir

| Denetim | Davranış |
| --- | --- |
| Rol | Çalışma alanının etkin **sahibi**, **yöneticisi** ya da salt okunur **denetçisi** ([roller](security/roles.md)). Üyeler, görüntüleyiciler, süresi dolmuş ve tam zamanında (just-in-time) destek üyelikleri reddedilir. |
| Ek doğrulama | Oturum, çalışma alanı MFA politikası isteğe bağlı olsa bile **AAL2** (çok faktörlü) düzeyinde olmalıdır. |
| Kimlik bariyeri | Oturum iptali, zorunlu SAML sağlayıcısı ve çalışma alanı MFA politikası önce uygulanır. |
| Çalışma alanı durumu | Çalışma alanı `active` olmalıdır. |
| Hız sınırı | Kullanıcı başına dakikada 3, çalışma alanı başına dakikada 6 rapor. Okunamayan bir sayaç isteği reddeder. |
| Dönem | En fazla **366 gün**, 2020-01-01'den önce başlamaz ve gelecekte bitmez. |
| Makbuz | Her rapor, döndürülmeden **önce** yönetici denetim kaydına `compliance_report.generated` (rapor kimliği, dönem, SHA-256, imza anahtarı kimliği) olarak eklenir. Makbuz yazılamazsa rapor döndürülmez. |

SQL fonksiyonu rol ve çalışma alanı denetimlerini satır kilitleri altında
tekrarlar; böylece istekle yarışan bir rol düşürme ya da kapatma araya
giremez. İki fonksiyonu da yalnız servis rolü çalıştırabilir.

Okunamayan bir üyelik, güvence düzeyi, hız sınırı sayacı, kanıt satırı, imza
anahtarı ya da denetim makbuzu hata üretir; hiçbir zaman eksik ya da imzasız
bir rapor üretilmez.

## Oluşturma ve indirme

1. Panelde **Uyum** sayfasını açın (sahipler, yöneticiler ve denetçiler görür).
2. Bir dönem seçin: son 30, 90, 180 ya da 365 gün veya tam UTC günlerinden
   oluşan özel bir aralık.
3. **Rapor oluştur** düğmesine basın. Tarayıcı, bir şey göstermeden önce
   raporun SHA-256 değerini yeniden hesaplar; kendi özetiyle uyuşmayan yanıt
   reddedilir.
4. İndirin:
   - **JSON**: geçerli ve doğrulanabilir asıl belge.
   - **CSV paketi (.zip)**: her bölüm tablosu için bir CSV ve rapor kimliğiyle
     özeti içeren `README.txt`. Tarayıcıda JSON'dan üretilir; imzalı değildir.
     Bir hesap tablosunun formül olarak çalıştıracağı değerlerin başına `'`
     eklenir.
   - **Yazdırılabilir rapor**, **Türkçe ya da İngilizce**: yazdırma CSS'i
     olan bağımsız bir HTML sayfası. **Yazdır / PDF olarak kaydet** ile
     kullanın ya da HTML'i indirin. JSON'dan türetilir.

API biçimi:

```http
POST /functions/v1/compliance-report
Authorization: Bearer <AAL2 user session>
Content-Type: application/json

{ "tenant_id": "<uuid>", "from": "2026-06-27T00:00:00Z", "to": "2026-09-25T00:00:00Z" }
```

Yanıt `{ "ok": true, "report": { ... } }` biçimindedir. Hatalar makine
tarafından okunabilir kodlardır: `mfa_required`, `compliance_role_insufficient`,
`workspace_forbidden`, `workspace_not_active`, `rate_limited`,
`invalid_period`, `period_too_long`, `period_in_future`,
`compliance_evidence_invalid`, `compliance_signing_unavailable`,
`compliance_audit_unavailable`, `compliance_report_unavailable`.

## Rapor yapısı

```text
schema            "aidr.compliance-report/v1"
report_id         rastgele UUID, denetim makbuzunda da yer alır
generated_at      kanıt anlık görüntüsünün veritabanı zamanı
generated_by      { user_id, role }
period            { from, to, days }   (from dahil, to hariç)
statement         yukarıdaki "ne olduğu / ne olmadığı" metni
sections          aşağıdaki dokuz bölüm
limitations       raporun gösteremediklerinin sabit listesi
integrity         { canonicalization, hash_algorithm, hashed_scope, sha256, signature }
```

## Bölümler: her biri neyi gösterir, neyi kanıtlamaz

| Bölüm | Ne gösterir | Hangi kanıta destek olur | Neyi **kanıtlamaz** |
| --- | --- | --- | --- |
| `tenant_profile` | Çalışma alanı kimliği, adı, türü, durumu, barındırma bölgesi (kayıtlıysa) ve varsayılan saklama günleri. | Veri sorumlusunun çalışma alanını ve nerede barındırıldığını tanımlama. | Bölgenin sözleşmelerinizle uyuştuğunu; eksik bölge, kaydedilmediği anlamına gelir. |
| `protection_coverage` | Çalışma ortamına göre ajanlar ve tarayıcı kurulumları: kayıtlı, dönemde etkin, ilk kayıt, son görülme. | Teknik tedbirin kapsamı; hangi uç noktaların korunduğu. | Kurumunuzdaki her cihazın kayıtlı olduğunu. Yönetilmeyen ve yerel moddaki uç noktalar kontrol sunucusuna görünmez. |
| `data_protection_activity` | Browser Guard taramaları: maskelenen, uyarılan, engellenen ve izin verilen; varlık türüne (TCKN, IBAN, e-posta, gizli anahtar vb.), AI sitesine, kanala ve güne göre; kurulumların bildirdiği yönetilen tarayıcı politikası kimlikleri. Ajan çalışma zamanı kararları (allow/ask/deny) kaynağa göre, DLP/istem koruma alt kümesiyle. **Yalnız sayılar.** | Veri en aza indirme ve işleme güvenliği tedbirlerinin çalıştığı (ör. GDPR md. 25 ve 32, KVKK md. 12). | Hiçbir kişisel verinin bir AI hizmetine ulaşmadığını: maskelenen gönderim yine maskelenmiş metni gönderdi, `monitor`/`allowed` gönderimler değişmeden gitti ve bildirim yapmayan tarayıcılar sayılmaz. |
| `policy_inventory` | DLP politikası sürümü, SHA-256 özeti ve kural/etiket/istisna sayıları; çalışma zamanı politikası sürümü, özeti, varsayılan eylemler ve liste boyutları; ekip politikası özeti; dönemdeki revizyonlar; onay modeli (`ask` bant dışı insan onayıdır, asla ajanın çağırabileceği bir araç değildir). | Hangi yapılandırmanın yürürlükte olduğu ve ne zaman değiştiği (değişiklik yönetimi). | Kuralların içeriğini. Gövdeler bilerek dışarıda bırakılır; içeriği kanıtlamanız gerekirse özeti kendi politika dışa aktarımınızla karşılaştırın. |
| `access_identity` | MFA zorunluluğu, SSO zorunluluğu, acil durum (break-glass) erişimi; SCIM belirteci ve sağlama sayıları; role göre üyeler; sahip/yönetici listesi (kullanıcı kimliği, e-posta, rol, katılım, bitiş, doğrulanmış MFA faktörü olup olmadığı); dönemdeki yönetici denetim işlemleri türüne göre. | Erişim denetimi ve dönemsel erişim gözden geçirme kanıtı. | Ürün dışında altyapıya ya da veritabanına kimin eriştiğini (barındırma sağlayıcısı, şirket içi operatörler). |
| `incidents` | Dönemdeki güvenlik olayları önem ve duruma göre; bulgu içeren eklenti taramaları. | Olay farkındalığı ve ele alınan hacim. | Bir olayın kişisel veri ihlali olup olmadığını ya da bildirim yükümlülüklerinin (GDPR'da 72 saat, KVKK Kurul bildirimi) yerine getirilip getirilmediğini. |
| `ai_security_posture` | Bildirilen CVE bulguları öneme göre (farklı CVE'ler, doğrulanmış uygulanabilirlik, en yüksek CVSS), MCP sunucu bulguları tasdik durumu, taşıma ve risk kategorisine göre, beceri/eklenti bulguları risk türüne göre. | AI araç zincirinin açıklık yönetimi. | Taramaların tüm ortamınızda tam ya da güncel olduğunu. Yalnız yüklenen taramalar sayılır. |
| `data_flows` | Ürünün gizlilik veri akışı matrisi (amaç, hedef, bölge, alt işleyen, hukuki sebep, saklama, silme, aktarım aracı) SHA-256'sıyla, adı geçen alt işleyenlerin listesi ve açık bilinmeyenlerin sayısı. | İşleme faaliyetleri kaydınız ve aktarım değerlendirmeniz için girdi. | Gerçek kurulumunuzun akışlarını. `unknown` işaretli değerler her kurulumda tamamlanmalıdır; matris derleme sırasında `docs/production-readiness/privacy-data-flow-matrix.json` dosyasından gömülür. |
| `retention_deletion` | Veri sınıfı başına saklama günleri, yedeklerin kapsanıp kapsanmadığı, saklanan en eski telemetri olayı ve telemetri penceresi içinde olup olmadığı (1 gün tolerans), yasal saklama durumu ve sayıları (gerekçe yok), aşama makbuzları ve silinen satır sayılarıyla kiracı kapatma çalışmaları, oluşturulan, saklanan ve temizlenmeyi bekleyen denetim dışa aktarımları. | Saklama sınırlaması ve silme kanıtı. | Yedeklerden silmeyi (ayrı yönetilir) ya da her saklama işi çalışmasının makbuzunu (saklama işleri kurulum düzeyindedir; rapor etkisini gösterir). |

### Raporun kendisinde veri en aza indirme

Rapor hiçbir zaman istem ya da araç metni, eşleşen değerler, olay yükleri,
sayfa adresleri, DLP anahtar sözcükleri ya da düzenli ifadeler, politika
gövdeleri, yasal saklama referansları ya da gerekçeleri, API anahtarları ya da
belirteçler ve sahip/yönetici erişim listesi dışında üye e-posta adresleri
içermez. Bu üç kez zorlanır:

1. SQL fonksiyonu yalnız sayıları, sabit değerleri, sınırlı kimlikleri, zaman
   damgalarını ve SHA-256 özetlerini seçer.
2. Edge Function, SQL sonucunu bildirime dayalı bir şemadan
   (`COMPLIANCE_EVIDENCE_SPEC`) geçirir. Bilinmeyen alanlar atılır; kalıbına
   uymayan bir alan (örneğin URL'ye benzeyen bir site) raporun tamamını
   reddettirir.
3. Statik bir test yayımlanan şemayı dolaşır ve bir alan adı içerik
   çağrıştırıyorsa ya da açık bir izin listesi dışında serbest metin alanı
   varsa başarısız olur
   (`supabase/functions/__tests__/compliance-report-contract.test.ts`).

## Bütünlük: özet ve imza

`integrity.sha256`, raporun `integrity` üyesi **olmadan**
`aidr-canonical-json/v1` biçiminde serileştirilmiş hâlinin SHA-256 değeridir:

- nesne anahtarları her düzeyde UTF-16 kod birimlerine göre sıralanır; diziler
  sıralarını korur,
- anlamsız boşluk yoktur, standart JSON dize kaçışı, UTF-8 baytlar,
- `undefined` ve sonlu olmayan sayılar reddedilir.

Bu nedenle güzel yazdırma ya da anahtarların yeniden sıralanması özeti
değiştirmez; herhangi bir değerin değişmesi değiştirir.

Kurulumda bir imza anahtarı varsa `integrity.signature`, aynı kanonik baytlar
üzerinde bir **Ed25519** imzası taşır:

```json
{
  "algorithm": "ed25519",
  "key_id": "compliance-2026-09",
  "public_key_spki_b64": "<DER SubjectPublicKeyInfo, base64>",
  "signed_payload": "canonical_json_utf8",
  "value_b64": "<signature, base64>"
}
```

Anahtar yoksa rapor yalnız özetlidir (`signature: null`) ve panel bunu söyler.

### Raporu çevrimdışı doğrulama

```bash
aidr compliance verify report.json                                  # özet + gömülü anahtarla imza
aidr compliance verify report.json --public-key issuer.pem          # düzenleyeni de sabitler
aidr compliance verify report.json --public-key issuer.pem --require-signature --json
```

Çıkış kodları: `0` doğrulandı, `2` doğrulanamadı (içerik değişmiş, istenen imza
yok, geçersiz imza ya da `--public-key` dışında bir anahtarla imzalanmış), `1`
dosya ya da anahtar okunamadı. Komut tamamen çevrimdışı çalışır.

Her denetimin kanıtladığı:

- **Özet eşleşiyor**: JSON, özet hesaplandıktan sonra değişmemiştir. Tek başına
  yalnız kazara değişikliği yakalar: raporu düzenleyen herkes özeti yeniden
  hesaplayabilir.
- **Gömülü anahtarla imza geçerli**: içerik o anahtarın sahibi tarafından
  imzalanmıştır. Saldırgan düzenlediği raporu kendi anahtarıyla yeniden
  imzalayabilir; bu tek başına düzenleyeni tanımlamaz.
- **`--public-key` sabitlenmiş imza geçerli**: rapor operatörün imza
  anahtarının sahibi tarafından düzenlenmiş ve sonra değiştirilmemiştir.
  Denetçilerin kullanması gereken denetim budur. Açık anahtarı operatörden ayrı
  bir kanalla alın.
- **Düzenleme makbuzu**: yönetici denetim kaydındaki
  `compliance_report.generated` girdisi rapor kimliğini ve SHA-256'yı kaydeder;
  operatör, sunulan bir raporun gerçekten düzenlendiğini (örneğin Ekip denetim
  dışa aktarımıyla) teyit edebilir.

Geçerli bir imza, alttaki kayıtların eksiksiz ya da doğru olduğunu **kanıtlamaz**;
raporu kimin düzenlediğini ve sonradan değiştirilmediğini kanıtlar.

## İmza anahtarının işletilmesi

İmza anahtarı yetkilendirme (entitlement) anahtarıyla aynı biçimi kullanır; ancak
uyum raporları ve lisansların bağımsız döndürülebilmesi için **ayrı** bir
anahtar kullanın.

```bash
openssl genpkey -algorithm ed25519 -outform DER -out compliance-signing.der
base64 -w0 compliance-signing.der          # AIDR_COMPLIANCE_SIGNING_PRIVATE_KEY_PKCS8_B64
openssl pkey -inform DER -in compliance-signing.der -pubout -out compliance-signing.pub.pem
```

`compliance-report` fonksiyonunda hem `AIDR_COMPLIANCE_SIGNING_KEY_ID`
(örneğin `compliance-2026-09`) hem `AIDR_COMPLIANCE_SIGNING_PRIVATE_KEY_PKCS8_B64`
tanımlayın. Yalnız birinin tanımlanması yanlış yapılandırma olarak reddedilir
(HTTP 500 `server_misconfigured`); imzalayamayan bir anahtar imzasız rapor
yerine `compliance_signing_unavailable` döndürür. `compliance-signing.pub.pem`
dosyasını raporları doğrulayacak kişilere yayımlayın. Döndürmek için yeni bir
anahtar kimliği çıkarın; önceki anahtarla imzalanmış raporlar önceki açık
anahtarla doğrulanabilir kalır.

Şirket içi yapılandırma üreteçleri (`deploy/helm/generate-secrets.mjs`,
`deploy/onprem/.env.onprem.example`) bu anahtarı henüz oluşturmaz. İmzalı rapor
isteyen şirket içi operatörler iki değişkeni fonksiyon kapsayıcısında elle
tanımlar; bunlar olmadan raporlar yalnız özetlidir.

## Sınırlamalar

- Sayılar yalnız bu kontrol sunucusuna ulaşan telemetriyi kapsar. Çevrimdışı,
  yerel moddaki ve yönetilmeyen uç noktalar temsil edilmez.
- Çalışma alanının saklama penceresinden eski telemetri silinmiştir; bu yüzden
  eski dönemlerin sayıları gerçekte olandan düşük olabilir.
- Veri akışı ve alt işleyen envanteri ürünün mühendislik matrisidir; `unknown`
  işaretli değerler kurulumunuz için tamamlanmalıdır.
- Saklama işi çalışmaları kurulum düzeyindeki işlemlerdir; rapor çalışma başına
  makbuzu değil, etkisini (saklanan en eski telemetri) gösterir.
- Yedekler canlı veri silme makbuzlarının dışındadır.
- CSV ve yazdırılabilir sürümler tarayıcıda türetilen kolaylıklardır; yalnız JSON
  özetlenir ve imzalanır.
- Yazdırılabilir Türkçe sürüm etiketleri, beyanı ve sabit sınırlamaları çevirir;
  veri akışı açıklamaları İngilizce mühendislik matrisinden gelir.

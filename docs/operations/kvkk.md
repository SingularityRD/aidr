# KVKK rehberi — Singularity AIDR işleten kurumlar için

Bu rehber, Singularity AIDR'ı kendi kurumunda işleten BT ve güvenlik
yöneticileri ile veri koruma sorumlusu (DPO) içindir. Hangi bileşenin hangi
kişisel veriyi nerede tuttuğunu, saklama sürelerinin nasıl ayarlanacağını,
VERBİS kaydına ne yazılacağını, yurt dışına aktarımın ne zaman doğduğunu ve bir
veri koruma etki değerlendirmesinin (VKED / DPIA) nasıl yapılacağını anlatır.

> Bu rehber hukuki görüş değildir. Kurumunuzun hukuk birimi ve veri koruma
> sorumlusu kararları verir. Yazılımı kuran kurum veri sorumlusudur;
> SingularityRD yalnız barındırılan hizmette ve destek taleplerinde veri
> işleyendir ([Veri İşleme Sözleşmesi taslağı](../legal/dpa.tr.md)).
> Ürün KVKK uyumunu "destekleyecek şekilde tasarlanmıştır"; kullanmak kurumu
> kendiliğinden uyumlu yapmaz.

İlgili belgeler: [çalışan aydınlatma metni şablonu](../legal/kvkk-aydinlatma-metni-calisan.tr.md),
[gizlilik ve veri akışı (EN)](../privacy.md) / [TR](../privacy.tr.md),
[uyum kanıt raporu](../compliance-report.tr.md),
[veri yerleşimi](../deployment/data-residency.md).

## 1. Veri envanteri (bileşen bazında)

"Varsayılan" sütunu, ayar değiştirilmeden ne olduğunu söyler. Uç noktada
varsayılan mod `local`'dır: tespit ağ erişimi olmadan yapılır ve hiçbir şey
gönderilmez.

### 1.1 Uç nokta (komut satırı aracı ve ajan bağlayıcıları)

| Veri | Konum | Varsayılan | İçerik | Kişisel veri mi? |
|---|---|---|---|---|
| Yerel denetim kaydı | `~/.singularity-aidr/audit.jsonl` (+3 dönmüş kopya) | Açık, 5 MiB × (1+3) | Zaman, araç adı, karar, eşleşen kural, araç girdisi özeti (komut, yol, URL) **açık metin** | Evet: kullanıcı hesabına bağlı işlem kaydı; komut ve yollarda ad, e-posta, müşteri bilgisi geçebilir |
| İmzalı karar zinciri | `audit.jsonl` kayıtlarında `_chain` alanı | Yerel modda kapalı, yönetilen modda açık | Aynı kayıtların SHA-256 zinciri ve Ed25519 imzası | Evet |
| İmzalı yanıt zinciri | `~/.singularity-aidr/response-audit.jsonl` | Kapalı (`response.audit.signed_chain`) | Karantina ve yanıt eylemleri, Ed25519 imzalı | Evet |
| Karantina kasası | `~/.singularity-aidr/quarantine` | Kapalı (`response.quarantine`); açılırsa 30 gün | Zararlı bulunan dosyanın kendisi | Dosyaya bağlı |
| Kurulum kimliği | `~/.singularity-aidr/installation-id` | Açık | Rastgele UUID | Dolaylı (cihaz/kullanıcıyla eşleştirilebilir) |
| Onay deposu | `~/.singularity-aidr/approvals.json`, anahtar işletim sistemi kasasında | Açık | Bekleyen ve verilmiş onaylar | Evet |
| Telemetri kuyruğu | Uç noktada kalıcı kuyruk | Yalnız yönetilen mod | Gönderilecek olaylar (aşağıdaki biçimde) | Evet |

Yerel kayıtlar kullanıcının ev dizinindedir ve dosya izinleriyle korunur;
aynı kullanıcıyla çalışan programlar okuyabilir. Kaldırırken
`aidr uninstall` bu dizini siler (`--keep-data` ile korunur).

### 1.2 Uç noktadan kontrol sunucusuna giden olaylar (yönetilen mod)

| Alan | Gönderilir mi | Not |
|---|---|---|
| Kurulum/ajan kimliği, sürüm, işletim sistemi | Evet | |
| Karar, kural kimliği, zaman, araç adı | Evet | `allow` kararları varsayılan gönderilmez (`send_clean_verdicts: false`) |
| Araç özeti ve eserler (komut, yol, URL) | **SHA-256 özeti** | `redact_mode: hash` (varsayılan). `full` hiç göndermez; `none` yalnız hata ayıklama içindir ve üretimde kullanılmamalıdır |
| Kimlik bilgileri (anahtar, belirteç, parola) | Hayır | Her modda zorunlu temizlik |
| Kaynak kod, dosya içeriği, tam istem | Hayır | |

### 1.3 Browser Guard (tarayıcı eklentisi)

| Veri | Konum | Not |
|---|---|---|
| Maskeleme eşleştirmesi (yer tutucu ↔ gerçek değer) | Yalnız sekmenin belleği | Diske yazılmaz, gönderilmez, sayfa yenilenince silinir |
| Sayaç telemetrisi | Kontrol sunucusu (`privacy_scan` olayları) | Yalnız `controlPlaneUrl` + anahtar verilirse; site, eylem, kanal ve tür başına sayı. İstem metni, değer, sayfa adresi yok ([sözleşme](../contracts/privacy-telemetry.md)) |
| Yapay zekâ sağlayıcısına giden istem | Sağlayıcı (OpenAI, Google, Anthropic…) | Tespit edilen değerler yer tutucuyla değişmiş hâlde. Tespit edilemeyen veri olduğu gibi gider. Bu aktarım kurumun kendi aktarımıdır (bkz. §4) |

### 1.4 Kontrol sunucusu (şirket içi ya da barındırılan)

Saklama sınıfları veritabanındaki `retention_policy_bounds` tablosuyla
yönetilir; panelde **Saklama** sayfasından ayarlanır (yalnız sahip).

| Saklama sınıfı | İçerik | Alt / üst sınır (gün) | Kiracı ayarlayabilir mi |
|---|---|---|---|
| `telemetry` | Uç nokta karar olayları, Browser Guard sayaçları, olaylar (incident) | 7 / 3650 | Evet (edisyon üst sınırı uygulanır) |
| `endpoint_identity` | Kayıtlı cihazlar, kurulum kimlikleri | 30 / 3650 | Evet |
| `security_intelligence` | Keşif, duruş tarama sonuçları | 7 / 3650 | Evet |
| `policy_configuration` | Politika sürümleri, onaylar, istisnalar | 30 / 3650 | Evet |
| `identity_membership` | Kullanıcılar, üyelikler, davetler, SCIM kayıtları | 30 / 3650 | Evet |
| `security_audit` | Yönetici denetim kayıtları | 365 / 3650 | Evet |
| `commercial_records` | Lisans, sipariş, fatura kayıtları | 2555 / 3650 | Evet |
| `temporary_exports` | Dışa aktarma dosyaları | 0 | Hayır (platform) |
| `access_credentials` | Geçici kimlik bilgileri | 0 | Hayır (platform) |
| `operational_ephemera` | Geçici işletim kayıtları | 0 / 7 | Hayır (platform) |

Yasal saklama (legal hold) konulan kiracıda olağan silme durur. Kiracı
kapatma (offboarding) verileri kayıtlı yetkiyle siler.

### 1.5 Diğer bileşenler

| Bileşen | Kişisel veri | Not |
|---|---|---|
| Yedekler | Veritabanının tamamı | Şifreli; saklama ve silme yedek hedefinin politikasına bağlıdır. Silinen kayıt, yedek süresi dolana kadar yedekte kalır; bunu aydınlatma metninde ve VERBİS'te yazın |
| SIEM iletimi | `aidr.siem.event/v1` olayları | Hedef kurumun SIEM'idir; SIEM'in saklama süresi geçerlidir |
| Destek paketi | İzin listeli tanılama özeti | Kişisel veri dışlanacak şekilde tasarlanmıştır; yalnız onaylı talepte paylaşılır ([prosedür](../runbooks/support-bundle.md)) |
| AI güvenlik duruşu tarayıcısı | Tarama hedefleri ve sonuçları | Hedef adreslerde kişisel veri olabilir; ayrı birimlerde tutulur, AIDR yedeğine girmez |
| E-posta (davet, kurtarma, uyarı) | Alıcı e-posta adresi | Şirket içinde kurumun SMTP sunucusu; barındırılanda e-posta sağlayıcısı (alt işleyen) |
| Kimlik sağlayıcı (SAML/OIDC/SCIM) | Kullanıcı ve grup kimlikleri | IdP kurumun kendi sistemidir |

## 2. Saklama ön ayarları

Aşağıdaki üç ön ayar başlangıç önerisidir; hukuki zorunluluk değildir. Kurumun
saklama ve imha politikasıyla (Kişisel Verilerin Silinmesi, Yok Edilmesi veya
Anonim Hale Getirilmesi Hakkında Yönetmelik) uyumlu olanı seçip **Saklama**
sayfasından sınıf sınıf girin; her değişiklik yönetici denetim kaydına yazılır.

| Sınıf | **Asgari** (veri en aza indirme önce) | **Dengeli** (önerilen başlangıç) | **Denetim** (kamu, finans, savunma) |
|---|---|---|---|
| `telemetry` | 30 | 90 | 365 |
| `endpoint_identity` | 90 | 180 | 730 |
| `security_intelligence` | 30 | 90 | 365 |
| `policy_configuration` | 365 | 730 | 1825 |
| `identity_membership` | 90 | 365 | 730 |
| `security_audit` | 365 | 730 | 1825 |
| `commercial_records` | 2555 | 2555 | 3650 |

Edisyon üst sınırı `telemetry` için geçerlidir (ör. Business 365 gün); daha uzun
süre Enterprise sözleşmesiyle verilir.

Uç nokta için aynı ön ayarlar:

| Ayar | Asgari | Dengeli | Denetim |
|---|---|---|---|
| `logging.max_bytes` × (`max_files` + 1) | 1 MiB × 2 | 5 MiB × 4 (varsayılan) | 20 MiB × 6 |
| `logging.log_clean` | `false` | `false` | `false` (izin kararlarını kaydetmek hacmi çok artırır) |
| `control_plane.redact_mode` | `full` | `hash` (varsayılan) | `hash` |
| `control_plane.send_clean_verdicts` | `false` | `false` | `false` |
| `audit.signed_chain` (imzalı karar zinciri) | kapalı | yerel modda kapalı, yönetilen modda açık (varsayılan) | açık |
| `response.audit.retention_days` (imzalı yanıt zinciri) | 90 | 365 | 0 (süresiz; merkezi arşive aktarın) |

Yerel kayıt boyuta göre döner, süreye göre değil: düşük kullanımlı bir
makinede kayıtlar uzun süre kalabilir. Merkezi saklama süresi kesin olması
gereken kurumlarda kayıtların SIEM'e iletilmesi ve yerel kaydın küçük tutulması
önerilir.

## 3. VERBİS

VERBİS'e kayıt yükümlülüğü ve muafiyet eşikleri (çalışan sayısı ve yıllık mali
bilanço toplamı) Kişisel Verileri Koruma Kurulu kararlarıyla belirlenir; güncel
eşiği Kurumun sitesinden teyit edin. Kayıt yükümlüsü bir kurum AIDR'ı devreye
aldığında envanterini aşağıdaki gibi günceller:

| VERBİS alanı | AIDR için önerilen giriş |
|---|---|
| İşleme amacı | Bilgi güvenliği süreçlerinin yürütülmesi; Yetkisiz erişim ve veri sızıntısının önlenmesi (kurumun amaç listesindeki karşılığı) |
| Veri konusu kişi grubu | Çalışan; [Stajyer]; [Yüklenici / dış kaynak çalışanı] |
| Veri kategorisi | Kimlik (ad, kullanıcı kimliği); İletişim (e-posta); İşlem Güvenliği (cihaz ve kurulum kimliği, karar ve denetim kayıtları, oturum kayıtları) |
| Hukuki sebep | KVKK 5/2-ç (veri güvenliği yükümlülüğü), 5/2-f (meşru menfaat) — hukuk birimi teyit eder |
| Alıcı / alıcı grubu | Kurum içi yetkili birimler (BT, bilgi güvenliği, SOC); yetkili kamu kurumları; [barındırılan hizmette: veri işleyen SingularityRD ve alt işleyenleri] |
| Yabancı ülkelere aktarım | Şirket içi kurulum (Türkiye): **yok**. Barındırılan hizmet: **var** (bkz. §4). Browser Guard açık olsa da yapay zekâ sohbet hizmetine yapılan aktarım AIDR'ın değil, o hizmeti kullanma kararının sonucudur ve ayrı bir faaliyet olarak değerlendirilir |
| Saklama süresi | §2'de seçilen ön ayarın süreleri; yedeklerin ek saklama süresi |
| İdari ve teknik tedbirler | Erişim yetki matrisi, rol bazlı erişim, log kayıtları, veri maskeleme, şifreleme (aktarımda TLS, yedek şifreleme), kimlik doğrulama (SSO/MFA), saldırı tespit ve önleme, sızma testi [yalnız yapıldıysa işaretleyin] |

SingularityRD kendi VERBİS kaydında, barındırılan hizmet için veri işleyen
sıfatıyla ayrıca yer almaz (VERBİS veri sorumlusu kaydıdır); kendi müşteri
iletişim verileri için kendi kaydını tutar.

## 4. Yurt dışına aktarım

KVKK madde 9 (7499 sayılı Kanunla 1 Haziran 2024'ten itibaren değişen hâliyle)
aktarımı yeterlilik kararı, uygun güvenceler (ör. Kurulun standart sözleşmesi;
imzadan sonra 5 iş günü içinde Kurula bildirim) ya da arızi aktarım hâllerine
bağlar.

| Kurulum | Yurt dışına aktarım | Ne yapılmalı |
|---|---|---|
| Kontrol sunucusu kurumun Türkiye'deki sunucusunda (şirket içi / internetsiz) | AIDR'dan kaynaklı **yok**, şu koşullarla: yedek hedefi, SMTP, SIEM ve IdP de yurt içinde; isteğe bağlı itibar sorguları ve Sentry kapalı | Çıkış trafiğini ([çıkış listesi](../../deploy/onprem/README.md)) bu koşullara göre kısıtlayın ve bir kez paket yakalamasıyla doğrulayın |
| Barındırılan kontrol sunucusu | **Var.** Pilot projenin birincil bölgesi `eu-central-1` (Frankfurt); istek iletimi Cloudflare üzerinden | DPA + standart sözleşme ve Kurula bildirim; alt işleyen listesi [DPA Ek-3](../legal/dpa.tr.md) |
| İsteğe bağlı URL / dosya / paket itibarı | Yapılandırılan uç noktaya bağlı | Varsayılan kapalı; açılacaksa hedefin yeri belirlenmeli |
| Destek paketi | Paylaşım kanalına bağlı | Paket kişisel veri dışlanarak tasarlanmıştır; yine de kanal yurt içinde seçilebilir |

Ayrıntı ve barındırılan hizmetin bilinen bölge bilgileri:
[veri yerleşimi](../deployment/data-residency.md).

## 5. Çalışanların bilgilendirilmesi

- Doldurulmuş [aydınlatma metnini](../legal/kvkk-aydinlatma-metni-calisan.tr.md)
  kurum içinde yayımlayın ve adresini makine politikasındaki
  `privacy_notice_url` anahtarına yazın; `support_contact_url` anahtarına da
  yanlış engelleme itirazlarının gideceği adresi yazın.
- Duyurunun yapıldığını kayda geçirin. Aydınlatma açık rıza değildir; açık rıza
  istemeyin (işleme açık rızaya dayanmıyorsa rıza istemek yanıltıcıdır).
- Engelleme mesajı nedeni ve kural kimliğini gösterir; bu, otomatik karara
  itiraz hakkının (KVKK 11/1-g) pratik karşılığıdır. İtirazları bir kişinin
  incelediğinden emin olun.

## 6. İlgili kişi başvuruları

| Talep | Nasıl karşılanır |
|---|---|
| Hakkımda ne işleniyor? | Panelde kişinin cihazları (Ajanlar), olaylar ve onay kayıtları; **Denetim dışa aktarımı** ile JSONL/CSV |
| Silinmesini istiyorum | Saklama süresi dolmamış ve yasal saklama yoksa: kullanıcıyı kaldırın (SCIM ya da panel), cihazlarını iptal edin ([işten ayrılma runbook'u](../runbooks/offboarding-and-device-swap.md)), yerel kayıt için `aidr uninstall` |
| Yerel kayıtlar | Kişinin bilgisayarındadır; kurum BT'si erişir. Merkezi kopya `hash` modunda özet içerir; özetten değer geri elde edilemez ama bilinen bir değerle eşleştirilebilir, bu nedenle hâlâ kişisel veri sayılabilir |

## 7. Veri koruma etki değerlendirmesi (VKED / DPIA) şablonu

KVKK açıkça VKED istemez; GDPR madde 35 belirli hâllerde ister ve birçok kurum
iç politika gereği yapar. Aşağıdaki şablonu doldurup DPO onayına sunun.

```text
VKED — Singularity AIDR                        Sürüm: [ ]   Tarih: [ ]
Hazırlayan: [ ]   DPO: [ ]   Sistem sahibi: [ ]

1. İşlemenin tanımı
   - Amaç: yapay zekâ araçlarının komut, dosya ve web isteklerini güvenlik
     açısından değerlendirmek; tarayıcıdan AI sohbetlerine kişisel veri
     sızıntısını azaltmak.
   - Kapsam: [N] çalışan, [N] cihaz, bileşenler: [CLI/bağlayıcılar, Browser
     Guard, MCP gateway, kontrol sunucusu, SIEM iletimi].
   - Kurulum: [şirket içi / internetsiz / barındırılan]; mod: [yerel / yönetilen].
   - Veri akışı: §1'deki tablolardan açık olan satırlar + şema
     (docs/security/whitepaper.md, "Veri akışı").

2. Gereklilik ve orantılılık
   - Hukuki sebep: [5/2-ç, 5/2-f]; meşru menfaat dengesi testi: [ ].
   - En aza indirme: redact_mode=[hash/full]; send_clean_verdicts=[false];
     Browser Guard telemetrisi=[kapalı/sayaç]; saklama ön ayarı=[ ].
   - Daha az müdahaleci seçenek değerlendirildi mi? (ör. yalnız yerel mod,
     merkezi telemetri yok): [ ].
   - Aydınlatma: [yayın tarihi, privacy_notice_url].

3. Riskler (olasılık × etki: düşük/orta/yüksek)
   R1 Yerel denetim kaydında açık metin komut ve yollar (aynı kullanıcıyla
      çalışan program okuyabilir)                       [ ] [ ]
   R2 Merkezi kayıtlarla çalışan davranışının izlenmesi (amaç dışı kullanım)
                                                       [ ] [ ]
   R3 Yetkisiz yönetici erişimi / rol aşımı             [ ] [ ]
   R4 Yedeklerde silinmiş verinin kalması               [ ] [ ]
   R5 Barındırılan hizmette yurt dışına aktarım          [ ] [ ]
   R6 Browser Guard'ın tespit edemediği kişisel verinin AI sağlayıcısına
      gitmesi                                          [ ] [ ]
   R7 Yanlış engelleme ile işin aksaması (otomatik karar)[ ] [ ]
   R8 Destek talebinde fazla veri paylaşımı              [ ] [ ]

4. Tedbirler (risk → tedbir → sahibi → tarih)
   R1 → yerel kayıt boyutu küçük (Asgari ön ayar), disk şifreleme, SIEM'e
        iletim
   R2 → amaç sınırlaması politikası; SOC dışında olay erişimi yok; yönetici
        işlemlerinin denetim kaydı ve üç ayda bir gözden geçirme
   R3 → SSO + MFA, rol matrisi, SCIM ile işten çıkışta otomatik kaldırma
   R4 → yedek saklama süresi yazılı; aydınlatma metninde belirtildi
   R5 → şirket içi kurulum ya da standart sözleşme + Kurula bildirim
   R6 → özel terimler / exact-data-match veri kümeleri; block modu; kullanıcı
        eğitimi; tespit oranı ölçülmedi, bu bir sınırlamadır
   R7 → itiraz kanalı (support_contact_url), kişi incelemesi, istisna süreci
   R8 → yalnız onaylı destek paketi; ek veri ayrı onayla

5. Kalan risk ve karar
   Kalan risk: [kabul edilebilir / değil]   Kurula danışma gerekli mi: [ ]
   DPO görüşü: [ ]   Onay: [ad, unvan, tarih]   Gözden geçirme tarihi: [ ]
```

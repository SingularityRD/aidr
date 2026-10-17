# Özellik envanteri ve işlevsel doğrulama (17 Ekim 2026)

Bu belge, [FEATURE_INVENTORY.json](../../FEATURE_INVENTORY.json) içindeki 110 özelliğin
**gerçekten çalıştırılarak** doğrulanmasının sonucudur. Envanterdeki `wired / partial /
external` etiketleri kaydın kendi beyanıdır; burada her özellik bir müşteri ya da yöneticinin
kullanacağı şekilde çalıştırıldı ve sonuç dört sınıftan birine ayrıldı:

- **ÇALIŞIYOR**: çalıştırıldı, belgelenen davranış gözlendi.
- **DÜZELTİLDİ**: çalıştırılırken hata bulundu; kök neden düzeltildi ve hatayı yakalayan bir
  regresyon testi eklendi.
- **AÇIK**: hata ya da eksik var, bu çalışmada kapatılmadı (nedeni yazılı).
- **BURADA DOĞRULANAMAZ**: gereken ortam yok (Windows/macOS makinesi, canlı IdP/SIEM/ödeme
  sağlayıcısı, Docker, Kubernetes kümesi, IPv6). Birim ve sözleşme testleri bu durumda da geçer.

Doğrulama ortamı: Linux x64, Node 22, PostgreSQL 16 (bütün migration zinciri, 210 migration),
PostgREST 12, 59 Edge Function'ın gerçek kodu, Chromium 141 (başsız), gerçek Claude Code
2.1.302 / Codex 0.141.0 / OpenCode 1.18.32 / OpenClaw 2026.9.6 binary'leri ve betikli bir
mock model. Dal: `claude/fervent-babbage-c2h8zd`.

## Özet

| Alan | Özellik | Çalışıyor | Düzeltildi | Açık | Burada doğrulanamaz |
|---|---|---|---|---|---|
| Tespit (DET) | 20 | 20 ¹ | 2 | 1 ² | — |
| MCP | 7 | 6 | — | — | 1 |
| AI altyapısı (INF) | 6 | 5 | — | — | 1 |
| Müdahale (RSP) | 9 | 5 | — | 1 | 3 |
| Politika (POL) | 6 | 3 | — | — | 3 |
| Uç nokta / CLI | 6 | 6 | 3 | — | — |
| Bağlayıcılar (CON) | 7 | 7 | 1 | 1 ³ | — |
| Yönetim (TEN) | 9 | 9 | 2 | — | — |
| Operasyon (OBS) | 9 | 8 | 1 | 1 ⁴ | — |
| Yönetişim (GOV) | 3 | 3 | — | — | — |
| Ticari (BIL) | 4 | 4 | 1 | — | — |
| Dağıtım (DEP) | 12 | 12 | 1 | — | kısmen ⁵ |
| Güvence (EVAL) | 3 | — | — | — | 3 (kod dışı) |
| Tarayıcı gizliliği (PRV) | 9 | 9 | 1 | — | kısmen ⁶ |

¹ Tespit kuralları ayrı bir uçtan uca denetimle değil; tam test paketi (13.955 test),
`aidr simulate` korpusu (93/93 tespit, 0/46 yanlış alarm) ve gerçek host senaryolarıyla
doğrulandı. ² Kapsam boşlukları (aşağıda). ³ SDK kapsamı (CON-06). ⁴ Offboarding silme
boşlukları (OBS-06). ⁵ Docker/Kubernetes/root gerektiren adımlar. ⁶ Canlı AI siteleri ve
Windows OCR.

## Alan alan sonuçlar

### Tespit (DET-01…20)

Hepsi tam test paketiyle ve gerçek host senaryolarıyla çalışıyor. Bu çalışmada düzeltilenler:

- **DET-06 / DET-16**: "developer mode" jailbreak kalıbı kuraldan tamamen düşmüştü; bağlama
  duyarlı olarak geri eklendi. Ajanın yazdığı içerik için tanınan talimat/hafıza yüzeyleri
  (`.windsurf`, `.kiro`, `.github/instructions`, `SKILL.md`, `.claude/memory` …) genişletildi.
- **DET-18**: test beklentileri 15 Ekim yanlış-pozitif kararıyla uyumlu hale getirildi.

**Açık:** betik dili tek satırlıkları, indir-çalıştır kalıpları ve Windows yolları için kapsam
boşlukları uç nokta denetiminde raporlandı; tespit ekibinin kendi korpusuyla ele alması
gerekiyor.

### MCP (MCP-01…07) ve AI altyapısı (INF-01…06)

Yerel bir test MCP sunucusu ve imzalı yayıncı manifestiyle gerçek gateway çalıştırıldı:
keşif, politika listeleri, araç seti karantinası ve operatör onayı, drift tespiti, çıktı
engelleme (`output_blocked`, `arguments_blocked`) ve 189 gateway testi geçti. `discover`,
`scan`, `aibom` (CycloneDX 1.6, sırlar maskeli, dosya 0600) çalışıyor.
Burada doğrulanamaz: MCP-06 (kimlik sağlayıcı), INF-03 (bulut IAM/MDM).

### Müdahale (RSP-01…09) ve Politika (POL-01…06)

Çalışıyor: bekleyen eylem → onay → tam bir tekrar (OpenCode, OpenClaw); karantina ve serbest
bırakma; anlık görüntü ve geri yükleme; imzalı müdahale zinciri (`aidr audit verify`, tek bayt
değişince FAILED); dosya sistemi/ağ/kabuk/MCP politika kuralları; YAML politika derleme ve
doğrulama; izin profilleri.

**Açık:** RSP-04 (süreç sınırlama) yalnızca kütüphane kodu; hiçbir bağlayıcı ya da CLI komutu
ona bağlı değil, müşteri erişemiyor.
Burada doğrulanamaz: RSP-06/07/09 ve POL-03/04/05 (Windows ya da canlı kontrol düzlemi).

### Uç nokta / CLI (CLI-01…06)

Önceki QA turunda düzeltilenler: audit log'da açık metin sır (`AWS_SECRET_ACCESS_KEY`
biçimleri), yeni kurulmuş Claude Code'un algılanmaması, kopuk Codex hook'unun "sağlıklı"
görünmesi ve göreli yol ile kaydedilmesi, `status`/`doctor` raporlaması, `config --yes`,
bilinmeyen kural ID'si kabulü, Türkçe çeviri eksikleri. Bu turda: `config` listeleri
`[object]` yerine değerleriyle gösteriliyor; karantina ve imzalı zinciri açmak artık
"korumayı zayıflatan değişiklik" sayılmıyor.

### Bağlayıcılar (CON-01…07)

Gerçek Claude Code, Codex, OpenCode ve OpenClaw binary'lerinde bütün senaryolar geçti.
Düzeltilen: çöken hook Linux/macOS kayıtlarında artık komutu blokluyor (gerçek host'ta
kanıtlandı). **Açık:** SDK (CON-06) bağlayıcıların ortak değerlendiricisini kullanmıyor;
aynı test korpusunda SDK 98 vakadan 14'üne izin verirken Claude Code hook'u 1'ine izin
veriyor. README düzeltildi; kapatmak için SDK'nın çekirdek değerlendiriciye bağlanması gerekir.

### Yönetim (TEN-01…09), Operasyon (OBS-01…09), Yönetişim (GOV), Ticari (BIL)

Tam migration zinciri, PostgREST, 59 gerçek Edge Function ve başsız Chromium'da dashboard ile
owner, admin, member, auditor ve platform operatörü rolleri EN ve TR olarak tıklandı;
27 Postgres suite'i ve `ci.yml`'nin 50 Postgres kapısı geçti. Bu turda düzeltilenler:

- **BIL-04 / TEN-08**: operatör ya da imzalı içe aktarma ile verilen lisans müşteri planını
  güncellemiyordu; Business/Enterprise lisanslı tenant Free kalıyor, SIEM/SCIM reddediliyor ve
  telemetri 7 güne sınırlanıyordu.
- **TEN-09 / GOV-03**: auditor rolü ayarlar ve varlık kaydı önizlemesinde 403 alıyordu.
- **OBS-03**: legal hold yüzünden reddedilen audit dışa aktarımı nedenini söylemiyordu.
- **Dashboard**: `/operator` sayfası geliştirme modunda takılı kalıyordu; faturalama hataları
  Türkçe arayüzde İngilizce görünüyordu.

Önceki turlarda düzeltilenler: fleet cihaz anahtarlarının bir yöneticiye bağlı olması, kayıt
token'larını bozan trigger, SIEM'e admin işlemlerinin gitmemesi, kuyruğa yazılamayan olayların
kaybolması, saklama süresinin yok sayılması, auditor rolü ve tarih aralıklı dışa aktarım.

**Açık (OBS-06):** tenant offboarding'de 4 tablonun (`false_positive_reports`,
`license_imports`, `agent_retirement_settings`, `fleet_enrollment_keys`) silme yolu yok;
düzeltmesi bu raporla birlikte yapılıyor.

### Dağıtım (DEP-01…12) ve yaşam döngüsü

Çalışıyor: CLI kurulum/durum/doğrulama/kaldırma (tarball, yetkisiz kullanıcı), SEA derleme ve
imzalama, deb ve tarball paketleri, masaüstü runtime hazırlama, Unix fleet betikleri (20/20),
self-hosted ve bulut hazırlama, 210 migration'lık yükseltme ve kurcalanmış migration'ın
reddi, sürüm imzalama (61 test), lisans verme/doğrulama/süre/iptal, intel paketi
oluşturma→imzalama→içe aktarma, indirme merkezi manifesti, Helm chart (53 kontrol, k8s
1.25/1.30 şema). Düzeltilen: genel `.rpm` paketi hiç üretilemiyordu.

Burada doğrulanamaz: `docker compose up`, duman testi, yedekleme/geri yükleme tatbikatı,
`helm install`, kök gerektiren makine politikası yazımı, canlı kayıt ve `aidr update`.

**Yaşam döngüsünde tamamen eksik olanlar:**

- İmzalı bir test kataloğu ya da sürüm paketi üreten araç yok; operatör `aidr update`'i
  gerçek sürüm anahtarı olmadan bir aynaya karşı prova edemiyor.
- Sunucu tarafı için bir on-prem kaldırma/hizmetten çıkarma betiği yok (yalnızca tenant
  offboarding var).
- Kaydı uçtan uca prova eden tek araç Docker tabanlı duman testi.

### Tarayıcı gizliliği (PRV-01…09)

Browser Guard, Chromium'da 8 AI sitesi fikstürüne karşı 52 senaryonun 49'unu geçti (0 hata;
3'ü yerel yardımcı ya da Windows gerektirdiği için atlandı). Maskeleme ve geri yükleme,
yapıştırma/dosya temizleme, tam veri eşleme, yönetilen politika, yalnızca sayı içeren
telemetri (ham değer sızmadığı doğrulandı), gölge AI ve kabul edilebilir kullanım bildirimi
çalışıyor; popup ve ayarlar sayfaları EN/TR. Düzeltilen: gizlilik denetim kayıtları motor
sürümünü 0.6.0 yerine 0.5.0-rc.1 yazıyordu. Burada doğrulanamaz: canlı siteler, Windows OCR.

## Kod dışı kapılar

Bu belge bir kapıyı kapatmaz. İmzalı ilk sürüm, kod imzalama sertifikası, mağaza hesabı,
bağımsız pentest, hukuk onayları (EULA, DPA, KVKK), SLA ve müşteri PoV kaydı
[SALES-READINESS-GAPS-2026-10-15.md](SALES-READINESS-GAPS-2026-10-15.md) içinde açık olarak
kalır.

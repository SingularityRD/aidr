# POC kiti — Singularity AIDR kavram kanıtlama (30 gün)

> **TASLAK — iş onayı gerekir.** Ürün sürüm kararı hâlâ **NO-GO**'dur
> ([ilk müşteri hazırlığı](../production-readiness/first-customer-ready.md)).
> İmzalı bir müşteri sürümü ve yayımlanmış lisans anahtarı olmadan POC
> başlatılmaz; bu kit o gün için hazırdır. POC ücretsizdir, üretim kullanımı
> için değildir ve destek "makul çaba" ile verilir
> ([SLA taslağı](../legal/sla.tr.md) §6). Son güncelleme: 14.10.2026 ·
> Sahibi: Satış + Çözüm mühendisi.

Bu kit, müşteriyle ilk görüşmeden POC kapanışına (ücretliye çevirme ya da
temiz kaldırma) kadar her adımı içerir. Müşteriye giden bölümler **[Müşteriye]**
etiketlidir.

## 1. POC'ye girmeden önce (eleme)

- [ ] Müşteri [ideal müşteri profiline](ideal-customer-profile.md) uyuyor:
      yapay zekâ kodlama araçları kullanılıyor ya da kullanılması planlanıyor.
- [ ] Kullanılan araçlar ve sürümleri [uyumluluk matrisinde](../compatibility-matrix.md)
      gerçek ortam kaydı olanlar arasında. Cursor / VS Code önizlemedir
      (önizleme — henüz gerçek ortam kabul kanıtı yok); POC başarı kriterine
      yalnız açık uyarıyla girer.
- [ ] Uç noktalar Windows 10/11 x64 ya da desteklenen Linux; macOS POC
      kapsamında değildir.
- [ ] Müşteride bir sponsor (BT/güvenlik yöneticisi) ve bir teknik sorumlu var;
      ikisi de kickoff'a katılacak.
- [ ] Kurulum türü seçildi: (a) yalnız yerel mod, (b) şirket içi kontrol
      sunucusu, (c) internetsiz. Barındırılan hizmet bugün müşteri kullanımı
      için kabul edilmediğinden POC'de kullanılmaz.

## 2. Kapsam **[Müşteriye]**

| Kalem | POC'de | Not |
|---|---|---|
| Uç nokta sayısı | En fazla [25] cihaz / kişi | Daha fazlası ücretli POC (`AIDR-SVC-POC`) |
| Bileşenler | CLI + ajan bağlayıcıları; isteğe bağlı Browser Guard | MCP gateway ve AI güvenlik duruşu tarayıcısı ayrıca istenirse |
| Kontrol sunucusu | Müşterinin bir Linux sanal makinesinde, `small` profil | [On-prem runbook](../operations/onprem-runbook.md); 4 vCPU, 8 GiB RAM, 100 GiB SSD |
| Kimlik | Yerel hesaplar; isteğe bağlı bir SSO (Entra ID / SAML) testi | |
| Entegrasyon | İsteğe bağlı: bir SIEM'e (Splunk / Sentinel / Elastic / syslog) olay iletimi | |
| Veri | Gerçek geliştirici iş akışı; Browser Guard testinde **yalnız sentetik kişisel veri** | Gerçek müşteri kişisel verisiyle maskeleme testi yapılmaz |
| Süre | 30 gün, kickoff'tan itibaren | En fazla bir kez [15] gün uzatma, yazılı |
| Dışında kalanlar | Yük testi, sızma testi, üretim SLA'sı, macOS, barındırılan hizmet | |

## 3. Başarı kriterleri **[Müşteriye]**

Kickoff'ta müşteriyle birlikte seçilir ve yazılı onaylanır. Her kriterin ölçüm
yöntemi önceden bellidir; "iyi hissettirdi" kriter değildir.

| # | Kriter | Ölçüm | Hedef (müşteriyle) |
|---|---|---|---|
| K1 | Kurulum | Kontrol sunucusu kurulumu + ilk 5 uç nokta kaydı | [1] iş günü içinde, `deployment-doctor` ve `aidr doctor` yeşil |
| K2 | Koruma çalışıyor | Her uç noktada `aidr verify` / `aidr canary` geçti | %100 cihaz |
| K3 | Tehdit senaryoları | [Müşteri tehdit demo matrisi](../demo/customer-threat-demo-matrix.md)'nden seçilen [N] senaryo, sentetik ortamda | Seçilen senaryoların hepsi beklenen kararı verir (deny / ask) |
| K4 | Yanlış pozitif | 2 hafta gerçek kullanımda geliştiricinin işini durduran yanlış engelleme sayısı | ≤ [__] / geliştirici / hafta; her biri için dar istisna ile çözüm |
| K5 | Gecikme | Araç çağrısı başına ek süre (`aidr status` / ölçüm betiği) | p95 ≤ [__] ms (müşteri kabul eşiği) |
| K6 | Görünürlük | Panelde olaylar, onay akışı, denetim dışa aktarımı | SOC sorumlusu bir olayı uçtan uca izler |
| K7 | Onay akışı | `ask` kararı panelden onaylanır, geliştirici yeniden dener | Onaylayıcı ve geliştirici akışı tamamlar |
| K8 | Browser Guard (isteğe bağlı) | Sentetik TCKN, IBAN, e-posta, gizli anahtar içeren istemler | Maskelenir; maskelenmeyen tür listelenir (oran ölçülmez, yalnız gözlem) |
| K9 | KVKK hazırlığı | Aydınlatma metni şablonu, veri envanteri, VKED taslağı | DPO gözden geçirdi |

Sonuç raporu her kriter için ölçüm ve kanıt (komut çıktısı, ekran görüntüsü,
dışa aktarım) içerir. Karşılanmayan kriter gizlenmez.

## 4. Zaman çizelgesi **[Müşteriye]**

| Gün | Adım | Kim |
|---|---|---|
| −5 … 0 | Ön koşullar: VM, DNS adı, TLS sertifikası (iç CA olabilir), NTP, çıkış kuralları, uç nokta listesi, POC sözleşmesi ve NDA | Müşteri BT + SingularityRD |
| 0 | Kickoff (1 saat): kapsam, başarı kriterleri, iletişim kanalı, haftalık toplantı saati | Herkes |
| 1 | Kontrol sunucusu kurulumu, ilk yönetici, POC lisansı (§5), ilk 5 uç nokta | Çözüm mühendisi + müşteri BT |
| 2–3 | Kalan uç noktalar, politika ön ayarı, (isteğe bağlı) SSO ve SIEM | |
| 3 | Senaryo oturumu (K3) — sentetik ortamda | |
| 4–24 | Gerçek kullanım; haftalık 30 dk gözden geçirme: yanlış pozitifler, istisnalar, sorular | |
| 25 | Ölçümlerin toplanması (K4, K5) | |
| 27 | Sonuç sunumu ve rapor | |
| 28–30 | Karar: ücretliye çevirme (§6) ya da kaldırma (§7) | Sponsor |

## 5. 30 günlük deneme lisansı (iç)

Ayrı bir "deneme" lisans türü yoktur; deneme, süresi kısa tutulmuş imzalı bir
`aidr-license-v1` lisansıdır ([lisanslama](../operations/licensing.md)):

| Alan | Değer |
|---|---|
| `license_id` | `POC-YYYY-NNN` (fatura ve CRM kaydında da bu) |
| `customer_id` | Müşteri kısa adı (`^[a-z0-9][a-z0-9-]{1,31}$`) |
| `plan_id` | `business` (internetsiz POC'de `enterprise`) |
| `seats` | Kapsamdaki cihaz sayısı, en fazla [25] |
| `deployment` | `onprem` ya da `airgap` |
| `not_before` / `expires_at` | Kickoff günü / kickoff + 30 gün (uzatmada yeni lisans) |
| `grace_days` | `3` |

Lisans /admin panelinden ya da `scripts/license-issue.mjs` ile imzalanır; POC
için imzasız pilot bayrağı (`--unsigned-license-for-pilot`) yalnız iç provada
kullanılır, müşteride kullanılmaz. Deneme süresi bitince yönetilen özellikler
ek süreden sonra durur; uç noktalardaki yerel tespit çalışmaya devam eder. Bu
yüzden POC sonunda ya ücretli lisans uygulanır ya da §7 kaldırma yapılır;
"kendiliğinden kapanır" denmez.

## 6. Ücretliye çevirme kontrol listesi

- [ ] Sonuç raporu sponsor tarafından kabul edildi.
- [ ] Teklif ([şablon](onprem-teklif-sablonu.tr.md)) onaylandı; imzalı teklif ya
      da satın alma siparişi geldi.
- [ ] EULA, DPA ve destek eki sürümleri hukukça onaylı ve müşteri tarafından
      kabul edildi.
- [ ] Ücretli lisans imzalandı; POC kontrol sunucusu **korunacaksa** yönetici
      `license-verify.mjs` ile doğrulayıp kabul operatörü üzerinden uygular
      ([yenileme](../operations/licensing.md#renewal)); kurulum yenilenecekse
      üretim kurulumu [on-prem runbook](../operations/onprem-runbook.md) ile
      sıfırdan yapılır ve POC verisi taşınmaz (yalnız politika ve istisnalar
      dışa aktarılıp gözden geçirilerek alınır).
- [ ] POC'deki geçici istisnalar gözden geçirildi; kalıcı olanlar gerekçeyle
      kayda geçti.
- [ ] Saklama ön ayarı seçildi ([KVKK rehberi](../operations/kvkk.md#2-saklama-ön-ayarları)).
- [ ] Çalışan aydınlatma metni yayımlandı; `privacy_notice_url` ayarlandı.
- [ ] Yedekleme, NTP ve izleme üretim düzeyine getirildi; geri yükleme tatbikatı
      yapıldı.
- [ ] Destek kanalı ve irtibat kişileri müşteriye yazılı bildirildi.
- [ ] e-Fatura / e-Arşiv ([kontrol listesi](e-fatura-kontrol-listesi.tr.md)).

## 7. POC kapatma (teardown) kontrol listesi

Müşteri devam etmezse, POC bitiminden sonra en geç [10] iş günü içinde:

- [ ] Her uç noktada kaldırma: Windows `msiexec /x` ya da Programlar ve
      Özellikler; Linux `apt remove` / `dnf remove`; kullanıcı başına
      `aidr uninstall` (yerel kayıtlar dahil siler; müşteri saklamak isterse
      `--keep-data`). Toplu kaldırma için [filo betikleri](../../deploy/fleet/windows/README.md).
- [ ] Browser Guard zorunlu kurulum politikası kaldırıldı.
- [ ] Müşteri isterse denetim kayıtları dışa aktarıldı ve kendisine verildi.
- [ ] Kontrol sunucusu: `node scripts/deployment-offboarding.mjs` ile kiracı
      kapatma, ardından [kaldırma adımları](../../deploy/onprem/README.md#uninstall)
      (`docker compose down --volumes`, `/srv/aidr` silme).
- [ ] SingularityRD tarafında: POC lisansı /admin'de sonlandırıldı, destek
      paketleri ve geçici erişimler silindi, müşteri verisi tutulmadığı yazılı
      teyit edildi.
- [ ] Müşteriye kapanış yazısı: neler kaldırıldı, hangi kayıtlar müşteride
      kaldı, POC lisansının bittiği.

## 8. Demo ortamı

Satış görüşmesi ve POC öncesi gösterim için sabit demo sanal makineleri:
[demo VM runbook'u](demo-vm-runbook.tr.md). Demo akışı:
[demo betiği](demo-script.md). Demo ortamı müşteri POC'si yerine geçmez.

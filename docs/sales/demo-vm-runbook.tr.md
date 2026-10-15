# Demo VM runbook'u — sabit gösterim ortamı

> **TASLAK — iş onayı gerekir.** Bu runbook, satış görüşmeleri ve POC öncesi
> gösterimler için her seferinde aynı sonucu veren, sentetik veriyle çalışan
> bir demo ortamını anlatır. Demo ortamı müşteri kurulumu, POC ya da kabul
> kanıtı değildir. Gösterimde yalnız o oturumdan önce aynı derlemede
> çalıştırdığınız şeyi gösterin ([demo betiği](demo-script.md)).
> Son güncelleme: 14.10.2026 · Sahibi: Çözüm mühendisi.

## 1. Ortam

Üç sanal makine, aynı izole sanal ağda (ör. Hyper-V, VMware ya da Proxmox iç
ağı). İnternet erişimi yalnız kurulum ve sürüm güncellemesi sırasında açılır;
gösterim internetsiz yapılabilir.

| VM | İşletim sistemi | Kaynak | Rol |
|---|---|---|---|
| `aidr-demo-cp` | Ubuntu 24.04 LTS x64 | 4 vCPU, 8 GiB, 100 GiB | Kontrol sunucusu (Docker Compose, `small` profil), iç CA ile TLS, NTP sunucusu |
| `aidr-demo-win` | Windows 11 x64 | 4 vCPU, 8 GiB, 80 GiB | Uç nokta: MSI kurulumu, Claude Code, Codex CLI, Chrome + Browser Guard |
| `aidr-demo-lnx` | Ubuntu 24.04 LTS x64 | 2 vCPU, 4 GiB, 40 GiB | Uç nokta: `.deb` kurulumu, Claude Code, OpenCode |

Ad çözümleme: iç DNS ya da her makinede `hosts` kaydı:
`console.aidr-demo.internal` ve `api.aidr-demo.internal` → `aidr-demo-cp`.
Tüm makineler `aidr-demo-cp` üzerindeki NTP'ye bağlıdır (saat farkı imzalı
lisansı, onayları ve kaydı bozar; `aidr doctor` bunu denetler).

## 2. İlk kurulum (bir kez, yaklaşık yarım gün)

1. **Sürüm.** Yalnız imzalı bir müşteri kitinden kurun; kaynak ağacından
   derleme gösterim için kullanılmaz. Kit ve imza doğrulaması:
   [ilk müşteri kılavuzu](../../deploy/FIRST_CUSTOMER.md).
2. **İç CA.** `aidr-demo-cp` üzerinde küçük bir iç CA oluşturun, iki ad için
   sertifika çıkarın ve kök sertifikayı iki uç noktanın güven deposuna ekleyin.
   Sertifikayı `deployment-tls-renew.mjs --mode static` ile kurun
   ([on-prem runbook](../operations/onprem-runbook.md#tls-public-ca-or-internal-ca)).
3. **Kontrol sunucusu.** [On-prem runbook'undaki](../operations/onprem-runbook.md)
   adımlar; `--profile small`. İlk yönetici: `demo-admin@aidr-demo.internal`.
4. **Demo lisansı.** `license_id: DEMO-<yıl>-<n>`, `customer_id: aidr-demo`,
   10 koltuk, 90 gün; bitmeden yenileyin.
5. **Uç noktalar.** MSI ve `.deb` kurulumu, şirket sayfasında
   `https://api.aidr-demo.internal` ve kayıt kodu; `aidr doctor` her satırı
   yeşil olana kadar düzeltin (saat satırı dahil).
6. **Demo içeriği.** Her uç noktada `~/aidr-demo/` çalışma klasörü; içinde
   sentetik proje, sahte `.env` (iptal edilmiş ya da uydurma anahtarlar),
   sentetik kişisel veri dosyası (sağlama toplamı geçen ama gerçek olmayan
   TCKN'ler, test IBAN'ları, sahte e-postalar). Gerçek müşteri ya da çalışan
   verisi **asla** kullanılmaz.
7. **Panel içeriği.** Bir politika sürümü yayımlayın, bir `ask` kararı üretip
   panelden onaylayın, bir olay (incident) oluşturun; denetim dışa aktarımı
   alın. Bunlar anlık görüntüye girer.
8. **Anlık görüntü.** Üç VM'yi kapatıp `demo-golden-<sürüm>` adıyla anlık
   görüntü alın.

## 3. Her gösterimden önce (30 dakika)

| Adım | Komut / eylem | Beklenen |
|---|---|---|
| 1 | Üç VM'yi `demo-golden-<sürüm>` görüntüsüne döndürün ve başlatın | |
| 2 | Saat: `timedatectl` (Linux), `w32tm /query /status` (Windows) | Senkronize, kaynak `aidr-demo-cp` |
| 3 | `node scripts/deployment-doctor.mjs --deployment /srv/aidr --online` (`aidr-demo-cp`) | Geçer |
| 4 | `aidr doctor` (iki uç noktada) | ✗ yok; saat satırı ✓ |
| 5 | `aidr verify` (iki uç noktada) | Koruma doğrulandı |
| 6 | Panelde Ajanlar sayfası | İki uç nokta çevrimiçi |
| 7 | Browser Guard açılır penceresi | Etkin, politika yüklü |
| 8 | Demo betiğinin ön kontrol bölümü | Hepsi geçti; geçmeyen bölüm gösterilmez |

Bir adım geçmezse o bölümü gösterimden çıkarın; sonucu sözlü anlatmayın.

## 4. Gösterimden sonra

- VM'leri kapatın; değişiklikleri **kaydetmeyin**, bir sonraki gösterim yine
  altın görüntüden başlar.
- Gösterimde müşterinin verdiği bir dosya ya da veri kullanıldıysa (yapılmamalı)
  görüntüyü atın ve olay kaydı açın.

## 5. Sürüm yükseltme

Yeni bir imzalı sürümde: altın görüntüden başlatın, kontrol sunucusunu
[yükseltme aracıyla](../operations/onprem-upgrade.md) yükseltin, uç noktalara yeni
MSI/`.deb` kurun, §3 kontrollerini çalıştırın, `demo-golden-<yeni sürüm>`
görüntüsü alın ve eski görüntüyü bir sürüm boyunca saklayın.

## 6. Taşınabilir demo (dizüstü)

Müşteri ağına bağlanılamayan sunumlarda aynı üç VM tek bir dizüstünde (en az 32
GiB RAM) çalıştırılır. Dizüstü disk şifrelemeli olmalı; demo VM'lerinde gerçek
kimlik bilgisi, müşteri verisi ya da üretim anahtarı bulunmaz.

# Kurulum belgeleri

[English](README.md)

[Hızlı başlangıç](../quickstart.tr.md) sayfasıyla başlayın: her rol için sıfırdan korumaya
tek sayfa. Aşağıdaki belgeler ayrıntıya girer. Singularity AIDR henüz müşteri kullanımı
için yayımlanmadı; bkz. [Sürüm durumu](../../README.md#release-status). Türkçesi olmayan
belgeler "(İngilizce)" olarak işaretlidir.

## Geliştirici (dizüstü bilgisayarda yapay zekâ kodlama araçları)

| Belge | Kapsam |
|---|---|
| [Masaüstü yükleyicileri](desktop-installers.tr.md) | Panelin İndirmeler sayfasından Windows MSI ve Linux .deb / .rpm / tar arşivi, `aidr status`, `aidr verify`, kaldırma, sorun giderme. macOS yükleyicisi henüz sunulmuyor. |
| [Getting Started](../getting-started.md) (İngilizce) | Yükleyicilerin kapsamadığı araçlar ve sistemler (macOS dahil) için araç başına bağlayıcı paketleri: Claude Code, Cursor, VS Code, OpenClaw, OpenCode, Codex |
| [Package Installation](../package-installation.md) (İngilizce) | Özel paket deposu erişimi ve sürümü sabitlenmiş paket kurulumu |
| [Integrity verification](../integrity.md) (İngilizce) | Bağlayıcı paketlerinin çalışmadan önce ihtiyaç duyduğu sürüm anahtarı (masaüstü yükleyicileri bu anahtarı zaten içerir) |
| Platform kılavuzları (İngilizce) | [Claude Code](../platform-guides/claude-code.md) · [Cursor / VS Code](../platform-guides/cursor.md) · [OpenClaw](../platform-guides/openclaw.md) · [OpenCode](../platform-guides/opencode.md) · [Codex](../platform-guides/codex.md) |
| [AIDR CLI](../../packages/cli/README.md) (İngilizce) | Tüm `aidr` komutları: setup, status, verify, doctor, pending, approve, uninstall |

## Ofis çalışanı (tarayıcıda yapay zekâ sohbeti)

| Belge | Kapsam |
|---|---|
| [Browser Guard'ı kurma](browser-guard.tr.md) | Chrome, Edge veya Firefox'a (Windows, Linux, macOS) mağaza bağlantısından kurma, çalıştığını denetleme, kaldırma |

## BT yöneticisi

| Belge | Kapsam |
|---|---|
| [Masaüstü yükleyicileri: sessiz ve yönetilen dağıtım](desktop-installers.tr.md) | Intune, SCCM/ConfigMgr, GPO, apt/yum/dnf, kullanıcı başına kurulum, imza denetimi |
| [Browser Guard'ı kurumda dağıtma](browser-guard-enterprise.tr.md) | Intune, Google Yönetici Konsolu, GPO, Jamf (macOS) ve Firefox ilkeleriyle zorunlu kurulum ve ayar kilitleme; pilot, dağıtım ve geri alma |
| [Browser Guard ilke dosyaları](../../deploy/browser-guard/README.md) (İngilizce) | Örnek ilke dosyaları ve tüm yönetilen ayarlar |
| [Filo betikleri](../../deploy/fleet/windows/README.md) (İngilizce) | Betikle filo kurulumu, güncelleme ve kaldırma (Windows; [Linux](../../deploy/fleet/linux/README.md)) |
| [VDI, devcontainer, Remote-SSH, WSL, CI](special-environments.tr.md) | Ajan kullanıcının kendi masaüstünde çalışmadığında AIDR'ın nereye kurulacağı |
| [İşten ayrılma ve makine değişimi](../runbooks/offboarding-and-device-swap.md#türkçe-özet) | Cihaz iptali, yerel denetim kaydının saklanması, makinenin başkasına verilmesi |
| [Operator approvals](../configuration.md#operator-approvals) (İngilizce) | Bekletilen bir işlemin bir kişi tarafından onaylanması (`aidr pending`, `aidr approve`, paneldeki Onaylar sayfası) |
| [Configuration](../configuration.md) (İngilizce) | Tüm ayarlar ve dosya yolları |
| [Support diagnostics](../support-diagnostics.md) (İngilizce) | `aidr support-bundle` ve içeriği |

## On-prem işletmecisi (kendi sunucularınız)

| Belge | Kapsam |
|---|---|
| [On-premises deployment](../deployment/onprem.md) (İngilizce) | Topolojiler (Docker Compose, Kubernetes, internetsiz kurulum) ve nereden başlanacağı |
| [AIDR on-prem installation](../../deploy/onprem/README.md) (İngilizce) | Docker Compose ile tek Linux sunucusu: kurulum, güncelleme, yedekleme, internetsiz sunucular |
| [Running AIDR on Kubernetes](../operations/kubernetes.md) (İngilizce) | Helm chart: imajlar, kimlik bilgileri, kurulum, güncelleme ve geri alma, yedekleme |
| [Configuration reference](../operations/onprem-config-reference.md) (İngilizce) | Tüm on-prem ayarları |
| [Upgrade runbook](../../deploy/UPGRADE.md) (İngilizce) | Kontrol düzlemi güncelleme ve geri alma |
| [Uçtan uca on-prem runbook'u](../operations/onprem-runbook.md) (İngilizce) | Sırasıyla tüm yol: ön koşullar, NTP, genel ya da iç CA ile TLS, kurulum, uç noktalar, kabul |
| [Licensing](../operations/licensing.md) (İngilizce) | Çevrim dışı lisans ve süresi dolduğunda ne olduğu |
| [KVKK rehberi](../operations/kvkk.md) | Bileşen bazında veri envanteri, saklama ön ayarları, VERBİS, yurt dışına aktarım, VKED şablonu |
| [İlk müşteri kurulum ve kabul kılavuzu](../../deploy/FIRST_CUSTOMER.md) | Kurulum ve kabul denetim listesi |

## Sürüm ve portal işletmecisi (Singularity tarafı)

| Belge | Kapsam |
|---|---|
| [Yükleyici indirme portalı](download-portal.tr.md) | İmzalı yükleyicilerin panelin İndirmeler sayfasında yayımlanması, mağaza bağlantısı ayarları |
| [Masaüstü yükleyicileri: derleme](desktop-installers.tr.md) | Yükleyicilerin derlenmesi ve imzalanması |
| [SaaS deployment](../deployment/saas.md) (İngilizce) | Barındırılan kontrol düzlemi |

## Güncelleme ve kaldırma

- Masaüstü yükleyicileri: yeni sürümü eskisinin üzerine kurun; güncelleme ve kaldırma
  için bkz. [Masaüstü yükleyicileri](desktop-installers.tr.md).
- Bağlayıcı paketleri ve komut satırı aracı: [Upgrade notes](../upgrade-notes.md) ve
  [Uninstall](../getting-started.md#uninstall) (İngilizce).

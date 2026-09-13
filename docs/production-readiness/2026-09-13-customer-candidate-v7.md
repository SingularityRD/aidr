# AIDR ilk müşteri adayı v7 — birleşik mühendislik ve kabul kaydı

**Karar: NO-GO (production ve destekli satış).** Bu kayıt, 13 Eylül 2026 tarihinde `b4361fa7d565e76f1604997b654a41e54c03db80` tabanındaki **değişiklik içeren çalışma ağacını** değerlendirir. Cloud ve self-hosted kurulum hedeflenir. Yerel kaynak, test ve paketleme ilerlemiştir; resmi yayıncı imzası, temiz immutable kaynak adayı, müşterinin gerçek host/OS/IdP/ağ ortamı, bağımsız güvenlik değerlendirmesi ve isimli müşteri kabulü yoktur.

## Ürün kapsamı ve karar

`FEATURE_INVENTORY.json/.md` içindeki 71 alt özelliğin **41'i bağlı/çalışan, 27'si kısmi, 1'i eksik, 2'si dış kabule bağlıdır**. Eksik `BIL-03`, yalnız satılan SKU içinde self-service abonelik portalı sunulacaksa uygulanmalıdır; doğrudan kurumsal fatura modeli için kapsam dışında bırakılması Product ve Finance tarafından yazılı onaylanmalıdır.

`PRODUCTION_SALES_GAPS.json/.md` içinde 46 teknik/operasyon paketi ve 13 ticari/dış kanıt kapısı vardır. Teknik işlerin 41'inde yerel uygulama ilerlemiş, saha kabulü açıktır. Beş iş `OPEN` kalır: T01 gerçek host ve işletim sistemi koruması, T13 native response yan etkisi, T25 bağımsız olay kanıtı ve anahtar saklama, T33 ödeme–entitlement mutabakatı, T39 bağımsız etkinlik/performance kıyası. Destekli satış ve production-GA profillerinin her birinde 12 zorunlu dış kapı açıktır. Bu sayılar bitiş yüzdesi veya benzersiz hata sayısı değildir.

## V7 ile kapanan yerel uygulama boşlukları

- **Detection:** Bütün bağlayıcılarda ortak araç/girdi normalizasyonu; paket/reputation hatalarında fail-closed `unknown/unavailable`; 2 MiB çıktı, 3 saniye best-effort süre ve 128 bulgu sınırı; Unicode/JSON görünümü; adayın kendi davranış baseline'ına katılmaması; publisher ve fetch zamanı bağlı feed güncelliği.
- **MCP:** Kararlı inventory kimliği; `key_id` dahil imzalı tool manifesti; sıkı delegated credential sayı/anahtar doğrulaması; initialize capability daraltma; JSON-RPC/framing/notification doğrulaması; DNS pinleme ve okunan/decompress edilmiş bayt sınırı. Doğrudan upstream erişimin zorunlu gateway yönlendirmesi, binary çıktı ve server-initiated yöntemler saha/ürün boşluğu olarak kalır.
- **Response ve telemetry:** Kolektörün geçici upload hatasından sonraki çevrime devam etmesi; tam tenant/global revocation kümesi; resume sırasında adapter yeteneğinin yeniden doğrulanması; bozuk/tampered WAL reddi ve stale-backlog readiness; SIEM state'in hedef fingerprintine bağlanması; deterministik olay receipt head'i; Storage silme doğrulaması ve authenticated offsite commit zamanı.
- **Policy ve endpoint:** Runtime ile simulator unknown-MCP parity; Windows config DACL'ı; kurulum/kaldırmada müşteri hook'larının korunması; imzasız/bozuk entitlement cache'in reddi ve kesin iptalde cache temizliği.
- **Identity ve tenancy:** Güvenli recovery URL ve parola değişiminden önce global session barrier; SCIM stale PATCH, remove-all ve pagination; invite list/revoke/resend; paket indirmede canlı tenant/üyelik/key kontrolü; büyük/stalled istekte fail-closed sınırlar; RLS yaşam döngüsü için gerçek yerel PostgreSQL migration testi.
- **Deployment ve operations:** Hazırlıkta secret yazılmadan önce girdi doğrulaması; public proxy/upstream loop reddi; receipt yolunun mutation öncesi doğrulanması; fault sonrası zorunlu recovery örneği; kesilen upgrade resume hash kontrolü; per-instance monitoring/empty-discovery alarmı; Windows timeout sürecinde shell alt sürecinin geçici dizini kilitlemesini önleyen doğrudan executable çalıştırma.
- **Commercial, privacy ve UX:** Sipariş cevabının tenant/request/quantity/quote bağı; 10 release kökünü denetleyen ticari preflight; stale onboarding state düzeltmesi; source-hash kararlı privacy canary; overlapping ve JSON Unicode-escaped DLP redaksiyonu; destek v7 runbook'u, ilk müşteri satın alma paketi ve imzalı benchmark girdi/ham kanıt sözleşmesi.

## Birleşik yerel doğrulama

| Kapı | Sonuç ve sınır |
| --- | --- |
| `pnpm check` | PASS. TypeScript ve workspace sözleşmeleri geçti. |
| `pnpm test:ci` | PASS: **237 dosya, 3.326 geçti, 2 açıklanmış skip, 0 hata**. Toplam 3.328 test. Skip'ler canlı reputation sağlayıcısı ve Windows üzerinde POSIX izin davranışıdır. |
| `pnpm test:coverage` | PASS: statements **%77,36**, branches **%69,58**, functions **%81,05**, lines **%80,77**; eşikler sırasıyla %70/%60/%70/%70. |
| `pnpm build:release` | PASS: 10 paket release manifesti ve consumer smoke; CycloneDX SBOM **231 bileşen**, SHA-256 `44f91f61f30147ae325e3eb14602cea2eb00c98e50a2da48f4c2fd154558006e`. Dashboard build'i 644,92 kB minified chunk uyarısı verir; bu işlevsel hata değildir, yükleme performansı tarayıcı sahasında ölçülmelidir. |
| `pnpm quality:static` | PASS. 148 lint uyarısı; Knip borcu 228 dosya/121 export/1 duplicate. Satış URL/e-posta, `DASHBOARD_SMOKE_BASE_URL` ve demo kimlik bilgileri verilmediği için ilgili canlı kontroller açık raporlanır. |
| Bağımlılık, Edge ve enforcement | `pnpm audit:prod` 0 advisory; 33 migration benzersiz/sıralı; 15 dashboard Edge çağrısı ve 31/31 function guard; enforcement 72/72, Codex 11/11 PASS. |
| Vitest dışı sözleşmeler | Endpoint kurulum/kaldırma, deployment preparation, offboarding, yük harness'i, release signing, ingress, monitoring ve benchmark testleri geçti. E2E runner dış makbuzu candidate digest ve zamanı ile bağlar; Windows timeout temizleme regresyonu 5/5 PASS ile doğrulandı. |
| AIG bridge | İzole `.release-evidence/aig-bridge-venv` içinde **31/31 pytest PASS**. Sistem Python'unda `tenacity` bulunmadığında suite fail-closed olur; müşteri/CI ortamı pinned test/runtime bağımlılıklarını kurmalıdır. |
| Release ve müşteri kiti | **14 release artefaktı** ve **338 dosyalı** portable kit doğrulandı; cloud/self-hosted preparation boş `PATH` ile çalıştı, 14 artefaktın hash'i korundu. Dashboard/CLI paket allowlist'i kaynak, test ve eski bakım betiklerini dışarıda bırakacak şekilde daraltıldı. Release-inventory candidate SHA-256 `bc1e435fa6f9d511a2940328dcd0c3b3fea8551a0b0d50e03322ff0cd330e295`. Paket ve dış zarf imzasızdır; `publisher_authenticated=false`. |
| Native host kapısı | **NO-GO, beklenen fail-closed.** Windows 10 x64 üzerinde OpenCode 1.18.30 ve Codex CLI 0.141.0 yalnız sürüm olarak bulundu. Claude, Cursor, VS Code ve OpenClaw hostları yok; hiçbirinde isimli native yan-etki kabul kaydı yok. |
| Release E2E | **NO-GO, beklenen fail-closed.** Kapı yukarıdaki release-inventory digestine bağlandı. AIG bridge 31/31, migration 1/1 ve yerel Supabase control-plane 9/9 geçti. Claude/OpenClaw/Cursor/VS Code host/kimlikleri, canlı AIG/Supabase ve browser makbuzları, dashboard URL'si ve isimli kabul yoktur; OpenCode'un provider gerektiren 13 vakası pending kalır. |
| Claim ve ticari yüzey | 10 claim-facing kök ve 10 release artefakt kökü tarandı; 0 pattern/unapproved hit, lisans/registry hatası yok. Inventory PASS; 13 dış onay kapısı açık olduğu için production claim gate beklenen biçimde FAIL. |

## Kaynak ve kapasite

Bu turda Docker daemon yanıt vermediği için yeni canlı self-hosted ölçüm üretilmedi. Aşağıdaki değerler v6 yerel Windows Docker Desktop provasıdır ve v7 kapasite kanıtı olarak yükseltilmez:

- 11 Compose servisi tek anlık örnekte **1.165,1 MiB RAM**; açılıştan kısa süre sonra yaklaşık **%66,52 tek çekirdek CPU**.
- Claude teslim dosyaları **28,17 MiB**. Üç zararsız ayrı hook sürecinde tanılama dahil p95 RSS **88,9 MiB**; ilk süreç **1.014 ms**, sonraki iki süreç **1.020–1.127 ms**.
- Konteyner imajlarının ortak katmanları çift sayan sanal açılmış boyut toplamı **1,69 GiB üst sınır**.
- Önceki kısa dashboard `/healthz` denemesi 10 RPS × 30 saniye, 300/300 HTTP 200 ve p95 7,2 ms idi. Kimlikli policy/ingest, çok tenant, failover veya SLA throughput'u değildir.

Müşteri bilgisi olmadan başlangıç planı: pilot/100 cihaz için **4 vCPU, 8 GiB RAM, 100 GiB SSD**; 1.000 cihazlık ilk yük testi için **8 vCPU, 16 GiB RAM, 250 GiB SSD**; uç cihaz başına **512 MiB disk rezervi**. Eşzamanlı hook süreçleri için süreç RSS'i ayrıca bütçelenir. 1.000 cihaz varsayımı günlük 400.000 policy+ingest çağrısı ve 47 RPS planlama zirvesi üretir. Bunlar tahsistir; customer-like soak, noisy-neighbor, backup ve failover ölçümüyle yeniden boyutlandırılmalıdır. TLS proxy, ingress signer, Docker VM/kernel, AI host, log, yedek ve offsite transfer yukarıdaki yerel ölçümde yoktur.

## İlk müşteri öncesi zorunlu kapanış

1. Satılacak connector/OS/host sürümlerini dondur; imzalı aynı candidate üzerinde pre-tool ve mümkünse pre-model-output yan etkisini, hook kapalı/çökmüş/ağsız/timeout/bypass hallerini bağımsız kaydet.
2. Seçilen cloud veya self-hosted ortamda public TLS ingress, DNS, region, IdP/SCIM/MFA, SMTP, MDM, iki tenant negatif matrisi, gerçek SIEM receipt, alarm paging ve destek ticket tatbikatını tamamla.
3. Kimlikli policy/ingest yükü, noisy-neighbor, failover ve en az sekiz saatlik soak; bağımsız failure-domain restore; upgrade/rollback ve RPO/RTO kabulünü aynı candidate digestine bağla.
4. Temiz immutable kaynaktan resmi offline publisher anahtarıyla imzalanmış paket ve dış zarf üret; private registry/air-gap teslimi, signer rotation/revoke ve müşteri doğrulama receipt'ini kanıtla.
5. Product/Finance/Legal/Privacy/Security/Support/Sales sahipleri SKU, fiyat/teklif, paid-to-entitlement, lisans/IP, DPA/region, SLA/destek ve iddia kayıtlarını onaylasın. Bağımsız pentest/retest ve isimli müşteri PoV kaydı eklensin.

İlk görüşme paketi `deploy/FIRST_CUSTOMER.md`, `docs/production-readiness/first-customer-sales-packet-v7.md`, `FEATURE_INVENTORY.md`, `PRODUCTION_SALES_GAPS.md`, `docs/runbooks/support-v7.md` ve bu kayıttan oluşur. Yerel unsigned paket kurulum hazırlığını tekrar edilebilir kılar; production veya destekli satış GO kararı vermez.

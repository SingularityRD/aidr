# AIDR ilk müşteri aday v6 — bütünleşik doğrulama ve kalan kabul

**Karar: NO-GO (production ve destekli satış).** 13 Eylül 2026 tarihinde `b4361fa7d565e76f1604997b654a41e54c03db80` üzerinde, **değişiklik içeren çalışma ağacından** oluşturulmuş yerel mühendislik adayıdır. Resmi yayıncı imzası, temiz kaynak sürümü, müşteri ortamı, gerçek host/OS kapsamı ve isimli kabul yoktur. Yönetim katmanının hem cloud hem self-hosted teslimi hedeflenir; burada çalışan altyapı yalnız self-hosted loopback provasıdır.

## Ürün durumu

`FEATURE_INVENTORY.json/.md` içindeki 71 alt özellikten **41'i bağlı, 27'si kısmi, 1'i eksik, 2'si dış kabule bağlı**. Bağlı olmak, müşterinin hostunda korunma veya SLA kanıtı değildir. `PRODUCTION_SALES_GAPS.json/.md` içindeki 46 teknik/operasyon paketin **41'inde yerel uygulama ilerledi ve saha kabulü açık**, **5'i uygulama/entegrasyon olarak açık**: T01 gerçek host/OS, T13 uçta güvenli response uygulayıcısı, T25 bağımsız olay kanıtı, T33 ödeme–entitlement yaşam döngüsü, T39 bağımsız etkinlik/performans kıyası. Destekli satış ve production-GA için **12 zorunlu dış kapı** açık. Bunlar benzersiz hata veya yüzde ilerleme sayısı değildir.

V6 değişiklikleri MCP stdio köprüsü ve ağ sınırları, merkezi discovery kolektör kimliği ve CLI yüklemesi, atomik politika sürüm karşılaştırması, ingest/sentry redaksiyonu, olay korelasyonu/yerel bütünlük denetimi, ayrı Ed25519 imzalı snapshot makbuzu, dar yetkili response tüketicisi ve HMAC+fsync restart-safe worker, onay bekleyen kurumsal sipariş kaydı, restore ACL koruması, yük aracı gözlemi, yerel native host matrisi ve taşınabilir kit sözleşmesini kapsar. Stdio desteği tüm MCP yöntemleri veya doğrudan upstream bypass engeli demek değildir. Response worker OS izolasyonunu uygulamaz; makbuzun bağımsız saklanması ve güvenilir zaman damgası kurumsal sahada açık kalır. Kurumsal sipariş yalnız `pending_finance` üretir, ödeme/koltuk hakkı vermez.

## Bütünleşik yerel kanıt

| Denetim | Sonuç ve sınır |
| --- | --- |
| `pnpm check`, `pnpm build:release` | PASS; 10 paket consumer kontrolü, SBOM ve MCP stdio artefaktı. Resmi imza yok. |
| Tam Vitest ve son değişiklik regresyonu | İlk bütünleşik koşu **223 dosya, 3.164 geçti, 2 atlandı, 0 hata**. Sonrasında eklenen response journal/worker ve imzalı olay makbuzu için 3 ilgili dosyada **26/26** geçti; root TypeScript ve release consumer kontrolleri tekrarlandı. İlk koşu son iki eklemeyi kapsamadığından 3.164 sayısı son kaynak ağacının tam tekrar koşusu değildir. Atlamalar canlı reputation sağlayıcısı ve Windows'ta POSIX izin testi. |
| `pnpm quality:static` | PASS; **140 lint uyarısı** ve Knip **225 dosya/121 export/1 duplicate** inceleme borcu devam ediyor. Ticari, Edge ve demo statik sözleşmeleri geçti; gerçek satış CTA/kimlikli tarayıcı provası yapılmadı. |
| Bağımlılık denetimi | `pnpm audit:prod`: **0 advisory**. İzole AIG Python ortamında `pip-audit -r requirements.txt`: **bilinen zafiyet bulunmadı**. Bu anlık kayıt yeni açıklanan zafiyetlerin olmayacağı garantisi değildir. |
| Migration ve Edge sözleşmesi | **33 benzersiz sıralı migration**, **15 dashboard Edge çağrısı**, **31/31 fonksiyon yapılandırma koruması**. |
| Temiz self-hosted kurulum | Yeni proje/veri alanında **11 servis**, **33/33 migration**, çevrimiçi doctor PASS. İlk açılışta Storage şema yarışını saptayıp migration aracına 90 sn sınırlı hazır olma beklemesi eklendi; idempotent tekrar PASS. |
| Canlı HTTP ve onboarding | 30 HTTP smoke + 9 müşteri onboarding kontrolü PASS; fixture'lar yalnız loopback geliştirme kurulumunda. |
| V6 yeni Edge yolları | 18 canlı kontrol PASS: siparişin `pending_finance` durumu/idempotency/çatışma, MFA issuance reddi, kolektör cursor–ingest–replay–read–revoke. Pozitif makine anahtarı yerel testte ayrıcalıklı RPC fixture'ıyla verildi; insanın gerçek MFA issuance akışı saha kabulü ister. |
| Release E2E kapısı | **NO-GO, fail-closed.** İzole Python ortamında AIG köprü sözleşmesi **31/31**, Supabase statik/yerel sözleşmeleri **1/1 + 9/9**, gerçek loopback dashboard rota smoke **1/1** geçti. Claude/OpenClaw/Cursor/VS Code ve canlı AIG/Supabase/browser kanıtları için host, kimlik veya dış makbuz eksik; OpenCode sağlayıcı gerektiren 13 test pending. Kapı bu eksikleri skip ile gizlemedi. |
| Native host matrisi | **NO-GO**; bu Windows hostta OpenCode **1.18.30** ve Codex CLI **0.141.0** sürümü bulundu, diğer GA host binary'leri mevcut değil. Sürüm sorgusu korunmuş yan etkiyi kanıtlamaz. |
| Gizlilik ve kurtarma | Yerel gizlilik canary **6/6**, support bundle **13/13**; aynı host restore provası **35 sn**, **18 migration/25 nesne dosyası**. Gerçek offsite failure domain, RPO/RTO ve müşteri veri işleme onayı açık. |
| Müşteri kiti | **324 dosya**, **14 release artefaktı** hash/manifest kontrolü PASS; cloud ve self-hosted hazırlık boş `PATH` ile çalıştı, özel prova sırları pakette bulunmadı. Dış zarf **imzasız**; `publisher_authenticated=false`. |
| Yerel kısa yük | Dashboard `/healthz` 10 RPS × 30 sn: **300/300 HTTP 200**, 0 düşme, p95 **7,2 ms**. Eski başarısız koşu korunur. Bu tek sağlık rotası kurumsal throughput veya failover kabulü değildir. |

Başlıca makine kanıtları: `.release-evidence/aidr-install-v6/`, `v6-edge-live-evidence.json`, `.release-evidence/aidr-customer-kit-v6/`, `.release-evidence/aidr-envelope-v6/`, `.release-evidence/load-dashboard-v6-local-20260913.json`, `.release-evidence/resource-profile-v6-local-20260913.json` ve `.release-evidence/resource-images-v6-local-20260913.json`. Kurulumun `.env` dosyaları ve smoke fixture kimlik bilgileri özeldir; müşteriyle paylaşılmaz.

## Kaynak ve kapasite sınırı

V6 yerel Windows Docker Desktop örneğinde 11 Compose servisinin tek anlık toplamı **1.165,1 MiB RAM** idi. Aynı anın **%66,52 tek çekirdek CPU** değeri açılıştan kısa süre sonra alınmıştır; idle, tepe veya müşteri yükü değildir. Claude kit dosyaları **28,17 MiB**; üç zararsız ayrı kanca sürecinde tanılama preload'u dahil p95 RSS **88,9 MiB**, ilk süreç **1.014 ms** ve sonraki iki süreç **1.020–1.127 ms**. İmajların sanal açılmış boyut toplamı, ortak katmanları çift sayan **1,69 GiB üst sınır**. TLS proxy, ingress signer, Docker VM, yedek, log ve AI host bu ölçüme dahil değil.

Müşteri bilgisi olmadan başlangıç tahsisi: pilot/100 cihaz için 4 vCPU, 8 GiB RAM, 100 GiB SSD; 1.000 cihazı **yalnız yük testine başlatmak** için 8 vCPU, 16 GiB RAM, 250 GiB SSD. Uç cihaz başına 512 MiB disk rezervi; eşzamanlı aktif kanca sayısı × ölçülen süreç RSS ayrıca host bütçesine eklenir. Trafik modeli 1.000 cihazda **400.000 policy+ingest çağrısı/gün** ve **47 RPS planlama zirvesi** üretir; bu ölçülmüş kapasite değildir. Formüller, 10/100/1.000 senaryoları ve dışarıda kalan trafik `deploy/RESOURCE_REQUIREMENTS.md` ile `docs/production-readiness/resource-sizing-v5.md` içindedir. Cloud planı ve Edge fatura/kota maliyeti seçilen proje/region olmadan hesaplanamaz.

## Sıradaki kapanış işleri

1. **Gerçek korunma:** İlk müşterinin OS/AI host/sürüm matrisini belirleyip her bağlayıcının benign, saldırı, ağsız, timeout ve kapalı-hook yan etkilerini bağımsız kaydet; MCP doğrudan upstream kaçışı, binary ve server-initiated kapsamı ile native response uygulayıcısını tamamla (T01, T04–T13, T25).
2. **Yönetim ve kimlik:** Gerçek cloud projesinde migration/Edge config, TLS ingress signer, DNS, veri bölgesi, Entra/Okta, MDM ve çok kiracılı erişimi sınayıp isimli kabul kaydı al. Yerel cloud hazırlık gerçek sağlayıcı dağıtımı değildir (T18–T23, T28, T42–T46).
3. **İşletim kapasitesi:** Kimlikli policy/ingest yükü ve noisy-neighbor/failover/8 saat soak, ayrı host offsite restore, imzalı upgrade/rollback, alarm nöbetçisi ve gerçek SIEM makbuzunu aynı aday hash'iyle ölç (T26–T32, T35, T39–T40).
4. **Satış ve güvenlik:** Onaylı SKU/teklif ve finans kaydı–entitlement mutabakatı; resmi temiz kaynak build'i ve çevrimdışı yayıncı imzası; lisans/NOTICE, DPA/bölge, destek, bağımsız pentest/retest ve isimli müşteri PoV; onaylı iddia defteri (T33–T34, T37, T41 ve COM/SEC-EXT/POV/CLM kapıları).

Müşterinin ortamı, cihazları, veri bölgesi, alan adları, imza/finans/hukuk sahipleri ve kabul eden kişiler henüz belli değil. Bu girdiler ve gerçek saha çalışması olmadan kurulum paketi **satışa/üretime hazır** diye etiketlenmez.

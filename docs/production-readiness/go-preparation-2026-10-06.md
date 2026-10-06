# Taşınabilir kurulum paketi ve GO hazırlığı — 6 Ekim 2026

Bu teslimin kapsamı **kurulabilir, taşınabilir mühendislik paketi ve operatör hazırlığıdır**. Bu turda staging veya canlı müşteri ortamı kurulmaz. Paketin üretilmesi, kaynak snapshot'ının commit edilmesi veya yerel testlerin geçmesi yayıncı, müşteri, Security, Legal ya da production onayı üretmez.

Bu belge mevcut kılavuzları bir araya getirir; yeni bir kabul defteri değildir. FCR ölçütlerinin kaynağı [first-customer-ready.md](first-customer-ready.md), ticari kararın kaynağı [commercial-go-evidence-registry.json](commercial-go-evidence-registry.json) ve [commercial-gate-receipts.json](commercial-gate-receipts.json) olarak kalır. Bu kayıtların açık kararları paket hazırlığıyla kapatılmaz. Kullanıcının düzenlediği `RELEASE_READINESS_REPORT.md` bu hazırlık tarafından değiştirilmez.

## Teslim sınırı ve çıktı indeksi

Release sorumlusu, kaynaklar dondurulduktan sonra ana çalışma ağacını bozmadan temiz, izole bir snapshot'tan release çıktısını ve müşteri-kit zarfını üretir. Eski kanıtlar silinmez veya üzerine yazılmaz. Yeni çıktının gerçek yolları, kaynak commit'i, envanter SHA-256'sı ve doğrulama kayıtları paket üretildikten sonra bu bölüme bağlanır; henüz verilmemiş bir yol veya hash kabul kanıtı sayılmaz.

| Teslim parçası | İçeriği ve sınırı | İzlenecek mevcut yol |
|---|---|---|
| Müşteri kiti | Kurulum betikleri, dashboard/release dosyaları, Supabase deployment kaynakları ve operatör belgeleri | [FIRST_CUSTOMER.md](../../deploy/FIRST_CUSTOMER.md), `scripts/customer-kit.mjs` |
| Dış teslim zarfı | Kit tar arşivi, metadata ve tam dosya envanteri; onaylı yayıncı imzası varsa bütün kit byte'larını bağlar | [Release kanıtı](../release-evidence.md), `scripts/release-sign.mjs` |
| Bağımsız doğrulama | Paket dışından önceden güvenilir kanalla alınmış doğrulayıcı, public-key policy ve ayrı kalıcı anti-rollback state | [Bağımsız teslim doğrulaması](../../deploy/FIRST_CUSTOMER.md#taşınabilir-paket-ve-yayıncı-doğrulaması) |
| Kurulum başlangıcı | Kitte `START-HERE.md`, `INSTALLATION.md`, `UPGRADE.md`, restore/support/secret kılavuzları | Kaynak: [FIRST_CUSTOMER.md](../../deploy/FIRST_CUSTOMER.md), [deploy/README.md](../../deploy/README.md) |
| Hazırlık ve test kanıtları | Tam aday kimliği, paket envanteri, ham sonuçlar ve bilinen açıklar; yerel başarı ayrı, dış kabul ayrı | [Kanıt indeksi işlemi](evidence-index-regeneration.md) |

Mevcut kit, Supabase self-hosted ve mevcut Supabase cloud deployment yolunu hazırlar. Seçilmiş gerçek cloud projesi ve hesap erişimi kurulum operatöründen gelir. Cloudflare pilotun kaynak release'i ve kardeş managed Clerk/Firestore/Polar uygulamasının yayını ayrı işlemlerdir; bu kitin çıkarılması onları dağıtmaz. Kitteki iç `artifacts/` imzası yalnız o alt dizini bağlar; `SHA256SUMS` dosyası yayıncı kimliği sağlamaz. Onaylı yayıncı imzası olmayan çıktı **unsigned mühendislik adayıdır**.

## Operatör girdi listesi

Örnek dosyaları paket dışındaki erişimi kısıtlı gerçek yapılandırmaya uyarlayın. Bunlar yeni varsayılanlar veya onay değildir. Parola, private key, API token veya ham müşteri verisini bu belgeye, repoya, transcript'e ya da kanıt arşivine koymayın. Gerekli sırlar kurumun secret manager'ından veya mevcut araçların güvenli girişinden sağlanır.

| Girdi | Kullanılacak mevcut dosya/kılavuz | Gerçek değer veya yetkiyi sağlayan |
|---|---|---|
| Sürüm, kaynak commit'i, release envanteri, paket/container digestleri | [Commercial Release Manifest taslağı](commercial-release-manifest-template.md), [release-evidence.md](../release-evidence.md) | Release + Engineering; aynı adayın kimliği ve varsa ayrı landing kaynak/build kimliği |
| Yayıncı Ed25519 anahtarı, key ID, SPKI fingerprint, geçerlilik/sıra ve kanal | [release-evidence.md](../release-evidence.md), [FIRST_CUSTOMER.md](../../deploy/FIRST_CUSTOMER.md) | Yetkili yayıncı; private key kit dışında. Public trust policy bağımsız ve önceden güvenilir kanaldan gelir; test anahtarı yayıncı onayı değildir |
| Windows publisher certificate/TSA; kapsamdaysa macOS notarization | [Code signing kılavuzu](../sales/code-signing-guide.md), mevcut release workflow | Yetkili certificate/notarization hesabı ve Release sorumlusu; gerçek OS kabulü ayrıca gerekir |
| Kurulum yolu, HTTPS domain/TLS, sağlayıcı proje/bölgesi, auth yöntemi, SMTP ve private registry erişimi | [FIRST_CUSTOMER.md](../../deploy/FIRST_CUSTOMER.md), [deploy/README.md](../../deploy/README.md), `deploy/regions.manifest.json`, [ingress kılavuzu](../../deploy/ingress/README.md) | Kurulum + Operations; gerçek DNS/TLS, provider hesabı ve izni. `deployment-prepare` özel `.env`, `.env.functions`, `.env.ingress` ve public `agent-config.json` üretir |
| Sunulacak host/OS/architecture/version, binary ve install/uninstall/policy hashleri, QA/endpoint/support sorumluları | [Native scenario hazırlığı](../../deploy/native/scenarios/README.md), `deploy/native/scenarios/TEMPLATE.json`, `deploy/native/support-matrix.json`, [.env.example](../../.env.example) | Host lisansı/hesabı ve gerçek kabul makinesi olan operatör. Native şablonların mevcut paket içeriği teslim envanterinden teyit edilir; repo şablonu kendi başına kabul kaydı değildir |
| Gerçek connector/provider credentials ve aday bağlamı | [External gates runbook](external-gates-runbook.md), [.env.example](../../.env.example) | Yetkili provider hesapları; exact candidate digest/zamanı, IDE için immutable VSIX/config yolları ve hashleri. Placeholder değerler gerçek E2E değildir |
| Off-host hedef, bölge/endpoint/Object Lock/retention, ayrı recovery key erişimi, restore hedefi ve RPO/RTO | `deploy/backup/aidr-backup-offsite.env.example`, `deploy/backup/aidr-restore-drill.env.example`, [backup kılavuzu](../../deploy/backup/README.md) | Operations + ayrı recovery erişimini doğrulayan kişi; gerçek yedekleme/geri yükleme ve başarısız hedef alarmı |
| Monitoring URL/token/health dosyaları, signer expiry, gerçek filo kuyruğu, on-call ve escalation | `deploy/monitoring/compose.monitoring.yml.example`, `prometheus-scrape.yml.example`, `oncall-ownership.yml.example`, `deploy/maintenance/aidr-readiness-evidence.env.example` | Operations + Support; etkin timer, gerçek alarm/ticket rotası, birincil ve yedek sorumlu |
| Cihaz/tenant/rate/retention sınırı, iki tenant auth, eşikler, soak ve fault zamanı | `deploy/ha/workload.local.example.json`, `workload.noisy-neighbor.template.json`, `workload.failover.template.json`, [HA kılavuzu](../../deploy/ha/README.md) | Operations + QA; ölçülecek gerçek kapsam ve güvenli fault izni. Yerel örnek profil kapasite/SLA kanıtı değildir |
| Etkin veri akışları, gerçek provider/region/subprocessor, retention/hold/deletion, pilot terms/DPA ve dağıtım hakları | [Privacy/Legal taslağı](privacy-legal-review-template.md), [veri akış matrisi](privacy-data-flow-matrix.json), [licence review paketi](bridge-notice-review-pack-2026-10-06.md) | Privacy/DPO + Legal + Security; kaynak envanteri deployed ölçüm veya imzalı hukuk kararı değildir |
| Teklif scope'u, fiyat/order/provider IDs, destek takvimi, kabul ve karar imzaları | [Commercial Manifest](commercial-release-manifest-template.md), [Support/SLA](support-sla-template.md), [PoV run sheet](pov-001-customer-acceptance-run-sheet.md) | Product, Finance, Commercial, Support ve ilgili bağımsız reviewer; müşteri gerektiren kayıtlar gerçek pilot/production aşamasında |

## GO için sekiz asgari kabul

**Bu tablodaki işler paket hazırlığıyla yapılmış sayılmaz.** Ön müşteri GO için isimli müşteri, müşteri IdP/MDM'i, imzalı sipariş veya müşteri PoV'si gerekmez; AIDR hesapları, cihazları, altyapısı ve bağımsız reviewer kullanılabilir. Mevcut FCR profili **hem self-hosted hem managed-cloud** yolunun kabulünü ister. Staging kurmama tercihi bu hazırlıkta uygulanır; ilerideki gerçek kabul koşullarını kaldırmaz.

| Kapı | Paketle hazırlanabilen | GO öncesi gerçekten tamamlanacak |
|---|---|---|
| FCR-01 — aday ve trust | Temiz source snapshot, immutable inventory/SBOM/provenance, kit/zarf ve doğrulayıcı yolu | Onaylı yayıncı imzası; ikinci makinede bağımsız trust ile tamper/expiry/wrong-signer/rollback reddi. Commit edilmiş snapshot tek başına onay değildir |
| FCR-02 — mühendislik | Aynı adaya bağlı test/statik/secret/audit/migration/install/build kanıtlarının toplanması | Zorunlu kontrollerin geçmesi, skip/fail/açık risklerin dürüst tutulması ve kanıt-index bağlarının doğrulanması; unsigned yerel fixture ticari imza değildir |
| FCR-03 — gerçek kurulum | Kurulum, enrollment, policy/event/browser, upgrade/uninstall/recovery betikleri ve kılavuzları | İki yolda gerçek DNS/TLS ve temiz başlangıçla tenant/login/fresh-device/policy/event/export/update/uninstall/failed-upgrade yolculuğu; loopback prova yerine geçmez |
| FCR-04 — host enforcement | Mevcut senaryo/template, kurucu ve destek scope'u | Sunulacak her host/version/OS/architecture için benign twin, deny canary ve bağımsız yan etki gözlemi; disabled/crash/timeout/offline/restart/update/rollback; named review. Eksik host kapsam dışıdır |
| FCR-05 — güvenlik ve veri | Triage, redaction/tenant/egress/retention/deletion ve bağımsız review hazırlığı | History bulgularına Security disposition ve canlı sırların revoke/rotation'ı; iki tenant negatifleri, gerçek veri akış kontrolü, kapsamlı bağımsız review, HIGH/CRITICAL düzeltme ve retest |
| FCR-06 — geri kazanılabilir operasyon | Backup/restore/timer/monitoring ve on-call örnekleri | İki yol için ayrı failure domain'e doğrulanmış restore ve bağımsız recovery erişimi, ölçülmüş RPO/RTO, başarısız backup/restore alarmı ve zamanlı gerçek destek drill'i |
| FCR-07 — yük ve arıza | Workload/noisy-neighbor/failover şablonları ve sonuç schema'sı | İki topolojide kimlikli temsilî yük, en az sekiz saat soak, iki tenant noisy-neighbor, node/DB/network arızası ve kayıp/latency ölçümü. Bu koşul 99.9% SLA onayı değildir |
| FCR-08 — alıcıya güvenli paket | Scope/exclusion, install/rollback, data-flow, terms/DPA, support/status ve charter taslakları | Legal/Privacy review, gerçek çalışan link/ticket yolları, kabul edilen scope'a uygun claims ve isimli Product/QA/Security/Operations/Privacy-Legal/Support GO kararı |

Optional AIG/MCP/privacy-model/discovery/SSO/SCIM/SIEM/MDM/multi-region/air-gap yolları ancak ayrı kanıtla kapsama alınır. T19 seçilmiş-directory provenance, T37 zorunlu kurum privacy rotası ve T38 onaylı TR/EN PERSON/ADDRESS modeli sunulacak vaadin parçasıysa uygulama ve saha kabulü tamamlanmalıdır. Etkin kapsamdaki tenant kaçışı, bilinmeyen deployment revision, gizlenen zorunlu test, canlı secret riski, kurtarılamayan veri veya onaysız hukuk/gizlilik/lisans/fiyat iddiası kapsam daraltma cümlesiyle geçerli hâle gelmez. Bridge mevcut kapsamda çalışacaksa açık güvenlik bulguları için gerçek Security disposition ve ilgili kabul gerekir; düzeltme sürümü bulunmaması onay değildir.

## Production ve assisted-sale için ayrı 12 kapı

Mevcut registry'de her iki profile aynı 12 zorunlu kapı uygulanır. Aşağıdaki tablo kabulü kaydetmez; gerekli girdiyi mevcut receipt sahibine yönlendirir. Registry kararını veya `open` receipt'leri değiştirmek yalnız yetkili reviewer'ın gerçek, aynı adaya bağlı kanıt ve onayıyla mümkündür.

| Mevcut kayıt | Gerçek dış kanıt/onay | Sahibi |
|---|---|---|
| COM-001 | Approved scope/SKU/fiyat/vergi/term/quote-order/manifest ve quote-to-offboarding prova | Commercial + Finance |
| COM-002 | Exact shipped package/container/native/upstream lisans, notice/source yükümlülükleri ve chain-of-title; açık licence reviews için Legal disposition | Legal + Engineering |
| COM-003 | Deployed field-level data-flow/retention/deletion/region ve gerçek DPA/TOM/uygulanıyorsa transfer aracı | Privacy/DPO + Legal + Security |
| COM-004 | Gerçek provider/order settlement, seats/expiry/revoke/refund/cancel/reconciliation | Finance + Product |
| COM-005 | Gerçek ticket/status/security/contact yolları, on-call/escalation ve timestamp'li destek drill'i | Support + Operations |
| COM-010 | İlan edilen beş direct-GA connector için exact host/OS/version gerçek E2E, signer, install/rollback ve support matrix | Product + QA + Engineering + Support |
| COM-011 | Mevcut EU/US/APAC vaadi için gerçek bölge/provider/placement/cross-region/privacy/backup/deletion kanıtı | Operations + Privacy + Legal |
| COM-012 | Authenticated private-registry imzalı install, invoice-entitlement/revoke ve satılıyorsa gerçek disconnected-host teslim | Finance + Release + Support |
| COM-013 | Onaylı SLI/SLA/credits, gerçek monitoring verisinden tam aylık pencere, incident ve support kanıtı | Operations + Legal + Support + Finance |
| SEC-EXT-001 | Aynı aday ve satılan scope için bağımsız assessment, remediation/retest ve gerekiyorsa kaydın izin verdiği isimli/süreli HIGH disposition; CRITICAL waivable değildir | Security + bağımsız assessor |
| POV-001 | İsimli customer/evaluator, imzalı Evaluation Charter, bağımsız gerçek koşu, intervention/deviation kaydı ve kabul/rezervasyon | Customer Success + Product + evaluator |
| CLM-001 | Aynı adaya bağlı claim registry/build taraması, kanıt eşlemesi ve Sales/Legal approval | Product/Marketing + Commercial + Legal |

Ön müşteri hazırlığı bu müşteri bağımlı işleri ortadan kaldırmaz. Gerçek müşteri pilotu öncesi yazılı izin, ilgili hukuk/gizlilik/güvenlik incelemesi ve müşterinin ortamında uygulanabilir kabul koşulları tamamlanır. Sınırlı değerlendirme teklifi için FCR GO, production veya ücretli GA satışına otomatik izin değildir.

## Çalıştırma sırası ve karar sınırı

1. Source/draft/konfigürasyon kapsamını dondurun. İzole temiz aday oluşturun; ana çalışma ağacında eşzamanlı build/gate çalıştırmayın. Landing gibi ayrı uygulama varsa kendi source/build kimliğiyle kaydedin.
2. Paket ve dış zarfı yeni çıktı dizinlerinde üretin. Üretim yetkisi olmayan anahtarı gerçek yayıncı gibi sunmayın. Onaylı signature için yayıncı ve ayrı trust teslimi gerekir; private key pakete girmez.
3. Yerel hazırlıkta mevcut `node scripts/run-evidence-gates.mjs --profile first-customer-local` akışını ve `pnpm evidence:index:verify` bağ kontrolünü kullanın. Runner eski fixed-output dosyalarını korur; collision'da yeni izole worktree gerekir. `first-customer-local`, 18/19/25/30 kapılarını `NOT_RUN` bırakır. Runner'ın exit 0 vermesi veya index'in hash doğrulaması **GO değildir**; her required sonuç ve açık scope/review kaydı ayrıca okunur.
4. Gerçek host/kurulum/recovery/load/provider girdileri hazır olduğunda ilgili kılavuzlarla aynı immutable aday üzerinde kabulü çalıştırın. Bu teslim kapsamında bu ortamlar açılmaz. Kanıtları sırlardan arındırın; failures, skips, interventions ve exclusion'ları saklayın. Sonuçtan sonra kaynak, aday veya bağlı byte'lar değişirse etkilenen kanıt yeniden üretilir.
5. FCR için isimli yetkili owner kararını; production/assisted-sale için ayrıca mevcut 12 receipt'in gerçek onaylarını alın. Kanıt indeksi run artifact olarak kalır; sonradan commit edip commit/candidate bağını bayatlatmayın. [Kanıt indeksi sırası](evidence-index-regeneration.md) ve [external gates runbook](external-gates-runbook.md) uygulanır.

Teslim sonunda kullanıcıya paket/zarf, checksum/envanter, kurulum başlangıç belgesi ve gerçek doğrulama loglarının **mevcut mutlak yolları** verilir. Taşınabilir paketin hazırlanmış olması ile FCR/production kararının ayrı olduğu açıkça belirtilir.

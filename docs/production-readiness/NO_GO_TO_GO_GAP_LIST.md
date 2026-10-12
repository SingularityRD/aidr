# NO-GO → GO: eksiksiz eksik listesi

Üretim tarihi: 2026-10-08, bölüm A ve I 2026-10-09 güncellendi (kayıtlardan ve yerel ölçümlerden türetilmiş anlık görüntü). Kaynaklar: `PRODUCTION_SALES_GAPS.json`, `FEATURE_INVENTORY.json`, `commercial-go-evidence-registry.json`, `commercial-gate-receipts.json`, `READINESS_BACKLOG.json`, `deploy/native/support-matrix.json`, `first-customer-ready.md`, `HANDOFF.md` ve 8 Ekim 2026 yerel ölçümleri. Bu belge **kabul defteri değildir**; karar kaydı registry + receipt'lerdir. Plan: [SALE_READY_COMPLETION_PLAN.md](./SALE_READY_COMPLETION_PLAN.md). Eski/bayat üretilmiş kayıtlar değişirse bu liste yeniden türetilmelidir.

**Karar kuralı:** Bir seviye için listelenen her madde kapanmadan karar **NO-GO** kalır. Kapanış = aynı aday için gerçek kanıt + isimli sahip + (gerekiyorsa) bağımsız gözden geçiren. Yerel test geçişi dış kanıt yerine geçmez.

## 0. Sayılarla özet

| Kategori | Adet |
|---|---|
| Anlık engeller (8 Eki ölçümü) | 8 madde, bölüm A |
| Zorunlu dış kapı (registry) | 13 (hepsi `open`) |
| FCR kapısı (kontrollü değerlendirme) | 8 |
| Teknik iş paketi | 47 (3 OPEN kod işi + 44 saha kabulü açık) |
| Kısmi / dış yetenek | 41 kısmi + 2 dış = 43 / 109 |
| Backlog `BLOCKED_EXTERNAL` | 9 |

## A. Anlık engeller — hiçbir şeyden önce (yeniden ölçüldü, 9 Ekim 2026, `master` @ `c2a0f5f0`)

8 Ekim'deki kırıkların çoğu #97–#99 ile kapandı (zod 4, koffi 3, react-dom 19.3, tokenizers,
Python 3.14 / Node 26 imajları ve codeql bump'ları geri alındı; `ci:local` kayması ve SCIM
fixture'ları düzeltildi). 9 Ekim ölçümü: `pnpm install --frozen-lockfile`, `pnpm check`,
`pnpm build`, `pnpm ci:local --list` → çıkış 0; `pnpm lint` → 0 hata, 746 uyarı; 494 kural / 29
dosya; 178 `supabase/migrations/*.sql` (`c2a0f5f0` ölçümünde 176; sonradan `20261009000100` ve
`20261009000200` eklendi). Docker çalışmıyor.

| # | Engel | Durum (9 Eki) | Kapanış ölçütü | Kim |
|---|---|---|---|---|
| A1 | `pnpm check` (zod 3→4, #75) | **Kapandı** — geri alındı, `check` yeşil. zod 4 göçü ayrı iş olarak açık | zod 4 göçü ayrı PR'da `check/build/test` yeşil | Mühendislik |
| A2 | `pnpm build` (koffi 2→3, #95) | **Kapandı** — geri alındı, `build` yeşil. koffi 3 göçü açık (`stage-windows-koffi.mjs` yol değişikliği) | koffi 3 ile Windows AMSI paketi doğrulandı | Mühendislik |
| A3 | react-dom 19.3 / react 19.2 (#80) | **Kapandı** — geri alındı; dashboard dahil tam test yeşil (A9) | react-dom 19.3 göçü ayrı PR | Mühendislik |
| A4 | SCIM admin contract kırmızıları | **Kapandı** (#97: `directory_id` fixture'ları) | — | Mühendislik |
| A5 | `ci:local --list` kayması | **Kapandı** (#98) | `ci:local --keep-going` temiz (Docker adımları hariç, gerekçeli) | Mühendislik |
| A6 | 746 `biome` uyarısı | Açık | baseline + yeni uyarı yok | Mühendislik |
| A7 | Merge edilmiş major bump'lar | Açık: jsdom 30, pino 10, @vscode/test-electron 3, @opencode-ai/plugin 1.18 tam test dışında tek tek doğrulanmadı | her biri için ilgili paket + E2E | Mühendislik |
| A8 | Yayındaki landing ve pilot depoyla uyuşmuyor (24 Eyl bulgusu) | Açık | landing kaynağı depoda ve taranmış; claim-check temiz; hostname çözülüyor | Ürün/Pazarlama + Operasyon |
| A9 | Tam `pnpm test` (9 Eki) | **Kapandı** — 628 dosya / 11.041 test geçti, 0 başarısız (I.0) | — | Mühendislik |
| A10 | **Postgres'te hiç çalışmamış 22 migration** (bölüm I.1) | Açık — yalnız statik testlerden geçti | Docker'lı ortamda 41 `*-postgres` paketi + yeni migration'lar temiz DB'ye ve mevcut veriye uygulandı | Mühendislik + DB |

## B. Zorunlu dış kapılar (registry `hardGates`)

- **evaluation** profili (8): COM-001, COM-002, COM-003, COM-005, COM-010, COM-011, POV-001, CLM-001
- **assisted-sale** profili (12): COM-001, COM-002, COM-003, COM-004, COM-005, COM-010, COM-011, COM-012, COM-013, SEC-EXT-001, POV-001, CLM-001
- **production-ga** profili (12): COM-001, COM-002, COM-003, COM-004, COM-005, COM-010, COM-011, COM-012, COM-013, SEC-EXT-001, POV-001, CLM-001
- **investor** profili (12): COM-001, COM-002, COM-003, COM-004, COM-010, COM-011, COM-012, COM-013, SEC-EXT-001, POV-001, INV-001, CLM-001

| Kapı | Gereksinim | Gereken kanıt | Sahip | Receipt |
|---|---|---|---|---|
| COM-001 | Commercial Release Manifest fixes SKU, price, metering, currency/tax, deployment, region, retention, SLA, support, licence rights, renewal, cancellation, and offboarding for the same Release Candidate. | approved manifest; sample quote/order; quote-to-offboarding rehearsal; immutable evidence hash | Commercial/Sales + Finance/Billing | open |
| COM-002 | Licences, notices, attribution, third-party source provenance, chain-of-title, and every shipped package license field are complete and counsel-approved; a non-empty LICENSE must reconcile with NOTICE and package metadata. | counsel approval; non-empty LICENSE; NOTICE/licence bundle; package-license reconciliation; first-party documentation licence audit; source and vendor provenance; exception register with expiry | Legal + Engineering | open |
| COM-003 | Actual telemetry, browser tracing, managed events, AIG payloads, retention, deletion, region, subprocessors, and transfer mechanisms match customer-facing notices and DPA/TOM/SCC terms. | field-level data-flow matrix; payload assertion report; DPA/TOM/SCC approval; subprocessor/region list; deletion/export receipt | Privacy/DPO + Legal + Security | open |
| COM-004 | Price and entitlements are enforced by one provider-of-record and survive order, seat change, invoice/reconciliation, cancellation, revocation, export, and deletion. | provider decision; SKU/entitlement tests; invoice/reconciliation evidence; revocation and deletion receipt | Finance/Billing + Product | open |
| COM-005 | Customer-visible support, status, security contact, privacy/terms, escalation, severity SLA, diagnostic-consent, and reachable ticket paths operate for the sold scope. | published support schedule/SLA; ticket drill with timestamps; status/security/privacy links; on-call escalation record | Support/Customer Success + Operations | open |
| COM-010 | Direct-GA scope includes every advertised connector: Claude Code, Cursor, VS Code, OpenClaw, OpenCode and Codex CLI (Product decision 2026-10-11 added Codex; deploy/native/support-matrix.json soldConnectorScope). The direct-GA scope is a target, not acceptance. Codex keeps its documented host limits on every surface that sells it: the host fails open on a crashing or untrusted hook (the connector maps ask and its own errors to an explicit deny), there is no output-side interception, and the packaged hook matcher covers Bash and apply_patch only. Each connector has a supported-host matrix, signed artifact, private-registry install path, real-host E2E, rollback, support owner, and limitations. | all-connector support matrix; real-host reports; private-registry install logs; rollback/disable drill; owner and limitations | Product + QA + Engineering + Support | open |
| COM-011 | Hybrid deployment supports EU, US, and APAC tenant placement with an approved routing, residency, retention, subprocessors, transfer, backup, and deletion model. | region/provider matrix; tenant placement test; cross-region negative test; DPA/SCC/TOM approval; backup/deletion receipts | Operations + Privacy/DPO + Legal | open |
| COM-012 | Enterprise customers receive invoice-based orders and signed artifacts/connectors through an authenticated private registry; entitlement, revocation, download, audit, and offline/air-gapped procedures are defined. | provider and registry decision; invoice-to-entitlement test; signed package install; revocation/offboarding test; air-gapped procedure | Finance/Billing + Release Engineering + Support | open |
| COM-013 | The managed control plane and dashboard API target a 99.9% monthly availability SLA with a measured SLI, exclusions, maintenance policy, service-credit terms, support escalation, and incident evidence. | approved SLA/support schedule; SLI definition and denominator; observation window; maintenance/exclusions; service-credit and incident drill | Operations + Legal + Support + Finance | open |
| SEC-EXT-001 | Independent penetration test or equivalent assessment has no unresolved critical/high finding for the sold Release Candidate and scope. | signed report; scope and dates; remediation/retest letter; exception approvals with expiry | Security Lead + independent assessor | open |
| POV-001 | A named customer or investor evaluator completes the signed Evaluation Charter, independent sandbox/PoV, mandatory scenarios, limitations review, and acceptance/reservations for the same Release Candidate. | signed charter; independent run report; intervention/deviation log; customer result/reservations; immutable evidence index | Customer Success + Product + evaluator | open |
| INV-001 | Every investor-facing technical, customer, security, compliance, traction, and financial metric has a formula, denominator, source, Release Candidate/environment, observation window, owner, reviewer, and limitation/confidence statement. | approved metric dictionary; source query or signed source; period/sample/denominator; reviewer approval | Product + Finance + Legal | open |
| CLM-001 | All customer, investor, procurement, landing, README, plugin, and sales claims are mapped to the Claim Registry; only approved, unexpired claims appear on release-facing surfaces. | registry snapshot; build-output scan JSON; claim-to-evidence links; Sales Approved review | Product/Marketing + Commercial + Legal | open |

## C. FCR-01…08 — kontrollü değerlendirme (AIDR'ın kendi hesap/altyapısıyla)

Her satır aynı **temiz kaynak commit + release envanteri digest'i** için PASS receipt ister. Başarısız/bilinmeyen satır açık kalır.

| ID | Eksik (kısaca) |
|---|---|
| FCR-01 aday ve güven | Vendored AIG ağacı sahip-kaynak pin'ine karşı doğrulanmış; temiz ağaçtan inşa; değişmez envanter/SBOM/provenance; **onaylı yayıncı kimliğiyle imza (anahtar paket dışında)**; ikinci makinede bağımsız güven politikasıyla doğrulama; tamper/expiry/yanlış imzacı/rollback reddi. |
| FCR-02 mühendislik | Aynı adayda tip/statik, birim/entegrasyon, prod bağımlılık + sır taraması, kanonik migration, paket-tüketici kurulumu, release build, kanıt-indeks doğrulaması. Atlamalar saklanır. Yüksek/kritik açık bağımlılık yok. |
| FCR-03 gerçek kurulum | **Hem self-hosted hem managed-cloud**, gerçek DNS/TLS: migration, tenant bootstrap, giriş, taze cihaz kaydı (device-start/poll), `managed.json`, politika yayını, olay alımı, tarayıcıda görüntüleme/dışa aktarma, güncelleme, kaldırma, başarısız yükseltme. |
| FCR-04 host zorlaması | Sunulacak **her connector × host × OS × mimari** için lisanslı gerçek ikili: benign-twin, güvenli deny canary, bağımsız yan etki gözlemi, devre dışı/çökme/zaman aşımı/çevrimdışı/yeniden başlatma/güncelleme/geri dönüş, isimli gözden geçiren. Eksik host kapsam dışı. |
| FCR-05 güvenlik ve veri | Tam git geçmişi sır taraması triyajı (AIDR-070), canlı sırların iptali/döndürülmesi; iki tenant negatif erişim, kimlik iptali, imza sınırları, çıkış alanları, günlük/destek paketi redaksiyonu, saklama/silme/yedek sona erme; kapsamlı bağımsız inceleme, HIGH/CRITICAL düzeltme + yeniden test. |
| FCR-06 kurtarılabilir operasyon | İki yol için ayrı arıza alanında off-host yedek, bağımsız kurtarma anahtarı erişimi, başka makine/projeye geri yükleme, kayıt/nesne karşılaştırması, **ölçülmüş RPO/RTO**, başarısız yedek/geri yükleme alarmı, zamanlı gerçek destek tatbikatı. |
| FCR-07 yük ve arıza | İlan edilen pilot sınırı (cihaz, eylem hızı, tenant, saklama); iki topolojide kimlikli temsilî yük **≥ 8 saat**; p50/p95/p99/hata/kayıp; iki tenant gürültülü komşu; node/DB/ağ arızası. SLA onayı değildir. |
| FCR-08 alıcıya güvenli paket | Kapsam/hariç tutulanlar, kurulum/geri alma kılavuzu, veri akışı ve alt işleyenler, pilot şartları/DPA/saklama (Hukuk/Gizlilik incelemeli), çalışan iletişim/durum yolu, "onaylı siparişle" fiyat ifadesi, Evaluation Charter şablonu; dağıtılmış demo ve yasal bağlantılar taranmış; isimli Product/QA/Security/Operations/Privacy-Legal/Support GO kararı. |

## D. Teknik / operasyon iş paketleri (T01…T47)

`OPEN` = hâlâ kod/entegrasyon işi. `SAHA` = yerel uygulama var, gerçek ortam/müşteri/operatör kabulü açık.

| ID | Ö | Tür | Başlık | Sahip | Bağımlılık | Kabul ölçütü | Kalan uygulama |
|---|---|---|---|---|---|---|---|
| T01 | P0 | SAHA | Gerçek host ve işletim sistemi kapsamı | QA + Endpoint Engineering | Müşteri test cihazları, runtime erişimi ve sürüm seçimi | Her zorunlu saldırıda yan etkinin oluşmadığını bağımsız kaydet; zararsız işlemler geçsin; kanca kapalı/bozuk/ağsız durumları ve yeniden başlatma ayrı sınansın. | — |
| T02 | P0 | SAHA | Bağlayıcılar arasında araç adı ve girdi normalizasyonu | Core + Connector Engineering | AIDR-060; native host matrisi | Aynı yasak paket, manifest ve dosya girdisi tüm bağlayıcılarda aynı denetime ulaşsın; denetleyici çağrısı ve engellenen yan etki kanıtlansın; boş/alternatif alan adları negatif test edilsin. | — |
| T03 | P0 | SAHA | Paket denetiminde hatanın sessiz kaybolması | Detection Engineering | AIDR-061; desteklenen araç sözleşmesi | Registry timeout, bozuk cevap, cache/intel ayrıştırma hatası ve denetleyici exception enjekte et; zorunlu kontrol sessiz allow üretmesin; benign ve iptal davranışları korunsun. | — |
| T04 | P1 | SAHA | Model tüketiminden önce çıktı denetimi | Connector + Detection Engineering | Host API kabiliyeti; MCP gateway | Parçalara bölünmüş saldırı, sınırın sonundaki payload, Unicode, JSON/text ve çok büyük cevaplar sınansın; engellenen baytlar modele ulaşmasın; zararsız çok parçalı cevap bozulmasın. | — |
| T05 | P1 | SAHA | Davranış, novelty ve ML kararlarının ürün akışına bağlanması | Detection + Data Engineering | Etiketli müşteri verisi ve bağımsız ölçüm seti | Soğuk başlangıç ve model yenilemede kararlı sonuç; tenant ayrımı; veri zehirleme denemeleri; holdout saldırı ve zararsız iş yükünde yanlış alarm ölçümü. | — |
| T06 | P1 | SAHA | Reputation ve AI altyapı verisinin güncelliği | Detection + Operations | Sağlayıcı/feed erişimi, Windows host ve müşteri corpus'u | Eski/bozuk/boş feed temiz verdict üretmesin; güncelleme/geri dönüş kanıtlansın; gerçek endpoint ve AMSI desteklenen Windows hostunda ölçülsün. | — |
| T07 | P1 | SAHA | MCP keşfi ve kimlik normalizasyonunun kapsamı | Endpoint + MCP Engineering | Host sürüm ve konfigürasyon matrisi | Bozuk/izin verilmeyen dosya, JSONC, boş argüman, alias ve aynı isimli farklı sunucu testleri; eksik tarama güvenli envanter gibi görünmesin. | — |
| T08 | P1 | SAHA | İmzalı MCP araç tanımı ve değişiklik onayı | MCP + Security Engineering | AIDR-046; signer/key custody ve yönetim UI'sı | Description/schema değişimi, eski manifest, yanlış signer, yeniden başlatma, eş zamanlı değişiklik ve onaysız retry reddedilsin; ajan kendi aracını onaylayamasın. | — |
| T09 | P1 | SAHA | Kullanıcı–ajan–araç–kaynak ilişkisi ve delegasyon | Identity + Backend Engineering | IdP ve araç sağlayıcısı API'leri | Başka tool/resource/audience için token kullanımı, süresi bitmiş delegasyon, kullanıcı ayrılması ve zincir yetki büyütme reddedilsin; olaydan kaynağa iz sürülsün. | — |
| T10 | P1 | SAHA | MCP gateway ve taşıma güvenliği | MCP + Network Security | AIDR-062; stdio/HTTP/SSE kapsam kararı | Kontrol ile bağlantı arasında DNS değişsin; private/mapped IPv6, redirect, başlıksız sonsuz stream, sınır aşımı, disconnect ve bozuk JSON/SSE ile gerçek ağ testi çalışsın. | — |
| T11 | P1 | SAHA | Sürekli kurum/filo keşfi | Discovery + Backend Engineering | Müşteri onaylı cloud/MDM API kapsamı ve credentials; üretim scheduler/paging ortamı; tool-provider kabulü | Onaylı kaynak dışında envanter gösterilmesin; tenant dışı rapor okunamasın; eski/partial cycle healthy görünmesin; raporlanmayan estate kapsamı çıkarılmasın; gerçek provider API, schedule ve paging tatbikatı ile tool-provider credential … | — |
| T12 | P1 | SAHA | Filo müdahalesi ve credential iptali | Response + Endpoint Engineering | OS yetkileri, sağlayıcı API'leri, müşteri müdahale yetkisi | Offline ajana süresi geçmiş komut uygulanmasın; tekrar gelen komut tek etki üretsin; başarısız izolasyon başarı görünmesin; ilgili izinler ve geri dönüş kanıtlansın. | — |
| T13 | P1 | SAHA | Response eylemlerinin güvenli uçtan uca işletimi | Response Engineering + Security Operations | Müşteri dosya sistemi/EDR/SOAR izinleri | Dosya sonradan değişmişken yanlış rollback yapılmasın; symlink/izin/disk hatası açık başarısız olsun; eylem ve geri dönüş aynı incidentten izlenebilsin. | — |
| T14 | P1 | SAHA | YAML politika yazımı ile gerçek runtime ilişkisi | Policy + Dashboard Engineering | Politika sözleşmesi ve migration planı | Kaydedilen/yayınlanan politika gerçek ajan kararında değişiklik üretsin; bilinmeyen alan sessiz atılmasın; allowlist ile açık deny önceliği doğrulansın. | — |
| T15 | P1 | SAHA | Politika dağıtımı saha kabulü ve ölçek sınırları | Policy + QA + Operations | Ajan sürümü, müşteri offline toleransı | Yetkisiz/stale receipt, rollback, offline süresi, 401/403, bozuk cache, yeniden başlatma ve hedef değiştirmede yanlış sürüm uygulanmasın; gerçek filoda yakınsama ölçülsün. | — |
| T16 | P1 | SAHA | Endpoint sır saklama ve anahtar rotasyonu | Endpoint + Security Engineering | Kurum secret manager'ı ve OS depoları | Yetkisiz kullanıcı sır okuyamasın; eski anahtar zamanında reddedilsin; yenileme kesintisi güvenli olsun; log, argüman ve destek arşivi sır sızdırmasın. | — |
| T17 | P1 | SAHA | İmzalı filo kurulumu, güncelleme ve kaldırma | Release + Endpoint Engineering | MDM test tenantı, signer, OS paketleme araçları | Temiz kurulum, yarım kalan upgrade, eski sürüme dönüş, host güncellemesi ve uninstall sonrasında başka kancalar/politika bozulmasın; gerçek MDM'de kanıt topla. | — |
| T18 | P0 | SAHA | Kurumsal giriş, MFA ve hesap kurtarma | Identity Engineering + Customer IT | IdP/SMTP/DNS ve kurum güvenlik politikası | Kayıp parola/MFA, kapatılmış kullanıcı, süresi dolmuş oturum ve başarısız IdP durumlarını sınayarak hesabın hem geri alınabilir hem yetkisiz erişime kapalı olduğunu kanıtla. | — |
| T19 | P1 | OPEN | SCIM ve güvenilir directory grup eşlemesi | Identity + Backend Engineering | AIDR-019/048; Entra/Okta test ortamı | Sahte metadata, benzer grup adı, grup kaldırma, hesap pasifleştirme, pagination/replay ve tenant karıştırma testleri; erişim belirtilen süre içinde kesilsin. | Clerk native API seçili-directory-active bilgisini her grant için sağlamıyor; manual/başka-directory üyeliğin strict deny garantisi için desteklenen provider kabiliyeti veya kurum kontrolü gerekir. |
| T20 | P1 | SAHA | Davet ve cihaz kayıt yaşam döngüsü | Identity + Customer Success | SMTP/IdP ve müşteri cihazları | Kullanılmış/iptal edilmiş davet, rol değişimi, başka ekip, eski device code ve kimlik değişiminde kayıt reddedilsin; mail linki gerçek tarayıcıda doğru ekibe dönsün. | — |
| T21 | P0 | SAHA | Mevcut API anahtarında ekip ve üyelik iptali | Backend Security | AIDR-063; yerel yeniden üretim kanıtı | Aktif kimlik 200; suspended/closing/closed tenant, expired/removed membership ve revoked key tüm tüketicilerde 401/403; stale cache ile erişim sürmesin. | — |
| T22 | P0 | SAHA | Tenant izolasyonu ve kaynak tüketim sınırları | Security + Backend + SRE | Bağımsız değerlendirme ve tanımlı yük profili | Farklı tenant, üyelik kaybı, viewer, eski anahtar, büyük body ve paralel isteklerle negatif matris çalışsın; tek tenant diğerinin SLO'sunu tüketemesin. | — |
| T23 | P0 | SAHA | Telemetri dayanıklılığı ve görünür veri kaybı | Telemetry Engineering + SRE | Müşteri cihaz/olay hacmi ve saklama hedefi | Ağ/DB/storage kesintisi ve ajan yeniden başlatmada kayıp/duplicate ölç; sessiz olay kaybı olmasın; disk dolması ve gecikme kullanıcıya görünür olsun. | — |
| T24 | P1 | SAHA | SIEM ve yerel telemetry üretim teslimi | Integrations + Customer SOC | SIEM test hesabı ve event schema anlaşması | SIEM kesintisi/429/401, sertifika değişimi, yeniden gönderim ve alan eşlemesi gerçek SIEM'de doğrulansın; yanlış başarı bildirimi olmasın. | — |
| T25 | P1 | SAHA | Olay araştırması ve kanıt bütünlüğü | Detection + SOC Product | Kimlik grafiği, güvenilir zaman ve arşiv sahibi | Saat kayması/duplicate/offline sıralama, silinmiş veya değiştirilmiş zincir ve çok ajanlı saldırıda kanıt boşlukları görünür olsun. | — |
| T26 | P0 | SAHA | Saklama, legal hold ve müşteri çıkışı | Backend + Privacy + Operations | Onaylı saklama/silme politikası; yedek istisnaları | Süre dolan verinin API, Storage, cache ve replikalardan yokluğu; hold verisinin korunması; retry ve yarım silme sonrası tutarlılık kanıtlansın. | — |
| T27 | P0 | SAHA | Offsite yedekleme ve RPO/RTO | SRE + Customer Operations | Offsite storage, key custodian, kabul edilmiş RPO/RTO | Yeni hostta yalnız offsite yedek ve ayrı anahtarla kurtar; tablo/nesne içerikleri eşleşsin; gerçek kayıp veri süresi ve toparlanma süresi ölçülsün. | — |
| T28 | P0 | SAHA | Gerçek cloud ve self-hosted üretim kurulumu | SRE + Customer IT | Alan adı, cloud hesabı/bölge ve ağ bilgisi | Temiz makinede müşteri kimliğiyle giriş→cihaz→deny→olay→export→rollback akışı; dış port/izin kontrolleri ve sertifika yenileme tatbikatı. | — |
| T29 | P0 | SAHA | Kimliği doğrulanan dağıtım ve release provenance | Release Engineering + Security | Signer ve registry yetkisi; lisans onayı | Yanlış signer/değişmiş arşiv/eski sürüm reddedilsin; müşteri temiz makinede internetsiz veya yetkili registry ile kurabilsin; imza/anahtar iptali sınansın. | — |
| T30 | P0 | SAHA | HA, failover, kapasite ve SLA ölçümü | SRE + Performance Engineering | Host boyutları, filo/olay profili, SLA anlaşması | Gerçekçi agent/event yükünde p50/p95/p99, hata/kayıp oranı, DB/servis/node arızası ve bakım etkisi raporlansın; kabul edilmiş gözlem penceresi tamamlanmış olsun. | — |
| T31 | P0 | SAHA | Migration, upgrade ve geri dönüş tatbikatı | Backend + Release + SRE | Önceki sürüm snapshotları ve bakım penceresi | Eski veriyle upgrade, kesilen migration, checksum değişikliği, uygulama/DB sürüm uyuşmazlığı ve kurtarma testi; veri kaybı ve sessiz schema drift olmasın. | — |
| T32 | P0 | SAHA | İzleme, alarm ve işletim sahipliği | SRE + Support | Gerçek izleme/paging kanalları ve isimli sorumlular | Servis, DB, storage, signer, kuyruk ve yedek hatası enjekte et; doğru kişiye zamanlı alarm ve çözüldü bildirimi gelsin; kayıtlı tatbikat tut. | — |
| T33 | P0 | SAHA | Satılan fatura ve entitlement yaşam döngüsü | Finance + Billing Engineering | Ticari karar, canlı provider anahtarları ve muhasebe onayı | Sipariş/ek koltuk/azaltma/yenileme/ödeme hatası/iptal ve mükerrer webhook aynı entitlement sonucunu versin; finans mutabakatı ve müşteri makbuzu eşleşsin. | — |
| T34 | P1 | SAHA | Readiness kayıtlarının ve ürün iddialarının tutarlılığı | Product + Release + Marketing | Güncel release candidate ve ticari onay sahipleri | Aynı sürümün paket/özellik/claim sayıları tutarlı; eksik paket zorunlu gate'i düşürsün; süresi dolmuş/onaysız iddia müşteri yüzüne çıkmasın. | — |
| T35 | P0 | SAHA | Test kapılarının kapsamı ve başarısızlığın saklanmaması | QA + Security Engineering | Native ortam, bağımsız corpus ve CI kapasitesi | Her satılan özellik için gerçek tüketicide deny/allow/outage kanıtı; aynı candidate checksum; 0 açıklanmamış zorunlu skip; değişmeyen timeoutlarla tekrar koşu ve açık borç kaydı. | — |
| T36 | P1 | SAHA | Operatör UI ve ilk müşteri kullanılabilirliği | Dashboard + Design + Customer Success | Desteklenen browser ve müşteri kullanıcıları | Yanlış ekipte sır/politika görünmesin; timeout/409/401 sonrası yanlış başarı olmasın; klavye ile kritik işler tamamlansın; büyük liste ve uzun değerlerde UI bozulmasın. | — |
| T37 | P0 | OPEN | Gerçek veri akışı, redaksiyon ve gizlilik kanıtı | Privacy + Security + Engineering | DPA ve müşteri veri sınıflandırması; hukuk incelemesi | Canary sırlar izinsiz kanalda bulunmasın; opt-out ve retention davranışı ölçülsün; bütün veri sınıfları için bölge/erişim/silme sahibi belli olsun. | Kurulu broker/MCP/CLI gönderim yolları bağlıdır; bütün native/browser/model-provider alternatif yollarını kapatan kurum MDM/egress dağıtımı ve gerçek authority materyali henüz yok. |
| T38 | P1 | OPEN | Kuruma özel DLP ve veri etiketleri | Detection + Customer Security | Etiket/kural sözlüğü ve maskelenmiş test verisi | Sentetik ve kuruma özgü sırlar tüm kapsanan giriş/çıkışlarda yakalansın; yetkili benign işlem geçsin; örnek dışı format unavailable olarak raporlansın. | Gerçek TR/EN NER candidate'ları ölçülen type recall/temiz yanlış alarm eşiklerini geçmedi. Onaylı kurum corpus/model ile formatı koruyan Office/PDF, gerçek ASR timestamp ve tam-frame video yolları … |
| T39 | P1 | SAHA | Bağımsız etkinlik, performans ve rakip kıyaslaması | Detection Research + QA + Independent Evaluator | Müşteri benign corpus'u, rakip değerlendirme erişimi, ölçüm bütçesi | Aynı workload/ortamda ham ölçüm, payda, sürüm, örneklem ve bağımsız değerlendirici imzası; görünmeyen yüzeyler başarı ortalamasına katılmasın. | — |
| T40 | P0 | SAHA | Güvenlik güncellemesi ve müşteri destek işletimi | Support + SRE + Security | İsimli ekip, iletişim kanalları, sözleşme ve çalışma saatleri | Gerçek ticket aç/kapat, kritik incident ve imza anahtarı kaybı tatbikatı; müşteri bildirim süresi, rollback ve sır içermeyen tanılama kanıtlansın. | — |
| T41 | P1 | SAHA | İlk müşteri satış ve satın alma değerlendirme paketi | Sales Engineering + Product + Legal + Finance | Müşteri satın alma formu, teklif sahibi, onaylı ürün kapsamı | Bir operatör kılavuzdan demoyu tekrar edebilsin; procurement soruları kaynak/kanıt/owner'a bağlı olsun; teklif kapsamı ile kurulan özellik ve destek koşulları eşleşsin; müşteri adı olmadan referans/başarı hikayesi uydurulmasın. | — |
| T42 | P0 | SAHA | Legacy RLS tenant yaşam döngüsü ve itibar satırı sahteciliği | Database + Security | Mevcut deployment verisi ve migration penceresi | Eski üye veya askıya alınmış tenant okuyamasın; başka tenant için insert reddedilsin; mevcut veride sahte kayıt kalmasın ve servis rolü işlemleri çalışsın. | — |
| T43 | P1 | SAHA | Enrollment exchange işlem bütünlüğü | Identity + Backend | Müşteri kurulum ortamı ve canlı DB | Hata rollback yaparken token yeniden kullanılabilsin; başarıda yalnız bir kimlik oluşsun; kayıp yanıt açık unknown durumuna düşsün. | — |
| T44 | P1 | SAHA | Entitlement grace ve eski imzalı önbellek geçişi | Identity + Endpoint | İmzalı eski kayıtlar ve müşteri ağ takvimi | 168 saat sonrasında 72 saat grace, ardından deny; iptal edilen/bozuk anahtar her aşamada reddedilsin. | — |
| T45 | P1 | SAHA | Device-start güvenilir IP ve giriş yönlendirmesi | Platform + Identity | TLS proxy, sır yönetimi ve müşteri ağı | Sahte başlıklar oranı değiştirmesin; imzasız istek 401; meşru kayıt akışı iki dağıtım modelinde çalışsın. | — |
| T46 | P1 | SAHA | Device-poll onaydan kayda atomik geçiş | Identity + QA | Canlı kurulum ve gerçek cihaz | Bir onay en çok bir token üretir; insert hatası oturumu tüketmez; tekrar poll belirsiz durum olarak raporlanır. | — |
| T47 | P1 | SAHA | Tarayıcı gizlilik koruması (Browser Guard) ve AIDR Privacy saha kabulü | Browser Guard + Privacy Engineering + QA | Müşteri tarayıcı filosu, MDM/GPO erişimi, mağaza/yayıncı hesabı ve COM-003 onayı | Her desteklenen canlı sitede TR/EN kişisel veri ve sırlar gönderimden önce maskelenip yanıtta doğru geri açılsın; tarama hatası veya eksik tarama gönderimi engellesin; yönetilen kilitli ayar kullanıcı tarafından değiştirilemesin; … | — |

## E. Kısmi ve dış yetenekler (envanter)

| ID | Yetenek | Durum | Kalan |
|---|---|---|---|
| DET-06 | Prompt injection inspection | partial | The real-host records quarantine one secret-bearing Bash/exec result with a scripted model; prompt-injection payloads, MCP and non-text results, Cursor/VS Code and Codex (no output interception) are not host-accepted, and OpenClaw's pre-model quarantine covers only the explicitly enabled plugin on the embedded runner (not the Codex harness); provider streams and native host … |
| DET-07 | Structured DLP and PII | partial | Real labels and TR/EN NER efficacy are unaccepted; later host callbacks cannot guarantee same-turn output blocking; unsupported opaque formats fail closed |
| DET-08 | Behavioral and novelty analysis | partial | Exit zero is not business success or process-tree isolation; real corpus efficacy, customer role custody and native OS acceptance remain required; OS owner can roll back the whole vault and journal |
| DET-09 | ML classification and similarity | partial | No independently validated production model efficacy or broad runtime adoption |
| DET-10 | URL reputation | partial | Provider feed, operational freshness and customer latency proof still required |
| DET-11 | File reputation and AMSI | partial | AMSI requires native Windows host acceptance; no clean verdict on unavailable leg |
| DET-12 | Package and plugin supply chain | partial | Registry/provider provenance and customer dependency corpus still need acceptance |
| DET-14 | Prompt protection and DLP input redaction | partial | The four records cover linux/x64, a development build and a scripted mock model only (no Windows/macOS/arm64, signed artefact or real model); the Cursor and VS Code prompt hooks have no real-host record and are not sold as enforced; a Codex prompt hook that is untrusted, crashed or timed out, and a Claude Code or VS Code hook killed before it answers, let the prompt through … |
| DET-16 | Data and context poisoning protection | partial | Pattern-based: a paraphrased instruction without a covered signal is caught only by the path-based review; shell writes built at run time are not attributed; tool descriptions are visible only through the MCP gateway or signed manifests; Codex has no read-time layer and enforces ask as deny; PyPI adoption uses release count because it has no download API |
| MCP-05 | Tool description attestation and drift | partial | Direct host paths outside the gateway and trusted publisher provisioning remain open |
| MCP-06 | Identity graph and delegated privileges | partial | Real identity-provider and tool-provider integration remains external |
| MCP-07 | MCP gateway response blocking | partial | Opaque data requires an actually capable guard and otherwise denies; resources/prompts/subscriptions and unrelated GET paths are outside tools scope; host egress controls and customer/native acceptance remain open |
| INF-03 | Continuous fleet discovery | partial | Actual customer cloud IAM/MDM licences, approved scopes, production schedules, paging and provider acceptance remain open; reported resources do not prove whole-estate coverage |
| INF-06 | Agent environment and autonomy posture | partial | A configuration snapshot, not proof of how a session was launched (a command-line flag can override config); Cursor/VS Code auto-run, OpenClaw sandbox and Gemini CLI/Aider autonomy settings are not read, and cloud credential privilege is not assessed |
| RSP-04 | Process containment | partial | No enterprise endpoint isolation or universal process authority |
| RSP-06 | Fleet kill switch and credential revoke | partial | Actual signed Windows VM/firewall/MDM acceptance remains open; non-Windows isolation and universal cloud credential revocation are unsupported; worker is not a SYSTEM impersonation service |
| RSP-07 | SOAR playbook orchestration | partial | External alarm source integration, real Windows permissions/effects, signed distribution, native rollback and customer incident acceptance remain open |
| CLI-04 | Enterprise fleet rollout | partial | Actual Intune/SCCM/Jamf execution and publisher signing acceptance remain external |
| CON-05 | Codex | partial | Host can fail open when hook execution is unavailable (an untrusted, crashed or timed-out hook); the UserPromptSubmit handler must be registered and trusted separately and codex exec shows no reason text for a blocked prompt; no tool output is inspected; not tamper-resistant isolation; the real-host record is recorded on linux/x64 only, with a development build and a scripted … |
| TEN-04 | SSO and directory group sync | partial | Real Entra/Okta provisioning acceptance and the separately audited SAML enforcement/rollback operation remain open |
| TEN-05 | Device pairing and enrollment | partial | Customer TLS proxy routing and browser-to-host pairing acceptance remain pending; direct unsigned device-start is rejected |
| OBS-04 | SIEM delivery and native telemetry | partial | Customer SIEM configuration, scheduled worker, native source coverage and delivery receipt remain open |
| OBS-06 | Retention and deletion | partial | External backups and customer retention/offboarding acceptance remain outside live-data receipts |
| BIL-01 | Invoice-based sales model | partial | Approved quote, provider receipt, reconciliation and audited paid-to-entitlement lifecycle remain open |
| BIL-02 | Stripe checkout and event processing | partial | Live keys/prices/webhook registration, refund/cancel/reconcile and tax acceptance remain open |
| BIL-03 | Subscription self-service portal | partial | Live provider keys, approved price/SKU catalogue, finance reconciliation and accounting approval remain external |
| BIL-04 | Plan catalog, pricing and Stripe plan admission | partial | List prices are not an approved SKU/price manifest (COM-001); self-service remains env-gated and off by default; live Stripe keys/prices, tax, reconciliation and finance approval remain external |
| DEP-02 | Cloud preparation | partial | Live project provisioning, per-region deployment, OAuth/SMTP and secrets installation remain external |
| DEP-05 | Authenticated signed release delivery | partial | Approved publisher key custody and private registry publication remain external |
| DEP-06 | Backup, restore and disaster recovery | partial | Real offsite provider, independent-host recovery and agreed RPO/RTO evidence remain open |
| DEP-07 | Availability and scale | partial | Authenticated workload, HA, capacity, noisy-neighbor and monthly SLI remain unproved |
| DEP-09 | On-prem bundle, resource profiles, posture scanner sidecar and egress … | partial | The Compose bundle is single-host (the Kubernetes chart is DEP-12); customer-host install, air-gap media transfer drill, sizing validation and customer TLS acceptance remain open |
| DEP-10 | Vendor-signed offline licence and offline pack import | partial | The shipped public-key registry is intentionally empty and fails closed until a vendor signing key is generated and custodied; vendor key custody, licence issuance operations and a customer air-gap update drill remain external |
| DEP-11 | Download center and release manifest | partial | No published release host or signed manifest exists yet; signatures depend on publisher key custody (DEP-05) and private registry delivery (COM-012) |
| DEP-12 | Kubernetes Helm chart for the self-hosted control plane | partial | Not exercised on a live cluster. CI does not install kubeconform, so schema validation there is skipped and is recorded only from development runs; without Helm the rendered checks skip (10 of 20 checks skipped in this review's local run). The chart does not deploy the device-start ingress signer or the maintenance timers, HA/failover is unproven (DEP-07) and customer cluster … |
| EVAL-01 | Independent attack and benign benchmarks | partial | Blind holdout corpus, customer benign tasks, latency and evasion evaluation remain open |
| PRV-01 | Browser Guard prompt masking on AI chat sites | partial | Fixture pages are not the live sites: real-site DOM drift, store publication/review and customer browser acceptance remain open; text typed outside a recognised editor or sent by site-internal paths is not visible |
| PRV-04 | Managed browser policy and fleet deployment | partial | Real GPO/Intune/Jamf rollout, store or self-hosted signed distribution and a customer fleet run remain external |
| PRV-06 | AIDR Privacy engine and optional native NER host | partial | Native host installation, NER/OCR accuracy and platform acceptance are unmeasured; privacy suites run separately via test:privacy with named optional-dependency skips (real Tesseract OCR is one) |
| PRV-07 | Shadow AI discovery/control and custom internal AI sites | partial | Counting and the blocked.html explanation page act only on origins the user granted (the block itself uses declarativeNetRequest block rules and needs no grant; without one the user sees the browser's own blocked page); services on a path of a general-purpose host are not catalogued; a worker restart can count a visit twice; other browsers, desktop apps and API clients are not … |
| PRV-08 | Office/OpenDocument document masking, PDF scanning and image OCR … | partial | Without the native host and its OCR no image is inspected, and OCR accuracy is unmeasured; images are blocked, never masked; JPEG 2000, JBIG2, CCITT, DeviceN and Lab images inside PDFs are not decoded (reported as not inspected); PDFs are never rewritten; encrypted PDFs and some CJK font encodings are not extracted; sheet and table names, defined names, named ranges and chart/pivot-cache values are not rewritten; legacy binary Office content is not … |
| EVAL-02 | Legal, privacy, residency and support | external | Named external approvals and candidate-bound proof cannot be generated from source code |
| EVAL-03 | Customer proof of value | external | Customer-run host matrix, observations and signed acceptance outstanding |

## F. Backlog — `BLOCKED_EXTERNAL`

| ID | Ö | Konu | Kabul ölçütü |
|---|---|---|---|
| AIDR-016 | P0 | Enrollment / control-plane connectivity (default endpoint) | A fresh install either completes device enrollment against a reachable endpoint and shows the verification URL+code, or clearly reports local-only protection. No silent 'auth_required' dead end. |
| AIDR-019 | P1 | Dashboard/Edge-Function contract completeness | Local acceptance (verified): no UI code invokes a non-existent function and every invoked function has a contract test in the release manifest. Live acceptance (open): device enrollment completes end-to-end from a browser against the deployed control plane, and live Entra/Okta SCIM provisioning is accepted. |
| AIDR-044 | P0 | Encrypted backup and validated restore | Restore database and objects to an independent environment; prove retention, key recovery and agreed RPO/RTO. |
| AIDR-049 | P0 | Production deployment and native host acceptance | Customer/cloud HTTPS onboarding, SMTP/IdP, supported host/OS canaries and failover evidence for the sold candidate. |
| AIDR-050 | P1 | Enterprise fleet installers and updates | MDM distribution, signed updates, policy-preserving rollback and uninstall across supported hosts. |
| AIDR-051 | P1 | Continuous agent discovery and delegated credential scope | Scheduled fleet/cloud collectors with freshness and identity; short-lived least-privilege tool credentials. |
| AIDR-052 | P0 | Measured availability, scale and isolation under load | Defined workload and observation window, HA/failover, tenant noisy-neighbor tests and agreed availability evidence. |
| AIDR-070 | P0 | Reproducible secret scanning and historical credential triage | The versioned scanner passes the current tree; every historical finding is classified by the Security owner; any live credential is revoked and rotated; approved fixtures receive exact fingerprint exceptions; the full-history release gate passes. |
| AIDR-080 | P0 | Pinned self-hosted upstream container runtime security | Classify exact vendor/package findings with primary evidence, select supported fixed compatible artifacts when available, verify package-recognition coverage and run affected native acceptance. Preserve original findings and do not silently edit pinned upstream source or accept unreviewed repacks. |

## G. Kod tarafında hâlâ yazılabilecek / karar bekleyen işler (HANDOFF §3A + native matrix)

- **T18 kurumsal SAML zorlama yönetimi:** `required_saml_provider_id` için dashboard yönetimi yok; **önce ürün kararı** (kim onaylar, AAL2, geri dönüş hedefi, hangi oturumlar iptal, süre/tekrar kuralları).
- **Azure AD grup eşlemesi (AIDR-019 / T19)** yarım; canlı Entra/Okta sağlama sınanmadı.
- **Öğrenilmiş davranış tespiti (T05)** ürün akışına bağlı değil; katalogda yok, **satılmamalı**.
- **Tespit boşlukları:** hostname'de DNS sızdırma; ters/bölünmüş canary; AI-BOM'da `-p <parola>` maskeleme; iki MCP sunucusuna yayılan zincir; MCP doğrudan upstream bypass (zorunlu yönlendirme).
- **Browser Guard:** PDF içi görseller native host OCR'ına gönderiliyor (host yoksa incelenmemiş sayılıp kapalı kalıyor) ama OCR doğruluğu ölçülmedi; eski `.doc/.xls/.ppt` içeriği taranmıyor; OCR doğruluğu ve ODF/LibreOffice doğrulaması yapılmadı; canlı sitelerde kabul yok.
- **Gerçek host kapsamı:** Cursor ve VS Code hiç çalıştırılmadı; yalnız linux/x64, geliştirme build'i, betikli sahte model; OpenClaw yalnız embedded runner; Codex çıktı yakalama yok; Windows/macOS yok.
- **Docker gerektiren:** 15 Postgres paketi ve `ci:local` Docker imaj adımları, `pwsh` adımı, kök olmayan kullanıcı adımı çalıştırılmadı.
- **NER/PERSON-ADDRESS doğruluk kabulü (600 örnek) hâlâ başarısız:** model onaysız, satış vaadine girmez (T37/PRV-06).
- **Bağımsız etkinlik/rakip kıyaslaması (T39)** harness'i hazır; bağımsız koşu ve rakip erişimi yok.
- **Connector kapsamı tutarsız:** registry 5 "direct-GA" connector, native matrix ve depo 6 connector (Codex dahil). Birini seçip README/matrix/registry'yi hizala.

Native matrix artıkları (`deploy/native/support-matrix.json` → `residual`):

- **T01-NATIVE-SCENARIOS**: Per-host native scenario manifests that drive a real host binary through denied-side-effect, benign-twin, disabled-hook, crash, timeout, offline and restart cases. Girdi: A licensed and installed copy of each sold host on a disposable Windows, Linux and macOS machine Sahip: QA + Endpoint Engineering
- **T01-OS-VERSION-MATRIX**: Pinned operating-system build numbers for each sold platform row. Girdi: First-release supported OS build list approved by Endpoint Engineering Sahip: Endpoint Engineering

## I. 7–9 Ekim çalışmasından kalanlar (kod yazıldı, kabul eksik)

7–9 Ekim'de katalog doğrulaması, 5 alanlı kod incelemesi ve düzeltmeler `master`'a girdi
(Browser Guard dalı birleşti; 494 kural; hook deadline; MCP politika eşitliği; PII maskeleme;
karantina + imzalı karar günlüğü; operatör onayı ve süreli istisnalar; plan kapısı; Shadow AI
panel kontrolü; operatör konsolu; gizlilik geçidi paketleme; çok sayıda güvenlik düzeltmesi).
Aşağıdakiler hâlâ açık.

### I.0 Tam test (9 Ekim, `c2a0f5f0`)

`AIDR_TEST_NO_BUILD=1 pnpm exec vitest run` (Windows 11, Node 24.18.1, `pnpm build` sonrası):
**628/628 dosya, 11.041 test geçti, 10 atlandı, 0 başarısız.** `pnpm test:privacy`, E2E katmanları
ve Docker gerektiren Postgres paketleri bu koşuya dahil değildir.

### I.1 Postgres'te hiç çalıştırılmamış migration'lar (Docker yoktu)

`20261005220000` … `20261008000100` arası 22 migration yalnız statik testlerden geçti. Özellikle
şunlar davranış değiştirir ve canlı veride doğrulanmalıdır:

| Migration | Risk |
|---|---|
| `20261007000050_scim_directory_authoritative` | SCIM dışı üyeliği commit anında reddeder; yanlış veri kiracıyı kilitleyebilir (break-glass var) |
| `20261007000000_discovery_target_pseudonyms` | Eski collector'lar `target_address_not_accepted` alır; yükseltme sırası önemli |
| `20261007000200_detection_exceptions` | Yeni tablo/RPC; 30 gün ve self-defense kısıtları DB'de |
| `20261007120000_security_review_hardening` | Global `alter default privileges ... revoke execute ... from public`: örtük PUBLIC execute'a dayanan bir fonksiyon kırılır |
| `20261007130000_plan_retention_and_feature_gating` | Plan çözücü; hiç ayar yapmamış kiracıların saklama süresi plan süresine geçer (ör. 30→365 gün) |
| `20261007140000_shadow_ai_site_decisions` | Overlay'e yeni alan; Browser Guard politikası buna bağlı (yoksa 503) |
| `20261007000100_tenant_identity_barrier_after_merge`, `20261008000100_restore_directory_membership_grants` | Kimlik bariyeri / üyelik izinleri |

Kapanış: Docker'lı makinede `scripts/*-postgres*.mjs` (41 dosya; yeni:
`scim-directory-authority-postgres.test.mjs`, `discovery-cloud-postgres.test.mjs`) +
`pnpm verify:retention`, `pnpm verify:offboarding`; hem temiz DB'ye hem önceki sürüm verisine uygula.

### I.2 Dağıtımda operatörün yapması gerekenler (kodda hazır, ortamda yok)

- Barındırılan Supabase "Invite user" e-posta şablonunu `supabase/templates/invite.html` ile değiştir
  (`token_hash` akışı; eski davetler reddedilir, yeniden gönder).
- `response-playbooks` fonksiyonunu `verify_jwt=false` ile dağıt (yoksa otomasyon tetikleyicisi geçitte kalır).
- Cloudflare worker'ı yeniden dağıt (`device-poll`, `identity-security`, `oidc-sso`, `version-check`, `waitlist-signup` imzalı IP bağlamları).
- İmza anahtarları: revocation (`AIDR_REVOCATION_SIGNING_KEY_ID` + özel anahtar; yoksa GET 503), runtime policy, compliance report, release manifest (`version-check` için `AIDR_RELEASE_MANIFEST_B64/_SIG/_SIGNING_PUBLIC_KEY_B64` veya `AIDR_LATEST_RELEASE_VERSION`).
- Kontrol düzlemini ajanlardan **önce** yükselt (revocation şema 2, keşif pseudonim).
- SSO zorunlu olmayan kiracılarda SCIM e-posta sağlaması için alan adı doğrulaması.
- Browser Guard yönetilen politikasında `dashboardPolicy` (imza açık anahtarı) + telemetri.
- `packages/privacy/parsers/worker.py` değişti → dağıtılmış `workerSha256` pin'ini güncelle.
- Helm: backup kapalı mevcut sürümler `helm upgrade`'de reddedilir (`migrations.allowWithoutBackup` veya backup aç); migrations imajına GNU tar (busybox xattr düşürüyor); `docs/operations/kubernetes.md` yedek bölümü kontrol.
- Windows bakım görevleri: `deployment-prepare.mjs` Windows'ta sahibi Administrators yapmalı; aksi halde yeni ACL kontrolü kaydı reddeder.

### I.3 Tespit kuralı düzeltmeleri (kırmızı takım bulguları; ajan otomasyonu güvenlik filtresine takıldı)

Kırmızı takım koşusu 114 kötü amaçlı vakadan 22'sinin `allow` aldığını ölçtü (merge sonrası kod).
Vakalar ve harness **depoda değil** (geliştirici makinesinin geçici klasöründe kaldı). Bu iş
Tespit Mühendisliği ekibine aittir: vakaları ekipçe yeniden üretin, kalıcı regresyon testine
çevirin, kural/normalizasyon düzeltmelerini `threats/` ve çıkarıcılarda yapın, ardından
`compile-threat-cache.mjs` ve `regex-performance.test.ts` ile doğrulayın. Aynı koşuda iki
zararsız komutta yanlış pozitif (paket kurulumu ve örnek `.env` kopyası) ölçüldü.

### I.4 Kod incelemesinden kalan bulgular (doğrulanmış, düzeltilmedi)

| Önem | Yer | Bulgu |
|---|---|---|
| Orta | `packages/core/src/detection-exceptions.ts` (`subjectMatches`) | Repo-remote kapsamlı istisna, ajanın yazabildiği `.git/config` origin'iyle eşleşiyor; başka depoya taşınabilir. Kök yolu da bağlanmalı. |
| Orta | `packages/core/src/guard.ts` (`resolveHostAsk`) | `operator` modunda config okunamazsa sessizce host diyaloğuna dönüyor; kapalı (deny) olmalı. |
| Düşük | `packages/mcp-gateway/src/gateway.mjs` | Kiracı kotası 64 × 4 kiracı = global 256; dört kiracı herkesi tüketebilir. |
| Düşük | `detection-exceptions.ts` (`readOriginRemote`) | `[` içeren (IPv6) origin URL'si ayrıştırılmıyor. |
| Düşük | `packages/cli/src/commands/audit.ts` | İki `audit verify` modu farklı çıkış kodları kullanıyor. |
| Düşük | `packages/core/src/hook-deadline.ts` | U+FFFD içeren her komut reddediliyor (yanlış pozitif). |
| Düşük | `packages/extension/src/aidr-hook.ts` | Bilinmeyen VS Code hook olayları deny alıyor. |
| Düşük | `packages/core/src/policy.ts` | MCP allow/envanter yalnız ilk kimlik okumasını kullanıyor (`a__b` sunucu adları). |
| Düşük | `packages/core/src/policy-signature.ts` | Kanonik JSON iki yerde ayrı uygulanmış; sapma imza reddine yol açar. |
| Bilgi | `packages/mcp-gateway` `package.test.mjs` | 2 test (ticari ikili, temiz paket fabrikası) başarısız; değişikliklerden bağımsız olduğu ölçüldü, kök neden açık. |
| Bilgi | Windows ilk karantina | Taze kurulumda ~2,8 s (4 s watchdog'a yakın). |
| Bilgi | Browser Guard dosya girişi rölesi | Yalnız jsdom'da test edildi; Chrome/Edge/Firefox'ta (özellikle Firefox DataTransfer) doğrulanmadı. |
| Bilgi | SEA | Windows ikilisi imzasız; macOS/Linux SEA hiç derlenmedi. |
| Bilgi | Release doğrulama | POSIX `O_NOFOLLOW`/0700 yolları yalnız Windows'ta koşuldu. |
| Bilgi | `CLAUDE.md` | Silinmiş `packages/dashboard/supabase/functions/` dizininden hâlâ söz ediyor. |

### I.4a 9 Ekim sonrası kapananlar (#121)

| Madde | Durum | Kalan |
|---|---|---|
| Tespit istisnalarının kiracı çıkışında (offboarding) silinmesi — `20261009000100` | **Kapandı** (`d4c82337`, `16d87b4e`) | Canlı veride `pnpm verify:offboarding` |
| `increment_rate_limit` için api-key ve version-check kapsamları — `20261009000200` | **Kapandı** (`7cc1f5d1`) | — |
| On-prem self-hosted prova: smoke **93/93**, soğuk yedek, doğrulama ve yeni projeye kurtarma (satır/nesne sayıları eşit, servisler sağlıklı) | **Doğrulandı** 2026-10-09 (`6dafe898`; Windows/Docker geliştirme modu) | Linux hostta `readyz` ve `apply` kabulü açık; müşteri hostu, offsite yedek ve RPO/RTO (FCR-06, T27, DEP-06) açık |

### I.5 Sahibinden karar bekleyenler (bu çalışmada ortaya çıktı)

- Kayıtsız ticari build: dijestler doğruysa yerel tespit çalışıyor (CLAUDE.md'ye uygun); eski
  sabitlenmiş politika "başlamayı reddet" idi ve Codex release testleri hâlâ onu bekliyor. Hangisi?
- Plan: deneme = Team; aktif lisanssız ücretli etiket = Free; ayar yapmamış kiracı saklaması plan
  süresine geçer (Business 30→365 gün); düşürülen planda OIDC/SCIM yönetimi kilitlenir.
- Yönetilen tespit istisnaları tek sahip/admin ile oluşturuluyor (dört göz yok).
- MCP politikası açıkken sunucusu tanımlanamayan çağrı artık `ask` (önceden politika atlanıyordu).
- Gizlilik paketi ~20 Python bağımlılığının (torch, transformers, numpy, Pillow, pypdfium2…)
  lisansı otomatik çözülemedi → Hukuk onayı.
- Satış kataloğu (`docs/sales/catalog/src/content.mjs`): madde 30 "ağ çıkışında trafiği denetler"
  diyor; geçit yalnız kendisine gönderileni görür. 146 bileşen / 2.000+ CVE / 14 MCP kategorisi
  vendored AI-Infra-Guard verisine atfedilmeli.

## H. GO için asgari set (kademeli)

1. **Kontrollü değerlendirme GO** = A bölümü kapalı + FCR-01…08 PASS + `evaluation` profilindeki 8 kapı (COM-001, COM-002, COM-003, COM-005, COM-010, COM-011, POV-001, CLM-001).
2. **Destekli satış GO** = (1) + `assisted-sale` profilindeki 12 kapının tamamı + D bölümündeki P0 saha kabulleri + F bölümü BLOCKED_EXTERNAL P0'lar.
3. **Production-GA GO** = (2) + `production-ga` kapıları + tam aylık SLI penceresi (COM-013) + bağımsız pentest yeniden testi (SEC-EXT-001) + isimli müşteri PoV (POV-001).
4. **Yatırımcı iddiaları** ayrı: INV-001 metrik sözlüğü onaylanmadan hiçbir metrik sunulmaz.

Hiçbir seviye "yüzde" ile raporlanmaz; her madde kapalı/açık ikilisidir.

# AIDR üretim ve satış hazırlığı: ayrıntılı eksik kaydı

13 Eylül 2026. **Karar: NO-GO.** Kurulabilir bir aday ve doğrulanmış yerel akışlar var; bütün ürünün üretim ve satış kabulü tamamlanmış değil.

71 alt özellik: **41 bağlı/çalışan, 28 kısmi, 0 eksik, 2 dış kabule bağlı**. Çalışan bir özellikte de saha veya işletim kabulü açık olabilir. Bu raporda **46 teknik/operasyon iş paketi ve 13 ticari/dış kanıt kapısı** ayrıntılandırıldı. Bunlar benzersiz yazılım hatası sayısı veya tamamlanma yüzdesi değildir; örtüşen gereksinimler kimliklerle ilişkilidir. Makine kaydı: [PRODUCTION_SALES_GAPS.json](PRODUCTION_SALES_GAPS.json).

46 teknik işte yerel uygulama ilerlemiş ve saha kabulü açık; 0 teknik iş uygulama/entegrasyon olarak açık. Başlangıç boşluğu tarihsel karşılaştırma için korunur; satırın güncel durumu ve kalan kabul koşulu esas alınmalıdır. Üretim ve destekli satış profillerinin her birinde **12 açık zorunlu dış kapı** var. Müşteri ortamı henüz bilinmiyor; cloud ve self-hosted kapsamları korunmuştur.

## Kanıt ve durum nasıl okunmalı?

- **Yerel uygulama, saha kabulü açık:** Kod ve hedefli yerel testler var; gerçek müşteri, native host, provider, SLA veya operatör kabulü ayrıca gerekir.
- **Açık:** Başlangıç bulgusu veya eksik ürün bağlantısı tamamlanmadı.
- **P0/P1:** Satılan kapsam önceliği. Ticari kapılar kendi profilinde zorunludur.

V7 birleşik test özeti [docs/production-readiness/2026-09-13-customer-candidate-v7.md](docs/production-readiness/2026-09-13-customer-candidate-v7.md) içindedir; önceki kurulum kaydı [docs/production-readiness/2026-09-13-customer-candidate-v6.md](docs/production-readiness/2026-09-13-customer-candidate-v6.md) altında saklanır. Yerel test geçişi native host, bağımsız güvenlik değerlendirmesi veya SLA kanıtının yerini tutmaz.

## Öncelikli kalan işler

1. Gerçek host/OS ve cloud/self-hosted altyapı kabulü; resmi yayıncı imzası ve özel dağıtım.
2. MCP doğrudan upstream bypass, binary/server-initiated kapsamı ve her connector için pre-model/pre-side-effect kabulü.
3. Gerçek Entra/Okta, SMTP, MDM, cloud project, TLS public proxy ve iki tenantlı canlı negatif test.
4. Kimlikli yük, failover/soak, bağımsız offsite kurtarma, SIEM alındısı ve alarm paging teslimi.
5. Ticari teklif/siparişten entitlement'a, veri işleme, destek kanalları, bağımsız pentest ve isimli müşteri PoV.

## Teknik ve operasyon eksikleri

### T01 — Gerçek host ve işletim sistemi kapsamı (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** deploy/native/support-matrix.json satilan connector/OS/arch/context/interception matrisini ve bilinen bypass/unobserved listesini tanimliyor; deploy/native/run-support-matrix.mjs kurulu olmayan hostu HOST_UNAVAILABLE olarak NO-GO uretiyor, gercek host ve isimli kabul acik.

**Başlangıç durumu:** Derlenmiş kanca ve SDK testleri var; müşterinin gerçek host/OS/sürüm matrisi yok.

**Başlangıç boşluğu / müşteri etkisi:** Kanca kararı hostun eylemi durdurduğunu tek başına kanıtlamaz. Devre dışı eklenti, süreç çökmesi, timeout ve yeni host sürümü kapsam dışında kalabilir.

**Tamamlanma hedefi:** Satılacak her bağlayıcı için OS/sürüm destek tablosu, gerçek host testi, kurulum/kaldırma ve destek sahibi belirle; görünmeyen eylemleri açıkça listele.

**Kalan kapanış testi:** Her zorunlu saldırıda yan etkinin oluşmadığını bağımsız kaydet; zararsız işlemler geçsin; kanca kapalı/bozuk/ağsız durumları ve yeniden başlatma ayrı sınansın.

**Sorumlu:** QA + Endpoint Engineering. **Bağımlılık:** Müşteri test cihazları, runtime erişimi ve sürüm seçimi.

**İlişkili özellikler:** CON-01, CON-02, CON-03, CON-04, CON-05, CON-06, DET-01, DET-02, DET-03, DET-04, DET-05, RSP-01. **Kaynak:** [scripts/run-e2e-release.mjs](scripts/run-e2e-release.mjs), [packages/codex/README.md](packages/codex/README.md).

### T02 — Bağlayıcılar arasında araç adı ve girdi normalizasyonu (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Ortak araç/girdi normalizasyonu evaluator öncesinde; Codex ve OpenClaw boş-artifact erken izin yolu kaldırıldı, named MCP çağrıları politikaya ulaşıyor.

**Başlangıç durumu:** OpenCode ham bash/write/edit adlarını iletiyor; bazı çekirdek denetimleri yalnızca Bash/Write/Edit dallarında çalışıyor. Mevcut sözleşme testi bu paket boşluğunu allow olarak kaydediyor.

**Başlangıç boşluğu / müşteri etkisi:** Paket kurulumları ve bazı dosya/AMSI girdileri ilgili denetim koluna ulaşmayabilir; birim testlerin yeşil olması bu kapsamı kapatmıyor.

**Tamamlanma hedefi:** Ortak semantik araç/girdi sözleşmesi tanımla; tüm bağlayıcıları eşle; command, file_path/filePath, content/new_string alanlarını standartlaştır. Bilinen boşluğu beklenen izin sonucu olarak sabitleyen testi değiştir.

**Kalan kapanış testi:** Aynı yasak paket, manifest ve dosya girdisi tüm bağlayıcılarda aynı denetime ulaşsın; denetleyici çağrısı ve engellenen yan etki kanıtlansın; boş/alternatif alan adları negatif test edilsin.

**Sorumlu:** Core + Connector Engineering. **Bağımlılık:** AIDR-060; native host matrisi.

**İlişkili özellikler:** DET-12, DET-11, CON-04. **Kaynak:** [packages/core/src/evaluator.ts](packages/core/src/evaluator.ts), [packages/opencode/src/tool-handler.ts](packages/opencode/src/tool-handler.ts), [packages/opencode/src/__tests__/aidr-contract.test.ts](packages/opencode/src/__tests__/aidr-contract.test.ts).

### T03 — Paket denetiminde hatanın sessiz kaybolması (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Paket, registry ve file-reputation hata/bozuk-200 yolları clean yerine unknown/unavailable üretiyor; gerçek 404 ve doğrulanmış clean ayrımı test edildi.

**Başlangıç durumu:** checkPackages içinde genel catch boş sonuç döndürüyor. Diğer tespit kollarında açık unavailable davranışları bulunuyor.

**Başlangıç boşluğu / müşteri etkisi:** Paket denetleyicisi beklenmedik hata verdiğinde üst akış başarılı bir boş kontrol gibi devam edebilir; diğer kurallar her vakayı yakalamaz.

**Tamamlanma hedefi:** Hata türlerini unavailable olarak taşı; zorunlu denetim politikasında deny/insan onayı üret; opsiyonel kolda görünür eksik tespit kaydı tut. Hatalı politika/cache/intel durumlarını ayır.

**Kalan kapanış testi:** Registry timeout, bozuk cevap, cache/intel ayrıştırma hatası ve denetleyici exception enjekte et; zorunlu kontrol sessiz allow üretmesin; benign ve iptal davranışları korunsun.

**Sorumlu:** Detection Engineering. **Bağımlılık:** AIDR-061; desteklenen araç sözleşmesi.

**İlişkili özellikler:** DET-10, DET-11, DET-12. **Kaynak:** [packages/core/src/evaluator.ts](packages/core/src/evaluator.ts), [packages/core/src/package-checker.ts](packages/core/src/package-checker.ts).

### T04 — Model tüketiminden önce çıktı denetimi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Çıktı tarayıcı 2 MiB UTF-8, 3000 ms best-effort ve 128 bulgu sınırında inspection_incomplete/critical fail-closed üretiyor; JSON/Unicode ve sınır payloadları test edildi. Her hostta aynı-tur blok kanıtı yok.

**Başlangıç durumu:** Claude çıktısında sınırlı tarama var; PostToolUse çalışmış eylemi geri alamaz. Diğer tüketim yollarının tamamı bağlı değil.

**Başlangıç boşluğu / müşteri etkisi:** Prompt injection veya sır içeren çıktı modele ulaşabilir. İlk 262144 karakterden sonraki içerik ve desteklenmeyen biçimler için kapsam eksiktir.

**Tamamlanma hedefi:** Hostun izin verdiği yerlerde çıktı tesliminden önce kontrol/karantina ekle; desteklenmeyen yollarda açık coverage durumu göster; boyut sınırı aşımını sessiz temiz sayma.

**Kalan kapanış testi:** Parçalara bölünmüş saldırı, sınırın sonundaki payload, Unicode, JSON/text ve çok büyük cevaplar sınansın; engellenen baytlar modele ulaşmasın; zararsız çok parçalı cevap bozulmasın.

**Sorumlu:** Connector + Detection Engineering. **Bağımlılık:** Host API kabiliyeti; MCP gateway.

**İlişkili özellikler:** DET-06, DET-07, MCP-07, CON-01, CON-02, CON-03, CON-04, CON-05, CON-06. **Kaynak:** [packages/claude-code/src/output-inspection.ts](packages/claude-code/src/output-inspection.ts), [packages/claude-code/src/post-tool-use.ts](packages/claude-code/src/post-tool-use.ts), [packages/core/src/output-scanner.ts](packages/core/src/output-scanner.ts).

### T05 — Davranış, novelty ve ML kararlarının ürün akışına bağlanması (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** BehavioralAnalyzer adayı kendi baseline'ına katmıyor ve tenant/session ayrımı korunuyor; üretim etkinliği ve kalıcı öğrenme kabulü açık.

**Başlangıç durumu:** Modüller ve testler var; sürekli çalışan tüketici, öğrenme yaşam döngüsü ve üretim başarı ölçümü kanıtı tamam değil.

**Başlangıç boşluğu / müşteri etkisi:** İhracat edilen sınıf veya demo skor, çalışan anomali koruması sayılmaz. Yanlış öğrenme ve tenantlar arası veri karışması riski değerlendirilmemiş.

**Tamamlanma hedefi:** Gerçek olay tüketicisi, tenant bazlı durum, cold-start, unutma/retention, model sürümü, karar açıklaması ve insan geri bildirimi akışlarını bağla.

**Kalan kapanış testi:** Soğuk başlangıç ve model yenilemede kararlı sonuç; tenant ayrımı; veri zehirleme denemeleri; holdout saldırı ve zararsız iş yükünde yanlış alarm ölçümü.

**Sorumlu:** Detection + Data Engineering. **Bağımlılık:** Etiketli müşteri verisi ve bağımsız ölçüm seti.

**İlişkili özellikler:** DET-08, DET-09. **Kaynak:** [packages/core/src/behavioral-analyzer.ts](packages/core/src/behavioral-analyzer.ts), [packages/core/src/novelty-detection.ts](packages/core/src/novelty-detection.ts), [packages/core/src/ml-model.ts](packages/core/src/ml-model.ts).

### T06 — Reputation ve AI altyapı verisinin güncelliği (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** İmzalı offline feed için publisher issued_at ve yerel fetched_at birlikte yaş sınırına bağlandı; canlı provider, dağıtım ve gecikme kabulü açık.

**Başlangıç durumu:** Yerel kurallar, derlenmiş veri ve kendine kurulabilen sorgu API'leri var.

**Başlangıç boşluğu / müşteri etkisi:** Feed kaynağı/güncelliği, sağlayıcı kesintisi, imzalı güncelleme, kapsanmayan format ve müşteri gecikme hedefleri doğrulanmadı; canlı reputation testi atlanıyor.

**Tamamlanma hedefi:** Feed sözleşmesi ve güncelleme işi, yaş sınırı, geri alma, eksik veri durumu ve müşteri veri/URL kategorisi kalibrasyonu kur.

**Kalan kapanış testi:** Eski/bozuk/boş feed temiz verdict üretmesin; güncelleme/geri dönüş kanıtlansın; gerçek endpoint ve AMSI desteklenen Windows hostunda ölçülsün.

**Sorumlu:** Detection + Operations. **Bağımlılık:** Sağlayıcı/feed erişimi, Windows host ve müşteri corpus'u.

**İlişkili özellikler:** DET-10, DET-11, DET-12, INF-01, INF-02. **Kaynak:** [supabase/functions/url-check/index.ts](supabase/functions/url-check/index.ts), [supabase/functions/file-check/index.ts](supabase/functions/file-check/index.ts), [packages/core/src/generated/aig-data-manifest.json](packages/core/src/generated/aig-data-manifest.json), [packages/core/src/aig-policy.ts](packages/core/src/aig-policy.ts).

### T07 — MCP keşfi ve kimlik normalizasyonunun kapsamı (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Yerel MCP keşfi konum/alias bazlı kararlı inventory_id ve merkezi stale/partial kapsam raporu üretiyor; ek host biçimleri/native kabul açık.

**Başlangıç durumu:** Yerel JSON konfigürasyonları ve sunucu/araç listeleri denetleniyor.

**Başlangıç boşluğu / müşteri etkisi:** JSONC, yeni runtime konumları, dinamik eklenen sunucular ve belirsiz server/tool kimlikleri için tam kapsama yok; yerel tarama kurum çapı keşif değildir.

**Tamamlanma hedefi:** Desteklenen konfigürasyon adaptörlerini ekle; okunamayan/kısmi keşfi raporla; yeniden adlandırma ve alias davranışını politikayla tutarlı yap.

**Kalan kapanış testi:** Bozuk/izin verilmeyen dosya, JSONC, boş argüman, alias ve aynı isimli farklı sunucu testleri; eksik tarama güvenli envanter gibi görünmesin.

**Sorumlu:** Endpoint + MCP Engineering. **Bağımlılık:** Host sürüm ve konfigürasyon matrisi.

**İlişkili özellikler:** MCP-01, MCP-02, MCP-03, MCP-04. **Kaynak:** [packages/core/src/mcp-discovery.ts](packages/core/src/mcp-discovery.ts), [packages/core/src/mcp-inventory.ts](packages/core/src/mcp-inventory.ts), [packages/core/src/policy.ts](packages/core/src/policy.ts).

### T08 — İmzalı MCP araç tanımı ve değişiklik onayı (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** İmzalı MCP manifest key_id'yi imzaya bağlıyor, geçersiz saat ve legacy imza fail-closed; eski manifestler güvenilir yayıncı tarafından yeniden imzalanmalı.

**Başlangıç durumu:** Süreç içi ilk şema referansı ve drift reddi var; tekrar ederek referansı değiştirme hatası düzeltildi.

**Başlangıç boşluğu / müşteri etkisi:** İmzalı sunucu/araç description ve schema manifesti, kalıcı onay, sürüm/expiry ve replay koruması yok. Süreç yeniden başlatılması güvenilir onay değildir.

**Tamamlanma hedefi:** Araç tanımını sunucu kimliği ve sürüme imzayla bağla; değişen araçları karantinaya al; yalnızca operatörün onaylayabildiği inceleme ve dağıtım akışı kur.

**Kalan kapanış testi:** Description/schema değişimi, eski manifest, yanlış signer, yeniden başlatma, eş zamanlı değişiklik ve onaysız retry reddedilsin; ajan kendi aracını onaylayamasın.

**Sorumlu:** MCP + Security Engineering. **Bağımlılık:** AIDR-046; signer/key custody ve yönetim UI'sı.

**İlişkili özellikler:** MCP-05. **Kaynak:** [packages/core/src/mcp-transport.ts](packages/core/src/mcp-transport.ts), [packages/core/src/mcp-discovery.ts](packages/core/src/mcp-discovery.ts).

### T09 — Kullanıcı–ajan–araç–kaynak ilişkisi ve delegasyon (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Ed25519 delegated lineage ve grant/introspection/revoke; geçersiz sayı ve Ed25519 olmayan EdDSA anahtarı reddediliyor. Gerçek IdP/tool provider kabulü açık.

**Başlangıç durumu:** Ajan/ekip anahtarı bağı ve yerel envanter var.

**Başlangıç boşluğu / müşteri etkisi:** Kimin hangi ajan üzerinden hangi kaynağa hangi yetkiyle eriştiğini gösteren tam ilişki grafiği; araç bazlı kısa ömürlü delegasyon yok.

**Tamamlanma hedefi:** Kaynak ve kimlik ilişkileri, audience/scope/expiry taşıyan kısıtlı token, delegation depth ve credential broker uygula.

**Kalan kapanış testi:** Başka tool/resource/audience için token kullanımı, süresi bitmiş delegasyon, kullanıcı ayrılması ve zincir yetki büyütme reddedilsin; olaydan kaynağa iz sürülsün.

**Sorumlu:** Identity + Backend Engineering. **Bağımlılık:** IdP ve araç sağlayıcısı API'leri.

**İlişkili özellikler:** MCP-06, TEN-06, OBS-02. **Kaynak:** [packages/core/src/mcp-inventory.ts](packages/core/src/mcp-inventory.ts), [supabase/functions/enroll/index.ts](supabase/functions/enroll/index.ts), [supabase/functions/api-keys/index.ts](supabase/functions/api-keys/index.ts).

### T10 — MCP gateway ve taşıma güvenliği (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Loopback/stdio JSON-RPC geçidi DNS pinleme, gerçek stream sınırı, tekil framing ve bozuk yanıt reddi uyguluyor; binary, server-initiated ve zorunlu routing kabulü açık.

**Başlangıç durumu:** Framing ve policy interception yardımcıları var; çalışan tam gateway tüketicisi yok. URL DNS kontrolünden sonra fetch yeniden çözümleme yapıyor; cevap sınırı Content-Length başlığına bakıyor.

**Başlangıç boşluğu / müşteri etkisi:** DNS rebinding, başlıksız/chunked büyük cevap, mapped IPv6 ve bağlantı ömrü için gerçek ağ kabulü eksik. Mevcut test adı DNS rebinding korumasını olduğundan güçlü anlatıyor.

**Tamamlanma hedefi:** Doğrulanan IP'yi bağlantıya sabitle; IP sınıflamasını tamamla; gerçek okunan/decompress edilmiş baytları sınırla; authentication/session/stream ve bypass akışlarını gateway'e bağla.

**Kalan kapanış testi:** Kontrol ile bağlantı arasında DNS değişsin; private/mapped IPv6, redirect, başlıksız sonsuz stream, sınır aşımı, disconnect ve bozuk JSON/SSE ile gerçek ağ testi çalışsın.

**Sorumlu:** MCP + Network Security. **Bağımlılık:** AIDR-062; stdio/HTTP/SSE kapsam kararı.

**İlişkili özellikler:** MCP-07. **Kaynak:** [packages/core/src/mcp-transport.ts](packages/core/src/mcp-transport.ts), [packages/core/src/__tests__/mcp-transport.test.ts](packages/core/src/__tests__/mcp-transport.test.ts).

### T11 — Sürekli kurum/filo keşfi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Kimlikli merkezi discovery upload var; interval modu geçici upload hatasını görünür tutarak sonraki çevrime devam ediyor. Cloud/MDM scheduler ve saha kabulü açık.

**Başlangıç durumu:** İsteğe bağlı yerel/altyapı taraması mevcut.

**Başlangıç boşluğu / müşteri etkisi:** Zamanlanmış kolektör, tenant envanteri, sahiplik, tekrar birleştirme, son görülme ve stale alarmı yok.

**Tamamlanma hedefi:** Filo/cloud kolektörleri, kapsam izinleri, zamanlama, retry, dedup, kimlik ve keşif tazeliği ekranlarını kur.

**Kalan kapanış testi:** Kapanan veya yeni açılan ajan görünür olsun; bağlantısız kolektör eski veriyi güncel göstermesin; tenant ayrımı ve keşif yük sınırları sınansın.

**Sorumlu:** Discovery + Backend Engineering. **Bağımlılık:** Müşteri cloud/MDM API erişimi ve ağ tarama kapsamı.

**İlişkili özellikler:** INF-03. **Kaynak:** [packages/cli/src/commands/scan.ts](packages/cli/src/commands/scan.ts), [packages/core/src/aig-infra-scan.ts](packages/core/src/aig-infra-scan.ts).

### T12 — Filo müdahalesi ve credential iptali (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** İmzalı revocation feed tenant+global kapsamı 5000 sınırından önce filtreliyor ve eksik/truncated seti imzalamıyor; native/provider iptali açık.

**Başlangıç durumu:** Yerel süreç müdahalesi ve iptal listesi temelleri var.

**Başlangıç boşluğu / müşteri etkisi:** Kurumsal endpoint izolasyonu, tüm cloud sağlayıcılarda credential iptali ve ajandan sonuç alan komut altyapısı yok.

**Tamamlanma hedefi:** Yetkili komut kuyruğu, TTL/idempotency, operatör yetkisi, ajan sonuç bildirimi, geri alma ve sağlayıcı adaptörleri ekle.

**Kalan kapanış testi:** Offline ajana süresi geçmiş komut uygulanmasın; tekrar gelen komut tek etki üretsin; başarısız izolasyon başarı görünmesin; ilgili izinler ve geri dönüş kanıtlansın.

**Sorumlu:** Response + Endpoint Engineering. **Bağımlılık:** OS yetkileri, sağlayıcı API'leri, müşteri müdahale yetkisi.

**İlişkili özellikler:** RSP-04, RSP-06. **Kaynak:** [packages/core/src/contain.ts](packages/core/src/contain.ts), [supabase/functions/revocations/index.ts](supabase/functions/revocations/index.ts).

### T13 — Response eylemlerinin güvenli uçtan uca işletimi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Yeni response-worker-contract.ts capability/onkosul/TTL/idempotency/rollback makbuzu sozlesmesini uyguluyor; desteklenmeyen action adapter tarafindan reddediliyor ve geri alinamayan adim partial olarak raporlaniyor. Native OS/provider adapter ve kurulu servis musteri tarafinda acik. Eski: Restart-safe worker resume sırasında adapter destek listesini yeniden doğruluyor ve kaldırılmış action'ı çalıştırmadan unsupported_action bildiriyor. Native OS/provider adapter ve kurulu servis açık.

**Başlangıç durumu:** Quarantine/restore, dosya snapshot/rollback ve imzalı olay zinciri yerel testli.

**Başlangıç boşluğu / müşteri etkisi:** Gerçek müşteri dosya izinleri, aynı anda değişen dosya, dış playbook etkileri, signer saklama ve bağımsız arşiv kanıtı eksik.

**Tamamlanma hedefi:** Desteklenen eylem ve dosya kapsamını sabitle; önkoşul/sonuç doğrulama, operatör sınırları, dış SOAR sonuçları ve bağımsız kanıt saklamayı tamamla.

**Kalan kapanış testi:** Dosya sonradan değişmişken yanlış rollback yapılmasın; symlink/izin/disk hatası açık başarısız olsun; eylem ve geri dönüş aynı incidentten izlenebilsin.

**Sorumlu:** Response Engineering + Security Operations. **Bağımlılık:** Müşteri dosya sistemi/EDR/SOAR izinleri.

**İlişkili özellikler:** RSP-02, RSP-03, RSP-05, RSP-07. **Kaynak:** [packages/core/src/quarantine.ts](packages/core/src/quarantine.ts), [packages/core/src/rollback.ts](packages/core/src/rollback.ts), [packages/core/src/response-command-worker-v6.ts](packages/core/src/response-command-worker-v6.ts), [packages/core/src/response-audit.ts](packages/core/src/response-audit.ts), [supabase/functions/autosecops-runtime/index.ts](supabase/functions/autosecops-runtime/index.ts).

### T14 — YAML politika yazımı ile gerçek runtime ilişkisi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Core/server dry-run unknown MCP fallback kararı runtime evaluator ile eşlendi; YAML/JSON compiler, parity ve dashboard publish akışı bağlı.

**Başlangıç durumu:** YAML belge kaydı var; ayrı runtime kontrolleri yayınlanıyor.

**Başlangıç boşluğu / müşteri etkisi:** Kaydedilen YAML kuralları runtime tarafından tüketilmiyor. Kullanıcı belge kaydını etkin güvenlik politikası sanabilir.

**Tamamlanma hedefi:** Desteklenen YAML şemasını runtime modeline derle veya belge akışını açıkça ayır; desteklenmeyen alanları reddet; öncelik ve etki simülasyonu sun.

**Kalan kapanış testi:** Kaydedilen/yayınlanan politika gerçek ajan kararında değişiklik üretsin; bilinmeyen alan sessiz atılmasın; allowlist ile açık deny önceliği doğrulansın.

**Sorumlu:** Policy + Dashboard Engineering. **Bağımlılık:** Politika sözleşmesi ve migration planı.

**İlişkili özellikler:** POL-01, POL-02. **Kaynak:** [packages/dashboard/src/enterprise/policy-editor.tsx](packages/dashboard/src/enterprise/policy-editor.tsx), [packages/dashboard/src/ui/pages/PolicyPage.tsx](packages/dashboard/src/ui/pages/PolicyPage.tsx), [packages/core/src/policy.ts](packages/core/src/policy.ts).

### T15 — Politika dağıtımı saha kabulü ve ölçek sınırları (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Hedefli stage işlemi atomik revision precondition ile eski eşzamanlı güncellemeyi 409 reddediyor; gerçek filo/ölçek kabulü açık.

**Başlangıç durumu:** Sürüm/geçmiş, hedefli dağıtım, rollback, sayfalama ve sabit offline grace çalışıyor.

**Başlangıç boşluğu / müşteri etkisi:** Receipt yalnızca ajanın yükleme bildirimi; host enforcement attestation değil. Eski bağlı olmayan anahtarlar, büyük filo batch planı ve gerçek offline saha kabulü açık.

**Tamamlanma hedefi:** Eski ajanları yeniden kaydet; dağıtım batch/ring işletimini ve zorunlu politika sürelerini müşteriye göre belirle; gözlem/uyarı ve native canary kabulü yap.

**Kalan kapanış testi:** Yetkisiz/stale receipt, rollback, offline süresi, 401/403, bozuk cache, yeniden başlatma ve hedef değiştirmede yanlış sürüm uygulanmasın; gerçek filoda yakınsama ölçülsün.

**Sorumlu:** Policy + QA + Operations. **Bağımlılık:** Ajan sürümü, müşteri offline toleransı.

**İlişkili özellikler:** POL-03, POL-04, POL-05. **Kaynak:** [supabase/functions/policy-management/index.ts](supabase/functions/policy-management/index.ts), [supabase/functions/policy-ack/index.ts](supabase/functions/policy-ack/index.ts), [packages/core/src/remote-policy.ts](packages/core/src/remote-policy.ts).

### T16 — Endpoint sır saklama ve anahtar rotasyonu (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Windows config create/update/reuse yolu owner+SYSTEM+Administrators DACL kuruyor ve ACL hatasında credential yazmıyor; OS vault ve server-side revocation açık.

**Başlangıç durumu:** Tipli/redakte config ve özel dosyalar mevcut.

**Başlangıç boşluğu / müşteri etkisi:** OS credential vault entegrasyonu, kurumsal dağıtımda signer rotasyonu, kayıp cihaz/anahtar kurtarma ve minimum API-key kapsamı eksik.

**Tamamlanma hedefi:** Windows/macOS/Linux için sır deposu adaptörü; anahtar rotasyonu ve iptali; config/export/support bundle redaksiyonunu tamamla.

**Kalan kapanış testi:** Yetkisiz kullanıcı sır okuyamasın; eski anahtar zamanında reddedilsin; yenileme kesintisi güvenli olsun; log, argüman ve destek arşivi sır sızdırmasın.

**Sorumlu:** Endpoint + Security Engineering. **Bağımlılık:** Kurum secret manager'ı ve OS depoları.

**İlişkili özellikler:** CLI-02, TEN-06. **Kaynak:** [packages/cli/src/utils/config-manager.ts](packages/cli/src/utils/config-manager.ts), [packages/core/src/types.ts](packages/core/src/types.ts), [docs/runbooks/secrets-management.md](docs/runbooks/secrets-management.md).

### T17 — İmzalı filo kurulumu, güncelleme ve kaldırma (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Installer ile Windows/Unix uninstall yalnız AIDR işaretli nested hook'u kaldırıyor, aynı entry'deki müşteri hook'larını koruyor; gerçek MDM/yayıncı kabulü açık.

**Başlangıç durumu:** Claude için yerel kurucu ve deny canary var; diğer paketler derleniyor.

**Başlangıç boşluğu / müşteri etkisi:** Intune/Jamf/SCCM teslimatı, tüm hostlarda upgrade/rollback/uninstall ve filo sağlık kanıtı tamam değil.

**Tamamlanma hedefi:** İmzalı dağıtım paketleri, detect/remediate betikleri, yönetici/kullanıcı kurulumları, policy-preserving upgrade ve uninstall kuralları üret.

**Kalan kapanış testi:** Temiz kurulum, yarım kalan upgrade, eski sürüme dönüş, host güncellemesi ve uninstall sonrasında başka kancalar/politika bozulmasın; gerçek MDM'de kanıt topla.

**Sorumlu:** Release + Endpoint Engineering. **Bağımlılık:** MDM test tenantı, signer, OS paketleme araçları.

**İlişkili özellikler:** CLI-01, CLI-03, CLI-04. **Kaynak:** [scripts/endpoint-install.mjs](scripts/endpoint-install.mjs), [packages/extension/package.json](packages/extension/package.json), [packages/cli/src/commands/setup.ts](packages/cli/src/commands/setup.ts).

### T18 — Kurumsal giriş, MFA ve hesap kurtarma (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Recovery URL yalnız hosted HTTPS/loopback HTTP kabul ediyor, credential URL'yi reddediyor ve parola değişiminden önce global session barrier kuruyor; canlı IdP açık.

**Başlangıç durumu:** İlk yönetici ve parolalı giriş SMTP olmadan çalışıyor.

**Başlangıç boşluğu / müşteri etkisi:** Gerçek IdP/SSO, MFA, parola sıfırlama, oturum sonlandırma, break-glass ve kimlik sahipliği işletimi kabul edilmedi.

**Tamamlanma hedefi:** Müşteri IdP'si, MFA ve kurtarma akışlarını bağla; bootstrap sahiplik prosedürü, session süreleri ve acil yönetici erişimini tanımla.

**Kalan kapanış testi:** Kayıp parola/MFA, kapatılmış kullanıcı, süresi dolmuş oturum ve başarısız IdP durumlarını sınayarak hesabın hem geri alınabilir hem yetkisiz erişime kapalı olduğunu kanıtla.

**Sorumlu:** Identity Engineering + Customer IT. **Bağımlılık:** IdP/SMTP/DNS ve kurum güvenlik politikası.

**İlişkili özellikler:** TEN-01, TEN-04, TEN-07. **Kaynak:** [packages/dashboard/src/ui/pages/LoginPage.tsx](packages/dashboard/src/ui/pages/LoginPage.tsx), [packages/dashboard/src/enterprise/auth.tsx](packages/dashboard/src/enterprise/auth.tsx), [scripts/deployment-bootstrap.mjs](scripts/deployment-bootstrap.mjs).

### T19 — SCIM ve güvenilir directory grup eşlemesi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** SCIM stale PATCH'i reddediyor, Remove members tüm üyeleri kaldırıyor ve büyük grup üyeliğini sayfalıyor; gerçek Entra/Okta kabulü açık.

**Başlangıç durumu:** Azure yardımcıları mevcut; azure-ad-groups endpointi ve tam SCIM yaşam döngüsü yok.

**Başlangıç boşluğu / müşteri etkisi:** Yardımcı kod user_metadata gruplarını önce okuyabiliyor ve isimde admin geçmesine göre rol eşliyor. Bu, sunucu yetkilendirmesi için güvenilir temel değildir; aktif bir yetki yükseltme kanıtı olarak sunulmuyor.

**Tamamlanma hedefi:** Sunucuda doğrulanmış immutable grup ID'leri, allowlist rol eşlemesi ve SCIM create/update/deactivate/groups uygula; kullanıcı metadata'sını yetki kaynağı yapma.

**Kalan kapanış testi:** Sahte metadata, benzer grup adı, grup kaldırma, hesap pasifleştirme, pagination/replay ve tenant karıştırma testleri; erişim belirtilen süre içinde kesilsin.

**Sorumlu:** Identity + Backend Engineering. **Bağımlılık:** AIDR-019/048; Entra/Okta test ortamı.

**İlişkili özellikler:** TEN-02, TEN-04. **Kaynak:** [packages/dashboard/src/auth/azure-ad.ts](packages/dashboard/src/auth/azure-ad.ts), [packages/dashboard/src/enterprise/team-provider.tsx](packages/dashboard/src/enterprise/team-provider.tsx).

### T20 — Davet ve cihaz kayıt yaşam döngüsü (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Tenant kapsamlı invite list/revoke/resend token rotasyonu ile device-start/exchange temeli var; SMTP, gerçek browser/IdP ve ağ kesintisi kabulü açık.

**Başlangıç durumu:** Davet bağlantısı ve açık ekip seçimiyle cihaz kaydı yerel provadan geçti.

**Başlangıç boşluğu / müşteri etkisi:** SMTP davet teslimi, gerçek cihaz yeniden kaydı, ekipten ayrılan çalışanın erişim kapanması ve müşteri mail/link akışı tam kabul edilmedi.

**Tamamlanma hedefi:** Davet dağıtımını, expiry/iptal/yeniden gönderme, yanlış ekip ve cihaz yenileme işletimini tamamla.

**Kalan kapanış testi:** Kullanılmış/iptal edilmiş davet, rol değişimi, başka ekip, eski device code ve kimlik değişiminde kayıt reddedilsin; mail linki gerçek tarayıcıda doğru ekibe dönsün.

**Sorumlu:** Identity + Customer Success. **Bağımlılık:** SMTP/IdP ve müşteri cihazları.

**İlişkili özellikler:** TEN-03, TEN-05. **Kaynak:** [supabase/functions/team-invite/index.ts](supabase/functions/team-invite/index.ts), [supabase/functions/device-poll/index.ts](supabase/functions/device-poll/index.ts), [packages/dashboard/src/ui/pages/public/VerifyPage.tsx](packages/dashboard/src/ui/pages/public/VerifyPage.tsx).

### T21 — Mevcut API anahtarında ekip ve üyelik iptali (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Packs manifest/download dahil anahtar kullanan yollar aktif tenant, üyelik ve revocation doğruluyor; önceden üretilmiş signed URL süre sonuna dek geçerli.

**Başlangıç durumu:** Anahtar yönetimi aktif ekip/üyeliği denetliyor; reputation API'leri yalnızca mevcut anahtarın revoked değerini kontrol ediyor.

**Başlangıç boşluğu / müşteri etkisi:** İzole gerçek HTTP provasında askıya alınmış ekip ve süresi bitmiş üyelikle hem URL hem dosya sorgusu 200 döndü; dört kabul yeniden üretildi. Başka tenant verisi okunduğu gösterilmedi.

**Tamamlanma hedefi:** Ortak doğrulanmış anahtar/aktif tenant/aktif üyelik sınırı uygula; iptal, kapanış ve deprovisioning semantiğini tüm servislerde birleştir.

**Kalan kapanış testi:** Aktif kimlik 200; suspended/closing/closed tenant, expired/removed membership ve revoked key tüm tüketicilerde 401/403; stale cache ile erişim sürmesin.

**Sorumlu:** Backend Security. **Bağımlılık:** AIDR-063; yerel yeniden üretim kanıtı.

**İlişkili özellikler:** TEN-01, TEN-06, DET-10, DET-11. **Kaynak:** [supabase/functions/url-check/index.ts](supabase/functions/url-check/index.ts), [supabase/functions/file-check/index.ts](supabase/functions/file-check/index.ts), [scripts/audit-reputation-lifecycle.mjs](scripts/audit-reputation-lifecycle.mjs).

### T22 — Tenant izolasyonu ve kaynak tüketim sınırları (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Edge byte/rate sınırı bozuk RPC'de 503 ve stalled stream'de 413 fail-closed üretiyor; müşteri yük/izolasyon kabulü açık.

**Başlangıç durumu:** RLS, rol ve bazı negatif uçtan uca testler var.

**Başlangıç boşluğu / müşteri etkisi:** Her endpoint/rol/tenant kombinasyonu, body/stream sınırı, rate-limit kesintisi ve komşu tenant kaynak tüketimi tam ölçülmedi.

**Tamamlanma hedefi:** Tüm endpointler için auth/RBAC/RLS sözleşmesi; servis rolü kullanan yollarda açık tenant sınırı; kuyruk/iş/istek/depoma kotaları ekle ve denetle.

**Kalan kapanış testi:** Farklı tenant, üyelik kaybı, viewer, eski anahtar, büyük body ve paralel isteklerle negatif matris çalışsın; tek tenant diğerinin SLO'sunu tüketemesin.

**Sorumlu:** Security + Backend + SRE. **Bağımlılık:** Bağımsız değerlendirme ve tanımlı yük profili.

**İlişkili özellikler:** TEN-01, OBS-01, DEP-07. **Kaynak:** [supabase/functions/_shared/auth.ts](supabase/functions/_shared/auth.ts), [supabase/migrations/20260805000000_hybrid_tenancy.sql](supabase/migrations/20260805000000_hybrid_tenancy.sql).

### T23 — Telemetri dayanıklılığı ve görünür veri kaybı (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Telemetry WAL bozuk/unknown/tampered committed kayıtları reddediyor, terminal drop sonrası retry ve stale backlog readiness sağlıyor; uzun kesinti saha testi açık.

**Başlangıç durumu:** Olay alımı ve dashboard bağlı.

**Başlangıç boşluğu / müşteri etkisi:** Filo yükünde teslim SLO'su, disk/kuyruk sınırı, offline retry/dedup ve uçtan uca kayıp oranı için kanıt eksik.

**Tamamlanma hedefi:** Olay teslim sözleşmesi, kimlik/idempotency, retry/backpressure, kayıp sayaçları ve tenant bazlı retention bütçelerini doğrula.

**Kalan kapanış testi:** Ağ/DB/storage kesintisi ve ajan yeniden başlatmada kayıp/duplicate ölç; sessiz olay kaybı olmasın; disk dolması ve gecikme kullanıcıya görünür olsun.

**Sorumlu:** Telemetry Engineering + SRE. **Bağımlılık:** Müşteri cihaz/olay hacmi ve saklama hedefi.

**İlişkili özellikler:** OBS-01. **Kaynak:** [supabase/functions/ingest/index.ts](supabase/functions/ingest/index.ts), [packages/core/src/audit-log.ts](packages/core/src/audit-log.ts).

### T24 — SIEM ve OpenTelemetry üretim teslimi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** SIEM durable state provider/endpoint/index routing fingerprint'e bağlı ve farklı hedefte reopen'i reddediyor; gerçek SIEM alındısı/zamanlayıcı açık.

**Başlangıç durumu:** Dışa aktarma/izleme bileşenleri mevcut.

**Başlangıç boşluğu / müşteri etkisi:** Named SIEM transport, teslim bildirimi, kesinti tamponu, şema sürümü ve müşteri SIEM alan eşlemesi kabul edilmedi.

**Tamamlanma hedefi:** Satılacak Splunk/Sentinel/Elastic vb. adaptörleri için gerçek endpoint entegrasyonu, retry/dedup ve sağlık göstergesi tamamla.

**Kalan kapanış testi:** SIEM kesintisi/429/401, sertifika değişimi, yeniden gönderim ve alan eşlemesi gerçek SIEM'de doğrulansın; yanlış başarı bildirimi olmasın.

**Sorumlu:** Integrations + Customer SOC. **Bağımlılık:** SIEM test hesabı ve event schema anlaşması.

**İlişkili özellikler:** OBS-04. **Kaynak:** [packages/core/src/siem-export.ts](packages/core/src/siem-export.ts), [packages/core/src/tracing.ts](packages/core/src/tracing.ts).

### T25 — Olay araştırması ve kanıt bütünlüğü (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** incidents/evidence-receipt.ts candidate/policy/device/actor/incident/action bagli append-only receipt, Lamport mantik saati ile offline/skew siralamasi, duplicate/tamper reddi ve fail-closed arsiv adapteri ekliyor. Dis arsiv sahibi ve key custody acik. Eski: Olay receipt head sırası deterministik UTF-16 ve legacy doğrulama uyumlu; ayrı Ed25519 snapshot makbuzu var. Dış saklama, key custody ve güvenilir zaman açık.

**Başlangıç durumu:** Yerel korelasyon ve imzalı response zinciri var.

**Başlangıç boşluğu / müşteri etkisi:** Tam cross-agent nedensellik, ayrıcalıklı değişikliklere karşı bağımsız kanıt saklama ve olay→araç→credential izi eksik.

**Tamamlanma hedefi:** Korelasyon kimlikleri, zaman sapması, ilişkili ajan/kaynak görünümü, zincir doğrulama ve bağımsız arşiv kur.

**Kalan kapanış testi:** Saat kayması/duplicate/offline sıralama, silinmiş veya değiştirilmiş zincir ve çok ajanlı saldırıda kanıt boşlukları görünür olsun.

**Sorumlu:** Detection + SOC Product. **Bağımlılık:** Kimlik grafiği, güvenilir zaman ve arşiv sahibi.

**İlişkili özellikler:** OBS-02, RSP-05. **Kaynak:** [packages/core/src/incidents/correlate.ts](packages/core/src/incidents/correlate.ts), [packages/core/src/incidents/anchor.ts](packages/core/src/incidents/anchor.ts), [packages/core/src/response-audit.ts](packages/core/src/response-audit.ts).

### T26 — Saklama, legal hold ve müşteri çıkışı (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Offboarding her Storage nesnesinin yokluğunu doğrulamadan ACK üretmiyor; legal hold/resume var, harici backup silme kanıtı açık.

**Başlangıç durumu:** Sayfalı export ve geçici dosyalar için silme komutu var; zamanlayıcı şablonu sağlanıyor.

**Başlangıç boşluğu / müşteri etkisi:** Zamanlayıcı müşteri ortamında aktif değil; tüm veri sınıfları için retention/deletion, legal hold ve doğrulanmış offboarding yok.

**Tamamlanma hedefi:** Tablo/nesne/log/cache/yedek bazında yaşam döngüsü; legal hold istisnası; kullanıcı/tenant kapanışı ve silme makbuzu kur.

**Kalan kapanış testi:** Süre dolan verinin API, Storage, cache ve replikalardan yokluğu; hold verisinin korunması; retry ve yarım silme sonrası tutarlılık kanıtlansın.

**Sorumlu:** Backend + Privacy + Operations. **Bağımlılık:** Onaylı saklama/silme politikası; yedek istisnaları.

**İlişkili özellikler:** OBS-03, OBS-06. **Kaynak:** [scripts/deployment-maintenance.mjs](scripts/deployment-maintenance.mjs), [deploy/maintenance/aidr-export-retention.timer](deploy/maintenance/aidr-export-retention.timer), [supabase/functions/audit-export/index.ts](supabase/functions/audit-export/index.ts).

### T27 — Offsite yedekleme ve RPO/RTO (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Offsite commit zamanı authenticated manifest'e bağlı ve S3 lookup hatası fail-closed; izole restore aracı var. Bağımsız host/provider ve RPO/RTO açık.

**Başlangıç durumu:** Şifreli soğuk yedek ve bağımsız volume geri dönüşünde 18 karşılaştırma geçti.

**Başlangıç boşluğu / müşteri etkisi:** Off-host kopya, otomatik zamanlama/retention, ayrı anahtar kurtarma ve gerçek felaket RPO/RTO kanıtı yok; bakım duruşu gerekiyor.

**Tamamlanma hedefi:** Yedek hedefi/anahtar custody, zamanlama, erişim ayrılığı, başarısızlık alarmı ve kayıp-host geri dönüş işletimini kur.

**Kalan kapanış testi:** Yeni hostta yalnız offsite yedek ve ayrı anahtarla kurtar; tablo/nesne içerikleri eşleşsin; gerçek kayıp veri süresi ve toparlanma süresi ölçülsün.

**Sorumlu:** SRE + Customer Operations. **Bağımlılık:** Offsite storage, key custodian, kabul edilmiş RPO/RTO.

**İlişkili özellikler:** DEP-06. **Kaynak:** [scripts/deployment-backup.mjs](scripts/deployment-backup.mjs), [scripts/verify-deployment-recovery.mjs](scripts/verify-deployment-recovery.mjs).

### T28 — Gerçek cloud ve self-hosted üretim kurulumu (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** 33 migrationlı self-hosted prova var; prepare inputları secret oluşturmadan doğruluyor ve cloud public proxy/provider upstream loop'unu reddediyor. Canlı provider/TLS açık.

**Başlangıç durumu:** İki model için kurulum hazırlama ve yerel Docker prova var.

**Başlangıç boşluğu / müşteri etkisi:** Cloud hesabı/projesi, bölge, DNS/TLS, reverse proxy, SMTP/IdP, secret installation ve gerçek internet erişimi bilinmiyor; cloud hazırlama çalışan cloud demek değil.

**Tamamlanma hedefi:** Her model için hedef ortamı kur; TLS yenileme ve HTTP/WebSocket başlıklarını doğrula; DB/Studio'yu özel ağda tut; public endpoint ve onboarding'i kabul et.

**Kalan kapanış testi:** Temiz makinede müşteri kimliğiyle giriş→cihaz→deny→olay→export→rollback akışı; dış port/izin kontrolleri ve sertifika yenileme tatbikatı.

**Sorumlu:** SRE + Customer IT. **Bağımlılık:** Alan adı, cloud hesabı/bölge ve ağ bilgisi.

**İlişkili özellikler:** DEP-01, DEP-02. **Kaynak:** [scripts/deployment-prepare.mjs](scripts/deployment-prepare.mjs), [deploy/FIRST_CUSTOMER.md](deploy/FIRST_CUSTOMER.md).

### T29 — Kimliği doğrulanan dağıtım ve release provenance (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Release verifier receipt hedefini mutation öncesi doğruluyor ve bundle/state/policy çakışmasını reddediyor; resmi key custody/private registry açık.

**Başlangıç durumu:** Taşınabilir aday, SBOM, paket tüketici ve SHA denetimleri var; yayıncı imzası yok.

**Başlangıç boşluğu / müşteri etkisi:** Checksum yayıncı kimliği değildir. Private registry kurulumu, imza doğrulama, key rotasyonu ve air-gap imaj teslimi kanıtı yok.

**Tamamlanma hedefi:** Aynı candidate'ı imzala; auth kontrollü registry/download, provenance ve sabit imaj digestleriyle teslim et; air-gap satılıyorsa tüm bağımlılık/imajları dahil et.

**Kalan kapanış testi:** Yanlış signer/değişmiş arşiv/eski sürüm reddedilsin; müşteri temiz makinede internetsiz veya yetkili registry ile kurabilsin; imza/anahtar iptali sınansın.

**Sorumlu:** Release Engineering + Security. **Bağımlılık:** Signer ve registry yetkisi; lisans onayı.

**İlişkili özellikler:** DEP-05, DEP-08, OBS-05. **Kaynak:** [scripts/customer-kit.mjs](scripts/customer-kit.mjs), [.github/scripts/build-release-bundle.mjs](.github/scripts/build-release-bundle.mjs), [scripts/release-artifact-manifests.mjs](scripts/release-artifact-manifests.mjs).

### T30 — HA, failover, kapasite ve SLA ölçümü (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Load harness her fault senaryosu için son hatadan sonra ardışık recovery ve tam gözlem istiyor; gerçek HA, kapasite ve aylık SLA açık.

**Başlangıç durumu:** Tek host Docker temel kurulumu var; 501 satır sayfalama testi yük testi değildir.

**Başlangıç boşluğu / müşteri etkisi:** HA topology, DB failover, tenant noisy-neighbor ve aylık availability SLI kanıtı yok; 99.9 ölçülmüş sonuç değil.

**Tamamlanma hedefi:** Desteklenen kapasite ve region topology tanımla; load/soak/failover, hata bütçesi ve ölçüm paydası kur.

**Kalan kapanış testi:** Gerçekçi agent/event yükünde p50/p95/p99, hata/kayıp oranı, DB/servis/node arızası ve bakım etkisi raporlansın; kabul edilmiş gözlem penceresi tamamlanmış olsun.

**Sorumlu:** SRE + Performance Engineering. **Bağımlılık:** Host boyutları, filo/olay profili, SLA anlaşması.

**İlişkili özellikler:** DEP-07. **Kaynak:** [deploy/dashboard/server.mjs](deploy/dashboard/server.mjs), [deploy/README.md](deploy/README.md).

### T31 — Migration, upgrade ve geri dönüş tatbikatı (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Kesilen rename resume yalnız kaynak/staged içerik preflight hash'leriyle eşleşirse devam ediyor; gerçek trafik cutover/rollback kabulü açık.

**Başlangıç durumu:** 18 migration checksum/transaction ile uygulanıyor; temiz kurulum smoke var.

**Başlangıç boşluğu / müşteri etkisi:** Önceki müşteri sürümünden upgrade, sürüm karmaşası ve gerçek üretim rollback tatbikatı açık.

**Tamamlanma hedefi:** Desteklenen upgrade yolları, ön kontrol/yedek, kesinti planı, kompatibilite ve başarısız migration geri dönüş prosedürü hazırla.

**Kalan kapanış testi:** Eski veriyle upgrade, kesilen migration, checksum değişikliği, uygulama/DB sürüm uyuşmazlığı ve kurtarma testi; veri kaybı ve sessiz schema drift olmasın.

**Sorumlu:** Backend + Release + SRE. **Bağımlılık:** Önceki sürüm snapshotları ve bakım penceresi.

**İlişkili özellikler:** DEP-03, DEP-04. **Kaynak:** [scripts/deployment-migrate.mjs](scripts/deployment-migrate.mjs), [scripts/deployment-doctor.mjs](scripts/deployment-doctor.mjs).

### T32 — İzleme, alarm ve işletim sahipliği (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Per-instance scrape/readiness ve empty-discovery alertleri eklendi; kural YAML/testleri var. Canlı paging, isimli nöbet ve SLA açık.

**Başlangıç durumu:** Runbook ve container sağlık kontrolleri var.

**Başlangıç boşluğu / müşteri etkisi:** Production dashboard, nöbetçi, gerçek paging, sertifika/disk/kuyruk/feed/backup alarmı ve incident tatbikatı tamamlanmadı.

**Tamamlanma hedefi:** SLI dashboard ve alarm eşikleri, sorumlu/nöbet takvimi, alarm sessizliği kontrolü, escalation ve olay sonrası inceleme akışı kur.

**Kalan kapanış testi:** Servis, DB, storage, signer, kuyruk ve yedek hatası enjekte et; doğru kişiye zamanlı alarm ve çözüldü bildirimi gelsin; kayıtlı tatbikat tut.

**Sorumlu:** SRE + Support. **Bağımlılık:** Gerçek izleme/paging kanalları ve isimli sorumlular.

**İlişkili özellikler:** DEP-01, DEP-02, OBS-01. **Kaynak:** [docs/runbooks/alerting.md](docs/runbooks/alerting.md), [docs/runbooks/incident-response.md](docs/runbooks/incident-response.md).

### T33 — Satılan fatura ve entitlement yaşam döngüsü (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** billing-portal Edge Function provider-of-record durum makinesi, sunucu tarafi tenant/uyelik/rol/MFA cozumlemesi, istemci customer/tenant/subscription id reddi, TTL/idempotency, cancel/refund ve seat reconciliation uyguluyor; finance fixture ile test edildi, canli provider ve muhasebe onayi acik. Eski: Pending Finance sipariş sonucu tenant/request/quantity/quote alanlarına fail-closed bağlı; provider-of-record, ödeme makbuzu ve paid-to-entitlement yok.

**Başlangıç durumu:** Varsayılan kurum faturası; opsiyonel Stripe checkout/webhook kaynak kodu mevcut.

**Başlangıç boşluğu / müşteri etkisi:** Onaylı SKU/fiyat/teklif, tahsilat-mutabakat, quota değişimi, iptal ve çıkış provası yok. Self-service portal uygulanmamış; yalnız satılan SKU'da gerekiyorsa blocker.

**Tamamlanma hedefi:** Provider-of-record ve kurumsal sipariş→quota işletimini tamamla; self-service satılacaksa gerçek portal, invoice, cancel/refund/reconcile akışlarını ekle.

**Kalan kapanış testi:** Sipariş/ek koltuk/azaltma/yenileme/ödeme hatası/iptal ve mükerrer webhook aynı entitlement sonucunu versin; finans mutabakatı ve müşteri makbuzu eşleşsin.

**Sorumlu:** Finance + Billing Engineering. **Bağımlılık:** Ticari karar, canlı provider anahtarları ve muhasebe onayı.

**İlişkili özellikler:** BIL-01, BIL-02, BIL-03. **Kaynak:** [packages/dashboard/src/ui/pages/BillingPage.tsx](packages/dashboard/src/ui/pages/BillingPage.tsx), [supabase/functions/billing-checkout/index.ts](supabase/functions/billing-checkout/index.ts), [supabase/functions/stripe-webhook/index.ts](supabase/functions/stripe-webhook/index.ts).

### T34 — Readiness kayıtlarının ve ürün iddialarının tutarlılığı (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** 71 özellik, 59 iş paketi, 10 release rootu ve claim candidate/expiry tutarlılığı otomatik kontrol ediliyor; 13 dış onay kapısı açık.

**Başlangıç durumu:** Envanter güncel; eski denetim alanları tarihsel metinler içeriyor.

**Başlangıç boşluğu / müşteri etkisi:** Ticari registry Ağustos tarihli ve artifactRoots/connector listesi mevcut dokuz paketi tam yansıtmıyor; eski checkout/default endpoint ifadeleri yeni implementasyonu anlatmıyor.

**Tamamlanma hedefi:** Tarihsel bulguyu korurken currentState alanlarını ayır; beklenen paket/connector kapsamını release manifestinden türet; web, README, demo ve teklif metnini tek kanıt sözlüğüne bağla.

**Kalan kapanış testi:** Aynı sürümün paket/özellik/claim sayıları tutarlı; eksik paket zorunlu gate'i düşürsün; süresi dolmuş/onaysız iddia müşteri yüzüne çıkmasın.

**Sorumlu:** Product + Release + Marketing. **Bağımlılık:** Güncel release candidate ve ticari onay sahipleri.

**İlişkili özellikler:** EVAL-02, EVAL-03, DEP-05. **Kaynak:** [docs/production-readiness/commercial-go-evidence-registry.json](docs/production-readiness/commercial-go-evidence-registry.json), [READINESS_BACKLOG.json](READINESS_BACKLOG.json), [README.md](README.md).

### T35 — Test kapılarının kapsamı ve başarısızlığın saklanmaması (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** v7 birleşik test 237 dosya/3326 geçiş/2 açıklanmış skip, coverage eşikleri ve 10 paket release consumer geçti; native kör corpus açık.

**Başlangıç durumu:** Binlerce yerel test ve derlenmiş kanca kontrolleri var; 1 canlı sağlayıcı senaryosu atlanıyor. Son koşu hatası ve düzeltme kaydı tutuluyor.

**Başlangıç boşluğu / müşteri etkisi:** Test sayısı özellik tamamlanması değildir; bazı gözlem testleri bilinen boşluğu allow olarak kabul ediyor. Native/soak/bağımsız corpus ve coverage kapanışı eksik; 132 lint uyarısı var.

**Tamamlanma hedefi:** Özellik→tüketici→pozitif/negatif→artefact bağını zorunlu kıl; bilinen açıkları test hedefi yap; mandatory skip ve stale evidence gate'i düşürsün; uyarı/dead-code borcunu sınıflandır.

**Kalan kapanış testi:** Her satılan özellik için gerçek tüketicide deny/allow/outage kanıtı; aynı candidate checksum; 0 açıklanmamış zorunlu skip; değişmeyen timeoutlarla tekrar koşu ve açık borç kaydı.

**Sorumlu:** QA + Security Engineering. **Bağımlılık:** Native ortam, bağımsız corpus ve CI kapasitesi.

**İlişkili özellikler:** EVAL-01, CON-05. **Kaynak:** [vitest.config.ts](vitest.config.ts), [packages/opencode/src/__tests__/aidr-contract.test.ts](packages/opencode/src/__tests__/aidr-contract.test.ts), [scripts/verify-enforcement.mjs](scripts/verify-enforcement.mjs).

### T36 — Operatör UI ve ilk müşteri kullanılabilirliği (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Onboarding stale token/tenant/error durumları fail-closed ve yapılandırılmış Azure/Entra login görünür; gerçek browser/IdP/erişilebilirlik kabulü açık.

**Başlangıç durumu:** Giriş, ekip seçimi, kayıt, politika ve export akışları yerel testli.

**Başlangıç boşluğu / müşteri etkisi:** Tüm desteklenen tarayıcılar, klavye/erişilebilirlik, ağ hataları, çok ekipli eş zamanlı kullanım ve gerçek müşteri eğitimi tamam değil.

**Tamamlanma hedefi:** Ekran bazlı loading/empty/error/permission sözleşmesi, erişilebilirlik ve tarayıcı matrisi; ilk müşteri kılavuzunu gerçek operatörle uygula.

**Kalan kapanış testi:** Yanlış ekipte sır/politika görünmesin; timeout/409/401 sonrası yanlış başarı olmasın; klavye ile kritik işler tamamlansın; büyük liste ve uzun değerlerde UI bozulmasın.

**Sorumlu:** Dashboard + Design + Customer Success. **Bağımlılık:** Desteklenen browser ve müşteri kullanıcıları.

**İlişkili özellikler:** CLI-01, TEN-07, TEN-03, POL-02, OBS-03. **Kaynak:** [packages/dashboard/src/main.tsx](packages/dashboard/src/main.tsx), [packages/dashboard/src/ui/pages/OnboardingPage.tsx](packages/dashboard/src/ui/pages/OnboardingPage.tsx), [packages/dashboard/src/enterprise/audit-view.tsx](packages/dashboard/src/enterprise/audit-view.tsx).

### T37 — Gerçek veri akışı, redaksiyon ve gizlilik kanıtı (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Privacy verifier canary boyunca source hash kararlılığı ve temp support-bundle izolasyonu istiyor; 6 canary/13 bundle kontrolü geçti, hukuk/saha açık.

**Başlangıç durumu:** Redaksiyon ve tenant ayrımı bileşenleri var.

**Başlangıç boşluğu / müşteri etkisi:** Tüm outbound alan/domain listesi, browser tracing, managed olaylar, AIG payloadları, region, subprocessors ve silme kanıtı müşteri metinleriyle onaylanmadı.

**Tamamlanma hedefi:** Alan bazlı data-flow ve egress envanteri çıkar; ham prompt/komut/secret canary'leriyle paket/log/export/support bundle sözleşmesi kur; metinleri gerçek işleyişe eşle.

**Kalan kapanış testi:** Canary sırlar izinsiz kanalda bulunmasın; opt-out ve retention davranışı ölçülsün; bütün veri sınıfları için bölge/erişim/silme sahibi belli olsun.

**Sorumlu:** Privacy + Security + Engineering. **Bağımlılık:** DPA ve müşteri veri sınıflandırması; hukuk incelemesi.

**İlişkili özellikler:** OBS-01, OBS-03, OBS-06, TEN-01. **Kaynak:** [docs/privacy.md](docs/privacy.md), [packages/core/src/tracing.ts](packages/core/src/tracing.ts), [supabase/functions/ingest/index.ts](supabase/functions/ingest/index.ts).

### T38 — Kuruma özel DLP ve veri etiketleri (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** DLP overlapping ve JSON Unicode-escaped secret spanlarını tam redact ediyor; malformed/mapping/oversize fail-closed. Versioned CAS storage/history/audit/offboarding ve owner/admin+MFA publish sınırı uygulandı; imzalı agent delivery ve müşteri label kabulü açık.

**Başlangıç durumu:** PII/DLP detektörleri ve bazı çıktı kontrolleri var.

**Başlangıç boşluğu / müşteri etkisi:** Müşteri etiketleri, belge/attachment türleri, her bağlayıcıdaki giriş/çıkış yolu ve düşük yanlış alarm kabulü tamam değil.

**Tamamlanma hedefi:** Kural/etiket yönetimi, kapsam hedefleri, maskeleme/engelleme/approval eylemleri ve exception yaşam döngüsünü bağla.

**Kalan kapanış testi:** Sentetik ve kuruma özgü sırlar tüm kapsanan giriş/çıkışlarda yakalansın; yetkili benign işlem geçsin; örnek dışı format unavailable olarak raporlansın.

**Sorumlu:** Detection + Customer Security. **Bağımlılık:** Etiket/kural sözlüğü ve maskelenmiş test verisi.

**İlişkili özellikler:** DET-07. **Kaynak:** [packages/core/src/dlp/index.ts](packages/core/src/dlp/index.ts), [packages/core/src/pii-detector.ts](packages/core/src/pii-detector.ts).

### T39 — Bağımsız etkinlik, performans ve rakip kıyaslaması (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Deterministik sentetik corpus, içerik-digest holdout manifesti, sold-scope coverage, confusion/P-R-F1/ROC-AUC, reason-coded unknown competitor hücreleri, trusted-key/duty-separation binding, ölçüm bütçesi, canonical digest ve byte-exact reproduce harness'ı uygulanıp test edildi. Gerçek müşteri benign corpus'u, competitor erişimi, bağımsız evaluator/trust kaydı ve bütçe onayı dış kanıt olarak açık.

**Başlangıç durumu:** Pazar yetenek kategorileri ve önerilen benchmark protokolü belgeli.

**Başlangıç boşluğu / müşteri etkisi:** En iyi ürün, sıfır false-positive, evasion dayanıklılığı veya latency üstünlüğünü gösteren bağımsız kanıt yok.

**Tamamlanma hedefi:** Geliştirme ve blind holdout setlerini ayır; saldırı ailesi/bağlayıcı bazında coverage, false block/approval, p50/p95/p99 ve limitations ölç; eşit koşullu karşılaştırma yap.

**Kalan kapanış testi:** Aynı workload/ortamda ham ölçüm, payda, sürüm, örneklem ve bağımsız değerlendirici imzası; görünmeyen yüzeyler başarı ortalamasına katılmasın.

**Sorumlu:** Detection Research + QA + Independent Evaluator. **Bağımlılık:** Müşteri benign corpus'u, rakip değerlendirme erişimi, ölçüm bütçesi.

**İlişkili özellikler:** EVAL-01, EVAL-02, EVAL-03. **Kaynak:** [docs/production-readiness/agent-security-market-and-release-plan.md](docs/production-readiness/agent-security-market-and-release-plan.md), [docs/production-readiness/customer-investor-validation-master-plan.md](docs/production-readiness/customer-investor-validation-master-plan.md).

### T40 — Güvenlik güncellemesi ve müşteri destek işletimi (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Support v7 runbook, izinli/hashli bundle, escalation ve emergency update akışı hazır; gerçek kanal, nöbet ve ticket tatbikatı açık.

**Başlangıç durumu:** Runbook ve destek şablonları bulunuyor.

**Başlangıç boşluğu / müşteri etkisi:** Çalışan ticket/security contact, nöbet, CVE/incident bildirimi, imzalı acil güncelleme, EOL ve tanılama izni işletimi onaylı değil.

**Tamamlanma hedefi:** Destek planı, severity/response hedefi, escalation, PSIRT/sorumlu, patch dağıtımı, EOL ve redakte tanılama prosedürü kur.

**Kalan kapanış testi:** Gerçek ticket aç/kapat, kritik incident ve imza anahtarı kaybı tatbikatı; müşteri bildirim süresi, rollback ve sır içermeyen tanılama kanıtlansın.

**Sorumlu:** Support + SRE + Security. **Bağımlılık:** İsimli ekip, iletişim kanalları, sözleşme ve çalışma saatleri.

**İlişkili özellikler:** DEP-05, OBS-05. **Kaynak:** [docs/runbooks/incident-response.md](docs/runbooks/incident-response.md), [docs/production-readiness/support-sla-template.md](docs/production-readiness/support-sla-template.md).

### T41 — İlk müşteri satış ve satın alma değerlendirme paketi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Güncel ilk müşteri satış paketi ve portable kit üreticisi var; yeni v7 kit imzası ile onaylı teklif/satın alma kabulü açık.

**Başlangıç durumu:** Kontrollü demo, değerlendirme planı, ilk kurulum ve sipariş şablonları mevcut.

**Başlangıç boşluğu / müşteri etkisi:** Müşterinin satın alma sürecine uygun onaylı ürün özeti, mimari/veri akışı, destek matrisi, güvenlik soru formu, kapsamlı teklif ve kanıta dayalı demo/PoV paketi tek sürümde birleştirilmedi. Bu çalışma ortamındaki static preflight satış URL/e-posta ayarı bulamadı; üretim satış CTA hedefi ayrıca doğrulanmalı.

**Tamamlanma hedefi:** Ürün özeti, gereksinimler, deployment seçenekleri, desteklenen araçlar, açık sınırlar, güvenlik/tedarikçi soru yanıtları, teklif ve PoV başarı ölçütlerini satış kitinde topla; ölçülmemiş ROI veya sertifikasyon iddiası ekleme.

**Kalan kapanış testi:** Bir operatör kılavuzdan demoyu tekrar edebilsin; procurement soruları kaynak/kanıt/owner'a bağlı olsun; teklif kapsamı ile kurulan özellik ve destek koşulları eşleşsin; müşteri adı olmadan referans/başarı hikayesi uydurulmasın.

**Sorumlu:** Sales Engineering + Product + Legal + Finance. **Bağımlılık:** Müşteri satın alma formu, teklif sahibi, onaylı ürün kapsamı.

**İlişkili özellikler:** EVAL-02, EVAL-03, BIL-01. **Kaynak:** [docs/production-readiness/controlled-demo-runbook.md](docs/production-readiness/controlled-demo-runbook.md), [docs/production-readiness/customer-investor-validation-master-plan.md](docs/production-readiness/customer-investor-validation-master-plan.md), [docs/production-readiness/enterprise-order-entitlement-template.md](docs/production-readiness/enterprise-order-entitlement-template.md).

### T42 — Legacy RLS tenant yaşam döngüsü ve itibar satırı sahteciliği (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Eski izin verici RLS kaldırıldı; forged claim, expired member, suspended tenant ve service-role kontrolleri yerel PostgreSQL'de geçti. Saha migrationı açık.

**Başlangıç durumu:** Eski izin verici RLS kuralları yabancı tenant itibar satırı ekleme ve üyelik sonrası erişime izin veriyordu.

**Başlangıç boşluğu / müşteri etkisi:** Yeni migration yetkiyi kapatır; önceden yazılmış olabilecek sahte satırlar otomatik temizlenmez ve kurulu müşteri verisi denetlenmedi.

**Tamamlanma hedefi:** Migrationı uygulamadan önce tenant itibar satırlarını denetle; migrationı kontrollü uygula, kalıcı rol matrisi ve PostgREST negatif testini çalıştır.

**Kalan kapanış testi:** Eski üye veya askıya alınmış tenant okuyamasın; başka tenant için insert reddedilsin; mevcut veride sahte kayıt kalmasın ve servis rolü işlemleri çalışsın.

**Sorumlu:** Database + Security. **Bağımlılık:** Mevcut deployment verisi ve migration penceresi.

**İlişkili özellikler:** TEN-01, DET-10, DET-11. **Kaynak:** [supabase/migrations/20260912000019_tenant_lifecycle_rls.sql](supabase/migrations/20260912000019_tenant_lifecycle_rls.sql), [scripts/tenant-lifecycle-rls-postgres.test.mjs](scripts/tenant-lifecycle-rls-postgres.test.mjs).

### T43 — Enrollment exchange işlem bütünlüğü (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Atomik token/seat/key RPC ve lost-response sonucu unknown sözleşmesi var; plaintext-key recovery protokolü ve canlı HTTP kabulü açık.

**Başlangıç durumu:** Tek kullanımlık token önceden tüketilip sonraki adım hata verince kurulum kilitlenebiliyordu.

**Başlangıç boşluğu / müşteri etkisi:** Yeni RPC atomik yazıyor; müşteri HTTP akışında kayıp yanıt, eski kayıt ve eşzamanlı seat yarışı henüz sınanmadı.

**Tamamlanma hedefi:** Migrationı dağıt, canlı HTTP hata enjeksiyonuyla token/seat/key durumunu doğrula, belirsiz commit sonrası yeniden kayıt operatör prosedürünü hazırla.

**Kalan kapanış testi:** Hata rollback yaparken token yeniden kullanılabilsin; başarıda yalnız bir kimlik oluşsun; kayıp yanıt açık unknown durumuna düşsün.

**Sorumlu:** Identity + Backend. **Bağımlılık:** Müşteri kurulum ortamı ve canlı DB.

**İlişkili özellikler:** TEN-05, TEN-06. **Kaynak:** [supabase/migrations/20260912000017_enrollment_exchange_atomic.sql](supabase/migrations/20260912000017_enrollment_exchange_atomic.sql), [supabase/functions/enroll/index.ts](supabase/functions/enroll/index.ts).

### T44 — Entitlement grace ve eski imzalı önbellek geçişi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Cache unsigned/unknown/schema-invalid entitlement'ı atıyor; kesin invalid_api_key signed state'i temizliyor, geçici hata grace'i koruyor. Canlı kabul açık.

**Başlangıç durumu:** Yedi günlük entitlement bitişinden sonraki 72 saatlik grace yanlış hesaplanıyordu.

**Başlangıç boşluğu / müşteri etkisi:** Kod düzeltildi; önceki yanlış imzalı snapshotlar çevrimdışı iken düzelmez, canlı Deno ve zaman geçişi kabulü açık.

**Tamamlanma hedefi:** Yeni entitlementları dağıtıp önbelleği güvenli yenile; saat sınırı ve eski istemci geçişi tatbikatı yap.

**Kalan kapanış testi:** 168 saat sonrasında 72 saat grace, ardından deny; iptal edilen/bozuk anahtar her aşamada reddedilsin.

**Sorumlu:** Identity + Endpoint. **Bağımlılık:** İmzalı eski kayıtlar ve müşteri ağ takvimi.

**İlişkili özellikler:** TEN-05, POL-04. **Kaynak:** [supabase/functions/enroll/index.ts](supabase/functions/enroll/index.ts), [supabase/functions/ingest/index.ts](supabase/functions/ingest/index.ts), [packages/core/src/managed.ts](packages/core/src/managed.ts).

### T45 — Device-start güvenilir IP ve giriş yönlendirmesi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Device-start signer placeholder/reused secret'i reddediyor; HMAC ingress/rate limit var. Gerçek public proxy/TLS routing ve müşteri yükü açık.

**Başlangıç durumu:** İstemcinin verdiği IP başlığıyla 30/dakika sınırı aşılabiliyordu.

**Başlangıç boşluğu / müşteri etkisi:** İmzalı ingress ve küresel sınır kodlandı; Nginx/TLS yönlendirmesi ve iki özel anahtarın müşteri ortamında kurulumu henüz kanıtlanmadı.

**Tamamlanma hedefi:** Cloud ve self-hosted girişini signer üzerinden geçir; proxy başlıklarını temizle, doğrudan Edge yolunu engelle ve yük testini çalıştır.

**Kalan kapanış testi:** Sahte başlıklar oranı değiştirmesin; imzasız istek 401; meşru kayıt akışı iki dağıtım modelinde çalışsın.

**Sorumlu:** Platform + Identity. **Bağımlılık:** TLS proxy, sır yönetimi ve müşteri ağı.

**İlişkili özellikler:** TEN-05, DEP-01, DEP-02. **Kaynak:** [supabase/functions/device-start/index.ts](supabase/functions/device-start/index.ts), [deploy/ingress/device-start.mjs](deploy/ingress/device-start.mjs).

### T46 — Device-poll onaydan kayda atomik geçiş (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Device-poll kayıp yanıt/eşzamanlı poll'da aynı hash-only tokenı geri buluyor, lookup hatasında 503 unknown dönüyor; canlı yarış kabulü açık.

**Başlangıç durumu:** Onaylanan oturum token eklenmeden exchanged olabiliyor, geçici hata kullanıcıyı yeniden kurulum başlatmaya zorluyordu.

**Başlangıç boşluğu / müşteri etkisi:** Yeni RPC atomik; canlı HTTP retry, yarış ve müşteri tarayıcısı/CLI kabulü açık.

**Tamamlanma hedefi:** Migrationı dağıtıp onay, poll ve enroll tam akışını hata enjeksiyonu ile çalıştır; eşzamanlı poll ve kayıp yanıtı ölç.

**Kalan kapanış testi:** Bir onay en çok bir token üretir; insert hatası oturumu tüketmez; tekrar poll belirsiz durum olarak raporlanır.

**Sorumlu:** Identity + QA. **Bağımlılık:** Canlı kurulum ve gerçek cihaz.

**İlişkili özellikler:** TEN-05. **Kaynak:** [supabase/functions/device-poll/index.ts](supabase/functions/device-poll/index.ts), [supabase/migrations/20260912000017_enrollment_exchange_atomic.sql](supabase/migrations/20260912000017_enrollment_exchange_atomic.sql).

## Ticari, dış değerlendirme ve müşteri kabul kapıları

Aşağıdakiler mevcut ticari registry'nin açık kayıtlarıdır. Doküman şablonu bulunması, yetkili onayı veya çalışan operasyon sayılmaz. Hukuki metin ve sözleşmelerin geçerliliğini bu rapor onaylamaz; ilgili kurum sahipleri incelemelidir.

### COM-001 — Onaylı SKU, fiyat, teklif ve ticari sürüm manifesti

**Durum:** open. **Geçerli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** Aynı sürüme bağlı SKU, fiyat, ölçüm birimi, para birimi/vergi, kurulum modeli, bölge, saklama, SLA, destek, lisans hakkı, yenileme, iptal ve çıkış koşulları onaylanmamış.

**Yapılacak iş:** Satış ve finans tek ticari manifesti onaylasın; örnek teklif/siparişten müşteri çıkışına kadar prova yapılsın.

**Kapatmak için gerekli somut kanıt:** İsimli onaylı ticari manifest; Örnek teklif ve sipariş; Siparişten offboarding'e prova; Sürüm ve değiştirilemeyen kanıt özeti.

**Sorumlu:** Commercial/Sales + Finance/Billing. **Kontrol:** claim-check --mode=gate plus signed-manifest verification.

### COM-002 — Lisans, fikri mülkiyet ve üçüncü taraf hakları

**Durum:** open. **Geçerli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** Lisans dosyası bulunması yeterli değil: dağıtılan kod/veri/model/üçüncü taraf bileşen hakları, atıflar ve fikri mülkiyet zinciri hukukça onaylanmamış.

**Yapılacak iş:** SBOM ve kaynak kökenini lisans/NOTICE/package metadata ile uzlaştır; dağıtım haklarını ve süreli istisnaları yetkili hukuk incelemesine sun.

**Kapatmak için gerekli somut kanıt:** Hukuk onayı; Eksiksiz LICENSE/NOTICE ve üçüncü taraf lisans paketi; Paket lisanslarının uzlaştırılması; Kaynak/vendor kökeni ve süreli istisna kaydı.

**Sorumlu:** Legal + Engineering. **Kontrol:** claim-check --mode=gate (license/NOTICE/package metadata check) plus licence inventory.

### COM-003 — Veri işleme, DPA ve gizlilik onayı

**Durum:** open. **Geçerli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** Gerçek telemetri, browser tracing, managed olaylar, AIG payloadları, retention/silme, veri bölgesi, alt işleyenler ve transferler müşteri belgeleriyle onaylı biçimde eşleştirilmemiş.

**Yapılacak iş:** Alan bazlı veri akışını ölç; müşteri bildirimi ve gerekli veri işleme/güvenlik eklerini Privacy/Legal sahipleriyle tamamla.

**Kapatmak için gerekli somut kanıt:** Alan bazlı veri akış matrisi ve payload testleri; DPA/TOM/SCC kapsam inceleme ve onayı; Alt işleyen/bölge listesi; Gerçek export ve silme makbuzu.

**Sorumlu:** Privacy/DPO + Legal + Security. **Kontrol:** privacy-payload-contract and outbound-domain/redaction gates.

### COM-004 — Fatura–ödeme–entitlement mutabakatı

**Durum:** open. **Geçerli profiller:** assisted-sale, production-ga, investor.

**Eksik gereksinim:** Sipariş, koltuk değişimi, fatura/mutabakat, iptal, erişim iptali ve müşteri silme tek kayıt sistemine göre uçtan uca kabul edilmemiş.

**Yapılacak iş:** Tek provider-of-record belirle; finans işlemlerini sunucudaki entitlement ile bağla; başarısız/tekrarlanan olay ve manuel müdahale işletimini tanımla.

**Kapatmak için gerekli somut kanıt:** Provider ve SKU kararı; Quota/entitlement senaryoları; Fatura ve mutabakat örneği; İptal, erişim kesme ve silme makbuzu.

**Sorumlu:** Finance/Billing + Product. **Kontrol:** billing contract suite and quote-to-offboarding rehearsal.

### COM-005 — Çalışan destek ve müşteri iletişim yolları

**Durum:** open. **Geçerli profiller:** evaluation, assisted-sale, production-ga.

**Eksik gereksinim:** Müşterinin gerçekten ulaşabildiği destek, durum sayfası, güvenlik iletişimi, privacy/terms, escalation, severity hedefi ve tanılama izni işletimi kanıtlanmamış.

**Yapılacak iş:** Kanalları yayınla; çalışma saatleri ve isimli nöbet/escalation sorumlularını ata; gerçek ticket tatbikatı yap.

**Kapatmak için gerekli somut kanıt:** Yayınlanmış destek/SLA planı; Zaman damgalı ticket tatbikatı; Çalışan status/security/privacy bağlantıları; Nöbet ve escalation kaydı.

**Sorumlu:** Support/Customer Success + Operations. **Kontrol:** deployed route/link crawl; ticket drill is manual evidence.

### COM-010 — Reklamı yapılan tüm bağlayıcıların kabulü

**Durum:** open. **Geçerli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** Reklamı yapılan bağlayıcıların her biri için gerçek host desteği, imzalı paket, özel registry kurulumu, geri dönüş ve destek sahibi tamam değil. Registry'nin kapsam listesi ayrıca güncellenmeli.

**Yapılacak iş:** Satılan connector manifestini sabitle; her connector/host/OS sürümünde aynı imzalı candidate için kurulum, native E2E, rollback ve disable kabulü topla.

**Kapatmak için gerekli somut kanıt:** Tam destek matrisi; Gerçek host test raporları; Private registry kurulum kayıtları; Rollback/disable tatbikatı; İsimli sahip ve sınırlar.

**Sorumlu:** Product + QA + Engineering + Support. **Kontrol:** expected connector manifest, package consumer tests, real-host E2E and claim-check.

### COM-011 — Bölge ve veri yerleşimi kanıtı

**Durum:** open. **Geçerli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** Registry'deki EU/US/APAC hedefleri çalışan ve onaylı bölge hizmeti kanıtı değildir; tenant yerleşimi, routing, yedek/silme ve transfer modeli açık.

**Yapılacak iş:** Satılacak bölgeleri provider ve veri işleme modeliyle eşle; her bölgede tenant yerleşimi ve sınır dışı erişim negatif testlerini tamamla.

**Kapatmak için gerekli somut kanıt:** Bölge/provider matrisi; Tenant yerleşim testi; Cross-region negatif test; Veri işleme onayları; Bölgeye bağlı yedek/silme makbuzları.

**Sorumlu:** Operations + Privacy/DPO + Legal. **Kontrol:** region manifest, outbound-domain/data-flow assertions and deployment smoke per region.

### COM-012 — Faturalı ve kimliği doğrulanan özel dağıtım

**Durum:** open. **Geçerli profiller:** assisted-sale, production-ga, investor.

**Eksik gereksinim:** Kurumsal fatura ile verilen erişimin kimliği doğrulanan private registry ve imzalı artefact teslimiyle çalıştığı kanıtlanmamış; air-gap prosedürü de tamam değil.

**Yapılacak iş:** Sipariş→entitlement→download→install→revoke/offboard zincirini gerçek müşteri erişim modeliyle tamamla; offline satılıyorsa imaj/bağımlılık teslimini ekle.

**Kapatmak için gerekli somut kanıt:** Provider ve registry kararı; Faturadan entitlement'a test; İmzalı paket kurulumu; İptal/offboarding testi; Doğrulanmış air-gap prosedürü.

**Sorumlu:** Finance/Billing + Release Engineering + Support. **Kontrol:** private-registry consumer install and entitlement contract suite.

### COM-013 — 99.9% SLA için ölçüm ve sözleşme

**Durum:** open. **Geçerli profiller:** assisted-sale, production-ga, investor.

**Eksik gereksinim:** 99.9% aylık availability bir hedef; ölçülmüş SLI, payda, kapsam dışı durumlar, bakım politikası, servis kredisi ve incident kanıtı tamam değil.

**Yapılacak iş:** SRE/Legal/Support/Finance ölçüm ve sözleşme kapsamını onaylasın; kabul edilen gözlem penceresinde veriyi topla ve incident tatbikatı yap.

**Kapatmak için gerekli somut kanıt:** Onaylı SLA ve destek planı; SLI tanımı, payda ve gözlem penceresi; Bakım ve kapsam dışı durumlar; Servis kredisi koşulları; Incident kanıtı.

**Sorumlu:** Operations + Legal + Support + Finance. **Kontrol:** monthly SLI/error-budget report and SLA manifest check.

### SEC-EXT-001 — Bağımsız güvenlik değerlendirmesi ve yeniden test

**Durum:** open. **Geçerli profiller:** assisted-sale, production-ga, investor.

**Eksik gereksinim:** Satılan candidate için bağımsız güvenlik değerlendirmesi, bulgu giderme ve yeniden test raporu yok.

**Yapılacak iş:** Bağımsız değerlendiriciyle scope/tarih belirle; tenant, kimlik, runtime, dağıtım ve sır sınırlarını kapsa; bulguları kapat ve yeniden test ettir.

**Kapatmak için gerekli somut kanıt:** İmzalı bağımsız rapor ve kapsam; Remediation/retest mektubu; Çözülmemiş kritik bulgu olmaması; Yüksek bulgularda registry'nin gerektirdiği gerekçeli isimli ve süreli kabul.

**Sorumlu:** Security Lead + independent assessor. **Kontrol:** assessment evidence expiry/RC match check.

### POV-001 — İsimli müşteri PoV ve kabul kaydı

**Durum:** open. **Geçerli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** İsimli müşteri/değerlendirici aynı candidate üzerinde zorunlu senaryoları ve sınırları inceleyerek kabul vermedi.

**Yapılacak iş:** Değerlendirme sözleşmesi/charter, bağımsız sandbox, zorunlu testler ve müdahale/sapma kaydını tamamla; müşterinin kabul/çekincelerini kaydet.

**Kapatmak için gerekli somut kanıt:** İmzalı charter; Bağımsız koşu raporu; Müdahale ve sapma günlüğü; Müşterinin kabul/çekinceleri; Değiştirilemeyen kanıt indeksi.

**Sorumlu:** Customer Success + Product + evaluator. **Kontrol:** expected-suite manifest and evidence-index completeness; acceptance is manual.

### INV-001 — Yatırımcı metriklerinin kanıt ve onay sözlüğü

**Durum:** open. **Geçerli profiller:** investor.

**Eksik gereksinim:** Yatırımcıya sunulan teknik başarı, müşteri, güvenlik, uyum, traction ve finans ölçülerinin tamamı formül/payda/kaynak/dönem/sürüm/onay sahibiyle kayıtlı değil. Bu kapı yatırımcı profili içindir.

**Yapılacak iş:** Her metriği veri sorgusuna veya imzalı kaynağa bağla; örneklem, dönem, sınır ve belirsizliği yaz; Product/Finance/Legal incelemesi al.

**Kapatmak için gerekli somut kanıt:** Onaylı metrik sözlüğü; Kaynak sorgu veya imzalı belge; Dönem/örneklem/payda; İnceleyen kişi onayı.

**Sorumlu:** Product + Finance + Legal. **Kontrol:** metric dictionary/evidence-index completeness.

### CLM-001 — Müşteri ve satış iddialarının kanıt onayı

**Durum:** open. **Geçerli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** Landing, README, plugin, teklif, procurement ve yatırımcı metinlerinin tamamı onaylı, güncel ve aynı sürüme bağlı iddia kanıtıyla eşlenmiş değil.

**Yapılacak iş:** Her iddiayı Claim Registry'ye bağla; kaynak ve derlenmiş yüzeyleri tara; yalnız süresi geçmemiş Sales Approved ifadeleri yayınla.

**Kapatmak için gerekli somut kanıt:** Registry snapshot; Derlenmiş çıktı tarama JSON'u; İddia→kanıt bağlantıları; Sales Approved incelemesi.

**Sorumlu:** Product/Marketing + Commercial + Legal. **Kontrol:** node docs/scripts/claim-check.mjs --mode=gate.

## 71 alt özelliğin eksik/kabul işleriyle eşlemesi

Tabloda wired yalnız çağrılabilen akış demektir; üretim kabulü değildir. Her özellik en az bir açık kabul işine bağlandı. Ayrıntılı kaynak ve mevcut davranış [FEATURE_INVENTORY.json](FEATURE_INVENTORY.json) içindedir.

| Özellik | Ad | Durum | İlgili açık işler |
|---|---|---|---|
| DET-01 | Tool artifact extraction | wired | T01 |
| DET-02 | Threat rules and confidence merge | wired | T01 |
| DET-03 | Obfuscation and command chains | wired | T01 |
| DET-04 | Credential access and exfiltration | wired | T01 |
| DET-05 | Cross-platform rules and mining | wired | T01 |
| DET-06 | Prompt injection inspection | partial | T04 |
| DET-07 | Structured DLP and PII | partial | T04, T38 |
| DET-08 | Behavioral and novelty analysis | partial | T05 |
| DET-09 | ML classification and similarity | partial | T05 |
| DET-10 | URL reputation | partial | T03, T06, T21, T42 |
| DET-11 | File reputation and AMSI | partial | T02, T03, T06, T21, T42 |
| DET-12 | Package and plugin supply chain | partial | T02, T03, T06 |
| MCP-01 | Local server discovery | wired | T07 |
| MCP-02 | Discovery completeness reporting | wired | T07 |
| MCP-03 | Server and tool policy lists | wired | T07 |
| MCP-04 | Empty-argument tool enforcement | wired | T07 |
| MCP-05 | Tool description attestation and drift | partial | T08 |
| MCP-06 | Identity graph and delegated privileges | partial | T09 |
| MCP-07 | MCP gateway response blocking | partial | T04, T10 |
| INF-01 | Native fingerprint and CVE scanning | wired | T06 |
| INF-02 | Scan report to runtime policy | wired | T06 |
| INF-03 | Continuous fleet discovery | partial | T11 |
| RSP-01 | Pre-execution block and approval | wired | T01 |
| RSP-02 | Quarantine and restore | wired | T13 |
| RSP-03 | File snapshot and rollback | wired | T13 |
| RSP-04 | Process containment | partial | T12 |
| RSP-05 | Signed response audit chain | wired | T13, T25 |
| RSP-06 | Fleet kill switch and credential revoke | partial | T12 |
| RSP-07 | SOAR playbook orchestration | partial | T13 |
| POL-01 | Local filesystem/network/tool controls | wired | T14 |
| POL-02 | Team YAML authoring | wired | T14, T36 |
| POL-03 | Runtime publication and history | wired | T15 |
| POL-04 | Native policy retrieval and cache | wired | T15, T44 |
| POL-05 | Fleet adoption and rollout controls | wired | T15 |
| CLI-01 | Setup and measured diagnostics | wired | T17, T36 |
| CLI-02 | Typed and redacted configuration | wired | T16 |
| CLI-03 | Claude local installer | wired | T17 |
| CLI-04 | Enterprise fleet rollout | partial | T17 |
| CON-01 | Claude Code | wired | T01, T04 |
| CON-02 | Cursor and VS Code | wired | T01, T04 |
| CON-03 | OpenClaw | wired | T01, T04 |
| CON-04 | OpenCode | wired | T01, T02, T04 |
| CON-05 | Codex | partial | T01, T04, T35 |
| CON-06 | SDK and framework adapters | wired | T01, T04 |
| TEN-01 | Tenant isolation and RBAC | wired | T18, T21, T22, T37, T42 |
| TEN-02 | Team creation and member lifecycle | wired | T19 |
| TEN-03 | Invitation issue and acceptance | wired | T20, T36 |
| TEN-04 | SSO and directory group sync | partial | T18, T19 |
| TEN-05 | Device pairing and enrollment | partial | T20, T43, T44, T45, T46 |
| TEN-06 | API keys and revocation | wired | T09, T16, T21, T43 |
| TEN-07 | First customer provisioning and login | wired | T18, T36 |
| OBS-01 | Telemetry ingest and dashboard | wired | T22, T23, T32, T37 |
| OBS-02 | Incident correlation and investigation | wired | T09, T25 |
| OBS-03 | Audit export | wired | T26, T36, T37 |
| OBS-04 | SIEM export and OpenTelemetry | partial | T24 |
| OBS-05 | Tamper and offline integrity | wired | T29, T40 |
| OBS-06 | Retention and deletion | partial | T26, T37 |
| BIL-01 | Invoice-based sales model | partial | T33, T41 |
| BIL-02 | Stripe checkout and event processing | partial | T33 |
| BIL-03 | Subscription self-service portal | partial | T33 |
| DEP-01 | Self-hosted preparation | wired | T28, T32, T45 |
| DEP-02 | Cloud preparation | partial | T28, T32, T45 |
| DEP-03 | Atomic migration runner | wired | T31 |
| DEP-04 | Installation smoke evidence | wired | T31 |
| DEP-05 | Authenticated signed release delivery | partial | T29, T34, T40 |
| DEP-06 | Backup, restore and disaster recovery | partial | T27 |
| DEP-07 | Availability and scale | partial | T22, T30 |
| DEP-08 | Portable installation candidate and doctor | wired | T29 |
| EVAL-01 | Independent attack and benign benchmarks | partial | T35, T39 |
| EVAL-02 | Legal, privacy, residency and support | external | T34, T39, T41 |
| EVAL-03 | Customer proof of value | external | T34, T39, T41 |

## Uygulama sırası ve kapanış kuralı

1. T01/T04/T10/T13 ile gerçek host interception, MCP forced-routing ve native response yan etkisini aynı aday hash'i üzerinde kanıtla.
2. T18/T19/T20/T28/T45 ile canlı IdP, SMTP, cloud project, public TLS proxy ve müşteri tarayıcısı akışını iki tenantta çalıştır.
3. T24/T25/T27/T30/T32/T39 ile SIEM receipt, bağımsız kanıt saklama, offsite restore, HA/soak ve kör benchmark ölçümünü tamamla.
4. T29/T33/T40/T41 ile resmi signer custody, private registry, invoice→paid entitlement ve çalışan destek kanalını aynı ticari candidate'a bağla.
5. Hukuk/Privacy/Finance/Security/Sales ve isimli müşteri PoV kayıtlarını 13 dış kapıya ekle.
6. Aynı imzalı candidate için bağımsız test, müşteri PoV ve onaylı iddia kaydı tamamlandıktan sonra GO kararı ver.

Her kapanış kaydı isimli sorumlu, gerçek sürüm/artefact özeti, değiştirilemeyen test kanıtı, gözlem tarihi, kabul eden kişi ve kalan sınıra sahip olmalı. Tahmini bitiş tarihi vermek için ekip kapasitesi, müşteri kapsamı ve altyapı bilgisi gerekiyor; bilinmeyen bağımlılığa hayali tarih atanmadı.

İlk görüşmeye götürülebilecek mevcut materyal: [deploy/FIRST_CUSTOMER.md](deploy/FIRST_CUSTOMER.md), [docs/production-readiness/first-customer-sales-packet-v7.md](docs/production-readiness/first-customer-sales-packet-v7.md), [docs/production-readiness/2026-09-13-customer-candidate-v7.md](docs/production-readiness/2026-09-13-customer-candidate-v7.md), [FEATURE_INVENTORY.md](FEATURE_INVENTORY.md). Bunlar genel üretim veya satış onayı değildir.

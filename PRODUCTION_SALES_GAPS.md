# AIDR ÃƒÂ¼retim ve satÃ„Â±Ã…Å¸ hazÃ„Â±rlÃ„Â±Ã„Å¸Ã„Â±: ayrÃ„Â±ntÃ„Â±lÃ„Â± eksik kaydÃ„Â±

13 EylÃƒÂ¼l 2026. **Karar: NO-GO.** Kurulabilir bir aday ve doÃ„Å¸rulanmÃ„Â±Ã…Å¸ yerel akÃ„Â±Ã…Å¸lar var; bÃƒÂ¼tÃƒÂ¼n ÃƒÂ¼rÃƒÂ¼nÃƒÂ¼n ÃƒÂ¼retim ve satÃ„Â±Ã…Å¸ kabulÃƒÂ¼ tamamlanmÃ„Â±Ã…Å¸ deÃ„Å¸il.

71 alt ÃƒÂ¶zellik: **41 baÃ„Å¸lÃ„Â±/ÃƒÂ§alÃ„Â±Ã…Å¸an, 28 kÃ„Â±smi, 0 eksik, 2 dÃ„Â±Ã…Å¸ kabule baÃ„Å¸lÃ„Â±**. Ãƒâ€¡alÃ„Â±Ã…Å¸an bir ÃƒÂ¶zellikte de saha veya iÃ…Å¸letim kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k olabilir. Bu raporda **46 teknik/operasyon iÃ…Å¸ paketi ve 13 ticari/dÃ„Â±Ã…Å¸ kanÃ„Â±t kapÃ„Â±sÃ„Â±** ayrÃ„Â±ntÃ„Â±landÃ„Â±rÃ„Â±ldÃ„Â±. Bunlar benzersiz yazÃ„Â±lÃ„Â±m hatasÃ„Â± sayÃ„Â±sÃ„Â± veya tamamlanma yÃƒÂ¼zdesi deÃ„Å¸ildir; ÃƒÂ¶rtÃƒÂ¼Ã…Å¸en gereksinimler kimliklerle iliÃ…Å¸kilidir. Makine kaydÃ„Â±: [PRODUCTION_SALES_GAPS.json](PRODUCTION_SALES_GAPS.json).

45 teknik iÃ…Å¸te yerel uygulama ilerlemiÃ…Å¸ ve saha kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k; 1 teknik iÃ…Å¸ uygulama/entegrasyon olarak aÃƒÂ§Ã„Â±k. BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u tarihsel karÃ…Å¸Ã„Â±laÃ…Å¸tÃ„Â±rma iÃƒÂ§in korunur; satÃ„Â±rÃ„Â±n gÃƒÂ¼ncel durumu ve kalan kabul koÃ…Å¸ulu esas alÃ„Â±nmalÃ„Â±dÃ„Â±r. ÃƒÅ“retim ve destekli satÃ„Â±Ã…Å¸ profillerinin her birinde **12 aÃƒÂ§Ã„Â±k zorunlu dÃ„Â±Ã…Å¸ kapÃ„Â±** var. MÃƒÂ¼Ã…Å¸teri ortamÃ„Â± henÃƒÂ¼z bilinmiyor; cloud ve self-hosted kapsamlarÃ„Â± korunmuÃ…Å¸tur.

## KanÃ„Â±t ve durum nasÃ„Â±l okunmalÃ„Â±?

- **Yerel uygulama, saha kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k:** Kod ve hedefli yerel testler var; gerÃƒÂ§ek mÃƒÂ¼Ã…Å¸teri, native host, provider, SLA veya operatÃƒÂ¶r kabulÃƒÂ¼ ayrÃ„Â±ca gerekir.
- **AÃƒÂ§Ã„Â±k:** BaÃ…Å¸langÃ„Â±ÃƒÂ§ bulgusu veya eksik ÃƒÂ¼rÃƒÂ¼n baÃ„Å¸lantÃ„Â±sÃ„Â± tamamlanmadÃ„Â±.
- **P0/P1:** SatÃ„Â±lan kapsam ÃƒÂ¶nceliÃ„Å¸i. Ticari kapÃ„Â±lar kendi profilinde zorunludur.

V7 birleÃ…Å¸ik test ÃƒÂ¶zeti [docs/production-readiness/2026-09-13-customer-candidate-v7.md](docs/production-readiness/2026-09-13-customer-candidate-v7.md) iÃƒÂ§indedir; ÃƒÂ¶nceki kurulum kaydÃ„Â± [docs/production-readiness/2026-09-13-customer-candidate-v6.md](docs/production-readiness/2026-09-13-customer-candidate-v6.md) altÃ„Â±nda saklanÃ„Â±r. Yerel test geÃƒÂ§iÃ…Å¸i native host, baÃ„Å¸Ã„Â±msÃ„Â±z gÃƒÂ¼venlik deÃ„Å¸erlendirmesi veya SLA kanÃ„Â±tÃ„Â±nÃ„Â±n yerini tutmaz.

## Ãƒâ€“ncelikli kalan iÃ…Å¸ler

1. GerÃƒÂ§ek host/OS ve cloud/self-hosted altyapÃ„Â± kabulÃƒÂ¼; resmi yayÃ„Â±ncÃ„Â± imzasÃ„Â± ve ÃƒÂ¶zel daÃ„Å¸Ã„Â±tÃ„Â±m.
2. MCP doÃ„Å¸rudan upstream bypass, binary/server-initiated kapsamÃ„Â± ve her connector iÃƒÂ§in pre-model/pre-side-effect kabulÃƒÂ¼.
3. GerÃƒÂ§ek Entra/Okta, SMTP, MDM, cloud project, TLS public proxy ve iki tenantlÃ„Â± canlÃ„Â± negatif test.
4. Kimlikli yÃƒÂ¼k, failover/soak, baÃ„Å¸Ã„Â±msÃ„Â±z offsite kurtarma, SIEM alÃ„Â±ndÃ„Â±sÃ„Â± ve alarm paging teslimi.
5. Ticari teklif/sipariÃ…Å¸ten entitlement'a, veri iÃ…Å¸leme, destek kanallarÃ„Â±, baÃ„Å¸Ã„Â±msÃ„Â±z pentest ve isimli mÃƒÂ¼Ã…Å¸teri PoV.

## Teknik ve operasyon eksikleri

### T01 Ã¢â‚¬â€ GerÃƒÂ§ek host ve iÃ…Å¸letim sistemi kapsamÃ„Â± (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** deploy/native/support-matrix.json satilan connector/OS/arch/context/interception matrisini ve bilinen bypass/unobserved listesini tanimliyor; deploy/native/run-support-matrix.mjs kurulu olmayan hostu HOST_UNAVAILABLE olarak NO-GO uretiyor, gercek host ve isimli kabul acik.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** DerlenmiÃ…Å¸ kanca ve SDK testleri var; mÃƒÂ¼Ã…Å¸terinin gerÃƒÂ§ek host/OS/sÃƒÂ¼rÃƒÂ¼m matrisi yok.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Kanca kararÃ„Â± hostun eylemi durdurduÃ„Å¸unu tek baÃ…Å¸Ã„Â±na kanÃ„Â±tlamaz. Devre dÃ„Â±Ã…Å¸Ã„Â± eklenti, sÃƒÂ¼reÃƒÂ§ ÃƒÂ§ÃƒÂ¶kmesi, timeout ve yeni host sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼ kapsam dÃ„Â±Ã…Å¸Ã„Â±nda kalabilir.

**Tamamlanma hedefi:** SatÃ„Â±lacak her baÃ„Å¸layÃ„Â±cÃ„Â± iÃƒÂ§in OS/sÃƒÂ¼rÃƒÂ¼m destek tablosu, gerÃƒÂ§ek host testi, kurulum/kaldÃ„Â±rma ve destek sahibi belirle; gÃƒÂ¶rÃƒÂ¼nmeyen eylemleri aÃƒÂ§Ã„Â±kÃƒÂ§a listele.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Her zorunlu saldÃ„Â±rÃ„Â±da yan etkinin oluÃ…Å¸madÃ„Â±Ã„Å¸Ã„Â±nÃ„Â± baÃ„Å¸Ã„Â±msÃ„Â±z kaydet; zararsÃ„Â±z iÃ…Å¸lemler geÃƒÂ§sin; kanca kapalÃ„Â±/bozuk/aÃ„Å¸sÃ„Â±z durumlarÃ„Â± ve yeniden baÃ…Å¸latma ayrÃ„Â± sÃ„Â±nansÃ„Â±n.

**Sorumlu:** QA + Endpoint Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** MÃƒÂ¼Ã…Å¸teri test cihazlarÃ„Â±, runtime eriÃ…Å¸imi ve sÃƒÂ¼rÃƒÂ¼m seÃƒÂ§imi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** CON-01, CON-02, CON-03, CON-04, CON-05, CON-06, DET-01, DET-02, DET-03, DET-04, DET-05, RSP-01. **Kaynak:** [scripts/run-e2e-release.mjs](scripts/run-e2e-release.mjs), [packages/codex/README.md](packages/codex/README.md).

### T02 Ã¢â‚¬â€ BaÃ„Å¸layÃ„Â±cÃ„Â±lar arasÃ„Â±nda araÃƒÂ§ adÃ„Â± ve girdi normalizasyonu (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Ortak araÃƒÂ§/girdi normalizasyonu evaluator ÃƒÂ¶ncesinde; Codex ve OpenClaw boÃ…Å¸-artifact erken izin yolu kaldÃ„Â±rÃ„Â±ldÃ„Â±, named MCP ÃƒÂ§aÃ„Å¸rÃ„Â±larÃ„Â± politikaya ulaÃ…Å¸Ã„Â±yor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** OpenCode ham bash/write/edit adlarÃ„Â±nÃ„Â± iletiyor; bazÃ„Â± ÃƒÂ§ekirdek denetimleri yalnÃ„Â±zca Bash/Write/Edit dallarÃ„Â±nda ÃƒÂ§alÃ„Â±Ã…Å¸Ã„Â±yor. Mevcut sÃƒÂ¶zleÃ…Å¸me testi bu paket boÃ…Å¸luÃ„Å¸unu allow olarak kaydediyor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Paket kurulumlarÃ„Â± ve bazÃ„Â± dosya/AMSI girdileri ilgili denetim koluna ulaÃ…Å¸mayabilir; birim testlerin yeÃ…Å¸il olmasÃ„Â± bu kapsamÃ„Â± kapatmÃ„Â±yor.

**Tamamlanma hedefi:** Ortak semantik araÃƒÂ§/girdi sÃƒÂ¶zleÃ…Å¸mesi tanÃ„Â±mla; tÃƒÂ¼m baÃ„Å¸layÃ„Â±cÃ„Â±larÃ„Â± eÃ…Å¸le; command, file_path/filePath, content/new_string alanlarÃ„Â±nÃ„Â± standartlaÃ…Å¸tÃ„Â±r. Bilinen boÃ…Å¸luÃ„Å¸u beklenen izin sonucu olarak sabitleyen testi deÃ„Å¸iÃ…Å¸tir.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** AynÃ„Â± yasak paket, manifest ve dosya girdisi tÃƒÂ¼m baÃ„Å¸layÃ„Â±cÃ„Â±larda aynÃ„Â± denetime ulaÃ…Å¸sÃ„Â±n; denetleyici ÃƒÂ§aÃ„Å¸rÃ„Â±sÃ„Â± ve engellenen yan etki kanÃ„Â±tlansÃ„Â±n; boÃ…Å¸/alternatif alan adlarÃ„Â± negatif test edilsin.

**Sorumlu:** Core + Connector Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** AIDR-060; native host matrisi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DET-12, DET-11, CON-04. **Kaynak:** [packages/core/src/evaluator.ts](packages/core/src/evaluator.ts), [packages/opencode/src/tool-handler.ts](packages/opencode/src/tool-handler.ts), [packages/opencode/src/__tests__/aidr-contract.test.ts](packages/opencode/src/__tests__/aidr-contract.test.ts).

### T03 Ã¢â‚¬â€ Paket denetiminde hatanÃ„Â±n sessiz kaybolmasÃ„Â± (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Paket, registry ve file-reputation hata/bozuk-200 yollarÃ„Â± clean yerine unknown/unavailable ÃƒÂ¼retiyor; gerÃƒÂ§ek 404 ve doÃ„Å¸rulanmÃ„Â±Ã…Å¸ clean ayrÃ„Â±mÃ„Â± test edildi.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** checkPackages iÃƒÂ§inde genel catch boÃ…Å¸ sonuÃƒÂ§ dÃƒÂ¶ndÃƒÂ¼rÃƒÂ¼yor. DiÃ„Å¸er tespit kollarÃ„Â±nda aÃƒÂ§Ã„Â±k unavailable davranÃ„Â±Ã…Å¸larÃ„Â± bulunuyor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Paket denetleyicisi beklenmedik hata verdiÃ„Å¸inde ÃƒÂ¼st akÃ„Â±Ã…Å¸ baÃ…Å¸arÃ„Â±lÃ„Â± bir boÃ…Å¸ kontrol gibi devam edebilir; diÃ„Å¸er kurallar her vakayÃ„Â± yakalamaz.

**Tamamlanma hedefi:** Hata tÃƒÂ¼rlerini unavailable olarak taÃ…Å¸Ã„Â±; zorunlu denetim politikasÃ„Â±nda deny/insan onayÃ„Â± ÃƒÂ¼ret; opsiyonel kolda gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r eksik tespit kaydÃ„Â± tut. HatalÃ„Â± politika/cache/intel durumlarÃ„Â±nÃ„Â± ayÃ„Â±r.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Registry timeout, bozuk cevap, cache/intel ayrÃ„Â±Ã…Å¸tÃ„Â±rma hatasÃ„Â± ve denetleyici exception enjekte et; zorunlu kontrol sessiz allow ÃƒÂ¼retmesin; benign ve iptal davranÃ„Â±Ã…Å¸larÃ„Â± korunsun.

**Sorumlu:** Detection Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** AIDR-061; desteklenen araÃƒÂ§ sÃƒÂ¶zleÃ…Å¸mesi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DET-10, DET-11, DET-12. **Kaynak:** [packages/core/src/evaluator.ts](packages/core/src/evaluator.ts), [packages/core/src/package-checker.ts](packages/core/src/package-checker.ts).

### T04 Ã¢â‚¬â€ Model tÃƒÂ¼ketiminden ÃƒÂ¶nce ÃƒÂ§Ã„Â±ktÃ„Â± denetimi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Ãƒâ€¡Ã„Â±ktÃ„Â± tarayÃ„Â±cÃ„Â± 2 MiB UTF-8, 3000 ms best-effort ve 128 bulgu sÃ„Â±nÃ„Â±rÃ„Â±nda inspection_incomplete/critical fail-closed ÃƒÂ¼retiyor; JSON/Unicode ve sÃ„Â±nÃ„Â±r payloadlarÃ„Â± test edildi. Her hostta aynÃ„Â±-tur blok kanÃ„Â±tÃ„Â± yok.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Claude ÃƒÂ§Ã„Â±ktÃ„Â±sÃ„Â±nda sÃ„Â±nÃ„Â±rlÃ„Â± tarama var; PostToolUse ÃƒÂ§alÃ„Â±Ã…Å¸mÃ„Â±Ã…Å¸ eylemi geri alamaz. DiÃ„Å¸er tÃƒÂ¼ketim yollarÃ„Â±nÃ„Â±n tamamÃ„Â± baÃ„Å¸lÃ„Â± deÃ„Å¸il.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Prompt injection veya sÃ„Â±r iÃƒÂ§eren ÃƒÂ§Ã„Â±ktÃ„Â± modele ulaÃ…Å¸abilir. Ã„Â°lk 262144 karakterden sonraki iÃƒÂ§erik ve desteklenmeyen biÃƒÂ§imler iÃƒÂ§in kapsam eksiktir.

**Tamamlanma hedefi:** Hostun izin verdiÃ„Å¸i yerlerde ÃƒÂ§Ã„Â±ktÃ„Â± tesliminden ÃƒÂ¶nce kontrol/karantina ekle; desteklenmeyen yollarda aÃƒÂ§Ã„Â±k coverage durumu gÃƒÂ¶ster; boyut sÃ„Â±nÃ„Â±rÃ„Â± aÃ…Å¸Ã„Â±mÃ„Â±nÃ„Â± sessiz temiz sayma.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** ParÃƒÂ§alara bÃƒÂ¶lÃƒÂ¼nmÃƒÂ¼Ã…Å¸ saldÃ„Â±rÃ„Â±, sÃ„Â±nÃ„Â±rÃ„Â±n sonundaki payload, Unicode, JSON/text ve ÃƒÂ§ok bÃƒÂ¼yÃƒÂ¼k cevaplar sÃ„Â±nansÃ„Â±n; engellenen baytlar modele ulaÃ…Å¸masÃ„Â±n; zararsÃ„Â±z ÃƒÂ§ok parÃƒÂ§alÃ„Â± cevap bozulmasÃ„Â±n.

**Sorumlu:** Connector + Detection Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Host API kabiliyeti; MCP gateway.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DET-06, DET-07, MCP-07, CON-01, CON-02, CON-03, CON-04, CON-05, CON-06. **Kaynak:** [packages/claude-code/src/output-inspection.ts](packages/claude-code/src/output-inspection.ts), [packages/claude-code/src/post-tool-use.ts](packages/claude-code/src/post-tool-use.ts), [packages/core/src/output-scanner.ts](packages/core/src/output-scanner.ts).

### T05 Ã¢â‚¬â€ DavranÃ„Â±Ã…Å¸, novelty ve ML kararlarÃ„Â±nÃ„Â±n ÃƒÂ¼rÃƒÂ¼n akÃ„Â±Ã…Å¸Ã„Â±na baÃ„Å¸lanmasÃ„Â± (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** BehavioralAnalyzer adayÃ„Â± kendi baseline'Ã„Â±na katmÃ„Â±yor ve tenant/session ayrÃ„Â±mÃ„Â± korunuyor; ÃƒÂ¼retim etkinliÃ„Å¸i ve kalÃ„Â±cÃ„Â± ÃƒÂ¶Ã„Å¸renme kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** ModÃƒÂ¼ller ve testler var; sÃƒÂ¼rekli ÃƒÂ§alÃ„Â±Ã…Å¸an tÃƒÂ¼ketici, ÃƒÂ¶Ã„Å¸renme yaÃ…Å¸am dÃƒÂ¶ngÃƒÂ¼sÃƒÂ¼ ve ÃƒÂ¼retim baÃ…Å¸arÃ„Â± ÃƒÂ¶lÃƒÂ§ÃƒÂ¼mÃƒÂ¼ kanÃ„Â±tÃ„Â± tamam deÃ„Å¸il.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Ã„Â°hracat edilen sÃ„Â±nÃ„Â±f veya demo skor, ÃƒÂ§alÃ„Â±Ã…Å¸an anomali korumasÃ„Â± sayÃ„Â±lmaz. YanlÃ„Â±Ã…Å¸ ÃƒÂ¶Ã„Å¸renme ve tenantlar arasÃ„Â± veri karÃ„Â±Ã…Å¸masÃ„Â± riski deÃ„Å¸erlendirilmemiÃ…Å¸.

**Tamamlanma hedefi:** GerÃƒÂ§ek olay tÃƒÂ¼keticisi, tenant bazlÃ„Â± durum, cold-start, unutma/retention, model sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼, karar aÃƒÂ§Ã„Â±klamasÃ„Â± ve insan geri bildirimi akÃ„Â±Ã…Å¸larÃ„Â±nÃ„Â± baÃ„Å¸la.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** SoÃ„Å¸uk baÃ…Å¸langÃ„Â±ÃƒÂ§ ve model yenilemede kararlÃ„Â± sonuÃƒÂ§; tenant ayrÃ„Â±mÃ„Â±; veri zehirleme denemeleri; holdout saldÃ„Â±rÃ„Â± ve zararsÃ„Â±z iÃ…Å¸ yÃƒÂ¼kÃƒÂ¼nde yanlÃ„Â±Ã…Å¸ alarm ÃƒÂ¶lÃƒÂ§ÃƒÂ¼mÃƒÂ¼.

**Sorumlu:** Detection + Data Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Etiketli mÃƒÂ¼Ã…Å¸teri verisi ve baÃ„Å¸Ã„Â±msÃ„Â±z ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m seti.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DET-08, DET-09. **Kaynak:** [packages/core/src/behavioral-analyzer.ts](packages/core/src/behavioral-analyzer.ts), [packages/core/src/novelty-detection.ts](packages/core/src/novelty-detection.ts), [packages/core/src/ml-model.ts](packages/core/src/ml-model.ts).

### T06 Ã¢â‚¬â€ Reputation ve AI altyapÃ„Â± verisinin gÃƒÂ¼ncelliÃ„Å¸i (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Ã„Â°mzalÃ„Â± offline feed iÃƒÂ§in publisher issued_at ve yerel fetched_at birlikte yaÃ…Å¸ sÃ„Â±nÃ„Â±rÃ„Â±na baÃ„Å¸landÃ„Â±; canlÃ„Â± provider, daÃ„Å¸Ã„Â±tÃ„Â±m ve gecikme kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Yerel kurallar, derlenmiÃ…Å¸ veri ve kendine kurulabilen sorgu API'leri var.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Feed kaynaÃ„Å¸Ã„Â±/gÃƒÂ¼ncelliÃ„Å¸i, saÃ„Å¸layÃ„Â±cÃ„Â± kesintisi, imzalÃ„Â± gÃƒÂ¼ncelleme, kapsanmayan format ve mÃƒÂ¼Ã…Å¸teri gecikme hedefleri doÃ„Å¸rulanmadÃ„Â±; canlÃ„Â± reputation testi atlanÃ„Â±yor.

**Tamamlanma hedefi:** Feed sÃƒÂ¶zleÃ…Å¸mesi ve gÃƒÂ¼ncelleme iÃ…Å¸i, yaÃ…Å¸ sÃ„Â±nÃ„Â±rÃ„Â±, geri alma, eksik veri durumu ve mÃƒÂ¼Ã…Å¸teri veri/URL kategorisi kalibrasyonu kur.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Eski/bozuk/boÃ…Å¸ feed temiz verdict ÃƒÂ¼retmesin; gÃƒÂ¼ncelleme/geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ kanÃ„Â±tlansÃ„Â±n; gerÃƒÂ§ek endpoint ve AMSI desteklenen Windows hostunda ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lsÃƒÂ¼n.

**Sorumlu:** Detection + Operations. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** SaÃ„Å¸layÃ„Â±cÃ„Â±/feed eriÃ…Å¸imi, Windows host ve mÃƒÂ¼Ã…Å¸teri corpus'u.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DET-10, DET-11, DET-12, INF-01, INF-02. **Kaynak:** [supabase/functions/url-check/index.ts](supabase/functions/url-check/index.ts), [supabase/functions/file-check/index.ts](supabase/functions/file-check/index.ts), [packages/core/src/generated/aig-data-manifest.json](packages/core/src/generated/aig-data-manifest.json), [packages/core/src/aig-policy.ts](packages/core/src/aig-policy.ts).

### T07 Ã¢â‚¬â€ MCP keÃ…Å¸fi ve kimlik normalizasyonunun kapsamÃ„Â± (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Yerel MCP keÃ…Å¸fi konum/alias bazlÃ„Â± kararlÃ„Â± inventory_id ve merkezi stale/partial kapsam raporu ÃƒÂ¼retiyor; ek host biÃƒÂ§imleri/native kabul aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Yerel JSON konfigÃƒÂ¼rasyonlarÃ„Â± ve sunucu/araÃƒÂ§ listeleri denetleniyor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** JSONC, yeni runtime konumlarÃ„Â±, dinamik eklenen sunucular ve belirsiz server/tool kimlikleri iÃƒÂ§in tam kapsama yok; yerel tarama kurum ÃƒÂ§apÃ„Â± keÃ…Å¸if deÃ„Å¸ildir.

**Tamamlanma hedefi:** Desteklenen konfigÃƒÂ¼rasyon adaptÃƒÂ¶rlerini ekle; okunamayan/kÃ„Â±smi keÃ…Å¸fi raporla; yeniden adlandÃ„Â±rma ve alias davranÃ„Â±Ã…Å¸Ã„Â±nÃ„Â± politikayla tutarlÃ„Â± yap.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Bozuk/izin verilmeyen dosya, JSONC, boÃ…Å¸ argÃƒÂ¼man, alias ve aynÃ„Â± isimli farklÃ„Â± sunucu testleri; eksik tarama gÃƒÂ¼venli envanter gibi gÃƒÂ¶rÃƒÂ¼nmesin.

**Sorumlu:** Endpoint + MCP Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Host sÃƒÂ¼rÃƒÂ¼m ve konfigÃƒÂ¼rasyon matrisi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** MCP-01, MCP-02, MCP-03, MCP-04. **Kaynak:** [packages/core/src/mcp-discovery.ts](packages/core/src/mcp-discovery.ts), [packages/core/src/mcp-inventory.ts](packages/core/src/mcp-inventory.ts), [packages/core/src/policy.ts](packages/core/src/policy.ts).

### T08 Ã¢â‚¬â€ Ã„Â°mzalÃ„Â± MCP araÃƒÂ§ tanÃ„Â±mÃ„Â± ve deÃ„Å¸iÃ…Å¸iklik onayÃ„Â± (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Ã„Â°mzalÃ„Â± MCP manifest key_id'yi imzaya baÃ„Å¸lÃ„Â±yor, geÃƒÂ§ersiz saat ve legacy imza fail-closed; eski manifestler gÃƒÂ¼venilir yayÃ„Â±ncÃ„Â± tarafÃ„Â±ndan yeniden imzalanmalÃ„Â±.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** SÃƒÂ¼reÃƒÂ§ iÃƒÂ§i ilk Ã…Å¸ema referansÃ„Â± ve drift reddi var; tekrar ederek referansÃ„Â± deÃ„Å¸iÃ…Å¸tirme hatasÃ„Â± dÃƒÂ¼zeltildi.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Ã„Â°mzalÃ„Â± sunucu/araÃƒÂ§ description ve schema manifesti, kalÃ„Â±cÃ„Â± onay, sÃƒÂ¼rÃƒÂ¼m/expiry ve replay korumasÃ„Â± yok. SÃƒÂ¼reÃƒÂ§ yeniden baÃ…Å¸latÃ„Â±lmasÃ„Â± gÃƒÂ¼venilir onay deÃ„Å¸ildir.

**Tamamlanma hedefi:** AraÃƒÂ§ tanÃ„Â±mÃ„Â±nÃ„Â± sunucu kimliÃ„Å¸i ve sÃƒÂ¼rÃƒÂ¼me imzayla baÃ„Å¸la; deÃ„Å¸iÃ…Å¸en araÃƒÂ§larÃ„Â± karantinaya al; yalnÃ„Â±zca operatÃƒÂ¶rÃƒÂ¼n onaylayabildiÃ„Å¸i inceleme ve daÃ„Å¸Ã„Â±tÃ„Â±m akÃ„Â±Ã…Å¸Ã„Â± kur.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Description/schema deÃ„Å¸iÃ…Å¸imi, eski manifest, yanlÃ„Â±Ã…Å¸ signer, yeniden baÃ…Å¸latma, eÃ…Å¸ zamanlÃ„Â± deÃ„Å¸iÃ…Å¸iklik ve onaysÃ„Â±z retry reddedilsin; ajan kendi aracÃ„Â±nÃ„Â± onaylayamasÃ„Â±n.

**Sorumlu:** MCP + Security Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** AIDR-046; signer/key custody ve yÃƒÂ¶netim UI'sÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** MCP-05. **Kaynak:** [packages/core/src/mcp-transport.ts](packages/core/src/mcp-transport.ts), [packages/core/src/mcp-discovery.ts](packages/core/src/mcp-discovery.ts).

### T09 Ã¢â‚¬â€ KullanÃ„Â±cÃ„Â±Ã¢â‚¬â€œajanÃ¢â‚¬â€œaraÃƒÂ§Ã¢â‚¬â€œkaynak iliÃ…Å¸kisi ve delegasyon (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Ed25519 delegated lineage ve grant/introspection/revoke; geÃƒÂ§ersiz sayÃ„Â± ve Ed25519 olmayan EdDSA anahtarÃ„Â± reddediliyor. GerÃƒÂ§ek IdP/tool provider kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Ajan/ekip anahtarÃ„Â± baÃ„Å¸Ã„Â± ve yerel envanter var.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Kimin hangi ajan ÃƒÂ¼zerinden hangi kaynaÃ„Å¸a hangi yetkiyle eriÃ…Å¸tiÃ„Å¸ini gÃƒÂ¶steren tam iliÃ…Å¸ki grafiÃ„Å¸i; araÃƒÂ§ bazlÃ„Â± kÃ„Â±sa ÃƒÂ¶mÃƒÂ¼rlÃƒÂ¼ delegasyon yok.

**Tamamlanma hedefi:** Kaynak ve kimlik iliÃ…Å¸kileri, audience/scope/expiry taÃ…Å¸Ã„Â±yan kÃ„Â±sÃ„Â±tlÃ„Â± token, delegation depth ve credential broker uygula.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** BaÃ…Å¸ka tool/resource/audience iÃƒÂ§in token kullanÃ„Â±mÃ„Â±, sÃƒÂ¼resi bitmiÃ…Å¸ delegasyon, kullanÃ„Â±cÃ„Â± ayrÃ„Â±lmasÃ„Â± ve zincir yetki bÃƒÂ¼yÃƒÂ¼tme reddedilsin; olaydan kaynaÃ„Å¸a iz sÃƒÂ¼rÃƒÂ¼lsÃƒÂ¼n.

**Sorumlu:** Identity + Backend Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** IdP ve araÃƒÂ§ saÃ„Å¸layÃ„Â±cÃ„Â±sÃ„Â± API'leri.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** MCP-06, TEN-06, OBS-02. **Kaynak:** [packages/core/src/mcp-inventory.ts](packages/core/src/mcp-inventory.ts), [supabase/functions/enroll/index.ts](supabase/functions/enroll/index.ts), [supabase/functions/api-keys/index.ts](supabase/functions/api-keys/index.ts).

### T10 Ã¢â‚¬â€ MCP gateway ve taÃ…Å¸Ã„Â±ma gÃƒÂ¼venliÃ„Å¸i (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Loopback/stdio JSON-RPC geÃƒÂ§idi DNS pinleme, gerÃƒÂ§ek stream sÃ„Â±nÃ„Â±rÃ„Â±, tekil framing ve bozuk yanÃ„Â±t reddi uyguluyor; binary, server-initiated ve zorunlu routing kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Framing ve policy interception yardÃ„Â±mcÃ„Â±larÃ„Â± var; ÃƒÂ§alÃ„Â±Ã…Å¸an tam gateway tÃƒÂ¼keticisi yok. URL DNS kontrolÃƒÂ¼nden sonra fetch yeniden ÃƒÂ§ÃƒÂ¶zÃƒÂ¼mleme yapÃ„Â±yor; cevap sÃ„Â±nÃ„Â±rÃ„Â± Content-Length baÃ…Å¸lÃ„Â±Ã„Å¸Ã„Â±na bakÃ„Â±yor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** DNS rebinding, baÃ…Å¸lÃ„Â±ksÃ„Â±z/chunked bÃƒÂ¼yÃƒÂ¼k cevap, mapped IPv6 ve baÃ„Å¸lantÃ„Â± ÃƒÂ¶mrÃƒÂ¼ iÃƒÂ§in gerÃƒÂ§ek aÃ„Å¸ kabulÃƒÂ¼ eksik. Mevcut test adÃ„Â± DNS rebinding korumasÃ„Â±nÃ„Â± olduÃ„Å¸undan gÃƒÂ¼ÃƒÂ§lÃƒÂ¼ anlatÃ„Â±yor.

**Tamamlanma hedefi:** DoÃ„Å¸rulanan IP'yi baÃ„Å¸lantÃ„Â±ya sabitle; IP sÃ„Â±nÃ„Â±flamasÃ„Â±nÃ„Â± tamamla; gerÃƒÂ§ek okunan/decompress edilmiÃ…Å¸ baytlarÃ„Â± sÃ„Â±nÃ„Â±rla; authentication/session/stream ve bypass akÃ„Â±Ã…Å¸larÃ„Â±nÃ„Â± gateway'e baÃ„Å¸la.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Kontrol ile baÃ„Å¸lantÃ„Â± arasÃ„Â±nda DNS deÃ„Å¸iÃ…Å¸sin; private/mapped IPv6, redirect, baÃ…Å¸lÃ„Â±ksÃ„Â±z sonsuz stream, sÃ„Â±nÃ„Â±r aÃ…Å¸Ã„Â±mÃ„Â±, disconnect ve bozuk JSON/SSE ile gerÃƒÂ§ek aÃ„Å¸ testi ÃƒÂ§alÃ„Â±Ã…Å¸sÃ„Â±n.

**Sorumlu:** MCP + Network Security. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** AIDR-062; stdio/HTTP/SSE kapsam kararÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** MCP-07. **Kaynak:** [packages/core/src/mcp-transport.ts](packages/core/src/mcp-transport.ts), [packages/core/src/__tests__/mcp-transport.test.ts](packages/core/src/__tests__/mcp-transport.test.ts).

### T11 Ã¢â‚¬â€ SÃƒÂ¼rekli kurum/filo keÃ…Å¸fi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Kimlikli merkezi discovery upload var; interval modu geÃƒÂ§ici upload hatasÃ„Â±nÃ„Â± gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r tutarak sonraki ÃƒÂ§evrime devam ediyor. Cloud/MDM scheduler ve saha kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Ã„Â°steÃ„Å¸e baÃ„Å¸lÃ„Â± yerel/altyapÃ„Â± taramasÃ„Â± mevcut.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** ZamanlanmÃ„Â±Ã…Å¸ kolektÃƒÂ¶r, tenant envanteri, sahiplik, tekrar birleÃ…Å¸tirme, son gÃƒÂ¶rÃƒÂ¼lme ve stale alarmÃ„Â± yok.

**Tamamlanma hedefi:** Filo/cloud kolektÃƒÂ¶rleri, kapsam izinleri, zamanlama, retry, dedup, kimlik ve keÃ…Å¸if tazeliÃ„Å¸i ekranlarÃ„Â±nÃ„Â± kur.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Kapanan veya yeni aÃƒÂ§Ã„Â±lan ajan gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r olsun; baÃ„Å¸lantÃ„Â±sÃ„Â±z kolektÃƒÂ¶r eski veriyi gÃƒÂ¼ncel gÃƒÂ¶stermesin; tenant ayrÃ„Â±mÃ„Â± ve keÃ…Å¸if yÃƒÂ¼k sÃ„Â±nÃ„Â±rlarÃ„Â± sÃ„Â±nansÃ„Â±n.

**Sorumlu:** Discovery + Backend Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** MÃƒÂ¼Ã…Å¸teri cloud/MDM API eriÃ…Å¸imi ve aÃ„Å¸ tarama kapsamÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** INF-03. **Kaynak:** [packages/cli/src/commands/scan.ts](packages/cli/src/commands/scan.ts), [packages/core/src/aig-infra-scan.ts](packages/core/src/aig-infra-scan.ts).

### T12 Ã¢â‚¬â€ Filo mÃƒÂ¼dahalesi ve credential iptali (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Ã„Â°mzalÃ„Â± revocation feed tenant+global kapsamÃ„Â± 5000 sÃ„Â±nÃ„Â±rÃ„Â±ndan ÃƒÂ¶nce filtreliyor ve eksik/truncated seti imzalamÃ„Â±yor; native/provider iptali aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Yerel sÃƒÂ¼reÃƒÂ§ mÃƒÂ¼dahalesi ve iptal listesi temelleri var.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Kurumsal endpoint izolasyonu, tÃƒÂ¼m cloud saÃ„Å¸layÃ„Â±cÃ„Â±larda credential iptali ve ajandan sonuÃƒÂ§ alan komut altyapÃ„Â±sÃ„Â± yok.

**Tamamlanma hedefi:** Yetkili komut kuyruÃ„Å¸u, TTL/idempotency, operatÃƒÂ¶r yetkisi, ajan sonuÃƒÂ§ bildirimi, geri alma ve saÃ„Å¸layÃ„Â±cÃ„Â± adaptÃƒÂ¶rleri ekle.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Offline ajana sÃƒÂ¼resi geÃƒÂ§miÃ…Å¸ komut uygulanmasÃ„Â±n; tekrar gelen komut tek etki ÃƒÂ¼retsin; baÃ…Å¸arÃ„Â±sÃ„Â±z izolasyon baÃ…Å¸arÃ„Â± gÃƒÂ¶rÃƒÂ¼nmesin; ilgili izinler ve geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ kanÃ„Â±tlansÃ„Â±n.

**Sorumlu:** Response + Endpoint Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** OS yetkileri, saÃ„Å¸layÃ„Â±cÃ„Â± API'leri, mÃƒÂ¼Ã…Å¸teri mÃƒÂ¼dahale yetkisi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** RSP-04, RSP-06. **Kaynak:** [packages/core/src/contain.ts](packages/core/src/contain.ts), [supabase/functions/revocations/index.ts](supabase/functions/revocations/index.ts).

### T13 Ã¢â‚¬â€ Response eylemlerinin gÃƒÂ¼venli uÃƒÂ§tan uca iÃ…Å¸letimi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Yeni response-worker-contract.ts capability/onkosul/TTL/idempotency/rollback makbuzu sozlesmesini uyguluyor; desteklenmeyen action adapter tarafindan reddediliyor ve geri alinamayan adim partial olarak raporlaniyor. Native OS/provider adapter ve kurulu servis musteri tarafinda acik. Eski: Restart-safe worker resume sÃ„Â±rasÃ„Â±nda adapter destek listesini yeniden doÃ„Å¸ruluyor ve kaldÃ„Â±rÃ„Â±lmÃ„Â±Ã…Å¸ action'Ã„Â± ÃƒÂ§alÃ„Â±Ã…Å¸tÃ„Â±rmadan unsupported_action bildiriyor. Native OS/provider adapter ve kurulu servis aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Quarantine/restore, dosya snapshot/rollback ve imzalÃ„Â± olay zinciri yerel testli.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** GerÃƒÂ§ek mÃƒÂ¼Ã…Å¸teri dosya izinleri, aynÃ„Â± anda deÃ„Å¸iÃ…Å¸en dosya, dÃ„Â±Ã…Å¸ playbook etkileri, signer saklama ve baÃ„Å¸Ã„Â±msÃ„Â±z arÃ…Å¸iv kanÃ„Â±tÃ„Â± eksik.

**Tamamlanma hedefi:** Desteklenen eylem ve dosya kapsamÃ„Â±nÃ„Â± sabitle; ÃƒÂ¶nkoÃ…Å¸ul/sonuÃƒÂ§ doÃ„Å¸rulama, operatÃƒÂ¶r sÃ„Â±nÃ„Â±rlarÃ„Â±, dÃ„Â±Ã…Å¸ SOAR sonuÃƒÂ§larÃ„Â± ve baÃ„Å¸Ã„Â±msÃ„Â±z kanÃ„Â±t saklamayÃ„Â± tamamla.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Dosya sonradan deÃ„Å¸iÃ…Å¸miÃ…Å¸ken yanlÃ„Â±Ã…Å¸ rollback yapÃ„Â±lmasÃ„Â±n; symlink/izin/disk hatasÃ„Â± aÃƒÂ§Ã„Â±k baÃ…Å¸arÃ„Â±sÃ„Â±z olsun; eylem ve geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ aynÃ„Â± incidentten izlenebilsin.

**Sorumlu:** Response Engineering + Security Operations. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** MÃƒÂ¼Ã…Å¸teri dosya sistemi/EDR/SOAR izinleri.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** RSP-02, RSP-03, RSP-05, RSP-07. **Kaynak:** [packages/core/src/quarantine.ts](packages/core/src/quarantine.ts), [packages/core/src/rollback.ts](packages/core/src/rollback.ts), [packages/core/src/response-command-worker-v6.ts](packages/core/src/response-command-worker-v6.ts), [packages/core/src/response-audit.ts](packages/core/src/response-audit.ts), [supabase/functions/autosecops-runtime/index.ts](supabase/functions/autosecops-runtime/index.ts).

### T14 Ã¢â‚¬â€ YAML politika yazÃ„Â±mÃ„Â± ile gerÃƒÂ§ek runtime iliÃ…Å¸kisi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Core/server dry-run unknown MCP fallback kararÃ„Â± runtime evaluator ile eÃ…Å¸lendi; YAML/JSON compiler, parity ve dashboard publish akÃ„Â±Ã…Å¸Ã„Â± baÃ„Å¸lÃ„Â±.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** YAML belge kaydÃ„Â± var; ayrÃ„Â± runtime kontrolleri yayÃ„Â±nlanÃ„Â±yor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Kaydedilen YAML kurallarÃ„Â± runtime tarafÃ„Â±ndan tÃƒÂ¼ketilmiyor. KullanÃ„Â±cÃ„Â± belge kaydÃ„Â±nÃ„Â± etkin gÃƒÂ¼venlik politikasÃ„Â± sanabilir.

**Tamamlanma hedefi:** Desteklenen YAML Ã…Å¸emasÃ„Â±nÃ„Â± runtime modeline derle veya belge akÃ„Â±Ã…Å¸Ã„Â±nÃ„Â± aÃƒÂ§Ã„Â±kÃƒÂ§a ayÃ„Â±r; desteklenmeyen alanlarÃ„Â± reddet; ÃƒÂ¶ncelik ve etki simÃƒÂ¼lasyonu sun.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Kaydedilen/yayÃ„Â±nlanan politika gerÃƒÂ§ek ajan kararÃ„Â±nda deÃ„Å¸iÃ…Å¸iklik ÃƒÂ¼retsin; bilinmeyen alan sessiz atÃ„Â±lmasÃ„Â±n; allowlist ile aÃƒÂ§Ã„Â±k deny ÃƒÂ¶nceliÃ„Å¸i doÃ„Å¸rulansÃ„Â±n.

**Sorumlu:** Policy + Dashboard Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Politika sÃƒÂ¶zleÃ…Å¸mesi ve migration planÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** POL-01, POL-02. **Kaynak:** [packages/dashboard/src/enterprise/policy-editor.tsx](packages/dashboard/src/enterprise/policy-editor.tsx), [packages/dashboard/src/ui/pages/PolicyPage.tsx](packages/dashboard/src/ui/pages/PolicyPage.tsx), [packages/core/src/policy.ts](packages/core/src/policy.ts).

### T15 Ã¢â‚¬â€ Politika daÃ„Å¸Ã„Â±tÃ„Â±mÃ„Â± saha kabulÃƒÂ¼ ve ÃƒÂ¶lÃƒÂ§ek sÃ„Â±nÃ„Â±rlarÃ„Â± (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Hedefli stage iÃ…Å¸lemi atomik revision precondition ile eski eÃ…Å¸zamanlÃ„Â± gÃƒÂ¼ncellemeyi 409 reddediyor; gerÃƒÂ§ek filo/ÃƒÂ¶lÃƒÂ§ek kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** SÃƒÂ¼rÃƒÂ¼m/geÃƒÂ§miÃ…Å¸, hedefli daÃ„Å¸Ã„Â±tÃ„Â±m, rollback, sayfalama ve sabit offline grace ÃƒÂ§alÃ„Â±Ã…Å¸Ã„Â±yor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Receipt yalnÃ„Â±zca ajanÃ„Â±n yÃƒÂ¼kleme bildirimi; host enforcement attestation deÃ„Å¸il. Eski baÃ„Å¸lÃ„Â± olmayan anahtarlar, bÃƒÂ¼yÃƒÂ¼k filo batch planÃ„Â± ve gerÃƒÂ§ek offline saha kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**Tamamlanma hedefi:** Eski ajanlarÃ„Â± yeniden kaydet; daÃ„Å¸Ã„Â±tÃ„Â±m batch/ring iÃ…Å¸letimini ve zorunlu politika sÃƒÂ¼relerini mÃƒÂ¼Ã…Å¸teriye gÃƒÂ¶re belirle; gÃƒÂ¶zlem/uyarÃ„Â± ve native canary kabulÃƒÂ¼ yap.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Yetkisiz/stale receipt, rollback, offline sÃƒÂ¼resi, 401/403, bozuk cache, yeniden baÃ…Å¸latma ve hedef deÃ„Å¸iÃ…Å¸tirmede yanlÃ„Â±Ã…Å¸ sÃƒÂ¼rÃƒÂ¼m uygulanmasÃ„Â±n; gerÃƒÂ§ek filoda yakÃ„Â±nsama ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lsÃƒÂ¼n.

**Sorumlu:** Policy + QA + Operations. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Ajan sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼, mÃƒÂ¼Ã…Å¸teri offline toleransÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** POL-03, POL-04, POL-05. **Kaynak:** [supabase/functions/policy-management/index.ts](supabase/functions/policy-management/index.ts), [supabase/functions/policy-ack/index.ts](supabase/functions/policy-ack/index.ts), [packages/core/src/remote-policy.ts](packages/core/src/remote-policy.ts).

### T16 Ã¢â‚¬â€ Endpoint sÃ„Â±r saklama ve anahtar rotasyonu (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Windows config create/update/reuse yolu owner+SYSTEM+Administrators DACL kuruyor ve ACL hatasÃ„Â±nda credential yazmÃ„Â±yor; OS vault ve server-side revocation aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Tipli/redakte config ve ÃƒÂ¶zel dosyalar mevcut.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** OS credential vault entegrasyonu, kurumsal daÃ„Å¸Ã„Â±tÃ„Â±mda signer rotasyonu, kayÃ„Â±p cihaz/anahtar kurtarma ve minimum API-key kapsamÃ„Â± eksik.

**Tamamlanma hedefi:** Windows/macOS/Linux iÃƒÂ§in sÃ„Â±r deposu adaptÃƒÂ¶rÃƒÂ¼; anahtar rotasyonu ve iptali; config/export/support bundle redaksiyonunu tamamla.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Yetkisiz kullanÃ„Â±cÃ„Â± sÃ„Â±r okuyamasÃ„Â±n; eski anahtar zamanÃ„Â±nda reddedilsin; yenileme kesintisi gÃƒÂ¼venli olsun; log, argÃƒÂ¼man ve destek arÃ…Å¸ivi sÃ„Â±r sÃ„Â±zdÃ„Â±rmasÃ„Â±n.

**Sorumlu:** Endpoint + Security Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Kurum secret manager'Ã„Â± ve OS depolarÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** CLI-02, TEN-06. **Kaynak:** [packages/cli/src/utils/config-manager.ts](packages/cli/src/utils/config-manager.ts), [packages/core/src/types.ts](packages/core/src/types.ts), [docs/runbooks/secrets-management.md](docs/runbooks/secrets-management.md).

### T17 Ã¢â‚¬â€ Ã„Â°mzalÃ„Â± filo kurulumu, gÃƒÂ¼ncelleme ve kaldÃ„Â±rma (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Installer ile Windows/Unix uninstall yalnÃ„Â±z AIDR iÃ…Å¸aretli nested hook'u kaldÃ„Â±rÃ„Â±yor, aynÃ„Â± entry'deki mÃƒÂ¼Ã…Å¸teri hook'larÃ„Â±nÃ„Â± koruyor; gerÃƒÂ§ek MDM/yayÃ„Â±ncÃ„Â± kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Claude iÃƒÂ§in yerel kurucu ve deny canary var; diÃ„Å¸er paketler derleniyor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Intune/Jamf/SCCM teslimatÃ„Â±, tÃƒÂ¼m hostlarda upgrade/rollback/uninstall ve filo saÃ„Å¸lÃ„Â±k kanÃ„Â±tÃ„Â± tamam deÃ„Å¸il.

**Tamamlanma hedefi:** Ã„Â°mzalÃ„Â± daÃ„Å¸Ã„Â±tÃ„Â±m paketleri, detect/remediate betikleri, yÃƒÂ¶netici/kullanÃ„Â±cÃ„Â± kurulumlarÃ„Â±, policy-preserving upgrade ve uninstall kurallarÃ„Â± ÃƒÂ¼ret.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Temiz kurulum, yarÃ„Â±m kalan upgrade, eski sÃƒÂ¼rÃƒÂ¼me dÃƒÂ¶nÃƒÂ¼Ã…Å¸, host gÃƒÂ¼ncellemesi ve uninstall sonrasÃ„Â±nda baÃ…Å¸ka kancalar/politika bozulmasÃ„Â±n; gerÃƒÂ§ek MDM'de kanÃ„Â±t topla.

**Sorumlu:** Release + Endpoint Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** MDM test tenantÃ„Â±, signer, OS paketleme araÃƒÂ§larÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** CLI-01, CLI-03, CLI-04. **Kaynak:** [scripts/endpoint-install.mjs](scripts/endpoint-install.mjs), [packages/extension/package.json](packages/extension/package.json), [packages/cli/src/commands/setup.ts](packages/cli/src/commands/setup.ts).

### T18 Ã¢â‚¬â€ Kurumsal giriÃ…Å¸, MFA ve hesap kurtarma (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Recovery URL yalnÃ„Â±z hosted HTTPS/loopback HTTP kabul ediyor, credential URL'yi reddediyor ve parola deÃ„Å¸iÃ…Å¸iminden ÃƒÂ¶nce global session barrier kuruyor; canlÃ„Â± IdP aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Ã„Â°lk yÃƒÂ¶netici ve parolalÃ„Â± giriÃ…Å¸ SMTP olmadan ÃƒÂ§alÃ„Â±Ã…Å¸Ã„Â±yor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** GerÃƒÂ§ek IdP/SSO, MFA, parola sÃ„Â±fÃ„Â±rlama, oturum sonlandÃ„Â±rma, break-glass ve kimlik sahipliÃ„Å¸i iÃ…Å¸letimi kabul edilmedi.

**Tamamlanma hedefi:** MÃƒÂ¼Ã…Å¸teri IdP'si, MFA ve kurtarma akÃ„Â±Ã…Å¸larÃ„Â±nÃ„Â± baÃ„Å¸la; bootstrap sahiplik prosedÃƒÂ¼rÃƒÂ¼, session sÃƒÂ¼releri ve acil yÃƒÂ¶netici eriÃ…Å¸imini tanÃ„Â±mla.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** KayÃ„Â±p parola/MFA, kapatÃ„Â±lmÃ„Â±Ã…Å¸ kullanÃ„Â±cÃ„Â±, sÃƒÂ¼resi dolmuÃ…Å¸ oturum ve baÃ…Å¸arÃ„Â±sÃ„Â±z IdP durumlarÃ„Â±nÃ„Â± sÃ„Â±nayarak hesabÃ„Â±n hem geri alÃ„Â±nabilir hem yetkisiz eriÃ…Å¸ime kapalÃ„Â± olduÃ„Å¸unu kanÃ„Â±tla.

**Sorumlu:** Identity Engineering + Customer IT. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** IdP/SMTP/DNS ve kurum gÃƒÂ¼venlik politikasÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** TEN-01, TEN-04, TEN-07. **Kaynak:** [packages/dashboard/src/ui/pages/LoginPage.tsx](packages/dashboard/src/ui/pages/LoginPage.tsx), [packages/dashboard/src/enterprise/auth.tsx](packages/dashboard/src/enterprise/auth.tsx), [scripts/deployment-bootstrap.mjs](scripts/deployment-bootstrap.mjs).

### T19 Ã¢â‚¬â€ SCIM ve gÃƒÂ¼venilir directory grup eÃ…Å¸lemesi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** SCIM stale PATCH'i reddediyor, Remove members tÃƒÂ¼m ÃƒÂ¼yeleri kaldÃ„Â±rÃ„Â±yor ve bÃƒÂ¼yÃƒÂ¼k grup ÃƒÂ¼yeliÃ„Å¸ini sayfalÃ„Â±yor; gerÃƒÂ§ek Entra/Okta kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Azure yardÃ„Â±mcÃ„Â±larÃ„Â± mevcut; azure-ad-groups endpointi ve tam SCIM yaÃ…Å¸am dÃƒÂ¶ngÃƒÂ¼sÃƒÂ¼ yok.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** YardÃ„Â±mcÃ„Â± kod user_metadata gruplarÃ„Â±nÃ„Â± ÃƒÂ¶nce okuyabiliyor ve isimde admin geÃƒÂ§mesine gÃƒÂ¶re rol eÃ…Å¸liyor. Bu, sunucu yetkilendirmesi iÃƒÂ§in gÃƒÂ¼venilir temel deÃ„Å¸ildir; aktif bir yetki yÃƒÂ¼kseltme kanÃ„Â±tÃ„Â± olarak sunulmuyor.

**Tamamlanma hedefi:** Sunucuda doÃ„Å¸rulanmÃ„Â±Ã…Å¸ immutable grup ID'leri, allowlist rol eÃ…Å¸lemesi ve SCIM create/update/deactivate/groups uygula; kullanÃ„Â±cÃ„Â± metadata'sÃ„Â±nÃ„Â± yetki kaynaÃ„Å¸Ã„Â± yapma.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Sahte metadata, benzer grup adÃ„Â±, grup kaldÃ„Â±rma, hesap pasifleÃ…Å¸tirme, pagination/replay ve tenant karÃ„Â±Ã…Å¸tÃ„Â±rma testleri; eriÃ…Å¸im belirtilen sÃƒÂ¼re iÃƒÂ§inde kesilsin.

**Sorumlu:** Identity + Backend Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** AIDR-019/048; Entra/Okta test ortamÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** TEN-02, TEN-04. **Kaynak:** [packages/dashboard/src/auth/azure-ad.ts](packages/dashboard/src/auth/azure-ad.ts), [packages/dashboard/src/enterprise/team-provider.tsx](packages/dashboard/src/enterprise/team-provider.tsx).

### T20 Ã¢â‚¬â€ Davet ve cihaz kayÃ„Â±t yaÃ…Å¸am dÃƒÂ¶ngÃƒÂ¼sÃƒÂ¼ (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Tenant kapsamlÃ„Â± invite list/revoke/resend token rotasyonu ile device-start/exchange temeli var; SMTP, gerÃƒÂ§ek browser/IdP ve aÃ„Å¸ kesintisi kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Davet baÃ„Å¸lantÃ„Â±sÃ„Â± ve aÃƒÂ§Ã„Â±k ekip seÃƒÂ§imiyle cihaz kaydÃ„Â± yerel provadan geÃƒÂ§ti.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** SMTP davet teslimi, gerÃƒÂ§ek cihaz yeniden kaydÃ„Â±, ekipten ayrÃ„Â±lan ÃƒÂ§alÃ„Â±Ã…Å¸anÃ„Â±n eriÃ…Å¸im kapanmasÃ„Â± ve mÃƒÂ¼Ã…Å¸teri mail/link akÃ„Â±Ã…Å¸Ã„Â± tam kabul edilmedi.

**Tamamlanma hedefi:** Davet daÃ„Å¸Ã„Â±tÃ„Â±mÃ„Â±nÃ„Â±, expiry/iptal/yeniden gÃƒÂ¶nderme, yanlÃ„Â±Ã…Å¸ ekip ve cihaz yenileme iÃ…Å¸letimini tamamla.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** KullanÃ„Â±lmÃ„Â±Ã…Å¸/iptal edilmiÃ…Å¸ davet, rol deÃ„Å¸iÃ…Å¸imi, baÃ…Å¸ka ekip, eski device code ve kimlik deÃ„Å¸iÃ…Å¸iminde kayÃ„Â±t reddedilsin; mail linki gerÃƒÂ§ek tarayÃ„Â±cÃ„Â±da doÃ„Å¸ru ekibe dÃƒÂ¶nsÃƒÂ¼n.

**Sorumlu:** Identity + Customer Success. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** SMTP/IdP ve mÃƒÂ¼Ã…Å¸teri cihazlarÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** TEN-03, TEN-05. **Kaynak:** [supabase/functions/team-invite/index.ts](supabase/functions/team-invite/index.ts), [supabase/functions/device-poll/index.ts](supabase/functions/device-poll/index.ts), [packages/dashboard/src/ui/pages/public/VerifyPage.tsx](packages/dashboard/src/ui/pages/public/VerifyPage.tsx).

### T21 Ã¢â‚¬â€ Mevcut API anahtarÃ„Â±nda ekip ve ÃƒÂ¼yelik iptali (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Packs manifest/download dahil anahtar kullanan yollar aktif tenant, ÃƒÂ¼yelik ve revocation doÃ„Å¸ruluyor; ÃƒÂ¶nceden ÃƒÂ¼retilmiÃ…Å¸ signed URL sÃƒÂ¼re sonuna dek geÃƒÂ§erli.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Anahtar yÃƒÂ¶netimi aktif ekip/ÃƒÂ¼yeliÃ„Å¸i denetliyor; reputation API'leri yalnÃ„Â±zca mevcut anahtarÃ„Â±n revoked deÃ„Å¸erini kontrol ediyor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Ã„Â°zole gerÃƒÂ§ek HTTP provasÃ„Â±nda askÃ„Â±ya alÃ„Â±nmÃ„Â±Ã…Å¸ ekip ve sÃƒÂ¼resi bitmiÃ…Å¸ ÃƒÂ¼yelikle hem URL hem dosya sorgusu 200 dÃƒÂ¶ndÃƒÂ¼; dÃƒÂ¶rt kabul yeniden ÃƒÂ¼retildi. BaÃ…Å¸ka tenant verisi okunduÃ„Å¸u gÃƒÂ¶sterilmedi.

**Tamamlanma hedefi:** Ortak doÃ„Å¸rulanmÃ„Â±Ã…Å¸ anahtar/aktif tenant/aktif ÃƒÂ¼yelik sÃ„Â±nÃ„Â±rÃ„Â± uygula; iptal, kapanÃ„Â±Ã…Å¸ ve deprovisioning semantiÃ„Å¸ini tÃƒÂ¼m servislerde birleÃ…Å¸tir.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Aktif kimlik 200; suspended/closing/closed tenant, expired/removed membership ve revoked key tÃƒÂ¼m tÃƒÂ¼keticilerde 401/403; stale cache ile eriÃ…Å¸im sÃƒÂ¼rmesin.

**Sorumlu:** Backend Security. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** AIDR-063; yerel yeniden ÃƒÂ¼retim kanÃ„Â±tÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** TEN-01, TEN-06, DET-10, DET-11. **Kaynak:** [supabase/functions/url-check/index.ts](supabase/functions/url-check/index.ts), [supabase/functions/file-check/index.ts](supabase/functions/file-check/index.ts), [scripts/audit-reputation-lifecycle.mjs](scripts/audit-reputation-lifecycle.mjs).

### T22 Ã¢â‚¬â€ Tenant izolasyonu ve kaynak tÃƒÂ¼ketim sÃ„Â±nÃ„Â±rlarÃ„Â± (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Edge byte/rate sÃ„Â±nÃ„Â±rÃ„Â± bozuk RPC'de 503 ve stalled stream'de 413 fail-closed ÃƒÂ¼retiyor; mÃƒÂ¼Ã…Å¸teri yÃƒÂ¼k/izolasyon kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** RLS, rol ve bazÃ„Â± negatif uÃƒÂ§tan uca testler var.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Her endpoint/rol/tenant kombinasyonu, body/stream sÃ„Â±nÃ„Â±rÃ„Â±, rate-limit kesintisi ve komÃ…Å¸u tenant kaynak tÃƒÂ¼ketimi tam ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lmedi.

**Tamamlanma hedefi:** TÃƒÂ¼m endpointler iÃƒÂ§in auth/RBAC/RLS sÃƒÂ¶zleÃ…Å¸mesi; servis rolÃƒÂ¼ kullanan yollarda aÃƒÂ§Ã„Â±k tenant sÃ„Â±nÃ„Â±rÃ„Â±; kuyruk/iÃ…Å¸/istek/depoma kotalarÃ„Â± ekle ve denetle.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** FarklÃ„Â± tenant, ÃƒÂ¼yelik kaybÃ„Â±, viewer, eski anahtar, bÃƒÂ¼yÃƒÂ¼k body ve paralel isteklerle negatif matris ÃƒÂ§alÃ„Â±Ã…Å¸sÃ„Â±n; tek tenant diÃ„Å¸erinin SLO'sunu tÃƒÂ¼ketemesin.

**Sorumlu:** Security + Backend + SRE. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** BaÃ„Å¸Ã„Â±msÃ„Â±z deÃ„Å¸erlendirme ve tanÃ„Â±mlÃ„Â± yÃƒÂ¼k profili.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** TEN-01, OBS-01, DEP-07. **Kaynak:** [supabase/functions/_shared/auth.ts](supabase/functions/_shared/auth.ts), [supabase/migrations/20260805000000_hybrid_tenancy.sql](supabase/migrations/20260805000000_hybrid_tenancy.sql).

### T23 Ã¢â‚¬â€ Telemetri dayanÃ„Â±klÃ„Â±lÃ„Â±Ã„Å¸Ã„Â± ve gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r veri kaybÃ„Â± (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Telemetry WAL bozuk/unknown/tampered committed kayÃ„Â±tlarÃ„Â± reddediyor, terminal drop sonrasÃ„Â± retry ve stale backlog readiness saÃ„Å¸lÃ„Â±yor; uzun kesinti saha testi aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Olay alÃ„Â±mÃ„Â± ve dashboard baÃ„Å¸lÃ„Â±.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Filo yÃƒÂ¼kÃƒÂ¼nde teslim SLO'su, disk/kuyruk sÃ„Â±nÃ„Â±rÃ„Â±, offline retry/dedup ve uÃƒÂ§tan uca kayÃ„Â±p oranÃ„Â± iÃƒÂ§in kanÃ„Â±t eksik.

**Tamamlanma hedefi:** Olay teslim sÃƒÂ¶zleÃ…Å¸mesi, kimlik/idempotency, retry/backpressure, kayÃ„Â±p sayaÃƒÂ§larÃ„Â± ve tenant bazlÃ„Â± retention bÃƒÂ¼tÃƒÂ§elerini doÃ„Å¸rula.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** AÃ„Å¸/DB/storage kesintisi ve ajan yeniden baÃ…Å¸latmada kayÃ„Â±p/duplicate ÃƒÂ¶lÃƒÂ§; sessiz olay kaybÃ„Â± olmasÃ„Â±n; disk dolmasÃ„Â± ve gecikme kullanÃ„Â±cÃ„Â±ya gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r olsun.

**Sorumlu:** Telemetry Engineering + SRE. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** MÃƒÂ¼Ã…Å¸teri cihaz/olay hacmi ve saklama hedefi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** OBS-01. **Kaynak:** [supabase/functions/ingest/index.ts](supabase/functions/ingest/index.ts), [packages/core/src/audit-log.ts](packages/core/src/audit-log.ts).

### T24 Ã¢â‚¬â€ SIEM ve OpenTelemetry ÃƒÂ¼retim teslimi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** SIEM durable state provider/endpoint/index routing fingerprint'e baÃ„Å¸lÃ„Â± ve farklÃ„Â± hedefte reopen'i reddediyor; gerÃƒÂ§ek SIEM alÃ„Â±ndÃ„Â±sÃ„Â±/zamanlayÃ„Â±cÃ„Â± aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** DÃ„Â±Ã…Å¸a aktarma/izleme bileÃ…Å¸enleri mevcut.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Named SIEM transport, teslim bildirimi, kesinti tamponu, Ã…Å¸ema sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼ ve mÃƒÂ¼Ã…Å¸teri SIEM alan eÃ…Å¸lemesi kabul edilmedi.

**Tamamlanma hedefi:** SatÃ„Â±lacak Splunk/Sentinel/Elastic vb. adaptÃƒÂ¶rleri iÃƒÂ§in gerÃƒÂ§ek endpoint entegrasyonu, retry/dedup ve saÃ„Å¸lÃ„Â±k gÃƒÂ¶stergesi tamamla.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** SIEM kesintisi/429/401, sertifika deÃ„Å¸iÃ…Å¸imi, yeniden gÃƒÂ¶nderim ve alan eÃ…Å¸lemesi gerÃƒÂ§ek SIEM'de doÃ„Å¸rulansÃ„Â±n; yanlÃ„Â±Ã…Å¸ baÃ…Å¸arÃ„Â± bildirimi olmasÃ„Â±n.

**Sorumlu:** Integrations + Customer SOC. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** SIEM test hesabÃ„Â± ve event schema anlaÃ…Å¸masÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** OBS-04. **Kaynak:** [packages/core/src/siem-export.ts](packages/core/src/siem-export.ts), [packages/core/src/tracing.ts](packages/core/src/tracing.ts).

### T25 Ã¢â‚¬â€ Olay araÃ…Å¸tÃ„Â±rmasÃ„Â± ve kanÃ„Â±t bÃƒÂ¼tÃƒÂ¼nlÃƒÂ¼Ã„Å¸ÃƒÂ¼ (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** incidents/evidence-receipt.ts candidate/policy/device/actor/incident/action bagli append-only receipt, Lamport mantik saati ile offline/skew siralamasi, duplicate/tamper reddi ve fail-closed arsiv adapteri ekliyor. Dis arsiv sahibi ve key custody acik. Eski: Olay receipt head sÃ„Â±rasÃ„Â± deterministik UTF-16 ve legacy doÃ„Å¸rulama uyumlu; ayrÃ„Â± Ed25519 snapshot makbuzu var. DÃ„Â±Ã…Å¸ saklama, key custody ve gÃƒÂ¼venilir zaman aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Yerel korelasyon ve imzalÃ„Â± response zinciri var.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Tam cross-agent nedensellik, ayrÃ„Â±calÃ„Â±klÃ„Â± deÃ„Å¸iÃ…Å¸ikliklere karÃ…Å¸Ã„Â± baÃ„Å¸Ã„Â±msÃ„Â±z kanÃ„Â±t saklama ve olayÃ¢â€ â€™araÃƒÂ§Ã¢â€ â€™credential izi eksik.

**Tamamlanma hedefi:** Korelasyon kimlikleri, zaman sapmasÃ„Â±, iliÃ…Å¸kili ajan/kaynak gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼mÃƒÂ¼, zincir doÃ„Å¸rulama ve baÃ„Å¸Ã„Â±msÃ„Â±z arÃ…Å¸iv kur.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Saat kaymasÃ„Â±/duplicate/offline sÃ„Â±ralama, silinmiÃ…Å¸ veya deÃ„Å¸iÃ…Å¸tirilmiÃ…Å¸ zincir ve ÃƒÂ§ok ajanlÃ„Â± saldÃ„Â±rÃ„Â±da kanÃ„Â±t boÃ…Å¸luklarÃ„Â± gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r olsun.

**Sorumlu:** Detection + SOC Product. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Kimlik grafiÃ„Å¸i, gÃƒÂ¼venilir zaman ve arÃ…Å¸iv sahibi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** OBS-02, RSP-05. **Kaynak:** [packages/core/src/incidents/correlate.ts](packages/core/src/incidents/correlate.ts), [packages/core/src/incidents/anchor.ts](packages/core/src/incidents/anchor.ts), [packages/core/src/response-audit.ts](packages/core/src/response-audit.ts).

### T26 Ã¢â‚¬â€ Saklama, legal hold ve mÃƒÂ¼Ã…Å¸teri ÃƒÂ§Ã„Â±kÃ„Â±Ã…Å¸Ã„Â± (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Offboarding her Storage nesnesinin yokluÃ„Å¸unu doÃ„Å¸rulamadan ACK ÃƒÂ¼retmiyor; legal hold/resume var, harici backup silme kanÃ„Â±tÃ„Â± aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** SayfalÃ„Â± export ve geÃƒÂ§ici dosyalar iÃƒÂ§in silme komutu var; zamanlayÃ„Â±cÃ„Â± Ã…Å¸ablonu saÃ„Å¸lanÃ„Â±yor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** ZamanlayÃ„Â±cÃ„Â± mÃƒÂ¼Ã…Å¸teri ortamÃ„Â±nda aktif deÃ„Å¸il; tÃƒÂ¼m veri sÃ„Â±nÃ„Â±flarÃ„Â± iÃƒÂ§in retention/deletion, legal hold ve doÃ„Å¸rulanmÃ„Â±Ã…Å¸ offboarding yok.

**Tamamlanma hedefi:** Tablo/nesne/log/cache/yedek bazÃ„Â±nda yaÃ…Å¸am dÃƒÂ¶ngÃƒÂ¼sÃƒÂ¼; legal hold istisnasÃ„Â±; kullanÃ„Â±cÃ„Â±/tenant kapanÃ„Â±Ã…Å¸Ã„Â± ve silme makbuzu kur.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** SÃƒÂ¼re dolan verinin API, Storage, cache ve replikalardan yokluÃ„Å¸u; hold verisinin korunmasÃ„Â±; retry ve yarÃ„Â±m silme sonrasÃ„Â± tutarlÃ„Â±lÃ„Â±k kanÃ„Â±tlansÃ„Â±n.

**Sorumlu:** Backend + Privacy + Operations. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** OnaylÃ„Â± saklama/silme politikasÃ„Â±; yedek istisnalarÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** OBS-03, OBS-06. **Kaynak:** [scripts/deployment-maintenance.mjs](scripts/deployment-maintenance.mjs), [deploy/maintenance/aidr-export-retention.timer](deploy/maintenance/aidr-export-retention.timer), [supabase/functions/audit-export/index.ts](supabase/functions/audit-export/index.ts).

### T27 Ã¢â‚¬â€ Offsite yedekleme ve RPO/RTO (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Offsite commit zamanÃ„Â± authenticated manifest'e baÃ„Å¸lÃ„Â± ve S3 lookup hatasÃ„Â± fail-closed; izole restore aracÃ„Â± var. BaÃ„Å¸Ã„Â±msÃ„Â±z host/provider ve RPO/RTO aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Ã…Âifreli soÃ„Å¸uk yedek ve baÃ„Å¸Ã„Â±msÃ„Â±z volume geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ÃƒÂ¼nde 18 karÃ…Å¸Ã„Â±laÃ…Å¸tÃ„Â±rma geÃƒÂ§ti.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Off-host kopya, otomatik zamanlama/retention, ayrÃ„Â± anahtar kurtarma ve gerÃƒÂ§ek felaket RPO/RTO kanÃ„Â±tÃ„Â± yok; bakÃ„Â±m duruÃ…Å¸u gerekiyor.

**Tamamlanma hedefi:** Yedek hedefi/anahtar custody, zamanlama, eriÃ…Å¸im ayrÃ„Â±lÃ„Â±Ã„Å¸Ã„Â±, baÃ…Å¸arÃ„Â±sÃ„Â±zlÃ„Â±k alarmÃ„Â± ve kayÃ„Â±p-host geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ iÃ…Å¸letimini kur.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Yeni hostta yalnÃ„Â±z offsite yedek ve ayrÃ„Â± anahtarla kurtar; tablo/nesne iÃƒÂ§erikleri eÃ…Å¸leÃ…Å¸sin; gerÃƒÂ§ek kayÃ„Â±p veri sÃƒÂ¼resi ve toparlanma sÃƒÂ¼resi ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lsÃƒÂ¼n.

**Sorumlu:** SRE + Customer Operations. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Offsite storage, key custodian, kabul edilmiÃ…Å¸ RPO/RTO.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DEP-06. **Kaynak:** [scripts/deployment-backup.mjs](scripts/deployment-backup.mjs), [scripts/verify-deployment-recovery.mjs](scripts/verify-deployment-recovery.mjs).

### T28 Ã¢â‚¬â€ GerÃƒÂ§ek cloud ve self-hosted ÃƒÂ¼retim kurulumu (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** 33 migrationlÃ„Â± self-hosted prova var; prepare inputlarÃ„Â± secret oluÃ…Å¸turmadan doÃ„Å¸ruluyor ve cloud public proxy/provider upstream loop'unu reddediyor. CanlÃ„Â± provider/TLS aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Ã„Â°ki model iÃƒÂ§in kurulum hazÃ„Â±rlama ve yerel Docker prova var.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Cloud hesabÃ„Â±/projesi, bÃƒÂ¶lge, DNS/TLS, reverse proxy, SMTP/IdP, secret installation ve gerÃƒÂ§ek internet eriÃ…Å¸imi bilinmiyor; cloud hazÃ„Â±rlama ÃƒÂ§alÃ„Â±Ã…Å¸an cloud demek deÃ„Å¸il.

**Tamamlanma hedefi:** Her model iÃƒÂ§in hedef ortamÃ„Â± kur; TLS yenileme ve HTTP/WebSocket baÃ…Å¸lÃ„Â±klarÃ„Â±nÃ„Â± doÃ„Å¸rula; DB/Studio'yu ÃƒÂ¶zel aÃ„Å¸da tut; public endpoint ve onboarding'i kabul et.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Temiz makinede mÃƒÂ¼Ã…Å¸teri kimliÃ„Å¸iyle giriÃ…Å¸Ã¢â€ â€™cihazÃ¢â€ â€™denyÃ¢â€ â€™olayÃ¢â€ â€™exportÃ¢â€ â€™rollback akÃ„Â±Ã…Å¸Ã„Â±; dÃ„Â±Ã…Å¸ port/izin kontrolleri ve sertifika yenileme tatbikatÃ„Â±.

**Sorumlu:** SRE + Customer IT. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Alan adÃ„Â±, cloud hesabÃ„Â±/bÃƒÂ¶lge ve aÃ„Å¸ bilgisi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DEP-01, DEP-02. **Kaynak:** [scripts/deployment-prepare.mjs](scripts/deployment-prepare.mjs), [deploy/FIRST_CUSTOMER.md](deploy/FIRST_CUSTOMER.md).

### T29 Ã¢â‚¬â€ KimliÃ„Å¸i doÃ„Å¸rulanan daÃ„Å¸Ã„Â±tÃ„Â±m ve release provenance (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Release verifier receipt hedefini mutation ÃƒÂ¶ncesi doÃ„Å¸ruluyor ve bundle/state/policy ÃƒÂ§akÃ„Â±Ã…Å¸masÃ„Â±nÃ„Â± reddediyor; resmi key custody/private registry aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** TaÃ…Å¸Ã„Â±nabilir aday, SBOM, paket tÃƒÂ¼ketici ve SHA denetimleri var; yayÃ„Â±ncÃ„Â± imzasÃ„Â± yok.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Checksum yayÃ„Â±ncÃ„Â± kimliÃ„Å¸i deÃ„Å¸ildir. Private registry kurulumu, imza doÃ„Å¸rulama, key rotasyonu ve air-gap imaj teslimi kanÃ„Â±tÃ„Â± yok.

**Tamamlanma hedefi:** AynÃ„Â± candidate'Ã„Â± imzala; auth kontrollÃƒÂ¼ registry/download, provenance ve sabit imaj digestleriyle teslim et; air-gap satÃ„Â±lÃ„Â±yorsa tÃƒÂ¼m baÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k/imajlarÃ„Â± dahil et.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** YanlÃ„Â±Ã…Å¸ signer/deÃ„Å¸iÃ…Å¸miÃ…Å¸ arÃ…Å¸iv/eski sÃƒÂ¼rÃƒÂ¼m reddedilsin; mÃƒÂ¼Ã…Å¸teri temiz makinede internetsiz veya yetkili registry ile kurabilsin; imza/anahtar iptali sÃ„Â±nansÃ„Â±n.

**Sorumlu:** Release Engineering + Security. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Signer ve registry yetkisi; lisans onayÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DEP-05, DEP-08, OBS-05. **Kaynak:** [scripts/customer-kit.mjs](scripts/customer-kit.mjs), [.github/scripts/build-release-bundle.mjs](.github/scripts/build-release-bundle.mjs), [scripts/release-artifact-manifests.mjs](scripts/release-artifact-manifests.mjs).

### T30 Ã¢â‚¬â€ HA, failover, kapasite ve SLA ÃƒÂ¶lÃƒÂ§ÃƒÂ¼mÃƒÂ¼ (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Load harness her fault senaryosu iÃƒÂ§in son hatadan sonra ardÃ„Â±Ã…Å¸Ã„Â±k recovery ve tam gÃƒÂ¶zlem istiyor; gerÃƒÂ§ek HA, kapasite ve aylÃ„Â±k SLA aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Tek host Docker temel kurulumu var; 501 satÃ„Â±r sayfalama testi yÃƒÂ¼k testi deÃ„Å¸ildir.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** HA topology, DB failover, tenant noisy-neighbor ve aylÃ„Â±k availability SLI kanÃ„Â±tÃ„Â± yok; 99.9 ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lmÃƒÂ¼Ã…Å¸ sonuÃƒÂ§ deÃ„Å¸il.

**Tamamlanma hedefi:** Desteklenen kapasite ve region topology tanÃ„Â±mla; load/soak/failover, hata bÃƒÂ¼tÃƒÂ§esi ve ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m paydasÃ„Â± kur.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** GerÃƒÂ§ekÃƒÂ§i agent/event yÃƒÂ¼kÃƒÂ¼nde p50/p95/p99, hata/kayÃ„Â±p oranÃ„Â±, DB/servis/node arÃ„Â±zasÃ„Â± ve bakÃ„Â±m etkisi raporlansÃ„Â±n; kabul edilmiÃ…Å¸ gÃƒÂ¶zlem penceresi tamamlanmÃ„Â±Ã…Å¸ olsun.

**Sorumlu:** SRE + Performance Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Host boyutlarÃ„Â±, filo/olay profili, SLA anlaÃ…Å¸masÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DEP-07. **Kaynak:** [deploy/dashboard/server.mjs](deploy/dashboard/server.mjs), [deploy/README.md](deploy/README.md).

### T31 Ã¢â‚¬â€ Migration, upgrade ve geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ tatbikatÃ„Â± (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Kesilen rename resume yalnÃ„Â±z kaynak/staged iÃƒÂ§erik preflight hash'leriyle eÃ…Å¸leÃ…Å¸irse devam ediyor; gerÃƒÂ§ek trafik cutover/rollback kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** 18 migration checksum/transaction ile uygulanÃ„Â±yor; temiz kurulum smoke var.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Ãƒâ€“nceki mÃƒÂ¼Ã…Å¸teri sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼nden upgrade, sÃƒÂ¼rÃƒÂ¼m karmaÃ…Å¸asÃ„Â± ve gerÃƒÂ§ek ÃƒÂ¼retim rollback tatbikatÃ„Â± aÃƒÂ§Ã„Â±k.

**Tamamlanma hedefi:** Desteklenen upgrade yollarÃ„Â±, ÃƒÂ¶n kontrol/yedek, kesinti planÃ„Â±, kompatibilite ve baÃ…Å¸arÃ„Â±sÃ„Â±z migration geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ prosedÃƒÂ¼rÃƒÂ¼ hazÃ„Â±rla.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Eski veriyle upgrade, kesilen migration, checksum deÃ„Å¸iÃ…Å¸ikliÃ„Å¸i, uygulama/DB sÃƒÂ¼rÃƒÂ¼m uyuÃ…Å¸mazlÃ„Â±Ã„Å¸Ã„Â± ve kurtarma testi; veri kaybÃ„Â± ve sessiz schema drift olmasÃ„Â±n.

**Sorumlu:** Backend + Release + SRE. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Ãƒâ€“nceki sÃƒÂ¼rÃƒÂ¼m snapshotlarÃ„Â± ve bakÃ„Â±m penceresi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DEP-03, DEP-04. **Kaynak:** [scripts/deployment-migrate.mjs](scripts/deployment-migrate.mjs), [scripts/deployment-doctor.mjs](scripts/deployment-doctor.mjs).

### T32 Ã¢â‚¬â€ Ã„Â°zleme, alarm ve iÃ…Å¸letim sahipliÃ„Å¸i (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Per-instance scrape/readiness ve empty-discovery alertleri eklendi; kural YAML/testleri var. CanlÃ„Â± paging, isimli nÃƒÂ¶bet ve SLA aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Runbook ve container saÃ„Å¸lÃ„Â±k kontrolleri var.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Production dashboard, nÃƒÂ¶betÃƒÂ§i, gerÃƒÂ§ek paging, sertifika/disk/kuyruk/feed/backup alarmÃ„Â± ve incident tatbikatÃ„Â± tamamlanmadÃ„Â±.

**Tamamlanma hedefi:** SLI dashboard ve alarm eÃ…Å¸ikleri, sorumlu/nÃƒÂ¶bet takvimi, alarm sessizliÃ„Å¸i kontrolÃƒÂ¼, escalation ve olay sonrasÃ„Â± inceleme akÃ„Â±Ã…Å¸Ã„Â± kur.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Servis, DB, storage, signer, kuyruk ve yedek hatasÃ„Â± enjekte et; doÃ„Å¸ru kiÃ…Å¸iye zamanlÃ„Â± alarm ve ÃƒÂ§ÃƒÂ¶zÃƒÂ¼ldÃƒÂ¼ bildirimi gelsin; kayÃ„Â±tlÃ„Â± tatbikat tut.

**Sorumlu:** SRE + Support. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** GerÃƒÂ§ek izleme/paging kanallarÃ„Â± ve isimli sorumlular.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DEP-01, DEP-02, OBS-01. **Kaynak:** [docs/runbooks/alerting.md](docs/runbooks/alerting.md), [docs/runbooks/incident-response.md](docs/runbooks/incident-response.md).

### T33 Ã¢â‚¬â€ SatÃ„Â±lan fatura ve entitlement yaÃ…Å¸am dÃƒÂ¶ngÃƒÂ¼sÃƒÂ¼ (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** billing-portal Edge Function provider-of-record durum makinesi, sunucu tarafi tenant/uyelik/rol/MFA cozumlemesi, istemci customer/tenant/subscription id reddi, TTL/idempotency, cancel/refund ve seat reconciliation uyguluyor; finance fixture ile test edildi, canli provider ve muhasebe onayi acik. Eski: Pending Finance sipariÃ…Å¸ sonucu tenant/request/quantity/quote alanlarÃ„Â±na fail-closed baÃ„Å¸lÃ„Â±; provider-of-record, ÃƒÂ¶deme makbuzu ve paid-to-entitlement yok.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** VarsayÃ„Â±lan kurum faturasÃ„Â±; opsiyonel Stripe checkout/webhook kaynak kodu mevcut.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** OnaylÃ„Â± SKU/fiyat/teklif, tahsilat-mutabakat, quota deÃ„Å¸iÃ…Å¸imi, iptal ve ÃƒÂ§Ã„Â±kÃ„Â±Ã…Å¸ provasÃ„Â± yok. Self-service portal uygulanmamÃ„Â±Ã…Å¸; yalnÃ„Â±z satÃ„Â±lan SKU'da gerekiyorsa blocker.

**Tamamlanma hedefi:** Provider-of-record ve kurumsal sipariÃ…Å¸Ã¢â€ â€™quota iÃ…Å¸letimini tamamla; self-service satÃ„Â±lacaksa gerÃƒÂ§ek portal, invoice, cancel/refund/reconcile akÃ„Â±Ã…Å¸larÃ„Â±nÃ„Â± ekle.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** SipariÃ…Å¸/ek koltuk/azaltma/yenileme/ÃƒÂ¶deme hatasÃ„Â±/iptal ve mÃƒÂ¼kerrer webhook aynÃ„Â± entitlement sonucunu versin; finans mutabakatÃ„Â± ve mÃƒÂ¼Ã…Å¸teri makbuzu eÃ…Å¸leÃ…Å¸sin.

**Sorumlu:** Finance + Billing Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Ticari karar, canlÃ„Â± provider anahtarlarÃ„Â± ve muhasebe onayÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** BIL-01, BIL-02, BIL-03. **Kaynak:** [packages/dashboard/src/ui/pages/BillingPage.tsx](packages/dashboard/src/ui/pages/BillingPage.tsx), [supabase/functions/billing-checkout/index.ts](supabase/functions/billing-checkout/index.ts), [supabase/functions/stripe-webhook/index.ts](supabase/functions/stripe-webhook/index.ts).

### T34 Ã¢â‚¬â€ Readiness kayÃ„Â±tlarÃ„Â±nÃ„Â±n ve ÃƒÂ¼rÃƒÂ¼n iddialarÃ„Â±nÃ„Â±n tutarlÃ„Â±lÃ„Â±Ã„Å¸Ã„Â± (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** 71 ÃƒÂ¶zellik, 59 iÃ…Å¸ paketi, 10 release rootu ve claim candidate/expiry tutarlÃ„Â±lÃ„Â±Ã„Å¸Ã„Â± otomatik kontrol ediliyor; 13 dÃ„Â±Ã…Å¸ onay kapÃ„Â±sÃ„Â± aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Envanter gÃƒÂ¼ncel; eski denetim alanlarÃ„Â± tarihsel metinler iÃƒÂ§eriyor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Ticari registry AÃ„Å¸ustos tarihli ve artifactRoots/connector listesi mevcut dokuz paketi tam yansÃ„Â±tmÃ„Â±yor; eski checkout/default endpoint ifadeleri yeni implementasyonu anlatmÃ„Â±yor.

**Tamamlanma hedefi:** Tarihsel bulguyu korurken currentState alanlarÃ„Â±nÃ„Â± ayÃ„Â±r; beklenen paket/connector kapsamÃ„Â±nÃ„Â± release manifestinden tÃƒÂ¼ret; web, README, demo ve teklif metnini tek kanÃ„Â±t sÃƒÂ¶zlÃƒÂ¼Ã„Å¸ÃƒÂ¼ne baÃ„Å¸la.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** AynÃ„Â± sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼n paket/ÃƒÂ¶zellik/claim sayÃ„Â±larÃ„Â± tutarlÃ„Â±; eksik paket zorunlu gate'i dÃƒÂ¼Ã…Å¸ÃƒÂ¼rsÃƒÂ¼n; sÃƒÂ¼resi dolmuÃ…Å¸/onaysÃ„Â±z iddia mÃƒÂ¼Ã…Å¸teri yÃƒÂ¼zÃƒÂ¼ne ÃƒÂ§Ã„Â±kmasÃ„Â±n.

**Sorumlu:** Product + Release + Marketing. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** GÃƒÂ¼ncel release candidate ve ticari onay sahipleri.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** EVAL-02, EVAL-03, DEP-05. **Kaynak:** [docs/production-readiness/commercial-go-evidence-registry.json](docs/production-readiness/commercial-go-evidence-registry.json), [READINESS_BACKLOG.json](READINESS_BACKLOG.json), [README.md](README.md).

### T35 Ã¢â‚¬â€ Test kapÃ„Â±larÃ„Â±nÃ„Â±n kapsamÃ„Â± ve baÃ…Å¸arÃ„Â±sÃ„Â±zlÃ„Â±Ã„Å¸Ã„Â±n saklanmamasÃ„Â± (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** v7 birleÃ…Å¸ik test 237 dosya/3326 geÃƒÂ§iÃ…Å¸/2 aÃƒÂ§Ã„Â±klanmÃ„Â±Ã…Å¸ skip, coverage eÃ…Å¸ikleri ve 10 paket release consumer geÃƒÂ§ti; native kÃƒÂ¶r corpus aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Binlerce yerel test ve derlenmiÃ…Å¸ kanca kontrolleri var; 1 canlÃ„Â± saÃ„Å¸layÃ„Â±cÃ„Â± senaryosu atlanÃ„Â±yor. Son koÃ…Å¸u hatasÃ„Â± ve dÃƒÂ¼zeltme kaydÃ„Â± tutuluyor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Test sayÃ„Â±sÃ„Â± ÃƒÂ¶zellik tamamlanmasÃ„Â± deÃ„Å¸ildir; bazÃ„Â± gÃƒÂ¶zlem testleri bilinen boÃ…Å¸luÃ„Å¸u allow olarak kabul ediyor. Native/soak/baÃ„Å¸Ã„Â±msÃ„Â±z corpus ve coverage kapanÃ„Â±Ã…Å¸Ã„Â± eksik; 132 lint uyarÃ„Â±sÃ„Â± var.

**Tamamlanma hedefi:** Ãƒâ€“zellikÃ¢â€ â€™tÃƒÂ¼keticiÃ¢â€ â€™pozitif/negatifÃ¢â€ â€™artefact baÃ„Å¸Ã„Â±nÃ„Â± zorunlu kÃ„Â±l; bilinen aÃƒÂ§Ã„Â±klarÃ„Â± test hedefi yap; mandatory skip ve stale evidence gate'i dÃƒÂ¼Ã…Å¸ÃƒÂ¼rsÃƒÂ¼n; uyarÃ„Â±/dead-code borcunu sÃ„Â±nÃ„Â±flandÃ„Â±r.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Her satÃ„Â±lan ÃƒÂ¶zellik iÃƒÂ§in gerÃƒÂ§ek tÃƒÂ¼keticide deny/allow/outage kanÃ„Â±tÃ„Â±; aynÃ„Â± candidate checksum; 0 aÃƒÂ§Ã„Â±klanmamÃ„Â±Ã…Å¸ zorunlu skip; deÃ„Å¸iÃ…Å¸meyen timeoutlarla tekrar koÃ…Å¸u ve aÃƒÂ§Ã„Â±k borÃƒÂ§ kaydÃ„Â±.

**Sorumlu:** QA + Security Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Native ortam, baÃ„Å¸Ã„Â±msÃ„Â±z corpus ve CI kapasitesi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** EVAL-01, CON-05. **Kaynak:** [vitest.config.ts](vitest.config.ts), [packages/opencode/src/__tests__/aidr-contract.test.ts](packages/opencode/src/__tests__/aidr-contract.test.ts), [scripts/verify-enforcement.mjs](scripts/verify-enforcement.mjs).

### T36 Ã¢â‚¬â€ OperatÃƒÂ¶r UI ve ilk mÃƒÂ¼Ã…Å¸teri kullanÃ„Â±labilirliÃ„Å¸i (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Onboarding stale token/tenant/error durumlarÃ„Â± fail-closed ve yapÃ„Â±landÃ„Â±rÃ„Â±lmÃ„Â±Ã…Å¸ Azure/Entra login gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼r; gerÃƒÂ§ek browser/IdP/eriÃ…Å¸ilebilirlik kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** GiriÃ…Å¸, ekip seÃƒÂ§imi, kayÃ„Â±t, politika ve export akÃ„Â±Ã…Å¸larÃ„Â± yerel testli.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** TÃƒÂ¼m desteklenen tarayÃ„Â±cÃ„Â±lar, klavye/eriÃ…Å¸ilebilirlik, aÃ„Å¸ hatalarÃ„Â±, ÃƒÂ§ok ekipli eÃ…Å¸ zamanlÃ„Â± kullanÃ„Â±m ve gerÃƒÂ§ek mÃƒÂ¼Ã…Å¸teri eÃ„Å¸itimi tamam deÃ„Å¸il.

**Tamamlanma hedefi:** Ekran bazlÃ„Â± loading/empty/error/permission sÃƒÂ¶zleÃ…Å¸mesi, eriÃ…Å¸ilebilirlik ve tarayÃ„Â±cÃ„Â± matrisi; ilk mÃƒÂ¼Ã…Å¸teri kÃ„Â±lavuzunu gerÃƒÂ§ek operatÃƒÂ¶rle uygula.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** YanlÃ„Â±Ã…Å¸ ekipte sÃ„Â±r/politika gÃƒÂ¶rÃƒÂ¼nmesin; timeout/409/401 sonrasÃ„Â± yanlÃ„Â±Ã…Å¸ baÃ…Å¸arÃ„Â± olmasÃ„Â±n; klavye ile kritik iÃ…Å¸ler tamamlansÃ„Â±n; bÃƒÂ¼yÃƒÂ¼k liste ve uzun deÃ„Å¸erlerde UI bozulmasÃ„Â±n.

**Sorumlu:** Dashboard + Design + Customer Success. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Desteklenen browser ve mÃƒÂ¼Ã…Å¸teri kullanÃ„Â±cÃ„Â±larÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** CLI-01, TEN-07, TEN-03, POL-02, OBS-03. **Kaynak:** [packages/dashboard/src/main.tsx](packages/dashboard/src/main.tsx), [packages/dashboard/src/ui/pages/OnboardingPage.tsx](packages/dashboard/src/ui/pages/OnboardingPage.tsx), [packages/dashboard/src/enterprise/audit-view.tsx](packages/dashboard/src/enterprise/audit-view.tsx).

### T37 Ã¢â‚¬â€ GerÃƒÂ§ek veri akÃ„Â±Ã…Å¸Ã„Â±, redaksiyon ve gizlilik kanÃ„Â±tÃ„Â± (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Privacy verifier canary boyunca source hash kararlÃ„Â±lÃ„Â±Ã„Å¸Ã„Â± ve temp support-bundle izolasyonu istiyor; 6 canary/13 bundle kontrolÃƒÂ¼ geÃƒÂ§ti, hukuk/saha aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Redaksiyon ve tenant ayrÃ„Â±mÃ„Â± bileÃ…Å¸enleri var.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** TÃƒÂ¼m outbound alan/domain listesi, browser tracing, managed olaylar, AIG payloadlarÃ„Â±, region, subprocessors ve silme kanÃ„Â±tÃ„Â± mÃƒÂ¼Ã…Å¸teri metinleriyle onaylanmadÃ„Â±.

**Tamamlanma hedefi:** Alan bazlÃ„Â± data-flow ve egress envanteri ÃƒÂ§Ã„Â±kar; ham prompt/komut/secret canary'leriyle paket/log/export/support bundle sÃƒÂ¶zleÃ…Å¸mesi kur; metinleri gerÃƒÂ§ek iÃ…Å¸leyiÃ…Å¸e eÃ…Å¸le.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Canary sÃ„Â±rlar izinsiz kanalda bulunmasÃ„Â±n; opt-out ve retention davranÃ„Â±Ã…Å¸Ã„Â± ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lsÃƒÂ¼n; bÃƒÂ¼tÃƒÂ¼n veri sÃ„Â±nÃ„Â±flarÃ„Â± iÃƒÂ§in bÃƒÂ¶lge/eriÃ…Å¸im/silme sahibi belli olsun.

**Sorumlu:** Privacy + Security + Engineering. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** DPA ve mÃƒÂ¼Ã…Å¸teri veri sÃ„Â±nÃ„Â±flandÃ„Â±rmasÃ„Â±; hukuk incelemesi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** OBS-01, OBS-03, OBS-06, TEN-01. **Kaynak:** [docs/privacy.md](docs/privacy.md), [packages/core/src/tracing.ts](packages/core/src/tracing.ts), [supabase/functions/ingest/index.ts](supabase/functions/ingest/index.ts).

### T38 Ã¢â‚¬â€ Kuruma ÃƒÂ¶zel DLP ve veri etiketleri (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** DLP overlapping ve JSON Unicode-escaped secret spanlarÃ„Â±nÃ„Â± tam redact ediyor; malformed/mapping/oversize fail-closed. Attachment/diÃ„Å¸er connector/mÃƒÂ¼Ã…Å¸teri label kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** PII/DLP detektÃƒÂ¶rleri ve bazÃ„Â± ÃƒÂ§Ã„Â±ktÃ„Â± kontrolleri var.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** MÃƒÂ¼Ã…Å¸teri etiketleri, belge/attachment tÃƒÂ¼rleri, her baÃ„Å¸layÃ„Â±cÃ„Â±daki giriÃ…Å¸/ÃƒÂ§Ã„Â±kÃ„Â±Ã…Å¸ yolu ve dÃƒÂ¼Ã…Å¸ÃƒÂ¼k yanlÃ„Â±Ã…Å¸ alarm kabulÃƒÂ¼ tamam deÃ„Å¸il.

**Tamamlanma hedefi:** Kural/etiket yÃƒÂ¶netimi, kapsam hedefleri, maskeleme/engelleme/approval eylemleri ve exception yaÃ…Å¸am dÃƒÂ¶ngÃƒÂ¼sÃƒÂ¼nÃƒÂ¼ baÃ„Å¸la.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Sentetik ve kuruma ÃƒÂ¶zgÃƒÂ¼ sÃ„Â±rlar tÃƒÂ¼m kapsanan giriÃ…Å¸/ÃƒÂ§Ã„Â±kÃ„Â±Ã…Å¸larda yakalansÃ„Â±n; yetkili benign iÃ…Å¸lem geÃƒÂ§sin; ÃƒÂ¶rnek dÃ„Â±Ã…Å¸Ã„Â± format unavailable olarak raporlansÃ„Â±n.

**Sorumlu:** Detection + Customer Security. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Etiket/kural sÃƒÂ¶zlÃƒÂ¼Ã„Å¸ÃƒÂ¼ ve maskelenmiÃ…Å¸ test verisi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DET-07. **Kaynak:** [packages/core/src/dlp/index.ts](packages/core/src/dlp/index.ts), [packages/core/src/pii-detector.ts](packages/core/src/pii-detector.ts).

### T39 Ã¢â‚¬â€ BaÃ„Å¸Ã„Â±msÃ„Â±z etkinlik, performans ve rakip kÃ„Â±yaslamasÃ„Â± (P1)

**Durum:** OPEN. **BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Pazar yetenek kategorileri ve ÃƒÂ¶nerilen benchmark protokolÃƒÂ¼ belgeli.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** En iyi ÃƒÂ¼rÃƒÂ¼n, sÃ„Â±fÃ„Â±r false-positive, evasion dayanÃ„Â±klÃ„Â±lÃ„Â±Ã„Å¸Ã„Â± veya latency ÃƒÂ¼stÃƒÂ¼nlÃƒÂ¼Ã„Å¸ÃƒÂ¼nÃƒÂ¼ gÃƒÂ¶steren baÃ„Å¸Ã„Â±msÃ„Â±z kanÃ„Â±t yok.

**Tamamlanma hedefi:** GeliÃ…Å¸tirme ve blind holdout setlerini ayÃ„Â±r; saldÃ„Â±rÃ„Â± ailesi/baÃ„Å¸layÃ„Â±cÃ„Â± bazÃ„Â±nda coverage, false block/approval, p50/p95/p99 ve limitations ÃƒÂ¶lÃƒÂ§; eÃ…Å¸it koÃ…Å¸ullu karÃ…Å¸Ã„Â±laÃ…Å¸tÃ„Â±rma yap.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** AynÃ„Â± workload/ortamda ham ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m, payda, sÃƒÂ¼rÃƒÂ¼m, ÃƒÂ¶rneklem ve baÃ„Å¸Ã„Â±msÃ„Â±z deÃ„Å¸erlendirici imzasÃ„Â±; gÃƒÂ¶rÃƒÂ¼nmeyen yÃƒÂ¼zeyler baÃ…Å¸arÃ„Â± ortalamasÃ„Â±na katÃ„Â±lmasÃ„Â±n.

**Sorumlu:** Detection Research + QA + Independent Evaluator. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** MÃƒÂ¼Ã…Å¸teri benign corpus'u, rakip deÃ„Å¸erlendirme eriÃ…Å¸imi, ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m bÃƒÂ¼tÃƒÂ§esi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** EVAL-01, EVAL-02, EVAL-03. **Kaynak:** [docs/production-readiness/agent-security-market-and-release-plan.md](docs/production-readiness/agent-security-market-and-release-plan.md), [docs/production-readiness/customer-investor-validation-master-plan.md](docs/production-readiness/customer-investor-validation-master-plan.md).

### T40 Ã¢â‚¬â€ GÃƒÂ¼venlik gÃƒÂ¼ncellemesi ve mÃƒÂ¼Ã…Å¸teri destek iÃ…Å¸letimi (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Support v7 runbook, izinli/hashli bundle, escalation ve emergency update akÃ„Â±Ã…Å¸Ã„Â± hazÃ„Â±r; gerÃƒÂ§ek kanal, nÃƒÂ¶bet ve ticket tatbikatÃ„Â± aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Runbook ve destek Ã…Å¸ablonlarÃ„Â± bulunuyor.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Ãƒâ€¡alÃ„Â±Ã…Å¸an ticket/security contact, nÃƒÂ¶bet, CVE/incident bildirimi, imzalÃ„Â± acil gÃƒÂ¼ncelleme, EOL ve tanÃ„Â±lama izni iÃ…Å¸letimi onaylÃ„Â± deÃ„Å¸il.

**Tamamlanma hedefi:** Destek planÃ„Â±, severity/response hedefi, escalation, PSIRT/sorumlu, patch daÃ„Å¸Ã„Â±tÃ„Â±mÃ„Â±, EOL ve redakte tanÃ„Â±lama prosedÃƒÂ¼rÃƒÂ¼ kur.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** GerÃƒÂ§ek ticket aÃƒÂ§/kapat, kritik incident ve imza anahtarÃ„Â± kaybÃ„Â± tatbikatÃ„Â±; mÃƒÂ¼Ã…Å¸teri bildirim sÃƒÂ¼resi, rollback ve sÃ„Â±r iÃƒÂ§ermeyen tanÃ„Â±lama kanÃ„Â±tlansÃ„Â±n.

**Sorumlu:** Support + SRE + Security. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Ã„Â°simli ekip, iletiÃ…Å¸im kanallarÃ„Â±, sÃƒÂ¶zleÃ…Å¸me ve ÃƒÂ§alÃ„Â±Ã…Å¸ma saatleri.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** DEP-05, OBS-05. **Kaynak:** [docs/runbooks/incident-response.md](docs/runbooks/incident-response.md), [docs/production-readiness/support-sla-template.md](docs/production-readiness/support-sla-template.md).

### T41 Ã¢â‚¬â€ Ã„Â°lk mÃƒÂ¼Ã…Å¸teri satÃ„Â±Ã…Å¸ ve satÃ„Â±n alma deÃ„Å¸erlendirme paketi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** GÃƒÂ¼ncel ilk mÃƒÂ¼Ã…Å¸teri satÃ„Â±Ã…Å¸ paketi ve portable kit ÃƒÂ¼reticisi var; yeni v7 kit imzasÃ„Â± ile onaylÃ„Â± teklif/satÃ„Â±n alma kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** KontrollÃƒÂ¼ demo, deÃ„Å¸erlendirme planÃ„Â±, ilk kurulum ve sipariÃ…Å¸ Ã…Å¸ablonlarÃ„Â± mevcut.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** MÃƒÂ¼Ã…Å¸terinin satÃ„Â±n alma sÃƒÂ¼recine uygun onaylÃ„Â± ÃƒÂ¼rÃƒÂ¼n ÃƒÂ¶zeti, mimari/veri akÃ„Â±Ã…Å¸Ã„Â±, destek matrisi, gÃƒÂ¼venlik soru formu, kapsamlÃ„Â± teklif ve kanÃ„Â±ta dayalÃ„Â± demo/PoV paketi tek sÃƒÂ¼rÃƒÂ¼mde birleÃ…Å¸tirilmedi. Bu ÃƒÂ§alÃ„Â±Ã…Å¸ma ortamÃ„Â±ndaki static preflight satÃ„Â±Ã…Å¸ URL/e-posta ayarÃ„Â± bulamadÃ„Â±; ÃƒÂ¼retim satÃ„Â±Ã…Å¸ CTA hedefi ayrÃ„Â±ca doÃ„Å¸rulanmalÃ„Â±.

**Tamamlanma hedefi:** ÃƒÅ“rÃƒÂ¼n ÃƒÂ¶zeti, gereksinimler, deployment seÃƒÂ§enekleri, desteklenen araÃƒÂ§lar, aÃƒÂ§Ã„Â±k sÃ„Â±nÃ„Â±rlar, gÃƒÂ¼venlik/tedarikÃƒÂ§i soru yanÃ„Â±tlarÃ„Â±, teklif ve PoV baÃ…Å¸arÃ„Â± ÃƒÂ¶lÃƒÂ§ÃƒÂ¼tlerini satÃ„Â±Ã…Å¸ kitinde topla; ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lmemiÃ…Å¸ ROI veya sertifikasyon iddiasÃ„Â± ekleme.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Bir operatÃƒÂ¶r kÃ„Â±lavuzdan demoyu tekrar edebilsin; procurement sorularÃ„Â± kaynak/kanÃ„Â±t/owner'a baÃ„Å¸lÃ„Â± olsun; teklif kapsamÃ„Â± ile kurulan ÃƒÂ¶zellik ve destek koÃ…Å¸ullarÃ„Â± eÃ…Å¸leÃ…Å¸sin; mÃƒÂ¼Ã…Å¸teri adÃ„Â± olmadan referans/baÃ…Å¸arÃ„Â± hikayesi uydurulmasÃ„Â±n.

**Sorumlu:** Sales Engineering + Product + Legal + Finance. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** MÃƒÂ¼Ã…Å¸teri satÃ„Â±n alma formu, teklif sahibi, onaylÃ„Â± ÃƒÂ¼rÃƒÂ¼n kapsamÃ„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** EVAL-02, EVAL-03, BIL-01. **Kaynak:** [docs/production-readiness/controlled-demo-runbook.md](docs/production-readiness/controlled-demo-runbook.md), [docs/production-readiness/customer-investor-validation-master-plan.md](docs/production-readiness/customer-investor-validation-master-plan.md), [docs/production-readiness/enterprise-order-entitlement-template.md](docs/production-readiness/enterprise-order-entitlement-template.md).

### T42 Ã¢â‚¬â€ Legacy RLS tenant yaÃ…Å¸am dÃƒÂ¶ngÃƒÂ¼sÃƒÂ¼ ve itibar satÃ„Â±rÃ„Â± sahteciliÃ„Å¸i (P0)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Eski izin verici RLS kaldÃ„Â±rÃ„Â±ldÃ„Â±; forged claim, expired member, suspended tenant ve service-role kontrolleri yerel PostgreSQL'de geÃƒÂ§ti. Saha migrationÃ„Â± aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Eski izin verici RLS kurallarÃ„Â± yabancÃ„Â± tenant itibar satÃ„Â±rÃ„Â± ekleme ve ÃƒÂ¼yelik sonrasÃ„Â± eriÃ…Å¸ime izin veriyordu.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Yeni migration yetkiyi kapatÃ„Â±r; ÃƒÂ¶nceden yazÃ„Â±lmÃ„Â±Ã…Å¸ olabilecek sahte satÃ„Â±rlar otomatik temizlenmez ve kurulu mÃƒÂ¼Ã…Å¸teri verisi denetlenmedi.

**Tamamlanma hedefi:** MigrationÃ„Â± uygulamadan ÃƒÂ¶nce tenant itibar satÃ„Â±rlarÃ„Â±nÃ„Â± denetle; migrationÃ„Â± kontrollÃƒÂ¼ uygula, kalÃ„Â±cÃ„Â± rol matrisi ve PostgREST negatif testini ÃƒÂ§alÃ„Â±Ã…Å¸tÃ„Â±r.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Eski ÃƒÂ¼ye veya askÃ„Â±ya alÃ„Â±nmÃ„Â±Ã…Å¸ tenant okuyamasÃ„Â±n; baÃ…Å¸ka tenant iÃƒÂ§in insert reddedilsin; mevcut veride sahte kayÃ„Â±t kalmasÃ„Â±n ve servis rolÃƒÂ¼ iÃ…Å¸lemleri ÃƒÂ§alÃ„Â±Ã…Å¸sÃ„Â±n.

**Sorumlu:** Database + Security. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Mevcut deployment verisi ve migration penceresi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** TEN-01, DET-10, DET-11. **Kaynak:** [supabase/migrations/20260912000019_tenant_lifecycle_rls.sql](supabase/migrations/20260912000019_tenant_lifecycle_rls.sql), [scripts/tenant-lifecycle-rls-postgres.test.mjs](scripts/tenant-lifecycle-rls-postgres.test.mjs).

### T43 Ã¢â‚¬â€ Enrollment exchange iÃ…Å¸lem bÃƒÂ¼tÃƒÂ¼nlÃƒÂ¼Ã„Å¸ÃƒÂ¼ (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Atomik token/seat/key RPC ve lost-response sonucu unknown sÃƒÂ¶zleÃ…Å¸mesi var; plaintext-key recovery protokolÃƒÂ¼ ve canlÃ„Â± HTTP kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Tek kullanÃ„Â±mlÃ„Â±k token ÃƒÂ¶nceden tÃƒÂ¼ketilip sonraki adÃ„Â±m hata verince kurulum kilitlenebiliyordu.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Yeni RPC atomik yazÃ„Â±yor; mÃƒÂ¼Ã…Å¸teri HTTP akÃ„Â±Ã…Å¸Ã„Â±nda kayÃ„Â±p yanÃ„Â±t, eski kayÃ„Â±t ve eÃ…Å¸zamanlÃ„Â± seat yarÃ„Â±Ã…Å¸Ã„Â± henÃƒÂ¼z sÃ„Â±nanmadÃ„Â±.

**Tamamlanma hedefi:** MigrationÃ„Â± daÃ„Å¸Ã„Â±t, canlÃ„Â± HTTP hata enjeksiyonuyla token/seat/key durumunu doÃ„Å¸rula, belirsiz commit sonrasÃ„Â± yeniden kayÃ„Â±t operatÃƒÂ¶r prosedÃƒÂ¼rÃƒÂ¼nÃƒÂ¼ hazÃ„Â±rla.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Hata rollback yaparken token yeniden kullanÃ„Â±labilsin; baÃ…Å¸arÃ„Â±da yalnÃ„Â±z bir kimlik oluÃ…Å¸sun; kayÃ„Â±p yanÃ„Â±t aÃƒÂ§Ã„Â±k unknown durumuna dÃƒÂ¼Ã…Å¸sÃƒÂ¼n.

**Sorumlu:** Identity + Backend. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** MÃƒÂ¼Ã…Å¸teri kurulum ortamÃ„Â± ve canlÃ„Â± DB.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** TEN-05, TEN-06. **Kaynak:** [supabase/migrations/20260912000017_enrollment_exchange_atomic.sql](supabase/migrations/20260912000017_enrollment_exchange_atomic.sql), [supabase/functions/enroll/index.ts](supabase/functions/enroll/index.ts).

### T44 Ã¢â‚¬â€ Entitlement grace ve eski imzalÃ„Â± ÃƒÂ¶nbellek geÃƒÂ§iÃ…Å¸i (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Cache unsigned/unknown/schema-invalid entitlement'Ã„Â± atÃ„Â±yor; kesin invalid_api_key signed state'i temizliyor, geÃƒÂ§ici hata grace'i koruyor. CanlÃ„Â± kabul aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Yedi gÃƒÂ¼nlÃƒÂ¼k entitlement bitiÃ…Å¸inden sonraki 72 saatlik grace yanlÃ„Â±Ã…Å¸ hesaplanÃ„Â±yordu.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Kod dÃƒÂ¼zeltildi; ÃƒÂ¶nceki yanlÃ„Â±Ã…Å¸ imzalÃ„Â± snapshotlar ÃƒÂ§evrimdÃ„Â±Ã…Å¸Ã„Â± iken dÃƒÂ¼zelmez, canlÃ„Â± Deno ve zaman geÃƒÂ§iÃ…Å¸i kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**Tamamlanma hedefi:** Yeni entitlementlarÃ„Â± daÃ„Å¸Ã„Â±tÃ„Â±p ÃƒÂ¶nbelleÃ„Å¸i gÃƒÂ¼venli yenile; saat sÃ„Â±nÃ„Â±rÃ„Â± ve eski istemci geÃƒÂ§iÃ…Å¸i tatbikatÃ„Â± yap.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** 168 saat sonrasÃ„Â±nda 72 saat grace, ardÃ„Â±ndan deny; iptal edilen/bozuk anahtar her aÃ…Å¸amada reddedilsin.

**Sorumlu:** Identity + Endpoint. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** Ã„Â°mzalÃ„Â± eski kayÃ„Â±tlar ve mÃƒÂ¼Ã…Å¸teri aÃ„Å¸ takvimi.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** TEN-05, POL-04. **Kaynak:** [supabase/functions/enroll/index.ts](supabase/functions/enroll/index.ts), [supabase/functions/ingest/index.ts](supabase/functions/ingest/index.ts), [packages/core/src/managed.ts](packages/core/src/managed.ts).

### T45 Ã¢â‚¬â€ Device-start gÃƒÂ¼venilir IP ve giriÃ…Å¸ yÃƒÂ¶nlendirmesi (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Device-start signer placeholder/reused secret'i reddediyor; HMAC ingress/rate limit var. GerÃƒÂ§ek public proxy/TLS routing ve mÃƒÂ¼Ã…Å¸teri yÃƒÂ¼kÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Ã„Â°stemcinin verdiÃ„Å¸i IP baÃ…Å¸lÃ„Â±Ã„Å¸Ã„Â±yla 30/dakika sÃ„Â±nÃ„Â±rÃ„Â± aÃ…Å¸Ã„Â±labiliyordu.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Ã„Â°mzalÃ„Â± ingress ve kÃƒÂ¼resel sÃ„Â±nÃ„Â±r kodlandÃ„Â±; Nginx/TLS yÃƒÂ¶nlendirmesi ve iki ÃƒÂ¶zel anahtarÃ„Â±n mÃƒÂ¼Ã…Å¸teri ortamÃ„Â±nda kurulumu henÃƒÂ¼z kanÃ„Â±tlanmadÃ„Â±.

**Tamamlanma hedefi:** Cloud ve self-hosted giriÃ…Å¸ini signer ÃƒÂ¼zerinden geÃƒÂ§ir; proxy baÃ…Å¸lÃ„Â±klarÃ„Â±nÃ„Â± temizle, doÃ„Å¸rudan Edge yolunu engelle ve yÃƒÂ¼k testini ÃƒÂ§alÃ„Â±Ã…Å¸tÃ„Â±r.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Sahte baÃ…Å¸lÃ„Â±klar oranÃ„Â± deÃ„Å¸iÃ…Å¸tirmesin; imzasÃ„Â±z istek 401; meÃ…Å¸ru kayÃ„Â±t akÃ„Â±Ã…Å¸Ã„Â± iki daÃ„Å¸Ã„Â±tÃ„Â±m modelinde ÃƒÂ§alÃ„Â±Ã…Å¸sÃ„Â±n.

**Sorumlu:** Platform + Identity. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** TLS proxy, sÃ„Â±r yÃƒÂ¶netimi ve mÃƒÂ¼Ã…Å¸teri aÃ„Å¸Ã„Â±.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** TEN-05, DEP-01, DEP-02. **Kaynak:** [supabase/functions/device-start/index.ts](supabase/functions/device-start/index.ts), [deploy/ingress/device-start.mjs](deploy/ingress/device-start.mjs).

### T46 Ã¢â‚¬â€ Device-poll onaydan kayda atomik geÃƒÂ§iÃ…Å¸ (P1)

**Durum:** LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN. **Mevcut yerel uygulama:** Device-poll kayÃ„Â±p yanÃ„Â±t/eÃ…Å¸zamanlÃ„Â± poll'da aynÃ„Â± hash-only tokenÃ„Â± geri buluyor, lookup hatasÃ„Â±nda 503 unknown dÃƒÂ¶nÃƒÂ¼yor; canlÃ„Â± yarÃ„Â±Ã…Å¸ kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ durumu:** Onaylanan oturum token eklenmeden exchanged olabiliyor, geÃƒÂ§ici hata kullanÃ„Â±cÃ„Â±yÃ„Â± yeniden kurulum baÃ…Å¸latmaya zorluyordu.

**BaÃ…Å¸langÃ„Â±ÃƒÂ§ boÃ…Å¸luÃ„Å¸u / mÃƒÂ¼Ã…Å¸teri etkisi:** Yeni RPC atomik; canlÃ„Â± HTTP retry, yarÃ„Â±Ã…Å¸ ve mÃƒÂ¼Ã…Å¸teri tarayÃ„Â±cÃ„Â±sÃ„Â±/CLI kabulÃƒÂ¼ aÃƒÂ§Ã„Â±k.

**Tamamlanma hedefi:** MigrationÃ„Â± daÃ„Å¸Ã„Â±tÃ„Â±p onay, poll ve enroll tam akÃ„Â±Ã…Å¸Ã„Â±nÃ„Â± hata enjeksiyonu ile ÃƒÂ§alÃ„Â±Ã…Å¸tÃ„Â±r; eÃ…Å¸zamanlÃ„Â± poll ve kayÃ„Â±p yanÃ„Â±tÃ„Â± ÃƒÂ¶lÃƒÂ§.

**Kalan kapanÃ„Â±Ã…Å¸ testi:** Bir onay en ÃƒÂ§ok bir token ÃƒÂ¼retir; insert hatasÃ„Â± oturumu tÃƒÂ¼ketmez; tekrar poll belirsiz durum olarak raporlanÃ„Â±r.

**Sorumlu:** Identity + QA. **BaÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k:** CanlÃ„Â± kurulum ve gerÃƒÂ§ek cihaz.

**Ã„Â°liÃ…Å¸kili ÃƒÂ¶zellikler:** TEN-05. **Kaynak:** [supabase/functions/device-poll/index.ts](supabase/functions/device-poll/index.ts), [supabase/migrations/20260912000017_enrollment_exchange_atomic.sql](supabase/migrations/20260912000017_enrollment_exchange_atomic.sql).

## Ticari, dÃ„Â±Ã…Å¸ deÃ„Å¸erlendirme ve mÃƒÂ¼Ã…Å¸teri kabul kapÃ„Â±larÃ„Â±

AÃ…Å¸aÃ„Å¸Ã„Â±dakiler mevcut ticari registry'nin aÃƒÂ§Ã„Â±k kayÃ„Â±tlarÃ„Â±dÃ„Â±r. DokÃƒÂ¼man Ã…Å¸ablonu bulunmasÃ„Â±, yetkili onayÃ„Â± veya ÃƒÂ§alÃ„Â±Ã…Å¸an operasyon sayÃ„Â±lmaz. Hukuki metin ve sÃƒÂ¶zleÃ…Å¸melerin geÃƒÂ§erliliÃ„Å¸ini bu rapor onaylamaz; ilgili kurum sahipleri incelemelidir.

### COM-001 Ã¢â‚¬â€ OnaylÃ„Â± SKU, fiyat, teklif ve ticari sÃƒÂ¼rÃƒÂ¼m manifesti

**Durum:** open. **GeÃƒÂ§erli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** AynÃ„Â± sÃƒÂ¼rÃƒÂ¼me baÃ„Å¸lÃ„Â± SKU, fiyat, ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m birimi, para birimi/vergi, kurulum modeli, bÃƒÂ¶lge, saklama, SLA, destek, lisans hakkÃ„Â±, yenileme, iptal ve ÃƒÂ§Ã„Â±kÃ„Â±Ã…Å¸ koÃ…Å¸ullarÃ„Â± onaylanmamÃ„Â±Ã…Å¸.

**YapÃ„Â±lacak iÃ…Å¸:** SatÃ„Â±Ã…Å¸ ve finans tek ticari manifesti onaylasÃ„Â±n; ÃƒÂ¶rnek teklif/sipariÃ…Å¸ten mÃƒÂ¼Ã…Å¸teri ÃƒÂ§Ã„Â±kÃ„Â±Ã…Å¸Ã„Â±na kadar prova yapÃ„Â±lsÃ„Â±n.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** Ã„Â°simli onaylÃ„Â± ticari manifest; Ãƒâ€“rnek teklif ve sipariÃ…Å¸; SipariÃ…Å¸ten offboarding'e prova; SÃƒÂ¼rÃƒÂ¼m ve deÃ„Å¸iÃ…Å¸tirilemeyen kanÃ„Â±t ÃƒÂ¶zeti.

**Sorumlu:** Commercial/Sales + Finance/Billing. **Kontrol:** claim-check --mode=gate plus signed-manifest verification.

### COM-002 Ã¢â‚¬â€ Lisans, fikri mÃƒÂ¼lkiyet ve ÃƒÂ¼ÃƒÂ§ÃƒÂ¼ncÃƒÂ¼ taraf haklarÃ„Â±

**Durum:** open. **GeÃƒÂ§erli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** Lisans dosyasÃ„Â± bulunmasÃ„Â± yeterli deÃ„Å¸il: daÃ„Å¸Ã„Â±tÃ„Â±lan kod/veri/model/ÃƒÂ¼ÃƒÂ§ÃƒÂ¼ncÃƒÂ¼ taraf bileÃ…Å¸en haklarÃ„Â±, atÃ„Â±flar ve fikri mÃƒÂ¼lkiyet zinciri hukukÃƒÂ§a onaylanmamÃ„Â±Ã…Å¸.

**YapÃ„Â±lacak iÃ…Å¸:** SBOM ve kaynak kÃƒÂ¶kenini lisans/NOTICE/package metadata ile uzlaÃ…Å¸tÃ„Â±r; daÃ„Å¸Ã„Â±tÃ„Â±m haklarÃ„Â±nÃ„Â± ve sÃƒÂ¼reli istisnalarÃ„Â± yetkili hukuk incelemesine sun.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** Hukuk onayÃ„Â±; Eksiksiz LICENSE/NOTICE ve ÃƒÂ¼ÃƒÂ§ÃƒÂ¼ncÃƒÂ¼ taraf lisans paketi; Paket lisanslarÃ„Â±nÃ„Â±n uzlaÃ…Å¸tÃ„Â±rÃ„Â±lmasÃ„Â±; Kaynak/vendor kÃƒÂ¶keni ve sÃƒÂ¼reli istisna kaydÃ„Â±.

**Sorumlu:** Legal + Engineering. **Kontrol:** claim-check --mode=gate (license/NOTICE/package metadata check) plus licence inventory.

### COM-003 Ã¢â‚¬â€ Veri iÃ…Å¸leme, DPA ve gizlilik onayÃ„Â±

**Durum:** open. **GeÃƒÂ§erli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** GerÃƒÂ§ek telemetri, browser tracing, managed olaylar, AIG payloadlarÃ„Â±, retention/silme, veri bÃƒÂ¶lgesi, alt iÃ…Å¸leyenler ve transferler mÃƒÂ¼Ã…Å¸teri belgeleriyle onaylÃ„Â± biÃƒÂ§imde eÃ…Å¸leÃ…Å¸tirilmemiÃ…Å¸.

**YapÃ„Â±lacak iÃ…Å¸:** Alan bazlÃ„Â± veri akÃ„Â±Ã…Å¸Ã„Â±nÃ„Â± ÃƒÂ¶lÃƒÂ§; mÃƒÂ¼Ã…Å¸teri bildirimi ve gerekli veri iÃ…Å¸leme/gÃƒÂ¼venlik eklerini Privacy/Legal sahipleriyle tamamla.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** Alan bazlÃ„Â± veri akÃ„Â±Ã…Å¸ matrisi ve payload testleri; DPA/TOM/SCC kapsam inceleme ve onayÃ„Â±; Alt iÃ…Å¸leyen/bÃƒÂ¶lge listesi; GerÃƒÂ§ek export ve silme makbuzu.

**Sorumlu:** Privacy/DPO + Legal + Security. **Kontrol:** privacy-payload-contract and outbound-domain/redaction gates.

### COM-004 Ã¢â‚¬â€ FaturaÃ¢â‚¬â€œÃƒÂ¶demeÃ¢â‚¬â€œentitlement mutabakatÃ„Â±

**Durum:** open. **GeÃƒÂ§erli profiller:** assisted-sale, production-ga, investor.

**Eksik gereksinim:** SipariÃ…Å¸, koltuk deÃ„Å¸iÃ…Å¸imi, fatura/mutabakat, iptal, eriÃ…Å¸im iptali ve mÃƒÂ¼Ã…Å¸teri silme tek kayÃ„Â±t sistemine gÃƒÂ¶re uÃƒÂ§tan uca kabul edilmemiÃ…Å¸.

**YapÃ„Â±lacak iÃ…Å¸:** Tek provider-of-record belirle; finans iÃ…Å¸lemlerini sunucudaki entitlement ile baÃ„Å¸la; baÃ…Å¸arÃ„Â±sÃ„Â±z/tekrarlanan olay ve manuel mÃƒÂ¼dahale iÃ…Å¸letimini tanÃ„Â±mla.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** Provider ve SKU kararÃ„Â±; Quota/entitlement senaryolarÃ„Â±; Fatura ve mutabakat ÃƒÂ¶rneÃ„Å¸i; Ã„Â°ptal, eriÃ…Å¸im kesme ve silme makbuzu.

**Sorumlu:** Finance/Billing + Product. **Kontrol:** billing contract suite and quote-to-offboarding rehearsal.

### COM-005 Ã¢â‚¬â€ Ãƒâ€¡alÃ„Â±Ã…Å¸an destek ve mÃƒÂ¼Ã…Å¸teri iletiÃ…Å¸im yollarÃ„Â±

**Durum:** open. **GeÃƒÂ§erli profiller:** evaluation, assisted-sale, production-ga.

**Eksik gereksinim:** MÃƒÂ¼Ã…Å¸terinin gerÃƒÂ§ekten ulaÃ…Å¸abildiÃ„Å¸i destek, durum sayfasÃ„Â±, gÃƒÂ¼venlik iletiÃ…Å¸imi, privacy/terms, escalation, severity hedefi ve tanÃ„Â±lama izni iÃ…Å¸letimi kanÃ„Â±tlanmamÃ„Â±Ã…Å¸.

**YapÃ„Â±lacak iÃ…Å¸:** KanallarÃ„Â± yayÃ„Â±nla; ÃƒÂ§alÃ„Â±Ã…Å¸ma saatleri ve isimli nÃƒÂ¶bet/escalation sorumlularÃ„Â±nÃ„Â± ata; gerÃƒÂ§ek ticket tatbikatÃ„Â± yap.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** YayÃ„Â±nlanmÃ„Â±Ã…Å¸ destek/SLA planÃ„Â±; Zaman damgalÃ„Â± ticket tatbikatÃ„Â±; Ãƒâ€¡alÃ„Â±Ã…Å¸an status/security/privacy baÃ„Å¸lantÃ„Â±larÃ„Â±; NÃƒÂ¶bet ve escalation kaydÃ„Â±.

**Sorumlu:** Support/Customer Success + Operations. **Kontrol:** deployed route/link crawl; ticket drill is manual evidence.

### COM-010 Ã¢â‚¬â€ ReklamÃ„Â± yapÃ„Â±lan tÃƒÂ¼m baÃ„Å¸layÃ„Â±cÃ„Â±larÃ„Â±n kabulÃƒÂ¼

**Durum:** open. **GeÃƒÂ§erli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** ReklamÃ„Â± yapÃ„Â±lan baÃ„Å¸layÃ„Â±cÃ„Â±larÃ„Â±n her biri iÃƒÂ§in gerÃƒÂ§ek host desteÃ„Å¸i, imzalÃ„Â± paket, ÃƒÂ¶zel registry kurulumu, geri dÃƒÂ¶nÃƒÂ¼Ã…Å¸ ve destek sahibi tamam deÃ„Å¸il. Registry'nin kapsam listesi ayrÃ„Â±ca gÃƒÂ¼ncellenmeli.

**YapÃ„Â±lacak iÃ…Å¸:** SatÃ„Â±lan connector manifestini sabitle; her connector/host/OS sÃƒÂ¼rÃƒÂ¼mÃƒÂ¼nde aynÃ„Â± imzalÃ„Â± candidate iÃƒÂ§in kurulum, native E2E, rollback ve disable kabulÃƒÂ¼ topla.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** Tam destek matrisi; GerÃƒÂ§ek host test raporlarÃ„Â±; Private registry kurulum kayÃ„Â±tlarÃ„Â±; Rollback/disable tatbikatÃ„Â±; Ã„Â°simli sahip ve sÃ„Â±nÃ„Â±rlar.

**Sorumlu:** Product + QA + Engineering + Support. **Kontrol:** expected connector manifest, package consumer tests, real-host E2E and claim-check.

### COM-011 Ã¢â‚¬â€ BÃƒÂ¶lge ve veri yerleÃ…Å¸imi kanÃ„Â±tÃ„Â±

**Durum:** open. **GeÃƒÂ§erli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** Registry'deki EU/US/APAC hedefleri ÃƒÂ§alÃ„Â±Ã…Å¸an ve onaylÃ„Â± bÃƒÂ¶lge hizmeti kanÃ„Â±tÃ„Â± deÃ„Å¸ildir; tenant yerleÃ…Å¸imi, routing, yedek/silme ve transfer modeli aÃƒÂ§Ã„Â±k.

**YapÃ„Â±lacak iÃ…Å¸:** SatÃ„Â±lacak bÃƒÂ¶lgeleri provider ve veri iÃ…Å¸leme modeliyle eÃ…Å¸le; her bÃƒÂ¶lgede tenant yerleÃ…Å¸imi ve sÃ„Â±nÃ„Â±r dÃ„Â±Ã…Å¸Ã„Â± eriÃ…Å¸im negatif testlerini tamamla.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** BÃƒÂ¶lge/provider matrisi; Tenant yerleÃ…Å¸im testi; Cross-region negatif test; Veri iÃ…Å¸leme onaylarÃ„Â±; BÃƒÂ¶lgeye baÃ„Å¸lÃ„Â± yedek/silme makbuzlarÃ„Â±.

**Sorumlu:** Operations + Privacy/DPO + Legal. **Kontrol:** region manifest, outbound-domain/data-flow assertions and deployment smoke per region.

### COM-012 Ã¢â‚¬â€ FaturalÃ„Â± ve kimliÃ„Å¸i doÃ„Å¸rulanan ÃƒÂ¶zel daÃ„Å¸Ã„Â±tÃ„Â±m

**Durum:** open. **GeÃƒÂ§erli profiller:** assisted-sale, production-ga, investor.

**Eksik gereksinim:** Kurumsal fatura ile verilen eriÃ…Å¸imin kimliÃ„Å¸i doÃ„Å¸rulanan private registry ve imzalÃ„Â± artefact teslimiyle ÃƒÂ§alÃ„Â±Ã…Å¸tÃ„Â±Ã„Å¸Ã„Â± kanÃ„Â±tlanmamÃ„Â±Ã…Å¸; air-gap prosedÃƒÂ¼rÃƒÂ¼ de tamam deÃ„Å¸il.

**YapÃ„Â±lacak iÃ…Å¸:** SipariÃ…Å¸Ã¢â€ â€™entitlementÃ¢â€ â€™downloadÃ¢â€ â€™installÃ¢â€ â€™revoke/offboard zincirini gerÃƒÂ§ek mÃƒÂ¼Ã…Å¸teri eriÃ…Å¸im modeliyle tamamla; offline satÃ„Â±lÃ„Â±yorsa imaj/baÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±k teslimini ekle.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** Provider ve registry kararÃ„Â±; Faturadan entitlement'a test; Ã„Â°mzalÃ„Â± paket kurulumu; Ã„Â°ptal/offboarding testi; DoÃ„Å¸rulanmÃ„Â±Ã…Å¸ air-gap prosedÃƒÂ¼rÃƒÂ¼.

**Sorumlu:** Finance/Billing + Release Engineering + Support. **Kontrol:** private-registry consumer install and entitlement contract suite.

### COM-013 Ã¢â‚¬â€ 99.9% SLA iÃƒÂ§in ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m ve sÃƒÂ¶zleÃ…Å¸me

**Durum:** open. **GeÃƒÂ§erli profiller:** assisted-sale, production-ga, investor.

**Eksik gereksinim:** 99.9% aylÃ„Â±k availability bir hedef; ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lmÃƒÂ¼Ã…Å¸ SLI, payda, kapsam dÃ„Â±Ã…Å¸Ã„Â± durumlar, bakÃ„Â±m politikasÃ„Â±, servis kredisi ve incident kanÃ„Â±tÃ„Â± tamam deÃ„Å¸il.

**YapÃ„Â±lacak iÃ…Å¸:** SRE/Legal/Support/Finance ÃƒÂ¶lÃƒÂ§ÃƒÂ¼m ve sÃƒÂ¶zleÃ…Å¸me kapsamÃ„Â±nÃ„Â± onaylasÃ„Â±n; kabul edilen gÃƒÂ¶zlem penceresinde veriyi topla ve incident tatbikatÃ„Â± yap.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** OnaylÃ„Â± SLA ve destek planÃ„Â±; SLI tanÃ„Â±mÃ„Â±, payda ve gÃƒÂ¶zlem penceresi; BakÃ„Â±m ve kapsam dÃ„Â±Ã…Å¸Ã„Â± durumlar; Servis kredisi koÃ…Å¸ullarÃ„Â±; Incident kanÃ„Â±tÃ„Â±.

**Sorumlu:** Operations + Legal + Support + Finance. **Kontrol:** monthly SLI/error-budget report and SLA manifest check.

### SEC-EXT-001 Ã¢â‚¬â€ BaÃ„Å¸Ã„Â±msÃ„Â±z gÃƒÂ¼venlik deÃ„Å¸erlendirmesi ve yeniden test

**Durum:** open. **GeÃƒÂ§erli profiller:** assisted-sale, production-ga, investor.

**Eksik gereksinim:** SatÃ„Â±lan candidate iÃƒÂ§in baÃ„Å¸Ã„Â±msÃ„Â±z gÃƒÂ¼venlik deÃ„Å¸erlendirmesi, bulgu giderme ve yeniden test raporu yok.

**YapÃ„Â±lacak iÃ…Å¸:** BaÃ„Å¸Ã„Â±msÃ„Â±z deÃ„Å¸erlendiriciyle scope/tarih belirle; tenant, kimlik, runtime, daÃ„Å¸Ã„Â±tÃ„Â±m ve sÃ„Â±r sÃ„Â±nÃ„Â±rlarÃ„Â±nÃ„Â± kapsa; bulgularÃ„Â± kapat ve yeniden test ettir.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** Ã„Â°mzalÃ„Â± baÃ„Å¸Ã„Â±msÃ„Â±z rapor ve kapsam; Remediation/retest mektubu; Ãƒâ€¡ÃƒÂ¶zÃƒÂ¼lmemiÃ…Å¸ kritik bulgu olmamasÃ„Â±; YÃƒÂ¼ksek bulgularda registry'nin gerektirdiÃ„Å¸i gerekÃƒÂ§eli isimli ve sÃƒÂ¼reli kabul.

**Sorumlu:** Security Lead + independent assessor. **Kontrol:** assessment evidence expiry/RC match check.

### POV-001 Ã¢â‚¬â€ Ã„Â°simli mÃƒÂ¼Ã…Å¸teri PoV ve kabul kaydÃ„Â±

**Durum:** open. **GeÃƒÂ§erli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** Ã„Â°simli mÃƒÂ¼Ã…Å¸teri/deÃ„Å¸erlendirici aynÃ„Â± candidate ÃƒÂ¼zerinde zorunlu senaryolarÃ„Â± ve sÃ„Â±nÃ„Â±rlarÃ„Â± inceleyerek kabul vermedi.

**YapÃ„Â±lacak iÃ…Å¸:** DeÃ„Å¸erlendirme sÃƒÂ¶zleÃ…Å¸mesi/charter, baÃ„Å¸Ã„Â±msÃ„Â±z sandbox, zorunlu testler ve mÃƒÂ¼dahale/sapma kaydÃ„Â±nÃ„Â± tamamla; mÃƒÂ¼Ã…Å¸terinin kabul/ÃƒÂ§ekincelerini kaydet.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** Ã„Â°mzalÃ„Â± charter; BaÃ„Å¸Ã„Â±msÃ„Â±z koÃ…Å¸u raporu; MÃƒÂ¼dahale ve sapma gÃƒÂ¼nlÃƒÂ¼Ã„Å¸ÃƒÂ¼; MÃƒÂ¼Ã…Å¸terinin kabul/ÃƒÂ§ekinceleri; DeÃ„Å¸iÃ…Å¸tirilemeyen kanÃ„Â±t indeksi.

**Sorumlu:** Customer Success + Product + evaluator. **Kontrol:** expected-suite manifest and evidence-index completeness; acceptance is manual.

### INV-001 Ã¢â‚¬â€ YatÃ„Â±rÃ„Â±mcÃ„Â± metriklerinin kanÃ„Â±t ve onay sÃƒÂ¶zlÃƒÂ¼Ã„Å¸ÃƒÂ¼

**Durum:** open. **GeÃƒÂ§erli profiller:** investor.

**Eksik gereksinim:** YatÃ„Â±rÃ„Â±mcÃ„Â±ya sunulan teknik baÃ…Å¸arÃ„Â±, mÃƒÂ¼Ã…Å¸teri, gÃƒÂ¼venlik, uyum, traction ve finans ÃƒÂ¶lÃƒÂ§ÃƒÂ¼lerinin tamamÃ„Â± formÃƒÂ¼l/payda/kaynak/dÃƒÂ¶nem/sÃƒÂ¼rÃƒÂ¼m/onay sahibiyle kayÃ„Â±tlÃ„Â± deÃ„Å¸il. Bu kapÃ„Â± yatÃ„Â±rÃ„Â±mcÃ„Â± profili iÃƒÂ§indir.

**YapÃ„Â±lacak iÃ…Å¸:** Her metriÃ„Å¸i veri sorgusuna veya imzalÃ„Â± kaynaÃ„Å¸a baÃ„Å¸la; ÃƒÂ¶rneklem, dÃƒÂ¶nem, sÃ„Â±nÃ„Â±r ve belirsizliÃ„Å¸i yaz; Product/Finance/Legal incelemesi al.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** OnaylÃ„Â± metrik sÃƒÂ¶zlÃƒÂ¼Ã„Å¸ÃƒÂ¼; Kaynak sorgu veya imzalÃ„Â± belge; DÃƒÂ¶nem/ÃƒÂ¶rneklem/payda; Ã„Â°nceleyen kiÃ…Å¸i onayÃ„Â±.

**Sorumlu:** Product + Finance + Legal. **Kontrol:** metric dictionary/evidence-index completeness.

### CLM-001 Ã¢â‚¬â€ MÃƒÂ¼Ã…Å¸teri ve satÃ„Â±Ã…Å¸ iddialarÃ„Â±nÃ„Â±n kanÃ„Â±t onayÃ„Â±

**Durum:** open. **GeÃƒÂ§erli profiller:** evaluation, assisted-sale, production-ga, investor.

**Eksik gereksinim:** Landing, README, plugin, teklif, procurement ve yatÃ„Â±rÃ„Â±mcÃ„Â± metinlerinin tamamÃ„Â± onaylÃ„Â±, gÃƒÂ¼ncel ve aynÃ„Â± sÃƒÂ¼rÃƒÂ¼me baÃ„Å¸lÃ„Â± iddia kanÃ„Â±tÃ„Â±yla eÃ…Å¸lenmiÃ…Å¸ deÃ„Å¸il.

**YapÃ„Â±lacak iÃ…Å¸:** Her iddiayÃ„Â± Claim Registry'ye baÃ„Å¸la; kaynak ve derlenmiÃ…Å¸ yÃƒÂ¼zeyleri tara; yalnÃ„Â±z sÃƒÂ¼resi geÃƒÂ§memiÃ…Å¸ Sales Approved ifadeleri yayÃ„Â±nla.

**Kapatmak iÃƒÂ§in gerekli somut kanÃ„Â±t:** Registry snapshot; DerlenmiÃ…Å¸ ÃƒÂ§Ã„Â±ktÃ„Â± tarama JSON'u; Ã„Â°ddiaÃ¢â€ â€™kanÃ„Â±t baÃ„Å¸lantÃ„Â±larÃ„Â±; Sales Approved incelemesi.

**Sorumlu:** Product/Marketing + Commercial + Legal. **Kontrol:** node docs/scripts/claim-check.mjs --mode=gate.

## 71 alt ÃƒÂ¶zelliÃ„Å¸in eksik/kabul iÃ…Å¸leriyle eÃ…Å¸lemesi

Tabloda wired yalnÃ„Â±z ÃƒÂ§aÃ„Å¸rÃ„Â±labilen akÃ„Â±Ã…Å¸ demektir; ÃƒÂ¼retim kabulÃƒÂ¼ deÃ„Å¸ildir. Her ÃƒÂ¶zellik en az bir aÃƒÂ§Ã„Â±k kabul iÃ…Å¸ine baÃ„Å¸landÃ„Â±. AyrÃ„Â±ntÃ„Â±lÃ„Â± kaynak ve mevcut davranÃ„Â±Ã…Å¸ [FEATURE_INVENTORY.json](FEATURE_INVENTORY.json) iÃƒÂ§indedir.

| Ãƒâ€“zellik | Ad | Durum | Ã„Â°lgili aÃƒÂ§Ã„Â±k iÃ…Å¸ler |
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

## Uygulama sÃ„Â±rasÃ„Â± ve kapanÃ„Â±Ã…Å¸ kuralÃ„Â±

1. T01/T04/T10/T13 ile gerÃƒÂ§ek host interception, MCP forced-routing ve native response yan etkisini aynÃ„Â± aday hash'i ÃƒÂ¼zerinde kanÃ„Â±tla.
2. T18/T19/T20/T28/T45 ile canlÃ„Â± IdP, SMTP, cloud project, public TLS proxy ve mÃƒÂ¼Ã…Å¸teri tarayÃ„Â±cÃ„Â±sÃ„Â± akÃ„Â±Ã…Å¸Ã„Â±nÃ„Â± iki tenantta ÃƒÂ§alÃ„Â±Ã…Å¸tÃ„Â±r.
3. T24/T25/T27/T30/T32/T39 ile SIEM receipt, baÃ„Å¸Ã„Â±msÃ„Â±z kanÃ„Â±t saklama, offsite restore, HA/soak ve kÃƒÂ¶r benchmark ÃƒÂ¶lÃƒÂ§ÃƒÂ¼mÃƒÂ¼nÃƒÂ¼ tamamla.
4. T29/T33/T40/T41 ile resmi signer custody, private registry, invoiceÃ¢â€ â€™paid entitlement ve ÃƒÂ§alÃ„Â±Ã…Å¸an destek kanalÃ„Â±nÃ„Â± aynÃ„Â± ticari candidate'a baÃ„Å¸la.
5. Hukuk/Privacy/Finance/Security/Sales ve isimli mÃƒÂ¼Ã…Å¸teri PoV kayÃ„Â±tlarÃ„Â±nÃ„Â± 13 dÃ„Â±Ã…Å¸ kapÃ„Â±ya ekle.
6. AynÃ„Â± imzalÃ„Â± candidate iÃƒÂ§in baÃ„Å¸Ã„Â±msÃ„Â±z test, mÃƒÂ¼Ã…Å¸teri PoV ve onaylÃ„Â± iddia kaydÃ„Â± tamamlandÃ„Â±ktan sonra GO kararÃ„Â± ver.

Her kapanÃ„Â±Ã…Å¸ kaydÃ„Â± isimli sorumlu, gerÃƒÂ§ek sÃƒÂ¼rÃƒÂ¼m/artefact ÃƒÂ¶zeti, deÃ„Å¸iÃ…Å¸tirilemeyen test kanÃ„Â±tÃ„Â±, gÃƒÂ¶zlem tarihi, kabul eden kiÃ…Å¸i ve kalan sÃ„Â±nÃ„Â±ra sahip olmalÃ„Â±. Tahmini bitiÃ…Å¸ tarihi vermek iÃƒÂ§in ekip kapasitesi, mÃƒÂ¼Ã…Å¸teri kapsamÃ„Â± ve altyapÃ„Â± bilgisi gerekiyor; bilinmeyen baÃ„Å¸Ã„Â±mlÃ„Â±lÃ„Â±Ã„Å¸a hayali tarih atanmadÃ„Â±.

Ã„Â°lk gÃƒÂ¶rÃƒÂ¼Ã…Å¸meye gÃƒÂ¶tÃƒÂ¼rÃƒÂ¼lebilecek mevcut materyal: [deploy/FIRST_CUSTOMER.md](deploy/FIRST_CUSTOMER.md), [docs/production-readiness/first-customer-sales-packet-v7.md](docs/production-readiness/first-customer-sales-packet-v7.md), [docs/production-readiness/2026-09-13-customer-candidate-v7.md](docs/production-readiness/2026-09-13-customer-candidate-v7.md), [FEATURE_INVENTORY.md](FEATURE_INVENTORY.md). Bunlar genel ÃƒÂ¼retim veya satÃ„Â±Ã…Å¸ onayÃ„Â± deÃ„Å¸ildir.

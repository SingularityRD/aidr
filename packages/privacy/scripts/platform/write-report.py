import json,re,datetime,platform,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2];P=R/'reports/platform'
def load(p):return json.loads((R/p).read_text())
def count(path):
 t=(R/path).read_text();return {k:int(re.search(r'^# '+k+r' (\d+)',t,re.M)[1]) for k in ['tests','pass','fail','skipped']}
node=count('reports/platform/all-node-coverage.txt');new=count('reports/platform/node-tests.txt')
python={name:int(re.search(r'Ran (\d+) tests',(P/path).read_text())[1]) for name,path in [('ner','ner-tests.txt'),('vision','vision-tests.txt'),('parser','parser-tests.txt')]}
t=(P/'all-node-coverage.txt').read_text();c=re.search(r'# all files\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)',t);coverage=dict(zip(['lines','branches','functions'],map(float,c.groups())))
browser=load('reports/browser/dom-e2e.json');native=load('reports/browser/native-e2e.json');portal=load('reports/platform/portal-dom-e2e.json');docs=load('reports/platform/documents-e2e.json');visual=load('reports/platform/visual-e2e.json');evaluation=load('reports/platform/pii-evaluation.json');model=load('models/training-report.json');bench=load('reports/platform/benchmark.json')
summary={'version':'0.5.0-rc.1','capturedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'node':node,'newPlatformNode':new,'python':python,'totalUnitIntegration':node['pass']+sum(python.values()),'coverage':coverage,'browserDomChromeAPIShims':{'passed':browser['passed'],'total':browser['total']},'nativeRealStdioChromePortShim':{'passed':native['passed'],'total':native['total']},'portalDomMockFetch':{'passed':portal['passed'],'total':portal['total']},'documentPipeline':{'passed':sum(x['passed'] for x in docs['cases']),'total':len(docs['cases'])},'visualPipeline':visual,'learnedBaseline':{k:model[k] for k in ['trainingSamples','heldoutSamples','origin','correct']},'corporateQualification':evaluation['qualification'],'notValidated':['independent corporate text/image corpus','production learned NER','installed MV3 extension','live authenticated ChatGPT/Gemini/Claude','real IdP/MDM/provider-account broker','real upstream provider/tool effects','multi-node HA','CVE advisory database','real ASR/video/face/handwriting/signature/CAD/steganography detectors'],'portalBrowserHttpsAttempt':'BLOCKED_BY_ADMINISTRATOR; 0 scenarios executed; API HTTPS and DOM tested separately','release': 'unsigned release candidate; not customer production acceptance'}
(P/'SUMMARY.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
report=f'''# AIDR Platform Privacy 0.5.0-rc.1 — çalıştırılan testler

Rapor: {summary['capturedAtUtc']}. Platform: {bench['node']}, Linux x64; Python {platform.python_version()}. Node `node:sqlite` deneysel uyarı verir; bu test sürümündeki SQLite 3.49.1 nedeniyle depoda varsayılan DELETE journal kullanıldı. Bu seçim diğer native bağımlılıkların güvenlik onayı değildir.

## Sonuç

| Grup | Geçen / toplam | Sınır |
|---|---:|---|
| Bütün Node testleri | {node['pass']} / {node['tests']} | Önceki 1181 dahil; yeni platform {new['pass']} test. Yeni sayı ayrıca toplama eklenmez |
| Python NER protokol/manifest | {python['ner']} / {python['ner']} | Gerçek öğrenilmiş NER çıkarımı yok |
| Python görsel worker | {python['vision']} / {python['vision']} | Alt bileşen testleri |
| Python yeni belge parser | {python['parser']} / {python['parser']} | Seccomp dahil gerçek alt süreçler |
| **Birim/entegrasyon toplamı** | **{summary['totalUnitIntegration']} geçti** | **0 başarısız; saha doğruluğu yüzdesi değildir** |
| Chrome davranış DOM senaryoları | {browser['passed']} / {browser['total']} | Gerçek Chromium, Chrome API sınırı test taklidi; kurulu MV3 değil |
| Native client/host | {native['passed']} / {native['total']} | Gerçek stdio, Chrome port'u shim; bir gerçek OCR görüntüsü dahil |
| Portal arayüzü | {portal['passed']} / {portal['total']} | Gerçek Chromium DOM, mock fetch; canlı SSO değil |
| Belge uçtan uca | {summary['documentPipeline']['passed']} / {summary['documentPipeline']['total']} | Dijital PDF, sade Word, EML, ZIP: 4 temiz TXT. CustomXML'li normal Word paketi: 1 beklenen blok |
| Yeni kalıcı audit + OCR | 1 / 1 | Gerçek Tesseract eng+tur; sentetik görselde altı satırın bilinen pikselleri |

Ayrı gerçek HTTPS portal API ve gerçek mTLS ingress testleri Node toplamının içindedir; tekrar sayılmaz. Aynı Türkçe görüntünün native ve platform yollarında kullanılması iki bağımsız veri kümesi veya on iki farklı kişisel veri örneği değildir.

## Gerçekten sınanan güven sınırları

Altı ayrı süreç, aynı SQLite dosyasında ortak kotaya yarıştı; limit aşılmadı. Tenant ayrımı, şifreli yeniden açma, sürümlü silme/CAS, tek kullanımlık onay, anahtar rotasyonu ve eski tam DB snapshot'ına dönüş/harici anchor testleri çalıştı. Seçici geçerli hücre rollback'ine karşı root/DB yöneticisi savunması veya dağıtık HA test edilmedi.

Kullanıcı/cihaz/sağlayıcı JWT'leri ayrı anahtarlarla kontrol edildi. RealmTLS denemesinde doğru peer certificate geçti; farklı ama CA tarafından yetkilendirilmiş sertifika ve sertifikasız tekrar başarısızdı. Test sertifikaları yerel ve geçiciydi. Canlı kurum hesabı/MDM/hardware attestation yoktu. HTTP istemcisi yerel self-signed server sertifikası için test istisnası kullandı; production taşıyıcıları bu istisnayı içermez.

Gönderim öncesi asenkron iptal, stale policy, byte snapshot, değiştirilmiş requestId, aynı onayın tekrar kullanımı, output withheld, no-original-fallback ve belirsiz dispatch kontrolleri çalıştı. Dış OpenAI/Gemini/upstream MCP çağrıları kontrollü taşıyıcı taklidiydi; gerçek müşteriye veya modele veri gönderilmedi. Yeni network modülünün gerçek dış HTTPS dispatch yolu bu ortamda çalıştırılmadı.

Parser alt sürecinde gerçek `socket()` ve `/etc/passwd` için yeni `open()` çağrıları EPERM aldı. Makro/embedded/şifreli içerik, DTD, path traversal, symlink, CRC, expansion/file-count/depth limitleri sınandı. Bunlar bağımsız parser güvenlik denetimi veya fuzzing kampanyası değildir. Default python-docx paketi customXML içerdiğinden bilinçli olarak reddedildi; ayrıca bu part'ları olmayan geçerli sade Word girdisi gerçekten temizlendi.

## Doğruluk: başarısız kabul kapısı rapordan çıkarılmadı

Kurallı TR/EN değerlendirmede 16 sentetik metin, 14 gold PII span vardır. İki etiketsiz kişi adı (`Ahmet`, `Jane`) kaçırıldı; her dilde PERSON recall **1/2** oldu. Diğer türlerde tekil olumlu örnekler başarılı olsa da örnek sayısı yeterli değildir. İki clean örnekte alarm çıkmaması false-positive başarımını kanıtlamaz.

`qualified:false`: bağımsız kurumsal veri, yeterli tür/dil örneği ve yeterli negatif örnek yok. `scripts/platform/evaluate-corpus.mjs` ile JSONL değerlendirmesi gerçekten çalıştırıldı ve beklenen nonqualification exit code **3** döndü. Dataset'in bağımsızlık alanı operatör beyanıdır; kurum etiketi kendiliğinden bağımsızlık kanıtı sayılmamalıdır.

Gerçekten eğitilen küçük model 80 özgün sentetik eğitim ve 18 ayrı sentetik örnek kullandı; 17 top-1 eşleşme. Bu oranı saha başarımı, kalibre risk skoru veya güvenilir prompt-injection/NER performansı diye yorumlamayın. Python ve TypeScript çıkarım olasılıkları karşılaştırıldı. Model, yalnız ek review sinyali verir; default defense NER kapısını açmaz.

## Kod kapsamı ve önemli boşluk

Tüm derlenmiş JavaScript: satır **%{coverage['lines']:.2f}**, dal **%{coverage['branches']:.2f}**, fonksiyon **%{coverage['functions']:.2f}**. Bu rakamlar bütün eski/yeni dosyaların birleşimidir. Özellikle yeni `network.js` satır kapsamı yaklaşık %54,63, `mcp-egress.js` dal kapsamı %40'tır. Dış network taşıyıcısının bütün akışları veya her MCP hata modu çalıştırılmadı. Yüksek toplam yüzdeyi bu boşlukların kapanması olarak sunmuyoruz. Dosya bazlı ayrıntı `all-node-coverage.txt` içindedir.

## Yerel performans

4054 byte sentetik metin; 20 ısınma, 200 sıralı çağrı. Farklı bileşen ölçümleri; birbirine toplanmış uçtan uca gecikme değildir.

| Bileşen | Medyan | p95 |
|---|---:|---:|
| Küçük character-linear sınıflandırıcı | {bench['rows'][0]['medianMs']:.3f} ms | {bench['rows'][0]['p95Ms']:.3f} ms |
| PII + enterprise gate + gerçek SQLite FULLsync audit | {bench['rows'][1]['medianMs']:.3f} ms | {bench['rows'][1]['p95Ms']:.3f} ms |

Yeni gerçek OCR pipeline tek çalıştırmada **{visual['elapsedMs']/1000:.3f} saniye** sürdü. İşlem sonunda örneklenen Node RSS {bench['sampledEndNodeRssBytes']/1048576:.2f} MiB; peak bellek, Python/native süreç belleği veya yalnız modül ek maliyeti değildir. Gerçek NER, network provider, çok kullanıcılı trafik ve HA maliyetleri bu ölçümlerde yoktur.

## Çalıştırılamayanlar

Bu ortamda gerçek portal HTTPS navigasyonu `ERR_BLOCKED_BY_ADMINISTRATOR` ile durdu: 0 browser/HTTPS senaryosu çalıştı. Bu başarısız deneme `portal-e2e.json` içinde korunuyor. API'nin gerçek HTTPS testi ve DOM fixture testi ayrı olarak geçti; bunları tek gerçek browser->SSO->portal akışı diye birleştirmiyoruz. Kurulu Chrome MV3, gerçek canlı oturumlu ChatGPT/Gemini/Claude ve Windows/macOS kurumsal native dağıtım doğrulanmadı.

Bağımsız müşteri veri kümesi, gerçek NER/ASR modelleri, signed corporate CRX/MDM, canlı DSPM kaynakları, model vulnerability DB ve full multimodal dedektörler yok. Bunlar `docs/PLATFORM_FEATURE_STATUS.md` içinde ayrı işaretli.

## Kanıt dosyaları

`all-node-coverage.txt`, `node-tests.txt`, `ner-tests.txt`, `vision-tests.txt`, `parser-tests.txt`, `mtls-tests.txt`, `portal-http-tests.txt`, `portal-dom-e2e.json`, `portal-e2e.json`, `documents-e2e.json`, `visual-e2e.json`, `benchmark.json`, `pii-evaluation.json`, `corpus-cli-report.json` ve `COMPONENT-INVENTORY.json`; model kanıtı `models/training-report.json`. Browser/native raporları `reports/browser/dom-e2e.json` ve `native-e2e.json` içindedir.

Bu rapor, BMC veya başka bir kurumun kabulü, KVKK/GDPR/SOC 2 sertifikasyonu, üçüncü taraf pentest ya da kusursuz PII yakalama iddiası değildir.
'''
(P/'TEST_REPORT.md').write_text(report)
print(json.dumps({'unitIntegration':summary['totalUnitIntegration'],'node':node,'python':python,'coverage':coverage}))

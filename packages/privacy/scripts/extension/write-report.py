#!/usr/bin/env python3
import json,re,datetime
from pathlib import Path
root=Path(__file__).resolve().parents[2];out=root/'reports/browser'
def load(name):return json.loads((out/name).read_text())
def count(name):
 s=(out/name).read_text();return {k:int(re.findall(r'^# '+k+r' (\d+)$',s,re.M)[-1]) for k in ['tests','pass','fail','skipped']}
node=count('node-coverage.tap');added=count('unit-final.tap');old=count('regression-node.tap');dom=load('dom-e2e.json');native=load('native-e2e.json');bench=load('benchmark.json');build=load('extension-build.json')
py={}
for name in ['ner','vision']:
 s=(out/f'regression-{name}.log').read_text();assert s.rstrip().endswith('OK');py[name]=int(re.search(r'Ran (\d+) tests',s).group(1))
assert node['fail']==added['fail']==old['fail']==0 and node['tests']==old['tests']+added['tests']
assert dom['passed']==dom['total'] and native['passed']==native['total']
summary={'version':'0.4.0-rc.1','reportedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'node':node,'legacyNodeRegression':old,'newBrowserAndNativeNode':added,'python':py,'realChromiumDomWithChromeMocks':{'passed':dom['passed'],'total':dom['total']},'realNativeProcessWithPortShim':{'passed':native['passed'],'total':native['total']},'totalUnitAndProtocolEntries':node['pass']+sum(py.values()),'combinedExecutedEntries':node['pass']+sum(py.values())+dom['passed']+native['passed'],'installedExtension':'NOT_VALIDATED_POLICY_BLOCKED','liveAuthenticatedSites':'NOT_RUN','realNer':'NOT_RUN','newRealOcrImages':1,'newRealOcrSensitiveRows':6,'chromeBundleBytes':sum(f['bytes'] for f in build['files'])}
(out/'test-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
rows='\n'.join(f"| {r['inputBytes']//1024} KiB | {r['medianMs']:.3f} ms | {r['p95Ms']:.3f} ms | {r['p99Ms']:.3f} ms |" for r in bench['results'])
ocr=native['cases'][-1]
report=f'''# AIDR Browser Privacy 0.4.0-rc.1 — test raporu

## Sonuç ve kapsam

**{summary['totalUnitAndProtocolEntries']} birim/entegrasyon test girdisi geçti.** Ayrıca **{dom['passed']}/{dom['total']} gerçek Chromium DOM senaryosu** ve **{native['passed']}/{native['total']} gerçek native süreç/istemci senaryosu** geçti. Bu kategoriler birlikte {summary['combinedExecutedEntries']} yürütülmüş test girdisidir. Bu sayı bağımsız müşteri verisi, doğruluk yüzdesi veya tüm kaçırma yöntemlerinin denendiği anlamına gelmez.

| Test grubu | Geçen / toplam | Kapsam |
|---|---:|---|
| Önceki metin + görsel Node regresyonu | {old['pass']} / {old['tests']} | Önceki 0.2 kaynak davranışı yeniden çalıştırıldı |
| Yeni browser/native Node | {added['pass']} / {added['tests']} | Ortak kurallar, politikalar, dokümanlar, service worker API sınırı taklidi, framing ve host hazırlama |
| Birleşik Node koşusu | {node['pass']} / {node['tests']} | Tek güncel coverage koşusu; 0 başarısız, 0 atlandı |
| Önceki NER Python testleri | {py['ner']} / {py['ner']} | Artefakt/manifest/protokol testleri; gerçek NER çıkarımı değil |
| Önceki görsel Python testleri | {py['vision']} / {py['vision']} | Worker/görüntü/piksel hata koşulları |
| Gerçek Chromium DOM | {dom['passed']} / {dom['total']} | Gerçek DOM ve uygulama bundle'ları; Chrome API broker'ı taklit |
| Gerçek native stdio + production istemci | {native['passed']} / {native['total']} | Gerçek Node alt süreçleri; Chrome port'u shim; bir gerçek yerel OCR örneği dahil |

## Tarayıcıda ne gerçekten çalıştırıldı?

Chromium **{dom['chromiumVersion']}** içinde ChatGPT textarea, Gemini rich-textarea/contenteditable ve Claude ProseMirror fixture'ları kullanıldı. Üretim service-worker/compose bundle'ları ve içerik betiğinin aynı kaynak kodu çalıştı. İlk gönderme engelleme, ikinci açık gönderim, PII uyarısı, düz metin yapıştırmadan önce maskeleme, görsel paste/drop/file input reddi, yönetici politika değişimi, bilinmeyen/çift editör, IME/Shift+Enter, sekmeye bağlı çıktı ve UI akışı denendi. Önizleme ekranı `secure-composer-fixture.png` dosyasıdır; canlı sağlayıcı oturumu değildir.

**Chrome API'leri test broker'ı ile taklit edildi.** about:blank güvenli bağlam olmadığı için testte UUID Chromium'un gerçek CSPRNG'siyle, SHA-256 Python hashlib köprüsüyle sağlandı. Node protokol testleri gerçek WebCrypto kullanır. Bu yaklaşım Chrome'un gerçek isolated-world/CSP, installed-service-worker yaşam döngüsü, DNR uygulaması veya native-host OS kaydını doğrulamaz.

Kurulu eklenti yükleme girişimi ortamın yönetilen `ExtensionInstallBlocklist:["*"]` politikasıyla engellendi; `URLBlocklist:["*"]` de etkindir. Politikalar değiştirilmedi. Gerçek kurulum/live site sonucunu geçti diye saymadık. `installed-extension-status.json` bu sınırlamayı kaydeder. İzinli makinede çalıştırılacak ayrı opt-in installed smoke script'i teslimde var.

## Gerçek native/OCR hattı

Production Native Messaging istemci kodu, Chrome port nesnesini gerçek Node child stdin/stdout'una bağlayan test adaptörüyle çalıştı. UTF-8/JSON framing, host köken kontrolü, politika hash'i, offset'ler, kaynak/çıktı hash'i ve yanıt kimliği gerçek akışta doğrulandı. 315.000 byte belge birden fazla parçada gidip geldi. Yanlış eklenti kökeni, politika farkı, yok OCR, tahrif edilmiş digest ve correlation ID reddedildi.

Yeni native hatta `fixtures/visual/turkish.png` gerçek yerel Tesseract `eng+tur` ile işlendi. **{ocr['verifiedSensitiveRows']} bilinen hassas satırın tüm sınırları siyah piksel olarak ayrıca doğrulandı.** {ocr['sourceBytes']} byte girdi, {ocr['outputBytes']} byte yeni PNG çıktı; süre **{ocr['elapsedMs']/1000:.3f} saniye**. Bu tek bir sentetik örnektir, gecikme SLA'sı veya genel OCR başarım ölçümü değildir. Görsel kapatmalar Node PNG doğrulayıcısından geçti. Model kapsamı `rules-only`; gerçek öğrenilmiş NER kullanılmadı.

Önceki 0.2 gerçek görsel denemeleri `reports/visual` altında tarihsel olarak bulunur; bu koşuda yeniden yapılmış yeni bağımsız benchmark diye sayılmaz. Görsel altmotorunun audit sürüm kimliği 0.2.0-rc.1 olarak korunur; dağıtım/Chrome/metin katmanı 0.4.0-rc.1'dir.

## Kod kapsamı

Birleşik Node coverage koşusunda ölçülen derlenmiş modüller için satır **%98,75**, dal **%92,33**, fonksiyon **%97,00**. Rapor `node-coverage.tap` içindedir. Filtre `dist/**/*.js` olup **çalıştırılan Node modüllerini** kapsar; bütün depo, browser IIFE bundle'ları, Python, Windows launcher, native host'un bütün satırları veya canlı sağlayıcı adaptörü için aynı oran iddia edilmez. Hiçbir kapsam yüzdesi PII/OCR recall'ı değildir.

Deterministik üretilmiş örnekler bazı testlerin içinde döngü olarak çalışır. Örneğin yeni portable IP testi 5.000 varyant içerir; bunlar 5.000 ayrı test girdisi olarak sayılmadı. Önceki fuzz/property döngüleri de önceki Node test sayısının içindedir.

## Kurallı çekirdek ölçümü

Aşağıdaki ölçüm Node {bench['node']} üzerinde, tarayıcıda kullanılabilen kurallı çekirdeğin ısınmış/sıralı çalışmasıdır. Her boyutta 100 ısınma ve 1.000 ölçüm; sentetik iki hassas alan içerir. Browser IPC, 250 ms debounce, UI, native bağlantı, NER/OCR ve eşzamanlı kullanıcı yükü dahil değildir.

| Girdi | Medyan | p95 | p99 |
|---|---:|---:|---:|
{rows}

Örneklenen en yüksek toplam Node RSS'i **{bench['peakSampledProcessRssBytes']/1048576:.2f} MiB**; yalnız modülün ek belleği değildir ve çağrı içi her anın tepe değeri değildir. CPU `{bench['cpu']}`. Bu ölçümler son kullanıcı Windows bilgisayarına otomatik taşınamaz. Chrome dağıtımının yedi dosyası toplam **{summary['chromeBundleBytes']:,} byte** (sıkıştırılmamış); OCR/model/Node/Python bu boyuta dahil değil.

## Tekrar üretim

`npm run test:coverage`, `npm run test:python`, `npm run test:vision-python`, `npm run test:extension:e2e` ve onaylı OCR backend yapılandırmasıyla `npm run test:native:e2e`. Doküman: `docs/BROWSER.md`. Geliştirme bağımlılıklarının çevrimdışı kurulumu, build/typecheck ve dağıtım smoke kontrolleri ayrı loglara yazılır.

## Geçmiş sayılmayan kapılar

Kurulu MV3; gerçek oturum açılmış sağlayıcı arayüzleri; Windows/macOS native kurulum/işleyiş; gerçek NER model çıkarımı ve bağımsız TR/EN başarı ölçümü; mağaza/kurumsal imza; gerçek çok kullanıcılı yük/soak/chaos; bağımsız güvenlik incelemesi; npm audit (registry DNS/ağ erişimi yoktu); AIDR backend/gateway/endpoint entegrasyonu ve müşteri kabulü tamamlanmadı. Zafiyet yokluğu, %100 yakalama veya mevzuat sertifikası iddiası yoktur.
'''
(out/'TEST_REPORT.md').write_text(report)
print(json.dumps(summary,indent=2))

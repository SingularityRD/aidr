# Browser Guard data-usage disclosure

Answers for the Chrome Web Store **Privacy practices** tab, the Microsoft Edge
Add-ons **Properties / Privacy** section and the addons.mozilla.org (AMO) data
collection declaration. They follow the fixed wire contract in
[`docs/contracts/privacy-telemetry.md`](../../../docs/contracts/privacy-telemetry.md)
and the code under `src/background/`; if either changes, update this file and the
privacy policy pages ([`privacy-policy.en.html`](privacy-policy.en.html),
[`privacy-policy.tr.html`](privacy-policy.tr.html)) in the same change.

Türkçe metin aşağıdadır ([Türkçe](#türkçe)).

## What leaves the device

| Flow | When | Where it goes | What is in it |
|---|---|---|---|
| Prompt, paste and file checks | always, on supported AI sites | nowhere: the checks run in the page | - |
| Placeholder-to-value mapping | while a tab is open | nowhere: page memory and `chrome.storage.session` (memory only) | deleted when the tab closes, after 4 hours without a save, or when the browser exits |
| `privacy_scan` telemetry | only when a `telemetry` target is configured (managed policy, or by the user on the options page) | `POST {controlPlaneUrl}/functions/v1/ingest`, the organisation's AIDR control plane | random per-install id, browser family and major version, extension version, and per event: site id (enum), action, channel, counts per entity type, total findings, optional policy id, native-NER status, pause flag, invalid-policy count. **No prompt text, masked text, values, file names or URLs** |
| `shadow_ai_usage` telemetry | only with telemetry and a managed `shadowAi` mode other than `off` | same endpoint | catalog service id, `visited`/`blocked`, count, sanctioned flag. **No URL, host, path or page title** |
| `aup_acknowledgement` | only with telemetry and a managed `acceptableUse` notice | same endpoint | site id, notice id and version. No user identity |
| Signed dashboard policy | only with telemetry and the managed `dashboardPolicy` trust anchor | `GET {controlPlaneUrl}/functions/v1/browser-guard-policy` | the telemetry key only; no body, no browsing data |
| Native host (NER/OCR) | only when `useNativeHost` is on and the user granted `nativeMessaging` | a separately installed program on the same computer, over native messaging | the text or image being checked; never sent over the network by the extension |

Nothing is sent to the publisher (Singularity R&D) by the extension itself. The
control plane belongs to the customer organisation: self-hosted, or a tenant on the
AIDR cloud service operated for that organisation under its customer agreement.

## Chrome Web Store: Privacy practices tab

- **Single purpose:** paste [`en/single-purpose.txt`](en/single-purpose.txt).
- **Permission justifications:** one field per permission, from
  [`permissions.json`](permissions.json) (`permissions`, `optional_permissions`,
  `host_permissions.justification`, `optional_host_permissions`).
- **Are you using remote code?** No. Justification: `remote_code` in
  [`permissions.json`](permissions.json).
- **Data usage (what the developer collects).** Recommended answer, to be confirmed by
  the publisher (see "Owner decision" below):
  - *Personally identifiable information, Health information, Financial and payment
    information, Authentication information, Personal communications, Location, Web
    history, Website content:* **not collected**. Prompt text and the values found in it
    never leave the browser; Shadow AI reports a catalog id and a count, never a URL.
  - *User activity:* **collected only when an administrator connects a control plane**:
    counts of masked/blocked items per AI site and of visits to catalogued AI services.
    Purpose: the organisation's own security reporting.
- **Certifications (all three must be ticked):** data is not sold to third parties; not
  used or transferred for purposes unrelated to the item's single purpose; not used or
  transferred to determine creditworthiness or for lending.
- **Privacy policy URL:** the hosted copy of [`privacy-policy.en.html`](privacy-policy.en.html)
  (see [`README.md`](README.md)).

## Microsoft Edge Add-ons

- **Does the extension collect personal information?** Same answer as above: no personal
  information; organisation-configured counts-only telemetry. Give the privacy policy URL.
- **Permission justifications / notes for certification:** paste the same texts from
  [`permissions.json`](permissions.json); add a test note that the extension can be tried
  on any supported site without an account (for example type `jane.doe@example.com` in a
  ChatGPT prompt and press Enter: the site receives `[EMAIL_1_xxxx]`).

## addons.mozilla.org

- The Firefox manifest declares
  `browser_specific_settings.gecko.data_collection_permissions.required: ["none"]`:
  the extension transmits nothing to the developer or to third parties on its own.
- **Owner decision:** if the publisher's own hosted control plane receives telemetry for a
  customer, Mozilla may treat those counts as `technicalAndInteraction` data. Declaring it
  as an *optional* data collection permission is a product decision (it adds a consent
  prompt); it is not made in this build.
- Source code: AMO requires the sources of minified or bundled code. Upload
  `aidr-browser-guard-source-<version>.zip` from the release (it contains
  `AMO-REVIEWER-NOTES.md` with the exact build steps).

## Owner decision

The answers above treat the organisation's control plane as the organisation's own
system. If the publisher operates that control plane as a hosted service, the counts
reach a system the publisher runs; decide with legal counsel whether to declare
*User activity* (Chrome) and `technicalAndInteraction` (Firefox) as collected for those
installs, and keep the privacy policy pages consistent with that decision.

---

## Türkçe

### Cihazdan ne çıkar

| Akış | Ne zaman | Nereye | İçerik |
|---|---|---|---|
| İstem, yapıştırma ve dosya denetimleri | her zaman, desteklenen yapay zekâ sitelerinde | hiçbir yere: denetim sayfada çalışır | - |
| Yer tutucu-değer eşlemesi | sekme açıkken | hiçbir yere: sayfa belleği ve `chrome.storage.session` (yalnızca bellek) | sekme kapanınca, 4 saat kaydedilmeyince veya tarayıcı kapanınca silinir |
| `privacy_scan` telemetrisi | yalnızca bir `telemetry` hedefi yapılandırıldığında (yönetilen politika veya kullanıcının seçenekler sayfası) | `POST {controlPlaneUrl}/functions/v1/ingest`, kurumun AIDR kontrol düzlemi | kurulum başına rastgele kimlik, tarayıcı ailesi ve ana sürümü, uzantı sürümü; olay başına site kimliği (sabit liste), eylem, kanal, varlık türü başına sayılar, toplam bulgu, isteğe bağlı politika kimliği, yerel NER durumu, duraklatma bayrağı, geçersiz politika sayısı. **İstem metni, maskeli metin, değerler, dosya adları veya URL'ler yoktur** |
| `shadow_ai_usage` telemetrisi | yalnızca telemetri ve `off` dışında bir yönetilen `shadowAi` modu varken | aynı uç nokta | katalog hizmet kimliği, `visited`/`blocked`, sayı, onaylı bayrağı. **URL, alan adı, yol veya sayfa başlığı yoktur** |
| `aup_acknowledgement` | yalnızca telemetri ve yönetilen `acceptableUse` bildirimi varken | aynı uç nokta | site kimliği, bildirim kimliği ve sürümü. Kullanıcı kimliği yoktur |
| İmzalı pano politikası | yalnızca telemetri ve yönetilen `dashboardPolicy` güven çapası varken | `GET {controlPlaneUrl}/functions/v1/browser-guard-policy` | yalnızca telemetri anahtarı; gövde ve gezinme verisi yoktur |
| Yerel ana bilgisayar (NER/OCR) | yalnızca `useNativeHost` açıkken ve kullanıcı `nativeMessaging` iznini verdiyse | aynı bilgisayara ayrıca kurulan program, native messaging ile | denetlenen metin veya görüntü; uzantı bunu ağ üzerinden göndermez |

Uzantı kendiliğinden yayıncıya (Singularity R&D) hiçbir şey göndermez. Kontrol
düzlemi müşteri kuruma aittir: kurumun kendi sunucusunda veya müşteri sözleşmesi
kapsamında o kurum için işletilen AIDR bulut hizmetinde bir kiracı olarak.

### Chrome Web Store: Gizlilik uygulamaları sekmesi

- **Tek amaç:** [`tr/single-purpose.txt`](tr/single-purpose.txt) (mağaza formu İngilizce
  metni ister; Türkçe metin yerelleştirilmiş açıklamalar içindir).
- **İzin gerekçeleri:** [`permissions.json`](permissions.json) içindeki `tr` metinleri.
- **Uzak kod kullanıyor musunuz?** Hayır (`remote_code` gerekçesi).
- **Veri kullanımı:** kişisel bilgi, sağlık, finans, kimlik doğrulama, kişisel iletişim,
  konum, web geçmişi ve web sitesi içeriği **toplanmaz**. *Kullanıcı etkinliği* yalnızca
  yönetici bir kontrol düzlemi bağladığında **sayılar olarak** toplanır (kurumun kendi
  güvenlik raporlaması için).
- **Taahhütler:** veriler üçüncü taraflara satılmaz; tek amaç dışında kullanılmaz veya
  aktarılmaz; kredi değerliliği veya borç verme için kullanılmaz.

### Sahibin vereceği karar

Yukarıdaki yanıtlar kontrol düzlemini kurumun kendi sistemi olarak ele alır. Yayıncı bu
kontrol düzlemini barındırılan bir hizmet olarak işletiyorsa sayılar yayıncının işlettiği
bir sisteme ulaşır; bu kurulumlar için *Kullanıcı etkinliği* (Chrome) ve
`technicalAndInteraction` (Firefox) beyanının gerekip gerekmediğine hukuk danışmanıyla
karar verin ve gizlilik politikası sayfalarını bu kararla tutarlı tutun.

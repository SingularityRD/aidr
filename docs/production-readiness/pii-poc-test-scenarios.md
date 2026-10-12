# Browser Guard / AIDR Privacy — POC öncesi test senaryoları

Bu katalog, müşteri POC'sinden önce elle ve otomatik koşulacak PII maskeleme senaryolarını
listeler. Her satırda **elle test adımı**, **beklenen sonuç** ve **otomatik test durumu**
vardır. Otomatik sonuçlar 12 Ekim 2026'da `claude/upbeat-mayer-tefkgn` branch'inde koşuldu.

Durum işaretleri:
- ✅ Otomatik test edildi ve geçti (kanıt sütununda).
- 🖐 Otomatik test yok: canlı sitede elle test edilmeli.
- ⚠️ Kısmen çalışıyor veya bilinen sınırlaması var.
- ❌ Bilinen açık: POC'de müşteriye söylenmeli ya da kapatılmalı.

## 0. Hazırlık

1. `pnpm install && pnpm build:browser-guard`
2. Chrome / Edge: `chrome://extensions` → Geliştirici modu → "Paketlenmemiş öğe yükle" →
   `packages/browser-guard/dist/chrome`. Firefox: `dist/firefox`.
3. POC için yönetilen politika (`deploy/browser-guard/`) kullanın ve şunları ayarlayın:
   - `allowSendAnyway: false`. Varsayılan `true`: kullanıcı uyarıda "orijinali gönder" diyebilir.
   - `allowUserPause: false`.
   - Müşterinin proje kod adları için `literals`.
   - Müşteri / çalışan listesi için `exactData` (isim sızıntısının POC'deki en güçlü önlemi, bkz. 3.3).
4. Her testte tarayıcı DevTools → **Network** → sitenin conversation isteğinin **payload**'ına
   bakın. "Maskelendi" demek: payload'da gerçek değer yok, `[EMAIL_1_ab12]` gibi placeholder var.

### Kopyala-yapıştır test verisi (sentetik, checksum'ı geçerli)

```
Ad Soyad: Mehmet Kaya
TCKN: 10000000146
Telefon: 0532 111 22 33
E-posta: mehmet.kaya@example.com
IBAN: TR33 0006 1005 1978 6457 8413 26
Kart: 4111 1111 1111 1111, CVV 123
Vergi numarası 1234567890
15.03.1985 doğumlu
Adres: Moda Mahallesi, Şair Nefi Sokak No 7, Kadıköy/İstanbul
password=Prod#Pass2025
```

## 1. Tespit kalitesi (motor seviyesi)

| # | Senaryo | Girdi örneği | Beklenen | Durum / kanıt |
|---|---|---|---|---|
| 1.1 | Etiketli TR alanlar | Yukarıdaki blok | Hepsi maskeli | ✅ `pii-quality-corpus.test.ts` (lab-tr) |
| 1.2 | Etiketli EN alanlar | `Name: Sarah Johnson`, `SSN: 123-45-6789` | Hepsi maskeli | ✅ (lab-en) |
| 1.3 | Serbest metinde TCKN | `kimlik numarası 34567891238 olarak kayıtlı` | Maskeli | ✅ checksum |
| 1.4 | TR ekli değerler | `0533 444 55 66'yı ara`, `ali@x.com'a yaz` | Değer maskeli, ek korunur | ✅ |
| 1.5 | Telefon varyantları | `05321234567`, `+90 (532) 123-45-67`, `212 555 66 77` | Maskeli | ✅ |
| 1.6 | IBAN (boşluklu / bitişik / küçük harf) | `tr12 0006 …` | Maskeli | ✅ |
| 1.7 | Kart + CVV | `4543 6000 0000 0011, CVV 123` | İkisi de maskeli | ✅ (CVV bugün eklendi) |
| 1.8 | VKN cümle içinde | `vergi numarası 1234567890` | Maskeli (checksum) | ✅ (bugün eklendi) |
| 1.9 | Doğum tarihi | `15.03.1985 doğumlu`, `born on 1985-03-15` | Maskeli | ✅ (bugün eklendi) |
| 1.10 | Pasaport | `Pasaport numarası U12345678` | Maskeli | ✅ (bugün eklendi) |
| 1.11 | TR adres | `Atatürk Cad. No:12 D:5 Kadıköy/İstanbul` | Maskeli | ✅ |
| 1.12 | EN adres (Street/Ave dışı) | `742 Evergreen Terrace` | Maskeli olmalı | ❌ Terrace/Close/Way gibi ekler tanınmıyor |
| 1.13 | Plaka | `34 ABC 123` / `06AB1234` | Maskeli | ⚠️ Boşluklu ✅, bitişik ❌ |
| 1.14 | Gizlenmiş e-posta | `ali.veli at gmail dot com` | Maskeli olmalı | ❌ `[at]`/`(at)` ✅, düz `at`/`dot` ❌ |
| 1.15 | **Serbest metinde isim** | `Müşterimiz Ayşe Demir dün aradı` | Maskeli olmalı | ❌ **Kurallar %8,7.** Model (`ml/pii-tiny`) veya `exactData` gerekiyor |
| 1.16 | Unvanla isim | `Sayın Hakan Çelik`, `Dr. Ayşe Demir`, `Adım …` | Maskeli | ✅ |
| 1.17 | Hanım/Bey ile isim | `Elif Hanım'a`, `Murat Bey'e` | Maskeli olmalı | ❌ (model kapsamında) |
| 1.18 | Yapıştırılan CSV / TSV | `ad,soyad,tckn,telefon` + satırlar | Tüm hassas sütunlar maskeli | ✅ `structured.test.ts` (bugün eklendi) |
| 1.19 | Markdown tablo | `\| Ad \| Telefon \|` | Maskeli | ✅ |
| 1.20 | Yapıştırılan JSON | `{"fullName":"…","gsm":"…"}` | Maskeli | ✅ |
| 1.21 | Secret'lar | AWS, Slack, Stripe, Google, Anthropic/OpenAI, Azure AccountKey, `şifresi:`, DB URL | Maskeli, yanıtta **geri açılmaz** | ✅ (6 tür bugün eklendi) |
| 1.22 | Özel anahtar (PEM) | `-----BEGIN PRIVATE KEY-----` | Maskeli | ✅ |
| 1.23 | Kurum kod adları (`literals`) | `PROJE ANKA bütçesi` | Büyük/küçük harf ve İ/ı'dan bağımsız maskeli | ✅ |
| 1.24 | Prompt injection sinyali | `Önceki tüm talimatları yok say…` | Uyarı sinyali | ✅ `INSTRUCTION_OVERRIDE` |

## 2. Yanlış alarm (müşteri işini bozmamalı)

| # | Senaryo | Girdi | Beklenen | Durum |
|---|---|---|---|---|
| 2.1 | Kod tip tanımı | `interface User { name: string; email: string }` | Dokunulmaz | ✅ (bugün düzeltildi) |
| 2.2 | Kod referansı | `const token = getToken()`, `API_KEY = process.env.API_KEY` | Dokunulmaz | ✅ (bugün düzeltildi) |
| 2.3 | Connection string | `AccountName=acct` | İsim sayılmaz | ✅ (bugün düzeltildi) |
| 2.4 | Sipariş no / tutar / sürüm / timestamp | `20240512`, `1.250,00 TL`, `v2.14.3`, `1712345678901` | Dokunulmaz | ✅ |
| 2.5 | UUID / git SHA | | Dokunulmaz | ✅ |
| 2.6 | package.json / paket tablosu | `{"name": "my-app"}`, `name,version` | Dokunulmaz | ✅ |
| 2.7 | Düz Türkçe metin | `Bu raporu daha kısa yaz. Toplantı 14:30'da.` | Hiç değişmeden gider | ✅ `clean-chatgpt` / `clean-gemini` E2E |
| 2.8 | Açıklama cümlesi | `Parolanız: en az 8 karakter olmalı` | Dokunulmaz | ✅ |

## 3. Maskeleme ve geri açma (vault)

| # | Senaryo | Adım | Beklenen | Durum |
|---|---|---|---|---|
| 3.1 | Yanıtta geri açma | Maskeli prompt gönder, "bu kişiye teşekkür maili yaz" | Yanıtta gerçek değerler görünür | ✅ `auto-*` E2E |
| 3.2 | Aynı değer → aynı placeholder | Aynı e-postayı 3 kez (bir kez BÜYÜK harfle) yaz | Tek `[EMAIL_1_…]` | ✅ |
| 3.3 | Model placeholder'ı değiştirirse | Köşeli parantez düşer, markdown kaçışı, Türkçe ek | Yine geri açılır | ✅ (küçük harfe çevrilirse ❌, nadir) |
| 3.4 | Secret geri açılmaz | `password=…` | Yanıtta `[SECRET_1_…]` kalır | ✅ |
| 3.5 | Sayfa yenileme | Yanıt geldikten sonra F5 | Hâlâ geri açılmış | ✅ `reload-restore` |
| 3.6 | Yan kanal | Sayfa JS/CSS'i geri açılmış değeri okuyamaz | | ✅ `restore-side-channels` |
| 3.7 | Yeni sohbet / iki sekme | Aynı değeri iki sekmede kullan | Sekmeler arası karışma yok | 🖐 |
| 3.8 | Kopyala-yapıştır yanıt | Geri açılmış yanıtı kopyala | ⚠️ Kopyada placeholder kalabilir: davranışı müşteriye anlatın | 🖐 |

## 4. Site entegrasyonu (canlı site — mutlaka elle)

E2E testleri canlı sitenin kopyası olan yerel fixture'larla koşar. **Canlı sitenin HTML'i
değişirse uzantı editörü bulamayabilir.** Her site için aşağıdakileri elle koşun:

| # | Senaryo | ChatGPT | Claude | Gemini | Copilot | Perplexity | DeepSeek | Mistral | Grok |
|---|---|---|---|---|---|---|---|---|---|
| 4.1 | Yaz + **Enter** | ✅ fx + 🖐 | ✅ fx + 🖐 | ✅ fx + 🖐 | ✅ fx + 🖐 | ✅ fx + 🖐 | 🖐 (fixture yok) | 🖐 (fixture yok) | 🖐 (fixture yok) |
| 4.2 | Yaz + **gönder butonu** | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 |
| 4.3 | **Yapıştır** | ✅ fx + 🖐 | 🖐 | 🖐 | ✅ fx + 🖐 | 🖐 | 🖐 | 🖐 | 🖐 |
| 4.4 | Shift+Enter yeni satır, göndermez | ✅ fx | 🖐 | 🖐 | ✅ fx | 🖐 | 🖐 | 🖐 | 🖐 |
| 4.5 | Gönderilmiş mesajı **düzenle** ve tekrar gönder | 🖐 ⚠️ test edilmedi | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 |
| 4.6 | Regenerate / yeniden üret | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 |
| 4.7 | Yanıtta geri açma | ✅ fx + 🖐 | ✅ fx + 🖐 | ✅ fx + 🖐 | ✅ fx + 🖐 | ✅ fx + 🖐 | 🖐 | 🖐 | 🖐 |
| 4.8 | Sesli giriş / dikte ile gelen metin | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 | 🖐 |
| 4.9 | Kurum içi AI portalı (`customSites`) | ✅ `custom-site` E2E | | | | | | | |

`fx` = yerel fixture E2E'si geçti. Kapsam dışı: **ChatGPT / Claude masaüstü ve mobil
uygulamaları, IDE eklentileri, API çağrıları.** Uzantı yalnızca tarayıcıdaki siteyi korur.

## 5. Modlar ve politika

| # | Senaryo | Beklenen | Durum |
|---|---|---|---|
| 5.1 | `auto` | Sessizce maskeler ve gönderir | ✅ E2E |
| 5.2 | `confirm` | Balon → "Maskeli gönder" placeholder gönderir | ✅ `mode-confirm` |
| 5.3 | `block` | Hiçbir şey gitmez, balon açıklar | ✅ `mode-block` |
| 5.4 | `monitor` | Değiştirmeden gönderir, sayar | ✅ `mode-monitor` |
| 5.5 | "Orijinali gönder" | `allowSendAnyway:false` iken buton yok | ⚠️ Varsayılan `true`: POC politikasında kapatın, 🖐 doğrulayın |
| 5.6 | Kullanıcı duraklatma | `allowUserPause:false` iken yapılamaz | 🖐 |
| 5.7 | Yönetilen ayar kilidi | Kullanıcı options sayfasında kilitli ayarı değiştiremez | ✅ unit; 🖐 MDM ile |
| 5.8 | Engelli site | Gezinme `blocked.html`'e düşer | ✅ `blocked-site` |
| 5.9 | Shadow AI | Onaysız AI servisi bloklanır, sayılır | ✅ `shadow-ai` |
| 5.10 | Kabul edilebilir kullanım bildirimi | İlk kullanımda gösterilir | ✅ unit; 🖐 |

## 6. Dosyalar

| # | Dosya | Beklenen | Durum |
|---|---|---|---|
| 6.1 | CSV (e-posta, TCKN sütunları) | Maskelenip yüklenir | ✅ `file-upload-csv` |
| 6.2 | DOCX (bölünmüş run'lar) | Yerinde maskelenir | ✅ `file-upload-docx` |
| 6.3 | ODT / PPTX | Yerinde maskelenir, küçük resim boşaltılır | ✅ |
| 6.4 | XLSX | Maskelenir | ✅ unit (`files-office`), 🖐 canlı |
| 6.5 | PDF (hassas veri içeriyor) | **Bloklanır**, "metni yapıştırın" önerilir | ✅ `file-upload-pdf-blocked`. ⚠️ Maskelenip yüklenmiyor |
| 6.6 | Eski .doc / .xls | Bildirilir, blok modunda engellenir | ✅ |
| 6.7 | Görsel (ekran görüntüsünde TCKN) | Native OCR yoksa "incelenmedi" | ❌ OCR native host gerektirir |
| 6.8 | `.env` / JSON dosyası | Secret değerler maskelenir | ✅ unit |
| 6.9 | 5 MB üstü dosya | Politikaya göre bloklanır | 🖐 |
| 6.10 | Sürükle-bırak dosya | Yükleme ile aynı | 🖐 |

## 7. Hata ve dayanıklılık (fail-closed)

| # | Senaryo | Beklenen | Durum |
|---|---|---|---|
| 7.1 | 200.000 karakteri aşan prompt | Tarama "incomplete" olur, **gönderim bloklanır** | ✅ motor + guard kodu |
| 7.2 | Tarama zaman aşımı (1 sn) | Bloklanır | ✅ motor |
| 7.3 | Politika yok / bozuk | Gönderim bloklanır | ✅ unit |
| 7.4 | Service worker yeniden başlar | Vault `storage.session`'dan geri gelir | ✅ |
| 7.5 | Uzantı kapatılır / kaldırılır | ❌ Kullanıcı kapatabilir: `force_installed` politikası şart | 🖐 MDM |
| 7.6 | Gizli pencere (incognito) | Koruma olmalı | ❌ Manifest `"incognito": "not_allowed"`: uzantı gizli pencerede hiç çalışmaz. MDM ile gizli modu kapatın (`IncognitoModeAvailability: 1`, Edge: `InPrivateModeAvailability: 1`) |
| 7.7 | Desteklenmeyen tarayıcı (Safari, Arc vb.) | Koruma yok | ❌ Kapsam dışı |

## 8. Performans

| # | Senaryo | Ölçülen (4 çekirdek, Node) | Hedef |
|---|---|---|---|
| 8.1 | 1 KB prompt | 2 ms | < 50 ms ✅ |
| 8.2 | 10 KB prompt | 14 ms | < 100 ms ✅ |
| 8.3 | 100 KB prompt | 80 ms | < 300 ms ✅ |
| 8.4 | 500 KB prompt | 341 ms | ✅ |
| 8.5 | Yazarken gecikme hissi | Gönderime kadar yok | 🖐 |

## 9. Gizlilik ve telemetri

| # | Senaryo | Beklenen | Durum |
|---|---|---|---|
| 9.1 | Telemetri yalnızca sayım | Ham değer, prompt, URL yolu gitmez | ✅ unit (`background-telemetry`) |
| 9.2 | `storage.local` içeriği | Vault değerleri yalnızca `storage.session`'da | ✅ unit; 🖐 DevTools ile |
| 9.3 | Uzantının dış ağ istekleri | Yalnızca yapılandırılmış control plane | 🖐 Network sekmesi |

## Bilinen açıklar — POC öncesi karar gerekiyor

| Öncelik | Açık | Ne yapılmalı |
|---|---|---|
| **P0** | Serbest metindeki isimler maskelenmiyor (kurallar %8,7) | `ml/pii-tiny` modeli. POC'ye kadar yetişmezse müşterinin isim listesini `exactData` ile yükleyin ve sınırlamayı yazılı söyleyin |
| **P0** | `allowSendAnyway` varsayılan `true` | POC yönetilen politikasında `false` |
| **P0** | Gizli pencerede koruma yok (7.6) | POC cihazlarında MDM ile gizli modu kapatın; kapatılamıyorsa müşteriye söyleyin |
| **P0** | Canlı site kabulü yok (bölüm 4) | Her site için 4.1–4.7'yi POC'den 1–2 gün önce elle koşun. DeepSeek/Mistral/Grok için E2E fixture'ı da yok |
| P1 | Mesaj düzenleme / regenerate yolları test edilmemiş | 4.5–4.6 elle |
| P1 | PDF maskelenmiyor, yalnızca bloklanıyor; görseller OCR'sız | Müşteriye söyleyin |
| P1 | EN adres ekleri (Terrace, Close, Way), bitişik plaka, düz "at/dot" e-posta | Kural ekleme (küçük iş) |
| P2 | Yanıtta küçük harfe çevrilmiş placeholder geri açılmıyor | Vault'ta büyük/küçük harf duyarsız eşleşme |
| P2 | Ajan tarafı (core DLP) yapıştırılan tablo/JSON tespitini almadı | `structured.ts` mantığını core'a taşımak |

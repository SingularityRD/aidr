# Singularity AIDR — Güvenlik Denetim Raporu

**Tarih:** 26 Mayıs 2026  
**Proje:** Singularity AIDR (AI Agent Detection & Response)  
**Kapsam:** `packages/`, `supabase/functions/`, `threats/`, `allowlists/`, konfigürasyon dosyaları  
**Metodoloji:** Kaynak kod incelemesi, mimari analiz, bağımlılık taraması, secret/konfig denetimi

---

## 1. Yönetici Özeti

Singularity AIDR, AI ajanlarının tool çağrılarını denetlemek için tasarlanmış bir güvenlik katmanıdır. Projenin güvenlik bilinci yüksektir: TypeScript strict mod, pre-commit hook'lar (gitleaks, secret taraması), Zod doğrulama, CSP/CORS yapılandırması ve Sentry entegrasyonu gibi temel güvenlik önlemleri mevcuttur.

**Genel Puan: 7.5 / 10** — İyi temel, ancak bazı kritik boşluklar var.

### Öne Çıkan Bulgular

| Kategori | Durum |
|----------|-------|
| Auth & Yetkilendirme | ⚠️ Dual auth sistemi (Clerk + Supabase) karmaşık, IDOR riskleri mevcut |
| Input Validasyonu | ✅ Heuristik motor var, ancak hook giriş noktalarında zayıf |
| Secret Yönetimi | ✅ Gitleaks + pre-commit, .env.example temiz |
| Bağımlılık Güvenliği | ⚠️ Pnpm overrides var, düzenli audit mekanizması eksik |
| Veri Gizliliği | ✅ Kaynak kodu gönderilmiyor, local-first tasarım |
| Altyapı | ⚠️ Supabase Edge Function'lar variable env doğrulaması yapmıyor |

---

## 2. Kimlik Doğrulama ve Yetkilendirme Değerlendirmesi

### 2.1. Çift Kimlik Doğrulama Sistemi

Projede **iki farklı auth sistemi** bulunmaktadır:

| Sistem | Lokasyon | Kullanım |
|--------|----------|----------|
| Clerk | `aidr-landing/` (ayrı repo) | Landing sayfası |
| Supabase Auth | `packages/dashboard/` | Dashboard, callback, device auth |

**Risk:** İki farklı auth sistemi arasında oturum paylaşımı yoktur. Kullanıcı landing sayfasında Clerk ile, dashboard'da Supabase ile oturum açar. Bu, kullanıcı deneyimini olumsuz etkiler ve potansiyel olarak **token sızıntısına** yol açabilir.

### 2.2. Supabase Auth (Dashboard)

**Dosya:** `packages/dashboard/src/lib/supabase.ts`
- `VITE_SUPABASE_ANON_KEY` kullanılmaktadır — Supabase anon key, Row Level Security (RLS) ile sınırlandırılmıştır.
- Anon key eksik olduğunda **fail-open** mock döndürür (satır 17-21). Bu, geliştirme sırasında güvenlik kontrollerini atlar ancak üretimde sorun yaratmaz.

**Dosya:** `packages/dashboard/src/main.tsx`
- Router loader'da `requireSessionLoader` (satır 27-34) ile route koruması yapılmıştır.
- Oturum yoksa `/login?returnTo=...` yönlendirmesi yapılır.
- **Eksik:** `requireSessionLoader` yalnızca belirli route'lar için kullanılır. Tüm korumalı route'ların bu loader'ı kullandığı doğrulanmalıdır.

### 2.3. Device Auth (Ajan Kaydı)

**Dosya:** `docs/device-auth.md`

Device authorization flow'u:
1. Ajan istemcisi kısa ömürlü bir doğrulama kodu üretir
2. Kullanıcı tarayıcıda kodu girerek yetkilendirir
3. Başarılı enrollment sonrası `~/.singularity-aidr/managed.json` önbelleğe alınır

**Artılar:**
- Kod kısa ömürlü ve tek kullanımlı (`docs/device-auth.md` satır 25)
- Pilot onayı ile kapılı (`supabase/functions/_shared/device-auth.ts` satır 28-30)
- Süre dolumu kontrolü (satır 22-23)

**Riskler:**
- `device-start` Edge Function'ı user_code ve device_code üretir. Kod uzunluğu ve entropy bilgisi incelenmelidir.
- Polling mekanizması (`interval_seconds`) brute-force saldırılarına açık olabilir.

### 2.4. OAuth Callback Güvenliği

**Dosya:** `packages/dashboard/src/ui/pages/AuthCallbackPage.tsx`
- `exchangeCodeForSession()` ile Supabase OAuth callback işleniyor (satır 25)
- 10 saniyelik timeout ile `onAuthStateChange` dinleniyor (satır 43-46)
- **Eksik:** `state` parametresi doğrulaması yok — CSRF saldırısı potansiyeli.

### 2.5. ReturnTo Yönlendirme Güvenliği

**Dosya:** `packages/dashboard/src/ui/return-to.ts`
- `returnTo` parametresi localStorage'da saklanır (satır 5-8)
- `buildReturnToFromRequest()` fonksiyonu (satır 22-30) URL'den path alır — Open Redirect riski kısmen azaltılmıştır
- **Risk:** `takePostAuthReturnTo()` değeri `startsWith("/")` kontrolünden geçer (`AuthCallbackPage.tsx` satır 17), ancak `EnterpriseAuth.tsx` (satır 12) sadece `.trim()` yapar.

### 2.6. Enterprise Auth

**Dosya:** `packages/dashboard/src/enterprise/auth.tsx`
- GitHub/GitLab OAuth, `read:org` / `read_api` scope'ları ile (satır 26)
- `returnTo` parametresi doğrudan URL'den alınıyor (satır 12) — validasyon yok
- Team invite token Edge Function'a ham olarak gönderiliyor (satır 43-44)

### 2.7. IDOR (Insecure Direct Object Reference) Riskleri

**Tespit:** `packages/dashboard/src/auth/google-provider.tsx`
- `loadSharedCredentials()` fonksiyonu (satır 71-77) `owner_id` ile credential_shares tablosundan veri çeker.
- **Risk:** Sunucu tarafı RLS politikaları olmadan, bir kullanıcı başka bir kullanıcının share'lerini görebilir.
- `credential_shares`, `api_keys`, `enrollment_tokens` tablolarında RLS politikalarının doğrulanması gerekir.

---

## 3. Input Validasyon Analizi

### 3.1. SDK Middleware

**Dosya:** `packages/sdk/src/middleware.ts`
- Express uyumlu middleware zinciri mevcut (satır 90-96)
- `wrap()` fonksiyonu (satır 68-85) ile fonksiyon sarmalama yapılabiliyor
- Security check sonucu `deny` ise hata fırlatılıyor (satır 76-78)
- **Eksik:** Middleware input validasyonu yok — request body doğrudan işleniyor.

### 3.2. Hook Entry Points

**Dosya:** `packages/extension/src/aidr-hook.ts`
- Hook payload'ı stdin'den JSON olarak okunuyor (satır 55)
- `handleCursor()` ve `handleVsCode()` normalizasyon yapıyor (satır 70-96)
- Normalizasyon başarısız olursa **allow** ile fail-open (satır 79-83, 89-95)
- **Kritik:** Hata durumunda default allow politikası uygulanıyor — bu, korumanın sessizce atlanmasına neden olabilir.

### 3.3. URL Check Input

**Dosya:** `supabase/functions/url-check/index.ts`
- `extractUrlLike()` (satır 38-49) URL doğrulaması yapıyor
- `domainFromUrl()` (satır 51-59) `new URL()` ile parse ediyor
- **İyi:** URL parsing try-catch ile sarılmış, geçersiz URL'ler null döndürüyor.

### 3.4. Waitlist Signup

**Dosya:** `supabase/functions/waitlist-signup/index.ts`
- CORS origin kontrolü yapılıyor (satır 71-73)
- IP-based rate limiting (satır 42-68) — IP hash'lenerek saklanıyor (SHA-256, ilk 16 hex karakter)
- **Fail-open:** Rate limit hatasında `return true` (satır 54) — limit aşımı sessizce geçilir.
- **Eksik:** Email validasyonu yok — body içindeki email kontrol edilmiyor.

### 3.5. DLP (Data Loss Prevention)

**Dosya:** `packages/core/src/dlp/entropy-detector.ts`
- Entropy bazlı secret dedeksiyonu mevcut
- Yüksek entropy değerleri tespit edildiğinde uyarı üretiliyor

---

## 4. Secret ve Konfigürasyon Değerlendirmesi

### 4.1. .env.example Analizi

**Dosya:** `.env.example`

| Değişken | Risk Seviyesi | Açıklama |
|----------|--------------|----------|
| `ANTHROPIC_API_KEY` | **YÜKSEK** | Placeholder `sk-ant-api03-xxxxxxxx` — gerçek key commit'lenirse felaket |
| `OPENCLAW_GATEWAY_TOKEN` | YÜKSEK | Gateway token placeholder |
| `SENTRY_DSN` | ORTA | Placeholder URL |
| `VITE_SUPABASE_URL` | ORTA | Geliştirme ortamına özel |
| `VITE_SUPABASE_ANON_KEY` | DÜŞÜK | Anon key, RLS ile korunmalı |

**İyi:** `.env.example` dosyasında gerçek secret bulunmuyor, tüm değerler placeholder.

### 4.2. Gitleaks Yapılandırması

**Dosya:** `.gitleaks.toml`
- Default kurallar kullanılıyor (`useDefault = true`)
- **Allowlist:**
  - Test dosyaları (`__tests__/`) — gerekli, test fixture'ları için
  - `landing/src/components/InstructionsSection.tsx` — izlenmeli
  - `.next/` klasörü — build çıktısı
- `AAAATESTKEY` regex — test key'leri için
- `gitleaks:allow` — inline override imkanı

**Risk:** Allowlist'teki `landing/` dosyaları ve `.next/` klasörü geniş kapsamlı. `.next/` içinde derlenmiş secret'lar olabilir.

### 4.3. Pre-commit Hooks

**Dosya:** `.pre-commit-config.yaml`
- Gitleaks (v8.24.2) — secret taraması
- detect-private-key — private key dedeksiyonu
- check-added-large-files (500KB limit)
- Biome lint + typecheck + test

**İyi:** Kapsamlı pre-commit zinciri. **Eksik:** `pnpm audit` veya güvenlik taraması pre-commit'e eklenmemiş.

### 4.4. Supabase Environment Variable Handling

**Sorun:** Birden çok Supabase Edge Function'da environment variable'lar boş string fallback ile kullanılıyor:

```typescript
// supabase/functions/url-check/index.ts
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
```

Boş string ile devam edilmesi, runtime hatalarına veya güvenlik açıklarına yol açabilir. Aynı pattern `waitlist-signup/index.ts` (satır 10-11) ve diğer fonksiyonlarda da mevcut.

---

## 5. Bağımlılık Güvenliği

### 5.1. Pnpm Overrides

**Dosya:** `package.json` (satır 7-12)
```json
"overrides": {
    "@hono/node-server": "1.19.10",
    "express-rate-limit": "8.2.2",
    "hono": "4.12.7",
    "path-to-regexp": "8.4.0"
}
```

**Overrides** belirli bağımlılıkları sabit sürümlere kilitleyerek güvenlik güncellemelerini engelleyebilir. Özellikle `path-to-regexp` regex ReDoS saldırılarına karşı hassastır.

### 5.2. Bağımlılık Sayısı ve Güven Ağı

- **pnpm-lock.yaml** 7748 satır — geniş bağımlılık ağacı
- **Kritik:** `@sentry/browser`, `@sentry/node`, Supabase JS client, OpenAI API istemcisi, MCP SDK
- `koffi` native binding — `onlyBuiltDependencies` içinde (satır 14) — native kod güvenilir değerlendirilmeli
- **pnpm.onlyBuiltDependencies** doğru yapılandırılmış, yalnızca `koffi`'ye izin veriliyor

### 5.3. Güvenlik Açığı Taraması

- `SECURITY.md` dosyasında `pnpm audit` düzenli kullanıldığı belirtilmiş
- Ancak CI/CD pipeline'ında otomatik `pnpm audit` adımı yok
- Güvenlik açığı raporlama için GitHub Security Advisories kullanılıyor

---

## 6. Veri Gizliliği Değerlendirmesi

### 6.1. Local-First Tasarım

**Dosya:** `docs/privacy.md`

| Veri Türü | İletim Durumu |
|-----------|--------------|
| Kaynak kodu | ❌ Asla gönderilmez |
| Komutlar | ❌ Lokal kalır |
| Dosya yolları | ❌ Lokal kalır |
| URL'ler | ✅ Repütasyon API'sine gönderilir |
| Package hash'leri | ✅ SHA-256 hash gönderilir |
| Versiyon bilgisi | ✅ POST ile gönderilir |
| Kurulum ID'si | ✅ Random UUID, ~/.singularity-aidr/installation-id |

**İyi:** Kaynak kodu asla gönderilmiyor, tüm heuristik eşleştirme lokal çalışıyor.

### 6.2. Kullanıcı Tarafından Devre Dışı Bırakma

```json
{
  "url_check": { "enabled": false },
  "file_check": { "enabled": false }
}
```

URL ve file repütasyon kontrolleri kapatıldığında tamamen lokal çalışma mümkün.

### 6.3. Telemetry ve İzleme

- `packages/dashboard/src/sentry.ts` — Sentry DSN env'den alınıyor
- `packages/extension/src/sentry.ts` — Aynı pattern
- **Risk:** Sentry DSN public (client-side) olduğundan, üretimde DSN'nin sızdırılması mümkün. Sentry rate limiting gereklidir.
- `packages/core/src/tracing.ts` — OTel tracing yapılandırması

---

## 7. Kod Güvenlik Pattern'leri

### 7.1. TypeScript Strict Mode

**Dosya:** `tsconfig.base.json`

```json
{
  "strict": true,
  "noUncheckedIndexedAccess": true,
  "verbatimModuleSyntax": true
}
```

**İyi:** Strict null checks, unchecked indexed access koruması mevcut. Bu, null/undefined hatalarını ve tip güvenliği açıklarını önler.

### 7.2. Biome Linter

**Dosya:** `biome.json`
- `noExplicitAny` lint kuralı aktif — `aidr-hook.ts`'te (satır 40) `any` cast ile baypas edilmiş
- `.pre-commit-config.yaml`'de lint zorunlu

### 7.3. Decision Engine

**Dosya:** `packages/core/src/engine.ts`
- **Confidence threshold:** 0.85 (balanced) — düşürülebilir (paranoid: 0.7)
- **Action mapping:** `block → deny`, `require_approval → ask`, `log → allow`
- **Severity mapping:** `critical → critical`, `high → warning`, `medium → warning`, `low → info`
- **Decision priority:** `deny > ask > allow` — doğru önceliklendirme
- **Eksik:** Decision logging veya audit trail entegrasyonu zorunlu değil

### 7.4. Threat Definitions

**Dosya:** `threats/commands.yaml`
- 60+ threat pattern — `curl | bash`, reverse shell, data exfiltration, crypto mining
- Platform-specific threatler: `mac-commands.yaml`, `win-commands.yaml`
- MITRE ATT&CK mapping: `threats/mitre.yaml`
- **İyi:** Kapsamlı threat kataloğu, expires_at ve revoked özellikleri ile sürdürülebilir

### 7.5. Integrity Verification

**Dosya:** `docs/integrity.md`
- Ed25519 imza doğrulaması
- **Fail-open:** İmza doğrulama başarısız olursa çalışmaya devam eder (sadece audit log'a yazar)
- Public key PEM formatında yapılandırılabilir

---

## 8. Altyapı Güvenliği

### 8.1. CORS Yapılandırması

**Dosya:** `supabase/functions/_shared/origin.ts`
- `parseAllowedOrigins()` — virgülle ayrılmış origin listesi
- `resolveAllowedOrigin()` — wildcard (`*`) desteği var
- `buildCorsHeaders()` — dinamik origin yansıtma

**Risk:** `AIDR_ALLOWED_ORIGINS` env değişkeninde wildcard kullanılırsa, tüm origin'lerden istek kabul edilir. Her Edge Function'da ayrı ayrı kontrol edilmelidir.

### 8.2. Edge Function Auth

**Dosya:** `supabase/functions/_shared/auth.ts`
- Basit Bearer token çıkarıcı (5 satır)
- **Eksik:** Token doğrulama fonksiyonu yok — her Edge Function token'ı kendi doğrulamalı

**Dosya:** `supabase/functions/url-check/index.ts`
- `getBearerToken()` ile Authorization header'dan token alınıyor (satır 23-27)
- Token doğrulaması `supabase` client ile yapılıyor
- **İyi:** API key kullanımı için Supabase Auth entegrasyonu

### 8.3. Rate Limiting

**Dosya:** `supabase/functions/waitlist-signup/index.ts`
- IP-based rate limiting (satır 42-68)
- Varsayılan: dakikada 10 istek (`AIDR_WAITLIST_RL_PER_MIN`)
- IP hash'lenerek saklanıyor (SHA-256, ilk 16 karakter)
- **Fail-open:** Veritabanı hatasında herkese izin verilir

### 8.4. CSP (Content Security Policy)

CSP header'ları kontrol edilmelidir. Mevcut kodda:
- Express middleware (`packages/sdk/src/middleware.ts`) CSP eklemiyor
- Dashboard'da CSP yapılandırması görünmüyor
- **Eksik:** CSP header'ları eklenmemiş — XSS saldırılarına karşı zafiyet

---

## 9. Kritik Sorunlar (P0)

| # | Sorun | Dosya | Açıklama |
|---|-------|-------|----------|
| P0-01 | **Hook fail-open default allow** | `packages/extension/src/aidr-hook.ts` satır 89-95 | Hata durumunda güvenlik kontrolü atlanır, tüm tool çağrılarına izin verilir |
| P0-02 | **IDOR riski — credential_shares** | `packages/dashboard/src/auth/google-provider.tsx` satır 71-77 | `owner_id` ile filtreleme yapılıyor ancak RLS politikaları doğrulanmamış |
| P0-03 | **Supabase Service Role Key env doğrulaması yok** | `supabase/functions/url-check/index.ts`, `waitlist-signup/index.ts` | `SUPABASE_SERVICE_ROLE_KEY` boş string ile kullanılırsa tüm veritabanı işlemleri başarısız olur |

---

## 10. Yüksek Öncelikli Sorunlar (P1)

| # | Sorun | Dosya | Açıklama |
|---|-------|-------|----------|
| P1-01 | **OAuth state parametresi doğrulaması yok** | `packages/dashboard/src/ui/pages/AuthCallbackPage.tsx` | CSRF saldırısı potansiyeli |
| P1-02 | **EnterpriseAuth returnTo open redirect** | `packages/dashboard/src/enterprise/auth.tsx` satır 12 | `returnTo` validasyonu sadece trim, `startsWith("/")` kontrolü yok |
| P1-03 | **Sentry DSN client-side sızıntısı** | `packages/dashboard/src/sentry.ts`, `packages/extension/src/sentry.ts` | Public DSN rate limiting olmadan abuse edilebilir |
| P1-04 | **pnpm overrides güvenlik güncellemelerini engelliyor** | `package.json` satır 7-12 | Sabit sürümler güvenlik patch'lerini atlar |
| P1-05 | **Edge Function'lar env doğrulaması yapmıyor** | Birden çok dosya | `?? ""` pattern'i runtime hatalarına yol açar |
| P1-06 | **Rate limit fail-open** | `supabase/functions/waitlist-signup/index.ts` satır 54 | DB hatasında rate limit atlanır |

---

## 11. Orta Öncelikli Sorunlar (P2)

| # | Sorun | Dosya | Açıklama |
|---|-------|-------|----------|
| P2-01 | **Çift auth sistemi (Clerk + Supabase)** | `aidr-landing/` + `packages/dashboard/` | Token sızıntısı, oturum yönetimi karmaşıklığı |
| P2-02 | **Biome noExplicitAny baypas** | `packages/extension/src/aidr-hook.ts` satır 40 | `any` cast ile tip güvenliği atlanmış |
| P2-03 | **CSP header'ları eksik** | `packages/sdk/src/middleware.ts` | XSS koruması zayıf |
| P2-04 | **pnpm audit CI/CD'de otomatik değil** | `.github/` (kontrol edilmeli) | Bağımlılık güvenlik taraması manuel |
| P2-05 | **Gitleaks allowlist geniş kapsamlı** | `.gitleaks.toml` satır 9-13 | `.next/` ve landing dosyaları tarama dışı |
| P2-06 | **Allowed origins wildcard riski** | `supabase/functions/_shared/origin.ts` | `*` origin tüm domain'lerden istek kabul eder |
| P2-07 | **Device code entropy bilinmiyor** | `supabase/functions/device-start/index.ts` | Kod uzunluğu ve karakter seti incelenmeli |

---

## 12. Düşük Öncelikli Sorunlar (P3)

| # | Sorun | Dosya | Açıklama |
|---|-------|-------|----------|
| P3-01 | **Session mock fail-open** | `packages/dashboard/src/lib/supabase.ts` satır 17-21 | Geliştirme ortamında auth kontrolleri atlanır |
| P3-02 | **Integrity check fail-open** | `docs/integrity.md` satır 9 | İmza doğrulama başarısız olursa çalışma devam eder |
| P3-03 | **Base64 user ID referral kod** | `packages/dashboard/src/auth/google-provider.tsx` satır 81-85 | `btoa(userId)` — kolayca decode edilebilir, güvenlik değil obfuscation |
| P3-04 | **Console.timeLog kullanımı** | Kod tabanında dağınık | Performans logging'i üretimde info sızıntısı |
| P3-05 | **pre-commit audit eklentisi yok** | `.pre-commit-config.yaml` | `pnpm audit` pre-commit hook'u eklenebilir |

---

## 13. Öneriler

### Acil (0-30 gün)

1. **Hook fail-open'i düzeltin:** `aidr-hook.ts`'de hata durumunda `deny` default politika uygulayın. Kullanıcıya hata gösterin, sessizce allow yapmayın.
   ```typescript
   // Mevcut:
   writeJson(internalCursorResponse("allow", "...internal error..."));
   // Önerilen:
   writeJson(internalCursorResponse("deny", "AIDR internal error; protection unavailable"));
   ```

2. **Supabase RLS politikalarını doğrulayın:** `credential_shares`, `api_keys`, `enrollment_tokens` tablolarında kullanıcı bazlı RLS politikalarının aktif olduğundan emin olun.

3. **Supabase Edge Function env validasyonu ekleyin:** Her fonksiyon başlangıcında kritik env değişkenlerini doğrulayın:
   ```typescript
   if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
     return new Response("Server configuration error", { status: 500 });
   }
   ```

### Kısa Vade (30-90 gün)

4. **OAuth state parametresi ekleyin:** PKCE flow'unda `state` parametresi doğrulamasını implemente edin.

5. **returnTo validasyonu ekleyin:** `EnterpriseAuth.tsx`'de `returnTo` değerini `startsWith("/")` ile doğrulayın.

6. **CSP header'ları ekleyin:** Express middleware'de veya Supabase Edge Function'larda Content-Security-Policy header'ı ekleyin.

7. **CI/CD'ye pnpm audit ekleyin:** GitHub Actions workflow'una otomatik güvenlik taraması adımı ekleyin.

### Orta Vade (90-180 gün)

8. **Tek auth sistemine geçiş planı yapın:** Clerk veya Supabase Auth'dan birine odaklanın. İkili sistem bakım yükünü artırır.

9. **pnpm overrides'ı gözden geçirin:** Her override için neden ve son kullanma tarihi ekleyin. Düzenli olarak güncelleyin.

10. **Device code entropy'sini artırın:** Brute-force saldırılarına karşı kod uzunluğunu ve karakter setini gözden geçirin.

11. **Rate limiting'i tüm Edge Function'lara ekleyin:** Her fonksiyon için uygun rate limit politikası belirleyin, fail-open yerine fail-closed tercih edin.

12. **Referral kod mekanizmasını güçlendirin:** Base64 yerine kriptografik olarak güvenli random string kullanın.

### Sürekli İyileştirme

- Haftalık `pnpm audit` ve `npm audit` taraması
- Aylık bağımlılık güncelleme döngüsü
- Üç aylık güvenlik denetimi
- Bug bounty programı (opsiyonel)

---

## Ekler

- **Threat definitions:** `threats/` (23 dosya, 60+ pattern)
- **Configured tools:** Gitleaks, Biome, pre-commit, pnpm overrides
- **Monitoring:** Sentry (dashboard + extension), OTel tracing
- **Auth systems:** Clerk (landing), Supabase Auth (dashboard), Device Auth (agent)
- **Local storage:** `~/.singularity-aidr/` (config, cache, audit log, managed state)

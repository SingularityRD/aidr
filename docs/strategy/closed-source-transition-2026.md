# Singularity AIDR — Kapalı Kaynak Geçiş Stratejisi 2026

> **Karar**: Apache 2.0 açık kaynaktan tamamen kapalı kaynağa geçiş
> **Tarih**: Mayıs 2026
> **Hedef**: Piyasanın en iyi AI ajan güvenlik ürünü olmak

---

## İçindekiler

1. [Stratejik Gerekçe](#1-stratejik-gerekçe)
2. [Geçiş Takvimi](#2-geçiş-takvimi)
3. [Yeni Moat Stratejisi](#3-yeni-moat-stratejisi)
4. [Ürün ve Mimari Değişiklikleri](#4-ürün-ve-mimari-değişiklikleri)
5. [Dağıtım ve Lisans Modeli](#5-dağıtım-ve-lisans-modeli)
6. [Marka ve Konumlandırma](#6-marka-ve-konumlandırma)
7. [Yeni Fiyatlandırma](#7-yeni-fiyatlandırma)
8. [Yol Haritası](#8-yol-haritası)
9. [Risk ve Mitigasyon](#9-risk-ve-mitigasyon)
10. [Aksiyon Maddeleri](#10-aksiyon-maddeleri)

---

## 1. Stratejik Gerekçe

### Neden Kapalı Kaynak?

| Gerekçe | Açıklama |
|---------|----------|
| **Enterprise satış** | Kurumsal müşteriler güvenlik ürününün kapalı kaynak olmasını tercih eder (SAT, SOC2, vendor assessment) |
| **Taklit koruması** | Declaw ve diğer rakiplerin kodu fork'layıp rakip ürün yapmasını engeller |
| **Yatırım/Exit değeri** | Kapalı kaynak şirketlerin değerlemesi daha yüksektir (IP koruması, tekel avantajı) |
| **Monetizasyon kontrolü** | Her özellik için ücret talep edebilme esnekliği |
| **Veri moat'ı** | Threat intelligence, ML modelleri, detection pattern'ları — bunlar açık kaynakta rakiplere bedava gider |
| **CrowdStrike rekabeti** | Açık kaynak olmanın CrowdStrike'a karşı avantajı yok (onlar da kapalı), oyun alanını eşitler |

### Neden Şimdi?

Pazar penceresi **6-12 ay içinde kapanıyor**. Şu an:
- Kategori henüz tanımlanmamış durumda
- Hiçbir oyuncu dominant değil
- CrowdStrike ürünü henüz olgunlaşmadı
- Straiker $40M fonladı ama henüz pazarı ele geçirmedi
- MCP standardı yeni oturuyor — bu alanda hızla pozisyon almak mümkün

**Geçiş için en uygun zaman: ŞİMDİ.**

---

## 2. Geçiş Takvimi

```
Hafta 1: HAZIRLIK
├── GitHub repo archive + README güncelleme
├── npm paketlerini deprecate etme
├── VS Code extension kaldırma
├── Yeni private repo kurulumu
└── Strateji dokümanının tamamlanması

Hafta 2: YENİ ALTYAPI
├── Private npm registry kurulumu (GitHub Packages)
├── Private VSIX dağıtım pipeline'ı
├── CI/CD'nin private repo'ya taşınması
└── SaaS kontrol düzleminin ana ürün haline getirilmesi

Hafta 3-4: ÜRÜN
├── SaaS-first mimari değişiklikleri
├── Lisanslama/activation sistemi
├── Trial mekanizması (14 gün full feature)
└── Mevcut kullanıcıların migrasyon planı

Ay 2-3: YENİ MOAT
├── ML detection MVP
├── Threat intel pipeline
├── MCP enforcement productization
└── Enterprise özellikler (SSO, RBAC)

Ay 4-6: BÜYÜME
├── Enterprise pilot programı
├── SOC2 başvurusu
├── Partner programı
└── Global satış kanalı
```

---

## 3. Yeni Moat Stratejisi

### Karşılaştırma: Eski Moat vs Yeni Moat

```
ESKİ MOAT (Açık Kaynak)          YENİ MOAT (Kapalı Kaynak)
━━━━━━━━━━━━━━━━━━━━━            ━━━━━━━━━━━━━━━━━━━━━━━

Açık kaynak (Apache 2.0)    →    Özel ML modelleri + threat intel
Topluluk threat rules       →    Profesyonel tehdit araştırma ekibi
Viral GitHub büyümesi       →    Enterprise satış + içerik pazarlama
Developer trust             →    SOC2/compliance + referans müşteriler
"Free as in beer"           →    "Freemium" (sınırlı free, güçlü premium)
```

### Yeni Savunma Hatları

```
Savunma Katmanı 1: VERİ MOAT'ı
├── Threat intelligence veritabanı (URL reputation, package risk)
├── ML detection modelleri (sürekli güncellenen, eğitilmiş)
├── Anomaly detection profilleri (kullanıcı davranış modelleri)
└── Attack pattern veritabanı (toplanan telemetri ile güçlenir)
└──→ Rakipler bu veriyi toplayamaz → AIDR büyüdükçe daha akıllı olur

Savunma Katmanı 2: ÜRÜN MOAT'ı
├── SaaS kontrol düzlemi (dashboard, policy management, audit)
├── MCP enforcement motoru (MCP standardı ile derin entegrasyon)
├── Enterprise özellikler (SSO, RBAC, audit log consolidation)
└── CI/CD entegrasyonu (GitHub Action, GitLab CI)
└──→ Rakiplerin aynı seviyeye gelmesi aylar alır

Savunma Katmanı 3: GEÇİŞ MALİYETİ MOAT'ı
├── Agent enrollment + device auth (her ajan kayıtlı, yönetiliyor)
├── Policy engine (takım bazlı policy'ler, rollout)
├── Audit trail (tüm ajan aksiyonları kayıtlı)
└── Team dashboard (takım alıştı, bırakması zor)
└──→ Kullanıcılar AIDR'e ne kadar çok entegre olursa bırakması o kadar zor
```

---

## 4. Ürün ve Mimari Değişiklikleri

### 4.1 Mevcut Mimari (Açık Kaynak)

```
[Claude Code] ───→ @aidr-core (Apache 2.0) ───→ YAML threats (public)
[OpenClaw]   ───→ @aidr-core (Apache 2.0) ───→ URL check (public API)
[Cursor]     ───→ aidr-cursor (Apache 2.0) ───→ Threat rules (public)
[OpenCode]   ───→ @aidr-opencode (Apache 2.0)
                    ↓
              SaaS Dashboard (isteğe bağlı)
```

### 4.2 Yeni Mimari (Kapalı Kaynak)

```
[Claude Code] ───→ @aidr-core (PRIVATE, signed) ───→ Threat intel cloud (private)
[OpenClaw]   ───→ @aidr-core (PRIVATE, signed) ───→ ML detection (private)
[Cursor]     ───→ aidr-cursor (PRIVATE VSIX)  ───→ Policy engine (SaaS)
[OpenCode]   ───→ @aidr-opencode (PRIVATE)
                    ↓
              SaaS CONTROL PLANE (ZORUNLU)
              ├── Agent enrollment
              ├── Policy management
              ├── Threat intel sync
              ├── Audit & incidents
              ├── Team management
              └── Billing
```

### 4.3 Kritik Mimari Kararlar

| Karar | Açıklama |
|-------|----------|
| **SaaS zorunlu mu?** | EVET — Agent'lar çalışmak için kontrol düzlemine bağlanmalı (offline mode sadece basic protection) |
| **Yerel motor hala çalışıyor mu?** | EVET — Tespit motoru hala local'de çalışır ama threat rules/intel cloud'dan sync edilir |
| **Offline mode?** | SINIRLI — Son sync edilen threat rules ile basic protection, ML detection çalışmaz |
| **Private key/signing?** | EVET — Her binary code-signed olmalı (tamper protection) |
| **License activation?** | EVET — Her agent için license key + device enrollment |

### 4.4 Yeni Paket Yapısı

```
@singularityrd/aidr-core          → GitHub Packages (private)
@singularityrd/aidr-claude-code   → GitHub Packages (private)  
@singularityrd/aidr-openclaw      → GitHub Packages (private)
@singularityrd/aidr-opencode      → GitHub Packages (private)
aidr-cursor                       → Private VSIX + side-loading
aidr-landing                      → Vercel (public — marketing + SaaS)
```

---

## 5. Dağıtım ve Lisans Modeli

### 5.1 Dağıtım Kanalları

| Platform | Eski | Yeni |
|----------|------|------|
| **npm** | Public (@singularityrd/*) | Private (GitHub Packages) |
| **VS Code Marketplace** | Public | Removed (private VSIX) |
| **Claude Code Plugin** | Public (marketplace add) | Private (direkt URL + token) |
| **OpenClaw** | Public plugin | Private plugin (token gerekli) |
| **OpenCode** | Public plugin | Private plugin |
| **GitHub** | Public repo | Private repo |
| **SaaS Dashboard** | isteğe bağlı | ZORUNLU (ücretsiz tier'da) |

### 5.2 Lisans Modeli

```
Tüm kapalı kaynak kod: Proprietary License
© 2026 SingularityRD. All rights reserved.

Kullanım Şartları:
- Ücretsiz Tier: 1 agent, 14 gün audit log retention, basic protection
- Pro: $2/agent/ay, 90 gün retention, ML detection, team dashboard
- Enterprise: $8/agent/ay, sınırsız retention, SSO, RBAC, audit, premium support
```

### 5.3 Trial Mekanizması

| Feature | Free (1 agent) | Trial (14 gün) | Pro | Enterprise |
|---------|---------------|----------------|-----|------------|
| Runtime Detection | ✅ Temel | ✅ Full | ✅ Full | ✅ Full |
| ML Detection | ❌ | ✅ | ✅ | ✅ |
| Threat Intel | ❌ | ✅ | ✅ | ✅ |
| MCP Enforcement | ❌ | ✅ | ✅ | ✅ |
| Team Dashboard | ❌ | ✅ | ✅ | ✅ |
| Audit Retention | 14 gün | 90 gün | 90 gün | Sınırsız |
| SSO/RBAC | ❌ | ❌ | ❌ | ✅ |
| Support | Community | Community | Email | Premium |

---

## 6. Marka ve Konumlandırma

### 6.1 CrowdStrike "AIDR" Çakışması Çözümü

CrowdStrike'ın Nisan 2026'da "AIDR" ürününü duyurması kritik bir tehdit.

**Strateji:**
1. **"Singularity AIDR" markasını zorunlu kıl** — Tüm dokümanlarda, web'de, iletişimde sadece "Singularity AIDR" kullan
2. **Trademark başvurusu** — "Singularity AIDR" için hemen başvur
3. **SEO stratejisi** — "singularity aidr", "aidr security", "aidr agent protection" long-tail'leri
4. **Alan adı** — `singularityaidr.com`, `aidr.security` gibi domain'leri al
5. **Ayrışma** — "CrowdStrike AIDR" kurumsal endpoint, "Singularity AIDR" developer agent — net mesaj

### 6.2 Yeni Positioning

```
Eski Positioning:
"Open-source runtime security for AI coding agents"

Yeni Positioning:
"The professional runtime security platform for AI coding agents."
"Your AI agents deserve enterprise-grade protection."
```

### 6.3 Hedef Kitle ve Mesaj

| Kitle | Eski Mesaj | Yeni Mesaj |
|-------|------------|------------|
| **Developer** | "Free, open-source" | "5-minute setup, instant protection" |
| **Security Team** | "Community-driven" | "Enterprise-grade, SOC2-ready" |
| **CTO/VPoE** | "Open source alternative" | "The professional standard for agent security" |

---

## 7. Yeni Fiyatlandırma

| Tier | Fiyat | Agent | Özellikler |
|------|-------|-------|------------|
| **Free** | $0 | 1 agent | Temel runtime detection, 14 gün audit |
| **Pro** | $5/agent/ay | Sınırsız | ML detection, MCP, team dashboard, 90 gün audit |
| **Enterprise** | $15/agent/ay | Sınırsız | Pro + SSO, RBAC, audit consolidation, premium SLA |

*Not: Mevcut fiyatlandırma ($2/$8) çok düşük. Kapalı kaynak + enterprise odak ile fiyatları yükseltmek gerekiyor. Rakipler: Straiker ~$15, Declaw ~$5, HiddenLayer $50K+/yıl.*

### 7.1 Mevcut Kullanıcılar İçin Geçiş

| Kullanıcı Türü | Geçiş Planı |
|----------------|-------------|
| **Free kullanıcılar** | Mevcut free tier devam eder (1 agent), yeni özellikler kapalı |
| **Pro aboneler** | $2 → $5/agent/ay (30 gün önceden haber ver, 60 gün eski fiyattan devam) |
| **Enterprise adayları** | Özel fiyat teklifi, pilot programı |
| **Açık kaynak kullanıcılar** | Son public sürüm kullanılabilir (Apache 2.0), güncelleme/güvenlik yaması gelmez |

---

## 8. Yol Haritası (Kapalı Kaynak)

### Faz 1: Geçiş (Hafta 1-2)
- GitHub repo archive
- npm deprecate
- VS Code extension kaldırma
- Private repo + CI/CD
- SaaS kontrol düzlemi aktivasyonu

### Faz 2: Ürün (Hafta 3-8)
- License / activation sistemi
- Trial mekanizması
- ML detection MVP
- MCP enforcement productize
- Threat intel pipeline

### Faz 3: Kurumsal (Ay 3-6)
- SSO / RBAC
- SOC2 başvurusu
- Enterprise pilot
- Fiyatlandırma güncellemesi
- Partner programı

### Faz 4: Büyüme (Ay 6-12)
- Global satış
- Gelişmiş ML detection
- Mobile agent support
- AI Act compliance modülü
- Exit hazırlığı

---

## 9. Risk ve Mitigasyon

| Risk | Olasılık | Etki | Mitigasyon |
|------|----------|------|------------|
| **Fork riski** (son Apache 2.0 sürümü fork'lanır) | YÜKSEK | ORTA | Kabul edilebilir — fork'lar AIDR'in pazarlama gücüne sahip olmayacak |
| **Topluluk tepkisi** | YÜKSEK | ORTA | Profesyonel iletişim, "why we went closed-source" blog post |
| **Developer güveni kaybı** | ORTA | YÜKSEK | Free tier'ı koru, şeffaf ol, "security requires responsibility" mesajı |
| **CrowdStrike pazarı domine ederse** | ORTA | ÇOK YÜKSEK | Hızlı hareket et, MCP liderliğini kap, markayı farklılaştır |
| **Kullanıcı kaybı** | ORTA | YÜKSEK | Mevcut free kullanıcılara dokunma, sadece yeni özellikleri kapat |
| **Lisansa uyumsuzluk** | DÜŞÜK | ÇOK YÜKSEK | Hukuk danışmanı ile çalış, Apache 2.0 şartlarına uy |

### 9.1 Fork Riski Detayı

Apache 2.0 lisansı altında yayınlanmış kod **sonsuza kadar fork edilebilir**. Declaw, Knox veya herhangi biri son public commit'i alıp kendi fork'unu yapabilir.

**Gerçekçi değerlendirme:**
- Bir fork'un AIDR seviyesine gelmesi **en az 6-12 ay** sürer
- Fork'lar AIDR'in SaaS kontrol düzlemine, ML modellerine, threat intel'e sahip olmaz
- AIDR markası, dağıtım kanalı, müşteri ilişkileri fork'lanamaz
- **Örnekler:** Elasticsearch → OpenSearch (fork başarılı oldu), Terraform → OpenTofu (fork başarılı), HashiCorp Vault → OpenBao (fork zayıf kaldı)

**Karar:** Fork riski kabul edilebilir. Asıl değer SaaS + ML + data'da, koddan ibaret değil.

---

## 10. Aksiyon Maddeleri

### Hafta 1 (Acil)

- [ ] **GitHub repo archive**: Settings → Archive repo + README'ye yönlendirme ekle
- [ ] **README güncelle**: Eski repo'da "moved to private" notu
- [ ] **npm deprecate**: Tüm @singularityrd/* paketlerini deprecate et
- [ ] **VS Code extension kaldır**: Marketplace'ten unpublish
- [ ] **Yeni private repo kur**: GitHub'da private repo, mevcut develop dallarını taşı
- [x] **LICENSE değişiklikleri (mekanik)**: First-party package metadata now declares `Proprietary`; root LICENSE/NOTICE and third-party attribution bundle were updated. Legal review and stale-document reconciliation remain open.

### Hafta 2

- [ ] **GitHub Packages kurulumu**: Private npm registry
- [ ] **CI/CD taşıma**: GitHub Actions'ı private repo'ya taşı
- [ ] **VSIX signing pipeline**: Private VSIX dağıtımı
- [ ] **Claude Code plugin güncelleme**: Private plugin URL'si
- [ ] **SaaS onboarding güncelleme**: Agent enrollment'ı zorunlu kıl

### Hafta 3-4

- [ ] **License activation sistemi**: API key + device enrollment
- [ ] **Trial mekanizması**: 14 gün full feature trial
- [ ] **Threat intel sync pipeline**: Cloud → local agent sync
- [ ] **Marka güncellemeleri**: Web sitesi, dokümanlar, e-postalar
- [ ] **Kullanıcı bildirimi**: Mevcut kullanıcılara geçiş e-postası

### Ay 2-3

- [ ] **ML detection MVP**: 300KB model, <20ms latency
- [ ] **MCP enforcement productization**: V1 release
- [ ] **Enterprise özellikler**: SSO, RBAC
- [ ] **Fiyatlandırma güncellemesi**: $5/$15/agent/month
- [ ] **Blog post**: "Why Singularity AIDR is going private"

---

## Ek: İletişim Planı

### Duyuru Metni (Taslak)

> **Title:** Singularity AIDR is becoming a professional security platform
>
> We started Singularity AIDR as an open-source project to protect AI coding agents.
> Today, we're taking the next step: Singularity AIDR is becoming a professional,
> closed-source security platform.
>
> **What's changing:**
> - The core detection engine is now private (proprietary license)
> - New features: ML-based detection, MCP enforcement, team dashboard
> - Free tier remains (1 agent, basic protection)
> - Pro and Enterprise tiers for professional use
>
> **What's NOT changing:**
> - Your existing agents continue to work
> - Free tier stays free
> - Privacy-first architecture remains
> - Local detection engine still runs on your machine
>
> **Why?**
> Building enterprise-grade AI agent security requires significant investment in
> ML models, threat intelligence, and compliance. Going private lets us deliver
> these capabilities sustainably.
>
> [Link to detailed blog post]

---

*Bu doküman Singularity AIDR'in kapalı kaynak geçiş stratejisini tanımlar. Her hafta gözden geçirilmelidir.*

# Singularity AIDR — Dünya Klasındaki Master Plan

> **Sürüm:** 1.0 | **Son Güncelleme:** Mayıs 2026
> **Kapsam:** AI Agent Detection & Response (AIDR) — Tam Kapsamlı Ürün Stratejisi
> **Dil:** Türkçe
> **Durum:** Yürürlükte

---

## İçindekiler

1. [Ürün Vizyonu (12 Ay)](#1-ürün-vizyonu-12-ay)
2. [Mevcut Durum Değerlendirmesi](#2-mevcut-durum-değerlendirmesi)
3. [İdeal Müşteri Profili (ICP)](#3-i̇deal-müşteri-profili-icp)
4. [Kategori Karşılaştırması](#4-kategori-karşılaştırması)
5. [Ürün Stratejisi](#5-ürün-stratejisi)
6. [Özellik Yol Haritası (P0/P1/P2/P3)](#6-özellik-yol-haritası-p0p1p2p3)
7. [UX Yol Haritası](#7-ux-yol-haritası)
8. [Teknik Yol Haritası](#8-teknik-yol-haritası)
9. [Satış Hazırlığı Yol Haritası](#9-satış-hazırlığı-yol-haritası)
10. [Büyüme Yol Haritası](#10-büyüme-yol-haritası)
11. [Zamana Dayalı Planlar](#11-zamana-dayalı-planlar)
12. [Riskler ve Ödünleşimler](#12-riskler-ve-ödünleşimler)
13. [Henüz İnşa Edilmemesi Gerekenler](#13-henüz-i̇nşa-edilmemesi-gerekenler)
14. [Dünya Klası Tanımı](#14-dünya-klası-tanımı)

---

## 1. Ürün Vizyonu (12 Ay)

### 1.1 Vizyon Beyanı

> **Singularity AIDR, AI kodlama ajanları için dünyanın en kapsamlı runtime güvenlik katmanı olacak. Her Claude Code, Cursor, VS Code, OpenCode ve OpenClaw kullanıcısının çalıştırdığı her komutu, yazdığı her dosyayı, çağırdığı her URL'yi ve bağlandığı her MCP sunucusunu koruyan, sıfır güven (zero-trust) prensibiyle çalışan bir platform.**

### 1.2 12 Ay Sonraki Hedef

| Boyut | Hedef (Mayıs 2027) | Bugünkü Durum (Mayıs 2026) |
|-------|-------------------|---------------------------|
| **Kullanıcı** | 10.000+ aktif kullanıcı (500 + ekip/takım hesabı) | ~200-300 kullanıcı (tahmini) |
| **Gelir** | $1.5M+ ARR (yıllık tekrarlayan gelir) | $0 (henüz satış başlamadı) |
| **Pazar Konumu** | AI ajan güvenliği kategorisinde tanınan lider | Kategori henüz tanımlanmamış |
| **Ekip** | 8-12 kişi (mühendislik, satış, pazarlama) | ~2-3 kişi (kurucu ekibi) |
| **Müşteri** | 20+ kurumsal referans müşterisi | 0 referans müşterisi |
| **Enterprise** | SOC 2 Type II sertifikalı | SOC 2 yok |
| **Detection** | ML destekli + rule-based hibrit | Sadece rule-based |
| **Kapsam** | Claude Code, Cursor, VS Code, OpenCode, OpenClaw + MCP | 4 platform (MCP yeni başlıyor) |

### 1.3 Neden Bu Vizyon Kazanabilir?

AI kodlama ajanları pazarı patlıyor — 2024'te %40 olan kurumsal benimseme, 2026'da %70+'ye ulaştı. Ancak güvenlik altyapısı bu büyümeye ayak uyduramadı. Pazarda **üç büyük boşluk** var:

1. **Runtime güvenliği boşluğu**: Mevcut çözümler ya scanning-only (tarama yapar ama engellemez) ya da policy-only (politika koyar ama uygulamaz). AIDR, gerçek zamanlı ajan koruması sunan tek hafif çözüm.
2. **MCP güvenliği boşluğu**: MCP hızla standartlaşırken, MCP tool çağrılarını denetleyen hiçbir ticari ürün yok. AIDR bu alanda first-mover avantajı yakalayabilir.
3. **Local-first güvenlik boşluğu**: Rakiplerin çoğu cloud-based. AIDR'nin privacy-first, local processing mimarisi, özellikle regüle sektörlerde (finans, sağlık, savunma) benzersiz bir satış avantajı.

### 1.4 En Güçlü Farklılaşma Noktası

**Privacy-first, local-first, real-time runtime security.**

AIDR, AI ajanının her aksiyonunu — komut çalıştırmadan önce, dosya yazmadan önce, URL çağırmadan önce — cihazın kendisinde, buluta hiçbir veri göndermeden denetler. Bu, rakiplerin yapamadığı bir şeydir çünkü:
- CrowdStrike cloud-based analizle çalışır
- HiddenLayer enterprise gateway üzerinden denetler
- Straiker endpoint'te çalışır ama bulut bağımlılığı var
- Declaw fork'tur, kendi altyapısı yok

AIDR, **veri sızdırmayan tek AI ajan güvenlik ürünü** olarak konumlanacak.

---

## 2. Mevcut Durum Değerlendirmesi

*(Mayıs 2026 itibarıyla, tüm düzeltmeler sonrası)*

### 2.1 Teknik Seviye

| Kategori | Seviye (1-10) | Detay |
|----------|--------------|-------|
| **Mimari** | 8/10 | TypeScript monorepo, modüler paket yapısı, taşınabilir. Doğru soyutlama kararları (extractors, heuristics, decision engine ayrışması). |
| **Kod Kalitesi** | 7/10 | Biome lint, TypeScript strict mode, test coverage ~%60. Biçimlendirme ve tip güvenliği iyi. |
| **Test Kapsamı** | 5/10 | Core logic testleri var ama integration/E2E testleri sınırlı. Connector testleri eksik. ML model testi yok. |
| **Build Stabilitesi** | 6/10 | pnpm workspace çalışıyor, SEA build var. Ama CI pipeline'ı private repo'ya taşınma aşamasında. |
| **Güvenlik** | 7/10 | Kod tabanında secret scanning var, gitleaks entegrasyonu mevcut. Ama güvenlik audit döngüsü otomatik değil. |
| **Dökümantasyon** | 6/10 | Kapsamlı README ve platform guide'ları var ama API dokümanı ve internal geliştirici kılavuzu eksik. |

**Genel Teknik Puan: 6.8/10**

### 2.2 Ürün Seviyesi

| Kategori | Seviye (1-10) | Detay |
|----------|--------------|-------|
| **Özellik Tamamlık** | 4/10 | Runtime detection sağlam ama ML, behavioral, MCP güvenliği, threat intel eksik. |
| **UX Olgunluğu** | 3/10 | SaaS dashboard var ama onboarding, empty states, error handling, mobile responsive eksik. |
| **Connector Kapsamı** | 6/10 | Claude Code, Cursor, VS Code, OpenCode, OpenClaw — 5 platform. Ama her biri farklı olgunlukta. |
| **Enterprise Özellikler** | 2/10 | SSO yok, RBAC yok, audit log yok, compliance raporlaması yok. |

**Genel Ürün Puanı: 3.8/10**

### 2.3 Güvenlik Seviyesi

| Kategori | Seviye (1-10) | Detay |
|----------|--------------|-------|
| **Detection Engine** | 7/10 | Kural tabanlı detection iyi çalışıyor. URL reputation, package supply-chain, AMSI scanning mevcut. |
| **ML Detection** | 0/10 | Henüz yok. Tüm detection statik kural tabanlı. |
| **Behavioral Analiz** | 0/10 | Henüz yok. Kullanıcı davranışı profili çıkarılmıyor. |
| **MCP Güvenliği** | 2/10 | Yeni başlandı. Temel MCP tool blocking var ama derinlemesine değil. |
| **Threat Intelligence** | 1/10 | Manuel rule güncellemesi. Otomatik threat feed yok. |

**Genel Güvenlik Puanı: 4.2/10**

### 2.4 Satış Hazırlığı

| Kategori | Seviye (1-10) | Detay |
|----------|--------------|-------|
| **Landing Page** | 4/10 | aidr.singularityrd.com var ama içerik zayıf, pricing yok. |
| **Pricing** | 1/10 | Taslak var ama aktif değil. Hiçbir ödeme sistemi canlı değil. |
| **Trial** | 0/10 | Deneyim yok. Kullanıcı kaydolup token alabiliyor ama trial süreci tanımlı değil. |
| **Demo** | 0/10 | Self-serve demo yok, sales demo yok. |
| **Customer Docs** | 5/10 | Teknik dokümantasyon iyi ama satış/ürün dokümanı yok. |
| **Trust Signals** | 0/10 | SOC 2 yok, referans müşteri yok, case study yok. |

**Genel Satış Puanı: 1.7/10**

### 2.5 Rekabet Pozisyonu

| Rakipler | AIDR'e Göre Güçlü Yanları | AIDR'e Göre Zayıf Yanları |
|----------|--------------------------|--------------------------|
| **CrowdStrike** | Marka, enterprise satış, SOC 2, bütünleşik platform | Cloud bağımlı, pahalı, AI ajan spesifik değil, ağır |
| **Straiker** | $40M fon, agresif büyüme, ML detection | Cloud bağımlı, privacy sorunu, henüz olgun değil |
| **Declaw** | Open source fork, hızlı iteration | AIDR'e bağımlı, sürdürülebilir değil, güvenilmez |
| **HiddenLayer** | ML-first, enterprise odaklı, güçlü ekip | Pahalı, sadece büyük enterprise, AI ajan spesifik değil |
| **MCPTotal** | MCP-first, OS-native | Sadece MCP, runtime yok, çok yeni |
| **Microsoft Defender AI** | Platform entegrasyonu, marka, mevcut müşteri tabanı | Sadece Azure/M365 ekosistemi, AI ajan spesifik değil |

**Genel Rekabet Puanı: 4.5/10**

---

## 3. İdeal Müşteri Profili (ICP)

### 3.1 Birincil ICP: "Güvenlik Bilincine Sahip AI-First Şirket"

| Boyut | Detay |
|-------|-------|
| **Şirket Büyüklüğü** | 50-500 çalışan |
| **Sektör** | Teknoloji, fintech, sağlık teknolojisi, yapay zeka |
| **AI Kullanımı** | 20+ mühendis Claude Code/Cursor kullanıyor |
| **Güvenlik Olgunluğu** | SOC 2/ISO 27001 sürecinde veya sertifikalı |
| **Karar Verici** | CISO, CTO, VP of Engineering, DevSecOps Lead |
| **Aylık Bütçe** | $500-$5.000/ay (güvenlik araçları) |
| **Satın Alma Motivasyonu** | AI ajan kaynaklı veri sızıntısı, uyumluluk gereksinimleri, shadow AI riski |
| **Başarı Tanımı** | "AI ajanlarının ne yaptığını görebiliyorum, kritik veriler sızmıyor, denetçiler mutlu" |

**Kişilik: "Ahmet" — 300 kişilik bir fintech'te CISO**
> "50 mühendisim Claude Code kullanıyor. Geçen hafta bir mühendisimizin AI ajanı production database'e drop table gönderdi — şans eseri read-only user'dı. Bunu engelleyecek bir sistem istiyorum. Ayrıca SOC 2 denetçileri AI ajan kontrollerimizi soruyor. Hem teknisyenleri yavaşlatmayan hem de denetçileri tatmin eden bir çözüm lazım."

### 3.2 İkincil ICP: "AI Geliştirici Takımı"

| Boyut | Detay |
|-------|-------|
| **Şirket Büyüklüğü** | 10-50 çalışan, AI-first startup |
| **Sektör** | Yapay zeka, SaaS, oyun |
| **AI Kullanımı** | Tüm mühendislik ekibi AI kodlama ajanı kullanıyor |
| **Güvenlik Olgunluğu** | Düşük/orta, formal süreçler yeni başlıyor |
| **Karar Verici** | CTO, Lead Engineer |
| **Aylık Bütçe** | $100-$500/ay |
| **Satın Alma Motivasyonu** | Shadow AI kontrolü, mühendislik kazalarını önleme, hızlı hareket ederken güvende kalma |
| **Başarı Tanımı** | "AI ajanlarımız hızlı çalışıyor ama güvenli. Takım üyeleri birbirinin dosyalarını yanlışlıkla silmiyor."

**Kişilik: "Zeynep" — 40 kişilik AI startup'ında CTO**
> "Herkes Claude Code kullanıyor. Harika üretkenlik artışı var ama bazen AI ajanı 'rm -rf /*' çalıştırmaya kalkıyor. Bunu engelleyecek basit bir çözüm istiyorum. Konfigürasyonu 5 dakikada yapıp unutmak istiyorum."

### 3.3 Üçüncül ICP: "Bireysel Güç Kullanıcı"

| Boyut | Detay |
|-------|-------|
| **Profil** | Solo geliştirici, freelance, indie hacker |
| **AI Kullanımı** | Şiddetli AI ajan kullanıcısı |
| **Bütçe** | Ücretsiz veya $10-20/ay |
| **Satın Alma Motivasyonu** | Kendi verilerini koruma, AI ajanının yanlış bir şey yapmasını engelleme |
| **Başarı Tanımı** | "AI ajanımın ne yaptığını biliyorum, şifrelerim sızmıyor."

### 3.4 Hedeflenmeyen Segmentler

| Segment | Neden Hedeflenmemeli |
|---------|---------------------|
| **Fortune 500 çok uluslu** | Enterprise satış döngüsü 12+ ay, SOC 2 Type II zorunlu, kaynak yetmez |
| **Devlet/kamu** | Uzun satış döngüsü, güvenlik clearances, düşük öncelik |
| **AI ajanı kullanmayan şirketler** | Eğitim maliyeti yüksek, hemen değer alamazlar |
| **Sadece ChatGPT kullanan şirketler** | AIDR kodlama ajanları için, genel AI kullanımı için değil |

---

## 4. Kategori Karşılaştırması

### 4.1 Rakiplerden Öğrenilenler

#### CrowdStrike'dan Öğrenilenler
- **İyi**: Enterprise satış makinesi, SOC 2 sertifikasyonu, 20+ yıllık güvenilirlik
- **Kötü**: Cloud bağımlı, pahalı ($100+/endpoint/ay), AI ajan spesifik değil
- **Ders**: Enterprise satış için SOC 2 şart. Ama hafif ve AI-spesifik olmak büyük avantaj.

#### Straiker'dan Öğrenilenler
- **İyi**: $40M fon toplama, agresif GTM, ML-first yaklaşım
- **Kötü**: Cloud bağımlı, privacy zayıf, ürün henüz olgun değil
- **Ders**: ML detection önemli ama privacy'den ödün vermeye gerek yok. Local ML yapılabilir.

#### Declaw'dan Öğrenilenler
- **İyi**: Açık kaynak fork'uyla hızlı iterasyon, topluluktan feedback
- **Kötü**: Fork'tur, sürdürülebilir değil, güvenlik garanti edemez
- **Ders**: Açık kaynağın riskini gösterdi. Kapalı kaynak kararı doğru.

#### HiddenLayer'dan Öğrenilenler
- **İyi**: Güçlü ML detection, enterprise odaklı, AI güvenliği uzmanlığı
- **Kötü**: Pahalı, sadece büyük enterprise, AI ajan spesifik değil
- **Ders**: ML detection olmazsa olmaz. Ama fiyat/performans dengesi önemli.

### 4.2 Kategori Standartları (Table Stakes)

2026 itibarıyla bir AI ajan güvenlik ürününde **olması gerekenler**:

| Özellik | Önem | AIDR Durumu |
|---------|------|------------|
| Command blocking (bash/kabuk) | Kritik | ✅ Var |
| File write protection | Kritik | ✅ Var |
| URL fetch protection | Kritik | ✅ Var |
| Package install protection | Kritik | ✅ Var |
| Plugin scanning | Yüksek | ✅ Var |
| AMSI scanning (Windows) | Yüksek | ✅ Var |
| Multi-IDE support | Yüksek | ✅ Var (5 platform) |
| SaaS dashboard | Yüksek | ✅ Var (ama erken aşama) |
| Team/ekip yönetimi | Yüksek | ⚠️ Temel seviye |
| Policy management | Yüksek | ⚠️ Temel seviye |
| Audit log | Yüksek | ❌ Yok |
| SSO/SAML | Orta | ❌ Yok |
| RBAC | Orta | ❌ Yok |
| ML-powered detection | Yüksek | ❌ Yok |
| Behavioral baselines | Orta | ❌ Yok |
| Automated threat intel | Orta | ❌ Yok |
| MCP security | Yüksek | ⚠️ Yeni başladı |
| API-first design | Yüksek | ⚠️ Kısmen |

### 4.3 Olmazsa Olmaz Özellikler (Müşteri Anketine Göre)

Varsayımsal müşteri geri bildirimlerine göre en kritik özellikler:

1. **AI ajan komutlarını gerçek zamanlı engelleme** — "AI ajanım silme komutu çalıştırmasın"
2. **Gizli veri sızıntısını önleme** — "API key'ler ve token'lar dışarı çıkmasın"
3. **Ne olduğunu gösteren bir dashboard** — "Hangi ajan ne yapmış, görebileyim"
4. **Hızlı kurulum** — "5 dakikada çalışır hale gelsin"
5. **Geliştirici iş akışını yavaşlatmama** — "Güvenlik bahanesiyle hızımızı kesmesin"

### 4.4 Farklılaşma Fırsatları

| Fırsat | Açıklama | Rekabet Avantajı |
|--------|----------|-----------------|
| **Local-first ML detection** | ONNX/WASM ile cihazda ML. Hiçbir rakip bunu yapmıyor. | Benzersiz |
| **MCP güvenlik katmanı** | MCP sunucuları için tam güvenlik denetimi. First-mover avantajı. | Benzersiz |
| **Privacy-first positioning** | "Verileriniz cihazınızdan çıkmaz" — özellikle regüle sektörlerde. | Benzersiz |
| **Hafif/taşınabilir mimari** | npm paketi + SEA binary. Hiçbir rakip bu kadar hafif değil. | Güçlü |
| **Open source'tan gelen güven** | Topluluk kökeni, şeffaflık geçmişi. Enterprise'lar için güven sinyali. | Orta |
| **AIG entegrasyonu** | Tencent AIG ile derin scanning. Benzersiz bir kombine çözüm. | Benzersiz |

---

## 5. Ürün Stratejisi

### 5.1 Core Workflow Tasarımı

AIDR'nin temel kullanıcı akışı şu şekilde tasarlanmalı:

```
KAYIT → KURULUM → İLK KORUMA → DASHBOARD → KEŞİF → POLİTİKA → BÜYÜME
   │          │           │            │         │          │         │
   v          v           v            v         v          v         v
  Email    Token      İlk tehdit    Ne        Detaylı    Takımı    Enterprise
  + Clerk  + CLI      engellendi   oluyor    raporlar   ekle      plana geç
            kurulum    (aha!)        göster
```

**Kritik Anlar:**
1. **"Aha!" Anı**: Kullanıcı, AI ajanının tehlikeli bir komutunu AIDR'nin engellediğini gördüğü an. Bu, ürünün değerini anında kanıtlar.
2. **"Güven" Anı**: Dashboard'da AI ajan aktivitelerinin loglandığını ve görünür olduğunu gördüğü an.
3. **"Kontrol" Anı**: Kendi politikalarını oluşturup uygulayabildiğini gördüğü an.

### 5.2 Aktivasyon Stratejisi (İlk Seans Değeri)

Kullanıcının ilk 5 dakikada yaşaması gerekenler:

1. **Kayıt → Anında Token** (30 sn): Clerk ile email + Google SSO, hemen token al
2. **Tek Komut Kurulum** (2 dk): `npx aidr-cli install --token XYZ` veya tek tıkla VS Code extension
3. **Varsayılan Koruma** (0 dk): Hiçbir konfigürasyon gerektirmeden aktif
4. **İlk Bildirim** (5 dk içinde): AI ajanı çalışırken bir şey engellendiğinde masaüstü bildirimi
5. **Dashboard'a İlk Bakış** (10 dk): "İşte AI ajanımın tüm aktiviteleri"

**Aktivasyon Metrikleri:**
- Kayıt → Token alma: >%90 dönüşüm
- Token alma → Kurulum tamamlama: >%70 dönüşüm
- Kurulum → İlk engelleme: >%50 (ilk 24 saat içinde)
- İlk engelleme → Dashboard ziyareti: >%80 dönüşüm

### 5.3 Retention Stratejisi (Alışkanlık Döngüleri)

**Haftalık Alışkanlık Döngüsü:**

```
 Pazartesi: Haftalık özet email'i (kaç tehdit engellendi, trendler)
 Çarşamba: Dashboard'a bir göz at (yeni threat rules, aktivite grafiği)
 Cuma: Yeni özellik duyurusu veya ipucu (ör: "MCP güvenliğini açtınız mı?")
```

**Aylık Alışkanlık Döngüsü:**
- Aylık güvenlik raporu (PDF, yöneticiye göndermelik)
- Yeni threat intelligence paketi
- Kullanım istatistikleri ve öneriler

**Bağımlılık Yaratma:**
- AIDR olmadan AI ajanı çalıştırma hissi "çıplak" hissettirmeli
- Policy'ler zamanla birikir, başka bir ürüne geçmek policy'leri yeniden yazmak demek
- Threat intel community'si (kapalı) — aynı sektördeki güvenlik ekipleri arasında bilgi paylaşımı

### 5.4 Monetizasyon Stratejisi

**Fiyatlandırma Katmanları:**

| Katman | Fiyat | Kime | Özellikler |
|--------|-------|------|------------|
| **Free** | $0 | Bireysel geliştiriciler | 1 kullanıcı, temel detection, topluluk rule'ları, 7 gün log retention |
| **Pro** | $20/kullanıcı/ay | Küçük takımlar (2-20 kişi) | Tüm detection, özel policy, 30 gün retention, email desteği |
| **Team** | $15/kullanıcı/ay (min 5) | Büyük takımlar (20-100 kişi) | SSO, RBAC, audit log, Slack/webhook entegrasyonu, dedicated support |
| **Enterprise** | Özel fiyatlandırma | 100+ kişi | SOC 2 raporu, on-prem opsiyonu, SLA, dedicated TAM, custom integration |

**Dönüşüm Hunisi:**
```
Free → Pro: %5-8 dönüşüm (14 gün trial ile)
Pro → Team: %15-20 (takım büyüdükçe)
Team → Enterprise: Satışla belirlenir
```

**Genişleme Mekanizmaları:**
- **Seat expansion**: Mevcut müşteri daha fazla geliştirici ekledikçe organik büyüme
- **Feature expansion**: ML detection, threat intel gibi premium eklentiler
- **Plan upgrade**: Free → Pro → Team → Enterprise doğal geçiş

### 5.5 Expansion Stratejisi

```
TEK GELİŞTİRİCİ → TAKIM → ORGANİZASYON → ENTERPRISE
     │              │            │              │
     v              v            v              v
  Free           Pro          Team          Enterprise
  Kendi          Takım       Departman     Tüm şirket
  koruması       politikası  politikaları  + compliance
```

**Top-Down (Yukarıdan Aşağı) Satış:**
- CISO/CTO'ya: "AI ajan güvenliğini nasıl yönetiyorsunuz?"
- Pilot program → Referans → Genişleme

**Bottom-Up (Aşağıdan Yukarı) Büyüme:**
- Bireysel geliştirici Free kullanır → Takım arkadaşlarına anlatır → Takım Pro'a geçer
- Viral loop: AIDR kullanan geliştirici, takım arkadaşını davet eder

### 5.6 Enterprise Readiness Stratejisi

Enterprise satış için olmazsa olmazlar:

1. **SOC 2 Type II** — İlk adım. Hemen başlamalı.
2. **SSO/SAML** — Okta, Azure AD, Google Workspace
3. **RBAC** — Admin, viewer, editor rolleri
4. **Audit Log** — Kim ne zaman ne yaptı, 1 yıl retention
5. **SLA** — %99.9 uptime, 4 saat yanıt süresi
6. **Data Residency** — AB, ABD, Asya bölgesel veri depolama
7. **On-prem Opsiyonu** — Hava boşluklu (air-gapped) ortamlar için
8. **Vendor Assessment Package** — SOC 2 raporu, penetrasyon testi sonuçları, BCP/DR dokümanı

---

## 6. Özellik Yol Haritası (P0/P1/P2/P3)

### 6.1 P0: Şimdi Yapılmalı (Production/Satış İçin Zorunlu)

| # | Özellik | Neden Gerekli | Kullanıcı Değeri | İş Değeri | Teknik Karmaşıklık |
|---|---------|--------------|-----------------|----------|-------------------|
| 1 | **ML Detection v1** | Rule-based yetersiz, yeni tehditleri kaçırıyor | Daha akıllı koruma | Pazar liderliği | Yüksek |
| 2 | **MCP Güvenlik Katmanı** | MCP standartlaşıyor, first-mover fırsatı | MCP tool çağrılarını korur | Yeni pazar segmenti | Orta |
| 3 | **SaaS Dashboard v2** | Mevcut dashboard erken aşama | Net görünürlük | Satış enabler'ı | Orta |
| 4 | **Ödeme Sistemi (Polar)** | Gelir başlatmak zorunlu | Pro/Team satın alma | ARR başlangıcı | Düşük |
| 5 | **Onboarding Flow** | Kullanıcılar üründe kayboluyor | Hızlı değer görme | Aktivasyon oranı artışı | Düşük |
| 6 | **Pilot Program Yönetimi** | İlk müşterileri yönetmek için | Yapılandırılmış deneyim | Referans müşteriler | Düşük |

**Risk Değerlendirmesi (P0):**
| Özellik | Risk | Mitigasyon |
|---------|------|------------|
| ML Detection v1 | False positive, latency, model boyutu | Küçük başla (TinyBERT), kademeli rollout, kullanıcı feedback loop'u |
| MCP Güvenlik Katmanı | MCP standardı hala değişiyor | Esnek plugin mimarisi, spec'e endeksli değil |
| SaaS Dashboard v2 | Kapsam genişlemesi riski | MVP odaklı, temel metrikler + incident timeline |

**Başarı Metrikleri (P0):**
- ML Detection: %90+ doğruluk, <%5 false positive
- MCP Güvenlik: 5+ MCP sunucu tipini destekleme
- Dashboard: Kullanıcıların %70'i haftada en az 1 kez dashboard ziyareti
- Ödeme: Kayıtlı kullanıcıların %3+'ü ücretli plana geçiş

**Uygulama Yaklaşımı (P0):**
- Parallel ekipler: Biri ML/MCP, diğeri Dashboard/Payment/Onboarding
- 2 haftalık sprint'ler
- Her sprint sonunda canlı demo

### 6.2 P1: Kısa Vadeli (Ürünü Güçlendirir)

| # | Özellik | Neden Gerekli | Karmaşıklık | Etki |
|---|---------|--------------|------------|------|
| 1 | **SSO/SAML Entegrasyonu** | Enterprise satışı için olmazsa olmaz | Orta | Yüksek |
| 2 | **RBAC Sistemi** | Takım yönetimi için gerekli | Orta | Yüksek |
| 3 | **Audit Log** | Compliance ve enterprise için | Düşük | Yüksek |
| 4 | **Policy-as-Code** | Geliştirici dostu politika yönetimi | Orta | Orta |
| 5 | **Slack/Webhook Entegrasyonu** | Anlık bildirimler için | Düşük | Orta |
| 6 | **CLI Dashboard** | Terminal'den dashboard erişimi | Düşük | Düşük |
| 7 | **API v1** | Integration ve extension için | Orta | Yüksek |
| 8 | **Threat Intelligence Feed** | Otomatik rule güncellemesi | Orta | Yüksek |
| 9 | **Behavioral Baselines v1** | Anomali tespiti için temel | Yüksek | Yüksek |
| 10 | **VS Code Extension v2** | VS Code deneyimini iyileştirme | Orta | Orta |

**Uygulama Önceliği (P1):**
```
Sprint 1-2: SSO + RBAC + Audit Log (Enterprise trinity)
Sprint 3-4: API v1 + Slack Integration
Sprint 5-6: Policy-as-Code + Threat Intel Feed
Sprint 7-8: Behavioral Baselines + VS Code v2
```

### 6.3 P2: Orta Vadeli (Büyümeyi Hızlandırır)

| # | Özellik | Neden Gerekli | Karmaşıklık | Etki |
|---|---------|--------------|------------|------|
| 1 | **SOC 2 Type II Sertifikasyonu** | Enterprise satış için | Yüksek (süreç) | Çok Yüksek |
| 2 | **GitHub Action/CI/CD Integration** | CI pipeline'ında güvenlik | Düşük | Orta |
| 3 | **Custom Detection Rules** | Kullanıcıların kendi rule'larını yazması | Orta | Yüksek |
| 4 | **Monthly Security Reports** | Yöneticilere göndermelik PDF | Düşük | Orta |
| 5 | **Multi-workspace Support** | Büyük organizasyonlar için | Orta | Orta |
| 6 | **AIG Deep Integration** | AIG scanning'i ürüne entegre etme | Yüksek | Yüksek |
| 7 | **Threat Hunting Mode** | Güvenlik analistleri için manuel tehdit avı | Yüksek | Orta |
| 8 | **Compliance Reports** | SOC 2, ISO 27001 raporları | Orta | Yüksek |
| 9 | **On-prem Deployment** | Air-gapped müşteriler için | Yüksek | Orta |
| 10 | **Mobile Dashboard** | CISO'nun telefonundan görüntüleme | Orta | Düşük |

### 6.4 P3: Uzun Vadeli (Kategori Liderliği)

| # | Özellik | Vizyon |
|---|---------|--------|
| 1 | **Autonomous Response** | AI ajan tehditlerine otomatik müdahale (izole et, durdur, rollback) |
| 2 | **Federated Threat Intelligence** | AIDR kullanıcıları arasında anonim tehdit verisi paylaşımı |
| 3 | **ML Model Marketplace** | Topluluk tarafından eğitilmiş detection modelleri |
| 4 | **Agent Behavior Forecasting** | AI ajanının bir sonraki hamlesini tahmin etme |
| 5 | **Cross-Platform Correlation** | Farklı IDE'ler ve CI/CD arasında tehdit korelasyonu |
| 6 | **Automated Incident Response Playbooks** | SOAR benzeri otomatik müdahale senaryoları |
| 7 | **AI Agent Bill of Materials (ABOM)** | Her AI oturumu için malzeme listesi çıkarma |
| 8 | **Real-time Threat Graph** | Tüm ajan aktivitelerini grafik olarak görselleştirme |

---

## 7. UX Yol Haritası

### 7.1 Mevcut UX Sorunları

| Sorun | Şiddet | Çözüm |
|-------|--------|-------|
| Onboarding yok, kullanıcı ne yapacağını bilmiyor | Kritik | Adım adım onboarding wizard |
| Dashboard boş/empty state yok | Yüksek | İlk kullanım için empty state tasarımı |
| Hata mesajları anlaşılır değil | Yüksek | Kullanıcı dostu hata mesajları + çözüm önerileri |
| Dashboard mobil uyumlu değil | Orta | Responsive tasarım |
| Karanlık mod eksik | Düşük | Dark mode desteği |
| Yavaş yükleme süreleri | Orta | Performans optimizasyonu |

### 7.2 Onboarding Tasarımı

**Adım 1: Hoş Geldin (30 sn)**
- "AI ajanlarınızı koruyalım" — basit değer teklifi
- Email + Google ile kayıt (Clerk)
- 30 saniyede tamamlanır

**Adım 2: Ortamını Seç (1 dk)**
- Claude Code, Cursor, VS Code, OpenCode, OpenClaw seçenekleri
- Seçtiği platforma özel kurulum talimatı
- Video veya GIF ile görsel anlatım

**Adım 3: Kurulum (2 dk)**
- Token kopyala
- Tek satır komut yapıştır
- "Çalışıyor mu?" test butonu

**Adım 4: İlk Bakış (1 dk)**
- Canlı event feed (eğer varsa)
- Veya demo data gösterimi
- "İşte bu kadar, koruma aktif!"

### 7.3 Dashboard Tasarımı

**Ana Sayfa — "Bugünün Özeti"**
```
┌─────────────────────────────────────────────────────────┐
│  Bugün AI Ajan Aktiviteniz                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ 142      │  │ 3        │  │ 1        │  │ 99.3%    │ │
│  │ Komut    │  │ Engellenen│  │ Uyarı    │  │ Güvenlik │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │
│                                                          │
│  Son Aktiviteler              [Tümünü Gör →]            │
│  ┌─────────────────────────────────────────────────┐    │
│  │ ⛔ rm -rf / && rm -rf ~    2 dk önce  Engellendi │    │
│  │ ⚠️ curl http://可疑.com    15 dk önce Uyarı      │    │
│  │ ✅ npm install express     30 dk önce İzin Verildi│    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  Hızlı Aksiyonlar:  [Politika Ekle]  [Takım Davet Et]   │
└─────────────────────────────────────────────────────────┘
```

**Sayfalar:**
1. **Dashboard** — Bugünün özeti, son aktiviteler, hızlı aksiyonlar
2. **Events/Incidents** — Tüm event'ler, filtreleme, arama, timeline
3. **Policies** — Kural listesi, oluşturma, düzenleme, test
4. **Team** — Takım üyeleri, roller, davet
5. **Settings** — Profil, billing, integrations, API keys
6. **Reports** — Haftalık/aylık güvenlik raporları

### 7.3 Empty States

| Sayfa | Empty State Mesajı | CTA |
|-------|-------------------|-----|
| Dashboard | "Henüz hiç AI ajan aktivitesi yok. Claude Code'u açıp bir şey sorun, görelim!" | "Claude Code'u Aç" |
| Events | "Henüz bir event yok. Bu iyi bir şey! Ama yine de politikalarınızı kontrol edin." | "Politikaları Kontrol Et" |
| Team | "Takımınızı davet edin. Birlikte daha güvenli." | "Takım Arkadaşını Davet Et" |
| Reports | "İlk raporunuz 7 gün içinde hazır olacak." | — |

### 7.4 Error States

| Hata | Kullanıcıya Gösterilen | Çözüm Önerisi |
|------|----------------------|-------------|
| Ajan bağlantısı koptu | "AI ajanınızla bağlantı kesildi" | "Tekrar bağlan" butonu + neden olabileceği açıklama |
| Token geçersiz | "Kurulum token'ınız süresi dolmuş" | "Yeni token al" butonu |
| Rule parse hatası | "Özel kuralınızda bir hata var" | Hata satırını göster + düzeltme önerisi |
| Rate limit aşıldı | "Çok fazla istek gönderdiniz" | "Bekleyin veya planınızı yükseltin" |

### 7.5 Mobile Dashboard

P3 öncelikli. Minimal MVP:
- Event bildirimleri (push)
- Kritik incident onayı (block/kabul)
- Dashboard özeti (read-only)

### 7.6 Erişilebilirlik

- WCAG 2.1 AA uyumluluğu
- Klavye navigasyonu
- Screen reader desteği
- Yüksek kontrast modu
- Renk körü dostu renk paleti

---

## 8. Teknik Yol Haritası

### 8.1 Mimari İyileştirmeler

| Madde | Mevcut Durum | Hedef | Karmaşıklık |
|-------|-------------|-------|------------|
| Monorepo yapısı | pnpm workspace, 5 paket | Paket sayısını 7-8'e çıkar (core, claude, cursor, vscode, opencode, openclaw, dashboard, cli) | Düşük |
| API Gateway | Yok | Express/Fastify API gateway (control plane) | Orta |
| Event Bus | Yok | Internal event bus (detection events → dashboard → notifications) | Orta |
| Plugin Sistemi | Yok | Genişletilebilir plugin mimarisi | Yüksek |
| Feature Flags | Yok | LaunchDarkly benzeri internal flag sistemi | Düşük |

### 8.2 Performans Hedefleri

| Metrik | Mevcut | Hedef |
|--------|--------|-------|
| Detection latency (ortalama) | ~15ms | <5ms |
| ML detection latency | Yok | <20ms |
| Dashboard page load | ~3s | <1s |
| SEA binary size | ~45MB | <25MB |
| npm package size | ~2MB | <500KB |
| Memory footprint (idle) | ~30MB | <15MB |

### 8.3 Güvenlik İyileştirmeleri

| Madde | Öncelik | Açıklama |
|-------|---------|----------|
| Dependency scanning | P0 | Otomatik günlük bağımlılık taraması (Dependabot + Snyk) |
| Secret scanning pipeline | P0 | CI'da gitleaks + custom scanner |
| Penetrasyon testi | P1 | Harici firma ile yıllık pentest |
| Security audit döngüsü | P1 | 3 aylık internal security review |
| Bug bounty programı | P3 | HackerOne/Intigriti ile ödüllü hata avı |

### 8.4 Test Stratejisi

| Katman | Hedef Kapsam | Araç |
|--------|-------------|------|
| Unit test | >%80 | Vitest |
| Integration test | Tüm extractor + detector kombinasyonları | Vitest + MSW |
| E2E test | Her platform için temel flow | Playwright + CLI testleri |
| ML model test | Doğruluk, FP/FN oranı | Custom benchmark suite |
| Security test | OWASP Top 10 | Semgrep + CodeQL |
| Performance benchmark | Her release'de | k6 (load test) + custom latency test |
| Fuzz test | Input validation | Custom fuzzer |

### 8.5 Observability

| Bileşen | Araç | Detay |
|---------|------|-------|
| Logging | Pino | Yapılandırılmış JSON log, log levels |
| Metrics | Prometheus + Grafana | Detection latency, error rates, active users |
| Tracing | OpenTelemetry | Distributed tracing (SaaS + local) |
| Error Tracking | Sentry | Production hata takibi |
| Uptime Monitoring | Better Stack | SaaS dashboard uptime |
| Usage Analytics | PostHog | Product analytics (opt-in) |

### 8.6 CI/CD Pipeline

```
Git Push → Lint → Type Check → Unit Test → Build → Integration Test → E2E Test → Publish
   │         │        │            │         │          │                │           │
   v         v        v            v         v          v                v           v
  Biome   tsc      Vitest       esbuild   Docker     Playwright        Release    npm/github
```

**Branch Stratejisi:**
- `main` — Production. Her zaman deploy edilebilir.
- `develop` — Geliştirme. Feature branch'ler buraya merge edilir.
- `feature/*` — Her özellik için ayrı branch.
- `release/*` — Release hazırlık branch'i.

### 8.7 Veri Modeli

**Local (Endpoint'te):**
- SQLite: Event log, cache, behavioral baseline
- Şifreleme: SQLite dosyası AES-256 ile şifrelenmiş
- Retention: Configurable (default 30 gün)

**Cloud (Control Plane):**
- Firestore: Kullanıcı, takım, policy, billing verisi
- Event log cloud copy (opsiyonel, enterprise plan)

### 8.8 Ölçeklenebilirlik

| Senaryo | Hedef | Strateji |
|---------|-------|----------|
| 1.000 kullanıcı | Sorunsuz | Mevcut mimari yeterli |
| 10.000 kullanıcı | Sorunsuz | Firestore scaling, read replicas |
| 100.000 kullanıcı | Planlı | Event bus partitioning, CDN for dashboard |
| 1.000.000+ kullanıcı | Mimari değişiklik | Microservices, Kafka event bus, dedicated ML inference |

### 8.9 Maintainability

| Uygulama | Detay |
|----------|-------|
| API versioning | `/v1/`, `/v2/` prefix |
| Deprecation policy | 6 ay önceden duyuru |
| Semantic versioning | Major.Minor.Patch |
| CHANGELOG | Otomatik oluşturma (changesets) |
| Migration guide | Her major release için |
| Developer onboarding | CONTRIBUTING.md + dev environment script |

---

## 9. Satış Hazırlığı Yol Haritası

### 9.1 Landing Page

**Mevcut Durum:** aidr.singularityrd.com var ama içerik zayıf.

**Hedef (30 gün içinde):**

```
Hero: "AI Ajanlarınızı Koruyun. Kod Hızınızı Korumayın."
Alt: "Claude Code, Cursor ve VS Code için runtime güvenlik. 5 dakikada kurulum."

CTA: "Ücretsiz Başla" / "Enterprise Demo İste"

Bölümler:
├── Sorun: AI ajanları tehlikeli olabilir (kısa video/GIF)
├── Çözüm: AIDR nasıl çalışır (3 adımlı açıklama)
├── Kanıt: Engellenen tehdit örnekleri (canlı sayaç opsiyonel)
├── Özellikler: 4 kart (Runtime, MCP, Dashboard, Privacy)
├── Platformlar: Claude Code, Cursor, VS Code, OpenCode, OpenClaw
├── Fiyatlandırma: Free / Pro / Team / Enterprise
├── SSS: Sık sorulan sorular
└── Footer: Blog, Docs, Contact, Legal
```

### 9.2 Pricing Sayfası

- Açık ve net fiyatlandırma
- Feature comparison tablosu
- "Hangi plan bana uygun?" quiz'i
- 14 gün ücretsiz Pro trial
- Yıllık ödemede 2 ay indirim

### 9.3 Trial Deneyimi

| Adım | Süre | Aksiyon |
|------|------|---------|
| Kayıt | 0. gün | Clerk ile kayıt, hemen Pro trial başlar |
| Kurulum | 0. gün | CLI/Extension kurulumu, test komutu |
| Aktivasyon | 1-3. gün | İlk tehdit engelleme, dashboard keşfi |
| Değer Görme | 3-7. gün | Düzenli kullanım, tehdit trendleri |
| Dönüşüm | 10-14. gün | Trial bitmeden upgrade teklifi |
| Churn Prevention | 14+ gün | Ücretsiz plana düşüş, özellik kısıtlamaları |

### 9.4 Demo Deneyimi

**Self-Serve Demo:**
- Otomatik onboarding (email + token → kurulum → ilk event)
- Demo data ile önceden doldurulmuş dashboard
- "30 saniyede AIDR'i deneyimleyin" interaktif walkthrough

**Sales Demo:**
- 30 dk standart demo script'i
- Enterprise kullanım senaryoları
- Compliance/audit özellikleri gösterimi
- Rakip karşılaştırması
- Özelleştirilebilir POC planı

### 9.5 Trust Signals

| Sinyal | Hedef Tarih | Nasıl Kazanılır |
|--------|------------|----------------|
| SOC 2 Type II | Ay 6-9 | SOC 2 audit firmasıyla anlaşma, süreç başlatma |
| Müşteri Referansı | Ay 2-3 | Pilot programdan ilk başarı hikayesi |
| Case Study | Ay 3-4 | Pilot müşteri ile ortak yayın |
| G2/TrustRadius | Ay 6+ | Ücretsiz kullanıcılardan review toplama |
| VC/Accelerator | Ay 3-6 | Bir hızlandırıcıdan referans |
| Açık kaynak geçmişi | Zaten var | GitHub stars, community trust |

### 9.6 Customer Documentation

| Doküman | Hedef | Format |
|---------|-------|--------|
| Getting Started Guide | İlk 10 dk'da çalışır hale gelme | Web + PDF |
| Admin Guide | Policy, team, billing yönetimi | Web |
| API Reference | REST API dokümantasyonu | OpenAPI/Swagger |
| Security Overview | Mimari, encryption, privacy | Web + PDF (sales) |
| Integration Guide | Her platform için detaylı kurulum | Web |
| FAQ | Sık sorulan sorular | Web |
| Release Notes | Her release için changelog | Web + email |
| Compliance Docs | SOC 2, GDPR, veri güvenliği | PDF (NDE ile) |

---

## 10. Büyüme Yol Haritası

### 10.1 Acquisition Loops (Edinme Döngüleri)

| Kanal | Öncelik | Strateji |
|-------|---------|----------|
| **Organic Search (SEO)** | Yüksek | "AI ajan güvenliği", "Claude Code güvenlik", "MCP güvenlik" gibi aramalarda üst sıra |
| **Content Marketing** | Yüksek | Blog: AI ajan güvenlik vakaları, nasıl yapılır rehberleri, karşılaştırmalar |
| **Developer Communities** | Yüksek | Reddit (r/ClaudeAI, r/ClaudeCode), Hacker News, Dev.to, Twitter/X |
| **GitHub** | Orta | Açık source repo (read-only), detaylı README, community issues |
| **Product Hunt** | Orta | Launch stratejisi (doğru zamanlama) |
| **Partnerships** | Orta | AI tool şirketleri ile entegrasyon (LangChain, CrewAI) |
| **Paid Ads** | Düşük | Daha sonra, PLG doğrulandıktan sonra |

**Viral Loop:**
```
Geliştirici AIDR kullanır → Takım arkadaşı "bu ne güzelmiş" der → 
Arkadaşı da kurar → İkisi de Pro'a ihtiyaç duyar → Takım planı satın alınır
```

### 10.2 Activation Improvements

| İyileştirme | Beklenen Etki |
|------------|--------------|
| "5 dk'da kurulum" promise'i | +%20 aktivasyon |
| Interactive onboarding wizard | +%15 aktivasyon |
| İlk event'te push notification | +%30 dashboard ziyareti |
| Demo data ile dolu dashboard | +%25 ilk izlenim |
| "İlk tehdidi bul" challenge'ı | +%10 engagement |
| Email ile onboarding sequence | +%15 7. gün retention |

### 10.3 Referral Loops

| Mekanizma | Detay |
|-----------|-------|
| Takım daveti | Kullanıcı takım arkadaşını davet eder, davet eden +7 gün Pro |
| Referral programı | Her referans için +1 ay ücretsiz Pro |
| Social sharing | "AI ajanımı AIDR ile koruyorum" paylaşımı |
| Community | Discord/ Slack topluluğu, aktif üyelere özel badge'ler |

### 10.4 Lifecycle Emails

| Email | Tetikleyici | İçerik |
|-------|------------|--------|
| Hoş Geldin | Kayıt anı | "AI ajanlarınızı korumaya başlayın" |
| Kurulum Hatırlatma | 24 saat kurulum yok | "Kurulumu tamamlayın, 2 dakikanızı alır" |
| Haftalık Özet | Her Pazartesi | Kaç tehdit engellendi, trendler |
| İlk Tehdit | İlk engelleme anı | "AIDR ilk tehdidinizi engelledi!" (push + email) |
| Feature Discovery | 7. gün | "Biliyor muydunuz? MCP güvenliğini de açabilirsiniz" |
| Trial Bitiş | Trial'ın 3. gün kala | "Pro trial'ınız bitiyor, upgrade edin" |
| Re-engagement | 14 gün inaktif | "AI ajanlarınız hala korunuyor mu?" |
| Referans İsteği | 30 gün aktif kullanım | "AIDR'i seviyorsanız arkadaşlarınıza anlatın" |

### 10.5 Kullanım Nudges

| Nudge | Tetikleyici | Aksiyon |
|-------|------------|---------|
| "Politika eklemediniz" | 3 gün, hiç özel politika yok | "Varsayılan politikalar iyi ama özelleştirin" |
| "Takımınızı davet edin" | 5 gün, tek kullanıcı | "Tek başınıza korunuyorsunuz, takımınızı da koruyun" |
| "Yeni özellik: MCP" | Feature release | "MCP güvenliği aktif, kontrol edin" |
| "Kullanım arttı" | Haftalık kullanım %50+ arttı | "Yoğun kullanım haftası, raporunuza göz atın" |
| "Güvenlik skorunuz" | Aylık | "Güvenlik skorunuz 85/100 — nasıl yükseltirsiniz?" |

### 10.6 Upgrade Prompts

| Prompt | Kullanıcı Profili | Mesaj |
|--------|-------------------|-------|
| Takım sınırı | Free'de 1 kişi, 2. kişi eklemeye çalışıyor | "Takım planına geçin, herkesi koruyun" |
| Log retention | Free'de 7 gün, 30 günlük log lazım | "Pro'da 30 gün log retention var" |
| Özel policy | Free'de sınırlı policy | "Pro'da sınırsız özel policy" |
| Enterprise özellik | SSO ihtiyacı | "Enterprise plan SSO destekler" |

### 10.7 Analytics Events

| Event Kategorisi | Events |
|-----------------|--------|
| **Acquisition** | page_view, signup_started, signup_completed, trial_started |
| **Activation** | install_started, install_completed, first_protection, dashboard_visited |
| **Engagement** | command_ran, threat_blocked, warning_seen, policy_created, team_invited |
| **Revenue** | plan_selected, checkout_started, payment_completed, plan_upgraded, plan_downgraded |
| **Retention** | weekly_active, monthly_active, report_viewed, feature_used |
| **Referral** | invite_sent, invite_accepted, referral_clicked |

---

## 11. Zamana Dayalı Planlar

### 11.1 7 Günlük Plan (En Yüksek Etki)

Bu hafta yapılacaklar — ürünü satılabilir hale getiren minimum değişiklikler.

| Gün | Odak | Yapılacaklar |
|-----|------|-------------|
| **Gün 1-2** | **Ödeme** | Polar entegrasyonu tamamlama, Free/Pro/Team planlarını aktifleştirme, Stripe test işlemi |
| **Gün 2-3** | **Onboarding** | Clerk sonrası onboarding flow'u (4 adım), empty state'leri düzeltme, ilk kullanım mesajları |
| **Gün 3-4** | **Dashboard** | Dashboard'a canlı event feed ekleme, event timeline sayfası, temel filtreleme |
| **Gün 4-5** | **Pilot Program** | Pilot başvuru formu, pilot kullanıcı yönetimi (admin paneli), welcome email sequence |
| **Gün 5-6** | **Landing Page** | Hero yenileme, pricing sayfası, feature cards, platform logos |
| **Gün 6-7** | **Testing + Launch** | E2E test (kayıttan satın almaya), güvenlik audit, launch hazırlığı |

**7 Gün Sonunda Kazanımlar:**
- Kullanıcı kaydolup ödeme yapabilir
- Onboarding çalışır, kullanıcı ilk 5 dk'da değer görür
- Dashboard temel bilgileri gösterir
- Pilot program başlamıştır
- Landing page satış yapabilir durumdadır

### 11.2 30 Günlük Plan (Güçlü V1)

| Hafta | Odak | Yapılacaklar |
|-------|------|-------------|
| **Hafta 1** | **Foundation** | 7 günlük planın tamamı + ilk bug fix'leri |
| **Hafta 2** | **ML Detection MVP** | TinyBERT model seçimi, ONNX runtime entegrasyonu, ilk training pipeline'ı, %80 doğruluk hedefi |
| **Hafta 3** | **MCP Güvenlik** | MCP tool çağrısı interception (claude-code + opencode), risk sınıflandırması, block/kabul mekanizması |
| **Hafta 4** | **Enterprise Trinity** | SSO/SAML (Okta, Google, Azure AD), RBAC (admin/viewer/editor), Audit log (30 gün retention) |

**30 Gün Sonunda Kazanımlar:**
- ML detection çalışıyor (temel seviye)
- MCP güvenlik katmanı aktif
- Enterprise müşteriye satış yapılabilir (SSO + RBAC + Audit)
- İlk 5 pilot müşteri onboard edilmiş
- $5K+ MRR hedefi

### 11.3 60 Günlük Plan (Rekabetçi)

| Hafta | Odak | Yapılacaklar |
|-------|------|-------------|
| **Hafta 5-6** | **Threat Intelligence** | Automated threat feed pipeline, community rule repository, rule update mechanism |
| **Hafta 6-7** | **API + Integrations** | REST API v1 (events, policies, teams), Slack/Webhook notification, GitHub Action |
| **Hafta 7-8** | **Behavioral Baselines** | Kullanıcı davranış profili oluşturma, anomaly detection (z-score), 7 gün baseline süresi |
| **Hafta 8-9** | **VS Code Extension v2** | VS Code extension yenileme, inline detection, policy management from VS Code |

**60 Gün Sonunda Kazanımlar:**
- Rakip ürünlerle feature-parity (en azından temel özelliklerde)
- 15+ pilot müşteri
- $15K+ MRR
- API ekosistemi başlamış
- Behavioral detection aktif

### 11.4 90 Günlük Plan (Kategori Liderliği Yörüngesi)

| Hafta | Odak | Yapılacaklar |
|-------|------|-------------|
| **Hafta 9-10** | **SOC 2 Başlangıç** | SOC 2 audit firması seçimi, readiness assessment, kontrol dokümantasyonu |
| **Hafta 10-11** | **AIG Derin Entegrasyon** | AIG sidecar entegrasyonu (docker-compose), deep scanning pipeline, combined report |
| **Hafta 11-12** | **Enterprise Raporlama** | Compliance reports (SOC 2, ISO 27001), monthly PDF reports, executive dashboard |
| **Hafta 12-13** | **GTM Launch** | Product Hunt launch, basın duyurusu, ilk case study yayını, web semineri |

**90 Gün Sonunda Kazanımlar:**
- SOC 2 süreci başlamış (Type I hedefi)
- AIG entegrasyonu tamam
- 30+ müşteri
- $30K+ MRR
- Kategori tanımlayıcısı olarak konumlanma
- İlk basın/analist kapsaması

---

## 12. Riskler ve Ödünleşimler

### 12.1 Teknik Riskler

| Risk | Olasılık | Etki | Mitigasyon |
|------|---------|------|------------|
| ML model false positive oranı yüksek çıkar | Orta | Yüksek | Kademeli rollout, kullanıcı feedback loop'u, threshold kalibrasyonu |
| MCP spec değişir | Orta | Yüksek | Esnek plugin mimarisi, spec'e sıkı bağlanmama |
| ONNX WASM performansı beklenenden düşük çıkar | Düşük | Orta | Fallback: cloud ML inference (opsiyonel) |
| SEA binary boyutu kontrol edilemez | Düşük | Düşük | Tree-shaking, optional module'ler |

### 12.2 Ürün Riskleri

| Risk | Olasılık | Etki | Mitigasyon |
|------|---------|------|------------|
| CrowdStrike AIDR kısaltmasını domine eder | Yüksek | Yüksek | Marka değişikliği planı (yedek isim: "Singularity Sentinel", "AEGIS") |
| Straiker daha hızlı büyür | Orta | Orta | Daha iyi ürün + privacy-first positioning |
| Kullanıcılar güvenlikten rahatsız olur | Orta | Yüksek | Zero-friction tasarımı, performans önceliği, kolay bypass |
| Pazar beklenenden yavaş büyür | Düşük | Yüksek | Mevcut veriler (Gartner) güçlü büyüme gösteriyor |

### 12.3 Pazar Riskleri

| Risk | Olasılık | Etki | Mitigasyon |
|------|---------|------|------------|
| AI kodlama ajanları trendi geçici (hype cycle) | Düşük | Çok Yüksek | Kurumsal benimseme verileri (Gartner) güçlü, kullanım %40→%70 |
| Microsoft/Apple platforma built-in güvenlik ekler | Orta | Yüksek | Cross-platform olmak, bağımsız olmak |
| Yeni bir protokol MCP'nin yerini alır | Düşük | Orta | Esnek mimari, abstraction layer |
| Regülasyon AI ajan güvenliğini zorunlu kılar | Orta | Pozitif | Fırsat: compliance-driven satış |

### 12.4 UX Riskleri

| Risk | Olasılık | Etki | Mitigasyon |
|------|---------|------|------------|
| Güvenlik önlemleri geliştirici hızını düşürür | Yüksek | Çok Yüksek | Performans hedefleri (<5ms), akıllı bypass, "sessiz mod" |
| False positive'ler güven kaybına yol açar | Orta | Yüksek | Confidence scoring, kullanıcı geri bildirimi, hızlı düzeltme |
| Onboarding çok karmaşık gelir | Orta | Yüksek | 5 dk promise'ı, video + GIF anlatım, zero-config başlangıç |

### 12.5 Güvenlik Riskleri

| Risk | Olasılık | Etki | Mitigasyon |
|------|---------|------|------------|
| AIDR'in kendisi bir güvenlik açığı hedefi olur | Orta | Çok Yüksek | Düzenli pentest, bug bounty, minimal attack surface |
| Token/API key sızıntısı | Orta | Yüksek | Token rotation, short-lived tokens, audit log |
| Local engine bypass edilebilir | Düşük | Yüksek | Defense in depth, cloud verification (opsiyonel) |
| Bağımlılık zinciri saldırısı | Orta | Yüksek | Dependency scanning, lockfile, SBOM |

### 12.6 Execution Riskleri

| Risk | Olasılık | Etki | Mitigasyon |
|------|---------|------|------------|
| Küçük ekip, çok şey aynı anda yapılmaya çalışılır | Yüksek | Orta | Net önceliklendirme (P0/P1), "hayır" deme disiplini |
| Yetenekli AI güvenlik mühendisi bulmak zor | Orta | Yüksek | Remote-first, global hiring, contractors |
| Kapalı kaynağa geçiş topluluk tepkisi yaratır | Orta | Düşük | Blog post, şeffaflık, eski sürüme erişim |

---

## 13. Henüz İnşa Edilmemesi Gerekenler

### 13.1 Çok Erken Özellikler

| Özellik | Neden Erken | Ne Zaman |
|---------|------------|----------|
| **Autonomous Response (auto-quarantine)** | Kullanıcı güveni yok, false positive felaket olur | P3 (12+ ay) |
| **Federated Threat Intelligence** | Yeterli kullanıcı tabanı yok, ağ etkisi sağlanamaz | P3 (18+ ay) |
| **Bug Bounty Programı** | Yönetim maliyeti yüksek, henüz gerekli değil | P3 (12+ ay) |
| **On-prem Enterprise Appliance** | Pazar talebi doğrulanmadı, kaynak yoğun | P2 (6+ ay) |
| **Mobile Native App** | Web dashboard yeterli, native app ek yük | P3 (12+ ay) |
| **Marketplace/Plugin Store** | Ekosistem henüz yok, chicken-and-egg | P3 (18+ ay) |

### 13.2 Aşırı Mühendislik Riskleri

| Konu | Risk | Alternatif |
|------|------|-----------|
| **Mikroservis mimarisi** | Küçük ekip için aşırı kompleks, operasyonel yük | Monolith + modular packages |
| **Kubernetes orchestration** | 10K kullanıcıdan önce gereksiz | Docker Compose + basit VM |
| **Custom LLM fine-tuning** | ML detection için gereksiz pahalı | TinyBERT/ONNX embedding yeterli |
| **Multi-region HA** | 100K kullanıcıdan önce gerekli değil | Single region + DR planı |
| **Real-time threat graph** | Görsel olarak etkileyici ama ticari değeri düşük | Simple timeline + event list |

### 13.3 Düşük ROI Geliştirme

| Özellik | Neden Düşük ROI |
|---------|----------------|
| **IDE dışı AI ajan desteği** (ChatGPT Desktop) | Pazar çok küçük, kodlama ajanı pazarı yeterince büyük |
| **Çoklu dil desteği** (dashboard) | İlk aşamada gerekli değil, tüm kullanıcılar İngilizce |
| **White-label / OEM** | Kaynak yoğun, ilk 6 ayda net gelir getirmez |
| **Custom branding** | Enterprise özellik ama erken |
| **Third-party SIEM entegrasyonu** (Splunk, Datadog) | Talep var ama standart log export yeterli |

---

## 14. Dünya Klası Tanımı

Singularity AIDR'in "dünya klasında" sayılması için aşağıdaki kriterlerin tamamını karşılaması gerekir:

### 14.1 Ürün Kriterleri

- [ ] **Tam Kapsamlı Detection**: AI ajanının her aksiyonunu (komut, dosya, URL, paket, MCP, output, PII) gerçek zamanlı denetler
- [ ] **Zero False Positive**: Kullanıcı raporladığı her false positive 24 saat içinde düzeltilir
- [ ] **Sıfır Gecikme**: Detection latency ortalaması <5ms, hiçbir kullanıcı fark etmez
- [ ] **Çoklu Platform**: 7+ AI ajan platformunu (Claude Code, Cursor, VS Code, OpenCode, OpenClaw, Copilot, Codeium) destekler
- [ ] **ML Destekli**: Rule-based + ML hibrit detection, yeni tehditleri %95+ doğrulukla tanır
- [ ] **MCP Lideri**: MCP güvenliğinde endüstri standardı, Anthropic/OpenAI ile resmi ortaklık

### 14.2 Enterprise Kriterleri

- [ ] **SOC 2 Type II Sertifikalı**: Her yıl güncellenen bağımsız denetim
- [ ] **SSO + RBAC + Audit Log**: Enterprise satış için üçlü olmazsa olmaz
- [ ] **99.9% Uptime SLA**: SaaS kontrol düzlemi için garanti
- [ ] **Data Residency**: AB, ABD, Asya bölgesel veri depolama
- [ ] **On-prem Opsiyonu**: Hava boşluklu ortamlar için dağıtılabilir
- [ ] **Vendor Assessment Package**: SOC 2, pentest, BCP dokümanları hazır

### 14.3 Pazar Kriterleri

- [ ] **Kategori Lideri**: Gartner/Forrester raporlarında "AI Ajan Güvenliği" kategorisinde örnek gösterilen
- [ ] **$10M+ ARR**: Sürdürülebilir, büyüyen gelir
- [ ] **100+ Enterprise Müşteri**: Referans verilebilir, sektör dağılımı olan
- [ ] **20.000+ Aktif Kullanıcı**: PLG motoru çalışıyor
- [ ] **NPS 50+**: Kullanıcılar ürünü seviyor ve tavsiye ediyor

### 14.4 Ekip Kriterleri

- [ ] **Dünya Klası Ekip**: AI güvenliği alanında tanınan isimler
- [ ] **Çeşitlilik**: Mühendislik, satış, pazarlama, destek dengesi
- [ ] **Remote-first**: Küresel yetenek havuzu, asenkron çalışma kültürü
- [ ] **Öğrenme Kültürü**: Blog, konferans, open source katkıları

### 14.5 Teknik Kriterler

- [ ] **Test Coverage >%90**: Unit, integration, E2E, security, performance test katmanları
- [ ] **Security Maturity**: OWASP Top 10 covered, düzenli pentest, bug bounty
- [ ] **API-first**: Her özellik API üzerinden erişilebilir, SDK'lar mevcut
- [ ] **Dökümantasyon**: Mükemmel developer docs, tutorial, örnek repo'lar

### 14.6 "Geçtim" Anı

Bu kriterlerin hepsi aynı anda sağlandığında, aşağıdaki senaryolar gerçekleşir:

1. **Bir CISO, "AI ajan güvenliği" dendiğinde ilk aklına gelen isim AIDR'dir**
2. **Bir geliştirici, yeni bir AI ajanı kullanmaya başladığında ilk iş AIDR'i kurar**
3. **Bir yatırımcı, AI altyapı güvenliği pazarını araştırırken AIDR'i kaçınılmaz olarak bulur**
4. **Bir rakip, "AIDR gibi yapıyoruz" demek zorunda kalır**
5. **Bir denetçi, SOC 2 audit'inde "AI ajan kontrolünüz nedir?" diye sorduğunda cevap "AIDR"dir**

---

## Ek: Metrik Hedefleri

| KPI | 7 Gün | 30 Gün | 60 Gün | 90 Gün | 12 Ay |
|-----|-------|--------|--------|--------|-------|
| **MRR** | $500 | $5K | $15K | $30K | $125K+ |
| **ARR** | $6K | $60K | $180K | $360K | $1.5M+ |
| **Ücretli Müşteri** | 5 | 30 | 75 | 150 | 500+ |
| **Toplam Kullanıcı** | 200 | 1K | 3K | 5K | 10K+ |
| **Aktivasyon Oranı** | %50 | %65 | %70 | %75 | %80+ |
| **Net Revenue Retention** | — | — | %90 | %95 | %110+ |
| **NPS** | 30 | 40 | 45 | 50 | 55+ |
| **SOC 2** | — | — | — | Type I Started | Type II |
| **ML Detection** | — | MVP (%80) | %90 | %95 | %97+ |
| **MCP Destek** | — | Temel | 10+ server | 20+ server | 50+ server |

---

> **Bu Master Plan, Singularity AIDR'in AI ajan güvenliği kategorisini tanımlama ve liderlik etme yol haritasıdır.**
> Her karar, her özellik, her yatırım bu planın bir parçasıdır.
> Öncelikler değişebilir, ama vizyon değişmez: **AI ajanlarını korumak, dünyayı daha güvenli yapmak.**
>
> *"Gelecek geliyor. Onu güvenli inşa edelim."*

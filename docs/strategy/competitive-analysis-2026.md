# Singularity AIDR — Kapsamlı Rekabet Analizi 2026

> Son Güncelleme: Mayıs 2026
> Kapsam: AI Agent Detection & Response (AIDR) Pazar Analizi
> Dil: Türkçe

> **Tarihsel araştırma taslağıdır; güncel rakip, pazar büyüklüğü, fiyat,
> lisans, sertifika veya ürün üstünlüğü kanıtı değildir.** Mayıs 2026
> hipotezleri müşteriye aktarılmadan önce birincil kaynaklarla ve aynı sürüm
> adayında ölçümle doğrulanmalıdır. Mevcut AIDR paket metadata'sı
> `Proprietary` lisanslıdır.

---

## 1. Yönetici Özeti

Bu taslak, AI kodlama ajanları için çalışma anı güvenliği kategorisini
araştırıyordu. Eski pazar büyüklüğü ve tahmin rakamlarının kaynak/kapsamı
doğrulanmadığından burada güncel veri veya yatırımcı iddiası olarak kullanılmaz.

**Mevcut Durum (Mayıs 2026):**
- Kategori henüz oluşma aşamasında — tanımlayıcı ürün henüz belli değil
- Q1-Q2 2026'da $500M+ VC fonu AI ajan güvenliği startup'larına aktı
- CrowdStrike Nisan 2026'da "AIDR" ürününü duyurdu — aynı kısaltma kritik marka riski
- MCP (Model Context Protocol) hızla standartlaşıyor — MCP güvenliği büyük fırsat
- Kurumsal AI kodlama ajanı kullanımı 2024'te %40'tan 2026'da %70+'ye çıktı

**AIDR'in Puanı (1-10): 6.2/10**
- Teknik mimari: 8/10 (doğru kararlar, taşınabilir, hafif)
- Pazar konumlandırma: 5/10 (henüz net değil, marka karmaşası riski var)
- Özellik tamamlık: 4/10 (temel güvenlik sağlam ama ML/behavioral/ MCP eksik)
- Topluluk: 3/10 (çok küçük, threat rule kütüphanesi yetersiz)
- Go-to-market: 5/10 (ücretsiz ama bilinirlik yok)

---

## 2. Pazar Büyüklüğü ve Trendler

### 2.1 Pazar Verileri

| Metrik | Değer | Kaynak |
|--------|-------|--------|
| Toplam AI harcaması (2026) | $2.59T (%47 YoY) | Gartner, Mayıs 2026 |
| AI Siber Güvenlik (2026) | $51.3B (%98 YoY) | Gartner, Mayıs 2026 |
| AI Siber Güvenlik (2027) | $86.0B | Gartner |
| AI Sistem Güvenliği (2030) | $8B (yeni kategori) | Dell'Oro Group |
| AI Ajan Güvenliği VC (Q1-Q2 2026) | $500M+ | Crunchbase |

### 2.2 Katalizör Olaylar (2025-2026)

1. **AI Kodlama Ajanlarına Tedarik Zinciri Saldırıları** (Q1 2026): npm/PyPI paketleri üzerinden AI ajanlarını hedef alan büyük saldırı dalgası — runtime güvenlik talebini patlattı
2. **CrowdStrike "AIDR" Duyurusu** (Nisan 2026): Falcon platformu için AI ajan güvenlik modülü — mevcut AIDR ürünüyle isim çakışması yarattı
3. **MCP'nin Endüstri Standardı Haline Gelmesi** (2025-2026): Anthropic öncülüğünde MCP, OpenAI, Google, Microsoft tarafından da benimsendi — güvenlik katmanı ihtiyacı doğurdu
4. **Kurumsal AI Ajanı Kullanım Patlaması**: %40 (%2024) → %70+ (%2026) — şirketler güvenlik önlemi olmadan ajan kullanmanın risklerini fark etmeye başladı

### 2.3 Pazar Dinamikleri

```
                    YÜKSELEN DALGA
                         │
      ┌──────────────────┼──────────────────┐
      │                  │                  │
      ↓                  ↓                  ↓
  TEDARİK ZİNCİRİ   KURUMSAL       MCP STANDARDİZASYONU
  SALDIRILARI       TALEP PATLAMASI
      │                  │                  │
      │   Runtime        │   Kodlama        │   Açık protokol
      │   güvenlik       │   ajanı          │   → Güvenlik
      │   ihtiyacı       │   kullanımı      │   katmanı ihtiyacı
      └──────────────────┼──────────────────┘
                         │
                         ↓
              AI AJAN GÜVENLİĞİ PAZARI
              (Oluşum aşamasında)
```

---

## 3. Rakip Kategorileri

### Kategori 1: Eski AI Güvenlik Vendorları (Enterprise AI Security)

Bu şirketler mevcut AI güvenlik ürünlerini ajan runtime'a doğru genişletiyor.

#### 1.1 CrowdStrike AIDR ⚠️ KRİTİK TEHDİT

| Özellik | Detay |
|---------|-------|
| **Ürün** | CrowdStrike Falcon AI Agent Detection & Response |
| **Duyuru** | Nisan 2026 |
| **Konum** | Kurumsal AI ajan güvenliği, Falcon platformu eklentisi |
| **Dağıtım** | 60%+ Fortune 500'de önceden yüklü Falcon ajanı |

**Güçlü Yönler:**
- ✅ Dev kurumsal dağıtım ağı (Falcon zaten yüklü → tek tıkla aktivasyon)
- ✅ Güçlü ML/behavioral detection altyapısı
- ✅ SOC entegrasyonu, tehdit istihbaratı
- ✅ Marka bilinirliği ve güven

**Zayıf Yönler:**
- ❌ Aynı isim ("AIDR") — ciddi marka karmaşası
- ❌ Ağır EPP ajanı (AIDR gibi hafif değil)
- ❌ IDE-native entegrasyon yok
- ❌ Windows/Mac odaklı, Linux IDE desteği sınırlı
- ❌ Açık kaynak değil
- ❌ Gizlilik-first değil (bulut zorunlu)

**AIDR için Risk: ÇOK YÜKSEK** — CrowdStrike'ın pazarı domine etme ve "AIDR" kısaltmasını ele geçirme riski var.

---

#### 1.2 Microsoft Defender for AI Agents

| Özellik | Detay |
|---------|-------|
| **Konum** | Agent 365 ekosistemi için güvenlik |
| **Kanal** | Microsoft 365 Enterprise abonelikleri |

**Güçlü Yönler:**
- ✅ Microsoft ekosisteminde sınırsız dağıtım
- ✅ Entegre compliance (SOC2, ISO27001, HIPAA)
- ✅ Kurumsal satış kanalı

**Zayıf Yönler:**
- ❌ Sadece Microsoft ekosistemi (Agent 365, Copilot)
- ❌ Claude Code, Cursor gibi rakip ajanları korumaz
- ❌ Açık kaynak değil
- ❌ Vendor lock-in

**AIDR için Risk: ORTA** — Microsoft dışı ekosistemde AIDR güvende ama MS pazarı büyüdükçe tehdit artar.

---

#### 1.3 HiddenLayer

| Özellik | Detay |
|---------|-------|
| **Konum** | Enterprise AI runtime security & threat hunting |
| **Müşteri** | Fortune 500, finans, savunma |

**Güçlü Yönler:**
- ✅ Olgun ML-based detection (adversarial ML konusunda lider)
- ✅ Güçlü threat hunting araçları
- ✅ SOC entegrasyonu

**Zayıf Yönler:**
- ❌ Enterprise-first (KOBİ/küçük ekip için uygun değil)
- ❌ Hafif IDE entegrasyonu yok
- ❌ Yerel işleme yok (bulut çağrısı gerekli)
- ❌ Pahalı (kurumsal satış, $50K+/yıl başlangıç)
- ❌ Açık kaynak değil

**AIDR için Risk: ORTA-DÜŞÜK** — Farklı segment (enterprise) ve farklı fiyat noktası.

---

#### 1.4 Protect AI / LLM Guard

| Özellik | Detay |
|---------|-------|
| **Konum** | LLM uygulamaları için enterprise firewall |
| **Topluluk** | 2.5M+ indirme (LLM Guard) |

**Güçlü Yönler:**
- ✅ Büyük açık kaynak topluluk
- ✅ Geniş scanner kütüphanesi (regex + ML)
- ✅ LangChain, Azure OpenAI entegrasyonu

**Zayıf Yönler:**
- ❌ Agent-aware değil (LLM API çağrılarına odaklı, ajan aksiyonlarına değil)
- ❌ IDE dağıtımı için ağır
- ❌ Davranışsal analiz yok
- ❌ Platform desteği sınırlı

**AIDR için Risk: DÜŞÜK** — Farklı odak (LLM API vs ajan runtime).

---

#### 1.5 Check Point / Lakera

| Özellik | Detay |
|---------|-------|
| **Konum** | Enterprise AI Gateway, prompt injection koruması |

**Güçlü Yönler:**
- ✅ Prompt injection detection'da lider
- ✅ API gateway modeli (mevcut altyapıya kolay eklenir)

**Zayıf Yönler:**
- ❌ Ajan runtime koruması yok
- ❌ API gateway → endpoint-native değil
- ❌ Açık kaynak değil

**AIDR için Risk: DÜŞÜK** — Tamamen farklı yaklaşım (gateway vs endpoint).

---

#### 1.6 Palo Alto Networks (Prisma Cloud)

| Özellik | Detay |
|---------|-------|
| **Konum** | Cloud-native AI güvenliği |

**Güçlü Yönler:**
- ✅ Geniş cloud güvenlik portföyü
- ✅ Kurumsal müşteri tabanı

**Zayıf Yönler:**
- ❌ Cloud-focused, endpoint/IDE native değil
- ❌ Kodlama ajanı koruması yok

**AIDR için Risk: DÜŞÜK** — Farklı katman.

---

### Kategori 2: AI Kodlama Ajanı Runtime Startup'ları

Bu startup'lar AIDR ile aynı kategoriyi hedefliyor.

#### 2.1 Straiker ⚠️ EN YAKIN RAKİP

| Özellik | Detay |
|---------|-------|
| **Fon** | $40M (Mart 2026, Series A) |
| **Odak** | Ajan davranışsal analizi + gerçek zamanlı engelleme |
| **Model** | Enterprise SaaS |

**Güçlü Yönler:**
- ✅ Büyük fon → hızlı büyüme
- ✅ ML-based behavioral analysis
- ✅ Enterprise satış kanalı

**Zayıf Yönler:**
- ❌ Enterprise fiyatlandırma (KOBİ'ler için pahalı)
- ❌ Açık kaynak değil
- ❌ Privacy-first değil
- ❌ Çok yeni (ürün olgunluğu sorgulanabilir)

**AIDR için Risk: YÜKSEK** — En yakın doğrudan rakip. Büyük fon avantajı var.

---

#### 2.2 Declaw

| Özellik | Detay |
|---------|-------|
| **Fon** | $12M seed |
| **Odak** | "Agent Firewall" — komut/dosya/ağ koruması |
| **Model** | Open-core |

**Güçlü Yönler:**
- ✅ AIDR'e en benzer ürün (open-core, ajan runtime firewall)
- ✅ Komut/dosya/ağ koruması

**Zayıf Yönler:**
- ❌ Küçük ekip
- ❌ Sadece CLI ajanları (IDE eklentisi yok)
- ❌ Sınırlı platform desteği

**AIDR için Risk: ORTA** — En benzer iş modeli, ama AIDR daha geniş platform desteğine sahip.

---

#### 2.3 Lupid

| Özellik | Detay |
|---------|-------|
| **Fon** | $8M seed |
| **Odak** | Ajan tedarik zinciri güvenliği (MCP server denetimi) |

**Güçlü Yönler:**
- ✅ MCP-specific güvenlik (niş odak)
- ✅ Tedarik zinciri vurgusu

**Zayıf Yönler:**
- ❌ Sadece MCP odaklı (genel ajan koruması yok)
- ❌ Çok erken aşama

**AIDR için Risk: DÜŞÜK** — MCP spesifik, AIDR MCP + genel koruma sunabilir.

---

#### 2.4 RuntimeAI

| Özellik | Detay |
|---------|-------|
| **Fon** | $30M Series A (Ocak 2026) |
| **Odak** | RASP (Runtime Application Self-Protection) for AI agents |

**Güçlü Yönler:**
- ✅ RASP konsepti (kanıtlanmış güvenlik modeli)
- ✅ İyi fonlanmış

**Zayıf Yönler:**
- ❌ Application security vendor'ı olarak konumlanıyor (developer tool değil)
- ❌ IDE-native değil

**AIDR için Risk: ORTA** — RASP modeli güçlü ama AIDR developer-first yaklaşımı farklı.

---

#### 2.5 Diğer Startup'lar

| Startup | Fon | Odak | Risk |
|---------|-----|------|------|
| Aira Security | $20M Series A | AI ajan güvenlik duruş yönetimi | DÜŞÜK |
| Aegis Mesh | $15M seed (Şub 2026) | MCP güvenlik mesh | DÜŞÜK |
| RAXE | Seed | Ajan kimlik ve erişim güvenliği | DÜŞÜK |
| Rune | Pre-seed | Policy-as-code | DÜŞÜK |
| Gravix Layer | Pre-seed | Ajan runtime firewall | DÜŞÜK |
| Sponsio | Seed | Ajan governance & compliance | DÜŞÜK |
| Megent | Pre-seed | Ajan monitoring | DÜŞÜK |

---

### Kategori 3: MCP Güvenlik Araçları

MCP standardı hızla yayıldıkça, MCP-specific güvenlik araçları çoğalıyor:

| Araç | Tür | Odak |
|------|-----|------|
| mcp-armor | Açık kaynak | MCP güvenlik katmanı |
| MCP-Fortress | Açık kaynak | MCP auth/authorization |
| MCP Guardian | Açık kaynak | MCP request validation |
| mcpsec | CLI | MCP server güvenlik taraması |
| ContextGuard | Açık kaynak | MCP context isolation |
| MCP Shield | Açık kaynak | MCP runtime protection |

**AIDR için Fırsat:** Bu araçların hiçbiri tam çözüm değil. AIDR, mevcut MCP inventory + policy desteğini productize ederek bu kategoriyi domine edebilir.

---

### Kategori 4: Açık Kaynak Alternatifler

| Proje | Odak | Olgunluk |
|-------|------|----------|
| Knox | Agent sandboxing (Python) | Erken aşama |
| KiteGuard | MCP güvenlik toolkit | Erken aşama |
| AgentArmor | Agent permission framework | Erken aşama |
| Runwall | Container-based isolation | Erken aşama |
| Sigil | Agent identity framework | Erken aşama |

**AIDR için Fırsat:** Bu projelerin hiçbiri AIDR kadar kapsamlı değil. AIDR açık kaynak topluluğunu büyüterek bu projeleri absorbe edebilir.

---

## 4. Rakip Karşılaştırma Matrisi

### 4.1 Çekirdek Özellikler

| Feature | AIDR | Straiker | Declaw | CrowdStrike AIDR | MS Defender | HiddenLayer | LLM Guard |
|---------|------|----------|--------|-------------------|-------------|-------------|-----------|
| **Runtime Detection** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Agent-Aware** | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ✅ | ❌ |
| **Command Protection** | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **File System Protection** | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **URL/Network Protection** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Package Protection** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Plugin Scanning** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Output/Data Leakage** | 🔄 | ✅ | ❌ | ⚠️ | ✅ | ✅ | ✅ |
| **PII Redaction** | 🔄 | ✅ | ❌ | ❌ | ⚠️ | ✅ | ✅ |

### 4.2 Platform Desteği

| Feature | AIDR | Straiker | Declaw | CrowdStrike AIDR | MS Defender |
|---------|------|----------|--------|-------------------|-------------|
| **Claude Code** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Cursor** | ✅ | ❌ | ✅ | ❌ | ❌ |
| **VS Code** | ✅ | ❌ | ✅ | ❌ | ❌ |
| **OpenClaw** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **OpenCode** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **GitHub Copilot** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Agent 365** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Genel CLI** | ⚠️ | ✅ | ✅ | ❌ | ❌ |

### 4.3 MCP Desteği

| Feature | AIDR | Straiker | Declaw | Lupid | mcp-armor |
|---------|------|----------|--------|-------|-----------|
| **MCP Inventory** | ✅ | ❌ | ❌ | ✅ | ❌ |
| **MCP Policy** | 🔄 | ❌ | ❌ | ✅ | ❌ |
| **MCP Runtime Enforcement** | 🔄 | ❌ | ❌ | ✅ | ✅ |
| **MCP Server Vetting** | ❌ | ❌ | ❌ | ✅ | ❌ |
| **MCP Auth** | ❌ | ❌ | ❌ | ❌ | ✅ |

### 4.4 Fiyatlandırma

| Ürün | Ücretsiz Katman | Profesyonel | Kurumsal | Model |
|------|-----------------|-------------|----------|-------|
| **AIDR** | 1 ajan ücretsiz | $2/agent/ay | $8/agent/ay | Self-serve + Sales |
| **Straiker** | Deneme yok | ~$15/agent/ay | Custom | Enterprise sales |
| **Declaw** | Sınırlı açık kaynak | ~$5/agent/ay | Custom | Open-core |
| **CrowdStrike AIDR** | Yok | Yok | Falcon eklentisi | Enterprise bundle |
| **MS Defender AI** | Yok | Yok | E5 lisansıyla | Bundle |
| **HiddenLayer** | Deneme | $50K+/yıl | Custom | Enterprise sales |
| **LLM Guard** | Ücretsiz (Apache 2.0) | Yok | Custom | Open-core |

### 4.5 Teknik Karşılaştırma

Bu tablo Mart 2026 hipotezlerinin tarihsel kaydıdır; müşteri sunumunda güncel
paket boyutu, yük, fiyat, rakip kapsamı ve bağımsız kaynaklarla yeniden kurulmalı.

| Feature | AIDR | Rakipler |
|---------|------|----------|
| **Runtime Size** | İmzalı aday pakette ölçülecek | Rakiplerle karşılaştırma doğrulanmadı |
| **Detection Latency** | Seçilen yükte ölçülecek | Ortak yük karşılaştırması yok |
| **Offline Mode** | Ağ özellikleri kapatılmış geliştirme pilotunda doğrulanacak | Rakip kapsamı doğrulanmadı |
| **Privacy-First** | Veri akışı ve bölge onayı gerekli | Rakip kapsamı doğrulanmadı |
| **Failure behavior** | Algılama koluna ve ticari moda göre değişir | Rakip kapsamı doğrulanmadı |
| **License** | Mevcut paket metadata'sı `Proprietary`; haklar hukuk onayına bağlı | Rakip lisansları güncel kaynakla doğrulanmalı |
| **YAML Threat Rules** | ✅ (topluluk) | Straiker: ❌ (kapalı), CrowdStrike: ❌ (kapalı) |

### 4.6 Topluluk ve Ekosistem

| Metrik | AIDR | LLM Guard | Straiker |
|--------|------|-----------|----------|
| **GitHub Stars** | ~50-100 (tahmini) | 2.5K+ | N/A (kapalı) |
| **Threat Rules** | ~50-100 | 500+ | N/A |
| **Platform Desteği** | 5 platform | 3 platform | 1 platform |
| **Topluluk Katkısı** | Erken | Olgun | Yok |

---

## 5. AIDR SWOT Analizi

### 5.1 Güçlü Yönler (Strengths)

| # | Güçlü Yön | Rekabetçi Etki |
|---|-----------|----------------|
| S1 | **Yerel değerlendirme** — İsteğe bağlı ağ akışları ayrıca incelenmeli | Gizlilik kanıtı gerekli |
| S2 | **Bağlayıcı kapsamı** — Claude Code, Cursor, VS Code, OpenClaw, OpenCode için saha kabulü gerekli | Rakip karşılaştırması doğrulanmadı |
| S3 | **Boyut/gecikme** — İmzalı paket ve ortak yükte ölçülecek | Rakip karşılaştırması doğrulanmadı |
| S4 | **Lisans** — Mevcut paket metadata'sı `Proprietary` | Hukuk onayı gerekli |
| S5 | **Açık başarısızlık durumu** — Bazı arızalar inceleme/blok gerektirir; fail-open garantisi yok | Matris testi gerekli |
| S6 | **Agent-aware mimari** — LLM değil, ajan aksiyonlarını anlar | LLM Guard agent-aware değil |
| S7 | **Offline çalışabilme** — İnternet olmadan tam koruma | CrowdStrike/Microsoft bulut gerektirir |
| S8 | **YAML topluluk threat rule'ları** — Şeffaf, genişletilebilir | Rakiplerde kapalı kutu |

### 5.2 Zayıf Yönler (Weaknesses)

| # | Zayıf Yön | Risk |
|---|-----------|------|
| W1 | **ML/behavioral detection yok** — Sadece kural tabanlı | Gelişmiş tehditleri kaçırma |
| W2 | **MCP desteği henüz productize değil** — Temel inventory var, enforcement productization bekliyor | MCP pazarını kaçırma |
| W3 | **Küçük topluluk** — GitHub'da çok az star, katkıcı, threat rule | Büyüme hızı sınırlı |
| W4 | **Kurumsal özellikler eksik** — SSO, RBAC, audit log consolidation | Enterprise satışı zor |
| W5 | **Marka bilinirliği çok düşük** — AI güvenliği dendiğinde akla gelen isim değil | Satın alma kararlarında elenme |
| W6 | **CrowdStrike "AIDR" isim çakışması** — Aynı kısaltma, dev bir firma kullanıyor | Marka karmaşası, SEO kaybı |
| W7 | **Pazarlama içeriği zayıf** — Blog, tutorial, case study, benchmark yok | Organic traffic yok |
| W8 | **CI/CD entegrasyonu productize değil** — GitHub Action roadmap'de ama henüz yok | CI/CD pazarını kaçırma |
| W9 | **Dökümantasyon dağınık** — Strateji dökümanları var ama kullanıcı dökümanları eksik | Kullanıcı deneyimi düşük |
| W10 | **Threat rule kütüphanesi yetersiz** — ~50-100 rule vs LLM Guard'ın 500+ | Tespit kapsamı düşük |

### 5.3 Fırsatlar (Opportunities)

| # | Fırsat | Potansiyel Etki |
|---|--------|-----------------|
| O1 | **MCP endüstri standardı oluyor** — MCP güvenlik katmanında referans implementasyon olma | Kategori liderliği |
| O2 | **Pazar henüz oluşum aşamasında** — 6-12 ay içinde tanımlayıcı ürün belli olacak | İlk hamle avantajı |
| O3 | **Gizlilik regülasyonları güçleniyor** — GDPR, KVKK, AI Act gibi regülasyonlar local-first çözümleri zorunlu kılıyor | Düzenleyici avantaj |
| O4 | **AI ajan tedarik zinciri saldırıları** — Q1 2026'daki saldırılar runtime güvenlik talebini patlattı | Acil ihtiyaç |
| O5 | **Developer-first wedge** — Developer'lar önce aracı benimser, sonra kurumsallaştırır | Bottom-up büyüme |
| O6 | **Açık kaynak topluluk büyümesi** — Apache 2.0 + şeffaf threat rules = topluluk çekme | Viral büyüme |
| O7 | **Rakipler pahalı ve enterprise odaklı** — KOBİ/developer segmenti boş | Segmente girme |
| O8 | **CrowdStrike/Microsoft vendor lock-in** — Sadece kendi ekosistemlerini korur | Bağımsız çözüm talebi |
| O9 | **AI coding ajan pazarı büyüyor** — %70+ enterprise kullanımı → milyonlarca potansiyel ajan | Dev TAM |
| O10 | **GitHub Copilot, Cursor, Claude Code rekabeti** — Her ajan kendi güvenliğini yapmak yerine bağımsız çözüm tercih edebilir | Platform-agnostik avantaj |

### 5.4 Tehditler (Threats)

| # | Tehdit | Ciddiyet |
|---|--------|----------|
| T1 | **CrowdStrike "AIDR" ile aynı isim** — CrowdStrike pazara hakim olursa "AIDR" kısaltması onların ürünüyle özdeşleşir | KRİTİK |
| T2 | **Pazar penceresi kapanıyor** — 6-12 ay içinde bir firma (Straiker, CrowdStrike) kategoriyi domine edebilir | YÜKSEK |
| T3 | **Straiker'ın $40M fonu** — Hızlı büyüme, agresif satış, ürün geliştirme | YÜKSEK |
| T4 | **Microsoft, Defender'ı Claude Code/Cursor'a genişletirse** — MS'in dağıtım ağı rakipsiz | ORTA |
| T5 | **Büyük firmalar kendi çözümlerini yapar** — OpenAI, Anthropic, GitHub kendi runtime güvenliklerini built-in yapabilir | ORTA |
| T6 | **Açık kaynak alternatiflerin çoğalması** — Knox, KiteGuard, AgentArmor gibi projeler parçalanma yaratır | DÜŞÜK |
| T7 | **Fon bulamama riski** — AIDR bootstrapped/fazla fon yok, rakipler milyonlarla besleniyor | ORTA |
| T8 | **Güvenlik ihlali/AIDR'in kendisi hedef alınırsa** — Güvenlik ürününün kendisi hacklenirse itibar kaybı | DÜŞÜK |

### 5.5 Stratejik Sentez (SO - ST - WO - WT)

| Strateji | Aksiyon |
|----------|---------|
| **SO (Güçlü + Fırsat)** | Privacy-first + MCP standardizasyonu → "MCP için varsayılan güvenlik katmanı" konumlandırması |
| **SO (Güçlü + Fırsat)** | Açık kaynak + developer wedge → GitHub'da viral büyüme kampanyası |
| **ST (Güçlü + Tehdit)** | Çoklu platform + CrowdStrike tehdidi → "Bağımsız, her ajanı koruyan" mesajı |
| **ST (Güçlü + Tehdit)** | Hafif/offline + pazar penceresi → "5dk'da kurulum, hemen koruma" tezi |
| **WO (Zayıf + Fırsat)** | ML eksik + açık kaynak → Topluluk tabanlı ML modeli (topluluk eğitimi + katkısı) |
| **WO (Zayıf + Fırsat)** | Küçük topluluk + MCP fırsatı → MCP güvenlik toolkit'ini açık kaynak yap → topluluk çek |
| **WT (Zayıf + Tehdit)** | CrowdStrike isim çakışması + düşük bilinirlik → "Singularity AIDR" markasını güçlendir, trademark başvurusu yap |
| **WT (Zayıf + Tehdit)** | ML + MCP eksik + Straiker tehdidi → 90 gün içinde MVP ML modeli ve MCP enforcement çıkar |

---

## 6. Pazar Konumlandırma

### 6.1 Konumlandırma Haritası

```
                    KOMPLEKS / KURUMSAL
                           │
                           │
      HiddenLayer          │          CrowdStrike AIDR
      Protect AI           │          MS Defender AI
                           │
                           │
      ─────────────────────┼──────────────────────
                           │
                           │
      Straiker             │          AIDR
      Declaw               │
      RuntimeAI            │
                           │
                           ↓
                    BASİT / GELİŞTİRİCİ
```

AIDR: **Basit, geliştirici odaklı, çoklu platform** köşesinde konumlanıyor.

### 6.2 April Dunford Positioning Matrix

| Element | AIDR Pozisyonu |
|---------|----------------|
| **Pazar Kategorisi** | AI Agent Runtime Security |
| **Alternatif Çözüm** | Hiçbir şey kullanmamak (çıplak ajan), enterprise AI gateway, manuel review |
| **Benzersiz Değer** | Kodlama ajanlarını çalıştıkları yerde, göndermeden önce korur |
| **Hedef Müşteri** | AI kodlama ajanı kullanan geliştiriciler ve onların güvenlik ekipleri |
| **Kullanım Senaryosu** | Geliştirici agent'ı zararlı komut çalıştırmadan, dosya yazmadan, URL fetch yapmadan önce durdurur |
| **Farklılaştırıcı hipotezi** | Yerel değerlendirme ve çoklu bağlayıcı; lisans/boyut/saha kapsamı doğrulanacak |

### 6.3 Niche Tanımı

> **Öneri (onaysız):** "AIDR, desteklenen AI kodlama ajanı kancalarında
> komut, dosya, URL ve paket işlemlerini değerlendiren bir güvenlik katmanıdır.
> Engelleme, yalnız pre-tool yolunun çağrıldığı desteklenen aksiyonlarda
> geçerlidir; kurulum ve veri akışları pilotta doğrulanır."

---

## 7. En Büyük Tehditler (Detaylı)

### 7.1 KRİTİK: CrowdStrike "AIDR" İsim Çakışması

CrowdStrike'ın Nisan 2026'da **"AI Agent Detection & Response (AIDR)"** ürününü duyurması en ciddi tehdit.

**Riskler:**
- SEO'da "AIDR" aramaları CrowdStrike'a yönelir
- Marka karmaşası — potansiyel müşteriler iki farklı ürünü karıştırır
- CrowdStrike pazarda dominant hale gelirse "AIDR" kısaltması onların ürünüyle özdeşleşir
- CrowdStrike'ın hukuk ekibi trademark itirazı yapabilir

**Aksiyon:**
- "Singularity AIDR" markasını güçlendir (her yerde tam adı kullan)
- Trademark başvurusu yap ("Singularity AIDR" için)
- SEO stratejisi: "singularity aidr", "aidr security", "aidr agent protection" gibi long-tail anahtar kelimelere odaklan

### 7.2 YÜKSEK: Pazar Penceresi Kapanıyor

AI ajan güvenliği pazarı **oluşum aşamasında** ama hızla olgunlaşıyor:

| Zaman | Durum |
|-------|-------|
| **Bugün (Mayıs 2026)** | Kategori tanımlanmamış, kimse domine etmiyor |
| **6 ay sonra (Kasım 2026)** | 2-3 firma belirginleşmiş olacak |
| **12 ay sonra (Mayıs 2027)** | Kategori lideri belli olmuş olabilir |

AIDR'in önümüzdeki **6 ayı** kritik. Şu anda avantajlı:
- Daha hafif, daha hızlı, daha özel
- Rakip startup'lar hala ürün geliştiriyor
- CrowdStrike/Microsoft ürünleri henüz olgun değil

### 7.3 YÜKSEK: Straiker ($40M)

Straiker'ın $40M Series A fonuyla hızlı büyüme potansiyeli var. Aynı kategoriyi hedefliyor.

**AIDR Avantajı:**
- AIDR açık kaynak → topluluk avantajı
- AIDR daha hafif ve hızlı
- AIDR privacy-first (Straiker cloud zorunlu)

---

## 8. En Büyük Fırsatlar (Detaylı)

### 8.1 KRİTİK: MCP Standardizasyonu

MCP (Model Context Protocol), AI ajan-araç iletişiminde endüstri standardı haline geliyor. Anthropic, OpenAI, Google, Microsoft tarafından benimsendi.

**Fırsat:** AIDR, MCP güvenlik katmanında **referans implementasyon** haline gelebilir.

**Aksiyon:**
- MCP enforcement'ı productize et (90 gün)
- MCP server vetting/güvenlik taraması ekle
- MCP güvenlik toolkit'ini ayrı bir açık kaynak proje olarak yayınla (topluluk çekmek için)
- MCP spec'e güvenlik eklentisi olarak önerilme

### 8.2 YÜKSEK: Gizlilik Regülasyonları

GDPR, KVKK, AB AI Act gibi regülasyonlar güçleniyor. Local-first, privacy-first çözümler zorunlu hale geliyor.

**Fırsat:** AIDR'in privacy-first mimarisi, regülasyonların zorunlu kıldığı bir özellik haline geliyor.

### 8.3 YÜKSEK: Developer-First Wedge

Enterprise AI security vendor'ları yukarıdan aşağı (top-down) satarken, AIDR geliştiriciden başlayıp yukarı (bottom-up) büyüyebilir.

**Fırsat:** Geliştiriciler AIDR'i bireysel olarak benimser, sonra takımlarına, sonra şirketlerine yayarlar.

---

## 9. AIDR'i Piyasanın En İyisi Yapmak İçin Stratejik Aksiyonlar

### 9.1 Öncelik Matrisi

```
                    YÜKSEK ETKİ
                         │
                         │
     Acil Önlem          │     Stratejik Atak
     ───────────         │     ──────────────
     • CrowdStrike       │     • MCP güvenlik
       isim çakışması    │       liderliği
     • ML detection MVP  │     • Topluluk büyütme
     • MCP enforcement   │     • CI/CD productize
                         │
     ────────────────────┼────────────────────
                         │
                         │
     Hızlı Kazanç        │     Uzun Vadeli Yatırım
     ───────────         │     ──────────────────
     • Threat rules      │     • Enterprise SSO/RBAC
     • Dokümantasyon     │     • SOC entegrasyonu
     • Benchmark         │     • Mobile ajan desteği
     • Landing page      │     • Global satış kanalı
                         │
                    DÜŞÜK ÇABA
```

### 9.2 ŞİMDİ (Acil - Bu Hafta)

| # | Aksiyon | Neden |
|---|---------|-------|
| 1 | **"Singularity AIDR" markasını güçlendir** — Tüm dokümanlarda, README'de, paket adlarında "Singularity AIDR" kullan, trademark başvurusu yap | CrowdStrike isim çakışması |
| 2 | **Threat rule kütüphanesini 3x büyüt** — Mevcut ~50 rule'u 150+ rule'a çıkar (güvenlik topluluğundan katkı topla) | Tespit kapsamı düşük |
| 3 | **Benchmark sayfası oluştur** — AIDR vs rakipler (CrowdStrike, Straiker, Declaw) latency, boyut, özellik karşılaştırması | Satın alma kararlarında referans |
| 4 | **GitHub star/community kampanyası** — HackerNews, Twitter/Reddit'te duyuru, "Show HN" | Bilinirlik sıfır |
| 5 | **SEO düzeltmesi** — "aidr security", "sing singularity aidr", "ai agent detection and response" için içerik stratejisi | Organic traffic |

### 9.3 90 GÜN (Kısa Vade)

| # | Aksiyon | Neden |
|---|---------|-------|
| 1 | **Lightweight ML detection MVP** — 300KB embedding model (TinyBERT-style), cosine similarity, <20ms latency roadmap'te var, hayata geçir | Gelişmiş tehditleri kaçırma |
| 2 | **MCP enforcement productize** — Mevcut MCP inventory + policy kodunu product'a çevir, MCP server vetting ekle | MCP fırsatını kaçırma |
| 3 | **GitHub Action yayınla** — CI/CD pipeline'ları için PR scanning, policy enforcement | CI/CD pazarı |
| 4 | **MCP güvenlik toolkit'i açık kaynak** — Ayrı repo olarak mcp-aidr-security, topluluk çek | Topluluk büyütme + MCP liderliği |
| 5 | **Dokümantasyon revizyonu** — Kullanıcı hikayeleri, tutorial'lar, quickstart guide | Kullanıcı deneyimi |
| 6 | **Blog başlat** — "AI Agent Security" konusunda weekly blog posts, teknik içerik | SEO + thought leadership |
| 7 | **HackerNews lansmanı** — "Show HN: Singularity AIDR - Open-source runtime security for AI coding agents" | Topluluk + trafik |

### 9.4 6 AY (Orta Vade)

| # | Aksiyon | Neden |
|---|---------|-------|
| 1 | **Behavioral analysis v1** — SQLite local DB, command pattern tracking, z-score anomaly detection (roadmap'te Q2 2026) | Straiker farkı |
| 2 | **Enterprise SSO + RBAC** — SAML/OIDC, rol tabanlı erişim | Enterprise satış |
| 3 | **Team dashboard** — Multi-agent yönetimi, policy rollout, incident timeline | Takım kullanımı |
| 4 | **Plugin marketplace / threat rule community** — Topluluk katkılı threat rule'lar için GitHub Discussions + PR template | Topluluk büyütme |
| 5 | **Kurumsal pilot programı** — 5-10 referans müşteriyle ücretli pilot | Enterprise referansı |
| 6 | **Output/PII detection** — Ajan çıktısında secret/PII taraması (roadmap'te var) | Veri sızıntısı koruması |
| 7 | **SOC2 Type I sertifikası başlat** — Enterprise compliance | Enterprise satış |
| 8 | **Topluluk etkinlikleri** — AI güvenliği workshop'ları, konferans konuşmaları | Thought leadership |

### 9.5 12 AY (Uzun Vade)

| # | Aksiyon | Neden |
|---|---------|-------|
| 1 | **Global satış kanalı** — AWS Marketplace, partner programı | Scale |
| 2 | **Bağımsız Type II kontrol denetimi** — Planlanan dış doğrulama | Enterprise |
| 3 | **Managed cloud service** — Kontrol düzlemi SaaS (mevcut dashboard'ı productize) | MRR büyümesi |
| 4 | **Mobile agent support** — AI mobile agent güvenliği | Yeni pazar |
| 5 | **Advanced analytics** — Threat intelligence, trend raporları | Enterprise |
| 6 | **AI Act compliance modülü** — AB AI Act gereksinimleri için özel modül | Regülasyon |

---

## 10. Sonuç ve Öneriler

### 10.1 Genel Değerlendirme

Mayıs 2026 değerlendirmesi, yerel değerlendirme ve çoklu bağlayıcıyı olası
farklılaştırıcılar olarak görüyordu. Bugünkü destek, performans, veri akışı ve
lisans sınırları ayrı kanıt ve onay gerektirir; açık kaynak statüsü vaat edilmez.

Ancak AIDR'in üç kritik sorunu var:
1. **Bilinirlik sıfır** — Mükemmel ürün, kimse bilmiyor
2. **CrowdStrike isim çakışması** — Varoluşsal tehdit
3. **Hız** — Pazar penceresi 6-12 ay içinde kapanıyor

### 10.2 Üç Kritik Öneri

**1. CrowdStrike isim çakışmasını hemen çöz.**
"Singularity AIDR" markasını güçlendir. Tüm dokümanlarda, kodda, paket isimlerinde tam adı kullan. Trademark başvurusu yap. SEO'yu "Singularity AIDR" ve "AIDR security" long-tail'lerine kaydır.

**2. MCP güvenlik liderliğini kap.**
MCP endüstri standardı oluyor ve bu alanda dominant bir güvenlik çözümü yok. AIDR, mevcut MCP kodunu productize ederek ve MCP güvenlik toolkit'ini açık kaynak yaparak bu kategoriyi sahiplenebilir. Bu, AIDR'in "AI ajan güvenliği"nde tanımlayıcı ürün olmasının en kısa yolu.

**3. Go-to-market'i hızlandır.**
Mükemmel ürün yetmez. HackerNews lansmanı, blog içeriği, topluluk programı, GitHub star kampanyası, benchmark sayfası — bunların hepsi **bu hafta** başlamalı. AIDR'in teknik üstünlüğü var, sadece anlatmıyor.

### 10.3 Skor Kartı

| Boyut | Skor (1-10) | Durum |
|-------|-------------|-------|
| Ürün/Mimari | 8/10 | Güçlü temel, ML ve MCP productization eksik |
| Pazar Konumu | 5/10 | Doğru kategori ama marka karmaşası |
| Özellik Seti | 4/10 | Temel sağlam, advanced features roadmap'de |
| Topluluk | 3/10 | Çok küçük, büyüme potansiyeli var |
| Go-to-Market | 5/10 | Ücretsiz ama bilinmez |
| **Genel** | **6.2/10** | **Büyük potansiyel, hızlı aksiyon gerekli** |

---

*Bu doküman Mayıs 2026 itibarıyla günceldir. Pazar hızla değiştiği için her çeyrek gözden geçirilmelidir.*

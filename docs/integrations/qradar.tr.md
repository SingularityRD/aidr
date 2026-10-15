# IBM QRadar entegrasyonu (syslog üzerinden LEEF)

English: [qradar.md](qradar.md). Sözleşme: [SIEM iletimi](../contracts/siem-forwarding.md).

AIDR, her güvenlik olayı, karar ve Browser Guard kaydı için QRadar'a bir LEEF 1.0 kaydı
gönderir. Singularity AIDR için IBM'in yayımladığı bir DSM yoktur; kayıtları QRadar'ın
yerleşik **Universal LEEF** DSM'i ayrıştırır, DSM Editor ile de QID'lere ve özel alanlara
eşlenir. Bu rehber henüz canlı bir QRadar kurulumunda denenmedi; ilk kurulumu bir test
ortamında prova olarak yapın.

## 1. Göndereni seçin

| Gönderen | Ne zaman | Ayar |
| --- | --- | --- |
| Merkezi (önerilen) | Tüm uç noktalar için AIDR sunucusundan tek akış | SIEM sayfası → **Merkezi iletim** → Hedef ekle: tür *Syslog*, biçim *LEEF (QRadar)*, aktarım *TLS*, toplayıcı = QRadar olay toplayıcısı, port 6514 |
| Uç nokta başına | Her bilgisayar kendi olaylarını gönderir (sunucu yolu yoksa ya da ağlar ayrıysa) | SIEM sayfası → **Uç nokta iletimi**: mesaj biçimi *LEEF (QRadar)*; oluşan `adapter` bloğunu (`"payloadFormat": "leef"`) bilgisayardaki `SINGULARITY_AIDR_SIEM_CONFIG_PATH` dosyasına kopyalayın |

Toplayıcı iç ağ adresindeyse (10.x, 172.16-31.x, 192.168.x), AIDR yöneticisi
`AIDR_SIEM_ALLOW_PRIVATE_NETWORKS=true` (Compose `.env.functions`) ya da
`siem.allowPrivateNetworks=true` (Helm) ayarını açar; siz de hedefte *iç ağdaki toplayıcıya
izin ver* kutusunu işaretlersiniz. Kubernetes'te toplayıcıyı `networkPolicy.siemEgress`
listesine de ekleyin.

## 2. QRadar kayıt kaynağı (log source)

1. **Admin → Log Source Management → New Log Source** (eski sürümlerde **Admin → Log Sources**).
2. *Log Source Type*: **Universal LEEF**.
3. *Protocol*:
   - **TLS Syslog** (önerilen): dinleme portu `6514`. QRadar'a kurumunuzun iç CA'sının
     verdiği bir sunucu sertifikası tanımlayın ve bu CA'nın PEM sertifikasını AIDR hedefine
     (*Özel CA sertifikası*) yapıştırın. AIDR sertifikayı ve sunucu adını her zaman doğrular.
   - **Syslog** (TCP ya da UDP 514): şifresizdir. AIDR açık bir şifresiz gönderim onayı ister;
     UDP'de alındı onayı yoktur.
4. *Log Source Identifier*: AIDR'ın gönderdiği syslog HOSTNAME değeri. Merkezi iletim, hedefte
   başka bir `hostname` verilmedikçe `aidr-control-plane` gönderir; uç nokta iletimi
   yapılandırılan `hostname` değerini (varsayılan `aidr`) gönderir.
5. Kaydedin ve **Deploy Changes** ile yayımlayın.

## 3. Doğrulama

SIEM sayfasında **Deneme gönder** düğmesine basın. QRadar Log Activity ekranında kayıt
kaynağından `EventID = AIDR-INFO-TEST` olan bir kayıt görünür. Gelmezse sayfa son hatayı
gösterir (`tls_verification_failed`, `destination_policy_rejected`, `network_error` gibi).

## 4. Kayıt yapısı

```
<PRI>Oct 14 07:59:58 aidr-control-plane aidr: LEEF:1.0|Singularity|AIDR|1.0|AIDR-CRITICAL-DECISION-DENY|cat=decision	sev=10	devTime=1791964798000	externalId=aidr_evt_4242	name=AIDR deny decision - T01	tenant_id=…	kind=decision	type=runtime_verdict	decision=deny	severity=critical	threat_id=T01	agent_iid=laptop-17	connector=claude-code	tool_name=Bash	…
```

| LEEF alanı | Anlamı | QRadar'da kullanım |
| --- | --- | --- |
| EventID (başlık) | `AIDR-<ÖNEM>-<TÜR>[-<KARAR ya da EYLEM>]`; uç nokta olayları: `AIDR-<ÖNEM>` | QID eşleme |
| `cat` | `incident`, `decision`, `browser`, `test` | Kategori / QID eşleme |
| `sev` | 0-10 (info 2, warning 5, high 8, critical 10) | Önem derecesi |
| `devTime` | Olay zamanı, milisaniye cinsinden epoch | Başlangıç zamanı |
| `externalId` | Değişmeyen kayıt kimliği (`aidr_evt_<n>`); yeniden iletimde aynıdır | Tekilleştirme, offense notları |
| `decision` | `allow`, `ask` (bant dışı onay bekliyor), `deny` | Özel alan |
| `threat_id` | AIDR kural kimliği (örneğin `T01`) | Özel alan |
| `agent_iid`, `connector`, `session_id`, `tool_name` | Hangi ajan, hangi bağlayıcı, hangi araç | Özel alanlar |
| `incident_id`, `status`, `findings_count` | Olay ilişkilendirme | Özel alanlar |
| `site`, `action`, `channel`, `entity_counts` | Browser Guard: yapay zekâ sitesi, engellendi/uyarıldı, istem/yapıştırma/dosya, veri türü sayıları | Özel alanlar |
| `tenant_id` | AIDR çalışma alanı | Çok kiracılı süzme |

İstem, komut, dosya yolu ya da adres hiçbir zaman gönderilmez (sözleşmeye bakın).

## 5. QID eşleme (DSM Editor)

**Admin → DSM Editor → Universal LEEF** ekranında ihtiyaç duyduğunuz EventID'ler için olay
eşlemeleri ekleyin. Önerilen alt kategoriler (kendi sınıflandırmanıza göre uyarlayın):

| EventID deseni | Önerilen kategori |
| --- | --- |
| `AIDR-*-DECISION-DENY` | Policy Violation / Access Denied |
| `AIDR-*-DECISION-ASK` | Suspicious Activity (onay bekliyor) |
| `AIDR-*-DECISION-ALLOW` | Information |
| `AIDR-*-INCIDENT`, `AIDR-<ÖNEM>` | Suspicious Activity / Malware (`threat_id` değerine göre) |
| `AIDR-*-BROWSER-BLOCKED` | Data Loss Prevention |
| `AIDR-INFO-TEST` | Information |

`decision`, `threat_id`, `agent_iid`, `tool_name` ve `incident_id` için özel olay alanları
(custom event properties) tanımlayın (Universal LEEF her `anahtar=değer` çiftini zaten
ayırır), ardından kurallar yazın; örneğin *“aynı agent_iid için 10 dakika içinde 3 ya da daha
fazla AIDR deny kararı”*.

Örnek AQL:

```sql
SELECT DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm') AS t, "decision", "threat_id", "agent_iid"
FROM events
WHERE LOGSOURCETYPENAME(devicetype) = 'Universal LEEF' AND "decision" = 'deny'
LAST 24 HOURS
```

## 6. Bunun yerine CEF (ArcSight ya da CEF ile QRadar)

Biçim olarak *CEF (ArcSight)* seçin. Kayıtlar şu yapıdadır:
`CEF:0|Singularity|AIDR|1.0|AIDR/<önem>/<TÜR>[/<KARAR>]|<ad>|<0-10>|rt=… externalId=… cat=… act=<karar> cs1Label=threat_id cs1=<kural> …`.
ArcSight'ta Syslog SmartConnector kullanın (CEF doğrudan ayrıştırılır); QRadar'da
**Universal CEF** DSM'ini seçin.

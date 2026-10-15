# Wazuh entegrasyonu (decoder ve kurallar)

English: [wazuh.md](wazuh.md). Sözleşme: [SIEM iletimi](../contracts/siem-forwarding.md).

İki desteklenen yol vardır. Bu rehber henüz canlı bir Wazuh kurulumunda denenmedi; ilk kurulumu
bir test ortamında prova olarak yapın ve decoder'ları `wazuh-logtest` ile doğrulayın.

| Yol | Aktarım | AIDR biçimi | Wazuh tarafı |
| --- | --- | --- | --- |
| A (önerilen) | Wazuh yönetici sunucusundaki rsyslog'a **TLS** ile syslog (iç CA) | JSON | rsyslog her kaydı tek satır JSON olarak yazar; Wazuh dosyayı `log_format json` ile okur; kurallar aşağıda |
| B | Doğrudan Wazuh yöneticisine **TCP** syslog (`remote` syslog dinleyicisi) | LEEF | Aşağıdaki özel `aidr` decoder'ları |

Wazuh'un syslog dinleyicisinin kendi TLS desteği yoktur; bu yüzden B yolunda kayıtlar iç ağda
şifresiz gider (AIDR açık bir şifresiz gönderim onayı ister). İki yol da merkezi iletimle (SIEM
sayfası → Merkezi iletim) ve uç nokta iletimiyle (SIEM sayfası → Uç nokta iletimi) çalışır.
Toplayıcı iç ağ adresindeyse AIDR yöneticisi `AIDR_SIEM_ALLOW_PRIVATE_NETWORKS=true`
(Compose) ya da `siem.allowPrivateNetworks=true` (Helm) ayarını açar, hedef de buna izin
verir.

## A yolu: rsyslog (TLS) → JSON dosyası → Wazuh

Wazuh yönetici sunucusunda `/etc/rsyslog.d/30-aidr.conf` (rsyslog 8 ve `rsyslog-gnutls`):

```
global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="/etc/rsyslog.d/aidr/ca.pem"
  DefaultNetstreamDriverCertFile="/etc/rsyslog.d/aidr/server.pem"
  DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/aidr/server.key"
)
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.AuthMode="anon")
input(type="imtcp" port="6514" ruleset="aidr")
# Yalnız JSON gövdesini tut (AIDR, JSON'dan önce BOM bulunan RFC 5424 gönderir).
template(name="aidrJson" type="string" string="%msg:R,ERE,1,DFLT:(\\{.*)--end%\n")
ruleset(name="aidr") {
  if $app-name == "aidr" then {
    action(type="omfile" file="/var/log/aidr/aidr.json" template="aidrJson" fileCreateMode="0640")
  }
  stop
}
```

`server.pem` kurumunuzun iç CA'sı tarafından verilir; bu CA'nın PEM sertifikasını AIDR hedefine
(*Özel CA sertifikası*) yapıştırın. rsyslog, AIDR'ın kullandığı uzunluk önekli (octet-counted)
çerçevelemeyi varsayılan olarak kabul eder. 6514 portunu sunucu güvenlik duvarında yalnız AIDR
sunucusuna (ya da uç noktalara) açın.

`/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/aidr/aidr.json</location>
</localfile>
```

Her kayıt kendi JSON alanlarıyla gelir (`schema_version`, `kind`, `tenant_id`,
`event.decision`, `event.severity`, `event.threat_id`, `event.agent_iid` …). Uç nokta
iletiminin gönderdiği güvenlik olayları ise uç nokta şemasını kullanır (`schema_version`
`aidr.siem.event/v1`, alanlar `incident.severity`, `incident.incident_id`,
`incident.agent_iid`); bunları `<field name="schema_version">^aidr.siem.event/v1$</field>` ile
eşleyin.

`/var/ossec/etc/rules/aidr_rules.xml` (kimlikleri kendi boş aralığınıza göre değiştirin):

```xml
<group name="aidr,">
  <rule id="100200" level="3">
    <decoded_as>json</decoded_as>
    <field name="source.product">^AIDR$</field>
    <description>Singularity AIDR kaydı</description>
  </rule>
  <rule id="100201" level="3">
    <if_sid>100200</if_sid>
    <field name="kind">^test$</field>
    <description>Singularity AIDR SIEM deneme kaydı</description>
  </rule>
  <rule id="100202" level="10">
    <if_sid>100200</if_sid>
    <field name="event.decision">^deny$</field>
    <description>AIDR bir yapay zekâ ajanı işlemini engelledi (kural $(event.threat_id), ajan $(event.agent_iid))</description>
    <group>policy_violation,</group>
  </rule>
  <rule id="100203" level="7">
    <if_sid>100200</if_sid>
    <field name="event.decision">^ask$</field>
    <description>AIDR bir ajan işlemini bant dışı onaya bekletti (ajan $(event.agent_iid))</description>
  </rule>
  <rule id="100204" level="12">
    <if_sid>100202</if_sid>
    <field name="event.severity">^critical$</field>
    <description>AIDR kritik bir ajan işlemini engelledi (kural $(event.threat_id))</description>
  </rule>
  <rule id="100205" level="10">
    <if_sid>100200</if_sid>
    <field name="kind">^incident$</field>
    <description>AIDR güvenlik olayı $(event.incident_id) ($(event.severity))</description>
  </rule>
  <rule id="100206" level="8">
    <if_sid>100200</if_sid>
    <field name="kind">^browser$</field>
    <description>AIDR Browser Guard $(event.action): $(event.site)</description>
    <group>data_protection,</group>
  </rule>
  <rule id="100207" level="12" frequency="5" timeframe="600">
    <if_matched_sid>100202</if_matched_sid>
    <same_field>event.agent_iid</same_field>
    <description>AIDR: aynı ajandan art arda engellenen işlemler</description>
  </rule>
</group>
```

## B yolu: doğrudan Wazuh'a TCP syslog (LEEF)

`ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>10.20.30.0/24</allowed-ips>
</remote>
```

AIDR hedefi: *Syslog*, aktarım *TCP*, biçim *LEEF (QRadar)*, şifresiz gönderim onaylı. Kayıtlar
`<PRI>Oct 14 07:59:58 aidr-control-plane aidr: LEEF:1.0|Singularity|AIDR|…` biçiminde gelir.

`/var/ossec/etc/decoders/aidr_decoders.xml` (Wazuh 4.3 ve sonrası, PCRE2):

```xml
<decoder name="aidr">
  <program_name>^aidr$</program_name>
  <prematch type="pcre2">LEEF:1\.0\|Singularity\|AIDR\|</prematch>
</decoder>
<decoder name="aidr-fields">
  <parent>aidr</parent>
  <regex type="pcre2">\|(AIDR-[A-Z-]+)\|cat=(\w+)</regex>
  <order>id, aidr.kind</order>
</decoder>
<decoder name="aidr-fields">
  <parent>aidr</parent>
  <regex type="pcre2">\tdecision=(\w+)</regex>
  <order>aidr.decision</order>
</decoder>
<decoder name="aidr-fields">
  <parent>aidr</parent>
  <regex type="pcre2">\tseverity=(\w+)</regex>
  <order>aidr.severity</order>
</decoder>
<decoder name="aidr-fields">
  <parent>aidr</parent>
  <regex type="pcre2">\tthreat_id=([\w.:-]+)</regex>
  <order>aidr.threat_id</order>
</decoder>
<decoder name="aidr-fields">
  <parent>aidr</parent>
  <regex type="pcre2">\tagent_iid=([\w.:-]+)</regex>
  <order>aidr.agent_iid</order>
</decoder>
<decoder name="aidr-fields">
  <parent>aidr</parent>
  <regex type="pcre2">\texternalId=([\w.:-]+)</regex>
  <order>aidr.event_id</order>
</decoder>
```

B yolunun kuralları `<decoded_as>aidr</decoded_as>` ve `aidr.*` alanlarını kullanır, örneğin:

```xml
<group name="aidr,">
  <rule id="100220" level="3">
    <decoded_as>aidr</decoded_as>
    <description>Singularity AIDR kaydı</description>
  </rule>
  <rule id="100221" level="10">
    <if_sid>100220</if_sid>
    <field name="aidr.decision">^deny$</field>
    <description>AIDR bir yapay zekâ ajanı işlemini engelledi (kural $(aidr.threat_id), ajan $(aidr.agent_iid))</description>
  </rule>
</group>
```

## Doğrulama

1. `sudo /var/ossec/bin/wazuh-logtest` çalıştırıp `/var/log/aidr/aidr.json` dosyasından bir
   satırı (A yolu) ya da gelen bir LEEF satırını (B yolu) yapıştırın; yukarıdaki kurallar
   tetiklenmelidir.
2. Yöneticiyi yeniden başlatın (`systemctl restart wazuh-manager`), ardından SIEM sayfasında
   **Deneme gönder** düğmesine basın: Wazuh panelinde 100201 kuralı (A yolu) görünür. Başarısız
   bir deneme, toplayıcının verdiği hatayı SIEM sayfasında gösterir.

AIDR istem, komut, dosya yolu ya da adres göndermez; alanların tam listesi sözleşmededir. Her
kayıt değişmeyen bir `event_id` / `externalId` taşır: zaman aşımından sonra yeniden iletilen
bir kayıt aynı kimliği taşır, sayım yaparken bu kimliğe göre tekilleştirin.

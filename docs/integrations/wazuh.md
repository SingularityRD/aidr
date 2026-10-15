# Wazuh integration (decoder and rules)

Türkçe: [wazuh.tr.md](wazuh.tr.md). Contract: [SIEM forwarding](../contracts/siem-forwarding.md).

Two supported paths. This guide has not yet been run against a live Wazuh installation; treat
the first set-up as a staging rehearsal and check the decoders with `wazuh-logtest`.

| Path | Transport | AIDR format | Wazuh side |
| --- | --- | --- | --- |
| A (recommended) | Syslog **TLS** to rsyslog on the Wazuh manager host (internal CA) | JSON | rsyslog writes each event as one JSON line; Wazuh reads the file with `log_format json`; rules below |
| B | Syslog **TCP** straight to the Wazuh manager (`remote` syslog listener) | LEEF | Custom `aidr` decoders below |

The Wazuh syslog listener has no TLS of its own, so path B sends events unencrypted on the
internal network (AIDR requires the explicit plaintext confirmation). Both paths work for
central forwarding (SIEM page → Central forwarding) and per-endpoint forwarding (SIEM page →
Host forwarding). For a collector on a private address the AIDR operator sets
`AIDR_SIEM_ALLOW_PRIVATE_NETWORKS=true` (Compose) or `siem.allowPrivateNetworks=true` (Helm),
and the destination opts in.

## Path A: rsyslog (TLS) → JSON file → Wazuh

`/etc/rsyslog.d/30-aidr.conf` on the Wazuh manager host (rsyslog 8 with `rsyslog-gnutls`):

```
global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="/etc/rsyslog.d/aidr/ca.pem"
  DefaultNetstreamDriverCertFile="/etc/rsyslog.d/aidr/server.pem"
  DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/aidr/server.key"
)
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.AuthMode="anon")
input(type="imtcp" port="6514" ruleset="aidr")
# Keep only the JSON body (AIDR sends RFC 5424 with a BOM before the JSON).
template(name="aidrJson" type="string" string="%msg:R,ERE,1,DFLT:(\\{.*)--end%\n")
ruleset(name="aidr") {
  if $app-name == "aidr" then {
    action(type="omfile" file="/var/log/aidr/aidr.json" template="aidrJson" fileCreateMode="0640")
  }
  stop
}
```

`server.pem` is issued by your internal CA; paste that CA's PEM certificate into the AIDR
destination (*Private CA certificate*). rsyslog accepts AIDR's octet-counted framing by
default. Restrict port 6514 to the AIDR server (or the endpoints) in the host firewall.

`/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/aidr/aidr.json</location>
</localfile>
```

Each event arrives with its JSON fields (`schema_version`, `kind`, `tenant_id`,
`event.decision`, `event.severity`, `event.threat_id`, `event.agent_iid`, …). Incidents sent
by per-endpoint forwarding use the endpoint schema instead (`schema_version`
`aidr.siem.event/v1`, fields `incident.severity`, `incident.incident_id`,
`incident.agent_iid`); match them with `<field name="schema_version">^aidr.siem.event/v1$</field>`.

`/var/ossec/etc/rules/aidr_rules.xml` (adjust the ids to your free range):

```xml
<group name="aidr,">
  <rule id="100200" level="3">
    <decoded_as>json</decoded_as>
    <field name="source.product">^AIDR$</field>
    <description>Singularity AIDR event</description>
  </rule>
  <rule id="100201" level="3">
    <if_sid>100200</if_sid>
    <field name="kind">^test$</field>
    <description>Singularity AIDR SIEM test event</description>
  </rule>
  <rule id="100202" level="10">
    <if_sid>100200</if_sid>
    <field name="event.decision">^deny$</field>
    <description>AIDR blocked an AI agent action (rule $(event.threat_id), agent $(event.agent_iid))</description>
    <group>policy_violation,</group>
  </rule>
  <rule id="100203" level="7">
    <if_sid>100200</if_sid>
    <field name="event.decision">^ask$</field>
    <description>AIDR held an AI agent action for out-of-band approval (agent $(event.agent_iid))</description>
  </rule>
  <rule id="100204" level="12">
    <if_sid>100202</if_sid>
    <field name="event.severity">^critical$</field>
    <description>AIDR blocked a critical AI agent action (rule $(event.threat_id))</description>
  </rule>
  <rule id="100205" level="10">
    <if_sid>100200</if_sid>
    <field name="kind">^incident$</field>
    <description>AIDR incident $(event.incident_id) ($(event.severity))</description>
  </rule>
  <rule id="100206" level="8">
    <if_sid>100200</if_sid>
    <field name="kind">^browser$</field>
    <description>AIDR Browser Guard $(event.action) on $(event.site)</description>
    <group>data_protection,</group>
  </rule>
  <rule id="100207" level="12" frequency="5" timeframe="600">
    <if_matched_sid>100202</if_matched_sid>
    <same_field>event.agent_iid</same_field>
    <description>AIDR: repeated blocked actions from the same agent</description>
  </rule>
</group>
```

## Path B: TCP syslog straight to Wazuh (LEEF)

`ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>10.20.30.0/24</allowed-ips>
</remote>
```

AIDR destination: *Syslog*, transport *TCP*, format *LEEF (QRadar)*, plaintext confirmed.
Records arrive as `<PRI>Oct 14 07:59:58 aidr-control-plane aidr: LEEF:1.0|Singularity|AIDR|…`.

`/var/ossec/etc/decoders/aidr_decoders.xml` (Wazuh 4.3+, PCRE2):

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

Rules for path B use `<decoded_as>aidr</decoded_as>` and the `aidr.*` fields, for example:

```xml
<group name="aidr,">
  <rule id="100220" level="3">
    <decoded_as>aidr</decoded_as>
    <description>Singularity AIDR event</description>
  </rule>
  <rule id="100221" level="10">
    <if_sid>100220</if_sid>
    <field name="aidr.decision">^deny$</field>
    <description>AIDR blocked an AI agent action (rule $(aidr.threat_id), agent $(aidr.agent_iid))</description>
  </rule>
</group>
```

## Verify

1. `sudo /var/ossec/bin/wazuh-logtest` and paste one line from `/var/log/aidr/aidr.json`
   (path A) or one received LEEF line (path B); the rule ids above must fire.
2. Restart the manager (`systemctl restart wazuh-manager`), then press **Send test** on the
   SIEM page: rule 100201 (path A) appears in the Wazuh dashboard. A failed test shows the
   collector's error on the SIEM page.

AIDR never sends prompts, commands, paths or URLs; the fields are listed in the contract.
Every event carries a stable `event_id` / `externalId`: a re-delivery after a timeout has the
same id, so deduplicate on it when counting.

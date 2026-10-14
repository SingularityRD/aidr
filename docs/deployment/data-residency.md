# Data residency

[Türkçe özet aşağıda](#türkçe-özet)

**Short answer for Turkish customers who need data to stay in Turkey: run the
control plane on-premises.** Singularity AIDR's control plane (the Supabase
stack and the dashboard in this repository) runs on the customer's own Linux
host or Kubernetes cluster, connected or air-gapped. The data then stays where
the customer puts it, and nothing goes to SingularityRD. That is the residency
offer today. The hosted service has **no Turkey region**, and its EU placement
is not yet verified end to end.

## Where data lives, per deployment

| Deployment | Endpoint data | Control-plane data | Goes to SingularityRD | Residency statement we can make |
|---|---|---|---|---|
| Local mode only (no control plane) | On each endpoint | None | Nothing | "Detection runs on the device; no AIDR data leaves it." |
| On-premises (Docker Compose or Helm) | On each endpoint | Customer's host, in the location the customer chooses | Nothing (support bundles only when the customer approves one) | "Stored where you run it." Holds when the backup target, SMTP, IdP, SIEM and optional lookups are also in-country; see [the KVKK guide](../operations/kvkk.md#4-yurt-dışına-aktarım) |
| Air-gapped on-premises | On each endpoint | Customer's isolated network | Nothing; updates arrive as signed offline bundles | Same as on-premises, with no outbound path |
| Hosted (SaaS) | On each endpoint | SingularityRD-operated cloud | Redacted events and dashboard data | Only the facts in the next section; no residency claim |

Endpoint detection is the same in every row: the connectors and Browser Guard
evaluate on the device, and only redacted, minimised events go to whichever
control plane the endpoint is enrolled in ([privacy](../privacy.md)).

## Hosted service: the facts we have

The hosted service is not accepted for customer use
([SaaS deployment](saas.md)). What is known, from the
[COM-011 audit](../production-readiness/com-011-region-residency-audit-2026-09-23.md):

- The linked pilot Supabase project's primary region is **`eu-central-1`
  (Frankfurt)**, observed on 23 September 2026. A project region locates
  primary project data; it does not by itself locate every log, backup or Edge
  Function execution (functions run near the caller unless pinned).
- Browser and API traffic for the pilot goes through a Cloudflare Worker on a
  **`workers.dev`** hostname, which cannot be regionalised.
- Hosted e-mail goes through the configured mail provider (Resend by default
  in the code), which is outside Turkey.
- [`deploy/regions.manifest.json`](../../deploy/regions.manifest.json) records
  operator declarations only; `managed-cloud` is still a placeholder.
- There is no hosted Turkey region, and none is planned in this repository.

Until a production cell is provisioned and verified, do **not** claim EU-only
processing, EU/US/APAC placement or Turkish residency for the hosted service.
The sale-safe statement is the one in the COM-011 audit.

## The vendor website and admin panel

The marketing site and the vendor `/admin` panel (the separate `aidr-landing`
application) are not the product control plane. They hold SingularityRD's own
commercial records about a customer (organisation name, contacts, licence
terms, seat count, installer builds), not the customer's endpoint telemetry.
Their database region is not documented in this repository; treat those
records as SingularityRD's own processing (covered by SingularityRD's privacy
notice, not by the customer's DPA).

## What a customer should ask for

- On-premises: the [end-to-end on-prem runbook](../operations/onprem-runbook.md),
  the egress list and a packet capture showing no unexpected destinations.
- Hosted: the verified region inventory per data path, the subprocessor list
  ([DPA Annex 3](../legal/dpa.en.md)) and the transfer mechanism. Today these
  are open.

## Türkçe özet

**Verinin Türkiye'de kalması gereken müşteriler için cevap: kontrol sunucusunu
şirket içinde çalıştırın.** Kontrol sunucusu (bu depodaki Supabase yığını ve
yönetim paneli) müşterinin kendi Linux sunucusunda ya da Kubernetes kümesinde,
internete bağlı ya da internetsiz çalışır; veri müşterinin koyduğu yerde kalır
ve SingularityRD'ye hiçbir şey gitmez. Barındırılan hizmetin **Türkiye bölgesi
yoktur**; pilot projenin birincil bölgesi `eu-central-1` (Frankfurt) olarak
gözlenmiştir, ancak uçtan uca yerleşim doğrulanmamıştır (istek iletimi
`workers.dev` üzerinden, e-posta yurt dışındaki sağlayıcıdan). Barındırılan
hizmet için yerleşim iddiasında bulunmayın. Pazarlama sitesi ve satıcı `/admin`
paneli ürün kontrol sunucusu değildir; yalnız SingularityRD'nin müşteriyle
ilgili ticari kayıtlarını tutar. Ayrıntı: [KVKK rehberi](../operations/kvkk.md).

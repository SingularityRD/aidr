# Supported versions policy

> **DRAFT — Product, Security, Support and Legal approval required.** No
> numeric support window is approved today, and no customer release has been
> cut, so no version is "supported" yet ([SECURITY.md](../../SECURITY.md)).
> Bracketed numbers are proposals. Version: draft 0.1, 14 October 2026.
> [Türkçe özet aşağıda](#türkçe-özet).

## Version numbers

Releases use semantic versions `MAJOR.MINOR.PATCH`. Release candidates
(`-rc.N`) are never supported for production. Each release has one version
across the CLI, connectors, desktop installers and control plane; Browser
Guard has its own version line (`browser-guard-vX.Y.Z`).

## Support phases

| Phase | What it gets | Proposed duration |
|---|---|---|
| **Active** | Fixes, security fixes, new rule and intel packs, host-compatibility updates | Latest minor of the current major |
| **Security-only** | Security fixes and rule/intel packs; no features | Previous minor, for [6] months after the next minor ships |
| **Extended (on-prem / air-gapped, by contract)** | Security fixes for one named minor | [12] months after it leaves Security-only, only under an Enterprise agreement |
| **End of life** | Nothing; local detection keeps running with its last rules | — |

Rule and intel packs declare the minimum engine version they need; an older
engine keeps its last compatible packs rather than receiving packs it cannot
evaluate.

## Rules that do not depend on approval

- A version is supported only while the customer's licence term is active
  (updates follow the licence; see the [EULA draft](../legal/eula.en.md) §5).
- Control plane and endpoints: endpoints may be at most [one] minor behind the
  control plane; the control plane is upgraded first.
- AI agent hosts change hook formats. A host version is supported only where
  the [compatibility matrix](../compatibility-matrix.md) lists a real-host
  acceptance record for it; other host versions are untested.
- Operating systems: Windows 10/11 x64 and the Linux distributions named in
  the [installer documentation](../installation/desktop-installers.md), for as
  long as their vendor supports them. Windows Server (for VDI hosts) is not
  listed yet and needs its own acceptance run. No macOS installer is offered.
- End-of-life notice: at least [6] months before a version leaves
  Security-only, sent through the customer's support channel and the release
  notes; affected customers are listed and their acknowledgement recorded
  ([support v7 runbook](../runbooks/support-v7.md#end-of-security-maintenance)).

## How to check what you run

`aidr status` and `aidr doctor` print the core version on each endpoint; the
dashboard's Agents page lists the versions across the fleet; the on-prem
deployment manifest (`deployment.json`) records the control-plane version.

## Türkçe özet

**Taslaktır; onaylı bir destek süresi yoktur ve henüz müşteri sürümü
çıkmamıştır.** Önerilen düzen: en son küçük sürüm "aktif" (tüm düzeltmeler ve
paketler), bir önceki küçük sürüm bir sonraki çıktıktan sonra [6] ay "yalnız
güvenlik", Enterprise sözleşmesiyle internetsiz kurulumlar için [12] ay
"uzatılmış" destek. Destek yalnız lisans süresi boyunca verilir. Uç noktalar
kontrol sunucusundan en fazla [bir] küçük sürüm geride olabilir; önce kontrol
sunucusu yükseltilir. AI ajan aracı sürümleri yalnız uyumluluk matrisinde
gerçek ortam kabul kaydı varsa desteklenir. Destek sonu en az [6] ay önceden
bildirilir. Sürüm kontrolü: `aidr status`, `aidr doctor`, panelde Ajanlar
sayfası.

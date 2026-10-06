# AIDR alt özellik envanteri

Otomatik üretim tarihi: **2026-10-06**. 71 alt özellik ve teslimat gereksinimi eşlendi: 41 çalışan kod akışına bağlı, 28 kısmi, 0 eksik, 2 dış kanıta bağlı. Bu sayılar üretim kabulü veya tespit başarım oranı değildir. Satış/GA kararı **NO-GO** olarak korunur.

Makine kaydı: [FEATURE_INVENTORY.json](FEATURE_INVENTORY.json). Kaynaklar, tüketen bileşenler ve her satırın kalan işi bu dosyada bulunur. Önceki PRODUCT_SCOPE_AND_FEATURES.md dosyasındaki modül erişilebilirlik sayıları tarihsel bir ara denetime aittir.

## Durum tanımları

- **wired:** Çağrılabilen kod akışı var; kapsam ve test sınırı geçerlidir.
- **partial:** Uygulama var, ancak teslimat veya kapsamın bir bölümü eksik.
- **missing:** Uçtan uca özellik bulunmuyor; mevcut temel modül tamamlanmış özellik sayılmaz.
- **external:** Müşteri/operasyon/hukuk gibi dış tarafların kanıtı gerekiyor.

## Detection

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| DET-01 | [Tool artifact extraction](packages/core/src/extractors.ts) | wired | Unrecognized or host-hidden actions remain outside visibility |
| DET-02 | [Threat rules and confidence merge](packages/core/src/engine.ts) | wired | Independent false-positive and evasion measurements remain required |
| DET-03 | [Obfuscation and suspicious shell patterns](threats/obfuscation.yaml) | wired | Stateful multi-step command-chain analysis is not implemented |
| DET-04 | [Credential access and exfiltration](threats/credentials.yaml) | wired | Customer secret types and benign workflow corpus need calibration |
| DET-05 | [Cross-platform rules and mining](threats/mining.yaml) | wired | Native host matrix and mining workload acceptance remain external |
| DET-06 | [Prompt injection inspection](packages/core/src/output-scanner.ts) | partial | Claude PostToolUse and OpenClaw after_tool_call cannot prove same-turn model blocking; provider streams and native host bypass need acceptance |
| DET-07 | [Structured DLP and PII](packages/core/src/dlp/scanner.ts) | partial | Real labels and TR/EN NER efficacy are unaccepted; later host callbacks cannot guarantee same-turn output blocking; unsupported opaque formats fail closed |
| DET-08 | [Behavioral and novelty analysis](packages/core/src/behavioral-orchestrator.ts) | partial | Exit zero is not business success or process-tree isolation; real corpus efficacy, customer role custody and native OS acceptance remain required; OS owner can roll back the whole vault and journal |
| DET-09 | [ML classification and similarity](packages/core/src/behavioral-orchestrator.ts) | partial | No independently validated production model efficacy or broad runtime adoption |
| DET-10 | [URL reputation](packages/core/src/clients/url-check.ts) | partial | Provider feed, operational freshness and customer latency proof still required |
| DET-11 | [File reputation and AMSI](packages/core/src/clients/file-check.ts) | partial | AMSI requires native Windows host acceptance; no clean verdict on unavailable leg |
| DET-12 | [Package and plugin supply chain](packages/core/src/package-checker.ts) | partial | Registry/provider provenance and customer dependency corpus still need acceptance |

## MCP

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| MCP-01 | [Local server discovery](packages/core/src/mcp-discovery.ts) | wired | Local configuration discovery only; not cloud-wide shadow-agent discovery |
| MCP-02 | [Discovery completeness reporting](packages/core/src/mcp-inventory.ts) | wired | Unlisted runtime-specific locations need adapters and native host acceptance |
| MCP-03 | [Server and tool policy lists](packages/core/src/policy.ts) | wired | Host must supply normalized server/tool identity |
| MCP-04 | [Empty-argument tool enforcement](packages/claude-code/src/pre-tool-use.ts) | wired | Live host event delivery still requires acceptance |
| MCP-05 | [Tool description attestation and drift](packages/core/src/mcp-attestation.ts) | partial | Direct host paths outside the gateway and trusted publisher provisioning remain open |
| MCP-06 | [Identity graph and delegated privileges](packages/core/src/delegated-credential.ts) | partial | Real identity-provider and tool-provider integration remains external |
| MCP-07 | [MCP gateway response blocking](packages/mcp-gateway/src/gateway.mjs) | partial | Opaque data requires an actually capable guard and otherwise denies; resources/prompts/subscriptions and unrelated GET paths are outside tools scope; host egress controls and customer/native acceptance remain open |

## AI infrastructure

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| INF-01 | [Native fingerprint and CVE scanning](packages/core/src/aig-infra-scan.ts) | wired | Compiled dataset freshness and unsupported fingerprint rules constrain coverage |
| INF-02 | [Scan report to runtime policy](packages/core/src/aig-policy.ts) | wired | Opt-in, scoped origins; report file is a trusted local administrative input |
| INF-03 | [Continuous fleet discovery](packages/cli/src/commands/collect.ts) | partial | Actual customer cloud IAM/MDM licences, approved scopes, production schedules, paging and provider acceptance remain open; reported resources do not prove whole-estate coverage |

## Response

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| RSP-01 | [Pre-execution block and approval](packages/core/src/guard.ts) | wired | Host bypass, disabled plugins and unavailable hook processes need platform-specific controls |
| RSP-02 | [Quarantine and restore](packages/core/src/quarantine.ts) | wired | Opt-in; does not quarantine a host or cloud account |
| RSP-03 | [File snapshot and rollback](packages/core/src/rollback.ts) | wired | Filesystem scope and restore preconditions; native acceptance still required |
| RSP-04 | [Process containment](packages/core/src/contain.ts) | partial | No enterprise endpoint isolation or universal process authority |
| RSP-05 | [Signed response audit chain](packages/core/src/response-audit.ts) | wired | Disabled by default; independent key custody and storage/retention evidence remain external |
| RSP-06 | [Fleet kill switch and credential revoke](supabase/functions/revocations/index.ts) | partial | Actual signed Windows VM/firewall/MDM acceptance remains open; non-Windows isolation and universal cloud credential revocation are unsupported; worker is not a SYSTEM impersonation service |
| RSP-07 | [SOAR playbook orchestration](supabase/functions/response-playbooks/index.ts) | partial | External alarm source integration, real Windows permissions/effects, signed distribution, native rollback and customer incident acceptance remain open |

## Policy

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| POL-01 | [Local filesystem/network/tool controls](packages/core/src/policy.ts) | wired | Policy composition and allowlist precedence require scenario-specific acceptance |
| POL-02 | [Team YAML authoring](packages/core/src/policy-document.ts) | wired | Customer native-policy rollout and actor authorization require field acceptance |
| POL-03 | [Runtime publication and history](supabase/functions/policy-management/index.ts) | wired | Revision review, targeted staging, republish/rollback and transactional publication audit are implemented; native field acceptance remains |
| POL-04 | [Native policy retrieval and cache](supabase/functions/policy/index.ts) | wired | Required policy uses a fixed offline grace and then denies; authorization failure or invalid policy cannot downgrade to local rules. Unenrolled devices retain local detection |
| POL-05 | [Fleet adoption and rollout controls](supabase/functions/policy-ack/index.ts) | wired | Receipts report loaded configuration, not host attestation; legacy unbound keys need reenrollment. Native enforcement acceptance remains |

## Endpoint

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| CLI-01 | [Setup and measured diagnostics](packages/cli/src/commands/setup.ts) | wired | Registration is not proof of host execution; setup alone does not install every connector |
| CLI-02 | [Typed and redacted configuration](packages/cli/src/commands/config.ts) | wired | Real macOS/Linux vault round trips and managed-host rotation/recovery acceptance remain open; file-ACL fallback requires explicit selection |
| CLI-03 | [Claude local installer](scripts/endpoint-install.mjs) | wired | Host restart/acceptance and authenticated signed distribution still required |
| CLI-04 | [Enterprise fleet rollout](deploy/fleet/windows/README.md) | partial | Actual Intune/SCCM/Jamf execution and publisher signing acceptance remain external |

## Connectors

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| CON-01 | [Claude Code](packages/claude-code/src/pre-tool-use.ts) | wired | Supported host version and disabled-hook behavior require native acceptance |
| CON-02 | [Cursor and VS Code](packages/extension/src/aidr-hook.ts) | wired | Editor commands outside hook visibility and native outage behavior remain limits |
| CON-03 | [OpenClaw](packages/openclaw/src/tool-handler.ts) | wired | Native version/event coverage acceptance required |
| CON-04 | [OpenCode](packages/opencode/src/tool-handler.ts) | wired | Native plugin loading and host cancellation acceptance required |
| CON-05 | [Codex](packages/codex/src/enforcement.ts) | partial | Host can fail open when hook execution is unavailable; not tamper-resistant isolation |
| CON-06 | [SDK client and generic middleware](packages/sdk/src/client.ts) | wired | Application must wrap every consequential tool path; host integration still needs an acceptance matrix |

## Management

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| TEN-01 | [Tenant isolation and RBAC](supabase/migrations/20260805000000_hybrid_tenancy.sql) | wired | Independent penetration test and full endpoint negative matrix remain required |
| TEN-02 | [Team creation and member lifecycle](supabase/migrations/20260805000001_team_creation_rpc.sql) | wired | Field identity-provider lifecycle acceptance remains required |
| TEN-03 | [Invitation issue and acceptance](supabase/functions/team-invite/index.ts) | wired | No SMTP invitation delivery; operator explicitly shares link |
| TEN-04 | [SSO and directory group sync](supabase/functions/scim/index.ts) | partial | Real Entra/Okta provisioning acceptance and the separately audited SAML enforcement/rollback operation remain open |
| TEN-05 | [Device pairing and enrollment](supabase/functions/device-poll/index.ts) | partial | Customer TLS proxy routing and browser-to-host pairing acceptance remain pending; direct unsigned device-start is rejected |
| TEN-06 | [API keys and revocation](supabase/functions/api-keys/index.ts) | wired | Per-tool short-lived delegation is tracked separately in MCP-06; live provider acceptance and endpoint secret-vault integration remain open |
| TEN-07 | [First customer provisioning and login](scripts/deployment-bootstrap.mjs) | wired | SMTP/IdP delivery and full service-role Edge MFA barriers require customer integration |

## Operations

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| OBS-01 | [Telemetry ingest and dashboard](supabase/functions/ingest/index.ts) | wired | Load, retention, delivery SLO, customer packet capture and multi-region tests remain external |
| OBS-02 | [Incident correlation and investigation](packages/core/src/incidents/correlate.ts) | wired | No full cross-agent causal graph or independently anchored forensic chain |
| OBS-03 | [Audit export](supabase/functions/audit-export/index.ts) | wired | 500-row keyset pages, user/tenant/format-bound signed cursor, bounded snapshot, browser 100000-row/64MB limit, 24-hour temporary object expiry and tested cleanup runner; operator must activate scheduling |
| OBS-04 | [SIEM delivery and native telemetry](packages/core/src/siem-delivery.ts) | partial | Customer SIEM configuration, scheduled worker, native source coverage and delivery receipt remain open |
| OBS-05 | [Tamper and offline integrity](packages/core/src/integrity/verify.ts) | wired | External signer custody, distribution and adversarial host tests remain required |
| OBS-06 | [Retention and deletion](supabase/migrations/20260912140000_tenant_offboarding_retention.sql) | partial | External backups and customer retention/offboarding acceptance remain outside live-data receipts |

## Commercial

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| BIL-01 | [Invoice-based sales model](packages/dashboard/src/ui/pages/BillingPage.tsx) | partial | Approved quote, provider receipt, reconciliation and audited paid-to-entitlement lifecycle remain open |
| BIL-02 | [Stripe checkout and event processing](supabase/functions/billing-checkout/index.ts) | partial | Live keys/prices/webhook registration, refund/cancel/reconcile and tax acceptance remain open |
| BIL-03 | [Subscription self-service portal](packages/dashboard/src/billing/billing-portal.ts) | partial | Live provider keys, approved price/SKU catalogue, finance reconciliation and accounting approval remain external |

## Deployment

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| DEP-01 | [Self-hosted preparation](scripts/deployment-prepare.mjs) | wired | Single-host Docker baseline; production TLS, SMTP, backup, sizing and HA acceptance required |
| DEP-02 | [Cloud preparation](scripts/deployment-prepare.mjs) | partial | Live project provisioning, per-region deployment, OAuth/SMTP and secrets installation remain external |
| DEP-03 | [Atomic migration runner](scripts/deployment-migrate.mjs) | wired | Restore and production upgrade drill required before customer changes |
| DEP-04 | [Installation smoke evidence](scripts/deployment-smoke.mjs) | wired | Development fixture evidence is not production or customer acceptance |
| DEP-05 | [Authenticated signed release delivery](scripts/release-sign.mjs) | partial | Approved publisher key custody and private registry publication remain external |
| DEP-06 | [Backup, restore and disaster recovery](scripts/deployment-backup.mjs) | partial | Real offsite provider, independent-host recovery and agreed RPO/RTO evidence remain open |
| DEP-07 | [Availability and scale](deploy/dashboard/monitoring.mjs) | partial | Authenticated workload, HA, capacity, noisy-neighbor and monthly SLI remain unproved |
| DEP-08 | [Portable installation candidate and doctor](scripts/customer-kit.mjs) | wired | Node 24/Docker/tar required; container images need network or a separate air-gap image delivery; publisher signatures remain external |

## Assurance

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| EVAL-01 | [Independent attack and benign benchmarks](scripts/verify-enforcement.mjs) | partial | Blind holdout corpus, customer benign tasks, latency and evasion evaluation remain open |
| EVAL-02 | [Legal, privacy, residency and support](docs/production-readiness/commercial-go-evidence-registry.json) | external | Named external approvals and candidate-bound proof cannot be generated from source code |
| EVAL-03 | [Customer proof of value](docs/production-readiness/commercial-go-evidence-registry.json) | external | Customer-run host matrix, observations and signed acceptance outstanding |

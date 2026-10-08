# AIDR alt özellik envanteri

Otomatik üretim tarihi: **2026-10-08**. 109 alt özellik ve teslimat gereksinimi eşlendi: 66 çalışan kod akışına bağlı, 41 kısmi, 0 eksik, 2 dış kanıta bağlı. Bu sayılar üretim kabulü veya tespit başarım oranı değildir. Satış/GA kararı **NO-GO** olarak korunur.

Makine kaydı: [FEATURE_INVENTORY.json](FEATURE_INVENTORY.json). Kaynaklar, tüketen bileşenler ve her satırın kalan işi bu dosyada bulunur. Önceki PRODUCT_SCOPE_AND_FEATURES.md dosyasındaki modül erişilebilirlik sayıları tarihsel bir ara denetime aittir.

## Durum tanımları

- **wired:** Çağrılabilen kod akışı var; kapsam ve test sınırı geçerlidir.
- **partial:** Uygulama var, ancak teslimat veya kapsamın bir bölümü eksik.
- **missing:** Uçtan uca özellik bulunmuyor; mevcut temel modül tamamlanmış özellik sayılmaz.
- **external:** Müşteri/operasyon/hukuk gibi dış tarafların kanıtı gerekiyor.

## Detection

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| DET-01 | [Tool artifact extraction](packages/core/src/extractors.ts) | wired | Unrecognized or host-hidden actions remain outside visibility; an oversized benign tool input is now denied rather than allowed, so the limits still need calibration against customer workloads |
| DET-02 | [Threat rules and confidence merge](packages/core/src/engine.ts) | wired | Independent false-positive and evasion measurements remain required |
| DET-03 | [Obfuscation and suspicious shell patterns](threats/obfuscation.yaml) | wired | Stateful multi-step command-chain analysis is not implemented |
| DET-04 | [Credential access and exfiltration](threats/credentials.yaml) | wired | Customer secret types and benign workflow corpus need calibration |
| DET-05 | [Cross-platform rules and mining](threats/mining.yaml) | wired | Native host matrix and mining workload acceptance remain external |
| DET-06 | [Prompt injection inspection](packages/core/src/output-scanner.ts) | partial | The real-host records quarantine one secret-bearing Bash/exec result with a scripted model; prompt-injection payloads, MCP and non-text results, Cursor/VS Code and Codex (no output interception) are not host-accepted, and OpenClaw's pre-model quarantine covers only the explicitly enabled plugin on the embedded runner (not the Codex harness); provider streams and native host bypass need acceptance; the precision filter trades recall on unlabelled formats and needs customer benign/attack corpus calibration |
| DET-07 | [Structured DLP and PII](packages/core/src/dlp/scanner.ts) | partial | Real labels and TR/EN NER efficacy are unaccepted; later host callbacks cannot guarantee same-turn output blocking; unsupported opaque formats fail closed |
| DET-08 | [Behavioral and novelty analysis](packages/core/src/behavioral-orchestrator.ts) | partial | Exit zero is not business success or process-tree isolation; real corpus efficacy, customer role custody and native OS acceptance remain required; OS owner can roll back the whole vault and journal |
| DET-09 | [ML classification and similarity](packages/core/src/behavioral-orchestrator.ts) | partial | No independently validated production model efficacy or broad runtime adoption |
| DET-10 | [URL reputation](packages/core/src/clients/url-check.ts) | partial | Provider feed, operational freshness and customer latency proof still required |
| DET-11 | [File reputation and AMSI](packages/core/src/clients/file-check.ts) | partial | AMSI requires native Windows host acceptance; no clean verdict on unavailable leg |
| DET-12 | [Package and plugin supply chain](packages/core/src/package-checker.ts) | partial | Registry/provider provenance and customer dependency corpus still need acceptance |
| DET-13 | [TR/EN privacy detectors in core DLP](packages/core/src/dlp/privacy-detectors.ts) | wired | Address/person detectors are heuristic and opt-in; Turkish/English customer corpus calibration and false-positive acceptance remain open |
| DET-14 | [Prompt protection and DLP input redaction](packages/core/src/prompt-protection.ts) | partial | The four records cover linux/x64, a development build and a scripted mock model only (no Windows/macOS/arm64, signed artefact or real model); the Cursor and VS Code prompt hooks have no real-host record and are not sold as enforced; a Codex prompt hook that is untrusted, crashed or timed out, and a Claude Code or VS Code hook killed before it answers, let the prompt through (host behaviour); OpenClaw's gate runs in the embedded and CLI runners only; Codex, Cursor, VS Code and OpenClaw keep redact as deny; with PII in the default warn mode a prompt that could not be fully inspected is still sent with a notice; the rewrite contract is verified locally against one Claude Code version and still needs native host-version acceptance |
| DET-15 | [Session toxic-flow and behavioral chain detection](packages/core/src/toxic-flow.ts) | wired | Classification is heuristic and one level deep (bash -c, eval, argv, common prefixes); a custom binary that uploads data is not recognised as external communication, taint does not cross agent sessions or follow a moved/renamed download, and false-positive rates on real agent sessions are unmeasured |
| DET-16 | [Data and context poisoning protection](threats/context-poisoning.yaml) | partial | Pattern-based: a paraphrased instruction without a covered signal is caught only by the path-based review; shell writes built at run time are not attributed; tool descriptions are visible only through the MCP gateway or signed manifests; Codex has no read-time layer and enforces ask as deny; PyPI adoption uses release count because it has no download API |
| DET-17 | [Canary credentials (honeytokens)](threats/canary.yaml) | wired | A split, reversed or encrypted value is not recognised (base64 only from the start of the run); directory-wide reads that do not name a decoy are caught only in the tool output; relative paths match by trailing segments; Browser Guard treats decoys as ordinary secrets |
| DET-18 | [Agent-safety guardrails for autonomous agents](threats/agent-safety.yaml) | wired | Shell rules see the command line, not what a script it runs does; diff-aware checks read the previous file from disk (regular files up to 1 MiB); a force-push without a branch name cannot be tied to a protected branch; repeated-failure detection depends on the host reporting failures; efficacy on real agent sessions is unmeasured |
| DET-19 | [AI model supply-chain and secure-code guardrails](threats/ai-supply-chain.yaml) | wired | Pattern rules over the written text: no cross-file data flow or renamed imports, model files themselves are not inspected, and the secure-code findings are advisory warnings, not a static-analysis or secure-code certification |
| DET-20 | [Prompt jailbreak and content-safety policy](packages/core/src/prompt-safety.ts) | wired | Phrase and pattern based, not a moderation model; the default is warn rather than block, a connector build that predates the prompt_safety field rejects a provisioned payload carrying it (and fails closed), so connectors must be upgraded first, and false-positive/evasion rates on customer prompts are unmeasured |

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
| INF-04 | [AI security posture findings](threats/skill-scan.yaml) | wired | A deterministic pattern port of the AIG taxonomy, not AIG's model-driven scanner; coverage is limited to what an enrolled collector uploads, and detection efficacy on real customer skills/plugins is unmeasured |
| INF-05 | [AI Bill of Materials (CycloneDX 1.6)](packages/core/src/aibom/cyclonedx.ts) | wired | Project root only (no nested workspaces or transitive lockfile-only packages), npm and PyPI only, MCP risk categories are name-based indicators, model files are not hashed, and a component outside the CVE index is marked not_in_cve_index rather than clean |
| INF-06 | [Agent environment and autonomy posture](packages/core/src/agent-environment-posture.ts) | partial | A configuration snapshot, not proof of how a session was launched (a command-line flag can override config); Cursor/VS Code auto-run, OpenClaw sandbox and Gemini CLI/Aider autonomy settings are not read, and cloud credential privilege is not assessed |

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
| RSP-08 | [Out-of-band operator approvals and operator CLI](packages/core/src/operator-approvals.ts) | wired | Approval is local to one host and OS user: there is no central/multi-approver workflow. The agent runs as the same OS user, so separation rests on the OS vault's own access policy and on pattern-based self-defense rules, not on process isolation; a shell construct the normaliser does not model, or a vault that releases secrets to any process of the user without a prompt, can still expose the channel. Real macOS/Windows/Linux vault behaviour, operator usability and native host acceptance remain open |
| RSP-09 | [Managed-mode dashboard approvals](packages/core/src/dashboard-approvals.ts) | wired | Requires managed enrollment and a published policy carrying approval_public_keys; not exercised against a deployed control plane or real approver workflow; polling latency and multi-approver (four-eyes) approval for tool calls are not provided |

## Policy

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| POL-01 | [Local filesystem/network/tool controls](packages/core/src/policy.ts) | wired | Policy composition and allowlist precedence require scenario-specific acceptance |
| POL-02 | [Team YAML authoring](packages/core/src/policy-document.ts) | wired | Customer native-policy rollout and actor authorization require field acceptance |
| POL-03 | [Runtime publication and history](supabase/functions/policy-management/index.ts) | wired | Revision review, targeted staging, republish/rollback and transactional publication audit are implemented; native field acceptance remains |
| POL-04 | [Native policy retrieval and cache](supabase/functions/policy/index.ts) | wired | Required policy uses a fixed offline grace and then denies; authorization failure or invalid policy cannot downgrade to local rules. Unenrolled devices retain local detection |
| POL-05 | [Fleet adoption and rollout controls](supabase/functions/policy-ack/index.ts) | wired | Receipts report loaded configuration, not host attestation; legacy unbound keys need reenrollment. Native enforcement acceptance remains |
| POL-06 | [Agent permission profiles](packages/core/src/agent-profile.ts) | wired | Command prefixes are coarse (a program an allowed prefix starts can do anything it does); shell words are checked lexically against files.deny; repository selection sees the host-reported working directory and absolute paths a call names, not paths reached indirectly; a staged profile is not enforced until an operator signs it into the bundle (the control plane holds no key connectors trust for detector policy and delivers no bundle) |

## Endpoint

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| CLI-01 | [Setup and measured diagnostics](packages/cli/src/commands/setup.ts) | wired | Registration is not proof of host execution; setup alone does not install every connector |
| CLI-02 | [Typed and redacted configuration](packages/cli/src/commands/config.ts) | wired | Real macOS/Linux vault round trips and managed-host rotation/recovery acceptance remain open; file-ACL fallback requires explicit selection |
| CLI-03 | [Claude local installer](scripts/endpoint-install.mjs) | wired | Host restart/acceptance and authenticated signed distribution still required |
| CLI-04 | [Enterprise fleet rollout](deploy/fleet/windows/README.md) | partial | Actual Intune/SCCM/Jamf execution and publisher signing acceptance remain external |
| CLI-05 | [Local TR/EN privacy scan](packages/cli/src/commands/privacy.ts) | wired | A local operator/CI utility, not an enforcement point: it inspects only the input it is given; address and person detectors are heuristic, and false-positive rates on customer Turkish/English data are unmeasured |
| CLI-06 | [Defensive detection self-test (aidr simulate)](packages/cli/src/commands/simulate.ts) | wired | Measures that the shipped rules still match their own fixtures, not efficacy against novel or customer-specific attacks; it is not an independent benchmark (EVAL-01) |

## Connectors

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| CON-01 | [Claude Code](packages/claude-code/src/pre-tool-use.ts) | wired | The real-host record is recorded on linux/x64 only, with a development build and a scripted mock model (no Windows/macOS/arm64, signed artefact or real model); a disabled plugin enforces nothing and a PreToolUse hook killed before it answers was observed to fail open; other host versions require native acceptance |
| CON-02 | [Cursor and VS Code](packages/extension/src/aidr-hook.ts) | wired | Editor commands outside hook visibility and native outage behavior remain limits |
| CON-03 | [OpenClaw](packages/openclaw/src/tool-handler.ts) | wired | The real-host record is recorded on linux/x64 only, with a development build and a scripted mock model (no Windows/macOS/arm64, signed artefact or real model); the gateway process and channel delivery are not exercised; the sold tool-output quarantine needs plugins.entries.aidr-openclaw.enabled: true and does not cover the Codex harness, the sold prompt gate runs in the embedded and CLI runners only and a non-bundled plugin needs hooks.allowConversationAccess: true; pre-delivery-response is not exercised; a removed plugin enforces nothing; other versions and event coverage require native acceptance |
| CON-04 | [OpenCode](packages/opencode/src/tool-handler.ts) | wired | The real-host record is recorded on linux/x64 only, with a development build and a scripted mock model (no Windows/macOS/arm64, signed artefact or real model); a removed plugin enforces nothing; prompt protection inspects the user's own text parts only (not synthetic parts such as attached file contents); other versions, interactive TUI presentation and host cancellation acceptance required |
| CON-05 | [Codex](packages/codex/src/enforcement.ts) | partial | Host can fail open when hook execution is unavailable (an untrusted, crashed or timed-out hook); the UserPromptSubmit handler must be registered and trusted separately and codex exec shows no reason text for a blocked prompt; no tool output is inspected; not tamper-resistant isolation; the real-host record is recorded on linux/x64 only, with a development build and a scripted mock model (no Windows/macOS/arm64, signed artefact or real model) |
| CON-06 | [SDK client and generic middleware](packages/sdk/src/client.ts) | wired | Application must wrap every consequential tool path; host integration still needs an acceptance matrix |
| CON-07 | [Cross-connector parity and fail-closed initialisation](packages/core/src/tool-normalization.ts) | wired | Parity is proven against built bundles in-process and over stdin, not against installed native hosts; documented host-verb differences (ask becomes block in Codex/OpenCode/OpenClaw, deny in Cursor) and redact differences (rewrite in Claude Code and OpenCode, block elsewhere) remain |

## Management

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| TEN-01 | [Tenant isolation and RBAC](supabase/migrations/20260805000000_hybrid_tenancy.sql) | wired | Independent penetration test and full endpoint negative matrix remain required |
| TEN-02 | [Team creation and member lifecycle](supabase/migrations/20260805000001_team_creation_rpc.sql) | wired | Field identity-provider lifecycle acceptance remains required |
| TEN-03 | [Invitation issue and acceptance](supabase/functions/team-invite/index.ts) | wired | Live mail-provider account, sender-domain SPF/DKIM/DMARC, deliverability and customer mail-flow acceptance remain open; with AIDR_MAIL_PROVIDER=none the operator still shares the link manually |
| TEN-04 | [SSO and directory group sync](supabase/functions/scim/index.ts) | partial | Real Entra/Okta provisioning acceptance and the separately audited SAML enforcement/rollback operation remain open |
| TEN-05 | [Device pairing and enrollment](supabase/functions/device-poll/index.ts) | partial | Customer TLS proxy routing and browser-to-host pairing acceptance remain pending; direct unsigned device-start is rejected |
| TEN-06 | [API keys and revocation](supabase/functions/api-keys/index.ts) | wired | Per-tool short-lived delegation is tracked separately in MCP-06; live provider acceptance and endpoint secret-vault integration remain open |
| TEN-07 | [First customer provisioning and login](scripts/deployment-bootstrap.mjs) | wired | SMTP/IdP delivery and full service-role Edge MFA barriers require customer integration |
| TEN-08 | [Platform operator administration](supabase/functions/operator-admin/index.ts) | wired | Named operator provisioning, operator credential custody and a live deployment run remain open; the surface is not independently penetration-tested (SEC-EXT-001) |
| TEN-09 | [Workspace settings and closure request](supabase/functions/tenant-settings/index.ts) | wired | Closure only requests offboarding; completion still depends on the operator-run offboarding and the external backup/retention acceptance tracked in OBS-06 |

## Operations

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| OBS-01 | [Telemetry ingest and dashboard](supabase/functions/ingest/index.ts) | wired | Load, retention, delivery SLO, customer packet capture and multi-region tests remain external |
| OBS-02 | [Incident correlation and investigation](packages/core/src/incidents/correlate.ts) | wired | No full cross-agent causal graph or independently anchored forensic chain |
| OBS-03 | [Audit export](supabase/functions/audit-export/index.ts) | wired | 500-row keyset pages, user/tenant/format-bound signed cursor, bounded snapshot, browser 100000-row/64MB limit, 24-hour temporary object expiry and tested cleanup runner; operator must activate scheduling |
| OBS-04 | [SIEM delivery and native telemetry](packages/core/src/siem-delivery.ts) | partial | Customer SIEM configuration, scheduled worker, native source coverage and delivery receipt remain open |
| OBS-05 | [Tamper and offline integrity](packages/core/src/integrity/verify.ts) | wired | External signer custody, distribution and adversarial host tests remain required |
| OBS-06 | [Retention and deletion](supabase/migrations/20260912140000_tenant_offboarding_retention.sql) | partial | External backups and customer retention/offboarding acceptance remain outside live-data receipts |
| OBS-07 | [Signed compliance evidence report](supabase/functions/compliance-report/index.ts) | wired | Supports KVKK/GDPR accountability but is not a certification or audit opinion; counts cover only telemetry that reached the control plane within retention; data-flow values marked unknown must be completed per deployment; only the JSON is signed |
| OBS-08 | [Real-time alert integrations](supabase/functions/notification-channels/index.ts) | wired | Delivery, including agent-offline detection, depends on the deployment running the dispatcher schedule and a mail transport; no live Slack/Teams/customer receiver has been exercised; receivers must deduplicate retries |

## Governance

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| GOV-01 | [Detection framework mapping (OWASP LLM 2025, OWASP Agentic 2026, MITRE ATLAS)](threats/mappings/frameworks.yaml) | wired | A mapping of product rules to framework categories, not an assessment by the framework owners; coverage of a category says a rule exists, not how well it detects |
| GOV-02 | [AI governance framework mapping, scorecard and scheduled summary](governance/frameworks/capabilities.yaml) | wired | Computed only from telemetry that reached the control plane within retention; organisational measures and other tools are invisible to it; the approver-review prompt is a timing heuristic; summaries need the deployment mail transport and maintenance timer |
| GOV-03 | [AI asset register, intake, exceptions and four-eyes policy change control](supabase/functions/ai-governance/index.ts) | wired | Only MCP servers and Browser Guard sites are enforced; other asset types are records only; enforcement needs a published runtime policy and connectors that understand the governance block (older connectors ignore it); not exercised with a real customer approval workflow |

## Commercial

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| BIL-01 | [Invoice-based sales model](packages/dashboard/src/ui/pages/BillingPage.tsx) | partial | Approved quote, provider receipt, reconciliation and audited paid-to-entitlement lifecycle remain open |
| BIL-02 | [Stripe checkout and event processing](supabase/functions/billing-checkout/index.ts) | partial | Live keys/prices/webhook registration, refund/cancel/reconcile and tax acceptance remain open |
| BIL-03 | [Subscription self-service portal](packages/dashboard/src/billing/billing-portal.ts) | partial | Live provider keys, approved price/SKU catalogue, finance reconciliation and accounting approval remain external |
| BIL-04 | [Plan catalog, pricing and Stripe plan admission](supabase/migrations/20260925000010_plan_catalog.sql) | partial | List prices are not an approved SKU/price manifest (COM-001); self-service remains env-gated and off by default; live Stripe keys/prices, tax, reconciliation and finance approval remain external |

## Deployment

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| DEP-01 | [Self-hosted preparation](scripts/deployment-prepare.mjs) | wired | Single-host Docker baseline; production TLS, SMTP, backup, sizing and HA acceptance required |
| DEP-02 | [Cloud preparation](scripts/deployment-prepare.mjs) | partial | Live project provisioning, per-region deployment, OAuth/SMTP and secrets installation remain external |
| DEP-03 | [Atomic migration runner and signal-safe upgrade](scripts/deployment-migrate.mjs) | wired | Restore and a production upgrade drill from a real previous customer version are required before customer changes |
| DEP-04 | [Installation smoke evidence](scripts/deployment-smoke.mjs) | wired | Development fixture evidence is not production or customer acceptance |
| DEP-05 | [Authenticated signed release delivery](scripts/release-sign.mjs) | partial | Approved publisher key custody and private registry publication remain external |
| DEP-06 | [Backup, restore and disaster recovery](scripts/deployment-backup.mjs) | partial | Real offsite provider, independent-host recovery and agreed RPO/RTO evidence remain open |
| DEP-07 | [Availability and scale](deploy/dashboard/monitoring.mjs) | partial | Authenticated workload, HA, capacity, noisy-neighbor and monthly SLI remain unproved |
| DEP-08 | [Portable installation candidate and doctor](scripts/customer-kit.mjs) | wired | Node 24/Docker/tar required; container images need network or a separate air-gap image delivery; publisher signatures remain external |
| DEP-09 | [On-prem bundle, resource profiles, posture scanner sidecar and egress proxy](deploy/onprem/README.md) | partial | The Compose bundle is single-host (the Kubernetes chart is DEP-12); customer-host install, air-gap media transfer drill, sizing validation and customer TLS acceptance remain open |
| DEP-10 | [Vendor-signed offline licence and offline pack import](scripts/license-issue.mjs) | partial | The shipped public-key registry is intentionally empty and fails closed until a vendor signing key is generated and custodied; vendor key custody, licence issuance operations and a customer air-gap update drill remain external |
| DEP-11 | [Download center and release manifest](packages/dashboard/src/ui/pages/DownloadsPage.tsx) | partial | No published release host or signed manifest exists yet; signatures depend on publisher key custody (DEP-05) and private registry delivery (COM-012) |
| DEP-12 | [Kubernetes Helm chart for the self-hosted control plane](deploy/helm/aidr/Chart.yaml) | partial | Not exercised on a live cluster. CI does not install kubeconform, so schema validation there is skipped and is recorded only from development runs; without Helm the rendered checks skip (10 of 20 checks skipped in this review's local run). The chart does not deploy the device-start ingress signer or the maintenance timers, HA/failover is unproven (DEP-07) and customer cluster acceptance remains open |

## Assurance

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| EVAL-01 | [Independent attack and benign benchmarks](scripts/verify-enforcement.mjs) | partial | Blind holdout corpus, customer benign tasks, latency and evasion evaluation remain open |
| EVAL-02 | [Legal, privacy, residency and support](docs/production-readiness/commercial-go-evidence-registry.json) | external | Named external approvals and candidate-bound proof cannot be generated from source code |
| EVAL-03 | [Customer proof of value](docs/production-readiness/commercial-go-evidence-registry.json) | external | Customer-run host matrix, observations and signed acceptance outstanding |

## Browser privacy

| Kimlik | Alt özellik | Durum | Kalan sınır / kabul işi |
|---|---|---|---|
| PRV-01 | [Browser Guard prompt masking on AI chat sites](packages/browser-guard/src/content/guard.ts) | partial | Fixture pages are not the live sites: real-site DOM drift, store publication/review and customer browser acceptance remain open; text typed outside a recognised editor or sent by site-internal paths is not visible |
| PRV-02 | [Paste and file-upload sanitisation](packages/browser-guard/src/content/file-guard.ts) | wired | Images are inspected only through the optional native host OCR and other binary formats not at all (blocked only in block mode, otherwise allowed with a marker); Office, OpenDocument, legacy Office, PDF and image uploads are handled by PRV-08; large-file and real-site upload acceptance remain open |
| PRV-03 | [Exact-data match on customer datasets](packages/browser-guard/src/engine/exact-data.ts) | wired | Customer dataset onboarding, HMAC key custody/rotation and false-positive calibration remain open |
| PRV-04 | [Managed browser policy and fleet deployment](packages/browser-guard/src/background/policy.ts) | partial | Real GPO/Intune/Jamf rollout, store or self-hosted signed distribution and a customer fleet run remain external |
| PRV-05 | [Counts-only privacy telemetry and Privacy Guard dashboard](packages/browser-guard/src/background/telemetry.ts) | wired | No live browser fleet has reported into a deployed control plane; a policy-distributed ingest key is visible to the local user (for example at chrome://policy) and can send forged counts up to its rate and install limits; the data-flow/DPA approval for this telemetry (COM-003) remains open |
| PRV-06 | [AIDR Privacy engine and optional native NER host](packages/privacy/src/rules.ts) | partial | Native host installation, NER/OCR accuracy and platform acceptance are unmeasured; privacy suites run separately via test:privacy with named optional-dependency skips (real Tesseract OCR is one) |
| PRV-07 | [Shadow AI discovery/control and custom internal AI sites](packages/browser-guard/src/background/shadow-ai.ts) | partial | Counting and the blocked.html explanation page act only on origins the user granted (the block itself uses declarativeNetRequest block rules and needs no grant; without one the user sees the browser's own blocked page); services on a path of a general-purpose host are not catalogued; a worker restart can count a visit twice; other browsers, desktop apps and API clients are not covered |
| PRV-08 | [Office/OpenDocument document masking, PDF scanning and image OCR gating](packages/browser-guard/src/engine/office/ooxml.ts) | partial | Without the native host and its OCR no image is inspected, and OCR accuracy is unmeasured; images are blocked, never masked; scanned PDFs are not OCR'd; PDFs are never rewritten; encrypted PDFs and some CJK font encodings are not extracted; sheet and table names, defined names, named ranges and chart/pivot-cache values are not rewritten; legacy binary Office content is not parsed |
| PRV-09 | [AI acceptable-use notice](packages/browser-guard/src/content/acceptable-use.ts) | wired | Informs and never blocks sending; coding-agent connectors do not show it; an acknowledgement made while telemetry is off is never reported |

# Portable private profile: operator handoff

This package prepares the implemented single-tenant Linux text route and optional signed MCP route. It does not start a service, install firewall rules, generate institutional identities or approve a model. Current public NER candidates have failed qualification. Keep this installation disabled until the required real inputs and acceptance below are complete.

## Install layout and preparation

The supported prefix is `/opt/aidr-private`, containing installed packages under `node_modules`. Install the verified private `@singularity/aidr-privacy` artifact, matching commercial `@singularityrd/aidr-core` and its complete approved runtime dependencies. The optional `@singularityrd/aidr-mcp-gateway@0.6.0` must be the signed delivered artifact. The SDK host sample also requires its matching SDK package. Offline installation needs the complete approved dependency cache or a preinstalled, verified dependency tree; the three product tarballs alone cannot satisfy core's external npm dependencies. Node, Python/wheels, OpenSSL, nftables, Secret Service/DBus/secret-tool and libseccomp are separate approved host/runtime inputs. No registry credentials or signing private keys are bundled.

Run the installed reference preparation script with an absolute **new** destination:

```sh
node /opt/aidr-private/node_modules/@singularity/aidr-privacy/deployment/prepare-private.mjs /var/tmp/aidr-private-operator
```

It creates only configuration references and the operator inventory, with restrictive permissions. Existing output directories are refused. Every `REPLACE_` value needs a reviewed real value. Keep executable `.mjs` configuration in the installed package tree so its package imports resolve. Copy only completed reference JSON to administrator-owned `/etc/aidr-privacy` and `/etc/aidr-mcp`; never copy modules there without a separately verified Node dependency installation.

## Fill the existing configuration

| File | Real inputs and owner |
|---|---|
| `service.json` | Tenant/policy authority: tenant, signed policy and Ed25519 public keys, provider ID/model and exact supported origin, role groups. Identity/MDM authority: real OIDC issuer/client/callback/CA, broker issuer/audience/CA/client certificate. Vault owner: separate encryption/audit/labels 32-byte Base64 keys, OIDC/provider secrets, broker/server PEM keys. Model authority: approved physical Python, model manifest and independently distributed digest. Parser authority: physical Linux parser and approved packaged worker digest. |
| `client.json` | Host owner: exact gateway origin, gateway CA, enrolled-device certificate, its private-key vault reference and session-bundle reference. Use separate actual service accounts/certificates/vault entries for ordinary application, administrator source synchronization and optional MCP service. |
| `source.json` | Data owner: authorized text directory, source ID, next monotonic generation, exact reader group IDs and one actual classification applying to every file. Separate roots/snapshots when ACLs or labels differ. This does not discover filesystem or cloud permissions. |
| `gateway.json` | Optional MCP owner: same tenant, current signed tool manifest/trusted signers, bounded tool allowlist, actual client-token SHA256, isolated credential vault references, exact HTTPS upstream and approved DNS/IP pins. |
| `*.nft.example` / service units | Host/network owner: dedicated numeric UIDs, exact resolver/identity/provider/upstream IPv4 sets, installed package/runtime paths and per-service vault DBus environment. Use one firewall profile for these UIDs. |

The reference service enables labels and the supported document parser. Remove `dataPolicy` and its administrator mapping together if source ingestion is deliberately disabled; stored source reads will then be denied. Remove `documents` if container parsing is disabled; document requests are denied. Unsupported scanned PDF, selective ASR/video and original binary egress remain blocked. No audio mode is enabled by this pack.

The default units/firewall assume loopback `8443` and optional MCP `7789`. Changing listener ports/addresses requires a coordinated approved firewall/client configuration; remote clients need their own real ingress/network boundary. Prepare local private state directories owned by each service account, umask0077, read-only package/model/configuration mounts and approved recovery before reusing an older RC database. Provision the accessible unlocked OS vault and each UID's actual DBus environment; do not use plaintext/file-acl fallback.

## Activate only on the accepted host

1. Verify the signed delivery and model/runtime/configuration digests using independently supplied organization trust. Current unsigned preparation and synthetic fixture signers are insufficient.
2. Follow `docs/MODEL_PROVIDER.md` and the existing pinned installer/qualification tools. Obtain an independent TR/EN domain gold corpus and institution model approval. Retain original thresholds; public synthetic comparison cannot supply independent acceptance. The generated candidate manifest is deliberately `approved:false` and cannot start this service.
3. Have the authoritative broker implement the exact bootstrap/login/refresh/revoke contract in `docs/CONFIGURED_BROKER.md`. Verify actual device compliance and enterprise provider-account evidence. Register the real OIDC callback; maintain issuer keys/CA/certificate rotation and short-lived grant refresh.
4. Validate the filled nftables rules with `nft --check`; install the approved required firewall unit before text/MCP units. Confirm effective rules, direct provider/upstream connection denial under the actual application UID and positive checked gateway traffic. A template or startup credential probe does not establish OS egress isolation.
5. Start `aidr-text.service`; it checks real model readiness, signed policy, broker bootstrap, vault/TLS and optional parser before opening the listener. Authenticate each enrolled host through the existing session CLI/callback; tokens go only into its OS vault. Then start the optional MCP unit and approve the exact signed/quarantined tool binding using the existing operator flow.
6. For labeled text sources, run the following under the actual source-administrator identity after its session is ready. No content or tokens are printed:

```sh
export AIDR_PRIVACY_CLIENT_CONFIG=/etc/aidr-privacy/source-admin-client.json
export AIDR_PRIVACY_SOURCE_CONFIG=/etc/aidr-privacy/source.json
node /opt/aidr-private/node_modules/@singularity/aidr-privacy/examples/platform/source-sync.mjs
```

The source host uses the existing safe text-directory reader and submits a complete snapshot over mTLS. Unsupported files/incomplete listings deny the whole snapshot. Only `synchronized:true` reports success. A failed or interrupted request can have committed the generation; inspect durable state/audit and use a reviewed newer generation instead of automatically replaying.

7. Connect the host's final provider function to `TextGatewayClient.send` or the packaged `sdk-final-send.mjs`; remove direct provider credentials/routes from that host. Exercise clean input/output, PII input/output masking, restricted source denial, unauthorized ACL/admin denial, expired/revoked sessions, unavailable scanner, changed policy/source epoch and denied opaque MCP content. Null/unknown/review/withheld output cannot fall back to original text or automatic resend.
8. Run the complete private CI control gate and installed signed MCP regression on the delivered runtime, then actual-model load/outage/backup/recovery and customer UAT. Record actual provider connectivity/account and host firewall evidence separately from synthetic local tests.

Current implementation/control evidence is in `reports/platform/INTEGRATION-2026-10-06.md`. Real institution inputs, passing independent model quality and signed/customer acceptance remain required; preparing these files cannot mark them GO.

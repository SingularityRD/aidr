# Cloud and Intune resource discovery

`aidr collect` supports `local`, `aws`, `azure`, `gcp` and `intune`. External
providers require `--provider-config` with an explicit AIDR tenant and resource
scope. Resource management visibility is separate from HTTP reachability and AI
product/CVE probes. Use optional `--target` arguments to probe separately approved
HTTP services; discovery does not turn resource names into network destinations.

```sh
aidr collect --tenant 123e4567-e89b-42d3-a456-426614174000 \
  --provider azure --provider-config ./azure-discovery.json --json
```

One run is suitable for an existing scheduler. `--interval 60` repeats sequentially.
Each cycle resolves the configured secret references again and obtains fresh
Microsoft/Google OAuth credentials. AWS temporary credentials require an explicit
session-token reference and must be rotated by the approved credential issuer.
No default SDK credential chain, instance metadata, browser login, arbitrary
endpoint, or local credential file is consulted.

Configuration contains secret **references**, never secret values. A reference is
`{"env":"AIDR_AZURE_SECRET"}` or
`{"vault":{"store":"windows-dpapi","id":"cloud-azure-secret"}}`. The other vault
choices are `macos-keychain` and `linux-secret-service`; `file-acl` is not accepted
for cloud discovery. Provision vault references through the existing AIDR secret
store API/native administrator tooling. Inject explicitly named environment
references through the approved scheduler or secret manager. Configuration files
are bounded to 64 KiB and reject unknown fields.

## Azure resource groups

```json
{
  "schemaVersion": 1,
  "provider": "azure",
  "tenantId": "123e4567-e89b-42d3-a456-426614174000",
  "directoryTenantId": "123e4567-e89b-42d3-a456-426614174001",
  "subscriptionIds": ["123e4567-e89b-42d3-a456-426614174002"],
  "resourceGroups": ["approved-ai-services"],
  "credentials": {
    "clientId": "123e4567-e89b-42d3-a456-426614174003",
    "clientSecret": {"env": "AIDR_AZURE_SECRET"}
  }
}
```

Give this service principal read-only access to the approved resource groups.
The [Resource Graph API](https://learn.microsoft.com/en-us/rest/api/azureresourcegraph/resourcegraph/resources/resources?view=rest-azureresourcegraph-resourcegraph-2024-04-01)
query uses explicit subscriptions and resource-group filters. Returned IDs,
subscriptions and groups are checked again. Result-count changes, missing
continuations and inconsistent truncation claims produce incomplete evidence.
Authentication uses Microsoft's tenant-specific
[client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow).

## AWS tagged resources

```json
{
  "schemaVersion": 1,
  "provider": "aws",
  "tenantId": "123e4567-e89b-42d3-a456-426614174000",
  "accountId": "123456789012",
  "regions": ["eu-west-1"],
  "resourceTypes": ["ec2:instance", "sagemaker:endpoint"],
  "credentials": {
    "accessKeyId": {"env": "AIDR_AWS_ACCESS_KEY_ID"},
    "secretAccessKey": {"env": "AIDR_AWS_SECRET_ACCESS_KEY"},
    "sessionToken": {"env": "AIDR_AWS_SESSION_TOKEN"}
  }
}
```

Use read-only `tag:GetResources` permission; the adapter verifies the account with
[STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
before each regional read. SigV4 uses fixed AWS commercial-partition endpoints.
[GetResources](https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html)
covers tagged/previously tagged resources, excluding untagged resources. This is
not whole-account coverage. Supported resources have unambiguous regional,
account-bearing ARNs with a resource-type prefix (for example EC2 instances,
SageMaker endpoints and Lambda functions). Global/accountless ARNs, bare-name
ARNs, China and GovCloud partitions fail closed. Omit `sessionToken` only for
explicitly supplied long-lived credentials.

## GCP project asset types

```json
{
  "schemaVersion": 1,
  "provider": "gcp",
  "tenantId": "123e4567-e89b-42d3-a456-426614174000",
  "projectNumbers": ["123456789012"],
  "assetTypes": ["compute.googleapis.com/Instance"],
  "credentials": {
    "serviceAccountEmail": "aidr-discovery@approved-project.iam.gserviceaccount.com",
    "privateKey": {"env": "AIDR_GCP_PRIVATE_KEY"}
  }
}
```

The secret reference contains the service account's RSA PEM private key; keys
smaller than 2048 bits are rejected. Grant
`cloudasset.assets.searchAllResources` on each explicitly approved project.
Only project numbers are accepted, so API results can be checked without project
ID/number ambiguity. The adapter uses Google's
[service-account OAuth flow](https://developers.google.com/identity/protocols/oauth2/service-account)
and the [Cloud Asset Inventory search API](https://docs.cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllResources).
It requests only name, asset type, project and location, excluding labels,
descriptions and ownership information.

## Intune device IDs

```json
{
  "schemaVersion": 1,
  "provider": "intune",
  "tenantId": "123e4567-e89b-42d3-a456-426614174000",
  "directoryTenantId": "123e4567-e89b-42d3-a456-426614174001",
  "deviceIds": ["123e4567-e89b-42d3-a456-426614174004"],
  "credentials": {
    "clientId": "123e4567-e89b-42d3-a456-426614174003",
    "clientSecret": {"env": "AIDR_INTUNE_SECRET"}
  }
}
```

The application requires `DeviceManagementManagedDevices.Read.All` admin consent
and an active Intune tenant license. Direct
[managed-device reads](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-get?view=graph-rest-1.0)
are restricted to the configured managed-device IDs (not Entra device IDs).
A missing/rejected device makes the cycle incomplete. Only device IDs are retained;
user principal names, device names and serial numbers are not requested or stored.
This adapter establishes management visibility, not installed-application, AI
endpoint or device-compliance verification.

## Central reporting, failure and bounds

The local JSON includes `providerEvidence.scopeHash`. It is SHA-256 over the
normalized provider, AIDR tenant and every scope filter; credential values and
references are excluded. Changing scope requires a new matching central grant.
For a machine collector, an owner/admin issues a credential with
`allowed_provider_scope: {"provider":"azure","scope_hash":"<64 hex characters>"}`
in the discovery credential flow. An existing HTTP-only credential cannot upload
cloud resource evidence. The existing discovery upload environment configuration
and tenant/collector/sequence receipt checks still apply. Keep provider evidence
in `provider_resources`; HTTP origins stay in `items`. The central feature also
requires migration `20261006003000` and the corresponding discovery function/UI.

To derive the grant, run one local cycle with discovery upload environment
variables unset, then take `collectorId` and `providerEvidence.scopeHash` from the
JSON result. Require `providerEvidence.complete:true`; otherwise correct the API
permission/scope failure first. In an authenticated owner/admin session that has
completed MFA (`aal2`), submit this request to `POST /functions/v1/discovery`:

```json
{
  "action": "issue_credential",
  "tenant_id": "123e4567-e89b-42d3-a456-426614174000",
  "collector_id": "<collectorId from the local result>",
  "expires_in_days": 30,
  "allowed_provider_scope": {
    "provider": "azure",
    "scope_hash": "<providerEvidence.scopeHash from the local result>"
  }
}
```

Use the tenant's anonymous API key header and the MFA operator bearer token.
The response contains the credential once: deliver it directly into the
approved secret manager and inject it as `AIDR_DISCOVERY_COLLECTOR_CREDENTIAL`.
Do not log, print, paste into a ticket, or commit the credential response. Set
`AIDR_DISCOVERY_URL` and `AIDR_DISCOVERY_ANON_KEY` for the same deployment; leave
`AIDR_DISCOVERY_ACCESS_TOKEN` unset in machine mode. Resume the same collector.
Revocation/offboarding denies subsequent uploads; rotating a legacy HTTP-only
credential clears any prior cloud grant, so request the scope grant explicitly.

Each successful API snapshot replaces the prior resources for that exact scope.
A failed cycle sets `complete:false`, retains the last positive local resources,
and uploads an empty partial provider item list. It never stamps retained items
as new observations. Scope changes do not reuse prior resource evidence.
Authentication failures, duplicate resources/tokens, invalid responses, resource
limits and timeouts exit nonzero. API bodies and credentials are not included in
error messages.

The collection allows at most 1000 resources, 100 continuation pages, 300 requests,
2 MiB per response, 8 MiB response bytes per cycle, and two minutes for management
API calls. Requests reject redirects and have a configurable per-request timeout.
429/503 and explicitly signaled AWS throttling retry at most twice with bounded
backoff and `Retry-After`; a longer requested wait fails the cycle. Uploads with
provider evidence are limited to 512 KiB. A successful empty scoped API result is
an empty management snapshot; it never proves absence of all cloud AI services.

Automated acceptance uses fixtures and real controlled loopback HTTPS, including
the consumed CLI flow. It does not prove a customer's external IAM permissions,
network route, Intune licensing or production identity configuration. Complete
those checks against the approved customer accounts before accepting the pilot.

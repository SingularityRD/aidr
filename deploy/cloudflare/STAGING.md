# Isolated cloud staging

`wrangler.jsonc` keeps the existing `aidr-pilot` default Worker and adds a named
`staging` environment. Cloudflare deploys that environment as the separate
`aidr-pilot-staging` Worker. Its only route is its own `workers.dev` hostname;
there is no custom-domain route. `aidr.singularityrd.com` is the existing landing
page and must not be changed. The selected GA application hostname is
`app.aidr.singularityrd.com`; it needs a separate approved production routing
and DNS/TLS change after staging acceptance. This file does not make that change.

Cloudflare [environments](https://developers.cloudflare.com/workers/wrangler/environments/)
create separate Workers. `vars` and `secrets` are not inherited, so staging
declares its own Azure flag and required secret names. The Worker entry point
and static asset routing are inherited from the pilot configuration. Release
version and source SHA are injected only by `staging-deploy.mjs` from a verified
signed release manifest.

## Preconditions

- Freeze a clean release-candidate checkout. Keep the signed bundle, independent
  signer policy, and anti-rollback state outside that checkout. Run the existing
  signed bundle verifier; a Git commit alone does not establish release identity.
- Provision a new staging Supabase project with no customer data in the approved
  region. Do not reuse the linked pilot or any project with unknown contents.
  Configure Data API exposure, Auth site/callback URLs, isolated test IdP, custom
  SMTP, function secrets, and the canonical `supabase/config.toml` JWT settings.
  The small `pilot-config/supabase/config.toml` is only an Auth URL example; it
  does not contain the per-function JWT configuration.
- Approve the exact `https://aidr-pilot-staging.<account>.workers.dev` hostname
  and confirm it belongs to the intended Cloudflare account. Test SMTP delivery
  and failure handling. Record the approver, Supabase project ref, candidate SHA,
  and origin in a private approval file. These are operator receipts, not
  assertions that the preflight can independently verify.
- Build the dashboard public support, status, legal, and sales links before
  signing the candidate. Stage the exact `packages/dashboard/dist` from the
  signed `aidr-dashboard-dist-VERSION.tar.gz` archive in the clean candidate
  checkout. Rebuilding with different `VITE_*` values needs a new signed
  candidate. The preflight compares the staged files with the signed manifest.

## Database and function order

Use an isolated checkout and explicitly name the new project on every command.
Review migration headers for release-specific code/schema cutover dependencies.
The database password comes from the approved vault and must never appear in
the command line, terminal transcript, or repository.

```sh
pnpm dlx supabase@2.117.0 link --project-ref <STAGING_REF>
pnpm dlx supabase@2.117.0 migration list --project-ref <STAGING_REF>
pnpm dlx supabase@2.117.0 db push --dry-run --project-ref <STAGING_REF> --skip-vault
# After reviewing the ordered plan and a recoverable staging backup:
pnpm dlx supabase@2.117.0 db push --project-ref <STAGING_REF> --skip-vault
pnpm dlx supabase@2.117.0 secrets set --env-file <PRIVATE_STAGING_ENV_FILE> --project-ref <STAGING_REF>
pnpm dlx supabase@2.117.0 functions deploy --project-ref <STAGING_REF> --use-api
pnpm dlx supabase@2.117.0 functions list --project-ref <STAGING_REF> --output-format json
```

For a fresh project, `db push` applies the timestamped files in
`supabase/migrations` order. Confirm every expected migration, RLS policy, and
all function names and `verify_jwt` settings before connecting the Worker.
Avoid `--prune`; migration rollback requires a tested forward fix or separate
restore, not a Worker code rollback. Supabase's
[environment guidance](https://supabase.com/docs/guides/deployment/managing-environments/)
supports separate staging and production projects.

## Worker preflight and staging release

Set the four staging Worker secrets interactively through Wrangler with
`--env staging`: `AIDR_PUBLIC_ORIGIN`, `AIDR_SUPABASE_ORIGIN`,
`AIDR_SUPABASE_ANON_KEY`, and `AIDR_DEVICE_START_INGRESS_SECRET`. The public
origin must be the approved staging Worker hostname; the Supabase origin must
be the new staging project. The device-start signing secret must also be bound
to that project's function. Do not place secret values in `vars` or a command
line. The wrapper never accepts a default or production environment.

```sh
pnpm dlx wrangler@4.137.0 secret put AIDR_PUBLIC_ORIGIN --env staging --config deploy/cloudflare/wrangler.jsonc
pnpm dlx wrangler@4.137.0 secret put AIDR_SUPABASE_ORIGIN --env staging --config deploy/cloudflare/wrangler.jsonc
pnpm dlx wrangler@4.137.0 secret put AIDR_SUPABASE_ANON_KEY --env staging --config deploy/cloudflare/wrangler.jsonc
pnpm dlx wrangler@4.137.0 secret put AIDR_DEVICE_START_INGRESS_SECRET --env staging --config deploy/cloudflare/wrangler.jsonc
```

Create the private approval record only after the named owners have checked
the domain and SMTP test receipt. Keep it outside the repository:

```json
{
  "release_sha": "<SIGNED_40_CHARACTER_COMMIT>",
  "manifest_sha256": "<VERIFIED_SIGNED_MANIFEST_DIGEST>",
  "origin": "https://aidr-pilot-staging.<account>.workers.dev",
  "staging_supabase_project_ref": "<NEW_STAGING_PROJECT_REF>",
  "domain_approved_by": "<NAMED_OWNER>",
  "smtp_approved_by": "<NAMED_OWNER>",
  "smtp_delivery_receipt": "<PRIVATE_RECEIPT_ID>",
  "approved_at_utc": "<UTC_TIMESTAMP>"
}
```

Run the same signed verification for the dry run and the eventual deployment.
The verifier sets a short-lived manifest digest for the child process. The
wrapper checks that digest, the release SHA against the clean checkout, the
signed dashboard files, the staging-only origin and routing, and the approval
record before it invokes Wrangler. Its release vars become `/version` values.
Use absolute paths for the bundle and child script: the verifier starts its
child in the bundle directory.

```sh
node scripts/release-verify.mjs --bundle <ABS_SIGNED_RC_BUNDLE> --policy <ABS_INDEPENDENT_SIGNER_POLICY> --state <ABS_PRIVATE_ANTI_ROLLBACK_STATE> -- node <ABS_CANDIDATE_CHECKOUT>/deploy/cloudflare/staging-deploy.mjs --env staging --bundle <ABS_SIGNED_RC_BUNDLE> --origin https://aidr-pilot-staging.<account>.workers.dev --mode dry-run
# Only after the domain, SMTP, signed candidate, and staging project are approved:
node scripts/release-verify.mjs --bundle <ABS_SIGNED_RC_BUNDLE> --policy <ABS_INDEPENDENT_SIGNER_POLICY> --state <ABS_PRIVATE_ANTI_ROLLBACK_STATE> -- node <ABS_CANDIDATE_CHECKOUT>/deploy/cloudflare/staging-deploy.mjs --env staging --bundle <ABS_SIGNED_RC_BUNDLE> --origin https://aidr-pilot-staging.<account>.workers.dev --mode deploy --approval <ABS_PRIVATE_APPROVAL_JSON>
```

The first command makes no Cloudflare change. The second creates or updates
only `aidr-pilot-staging`; do not run it until the external approvals exist.
Neither command provisions Supabase, changes DNS, or touches the landing page.

After deployment, run the independent `verify-operational.mjs --pilot` probe
with the signed version and SHA. Complete synthetic sign-in, tenant isolation,
device enrollment, allowed and blocked host actions, telemetry, recovery,
backup/restore, and alert delivery in staging. `/readyz` and `/metrics` still
block production acceptance. For paid multi-customer GA, provision a separate
production Supabase project and Worker on `app.aidr.singularityrd.com`, approve
its Cloudflare [custom domain](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/),
SMTP, backup/PITR and Storage restore, capacity, SLI/alerts, residency and
legal terms, then repeat the signed-candidate acceptance. Preserve
`aidr.singularityrd.com` as the landing page.

# Product brochure

A four-page A4 brochure for Singularity AIDR, in Turkish (primary) and English.

| File | What it is |
| --- | --- |
| `brochure.tr.html`, `brochure.en.html` | Source. Self-contained: inline CSS, inline SVG icons and diagram, base64-embedded logo; no external fonts, scripts or CDNs. Opens in any browser and prints to A4. |
| `singularity-aidr-brochure-tr.pdf`, `singularity-aidr-brochure-en.pdf` | Rendered PDFs, 4 pages each. |
| `preview/brochure-<lang>-p<n>.png` | Page previews (1.5x). |

Pages: 1 cover, 2 problem and the four product lines, 3 how it works (flow diagram,
capabilities, Browser Guard example), 4 deployment options, security and privacy, editions
(Free, Team, Business, Enterprise; no prices) and contact.

## Editing

- Edit the two HTML files directly. They carry **one identical `<style>` block**; change
  both together (the fact test fails if they drift). The logo is the
  company logo `images/singularity-logo.png` (white on pure black), embedded unchanged
  as base64 in the shared `.sg-logo` rule. Only place it on pure black: the cover
  background is `#000` and the page headers show it in a small black badge. Do not
  recolour, redraw or add a glow to it.
- Each page is a fixed 210 × 297 mm `<section class="page">`. Content must fit; the
  renderer rejects overflow instead of adding a fifth page.
- Wrap every countable claim in `data-fact="<key>"` (see the keys in
  `scripts/brochure-facts.test.mjs`). Do not add a number that the repository cannot
  back.
- The Turkish copy is written, not translated; keep both versions saying the same
  things.
- Fonts come from the system stack (Inter, Segoe UI, Helvetica Neue, then Liberation
  Sans/Arial). Rendering on a machine with different fonts can change line breaks; run
  the renderer after any copy change.

## Rendering

```bash
pnpm brochure:render                              # both languages: PDFs + PNG previews
node scripts/render-brochure.mjs --lang=tr        # one language
node scripts/render-brochure.mjs --check          # layout checks only, write nothing
node scripts/render-brochure.mjs --force          # write even when a check fails (while iterating)
node --test scripts/brochure-facts.test.mjs       # fact, honesty and self-containment checks
```

The renderer uses `playwright-core` from `packages/browser-guard` and the Chromium build
under `PLAYWRIGHT_BROWSERS_PATH` (or `AIDR_CHROMIUM_PATH`). It fails when a page
overflows, content runs into the footer, an element leaves the safe area or is clipped,
diagram text leaves the figure, the page makes a network request, or a PDF does not have
exactly 4 pages. Look at the PNG previews before committing.

## Fact sources

| Claim | Source |
| --- | --- |
| 428 YAML rules in 27 files | `grep -h '^- id:' threats/*.yaml \| wc -l`; `ls threats/*.yaml \| wc -l` |
| 2,000+ CVE rules, 146 AI components | files under `vendor/ai-infra-guard/data/vuln` and `data/fingerprints`; floor in `packages/dashboard/src/ui/pages/public/product-facts.ts` |
| Connectors, Browser Guard sites and browsers | `product-facts.ts` (`AGENT_CONNECTORS`, `BROWSER_GUARD_SITES`, `BROWSER_GUARD_BROWSERS`) |
| 14 MCP risk categories, T01–T09 skill/plugin categories, posture dashboard | `packages/core/src/mcp-aig-categories.ts` (`mcp-01`…`mcp-14`), `threats/skill-scan.yaml`, `docs/ai-security-posture.md` |
| Editions: minimums, retention, deployment, features | `packages/dashboard/src/billing/plans.ts` (mirror of the `public.plans` seed) |
| 14-day cloud trial | `supabase/migrations/20260923000034_tenant_ga_admission.sql` |
| `aidr approve`, `aidr scan`, `aidr discover`; severity and CVSS on infrastructure findings | `packages/cli/src/`, `docs/ai-security-posture.md` |
| GPO / Intune / Jamf policy | `deploy/browser-guard/` |
| Failure behaviour, telemetry, tenancy, SSO/SCIM, audit, signing, KVKK/GDPR wording | `docs/sales/security-faq.md`, `docs/product/overview.md` |
| On-prem, Helm and air-gapped | `deploy/onprem/README.md`, `docs/deployment/onprem.md` |

## Honesty rules

The brochure follows `docs/sales/pricing.md` §6 and the claim registry
(`docs/production-readiness/commercial-go-evidence-registry.json`, which scans
`docs/sales`): no certification, customer, testimonial or efficacy claims; no latency
figures; no "fail-open", open-source or "only tool" wording; KVKK/GDPR only as
"designed to support"; no prices, currency amounts or billing terms at all (pricing is by quote through
anil@singularityrd.com, the only contact address); the AI Security Posture capability is
presented as part of Singularity AIDR and the upstream scanner project is not named.
`scripts/brochure-facts.test.mjs` enforces these rules and the registry patterns.

The brochure describes the implemented product. The release decision is recorded in
`docs/production-readiness/first-customer-ready.md`; check it before sending the brochure
to a prospect.

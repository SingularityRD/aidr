# Product catalog

The Singularity AIDR product catalog: ten A4 pages in Turkish (primary) and English,
handed directly to prospects' security, IT, data-protection and procurement teams.
It carries no prices.

| File | What it is |
| --- | --- |
| `src/content.mjs` | The single source: facts, lifecycle stages, the numbered feature list (one line per feature, with evidence paths) and the page templates, written as `t("Türkçe", "English")` pairs. |
| `src/styles.css`, `src/icons.svg` | The shared stylesheet and inline line-icon sprite. |
| `catalog.tr.html`, `catalog.en.html` | Generated, self-contained pages (inline CSS, SVG and the logo as a data URI; no external requests). Do not edit by hand. |
| `singularity-aidr-catalog-tr.pdf`, `singularity-aidr-catalog-en.pdf` | Rendered A4 PDFs, 10 pages each. |
| `preview/catalog-<lang>-p<nn>.png` | Page previews (1.5x). |

Pages: 1 cover, 2 end-to-end lifecycle (seven stages and the governance layer, product
lines), 3 coverage matrix (with an AI safety row), differentiators and the lethal-trifecta
callout, 4 Discover and Assess, 5 Protect data (Browser Guard before/after strip),
6 Control actions with the AI safety group (risks from the agent's own behaviour; shipped
safety controls listed elsewhere are cross-referenced by number, not repeated), 7 Inspect
output and Approve and respond, 8 Prove and improve and Govern and comply, 9 platform and
editions, 10 next steps and contact.

## Editing

- Edit `src/content.mjs` and run `pnpm catalog:render`. The Turkish and English editions
  come from the same templates, so they always carry the same pages and features.
- One line per feature: `[name, what it is good for]`. Keep lines short enough to fit one
  line at 9 pt; the page budget is ten pages and the renderer rejects an eleventh.
- Countable claims use `{fact-key}` tokens in feature text or `h.fact("key")` in
  templates, backed by `FACTS`. `scripts/catalog-facts.test.mjs` recomputes every fact
  from the repository (threat rules, AI component fingerprints and CVE rules, MCP risk
  taxonomy, Browser Guard entity types and sites, DLP detectors, connectors, plan
  catalog, trial length).
- Every feature lists `evidence`: repository paths that implement it. The catalog lists
  shipped capabilities only: the test fails on a missing path or a feature marked
  `pending`. Add a feature once its code has landed, with a one-liner that matches the
  merged behaviour (and its documented limits).
- `SAFETY_ALSO` lists shipped safety controls the AI safety group cross-references
  (`h.ref("feature-key")` renders the feature's number); the test checks each rule file
  and that every referenced feature exists and is not pending.
- The logo is `images/singularity-logo.png`, embedded unchanged. Edition membership,
  deployment options and retention come from `packages/dashboard/src/billing/plans.ts`.
- Fonts: the pages are fitted to Liberation Sans / Liberation Mono, which is what the CSS
  stack (Inter, Segoe UI, Helvetica Neue, then Liberation Sans/Arial) resolves to on Linux
  without Inter. On Linux the renderer runs Chromium with
  `FONTCONFIG_FILE=scripts/lib/render-fonts.conf`, which hides every font except
  Liberation, DejaVu and Noto Color Emoji, so an installed Inter (or a fontconfig rule
  preferring it) does not change the layout. It refuses to run without the Liberation fonts
  (`fonts-liberation` / `liberation-fonts`). If the pinned Playwright Chromium is not
  installed, the newest installed one is used and logged (`AIDR_CHROMIUM_PATH` overrides).
  Re-render after any copy change and look at every preview.

## Rendering

```bash
pnpm catalog:render                             # build the HTML, then PDFs + PNG previews
node scripts/render-catalog.mjs --lang=tr       # one language
node scripts/render-catalog.mjs --check         # layout checks only, write nothing
node scripts/render-catalog.mjs --force         # write even when a check fails (while iterating)
node scripts/build-catalog.mjs --check          # fail when the committed HTML is stale
node --test scripts/catalog-facts.test.mjs      # facts, evidence, honesty and structure checks
```

The renderer uses `playwright-core` from `packages/browser-guard` and the Chromium build
under `PLAYWRIGHT_BROWSERS_PATH` (or `AIDR_CHROMIUM_PATH`). It fails when a page
overflows, content runs into the footer, an element leaves the safe area or is clipped,
diagram text leaves its figure, a heading is orphaned, an icon reference is broken, the
page makes a network request, or a PDF does not have exactly ten pages.

## Honesty rules

The catalog follows `docs/sales/pricing.md` §6 and the claim registry
(`docs/production-readiness/commercial-go-evidence-registry.json`). The facts test
enforces: no prices or currency amounts; no certification, customer, testimonial,
efficacy, latency or superlative claims; no "fail-open" or open-source wording;
KVKK/GDPR only as "designed to support"; no upstream vendor names; no internal codes or
repository paths in the pages; contact `anil@singularityrd.com`.

The catalog describes the product. Features marked `pending` in `src/content.mjs` are
listed at the product owner's direction while their code is merged; check the release
decision in `docs/production-readiness/first-customer-ready.md` before sending the
catalog to a prospect.

# Singularity AIDR feature guide

The feature guide explains every feature of Singularity AIDR: what it does, why it matters,
how it works, how to use it, where it is available and where its limits are. It has three
parts and is written in Turkish and English. Both languages cover the same content.

| Part | Türkçe | English |
| --- | --- | --- |
| 1. AI coding agent security: connectors, detection, content protection, operations, MCP gateway, SDK and CLI | [tr/01-ai-agent-security.md](tr/01-ai-agent-security.md) | [en/01-ai-agent-security.md](en/01-ai-agent-security.md) |
| 2. AIDR Browser Guard and the AIDR Privacy engine | [tr/02-browser-guard-and-privacy.md](tr/02-browser-guard-and-privacy.md) | [en/02-browser-guard-and-privacy.md](en/02-browser-guard-and-privacy.md) |
| 3. Control plane and deployment: dashboard, identity, tenancy, plans, telemetry, audit, retention, backups, monitoring, deployment options | [tr/03-control-plane-and-deployment.md](tr/03-control-plane-and-deployment.md) | [en/03-control-plane-and-deployment.md](en/03-control-plane-and-deployment.md) |

## Printable edition

All three parts are also published as one document per language, with a cover, a
clickable table of contents with page numbers, and page numbers in the footer:

| Language | PDF (A4) | HTML (self-contained) |
| --- | --- | --- |
| Türkçe | [singularity-aidr-feature-guide-tr.pdf](singularity-aidr-feature-guide-tr.pdf) | [singularity-aidr-feature-guide-tr.html](singularity-aidr-feature-guide-tr.html) |
| English | [singularity-aidr-feature-guide-en.pdf](singularity-aidr-feature-guide-en.pdf) | [singularity-aidr-feature-guide-en.html](singularity-aidr-feature-guide-en.html) |

The PDF and HTML files are generated from the Markdown chapters. Do not edit them by hand.
Links to other repository files cannot be followed in a standalone PDF. They are printed
as the link text followed by the repository path, for example
`(docs/configuration.md)`. Links between the three parts become links inside the
document.

## Regenerating the printable edition

Run the renderer after changing any chapter:

```bash
pnpm feature-guide:render                          # both languages: HTML + PDF
node scripts/render-feature-guide.mjs --lang=tr    # one language
node scripts/render-feature-guide.mjs --check      # convert and check the layout, write nothing
node --test scripts/render-feature-guide.test.mjs  # converter and link-resolution tests
```

The renderer reads every `0N-*.md` file in `tr/` and `en/` in order. It converts them with
a small built-in Markdown converter that supports headings, paragraphs, emphasis, code,
tables, lists, blockquotes and links. It then prints the result with headless Chromium,
using `playwright-core` from `packages/browser-guard` and the browser build in
`PLAYWRIGHT_BROWSERS_PATH`, or the one in `AIDR_CHROMIUM_PATH` if that is set. Unless
`--force` is given, it writes no output and exits non-zero when a check fails, for example
when:

- a link inside the guide points to a heading that does not exist;
- a table, code block or other element runs past the right margin;
- the page numbers in the table of contents do not settle.

Headings get the same ids GitHub generates, so the links in the chapters' own tables of
contents keep working. The chapters' own "Contents" / "İçindekiler" sections are left out
of the printed edition, because it has one combined table of contents.

Fonts come from the system font stack (Inter, Segoe UI or Helvetica Neue, falling back to
Liberation Sans or Arial). Rendering on a machine with different fonts can change line
and page breaks. The table of contents is always renumbered to match.

# Browser Guard store kit

Everything needed to publish Browser Guard as an **unlisted** item on the Chrome Web
Store and Microsoft Edge Add-ons (a one-click install link for individuals, force-install
by store ID for organisations) and as a Mozilla-signed **unlisted** add-on on
addons.mozilla.org (AMO) for self-distribution.

| File | Use |
|---|---|
| `en/short-description.txt`, `tr/short-description.txt` | Summary (= the manifest `extDescription`, at most 132 characters) |
| `en/description.txt`, `tr/description.txt` | Detailed description, plain text (250-10,000 characters, includes what is not covered) |
| `en/single-purpose.txt`, `tr/single-purpose.txt` | Chrome Web Store single-purpose statement |
| `permissions.json` | Justification for every permission and host permission (EN/TR), and the remote-code answer |
| `data-usage.md` | Answers for the Chrome Web Store privacy practices, Edge and AMO data declarations |
| `privacy-policy.en.html`, `privacy-policy.tr.html` | Privacy policy pages to host (self-contained, no external resources) |
| `images/screenshot-*-{en,tr}.png` | Store screenshots, 1280x800 |
| `images/promo-small-{en,tr}.png` | Small promo tile, 440x280 (Chrome Web Store, Edge) |

`scripts/validate-store.mjs` checks the packages and this kit offline and runs in every
release build (`pnpm package:browser-guard`). It fails on: a manifest `key` or
`update_url`, a malformed version, a name or description over the store limit in any
locale, a missing or wrongly sized 16/32/48/128 icon, a forbidden or unjustified
permission (or a justification for a permission that is gone), a non-exact host
permission, an extension-page CSP that allows anything but `'self'` scripts, remote code,
source maps or stray files in a package, a missing referenced file, wrong per-browser
keys (service worker vs event page, the gecko id, `data_collection_permissions`), and in
the kit: a short description that differs from the manifest, a detailed description
outside the limits, without its "not covered" section or with unverifiable claims
("100%", "guarantee", "complete protection", compliance claims...), missing EN/TR
justifications, privacy pages with scripts or external resources, and images of the
wrong size. `<PRIVACY_CONTACT_EMAIL>` is reported as a notice until it is replaced.

## Images

Generated from the real extension on the hermetic E2E fixtures (no real AI service is
contacted; the data is synthetic):

```bash
pnpm -C packages/browser-guard store:assets   # build, then scripts/store-assets.mjs
```

The generator loads the build into the pinned Playwright Chromium (falls back to an
installed `chromium-*`, e.g. `/opt/pw-browsers/chromium-1194`), drives the ChatGPT
fixture in confirm and auto mode, captures the popup and the options page, and frames
each capture with a caption at the store size. Fonts and anti-aliasing depend on the
host, so regenerate all images on one machine and commit them together (about 0.8 MB).

## Release packages

`pnpm package:browser-guard` writes to `packages/browser-guard/dist/`:

| File | Upload to |
|---|---|
| `aidr-browser-guard-chrome-<version>.zip` | Chrome Web Store **and** Edge Add-ons (same package) |
| `aidr-browser-guard-firefox-<version>.zip` | addons.mozilla.org |
| `aidr-browser-guard-source-<version>.zip` | addons.mozilla.org "source code" (required for bundled/minified code; holds `AMO-REVIEWER-NOTES.md` with the exact esbuild version, build commands and the expected SHA-256 of the Firefox package) |
| `SHA256SUMS` | all three |

All three are reproducible: the same tag gives the same SHA-256.

## What only the owner can do

### Once

1. **Developer accounts.** Chrome Web Store developer account (one-time registration
   fee, verified publisher email), Microsoft Partner Center account enrolled in the
   Microsoft Edge program, and an addons.mozilla.org developer account. Use an
   organisation account, not a personal one.
2. **Host the privacy policy.** Replace `<PRIVACY_CONTACT_EMAIL>` in both pages and host
   them over HTTPS (for example on the product website); the stores ask for the URL.
3. **Create the listings (first upload is manual).** The Chrome Web Store API cannot
   create an item, and the first AMO submission confirms the add-on ID:
   - Chrome Web Store: *Add new item*, upload the Chrome zip of a release, fill the
     *Store listing* (descriptions, screenshots, small promo tile, category
     *Productivity* or *Tools*, languages EN and TR), *Privacy practices* (from
     `en/single-purpose.txt`, `permissions.json`, `data-usage.md`) and set
     **Visibility: Unlisted**. Submit for review.
   - Edge Add-ons (Partner Center): *Create new extension*, upload the same Chrome zip,
     fill *Properties*, *Store listings* (EN and TR) and *Availability*:
     **Hidden** (the unlisted equivalent; installable from its link). Add the test note
     from `data-usage.md` for certification.
   - addons.mozilla.org: *Submit a New Add-on*, **On your own** (unlisted), upload the
     Firefox zip and the source zip. The add-on ID is fixed by the manifest:
     `browser-guard@singularityrd.com`.
4. **Record the IDs.** The Chrome Web Store item ID and the Edge Add-ons product ID /
   extension ID go into the customer policy templates (`<CHROME_WEB_STORE_ID>`,
   `<EDGE_ADDONS_ID>` in `deploy/browser-guard/`), the install links into
   `docs/installation/browser-guard.md`.
5. **CI credentials (optional).** In the repository, create the GitHub environment
   `browser-guard-store` with **required reviewers**, and add these environment secrets:

   | Secret | Where it comes from |
   |---|---|
   | `CWS_CLIENT_ID`, `CWS_CLIENT_SECRET` | a Google Cloud OAuth client (type *Desktop app*) in a project with the Chrome Web Store API enabled |
   | `CWS_REFRESH_TOKEN` | a refresh token for that client with the scope `https://www.googleapis.com/auth/chromewebstore`, created by the publisher account |
   | `CWS_PUBLISHER_ID` | the publisher ID shown in the Chrome Web Store developer dashboard (needed by API v2) |
   | `CWS_EXTENSION_ID` | the Chrome Web Store item ID |
   | `EDGE_ADDONS_CLIENT_ID`, `EDGE_ADDONS_API_KEY` | Partner Center > Microsoft Edge > *Publish API* > create API credentials |
   | `EDGE_ADDONS_PRODUCT_ID` | the product ID of the extension in Partner Center (not the store extension ID) |
   | `AMO_JWT_ISSUER`, `AMO_JWT_SECRET` | addons.mozilla.org > *Manage API Keys* |

   A store without any of its secrets is skipped (notice in the job summary; the packages
   are still on the draft GitHub release). A store with only some of them fails the job,
   so a misconfiguration is never silent. API keys expire or are rotated by the stores;
   replace them in the environment when they do.

### Every release

1. Push the signed `browser-guard-vX.Y.Z` tag. `release-browser-guard.yml` tests, builds
   twice, validates, attests and creates the draft GitHub release.
2. Approve the `browser-guard-store` deployment. The `store-drafts` job uploads:
   Chrome Web Store: the package to the item's draft (never published); Edge: the package
   to the draft submission (never submitted); AMO: an **unlisted** version with the source
   archive, which Mozilla signs for self-distribution (never listed). The job uploads
   receipts (store, version, package SHA-256, state) as an artifact.
3. In each dashboard, check the draft (version, permissions warning, listing text) and
   **submit it for review / publish** yourself. Store review takes from hours to several
   days; nothing reaches users before you publish and the review passes.
4. Firefox: download the signed XPI from the AMO Developer Hub when signing finishes and
   publish it where customers' `policies.json` `install_url` points.
5. Publish the draft GitHub release.

### Rollback

The stores serve only the latest published version and reject a lower version number.
To roll back, check out the last good tag, raise the version in `package.json`, tag and
release it; customers can stop the extension at once by removing it from their
force-install policy (see `docs/installation/browser-guard-enterprise.md`, section 9).

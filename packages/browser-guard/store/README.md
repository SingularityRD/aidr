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

The self-hosted packages (`-selfhosted-`, see below) pass the same rules except one: each
must carry exactly its browser's https update URL (Chrome/Edge `update_url` ending in
`/update.xml`, Firefox `browser_specific_settings.gecko.update_url` ending in
`/updates.json`, both on the same feed). The validator also fails when a self-hosted
package differs from its store package in anything but that URL, and when a store
package carries any update URL.

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

With `BROWSER_GUARD_UPDATE_BASE_URL=https://<host>/browser-guard` (or
`--update-base-url`), the build also writes the self-hosted channel, for browsers that
update from an HTTPS feed instead of a store:

| File | Use |
|---|---|
| `aidr-browser-guard-chrome-selfhosted-<version>.zip` | signed as a CRX3 by `scripts/update-feed.mjs` with the owner's extension key; `update_url` = `<base>/update.xml` |
| `aidr-browser-guard-firefox-selfhosted-<version>.zip` | uploaded to AMO (unlisted) instead of the Firefox zip; `gecko.update_url` = `<base>/updates.json` |

`scripts/update-feed.mjs` turns them into a feed directory for any static HTTPS host
(`update.xml`, `updates.json`, `packages/`, `SHA256SUMS`); see its header and
["Hosting Browser Guard updates internally"](../../../docs/installation/browser-guard-enterprise.md#10-hosting-browser-guard-updates-internally).

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
6. **Self-hosted update channel (optional).** For customers who cannot use the stores
   (isolated networks) and for self-distributed Firefox updates:
   - Create the extension key once, offline, and keep it like a release signing key
     (it fixes the self-hosted extension ID for good; losing it means a new ID and new
     customer policies): `openssl genrsa -out browser-guard-crx.pem 3072`.
   - Print its ID: `BROWSER_GUARD_CRX_KEY_PEM="$(cat browser-guard-crx.pem)" node packages/browser-guard/scripts/update-feed.mjs --print-extension-id`.
   - Create the GitHub environment `browser-guard-self-hosted` with **required
     reviewers** and the secret `BROWSER_GUARD_CRX_KEY_PEM` (the PEM text). Set the
     repository variables `BROWSER_GUARD_UPDATE_BASE_URL` (the HTTPS folder that will
     serve the publisher feed, for example `https://downloads.<your domain>/browser-guard`)
     and `BROWSER_GUARD_CRX_EXTENSION_ID` (the printed ID). Give that ID to customers as
     `<SELF_HOSTED_EXTENSION_ID>`.
   - With the variable set, a release without the key or the pinned ID fails: nothing is
     ever signed with another key. Without the variable the release has store packages
     only (notice in the job summary).

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
5. Self-hosted channel (when configured): the `self-hosted-feed` job signed the CRX (it is
   on the draft release) and uploaded the feed artifact `aidr-browser-guard-update-feed-<version>`.
   Add the signed XPI and merge it with the feed you host, then upload the result (packages
   first, `update.xml` / `updates.json` last):

   ```bash
   node packages/browser-guard/scripts/update-feed.mjs \
     --base-url "$BROWSER_GUARD_UPDATE_BASE_URL" --out feed-next --previous feed-hosted \
     --chrome-crx aidr-browser-guard-<version>.crx --extension-id <SELF_HOSTED_EXTENSION_ID> \
     --firefox-xpi <signed>.xpi --firefox-zip aidr-browser-guard-firefox-selfhosted-<version>.zip
   ```

   No key is needed here: the CRX signature and ID are verified, the signed XPI must be
   the attested build plus Mozilla's signature and point at this feed, and versions must
   go up.
6. Publish the draft GitHub release.

### Rollback

The stores serve only the latest published version and reject a lower version number.
To roll back, check out the last good tag, raise the version in `package.json`, tag and
release it; customers can stop the extension at once by removing it from their
force-install policy (see `docs/installation/browser-guard-enterprise.md`, section 9).

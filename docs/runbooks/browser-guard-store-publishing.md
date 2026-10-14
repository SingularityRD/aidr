# Browser Guard: store publishing ownership and CRX key custody

The mechanics of building, validating and uploading Browser Guard are in the
[store kit README](../../packages/browser-guard/store/README.md) and
`.github/workflows/release-browser-guard.yml`. The workflow only ever uploads
**drafts**; a person publishes. This runbook names who that person is, how the
self-hosted CRX signing key is created and kept, and what to do when a key or a
store account is lost or compromised.

> **Status.** No store listing, store account or CRX key exists yet. The roles
> below must be filled with names before the first release; until then the
> release produces the GitHub draft release only. Items a human must do are
> collected in [What only people can do](#what-only-people-can-do).

## Roles

| Role | Responsibility | Holder | Backup |
|---|---|---|---|
| **Publishing owner** | Owns the store accounts; reviews each draft and presses publish; answers store review questions; keeps listing text and privacy policy current | [name] | [name] |
| **Release engineer** | Pushes the signed `browser-guard-vX.Y.Z` tag; checks the workflow run, attestation and receipts; publishes the GitHub draft release | [name] | [name] |
| **Key custodians (2)** | Hold the offline CRX key backup shares; take part in key ceremonies; approve the `browser-guard-self-hosted` environment | [name], [name] | — |
| **Environment approvers** | Required reviewers on the `browser-guard-store` and `browser-guard-self-hosted` GitHub environments | Publishing owner + one custodian | — |

Rules:

- The release engineer and the publishing owner are different people: the
  person who builds is not the person who ships to users.
- Store accounts are **organisation** accounts with at least two owners, MFA
  with hardware keys, and a shared mailbox (not a personal address) as the
  publisher contact.
- Every publish is logged in the release record: version, store, package
  SHA-256 from the workflow receipts, who published, when.

## CRX key custody

The CRX key (RSA 3072) fixes the **self-hosted extension ID** forever. Every
customer who force-installs from the internal update feed pins that ID in
policy. Losing the key means a new ID and new policy at every such customer;
leaking it lets anyone sign an update that those browsers will accept from the
feed. Treat it like a release signing key. (The store channels do not use it:
the Chrome Web Store and Edge Add-ons sign with their own keys; AMO signs the
Firefox package.)

### Creation ceremony (once)

1. Two custodians and the publishing owner, one offline machine (live USB, no
   network), a recorded checklist.
2. Generate: `openssl genrsa -out browser-guard-crx.pem 3072`.
3. Print and record the extension ID:
   `BROWSER_GUARD_CRX_KEY_PEM="$(cat browser-guard-crx.pem)" node packages/browser-guard/scripts/update-feed.mjs --print-extension-id`.
4. Back up: encrypt the PEM to both custodians (for example with `age` to each
   custodian's hardware-backed key) onto two USB media stored in separate
   locked places. Record SHA-256 of the
   PEM and of each encrypted backup.
5. Load the PEM into the GitHub environment secret `BROWSER_GUARD_CRX_KEY_PEM`
   (`browser-guard-self-hosted`, required reviewers set) directly from the
   offline machine's clipboard session or a one-time encrypted transfer, and set
   the variable `BROWSER_GUARD_CRX_EXTENSION_ID` to the printed ID.
6. Wipe the working copy on the offline machine. Sign the ceremony record.

The GitHub secret is the only online copy. Nobody keeps the PEM on a laptop.

### Every release

- The `self-hosted-feed` job signs with the environment secret after an
  approver approves the deployment. The approver checks that the run comes
  from the signed tag and that the CRX ID in the job summary equals the pinned
  ID.

### Yearly check

- Custodians confirm both backups decrypt on the offline machine and the
  SHA-256 matches; record the check. Rotate custodians when people leave.

### Key loss

If the GitHub secret is deleted but a backup exists: restore it from backup in
a ceremony. If every copy is lost: the self-hosted ID cannot be kept. Create a
new key and ID (creation ceremony), publish a customer notice with the new ID,
new policy values and the date the old feed stops receiving updates, and keep
the old feed serving its last version.

### Key compromise

1. Remove the secret from the environment; stop self-hosted releases.
2. Tell customers who use the self-hosted feed to pause force-install updates
   from it (they can keep the installed version) and to check the installed
   version against the published SHA-256 list.
3. Assess what was signed since the last trusted point; publish an advisory
   through the support channel.
4. New key and ID as for key loss; customers move their policy to the new ID.
5. Record the incident per the [incident response runbook](incident-response.md).

## Store account compromise

Revoke the store API credentials (CWS OAuth client and refresh token, Edge
Publish API key, AMO JWT) and replace the environment secrets; review the
store's version history for any publish not in the release record; if a
malicious version was published, publish a fixed higher version immediately,
contact the store's abuse/security team and notify customers to pin or remove
the extension through policy until the fix is live.

## What only people can do

- [ ] Name the publishing owner, release engineer and two custodians.
- [ ] Create the three store developer accounts (organisation accounts, MFA)
      and the first listings (manual first upload, see the store kit README).
- [ ] Host the privacy policy pages with a real contact address.
- [ ] Run the CRX key ceremony and store the backups.
- [ ] Configure the `browser-guard-store` and `browser-guard-self-hosted`
      environments with required reviewers and secrets.
- [ ] Record the store IDs in the customer policy templates.

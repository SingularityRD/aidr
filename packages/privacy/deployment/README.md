# Deployment configuration only

These generated files do not install anything. Default extension ID is the development public identity; no private signing key is present. The update URL uses `.invalid` deliberately. Replace ID/URL with your approved publisher and signed distribution, review policy conflicts, and deploy through your actual MDM. Do not import an unreviewed REG file on a production machine.

`extension-managed.json` defaults to complete provider blocking until acceptance. It must be mapped to the correct per-extension managed policy namespace by the organization's MDM. The macOS JSON is a policy fragment, NOT a signed installable mobileconfig. Native binary code signing, Windows/macOS deployment, required Chrome version and real browser policy verification remain acceptance tasks. No MDM action was performed here.

Generate with reviewed configuration:

```bash
AIDR_EXTENSION_ID=your32characterpublishedid AIDR_EXTENSION_UPDATE_URL=https://your-approved-host/update.xml node deployment/generate.mjs
```

Use a non-root Linux service account, private state directory and keys from an approved secret store. Only the gateway holds provider credentials. Allowlist approved provider origins at the network boundary; block all direct alternative first-upload/provider/tool routes. Pin all parser/OCR/runtime dependencies in an approved image. Parser seccomp is tested, but the whole application image and kernel were not independently audited. Add request rate limits, retention/GC, capacity limits, backups and off-host checkpoints before unattended operation.

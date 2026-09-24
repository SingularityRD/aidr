# Delivery notice — 0.2.0-rc.1

This source package is a private integration work product for Singularity AIDR. `private: true` and `license: UNLICENSED` are publication safeguards for the internal package. They do not override any third-party dependency licenses.

No third-party npm runtime code, pretrained weights, tokenizers or font files are bundled. Synthetic raster test fixtures and their ground-truth strings are bundled; they are not customer data. The optional local vision runtime requires separately installed Pillow, pyzbar, Tesseract, eng/tur traineddata, libzbar and native decoder/shared libraries. The optional NER runtime has separate dependencies.

Review the exact installed component versions and their licenses in the approved deployment. Relevant upstream licenses include Pillow's HPND-style license, Tesseract Apache-2.0, pyzbar MIT and libzbar LGPL-2.1. Binary distribution, modifications, notice/relinking obligations and transitive libraries must be reviewed against their actual license texts; this inventory is not legal clearance. Official source links are in docs/VISUAL_SOURCES.md.

The original standalone delivery supplied source and compiled distribution together. This workspace import retains source and regenerates compiled output during build. No claim of accreditation, suitability for classified data, warranty of complete detection, third-party security audit, BMC deployment, real enterprise acceptance or learned-NER inference evaluation is made. Runtime model hash inventories and the original release manifest are integrity checks, not digital signatures.


## 0.3.0 build/runtime additions

The Chrome bundle contains statically compiled local application sources, no remote code, fonts or model weights. The full source archive vendors development-only TypeScript 5.8.3 (Apache-2.0), @types/node 24.0.4 (MIT), and undici-types 7.8.0 (MIT) tarballs, retaining their upstream license files. They are not shipped in the minimal Chrome ZIP or required at application runtime. The native launcher sources are application scaffolding, not an independently audited installer or OS sandbox. Runtime dependency vulnerability scanning and approved native/model provenance remain deployment gates.

## 0.4.0 integration additions

Enterprise controls use Node built-ins and project source; no new third-party runtime npm packages or vendor product source code/weights were bundled. Gartner access was limited to public abstracts; no licensed full reports are copied. Vendor feature descriptions are comparisons, not endorsements, attestations, or independent performance measurements. Ed25519 policy signing is implemented, but a release SHA-256 inventory is still not a signed release. The original AIDR application was not available for a direct merge.

## 0.5.0 control-plane additions

Platform source and the small original synthetic character-linear classifier were created for this integration. No external pretrained NER/ASR/vision-model weights or font files were added. PDF/Office synthetic fixtures may reference font names but contain no distributed font program files. Python/native document parsing dependencies must be installed and reviewed separately. A component inventory is supplied with `vulnerabilityDatabaseChecked:false` and does not constitute license or vulnerability clearance.

The implementation is not an SSO/MDM service enrollment, hardware attestation, complete MCP proxy, WORM datastore, multi-node HA deployment or full multimodal AI system. Real corporate data and the original AIDR application were unavailable for acceptance and merge. The default gateway profile refuses release without a configured, approved real NER provider. Review-only audio artifacts must never be forwarded as sanitized output.

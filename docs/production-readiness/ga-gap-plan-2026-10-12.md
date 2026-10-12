# GA öncesi eksik kaydı ve düzeltme planı — 12 Ekim 2026

Bu kayıt, 12 Ekim 2026'da ürünün tamamında yapılan bağımsız GA (genel kullanıma açılış) denetiminin
sonucudur. Yedi alan denetçisi kodu okudu ve hedefli testlerle davranışı **gerçekten çalıştırarak**
doğruladı. Dokuz P0'ın beşi ayrıca bağımsız olarak yeniden üretildi (DET-1, PRD-1, CON-1, MSC-1, BG-1).
Mevcut kayıtlar (READINESS_BACKLOG.json, PRODUCTION_SALES_GAPS) süreç ve saha kabulünü izler; bu
kayıttaki bulguların neredeyse tamamı **orada yoktur**.

Ham kanıt (dosya:satır, tekrar üretme komutu ve çıktısı, önerilen düzeltme, efor):
[ga-audit-2026-10-12.findings.json](ga-audit-2026-10-12.findings.json). PII maskeleme kalitesi ayrıca
[pii-poc-test-scenarios.md](pii-poc-test-scenarios.md) ve `ml/pii-tiny/` içinde izlenir.

## Özet

| Önem | Adet | Anlamı |
|---|---|---|
| P0 | 9 | GA engeli: güvenlik atlatması, vaat edilen fail-closed'un fail-open çalışması, yanlış koruma iddiası, release yolu yok |
| P1 | 40 | GA öncesi düzeltilmeli |
| P2 | 36 | GA sonrasına kalabilir |

Ayrıca iki kayıt (DET-6, MSC-16) eski "kapalı" bulguların gerçekten kapalı olduğunu teyit eder. Teyit
edilmeyenler: **AIDR-015** (lisans durumunda yerel tespit, bkz. PRD-1), **AIDR-013** (kural sayısı
iddiaları, bkz. PRD-5) ve **AIDR-060** (OpenCode araç kapsamı, bkz. CON-3).

**Sağlam bulunan alanlar:** kiracı izolasyonu ve RLS, Edge Function yetki matrisi (48 route), webhook
imzaları, Browser Guard vault ve mesaj güveni, imzalı dashboard politikası, Claude Code/Codex hook'larının
bozuk girdi ve zaman aşımında fail-closed çalışması, kabuk gizleme normalizasyonunun kendisi (yalnız tüm
kural ailelerine bağlı değil), 507 kural regex'inde ReDoS yok, bağımlılık denetimi temiz (`pnpm audit` 0).

## Dalgalar

- **Dalga 1 — hemen:** bütün kod tarafı P0'lar ve hızlı güvenlik P1'leri. Her düzeltme kendi testiyle gelir.
- **Dalga 2 — GA öncesi:** kalan P1'ler (ilk kullanım, kontrol paneli, release otomasyonu).
- **Dalga 3 — GA sonrası olabilir:** P2'ler ve doküman inceltmeleri.
- **Dış:** bu ortamdan kapatılamayan, insan, altyapı veya karar gerektiren işler (aşağıdaki listede).


## Tema A — Tespit atlatmaları (core motor)

| ID | Önem | Dalga | Efor | Doğrulandı | Bulgu |
|---|---|---|---|---|---|
| DET-1 | P0 | 1 | M | evet | Reverse-shell / RCE rules are literal-only and bypassed by trivial shell quoting, concatenation and variable indirection |
| DET-2 | P1 | 1 | M | evet | node -e network reverse shell is not detected (interpreter inline-code coverage is language-incomplete) |
| CON-4 | P1 | 1 | M | evet | Unknown/MCP tool extraction ignores argv arrays and non-command keys, so shell payloads in MCP tools are allowed |
| CON-10 | P1 | 1 | M | evet | Credential-file read guard evaded by cd/globs/grep -r and by Grep/Glob/list tools |
| DET-3 | P2 | 1 | S | evet | base64-decode-and-exec via command substitution evades the decode-exec detector |
| DET-4 | P2 | 1 | S | evet | netcat alternate exec flags (-c, OpenBSD) not covered |
| DET-5 | P2 | 3 | S | kod okuması | Trusted-installer suffix allowlist includes deno.land, a public third-party module registry |

## Tema B — Öz-savunma ve onay sınırı (ajan AIDR'yi kapatamamalı, kendi onayını verememeli)

| ID | Önem | Dalga | Efor | Doğrulandı | Bulgu |
|---|---|---|---|---|---|
| CON-1 | P0 | 1 | M | evet | Agent can disable/uninstall AIDR via host CLIs and config file ops with no ask/deny |
| MSC-1 | P0 | 1 | M | evet | Any process running as the gateway user (the agent, in stdio mode) can approve a quarantined MCP toolset by editing the unauthenticated attestation state JSON |
| MSC-2 | P1 | 1 | M | evet | CLT-SELF-007 (agent may not run aidr-mcp-approve) is bypassed by a shell glob or by importing the gateway library and calling approve() |
| CON-7 | P1 | 1 | S | evet | AIDR_THREATS_DIR/AIDR_ALLOWLISTS_DIR override silently replaces the whole rule set in every build (no manifest, no warning) |
| MSC-14 | P2 | 3 | S | kod okuması | Gateway stateDir may be relative (resolved against cwd) and its permissions are never checked on an existing directory |

## Tema C — Fail-open yollar (hata/lisans/güncelleme durumunda korumasız kalma)

| ID | Önem | Dalga | Efor | Doğrulandı | Bulgu |
|---|---|---|---|---|---|
| PRD-1 | P0 | 1 | M | evet | Expired/missing entitlement disables local detection: commercial build asks on every call, default build silently allows (contradicts licensing doc and README) |
| CON-5 | P0 | 1 | M | evet | Cursor/VS Code hook shim hard-codes versioned extension path; update/uninstall silently disables protection (exit 1, no verdict) |
| CON-2 | P0 | 1 | M | evet | OpenClaw process (write/submit/paste/send-keys) and nodes(run) tools bypass command inspection |
| CON-9 | P1 | 1 | S | evet | Claude Code PostToolUse output DLP fails open on timeout or >1 MiB input: secret output reaches the model unreplaced |
| CON-3 | P1 | 1 | S | evet | OpenCode patch(patchText)/list tools bypass file-path policy that apply_patch/write enforce; AIDR-060 incompletely closed |
| MSC-3 | P1 | 1 | S | evet | MCP gateway output scanner is bypassed by splitting an injection or secret across two text content blocks |

## Tema D — Browser Guard gönderim yolları ve yönetilen politika

| ID | Önem | Dalga | Efor | Doğrulandı | Bulgu |
|---|---|---|---|---|---|
| BG-1 | P0 | 1 | M | evet | Sending an edited message ("Send"/"Save" button on a sent turn) skips the guard, so the original PII goes out unmasked |
| BG-2 | P1 | 1 | S | evet | Send-button click scans the focused or last-focused editable (e.g. an empty search box), not the composer the site sends |
| BG-3 | P1 | 1 | M | evet | Enter in an editor inside a shadow root (custom sites, web-component UIs) is never intercepted: fail-open, contrary to the 'prompt box not found -> block' claim |
| BG-4 | P1 | 1 | M | evet | Invalid or mistyped managed policy values silently fall back to the permissive defaults; one bad list entry drops the whole list; warnings only reach the worker console |
| BG-6 | P1 | 1 | S | evet | User pause defaults to allowed even under a managed policy, is not locked by allowUserOverrides:false, and is not reported to telemetry |
| BG-7 | P1 | 1 | S | evet | AI tabs already open at install/enable time are left unprotected (no injection into open tabs), and the popup still reports them as 'Protected' |
| BG-8 | P1 | 2 | M | evet | exactData datasets (HMAC key + fingerprints) are readable by every endpoint user via chrome://policy, and low-entropy columns are recoverable offline |
| BG-5 | P1 | 2 | S | evet | Shipped MDM examples omit the hardening policies that make the guard non-bypassable (incognito/InPrivate/Firefox private browsing, Guest mode, DevTools, other extensions) |
| BG-10 | P1 | 2 | M | evet | Microsoft 365 Copilot Chat (m365.cloud.microsoft / copilot.cloud.microsoft) is neither protected nor in the Shadow AI catalog |
| BG-9 | P2 | 3 | M | evet | On sites where plain Enter inserts a newline (mobile layouts, Firefox for Android, custom sites), the guard turns Enter into a send |
| BG-13 | P2 | 3 | S | kod okuması | Shadow AI / blockedSites blocks do not stop an already-open session (only main_frame/sub_frame navigations are blocked) |

## Tema E — İlk kurulum ve günlük kullanım (müşteriyi kaldırmaya iten engeller)

| ID | Önem | Dalga | Efor | Doğrulandı | Bulgu |
|---|---|---|---|---|---|
| PRD-2 | P1 | 2 | M | evet | Default install asks/blocks every URL fetch and every package install, with no configuration that avoids it |
| CON-8 | P1 | 2 | M | evet | Default local mode asks on every URL/package (git clone, npm install react, docs WebFetch); on Codex/Cursor/OpenClaw/OpenCode that is a hard deny |
| PRD-3 | P1 | 2 | S | evet | Codex/OpenClaw/OpenCode asks cannot be approved on hosts without an OS credential vault (headless Linux, WSL, containers) |
| CON-11 | P1 | 2 | M | evet | OpenClaw/OpenCode/Codex operator-approval ask channel is unusable without an OS vault; asks are recordable only where libsecret exists |
| PRD-4 | P1 | 2 | S | evet | `aidr setup` fails on headless Linux in local mode because it insists on vaulting an unneeded CLI credential |
| PRD-7 | P1 | 2 | M | kod okuması | Release builds are managed-only, but the README sells a 'Local mode (free)' tier and quick start never shows the required trust-key step |
| PRD-8 | P1 | 2 | S | evet | Dashboard onboarding for Codex registers only PreToolUse; sold prompt protection (UserPromptSubmit) and MCP output hook are missing |
| PRD-9 | P1 | 2 | M | evet | No complete uninstall or data-deletion path; `aidr uninstall` only removes Claude Code hooks and refuses marketplace installs |
| PRD-10 | P1 | dış | M | evet | No endpoint diagnostics/support bundle for connector problems and no support channel |
| MSC-13 | P2 | 3 | S | evet | `aidr setup` fails (exit 1) by default on headless Linux without libsecret; the only workaround writes the CLI credential in plaintext to config.json |
| CON-13 | P2 | 3 | M | evet | CLI `aidr setup` never installs any connector; a user who only runs setup is unprotected |
| PRD-14 | P2 | 3 | S | evet | CLI setup reports a detected agent that `aidr status` reports as not detected (cwd-based detection) |
| MSC-10 | P2 | 3 | S | evet | SDK requires an apiKey even for local-only enforcement |
| MSC-12 | P2 | 3 | S | kod okuması | `aidr simulate` defaults --min-score to 0, so it prints PASS and exits 0 for any detection score |
| MSC-15 | P2 | 3 | S | evet | Malformed request encodings (gzip Content-Encoding, UTF-16) are refused with the misleading reason gateway_unavailable |
| PRD-13 | P2 | 3 | S | evet | Dead or private links in customer-facing text (Cursor build guide, VS Code update notice) |
| PRD-15 | P2 | dış | L | evet | Endpoint UIs are English-only (CLI, VS Code/Cursor extension, hook messages, dashboard) despite a TR-first market |

## Tema F — Kontrol paneli, uyum ve veri saklama

| ID | Önem | Dalga | Efor | Doğrulandı | Bulgu |
|---|---|---|---|---|---|
| CP-1 | P1 | 2 | M | kod okuması | Device-code flow is open to remote phishing: a link-prefilled code is authorized with one click and no device context |
| CP-3 | P1 | 2 | M | evet | Retention, erasure and digest maintenance is never scheduled on Kubernetes (Helm) or Supabase Cloud deployments |
| CP-4 | P1 | 2 | M | evet | Public waitlist PII (and pilot free-text notes) has no retention or erasure path |
| CP-2 | P1 | dış | L | evet | Premium intel pack keys are per-tenant HKDF keys under one shared key_id, so no published (vendor/global) encrypted pack can be decrypted |
| CP-9 | P2 | 3 | S | kod okuması | No separation of duties on out-of-band approvals: an owner/admin can approve the request raised by their own key/agent |
| CP-8 | P2 | 3 | S | kod okuması | API key hygiene: tenant keys never expire, renewed Browser Guard ingest keys come back with the aidr_live_ prefix, labels are unbounded |
| CP-6 | P2 | 3 | S | kod okuması | version-check shares one aggregate rate-limit bucket between attested and unattested callers |
| CP-7 | P2 | 3 | S | kod okuması | Revocation feed TTL and epoch env values are not validated (NaN gives an already-expired feed, no upper bound, bad epoch silently becomes 1) |
| CP-5 | P2 | 3 | S | evet | 22 of 48 Edge Functions are never Deno type-checked, including device-start/poll, api-keys, operator-admin and notification-dispatch |

## Tema G — Release, tedarik zinciri ve dağıtım

| ID | Önem | Dalga | Efor | Doğrulandı | Bulgu |
|---|---|---|---|---|---|
| OPS-1 | P0 | dış | L | evet | No enforced release path exists: every signing, attestation and acceptance gate lives in GitHub Actions workflows that cannot run, and no release has ever been cut |
| OPS-2 | P1 | 2 | S | evet | verify:release-signing (a release-rc quality gate) fails today because a Dependabot bump of changesets/action was never mirrored in its contract test; the gate runs nowhere else so the drift went unnoticed |
| OPS-3 | P1 | 2 | S | evet | Pending version bump to 1.0.0 leaves the Helm chart at appVersion 0.6.0: version sync does not cover Chart.yaml and the chart test hard-codes 0.6.0 |
| OPS-6 | P1 | 2 | S | kod okuması | build-release-candidate binds whatever dist/ trees are on disk to HEAD's commit; it never checks that the dist manifests were built from that commit |
| OPS-7 | P1 | 2 | S | evet | The built-artifact enforcement check (verify:enforcement, verify:codex) is wired into no gate, and the sales demo preflight that relies on it always fails after the documented `pnpm build` |
| OPS-4 | P1 | dış | M | evet | The optional AI Security Posture scanner ships vendored AIG images that are outside every dependency audit, image scan, SBOM and Dependabot scope; its frontend has 2 critical / 32 high production advisories and the agent builds on EOL Go 1.23.2 |
| OPS-5 | P1 | dış | M | evet | Kubernetes distribution has no vendor-built, signed or attested images or chart package; customers build images from a source checkout, and the migrations base image is not digest-pinned |
| MSC-11 | P2 | 3 | M | kod okuması | SEA 'standalone' binaries are not standalone: no embedded rules (relocated binary asks on every call), only 2 of the hook entry points, unsigned, and the docs name the wrong entry bundle |
| OPS-8 | P2 | 3 | M | kod okuması | Promotion anti-rollback state lives in an expiring, deletable Actions artifact and a missing state is silently treated as a first release |
| OPS-9 | P2 | 3 | M | evet | Helm backups are plaintext pg_dumps on a same-cluster PVC, omit the pgsodium/Vault root key, and are off by default; restore is a manual procedure with no drill script, unlike the Compose path |
| OPS-10 | P2 | 3 | S | kod okuması | Helm accepts the bridge's api_key auth mode, in which the tenant comes from a caller-supplied header, so any holder of the shared key can act for any tenant |
| OPS-11 | P2 | 3 | M | evet | RC pipeline allows exactly one candidate per version (rc.0 only), so any failed acceptance forces a version bump |
| OPS-12 | P2 | 3 | S | evet | aig-bridge ships an unused prometheus-client dependency and exposes no metrics endpoint; the monitoring config does not scrape it |

## Tema H — Kanıt ve iddialar (doküman, uyumluluk matrisi, satış metni)

| ID | Önem | Dalga | Efor | Doğrulandı | Bulgu |
|---|---|---|---|---|---|
| CON-6 | P0 | dış | L | evet | Cursor and VS Code connectors have no real-host enforcement evidence yet are sold and described as fail-closed |
| PRD-11 | P1 | 2 | M | evet | No customer-facing compatibility matrix or upgrade notes; changelogs stop at a 0.6.0 'rebrand' entry |
| BG-12 | P1 | 2 | S | kod okuması | Docs overstate the send-interception guarantee ('the only ways to let text through unmasked are monitor and disabledSites'; voice/drag text 'checked at send time') |
| MSC-4 | P1 | 2 | M | kod okuması | stdio bridge mode cannot meet the gateway's own isolation requirements: upstream credential and client token live in the agent host's MCP config/env |
| MSC-5 | P1 | 2 | M | evet | Signed MCP manifests expire after at most 7 days (hard-coded); gateway starts 'listening' with an expired/invalid manifest and every call fails with an undifferentiated manifest_rejected |
| BG-11 | P1 | dış | L | kod okuması | Native-host NER is impractical as an enforced requirement: a new host process (and NER worker) per scan with a 2 s budget; Windows launcher unvalidated; Firefox unsupported |
| CON-12 | P2 | 3 | S | evet | Codex PostToolUse output inspection and apply_patch/MCP coverage are documented-but-unenforced; no output-side block observed on a real host |
| CON-14 | P2 | 3 | M | evet | Connectors declare no host-version compatibility check; verified only against single pinned host versions |
| PRD-5 | P2 | 3 | S | evet | Rule-count and capability claims out of date across customer docs (494 / 351 vs 507 rules; block/approval split) |
| PRD-6 | P2 | 3 | S | evet | Product overview states placeholder originals are never stored and that PDF/DOCX/XLSX cannot be inspected; both are stale |
| PRD-12 | P2 | 3 | S | evet | Sales catalog advertises 'Fail-closed connectors' without the host fail-open caveat |
| BG-14 | P2 | 3 | S | evet | README claims a page cannot fingerprint the extension, but the MAIN-world script sets window.__aidrFileInputHook and patches HTMLInputElement prototypes |
| BG-15 | P2 | 3 | S | evet | Product docs still say the optional https://*/* permission is unused, but customSites relies on it; chat widgets in iframes (all_frames:false) are not covered |
| MSC-6 | P2 | 3 | S | evet | MCP gateway accepts any Host header (no DNS-rebinding/Host allowlist), relying solely on Origin rejection + bearer token |
| MSC-7 | P2 | 3 | M | evet | Gateway output scanner misses encoded (base64/hex) and paraphrased injection; protection is regex-only and this is not stated |
| MSC-8 | P2 | 3 | S | evet | SDK express()/nextjs() 403 responses return the full CheckResult (threatId, reasons) to the remote HTTP caller; init errors with filesystem paths are passed to next(err) |
| MSC-9 | P2 | 3 | S | evet | SDK HTTP middleware passes request headers in context but never inspects them |

## Dış bağımlılıklar (insan, altyapı veya karar gerektirir)

| ID | Gereken |
|---|---|
| OPS-1 | GitHub Actions'ın açılması veya imza anahtarlarına sahip ayrı bir release makinesi |
| CON-6 | Gerçek Cursor ve VS Code kurulumları (bu ortamda yok) |
| OPS-4 | Görüntü tarama/imzalama altyapısı |
| OPS-5 | Görüntü kayıt defteri ve imzalama anahtarı |
| CP-2 | Anahtar tasarımı kararı (ürün sahibi) |
| BG-11 | Native host performans ölçümü gerçek uç noktada |
| PRD-10 | Destek kanalı ve sahibi (insan) |
| PRD-15 | Çeviri kapsamı kararı |
| PII-NER | Frontier kalite PII modeli için önceden eğitilmiş ağırlıklar (`huggingface.co` ağ erişimi) |
| BG-LIVE | Canlı ChatGPT/Claude/Gemini/Copilot/Perplexity/DeepSeek/Mistral/Grok kabul testi (pii-poc-test-scenarios.md bölüm 4) |
| SEC-EXT | Bağımsız güvenlik değerlendirmesi (mevcut SEC-EXT-001) |

## PII maskeleme (ayrı izlenir)

- Serbest metindeki isimler: kurallar %9,8 (doğal set). Küçük model `ml/pii-tiny` v2 %86,5 recall,
  %14,7 yanlış alarm; hedef %95 / %2. Ürüne girmeden önce model kapısı geçilmeli.
- `allowSendAnyway` varsayılan `true`: Dalga 1'de yönetilen politikada güvenli varsayılana çekilecek.


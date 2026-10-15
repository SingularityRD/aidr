# Offboarding a person and swapping a machine

This runbook covers two everyday changes: a person leaves (or loses access), and a
person moves to a new machine. Tenant (customer) offboarding, the deletion of a
whole workspace, is a different process; see "Retention maintenance" in
[docs/control-plane.md](../control-plane.md).

## What happens automatically when the directory deprovisions a person

When the identity provider deactivates a SCIM user (`active: false`, a PATCH, a
PUT or a SCIM `DELETE`), the same database transaction
(migration `20261014000120_scim_deprovision_revokes_device_access.sql`):

| Revoked | Effect |
| --- | --- |
| Every API key the person owns in the tenant (device keys from enrollment and keys issued in the dashboard), including a renewed key's retired secret | Their enrolled agents can no longer send telemetry, fetch policy, file or receive approvals, or send heartbeats. The device stops being counted as active and raises `agent.offline` if a channel watches agent health |
| Their **pending** approval requests | Expired: nobody approves an action for a person who left |
| Their unused enrollment codes and open device-code sessions | Expire immediately |
| — | One audit row, `scim.user.deprovisioned`, records the counts |

Also true, independent of this change:

- A SCIM-managed membership is removed, which removes dashboard access.
- A **hand-made** membership (the person was invited before SCIM was connected) is
  kept: owners use hand-made memberships as break-glass access. Their device keys
  are revoked anyway. To make the directory the only source of membership, enable
  directory-authoritative mode on the SCIM page (`/scim`).
- Reactivating the person in the directory never brings a revoked key back. They
  enrol their device again.
- An approval that was already decided carries a signed token that lives at most
  15 minutes and is delivered only with the requester's key, which is now
  revoked. Approvals recorded locally by an operator (`aidr approve`) on the
  endpoint stay on that endpoint until it is cleaned (below).

### Check before you deprovision an administrator

API keys belong to the person who created them. If a leaving administrator
created keys that other machines use (for example a key baked into a golden
image or a Browser Guard ingest key), those keys stop working when the person
is deprovisioned. On the API keys page (`/api-keys`) review the keys that person
created, and re-issue any shared key under a service owner first.

## What stays on the person's machine

Revoking credentials stops the machine talking to the control plane. It does not
erase what is already on the disk:

| On the endpoint | Where | What to do |
| --- | --- | --- |
| Local audit log (verdicts, hashed artifacts) | `~/.singularity-aidr/audit*.jsonl` (`aidr audit tail` shows the path) | Collect it first if you need it: `aidr support-bundle` or `aidr audit export`; then delete it with the user profile |
| Operator-recorded approvals, allowlist, exceptions | `~/.singularity-aidr/` | Removed by `aidr uninstall` (without `--keep-data`) |
| The managed API key and enrollment state | `~/.singularity-aidr/managed.json` and the OS secret store | Already useless once revoked; removed by `aidr uninstall` |
| AIDR hook entries in the AI tools' user files | `~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.cursor/hooks.json`, OpenCode/OpenClaw config | Removed by `aidr uninstall` |
| System-wide hooks and the heartbeat task (per-machine installs) | See [hook-tamper-resistance.md](hook-tamper-resistance.md) | Keep them if the machine is reissued to someone else; the next user enrols with their own account |

## Leaving employee: checklist

1. Deactivate the person in the identity provider. When SCIM is not
   connected, remove them on the Team page (`/team`): removing a member revokes
   their API keys too, but their pending approval requests and unused
   enrollment codes only expire on their own.
2. In the dashboard, confirm the audit entry `scim.user.deprovisioned` and that
   the person's agents show no recent activity.
3. Re-issue any shared key the person owned (see above).
4. If the machine is returned: sign in as an administrator, collect the local
   audit log if required, run `aidr uninstall` in the person's profile (or remove
   the profile), and reissue the machine. Per-machine installs keep their
   system-wide hooks for the next user.
5. If the machine is not returned: nothing further is needed for AIDR; its keys
   are revoked. Record the device as lost in your asset process.

## Machine swap (same person, new machine)

1. Install AIDR on the new machine with the same installer (per-machine MSI /
   .deb) and enrol it: the person signs in with the device code, or the
   installer enrols it with a fleet enrollment key.
2. Confirm in the dashboard that the new agent reports a heartbeat and its
   connectors are `protected`.
3. On the old machine run `aidr uninstall`, or in the dashboard revoke the old
   device's key on the API keys page (`/api-keys`).
   The old agent then raises `agent.offline` once and stops; delete it from the
   agent list when it is no longer needed.
4. Pending approvals on the old machine expire on their own (at most 31 minutes).

## Türkçe özet (kontrol listesi)

**Çalışan ayrıldığında**

1. Kişiyi kimlik sağlayıcısında (IdP) devre dışı bırakın. SCIM bağlı değilse
   Ekip sayfasından (`/team`) çıkarın; üyelikten çıkarma API anahtarlarını da
   iptal eder, bekleyen onaylar ve kayıt kodları ise kendi süresiyle dolar.
2. SCIM ile devre dışı bırakma aynı anda şunları yapar: kişinin bu kiracıdaki tüm
   API anahtarlarını (cihaz anahtarları dahil) iptal eder, bekleyen onay
   isteklerini sona erdirir, kullanılmamış kayıt kodlarını ve açık cihaz
   oturumlarını geçersiz kılar, denetim kaydına `scim.user.deprovisioned`
   yazar. Kişi IdP'de yeniden etkinleştirilse bile iptal edilen anahtar geri
   gelmez; cihaz yeniden kaydedilir.
3. Elle oluşturulmuş üyelik (SCIM öncesi davet) korunur; üyeliğin yalnızca
   dizinden gelmesini istiyorsanız SCIM sayfasında (`/scim`) dizin yetkili
   modunu açın.
4. Ayrılan yöneticinin oluşturduğu ve başka makinelerin kullandığı ortak
   anahtarları önceden bir hizmet sahibi adına yeniden çıkarın.
5. Makine iade edilirse: gerekiyorsa yerel denetim kaydını toplayın
   (`aidr support-bundle`), kullanıcı profilinde `aidr uninstall` çalıştırın,
   makineyi yeniden dağıtın.

**Makine değişimi**

1. Yeni makineye aynı kurulum paketini kurun ve kaydedin.
2. Panelde yeni ajanın sinyal gönderdiğini ve bağlayıcılarının `protected`
   olduğunu doğrulayın.
3. Eski makinede `aidr uninstall` çalıştırın ya da API anahtarları sayfasından
   (`/api-keys`) eski cihaz anahtarını iptal edin; eski ajan bir kez "çevrim
   dışı" uyarısı verir.

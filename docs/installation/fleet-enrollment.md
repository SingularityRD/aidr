# Fleet enrollment keys (many machines, one key)

[Türkçe](fleet-enrollment.tr.md)

A single-use enrollment code connects one computer. To connect hundreds of
Windows and Linux machines from an MSI rollout, Intune, GPO or Ansible, create
one **fleet enrollment key** and put it in the machine policy. Each machine
then enrolls itself the first time AIDR runs, with no browser step and no
per-machine code.

| | Single-use enrollment code | Fleet enrollment key |
|---|---|---|
| Prefix | `aidr_enroll_` | `aidr_fleet_` |
| Uses | one computer | up to the key's machine limit |
| Lifetime | hours (default 24) | 30, 90, 180 or 365 days |
| Who creates it | owner, admin or member | owner or admin only |
| Revocable | delete before use | revoke at any time |
| Enrollment rate limit | 30 per minute per person | 600 per minute per key (configurable) |

The enrollment endpoint (`/v1/enroll`) accepts a fleet key wherever it accepts
an enrollment code. Your licensed seat limit still applies to every machine.

## Create a key

1. Sign in to the dashboard as an **owner or admin** and select the team.
2. Open **API keys**, then **Fleet enrollment keys**.
3. Enter a label (for example `finance-laptops`), the **maximum new machines**
   this key may enroll (1 to 100,000) and a lifetime.
4. Select **Create fleet key** and copy the key. It is shown **once**; only a
   SHA-256 hash and its last four characters are stored.

The list shows, for each key, the last four characters, machines enrolled
against the limit, total uses, expiry and status (`active`, `limit reached`,
`expired`, `revoked`). **Revoke** asks for a second confirmation.

## Put the key in machine policy

Endpoints read two values from machine policy. Users cannot change machine
policy, and it wins over their own configuration.

| Value | Meaning |
|---|---|
| `control_plane_url` | Your control plane, for example `https://aidr.example.com` |
| `enrollment_key` | The fleet key, `aidr_fleet_…` |

Machine policy also carries `ca_file`, `https_proxy`, `no_proxy` and the other
keys described in the configuration reference.

### Windows: registry (`HKLM\SOFTWARE\Policies\Singularity AIDR`)

Both values are strings (`REG_SZ`). Run as an administrator or as SYSTEM:

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Singularity AIDR'
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name control_plane_url -Value 'https://aidr.example.com'
Set-ItemProperty -Path $path -Name enrollment_key -Value $env:AIDR_FLEET_KEY
```

- **MSI rollout (SCCM/ConfigMgr, PDQ, scripts):** write the policy in the same
  deployment step, before or after
  `msiexec /i singularity-aidr-<version>-windows-x64.msi /qn`. The installer
  does not need the key on its command line, so the key never appears in the
  msiexec log.
- **Intune:** deploy the script above as a platform script (run as system,
  64-bit PowerShell) or as part of the Win32 app's install command, and keep
  the key in the script, not in the app's visible command line. Assign it to
  the same device group as the AIDR app.
- **GPO:** Computer Configuration → Preferences → Windows Settings → Registry,
  action *Update*, hive `HKEY_LOCAL_MACHINE`, key
  `SOFTWARE\Policies\Singularity AIDR`, two `REG_SZ` values.

### Linux: `/etc/singularity-aidr/managed.json`

The file must be owned by root and not writable by users:

```json
{
  "control_plane_url": "https://aidr.example.com",
  "enrollment_key": "aidr_fleet_…"
}
```

Ansible example (keep the key in Ansible Vault):

```yaml
- name: Singularity AIDR machine policy
  hosts: developer_workstations
  become: true
  tasks:
    - name: Policy directory
      ansible.builtin.file:
        path: /etc/singularity-aidr
        state: directory
        owner: root
        group: root
        mode: "0755"
    - name: Machine policy with the fleet enrollment key
      ansible.builtin.copy:
        dest: /etc/singularity-aidr/managed.json
        owner: root
        group: root
        mode: "0644"
        content: "{{ {'control_plane_url': aidr_control_plane_url, 'enrollment_key': aidr_fleet_key} | to_nice_json }}"
      no_log: true
    - name: AIDR package
      ansible.builtin.package:
        name: singularity-aidr
        state: present
```

## What counts against the limit

- Each enrollment registers an **AIDR installation ID** (today each user
  profile on a machine has its own). A new installation uses one place in the
  key's limit and one seat.
- Re-enrolling an installation the team already knows (a retry, a re-run of
  your deployment) uses neither; it only increases the key's use count.
- When the key's limit is reached, new machines get `409 fleet_key_exhausted`;
  create another key or raise the limit with a new key. When the team's seats
  are used up, they get `402 agent_limit_exceeded`, whatever the key's limit.
- More than 600 enrollments per minute on one key answer `429 rate_limited`
  with `retry_after_seconds`; the endpoint retries later.

## Security notes

- **Anyone who can read the machine policy can read the key.** Registry
  policies and `managed.json` are readable by local users. The key cannot read
  data or act as a user; it can only enroll new installations into your team,
  within its limit and lifetime. Keep the limit close to the fleet size, use a
  short lifetime for a rollout window, use separate keys per department or
  site, and revoke a key when the rollout ends.
- **Revoking a key stops new enrollments only.** Machines it already enrolled
  keep their own per-machine API keys until you revoke those.
- **A key acts for the admin who created it.** If that person is removed from
  the team, the key stops working, and the per-machine API keys it issued are
  revoked with that person's other keys. If they lose the owner/admin role,
  the key stops working. Create fleet keys from an administrator account that
  outlives individual staff changes.
- Every issue, revoke and enrollment writes an audit entry
  (`fleet_key.create`, `fleet_key.revoke`, `fleet_key.enroll`) in the same
  transaction; if the audit entry cannot be written, nothing changes.

## For operators

`/v1/enroll` reads `AIDR_ENROLL_FLEET_RL_PER_MIN` (default `600`, range
`1..100000`) for the per-key budget; an invalid value answers
`503 enrollment_rate_limit_config_invalid` instead of disabling the limit.
`/v1/fleet-keys` reads `AIDR_FLEETKEY_CREATE_RL_PER_MIN` (default `10`) for
key creation per admin per minute. Each team can hold at most 50 active fleet
keys. Schema: `supabase/migrations/20261014000210_fleet_enrollment_keys.sql`.

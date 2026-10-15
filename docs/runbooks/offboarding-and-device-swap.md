# Leaving employees and machine swaps

For the customer's IT administrator. Covers three cases: an employee leaves, an
employee gets a new or reinstalled machine, and a machine is handed to another
person. [Türkçe özet aşağıda](#türkçe-özet).

What exists per person and per machine:

| Item | Where | Removed by |
|---|---|---|
| Dashboard account and role (only for people who use the dashboard) | Control plane (`tenant_members`) | IdP + SCIM deprovisioning, or removal in **Team** |
| Enrolled device: installation ID, device API key, entitlement snapshot, seat | Control plane (Agents) | Device revocation (below); **not** by SCIM in this release |
| Local state: config, audit log, approval store, approval key in the OS vault | The machine, under the user's profile (`~/.singularity-aidr`) | `aidr uninstall` or profile deletion |
| Events, incidents and audit records about the person | Control plane | Retention schedule; not deleted at offboarding unless requested ([KVKK guide](../operations/kvkk.md)) |

## Employee leaves

1. **Identity.** Disable the user in the IdP. With SCIM, the dashboard account
   is deactivated and the membership reconciled automatically; without SCIM,
   remove the person in **Team**. Check the admin audit log for the change.
2. **Pending approvals.** If the person was an approver, make sure another
   approver covers their policies; if the person had pending `ask` requests,
   they expire on their own and need no action.
3. **Devices.** SCIM deprovisioning does **not** revoke the person's enrolled
   devices in this release. For each of the person's devices on **Agents**:
   - if your release offers a retire/revoke action on the device page, use it
     (it revokes the device credential and releases the seat);
   - otherwise revoke the device's API key on **API Keys** (the key the device
     received at enrollment; match it by creation time and the device listed
     on Agents) and record the device ID in the offboarding ticket.
   A revoked device keeps enforcing local detection with its last policy; it
   stops sending events and receiving managed policy.
4. **Seat.** Check the Agents count against the licence after revocation. If
   the seat is still counted, raise it with support with the device ID; do not
   edit the database.
5. **Machine.** If the machine is wiped or reimaged, nothing else is needed on
   it. If it is kept (for example given to someone else), follow
   [machine handed to another person](#machine-handed-to-another-person).
6. **Local audit records.** They are on the machine, not in the control plane.
   If they must be kept (investigation, legal hold), copy
   `~/.singularity-aidr/audit.jsonl*` (and `response-audit.jsonl` if used) to
   the case store **before** the machine is wiped, record the SHA-256 of each
   file, and verify signed chains with `aidr audit verify`. Otherwise they are
   deleted with the profile.
7. **Records about the person** stay under the tenant retention schedule. Delete
   earlier only on a documented request and when no legal hold applies.

## New or reinstalled machine for the same person

1. Install AIDR on the new machine (installer or managed deployment) and enroll
   it. It gets a new installation ID and uses a seat.
2. Revoke the old device as in step 3 above, so that it does not keep a seat.
3. If the old machine is still in use during the overlap, both devices count;
   revoke the old one as soon as it is returned.
4. Local allowlists and approvals do not move with the person; managed policy
   and exceptions do (they are in the control plane). Ask the person to rerun
   any approved one-off action if needed.
5. In VDI or containers, avoid this case altogether by persisting the AIDR
   state ([install recipes](../installation/special-environments.md)).

## Machine handed to another person

1. As the previous user (or as administrator for that profile):
   `aidr uninstall --yes` with `AIDR_OPERATOR_NONINTERACTIVE=1` removes the
   connectors, managed hooks, `~/.singularity-aidr` and the vault items for
   that profile; keep a copy of the audit log first if step 6 above applies.
   Fleet tooling can do the same for many profiles
   ([Windows](../../deploy/fleet/windows/README.md), [Linux](../../deploy/fleet/linux/README.md)).
2. Revoke the old device in the dashboard.
3. The new user signs in; Active Setup (Windows) or `aidr setup` (Linux) runs for
   the new profile and the device enrolls as a new device.

## Checklist for the offboarding ticket

- [ ] IdP account disabled; dashboard access gone (audit log entry)
- [ ] Approver coverage reassigned
- [ ] Every device of the person revoked; device IDs listed
- [ ] Seat count checked
- [ ] Local audit logs preserved (with SHA-256) or knowingly discarded
- [ ] Machine wiped, or profile removed with `aidr uninstall`

## Türkçe özet

**İşten ayrılan çalışan:** IdP'de hesabı kapatın (SCIM varsa panel erişimi
kendiliğinden kalkar, yoksa **Ekip** sayfasından kaldırın). Bu sürümde SCIM
kişinin kayıtlı **cihazlarını iptal etmez**: **Ajanlar** sayfasında kişinin her
cihazı için, sürümünüzde varsa cihazı emekliye ayırma/iptal eylemini kullanın;
yoksa cihazın kayıtta aldığı API anahtarını **API Anahtarları** sayfasından iptal
edin ve cihaz kimliğini kayda yazın. İptal edilen cihaz yerel tespitle korumaya
devam eder, olay göndermez. Koltuk sayısını kontrol edin. Yerel denetim kaydı
makinededir: saklanması gerekiyorsa makine silinmeden önce `audit.jsonl*`
dosyalarını SHA-256 değerleriyle olay deposuna kopyalayın. **Aynı kişiye yeni
makine:** yenisini kurup kaydedin, eskisini iptal edin. **Makine başkasına
veriliyorsa:** eski profilde `aidr uninstall` (önce gerekiyorsa kayıtları
kopyalayın), panelde eski cihazı iptal edin, yeni kullanıcının oturumunda kurulum
kendiliğinden çalışır.

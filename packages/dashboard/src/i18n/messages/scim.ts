import type { MessagePairs } from "./define";

/** SCIM directory provisioning page. */
export const scimMessages = {
	"scim.err.owner": [
		"Only an active tenant owner can view or manage directory provisioning.",
		"Dizin sağlamayı yalnızca etkin bir çalışma alanı sahibi görebilir ya da yönetebilir.",
	],
	"scim.err.directoryRequired": [
		"Enter the directory identifier this credential provisions for. Legacy credentials must be bound when rotated.",
		"Bu kimlik bilgisinin sağladığı dizinin tanımlayıcısını girin. Eski kimlik bilgileri yenilenirken bir dizine bağlanmalıdır.",
	],
	"scim.err.directoryMismatch": [
		"A rotation keeps its credential's directory. Leave the directory identifier empty or use the same one.",
		"Yenileme, kimlik bilgisinin dizinini korur. Dizin tanımlayıcısını boş bırakın ya da aynısını kullanın.",
	],
	"scim.err.notAuthoritative": [
		"Directory-authoritative mode is on. Only the configured directory can receive credentials.",
		"Dizinin belirlediği üyelik modu açık. Yalnızca yapılandırılmış dizin kimlik bilgisi alabilir.",
	],
	"scim.err.alreadyOn": [
		"Directory-authoritative mode is already on. Refresh to see its configuration.",
		"Dizinin belirlediği üyelik modu zaten açık. Yapılandırmasını görmek için yenileyin.",
	],
	"scim.err.tokenRequired": [
		"Create an active credential for this directory before making it authoritative.",
		"Bu dizini yetkili yapmadan önce onun için etkin bir kimlik bilgisi oluşturun.",
	],
	"scim.err.foreignToken": [
		"Revoke every active credential for other directories (including unbound legacy credentials) first.",
		"Önce diğer dizinlere ait tüm etkin kimlik bilgilerini (bağlanmamış eski kimlik bilgileri dahil) iptal edin.",
	],
	"scim.err.adoptionAmbiguous": [
		"Credentials for another directory existed, so existing SCIM memberships cannot be attributed to this directory. Leave adoption off and let the directory re-provision them.",
		"Başka bir dizin için kimlik bilgileri vardı; bu yüzden mevcut SCIM üyelikleri bu dizine atfedilemez. Devralmayı kapalı bırakın ve dizinin onları yeniden sağlamasına izin verin.",
	],
	"scim.err.breakGlassMismatch": [
		"Every active owner must be listed as a break-glass account (at most two). Remove or demote extra owners first, then refresh.",
		"Her etkin sahip bir acil durum hesabı olarak listelenmelidir (en fazla iki). Önce fazla sahipleri çıkarın ya da rollerini düşürün, sonra yenileyin.",
	],
	"scim.err.breakGlassInvalid": [
		"A break-glass owner is unavailable or directory-provisioned. Use active, manually managed owner accounts.",
		"Bir acil durum sahibi kullanılamıyor ya da dizin tarafından sağlanmış. Etkin ve elle yönetilen sahip hesapları kullanın.",
	],
	"scim.err.noAdmins": [
		"Enabling would leave no owner or admin with access. No change was made.",
		"Açmak, erişimi olan hiçbir sahip ya da yönetici bırakmaz. Hiçbir değişiklik yapılmadı.",
	],
	"scim.err.unsupported": [
		"Directory-authoritative mode is available only for active team workspaces.",
		"Dizinin belirlediği üyelik modu yalnızca etkin ekip çalışma alanlarında kullanılabilir.",
	],
	"scim.err.membershipRequired": [
		"That change would give access to someone the configured directory does not provision.",
		"Bu değişiklik, yapılandırılmış dizinin sağlamadığı birine erişim verirdi.",
	],
	"scim.err.breakGlassOwner": [
		"At least one break-glass owner must keep owner access while the mode is on.",
		"Mod açıkken en az bir acil durum sahibi sahip erişimini korumalıdır.",
	],
	"scim.err.assurance": [
		"Multi-factor status could not be verified. No change was confirmed.",
		"Çok adımlı doğrulama durumu doğrulanamadı. Hiçbir değişiklik onaylanmadı.",
	],
	"scim.err.manualConflict": [
		"This group would take over a manually assigned team membership. Resolve that membership explicitly, then retry.",
		"Bu grup elle atanmış bir ekip üyeliğini devralırdı. Önce o üyeliği açıkça çözün, sonra yeniden deneyin.",
	],
	"scim.err.tokenInactive": [
		"The selected credential is no longer active. Refresh the list and retry.",
		"Seçilen kimlik bilgisi artık etkin değil. Listeyi yenileyip yeniden deneyin.",
	],
	"scim.err.tokenRevoked": [
		"The credential is already revoked or no longer exists.",
		"Kimlik bilgisi zaten iptal edilmiş ya da artık yok.",
	],
	"scim.err.mappingMissing": [
		"The group mapping no longer exists. Refresh the list and retry.",
		"Grup eşlemesi artık yok. Listeyi yenileyip yeniden deneyin.",
	],
	"scim.err.conflict": [
		"A conflicting directory resource already exists. Refresh the list and review it before retrying.",
		"Çakışan bir dizin kaynağı zaten var. Yeniden denemeden önce listeyi yenileyip inceleyin.",
	],
	"scim.err.invalid": [
		"The request was rejected. Check the selected role, label, and exact group identifier.",
		"İstek reddedildi. Seçilen rolü, etiketi ve tam grup tanımlayıcısını kontrol edin.",
	],
	"scim.err.unavailable": [
		"Directory management is temporarily unavailable. No change was confirmed.",
		"Dizin yönetimi geçici olarak kullanılamıyor. Hiçbir değişiklik onaylanmadı.",
	],
	"scim.err.invalidMode": [
		"Directory management returned an invalid membership mode.",
		"Dizin yönetimi geçersiz bir üyelik modu döndürdü.",
	],
	"scim.err.invalidResponse": [
		"Directory management returned an invalid response.",
		"Dizin yönetimi geçersiz bir yanıt döndürdü.",
	],
	"scim.err.invalidRecord": [
		"Directory management returned an invalid record.",
		"Dizin yönetimi geçersiz bir kayıt döndürdü.",
	],
	"scim.err.invalidCursor": [
		"Directory management returned an invalid pagination cursor.",
		"Dizin yönetimi geçersiz bir sayfalama imleci döndürdü.",
	],
	"scim.err.unmanagedOne": [
		"1 active member is not provisioned by this directory. Adopt existing SCIM memberships, or explicitly choose to remove unprovisioned members, then retry. No change was made.",
		"1 etkin üye bu dizin tarafından sağlanmıyor. Mevcut SCIM üyeliklerini devralın ya da sağlanmayan üyeleri çıkarmayı açıkça seçin, sonra yeniden deneyin. Hiçbir değişiklik yapılmadı.",
	],
	"scim.err.unmanagedMany": [
		"{count} active members are not provisioned by this directory. Adopt existing SCIM memberships, or explicitly choose to remove unprovisioned members, then retry. No change was made.",
		"{count} etkin üye bu dizin tarafından sağlanmıyor. Mevcut SCIM üyeliklerini devralın ya da sağlanmayan üyeleri çıkarmayı açıkça seçin, sonra yeniden deneyin. Hiçbir değişiklik yapılmadı.",
	],
	"scim.err.unmanagedSome": [
		"Some active members are not provisioned by this directory. Adopt existing SCIM memberships, or explicitly choose to remove unprovisioned members, then retry. No change was made.",
		"Bazı etkin üyeler bu dizin tarafından sağlanmıyor. Mevcut SCIM üyeliklerini devralın ya da sağlanmayan üyeleri çıkarmayı açıkça seçin, sonra yeniden deneyin. Hiçbir değişiklik yapılmadı.",
	],
	"scim.never": ["Never", "Hiç"],
	"scim.invalidDirectory": [
		"Enter the directory identifier (1–128 letters, digits, dot, underscore, colon or hyphen; starting with a letter or digit).",
		"Dizin tanımlayıcısını girin (1–128 harf, rakam, nokta, alt çizgi, iki nokta ya da tire; harf ya da rakamla başlamalı).",
	],
	"scim.unbound": ["Unbound (legacy)", "Bağlanmamış (eski)"],
	"scim.removedOne": ["1 unprovisioned member was removed. ", "Sağlanmayan 1 üye çıkarıldı. "],
	"scim.removedMany": [
		"{count} unprovisioned members were removed. ",
		"Sağlanmayan {count} üye çıkarıldı. ",
	],
	"scim.enabledNotice": [
		"Directory-authoritative mode is on for {directory}. {removal}Only memberships this directory provisions, and the break-glass owners, grant access.",
		"{directory} için dizinin belirlediği üyelik modu açık. {removal}Yalnızca bu dizinin sağladığı üyelikler ve acil durum sahipleri erişim verir.",
	],
	"scim.selectTenant": [
		"Select a tenant to manage directory provisioning.",
		"Dizin sağlamayı yönetmek için bir çalışma alanı seçin.",
	],
	"scim.loadFailed": ["Unable to load directory settings.", "Dizin ayarları yüklenemedi."],
	"scim.labelRequired": [
		"Enter a descriptive credential label.",
		"Açıklayıcı bir kimlik bilgisi etiketi girin.",
	],
	"scim.createUnconfirmed": [
		"Credential creation was not confirmed.",
		"Kimlik bilgisi oluşturma onaylanmadı.",
	],
	"scim.invalidSecret": [
		"The credential service returned an invalid one-time secret response.",
		"Kimlik bilgisi hizmeti geçersiz bir tek seferlik gizli değer yanıtı döndürdü.",
	],
	"scim.rotated": [
		"Replacement created. The previous credential remains valid; verify the new secret with your provider, then revoke the old credential.",
		"Yenisi oluşturuldu. Önceki kimlik bilgisi geçerliliğini korur; yeni gizli değeri sağlayıcınızda doğrulayın, sonra eskisini iptal edin.",
	],
	"scim.created": [
		"Credential created. Copy it into your approved secret manager now; it cannot be shown again.",
		"Kimlik bilgisi oluşturuldu. Şimdi onaylı gizli değer yöneticinize kopyalayın; bir daha gösterilemez.",
	],
	"scim.mayHaveCommitted": [
		"{message} The request may have reached AIDR before the connection failed. If a new active credential is listed but its secret was not shown, revoke it before retrying.",
		"{message} İstek, bağlantı kopmadan önce AIDR'ye ulaşmış olabilir. Listede yeni bir etkin kimlik bilgisi varsa ama gizli değeri gösterilmediyse, yeniden denemeden önce onu iptal edin.",
	],
	"scim.revokeUnconfirmed": [
		"Credential revocation was not confirmed.",
		"Kimlik bilgisi iptali onaylanmadı.",
	],
	"scim.revoked": [
		"Credential revoked. Its secret can no longer provision directory changes.",
		"Kimlik bilgisi iptal edildi. Gizli değeri artık dizin değişikliği sağlayamaz.",
	],
	"scim.enableUnconfirmed": [
		"Directory-authoritative mode was not confirmed.",
		"Dizinin belirlediği üyelik modu onaylanmadı.",
	],
	"scim.disableUnconfirmed": [
		"Disabling directory-authoritative mode was not confirmed.",
		"Dizinin belirlediği üyelik modunun kapatılması onaylanmadı.",
	],
	"scim.disabled": [
		"Directory-authoritative mode is off. Manually added members can be granted access again.",
		"Dizinin belirlediği üyelik modu kapalı. Elle eklenen üyeler yeniden erişim kazanabilir.",
	],
	"scim.modeUnconfirmed": [
		"The membership mode change was not confirmed.",
		"Üyelik modu değişikliği onaylanmadı.",
	],
	"scim.modeMayHaveChanged": [
		"{message} Refresh shows the current mode; it may have changed before the connection failed.",
		"{message} Yenileme geçerli modu gösterir; bağlantı kopmadan önce değişmiş olabilir.",
	],
	"scim.badGroup": [
		"Enter the exact immutable SCIM Group.externalId (1–255 characters, without surrounding whitespace or control characters).",
		"SCIM Group.externalId değerini tam ve değişmez haliyle girin (1–255 karakter, başta/sonda boşluk ya da kontrol karakteri olmadan).",
	],
	"scim.mappingUnconfirmed": [
		"Group-role mapping was not confirmed.",
		"Grup-rol eşlemesi onaylanmadı.",
	],
	"scim.mappingSaved": [
		"Group-role mapping saved. Only the exact immutable external ID is used; SCIM cannot grant owner.",
		"Grup-rol eşlemesi kaydedildi. Yalnızca tam ve değişmez dış kimlik kullanılır; SCIM sahip rolü veremez.",
	],
	"scim.removeUnconfirmed": [
		"Group-role mapping removal was not confirmed.",
		"Grup-rol eşlemesinin kaldırılması onaylanmadı.",
	],
	"scim.mappingRemoved": [
		"Group-role mapping removed. SCIM-managed memberships were reconciled by the service.",
		"Grup-rol eşlemesi kaldırıldı. SCIM ile yönetilen üyelikler hizmet tarafından uzlaştırıldı.",
	],
	"scim.title": ["Directory provisioning", "Dizin sağlama"],
	"scim.ownersOnly": [
		"SCIM credentials and group-role mappings are available to active tenant owners only.",
		"SCIM kimlik bilgileri ve grup-rol eşlemeleri yalnızca etkin çalışma alanı sahipleri içindir.",
	],
	"scim.lead": [
		"Configure inbound SCIM for {team}. The service verifies owner access on every request.",
		"{team} için gelen SCIM'i yapılandırın. Hizmet her istekte sahip erişimini doğrular.",
	],
	"scim.leadSaml": [
		"SCIM provisions users and roles. SAML sign-in enforcement is managed separately below, with approval from two owners.",
		"SCIM kullanıcıları ve rolleri sağlar. SAML ile oturum açma zorunluluğu aşağıda, iki sahibin onayıyla ayrıca yönetilir.",
	],
	"scim.credentials": ["Provisioning credentials", "Sağlama kimlik bilgileri"],
	"scim.credentialsLead": [
		"New credentials expire after 90 days by default. Rotation keeps the previous credential active until you verify the replacement and revoke the old one.",
		"Yeni kimlik bilgilerinin süresi varsayılan olarak 90 gün sonra dolar. Yenileme, yenisini doğrulayıp eskisini iptal edene kadar önceki kimlik bilgisini etkin tutar.",
	],
	"scim.credentialLabel": ["Credential label", "Kimlik bilgisi etiketi"],
	"scim.directoryId": ["Directory identifier", "Dizin tanımlayıcısı"],
	"scim.directoryHelp": [
		"A stable name for the identity directory this credential provisions from. It is recorded on the credential and cannot be changed. Rotations keep it; enter it only to bind an unbound legacy credential when rotating.",
		"Bu kimlik bilgisinin sağladığı kimlik dizini için kalıcı bir ad. Kimlik bilgisine kaydedilir ve değiştirilemez. Yenilemeler bunu korur; yalnızca bağlanmamış eski bir kimlik bilgisini yenilerken bağlamak için girin.",
	],
	"scim.create": ["Create credential", "Kimlik bilgisi oluştur"],
	"scim.copyNow": ["Copy this credential now", "Bu kimlik bilgisini şimdi kopyalayın"],
	"scim.shownOnce": [
		"Shown once. Store it only in your approved secret manager and configure the IdP with that value. Expires {time}.",
		"Yalnızca bir kez gösterilir. Yalnızca onaylı gizli değer yöneticinizde saklayın ve kimlik sağlayıcıyı bu değerle yapılandırın. Sona erme: {time}.",
	],
	"scim.newCredential": ["New SCIM credential", "Yeni SCIM kimlik bilgisi"],
	"scim.hide": ["Hide", "Gizle"],
	"scim.reveal": ["Reveal", "Göster"],
	"scim.clipboard": [
		"Clipboard access was blocked. Reveal the credential and copy it manually.",
		"Panoya erişim engellendi. Kimlik bilgisini gösterip elle kopyalayın.",
	],
	"scim.copied": ["Copied", "Kopyalandı"],
	"scim.copy": ["Copy", "Kopyala"],
	"scim.clearSecret": ["Clear secret", "Gizli değeri temizle"],
	"scim.loadingCredentials": ["Loading credentials…", "Kimlik bilgileri yükleniyor…"],
	"scim.noCredentials": [
		"No SCIM credentials have been issued.",
		"Henüz SCIM kimlik bilgisi verilmedi.",
	],
	"scim.credentialsCaption": ["SCIM provisioning credentials", "SCIM sağlama kimlik bilgileri"],
	"scim.col.label": ["Label", "Etiket"],
	"scim.col.directory": ["Directory", "Dizin"],
	"scim.col.expires": ["Expires", "Sona erme"],
	"scim.col.lastUsed": ["Last used", "Son kullanım"],
	"scim.col.actions": ["Actions", "İşlemler"],
	"scim.revokedState": ["Revoked", "İptal edildi"],
	"scim.activeState": ["Active", "Etkin"],
	"scim.expiredState": ["Expired", "Süresi doldu"],
	"scim.rotate": ["Rotate", "Yenile"],
	"scim.revoke": ["Revoke", "İptal et"],
	"scim.revokeConfirm": ["Revoke permanently?", "Kalıcı olarak iptal edilsin mi?"],
	"scim.confirmRevoke": ["Confirm revoke", "İptali onayla"],
	"scim.mappings": ["Group-to-role mappings", "Gruptan role eşlemeler"],
	"scim.mappingsLead": [
		"Use the exact immutable SCIM {field}; display names and user metadata never grant roles. SCIM cannot grant owner.",
		"SCIM {field} değerini tam ve değişmez haliyle kullanın; görünen adlar ve kullanıcı meta verileri asla rol vermez. SCIM sahip rolü veremez.",
	],
	"scim.groupId": ["Exact external group ID", "Tam dış grup kimliği"],
	"scim.groupPlaceholder": ["Immutable Group.externalId", "Değişmez Group.externalId"],
	"scim.role": ["AIDR role", "AIDR rolü"],
	"scim.saveMapping": ["Save mapping", "Eşlemeyi kaydet"],
	"scim.clear": ["Clear", "Temizle"],
	"scim.loadingMappings": ["Loading mappings…", "Eşlemeler yükleniyor…"],
	"scim.noMappings": [
		"No group-role mappings have been configured.",
		"Henüz grup-rol eşlemesi yapılandırılmadı.",
	],
	"scim.mappingsCaption": ["SCIM group-role mappings", "SCIM grup-rol eşlemeleri"],
	"scim.edit": ["Edit", "Düzenle"],
	"scim.remove": ["Remove", "Kaldır"],
	"scim.removeConfirm": ["Remove mapping?", "Eşleme kaldırılsın mı?"],
	"scim.confirmRemove": ["Confirm remove", "Kaldırmayı onayla"],
	"scim.loadMore": ["Load more", "Daha fazla yükle"],
} as const satisfies MessagePairs<string>;

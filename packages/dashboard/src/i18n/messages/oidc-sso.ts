import type { MessagePairs } from "./define";

/** OIDC single sign-on settings page. */
export const oidcSsoMessages = {
	"sso.err.owner": [
		"Only an active tenant owner can manage single sign-on.",
		"Tek oturum açmayı yalnızca etkin bir çalışma alanı sahibi yönetebilir.",
	],
	"sso.err.mfa": [
		"Complete multi-factor verification (AAL2) to change single sign-on settings.",
		"Tek oturum açma ayarlarını değiştirmek için çok adımlı doğrulamayı (AAL2) tamamlayın.",
	],
	"sso.err.provider": [
		"The provider settings were rejected. Check each field.",
		"Sağlayıcı ayarları reddedildi. Her alanı kontrol edin.",
	],
	"sso.err.discovery": [
		"The identity provider's discovery document could not be fetched or validated.",
		"Kimlik sağlayıcının keşif belgesi alınamadı ya da doğrulanamadı.",
	],
	"sso.err.secret": [
		"The client secret is not configured in the Edge function secrets yet.",
		"İstemci gizli anahtarı henüz Edge function gizli değerlerinde yapılandırılmamış.",
	],
	"sso.err.locked": [
		"Disable enforcement before changing the provider.",
		"Sağlayıcıyı değiştirmeden önce zorunluluğu kapatın.",
	],
	"sso.err.changed": [
		"The provider was changed by someone else while discovery was refreshing. Reload and try again.",
		"Keşif yenilenirken sağlayıcı başka biri tarafından değiştirildi. Sayfayı yenileyip yeniden deneyin.",
	],
	"sso.err.domain": [
		"Enter a valid domain such as example.com.",
		"example.com gibi geçerli bir alan adı girin.",
	],
	"sso.err.dns": [
		"The verification record could not be looked up yet. DNS changes can take time.",
		"Doğrulama kaydı henüz sorgulanamadı. DNS değişiklikleri zaman alabilir.",
	],
	"sso.err.recordMissing": [
		"The verification record was not found. Check the name and value.",
		"Doğrulama kaydı bulunamadı. Adı ve değeri kontrol edin.",
	],
	"sso.err.otherTenant": [
		"Another workspace has already verified this domain.",
		"Bu alan adını başka bir çalışma alanı zaten doğruladı.",
	],
	"sso.err.lastDomain": [
		"Disable enforcement before removing the last verified domain.",
		"Son doğrulanmış alan adını kaldırmadan önce zorunluluğu kapatın.",
	],
	"sso.err.owners": [
		"Every owner must link an identity first, and at least two owners are required.",
		"Önce her sahip bir kimlik bağlamalıdır ve en az iki sahip gerekir.",
	],
	"sso.err.actorSession": [
		"Sign in through single sign-on first, so enforcement cannot lock you out.",
		"Zorunluluk sizi dışarıda bırakmasın diye önce tek oturum açmayla oturum açın.",
	],
	"sso.err.identityConflict": [
		"Some provisioned users are bound to other accounts. They must link their identity first.",
		"Sağlanan bazı kullanıcılar başka hesaplara bağlı. Önce kimliklerini bağlamaları gerekir.",
	],
	"sso.err.saml": [
		"SAML enforcement is active; a tenant cannot enforce both.",
		"SAML zorunluluğu etkin; bir çalışma alanı ikisini birden zorunlu kılamaz.",
	],
	"sso.err.providerDisabled": [
		"The provider must be enabled before it can be enforced.",
		"Zorunlu kılınmadan önce sağlayıcının açılması gerekir.",
	],
	"sso.err.invalid": [
		"The request was rejected. Check the fields.",
		"İstek reddedildi. Alanları kontrol edin.",
	],
	"sso.err.unavailable": [
		"Single sign-on administration is temporarily unavailable. No change was confirmed.",
		"Tek oturum açma yönetimi geçici olarak kullanılamıyor. Hiçbir değişiklik onaylanmadı.",
	],
	"sso.err.notConfirmed": ["The request was not confirmed.", "İstek onaylanmadı."],
	"sso.err.load": [
		"Unable to load single sign-on settings.",
		"Tek oturum açma ayarları yüklenemedi.",
	],
	"sso.hint.entra": [
		"Use your directory (tenant) ID, never common or organizations.",
		"Dizin (tenant) kimliğinizi kullanın; asla common ya da organizations kullanmayın.",
	],
	"sso.hint.okta": [
		"The issuer of the authorization server that issues your ID tokens.",
		"Kimlik belirteçlerinizi üreten yetkilendirme sunucusunun issuer değeri.",
	],
	"sso.hint.generic": [
		"Any OpenID Connect provider with a discovery document, for example Keycloak (https://sso.example.com/realms/<realm>) or ADFS (https://adfs.example.com/adfs).",
		"Keşif belgesi olan herhangi bir OpenID Connect sağlayıcısı; örneğin Keycloak (https://sso.example.com/realms/<realm>) ya da ADFS (https://adfs.example.com/adfs).",
	],
	"sso.selectTenant": [
		"Select a tenant to manage single sign-on.",
		"Tek oturum açmayı yönetmek için bir çalışma alanı seçin.",
	],
	"sso.ownersOnly": [
		"OIDC single sign-on is available to active tenant owners only.",
		"OIDC tek oturum açma yalnızca etkin çalışma alanı sahipleri içindir.",
	],
	"sso.saved": [
		"Provider saved and discovery validated.",
		"Sağlayıcı kaydedildi ve keşif doğrulandı.",
	],
	"sso.title": ["Single sign-on (OIDC)", "Tek oturum açma (OIDC)"],
	"sso.lead": [
		"Configure OpenID Connect sign-in for {team} with Microsoft Entra ID, Okta, Keycloak, ADFS or another provider. Users and roles come from SCIM or, if you turn it on below, from just-in-time provisioning at sign-in.",
		"{team} için Microsoft Entra ID, Okta, Keycloak, ADFS ya da başka bir sağlayıcıyla OpenID Connect oturum açmayı yapılandırın. Kullanıcılar ve roller SCIM'den ya da aşağıda açarsanız oturum açılırken anında hesap oluşturmadan (JIT) gelir.",
	],
	"sso.redirect": [
		"Register this redirect URI at your provider: {uri}",
		"Bu yönlendirme URI'sini sağlayıcınıza kaydedin: {uri}",
	],
	"sso.samlActive": [
		"SAML enforcement is active for this workspace; OIDC cannot be enforced at the same time.",
		"Bu çalışma alanında SAML zorunluluğu etkin; OIDC aynı anda zorunlu kılınamaz.",
	],
	"sso.provider": ["Provider", "Sağlayıcı"],
	"sso.providerType": ["Provider type", "Sağlayıcı türü"],
	"sso.generic": ["Generic OpenID Connect", "Genel OpenID Connect"],
	"sso.displayName": ["Display name", "Görünen ad"],
	"sso.issuer": ["Issuer", "Issuer (yayıncı)"],
	"sso.clientId": ["Client (application) ID", "İstemci (uygulama) kimliği"],
	"sso.clientAuth": ["Client authentication", "İstemci kimlik doğrulaması"],
	"sso.basic": ["Client secret (HTTP Basic)", "İstemci gizli anahtarı (HTTP Basic)"],
	"sso.post": ["Client secret (request body)", "İstemci gizli anahtarı (istek gövdesi)"],
	"sso.none": ["None (public client, PKCE only)", "Yok (açık istemci, yalnızca PKCE)"],
	"sso.secretRef": ["Client secret reference", "İstemci gizli anahtarı başvurusu"],
	"sso.secretHint": [
		"Store the secret as the Edge function secret {name}; it is never saved in the database or shown here.",
		"Gizli anahtarı {name} adlı Edge function gizli değeri olarak saklayın; veritabanına asla kaydedilmez ve burada gösterilmez.",
	],
	"sso.secretMissing": [" It is not configured yet.", " Henüz yapılandırılmamış."],
	"sso.groupsClaim": ["Groups claim (optional)", "Grup claim'i (isteğe bağlı)"],
	"sso.groupRequirement": ["Group requirement", "Grup şartı"],
	"sso.ignoreGroups": [
		"Ignore groups (SCIM or just-in-time provisioning decides access)",
		"Grupları yok say (erişime SCIM ya da anında hesap oluşturma karar verir)",
	],
	"sso.requireGroup": [
		"Require a mapped group (exact group IDs from SCIM mappings)",
		"Eşlenmiş bir grup iste (SCIM eşlemelerindeki tam grup kimlikleri)",
	],
	"sso.enable": ["Enable sign-in", "Oturum açmayı etkinleştir"],
	"sso.save": ["Save and validate", "Kaydet ve doğrula"],
	"sso.domains": ["Verified email domains", "Doğrulanmış e-posta alan adları"],
	"sso.domainsLead": [
		"Sign-in is accepted only for email addresses on a domain this workspace has verified with a DNS TXT record.",
		"Oturum açma yalnızca bu çalışma alanının DNS TXT kaydıyla doğruladığı bir alan adındaki e-posta adresleri için kabul edilir.",
	],
	"sso.verified": ["verified", "doğrulandı"],
	"sso.pending": ["pending", "bekliyor"],
	"sso.domainVerified": ["{domain} verified.", "{domain} doğrulandı."],
	"sso.verifyDomain": ["Verify {domain}", "{domain} doğrula"],
	"sso.domainRemoved": ["{domain} removed.", "{domain} kaldırıldı."],
	"sso.removeDomain": ["Remove {domain}", "{domain} kaldır"],
	"sso.addDomainLabel": ["Add a domain", "Alan adı ekleyin"],
	"sso.domainAdded": [
		"Domain added. Publish the TXT record, then verify.",
		"Alan adı eklendi. TXT kaydını yayımlayın, sonra doğrulayın.",
	],
	"sso.addDomain": ["Add domain", "Alan adı ekle"],
	"sso.enforcement": ["Enforcement", "Zorunluluk"],
	"sso.enforcementLead": [
		"Link your own account first, then have every other owner do the same. Enforcement requires you to be signed in through this provider, at least two linked owners and no unlinked owner. Email, password and other sessions are refused for this workspace once it is on.",
		"Önce kendi hesabınızı bağlayın, sonra diğer her sahibin de aynısını yapmasını sağlayın. Zorunluluk için bu sağlayıcıyla oturum açmış olmanız, en az iki bağlı sahip olması ve bağlanmamış sahip kalmaması gerekir. Açıldıktan sonra bu çalışma alanı için e-posta, parola ve diğer oturumlar reddedilir.",
	],
	"sso.redirecting": [
		"Redirecting to your identity provider…",
		"Kimlik sağlayıcınıza yönlendiriliyorsunuz…",
	],
	"sso.link": ["Link my account", "Hesabımı bağla"],
	"sso.changeRef": ["Change reference", "Değişiklik başvurusu"],
	"sso.disabled": ["Enforcement disabled.", "Zorunluluk kapatıldı."],
	"sso.disable": ["Disable enforcement", "Zorunluluğu kapat"],
	"sso.enabled": ["Enforcement enabled.", "Zorunluluk açıldı."],
	"sso.enforce": ["Enforce single sign-on", "Tek oturum açmayı zorunlu kıl"],
	"sso.breakGlassOn": [
		"Break-glass: enabled. An owner's single-use recovery code can suspend enforcement if the identity provider is unavailable.",
		"Acil durum erişimi: açık. Kimlik sağlayıcı kullanılamazsa bir sahibin tek kullanımlık kurtarma kodu zorunluluğu askıya alabilir.",
	],
	"sso.breakGlassOff": [
		"Break-glass: disabled. Enable break-glass recovery in identity policy before enforcing, so an identity provider outage is recoverable.",
		"Acil durum erişimi: kapalı. Kimlik sağlayıcı kesintisinden kurtulabilmek için zorunlu kılmadan önce kimlik politikasında acil durum kurtarmasını açın.",
	],
	"sso.extraScopes": ["Extra scopes (optional)", "Ek kapsamlar (isteğe bağlı)"],
	"sso.extraScopesHint": [
		"Only allatclaims (ADFS, needed for group claims in the ID token), groups (Okta) or roles (Keycloak). Leave empty otherwise.",
		"Yalnızca allatclaims (ADFS; kimlik belirtecinde grup claim'leri için gerekir), groups (Okta) ya da roles (Keycloak). Aksi halde boş bırakın.",
	],
	"sso.jit.title": ["Just-in-time provisioning", "Anında hesap oluşturma (JIT)"],
	"sso.jit.lead": [
		"Without SCIM, create the AIDR membership when a user first signs in. The role comes from the user's groups in the identity provider; a user whose groups no longer map loses access at the next sign-in. SCIM-provisioned users are never managed here.",
		"SCIM olmadan, kullanıcı ilk kez oturum açtığında AIDR üyeliğini oluşturun. Rol, kullanıcının kimlik sağlayıcıdaki gruplarından gelir; grupları artık eşleşmeyen kullanıcı bir sonraki oturum açışta erişimini kaybeder. SCIM ile oluşturulan kullanıcılar burada yönetilmez.",
	],
	"sso.jit.enable": ["Create members at sign-in", "Oturum açılırken üye oluştur"],
	"sso.jit.domains": ["Allowed email domains", "İzin verilen e-posta alan adları"],
	"sso.jit.domainsHint": [
		"Comma-separated. Each domain must be verified above.",
		"Virgülle ayırın. Her alan adı yukarıda doğrulanmış olmalıdır.",
	],
	"sso.jit.defaultRole": ["Role when no group matches", "Hiçbir grup eşleşmezse rol"],
	"sso.jit.noDefault": [
		"No access (a mapped group is required)",
		"Erişim yok (eşleşen bir grup gerekir)",
	],
	"sso.jit.viewer": ["Viewer", "Görüntüleyici"],
	"sso.jit.member": ["Member", "Üye"],
	"sso.jit.mappings": ["Group to role mapping", "Grup - rol eşlemesi"],
	"sso.jit.mappingsHint": [
		"Exact group claim values, one per line as value=role (admin, member or viewer), for example /aidr/admins=admin. Matching is case-sensitive; the highest role wins; owner is never granted. Set the groups claim name in the provider settings above.",
		"Grup claim değerlerini tam olarak, her satıra bir tane değer=rol (admin, member ya da viewer) biçiminde yazın; örneğin /aidr/admins=admin. Eşleşme büyük-küçük harfe duyarlıdır; en yüksek rol geçerlidir; sahip (owner) rolü asla verilmez. Grup claim adını yukarıdaki sağlayıcı ayarlarında belirtin.",
	],
	"sso.jit.save": ["Save provisioning", "Hesap oluşturma ayarını kaydet"],
	"sso.jit.saved": ["Just-in-time provisioning saved.", "Anında hesap oluşturma ayarı kaydedildi."],
	"sso.jit.invalidMapping": [
		"Line {line} is not value=role with role admin, member or viewer.",
		"{line}. satır değer=rol biçiminde değil ya da rol admin, member veya viewer değil.",
	],
	"sso.jit.issuerChanged": [
		"The provider's issuer changed since this was saved. Nobody is provisioned until you save again.",
		"Bu ayar kaydedildikten sonra sağlayıcının issuer değeri değişti. Yeniden kaydedene kadar kimse için hesap oluşturulmaz.",
	],
	"sso.jit.directoryAuthoritative": [
		"Directory-authoritative membership is on, so only SCIM can grant access. Turn it off to use just-in-time provisioning.",
		"Dizin yetkili üyelik modu açık; bu nedenle erişimi yalnızca SCIM verebilir. Anında hesap oluşturmayı kullanmak için bu modu kapatın.",
	],
	"sso.jit.groupModeHint": [
		"Keep Group requirement on Ignore groups: just-in-time provisioning applies the mapping in this section.",
		'Grup şartını "Grupları yok say" olarak bırakın: anında hesap oluşturma bu bölümdeki kendi eşlemesini uygular.',
	],
	"sso.jit.activeMembers": [
		"Members created at sign-in: {count}",
		"Oturum açılırken oluşturulan üyeler: {count}",
	],
	"sso.jit.removed": ["Removed by an administrator", "Bir yönetici tarafından çıkarıldı"],
	"sso.jit.removedLead": [
		"These users were removed in AIDR and are not re-added at sign-in until you re-admit them.",
		"Bu kullanıcılar AIDR'da çıkarıldı; siz yeniden kabul edene kadar oturum açtıklarında geri eklenmezler.",
	],
	"sso.jit.readmit": ["Re-admit {user}", "{user} kullanıcısını yeniden kabul et"],
	"sso.jit.readmitted": [
		"Re-admitted. The user gets access again at the next sign-in.",
		"Yeniden kabul edildi. Kullanıcı bir sonraki oturum açışta erişimi yeniden alır.",
	],
	"sso.err.jitDomain": [
		"Each allowed domain must be a verified domain of this workspace.",
		"İzin verilen her alan adı bu çalışma alanının doğrulanmış bir alan adı olmalıdır.",
	],
	"sso.err.jitDomainRequired": [
		"Add at least one allowed email domain before turning this on.",
		"Bunu açmadan önce en az bir izin verilen e-posta alan adı ekleyin.",
	],
	"sso.err.jitPolicy": [
		"The provisioning settings were rejected. Check the domains, the default role and the mapping lines.",
		"Hesap oluşturma ayarları reddedildi. Alan adlarını, varsayılan rolü ve eşleme satırlarını kontrol edin.",
	],
	"sso.err.jitDirectory": [
		"Directory-authoritative membership is on; only SCIM can grant access.",
		"Dizin yetkili üyelik modu açık; erişimi yalnızca SCIM verebilir.",
	],
	"sso.err.providerMissing": ["Save the provider first.", "Önce sağlayıcıyı kaydedin."],
	"sso.err.notRemoved": [
		"This user is not in the removed list any more.",
		"Bu kullanıcı artık çıkarılanlar listesinde değil.",
	],
} as const satisfies MessagePairs<string>;

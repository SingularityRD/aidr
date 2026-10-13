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
		"Any OpenID Connect provider with a discovery document.",
		"Keşif belgesi olan herhangi bir OpenID Connect sağlayıcısı.",
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
		"Configure OpenID Connect sign-in for {team} with Microsoft Entra ID, Okta or another provider. SCIM still provisions users and roles; this page controls how they sign in.",
		"{team} için Microsoft Entra ID, Okta ya da başka bir sağlayıcıyla OpenID Connect oturum açmayı yapılandırın. Kullanıcıları ve rolleri yine SCIM sağlar; bu sayfa yalnızca nasıl oturum açtıklarını belirler.",
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
		"Ignore groups (SCIM decides access)",
		"Grupları yok say (erişime SCIM karar verir)",
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
} as const satisfies MessagePairs<string>;

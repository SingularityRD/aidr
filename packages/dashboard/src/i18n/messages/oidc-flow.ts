import type { MessagePairs } from "./define";

/** Messages of the OIDC single sign-on start and callback flow. */
export const oidcFlowMessages = {
	"of.notAvailable": [
		"Single sign-on is not available for this address. Check the spelling or contact your administrator.",
		"Bu adres için tek oturum açma kullanılamıyor. Yazımı kontrol edin ya da yöneticinize başvurun.",
	],
	"of.rateLimited": [
		"Too many attempts. Wait a minute and try again.",
		"Çok fazla deneme. Bir dakika bekleyip yeniden deneyin.",
	],
	"of.notMember": [
		"Your account is not a member of this workspace.",
		"Hesabınız bu çalışma alanının üyesi değil.",
	],
	"of.ssoRequired": [
		"This workspace requires single sign-on.",
		"Bu çalışma alanı tek oturum açma gerektirir.",
	],
	"of.requestInvalid": [
		"This sign-in link has expired or was already used. Start again from the sign-in page.",
		"Bu oturum açma bağlantısının süresi doldu ya da zaten kullanıldı. Oturum açma sayfasından yeniden başlayın.",
	],
	"of.bindingMismatch": [
		"This sign-in was started in a different browser. Start again from the sign-in page.",
		"Bu oturum açma başka bir tarayıcıda başlatıldı. Oturum açma sayfasından yeniden başlayın.",
	],
	"of.tokenInvalid": [
		"The identity provider's response could not be verified. Contact your administrator.",
		"Kimlik sağlayıcının yanıtı doğrulanamadı. Yöneticinize başvurun.",
	],
	"of.exchangeFailed": [
		"The identity provider rejected the sign-in. Contact your administrator.",
		"Kimlik sağlayıcı oturum açmayı reddetti. Yöneticinize başvurun.",
	],
	"of.domain": [
		"Your email domain is not verified for this workspace. Contact your administrator.",
		"E-posta alan adınız bu çalışma alanı için doğrulanmamış. Yöneticinize başvurun.",
	],
	"of.noEmail": [
		"The identity provider did not return an email address. Contact your administrator.",
		"Kimlik sağlayıcı bir e-posta adresi döndürmedi. Yöneticinize başvurun.",
	],
	"of.notProvisioned": [
		"Your account has not been provisioned for this workspace yet. Contact your administrator.",
		"Hesabınız bu çalışma alanı için henüz oluşturulmadı. Yöneticinize başvurun.",
	],
	"of.groupNotMapped": [
		"None of your directory groups grants access to this workspace.",
		"Dizin gruplarınızın hiçbiri bu çalışma alanına erişim vermiyor.",
	],
	"of.groupsOverage": [
		"Your directory group list is too large to evaluate. Contact your administrator.",
		"Dizin grubu listeniz değerlendirilemeyecek kadar büyük. Yöneticinize başvurun.",
	],
	"of.identityConflict": [
		"This identity is already linked to a different account. Contact your administrator.",
		"Bu kimlik zaten başka bir hesaba bağlı. Yöneticinize başvurun.",
	],
	"of.providerUnavailable": [
		"Single sign-on is temporarily unavailable. Try again later.",
		"Tek oturum açma geçici olarak kullanılamıyor. Daha sonra yeniden deneyin.",
	],
	"of.sessionUnavailable": [
		"A session could not be created. Try again later.",
		"Oturum oluşturulamadı. Daha sonra yeniden deneyin.",
	],
	"of.storageBlocked": [
		"This browser blocks the storage single sign-on needs. Enable it and try again.",
		"Bu tarayıcı tek oturum açmanın ihtiyaç duyduğu depolamayı engelliyor. Açıp yeniden deneyin.",
	],
	"of.unavailable": [
		"Single sign-on is unavailable. Try again later.",
		"Tek oturum açma kullanılamıyor. Daha sonra yeniden deneyin.",
	],
} as const satisfies MessagePairs<string>;

import type { MessagePairs } from "./define";

/** SAML sign-in enforcement panel (two-owner approval). */
export const samlMessages = {
	"saml.err.owner": [
		"Only an active tenant owner can manage SAML enforcement.",
		"SAML zorunluluğunu yalnızca etkin bir çalışma alanı sahibi yönetebilir.",
	],
	"saml.err.mfa": [
		"Complete multi-factor verification, then try again.",
		"Çok adımlı doğrulamayı tamamlayıp yeniden deneyin.",
	],
	"saml.err.sso": [
		"Sign in through this workspace's required identity provider, then try again.",
		"Bu çalışma alanının zorunlu kimlik sağlayıcısıyla oturum açıp yeniden deneyin.",
	],
	"saml.err.sessionInvalid": [
		"Sign in again before changing SAML enforcement.",
		"SAML zorunluluğunu değiştirmeden önce yeniden oturum açın.",
	],
	"saml.err.sessionRevoked": [
		"This session was revoked. Sign in again.",
		"Bu oturum kapatıldı. Yeniden oturum açın.",
	],
	"saml.err.providerSession": [
		"Sign in through the SAML provider being enabled or currently required, then try again.",
		"Açılmakta olan ya da şu anda zorunlu olan SAML sağlayıcısıyla oturum açıp yeniden deneyin.",
	],
	"saml.err.providerUnavailable": [
		"The selected SAML provider is unavailable.",
		"Seçilen SAML sağlayıcısı kullanılamıyor.",
	],
	"saml.err.ownersNotVerified": [
		"At least two active owners are required. Every active owner must first verify their account through this SAML provider.",
		"En az iki etkin sahip gerekir. Her etkin sahip önce hesabını bu SAML sağlayıcısıyla doğrulamalıdır.",
	],
	"saml.err.scimConflict": [
		"A provisioned identity conflicts with an owner account. Resolve the identity before retrying.",
		"Sağlanan bir kimlik bir sahip hesabıyla çakışıyor. Yeniden denemeden önce kimliği düzeltin.",
	],
	"saml.err.transition": [
		"Disable the current SAML provider with two-owner approval before enabling another provider.",
		"Başka bir sağlayıcıyı açmadan önce mevcut SAML sağlayıcısını iki sahibin onayıyla kapatın.",
	],
	"saml.err.policyConflict": [
		"The identity policy changed. Refresh and create a new request.",
		"Kimlik politikası değişti. Yenileyip yeni bir talep oluşturun.",
	],
	"saml.err.expired": [
		"This request expired. Create a new request for review.",
		"Bu talebin süresi doldu. İnceleme için yeni bir talep oluşturun.",
	],
	"saml.err.consumed": [
		"This request was already approved. Refresh its status.",
		"Bu talep zaten onaylandı. Durumunu yenileyin.",
	],
	"saml.err.distinctOwner": [
		"A different active owner must approve this request.",
		"Bu talebi başka bir etkin sahip onaylamalıdır.",
	],
	"saml.err.notFound": [
		"This request was not found in the selected workspace.",
		"Bu talep seçili çalışma alanında bulunamadı.",
	],
	"saml.err.pendingLimit": [
		"Too many requests are pending. Wait for them to expire before creating another.",
		"Bekleyen çok fazla talep var. Yenisini oluşturmadan önce sürelerinin dolmasını bekleyin.",
	],
	"saml.err.invalid": [
		"Check the provider ID, change reason, and change reference.",
		"Sağlayıcı kimliğini, değişiklik gerekçesini ve değişiklik başvurusunu kontrol edin.",
	],
	"saml.err.rateLimited": [
		"Too many attempts. Wait a moment before retrying.",
		"Çok fazla deneme. Yeniden denemeden önce biraz bekleyin.",
	],
	"saml.err.invalidChange": [
		"SAML enforcement returned an invalid change request. No change was confirmed.",
		"SAML zorunluluğu geçersiz bir değişiklik talebi döndürdü. Hiçbir değişiklik onaylanmadı.",
	],
	"saml.err.unavailable": [
		"SAML enforcement is unavailable. No change was confirmed.",
		"SAML zorunluluğu kullanılamıyor. Hiçbir değişiklik onaylanmadı.",
	],
	"saml.err.statusDisabled": [
		"SAML enforcement status could not be verified. Changes are disabled.",
		"SAML zorunluluk durumu doğrulanamadı. Değişiklikler kapalı.",
	],
	"saml.err.status": [
		"SAML enforcement status could not be verified.",
		"SAML zorunluluk durumu doğrulanamadı.",
	],
	"saml.err.notConfirmed": [
		"The SAML policy change was not confirmed.",
		"SAML politika değişikliği onaylanmadı.",
	],
	"saml.err.form": [
		"Enter a valid provider ID, a change reason of 12–500 characters, and a change reference.",
		"Geçerli bir sağlayıcı kimliği, 12–500 karakterlik bir değişiklik gerekçesi ve bir değişiklik başvurusu girin.",
	],
	"saml.err.mismatch": [
		"The returned request does not match this change. No change was confirmed.",
		"Dönen talep bu değişiklikle eşleşmiyor. Hiçbir değişiklik onaylanmadı.",
	],
	"saml.requested": [
		"Request created. SAML enforcement is unchanged until another owner reviews and approves it.",
		"Talep oluşturuldu. Başka bir sahip inceleyip onaylayana kadar SAML zorunluluğu değişmez.",
	],
	"saml.err.requestId": [
		"Enter the complete change request ID.",
		"Değişiklik talebinin tam kimliğini girin.",
	],
	"saml.err.selectedMismatch": [
		"The returned request does not match the selected change.",
		"Dönen talep seçili değişiklikle eşleşmiyor.",
	],
	"saml.title": ["SAML sign-in enforcement", "SAML ile oturum açma zorunluluğu"],
	"saml.lead": [
		"Enabling or disabling required SAML sign-in needs two active owners, each signed in through the relevant provider with multi-factor verification. Review requests expire after five minutes.",
		"Zorunlu SAML oturum açmayı açmak ya da kapatmak için, her biri ilgili sağlayıcıyla ve çok adımlı doğrulamayla oturum açmış iki etkin sahip gerekir. İnceleme talepleri beş dakika sonra sona erer.",
	],
	"saml.replace": [
		"To replace a provider, first disable the current requirement with two-owner approval, then request the new provider. Recovery sessions cannot approve these changes.",
		"Bir sağlayıcıyı değiştirmek için önce mevcut zorunluluğu iki sahibin onayıyla kapatın, sonra yeni sağlayıcıyı isteyin. Kurtarma oturumları bu değişiklikleri onaylayamaz.",
	],
	"saml.current": ["Current requirement: {provider}", "Geçerli zorunluluk: {provider}"],
	"saml.off": ["Off", "Kapalı"],
	"saml.statusUnavailable": [
		"SAML enforcement status is unavailable.",
		"SAML zorunluluk durumu alınamıyor.",
	],
	"saml.verifying": ["Verifying SAML enforcement status…", "SAML zorunluluk durumu doğrulanıyor…"],
	"saml.providerId": ["SAML provider ID", "SAML sağlayıcı kimliği"],
	"saml.reason": ["Change reason", "Değişiklik gerekçesi"],
	"saml.ref": ["Change reference", "Değişiklik başvurusu"],
	"saml.requestDisable": ["Request disabling SAML", "SAML'ı kapatmayı iste"],
	"saml.requestEnable": ["Request enabling SAML", "SAML'ı açmayı iste"],
	"saml.requestId": ["Change request ID", "Değişiklik talebi kimliği"],
	"saml.share": [
		"Share this ID with a different owner. That owner can paste it here to review the exact change.",
		"Bu kimliği başka bir sahiple paylaşın. O sahip, değişikliği aynen incelemek için kimliği buraya yapıştırabilir.",
	],
	"saml.review": ["Review request", "Talebi incele"],
	"saml.reviewLabel": ["SAML change review", "SAML değişiklik incelemesi"],
	"saml.requestedBy": ["Requested by", "Talep eden"],
	"saml.currentProvider": ["Current provider", "Geçerli sağlayıcı"],
	"saml.requestedProvider": ["Requested provider", "İstenen sağlayıcı"],
	"saml.expires": ["Expires", "Sona erme"],
	"saml.approvedBy": [
		"Approved by {owner}. The policy change was applied.",
		"{owner} onayladı. Politika değişikliği uygulandı.",
	],
	"saml.self": [
		"A different owner must approve your request.",
		"Talebinizi başka bir sahip onaylamalıdır.",
	],
	"saml.reviewHint": [
		"Review the provider and change details before approving. Approval applies this exact change.",
		"Onaylamadan önce sağlayıcıyı ve değişiklik ayrıntılarını inceleyin. Onay, bu değişikliği aynen uygular.",
	],
	"saml.err.approvalMismatch": [
		"Approval was not confirmed for this exact request. Refresh its status before retrying.",
		"Onay bu talep için doğrulanamadı. Yeniden denemeden önce durumunu yenileyin.",
	],
	"saml.applied": [
		"The second owner approved the change. SAML enforcement was updated.",
		"İkinci sahip değişikliği onayladı. SAML zorunluluğu güncellendi.",
	],
	"saml.approve": ["Approve as a second owner", "İkinci sahip olarak onayla"],
	"saml.refresh": ["Refresh SAML status", "SAML durumunu yenile"],
} as const satisfies MessagePairs<string>;

import type { MessagePairs } from "./define";

/** Machine-readable AI governance errors (lib/ai-governance.ts). */
export const governanceErrorsMessages = {
	"gov.err.mfa": [
		"Multi-factor verification (AAL2) is required for this action. Verify with your authenticator, then try again.",
		"Bu işlem için çok faktörlü doğrulama (AAL2) gerekir. Doğrulama uygulamanızla doğrulayıp yeniden deneyin.",
	],
	"gov.err.sso": [
		"This workspace requires single sign-on. Sign in with your identity provider, then try again.",
		"Bu çalışma alanı çoklu oturum açma (SSO) gerektirir. Kimlik sağlayıcınızla oturum açıp yeniden deneyin.",
	],
	"gov.err.selfApproval": [
		"You filed this request, so someone else must decide it (four-eyes).",
		"Bu isteği siz oluşturdunuz; bu yüzden kararı başka biri vermelidir (dört göz).",
	],
	"gov.err.fourEyes": [
		"Four-eyes change control is on: relaxing a ban or restriction needs an intake request decided by another person.",
		"Dört göz değişiklik denetimi açık: bir yasağı ya da kısıtlamayı gevşetmek için başka bir kişinin karar verdiği bir talep gerekir.",
	],
	"gov.err.bgFourEyes": [
		"Four-eyes change control is on: switching off required native NER needs four-eyes to be turned off first, which another owner or administrator must approve.",
		"Dört göz değişiklik denetimi açık: zorunlu yerel ad/adres denetimini kapatmak için önce dört göz denetiminin kapatılması gerekir; bunu başka bir sahip ya da yönetici onaylamalıdır.",
	],
	"gov.err.reviewerScope": [
		"Designated reviewers cannot lift a ban or restriction; an owner or administrator must decide this request.",
		"Atanmış inceleyiciler bir yasağı ya da kısıtlamayı kaldıramaz; bu isteğe bir sahip ya da yönetici karar vermelidir.",
	],
	"gov.err.role": [
		"Your role cannot perform this action in this workspace.",
		"Rolünüz bu çalışma alanında bu işlemi yapamaz.",
	],
	"gov.err.notMember": [
		"You are not an active member of this workspace.",
		"Bu çalışma alanının etkin bir üyesi değilsiniz.",
	],
	"gov.err.assetExists": [
		"This AI system is already in the register.",
		"Bu yapay zekâ sistemi zaten envanterde.",
	],
	"gov.err.versionConflict": [
		"Someone else changed this entry. Reload and try again.",
		"Bu kaydı başka biri değiştirdi. Sayfayı yenileyip yeniden deneyin.",
	],
	"gov.err.ownerNotMember": [
		"The owner must be an active member of this workspace.",
		"Sorumlu kişi bu çalışma alanının etkin bir üyesi olmalıdır.",
	],
	"gov.err.prohibited": [
		"A prohibited-tier system cannot be approved or waived; it must stay banned or retired.",
		"Yasaklı düzeydeki bir sistem onaylanamaz ya da muaf tutulamaz; yasaklı ya da kullanımdan kaldırılmış kalmalıdır.",
	],
	"gov.err.alreadyApproved": [
		"This AI system is already approved.",
		"Bu yapay zekâ sistemi zaten onaylı.",
	],
	"gov.err.intakePending": [
		"A request for this AI system is already pending.",
		"Bu yapay zekâ sistemi için bekleyen bir talep zaten var.",
	],
	"gov.err.notRestricted": [
		"Exceptions apply only to banned or restricted systems.",
		"İstisnalar yalnızca yasaklı ya da kısıtlı sistemlere uygulanır.",
	],
	"gov.err.twoApprovers": [
		"Four-eyes needs at least two active owners or administrators in this workspace.",
		"Dört göz denetimi için bu çalışma alanında en az iki etkin sahip ya da yönetici gerekir.",
	],
	"gov.err.quota": [
		"At most 500 MCP servers can be banned or restricted.",
		"En fazla 500 MCP sunucusu yasaklanabilir ya da kısıtlanabilir.",
	],
	"gov.err.final": ["This request was already decided.", "Bu istek için zaten karar verildi."],
	"gov.err.expired": [
		"This request expired before it was decided.",
		"Bu isteğin süresi karar verilmeden doldu.",
	],
	"gov.err.exceptionInactive": [
		"This exception is no longer active.",
		"Bu istisna artık etkin değil.",
	],
	"gov.err.superseded": [
		"The policy changed after this request was filed, so nothing was applied. The author must file a new change.",
		"Bu istek oluşturulduktan sonra politika değişti; bu yüzden hiçbir şey uygulanmadı. Yazarın yeni bir değişiklik oluşturması gerekir.",
	],
	"gov.err.changeFailed": [
		"The change could not be applied (for example the author is no longer an administrator). Nothing was published.",
		"Değişiklik uygulanamadı (örneğin yazar artık yönetici değil). Hiçbir şey yayımlanmadı.",
	],
	"gov.err.rateLimited": [
		"Too many requests. Wait a minute and try again.",
		"Çok fazla istek gönderildi. Bir dakika bekleyip yeniden deneyin.",
	],
	"gov.err.invalid": [
		"Check the form: a field is missing, too long or not allowed.",
		"Formu kontrol edin: bir alan eksik, çok uzun ya da izin verilmeyen bir değer içeriyor.",
	],
	"gov.err.generic": [
		"The governance service did not confirm the request. Nothing changed.",
		"Yönetişim hizmeti isteği doğrulamadı. Hiçbir şey değişmedi.",
	],
} as const satisfies MessagePairs<string>;

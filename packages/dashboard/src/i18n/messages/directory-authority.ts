import type { MessagePairs } from "./define";

/** Directory-authoritative membership panel on the SCIM page. */
export const directoryAuthorityMessages = {
	"da.you": ["{name} (you)", "{name} (siz)"],
	"da.title": ["Directory-authoritative membership", "Dizinin belirlediği üyelik"],
	"da.lead": [
		"When on, a membership in this workspace grants access only if the selected SCIM directory provisions it with the same role. Manually added members, invitations and credentials for any other directory stop granting access. Owners are kept as named break-glass accounts so a directory outage or mass deprovisioning cannot lock the workspace out.",
		"Açıkken bu çalışma alanındaki bir üyelik, yalnızca seçilen SCIM dizini onu aynı rolle sağlıyorsa erişim verir. Elle eklenen üyeler, davetler ve başka dizinlere ait kimlik bilgileri erişim vermeyi bırakır. Sahipler, bir dizin kesintisi ya da toplu üyelik kaldırma çalışma alanını kilitlemesin diye adlandırılmış acil durum hesapları olarak tutulur.",
	],
	"da.onLine": [
		"{state} — authoritative directory {directory}.",
		"{state} — yetkili dizin {directory}.",
	],
	"da.on": ["On", "Açık"],
	"da.off": ["Off", "Kapalı"],
	"da.breakGlass": ["Break-glass owners:", "Acil durum sahipleri:"],
	"da.locked": [
		"While the mode is on, owners cannot be added, removed or demoted. Turn it off first, make the owner change, then turn it on again. Turning it off is audited and requires multi-factor verification.",
		"Bu mod açıkken sahip eklenemez, çıkarılamaz ya da rolü düşürülemez. Önce kapatın, sahip değişikliğini yapın, sonra yeniden açın. Kapatma denetim kaydına yazılır ve çok adımlı doğrulama gerektirir.",
	],
	"da.confirmOff": [
		"Turn off? Manually added members could be granted access again.",
		"Kapatılsın mı? Elle eklenen üyeler yeniden erişim kazanabilir.",
	],
	"da.confirmOffButton": ["Confirm turn off", "Kapatmayı onayla"],
	"da.turnOff": [
		"Turn off directory-authoritative mode",
		"Dizinin belirlediği üyelik modunu kapat",
	],
	"da.offLine": [
		"{state} — manual memberships and every directory's credentials grant access.",
		"{state} — elle eklenen üyelikler ve tüm dizinlerin kimlik bilgileri erişim verir.",
	],
	"da.noDirectory": [
		"Create an active provisioning credential with a directory identifier first.",
		"Önce dizin tanımlayıcısı olan etkin bir sağlama kimlik bilgisi oluşturun.",
	],
	"da.directory": ["Authoritative directory", "Yetkili dizin"],
	"da.breakGlassAll": [
		"Break-glass owners (every active owner, at most two):",
		"Acil durum sahipleri (tüm etkin sahipler, en fazla iki):",
	],
	"da.tooMany": [
		"This workspace has more than two owners. Remove or demote owners until at most two remain; they become the break-glass accounts.",
		"Bu çalışma alanında ikiden fazla sahip var. En fazla iki sahip kalana kadar sahip çıkarın ya da rollerini düşürün; kalanlar acil durum hesapları olur.",
	],
	"da.adopt": [
		"Treat existing SCIM-provisioned memberships as coming from this directory",
		"Mevcut SCIM ile sağlanmış üyelikleri bu dizinden gelmiş say",
	],
	"da.adoptHint": [
		"Only choose this if no other directory ever provisioned this workspace. Otherwise leave it off and let the directory re-provision its users.",
		"Bunu yalnızca bu çalışma alanını başka hiçbir dizin sağlamadıysa seçin. Aksi halde kapalı bırakın ve dizinin kullanıcılarını yeniden sağlamasına izin verin.",
	],
	"da.remove": [
		"Remove members this directory does not provision",
		"Bu dizinin sağlamadığı üyeleri çıkar",
	],
	"da.removeHint": [
		"Removal is permanent and audited, and revokes their API keys and enrollments. If left off, enabling is refused while such members exist and nothing changes.",
		"Çıkarma kalıcıdır, denetim kaydına yazılır ve bu üyelerin API anahtarlarını ve kayıtlarını iptal eder. Kapalı bırakılırsa, böyle üyeler varken açma reddedilir ve hiçbir şey değişmez.",
	],
	"da.confirmOn": ["Make {directory} authoritative?", "{directory} yetkili dizin yapılsın mı?"],
	"da.confirmOnButton": ["Confirm turn on", "Açmayı onayla"],
	"da.turnOn": ["Turn on directory-authoritative mode", "Dizinin belirlediği üyelik modunu aç"],
} as const satisfies MessagePairs<string>;

import type { MessagePairs } from "./define";

/** Fleet enrollment keys card on the API keys page. */
export const fleetKeysMessages = {
	"fleet.title": ["Fleet enrollment keys", "Filo kayıt anahtarları"],
	"fleet.intro": [
		"One key enrolls many machines. Put it in the machine policy of your installer or device management tool and every machine enrolls itself on first run, with no browser step. A key belongs to this team, can enroll at most the number of new machines you set, expires, and can be revoked at any time. Your licensed seat limit still applies. Only owners and admins can see and manage these keys.",
		"Tek anahtar çok sayıda makineyi kaydeder. Anahtarı kurulum paketinizin ya da cihaz yönetim aracınızın makine ilkesine koyun; her makine ilk çalıştığında tarayıcı adımı olmadan kendini kaydeder. Anahtar bu ekibe aittir, en fazla belirlediğiniz sayıda yeni makine kaydedebilir, süresi dolar ve istediğiniz an iptal edilebilir. Lisanslı koltuk sınırınız yine geçerlidir. Bu anahtarları yalnızca sahipler ve yöneticiler görebilir ve yönetebilir.",
	],
	"fleet.policyHint": [
		"Machine policy key: enrollment_key (Windows: HKLM\\SOFTWARE\\Policies\\Singularity AIDR; Linux: /etc/singularity-aidr/managed.json). Revoking a key stops new enrollments only; machines already enrolled keep working until you revoke their own keys. A key acts for the admin who creates it: if that person loses the admin role the key stops working, and if they are removed from the team the machine keys it issued are revoked too. Create fleet keys from an administrator account that outlives staff changes.",
		"Makine ilkesindeki alan: enrollment_key (Windows: HKLM\\SOFTWARE\\Policies\\Singularity AIDR; Linux: /etc/singularity-aidr/managed.json). Anahtarı iptal etmek yalnızca yeni kayıtları durdurur; kayıtlı makineler kendi anahtarları iptal edilene kadar çalışmaya devam eder. Anahtar, onu oluşturan yönetici adına çalışır: bu kişi yönetici rolünü kaybederse anahtar çalışmaz, ekipten çıkarılırsa anahtarın verdiği makine anahtarları da iptal edilir. Filo anahtarlarını personel değişikliklerinden etkilenmeyecek bir yönetici hesabıyla oluşturun.",
	],
	"fleet.labelPlaceholder": [
		"finance-laptops, build-servers, etc.",
		"finans-dizüstü, derleme-sunucuları vb.",
	],
	"fleet.label": ["Fleet key label (optional)", "Filo anahtarı etiketi (isteğe bağlı)"],
	"fleet.lifetime": ["Fleet key valid for", "Filo anahtarı geçerlilik süresi"],
	"fleet.seatCap": ["Maximum new machines", "En fazla yeni makine sayısı"],
	"fleet.seatCapInvalid": [
		"Enter a whole number from 1 to {max}.",
		"1 ile {max} arasında bir tam sayı girin.",
	],
	"fleet.life.30": ["30 days", "30 gün"],
	"fleet.life.90": ["90 days (recommended)", "90 gün (önerilen)"],
	"fleet.life.180": ["180 days", "180 gün"],
	"fleet.life.365": ["1 year", "1 yıl"],
	"fleet.generate": ["Create fleet key", "Filo anahtarı oluştur"],
	"fleet.copyOnce": [
		"Copy this fleet key now. It is shown once and cannot be recovered. Store it only in machine policy or your deployment tool's secret store.",
		"Bu filo anahtarını şimdi kopyalayın. Yalnızca bir kez gösterilir ve geri alınamaz. Yalnızca makine ilkesinde ya da dağıtım aracınızın gizli bilgi deposunda saklayın.",
	],
	"fleet.newKey": ["New fleet enrollment key", "Yeni filo kayıt anahtarı"],
	"fleet.listInvalid": [
		"Fleet key list response is invalid.",
		"Filo anahtarı listesi yanıtı geçersiz.",
	],
	"fleet.createUnconfirmed": [
		"Fleet key creation was not confirmed.",
		"Filo anahtarı oluşturma doğrulanmadı.",
	],
	"fleet.createUnavailable": [
		"Fleet key creation is unavailable. Please retry.",
		"Filo anahtarı oluşturma kullanılamıyor. Lütfen yeniden deneyin.",
	],
	"fleet.revokeUnconfirmed": [
		"Fleet key revocation was not confirmed.",
		"Filo anahtarı iptali doğrulanmadı.",
	],
	"fleet.revokeUnavailable": [
		"Fleet key revocation is unavailable.",
		"Filo anahtarı iptali kullanılamıyor.",
	],
	"fleet.confirmRevoke": ["Confirm revoke", "İptali onayla"],
	"fleet.col.hint": ["Ends with", "Son karakterler"],
	"fleet.col.machines": ["Machines / limit", "Makine / sınır"],
	"fleet.col.uses": ["Uses", "Kullanım"],
	"fleet.status.active": ["active", "etkin"],
	"fleet.status.exhausted": ["limit reached", "sınıra ulaşıldı"],
	"fleet.status.expired": ["expired", "süresi doldu"],
	"fleet.status.revoked": ["revoked", "iptal edildi"],
	"fleet.empty": ["No fleet keys yet.", "Henüz filo anahtarı yok."],
} as const satisfies MessagePairs<string>;

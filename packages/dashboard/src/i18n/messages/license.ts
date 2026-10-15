import type { MessagePairs } from "./define";

/** License banner, Settings -> License (signed import, usage report). */
export const licenseMessages = {
	"license.banner.expires30": [
		"Your AIDR license {id} ends in {days} days ({date}). Ask your vendor for the renewal and import the signed file.",
		"AIDR lisansınız ({id}) {days} gün sonra bitiyor ({date}). Satıcınızdan yenileme isteyin ve imzalı dosyayı içe aktarın.",
	],
	"license.banner.expires7": [
		"Your AIDR license {id} ends in {days} days ({date}). Import the renewed signed license now.",
		"AIDR lisansınız ({id}) {days} gün sonra bitiyor ({date}). Yenilenmiş imzalı lisansı şimdi içe aktarın.",
	],
	// Admission terms without a stored signed license (an unsigned pilot bootstrap) have no id.
	"license.banner.expires30NoId": [
		"Your AIDR license ends in {days} days ({date}). Ask your vendor for the renewal and import the signed file.",
		"AIDR lisansınız {days} gün sonra bitiyor ({date}). Satıcınızdan yenileme isteyin ve imzalı dosyayı içe aktarın.",
	],
	"license.banner.expires7NoId": [
		"Your AIDR license ends in {days} days ({date}). Import the renewed signed license now.",
		"AIDR lisansınız {days} gün sonra bitiyor ({date}). Yenilenmiş imzalı lisansı şimdi içe aktarın.",
	],
	"license.banner.grace": [
		"Your AIDR license ended on {date}. Grace period: managed features stop in {days} days ({graceDate}). Local detection on every device keeps enforcing.",
		"AIDR lisansınız {date} tarihinde bitti. Ek süre: yönetim özellikleri {days} gün sonra duracak ({graceDate}). Her cihazdaki yerel koruma çalışmaya devam eder.",
	],
	"license.banner.expired": [
		"Your AIDR license and its grace period ended on {graceDate}. Managed features (new enrollments, policy sync, dashboard telemetry) are stopped. Local detection on every device keeps enforcing. Import a renewed license.",
		"AIDR lisansınız ve ek süresi {graceDate} tarihinde bitti. Yönetim özellikleri (yeni cihaz kaydı, politika eşitleme, panel olayları) durdu. Her cihazdaki yerel koruma çalışmaya devam eder. Yenilenmiş lisansı içe aktarın.",
	],
	"license.banner.action": ["License settings", "Lisans ayarları"],

	"license.title": ["License", "Lisans"],
	"license.intro": [
		"The license sets how many devices this workspace may enroll and until when managed features run. Local detection on devices never depends on it.",
		"Lisans, bu çalışma alanının kaç cihaz kaydedebileceğini ve yönetim özelliklerinin ne zamana kadar çalışacağını belirler. Cihazlardaki yerel koruma lisansa bağlı değildir.",
	],
	"license.loading": ["Loading license status…", "Lisans durumu yükleniyor…"],
	"license.unavailable": [
		"License status is unavailable right now.",
		"Lisans durumu şu anda alınamıyor.",
	],
	"license.none": [
		"No licensed admission is recorded for this workspace.",
		"Bu çalışma alanı için kayıtlı bir lisans yok.",
	],
	"license.source.signed": ["Vendor-signed license", "Satıcı tarafından imzalı lisans"],
	"license.source.admission": [
		"Admission terms (no signed license file stored)",
		"Kabul koşulları (saklanan imzalı lisans dosyası yok)",
	],
	"license.field.seats": ["Seats", "Koltuk"],
	"license.field.expires": ["Ends", "Bitiş"],
	"license.field.graceEnds": ["Managed features until", "Yönetim özellikleri şu tarihe kadar"],
	"license.pending.title": ["Waiting for operator approval", "Operatör onayı bekleniyor"],
	"license.pending.body": [
		"License {id} ({seats} seats, ends {date}) was verified and is waiting for a platform operator to apply it. The current terms stay in force until then.",
		"{id} lisansı ({seats} koltuk, bitiş {date}) doğrulandı ve bir platform operatörünün uygulamasını bekliyor. O zamana kadar mevcut koşullar geçerlidir.",
	],
	"license.import.title": ["Import signed license", "İmzalı lisansı içe aktar"],
	"license.import.body": [
		"Choose the aidr-license-v1 file from your vendor. The server checks its signature against this deployment's trusted keys. Importing does not change seats by itself: a platform operator who is not a member of this workspace applies it (separation of duty).",
		"Satıcınızdan gelen aidr-license-v1 dosyasını seçin. Sunucu imzayı bu kurulumun güvenilen anahtarlarıyla doğrular. İçe aktarma tek başına koltuk sayısını değiştirmez: bu çalışma alanının üyesi olmayan bir platform operatörü lisansı uygular (görevler ayrılığı).",
	],
	"license.import.file": ["License file", "Lisans dosyası"],
	"license.import.submit": ["Verify and submit", "Doğrula ve gönder"],
	"license.import.busy": ["Verifying…", "Doğrulanıyor…"],
	"license.import.invalidFile": [
		"The file is not an aidr-license-v1 JSON document.",
		"Dosya bir aidr-license-v1 JSON belgesi değil.",
	],
	"license.import.done": [
		"License {id} verified ({seats} seats, ends {date}) and submitted for operator approval.",
		"{id} lisansı doğrulandı ({seats} koltuk, bitiş {date}) ve operatör onayına gönderildi.",
	],
	"license.import.readOnly": [
		"Only workspace owners and admins can import a license.",
		"Lisansı yalnızca çalışma alanı sahipleri ve yöneticileri içe aktarabilir.",
	],
	"license.err.role": [
		"Only workspace owners and admins can import a license.",
		"Lisansı yalnızca çalışma alanı sahipleri ve yöneticileri içe aktarabilir.",
	],
	"license.err.mfa": [
		"Confirm with your second factor (MFA) and try again.",
		"İkinci doğrulama adımıyla (MFA) onaylayıp tekrar deneyin.",
	],
	"license.err.rejected": ["The license was refused: {reason}", "Lisans reddedildi: {reason}"],
	"license.err.registry": [
		"This deployment has no trusted license keys. Ask your operator to install the vendor-published key registry.",
		"Bu kurulumda güvenilen lisans anahtarı yok. Operatörünüzden satıcının yayımladığı anahtar listesini kurmasını isteyin.",
	],
	"license.err.otherTenant": [
		"This license is already applied to another workspace.",
		"Bu lisans zaten başka bir çalışma alanına uygulanmış.",
	],
	"license.err.rateLimited": [
		"Too many attempts. Wait a minute and try again.",
		"Çok fazla deneme. Bir dakika bekleyip tekrar deneyin.",
	],
	"license.err.tooLarge": ["The license file is too large.", "Lisans dosyası çok büyük."],
	"license.err.unavailable": [
		"The license could not be submitted. Try again later.",
		"Lisans gönderilemedi. Daha sonra tekrar deneyin.",
	],
	"license.reason.bad_signature": [
		"the signature does not match (the file was changed or signed by another key)",
		"imza eşleşmiyor (dosya değiştirilmiş ya da başka bir anahtarla imzalanmış)",
	],
	"license.reason.expired": ["it is past its grace period", "ek süresi dolmuş"],
	"license.reason.customer_mismatch": [
		"it was issued for another customer",
		"başka bir müşteri için düzenlenmiş",
	],
	"license.reason.unknown_key": [
		"it was signed by a key this deployment does not trust",
		"bu kurulumun güvenmediği bir anahtarla imzalanmış",
	],
	"license.reason.revoked_key": ["its signing key was revoked", "imzalama anahtarı iptal edilmiş"],
	"license.reason.other": [
		"the file is not a valid license ({code})",
		"dosya geçerli bir lisans değil ({code})",
	],
	"license.report.title": ["Usage report", "Kullanım raporu"],
	"license.report.body": [
		"Download a counts-only usage report (aidr-usage-report-v1) to send to your vendor. It contains no device names, users or events. It is customer-attested: report_sha256 detects later edits but is not a signature.",
		"Satıcınıza göndermek için yalnızca sayılardan oluşan bir kullanım raporu (aidr-usage-report-v1) indirin. Cihaz adı, kullanıcı ya da olay içermez. Rapor müşteri beyanıdır: report_sha256 sonradan yapılan değişiklikleri gösterir ama bir imza değildir.",
	],
	"license.report.download": ["Download usage report", "Kullanım raporunu indir"],
	"license.report.failed": [
		"The usage report could not be generated.",
		"Kullanım raporu oluşturulamadı.",
	],
} as const satisfies MessagePairs<string>;

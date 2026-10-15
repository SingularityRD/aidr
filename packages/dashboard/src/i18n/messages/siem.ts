import type { MessagePairs } from "./define";

/** SIEM syslog destination page. */
export const siemMessages = {
	"siem.title": ["SIEM integration", "SIEM entegrasyonu"],
	"siem.pageLead": [
		"Send AIDR incidents and decisions to your SIEM. Central forwarding runs on the AIDR server and is managed here; host forwarding runs on each endpoint from its local queue.",
		"AIDR olaylarını ve kararlarını SIEM sisteminize gönderin. Merkezi iletim AIDR sunucusunda çalışır ve buradan yönetilir; uç nokta iletimi her bilgisayarda yerel kuyruktan çalışır.",
	],
	"siem.hostTitle": ["Host forwarding (per endpoint)", "Uç nokta iletimi (bilgisayar başına)"],
	"siem.payloadFormat": ["Message format", "Mesaj biçimi"],
	"siem.format.json": ["JSON (RFC 5424)", "JSON (RFC 5424)"],
	"siem.format.cef": ["CEF (ArcSight)", "CEF (ArcSight)"],
	"siem.format.leef": ["LEEF (QRadar)", "LEEF (QRadar)"],
	"siem.central.title": ["Central forwarding (AIDR server)", "Merkezi iletim (AIDR sunucusu)"],
	"siem.central.lead": [
		"The AIDR server forwards incidents and decision events to these destinations at least once, retries with backoff and keeps failed events as dead letters you can resend. Tokens, keys and certificates are stored encrypted and are never shown again.",
		"AIDR sunucusu olayları ve karar kayıtlarını bu hedeflere en az bir kez iletir, hata olursa artan aralıklarla yeniden dener ve iletilemeyen kayıtları yeniden gönderebileceğiniz bir bekleme listesinde tutar. Belirteçler, anahtarlar ve sertifikalar şifreli saklanır ve bir daha gösterilmez.",
	],
	"siem.central.provider": ["Destination type", "Hedef türü"],
	"siem.central.provider.syslog": [
		"Syslog (QRadar, Wazuh, ArcSight, rsyslog)",
		"Syslog (QRadar, Wazuh, ArcSight, rsyslog)",
	],
	"siem.central.provider.webhook": ["Signed HTTPS webhook", "İmzalı HTTPS webhook"],
	"siem.central.format": ["Message format", "Mesaj biçimi"],
	"siem.central.url": ["Collector URL (https)", "Toplayıcı adresi (https)"],
	"siem.central.hecToken": ["HEC token", "HEC belirteci"],
	"siem.central.index": ["Index", "Dizin (index)"],
	"siem.central.apiKey": ["API key", "API anahtarı"],
	"siem.central.secret": ["Signing secret", "İmza anahtarı"],
	"siem.central.generate": ["Generate secret", "Anahtar üret"],
	"siem.central.dce": ["Data collection endpoint (https)", "Veri toplama uç noktası (https)"],
	"siem.central.dcr": ["Data collection rule immutable ID", "Veri toplama kuralı değişmez kimliği"],
	"siem.central.stream": ["Stream name", "Akış adı"],
	"siem.central.azureTenant": ["Microsoft Entra tenant ID", "Microsoft Entra kiracı kimliği"],
	"siem.central.clientId": ["Application (client) ID", "Uygulama (istemci) kimliği"],
	"siem.central.clientSecret": ["Client secret", "İstemci gizli anahtarı"],
	"siem.central.events": ["Events to forward", "İletilecek kayıtlar"],
	"siem.central.events.incidents": ["Incidents", "Güvenlik olayları"],
	"siem.central.events.browser": [
		"Browser Guard blocks and warnings",
		"Browser Guard engellemeleri ve uyarıları",
	],
	"siem.central.decision.deny": ["Blocked actions", "Engellenen işlemler"],
	"siem.central.decision.ask": ["Actions held for approval", "Onay bekleyen işlemler"],
	"siem.central.decision.allow": [
		"Allowed actions (high volume)",
		"İzin verilen işlemler (yüksek hacim)",
	],
	"siem.central.minSeverity": ["Minimum severity", "En düşük önem derecesi"],
	"siem.central.writeOnly": [
		"Connection settings are write-only. To change a token or address, delete the destination and add it again.",
		"Bağlantı ayarları yalnızca yazılabilir. Bir belirteci ya da adresi değiştirmek için hedefi silip yeniden ekleyin.",
	],
	"siem.central.add": ["Add destination", "Hedef ekle"],
	"siem.central.save": ["Save destination", "Hedefi kaydet"],
	"siem.central.created": ["Destination {name} saved.", "{name} hedefi kaydedildi."],
	"siem.central.updated": ["Destination updated.", "Hedef güncellendi."],
	"siem.central.deleted": ["Destination deleted.", "Hedef silindi."],
	"siem.central.requeued": [
		"{count} dead letters queued for another attempt.",
		"İletilemeyen {count} kayıt yeniden gönderim için kuyruğa alındı.",
	],
	"siem.central.testOk": ["Test event delivered.", "Deneme kaydı iletildi."],
	"siem.central.testFailed": [
		"Test event not delivered: {code}",
		"Deneme kaydı iletilemedi: {code}",
	],
	"siem.central.test": ["Send test", "Deneme gönder"],
	"siem.central.enable": ["Enable", "Aç"],
	"siem.central.disable": ["Disable", "Kapat"],
	"siem.central.requeue": ["Resend dead letters", "İletilemeyenleri yeniden gönder"],
	"siem.central.delete": ["Delete", "Sil"],
	"siem.central.actions": ["Actions", "İşlemler"],
	"siem.central.target": ["Collector", "Toplayıcı"],
	"siem.central.queueHeading": ["Queue", "Kuyruk"],
	"siem.central.queue": [
		"{pending} waiting · {dead} failed · {dropped} dropped",
		"{pending} bekliyor · {dead} iletilemedi · {dropped} atlandı",
	],
	"siem.central.empty": ["No central destination yet.", "Henüz merkezi hedef yok."],
	"siem.central.deadLetters": ["Dead letters", "İletilemeyen kayıtlar"],
	"siem.central.deadLettersLead": [
		"Events that could not be delivered after every retry. They are kept for up to 7 days; fix the collector, then resend them.",
		"Tüm denemelere rağmen iletilemeyen kayıtlar. En fazla 7 gün saklanır; toplayıcıyı düzelttikten sonra yeniden gönderin.",
	],
	"siem.central.deadAt": ["Failed at", "Başarısız olduğu zaman"],
	"siem.central.event": ["Event", "Kayıt"],
	"siem.central.lastError": ["Last error", "Son hata"],
	"siem.central.error.mfa": [
		"Verify with your authenticator app before changing SIEM destinations.",
		"SIEM hedeflerini değiştirmeden önce doğrulama uygulamanızla kimliğinizi doğrulayın.",
	],
	"siem.central.error.forbidden": [
		"Only workspace owners and administrators can manage SIEM forwarding.",
		"SIEM iletimini yalnızca çalışma alanı sahipleri ve yöneticileri yönetebilir.",
	],
	"siem.central.error.plan": [
		"Central SIEM forwarding needs the Business plan or higher.",
		"Merkezi SIEM iletimi için Business ya da daha üst bir plan gerekir.",
	],
	"siem.central.error.notConfigured": [
		"The server has no encryption key for destination secrets (AIDR_NOTIFICATION_ENCRYPTION_KEYS). Ask your AIDR operator.",
		"Sunucuda hedef gizli bilgileri için şifreleme anahtarı yok (AIDR_NOTIFICATION_ENCRYPTION_KEYS). AIDR yöneticinize başvurun.",
	],
	"siem.central.error.limit": [
		"This workspace already has the maximum number of destinations.",
		"Bu çalışma alanında en fazla hedef sayısına ulaşıldı.",
	],
	"siem.central.error.nameConflict": [
		"A destination with this name already exists.",
		"Bu adla bir hedef zaten var.",
	],
	"siem.central.error.private": [
		"Private network collectors are disabled on this server. The operator can allow them with AIDR_SIEM_ALLOW_PRIVATE_NETWORKS=true.",
		"Bu sunucuda iç ağdaki toplayıcılar kapalı. Yönetici AIDR_SIEM_ALLOW_PRIVATE_NETWORKS=true ile izin verebilir.",
	],
	"siem.central.error.plaintext": [
		"Plain TCP and UDP send events unencrypted. Choose TLS, or tick the plaintext option to accept that risk.",
		"Düz TCP ve UDP kayıtları şifresiz gönderir. TLS seçin ya da bu riski kabul etmek için şifresiz gönderim seçeneğini işaretleyin.",
	],
	"siem.central.error.ca": [
		"The CA certificate must be PEM certificates (TLS only).",
		"CA sertifikası PEM biçiminde olmalıdır (yalnız TLS için).",
	],
	"siem.central.error.https": [
		"The collector URL must use https.",
		"Toplayıcı adresi https kullanmalıdır.",
	],
	"siem.central.error.secret": [
		"The token, key or secret is missing or has the wrong length.",
		"Belirteç, anahtar ya da gizli bilgi eksik veya uzunluğu yanlış.",
	],
	"siem.central.error.host": [
		"Enter a valid host name or IP address.",
		"Geçerli bir sunucu adı ya da IP adresi girin.",
	],
	"siem.central.error.url": [
		"Enter the collector's base URL without a query string or credentials.",
		"Toplayıcının temel adresini sorgu dizesi ya da kimlik bilgisi olmadan girin.",
	],
	"siem.central.error.generic": ["The request failed ({code}).", "İstek başarısız oldu ({code})."],
	"siem.lead": [
		"Generate the {adapter} block for the host SIEM config ({path}). Delivery runs on the host from the durable local queue; nothing entered here is sent to the control plane, and no certificate check can be disabled.",
		"Sunucudaki SIEM yapılandırması ({path}) için {adapter} bloğunu oluşturun. Gönderim, sunucudaki kalıcı yerel kuyruktan yapılır; burada girilen hiçbir şey yönetim paneline gönderilmez ve hiçbir sertifika denetimi kapatılamaz.",
	],
	"siem.collector": ["Collector", "Toplayıcı"],
	"siem.transport": ["Transport", "Aktarım"],
	"siem.tls": [
		"TLS (RFC 5425 style, certificate verified)",
		"TLS (RFC 5425 tarzı, sertifika doğrulanır)",
	],
	"siem.tcp": [
		"TCP (RFC 6587 octet counting, unencrypted)",
		"TCP (RFC 6587 sekizli sayımı, şifresiz)",
	],
	"siem.udp": ["UDP (unacknowledged, unencrypted)", "UDP (alındı onayı yok, şifresiz)"],
	"siem.host": ["Collector host", "Toplayıcı sunucusu"],
	"siem.port": ["Port", "Bağlantı noktası"],
	"siem.facility": ["Facility (0-23)", "Syslog tesisi (facility, 0-23)"],
	"siem.appName": ["Application name", "Uygulama adı"],
	"siem.hostname": ["Reporting hostname (optional)", "Bildiren sunucu adı (isteğe bağlı)"],
	"siem.ca": ["Private CA certificate (PEM, optional)", "Özel CA sertifikası (PEM, isteğe bağlı)"],
	"siem.pins": [
		"Public-key pins, SHA-256 (optional)",
		"Açık anahtar sabitlemeleri, SHA-256 (isteğe bağlı)",
	],
	"siem.plaintext": [
		"I accept that incident data is sent unencrypted on this link",
		"Güvenlik vakası verilerinin bu bağlantıda şifresiz gönderileceğini kabul ediyorum",
	],
	"siem.private": [
		"The collector is on a private (on-premises) network",
		"Toplayıcı özel (şirket içi) bir ağda",
	],
	"siem.config": ["Host configuration", "Sunucu yapılandırması"],
	"siem.configLabel": ["Generated SIEM configuration", "Oluşturulan SIEM yapılandırması"],
	"siem.saveNote": [
		"Save the file with owner-only permissions on the host. Loopback, link-local and cloud-metadata destinations are always refused by the sender.",
		"Dosyayı sunucuda yalnızca sahibinin erişebileceği izinlerle kaydedin. Gönderici, loopback, link-local ve bulut meta veri hedeflerini her zaman reddeder.",
	],
	"siem.err.pem": [
		"The CA certificate must be PEM text (BEGIN CERTIFICATE ... END CERTIFICATE).",
		"CA sertifikası PEM metni olmalıdır (BEGIN CERTIFICATE ... END CERTIFICATE).",
	],
	"siem.err.pemSize": ["The CA certificate bundle is too large.", "CA sertifika paketi çok büyük."],
	"siem.err.pinCount": [
		"Provide at most 8 public-key pins.",
		"En fazla 8 açık anahtar sabitlemesi girin.",
	],
	"siem.err.pinFormat": [
		"Each pin must be a SHA-256 value in hex (64 characters) or base64.",
		"Her sabitleme onaltılık (64 karakter) ya da base64 biçiminde bir SHA-256 değeri olmalıdır.",
	],
	"siem.err.tlsOnly": [
		"CA and pin settings apply only to TLS destinations.",
		"CA ve sabitleme ayarları yalnızca TLS hedeflerine uygulanır.",
	],
	"siem.err.host": [
		"Enter the collector host name or address.",
		"Toplayıcı sunucusunun adını ya da adresini girin.",
	],
	"siem.err.blocked": [
		"Loopback, link-local, metadata and other non-routable addresses are not accepted for SIEM delivery.",
		"Loopback, link-local, meta veri ve diğer yönlendirilemeyen adresler SIEM gönderimi için kabul edilmez.",
	],
	"siem.err.hostInvalid": [
		"The host is not a valid DNS name or IP address.",
		"Sunucu geçerli bir DNS adı ya da IP adresi değil.",
	],
	"siem.err.private": [
		"This address is in a private range. Tick the private-network option to confirm an on-premises collector.",
		"Bu adres özel bir aralıkta. Şirket içi bir toplayıcı olduğunu doğrulamak için özel ağ seçeneğini işaretleyin.",
	],
	"siem.warn.resolve": [
		"The host name is resolved on the host at every send; every address it returns must satisfy the same policy.",
		"Sunucu adı her gönderimde sunucuda çözümlenir; döndürdüğü her adres aynı politikaya uymalıdır.",
	],
	"siem.err.port": [
		"The port must be a number from 1 to 65535.",
		"Bağlantı noktası 1 ile 65535 arasında bir sayı olmalıdır.",
	],
	"siem.err.facility": [
		"The facility must be a whole number from 0 to 23.",
		"Facility değeri 0 ile 23 arasında bir tam sayı olmalıdır.",
	],
	"siem.err.hostname": [
		"The reporting hostname must be printable ASCII without spaces.",
		"Bildiren sunucu adı boşluk içermeyen yazdırılabilir ASCII olmalıdır.",
	],
	"siem.err.appName": [
		"The application name must be printable ASCII without spaces (48 characters maximum).",
		"Uygulama adı boşluk içermeyen yazdırılabilir ASCII olmalıdır (en fazla 48 karakter).",
	],
	"siem.err.plaintext": [
		"Plain TCP and UDP send incident data unencrypted. Choose TLS, or tick the plaintext option to accept that risk.",
		"Düz TCP ve UDP güvenlik vakası verilerini şifresiz gönderir. TLS seçin ya da bu riski kabul etmek için şifresiz gönderim seçeneğini işaretleyin.",
	],
	"siem.warn.udp": [
		"UDP has no acknowledgement. The delivery receipt records the datagram as sent, not received.",
		"UDP'de alındı onayı yoktur. Teslim makbuzu, paketi alındı olarak değil gönderildi olarak kaydeder.",
	],
	"siem.warn.tcp": [
		"Plain TCP offers neither encryption nor server authentication.",
		"Düz TCP ne şifreleme ne de sunucu kimlik doğrulaması sunar.",
	],
} as const satisfies MessagePairs<string>;

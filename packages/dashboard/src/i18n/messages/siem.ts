import type { MessagePairs } from "./define";

/** SIEM syslog destination page. */
export const siemMessages = {
	"siem.title": ["SIEM syslog destination", "SIEM syslog hedefi"],
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

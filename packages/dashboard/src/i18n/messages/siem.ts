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
} as const satisfies MessagePairs<string>;

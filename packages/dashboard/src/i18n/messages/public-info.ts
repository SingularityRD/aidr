import type { MessagePairs } from "./define";

/** Public support, status, terms, privacy and security pages. */
export const publicInfoMessages = {
	"pi.support": ["Support", "Destek"],
	"pi.supportLead": [
		"Use the configured support channel for product questions, onboarding help, or incident reports. Do not include API keys, enrollment tokens, customer content, or access tokens in a ticket.",
		"Ürün soruları, kurulum yardımı ya da olay bildirimleri için yapılandırılmış destek kanalını kullanın. Bir destek talebine API anahtarı, kayıt belirteci, müşteri içeriği ya da erişim belirteci eklemeyin.",
	],
	"pi.openSupport": ["Open support channel", "Destek kanalını aç"],
	"pi.noSupport": [
		"No safe HTTPS support URL or approved support mailbox is configured. Do not promise a support SLA.",
		"Güvenli bir HTTPS destek adresi ya da onaylı bir destek e-posta kutusu yapılandırılmamış. Bir destek SLA'sı vaat etmeyin.",
	],
	"pi.emailSupport": ["Email support", "Desteğe e-posta gönder"],
	"pi.commitment": [
		"{lead} response schedule and escalation SLA are deployment-specific. Confirm those terms in your Order Form before relying on them.",
		"{lead} yanıt süreleri ve üst kademeye aktarma SLA'sı kuruluma göre değişir. Bunlara güvenmeden önce koşulları Sipariş Formunuzda doğrulayın.",
	],
	"pi.commitmentLead": ["Support commitment:", "Destek taahhüdü:"],
	"pi.diagnostics": ["Safe diagnostics", "Güvenli tanılama"],
	"pi.diagnosticsLead": [
		"When support asks for diagnostics, share only the redacted bundle produced by the documented workflow. Support access requires customer consent and must never require a raw secret.",
		"Destek tanılama bilgisi istediğinde yalnızca belgelenmiş akışın ürettiği maskelenmiş paketi paylaşın. Destek erişimi müşteri onayı gerektirir ve asla ham bir gizli bilgi istememelidir.",
	],
	"pi.status": ["Service status", "Hizmet durumu"],
	"pi.statusLead": [
		"Open the configured status link for deployment updates. This page does not monitor availability or verify when that destination was last updated.",
		"Kurulum güncellemeleri için yapılandırılmış durum bağlantısını açın. Bu sayfa erişilebilirliği izlemez ve o adresin en son ne zaman güncellendiğini doğrulamaz.",
	],
	"pi.openStatus": ["Open status updates", "Durum güncellemelerini aç"],
	"pi.noStatus": [
		"No live status feed is configured for this deployment. Do not infer availability from this page.",
		"Bu kurulum için canlı bir durum akışı yapılandırılmamış. Bu sayfadan erişilebilirlik sonucu çıkarmayın.",
	],
	"pi.terms": ["Terms and order scope", "Koşullar ve sipariş kapsamı"],
	"pi.termsLead": [
		"The signed Order Form and deployment-specific terms control your scope, pricing, support, data region, retention, and offboarding obligations.",
		"İmzalı Sipariş Formu ve kuruluma özel koşullar; kapsamınızı, fiyatlandırmayı, desteği, veri bölgesini, saklamayı ve hizmetten çıkış yükümlülüklerini belirler.",
	],
	"pi.readTerms": ["Read terms", "Koşulları oku"],
	"pi.noTerms": [
		"Terms URL is not configured. Do not sell or accept production data until legal terms are published and approved.",
		"Koşullar adresi yapılandırılmamış. Hukuki koşullar yayımlanıp onaylanana kadar satış yapmayın ve üretim verisi kabul etmeyin.",
	],
	"pi.privacy": ["Privacy notice", "Gizlilik bildirimi"],
	"pi.security": ["Security", "Güvenlik"],
	"pi.docLead": [
		"Review the configured deployment document before sending managed telemetry, AI Security Posture scan data, or customer content to this service.",
		"Bu hizmete yönetilen telemetri, yapay zekâ güvenlik durumu tarama verisi ya da müşteri içeriği göndermeden önce yapılandırılmış kurulum belgesini inceleyin.",
	],
	"pi.readPrivacy": ["Read privacy notice", "Gizlilik bildirimini oku"],
	"pi.readSecurity": ["Read security", "Güvenlik belgesini oku"],
	"pi.noPrivacy": [
		"Privacy notice URL is not configured with a safe HTTPS URL. Do not claim this document is available.",
		"Gizlilik bildirimi için güvenli bir HTTPS adresi yapılandırılmamış. Bu belgenin mevcut olduğunu söylemeyin.",
	],
	"pi.noSecurity": [
		"Security URL is not configured with a safe HTTPS URL. Do not claim this document is available.",
		"Güvenlik belgesi için güvenli bir HTTPS adresi yapılandırılmamış. Bu belgenin mevcut olduğunu söylemeyin.",
	],
	"pi.scope": [
		"Need help deciding whether your deployment is in scope? {link}.",
		"Kurulumunuzun kapsamda olup olmadığına karar vermek için yardım mı gerekiyor? {link}.",
	],
	"pi.contactSupport": ["Contact support", "Destekle iletişime geçin"],
} as const satisfies MessagePairs<string>;

import type { MessagePairs } from "./define";

/** AutoSecOps runtime integration page. */
export const autosecopsMessages = {
	"aso.notConfigured": [
		"AutoSecOps is not configured for this deployment. Ask your administrator to configure the runtime integration.",
		"AutoSecOps bu kurulumda yapılandırılmamış. Çalışma zamanı entegrasyonunu yapılandırması için yöneticinize başvurun.",
	],
	"aso.healthUnavailable": [
		"AutoSecOps health is unavailable.",
		"AutoSecOps durum bilgisi alınamıyor.",
	],
	"aso.healthInvalid": [
		"AutoSecOps health response is invalid.",
		"AutoSecOps durum yanıtı geçersiz.",
	],
	"aso.fleetUnavailable": [
		"AutoSecOps fleet is unavailable.",
		"AutoSecOps araç listesi alınamıyor.",
	],
	"aso.fleetInvalid": [
		"AutoSecOps fleet response is invalid.",
		"AutoSecOps araç listesi yanıtı geçersiz.",
	],
	"aso.selectTeam": [
		"Select a team to view its AutoSecOps runtime.",
		"AutoSecOps çalışma zamanını görmek için bir ekip seçin.",
	],
	"aso.bridgeUnavailable": [
		"AutoSecOps bridge is unavailable.",
		"AutoSecOps bağlantısı kullanılamıyor.",
	],
	"aso.team": ["AIDR team", "AIDR ekibi"],
	"aso.fleet": ["AutoSecOps runtime fleet", "AutoSecOps çalışma zamanı araçları"],
	"aso.fleetLead": [
		"Registered Claude Code, Codex, OpenCode, and other AIDR runtime connectors observed by AutoSecOps.",
		"AutoSecOps tarafından görülen kayıtlı Claude Code, Codex, OpenCode ve diğer AIDR bağlayıcıları.",
	],
	"aso.col.agent": ["Agent", "Yapay zekâ aracı"],
	"aso.col.runtime": ["Runtime / connector", "Çalışma zamanı / bağlayıcı"],
	"aso.col.state": ["State", "Durum"],
	"aso.col.lastEvent": ["Last event", "Son olay"],
	"aso.unknownId": ["unknown id", "bilinmeyen kimlik"],
	"aso.unknownConnector": ["unknown connector", "bilinmeyen bağlayıcı"],
	"aso.health": ["health: {state}", "sağlık: {state}"],
	"aso.fleetDataUnavailable": ["Fleet data is unavailable.", "Araç verileri alınamıyor."],
	"aso.noAgents": [
		"No AutoSecOps runtime agents reported yet.",
		"AutoSecOps henüz hiçbir yapay zekâ aracı bildirmedi.",
	],
	"aso.boundary": ["Integration boundary", "Entegrasyon sınırı"],
	"aso.boundaryLocal": [
		"AIDR performs local interception, redaction, and fail-closed policy checks.",
		"AIDR, araç çağrılarını yerelde yakalar, hassas verileri maskeler ve bir hata olduğunda engelleyen politika denetimleri yapar.",
	],
	"aso.boundaryRemote": [
		"AutoSecOps receives bounded identity, health, event, and decision observations through its canonical runtime API. It does not receive raw secrets or model authority.",
		"AutoSecOps, kendi çalışma zamanı API'si üzerinden yalnızca sınırlı kimlik, sağlık, olay ve karar bilgilerini alır. Ham gizli bilgileri almaz ve modeli yönetemez.",
	],
	"aso.component": ["component", "bileşen"],
	"aso.connected": ["Connected", "Bağlı"],
	"aso.connectedRestricted": ["Connected with restrictions", "Kısıtlamalarla bağlı"],
	"aso.unavailable": ["Unavailable", "Kullanılamıyor"],
	"aso.notConnected": ["Not connected", "Bağlı değil"],
	"aso.eyebrow": ["AIDR integration", "AIDR entegrasyonu"],
	"aso.lead": [
		"View the AutoSecOps runtime security control plane from AIDR. AIDR remains the local enforcement surface; AutoSecOps supplies tenant-scoped central runtime visibility.",
		"AutoSecOps çalışma zamanı güvenlik denetim katmanını AIDR'den görüntüleyin. Kararları yerelde AIDR uygular; AutoSecOps çalışma alanınız için merkezi görünürlük sağlar.",
	],
	"aso.integration": ["Integration", "Entegrasyon"],
	"aso.refreshing": ["Refreshing…", "Yenileniyor…"],
	"aso.updated": ["Updated {time}", "Güncellendi: {time}"],
	"aso.noSynthetic": [
		"No synthetic or cached AutoSecOps data is shown when the bridge is unavailable.",
		"Bağlantı kullanılamadığında örnek ya da önbellekteki AutoSecOps verisi gösterilmez.",
	],
	"aso.runtimeState": ["Runtime state", "Çalışma zamanı durumu"],
	"aso.runtimeStateHint": ["AutoSecOps observation", "AutoSecOps gözlemi"],
	"aso.activeAgents": ["Active agents", "Etkin yapay zekâ araçları"],
	"aso.activeAgentsHint": ["tenant-scoped runtime sessions", "çalışma alanına ait oturumlar"],
	"aso.degradations": ["Open degradations", "Açık bozulmalar"],
	"aso.degradationsHint": [
		"fail-closed health signal",
		"sorun olduğunda engelleyen sağlık sinyali",
	],
} as const satisfies MessagePairs<string>;

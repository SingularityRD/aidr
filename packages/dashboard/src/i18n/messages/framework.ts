import type { MessagePairs } from "./define";

/** Security framework coverage section (OWASP, MITRE ATLAS). */
export const frameworkMessages = {
	"fw.status.covered": ["covered", "kapsanıyor"],
	"fw.status.partial": ["partial", "kısmi"],
	"fw.status.notCovered": ["not covered", "kapsanmıyor"],
	"fw.status.notApplicable": ["not applicable", "uygulanamaz"],
	"fw.atlasSummary": [
		"{mapped} of {total} techniques and sub-techniques mapped ({covered} covered, {partial} partial); {touched} of {tactics} tactics touched. Unlisted techniques are not covered by the rule set.",
		"{total} teknik ve alt teknikten {mapped} tanesi eşlendi ({covered} kapsanıyor, {partial} kısmi); {tactics} taktikten {touched} tanesine dokunuldu. Listede olmayan teknikler kural setince kapsanmaz.",
	],
	"fw.summary": [
		"{covered} covered, {partial} partial, {notCovered} not covered, {notApplicable} not applicable of {total}.",
		"{total} maddeden {covered} kapsanıyor, {partial} kısmi, {notCovered} kapsanmıyor, {notApplicable} uygulanamaz.",
	],
	"fw.col.title": ["Title", "Başlık"],
	"fw.col.status": ["Status", "Durum"],
	"fw.col.rules": ["Rules", "Kurallar"],
	"fw.col.examples": ["Example rules", "Örnek kurallar"],
	"fw.col.rationale": ["Rationale", "Gerekçe"],
	"fw.title": ["Framework coverage", "Çerçeve kapsamı"],
	"fw.lead": [
		"How the {rules} detection rules shipped in {files} rule files map to OWASP and MITRE ATLAS. A mapping means a rule detects an instance of the risk at the agent's tool-call boundary or in a skill/plugin file; it is not a claim that every variant is prevented. Each rationale says what is not detected. This reflects the rule set this dashboard was built with; {command} prints the same matrix for the rules installed on an endpoint.",
		"{files} kural dosyasıyla gelen {rules} tespit kuralının OWASP ve MITRE ATLAS ile eşlemesi. Bir eşleme, kuralın bu riskin bir örneğini yapay zekâ aracının araç çağrısında ya da bir beceri/eklenti dosyasında yakaladığı anlamına gelir; her türün önlendiği iddiası değildir. Her gerekçe neyin yakalanmadığını da söyler. Bu tablo, bu panelin derlendiği kural setini yansıtır; {command} bir cihazda kurulu kurallar için aynı tabloyu yazdırır.",
	],
} as const satisfies MessagePairs<string>;

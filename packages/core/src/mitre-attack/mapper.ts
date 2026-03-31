/**
 * MITRE ATT&CK Framework Integration
 * Maps AIDR threat detections to ATT&CK techniques
 */

export interface AttackTechnique {
	id: string; // Txxxx.xxx format
	name: string;
	tactic: string;
	platform: string[];
	dataSources: string[];
	description: string;
	url: string;
	detection: string;
}

export interface AttackMapping {
	threatId: string;
	techniques: AttackTechnique[];
	confidence: number;
	dataComponents: string[];
}

export const ATTACK_TECHNIQUES: Record<string, AttackTechnique> = {
	T1059: {
		id: "T1059",
		name: "Command and Scripting Interpreter",
		tactic: "Execution",
		platform: ["Linux", "macOS", "Windows"],
		dataSources: ["Command Execution", "Process Creation", "Script Execution"],
		description:
			"Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
		url: "https://attack.mitre.org/techniques/T1059/",
		detection: "Monitor for command-line interface usage and suspicious script execution",
	},
	"T1059.004": {
		id: "T1059.004",
		name: "Unix Shell",
		tactic: "Execution",
		platform: ["Linux", "macOS"],
		dataSources: ["Command Execution", "Process Creation"],
		description: "Adversaries may abuse Unix shell commands and scripts for execution.",
		url: "https://attack.mitre.org/techniques/T1059/004/",
		detection: "Monitor for bash/sh/zsh execution with suspicious arguments",
	},
	T1105: {
		id: "T1105",
		name: "Ingress Tool Transfer",
		tactic: "Command and Control",
		platform: ["Linux", "macOS", "Windows"],
		dataSources: ["File Creation", "Network Traffic"],
		description:
			"Adversaries may transfer tools or other files from an external system into a compromised environment.",
		url: "https://attack.mitre.org/techniques/T1105/",
		detection: "Monitor for file downloads via curl/wget from external sources",
	},
	T1567: {
		id: "T1567",
		name: "Exfiltration Over Web Service",
		tactic: "Exfiltration",
		platform: ["Linux", "macOS", "Windows"],
		dataSources: ["Network Traffic", "File Access"],
		description:
			"Adversaries may use an existing, legitimate external Web service to exfiltrate data.",
		url: "https://attack.mitre.org/techniques/T1567/",
		detection: "Monitor for data sent to web services like pastebin, transfer.sh",
	},
	T1071: {
		id: "T1071",
		name: "Application Layer Protocol",
		tactic: "Command and Control",
		platform: ["Linux", "macOS", "Windows"],
		dataSources: ["Network Traffic"],
		description:
			"Adversaries may communicate using application layer protocols to avoid detection.",
		url: "https://attack.mitre.org/techniques/T1071/",
		detection: "Monitor for suspicious HTTP/HTTPS traffic patterns",
	},
	T1041: {
		id: "T1041",
		name: "Exfiltration Over C2 Channel",
		tactic: "Exfiltration",
		platform: ["Linux", "macOS", "Windows"],
		dataSources: ["Network Traffic"],
		description: "Adversaries may exfiltrate data over the command and control channel.",
		url: "https://attack.mitre.org/techniques/T1041/",
		detection: "Monitor for data sent over established C2 channels",
	},
	T1574: {
		id: "T1574",
		name: "Hijack Execution Flow",
		tactic: "Persistence",
		platform: ["Linux", "macOS", "Windows"],
		dataSources: ["File Modification", "Process Creation"],
		description: "Adversaries may hijack execution flow to establish persistence.",
		url: "https://attack.mitre.org/techniques/T1574/",
		detection: "Monitor for modification of .bashrc, .profile, cron jobs",
	},
	T1098: {
		id: "T1098",
		name: "Account Manipulation",
		tactic: "Persistence",
		platform: ["Linux", "macOS", "Windows"],
		dataSources: ["Authentication Logs", "Account Modification"],
		description: "Adversaries may manipulate accounts to maintain access.",
		url: "https://attack.mitre.org/techniques/T1098/",
		detection: "Monitor for SSH authorized_keys modifications, password changes",
	},
	T1083: {
		id: "T1083",
		name: "File and Directory Discovery",
		tactic: "Discovery",
		platform: ["Linux", "macOS", "Windows"],
		dataSources: ["Command Execution", "File Access"],
		description: "Adversaries may enumerate files and directories.",
		url: "https://attack.mitre.org/techniques/T1083/",
		detection: "Monitor for ls, find, dir commands with suspicious patterns",
	},
	T1552: {
		id: "T1552",
		name: "Unsecured Credentials",
		tactic: "Credential Access",
		platform: ["Linux", "macOS", "Windows"],
		dataSources: ["File Access", "Command Execution"],
		description:
			"Adversaries may search compromised systems to find and obtain unsecured credentials.",
		url: "https://attack.mitre.org/techniques/T1552/",
		detection: "Monitor for access to .env, .aws/credentials, .ssh files",
	},
	T1213: {
		id: "T1213",
		name: "Data from Information Repositories",
		tactic: "Collection",
		platform: ["Linux", "macOS", "Windows"],
		dataSources: ["File Access"],
		description: "Adversaries may leverage information repositories to mine valuable information.",
		url: "https://attack.mitre.org/techniques/T1213/",
		detection: "Monitor for access to database files, config files",
	},
	T1659: {
		id: "T1659",
		name: "Content Injection",
		tactic: "Impact",
		platform: ["Linux", "macOS", "Windows"],
		dataSources: ["File Modification"],
		description: "Adversaries may inject malicious content into files.",
		url: "https://attack.mitre.org/techniques/T1659/",
		detection: "Monitor for file modifications with suspicious content",
	},
};

// Map AIDR threat IDs to ATT&CK techniques
export const THREAT_TO_ATTACK_MAPPING: Record<string, string[]> = {
	// Command execution threats
	"CLT-CMD-001": ["T1059", "T1059.004", "T1105"], // curl | bash
	"CLT-CMD-002": ["T1059", "T1059.004", "T1105"], // wget | bash
	"CLT-CMD-003": ["T1059", "T1059.004"], // /dev/tcp reverse shell
	"CLT-CMD-004": ["T1059"], // netcat -e
	"CLT-CMD-005": ["T1059"], // bash -i reverse shell
	"CLT-CMD-014": ["T1059", "T1059.004"], // sudo curl | bash

	// Data exfiltration
	"CLT-CMD-013": ["T1567", "T1041"], // curl with sensitive data
	"CLT-CMD-020": ["T1567", "T1071"], // DNS exfiltration
	"CLT-CMD-021": ["T1567", "T1071"], // DNS exfiltration

	// Persistence
	"CLT-PERSIST-001": ["T1574"], // Shell RC modification
	"CLT-PERSIST-002": ["T1574"], // Crontab manipulation
	"CLT-PERSIST-003": ["T1574"], // Cron directory writes
	"CLT-PERSIST-005": ["T1574"], // systemd service
	"CLT-PERSIST-006": ["T1098"], // SSH authorized_keys
	"CLT-PERSIST-007": ["T1574"], // Echo append to RC files

	// Credential access
	"CLT-CRED-001": ["T1552"], // API key patterns
	"CLT-CRED-002": ["T1552"], // Export credentials
	"CLT-CRED-003": ["T1552"], // .env writes
	"CLT-CRED-004": ["T1552"], // Reading credential files
	"CLT-CRED-005": ["T1552"], // Plaintext credential assignment

	// File/directory discovery
	"CLT-FILE-001": ["T1083"], // /etc/passwd access
	"CLT-FILE-003": ["T1552"], // SSH keys
	"CLT-FILE-008": ["T1552"], // .env files
	"CLT-FILE-019": ["T1213"], // Shell history

	// Content injection
	"CLT-CMD-006": ["T1659"], // rm -rf /
	"CLT-CMD-027": ["T1659"], // .env deletion
	"CLT-CMD-028": ["T1659"], // Database deletion
	"CLT-CMD-029": ["T1659"], // .git deletion
};

export class MitreAttackMapper {
	/**
	 * Get ATT&CK technique details by ID
	 */
	static getTechnique(techniqueId: string): AttackTechnique | undefined {
		return ATTACK_TECHNIQUES[techniqueId];
	}

	/**
	 * Map AIDR threat ID to ATT&CK techniques
	 */
	static mapThreat(threatId: string): AttackMapping | null {
		const techniqueIds = THREAT_TO_ATTACK_MAPPING[threatId];
		if (!techniqueIds) {
			return null;
		}

		const techniques = techniqueIds
			.map((id) => ATTACK_TECHNIQUES[id])
			.filter((t): t is AttackTechnique => t !== undefined);

		return {
			threatId,
			techniques,
			confidence: 0.85,
			dataComponents: MitreAttackMapper.extractDataComponents(techniques),
		};
	}

	/**
	 * Get all mappings for a list of threats
	 */
	static mapThreats(threatIds: string[]): AttackMapping[] {
		return threatIds
			.map((id) => MitreAttackMapper.mapThreat(id))
			.filter(Boolean) as AttackMapping[];
	}

	/**
	 * Get coverage summary for reporting
	 */
	static getCoverageSummary(mappings: AttackMapping[]): {
		tactics: string[];
		techniques: string[];
		platforms: string[];
		coverage: number;
	} {
		const tactics = new Set<string>();
		const techniques = new Set<string>();
		const platforms = new Set<string>();

		for (const mapping of mappings) {
			for (const tech of mapping.techniques) {
				tactics.add(tech.tactic);
				techniques.add(tech.id);
				tech.platform.forEach((p) => platforms.add(p));
			}
		}

		const totalTechniques = Object.keys(ATTACK_TECHNIQUES).length;
		const coverage = (techniques.size / totalTechniques) * 100;

		return {
			tactics: [...tactics],
			techniques: [...techniques],
			platforms: [...platforms],
			coverage: Math.round(coverage * 100) / 100,
		};
	}

	/**
	 * Generate STIX 2.1 compatible indicator
	 */
	static generateStixIndicator(threatId: string, toolName: string): Record<string, unknown> {
		const mapping = MitreAttackMapper.mapThreat(threatId);
		if (!mapping) return {};

		return {
			type: "indicator",
			spec_version: "2.1",
			id: `indicator--${threatId.toLowerCase()}`,
			created: new Date().toISOString(),
			modified: new Date().toISOString(),
			name: `AIDR Detection: ${threatId}`,
			description: `Automatically generated indicator for ${threatId}`,
			pattern: `[tool:name = '${toolName}']`,
			pattern_type: "stix",
			valid_from: new Date().toISOString(),
			kill_chain_phases: mapping.techniques.map((t) => ({
				kill_chain_name: "mitre-attack",
				phase_name: t.tactic.toLowerCase().replace(/\s+/g, "-"),
			})),
			labels: mapping.techniques.map((t) => t.id),
		};
	}

	private static extractDataComponents(techniques: AttackTechnique[]): string[] {
		const components = new Set<string>();
		for (const tech of techniques) {
			tech.dataSources.forEach((ds) => components.add(ds));
		}
		return [...components];
	}
}

export function createMitreAttackMapper(): typeof MitreAttackMapper {
	return MitreAttackMapper;
}

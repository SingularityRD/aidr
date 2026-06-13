import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";

export interface EntropyMatch {
	type: "high_entropy";
	value: string;
	entropy: number;
	encoding: "base64" | "hex" | "url" | "unknown";
	decodedContent?: string;
	riskScore: number;
}

export class EntropyDetector {
	private readonly entropyThreshold: number;
	private readonly logger: Logger;

	constructor(entropyThreshold = 4.5, logger: Logger = nullLogger) {
		this.entropyThreshold = entropyThreshold;
		this.logger = logger;
	}

	detectObfuscation(content: string): EntropyMatch[] {
		const matches: EntropyMatch[] = [];

		const highEntropyStrings = this.extractHighEntropyStrings(content);

		for (const str of highEntropyStrings) {
			const encoding = this.detectEncoding(str);
			const decoded = this.tryDecode(str, encoding);

			if (decoded && this.isMalicious(decoded)) {
				matches.push({
					type: "high_entropy",
					value: str,
					entropy: this.calculateShannonEntropy(str),
					encoding,
					decodedContent: decoded,
					riskScore: this.calculateRisk(str, decoded),
				});
			}
		}

		return matches;
	}

	private extractHighEntropyStrings(content: string): string[] {
		const results: string[] = [];
		const minLength = 20;

		const patterns = [/[A-Za-z0-9+/]{40,}={0,2}/g, /[0-9a-fA-F]{40,}/g, /%[0-9a-fA-F]{2}/g];

		for (const pattern of patterns) {
			const matches = content.match(pattern) || [];
			for (const match of matches) {
				if (
					match.length >= minLength &&
					this.calculateShannonEntropy(match) > this.entropyThreshold
				) {
					results.push(match);
				}
			}
		}

		return [...new Set(results)];
	}

	private calculateShannonEntropy(str: string): number {
		const charCounts = new Map<string, number>();

		for (const char of str) {
			charCounts.set(char, (charCounts.get(char) || 0) + 1);
		}

		let entropy = 0;
		const len = str.length;

		for (const count of charCounts.values()) {
			const probability = count / len;
			entropy -= probability * Math.log2(probability);
		}

		return entropy;
	}

	private detectEncoding(str: string): EntropyMatch["encoding"] {
		if (/^[A-Za-z0-9+/]*={0,2}$/.test(str) && str.length % 4 === 0) {
			return "base64";
		}
		if (/^[0-9a-fA-F]+$/.test(str)) {
			return "hex";
		}
		if (str.startsWith("%") && /%[0-9a-fA-F]{2}/.test(str)) {
			return "url";
		}
		return "unknown";
	}

	private tryDecode(str: string, encoding: string): string | undefined {
		try {
			if (encoding === "base64") {
				const decoded = atob(str);
				if (/^[\x20-\x7E\n\r\t]*$/.test(decoded)) {
					return decoded;
				}
			} else if (encoding === "hex") {
				const bytes = str.match(/.{1,2}/g) || [];
				const decoded = bytes.map((b) => String.fromCharCode(parseInt(b, 16))).join("");
				if (/^[\x20-\x7E\n\r\t]*$/.test(decoded)) {
					return decoded;
				}
			} else if (encoding === "url") {
				return decodeURIComponent(str);
			}
		} catch {
			return undefined;
		}
		return undefined;
	}

	private isMalicious(decoded: string): boolean {
		const maliciousPatterns = [
			/bash|sh|zsh|ksh/,
			/curl|wget|fetch/,
			/eval|exec|system/,
			/import\s+os|import\s+subprocess/,
			/nc\s+-e|netcat/,
			/\/dev\/tcp/,
			/>\s*\/etc\/|>>\s*\/etc\//,
		];

		return maliciousPatterns.some((p) => p.test(decoded.toLowerCase()));
	}

	private calculateRisk(encoded: string, decoded: string): number {
		let risk = 50;

		risk += Math.min(30, this.calculateShannonEntropy(encoded) * 5);

		const maliciousKeywords = ["bash", "sh", "curl", "wget", "eval", "exec"];
		for (const kw of maliciousKeywords) {
			if (decoded.toLowerCase().includes(kw)) {
				risk += 10;
			}
		}

		return Math.min(100, risk);
	}
}

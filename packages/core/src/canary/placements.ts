/**
 * Decoy credential shapes and the file names they are planted under.
 *
 * Every value is freshly random, looks like the real credential to an agent,
 * and is never valid anywhere:
 *   - AWS access key IDs use a character outside AWS's key-ID alphabet
 *     (A-Z, 2-7), so no AWS account can ever have issued one;
 *   - the other values are random strings no provider issued, and hosts sit
 *     under the non-public `.internal` domain.
 *
 * Each value's detection core is an alphanumeric run of at least 20 characters
 * that the file delimits with non-alphanumeric characters; the detector hashes
 * alphanumeric runs and compares digests, so the core must stay alphanumeric.
 */

import { randomInt } from "node:crypto";
import type { CanaryKind } from "./registry.js";

export type CanaryScope = "home" | "project";

export interface CanaryPlacement {
	/** `home`: under the user's home directory; `project`: under `--path` (default: cwd). */
	scope: CanaryScope;
	/** Relative candidate paths, tried in order; the first that does not exist is used. */
	candidates: readonly string[];
}

/** Data list of decoy locations. Deploy only ever creates one of these; it never edits a file. */
export const CANARY_PLACEMENTS: Readonly<Record<CanaryKind, CanaryPlacement>> = {
	aws: {
		scope: "home",
		candidates: [
			".aws/credentials.old",
			".aws/credentials.bak",
			".aws/credentials.backup",
			".aws/credentials-2023.bak",
		],
	},
	github: {
		scope: "home",
		candidates: [".git-credentials.old", ".git-credentials.bak", ".git-credentials.backup"],
	},
	openai: {
		scope: "home",
		candidates: [".config/openai/api_key.old", ".config/openai/api_key.bak", ".openai_api_key.bak"],
	},
	env: {
		scope: "project",
		candidates: [".env.backup", ".env.production.bak", ".env.old", ".env.local.backup"],
	},
	"ssh-config": {
		scope: "home",
		candidates: [".ssh/config.old", ".ssh/config.bak", ".ssh/config.backup"],
	},
	"db-url": {
		scope: "project",
		candidates: [".env.database.bak", "database.url.bak", ".db-credentials.old"],
	},
};

const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
const ALNUM = UPPER + LOWER + DIGITS;
/** AWS key IDs are base32 (A-Z, 2-7). These digits can never appear in a real one. */
const AWS_KEY_ID_ALPHABET = `${UPPER}234567`;
const NON_AWS_DIGITS = "0189";

export type RandomIndex = (max: number) => number;

const cryptoIndex: RandomIndex = (max) => randomInt(max);

function randomString(length: number, alphabet: string, next: RandomIndex): string {
	let value = "";
	for (let index = 0; index < length; index += 1) value += alphabet[next(alphabet.length)];
	return value;
}

/** `AKIA` + 16 characters, one of which is outside the AWS key-ID alphabet. */
export function decoyAwsAccessKeyId(next: RandomIndex = cryptoIndex): string {
	const body = randomString(16, AWS_KEY_ID_ALPHABET, next).split("");
	body[1 + next(15)] = NON_AWS_DIGITS[next(NON_AWS_DIGITS.length)] as string;
	return `AKIA${body.join("")}`;
}

export interface RenderedCanary {
	content: string;
	/** Alphanumeric detection cores; only their digests are registered. */
	tokens: string[];
}

/** Render the decoy file for a kind with fresh random values. */
export function renderCanary(kind: CanaryKind, next: RandomIndex = cryptoIndex): RenderedCanary {
	switch (kind) {
		case "aws": {
			const keyId = decoyAwsAccessKeyId(next);
			const secret = randomString(40, ALNUM, next);
			return {
				content: [
					"# Rotated credentials - keep until the prod-admin migration is complete",
					"[prod-admin]",
					`aws_access_key_id = ${keyId}`,
					`aws_secret_access_key = ${secret}`,
					"region = us-east-1",
					"",
				].join("\n"),
				tokens: [keyId, secret],
			};
		}
		case "github": {
			const token = randomString(36, ALNUM, next);
			return {
				content: `https://ci-deploy-bot:ghp_${token}@github.com\n`,
				tokens: [token],
			};
		}
		case "openai": {
			const token = randomString(48, ALNUM, next);
			return {
				content: `# batch-jobs service key (old org)\nOPENAI_API_KEY=sk-proj-${token}\n`,
				tokens: [token],
			};
		}
		case "env": {
			const appSecret = randomString(40, ALNUM, next);
			const jwtSecret = randomString(48, ALNUM, next);
			const apiToken = randomString(32, ALNUM, next);
			return {
				content: [
					"# production backup - do not commit",
					"NODE_ENV=production",
					`APP_SECRET=${appSecret}`,
					`JWT_SECRET=${jwtSecret}`,
					`INTERNAL_API_KEY=itk_${apiToken}`,
					"",
				].join("\n"),
				tokens: [appSecret, jwtSecret, apiToken],
			};
		}
		case "ssh-config": {
			const host = randomString(24, LOWER + DIGITS, next);
			return {
				content: [
					"Host prod-bastion",
					`    HostName bastion-${host}.corp.internal`,
					"    User deploy",
					"    IdentityFile ~/.ssh/deploy_prod_ed25519",
					"    Port 22",
					"",
				].join("\n"),
				tokens: [host],
			};
		}
		case "db-url": {
			const password = randomString(32, ALNUM, next);
			return {
				content: `DATABASE_URL=postgres://svc_reporting:${password}@db-primary.corp.internal:5432/production\n`,
				tokens: [password],
			};
		}
	}
}

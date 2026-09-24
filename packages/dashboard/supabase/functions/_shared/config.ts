// Fail-fast configuration validation for Supabase Edge Functions.
//
// Every Edge Function reads platform configuration from `Deno.env`. Reading a
// REQUIRED value with an empty-string fallback (the `?? <empty>` idiom this
// finding is about) does not fail fast: the function proceeds with an empty
// credential and either fails later with an opaque downstream error or, worse,
// behaves in a way that merely looks successful. (AIDR-011)
//
// This module is the single fail-closed boundary for that read:
//
//   1. `loadConfig` validates every required variable and returns a structured
//      `ConfigurationError` when one of them is absent. Handlers call it before
//      any authentication, database or network work, so a misconfigured
//      deployment answers with an explicit 5xx instead of a confusing
//      downstream failure.
//   2. The error names the missing VARIABLE and never its value. `missing` and
//      `invalid` are filtered against the environment-variable name grammar, so
//      even a caller that passes a value by mistake cannot publish it.
//   3. `toResponseBody()` is the caller-visible projection: a machine-readable
//      code plus variable names. Every other detail stays server-side.
//
// Reading the values at module scope is safe (the Edge Functions runtime fixes
// `Deno.env` for the lifetime of the isolate); what must happen per request is
// the *validation*, so that a missing variable produces a 500 with a clear body
// rather than a boot failure with an opaque one.
//
// This module deliberately imports nothing Deno-, Node- or SDK-specific, so the
// exact code shipped inside the Edge Functions is the code exercised by
// `supabase/functions/__tests__/config.test.ts` under vitest.

/** Reads one variable. Returns "" when it is unset. */
export type EnvReader = (name: string) => string | undefined | null;

/** Machine-readable code for every server configuration failure. */
export const CONFIGURATION_ERROR_CODE = "server_misconfigured";

/** HTTP status for a server configuration failure: the caller cannot fix it. */
export const CONFIGURATION_ERROR_STATUS = 500;

/**
 * Environment-variable names only. Anything else is dropped from a
 * caller-visible projection, so a secret value can never be emitted even if a
 * caller misuses the API.
 */
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;

function envNames(values: readonly string[]): string[] {
	return values.filter((value) => typeof value === "string" && ENV_NAME.test(value));
}

export interface ConfigurationErrorOptions {
	/** Override the machine-readable code. Defaults to `server_misconfigured`. */
	code?: string;
	/** Override the HTTP status. Defaults to 500. */
	status?: number;
}

/**
 * A server-side configuration failure.
 *
 * The instance holds variable NAMES only. It never receives, stores or echoes a
 * configured value, so neither `message`, `toResponseBody()` nor
 * `toLogDetail()` can leak a secret.
 */
export class ConfigurationError extends Error {
	readonly code: string;
	readonly status: number;
	readonly missing: readonly string[];
	readonly invalid: readonly string[];

	constructor(
		problem: { missing?: readonly string[]; invalid?: readonly string[] },
		options: ConfigurationErrorOptions = {},
	) {
		const missing = envNames(problem.missing ?? []);
		const invalid = envNames(problem.invalid ?? []);
		super(describe(missing, invalid));
		this.name = "ConfigurationError";
		this.code = options.code ?? CONFIGURATION_ERROR_CODE;
		this.status = options.status ?? CONFIGURATION_ERROR_STATUS;
		this.missing = missing;
		this.invalid = invalid;
	}

	/** Every variable named by this error, missing and invalid alike. */
	get variables(): readonly string[] {
		return [...this.missing, ...this.invalid];
	}

	/** Caller-visible body: code plus variable names, never a value. */
	toResponseBody(): Record<string, unknown> {
		const body: Record<string, unknown> = { error: this.code };
		if (this.missing.length > 0) body.missing = [...this.missing];
		if (this.invalid.length > 0) body.invalid = [...this.invalid];
		return body;
	}

	/** Operator-visible detail for the server log: names, never values. */
	toLogDetail(): Record<string, unknown> {
		return {
			code: this.code,
			status: this.status,
			missing: [...this.missing],
			invalid: [...this.invalid],
		};
	}
}

function describe(missing: readonly string[], invalid: readonly string[]): string {
	const parts: string[] = [];
	if (missing.length > 0) parts.push(`missing ${missing.join(", ")}`);
	if (invalid.length > 0) parts.push(`invalid ${invalid.join(", ")}`);
	return parts.length > 0
		? `server configuration error: ${parts.join("; ")}`
		: "server configuration error";
}

export function isConfigurationError(value: unknown): value is ConfigurationError {
	return value instanceof ConfigurationError;
}

/** Read one variable. Whitespace-only values are treated as unset. */
export function readConfigValue(env: EnvReader, name: string): string {
	if (!ENV_NAME.test(name)) return "";
	let value: string | undefined | null;
	try {
		value = env(name);
	} catch {
		// An unreadable variable is an absent variable: fail closed.
		return "";
	}
	return typeof value === "string" ? value : "";
}

export function isConfiguredValue(value: string | undefined | null): boolean {
	return typeof value === "string" && value.trim() !== "";
}

interface LoadedConfig {
	readonly ok: true;
	readonly values: Readonly<Record<string, string>>;
}

interface MissingConfig {
	readonly ok: false;
	readonly error: ConfigurationError;
}

export type ConfigResult = LoadedConfig | MissingConfig;

/**
 * Validate every required variable.
 *
 * All absent names are reported at once, so one fix cycle reveals the whole
 * misconfiguration. Values are returned unmodified (no trimming) so an existing
 * deployment cannot be changed by this helper.
 *
 * @throws TypeError when a name is not an environment-variable name. That is a
 * programming error in the calling function, not a deployment error, and it
 * must fail loudly in tests rather than publish an arbitrary string.
 */
export function loadConfig(env: EnvReader, names: readonly string[]): ConfigResult {
	const values: Record<string, string> = {};
	const missing: string[] = [];

	for (const name of names) {
		if (!ENV_NAME.test(name)) {
			// The offending name is deliberately not echoed: it could be a value.
			throw new TypeError("required configuration names must match /^[A-Z][A-Z0-9_]{0,63}$/");
		}
		const value = readConfigValue(env, name);
		if (!isConfiguredValue(value)) {
			missing.push(name);
			continue;
		}
		values[name] = value;
	}

	if (missing.length > 0) return { ok: false, error: new ConfigurationError({ missing }) };
	return { ok: true, values };
}

/**
 * Report a half-configured "all or nothing" group: a signing key id plus its
 * private key, an endpoint plus its token.
 *
 * A group whose members are ALL absent is simply not provisioned; the calling
 * function handles that explicitly. A group with only SOME members present is a
 * misconfiguration: the operator believes the feature is enabled and the
 * function would otherwise silently degrade.
 *
 * Only the record's KEYS (environment-variable names) are used; the values are
 * inspected for emptiness and are never stored on, or reported by, the result.
 */
export function partialGroupError(group: Readonly<Record<string, string>>): ConfigurationError | null {
	const names = Object.keys(group).filter((name) => ENV_NAME.test(name));
	if (names.length < 2) return null;
	const missing = names.filter((name) => !isConfiguredValue(group[name]));
	if (missing.length === 0 || missing.length === names.length) return null;
	return new ConfigurationError({ missing });
}

/** Operator-visible log line. Names the variables; never a value. */
export function logConfigFailure(scope: string, error: ConfigurationError): void {
	console.error(`[${scope}] configuration error`, JSON.stringify(error.toLogDetail()));
}

/** Maps a configuration failure onto the function's own response helper. */
export type ConfigErrorResponder = (
	status: number,
	body: Record<string, unknown>,
) => Response;

/**
 * Log the internal detail and answer the caller with the variable names.
 *
 * Naming the variable is what makes a misconfigured deployment unambiguous; a
 * value is never part of the body (see `toResponseBody`).
 */
export function configFailure(
	scope: string,
	error: ConfigurationError,
	respond: ConfigErrorResponder,
): Response {
	logConfigFailure(scope, error);
	return respond(error.status, error.toResponseBody());
}

/**
 * Reader bound to the Edge Functions runtime.
 *
 * `Deno.env` is referenced inside the closure, so importing this module under
 * Node (vitest) is safe - the reference is only resolved when the reader is
 * actually called.
 */
export const runtimeEnv: EnvReader = (name) => Deno.env.get(name);

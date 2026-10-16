const SECRET_PATH = /api[_-]?key|token|secret|password|private[_-]?key/i;

export function isSecretConfigPath(path: string): boolean {
	return SECRET_PATH.test(path);
}

export function containsSecretConfigValue(value: unknown): boolean {
	return (
		value !== null &&
		typeof value === "object" &&
		Object.entries(value).some(
			([key, nested]) => isSecretConfigPath(key) || containsSecretConfigValue(nested),
		)
	);
}

export function configPathParts(path: string): string[] {
	const parts = path.split(".");
	if (
		parts.some(
			(part) =>
				!/^[A-Za-z][A-Za-z0-9_]*$/.test(part) ||
				["__proto__", "prototype", "constructor"].includes(part),
		)
	) {
		throw new Error("Invalid configuration path");
	}
	return parts;
}
export function displayConfigValue(path: string, value: unknown): string {
	if (isSecretConfigPath(path)) return value ? "[redacted]" : "(not set)";
	return typeof value === "object" ? "[object]" : String(value);
}
export function parseConfigValue(value: string): unknown {
	try {
		return JSON.parse(value);
	} catch {
		return value;
	}
}

/**
 * Whether a dotted path names a field of the configuration schema. An optional
 * field that is simply unset still exists; a misspelled key does not.
 */
export function isKnownConfigPath(schema: unknown, parts: readonly string[]): boolean {
	let node = schema as { _def?: Record<string, unknown> } | undefined;
	for (const part of parts) {
		node = unwrapSchema(node);
		const def = node?._def;
		if (!def) return false;
		if (def.typeName === "ZodObject") {
			const shape = (def.shape as () => Record<string, unknown>)();
			if (!(part in shape)) return false;
			node = shape[part] as typeof node;
		} else if (def.typeName === "ZodRecord") {
			node = def.valueType as typeof node;
		} else if (def.typeName === "ZodArray" && /^\d+$/.test(part)) {
			node = def.type as typeof node;
		} else {
			return false;
		}
	}
	return node !== undefined;
}

function unwrapSchema(node: { _def?: Record<string, unknown> } | undefined) {
	let current = node;
	for (let depth = 0; depth < 10 && current?._def; depth++) {
		const def = current._def;
		const inner =
			def.typeName === "ZodOptional" ||
			def.typeName === "ZodNullable" ||
			def.typeName === "ZodDefault" ||
			def.typeName === "ZodReadonly"
				? def.innerType
				: def.typeName === "ZodEffects"
					? def.schema
					: def.typeName === "ZodPipeline"
						? def.in
						: undefined;
		if (!inner) break;
		current = inner as typeof current;
	}
	return current;
}

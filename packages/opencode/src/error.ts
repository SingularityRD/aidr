export abstract class AidrVerdictError extends Error {
	constructor(message: string, name?: string) {
		super(message);
		this.name = name ?? "AidrVerdictError";
	}
}

export class AidrVerdictBlockError extends AidrVerdictError {
	constructor(message: string) {
		super(message, "AidrVerdictBlockError");
	}
}

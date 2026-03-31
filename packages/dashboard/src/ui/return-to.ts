const KEY = "aidr.postAuthReturnTo.v1";

export function setPostAuthReturnTo(path: string) {
	try {
		localStorage.setItem(KEY, path);
	} catch {
		// ignore
	}
}

export function takePostAuthReturnTo(): string | null {
	try {
		const v = localStorage.getItem(KEY);
		if (!v) return null;
		localStorage.removeItem(KEY);
		return v;
	} catch {
		return null;
	}
}

export function buildReturnToFromRequest(request: Request): string {
	try {
		const url = new URL(request.url);
		const path = `${url.pathname}${url.search}`;
		return path || "/";
	} catch {
		return "/";
	}
}

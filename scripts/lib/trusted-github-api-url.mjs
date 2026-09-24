export function assertTrustedGitHubApiUrl(apiUrl, serverUrl) {
	let api;
	let server;
	try {
		api = new URL(apiUrl);
		server = new URL(serverUrl);
	} catch {
		throw new Error("GitHub API and server URLs must be valid absolute URLs");
	}
	if (
		api.protocol !== "https:" ||
		api.username ||
		api.password ||
		api.search ||
		api.hash ||
		server.protocol !== "https:" ||
		server.username ||
		server.password ||
		server.search ||
		server.hash
	) {
		throw new Error("GitHub API and server URLs must be credential-free HTTPS URLs");
	}
	const expectedOrigin = server.hostname.toLowerCase() === "github.com" ? "https://api.github.com" : server.origin;
	if (api.origin !== expectedOrigin) {
		throw new Error("GitHub API origin does not match the trusted GitHub server");
	}
	return api;
}

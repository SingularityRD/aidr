const PROVIDER_ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;

function validDomain(domain) {
	return domain.length <= 253 && domain.includes(".") && domain.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}

export function parseSamlRuntimeConfig({ providers: rawProviders, providerId: rawProviderId, domain: rawDomain }) {
	const providersText = rawProviders?.trim();
	const providerId = rawProviderId?.trim();
	const domain = rawDomain?.trim();
	const configured = [providersText, providerId, domain].filter(Boolean).length;
	if (configured > 1) throw new Error("Configure only one of AIDR_SAML_PROVIDERS, AIDR_SAML_PROVIDER_ID, or AIDR_SAML_DOMAIN");
	if (providersText) {
		if (providersText.length > 4096) throw new Error("Invalid AIDR_SAML_PROVIDERS");
		let entries;
		try { entries = JSON.parse(providersText); } catch { throw new Error("Invalid AIDR_SAML_PROVIDERS"); }
		if (!Array.isArray(entries) || entries.length < 1 || entries.length > 8) throw new Error("Invalid AIDR_SAML_PROVIDERS");
		const seenIds = new Set();
		const seenLabels = new Set();
		const samlProviders = entries.map((entry) => {
			if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error("Invalid AIDR_SAML_PROVIDERS");
			const id = typeof entry.providerId === "string" ? entry.providerId.trim() : "";
			const label = typeof entry.label === "string" ? entry.label.trim() : "";
			if (!PROVIDER_ID.test(id) || label.length < 1 || label.length > 64 || /[\u0000-\u001f\u007f-\u009f]/.test(label)) throw new Error("Invalid AIDR_SAML_PROVIDERS");
			const normalizedId = id.toLowerCase();
			const normalizedLabel = label.toLowerCase();
			if (seenIds.has(normalizedId) || seenLabels.has(normalizedLabel)) throw new Error("Invalid AIDR_SAML_PROVIDERS");
			seenIds.add(normalizedId);
			seenLabels.add(normalizedLabel);
			return { providerId: id, label };
		});
		return { samlProviders };
	}
	if (providerId && !PROVIDER_ID.test(providerId)) throw new Error("Invalid AIDR_SAML_PROVIDER_ID");
	if (domain && !validDomain(domain)) throw new Error("Invalid AIDR_SAML_DOMAIN");
	return providerId ? { samlProviderId: providerId } : domain ? { samlDomain: domain } : {};
}

/** AIDR_OIDC_SSO=true shows the work-email OIDC sign-in form. Anything else (including unset) leaves it off. */
export function parseOidcRuntimeConfig(raw) {
	const value = raw?.trim().toLowerCase();
	if (value === undefined || value === "" || value === "false") return {};
	if (value === "true") return { oidcSso: true };
	throw new Error("Invalid AIDR_OIDC_SSO");
}

export function checkoutParameters(input: {
	userId: string; tenantId: string; settlementId: string; requestId: string; seats: number; plan: string; monthlyPrice: string; yearlyPrice?: string; dashboardUrl: string;
}): URLSearchParams {
	if (!Number.isSafeInteger(input.seats) || input.seats < 1 || input.seats > 10000) throw new Error("invalid_seat_count");
	if (!["monthly", "yearly"].includes(input.plan)) throw new Error("invalid_billing_interval");
	if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.settlementId)) throw new Error("invalid_settlement_id");
	if (!/^[a-zA-Z0-9_-]{16,80}$/.test(input.requestId)) throw new Error("invalid_request_id");
	const price = input.plan === "yearly" ? input.yearlyPrice : input.monthlyPrice;
	if (!price || !/^price_[a-zA-Z0-9]+$/.test(price)) throw new Error("billing_price_not_configured");
	const url = new URL(input.dashboardUrl);
	if (url.protocol !== "https:" || url.username || url.password) throw new Error("invalid_dashboard_url");
	const form = new URLSearchParams({ mode: "subscription", "line_items[0][price]": price, "line_items[0][quantity]": String(input.seats), client_reference_id: input.userId,
		success_url: `${url.origin}/settings?checkout=success`, cancel_url: `${url.origin}/settings?checkout=cancelled` });
	for (const prefix of ["metadata", "subscription_data[metadata]"]) {
		form.set(`${prefix}[user_id]`, input.userId);
		form.set(`${prefix}[tenant_id]`, input.tenantId);
		form.set(`${prefix}[settlement_id]`, input.settlementId);
		form.set(`${prefix}[request_id]`, input.requestId);
	}
	return form;
}

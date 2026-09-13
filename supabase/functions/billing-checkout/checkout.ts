export function checkoutParameters(input: {
	userId: string; tenantId: string; seats: number; plan: string; monthlyPrice: string; yearlyPrice?: string; dashboardUrl: string;
}): URLSearchParams {
	if (!Number.isSafeInteger(input.seats) || input.seats < 1 || input.seats > 10000) throw new Error("invalid_seat_count");
	if (!["monthly", "yearly"].includes(input.plan)) throw new Error("invalid_billing_interval");
	const price = input.plan === "yearly" ? input.yearlyPrice : input.monthlyPrice;
	if (!price || !/^price_[a-zA-Z0-9]+$/.test(price)) throw new Error("billing_price_not_configured");
	const url = new URL(input.dashboardUrl);
	if (url.protocol !== "https:" || url.username || url.password) throw new Error("invalid_dashboard_url");
	const form = new URLSearchParams({ mode: "subscription", "line_items[0][price]": price, "line_items[0][quantity]": String(input.seats), client_reference_id: input.userId,
		success_url: `${url.origin}/settings?checkout=success`, cancel_url: `${url.origin}/settings?checkout=cancelled` });
	for (const prefix of ["metadata", "subscription_data[metadata]"]) {
		form.set(`${prefix}[user_id]`, input.userId);
		form.set(`${prefix}[tenant_id]`, input.tenantId);
	}
	return form;
}

import { selfServiceCheckoutEnabled } from "./commercial";
import type { ProviderType } from "./payment-router";

interface ProviderOption {
	id: ProviderType;
	name: string;
	icon: string;
	features: string[];
	recommended?: boolean;
}

interface PaymentProviderSelectorProps {
	userLocation: string;
	onSelect: (provider: ProviderType) => void;
	selectedProvider?: ProviderType;
}

export function PaymentProviderSelector({
	userLocation,
	onSelect,
	selectedProvider,
}: PaymentProviderSelectorProps) {
	const providers = buildProviderList(userLocation);

	return (
		<div className="payment-provider-selector">
			<h3>Select Payment Method</h3>
			<div className="provider-cards">
				{providers.map((provider) => (
					<ProviderCard
						key={provider.id}
						provider={provider}
						isSelected={selectedProvider === provider.id}
						onClick={() => onSelect(provider.id)}
					/>
				))}
			</div>
		</div>
	);
}

interface ProviderCardProps {
	provider: ProviderOption;
	isSelected: boolean;
	onClick: () => void;
}

function ProviderCard({ provider, isSelected, onClick }: ProviderCardProps) {
	return (
		<div
			className={`provider-card ${isSelected ? "selected" : ""} ${provider.recommended ? "recommended" : ""}`}
			onClick={onClick}
			role="button"
			tabIndex={0}
			onKeyDown={(e) => e.key === "Enter" && onClick()}
		>
			{provider.recommended && <span className="badge recommended">Recommended</span>}

			<img src={provider.icon} alt={provider.name} className="provider-icon" />

			<h4>{provider.name}</h4>

			<ul className="features">
				{provider.features.map((feature) => (
					<li key={feature}>{feature}</li>
				))}
			</ul>
		</div>
	);
}

export function ProviderCards({
	providers,
	onSelect,
	selectedProvider,
}: {
	providers: ProviderOption[];
	onSelect?: (provider: ProviderType) => void;
	selectedProvider?: ProviderType;
}) {
	return (
		<div className="provider-cards">
			{providers.map((provider) => (
				<ProviderCard
					key={provider.id}
					provider={provider}
					isSelected={selectedProvider === provider.id}
					onClick={() => onSelect?.(provider.id)}
				/>
			))}
		</div>
	);
}

/**
 * Build provider list - now LemonSqueezy only
 * Removed: iyzico, stripe, crypto providers (user requested only LemonSqueezy)
 */
export function buildProviderList(_userLocation: string): ProviderOption[] {
	if (!selfServiceCheckoutEnabled) return [];
	return [
		{
			id: "lemon-squeezy",
			name: "LemonSqueezy (Global)",
			icon: "/lemonsqueezy-logo.svg",
			features: ["USD/EUR/GBP", "Subscription", "Checkout", "Customer Portal"],
			recommended: true,
		},
	];
}

/**
 * Get payment button text - now always returns LemonSqueezy text
 */
export function getPaymentButtonText(_provider: ProviderType, _userLocation: string): string {
	if (!selfServiceCheckoutEnabled) return "Request enterprise invoice";
	return "Subscribe with LemonSqueezy";
}

/**
 * Get currency display symbol
 */
export function getCurrencySymbol(currency: string): string {
	const symbols: Record<string, string> = {
		USD: "$",
		EUR: "€",
		GBP: "£",
		TRY: "₺",
		JPY: "¥",
	};
	return symbols[currency] || currency;
}

/**
 * Format price with psychological pricing (.99)
 */
export function formatPrice(amount: number, currency: string): string {
	const symbol = getCurrencySymbol(currency);
	const formatted = amount.toFixed(2);
	return `${symbol}${formatted}`;
}

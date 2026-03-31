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
			{provider.id === "crypto" && <span className="badge privacy">Privacy</span>}

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
 * Build provider list based on user location
 */
export function buildProviderList(userLocation: string): ProviderOption[] {
	const providers: ProviderOption[] = [];

	if (userLocation === "TR") {
		providers.push({
			id: "iyzico",
			name: "Kredi/Banka Kartı (Türkiye)",
			icon: "/iyzico-logo.svg",
			features: ["TL Fatura", "3D Secure", "Taksit", "%20 KDV"],
			recommended: true,
		});
	}

	providers.push(
		{
			id: "stripe",
			name: "Credit Card (Global)",
			icon: "/stripe-logo.svg",
			features: ["USD/EUR/GBP", "Subscription", "Invoice"],
		},
		{
			id: "crypto",
			name: "Crypto (BTC/ETH/USDC)",
			icon: "/bitcoin-logo.svg",
			features: ["Anonymous", "Privacy", "No KYC"],
		},
	);

	return providers;
}

/**
 * Get payment button text based on provider and location
 */
export function getPaymentButtonText(provider: ProviderType, userLocation: string): string {
	if (provider === "iyzico" && userLocation === "TR") {
		return "Ödeme Yap (3D Secure)";
	}
	if (provider === "crypto") {
		return "Pay with Crypto";
	}
	return "Subscribe Now";
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

/**
 * Minimal inline icon set for the Control Plane Paper design system.
 * Stroke-based SVGs so the dashboard ships zero icon-font or external-image
 * dependencies (CSP: default-src 'self'). All icons are decorative
 * (aria-hidden) — pair them with visible text or an aria-label on the
 * interactive element.
 */

type IconProps = {
	size?: number;
	strokeWidth?: number;
	className?: string;
};

function base(size: number) {
	return {
		width: size,
		height: size,
		viewBox: "0 0 24 24",
		fill: "none",
		stroke: "currentColor",
		strokeLinecap: "round" as const,
		strokeLinejoin: "round" as const,
		"aria-hidden": true as const,
		focusable: false as const,
	};
}

export function ShieldIcon({ size = 18, strokeWidth = 1.7, className }: IconProps) {
	return (
		<svg {...base(size)} strokeWidth={strokeWidth} className={className}>
			<path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6l7-3z" />
			<path d="M9.2 12l2 2 3.6-4" />
		</svg>
	);
}

export function SunIcon({ size = 16, strokeWidth = 1.7, className }: IconProps) {
	return (
		<svg {...base(size)} strokeWidth={strokeWidth} className={className}>
			<circle cx="12" cy="12" r="4.4" />
			<path d="M12 2.5v2M12 19.5v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2.5 12h2M19.5 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
		</svg>
	);
}

export function MoonIcon({ size = 16, strokeWidth = 1.7, className }: IconProps) {
	return (
		<svg {...base(size)} strokeWidth={strokeWidth} className={className}>
			<path d="M20.6 14.2A8.6 8.6 0 019.8 3.4a8.6 8.6 0 1010.8 10.8z" />
		</svg>
	);
}

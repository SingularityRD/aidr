import { useEffect, useRef, useState } from "react";

interface TurnstileProps {
	onVerify: (token: string) => void;
	onError?: () => void;
	onExpire?: () => void;
}

declare global {
	interface Window {
		turnstile?: {
			render: (container: HTMLElement, options: unknown) => string;
			reset: (widgetId: string) => void;
			remove: (widgetId: string) => void;
		};
	}
}

export function Turnstile({ onVerify, onError, onExpire }: TurnstileProps) {
	const containerRef = useRef<HTMLDivElement>(null);
	const widgetIdRef = useRef<string | null>(null);
	const [isLoading, setIsLoading] = useState(true);
	const [hasError, setHasError] = useState(false);

	const siteKey = import.meta.env.VITE_TURNSTILE_SITE_KEY;

	useEffect(() => {
		if (!siteKey) {
			setIsLoading(false);
			return;
		}

		const scriptId = "turnstile-script";
		if (document.getElementById(scriptId)) {
			renderTurnstile();
			return;
		}

		const script = document.createElement("script");
		script.id = scriptId;
		script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
		script.async = true;
		script.defer = true;
		script.onload = () => renderTurnstile();
		script.onerror = () => {
			setIsLoading(false);
			setHasError(true);
			onError?.();
		};
		document.head.appendChild(script);

		return () => {
			if (widgetIdRef.current && window.turnstile) {
				window.turnstile.remove(widgetIdRef.current);
			}
		};

		function renderTurnstile() {
			if (!containerRef.current || !window.turnstile) return;
			try {
				widgetIdRef.current = window.turnstile.render(containerRef.current, {
					sitekey: siteKey,
					callback: (token: string) => {
						setIsLoading(false);
						onVerify(token);
					},
					"error-callback": () => {
						setIsLoading(false);
						setHasError(true);
						onError?.();
					},
					"expired-callback": () => {
						onExpire?.();
					},
				});
			} catch {
				setIsLoading(false);
				setHasError(true);
				onError?.();
			}
		}
	}, [onVerify, onError, onExpire]);

	if (!siteKey) {
		return (
			<div
				style={{ padding: 12, background: "#fef3c7", borderRadius: 8, fontSize: 12, marginTop: 16 }}
			>
				⚠️ CAPTCHA not configured. Add VITE_TURNSTILE_SITE_KEY to enable bot protection.
			</div>
		);
	}

	return (
		<div style={{ marginTop: 16, marginBottom: 16 }}>
			{isLoading && (
				<div style={{ padding: 20, textAlign: "center", color: "var(--text-secondary)" }}>
					Loading verification...
				</div>
			)}
			{hasError && (
				<div
					style={{
						padding: 12,
						background: "rgba(239, 68, 68, 0.1)",
						borderRadius: 8,
						fontSize: 13,
						color: "#dc2626",
					}}
				>
					Verification failed to load. Please refresh the page.
				</div>
			)}
			<div ref={containerRef} style={{ display: isLoading || hasError ? "none" : "block" }} />
		</div>
	);
}

import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
	const sentry = loadEnv(mode, process.cwd(), "SENTRY_");
	return {
		plugins: [react()],
		// Expose only the three public Sentry settings documented for operators.
		define: {
			"import.meta.env.VITE_SENTRY_DSN": JSON.stringify(sentry.SENTRY_DSN || ""),
			"import.meta.env.VITE_SENTRY_ENVIRONMENT": JSON.stringify(sentry.SENTRY_ENVIRONMENT || ""),
			"import.meta.env.VITE_SENTRY_TRACES_SAMPLE_RATE": JSON.stringify(
				sentry.SENTRY_TRACES_SAMPLE_RATE || "",
			),
		},
		// The dashboard is deployed at the origin root. Relative assets resolve below
		// nested SPA routes (for example /auth/assets on /auth/callback) and break the
		// OAuth/recovery entry points before React can start.
		base: "/",
		build: {
			sourcemap: false,
		},
		css: {
			devSourcemap: false,
		},
		esbuild: {
			legalComments: "none",
		},
		server: {
			port: 5173,
		},
	};
});

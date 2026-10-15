import { readFileSync } from "node:fs";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
	const sentry = loadEnv(mode, process.cwd(), "SENTRY_");
	// The usage report names the deployed dashboard version.
	const version = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")).version;
	return {
		plugins: [react()],
		// Expose only the three public Sentry settings documented for operators,
		// plus the dashboard version named in the usage report.
		define: {
			"import.meta.env.VITE_SENTRY_DSN": JSON.stringify(sentry.SENTRY_DSN || ""),
			"import.meta.env.VITE_SENTRY_ENVIRONMENT": JSON.stringify(sentry.SENTRY_ENVIRONMENT || ""),
			"import.meta.env.VITE_SENTRY_TRACES_SAMPLE_RATE": JSON.stringify(
				sentry.SENTRY_TRACES_SAMPLE_RATE || "",
			),
			"import.meta.env.VITE_AIDR_DASHBOARD_VERSION": JSON.stringify(String(version)),
		},
		// The dashboard is deployed at the origin root. Relative assets resolve below
		// nested SPA routes (for example /auth/assets on /auth/callback) and break the
		// OAuth/recovery entry points before React can start.
		base: "/",
		build: {
			// esbuild 0.28 requires Safari 14.1 for destructuring. Keep the other
			// Vite 6 browser minima while retaining the patched build toolchain.
			target: ["es2020", "chrome87", "edge88", "firefox78", "safari14.1"],
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

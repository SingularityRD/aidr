import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
	plugins: [react()],
	// Leak-hardening for commercial/closed-source releases:
	// - No sourcemaps
	// - No bundled license/debug banners
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
});


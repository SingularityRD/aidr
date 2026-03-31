import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
	plugins: [react()],
	base: "./",
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


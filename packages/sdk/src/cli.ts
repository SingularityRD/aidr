#!/usr/bin/env node
import { initSentry } from "./sentry.js";

// Initialize Sentry at the top of the CLI entry point
initSentry();

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { VERSION } from "@singularityrd/aidr-core";
import { Command } from "commander";
import { LemonSqueezyBilling } from "./billing.js";
import { AIDRClient } from "./client.js";
import { SDKConfigSchema } from "./config.js";
import { FreemiumManager, InMemoryLicenseManager } from "./freemium.js";

const CONFIG_FILE_NAME = ".aidr.json";
const GLOBAL_CONFIG_PATH = resolve(homedir(), CONFIG_FILE_NAME);
const BILLING_CONFIG_NAME = ".aidr-billing.json";

/**
 * Load configuration from local or global config file
 */
function loadConfig(): unknown {
	// Check local config first
	const localPath = resolve(process.cwd(), CONFIG_FILE_NAME);
	if (existsSync(localPath)) {
		return JSON.parse(readFileSync(localPath, "utf-8"));
	}
	// Fall back to global config
	if (existsSync(GLOBAL_CONFIG_PATH)) {
		return JSON.parse(readFileSync(GLOBAL_CONFIG_PATH, "utf-8"));
	}
	return null;
}

/**
 * Load billing configuration
 */
function loadBillingConfig(): unknown {
	const localPath = resolve(process.cwd(), BILLING_CONFIG_NAME);
	if (existsSync(localPath)) {
		return JSON.parse(readFileSync(localPath, "utf-8"));
	}
	const globalPath = resolve(homedir(), BILLING_CONFIG_NAME);
	if (existsSync(globalPath)) {
		return JSON.parse(readFileSync(globalPath, "utf-8"));
	}
	return null;
}

/**
 * Prompt user for input
 */
function prompt(question: string): Promise<string> {
	const rl = createInterface({
		input: process.stdin,
		output: process.stdout,
	});
	return new Promise((resolve) => {
		rl.question(question, (answer) => {
			rl.close();
			resolve(answer.trim());
		});
	});
}

/**
 * Get or create FreemiumManager instance
 */
function getFreemiumManager(): FreemiumManager | null {
	const billingConfig = loadBillingConfig() as {
		lemonSqueezyApiKey?: string;
		storeId?: string;
		productId?: string;
	} | null;

	if (!billingConfig?.lemonSqueezyApiKey || !billingConfig.storeId || !billingConfig.productId) {
		return null;
	}

	const billing = new LemonSqueezyBilling({
		lemonSqueezyApiKey: billingConfig.lemonSqueezyApiKey,
		storeId: billingConfig.storeId,
		productId: billingConfig.productId,
	});

	const licenseManager = new InMemoryLicenseManager();
	return new FreemiumManager(billing, licenseManager);
}

const program = new Command();

program.name("aidr").description("AIDR SDK CLI - Security checks for AI agents").version(VERSION);

program
	.command("init")
	.description("Initialize AIDR configuration")
	.option("-g, --global", "Create global config in home directory")
	.option("-f, --force", "Overwrite existing config")
	.action(async (options) => {
		const configPath = options.global
			? GLOBAL_CONFIG_PATH
			: resolve(process.cwd(), CONFIG_FILE_NAME);

		// Check for existing config
		if (existsSync(configPath) && !options.force) {
			console.error(`Error: Config already exists at ${configPath}`);
			console.error("Use --force to overwrite");
			process.exit(1);
		}

		console.log("Initializing AIDR configuration...\n");

		// Prompt for configuration
		const apiKey = await prompt("API Key (required): ");
		if (!apiKey) {
			console.error("Error: API key is required");
			process.exit(1);
		}

		const baseUrl = await prompt("Base URL (optional, press Enter to skip): ");
		const timeoutInput = await prompt("Timeout in ms (default: 5000): ");
		const retriesInput = await prompt("Retries (default: 2): ");
		const cacheInput = await prompt("Enable caching? (Y/n): ");
		const environment = await prompt(
			"Environment (production/staging/development, default: production): ",
		);

		// Build config
		const config = {
			apiKey,
			baseUrl: baseUrl || undefined,
			timeout: timeoutInput ? parseInt(timeoutInput, 10) : 5000,
			retries: retriesInput ? parseInt(retriesInput, 10) : 2,
			cache: cacheInput.toLowerCase() !== "n",
			environment: (environment || "production") as "production" | "staging" | "development",
		};

		// Validate config
		const parsed = SDKConfigSchema.safeParse(config);
		if (!parsed.success) {
			console.error("Error: Invalid configuration");
			for (const error of parsed.error.errors) {
				console.error(`  ${error.path.join(".")}: ${error.message}`);
			}
			process.exit(1);
		}

		// Write config file
		try {
			writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
			console.log(`\n✓ Configuration saved to ${configPath}`);
		} catch (error) {
			console.error(`Error: Failed to write config file: ${error}`);
			process.exit(1);
		}
	});

program
	.command("billing:init")
	.description("Initialize Lemon Squeezy billing configuration")
	.option("-g, --global", "Create global config in home directory")
	.option("-f, --force", "Overwrite existing config")
	.action(async (options) => {
		const configPath = options.global
			? resolve(homedir(), BILLING_CONFIG_NAME)
			: resolve(process.cwd(), BILLING_CONFIG_NAME);

		if (existsSync(configPath) && !options.force) {
			console.error(`Error: Billing config already exists at ${configPath}`);
			console.error("Use --force to overwrite");
			process.exit(1);
		}

		console.log("Initializing Lemon Squeezy billing configuration...\n");

		const apiKey = await prompt("Lemon Squeezy API Key (required): ");
		if (!apiKey) {
			console.error("Error: API key is required");
			process.exit(1);
		}

		const storeId = await prompt("Store ID (required): ");
		if (!storeId) {
			console.error("Error: Store ID is required");
			process.exit(1);
		}

		const productId = await prompt("Product ID (required): ");
		if (!productId) {
			console.error("Error: Product ID is required");
			process.exit(1);
		}

		const webhookSecret = await prompt("Webhook Secret (optional): ");

		const config = {
			lemonSqueezyApiKey: apiKey,
			storeId,
			productId,
			webhookSecret: webhookSecret || undefined,
		};

		try {
			writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
			console.log(`\n✓ Billing configuration saved to ${configPath}`);
		} catch (error) {
			console.error(`Error: Failed to write config file: ${error}`);
			process.exit(1);
		}
	});

program
	.command("billing:checkout")
	.description("Generate checkout URL for license purchase")
	.argument("<userId>", "User ID for the license")
	.option("--variant <variantId>", "Product variant ID")
	.option("--redirect <url>", "Redirect URL after purchase")
	.action(async (userId, options) => {
		const billingConfig = loadBillingConfig() as {
			lemonSqueezyApiKey?: string;
			storeId?: string;
			productId?: string;
		} | null;

		if (
			!billingConfig?.lemonSqueezyApiKey ||
			!billingConfig.storeId ||
			!billingConfig.productId
		) {
			console.error("Error: Billing not configured");
			console.error("Run 'aidr billing:init' to set up billing");
			process.exit(1);
		}

		const billing = new LemonSqueezyBilling({
			lemonSqueezyApiKey: billingConfig.lemonSqueezyApiKey,
			storeId: billingConfig.storeId,
			productId: billingConfig.productId,
		});

		try {
			const url = await billing.createCheckout(userId, {
				variantId: options.variant,
				redirectUrl: options.redirect,
			});
			console.log("✓ Checkout URL generated:");
			console.log(`  ${url}`);
		} catch (error) {
			console.error(
				`Error: Failed to create checkout: ${error instanceof Error ? error.message : String(error)}`,
			);
			process.exit(1);
		}
	});

program
	.command("billing:validate")
	.description("Validate a license key")
	.argument("<licenseKey>", "License key to validate")
	.action(async (licenseKey) => {
		const billingConfig = loadBillingConfig() as {
			lemonSqueezyApiKey?: string;
			storeId?: string;
			productId?: string;
		} | null;

		if (
			!billingConfig?.lemonSqueezyApiKey ||
			!billingConfig.storeId ||
			!billingConfig.productId
		) {
			console.error("Error: Billing not configured");
			console.error("Run 'aidr billing:init' to set up billing");
			process.exit(1);
		}

		const billing = new LemonSqueezyBilling({
			lemonSqueezyApiKey: billingConfig.lemonSqueezyApiKey,
			storeId: billingConfig.storeId,
			productId: billingConfig.productId,
		});

		try {
			const result = await billing.validateLicense(licenseKey);
			console.log("License validation result:");
			console.log(`  Valid: ${result.valid ? "✓" : "✗"}`);
			console.log(`  Seats: ${result.seats}`);
			if (result.expiresAt) {
				console.log(`  Expires: ${result.expiresAt.toISOString()}`);
			}
		} catch (error) {
			console.error(
				`Error: Validation failed: ${error instanceof Error ? error.message : String(error)}`,
			);
			process.exit(1);
		}
	});

program
	.command("license:activate")
	.description("Activate a license for current user")
	.argument("<licenseKey>", "License key to activate")
	.option("-u, --user <userId>", "User ID (defaults to 'cli-user')", "cli-user")
	.action(async (licenseKey, options) => {
		const freemium = getFreemiumManager();
		if (!freemium) {
			console.error("Error: Billing not configured");
			console.error("Run 'aidr billing:init' to set up billing");
			process.exit(1);
		}

		const result = await freemium.activateLicense(options.user, licenseKey);
		if (result.success) {
			console.log("✓ License activated successfully");
			console.log(`  Tier: ${result.license?.tier}`);
			console.log(`  Seats: ${result.license?.seats}`);
		} else {
			console.error(`✗ License activation failed: ${result.error}`);
			process.exit(1);
		}
	});

program
	.command("license:status")
	.description("Check current license status")
	.option("-u, --user <userId>", "User ID (defaults to 'cli-user')", "cli-user")
	.action(async (options) => {
		const freemium = getFreemiumManager();
		if (!freemium) {
			console.error("Error: Billing not configured");
			console.error("Run 'aidr billing:init' to set up billing");
			process.exit(1);
		}

		const status = await freemium.getStatus(options.user);
		console.log("License status:");
		console.log(`  Tier: ${status.tier}`);
		console.log(
			`  Usage: ${status.usage.used} / ${status.usage.total === Number.POSITIVE_INFINITY ? "∞" : status.usage.total}`,
		);
		if (status.usage.remaining !== Number.POSITIVE_INFINITY) {
			console.log(`  Remaining: ${status.usage.remaining}`);
		}
	});

program
	.command("license:usage")
	.description("Track usage for an operation")
	.argument("<operation>", "Operation name to track")
	.option("-u, --user <userId>", "User ID (defaults to 'cli-user')", "cli-user")
	.action(async (operation, options) => {
		const freemium = getFreemiumManager();
		if (!freemium) {
			console.error("Error: Billing not configured");
			console.error("Run 'aidr billing:init' to set up billing");
			process.exit(1);
		}

		await freemium.trackUsage(options.user, operation);
		const status = await freemium.getStatus(options.user);
		console.log(`✓ Usage tracked for operation: ${operation}`);
		console.log(`  Current usage: ${status.usage.used}`);
		console.log(`  Remaining: ${status.usage.remaining}`);
	});

program
	.command("test")
	.description("Test AIDR configuration")
	.action(async () => {
		console.log("Testing AIDR configuration...\n");

		const rawConfig = loadConfig();
		if (!rawConfig) {
			console.error("Error: No configuration found");
			console.error("Run 'aidr init' to create one");
			process.exit(1);
		}

		// Validate config
		const parsed = SDKConfigSchema.safeParse(rawConfig);
		if (!parsed.success) {
			console.error("✗ Configuration is invalid");
			for (const error of parsed.error.errors) {
				console.error(`  ${error.path.join(".")}: ${error.message}`);
			}
			process.exit(1);
		}

		console.log("✓ Configuration is valid");
		console.log(`  API Key: ${parsed.data.apiKey.slice(0, 8)}...`);
		console.log(`  Base URL: ${parsed.data.baseUrl || "default"}`);
		console.log(`  Timeout: ${parsed.data.timeout}ms`);
		console.log(`  Retries: ${parsed.data.retries}`);
		console.log(`  Cache: ${parsed.data.cache ? "enabled" : "disabled"}`);
		console.log(`  Environment: ${parsed.data.environment}`);

		// Test connection
		console.log("\nTesting API connection...");
		try {
			const client = new AIDRClient(parsed.data);
			// Simple check to verify connection
			const result = await client.check({
				action: "read",
				resource: "test://connection",
				context: { test: true },
			});
			console.log("✓ API connection successful");
			console.log(`  Response: ${result.decision} (confidence: ${result.confidence})`);
			client.dispose();
		} catch (error) {
			console.error("✗ API connection failed");
			console.error(`  Error: ${error instanceof Error ? error.message : String(error)}`);
			process.exit(1);
		}

		console.log("\n✓ All tests passed");
	});

program
	.command("check")
	.argument("<input>", "Input to check (URL, file path, or command)")
	.option("-a, --action <action>", "Action type (read, write, execute, delete, fetch)", "fetch")
	.option("-t, --tool <tool>", "Tool name (optional)")
	.option("-f, --format <format>", "Output format (json, pretty)", "json")
	.action(async (input, options) => {
		const rawConfig = loadConfig();
		if (!rawConfig) {
			console.error("Error: No configuration found");
			console.error("Run 'aidr init' to create one");
			process.exit(1);
		}

		const parsed = SDKConfigSchema.safeParse(rawConfig);
		if (!parsed.success) {
			console.error("Error: Invalid configuration");
			for (const error of parsed.error.errors) {
				console.error(`  ${error.path.join(".")}: ${error.message}`);
			}
			process.exit(1);
		}

		const client = new AIDRClient(parsed.data);

		try {
			const result = await client.check({
				action: options.action,
				resource: input,
				context: options.tool ? { tool: options.tool } : undefined,
			});

			if (options.format === "pretty") {
				console.log("Security Check Result:");
				console.log(`  Decision: ${result.decision}`);
				console.log(`  Allowed: ${result.allowed ? "yes" : "no"}`);
				console.log(`  Confidence: ${result.confidence}`);
				if (result.reason) console.log(`  Reason: ${result.reason}`);
				if (result.threatId) console.log(`  Threat ID: ${result.threatId}`);
			} else {
				console.log(JSON.stringify(result, null, 2));
			}

			// Exit with non-zero code if denied
			if (result.decision === "deny") {
				process.exit(2);
			}
			if (result.decision === "ask") {
				process.exit(3);
			}
		} catch (error) {
			console.error(
				`Error: Check failed: ${error instanceof Error ? error.message : String(error)}`,
			);
			process.exit(1);
		} finally {
			client.dispose();
		}
	});

program
	.command("diagnose")
	.description("Diagnose AIDR issues")
	.action(async () => {
		console.log("AIDR Diagnostic Tool\n");

		let exitCode = 0;

		// Check 1: Config exists
		console.log("[1/5] Checking configuration...");
		const localPath = resolve(process.cwd(), CONFIG_FILE_NAME);
		const globalPath = GLOBAL_CONFIG_PATH;

		if (existsSync(localPath)) {
			console.log("  ✓ Local config found:", localPath);
		} else if (existsSync(globalPath)) {
			console.log("  ✓ Global config found:", globalPath);
		} else {
			console.error("  ✗ No configuration found");
			console.error("    Run 'aidr init' to create one");
			exitCode = 1;
		}

		// Check 2: Config validity
		console.log("\n[2/5] Validating configuration...");
		const rawConfig = loadConfig();
		if (rawConfig) {
			const parsed = SDKConfigSchema.safeParse(rawConfig);
			if (parsed.success) {
				console.log("  ✓ Configuration is valid");
			} else {
				console.error("  ✗ Configuration is invalid");
				for (const error of parsed.error.errors) {
					console.error(`    ${error.path.join(".")}: ${error.message}`);
				}
				exitCode = 1;
			}
		}

		// Check 3: Node.js version
		console.log("\n[3/5] Checking Node.js version...");
		const nodeVersion = process.version;
		const versionParts = nodeVersion.slice(1).split(".");
		const majorVersionStr = versionParts[0] ?? "0";
		const majorVersion = parseInt(majorVersionStr, 10);
		if (majorVersion >= 18) {
			console.log(`  ✓ Node.js version ${nodeVersion} (>= 18)`);
		} else {
			console.error(`  ✗ Node.js version ${nodeVersion} (>= 18 required)`);
			exitCode = 1;
		}

		// Check 4: Environment
		console.log("\n[4/5] Checking environment...");
		console.log(`  Node.js: ${process.version}`);
		console.log(`  Platform: ${process.platform}`);
		console.log(`  Architecture: ${process.arch}`);
		if (process.env.ANTHROPIC_API_KEY) {
			console.log("  ANTHROPIC_API_KEY: set");
		}
		if (process.env.AIDR_API_KEY) {
			console.log("  AIDR_API_KEY: set");
		}

		// Check 5: API connectivity
		console.log("\n[5/5] Testing API connectivity...");
		if (rawConfig) {
			const parsed = SDKConfigSchema.safeParse(rawConfig);
			if (parsed.success) {
				try {
					const client = new AIDRClient(parsed.data);
					const result = await client.check({
						action: "read",
						resource: "diagnostic://test",
					});
					console.log("  ✓ API connection successful");
					console.log(`    Response: ${result.decision}`);
					client.dispose();
				} catch (error) {
					console.error("  ✗ API connection failed");
					console.error(`    Error: ${error instanceof Error ? error.message : String(error)}`);
					exitCode = 1;
				}
			} else {
				console.log("  ⚠ Skipping (invalid config)");
			}
		} else {
			console.log("  ⚠ Skipping (no config)");
		}

		console.log(`\n${exitCode === 0 ? "✓ All checks passed" : "✗ Some checks failed"}`);
		process.exit(exitCode);
	});

program.parse();

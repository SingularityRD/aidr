#!/usr/bin/env node
// Start the desktop app from the source build (dist/ + build/runtime/).
import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { electronBinary } from "./electron-path.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const child = spawn(electronBinary(), [root, ...process.argv.slice(2)], { stdio: "inherit" });
child.on("exit", (code) => process.exit(code ?? 0));

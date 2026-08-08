#!/usr/bin/env node

import { VERSION } from "@singularityrd/aidr-core";
import { Command } from "commander";
import configCommand from "./commands/config.js";
import setupCommand from "./commands/setup.js";
import statusCommand from "./commands/status.js";

const program = new Command();

program
	.name("aidr")
	.description("Singularity AIDR command-line setup and diagnostics")
	.version(VERSION);

program
	.command("setup")
	.description("Configure AIDR and install the detected agent hooks")
	.option("-f, --force", "Replace an existing local configuration")
	.action(setupCommand);

program
	.command("config")
	.description("Read or update the local AIDR configuration")
	.option("-g, --get <key>", "Read a dotted configuration key")
	.option("-s, --set <values...>", "Set a dotted configuration key and value")
	.option("-l, --list", "Print all configuration values")
	.action(configCommand);

program
	.command("status")
	.description("Show the local AIDR configuration and hook status")
	.action(statusCommand);

await program.parseAsync(process.argv);

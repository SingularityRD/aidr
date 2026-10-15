import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { releaseMinifyOptions } from "../../../scripts/lib/release-minify.mjs";

const packageRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const repositoryRoot = resolve(packageRoot, "../..");
const RULE_FILE = /^[A-Za-z0-9_.-]+\.yaml$/;

export const GATEWAY_ENTRIES = [
  ["cli.mjs", "aidr-mcp-gateway.mjs"],
  ["approve.mjs", "aidr-mcp-approve.mjs"],
  ["stdio-cli.mjs", "aidr-mcp-stdio.mjs"],
  ["library.mjs", "aidr-mcp-library.mjs"],
];

/** Read the repository threat and trusted-domain rules that ship inside the signed bundle. */
export async function readRuleSets(root = repositoryRoot) {
  const ruleSets = {};
  for (const kind of ["threats", "allowlists"]) {
    const names = (await readdir(join(root, kind))).filter((name) => RULE_FILE.test(name)).sort();
    if (names.length === 0) throw new Error(`No ${kind} rule files found for the MCP gateway bundle`);
    ruleSets[kind] = {};
    for (const name of names) ruleSets[kind][name] = await readFile(join(root, kind, name), "utf8");
  }
  return ruleSets;
}

/**
 * esbuild options shared by the release build and the integrity test. The core
 * is bundled from its package export; CommonJS dependencies inside it get a
 * real `require`, and the Windows-only native AMSI addon stays external (it is
 * loaded lazily and falls back to PowerShell when absent). `release` minifies
 * with function/class names kept (scripts/lib/release-minify.mjs).
 */
export function gatewayBundleOptions({ ruleSets, release = false }) {
  const embeddedRules = resolve(packageRoot, "src", "embedded-rules.mjs");
  return {
    bundle: true,
    platform: "node",
    target: "node22.12",
    format: "esm",
    packages: "bundle",
    external: ["koffi"],
    minify: false,
    ...releaseMinifyOptions(release),
    sourcemap: false,
    legalComments: "none",
    logLevel: "warning",
    banner: {
      js: 'import { createRequire as __aidrCreateRequire } from "node:module";\nconst require = __aidrCreateRequire(import.meta.url);',
    },
    plugins: [
      {
        name: "aidr-embedded-rules",
        setup(build) {
          build.onLoad({ filter: /embedded-rules\.mjs$/ }, (args) => {
            if (resolve(args.path) !== embeddedRules) return undefined;
            // Rules are data, not code: embed them base64-encoded so their
            // path-matching patterns are not mistaken for bundled host paths.
            const encoded = Buffer.from(JSON.stringify(ruleSets), "utf8").toString("base64");
            return {
              contents: `export const EMBEDDED_RULE_SETS = Object.freeze(JSON.parse(Buffer.from(${JSON.stringify(encoded)}, "base64").toString("utf8")));\n`,
              loader: "js",
            };
          });
        },
      },
    ],
  };
}

/**
 * Resolve the core library to its TypeScript source instead of its compiled
 * dist, for tests and isolated fixtures that must not depend on a core build.
 * Both the package import and relative `core/dist/*.js` imports are mapped, so
 * the bundle carries a single copy of every core module.
 */
export function coreSourcePlugin() {
	const coreSource = resolve(repositoryRoot, "packages", "core", "src");
	return {
		name: "core-source",
		setup(builder) {
			builder.onResolve({ filter: /^@singularityrd\/aidr-core$/ }, () => ({
				path: join(coreSource, "index.ts"),
			}));
			builder.onResolve({ filter: /core\/dist\/.*\.js$/ }, ({ path, resolveDir }) => ({
				path: resolve(resolveDir, path.replace("/dist/", "/src/").replace(/\.js$/, ".ts")),
			}));
		},
	};
}

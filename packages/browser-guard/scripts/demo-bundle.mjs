#!/usr/bin/env node
/**
 * Packs the Chrome/Edge build for a customer demo ("Load unpacked"), after
 * `node scripts/build.mjs --release --zip` (see `pnpm demo:package`):
 *
 *   dist/demo/aidr-browser-guard-demo-<version>.zip
 *     aidr-browser-guard-chrome-<version>/   the unpacked extension (select this folder in Load unpacked)
 *     DEMO-KURULUM.txt                       short Turkish install steps (full guide: docs/demo/browser-guard-demo.tr.md)
 *   dist/demo/SHA256SUMS
 *
 * Deterministic (scripts/zip.mjs: sorted entries, fixed timestamps). The extension files
 * are byte-identical to the store package dist/aidr-browser-guard-chrome-<version>.zip; the
 * folder only gives the unpacked copy a stable, readable name.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createZip, readZip } from "./zip.mjs";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const INSTALL_TXT = (folder) => `Singularity AIDR Browser Guard - demo kurulumu (Chrome / Edge)
==================================================================

1. Bu zip dosyasini bir klasore cikarin (ornek: C:\\AIDR-Demo).
2. Chrome: adres cubuguna chrome://extensions yazin.
   Edge:   adres cubuguna edge://extensions yazin.
3. Sag ustteki (Edge'de sol alttaki) "Gelistirici modu" anahtarini acin.
4. "Paketlenmemis oge yukle" (Load unpacked) dugmesine basin ve
   ${folder} klasorunu secin (icinde manifest.json olan klasor).
5. Arac cubugundaki yapboz simgesinden Singularity AIDR Browser Guard'i sabitleyin.

Klasoru tasimayin veya silmeyin: tarayici eklentiyi bu klasorden calistirir.
Ayrintili demo senaryosu: packages/browser-guard/docs/demo/browser-guard-demo.tr.md
`;

export function buildDemoBundle({ distDir = join(PACKAGE_ROOT, "dist"), version } = {}) {
	const pkgVersion = version ?? JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8")).version;
	const storeZip = join(distDir, `aidr-browser-guard-chrome-${pkgVersion}.zip`);
	if (!existsSync(storeZip)) {
		throw new Error(`missing ${storeZip}: run node scripts/build.mjs --release --zip first`);
	}
	const folder = `aidr-browser-guard-chrome-${pkgVersion}`;
	const entries = [...readZip(readFileSync(storeZip))].map(([name, data]) => ({ name: `${folder}/${name}`, data }));
	if (!entries.some((e) => e.name === `${folder}/manifest.json`)) throw new Error("the store package has no manifest.json");
	entries.push({ name: "DEMO-KURULUM.txt", data: Buffer.from(INSTALL_TXT(folder).replace(/\n/g, "\r\n"), "utf8") });
	const archive = createZip(entries);
	const outDir = join(distDir, "demo");
	mkdirSync(outDir, { recursive: true });
	const name = `aidr-browser-guard-demo-${pkgVersion}.zip`;
	writeFileSync(join(outDir, name), archive);
	const sum = createHash("sha256").update(archive).digest("hex");
	writeFileSync(join(outDir, "SHA256SUMS"), `${sum}  ${name}\n`);
	return { zip: join(outDir, name), sha256: sum, folder, files: entries.length };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		const result = buildDemoBundle();
		console.log(`[demo-bundle] ${result.zip} (${result.files} files, sha256 ${result.sha256})`);
	} catch (error) {
		console.error(`[demo-bundle] ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 1;
	}
}

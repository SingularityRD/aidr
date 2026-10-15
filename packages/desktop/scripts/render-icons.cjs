// Electron main script: render the app and tray icons from branding/singularity-mark.svg
// in an offscreen window and write PNGs + a multi-size ICO. Run through scripts/icons.mjs.
//
//   electron scripts/render-icons.cjs <mark.svg> <out-dir>

const { app, BrowserWindow } = require("electron");
const { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");

const [markPath, outDir] = process.argv.slice(-2);
const MASTER = 1024;

/** The mark recoloured: `currentColor` becomes a concrete fill. */
function mark(fill) {
	return readFileSync(markPath, "utf8")
		.replace(/<\?xml[^>]*>/, "")
		.replace(/<title>[^<]*<\/title>/, "")
		.replace(/fill="currentColor"/g, `fill="${fill}"`);
}

function page(body) {
	return `<!doctype html><html><head><style>
html,body{margin:0;width:${MASTER}px;height:${MASTER}px;background:transparent;overflow:hidden}
.tile{width:${MASTER}px;height:${MASTER}px;display:grid;place-items:center}
.tile svg{display:block}
</style></head><body>${body}</body></html>`;
}

function trayPage(color) {
	const size = MASTER * 0.8;
	return page(`<div class="tile" style="border-radius:50%;background:${color}"><div style="width:${size}px;height:${size}px">${mark("#ffffff").replace("<svg ", `<svg width="${size}" height="${size}" `)}</div></div>`);
}

const designs = {
	// App icon: the white mark on an ink-blue rounded square.
	app: page(`<div class="tile" style="border-radius:224px;background:linear-gradient(150deg,#3546d1 0%,#1f2a8c 55%,#121a5c 100%)">
<div style="width:${MASTER * 0.66}px;height:${MASTER * 0.66}px">${mark("#ffffff").replace("<svg ", `<svg width="${MASTER * 0.66}" height="${MASTER * 0.66}" `)}</div></div>`),
	// Tray: a status-coloured disc carrying the white mark (green: protected, amber: not).
	trayProtected: trayPage("#1a9a5c"),
	trayUnprotected: trayPage("#d98200"),
};

const scratch = mkdtempSync(join(tmpdir(), "aidr-icons-"));
let pages = 0;

async function render(html) {
	const window = new BrowserWindow({
		width: MASTER,
		height: MASTER,
		show: false,
		frame: false,
		transparent: true,
		backgroundColor: "#00000000",
		useContentSize: true,
		webPreferences: { offscreen: true, javascript: false },
	});
	window.webContents.setZoomFactor(1);
	const file = join(scratch, `icon-${++pages}.html`);
	writeFileSync(file, html);
	await window.loadFile(file);
	await new Promise((resolve) => setTimeout(resolve, 300));
	const image = await window.webContents.capturePage({ x: 0, y: 0, width: MASTER, height: MASTER });
	window.destroy();
	return image;
}

function resized(image, size) {
	return image.resize({ width: size, height: size, quality: "best" }).toPNG();
}

/** A Windows ICO whose entries are PNG images (supported since Vista). */
function ico(pngs) {
	const header = Buffer.alloc(6 + 16 * pngs.length);
	header.writeUInt16LE(0, 0);
	header.writeUInt16LE(1, 2);
	header.writeUInt16LE(pngs.length, 4);
	let offset = header.length;
	pngs.forEach(({ size, data }, index) => {
		const entry = 6 + index * 16;
		header.writeUInt8(size >= 256 ? 0 : size, entry);
		header.writeUInt8(size >= 256 ? 0 : size, entry + 1);
		header.writeUInt8(0, entry + 2);
		header.writeUInt8(0, entry + 3);
		header.writeUInt16LE(1, entry + 4);
		header.writeUInt16LE(32, entry + 6);
		header.writeUInt32LE(data.length, entry + 8);
		header.writeUInt32LE(offset, entry + 12);
		offset += data.length;
	});
	return Buffer.concat([header, ...pngs.map(({ data }) => data)]);
}

app.disableHardwareAcceleration();
// Each icon renders in its own window; closing one must not quit the app.
app.on("window-all-closed", () => {});
app.whenReady().then(async () => {
	try {
		mkdirSync(outDir, { recursive: true });
		const appIcon = await render(designs.app);
		if (appIcon.isEmpty()) throw new Error("the app icon rendered empty");
		const icoSizes = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256];
		const entries = icoSizes.map((size) => ({ size, data: resized(appIcon, size) }));
		writeFileSync(join(outDir, "icon.ico"), ico(entries));
		for (const size of [32, 64, 128, 256, 512]) writeFileSync(join(outDir, `icon-${size}.png`), resized(appIcon, size));
		for (const [name, html] of [
			["tray-protected", designs.trayProtected],
			["tray-unprotected", designs.trayUnprotected],
		]) {
			const image = await render(html);
			writeFileSync(join(outDir, `${name}.png`), resized(image, 16));
			writeFileSync(join(outDir, `${name}@2x.png`), resized(image, 32));
		}
		console.log(`Icons written to ${outDir}`);
		rmSync(scratch, { recursive: true, force: true, maxRetries: 5 });
		app.exit(0);
	} catch (error) {
		console.error(error);
		app.exit(1);
	}
});

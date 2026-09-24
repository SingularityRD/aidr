// Shared behaviour for the simulated AI chat pages (served at /__fixture__/kit.js).
//
// Emulates what the real products' frameworks do, closely enough to exercise
// the extension the same way:
// - the prompt is read from the editor DOM at send time (ProseMirror/Quill/React
//   all serialise their current document on submit), never from a cached copy;
// - Enter sends, Shift+Enter inserts a new line/paragraph, IME composition is ignored;
// - the send button is disabled while the editor is empty and is re-enabled by
//   `input` events (so a rewrite that skips input events leaves it disabled);
// - paste is handled by the page (insert clipboard text) unless already handled;
// - the assistant reply streams in over several DOM updates, as SSE renderers do;
// - file inputs upload the selected file's bytes as soon as `change` fires.
//
// The page never sees the harness: it only talks to its own origin, which the
// Playwright route layer serves and records.
(() => {
	const state = { sends: [], uploads: [], replies: [] };
	window.__fixture = state;

	const BLOCK = /^(P|DIV|H[1-6]|LI|PRE|BLOCKQUOTE)$/;

	/** Serialises the editor like ProseMirror's textBetween(..., "\n"): one line per block. */
	function readEditor(editor, kind) {
		if (kind === "textarea") return editor.value;
		const lines = [];
		let inline = null;
		for (const node of editor.childNodes) {
			if (node.nodeType === Node.ELEMENT_NODE && BLOCK.test(node.tagName)) {
				if (inline !== null) lines.push(inline);
				inline = null;
				// A paragraph containing only <br> is an empty line.
				lines.push(node.textContent ?? "");
			} else if (node.nodeType === Node.ELEMENT_NODE && node.tagName === "BR") {
				lines.push(inline ?? "");
				inline = null;
			} else {
				inline = (inline ?? "") + (node.textContent ?? "");
			}
		}
		if (inline !== null) lines.push(inline);
		return lines.join("\n");
	}

	function clearEditor(editor, kind) {
		if (kind === "textarea") {
			editor.value = "";
		} else {
			editor.innerHTML = "<p><br></p>";
		}
		editor.dispatchEvent(new Event("input", { bubbles: true }));
	}

	function placeCaretAtStart(node) {
		const range = document.createRange();
		range.setStart(node, 0);
		range.collapse(true);
		const selection = window.getSelection();
		selection.removeAllRanges();
		selection.addRange(range);
	}

	function insertParagraph(editor) {
		const selection = window.getSelection();
		let block = selection.anchorNode;
		while (block && block.parentNode !== editor) block = block.parentNode;
		const p = document.createElement("p");
		p.appendChild(document.createElement("br"));
		if (block) block.after(p);
		else editor.appendChild(p);
		placeCaretAtStart(p);
		editor.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertParagraph" }));
	}

	/** Keep the ProseMirror/Quill invariant: the document is a list of <p> blocks. */
	function normaliseBlocks(editor) {
		const loose = [...editor.childNodes].filter(
			(n) =>
				n.nodeType === Node.TEXT_NODE || (n.nodeType === Node.ELEMENT_NODE && n.tagName === "BR"),
		);
		if (loose.length === 0) {
			if (editor.childNodes.length === 0) editor.innerHTML = "<p><br></p>";
			return;
		}
		const p = document.createElement("p");
		loose[0].before(p);
		for (const n of loose) p.appendChild(n);
	}

	function streamInto(target, reply, done) {
		const steps = 4;
		let i = 0;
		const tick = () => {
			i += 1;
			const cut = Math.ceil((reply.length * i) / steps);
			// Markdown renderers rebuild the paragraph on every chunk.
			target.innerHTML = "";
			const p = document.createElement("p");
			p.textContent = reply.slice(0, cut);
			target.appendChild(p);
			if (i < steps) setTimeout(tick, 40);
			else done();
		};
		setTimeout(tick, 40);
	}

	async function upload(file) {
		const content = await file.text();
		state.uploads.push({ name: file.name, size: file.size });
		await fetch("/__fixture__/upload", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ name: file.name, type: file.type, content }),
		});
	}

	/**
	 * cfg: { site, kind: 'prosemirror'|'quill'|'textarea', editor, send, endpoint,
	 *        thread, renderUser(text) -> Element, renderAssistant() -> { root, body } ,
	 *        form?: selector submitted instead of button click, fileInput?: selector }
	 */
	function init(cfg) {
		const editor = document.querySelector(cfg.editor);
		const button = document.querySelector(cfg.send);
		const thread = document.querySelector(cfg.thread);
		const isRich = cfg.kind !== "textarea";

		const syncButton = () => {
			button.disabled = readEditor(editor, cfg.kind).trim().length === 0;
		};

		async function send() {
			const text = readEditor(editor, cfg.kind).trim();
			if (!text) return;
			state.sends.push(text);
			thread.appendChild(cfg.renderUser(text));
			clearEditor(editor, cfg.kind);
			const response = await fetch(cfg.endpoint, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ site: cfg.site, prompt: text }),
			});
			const { reply } = await response.json();
			const { root, body } = cfg.renderAssistant();
			thread.appendChild(root);
			streamInto(body, reply, () => {
				state.replies.push(reply);
				root.setAttribute("data-fixture-complete", "true");
			});
		}

		editor.addEventListener("keydown", (event) => {
			if (event.key !== "Enter" || event.isComposing || event.keyCode === 229) return;
			if (event.defaultPrevented) return;
			if (event.shiftKey) {
				if (isRich) {
					event.preventDefault();
					insertParagraph(editor);
				}
				return; // textarea: the browser inserts "\n"
			}
			event.preventDefault();
			void send();
		});

		editor.addEventListener("input", () => {
			if (isRich) normaliseBlocks(editor);
			syncButton();
		});

		editor.addEventListener("paste", (event) => {
			if (event.defaultPrevented) return;
			event.preventDefault();
			const text = event.clipboardData?.getData("text/plain") ?? "";
			document.execCommand("insertText", false, text);
		});

		if (cfg.form) {
			document.querySelector(cfg.form).addEventListener("submit", (event) => {
				event.preventDefault();
				void send();
			});
		} else {
			button.addEventListener("click", () => void send());
		}

		if (cfg.fileInput) {
			const input = document.querySelector(cfg.fileInput);
			input.addEventListener("change", () => {
				for (const file of input.files ?? []) void upload(file);
			});
		}

		syncButton();
		document.documentElement.setAttribute("data-fixture-ready", cfg.site);
	}

	window.FixtureChat = { init, readEditor };
})();

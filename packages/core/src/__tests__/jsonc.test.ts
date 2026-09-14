import { describe, expect, it } from "vitest";
import { parseJsonc, stripJsonComments } from "../jsonc.js";

describe("JSONC reader", () => {
	it("strips comments and trailing commas without touching string contents", () => {
		const content = `{
	// a line comment that must disappear
	"mcpServers": {
		/* a block
		   comment that must disappear */
		"filesystem": {
			"command": "node",
			"args": ["//not-a-comment", "trailing, comma, inside", "value/*not-a-comment*/"],
			"url": "https://mcp.example/tool?path=a,b//c",
			"note": "he said \\"//\\" and it stuck, twice,", // trailing comment
		},
	},
}`;
		const stripped = stripJsonComments(content);
		expect(stripped).not.toContain("a line comment");
		expect(stripped).not.toContain("a block");
		expect(stripped).toContain('"//not-a-comment"');
		expect(stripped).toContain('"trailing, comma, inside"');
		expect(stripped).toContain('"value/*not-a-comment*/"');
		expect(stripped).toContain('"https://mcp.example/tool?path=a,b//c"');
		expect(stripped).toContain('"he said \\"//\\" and it stuck, twice,"');

		const parsed = parseJsonc(content);
		expect(parsed.status).toBe("ok");
		expect(parsed.value).toEqual({
			mcpServers: {
				filesystem: {
					command: "node",
					args: ["//not-a-comment", "trailing, comma, inside", "value/*not-a-comment*/"],
					url: "https://mcp.example/tool?path=a,b//c",
					note: 'he said "//" and it stuck, twice,',
				},
			},
		});
	});

	it("does not corrupt a // or a comma that appears inside a quoted string", () => {
		const content = '{"a":"http://x//y","b":"c, d,","c":["e,//f",],"d":"/*","e":1// real comment\n}';
		expect(stripJsonComments(content)).toBe(
			'{"a":"http://x//y","b":"c, d,","c":["e,//f",],"d":"/*","e":1\n}',
		);
		expect(parseJsonc(content)).toEqual({
			status: "ok",
			value: { a: "http://x//y", b: "c, d,", c: ["e,//f"], d: "/*", e: 1 },
		});
	});

	it("reports invalid JSONC explicitly instead of throwing", () => {
		expect(parseJsonc('{"a": 1}')).toEqual({ status: "ok", value: { a: 1 } });
		expect(parseJsonc('\uFEFF{"a": 1}')).toEqual({ status: "ok", value: { a: 1 } });
		expect(parseJsonc('{"a": /* unterminated')).toMatchObject({
			status: "invalid",
			error: "unterminated_block_comment",
		});
		expect(parseJsonc('{"a": 1')).toMatchObject({ status: "invalid" });
		expect(parseJsonc("")).toMatchObject({ status: "invalid" });
		// A single quote, an unquoted key or a trailing comma inside a string is
		// not silently repaired — a guess would be a coverage lie.
		expect(parseJsonc("{a: 1,}")).toMatchObject({ status: "invalid" });
	});

	it("accepts comments and trailing commas at the end of a file without a newline", () => {
		expect(parseJsonc('{"a": [1, 2,], "b": {"c": 3,},} // eof')).toEqual({
			status: "ok",
			value: { a: [1, 2], b: { c: 3 } },
		});
	});
});

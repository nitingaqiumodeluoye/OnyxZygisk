import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import Icons from "unplugin-icons/vite";
import { defineConfig, type Plugin } from "vite";

/** Removes one brace-balanced at-rule without interpreting nested CSS. */
function stripAtRule(css: string, atRule: string): string {
	let result = "";
	let cursor = 0;
	while (cursor < css.length) {
		const start = css.indexOf(atRule, cursor);
		if (start < 0) return result + css.slice(cursor);
		const open = css.indexOf("{", start);
		if (open < 0) return result + css.slice(cursor);
		let depth = 1;
		let end = open + 1;
		while (end < css.length && depth > 0) {
			if (css[end] === "{") depth += 1;
			else if (css[end] === "}") depth -= 1;
			end += 1;
		}
		result += css.slice(cursor, start);
		cursor = end;
	}
	return result;
}

/**
 * Cascade layers arrived in Chromium 99. Android 12 can remain on WebView 96,
 * which otherwise drops Tailwind's base, theme, and utilities completely.
 */
function unwrapCssLayers(): Plugin {
	return {
		name: "unwrap-css-layers-for-webview-96",
		enforce: "post",
		generateBundle(_options, bundle) {
			for (const item of Object.values(bundle)) {
				if (item.type !== "asset" || !item.fileName.endsWith(".css")) continue;
				const source =
					typeof item.source === "string"
						? item.source
						: new TextDecoder().decode(item.source);
				item.source = stripAtRule(source, "@layer properties")
					.replaceAll("@layer theme", "@media all")
					.replaceAll("@layer base", "@media all")
					.replaceAll("@layer components;", "")
					.replaceAll("@layer utilities", "@media all");
			}
		},
	};
}

export default defineConfig({
	// KernelSU loads the page straight off the filesystem, so every emitted URL
	// must be relative rather than rooted at "/".
	base: "",
	plugins: [
		react(),
		tailwindcss(),
		Icons({ compiler: "jsx", jsx: "react", autoInstall: false }),
		unwrapCssLayers(),
	],
	resolve: {
		alias: {
			"@": fileURLToPath(new URL("./src", import.meta.url)),
			"@components": fileURLToPath(new URL("./src/components", import.meta.url)),
			"@bridge": fileURLToPath(new URL("./src/bridge", import.meta.url)),
		},
	},
	build: {
		// Android 12 devices can be stuck on WebView 96. Tailwind 4.3 wraps its
		// utilities in a Chromium 105 feature query, so a newer CSS target makes
		// that browser discard the entire layout layer.
		target: "chrome96",
		cssTarget: "chrome96",
		outDir: "dist",
		emptyOutDir: true,
		cssCodeSplit: false,
	},
});

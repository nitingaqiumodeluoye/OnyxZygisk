// Upstream ships 120. This fork lowers it to the floor the emitted bundle
// actually needs, because Android 12 devices are otherwise locked out of the
// WebUI entirely: the highest WebView they can install is capped well below
// 120, while the assets they do have are sufficient.
//
// Measured against the compiled output (dist/assets), not guessed:
//   - @property (34 uses)            -> Chromium 85
//   - Array.prototype.at (4 uses)    -> Chromium 92  <- the binding constraint
//   - contain-intrinsic-size         -> Chromium 83
//   - optional chaining / ??=        -> Chromium 80 / 85 (syntax, transpiled)
//   - color-mix() (2 uses)           -> guarded by @supports, falls back to
//                                       currentColor, so it costs nothing
// Nothing in the bundle needs findLast/toSorted/groupBy/structuredClone or
// any other post-96 API, which is what a blanket 120 would have implied.
const MIN_ANDROID_WEBVIEW_VERSION = 92;

interface NavigatorUAData {
	readonly brands: ReadonlyArray<{
		readonly brand: string;
		readonly version: string;
	}>;
}

export function getWebviewVersion(): number | null {
	const brands = (
		navigator as Navigator & { readonly userAgentData?: NavigatorUAData }
	).userAgentData?.brands;
	if (Array.isArray(brands) && brands.length > 0) {
		const webViewBrand = brands.find(
			(entry) => entry.brand === "Android WebView",
		);
		if (webViewBrand) return Number.parseInt(webViewBrand.version, 10);
	}

	const userAgent = navigator.userAgent;
	if (/Android/i.test(userAgent) && /\bwv\b/.test(userAgent)) {
		const match = userAgent.match(/Chrome\/(\d+)/);
		return match ? Number.parseInt(match[1] ?? "0", 10) : 0;
	}
	return null;
}

export function isSupported(): boolean {
	const version = getWebviewVersion();
	return version === null || version >= MIN_ANDROID_WEBVIEW_VERSION;
}

function blockingPage(message: string): HTMLElement {
	const container = document.createElement("div");
	container.className = "onx-blocking";
	const text = document.createElement("p");
	text.textContent = message;
	container.appendChild(text);
	return container;
}

/**
 * Shown when the WebUI is running in a release build without a host bridge.
 * The alternative — rendering the ordinary shell — would leave every field
 * reading "unavailable" with no indication of why.
 */
export function renderBridgeUnavailablePage(): HTMLElement {
	return blockingPage(
		"The KernelSU, APatch or MMRL WebUI bridge is not available.",
	);
}

export function renderBlockingPage(): HTMLElement {
	return blockingPage("Android System WebView 120 or newer is required.");
}

// OnyxZygisk — Vitest setup.
//
// jsdom does not implement window.matchMedia, which the theme composable needs
// to resolve the "system" preference. Stub it so tests can exercise theme logic.
if (typeof window !== "undefined" && !window.matchMedia) {
  window.matchMedia = (query: string): MediaQueryList =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as unknown as MediaQueryList;
}

// Newer Node releases define a global `localStorage` that resolves to undefined
// unless the process was started with --localstorage-file, and that binding
// shadows jsdom's implementation. The locale/theme composables read
// localStorage at module scope, so without a working Storage every suite that
// imports them fails to collect. Provide an in-memory Storage when either the
// global or the jsdom window copy is missing.
function memoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    key: (i: number) => Array.from(map.keys())[i] ?? null,
    removeItem: (k: string) => void map.delete(k),
    setItem: (k: string, v: string) => void map.set(k, String(v)),
  } as Storage;
}

if (typeof window !== "undefined" && !window.localStorage) {
  Object.defineProperty(window, "localStorage", {
    value: memoryStorage(),
    configurable: true,
    writable: true,
  });
}
if (typeof globalThis !== "undefined" && !globalThis.localStorage) {
  Object.defineProperty(globalThis, "localStorage", {
    value: (typeof window !== "undefined" && window.localStorage) || memoryStorage(),
    configurable: true,
    writable: true,
  });
}

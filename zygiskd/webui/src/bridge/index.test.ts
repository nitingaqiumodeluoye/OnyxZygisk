import { beforeEach, describe, expect, it, vi } from "vitest";

import { exec } from "./index";

/** Capture what the bridge hands to the root manager. */
function stubKsu() {
  const calls: { cmd: string; cb: string }[] = [];
  const g = globalThis as unknown as { window?: Record<string, unknown> };
  const win: Record<string, unknown> = {};
  (g as { window: unknown }).window = win;
  win.ksu = {
    exec(cmd: string, _opts: string, cb: string) {
      calls.push({ cmd, cb });
    },
    toast() {},
  };
  return { calls, win };
}

function settle(calls: { cb: string }[], win: Record<string, unknown>, errno = 0, out = "aGk=") {
  for (const c of calls) {
    const fn = win[c.cb] as (e: number, o: string, s: string) => void;
    fn(errno, out, "");
  }
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("exec wrapper", () => {
  it("does not emit a bare exit at the top level", async () => {
    const { calls, win } = stubKsu();
    const p = exec("echo hi");
    // The wrapper is the single command handed to ksu.exec.
    expect(calls).toHaveLength(1);
    const cmd = calls[0].cmd;

    // A top-level `exit` would terminate the manager's shared libsu root shell,
    // which makes every later call fail with errno -1 and empty output. Only
    // `(exit ...)` is safe.
    const bare = cmd
      .split("\n")
      .filter((l) => /^exit\b/.test(l.trim()) && !l.trim().startsWith("("));
    expect(bare).toEqual([]);

    settle(calls, win);
    await expect(p).resolves.toMatchObject({ errno: 0, stdout: "hi" });
  });

  it("still propagates the wrapped command's exit status", async () => {
    const { calls, win } = stubKsu();
    const p = exec("false");
    settle(calls, win, 1, "");
    await expect(p).resolves.toMatchObject({ errno: 1 });
  });

  it("routes the payload through the subshell exit so rc survives", async () => {
    const { calls, win } = stubKsu();
    const p = exec("echo hi");
    expect(calls[0].cmd).toContain('(exit "$rc")');
    settle(calls, win);
    await p;
  });
});

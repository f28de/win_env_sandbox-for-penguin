/**
 * The built launcher, as the harness will actually run it.
 *
 * This file exists because of a build failure the source-level suites could not see: `live`
 * calls `runJob()` in-process, so it never touched `dist/`. With code splitting on, the built
 * `runner.js` was a re-export shell whose "am I the entry?" check had moved into a shared chunk
 * — where `import.meta.url` is the chunk's — so `main()` never ran and EVERY confined command
 * exited 0 having executed nothing. Silent success is the worst failure a sandbox launcher can
 * have, and nothing in the repository's tests would have caught it.
 *
 * The launcher has its own build (`tsup.launcher.config.ts`), which the package's `test` script
 * runs BEFORE the suites — so this test never has an artifact to skip on, and the first case
 * below FAILS if the build did not happen. A skipped regression test is a green lie; this one
 * is not allowed to be one.
 *
 * - Given the built launcher, when it is started with a job, the command it wraps really runs
 *   and its output reaches the caller.
 * - Given the same, when the command exits 9, the launcher exits 9 — the status is not lost on
 *   the way through the token.
 * - Given a job the launcher must refuse, when it is started, it exits 127 behind
 *   `penguin-win-run:` rather than running anything.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const launcher = fileURLToPath(new URL("../dist/launch.js", import.meta.url));
const built = existsSync(launcher);

let root = "";
let workspace = "";

beforeAll(() => {
  if (!built || process.platform !== "win32") return;
  root = mkdtempSync(path.join(tmpdir(), "penguin-dist-"));
  workspace = path.join(root, "workspace");
  mkdirSync(workspace, { recursive: true });
});

afterAll(() => {
  if (root !== "") rmSync(root, { recursive: true, force: true });
});

/** Run the built launcher with a job and return what the caller sees. */
function run(flags: readonly string[], argv: readonly string[]) {
  return spawnSync(process.execPath, [launcher, ...flags, ...argv], {
    cwd: workspace,
    env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" },
    encoding: "utf8",
  });
}

/** The job flags for the throwaway Workspace. A function: `workspace` exists only after setup. */
const job = (): string[] => [
  "--workspace",
  workspace,
  "--temp",
  path.join(root, "temp"),
  "--mode",
  "workspace-write",
  "--",
];

describe("the built launcher", () => {
  it("exists: the test script builds it before the suites run", () => {
    expect(
      built,
      "dist/launch.js is missing: `pnpm test` builds it with `tsup --config tsup.launcher.config.ts` " +
        "before vitest runs, so this suite must never have to skip itself",
    ).toBe(true);
  });

  describe.runIf(built && process.platform === "win32")("on Windows", () => {
    it("runs the command it is given", () => {
      const result = run(job(), ["cmd.exe", "/c", "echo RAN"]);
      expect(result.stdout).toContain("RAN");
      expect(result.status).toBe(0);
    });

    it("carries the command's exit code back", () => {
      expect(run(job(), ["cmd.exe", "/c", "exit 9"]).status).toBe(9);
    });

    it("refuses a job it cannot serve, without running anything", () => {
      const result = run([], ["cmd.exe", "/c", "echo RAN"]);
      expect(result.status).toBe(127);
      expect(result.stderr).toContain("penguin-win-run:");
      expect(result.stdout).not.toContain("RAN");
    });

    it("refuses a Workspace on a system location", () => {
      const result = run(
        [
          "--workspace",
          process.env.SystemRoot ?? "C:\\Windows",
          "--temp",
          path.join(root, "temp"),
          "--",
        ],
        ["cmd.exe", "/c", "echo RAN"],
      );
      expect(result.status).toBe(127);
      expect(result.stderr).toContain("protected system location");
    });
  });
});

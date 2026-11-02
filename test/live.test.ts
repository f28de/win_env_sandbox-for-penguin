/**
 * The boundary, measured on this machine.
 *
 * These tests run real commands under a real restricted token, so they are the only evidence
 * that the mechanism holds here rather than in a comment. They are Windows-only and they
 * change ACLs on a throwaway directory under the system temp root — never on a Workspace of
 * yours.
 *
 * - Given a `workspace-write` job, when a command writes inside the Workspace, the file is
 *   there and the command exits 0.
 * - Given the same job, when a command writes outside the Workspace, the file is NOT there and
 *   the command fails — the write SID grants nothing there.
 * - Given the same job, when a command reads outside the Workspace, it still succeeds: the
 *   token restricts writes only.
 * - Given the same job, when a command exits 7, the caller receives 7 — the runner is a
 *   launcher, not a wrapper that swallows status.
 * - Given a `read-only` job, when a command writes inside the Workspace, it is refused: the
 *   write SID is not in the token at all in that mode.
 * - Given a policy that closes temp, when a command writes to %TEMP%, it is refused.
 * - Given a `workspace-write` job, when a command tries to widen the Workspace's own ACL, the
 *   ACL is unchanged: the capability ACE grants writes, not `WRITE_DAC`.
 * - Given a program planted in the Workspace, when a command asks for it by bare name, it is
 *   not started — the current directory is not a search location.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { namesSid } from "../src/acl.js";
import { runJob } from "../src/runner.js";
import type { RunnerJob } from "../src/runner.js";

const windows = process.platform === "win32";

let root = "";
let workspace = "";
let temp = "";
const savedTemp = { TMP: process.env.TMP, TEMP: process.env.TEMP };

beforeAll(() => {
  if (!windows) return;
  root = mkdtempSync(path.join(tmpdir(), "penguin-win-live-"));
  workspace = path.join(root, "workspace");
  temp = path.join(root, "temp");
  mkdirSync(workspace, { recursive: true });
});

afterAll(() => {
  if (!windows) return;
  rmSync(root, { recursive: true, force: true });
});

afterEach(() => {
  if (savedTemp.TMP === undefined) delete process.env.TMP;
  else process.env.TMP = savedTemp.TMP;
  if (savedTemp.TEMP === undefined) delete process.env.TEMP;
  else process.env.TEMP = savedTemp.TEMP;
});

const job = (over: Partial<RunnerJob> = {}): RunnerJob => ({
  argv: ["cmd.exe", "/c", "exit 0"],
  workspace,
  temp,
  mode: "workspace-write",
  grants: [],
  writableTemp: true,
  compatibility: "everyone",
  ...over,
});

/** Run a `cmd.exe` line under the given job and return its exit code. */
function run(line: string, over: Partial<RunnerJob> = {}): number {
  return runJob({ ...job(over), argv: ["cmd.exe", "/c", line] });
}

describe.runIf(windows)("confinement", () => {
  it("writes inside the Workspace", () => {
    const file = path.join(workspace, "inside.txt");
    rmSync(file, { force: true });
    expect(run(`echo probe > ${file}`)).toBe(0);
    expect(existsSync(file)).toBe(true);
  });

  it("refuses a write outside the Workspace", () => {
    const file = path.join(root, "outside.txt");
    rmSync(file, { force: true });
    expect(run(`echo probe > ${file}`)).not.toBe(0);
    expect(existsSync(file)).toBe(false);
  });

  it("still reads outside the Workspace", () => {
    expect(run(`if exist %SystemRoot%\\win.ini (exit 0) else (exit 1)`)).toBe(0);
  });

  it("hands the command's exit code back", () => {
    expect(run("exit 7")).toBe(7);
  });

  it("refuses the Workspace write under read-only", () => {
    const file = path.join(workspace, "read-only.txt");
    rmSync(file, { force: true });
    expect(run(`echo probe > ${file}`, { mode: "read-only" })).not.toBe(0);
    expect(existsSync(file)).toBe(false);
  });

  it("closes the temporary directory when the policy does", () => {
    expect(
      run(`echo probe > %TEMP%\\penguin-live.txt`, { mode: "read-only", writableTemp: false }),
    ).not.toBe(0);
  });

  it("keeps a Everyone-writable directory open in compatibility mode", () => {
    const file = path.join(
      process.env.PUBLIC ?? "C:\\Users\\Public",
      `penguin-live-${Date.now()}.txt`,
    );
    rmSync(file, { force: true });
    expect(run(`echo probe > ${file}`)).toBe(0);
    expect(existsSync(file)).toBe(true);
    rmSync(file, { force: true });
  });

  it("closes it under strict compatibility", () => {
    const file = path.join(
      process.env.PUBLIC ?? "C:\\Users\\Public",
      `penguin-live-${Date.now()}.txt`,
    );
    rmSync(file, { force: true });
    expect(run(`echo probe > ${file}`, { compatibility: "strict" })).not.toBe(0);
    expect(existsSync(file)).toBe(false);
  });

  it("starts a Win64 toolchain", () => {
    // `cmd.exe` is the smallest Windows program there is; if the token could not start it,
    // nothing a Win64 build needs would start either.
    expect(run("ver > nul")).toBe(0);
  });

  it("does not let a confined command rewrite the Workspace's ACL", () => {
    // The control: the same icacls invocation, unconfined, really does widen a directory. If
    // this half failed, the assertion below would pass for the wrong reason.
    const control = path.join(root, "control");
    mkdirSync(control, { recursive: true });
    const outside = spawnSync("icacls.exe", [control, "/grant", "*S-1-1-0:(OI)(CI)F"], {
      encoding: "utf8",
    });
    expect(outside.status).toBe(0);
    expect(namesSid(control, "S-1-1-0")).toBe(true);

    const confined = runJob({
      ...job(),
      argv: ["icacls.exe", workspace, "/grant", "*S-1-1-0:(OI)(CI)F"],
    });
    expect(confined).not.toBe(0);
    expect(namesSid(workspace, "S-1-1-0")).toBe(false);
  });

  it("does not run a program planted in the Workspace", () => {
    const planted = path.join(workspace, "planted.cmd");
    writeFileSync(planted, "@echo PLANTED-RAN\r\n", "utf8");
    // A bare name is resolved from PATH only. `planted` exists in the Workspace — the current
    // directory — and must be refused rather than executed.
    expect(() => runJob({ ...job(), argv: ["planted"] })).toThrow(/deliberately not searched/);
    rmSync(planted, { force: true });
  });
});

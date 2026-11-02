/**
 * How a command's first argument becomes the program Windows runs.
 *
 * - Given a name that carries a path, when it is resolved, it is resolved against the working
 *   directory and used as given — a build's own `build\Release\app.exe` has to be runnable.
 * - Given a bare name that is on PATH, when it is resolved, the absolute path comes back.
 * - Given a bare name that exists ONLY in the working directory, when it is resolved, it is
 *   REFUSED. That directory is the Workspace, the one place a confined command can write, so a
 *   program planted there must never become the command.
 * - Given PATHEXT, when a bare name has no extension, the extensions are tried in order; when
 *   it already has one, it is tried as written (appending PATHEXT would look for `cmd.exe.EXE`).
 * - Given a name nothing provides, when it is resolved, the refusal says the current directory
 *   was deliberately not searched.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { UnresolvableProgram, carriesPath, resolveProgram, searchPath } from "../src/program.js";

let root = "";
let cwd = "";
let bin = "";

const env = (pathValue: string): NodeJS.ProcessEnv => ({
  PATH: pathValue,
  PATHEXT: ".COM;.EXE;.BAT;.CMD",
});

/** Windows paths are case-insensitive: `tool.EXE` and `tool.exe` are the same file. */
const same = (actual: string, expected: string): boolean =>
  actual.toLowerCase() === expected.toLowerCase();

beforeAll(() => {
  root = mkdtempSync(path.join(tmpdir(), "penguin-program-"));
  cwd = path.join(root, "workspace");
  bin = path.join(root, "bin");
  mkdirSync(cwd, { recursive: true });
  mkdirSync(bin, { recursive: true });
  // The plant: a program that exists only where the Agent can write.
  writeFileSync(path.join(cwd, "planted.exe"), "");
  writeFileSync(path.join(cwd, "planted.cmd"), "");
  // A program that exists where the machine keeps programs.
  writeFileSync(path.join(bin, "tool.exe"), "");
  writeFileSync(path.join(bin, "script.cmd"), "");
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("what counts as a path", () => {
  it("treats a separator or a drive as a path", () => {
    expect(carriesPath("build\\app.exe")).toBe(true);
    expect(carriesPath("./run")).toBe(true);
    expect(carriesPath("C:tool.exe")).toBe(true);
    expect(carriesPath("git")).toBe(false);
  });
});

describe("resolving a program", () => {
  const resolve = (name: string) =>
    resolveProgram(name, { cwd, env: env(bin), interpreter: path.join(bin, "node.exe") });

  it("resolves a name that carries a path against the working directory", () => {
    // `.\planted.exe` is the caller naming a file in the Workspace — a build's own output. The
    // bare `planted.exe` below is NOT the same request: it asks to be searched for.
    expect(same(resolve(".\\planted.exe"), path.join(cwd, "planted.exe"))).toBe(true);
    expect(same(resolve(".\\planted.cmd"), path.join(cwd, "planted.cmd"))).toBe(true);
  });

  it("resolves a bare name from PATH", () => {
    expect(same(resolve("tool"), path.join(bin, "tool.exe"))).toBe(true);
  });

  it("tries PATHEXT in order", () => {
    expect(same(resolve("script"), path.join(bin, "script.cmd"))).toBe(true);
  });

  it("takes a name that already has an extension as written", () => {
    // Not `tool.exe.EXE`: PATHEXT is not appended to a name that carries an extension.
    expect(same(resolve("tool.exe"), path.join(bin, "tool.exe"))).toBe(true);
  });

  it("never takes a bare name from the working directory", () => {
    expect(() => resolve("planted")).toThrow(UnresolvableProgram);
  });

  it("says why a program was not found", () => {
    expect(() => resolve("nowhere")).toThrow(/current directory is deliberately not searched/);
  });

  it("refuses a name that carries a path but does not exist", () => {
    expect(() => resolve("build\\missing.exe")).toThrow(/does not exist/);
  });

  it("refuses an empty program", () => {
    expect(() => resolve("  ")).toThrow(UnresolvableProgram);
  });
});

describe("the search path", () => {
  it("leaves out the current directory and empty entries", () => {
    const dirs = searchPath(env(`;${bin};.;`), path.join(bin, "node.exe"));
    expect(dirs).toEqual([bin]);
  });

  it("ends with the interpreter's own directory, once", () => {
    const interpreter = path.join(root, "app", "node.exe");
    const dirs = searchPath(env(bin), interpreter);
    expect(dirs.at(-1)).toBe(path.join(root, "app"));
    expect(searchPath(env(`${bin};${path.join(root, "app")}`), interpreter)).toEqual([
      bin,
      path.join(root, "app"),
    ]);
  });
});

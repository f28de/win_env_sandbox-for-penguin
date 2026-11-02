/**
 * The launcher's argv contract, and the token it builds from it.
 *
 * - Given a well-formed job, when it is parsed, the command is everything after `--` and the
 *   flags are the job — including every repeated `--grant`.
 * - Given a job that names no `--workspace`, no `--temp`, no `--`, or an unknown mode, when it
 *   is parsed, it is refused with a message that names what is missing: a refused job exits
 *   127 behind `penguin-win-run:`, never unconfined.
 * - Given `workspace-write`, when the restricting SIDs are computed, the Workspace's capability
 *   SID is in the list; given `read-only`, it is not — that omission is the mode.
 * - Given `strict` compatibility, when the restricting SIDs are computed, `Everyone` is absent;
 *   given `everyone`, it is present.
 */
import path from "node:path";
import { describe, expect, it } from "vitest";
import { realPathOf } from "../src/paths.js";
import { parseJob, restrictingOf } from "../src/runner.js";
import type { RunnerJob } from "../src/runner.js";
import { capabilitySid } from "../src/sid.js";
import { EVERYONE } from "../src/token.js";

const workspace = "D:\\work\\project";
const temp = "C:\\state\\temp\\abc";

const job = (over: Partial<RunnerJob> = {}): RunnerJob => ({
  argv: ["cmd.exe", "/c", "echo hi"],
  workspace,
  temp,
  mode: "workspace-write",
  grants: [],
  writableTemp: true,
  compatibility: "everyone",
  ...over,
});

describe("parsing a job", () => {
  it("reads the flags and everything after the separator", () => {
    const parsed = parseJob([
      "--workspace",
      workspace,
      "--temp",
      temp,
      "--mode",
      "workspace-write",
      "--grant",
      "C:\\scratch",
      "--grant",
      "C:\\other",
      "--",
      "cmd.exe",
      "/c",
      "echo hi",
    ]);
    expect(parsed.workspace).toBe(workspace);
    expect(parsed.temp).toBe(temp);
    expect(parsed.mode).toBe("workspace-write");
    expect(parsed.grants).toEqual(["C:\\scratch", "C:\\other"]);
    expect(parsed.argv).toEqual(["cmd.exe", "/c", "echo hi"]);
    expect(parsed.writableTemp).toBe(true);
    expect(parsed.compatibility).toBe("everyone");
  });

  it("defaults the mode to workspace-write and compatibility to everyone", () => {
    const parsed = parseJob(["--workspace", workspace, "--temp", temp, "--", "cmd.exe"]);
    expect(parsed.mode).toBe("workspace-write");
    expect(parsed.compatibility).toBe("everyone");
    expect(parsed.writableTemp).toBe(true);
  });

  it("honours a closed temp directory", () => {
    const parsed = parseJob([
      "--workspace",
      workspace,
      "--temp",
      temp,
      "--writable-temp",
      "false",
      "--",
      "cmd.exe",
    ]);
    expect(parsed.writableTemp).toBe(false);
  });

  it.each([
    [["--temp", temp, "--", "cmd.exe"], /no --workspace/],
    [["--workspace", workspace, "--", "cmd.exe"], /no --temp/],
    [["--workspace", workspace, "--temp", temp, "cmd.exe"], /no `--`/],
    [["--workspace", workspace, "--temp", temp, "--"], /names no command/],
    [
      ["--workspace", workspace, "--temp", temp, "--mode", "sandbox", "--", "cmd.exe"],
      /unknown --mode/,
    ],
    [
      ["--workspace", workspace, "--temp", temp, "--compatibility", "loose", "--", "cmd.exe"],
      /unknown --compatibility/,
    ],
    [
      ["--workspace", workspace, "--temp", temp, "--grant", "--", "cmd.exe"],
      /--grant has no value/,
    ],
    [["--workspace", workspace, "--temp", temp, "--nonsense", "x", "--", "cmd.exe"], /--nonsense/],
  ])("refuses %j", (argv, message) => {
    expect(() => parseJob(argv)).toThrow(message);
  });
});

describe("refusing a directory it must never grant", () => {
  const system = process.env.SystemRoot ?? "C:\\Windows";
  const programFiles = process.env.ProgramFiles ?? "C:\\Program Files";
  const profile = process.env.USERPROFILE ?? "C:\\Users\\someone";

  it("refuses a drive root as the Workspace", () => {
    expect(() => parseJob(["--workspace", "D:\\", "--temp", temp, "--", "cmd.exe"])).toThrow(
      /drive root/,
    );
  });

  it("refuses %SystemRoot% ITSELF, not only what is inside it", () => {
    // The first version compared against `%SystemRoot%` WITH a trailing separator, so the
    // directory itself slipped through — and a capability ACE on `C:\Windows` is the worst case
    // of all. Measured before the fix: the ACE was written and the command ran.
    expect(() => parseJob(["--workspace", system, "--temp", temp, "--", "cmd.exe"])).toThrow(
      /protected system location/,
    );
  });

  it("refuses a Workspace inside %SystemRoot%", () => {
    expect(() =>
      parseJob(["--workspace", path.join(system, "Temp"), "--temp", temp, "--", "cmd.exe"]),
    ).toThrow(/protected system location/);
  });

  it("refuses the program files and the program data", () => {
    expect(() => parseJob(["--workspace", programFiles, "--temp", temp, "--", "cmd.exe"])).toThrow(
      /protected system location/,
    );
    expect(() =>
      parseJob(["--workspace", "C:\\ProgramData", "--temp", temp, "--", "cmd.exe"]),
    ).toThrow(/protected system location/);
  });

  it("refuses an ancestor of the user profile", () => {
    // The parent of the profile (`C:\Users`) would propagate the grant over every profile on
    // the machine, so the rule follows the environment rather than a hard-coded path.
    expect(() =>
      parseJob(["--workspace", path.dirname(profile), "--temp", temp, "--", "cmd.exe"]),
    ).toThrow(/every user profile/);
  });

  it("refuses a scratchpad grant inside %SystemRoot%", () => {
    expect(() =>
      parseJob([
        "--workspace",
        workspace,
        "--temp",
        temp,
        "--grant",
        path.join(system, "System32"),
        "--",
        "cmd.exe",
      ]),
    ).toThrow(/protected system location/);
  });

  it("refuses a drive root as the temp directory", () => {
    expect(() => parseJob(["--workspace", workspace, "--temp", "C:\\", "--", "cmd.exe"])).toThrow(
      /drive root/,
    );
  });

  it("refuses the user profile itself", () => {
    // Measured: an inheritable grant over a whole profile had not finished after five minutes,
    // and it would make every file in it writable — credentials and browser profiles included.
    expect(() => parseJob(["--workspace", profile, "--temp", temp, "--", "cmd.exe"])).toThrow(
      /is the user profile/,
    );
  });

  it("allows a Workspace inside the user profile", () => {
    // The ordinary case: a project under the home directory.
    expect(() =>
      parseJob([
        "--workspace",
        path.join(profile, "projects", "app"),
        "--temp",
        temp,
        "--",
        "cmd.exe",
      ]),
    ).not.toThrow();
  });

  // Windows strips trailing dots and spaces from every component before it looks the name up,
  // while `path.resolve` leaves them in place — so these spellings name the protected directory
  // while comparing as something else. Measured: `icacls "C:\Windows."` reads the real ACL.
  it.each([".", " ", "..", " . "])(
    "refuses %j appended to %SystemRoot%, which Windows resolves back to it",
    (suffix) => {
      expect(() =>
        parseJob(["--workspace", `${system}${suffix}`, "--temp", temp, "--", "cmd.exe"]),
      ).toThrow(/protected system location/);
    },
  );

  it("refuses a verbatim path, which bypasses that normalization entirely", () => {
    expect(() =>
      parseJob(["--workspace", `\\\\?\\${system}`, "--temp", temp, "--", "cmd.exe"]),
    ).toThrow(/verbatim or device path/);
    expect(() =>
      parseJob(["--workspace", `\\\\.\\${system}`, "--temp", temp, "--", "cmd.exe"]),
    ).toThrow(/verbatim or device path/);
  });

  it("refuses a component Windows reduces to nothing", () => {
    // `C:\...` is not "a directory called ...": Windows reduces it and addresses the root.
    expect(() => parseJob(["--workspace", "C:\\...", "--temp", temp, "--", "cmd.exe"])).toThrow(
      /reduces to nothing/,
    );
  });

  it("keeps a dot INSIDE a name, which is an ordinary directory name", () => {
    expect(() =>
      parseJob(["--workspace", path.join(profile, "my.project"), "--temp", temp, "--", "cmd.exe"]),
    ).not.toThrow();
  });

  // Only where the volume really resolves 8.3 names; the check is a fact about the filesystem,
  // so the assertion is made only when that fact holds.
  const shortName = "C:\\PROGRA~1";
  it.runIf(realPathOf(shortName) !== null)(
    "refuses an 8.3 short name that resolves to a protected location",
    () => {
      expect(() => parseJob(["--workspace", shortName, "--temp", temp, "--", "cmd.exe"])).toThrow(
        /protected system location/,
      );
    },
  );
});

describe("the restricting SID list", () => {
  it("carries the workspace capability under workspace-write", () => {
    const sids = restrictingOf(job());
    expect(sids).toContain(capabilitySid("workspace", workspace));
    expect(sids).toContain(capabilitySid("temp", workspace));
  });

  it("leaves the workspace capability out under read-only", () => {
    const sids = restrictingOf(job({ mode: "read-only" }));
    expect(sids).not.toContain(capabilitySid("workspace", workspace));
    expect(sids).toContain(capabilitySid("temp", workspace));
  });

  it("leaves the temp capability out when the policy closes temp", () => {
    expect(restrictingOf(job({ writableTemp: false }))).not.toContain(
      capabilitySid("temp", workspace),
    );
  });

  it("keeps Everyone only in the compatibility setting", () => {
    expect(restrictingOf(job())).toContain(EVERYONE);
    expect(restrictingOf(job({ compatibility: "strict" }))).not.toContain(EVERYONE);
  });

  it("never names the same SID twice", () => {
    const sids = restrictingOf(job());
    expect(new Set(sids).size).toBe(sids.length);
  });
});

/**
 * Policy → runner flags, and what the backend promises.
 *
 * - Given a `workspace-write` policy with a Session scratchpad, when the flags are built, the
 *   Workspace is the job's workspace and the scratchpad arrives as `--grant` — a command that
 *   cannot write the plan file is a command the harness cannot use.
 * - Given a `read-only` policy, when the flags are built, no `--grant` is present and the mode
 *   says so: the write SID never reaches the token in that mode.
 * - Given a policy that closes the temporary directory, when the flags are built, the runner
 *   is told, so its own temp grant stays out.
 * - Given either compatibility setting, when enforcement and limits are asked for, the answer
 *   is `partial` with Everyone kept and `full` without, and the disclosed limits say what that
 *   costs — the card shows those words verbatim.
 */
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { SandboxPolicy } from "@prismshadow/penguin-core/plugin";
import { enforcementOf, limitsOf, runnerFlags, writableRoots } from "../src/profile.js";
import type { WinSettings } from "../src/profile.js";
import { tempDirFor } from "../src/sid.js";

const settings = (compatibility: "everyone" | "strict" = "everyone"): WinSettings => ({
  compatibility,
  tempRoot: path.join("C:", "state", "temp"),
});

const policy = (over: Partial<SandboxPolicy> = {}): SandboxPolicy => ({
  mode: "workspace-write",
  workspaceRoot: "D:\\work\\project",
  writableTemp: true,
  ...over,
});

/** The flags as a map, with `--grant` collected into a list (it repeats). */
function read(flags: readonly string[]): {
  values: Map<string, string>;
  grants: string[];
  tail: string;
} {
  const values = new Map<string, string>();
  const grants: string[] = [];
  let i = 0;
  for (; i < flags.length; i += 1) {
    const flag = flags[i]!;
    if (flag === "--") return { values, grants, tail: flag };
    const value = flags[i + 1]!;
    if (flag === "--grant") grants.push(value);
    else values.set(flag, value);
    i += 1;
  }
  return { values, grants, tail: "" };
}

describe("runner flags", () => {
  it("names the workspace, its temp directory and the mode", () => {
    const { values, tail } = read(runnerFlags(policy(), settings()));
    expect(values.get("--workspace")).toBe("D:\\work\\project");
    expect(values.get("--temp")).toBe(tempDirFor(settings().tempRoot, "D:\\work\\project"));
    expect(values.get("--mode")).toBe("workspace-write");
    expect(values.get("--writable-temp")).toBe("true");
    expect(tail).toBe("--");
  });

  it("passes the Session scratchpad as a grant", () => {
    const scratchpad = "C:\\Users\\someone\\AppData\\Local\\penguin\\sessions\\abc";
    const { grants } = read(runnerFlags(policy({ writableRoots: [scratchpad] }), settings()));
    expect(grants).toEqual([scratchpad]);
  });

  it("grants nothing under read-only", () => {
    const { values, grants } = read(
      runnerFlags(policy({ mode: "read-only", writableRoots: ["C:\\scratch"] }), settings()),
    );
    expect(values.get("--mode")).toBe("read-only");
    expect(grants).toEqual([]);
    expect(writableRoots(policy({ mode: "read-only", writableRoots: ["C:\\scratch"] }))).toEqual(
      [],
    );
  });

  it("tells the runner when the policy closes temp", () => {
    const { values } = read(runnerFlags(policy({ writableTemp: false }), settings()));
    expect(values.get("--writable-temp")).toBe("false");
  });

  it("carries the compatibility setting", () => {
    expect(read(runnerFlags(policy(), settings("strict"))).values.get("--compatibility")).toBe(
      "strict",
    );
    expect(read(runnerFlags(policy(), settings())).values.get("--compatibility")).toBe("everyone");
  });
});

describe("what the backend promises", () => {
  it("reports full enforcement only without the compatibility SID", () => {
    expect(enforcementOf(settings("everyone"))).toBe("partial");
    expect(enforcementOf(settings("strict"))).toBe("full");
  });

  it("discloses reads, the network and MSYS in both modes", () => {
    for (const mode of ["everyone", "strict"] as const) {
      const text = limitsOf(settings(mode))
        .map((limit) => limit.text)
        .join("\n");
      expect(text).toMatch(/Reads are not restricted/);
      expect(text).toMatch(/network is not cut/);
      expect(text).toMatch(/MSYS-runtime programs/);
    }
  });

  it("says what the compatibility setting costs, in the wording of that setting", () => {
    expect(
      limitsOf(settings("everyone"))
        .map((l) => l.text)
        .join("\n"),
    ).toMatch(/C:\\Users\\Public/);
    expect(
      limitsOf(settings("strict"))
        .map((l) => l.text)
        .join("\n"),
    ).toMatch(/PowerShell 5\.1/);
  });

  it("is bilingual everywhere the card shows it", () => {
    for (const limit of limitsOf(settings("everyone"))) {
      expect(limit.textZh).toBeTruthy();
    }
  });
});

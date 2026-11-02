/**
 * The capability SIDs, and the paths they are derived from.
 *
 * - Given two spellings of one Workspace (case, separator, trailing backslash), when the SID
 *   is derived, both produce the same SID — otherwise the second spelling would grant a tree
 *   that is already granted.
 * - Given one Workspace and two purposes, when both SIDs are derived, they differ — the temp
 *   grant must not be the workspace grant.
 * - Given any Workspace, when the SID is derived twice in two processes, it is identical —
 *   the identity is derived, never stored, and a restart must re-hit the standing ACE.
 * - Given a temp root, when the private temp directory is derived, it is one stable 16-hex
 *   directory per Workspace, so Remove can find it again.
 * - Given a spelling Windows resolves back to the same directory (a trailing dot or space),
 *   when the SID is derived, it is the SAME SID — the ACE is written to that directory, so the
 *   identity has to be that directory.
 */
import path from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalWorkspace, capabilitySid, tempDirFor } from "../src/sid.js";

describe("the canonical Workspace path", () => {
  it("folds case, separators and a trailing backslash", () => {
    const canonical = canonicalWorkspace("D:\\Work\\Project\\");
    expect(canonical).toBe("d:\\work\\project");
    expect(canonicalWorkspace("d:/WORK/project")).toBe(canonical);
  });

  it("keeps a drive root as it is", () => {
    expect(canonicalWorkspace("D:\\")).toBe("d:\\");
  });

  it("resolves a relative path against the process's directory", () => {
    expect(canonicalWorkspace("sub/dir")).toBe(path.resolve("sub", "dir").toLowerCase());
  });

  it("strips the trailing dots and spaces Win32 strips", () => {
    // `D:\proj.` and `D:\proj ` name the same directory to every Win32 API that takes a path.
    expect(canonicalWorkspace("D:\\work\\a.")).toBe("d:\\work\\a");
    expect(canonicalWorkspace("D:\\work\\a ")).toBe("d:\\work\\a");
  });

  it("keeps a dot inside a name", () => {
    expect(canonicalWorkspace("D:\\work\\my.project")).toBe("d:\\work\\my.project");
  });
});

describe("capability SIDs", () => {
  it("is a SID no account can hold", () => {
    expect(capabilitySid("workspace", "D:\\work")).toMatch(/^S-1-4-\d+-\d+$/);
  });

  it("is stable across spellings of the same Workspace", () => {
    expect(capabilitySid("workspace", "D:\\Work\\A")).toBe(
      capabilitySid("workspace", "d:\\work\\a\\"),
    );
  });

  it("differs between two Workspaces", () => {
    expect(capabilitySid("workspace", "D:\\work\\a")).not.toBe(
      capabilitySid("workspace", "D:\\work\\b"),
    );
  });

  it("differs between the workspace and temp purposes", () => {
    const workspace = capabilitySid("workspace", "D:\\work\\a");
    const temp = capabilitySid("temp", "D:\\work\\a");
    expect(workspace).not.toBe(temp);
  });

  it("keeps both sub-authorities inside the positive 31-bit range", () => {
    for (const workspace of ["D:\\work\\a", "C:\\Users\\someone\\project", "E:\\"]) {
      for (const sid of [capabilitySid("workspace", workspace), capabilitySid("temp", workspace)]) {
        const [, , first, second] = sid.split("-");
        expect(Number(first)).toBeLessThan(2 ** 31);
        expect(Number(second)).toBeLessThan(2 ** 31);
      }
    }
  });
});

describe("the private temp directory", () => {
  it("is one stable directory per Workspace", () => {
    const root = path.join("C:", "temp", "sandbox-win");
    expect(tempDirFor(root, "D:\\work\\a")).toBe(tempDirFor(root, "d:/WORK/A"));
    expect(tempDirFor(root, "D:\\work\\a")).not.toBe(tempDirFor(root, "D:\\work\\b"));
  });

  it("is a 16-hex name under the root", () => {
    const root = path.join("C:", "temp", "sandbox-win");
    const dir = tempDirFor(root, "D:\\work\\a");
    expect(path.dirname(dir)).toBe(root);
    expect(path.basename(dir)).toMatch(/^[0-9a-f]{16}$/);
  });
});

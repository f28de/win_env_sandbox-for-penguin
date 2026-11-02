/**
 * What a path really names, on Windows — one answer for every caller that has to agree on it.
 *
 * TWO NORMALIZATIONS DISAGREE, and this module exists because of it:
 *
 * - `path.resolve`, and every Node `fs` call, treats the path as a string. Node opens files
 *   with `\\?\` verbatim paths, which switch OFF the Win32 name cleanup — so
 *   `fs.statSync("C:\\Windows.")` is ENOENT and `fs.realpathSync` throws.
 * - The ACL APIs take a DOS path and let the object manager clean it: trailing dots and spaces
 *   are stripped from every component. Measured: `icacls "C:\Windows."` prints the ACL of the
 *   real `C:\Windows`, and `GetNamedSecurityInfoW("C:\Windows.")` succeeds.
 *
 * A guard that compares raw strings therefore checks a DIFFERENT path from the one the ACE
 * lands on — `--workspace "C:\Windows."` passed a deny-list holding `C:\Windows` and the
 * capability ACE went onto Windows itself. So nothing here compares spellings: the guard
 * compares the name Win32 will look up, plus the name the filesystem resolves it to.
 *
 * The same rule has to hold for the capability SID, which is hashed out of the Workspace path:
 * `D:\proj` and `D:\proj.` are one directory, so they must be one identity, or the token and
 * the ACE would name different SIDs for one grant.
 */
import fs from "node:fs";
import path from "node:path";

/** A path, as the two views of it: the string Node sees, and the name Win32 looks up. */
export interface Win32Path {
  /** `path.resolve` of the input — the string form, `..` and separators handled. */
  resolved: string;
  /** The name Win32 will look up: trailing dots and spaces stripped from every component. */
  path: string;
  /**
   * True when a component reduced to nothing (`C:\...`), which Windows cannot address as
   * written. Such a path is refused rather than guessed at: it resolves to something else
   * entirely (`C:\...` behaves like `C:\`).
   */
  empty: boolean;
}

/**
 * Strip what Win32 strips: the trailing dots and spaces of every component.
 *
 * Only TRAILING ones — `D:\my.project` is a name, `D:\my.project.` is the same name spelled
 * the way Windows also accepts it.
 */
export function win32Path(value: string): Win32Path {
  const resolved = path.resolve(value);
  const parsed = path.parse(resolved);
  let empty = false;
  const cleaned = resolved
    .slice(parsed.root.length)
    .split(path.sep)
    .map((part) => {
      const trimmed = part.replace(/[. ]+$/, "");
      if (trimmed === "" && part !== "") empty = true;
      return trimmed;
    });
  return { resolved, path: parsed.root + cleaned.join(path.sep), empty };
}

/** The name Win32 will look up for `value`. */
export function canonicalPath(value: string): string {
  return win32Path(value).path;
}

/**
 * The canonical form of a Workspace path, which is what the capability SID is hashed from.
 *
 * Case-folded because Windows paths are case-insensitive, and separator-normalized for the same
 * reason: `D:\work` and `d:/WORK/` are one directory and must be one SID, or the second spelling
 * would re-grant a tree that is already granted.
 */
export function canonicalWorkspace(workspace: string): string {
  const canonical = canonicalPath(workspace).replaceAll("/", "\\");
  return canonical.length > 3
    ? canonical.replace(/\\+$/, "").toLowerCase()
    : canonical.toLowerCase();
}

/**
 * The path the filesystem resolves `value` to — 8.3 short names expanded, junctions followed —
 * or `null` when it does not resolve (the path does not exist, or Node cannot open it).
 *
 * `fs.realpathSync.native` is `GetFinalPathNameByHandleW` under the hood, which is the same
 * answer Explorer would give. It is a second opinion, not the primary one: the primary is
 * {@link canonicalPath}, because a path that does not exist yet has no real path and still has
 * to be judged.
 */
export function realPathOf(value: string): string | null {
  try {
    return fs.realpathSync.native(value);
  } catch {
    return null;
  }
}

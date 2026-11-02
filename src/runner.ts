/**
 * The launcher's job: what a confined command becomes.
 *
 * The harness spawns `launch.js` in place of the command — `node launch.js --workspace … -- argv`
 * — which is the same shape bwrap, the Landlock launcher and `sandbox-exec` present to the
 * sandbox seam, so nothing in the harness needs to know Windows exists. Everything that can
 * fail happens HERE, before a process exists: parsing the job, granting the Workspace, building
 * the token. A failure prints one line beginning `penguin-win-run:` and exits 127, which the
 * seam's `runnerFailureRules` matches, so a refused command is never mistaken for a denial the
 * policy produced (a denial looks like `Access is denied.` on the command's own stderr).
 *
 * THIS MODULE HAS NO SIDE EFFECTS, deliberately: `launch.ts` is the entry that calls `main()`,
 * because an entry file that decides "am I the entry?" by comparing `import.meta.url` with
 * `process.argv[1]` stops working the moment a bundler moves that code into a shared chunk.
 *
 * Grants happen here rather than in the provider because they can be slow: the first grant on
 * a large tree propagates one inheritable ACE across all of it, and doing that inside the
 * server's `confine()` would block the event loop of every other Session. A runner has its own
 * process to block.
 *
 * `--compatibility strict` drops `Everyone` from the token's restricting list; the default
 * keeps it so .NET and MSYS-linked toolchains start. See `src/token.ts` for what that costs.
 */
import { mkdirSync } from "node:fs";
import path from "node:path";
import { grantWrite } from "./acl.js";
import { canonicalPath, realPathOf, win32Path } from "./paths.js";
import { capabilitySid } from "./sid.js";
import { EVERYONE, spawnRestricted } from "./token.js";

/** How the token is built for one command. */
export type Compatibility = "everyone" | "strict";

/** A parsed job: what to run, where, and with what write allowlist. */
export interface RunnerJob {
  /** The command, exactly as the caller asked for it. */
  argv: readonly string[];
  /** The Workspace the policy named. */
  workspace: string;
  /** The private temp directory of this Workspace. */
  temp: string;
  /** `read-only` or `workspace-write`. */
  mode: "read-only" | "workspace-write";
  /** Further directories `workspace-write` may write (the Session's scratchpad). */
  grants: readonly string[];
  /** Whether the system temporary directory is writable. */
  writableTemp: boolean;
  /** `everyone` keeps the compatibility SID; `strict` drops it. */
  compatibility: Compatibility;
}

/** What the runner calls to stop: the message goes to stderr behind `penguin-win-run:`. */
class Refusal extends Error {}

/** The flags a job may carry; anything else is a refusal, not a typo to ignore. */
const KNOWN_FLAGS = new Set([
  "--workspace",
  "--temp",
  "--mode",
  "--compatibility",
  "--writable-temp",
]);

/**
 * Locations no capability ACE may ever be written on, and no tree may contain.
 *
 * A deny-list, not a prefix match on one location. The first version of this check compared the
 * target against `%SystemRoot%` with a trailing separator — which let `C:\Windows` ITSELF
 * through, and said nothing about `C:\Program Files` or `C:\ProgramData`. Both are exactly the
 * targets that must never receive an ACE: the first is Windows, the others hold installed
 * programs, and an inheritable ACE on either propagates across a tree of tens of thousands of
 * files (measured: a grant on `C:\Program Files` ran for minutes and left inherited ACEs in
 * seven directories before it was interrupted).
 */
function systemLocations(): string[] {
  const env = process.env;
  const places = [env.SystemRoot, env.ProgramFiles, env["ProgramFiles(x86)"], env.ProgramData];
  return places
    .filter((place): place is string => typeof place === "string" && place !== "")
    .map((place) => path.resolve(place).toLowerCase());
}

/** The user's own profile: never the target of a grant, though a directory inside it may be. */
function profileRoots(): string[] {
  const env = process.env;
  return [env.USERPROFILE, env.HOME]
    .filter((place): place is string => typeof place === "string" && place !== "")
    .map((place) => path.resolve(place).toLowerCase());
}

/**
 * Refuse a directory this backend must never write an ACE onto.
 *
 * The provider derives these flags from the policy, not from the model, so this is the second
 * line rather than the first: a policy that arrived wrong — a Workspace at `D:\`, a scratchpad
 * inside `%SystemRoot%` — would otherwise have this backend grant a capability SID write access
 * to an entire volume, to Windows, or to a tree big enough to hang the command.
 *
 * IT COMPARES NAMES, NOT SPELLINGS. Windows strips trailing dots and spaces from every
 * component of a DOS path before looking it up, while `path.resolve` leaves them in place — so
 * `--workspace "C:\Windows."` passed a deny-list holding `C:\Windows`, and the ACE went onto
 * Windows itself (measured: `icacls "C:\Windows."` reads the real Windows ACL). Every candidate
 * spelling is therefore reduced to the name Win32 will use (`win32Path`), and the filesystem's
 * own answer (`realPathOf`, which expands 8.3 short names and follows junctions) is checked as
 * a second opinion.
 *
 * Four shapes are refused:
 *
 * - the drive root (`D:\`) — a whole volume;
 * - a system location itself (`C:\Windows`, `C:\Program Files`) or anything inside it;
 * - an ANCESTOR of one — `C:\Program`, `C:\Users` — which would sweep the protected location
 *   into the grant anyway, and would propagate over every profile on the machine;
 * - the user profile itself. Measured: granting it propagates one inheritable ACE across the
 *   whole home directory, and the command had not started after five minutes. It is also the
 *   wrong shape of grant — it would make every file in the profile writable, credentials and
 *   browser profiles included. A directory INSIDE the profile is the ordinary Workspace and is
 *   allowed, so the message says to pick one.
 *
 * Two spellings are refused outright rather than judged: a verbatim/device path (`\\?\…`,
 * `\\.\…`) switches off the very normalization this guard depends on, and a component Windows
 * reduces to nothing (`C:\...`) addresses something other than what it says.
 *
 * A legitimately huge Workspace is not refused: it is the user's own choice, and the cost is a
 * slow first grant (documented in the README). The guard is aimed at targets no one meant to
 * choose, not at large projects.
 */
function assertGrantable(flag: string, value: string): void {
  if (/^\\\\[?.]\\/.test(value)) {
    throw new Refusal(
      `${flag} ${value} is a verbatim or device path: it bypasses the name normalization this ` +
        "check depends on, so it cannot be compared against the protected locations",
    );
  }
  const named = win32Path(value);
  if (named.empty) {
    throw new Refusal(
      `${flag} ${value} has a path component that Windows reduces to nothing: refusing to guess ` +
        "which directory it names",
    );
  }
  const root = path.parse(named.path).root.toLowerCase();
  const candidates = new Set<string>([named.path.toLowerCase()]);
  const real = realPathOf(named.path);
  if (real !== null) candidates.add(real.toLowerCase());
  for (const target of candidates) {
    if (target === root) {
      throw new Refusal(
        `${flag} ${value} is a drive root: refusing to grant write access to a volume`,
      );
    }
    for (const place of systemLocations()) {
      if (target === place) {
        throw new Refusal(`${flag} ${value} is a protected system location: refusing to grant it`);
      }
      if (target.startsWith(`${place}${path.sep}`)) {
        throw new Refusal(`${flag} ${value} is inside a protected system location: refusing it`);
      }
      if (place.startsWith(`${target}${path.sep}`)) {
        throw new Refusal(
          `${flag} ${value} contains a protected system location (${place}): refusing to grant it`,
        );
      }
    }
    for (const profile of profileRoots()) {
      if (target === profile) {
        throw new Refusal(
          `${flag} ${value} is the user profile: a grant over every file in it takes minutes and ` +
            "would make your whole home directory writable — choose a directory inside it",
        );
      }
      if (profile.startsWith(`${target}${path.sep}`)) {
        throw new Refusal(
          `${flag} ${value} contains every user profile on this machine: refusing to grant it`,
        );
      }
    }
  }
}

/** Parse the runner's argv, or explain why it cannot be parsed. */
export function parseJob(argv: readonly string[]): RunnerJob {
  const separator = argv.indexOf("--");
  if (separator < 0) throw new Refusal("the job has no `--` before the command");
  const flags = argv.slice(0, separator);
  const command = argv.slice(separator + 1);
  if (command.length === 0) throw new Refusal("the job names no command");

  const values = new Map<string, string>();
  const grants: string[] = [];
  for (let i = 0; i < flags.length; i += 1) {
    const flag = flags[i]!;
    const value = flags[i + 1];
    if (flag === "--grant") {
      if (value === undefined) throw new Refusal("--grant has no value");
      grants.push(value);
      i += 1;
      continue;
    }
    if (!flag.startsWith("--")) throw new Refusal(`unexpected argument ${flag}`);
    if (!KNOWN_FLAGS.has(flag)) throw new Refusal(`unknown flag ${flag}`);
    if (value === undefined) throw new Refusal(`${flag} has no value`);
    values.set(flag.slice(2), value);
    i += 1;
  }

  const workspace = values.get("workspace");
  if (workspace === undefined) throw new Refusal("the job names no --workspace");
  assertGrantable("--workspace", workspace);
  const mode = values.get("mode") ?? "workspace-write";
  if (mode !== "read-only" && mode !== "workspace-write") {
    throw new Refusal(`unknown --mode ${mode}`);
  }
  const compatibility = values.get("compatibility") ?? "everyone";
  if (compatibility !== "everyone" && compatibility !== "strict") {
    throw new Refusal(`unknown --compatibility ${compatibility}`);
  }
  const tempRoot = values.get("temp");
  if (tempRoot === undefined) throw new Refusal("the job names no --temp");
  assertGrantable("--temp", tempRoot);
  for (const grant of grants) assertGrantable("--grant", grant);
  const writableTemp = values.get("writable-temp") !== "false";
  // One spelling from here on: the guard judged the canonical name, the ACE has to land on it,
  // and the capability SID has to be hashed from it. `D:\proj.` and `D:\proj` are one
  // directory, so they must be one grant and one identity.
  return {
    argv: command,
    workspace: canonicalPath(workspace),
    temp: canonicalPath(tempRoot),
    mode,
    grants: grants.map((grant) => canonicalPath(grant)),
    writableTemp,
    compatibility,
  };
}

/** The SIDs this job's token may write as. */
export function restrictingOf(job: RunnerJob): string[] {
  const sids: string[] = [];
  if (job.compatibility === "everyone") sids.push(EVERYONE);
  if (job.mode === "workspace-write") sids.push(capabilitySid("workspace", job.workspace));
  if (job.writableTemp) sids.push(capabilitySid("temp", job.workspace));
  return sids;
}

/**
 * Run one job and return the command's exit code.
 *
 * Under `workspace-write` the Workspace, the policy's further roots and (when the policy grants
 * temp) the private temp directory are granted before the token is built — so a grant that
 * fails stops the command instead of running it against a boundary that is not there. Under
 * `read-only` nothing is granted: the write SID stays out of the token's list entirely, which
 * is what makes a standing ACE from an earlier `workspace-write` run inert.
 */
export function runJob(job: RunnerJob): number {
  if (job.mode === "workspace-write") {
    for (const dir of [job.workspace, ...job.grants])
      grantWrite(dir, capabilitySid("workspace", job.workspace));
  }
  const env: Record<string, string | undefined> = {
    // The runner's own launcher variable: in the desktop app `node` is the app's binary, and
    // the command it starts must not inherit "run me as node".
    ELECTRON_RUN_AS_NODE: undefined,
  };
  if (job.writableTemp) {
    mkdirSync(job.temp, { recursive: true });
    grantWrite(job.temp, capabilitySid("temp", job.workspace));
    env.TMP = job.temp;
    env.TEMP = job.temp;
  }
  return spawnRestricted({
    argv: job.argv,
    cwd: process.cwd(),
    restricting: restrictingOf(job),
    env,
  });
}

/** The entry point: parse, run, and turn any failure into the runner's own signal. */
export function main(argv: readonly string[]): number {
  try {
    return runJob(parseJob(argv));
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    process.stderr.write(`penguin-win-run: ${detail}\n`);
    return 127;
  }
}

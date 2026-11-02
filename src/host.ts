/**
 * What this machine is, and what the last task left behind.
 *
 * The state file is small on purpose. There is no rootfs to download and no distro to
 * register — the boundary is a token, and the token is built from the caller's own — so the
 * only thing worth persisting is (a) that the mechanism was proved on this machine and (b)
 * which Workspaces carry a standing capability ACE, so Remove can take them back out. The
 * SIDs themselves are derived from the path (see `src/sid.ts`), never stored.
 */
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";

/** Where this backend keeps its state and its private temp root. */
export function stateDir(env: NodeJS.ProcessEnv = process.env): string {
  const base = env.LOCALAPPDATA ?? env.APPDATA ?? path.join(os.homedir(), "AppData", "Local");
  return path.join(base, "penguin", "sandbox-win");
}

/** The temp root every Workspace's private temp directory lives under. */
export function tempRoot(): string {
  return path.join(stateDir(), "temp");
}

/** What `Initialize` recorded, and what `Remove` needs to undo. */
export interface WinState {
  /** Bumped when the shape changes; a state from another shape is re-initialized. */
  version: 1;
  /** When the mechanism was last proved on this machine. */
  initializedAt: string;
  /** Workspaces that carry a standing write ACE, so Remove can revoke them. */
  workspaces: string[];
}

/** The state file's path. */
export function statePath(): string {
  return path.join(stateDir(), "state.json");
}

/** The recorded state, or `null` when this machine has not been initialized. */
export function readState(): WinState | null {
  try {
    const raw = JSON.parse(fs.readFileSync(statePath(), "utf8")) as Partial<WinState>;
    if (raw.version !== 1 || typeof raw.initializedAt !== "string") return null;
    return {
      version: 1,
      initializedAt: raw.initializedAt,
      workspaces: Array.isArray(raw.workspaces)
        ? raw.workspaces.filter((w) => typeof w === "string")
        : [],
    };
  } catch {
    return null;
  }
}

/** Write the state file (creating its directory). */
export function writeState(state: WinState): void {
  fs.mkdirSync(stateDir(), { recursive: true });
  fs.writeFileSync(statePath(), `${JSON.stringify(state, null, 2)}\n`, "utf8");
}

/**
 * Remember that `workspace` carries a standing ACE, so Remove can find it later.
 *
 * Called from `confine()`, which runs on the server's event loop: it does nothing at all once
 * the Workspace is known, and never throws — bookkeeping must not be able to refuse a command
 * the boundary would otherwise allow.
 */
export function rememberWorkspace(workspace: string): void {
  try {
    const state = readState();
    if (state === null) return;
    if (state.workspaces.some((w) => w.toLowerCase() === workspace.toLowerCase())) return;
    writeState({ ...state, workspaces: [...state.workspaces, workspace] });
  } catch {
    // A read-only %LOCALAPPDATA%, a full disk: none of it is the command's problem.
  }
}

/** The programs an MSYS runtime refuses to start under a write-restricted token. */
const MSYS_SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh", "mksh", "fish", "git-bash"]);

/**
 * True when `program` is a POSIX shell shipped by an MSYS distribution (Git for Windows, the
 * MinGit the Windows package bundles, MSYS2) — or any program inside an MSYS `usr\bin`, which
 * is where every binary linked against `msys-2.0.dll` lives.
 *
 * Measured: under the write-restricted token the MSYS runtime aborts before the shell runs —
 * `cygheap_user::init: NtSetInformationToken (TokenDefaultDacl), 0xC0000022`, then
 * `couldn't create signal pipe, Win32 error 5` — with or without the compatibility SID. It is
 * the runtime, not the shell, so the whole family is refused by runtime rather than by name.
 */
export function unstartable(program: string): boolean {
  const segments = program.toLowerCase().split(/[\\/]+/);
  const base = (segments.at(-1) ?? "").replace(/\.exe$/, "");
  return MSYS_SHELLS.has(base) || (segments.at(-3) === "usr" && segments.at(-2) === "bin");
}

/** The one setting that fixes an MSYS-runtime session shell, as every refusal of it words it. */
export const SHELL_FIX =
  "Set PENGUIN_SHELL=pwsh (PowerShell 7) — or PENGUIN_SHELL=powershell (Windows PowerShell 5.1) " +
  "where PowerShell 7 is not installed — in the harness's environment and restart it";

/** The harness's session shell, as core's `ShellInvocation` describes it. */
export interface SessionShell {
  command: string;
}

/**
 * The harness's session shell, read from the HOST's copy of core at run time.
 *
 * Read by namespace through a specifier a bundler leaves alone: a second, bundled copy of core
 * would answer from this package's resolution rather than the harness's, and a host core from
 * before `sessionShell` existed must fail here (returning `null`) instead of failing to link.
 */
const HOST_CORE: string = "@prismshadow/penguin-core/plugin";

export async function hostSessionShell(
  load: () => Promise<unknown> = () => import(HOST_CORE),
): Promise<SessionShell | null> {
  let core: { sessionShell?: unknown };
  try {
    core = (await load()) as { sessionShell?: unknown };
  } catch {
    return null;
  }
  return typeof core.sessionShell === "function" ? (core.sessionShell() as SessionShell) : null;
}

/**
 * Fail the backend's load on Windows when the harness's session shell is one the token cannot
 * start. A backend whose load fails is not mounted, and the sandbox card reports it with this
 * reason — better than mounting and then refusing every single command with the MSYS runtime's
 * own cryptic abort.
 */
export function assertSessionShellConfinable(
  shell: SessionShell | null,
  platform: NodeJS.Platform = process.platform,
): void {
  if (platform !== "win32" || shell === null || !unstartable(shell.command)) return;
  throw new Error(
    `sandbox-win cannot confine commands under the session shell "${shell.command}": the MSYS ` +
      "runtime behind it (Git for Windows, MinGit, MSYS2) aborts under a write-restricted " +
      `token before the shell starts. ${SHELL_FIX}.`,
  );
}

/** True when `koffi` loads on this host — the one prerequisite with no Windows-only fallback. */
export function koffiLoads(): boolean {
  try {
    createRequire(import.meta.url)("koffi");
    return true;
  } catch {
    return false;
  }
}

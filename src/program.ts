/**
 * Turning the command's first argument into the program Windows is told to run.
 *
 * `CreateProcessAsUserW` with `lpApplicationName` NULL resolves the program itself, and its
 * search order puts **the current directory** ahead of `PATH`. The current directory of a
 * confined command is the Workspace — the one place the Agent can write. So a bare `git` in a
 * command would find `.\git.exe` if the Agent had dropped one there, and that file would run
 * with the Agent's reads and its network. Confinement restricts writes; it cannot undo an
 * execution the launcher itself chose.
 *
 * This module therefore resolves the program the way Windows does MINUS the current directory,
 * and hands the absolute path to `CreateProcessAsUserW`. What is deliberately kept:
 *
 * - a name that carries a path (`.\build\app.exe`, `D:\tools\x.exe`) is the caller naming a
 *   file, so it is resolved against the working directory and used as given — a build's own
 *   output has to be runnable;
 * - `PATH` and `PATHEXT` are honoured, so `cmake`, `git`, `node` behave as they do outside;
 * - the directory of the running interpreter is searched last, which is where `node.exe` sits
 *   in the desktop app (a directory the Agent cannot write);
 * - the current directory is NOT searched. A program that exists only there is refused, by
 *   name, rather than silently taken from the Workspace.
 *
 * A shell defeats this by design: `cmd.exe /c git status` lets `cmd` do its own search, which
 * does include the current directory. That is the shell's behaviour, identical confined or not,
 * and it is why the resolution here only claims to govern what THIS launcher starts.
 */
import fs from "node:fs";
import path from "node:path";

/** Why a program could not be resolved, in the words the runner prints. */
export class UnresolvableProgram extends Error {}

/** True when `name` names a file rather than asking to be searched for. */
export function carriesPath(name: string): boolean {
  return name.includes("\\") || name.includes("/") || /^[a-zA-Z]:/.test(name);
}

/**
 * The extensions to try, in `PATHEXT` order.
 *
 * A name that already carries one is tried as written and nothing else: appending `PATHEXT` to
 * `cmd.exe` would look for `cmd.exe.EXE` and find nothing, which is how the first version of
 * this function lost every program the harness names in full.
 */
function extensionsFor(name: string, pathext: string): string[] {
  if (path.extname(name) !== "") return [""];
  return pathext
    .split(";")
    .map((one) => one.trim())
    .filter((one) => one !== "")
    .concat("");
}

function isFile(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isFile();
  } catch {
    return false;
  }
}

/** The directories a bare name is searched in, in order, with the current directory left out. */
export function searchPath(
  env: NodeJS.ProcessEnv = process.env,
  interpreter: string = process.execPath,
): string[] {
  const dirs: string[] = [];
  for (const entry of (env.PATH ?? env.Path ?? "").split(path.delimiter)) {
    const dir = entry.trim();
    if (dir === "" || dir === "." || dir === ".\\") continue;
    dirs.push(path.resolve(dir));
  }
  // Where the runner's own interpreter lives: `node.exe` in a bundled app, and a directory no
  // confined command can write.
  const own = path.dirname(interpreter);
  if (!dirs.some((dir) => dir.toLowerCase() === own.toLowerCase())) dirs.push(own);
  return dirs;
}

/**
 * Resolve `name` to an absolute path, or throw {@link UnresolvableProgram}.
 *
 * `cwd` is used only for a name that carries a path — never as a search location.
 */
export function resolveProgram(
  name: string,
  options: {
    cwd: string;
    env?: NodeJS.ProcessEnv;
    interpreter?: string;
  },
): string {
  if (name.trim() === "") throw new UnresolvableProgram("the command names no program");
  const env = options.env ?? process.env;
  const pathext = env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD";
  if (carriesPath(name)) {
    const absolute = path.resolve(options.cwd, name);
    if (!isFile(absolute)) throw new UnresolvableProgram(`${name} does not exist (${absolute})`);
    return absolute;
  }
  for (const dir of searchPath(env, options.interpreter ?? process.execPath)) {
    for (const ext of extensionsFor(name, pathext)) {
      const candidate = path.join(dir, `${name}${ext}`);
      if (isFile(candidate)) return candidate;
    }
  }
  throw new UnresolvableProgram(
    `${name} is not on PATH. The current directory is deliberately not searched: a confined ` +
      "command runs in the Workspace, and a program planted there must not become the command.",
  );
}

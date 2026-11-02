/**
 * Building the write-restricted token, and starting one process under it.
 *
 * The token is the whole boundary. It is the caller's own token — so the command runs as the
 * person running the harness, with their reads, their environment and their settings — with
 * two changes:
 *
 *   `WRITE_RESTRICTED`  every write access is checked a second time, against the restricting
 *                       SID list alone. The normal SIDs still answer the read checks, which is
 *                       why a confined command can read `C:\Windows` and your profile.
 *   `DISABLE_MAX_PRIVILEGE`
 *                       no privilege beyond the standard ones, so nothing in the child can
 *                       take ownership or restore a right it was denied.
 *
 * The restricting list always carries the logon SID (see below) and, per policy, the
 * Workspace's capability SID and the temp capability SID. `Attributes` is 0 on every entry:
 * measured on Windows 11, `SE_GROUP_ENABLED` (4) makes `CreateRestrictedToken` fail with
 * `ERROR_INVALID_PARAMETER` (87) even though the documentation calls the field ignored.
 *
 * THE LOGON SID IS NOT OPTIONAL. A restricted token whose list is only the capability SID
 * starts a process that dies before `main`: `cmd.exe` returns `STATUS_DLL_INIT_FAILED`
 * (0xC0000142) during DLL initialization, because the loader creates its section objects with
 * a DACL the restricted write check then refuses. The logon SID is the ambient identity of
 * the session, and its presence is what lets ordinary process startup happen at all.
 *
 * `Everyone` (`S-1-1-0`) is the compatibility switch, and it is a real trade. With it,
 * .NET Framework and MSYS-linked programs work — `powershell.exe` starts, `git.exe` opens
 * `NUL` — because they write to objects whose DACL grants Everyone. Without it they fail
 * (`CLR … 0x80070005`, `could not open '/dev/null'`), and every directory that grants
 * Everyone write becomes writable: `C:\Users\Public` above all. The default keeps it, because
 * a Win64 toolchain (MSBuild is .NET Framework) and a Windows session shell (Windows
 * PowerShell 5.1 is too) are what this backend exists for; the `strict` setting drops it and
 * the card says what that costs.
 *
 * WHAT THE TOKEN CANNOT DO. It restricts writes only. Reads, the network and process
 * visibility are untouched — that is the shape of the primitive, not a shortcut — so this
 * backend declares `fs-write` and `closed-temp` and nothing else, and the sandbox service
 * never routes a network or mask-paths policy here.
 */
import {
  CREATE_SUSPENDED,
  DISABLE_MAX_PRIVILEGE,
  HANDLE_FLAG_INHERIT,
  INFINITE,
  JOB_EXTENDED_LIMIT_CLASS,
  KILL_ON_JOB_CLOSE,
  SE_GROUP_LOGON_ID,
  STARTF_USESTDHANDLES,
  STD_HANDLES,
  TOKEN_ALL_NEEDED,
  TOKEN_GROUPS_CLASS,
  WRITE_RESTRICTED,
  Win32Error,
  close,
  isNull,
  localFree,
  nativeBytes,
  readBytes,
  win32,
} from "./win32.js";
import type { NativeBytes, Ptr } from "./win32.js";
import { resolveProgram } from "./program.js";
import { sidPtr } from "./sid.js";

/** One process to start under a restricted token. */
export interface SpawnRequest {
  /** The program and its arguments, exactly as the caller asked for them. */
  argv: readonly string[];
  /** The working directory (the command's own). */
  cwd: string;
  /** SIDs the write check is allowed to pass, besides the logon SID. */
  restricting: readonly string[];
  /** Environment entries to set (or, with `undefined`, delete) for the duration of the spawn. */
  env?: Readonly<Record<string, string | undefined>>;
}

/** `Everyone` — see the note at the top of this file. */
export const EVERYONE = "S-1-1-0";

/** The process's own primary token, opened for duplication. */
function primaryToken(): Ptr {
  const c = win32();
  const token: Ptr[] = [0n];
  if (!c.OpenProcessToken(c.GetCurrentProcess(), TOKEN_ALL_NEEDED, token)) {
    throw new Win32Error("OpenProcessToken", c.GetLastError());
  }
  return token[0]!;
}

/** The session's logon SID, and the allocation its pointer lives in. */
interface LogonSid {
  /** The SID itself; valid while `keep` is alive. */
  sid: Ptr;
  /** The TOKEN_GROUPS buffer holding that SID. Release it when the SID is no longer needed. */
  keep: NativeBytes;
}

/**
 * The session's logon SID, read out of the token's groups.
 *
 * `GetTokenInformation(TokenLogonSid)` would be the direct route, but the class number moved
 * across SDK versions (27 is `TokenMandatoryPolicy`; `TokenLogonSid` is 28), and a wrong
 * number fails as a size error rather than as a wrong answer. The logon SID is the one group
 * flagged `SE_GROUP_LOGON_ID`, which is stable and needs no constant.
 */
function logonSid(token: Ptr): LogonSid {
  const c = win32();
  const needed: number[] = [0];
  c.GetTokenInformation(token, TOKEN_GROUPS_CLASS, null, 0, needed);
  const length = needed[0]!;
  const memory = nativeBytes(Buffer.alloc(length));
  if (!c.GetTokenInformation(token, TOKEN_GROUPS_CLASS, memory.ptr, length, needed)) {
    throw new Win32Error("GetTokenInformation", c.GetLastError(), "TokenGroups");
  }
  const raw = readBytes(memory.ptr, length);
  const groups = raw.readUInt32LE(0);
  for (let i = 0; i < groups; i += 1) {
    // SID_AND_ATTRIBUTES is 16 bytes on x64: the SID pointer, then its attributes.
    const base = 8 + i * 16;
    const attributes = raw.readUInt32LE(base + 8);
    if ((attributes & SE_GROUP_LOGON_ID) >>> 0 === SE_GROUP_LOGON_ID) {
      return { sid: raw.readBigUInt64LE(base), keep: memory };
    }
  }
  throw new Error("the caller's token carries no logon SID");
}

/** The write-restricted token: the caller's token, with `restricting` as its write allowlist. */
export function restrictedToken(restricting: readonly string[]): Ptr {
  const c = win32();
  const token = primaryToken();
  const converted: Ptr[] = [];
  let logon: LogonSid | null = null;
  try {
    logon = logonSid(token);
    const sids = [logon.sid];
    for (const sid of restricting) {
      const ptr = sidPtr(sid);
      converted.push(ptr);
      sids.push(ptr);
    }
    const list = sids.map((sid) => ({
      Sid: sid,
      // Measured: SE_GROUP_ENABLED here fails CreateRestrictedToken with error 87.
      Attributes: 0,
    }));
    const out: Ptr[] = [0n];
    const ok = c.CreateRestrictedToken(
      token,
      WRITE_RESTRICTED | DISABLE_MAX_PRIVILEGE,
      0,
      0n,
      0,
      0n,
      list.length,
      list,
      out,
    );
    if (!ok) throw new Win32Error("CreateRestrictedToken", c.GetLastError());
    return out[0]!;
  } finally {
    // The TOKEN_GROUPS buffer is freed HERE, after the call that reads the SID pointer out of
    // it. "Still in scope" is not a lifetime: V8 may consider the object dead the moment its
    // last read happens, and the pointer inside it is a bare address into that memory.
    logon?.keep.release();
    for (const ptr of converted) localFree(ptr);
    close(token);
  }
}

/**
 * Quote one argument the way `CommandLineToArgvW` and the C runtime read it back.
 *
 * `CreateProcessAsUserW` takes a command LINE, not an argv. The rules are the documented ones:
 * wrap in quotes when the argument is empty or holds a space or a quote, double the
 * backslashes that precede a quote, and double every backslash that ends the argument.
 */
export function quoteArg(arg: string): string {
  if (arg !== "" && !/[\s"]/.test(arg)) return arg;
  let out = '"';
  let backslashes = 0;
  for (const ch of arg) {
    if (ch === "\\") {
      backslashes += 1;
      continue;
    }
    if (ch === '"') {
      out += "\\".repeat(backslashes * 2 + 1) + '"';
      backslashes = 0;
      continue;
    }
    out += "\\".repeat(backslashes) + ch;
    backslashes = 0;
  }
  return `${out}${"\\".repeat(backslashes * 2)}"`;
}

/** A command line for `argv`. */
export function commandLine(argv: readonly string[]): string {
  return argv.map(quoteArg).join(" ");
}

/** Apply `env` to this process, returning how to undo it. */
function overlay(env: Readonly<Record<string, string | undefined>>): () => void {
  const saved = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(env)) {
    saved.set(key, process.env[key]);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  return () => {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
}

/**
 * Start `argv` under a restricted token and wait for it, returning its exit code.
 *
 * THE PROGRAM IS RESOLVED HERE, not by Windows. `CreateProcessAsUserW` with a NULL
 * `lpApplicationName` searches the current directory before `PATH` — and the current directory
 * of a confined command is the Workspace, the one place the Agent can write. A bare `git` would
 * then run `.\git.exe` if the Agent had planted one. `resolveProgram` searches the way Windows
 * does without that directory and the absolute path goes in as `lpApplicationName`; a name that
 * carries a path (`build\app.exe`) is still the caller naming a file and is used as given.
 *
 * THE CHILD STARTS SUSPENDED, and only runs once it is in its job. Assigning after the fact
 * leaves a window in which the child can spawn a grandchild that the job never sees, and
 * `KILL_ON_JOB_CLOSE` would then miss it when a cancelled command is supposed to take its whole
 * tree down. Both the assignment and the job's limit are checked: a job this process cannot
 * join (a host that already put the runner in a non-breakaway job) is a refusal, not a silent
 * "the child may outlive us".
 *
 * The child's stdio is the runner's own: Node marks its std handles non-inheritable at
 * startup, so they are made inheritable again here and handed over through `STARTUPINFO`.
 */
export function spawnRestricted(request: SpawnRequest): number {
  const c = win32();
  const program = resolveProgram(request.argv[0] ?? "", { cwd: request.cwd });
  const restore = overlay(request.env ?? {});
  const token = restrictedToken(request.restricting);
  let job: Ptr = 0n;
  try {
    for (const which of STD_HANDLES) {
      c.SetHandleInformation(c.GetStdHandle(which), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    }
    const startup = Buffer.alloc(c.koffi.sizeof("PENGUIN_STARTUPINFOW"));
    const view = c.koffi.decode(startup, "PENGUIN_STARTUPINFOW");
    view.cb = startup.length;
    view.dwFlags = STARTF_USESTDHANDLES;
    view.hStdInput = c.GetStdHandle(STD_HANDLES[0]);
    view.hStdOutput = c.GetStdHandle(STD_HANDLES[1]);
    view.hStdError = c.GetStdHandle(STD_HANDLES[2]);
    c.koffi.encode(startup, "PENGUIN_STARTUPINFOW", view);

    const info = Buffer.alloc(c.koffi.sizeof("PENGUIN_PROCESS_INFORMATION"));
    const started = c.CreateProcessAsUserW(
      token,
      program,
      commandLine(request.argv),
      0n,
      0n,
      1, // bInheritHandles: the std handles above
      CREATE_SUSPENDED, // no CREATE_NO_WINDOW: under a restricted token that dies in DLL init
      0n, // lpEnvironment: inherit the runner's block (already carrying `env`)
      request.cwd,
      startup,
      info,
    );
    if (!started) {
      throw new Win32Error("CreateProcessAsUserW", c.GetLastError(), program);
    }
    const child = c.koffi.decode(info, "PENGUIN_PROCESS_INFORMATION");
    try {
      job = c.CreateJobObjectW(0n, 0n);
      if (isNull(job)) throw new Win32Error("CreateJobObjectW", c.GetLastError());
      const limits = Buffer.alloc(c.koffi.sizeof("PENGUIN_JOBOBJECT_EXTENDED_LIMIT_INFORMATION"));
      const values = c.koffi.decode(limits, "PENGUIN_JOBOBJECT_EXTENDED_LIMIT_INFORMATION");
      values.BasicLimitInformation.LimitFlags = KILL_ON_JOB_CLOSE;
      c.koffi.encode(limits, "PENGUIN_JOBOBJECT_EXTENDED_LIMIT_INFORMATION", values);
      if (!c.SetInformationJobObject(job, JOB_EXTENDED_LIMIT_CLASS, limits, limits.length)) {
        throw new Win32Error("SetInformationJobObject", c.GetLastError());
      }
      if (!c.AssignProcessToJobObject(job, child.hProcess)) {
        throw new Win32Error("AssignProcessToJobObject", c.GetLastError(), program);
      }
      if (c.ResumeThread(child.hThread) === 0xffffffff) {
        throw new Win32Error("ResumeThread", c.GetLastError(), program);
      }
      c.WaitForSingleObject(child.hProcess, INFINITE);
      const code: number[] = [0];
      if (!c.GetExitCodeProcess(child.hProcess, code)) {
        throw new Win32Error("GetExitCodeProcess", c.GetLastError());
      }
      return code[0]!;
    } finally {
      close(child.hThread);
      close(child.hProcess);
    }
  } finally {
    if (!isNull(job)) close(job);
    close(token);
    restore();
  }
}

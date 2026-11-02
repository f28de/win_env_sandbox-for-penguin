/**
 * Policy → runner job, and what this backend promises on this machine.
 *
 * Pure on purpose: the mapping from a {@link SandboxPolicy} to the flags the runner reads is
 * the part worth testing without Windows, so it lives here and `src/index.ts` only wraps it in
 * the `ConfinedArgv` the harness expects.
 */
import { fileURLToPath } from "node:url";
import type { SandboxLimit, SandboxPolicy } from "@prismshadow/penguin-core/plugin";
import { tempDirFor } from "./sid.js";
import type { Compatibility } from "./runner.js";

/** The settings group this backend declares, drawn inside the Sandbox card. */
export const WIN_GROUP = "sandbox-win";

/** This backend's own settings, as it reads them from its group. */
export interface WinSettings {
  /**
   * `everyone` keeps `S-1-1-0` in the token's restricting list, which is what lets .NET
   * Framework and MSYS-linked programs start; `strict` drops it, closing every directory that
   * grants Everyone write (`C:\Users\Public` above all) and breaking those programs.
   */
  compatibility: Compatibility;
  /** Where each Workspace's private temp directory lives. */
  tempRoot: string;
}

/**
 * The launcher, beside this package's built modules.
 *
 * `launch.js`, not `runner.js`: the launcher has to be a file whose top level RUNS, so that no
 * bundler can move the call into a shared chunk where it never fires (see `src/launch.ts`).
 */
export function launcherPath(): string {
  return fileURLToPath(new URL("./launch.js", import.meta.url));
}

/** The roots a policy lets a confined command write: the Workspace, its scratchpad, its temp. */
export function writableRoots(policy: SandboxPolicy): string[] {
  if (policy.mode !== "workspace-write") return [];
  return [policy.workspaceRoot, ...(policy.writableRoots ?? [])];
}

/**
 * The flags the runner reads, ending with the `--` that separates them from the command.
 *
 * The temp directory is derived from the Workspace rather than from the Session: a resumed
 * Session computes the same one, and a Workspace's temp litter is then a single directory the
 * card's Remove can delete, instead of one per Session id.
 */
export function runnerFlags(policy: SandboxPolicy, settings: WinSettings): string[] {
  const flags = [
    "--workspace",
    policy.workspaceRoot,
    "--temp",
    tempDirFor(settings.tempRoot, policy.workspaceRoot),
    "--mode",
    policy.mode === "read-only" ? "read-only" : "workspace-write",
    "--compatibility",
    settings.compatibility,
    "--writable-temp",
    policy.writableTemp === false ? "false" : "true",
  ];
  for (const root of writableRoots(policy).slice(1)) flags.push("--grant", root);
  flags.push("--");
  return flags;
}

/**
 * How completely this backend enforces the policy here.
 *
 * `strict` governs writes fully: the write SID is the only write allowlist, and it exists on
 * the Workspace, the scratchpad and the private temp directory. `everyone` does not: the
 * compatibility SID is in the same list, so a directory whose DACL grants Everyone write
 * (`C:\Users\Public`) stays writable. Reported as fact, because a caller that needs an
 * absolute boundary must not be told `full`.
 */
export function enforcementOf(settings: WinSettings): "full" | "partial" {
  return settings.compatibility === "strict" ? "full" : "partial";
}

/** What this backend leaves open, in an administrator's words, for the card to disclose. */
export function limitsOf(settings: WinSettings): SandboxLimit[] {
  const limits: SandboxLimit[] = [
    {
      text: "Reads are not restricted: a confined command reads everything you can read. The token restricts writes only.",
      textZh: "读取不受限制：被隔离的命令能读你能读的一切。该令牌只限制写入。",
    },
    {
      text: "The network is not cut, and paths cannot be masked: this backend declares fs-write and closed-temp only, so the sandbox service never routes a network or mask-paths policy here.",
      textZh:
        "不断网，也不能屏蔽路径：本后端只声明 fs-write 与 closed-temp，因此沙箱服务不会把网络或路径屏蔽策略路由到这里。",
    },
    {
      text: "The compatibility SID is in the token: directories that grant Everyone write stay writable, C:\\Users\\Public above all. Switch the compatibility setting to strict to close them, at the cost of .NET Framework and MSYS-linked programs.",
      textZh:
        "令牌中含有兼容性 SID：授予 Everyone 写权限的目录仍可写，首当其冲是 C:\\Users\\Public。把兼容性设置改为 strict 可关闭它，代价是 .NET Framework 与 MSYS 相关程序无法运行。",
    },
    {
      text: "MSYS-runtime programs (Git for Windows' bash, MinGit's sh, MSYS2) cannot start under the token at all: their runtime aborts with NtSetInformationToken 0xC0000022.",
      textZh:
        "MSYS 运行时程序（Git for Windows 的 bash、MinGit 的 sh、MSYS2）在令牌下完全无法启动：其运行时会以 NtSetInformationToken 0xC0000022 中止。",
    },
  ];
  if (settings.compatibility === "strict") {
    limits.splice(2, 1, {
      text: "Strict compatibility drops Everyone from the token: .NET Framework programs (Windows PowerShell 5.1, MSBuild) and programs that write to NUL (git.exe) fail to start.",
      textZh:
        "严格兼容性从令牌中去掉了 Everyone：.NET Framework 程序（Windows PowerShell 5.1、MSBuild）以及会写 NUL 的程序（git.exe）无法启动。",
    });
  }
  return limits;
}

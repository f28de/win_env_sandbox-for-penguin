/**
 * @penguinharness/sandbox-win — a Windows sandbox backend that confines by TOKEN, so a Win64
 * toolchain builds in the Workspace and writes nowhere else.
 *
 * A PLUGIN PACKAGE, not part of the platform: a Project asks for it on the Plugins page and
 * the harness resolves it from the installation. It compiles against the
 * `@prismshadow/penguin-core/plugin` surface and has no runtime dependency on the harness.
 *
 * WHY THIS EXISTS BESIDE `sandbox-wsl`. On Windows the other confining backends cannot run
 * the thing Windows development is made of. `sandbox-wsl` runs commands in a Linux distro,
 * where `cl.exe`, `msbuild`, `link.exe` and every Win64 SDK path mean nothing. `sandbox-dsh`
 * adapts DSH's ACL runner, which confines file writes only and refuses MSYS shells. This
 * backend is Windows-native and declares what it can actually do — `fs-write` and
 * `closed-temp` — so the sandbox service routes a network or mask-paths policy to a backend
 * that implements it instead of silently dropping the dimension here.
 *
 * HOW IT CONFINES. The command's token is the caller's token duplicated into a
 * `WRITE_RESTRICTED` token: reads stay as they were, and every write is checked a second time
 * against a restricting SID list holding a capability SID that grants nothing anywhere except
 * the ACEs this backend writes on the Workspace, the Session's scratchpad and a private temp
 * directory. `read-only` simply leaves that SID out of the list, which is also why a standing
 * Workspace ACE from an earlier `workspace-write` run is inert rather than a hole.
 *
 * WHAT IT COSTS. A capability ACE has to be written before the first confined command on a
 * Workspace, and writing it propagates across the whole tree once (the runner does it, so the
 * server's event loop is not the one blocking). The token restricts writes only: reads, the
 * network and process visibility are untouched, and MSYS-runtime programs cannot start at all.
 * The card discloses all of it; `src/profile.ts` holds the exact wording.
 */
import { Bind, Component, Interface, Use } from "@prismshadow/penguin-core/plugin";
import type {
  ConfinedArgv,
  Plugin,
  SandboxPolicy,
  SandboxProvider,
  SandboxProviderSource,
} from "@prismshadow/penguin-core/plugin";
import {
  assertSessionShellConfinable,
  hostSessionShell,
  koffiLoads,
  readState,
  rememberWorkspace,
  stateDir,
  tempRoot,
} from "./host.js";
import { WIN_GROUP, enforcementOf, launcherPath, limitsOf, runnerFlags } from "./profile.js";
import type { WinSettings } from "./profile.js";
import { TASK_TITLES, Tasks, check, initialize, remove } from "./tasks.js";
import type { Bilingual, CheckLine, TaskKind } from "./tasks.js";

export { capabilitySid, canonicalWorkspace, tempDirFor } from "./sid.js";
export { grantWrite, hasWriteGrant, revokeSid } from "./acl.js";
export { EVERYONE, quoteArg, commandLine } from "./token.js";
export { parseJob, restrictingOf, runJob } from "./runner.js";
export {
  WIN_GROUP,
  enforcementOf,
  launcherPath,
  limitsOf,
  runnerFlags,
  writableRoots,
} from "./profile.js";
export { Tasks, check, initialize, remove } from "./tasks.js";
export { stateDir, tempRoot, readState, unstartable, SHELL_FIX } from "./host.js";
export type { WinSettings } from "./profile.js";
export type { CheckLine, Outcome, Report, TaskKind } from "./tasks.js";
export type { RunnerJob, Compatibility } from "./runner.js";

/**
 * The messages a denied write produces on this backend, which a consumer matches to tell a
 * policy denial from a broken command.
 *
 * Kept narrow on purpose: every entry here is a phrase a DENIAL produces, and a phrase that
 * ordinary output does not, because a false positive tells the model the sandbox blocked
 * something it never touched. `cmd.exe` and the Win32 layer say "Access is denied" (localized:
 * 拒绝访问); Node reports `EPERM`/`EACCES`; an MSYS-linked program says "Permission denied"
 * before it aborts.
 */
const DENIAL_SIGNATURES = ["access is denied", "permission denied", "eperm", "eacces", "拒绝访问"];

/** What this backend requires of plugin configuration: to read the group it declares. */
@Interface()
export abstract class WinConfigReader {
  abstract get(name: string): Record<string, unknown>;
}

/** The card's live half, in the consumer's own shape (see the settings page's contract). */
export interface SettingsGroupStatus {
  notices(): Array<{ tone: "attention" | "muted" | "progress"; text: string; textZh?: string }>;
  actions(): Array<{
    id: string;
    title: string;
    titleZh?: string;
    description?: string;
    descriptionZh?: string;
  }>;
  run(action: string): Promise<{
    ok: boolean;
    message: string;
    messageZh?: string;
    settled?: Promise<void>;
  }>;
}

/** Its group's stored document as settings; anything unusable falls back to the default. */
export function winSettingsOf(doc: Record<string, unknown>): WinSettings {
  const compatibility = doc.compatibility === "strict" ? "strict" : "everyone";
  return { compatibility, tempRoot: tempRoot() };
}

/** Test seams: the platform, the launcher, and the node binary the runner is started with. */
export interface WinInternals {
  platform?: NodeJS.Platform;
  node?: string;
  launcher?: string;
}

/**
 * Why the backend cannot serve yet, or `null` when it can.
 *
 * `koffi` is checked first because it is the only prerequisite with no fallback: without it
 * nothing in this package can call Win32 at all. Initialization is checked second — not
 * because the mechanism needs setup, but because an operator who has not seen the check's
 * result does not yet know what this boundary does and does not stop on their machine.
 */
export function unavailable(platform: NodeJS.Platform = process.platform): string | null {
  if (platform !== "win32") return null;
  if (!koffiLoads()) {
    return "the koffi FFI binding does not load: reinstall the plugin (its dependencies carry prebuilt binaries for win32-x64 and win32-arm64)";
  }
  if (readState() === null) {
    return "the backend is not initialized: open Settings → Plugins → Agent Sandbox and use Initialize on the Windows card";
  }
  return null;
}

/**
 * Load the backend: on Windows only (elsewhere it declines — another backend serves), and only
 * once Initialize has run. A task that finishes on this card loads it again, so an operator
 * never restarts the server to switch it on.
 */
export async function loadWinProvider(
  settings: () => WinSettings,
  internals: WinInternals = {},
): Promise<SandboxProvider | null> {
  const platform = internals.platform ?? process.platform;
  if (platform !== "win32") return null;
  const reason = unavailable(platform);
  if (reason !== null) throw new Error(reason);
  assertSessionShellConfinable(await hostSessionShell(), platform);
  return createWinProvider(settings, internals);
}

export function createWinProvider(
  settings: () => WinSettings,
  internals: WinInternals = {},
): SandboxProvider {
  const node = internals.node ?? process.execPath;
  const launcher = internals.launcher ?? launcherPath();
  return {
    dimensions: ["fs-write", "closed-temp"],
    mechanism: "a write-restricted token (CreateRestrictedToken + WRITE_RESTRICTED)",
    get limits() {
      return limitsOf(settings());
    },
    confine(argv: readonly string[], policy: SandboxPolicy): ConfinedArgv {
      if (policy.mode === "danger-full-access") {
        // Unreachable: this backend declares no dimension a full-access policy could require
        // (the service adds `closed-temp` only while confining). Refusing beats running a
        // command with a boundary the caller did not ask for.
        throw new Error("sandbox-win does not run commands with full filesystem access");
      }
      const current = settings();
      rememberWorkspace(policy.workspaceRoot);
      return {
        argv: [node, launcher, ...runnerFlags(policy, current), ...argv],
        // In the desktop app `node` is the app's own binary, which runs a script only with this.
        env: { ELECTRON_RUN_AS_NODE: "1" },
        enforcement: enforcementOf(current),
        denialSignatures: DENIAL_SIGNATURES,
        runnerFailureRules: [{ fatalSignatures: ["penguin-win-run:"] }],
      };
    },
  };
}

const when = (at: number) => new Date(at).toLocaleString();

/** What a finished task is called on the card. */
const DONE: Record<TaskKind, Bilingual> = {
  initialize: { en: "Initialization", zh: "初始化" },
  check: { en: "Check", zh: "检查" },
  remove: { en: "Removal", zh: "移除" },
};

/** The lines the check produced, as notices. */
function checkNotices(lines: readonly CheckLine[]): ReturnType<SettingsGroupStatus["notices"]> {
  return lines.map((line) => {
    const mark = line.ok === true ? "✓" : line.ok === false ? "✗" : "·";
    return {
      tone: line.ok === false ? "attention" : "muted",
      text: `${mark} ${line.name.en}${line.ok === false && line.detail ? ` — ${line.detail}` : ""}`,
      textZh: `${mark} ${line.name.zh}${line.ok === false && line.detail ? `——${line.detail}` : ""}`,
    } as const;
  });
}

/**
 * The card: what this machine is, the button for the next step, and the step a running task is
 * on. Everything it shows is a fact it read — the state file, the last task, the check's own
 * lines — never an assumption about the host.
 */
@Component({
  contributes: {
    "PluginConfigPage.status": [{ id: "sandbox-win.status", group: WIN_GROUP }],
  },
})
export class SandboxWinStatus {
  @Use() private readonly config!: WinConfigReader;
  @Bind("sandbox-win.status") status!: SettingsGroupStatus;

  setup() {
    const config = this.config;
    const settings = () => winSettingsOf(config.get(WIN_GROUP));
    const tasks = new Tasks();
    const windows = process.platform === "win32";
    const koffi = windows && koffiLoads();

    const initialized = () => readState() !== null;

    const bodies: Record<TaskKind, () => Promise<void>> = {
      initialize: () =>
        tasks.start("initialize", async (report) => {
          const outcome = await initialize(settings(), report);
          tasks.lastCheck = { at: Date.now(), lines: outcome.lines };
          return outcome;
        }),
      check: () =>
        tasks.start("check", async (report) => {
          const verdict = await check(settings(), report);
          tasks.lastCheck = { at: Date.now(), lines: verdict.lines };
          return verdict.result;
        }),
      remove: () =>
        tasks.start("remove", async (report) => {
          tasks.lastCheck = null;
          return remove(settings(), report);
        }),
    };

    this.status = {
      notices: () => {
        if (!windows) {
          return [
            {
              tone: "muted",
              text: "This backend confines Windows commands; on this host another backend serves.",
              textZh: "此后端只隔离 Windows 命令；本机由其他后端提供服务。",
            },
          ];
        }
        const out: ReturnType<SettingsGroupStatus["notices"]> = [];
        const running = tasks.running;
        if (running !== null) {
          const title = TASK_TITLES[running.kind];
          const secs = Math.round((Date.now() - running.startedAt) / 1000);
          out.push({
            tone: "progress",
            text: `${title.en} (${secs}s): ${running.step.en}`,
            textZh: `${title.zh}（${secs} 秒）：${running.step.zh}`,
          });
        }
        const last = tasks.last;
        if (last !== null && running === null) {
          out.push({
            tone: last.ok ? "muted" : "attention",
            text: `${DONE[last.kind].en} ${last.ok ? "finished" : "failed"} at ${when(last.at)}: ${last.message.en}`,
            textZh: `${DONE[last.kind].zh}——${last.ok ? "完成" : "失败"}于 ${when(last.at)}：${last.message.zh}`,
          });
        }
        if (!koffi) {
          out.push({
            tone: "attention",
            text: "The koffi FFI binding does not load, so this backend cannot call Win32 at all. Reinstall the plugin: its dependencies carry prebuilt binaries for win32-x64 and win32-arm64.",
            textZh:
              "koffi FFI 绑定无法加载，此后端因此完全无法调用 Win32。请重新安装插件：其依赖自带 win32-x64 与 win32-arm64 的预编译二进制。",
          });
          return out;
        }
        const state = readState();
        if (state === null) {
          out.push({
            tone: "attention",
            text: "Not initialized. Initialize proves the boundary on this machine: it runs real commands under the token and reports what each one could and could not write. No administrator is needed and nothing is downloaded.",
            textZh:
              "尚未初始化。初始化会在这台机器上验证边界：用真实命令在令牌下运行，并报告每条命令能写什么、不能写什么。无需管理员权限，也不下载任何东西。",
          });
          return out;
        }
        out.push({
          tone: "muted",
          text: `Initialized ${when(Date.parse(state.initializedAt))}; ${state.workspaces.length} Workspace${state.workspaces.length === 1 ? "" : "s"} carry a capability ACE; state in ${stateDir()}. Commands run as you, under a write-restricted token.`,
          textZh: `初始化于 ${when(Date.parse(state.initializedAt))}；${state.workspaces.length} 个工作区带有能力 ACE；状态位于 ${stateDir()}。命令以你的身份、在写受限令牌下运行。`,
        });
        if (tasks.lastCheck !== null && running === null) {
          out.push(...checkNotices(tasks.lastCheck.lines));
        }
        return out;
      },
      actions: () => {
        if (!windows || tasks.running !== null || !koffi) return [];
        const actions: ReturnType<SettingsGroupStatus["actions"]> = [];
        if (!initialized()) {
          actions.push({
            id: "initialize",
            title: "Initialize",
            titleZh: "初始化",
            description:
              "Creates the state and temp directories, then runs real confined commands and reports what each one could write. No administrator needed.",
            descriptionZh:
              "创建状态与临时目录，然后用真实的隔离命令验证，并报告每条命令能写什么。无需管理员权限。",
          });
          return actions;
        }
        actions.push({
          id: "check",
          title: "Check confinement",
          titleZh: "检查隔离效果",
          description:
            "Writes inside and outside the Workspace, reads outside it, runs the same command read-only, closes temp, tries to widen the Workspace's own ACL from inside, and starts the programs the compatibility setting decides.",
          descriptionZh:
            "在工作区内与区外写入、读取区外文件、以只读模式运行同一命令、关闭临时目录、在隔离内尝试放宽工作区自身的 ACL，并启动受兼容性设置影响的程序。",
        });
        actions.push({
          id: "initialize",
          title: "Initialize again",
          titleZh: "重新初始化",
          description: "Re-records this machine and re-runs the checks.",
          descriptionZh: "重新记录这台机器并重跑检查。",
        });
        actions.push({
          id: "remove",
          title: "Remove",
          titleZh: "移除",
          description:
            "Revokes the capability ACEs this backend wrote on your Workspaces and deletes its state and temp directories. Your Workspaces themselves are untouched.",
          descriptionZh:
            "撤销本后端在你工作区上写入的能力 ACE，并删除其状态与临时目录。你的工作区本身不受影响。",
        });
        return actions;
      },
      run: async (action) => {
        const start = bodies[action as TaskKind];
        if (start === undefined) {
          return {
            ok: false,
            message: `No action ${action}.`,
            messageZh: `没有 ${action} 操作。`,
          };
        }
        const settled = start();
        const title = TASK_TITLES[action as TaskKind];
        return {
          ok: true,
          message: `${title.en}: its progress shows on the Windows card.`,
          messageZh: `${title.zh}：进度显示在 Windows 卡片上。`,
          settled,
        };
      },
    };
  }
}

@Component({
  contributes: {
    "SandboxModule.providers": [
      {
        id: "sandbox-win.provider",
        name: "penguin-win",
        dimensions: ["fs-write", "closed-temp"],
      },
    ],
    "PluginConfigProvider.groups": [
      {
        id: WIN_GROUP,
        parent: "sandbox",
        title: "Windows",
        properties: {
          compatibility: {
            type: "enum",
            title: "Compatibility",
            titleZh: "兼容性",
            description:
              "Everyone in the token: .NET Framework programs (MSBuild, Windows PowerShell 5.1) and programs that write to NUL (git.exe) start, and directories that grant Everyone write — C:\\Users\\Public above all — stay writable. Strict drops Everyone: those directories close, and those programs fail to start.",
            descriptionZh:
              "令牌中含 Everyone：.NET Framework 程序（MSBuild、Windows PowerShell 5.1）与会写 NUL 的程序（git.exe）可以启动，而授予 Everyone 写权限的目录（首当其冲是 C:\\Users\\Public）仍可写。strict 去掉 Everyone：这些目录关闭，但上述程序无法启动。",
            options: [
              {
                value: "everyone",
                title: "Everyone kept (Win64 toolchains work)",
                titleZh: "保留 Everyone（Win64 工具链可用）",
              },
              {
                value: "strict",
                title: "Strict (nothing Everyone-writable)",
                titleZh: "严格（Everyone 可写目录也关闭）",
              },
            ],
            default: "everyone",
          },
        },
      },
    ],
  },
})
export class SandboxWin {
  @Use() private readonly config!: WinConfigReader;
  @Bind("sandbox-win.provider") provider!: SandboxProviderSource;

  setup() {
    const config = this.config;
    const settings = () => winSettingsOf(config.get(WIN_GROUP));
    // A loader: the service calls it again after this card's task ends or the Sandbox card is
    // saved, so Initialize switches the backend on without a restart.
    this.provider = () => loadWinProvider(settings);
  }
}

const plugin: Plugin = { modules: [SandboxWin, SandboxWinStatus] };
export default plugin;

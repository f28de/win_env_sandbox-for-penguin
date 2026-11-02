/**
 * The card's tasks: prove the boundary on this machine, and take it back out again.
 *
 * Nothing here needs an administrator, and nothing downloads anything: the token is built
 * from the caller's own, the ACEs are written by the owner of the Workspace (whose implicit
 * `WRITE_DAC` is what lets a normal user edit its DACL), and the temp root is a directory
 * under `%LOCALAPPDATA%`. What `Initialize` buys is therefore not setup but PROOF: it runs
 * real confined commands and reports what each one could and could not do, so an operator
 * learns the shape of the boundary before turning the mode on rather than from a failed build.
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { grantWrite, namesSid, revokeSid } from "./acl.js";
import { readState, stateDir, tempRoot, writeState } from "./host.js";
import { launcherPath } from "./profile.js";
import type { WinSettings } from "./profile.js";
import { capabilitySid, tempDirFor } from "./sid.js";

/** A step or a result the card can show in both languages. */
export interface Bilingual {
  en: string;
  zh: string;
}

/** What a task reports while it runs. */
export type Report = (step: Bilingual) => void;

/** What a task ends with. */
export interface Outcome {
  ok: boolean;
  message: Bilingual;
}

/** The tasks this backend's card offers. */
export type TaskKind = "initialize" | "check" | "remove";

/** The card's titles for them. */
export const TASK_TITLES: Record<TaskKind, Bilingual> = {
  initialize: { en: "Initialize", zh: "初始化" },
  check: { en: "Check confinement", zh: "检查隔离效果" },
  remove: { en: "Remove", zh: "移除" },
};

/** One line of the check, as the card lists it. */
export interface CheckLine {
  name: Bilingual;
  ok: boolean | null;
  detail?: string;
}

/** A task in flight: what it is, when it started, and the step it is on. */
export interface RunningTask {
  kind: TaskKind;
  startedAt: number;
  step: Bilingual;
}

/** The card's task bookkeeping: one at a time, the last outcome, the last check's lines. */
export class Tasks {
  running: RunningTask | null = null;
  last: (Outcome & { kind: TaskKind; at: number }) | null = null;
  lastCheck: { at: number; lines: CheckLine[] } | null = null;

  /**
   * Start `body`, showing its steps. Returns at once; the caller awaits `settled`.
   *
   * The body is invoked inside a promise chain rather than called first: a body that throws
   * SYNCHRONOUSLY would otherwise leave `running` set forever, and the card's buttons — which
   * disappear while a task runs — would never come back.
   */
  start(kind: TaskKind, body: (report: Report) => Promise<Outcome>): Promise<void> {
    this.running = { kind, startedAt: Date.now(), step: { en: "Starting", zh: "正在开始" } };
    const report: Report = (step) => {
      if (this.running !== null) this.running.step = step;
    };
    return Promise.resolve()
      .then(() => body(report))
      .then((outcome) => {
        this.last = { ...outcome, kind, at: Date.now() };
      })
      .catch((error: unknown) => {
        const detail = error instanceof Error ? error.message : String(error);
        this.last = { ok: false, kind, at: Date.now(), message: { en: detail, zh: detail } };
      })
      .finally(() => {
        this.running = null;
      });
  }
}

/** One confined command's result, as the check reads it. */
interface Run {
  code: number | null;
  out: string;
  err: string;
}

/** Anything at or above this is an NTSTATUS: the process died before it could exit. */
const NTSTATUS_BASE = 0xc0000000;

/** Run one job through the real launcher, exactly as a confined command would. */
function runConfined(flags: readonly string[], argv: readonly string[], cwd: string): Promise<Run> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [launcherPath(), ...flags, ...argv], {
      cwd,
      env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" },
      windowsHide: true,
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (chunk: Buffer) => (out += chunk.toString("utf8")));
    child.stderr.on("data", (chunk: Buffer) => (err += chunk.toString("utf8")));
    child.on("error", (error) => resolve({ code: null, out, err: String(error) }));
    child.on("close", (code) => resolve({ code, out, err }));
  });
}

/** The `key=value` lines a probe prints, as a map. */
function pairs(out: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const line of out.split(/\r?\n/)) {
    const at = line.indexOf("=");
    if (at > 0) map.set(line.slice(0, at).trim(), line.slice(at + 1).trim());
  }
  return map;
}

/** The probe: a batch file, because `cmd.exe` is the one program every Windows has. */
function probeScript(): string {
  return [
    "@echo off",
    "set ID=%~1",
    'call :write "inside-%ID%.txt" INSIDE',
    'call :write "%~dp0..\\outside-%ID%.txt" OUTSIDE',
    'call :write "%TEMP%\\temp-%ID%.txt" TEMP',
    'if exist "%SystemRoot%\\win.ini" (echo READ=OK) else (echo READ=FAIL)',
    "exit /b 3",
    ":write",
    '> "%~1" echo probe 2>nul',
    'if exist "%~1" (echo %~2=WROTE) else (echo %~2=DENIED)',
    "exit /b 0",
    "",
  ].join("\r\n");
}

/** The programs whose start-up the compatibility setting decides, and how to run them. */
function toolProbes(): Array<{ name: string; file: string; args: string[] }> {
  return [
    { name: "cmd.exe", file: "cmd.exe", args: ["/c", "exit 0"] },
    { name: "git.exe", file: "git.exe", args: ["--version"] },
    { name: "powershell.exe", file: "powershell.exe", args: ["-NoProfile", "-Command", "exit 0"] },
  ];
}

/** Where `file` is on PATH, or `null`. */
function onPath(file: string): string | null {
  const dirs = (process.env.PATH ?? "").split(path.delimiter).filter((d) => d !== "");
  const exts = (process.env.PATHEXT ?? ".EXE;.CMD;.BAT").split(";").filter((e) => e !== "");
  for (const dir of dirs) {
    for (const ext of ["", ...exts]) {
      const candidate = path.join(
        dir,
        file.toLowerCase().endsWith(ext.toLowerCase()) ? file : `${file}${ext}`,
      );
      try {
        if (fs.statSync(candidate).isFile()) return candidate;
      } catch {
        // Not here.
      }
    }
  }
  return null;
}

/** A fresh, empty check directory: the Workspace, its parent, and the probe beside them. */
function prepareCheck(): { root: string; workspace: string } {
  const root = path.join(stateDir(), "check");
  fs.rmSync(root, { recursive: true, force: true });
  const workspace = path.join(root, "ws");
  fs.mkdirSync(workspace, { recursive: true });
  fs.writeFileSync(path.join(workspace, "probe.cmd"), probeScript(), "utf8");
  return { root, workspace };
}

/** The flags for one check run, matching what the provider would build for that policy. */
function checkFlags(
  settings: WinSettings,
  workspace: string,
  mode: "read-only" | "workspace-write",
  writableTemp: boolean,
): string[] {
  return [
    "--workspace",
    workspace,
    "--temp",
    tempDirFor(settings.tempRoot, workspace),
    "--mode",
    mode,
    "--compatibility",
    settings.compatibility,
    "--writable-temp",
    writableTemp ? "true" : "false",
    "--",
  ];
}

/**
 * Run the checks and return their lines.
 *
 * Every line is a real command under a real token — no simulation, no capability probing. The
 * two runs differ only in the mode, which is what makes them evidence: the same probe writes
 * inside the Workspace under `workspace-write` and cannot under `read-only`.
 */
export async function check(
  settings: WinSettings,
  report: Report,
): Promise<{ lines: CheckLine[]; result: Outcome }> {
  const lines: CheckLine[] = [];
  const { root, workspace } = prepareCheck();
  const id = String(Date.now());

  report({ en: "Writing the Workspace's capability ACE", zh: "正在写入工作区的能力 ACE" });
  grantWrite(workspace, capabilitySid("workspace", workspace));

  report({ en: "Running a command under workspace-write", zh: "在 workspace-write 下运行命令" });
  const write = await runConfined(
    checkFlags(settings, workspace, "workspace-write", true),
    ["cmd.exe", "/c", path.join(workspace, "probe.cmd"), id],
    workspace,
  );
  const wrote = pairs(write.out);
  lines.push({
    name: { en: "Write inside the Workspace", zh: "工作区内写入" },
    ok: wrote.get("INSIDE") === "WROTE",
    detail:
      wrote.get("INSIDE") === "WROTE" ? undefined : write.err.trim() || `exit ${write.code ?? "?"}`,
  });
  lines.push({
    name: { en: "Write outside the Workspace is refused", zh: "工作区外写入被拒绝" },
    ok: wrote.get("OUTSIDE") === "DENIED",
    detail:
      wrote.get("OUTSIDE") === "DENIED" ? undefined : `${wrote.get("OUTSIDE") ?? "no answer"}`,
  });
  lines.push({
    name: { en: "Read outside the Workspace still works", zh: "工作区外读取仍可用" },
    ok: wrote.get("READ") === "OK",
  });
  lines.push({
    name: { en: "The command's exit code reaches the caller", zh: "命令的退出码回到调用方" },
    ok: write.code === 3,
    detail: write.code === 3 ? undefined : `exit ${write.code ?? "?"}`,
  });
  lines.push({
    name: { en: "The private temp directory is writable", zh: "私有临时目录可写" },
    ok: wrote.get("TEMP") === "WROTE",
    detail: wrote.get("TEMP") === "WROTE" ? undefined : `${wrote.get("TEMP") ?? "no answer"}`,
  });

  report({
    en: "Trying to widen the Workspace's own security from inside",
    zh: "在隔离内尝试放宽工作区自身的权限",
  });
  // The capability ACE grants writes, NOT the right to edit a DACL. `icacls.exe` is run
  // directly — no shell, so no quoting surprises — and the answer is read off the ACL itself
  // rather than off the exit code: what matters is whether an ACE for `Everyone` appeared.
  await runConfined(
    checkFlags(settings, workspace, "workspace-write", true),
    ["icacls.exe", workspace, "/grant", "*S-1-1-0:(OI)(CI)F"],
    workspace,
  );
  const widened = namesSid(workspace, "S-1-1-0");
  lines.push({
    name: {
      en: "A confined command cannot rewrite the Workspace's ACL",
      zh: "受隔离的命令无法改写工作区 ACL",
    },
    ok: !widened,
    detail: widened ? "a confined icacls widened the Workspace" : undefined,
  });

  report({
    en: "Running the same command under read-only",
    zh: "在 read-only 下运行同一命令",
  });
  const readOnly = await runConfined(
    checkFlags(settings, workspace, "read-only", true),
    ["cmd.exe", "/c", path.join(workspace, "probe.cmd"), `${id}-ro`],
    workspace,
  );
  const ro = pairs(readOnly.out);
  lines.push({
    name: { en: "Read-only refuses the Workspace write", zh: "只读模式拒绝工作区写入" },
    ok: ro.get("INSIDE") === "DENIED",
    detail: ro.get("INSIDE") === "DENIED" ? undefined : `${ro.get("INSIDE") ?? "no answer"}`,
  });
  lines.push({
    name: {
      en: "Read-only still grants the private temp directory",
      zh: "只读模式仍授予私有临时目录",
    },
    ok: ro.get("TEMP") === "WROTE",
  });

  report({ en: "Running the same command with temp closed", zh: "关闭临时目录后再运行同一命令" });
  const closed = await runConfined(
    checkFlags(settings, workspace, "read-only", false),
    ["cmd.exe", "/c", path.join(workspace, "probe.cmd"), `${id}-ct`],
    workspace,
  );
  lines.push({
    name: { en: "A closed temp directory is really closed", zh: "关闭的临时目录确实不可写" },
    ok: pairs(closed.out).get("TEMP") === "DENIED",
    detail:
      pairs(closed.out).get("TEMP") === "DENIED"
        ? undefined
        : `${pairs(closed.out).get("TEMP") ?? "no answer"}`,
  });

  report({
    en: "Starting the programs the compatibility setting decides",
    zh: "启动受兼容性设置影响的程序",
  });
  for (const probe of toolProbes()) {
    const file = onPath(probe.file);
    if (file === null) {
      lines.push({
        name: { en: `${probe.name} starts confined`, zh: `${probe.name} 能在沙箱内启动` },
        ok: null,
        detail: "not on PATH",
      });
      continue;
    }
    const run = await runConfined(
      checkFlags(settings, workspace, "workspace-write", true),
      [file, ...probe.args],
      workspace,
    );
    const started =
      run.code !== null && run.code < NTSTATUS_BASE && !run.err.includes("penguin-win-run:");
    lines.push({
      name: { en: `${probe.name} starts confined`, zh: `${probe.name} 能在沙箱内启动` },
      ok: started,
      detail: started ? undefined : `exit 0x${(run.code ?? 0).toString(16)}`,
    });
  }

  if (settings.compatibility === "strict") {
    report({
      en: "Checking a directory that grants Everyone write",
      zh: "检查授予 Everyone 写权限的目录",
    });
    // No quotes around the path: `cmd /c` mangles a command line that holds quotes inside it,
    // and `%PUBLIC%` expands to a path with none.
    const run = await runConfined(
      checkFlags(settings, workspace, "workspace-write", true),
      [
        "cmd.exe",
        "/c",
        `> %PUBLIC%\\penguin-check-${id}.txt echo probe 2>nul & if exist %PUBLIC%\\penguin-check-${id}.txt (echo OUT=WROTE) else (echo OUT=DENIED)`,
      ],
      workspace,
    );
    lines.push({
      name: { en: "A Everyone-writable directory stays closed", zh: "Everyone 可写目录仍然关闭" },
      ok: pairs(run.out).get("OUT") === "DENIED",
      detail:
        pairs(run.out).get("OUT") === "DENIED"
          ? undefined
          : "it is writable under strict compatibility",
    });
  } else {
    // Not a failure — the default — but the operator should see the trade they are making at
    // the moment they initialize, not only in the settings description.
    lines.push({
      name: {
        en: "Everyone-writable directories stay open (compatibility mode)",
        zh: "Everyone 可写目录保持开放（兼容模式）",
      },
      ok: null,
      detail: "C:\\Users\\Public and the like; set Compatibility to strict to close them",
    });
  }

  fs.rmSync(root, { recursive: true, force: true });
  const failed = lines.filter((line) => line.ok === false);
  return {
    lines,
    result:
      failed.length === 0
        ? {
            ok: true,
            message: {
              en: `Confinement holds on this machine (${settings.compatibility} compatibility).`,
              zh: `这台机器上的隔离成立（${settings.compatibility} 兼容模式）。`,
            },
          }
        : {
            ok: false,
            message: {
              en: `${failed.length} check${failed.length === 1 ? "" : "s"} failed: ${failed.map((l) => l.name.en).join(", ")}.`,
              zh: `${failed.length} 项检查未通过：${failed.map((l) => l.name.zh).join("、")}。`,
            },
          },
  };
}

/** Record this machine as initialized, and prove the boundary right away. */
export async function initialize(
  settings: WinSettings,
  report: Report,
): Promise<Outcome & { lines: CheckLine[] }> {
  report({ en: "Creating the state and temp directories", zh: "正在创建状态与临时目录" });
  fs.mkdirSync(stateDir(), { recursive: true });
  fs.mkdirSync(tempRoot(), { recursive: true });
  const previous = readState();
  writeState({
    version: 1,
    initializedAt: new Date().toISOString(),
    workspaces: previous?.workspaces ?? [],
  });
  const verdict = await check(settings, report);
  return { ...verdict.result, lines: verdict.lines };
}

/**
 * Take the standing ACEs back out and forget this machine.
 *
 * The Workspace ACEs are a cache, not a leak: a read-only token does not carry the write SID,
 * so a standing ACE grants nothing while it stands. They are revoked here anyway, because an
 * operator who removes the backend should not be left with ACL entries naming a SID nothing
 * will ever use again.
 */
export async function remove(settings: WinSettings, report: Report): Promise<Outcome> {
  const state = readState();
  const workspaces = state?.workspaces ?? [];
  let revoked = 0;
  for (const workspace of workspaces) {
    report({
      en: `Revoking the capability ACE on ${workspace}`,
      zh: `正在撤销 ${workspace} 上的能力 ACE`,
    });
    for (const sid of [capabilitySid("workspace", workspace), capabilitySid("temp", workspace)]) {
      try {
        if (revokeSid(workspace, sid) === "revoked") revoked += 1;
      } catch {
        // A Workspace that was moved or deleted has nothing to revoke.
      }
      const temp = tempDirFor(settings.tempRoot, workspace);
      try {
        if (revokeSid(temp, sid) === "revoked") revoked += 1;
      } catch {
        // Same: the temp directory may already be gone.
      }
    }
    try {
      fs.rmSync(tempDirFor(settings.tempRoot, workspace), { recursive: true, force: true });
    } catch {
      // Locked by a process that outlived its command; OS temp hygiene will get it.
    }
  }
  report({ en: "Deleting the state directory", zh: "正在删除状态目录" });
  fs.rmSync(stateDir(), { recursive: true, force: true });
  return {
    ok: true,
    message: {
      en: `Removed: ${revoked} capability ACE${revoked === 1 ? "" : "s"} revoked on ${workspaces.length} Workspace${workspaces.length === 1 ? "" : "s"}. The backend stays off until you initialize again.`,
      zh: `已移除：在 ${workspaces.length} 个工作区上撤销了 ${revoked} 个能力 ACE。重新初始化之前后端保持停用。`,
    },
  };
}

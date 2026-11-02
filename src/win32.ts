/**
 * The Win32 calls this backend is made of, and nothing else.
 *
 * Windows has no `bwrap` and no `sandbox-exec`: the boundary is a TOKEN, so the backend
 * cannot be an argv rewrite over a launcher the system ships — it has to build the token
 * itself. That means calling kernel32/advapi32 directly, which Node cannot do, so this
 * package reaches them through [koffi](https://koffi.dev/), a prebuilt FFI binding with no
 * compiler and no node-gyp at install time. `koffi` is this package's own dependency: the
 * harness does not depend on it, and nothing here runs unless the plugin is installed on
 * Windows.
 *
 * Every call is checked. A POC of this mechanism (huoyaoyuan/windows-acl-restrict-poc) is
 * the reason for that rule: it ignored every return value, and when `CreateRestrictedToken`
 * failed it silently ran the child with the caller's FULL token — fail-open. Here a failed
 * call throws {@link Win32Error}, which carries the API name, the exact code and the system's
 * own text, and the runner turns it into `penguin-win-run:` on stderr and exit 127.
 *
 * Pointers are `uintptr_t` rather than `void *` throughout: koffi refuses to guess a bare
 * `void *` argument ("Cannot pass ambiguous value"), and a pointer we hold as a BigInt is
 * unambiguous. `SID_AND_ATTRIBUTES` is laid out by hand for the same reason it is elsewhere:
 * the struct is 16 bytes on x64 (8 for the pointer, 4 for the attributes, 4 of padding) and a
 * packed 12-byte stride is exactly the kind of silent corruption a struct definition buys.
 */
import { createRequire } from "node:module";

/* eslint-disable @typescript-eslint/no-explicit-any */

/** A Win32 call that failed: which one, with what code, and what Windows says about it. */
export class Win32Error extends Error {
  constructor(
    readonly api: string,
    readonly code: number,
    readonly context = "",
  ) {
    super(
      `${api} failed with ${code}${context === "" ? "" : ` (${context})`}: ${systemText(code)}`,
    );
    this.name = "Win32Error";
  }
}

/** The one `koffi` module this process holds, loaded on first use. */
let ffi: any = null;

/** The resolved call table; built once. */
let calls: Calls | null = null;

/** A function pointer, as koffi hands it back. */
type Fn = (...args: any[]) => any;

interface Calls {
  koffi: any;
  GetCurrentProcess: Fn;
  GetStdHandle: Fn;
  SetHandleInformation: Fn;
  CloseHandle: Fn;
  LocalFree: Fn;
  GetLastError: Fn;
  FormatMessageW: Fn;
  CreateJobObjectW: Fn;
  SetInformationJobObject: Fn;
  AssignProcessToJobObject: Fn;
  WaitForSingleObject: Fn;
  GetExitCodeProcess: Fn;
  ResumeThread: Fn;
  OpenProcessToken: Fn;
  GetTokenInformation: Fn;
  GetLengthSid: Fn;
  CreateRestrictedToken: Fn;
  ConvertStringSidToSidW: Fn;
  CreateProcessAsUserW: Fn;
  GetNamedSecurityInfoW: Fn;
  SetNamedSecurityInfoW: Fn;
  GetSecurityDescriptorControl: Fn;
}

/**
 * Load koffi and bind every call. Throws a plain `Error` (not {@link Win32Error}) when koffi
 * itself is missing — that is an installation problem, not a Win32 one, and the settings card
 * shows the difference.
 */
export function win32(): Calls {
  if (calls !== null) return calls;
  if (process.platform !== "win32") {
    throw new Error("the Windows sandbox backend only runs on Windows");
  }
  const require = createRequire(import.meta.url);
  ffi = require("koffi");
  const koffi = ffi;
  const k32 = koffi.load("kernel32.dll");
  const adv = koffi.load("advapi32.dll");

  // koffi's type registry is per PROCESS, not per module instance: a hot-swapped copy of this
  // package re-runs this function and would hit `Duplicate type name`. The names are prefixed
  // with this package's own, so a duplicate is always the same definition.
  const define = (name: string, spec: Record<string, string>): void => {
    try {
      koffi.struct(name, spec);
    } catch (error) {
      if (!String((error as Error).message).includes("Duplicate type name")) throw error;
    }
  };

  define("PENGUIN_SID_AND_ATTRIBUTES", { Sid: "uintptr_t", Attributes: "uint32" });
  define("PENGUIN_STARTUPINFOW", {
    cb: "uint32",
    lpReserved: "uintptr_t",
    lpDesktop: "uintptr_t",
    lpTitle: "uintptr_t",
    dwX: "uint32",
    dwY: "uint32",
    dwXSize: "uint32",
    dwYSize: "uint32",
    dwXCountChars: "uint32",
    dwYCountChars: "uint32",
    dwFillAttribute: "uint32",
    dwFlags: "uint32",
    wShowWindow: "uint16",
    cbReserved2: "uint16",
    lpReserved2: "uintptr_t",
    hStdInput: "uintptr_t",
    hStdOutput: "uintptr_t",
    hStdError: "uintptr_t",
  });
  define("PENGUIN_PROCESS_INFORMATION", {
    hProcess: "uintptr_t",
    hThread: "uintptr_t",
    dwProcessId: "uint32",
    dwThreadId: "uint32",
  });
  define("PENGUIN_JOBOBJECT_BASIC_LIMIT_INFORMATION", {
    PerProcessUserTimeLimit: "int64",
    PerJobUserTimeLimit: "int64",
    LimitFlags: "uint32",
    MinimumWorkingSetSize: "uintptr_t",
    MaximumWorkingSetSize: "uintptr_t",
    ActiveProcessLimit: "uint32",
    Affinity: "uintptr_t",
    PriorityClass: "uint32",
    SchedulingClass: "uint32",
  });
  define("PENGUIN_IO_COUNTERS", {
    ReadOperationCount: "uint64",
    WriteOperationCount: "uint64",
    OtherOperationCount: "uint64",
    ReadTransferCount: "uint64",
    WriteTransferCount: "uint64",
    OtherTransferCount: "uint64",
  });
  define("PENGUIN_JOBOBJECT_EXTENDED_LIMIT_INFORMATION", {
    BasicLimitInformation: "PENGUIN_JOBOBJECT_BASIC_LIMIT_INFORMATION",
    IoInfo: "PENGUIN_IO_COUNTERS",
    ProcessMemoryLimit: "uintptr_t",
    JobMemoryLimit: "uintptr_t",
    PeakProcessMemoryUsed: "uintptr_t",
    PeakJobMemoryUsed: "uintptr_t",
  });

  calls = {
    koffi,
    GetCurrentProcess: k32.func("uintptr_t __stdcall GetCurrentProcess()"),
    GetStdHandle: k32.func("uintptr_t __stdcall GetStdHandle(int32 nStdHandle)"),
    SetHandleInformation: k32.func(
      "int __stdcall SetHandleInformation(uintptr_t hObject, uint32 dwMask, uint32 dwFlags)",
    ),
    CloseHandle: k32.func("int __stdcall CloseHandle(uintptr_t hObject)"),
    LocalFree: k32.func("uintptr_t __stdcall LocalFree(uintptr_t hMem)"),
    GetLastError: k32.func("uint32 __stdcall GetLastError()"),
    FormatMessageW: k32.func(
      "uint32 __stdcall FormatMessageW(uint32 flags, uintptr_t source, uint32 id, uint32 lang, void *buffer, uint32 size, uintptr_t args)",
    ),
    CreateJobObjectW: k32.func(
      "uintptr_t __stdcall CreateJobObjectW(uintptr_t sa, uintptr_t name)",
    ),
    SetInformationJobObject: k32.func(
      "int __stdcall SetInformationJobObject(uintptr_t job, int32 cls, void *info, uint32 len)",
    ),
    AssignProcessToJobObject: k32.func(
      "int __stdcall AssignProcessToJobObject(uintptr_t job, uintptr_t process)",
    ),
    WaitForSingleObject: k32.func(
      "uint32 __stdcall WaitForSingleObject(uintptr_t handle, uint32 ms)",
    ),
    GetExitCodeProcess: k32.func(
      "int __stdcall GetExitCodeProcess(uintptr_t process, _Out_ uint32 *code)",
    ),
    ResumeThread: k32.func("uint32 __stdcall ResumeThread(uintptr_t thread)"),
    OpenProcessToken: adv.func(
      "int __stdcall OpenProcessToken(uintptr_t process, uint32 access, _Out_ uintptr_t *token)",
    ),
    GetTokenInformation: adv.func(
      "int __stdcall GetTokenInformation(uintptr_t token, int32 cls, void *info, uint32 len, _Out_ uint32 *needed)",
    ),
    GetLengthSid: adv.func("uint32 __stdcall GetLengthSid(uintptr_t sid)"),
    CreateRestrictedToken: adv.func(
      "int __stdcall CreateRestrictedToken(uintptr_t token, uint32 flags, uint32 disableCount, uintptr_t disableSids, uint32 deleteCount, uintptr_t deleteSids, uint32 restrictCount, PENGUIN_SID_AND_ATTRIBUTES *restrictSids, _Out_ uintptr_t *newToken)",
    ),
    ConvertStringSidToSidW: adv.func(
      "int __stdcall ConvertStringSidToSidW(str16 str, _Out_ uintptr_t *sid)",
    ),
    CreateProcessAsUserW: adv.func(
      "int __stdcall CreateProcessAsUserW(uintptr_t token, str16 app, str16 cmdline, uintptr_t pa, uintptr_t ta, int inherit, uint32 flags, uintptr_t env, str16 cwd, void *si, void *pi)",
    ),
    GetNamedSecurityInfoW: adv.func(
      "uint32 __stdcall GetNamedSecurityInfoW(str16 name, int32 type, uint32 info, _Out_ uintptr_t *owner, _Out_ uintptr_t *group, _Out_ uintptr_t *dacl, _Out_ uintptr_t *sacl, _Out_ uintptr_t *sd)",
    ),
    SetNamedSecurityInfoW: adv.func(
      "uint32 __stdcall SetNamedSecurityInfoW(str16 name, int32 type, uint32 info, uintptr_t owner, uintptr_t group, void *dacl, uintptr_t sacl)",
    ),
    GetSecurityDescriptorControl: adv.func(
      "int __stdcall GetSecurityDescriptorControl(uintptr_t sd, _Out_ uint16 *control, _Out_ uint32 *revision)",
    ),
  };
  return calls;
}

/** The system's own text for a Win32 code, or `""` when it has none. */
export function systemText(code: number): string {
  try {
    const c = win32();
    const buffer = Buffer.alloc(1024);
    const written = c.FormatMessageW(
      0x00001000 /* FORMAT_MESSAGE_FROM_SYSTEM */ | 0x00000200 /* FORMAT_MESSAGE_IGNORE_INSERTS */,
      0n,
      code,
      0,
      buffer,
      buffer.length / 2,
      0n,
    );
    if (written === 0) return "";
    return buffer.toString("utf16le", 0, written * 2).trim();
  } catch {
    return "";
  }
}

/** A handle or pointer, as koffi hands it back (a BigInt, or a plain number when small). */
export type Ptr = bigint | number;

/**
 * True when a handle or pointer is NULL.
 *
 * koffi returns a small pointer as a Number and a large one as a BigInt, so `job !== 0n` is
 * TRUE for a failed `CreateJobObjectW` that returned 0 — the comparison this file exists to
 * get right. Both spellings are checked here instead.
 */
export function isNull(ptr: Ptr | null | undefined): boolean {
  return ptr === null || ptr === undefined || ptr === 0 || ptr === 0n;
}

/** The bytes a pointer points at, as a Buffer. */
export function readBytes(ptr: Ptr, length: number): Buffer {
  const koffi = win32().koffi;
  return Buffer.from(koffi.decode(ptr, koffi.array("uint8", length)));
}

/**
 * Native memory holding a copy of `bytes`, alive until it is released.
 *
 * koffi does NOT free an allocation when its handle is collected — measured: 200 000
 * allocations of 1 KB with a forced GC in between grew the process RSS linearly (50 MB → 290 MB)
 * and never came back. There is no finalizer behind `koffi.alloc`; the only way the memory goes
 * back is `koffi.free`, which is what {@link NativeBytes.release} calls.
 *
 * So the lifetime is explicit, and the caller has to say when it is over. That is not a detail:
 * the buffer this holds is the TOKEN_GROUPS whose SID pointer the restricted token is built
 * from, and a buffer freed too early would hand `CreateRestrictedToken` a dangling pointer.
 */
export interface NativeBytes {
  /** The address to hand to a Win32 call. */
  ptr: Ptr;
  /** The allocation itself: keep this reference alive while `ptr` is in use. */
  handle: unknown;
  /** Give the memory back. Safe to call once; a second call does nothing. */
  release(): void;
}

export function nativeBytes(bytes: Buffer): NativeBytes {
  const koffi = win32().koffi;
  const handle = koffi.alloc("uint8", bytes.length);
  koffi.encode(handle, koffi.array("uint8", bytes.length), [...bytes]);
  let released = false;
  return {
    ptr: koffi.address(handle),
    handle,
    release(): void {
      if (released) return;
      released = true;
      koffi.free(handle);
    },
  };
}

/** Free a pointer that Windows allocated for us (`LocalFree`), ignoring NULL. */
export function localFree(ptr: Ptr | null | undefined): void {
  if (isNull(ptr)) return;
  win32().LocalFree(ptr as Ptr);
}

/** Close a handle, ignoring a double close. */
export function close(handle: Ptr): void {
  win32().CloseHandle(handle);
}

// ------------------------------------------------------------------ constants

/**
 * The mask a granted directory carries: everything a build needs to write, and NOT the right
 * to change the directory's own security.
 *
 * `FILE_ALL_ACCESS` (0x1f01ff) was the first version of this constant, and it was wrong: it
 * includes `STANDARD_RIGHTS_REQUIRED`, hence `WRITE_DAC` (0x40000) and `WRITE_OWNER` (0x80000).
 * A confined command holding that ACE could rewrite the Workspace's DACL — measured: it could
 * append `Everyone:FullControl` and the change outlived the command. In `everyone`
 * compatibility mode that is a cross-subject write path, and in any mode it lets a command
 * edit the very allowlist that confines it.
 *
 * So the mask is built from the rights a write allowlist actually needs:
 * `FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA | FILE_WRITE_EA |
 * FILE_EXECUTE | FILE_DELETE_CHILD | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES` (0x1ff, the
 * file-generic bits), plus `DELETE` (0x10000, replacing a file needs it), `READ_CONTROL`
 * (0x20000) and `SYNCHRONIZE` (0x100000) — and minus `WRITE_DAC` and `WRITE_OWNER`.
 */
export const FILE_WRITE_ACCESS = 0x1301ff;
/** `SE_FILE_OBJECT` */
export const SE_FILE_OBJECT = 1;
/** `DACL_SECURITY_INFORMATION` */
export const DACL_SECURITY_INFORMATION = 0x00000004;
/** `UNPROTECTED_DACL_SECURITY_INFORMATION`: the DACL inherits from its parent. */
export const UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000;
/** `PROTECTED_DACL_SECURITY_INFORMATION`: the DACL does not inherit (kept as it was found). */
export const PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
/** `SE_DACL_PROTECTED`: set in a descriptor's control word when its DACL is protected. */
export const SE_DACL_PROTECTED = 0x1000;
/** `OBJECT_INHERIT_ACE` | `CONTAINER_INHERIT_ACE`: files and directories created below inherit it. */
export const INHERIT_ALL = 0x3;
/** `ACCESS_ALLOWED_ACE_TYPE` */
export const ACCESS_ALLOWED = 0;
/** `SE_GROUP_LOGON_ID`: marks the logon SID among a token's groups. */
export const SE_GROUP_LOGON_ID = 0xc0000000;
/** `TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY` */
export const TOKEN_ALL_NEEDED = 0x0002 | 0x0008 | 0x0001;
/** `WRITE_RESTRICTED`: write access is checked against the restricting SIDs as well. */
export const WRITE_RESTRICTED = 0x0008;
/** `DISABLE_MAX_PRIVILEGE`: the token carries no privileges beyond the standard ones. */
export const DISABLE_MAX_PRIVILEGE = 0x0001;
/** `TokenGroups` */
export const TOKEN_GROUPS_CLASS = 2;
/** `HANDLE_FLAG_INHERIT` */
export const HANDLE_FLAG_INHERIT = 0x1;
/** `STARTF_USESTDHANDLES` */
export const STARTF_USESTDHANDLES = 0x100;
/** `STD_INPUT_HANDLE` / `STD_OUTPUT_HANDLE` / `STD_ERROR_HANDLE` */
export const STD_HANDLES = [-10, -11, -12] as const;
/** `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: the child dies with the runner. */
export const KILL_ON_JOB_CLOSE = 0x2000;
/** `JobObjectExtendedLimitInformation` */
export const JOB_EXTENDED_LIMIT_CLASS = 9;
/** `CREATE_SUSPENDED`: start the child stopped, so it can be put in its job before it runs. */
export const CREATE_SUSPENDED = 0x00000004;
/** `INFINITE` */
export const INFINITE = 0xffffffff;

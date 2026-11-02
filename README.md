# @penguinharness/sandbox-win

A Windows sandbox backend for PenguinHarness. Each agent command runs under a **write-restricted
token**: the command is still you — your reads, your environment, your installed toolchain — and
every write it attempts is checked a second time against a capability SID that grants nothing
anywhere except the ACEs this backend writes.

That is what makes it usable for Win64 development: `cl.exe`, `link.exe`, `msbuild`, `cmake`,
`ninja`, `cargo` and `node.exe` are Windows programs, and they start inside this boundary. The
Linux backends cannot run them at all.

| Dimension   | How                                                                                                                                                                                                                                       |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| fs-write    | The Workspace, the policy's `writableRoots` (the Session's scratchpad) and a private temp directory carry an inheritable ACE for the Workspace's capability SID; nothing else does. `read-only` leaves that SID out of the token entirely |
| closed-temp | The private temp directory is granted only when the policy grants temp; `TMP`/`TEMP` point at it, so a closed temp is closed for the command's children too                                                                               |
| network     | **not implemented** — declared absent, so the sandbox service never routes a network policy here                                                                                                                                          |
| mask-paths  | **not implemented** — same; use `sandbox-bwrap`/`sandbox-seatbelt` for that                                                                                                                                                               |

> **What this is, and is not.** It confines WRITES: a build that wanders out of the Workspace is
> refused, and an Agent's stray `rm`/`del` cannot leave the tree. It is not a boundary against
> malicious code. Reads stay open (your `.ssh`, your `.env`, your browser profile), the network is
> not cut, and process visibility is unchanged — so anything determined to exfiltrate can. Pair it
> with a backend that cuts the network when that is the threat you are defending against.

## How it confines

The caller's own token is duplicated into a `WRITE_RESTRICTED` token
(`CreateRestrictedToken`, `DISABLE_MAX_PRIVILEGE`). Windows then performs every write access check
twice: once against the token's normal SIDs — which still answer the _read_ checks, so a confined
command reads everything you can — and once against a restricting SID list. That list is the write
allowlist:

- the **logon SID**, always. Without it a process dies before `main` with `STATUS_DLL_INIT_FAILED`
  (0xC0000142): the loader creates section objects with a DACL the restricted write check refuses.
- the **Workspace's capability SID**, under `workspace-write` only. It is derived from the
  canonical Workspace path (`S-1-4-x-y`, the non-unique authority — no account can hold it, so an
  ACE naming it grants nothing to anyone else), which is why the grant is a cache: every later
  session re-hits the same ACE and skips the write.
- the **temp capability SID**, only when the policy grants temp.
- **`Everyone`**, unless the compatibility setting is `strict`. See below.

The ACE itself is written by the runner before the token is built, so a grant that fails stops the
command instead of running it against a boundary that is not there. `read-only` simply omits the
Workspace SID: the pass-2 check grants only what the list carries, so a standing ACE from an
earlier `workspace-write` run is inert rather than a hole.

The ACE's mask is **`0x1301ff`** — the file-generic bits, `DELETE`, `READ_CONTROL` and
`SYNCHRONIZE` — and deliberately **not** `FILE_ALL_ACCESS`. The wider mask carries `WRITE_DAC` and
`WRITE_OWNER`, which would let a confined command rewrite the very ACL that confines it; measured
before the change, a confined `icacls` could append `Everyone:FullControl` to the Workspace and the
change outlived the command. A grant that finds an ACE for the capability SID carrying any other
mask replaces it, so an install from before that fix heals itself on its next command.

## What it refuses to grant

The policy names the Workspace; this backend refuses to write a capability ACE on a target that
cannot sensibly be one, and it refuses BEFORE any ACE exists — a refused job exits 127 and the
command never starts:

| Target                                                                    | Why                                                                                                                                                                                    |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| a drive root (`D:\`)                                                      | a whole volume                                                                                                                                                                         |
| a system location, or anything inside it — `%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramData` | Windows and every installed program                                                                                                            |
| an ancestor of one (`C:\Users`, `C:\Program`)                             | it would sweep the protected location into the grant, and propagate over every profile on the machine                                                                                  |
| the user profile itself                                                   | measured: the grant had not finished after five minutes, and it would make every file in the home directory writable — credentials and browser profiles included                        |
| a verbatim or device path (`\\?\C:\…`, `\\.\C:\…`)                        | it switches off the name normalization the check depends on, so it cannot be compared against the protected locations                                                                  |

A directory *inside* the profile — the ordinary project case — is granted normally. A
legitimately large Workspace is not refused: it is the user's own choice, and the only cost is a
slow first grant.

**The check compares names, not spellings.** Windows strips trailing dots and spaces from every
component before it looks a DOS path up — `icacls "C:\Windows."` prints the real Windows ACL, and
`GetNamedSecurityInfoW("C:\Windows.")` succeeds — while `path.resolve` and every Node `fs` call
leave the characters in place (Node opens files with `\\?\` verbatim paths, which skip that
cleanup). So each target is reduced to the name Win32 will use, and the filesystem's own answer
(`fs.realpathSync.native`, which expands 8.3 short names and follows junctions) is checked as a
second opinion. The capability SID is hashed from that same canonical form, so one directory has
one identity however it is spelled: `D:\proj` and `D:\proj.` are one grant, not two.

## What a command may run

The program is resolved by the launcher, not by Windows: `CreateProcessAsUserW` with a NULL
`lpApplicationName` searches the current directory first, and a confined command's current
directory is the Workspace — the one place the Agent can write. So

- `cmake`, `git`, `node` and every other bare name are resolved from `PATH` (and `PATHEXT`), plus
  the directory of the running interpreter; the current directory is **not** searched, and a
  program that exists only there is refused by name;
- `build\Release\app.exe` — a name that carries a path — is resolved against the working directory
  and run as given, because a build's own output has to be runnable;
- a shell still searches its own way: `cmd.exe /c git status` lets `cmd` find `git`, current
  directory included. That is the shell's behaviour, confined or not.

## Setup

Everything happens on the Windows card under **Settings → Plugins → Agent Sandbox**:

1. **Initialize** — creates the state and temp directories, then runs real confined commands and
   reports what each one could and could not write. No administrator, nothing downloaded: the token
   is built from your own, and the ACEs are written by the owner of the Workspace (whose implicit
   `WRITE_DAC` is what lets a normal user edit its DACL).
2. **Check confinement** — re-runs the checks any time: writes inside and outside the Workspace,
   reads outside it, the exit code, `read-only`, a closed temp, an attempt to widen the Workspace's
   own ACL from inside, and the programs your compatibility setting decides.
3. **Remove** — revokes the capability ACEs this backend wrote on your Workspaces and deletes its
   state and temp directories. Your Workspaces themselves are untouched.

State lives in `%LOCALAPPDATA%\penguin\sandbox-win` (`state.json`, the temp root, and each
Workspace's private temp directory).

## The compatibility setting

`Everyone` in the restricting list is a real trade, and the card makes you choose:

| Setting              | What starts                                                                 | What stays writable                                                 |
| -------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `everyone` (default) | .NET Framework (`powershell.exe`, MSBuild), `git.exe`, MSYS-free toolchains | Directories that grant Everyone write — `C:\Users\Public` above all |
| `strict`             | Native Win64 programs only                                                  | Only the Workspace, the scratchpad and the private temp directory   |

Measured on Windows 11, same token, same command, only the list differing:

- `powershell.exe -NoProfile -Command exit 0` → exit 0 with `everyone`, `CLR … 0x80070005` with `strict`.
- `git.exe --version` → prints its version with `everyone`, `could not open '/dev/null' … Permission denied` with `strict`.
- Writing `C:\Users\Public\x.txt` → written with `everyone`, `Access is denied` with `strict`.

The default keeps `everyone` because a Win64 toolchain is mostly .NET Framework (MSBuild) and
because `git.exe` is how most projects get their sources. `strict` is the honest answer when the
boundary matters more than the toolchain, and the card reports enforcement as `partial` while
`everyone` is in force — a caller that needs an absolute boundary must not be told `full`.

## Limits

- **Reads, network and process visibility are untouched.** The token restricts writes only. This is
  the shape of the primitive, not a shortcut.
- **MSYS-runtime programs cannot start at all** — Git for Windows' `bash`, MinGit's `sh`, MSYS2.
  The runtime aborts before the shell runs (`cygheap_user::init: NtSetInformationToken
(TokenDefaultDacl), 0xC0000022`, then `couldn't create signal pipe, Win32 error 5`). Because the
  harness's Windows session shell is often one of them, the backend refuses to mount with that
  shell and names the fix: `PENGUIN_SHELL=pwsh` (or `PENGUIN_SHELL=powershell`).
- **`cmd.exe`'s own quoting rules still apply.** A command line is passed to `CreateProcessAsUser`
  exactly as `spawn` would build it; `cmd /c "…"` with quotes inside the command text is the
  usual casualty, confined or not.
- **The first confined write on a Workspace is slow.** Writing an inheritable ACE propagates it
  across the whole tree once; the runner does it (not the server), so nothing else blocks, but a
  very large Workspace pays that cost on the first command and never again.
- **Console isolation is unavailable.** Children share the host console; stdio redirection is
  pipe-based and unaffected.
- **Two grants racing on one directory can lose an update.** Windows offers no transaction for a
  DACL read-modify-write. The writers are this backend's own runners, one per command, and the next
  command's grant repairs what a race dropped.
- **A capability SID identifies a Workspace, not a person.** Two users confining the same path share
  one write SID; the double access check still requires each of them to hold the ACE, so neither
  gains anything the other did not have, and the SID stays derivable instead of stored.

## Building a Win64 app in it

Nothing special is required — the toolchain runs as it does outside, with writes confined to the
Workspace:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64   # or -G Ninja with the MSVC environment
cmake --build build --config Release
build\Release\app.exe
```

Two consequences worth knowing: a build that writes into `%ProgramFiles%`, the registry-mapped
locations or a sibling checkout outside the Workspace will be refused (that is the point), and
`%TEMP%` is the Workspace's private directory rather than yours, so intermediate files do not leak
between Sessions.

## Installing

This package is a member of the PenguinHarness monorepo, not a standalone npm package: its
`devDependencies` use the workspace protocol and its `tsconfig.json` extends the repository's
base, exactly like every other `sandbox-*` backend. `npm install` inside the package directory is
not the path — `pnpm` at the repository root is:

```sh
cp -r <this directory> plugins/sandbox-win      # if it is not already there
pnpm install                                    # links the workspace, installs koffi
pnpm --filter @penguinharness/sandbox-win build # writes dist/ and ifaces.json
```

Then install it from the **Plugins** page, or add `@penguinharness/sandbox-win` to a Project's
plugin list. `ifaces.json` is generated by that build (it is in `files`, and absent before the
first build); `LICENSE` is the repository's root file, as for every sibling plugin.

`pnpm test` inside the package builds the launcher first — it needs nothing from
`@prismshadow/penguin-core`, so it works before the rest of the workspace is built — and then runs
the suites, including the one that executes the built launcher. That test cannot be skipped.

## Requirements

- Windows 10 or later, x64 or arm64.
- [koffi](https://koffi.dev/) — a prebuilt FFI binding, a dependency of this package, no compiler
  and no node-gyp at install time. Without it nothing here can call Win32, and the card says so.
- No administrator, ever.

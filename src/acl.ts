/**
 * Writing and un-writing the one ACE that makes a directory writable for a capability SID.
 *
 * This is DACL surgery by hand, for two reasons. `icacls` cannot do it: the SID is unresolved
 * (`S-1-4-…` names no account), and `icacls <dir> /remove '*S-1-4-…'` fails with
 * `ERROR_NONE_MAPPED` (1332) on this platform — a documented dead end of the POC this
 * backend follows. And the alternative API, `SetEntriesInAclW`, would have to be fed the
 * ACL's entries through `GetExplicitEntriesFromAclW`, which returns nothing useful here
 * (measured: `ERROR_SUCCESS`, zero entries, NULL list, for an ACL holding eight ACEs).
 *
 * So the ACL is read as bytes and rebuilt as bytes: header, then the new ACE, then every ACE
 * that was already there, in order. Prepending is safe because the new ACE is an ALLOW for a
 * SID that appears nowhere else — deny-before-allow ordering is not disturbed — and because
 * the exact-ACE check makes a repeat grant a no-op that never touches the object again
 * (re-applying an inheritable ACE eagerly re-propagates it across the whole tree: minutes on
 * a large Workspace).
 *
 * TWO THINGS THIS FILE OWNS, beyond "write one ACE":
 *
 * - The mask is {@link FILE_WRITE_ACCESS}, not `FILE_ALL_ACCESS`. The wider mask carries
 *   `WRITE_DAC`, which would let a confined command edit the Workspace's own security — the
 *   allowlist that confines it — and leave that edit behind after it exits. Measured before
 *   the change: a confined process could append `Everyone:FullControl` to the Workspace.
 * - Every ACE for the capability SID that is not exactly the wanted one is dropped as the new
 *   one is written. That is how an install that granted the old, wider mask heals itself: the
 *   next command on that Workspace replaces the broad ACE instead of adding a second one
 *   beside it.
 *
 * A directory whose DACL is NULL is left alone: a NULL DACL grants everyone everything, so
 * the write-restricted check passes there already and writing an ACE would only add noise.
 *
 * The read-modify-write is not atomic (Windows offers no transaction here), so two grants
 * racing on one directory can lose an update. The writers are this backend's own runners, one
 * per command, and a lost update is repaired by the next command's grant.
 */
import {
  ACCESS_ALLOWED,
  DACL_SECURITY_INFORMATION,
  FILE_WRITE_ACCESS,
  INHERIT_ALL,
  PROTECTED_DACL_SECURITY_INFORMATION,
  SE_DACL_PROTECTED,
  SE_FILE_OBJECT,
  UNPROTECTED_DACL_SECURITY_INFORMATION,
  Win32Error,
  localFree,
  readBytes,
  win32,
} from "./win32.js";
import type { Ptr } from "./win32.js";
import { sidBytes } from "./sid.js";

/** The largest ACL this backend will read: anything bigger is not a directory DACL. */
const MAX_ACL_BYTES = 1 << 20;

/** One ACE, as the bytes it occupies inside the ACL. */
interface Ace {
  /** Offset of the ACE inside {@link Acl.aces}. */
  offset: number;
  /** `AceSize`, in bytes. */
  size: number;
  /** `AceType` — 0 is ACCESS_ALLOWED, 1 is ACCESS_DENIED, 0x10 marks an inherited ACE. */
  type: number;
  /** `AceFlags`. */
  flags: number;
}

/** An ACL read out of a security descriptor: its ACEs, and the allocation to free. */
export interface Acl {
  /** The descriptor `GetNamedSecurityInfoW` allocated; free it with {@link freeAcl}. */
  sd: Ptr;
  /** The DACL, or 0 when the object has none (everything is permitted there). */
  dacl: Ptr;
  /** `AceCount` as the header states it. */
  count: number;
  /** The ACEs, back to back, exactly as they sit in the DACL. */
  aces: Buffer;
  /** True when the DACL does not inherit from its parent (`SE_DACL_PROTECTED`). */
  protected: boolean;
}

/**
 * Read the DACL of `path`. Throws {@link Win32Error} when the object cannot be read.
 *
 * The header is validated before a single byte is trusted: an ACL whose stated size is under
 * the header's own, over {@link MAX_ACL_BYTES}, or too small for the ACE count it claims would
 * otherwise turn a corrupt descriptor into an out-of-bounds read.
 */
export function readAcl(path: string): Acl {
  const c = win32();
  const owner: Ptr[] = [0n];
  const group: Ptr[] = [0n];
  const dacl: Ptr[] = [0n];
  const sacl: Ptr[] = [0n];
  const sd: Ptr[] = [0n];
  const rc = c.GetNamedSecurityInfoW(
    path,
    SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION,
    owner,
    group,
    dacl,
    sacl,
    sd,
  );
  if (rc !== 0) throw new Win32Error("GetNamedSecurityInfoW", rc, path);
  const descriptor = sd[0] ?? 0n;
  const control = Buffer.alloc(2);
  const revision = Buffer.alloc(4);
  const described = c.GetSecurityDescriptorControl(descriptor, control, revision);
  const protectedDacl = described !== 0 && (control.readUInt16LE(0) & SE_DACL_PROTECTED) !== 0;
  const daclPtr = dacl[0] ?? 0n;
  if (daclPtr === 0n) {
    return { sd: descriptor, dacl: 0n, count: 0, aces: Buffer.alloc(0), protected: protectedDacl };
  }
  const header = readBytes(daclPtr, 8);
  const size = header.readUInt16LE(2);
  const count = header.readUInt16LE(4);
  if (size < 8 || size > MAX_ACL_BYTES || count > (size - 8) / 4) {
    localFree(descriptor);
    throw new Error(
      `the DACL of ${path} is malformed (size ${size}, ${count} ACEs): refusing to rewrite it`,
    );
  }
  return {
    sd: descriptor,
    dacl: daclPtr,
    count,
    aces: readBytes(daclPtr, size).subarray(8),
    protected: protectedDacl,
  };
}

/** Free what {@link readAcl} allocated. */
export function freeAcl(acl: Acl): void {
  localFree(acl.sd);
}

/** Walk the ACEs of an ACL, stopping at the first one that does not fit. */
export function* aces(acl: Acl): Generator<Ace> {
  for (let offset = 0; offset + 4 <= acl.aces.length;) {
    const size = acl.aces.readUInt16LE(offset + 2);
    if (size < 8 || offset + size > acl.aces.length) return;
    yield { offset, size, type: acl.aces[offset]!, flags: acl.aces[offset + 1]! };
    offset += size;
  }
}

/** The bytes of an ALLOW ACE granting `mask` on a directory and everything below it. */
export function writeAce(sid: Buffer, mask: number = FILE_WRITE_ACCESS): Buffer {
  const ace = Buffer.alloc(8 + sid.length);
  ace[0] = ACCESS_ALLOWED;
  ace[1] = INHERIT_ALL;
  ace.writeUInt16LE(8 + sid.length, 2);
  ace.writeUInt32LE(mask, 4);
  sid.copy(ace, 8);
  return ace;
}

/** True when the ACE's SID is `sid`. */
function aceIsFor(ace: Buffer, sid: Buffer): boolean {
  return ace.length >= 8 + sid.length && Buffer.compare(ace.subarray(8, 8 + sid.length), sid) === 0;
}

/** True when the ACL already carries exactly this ACE. */
export function carries(acl: Acl, ace: Buffer): boolean {
  for (const one of aces(acl)) {
    if (one.offset + ace.length > acl.aces.length) continue;
    if (Buffer.compare(acl.aces.subarray(one.offset, one.offset + ace.length), ace) === 0)
      return true;
  }
  return false;
}

/**
 * Replace `path`'s DACL with `acl`, keeping the descriptor's inheritance semantics as they
 * were found: a DACL that was protected stays protected, one that inherited keeps inheriting.
 */
function apply(path: string, acl: Buffer, wasProtected: boolean): void {
  const inheritance = wasProtected
    ? PROTECTED_DACL_SECURITY_INFORMATION
    : UNPROTECTED_DACL_SECURITY_INFORMATION;
  const rc = win32().SetNamedSecurityInfoW(
    path,
    SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION | inheritance,
    0n,
    0n,
    acl,
    0n,
  );
  if (rc !== 0) throw new Win32Error("SetNamedSecurityInfoW", rc, path);
}

/** Build an ACL from `body` ACEs, with `head` first when given. */
function rebuild(count: number, body: Buffer, head?: Buffer): Buffer {
  const next = Buffer.alloc(8 + (head?.length ?? 0) + body.length);
  next[0] = 2; // ACL_REVISION
  next.writeUInt16LE(next.length, 2);
  next.writeUInt16LE(count, 4);
  if (head !== undefined) head.copy(next, 8);
  body.copy(next, 8 + (head?.length ?? 0));
  return next;
}

/**
 * Make `path` writable for `sid`, inheriting to everything created below it.
 *
 * `granted` when the DACL was rewritten, `skipped` when the exact ACE already stood with no
 * stale ACE for this SID beside it, and `skipped` too when the object has no DACL at all.
 */
export function grantWrite(path: string, sid: string): "granted" | "skipped" {
  const bytes = sidBytes(sid);
  const want = writeAce(bytes);
  const acl = readAcl(path);
  try {
    if (acl.dacl === 0n) return "skipped";
    let stale = false;
    for (const one of aces(acl)) {
      const slice = acl.aces.subarray(one.offset, one.offset + one.size);
      if (!aceIsFor(slice, bytes)) continue;
      const exact = slice.length === want.length && Buffer.compare(slice, want) === 0;
      if (!exact) stale = true;
    }
    if (!stale && carries(acl, want)) return "skipped";
    const keep: Buffer[] = [];
    for (const one of aces(acl)) {
      const slice = acl.aces.subarray(one.offset, one.offset + one.size);
      // Drop every ACE for this SID: the wanted one is re-added at the front, and anything
      // else for it is a grant from an older mask that must not survive.
      if (aceIsFor(slice, bytes)) continue;
      keep.push(slice);
    }
    apply(path, rebuild(keep.length + 1, Buffer.concat(keep), want), acl.protected);
    return "granted";
  } finally {
    freeAcl(acl);
  }
}

/**
 * Take every ACE granting `sid` anything back out of `path`.
 *
 * `revoked` when something was removed, `absent` when nothing was there — which is the
 * answer for a directory this backend never granted, and the one the Remove action reports.
 */
export function revokeSid(path: string, sid: string): "revoked" | "absent" {
  const want = sidBytes(sid);
  const acl = readAcl(path);
  try {
    if (acl.dacl === 0n) return "absent";
    const keep: Buffer[] = [];
    let removed = 0;
    for (const one of aces(acl)) {
      const slice = acl.aces.subarray(one.offset, one.offset + one.size);
      if (aceIsFor(slice, want) && (one.type === ACCESS_ALLOWED || one.type === 1)) {
        removed += 1;
        continue;
      }
      keep.push(slice);
    }
    if (removed === 0) return "absent";
    apply(path, rebuild(acl.count - removed, Buffer.concat(keep)), acl.protected);
    return "revoked";
  } finally {
    freeAcl(acl);
  }
}

/** True when `path` already grants `sid` write access (used by the card's check). */
export function hasWriteGrant(path: string, sid: string): boolean {
  const ace = writeAce(sidBytes(sid));
  const acl = readAcl(path);
  try {
    return carries(acl, ace);
  } finally {
    freeAcl(acl);
  }
}

/**
 * True when any ACE on `path` names `sid`, whatever mask it carries.
 *
 * The card's check uses this to answer a question the mask cannot: after a confined command
 * TRIES to widen the Workspace's ACL, did an ACE for `Everyone` appear? A grant mask that
 * carried `WRITE_DAC` would let one.
 */
export function namesSid(path: string, sid: string): boolean {
  const bytes = sidBytes(sid);
  const acl = readAcl(path);
  try {
    for (const one of aces(acl)) {
      if (aceIsFor(acl.aces.subarray(one.offset, one.offset + one.size), bytes)) return true;
    }
    return false;
  } finally {
    freeAcl(acl);
  }
}

/**
 * The capability SIDs: the identity a confined command may write AS, derived from the
 * Workspace it is confined to.
 *
 * The mechanism, in one line: the caller's token is duplicated into a `WRITE_RESTRICTED`
 * token, and Windows then checks every write twice — once against the token's normal SIDs
 * and once against the restricting SID list. The normal SIDs let the command READ everything
 * the person can read; the restricting list is the write allowlist, and it holds a SID that
 * grants nothing anywhere on the system except the ACEs this backend wrote.
 *
 * Why authority 4 (`S-1-4-x-y`) and not a machine SID: an ACE needs a SID, and every
 * machine-local SID (`S-1-5-21-…`) already names an account or could. `S-1-4` is the
 * non-unique authority — Windows stores and evaluates such an ACE happily, `icacls` renders
 * it as an unresolved number, and no account can ever log on as it. Two numbers are hashed
 * out of the canonical Workspace path, so the identity is DERIVED rather than stored: every
 * later session, call or restart on the same Workspace computes the same SID, re-hits the
 * standing ACE and skips the write, and there is no state file to go stale or be tampered
 * with.
 *
 * The SID is per Workspace, not per session, which is what makes the grant a cache: the ACE
 * stands after the command ends (it is the thing that makes the next command's grant free),
 * and a later `read-only` run is unaffected by it, because a read-only token's restricting
 * list does not carry the write SID at all — the pass-2 check grants only what the list
 * carries.
 */
import { createHash } from "node:crypto";
import path from "node:path";
import { canonicalWorkspace } from "./paths.js";
import { localFree, readBytes, win32 } from "./win32.js";
import type { Ptr } from "./win32.js";

/** What a capability SID is for: writing the Workspace, or writing the private temp directory. */
export type Capability = "workspace" | "temp";

/**
 * The canonical form of a Workspace path, which is what the SID is hashed from.
 *
 * It lives in `paths.ts` with the rest of the "what does this name mean on Windows" rules,
 * because the SID and the grant guard have to answer that question the same way: `D:\proj` and
 * `D:\proj.` are one directory, so they must be one identity, or the token and the ACE would
 * name different SIDs for one grant.
 */
export { canonicalWorkspace };

/**
 * The capability SID for one Workspace and one purpose, as a SID string.
 *
 * Deterministic and side-effect free: the runner derives it to grant, the card derives it to
 * check and to revoke, and neither stores it.
 */
export function capabilitySid(kind: Capability, workspace: string): string {
  const digest = createHash("sha256")
    .update(`penguin-sandbox-win\u0000${kind}\u0000${canonicalWorkspace(workspace)}`)
    .digest();
  // Two 31-bit halves: SID sub-authorities are 32-bit unsigned, and staying below 2^31 keeps
  // the value the same whether it is read as signed or unsigned anywhere in the chain.
  const first = digest.readUInt32BE(0) & 0x7fffffff;
  const second = digest.readUInt32BE(4) & 0x7fffffff;
  return `S-1-4-${first}-${second}`;
}

/** The private temp directory of a Workspace, under the backend's temp root. */
export function tempDirFor(tempRoot: string, workspace: string): string {
  const digest = createHash("sha256").update(canonicalWorkspace(workspace)).digest("hex");
  return path.join(tempRoot, digest.slice(0, 16));
}

/** A SID string as a pointer Windows owns. The caller must `localFree` it when done. */
export function sidPtr(sid: string): Ptr {
  const out: Ptr[] = [0n];
  if (!win32().ConvertStringSidToSidW(sid, out)) {
    throw new Error(`not a SID: ${sid}`);
  }
  return out[0]!;
}

/** A SID string as its bytes, for comparing against the SID inside an ACE. */
export function sidBytes(sid: string): Buffer {
  const ptr = sidPtr(sid);
  try {
    return readBytes(ptr, win32().GetLengthSid(ptr));
  } finally {
    localFree(ptr);
  }
}

/** True when `sid` parses as a SID. */
export function isSid(sid: string): boolean {
  let ptr: Ptr | null = null;
  try {
    ptr = sidPtr(sid);
    return true;
  } catch {
    return false;
  } finally {
    // The SID `ConvertStringSidToSidW` allocated belongs to us; nobody else frees it.
    if (ptr !== null) localFree(ptr);
  }
}

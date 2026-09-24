import { constants } from 'node:fs';
import { open, unlink } from 'node:fs/promises';
import { dirname, isAbsolute } from 'node:path';
import type { AuditRecord, AuditWriter } from './audit.js';
import { validateAuditEvent } from './audit.js';
import { canonical, frozen, object, id, integer, hash, deny } from './util.js';

export interface FileAuditSink {
  readonly write: AuditWriter;
  readonly close: () => Promise<void>;
}
/** Local, exclusive NEW segment with mode 0600 and an fsync before acknowledging each record.
 * Parent directory and path MUST be administrator-controlled. Refuses overwrite/restart append;
 * retain prior segments and anchor journal checkpoints in independently trusted storage.
 * This is not WORM, a central database, automatic rotation, or an exactly-once provider-send log.
 * Linux-tested. Storage hardware/filesystem must honor fsync for power-loss durability. */
export async function createFileAuditSink(path: string, maxBytes = 64 * 1024 * 1024): Promise<FileAuditSink> {
  if (typeof path !== 'string' || !isAbsolute(path) || path.includes('\0')) deny('AUDIT_PATH_INVALID');
  integer(maxBytes, 1024, 1024 * 1024 * 1024);
  // O_EXCL refuses existing regular files and symlinks. Parent traversal is a deployment trust boundary.
  const fd = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600)
    .catch(() => deny('AUDIT_OPEN_FAILURE'));
  try {
    await fd.sync();
    const directory = await open(dirname(path), constants.O_RDONLY);
    try { await directory.sync(); } finally { await directory.close(); }
  } catch {
    await fd.close().catch(() => {});
    await unlink(path).catch(() => {});
    deny('AUDIT_SYNC_FAILURE');
  }
  let queue: Promise<void> = Promise.resolve();
  let closing = false, failed = false, pending = 0, bytes = 0, sequence = 0;
  let head = '0'.repeat(64), identity = '';
  const write: AuditWriter = input => {
    if (closing || failed || pending >= 64) return Promise.reject(new Error('AUDIT_UNAVAILABLE'));
    let record: AuditRecord, encoded: string;
    try {
      record = object(frozen(input), ['format','tenantId','logId','keyId','sequence','previousHash','event','entryHash','auth']) as unknown as AuditRecord;
      if (record.format !== 'aidr-audit-v1') deny('AUDIT_INVALID');
      id(record.tenantId); id(record.logId); id(record.keyId); integer(record.sequence, 1);
      for (const digest of [record.previousHash, record.entryHash, record.auth]) {
        if (!/^[0-9a-f]{64}$/.test(digest)) deny('AUDIT_INVALID');
      }
      validateAuditEvent(record.event);
      const { entryHash, auth, ...body } = record;
      if (hash(body) !== entryHash) deny('AUDIT_INVALID');
      encoded = canonical(record) + '\n';
    } catch { return Promise.reject(new Error('AUDIT_INVALID')); }
    pending++;
    const task = queue.then(async () => {
      if (failed) deny('AUDIT_UNAVAILABLE');
      const incoming = canonical([record.tenantId, record.logId, record.keyId]);
      if (record.sequence !== sequence + 1 || record.previousHash !== head || identity && identity !== incoming) deny('AUDIT_SEQUENCE_INVALID');
      const size = Buffer.byteLength(encoded);
      if (bytes + size > maxBytes) deny('AUDIT_STORAGE_LIMIT');
      try { await fd.writeFile(encoded, 'utf8'); await fd.sync(); }
      catch { deny('AUDIT_WRITE_FAILURE'); }
      bytes += size; sequence = record.sequence; head = record.entryHash; identity = incoming;
    });
    queue = task.then(() => { pending--; }, () => { pending--; failed = true; });
    return task;
  };
  const close = async (): Promise<void> => {
    if (closing) { await queue; return; }
    closing = true;
    await queue;
    try { await fd.sync(); } finally { await fd.close(); }
  };
  return Object.freeze({ write, close });
}

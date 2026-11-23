#!/usr/bin/env node
/**
 * Zero-dependency offline verifier for Maestro evidence-pack.v1 bundles.
 * Requires Node.js >= 18 (uses only node:crypto, node:fs, node:path, node:url).
 */
import { createHash, createPublicKey, verify } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const GENESIS_HASH = '0'.repeat(64);

function sha256Hex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function canonicalizeJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? JSON.stringify(value) : 'null';
  }
  if (value instanceof Date) {
    return JSON.stringify(value.toISOString());
  }
  if (Array.isArray(value)) {
    const parts = value.map(item => (item === undefined ? 'null' : canonicalizeJson(item)));
    return `[${parts.join(',')}]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const fields = [];
    for (const key of keys) {
      const prop = value[key];
      if (prop === undefined) continue;
      fields.push(`${JSON.stringify(key)}:${canonicalizeJson(prop)}`);
    }
    return `{${fields.join(',')}}`;
  }
  return 'null';
}

function computeAuditEntryHash(entry) {
  const canonicalPayload = canonicalizeJson({
    orgId: entry.orgId,
    seq: entry.seq,
    eventType: entry.eventType,
    category: entry.category,
    actorId: entry.actorId,
    actorClass: entry.actorClass,
    actorRole: entry.actorRole,
    channel: entry.channel,
    targetSubject: entry.targetSubject,
    outcomeId: entry.outcomeId,
    decisionId: entry.decisionId,
    metadata: entry.metadata,
    occurredAt: entry.occurredAt,
  });
  return sha256Hex(`${canonicalPayload}\n${entry.prevHash}`);
}

function verifyAuditChain(auditChain) {
  if (!auditChain || !Array.isArray(auditChain.entries)) {
    return { auditChainOk: false, checked: 0, reason: 'missing_audit_chain' };
  }
  const { entries, entryCount, headHash } = auditChain;
  if (entries.length !== entryCount || entries.length === 0) {
    return { auditChainOk: false, checked: entries.length, reason: 'entry_count_mismatch' };
  }
  const first = entries[0];
  let runningPrevHash = first.seq === 1 ? GENESIS_HASH : first.prevHash;
  const startSeq = first.seq;

  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    if (entry.seq !== startSeq + i) {
      return { auditChainOk: false, checked: i, reason: `sequence_gap_at_${String(entry.seq)}` };
    }
    if (entry.prevHash !== runningPrevHash) {
      return { auditChainOk: false, checked: i, reason: `prev_hash_mismatch_at_${String(entry.seq)}` };
    }
    const expectedEntryHash = computeAuditEntryHash(entry);
    if (entry.entryHash !== expectedEntryHash) {
      return { auditChainOk: false, checked: i, reason: `entry_hash_mismatch_at_${String(entry.seq)}` };
    }
    runningPrevHash = entry.entryHash;
  }

  const last = entries[entries.length - 1];
  if (!last || last.entryHash !== headHash) {
    return { auditChainOk: false, checked: entries.length, reason: 'head_hash_mismatch' };
  }
  return { auditChainOk: true, checked: entries.length, reason: null };
}

function main() {
  const defaultDir = dirname(fileURLToPath(import.meta.url));
  const rawTarget = resolve(process.argv[2] ?? defaultDir);
  const isDir = existsSync(rawTarget) && statSync(rawTarget).isDirectory();
  const packPath = isDir ? join(rawTarget, 'evidence-pack.json') : rawTarget;
  const htmlPath = isDir ? join(rawTarget, 'evidence-pack.html') : join(dirname(rawTarget), 'evidence-pack.html');

  const pack = JSON.parse(readFileSync(packPath, 'utf8'));
  const html = readFileSync(htmlPath, 'utf8');
  const { signature, ...payload } = pack;

  if (!signature || !signature.publicKeyPem || !signature.digestSha256 || !signature.signatureBase64) {
    throw new Error('missing_signature_envelope');
  }

  const computedKeyId = sha256Hex(signature.publicKeyPem.trim()).slice(0, 16);
  const keyMatch = computedKeyId === signature.keyId;

  const canonical = canonicalizeJson(payload);
  const computedDigest = sha256Hex(canonical);
  const digestMatch = computedDigest === signature.digestSha256;

  const publicKey = createPublicKey(signature.publicKeyPem);
  const jsonOk = verify(
    null,
    Buffer.from(canonical, 'utf8'),
    publicKey,
    Buffer.from(signature.signatureBase64, 'base64')
  );

  const computedHtmlSha = sha256Hex(html);
  const htmlShaMatch = Boolean(signature.htmlSha256) && computedHtmlSha === signature.htmlSha256;
  const htmlContainsDigest = html.includes(signature.digestSha256);
  const htmlMsg = `html:${signature.digestSha256}:${computedHtmlSha}`;
  const htmlOk = Boolean(
    signature.htmlSignatureBase64 &&
      htmlContainsDigest &&
      verify(
        null,
        Buffer.from(htmlMsg, 'utf8'),
        publicKey,
        Buffer.from(signature.htmlSignatureBase64, 'base64')
      )
  );

  const chainResult = verifyAuditChain(payload.auditChain);
  const valid = Boolean(
    keyMatch &&
      digestMatch &&
      jsonOk &&
      htmlShaMatch &&
      htmlOk &&
      chainResult.auditChainOk
  );

  const output = {
    valid,
    scope: payload.executiveSummary?.scope ?? null,
    verdict: payload.executiveSummary?.verdict ?? null,
    claimBoundary: payload.executiveSummary?.claimBoundary ?? null,
    keyMatch,
    digestMatch,
    htmlShaMatch,
    jsonOk,
    htmlOk,
    auditChainOk: chainResult.auditChainOk,
    auditEntriesChecked: chainResult.checked,
    ...(chainResult.reason ? { chainFailureReason: chainResult.reason } : {}),
  };

  console.log(JSON.stringify(output, null, 2));
  process.exitCode = valid ? 0 : 1;
}

try {
  main();
} catch (error) {
  console.log(
    JSON.stringify(
      {
        valid: false,
        reason: error instanceof Error ? error.message : String(error),
      },
      null,
      2
    )
  );
  process.exitCode = 1;
}

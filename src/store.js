'use strict';
/*
 * Frozen verdict persistence. One JSON file per audit id; a new
 * submission atomically replaces the previous verdict, so stale
 * success evidence from an earlier run can never survive.
 */

const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const AUDIT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

function isValidAuditId(id) {
  return typeof id === 'string' && AUDIT_ID_RE.test(id);
}

function verdictPath(auditId) {
  return path.join(DATA_DIR, `${auditId}.json`);
}

function ensureDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

/** Atomically replace any previous verdict for this audit id. */
function saveVerdict(auditId, verdict) {
  ensureDir();
  const tmp = `${verdictPath(auditId)}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(verdict, null, 2));
  fs.renameSync(tmp, verdictPath(auditId)); // old success evidence cleared here
}

/** Load a frozen verdict, or null if none exists. */
function loadVerdict(auditId) {
  try {
    return JSON.parse(fs.readFileSync(verdictPath(auditId), 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    return null; // corrupt file: treat as missing rather than crashing
  }
}

module.exports = { DATA_DIR, isValidAuditId, saveVerdict, loadVerdict };

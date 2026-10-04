'use strict';
/*
 * Deep-space relay audit service: HTTP API + audit page.
 *
 *   GET  /healthz            health response
 *   GET  /                   audit page
 *   POST /api/audits         run an audit, freeze and return the verdict
 *   GET  /api/audits/:id     reopen a frozen verdict
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { runAudit } = require('./dtls13');
const store = require('./store');

const PORT = parseInt(process.env.PORT || '8080', 10);
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const MAX_BODY = 2 * 1024 * 1024;
const MAX_RECORDS = 48;
const MAX_RECORD_BYTES = 16640; // 2^14 ciphertext + header slack

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
};

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function decodeBase64Strict(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length % 4 !== 0) return null;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const buf = Buffer.from(s, 'base64');
  if (buf.length === 0 || buf.toString('base64') !== s) return null;
  return buf;
}

/** Validate a submission; returns {error} or the parsed audit request. */
function validateSubmission(body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { error: 'JSON object expected' };
  }
  const { audit_id, initial_epoch, traffic_secret, records } = body;

  if (!store.isValidAuditId(audit_id)) {
    return { error: 'audit_id must match ^[A-Za-z0-9_-]{1,64}$' };
  }
  if (!Number.isInteger(initial_epoch) || initial_epoch < 0 || initial_epoch > 0xffff) {
    return { error: 'initial_epoch must be an integer in [0, 65535]' };
  }
  if (typeof traffic_secret !== 'string' || !/^[0-9a-fA-F]{64}$/.test(traffic_secret)) {
    return { error: 'traffic_secret must be exactly 32 bytes as 64 hex characters' };
  }
  if (!Array.isArray(records) || records.length === 0 || records.length > MAX_RECORDS) {
    return { error: `records must contain between 1 and ${MAX_RECORDS} base64 entries` };
  }
  const decoded = [];
  for (let i = 0; i < records.length; i++) {
    const buf = decodeBase64Strict(records[i]);
    if (buf === null) return { error: `records[${i}] is not valid strict base64` };
    if (buf.length > MAX_RECORD_BYTES) {
      return { error: `records[${i}] exceeds ${MAX_RECORD_BYTES} decoded bytes` };
    }
    decoded.push(buf);
  }
  return {
    auditId: audit_id,
    initialEpoch: initial_epoch,
    trafficSecret: Buffer.from(traffic_secret, 'hex'),
    records: decoded,
  };
}

function serveStatic(res, filePath) {
  const full = path.join(PUBLIC_DIR, filePath);
  if (!full.startsWith(PUBLIC_DIR)) {
    res.writeHead(403).end();
    return;
  }
  fs.readFile(full, (err, data) => {
    if (err) {
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }).end('not found');
      return;
    }
    res.writeHead(200, { 'content-type': MIME[path.extname(full)] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const { pathname } = url;

    if (req.method === 'GET' && pathname === '/healthz') {
      return sendJson(res, 200, { ok: true, service: 'dtls13-relay-audit' });
    }

    if (req.method === 'GET' && pathname === '/') {
      return serveStatic(res, 'index.html');
    }

    if (req.method === 'GET' && pathname.startsWith('/api/audits/')) {
      const auditId = decodeURIComponent(pathname.slice('/api/audits/'.length));
      if (!store.isValidAuditId(auditId)) {
        return sendJson(res, 400, { error: 'invalid audit id' });
      }
      const verdict = store.loadVerdict(auditId);
      if (verdict === null) {
        return sendJson(res, 404, { error: 'no frozen verdict for this audit id' });
      }
      return sendJson(res, 200, verdict);
    }

    if (req.method === 'POST' && pathname === '/api/audits') {
      const raw = await readBody(req);
      let body;
      try {
        body = JSON.parse(raw.toString('utf8'));
      } catch {
        return sendJson(res, 400, { error: 'request body must be JSON' });
      }
      const parsed = validateSubmission(body);
      if (parsed.error) {
        return sendJson(res, 400, { error: parsed.error });
      }
      const verdict = runAudit({
        initialEpoch: parsed.initialEpoch,
        trafficSecret: parsed.trafficSecret,
        records: parsed.records,
      });
      const frozen = {
        audit_id: parsed.auditId,
        created_at: new Date().toISOString(),
        ...verdict,
      };
      store.saveVerdict(parsed.auditId, frozen); // replaces any old success evidence
      return sendJson(res, 200, frozen);
    }

    if (req.method === 'GET' && (pathname === '/app.js' || pathname === '/style.css')) {
      return serveStatic(res, pathname.slice(1));
    }

    sendJson(res, 404, { error: 'not found' });
  } catch (err) {
    sendJson(res, 500, { error: 'internal error' });
  }
});

server.listen(PORT, () => {
  console.log(`dtls13-relay-audit listening on port ${PORT}`);
});

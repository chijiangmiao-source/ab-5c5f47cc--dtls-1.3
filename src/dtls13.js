'use strict';
/*
 * DTLS 1.3 (RFC 9147) record-layer audit engine.
 *
 * Scope (per audit requirements):
 *   - unified header without CID only
 *   - TLS_AES_128_GCM_SHA256 only
 *   - a single direction, keyed by one 32-byte traffic secret
 *
 * The engine recovers the 48-bit sequence number from the raw header,
 * derives record key/IV with the "dtls13 " HKDF labels, and only after
 * AEAD authentication succeeds unwraps the inner content type. Receive
 * state is the per-epoch highest sequence number plus a 64-bit bitmap.
 * A KeyUpdate is honoured only after authentication and replay
 * adjudication pass; failed, duplicate or old-epoch records never
 * advance secrets or windows.
 */

const crypto = require('crypto');

const AEAD_KEY_LEN = 16; // AES-128-GCM
const AEAD_IV_LEN = 12;
const AEAD_TAG_LEN = 16;
const HASH_LEN = 32; // SHA-256
const MAX_EPOCH = 0xffff; // 16-bit epoch space
const MAX_SEQ = (1n << 48n) - 1n; // 48-bit record sequence space
const WINDOW_BITS = 64n;
const WINDOW_MASK = (1n << WINDOW_BITS) - 1n;

const CONTENT_TYPES = {
  20: 'change_cipher_spec',
  21: 'alert',
  22: 'handshake',
  23: 'application_data',
  24: 'heartbeat',
  26: 'ack',
};

const HANDSHAKE_TYPE_KEY_UPDATE = 24;

/* ------------------------------------------------------------------ */
/* Violations                                                          */
/* ------------------------------------------------------------------ */

class AuditViolation extends Error {
  /**
   * @param {string} kind   truncation | length | auth | state | header | content
   * @param {number} offset raw byte offset inside the record where the
   *                        violation was detected
   * @param {string} detail human readable explanation
   */
  constructor(kind, offset, detail) {
    super(detail);
    this.kind = kind;
    this.offset = offset;
    this.detail = detail;
  }
  toJSON() {
    return { kind: this.kind, offset: this.offset, detail: this.detail };
  }
}

/* ------------------------------------------------------------------ */
/* Key schedule: HKDF-Expand-Label with the "dtls13 " prefix           */
/* ------------------------------------------------------------------ */

function hkdfExpand(prk, info, length) {
  const out = [];
  let t = Buffer.alloc(0);
  for (let i = 1; out.length === 0 || Buffer.concat(out).length < length; i++) {
    t = crypto
      .createHmac('sha256', prk)
      .update(Buffer.concat([t, info, Buffer.from([i])]))
      .digest();
    out.push(t);
  }
  return Buffer.concat(out).subarray(0, length);
}

function hkdfExpandLabel(secret, label, context, length) {
  const fullLabel = Buffer.concat([Buffer.from('dtls13 ', 'utf8'), Buffer.from(label, 'utf8')]);
  if (fullLabel.length < 7 || fullLabel.length > 255) {
    throw new Error('invalid HKDF label length');
  }
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16BE(length, 0);
  const hkdfLabel = Buffer.concat([
    lenBuf,
    Buffer.from([fullLabel.length]),
    fullLabel,
    Buffer.from([context.length]),
    context,
  ]);
  return hkdfExpand(secret, hkdfLabel, length);
}

function deriveRecordKeys(trafficSecret) {
  return {
    key: hkdfExpandLabel(trafficSecret, 'key', Buffer.alloc(0), AEAD_KEY_LEN),
    iv: hkdfExpandLabel(trafficSecret, 'iv', Buffer.alloc(0), AEAD_IV_LEN),
  };
}

function nextTrafficSecret(trafficSecret) {
  return hkdfExpandLabel(trafficSecret, 'traffic upd', Buffer.alloc(0), HASH_LEN);
}

/* ------------------------------------------------------------------ */
/* AEAD (AES-128-GCM)                                                  */
/* ------------------------------------------------------------------ */

function computeNonce(iv, seq) {
  const nonce = Buffer.from(iv);
  let s = BigInt(seq);
  for (let i = 11; i >= 4; i--) {
    nonce[i] ^= Number(s & 0xffn);
    s >>= 8n;
  }
  return nonce;
}

function aeadDecrypt(key, nonce, aad, ciphertext) {
  if (ciphertext.length < AEAD_TAG_LEN) return null;
  const tag = ciphertext.subarray(ciphertext.length - AEAD_TAG_LEN);
  const body = ciphertext.subarray(0, ciphertext.length - AEAD_TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-128-gcm', key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    return null; // authentication failed
  }
}

/* ------------------------------------------------------------------ */
/* Unified header (no CID)                                             */
/* ------------------------------------------------------------------ */

/**
 * Parse a DTLS 1.3 unified header. Returns header fields plus the raw
 * header bytes (used as AEAD AAD) and ciphertext boundaries.
 * Throws AuditViolation on truncation / length / header problems.
 */
function parseUnifiedHeader(buf) {
  if (buf.length < 1) {
    throw new AuditViolation('truncation', 0, 'empty record: unified header byte missing');
  }
  const b0 = buf[0];
  if ((b0 & 0xe0) !== 0x20) {
    throw new AuditViolation('header', 0, 'fixed bits 001 not set: not a DTLS 1.3 unified header');
  }
  if (b0 & 0x10) {
    throw new AuditViolation('header', 0, 'CID bit set: connection IDs are out of audit scope');
  }
  const seqBytes = b0 & 0x08 ? 2 : 1;
  const hasLength = (b0 & 0x04) !== 0;
  const epochBits = b0 & 0x03;

  let off = 1;
  if (buf.length < off + seqBytes) {
    throw new AuditViolation(
      'truncation',
      buf.length,
      `sequence number field truncated: need ${seqBytes} byte(s), have ${buf.length - off}`
    );
  }
  const seqLow = buf.readUIntBE(off, seqBytes);
  off += seqBytes;

  let declaredLen = null;
  if (hasLength) {
    if (buf.length < off + 2) {
      throw new AuditViolation('truncation', buf.length, 'length field truncated');
    }
    declaredLen = buf.readUInt16BE(off);
    off += 2;
  }

  const headerLen = off;
  const aad = buf.subarray(0, headerLen);
  const available = buf.length - headerLen;
  let ciphertextLen;
  if (declaredLen !== null) {
    if (available < declaredLen) {
      throw new AuditViolation(
        'truncation',
        buf.length,
        `ciphertext truncated: length field declares ${declaredLen} byte(s), only ${available} present`
      );
    }
    if (available > declaredLen) {
      throw new AuditViolation(
        'length',
        headerLen + declaredLen,
        `trailing ${available - declaredLen} byte(s) beyond declared ciphertext length`
      );
    }
    ciphertextLen = declaredLen;
  } else {
    ciphertextLen = available;
  }
  if (ciphertextLen < AEAD_TAG_LEN + 1) {
    throw new AuditViolation(
      'length',
      headerLen,
      `ciphertext of ${ciphertextLen} byte(s) cannot hold inner content type plus 16-byte GCM tag`
    );
  }

  return {
    epochBits,
    seqBits: seqBytes * 8,
    seqLow,
    hasLength,
    declaredLen,
    headerLen,
    aad,
    ciphertext: buf.subarray(headerLen, headerLen + ciphertextLen),
  };
}

/* ------------------------------------------------------------------ */
/* Sequence number reconstruction (RFC 9147 Section 4.2.2.1)           */
/* ------------------------------------------------------------------ */

/**
 * Reconstruct the full sequence number whose low `tBits` equal `seqLow`,
 * numerically closest to (highest received sequence number + 1).
 */
function reconstructSeq(maxSeq, tBits, seqLow) {
  const mod = 1n << BigInt(tBits);
  const half = mod >> 1n;
  const expected = maxSeq + 1n;
  let d = (BigInt(seqLow) - (expected % mod)) % mod;
  if (d < 0n) d += mod;
  if (d >= half) d -= mod;
  let seq = expected + d;
  if (seq < 0n) seq += mod;
  return seq;
}

/* ------------------------------------------------------------------ */
/* Replay window: highest sequence number + 64-bit bitmap              */
/* ------------------------------------------------------------------ */

class ReplayWindow {
  constructor() {
    this.maxSeq = -1n; // highest authenticated sequence number, -1 = none
    this.bitmap = 0n; // bit i set <=> (maxSeq - i) received, i in [0,64)
  }

  /** Adjudicate without mutating: 'new' | 'duplicate' | 'too_old'. */
  check(seq) {
    if (this.maxSeq < 0n) return 'new';
    if (seq > this.maxSeq) return 'new';
    const diff = this.maxSeq - seq;
    if (diff >= WINDOW_BITS) return 'too_old';
    if (this.bitmap & (1n << diff)) return 'duplicate';
    return 'new';
  }

  /** Mark an authenticated, adjudicated-new sequence number as received. */
  accept(seq) {
    if (this.maxSeq < 0n) {
      this.maxSeq = seq;
      this.bitmap = 1n;
      return;
    }
    if (seq > this.maxSeq) {
      const shift = seq - this.maxSeq;
      this.bitmap = shift >= WINDOW_BITS ? 1n : ((this.bitmap << shift) | 1n) & WINDOW_MASK;
      this.maxSeq = seq;
      return;
    }
    this.bitmap |= 1n << (this.maxSeq - seq);
  }

  snapshot() {
    return {
      max_seq: this.maxSeq < 0n ? null : this.maxSeq.toString(),
      bitmap: '0x' + this.bitmap.toString(16).padStart(16, '0'),
    };
  }
}

/* ------------------------------------------------------------------ */
/* Inner plaintext and handshake content                               */
/* ------------------------------------------------------------------ */

function unwrapInnerContent(plaintext, contentOffset) {
  let i = plaintext.length - 1;
  while (i >= 0 && plaintext[i] === 0) i--;
  if (i < 0) {
    throw new AuditViolation('content', contentOffset, 'inner plaintext has no content type byte');
  }
  const contentType = plaintext[i];
  if (!(contentType in CONTENT_TYPES)) {
    throw new AuditViolation('content', contentOffset, `unknown inner content type ${contentType}`);
  }
  return { contentType, content: plaintext.subarray(0, i) };
}

/** Parse unfragmented handshake messages; detect a well-formed KeyUpdate. */
function inspectHandshake(content, contentOffset) {
  const messages = [];
  let off = 0;
  while (off < content.length) {
    if (content.length - off < 12) {
      throw new AuditViolation('content', contentOffset, 'handshake message header truncated');
    }
    const msgType = content[off];
    const length = content.readUIntBE(off + 1, 3);
    const messageSeq = content.readUInt16BE(off + 4);
    const fragmentOffset = content.readUIntBE(off + 6, 3);
    const fragmentLength = content.readUIntBE(off + 9, 3);
    if (fragmentOffset !== 0 || fragmentLength !== length) {
      throw new AuditViolation(
        'content',
        contentOffset,
        'fragmented handshake messages are out of audit scope'
      );
    }
    if (content.length - off - 12 < length) {
      throw new AuditViolation('content', contentOffset, 'handshake message body truncated');
    }
    messages.push({ msgType, messageSeq, body: content.subarray(off + 12, off + 12 + length) });
    off += 12 + length;
  }

  let keyUpdate = false;
  for (const m of messages) {
    if (m.msgType !== HANDSHAKE_TYPE_KEY_UPDATE) continue;
    if (m.body.length !== 1 || m.body[0] > 1) {
      throw new AuditViolation('content', contentOffset, 'malformed KeyUpdate body');
    }
    if (keyUpdate) {
      throw new AuditViolation('content', contentOffset, 'multiple KeyUpdate messages in one record');
    }
    keyUpdate = true;
  }
  return { keyUpdate, messageCount: messages.length };
}

/* ------------------------------------------------------------------ */
/* Audit engine                                                        */
/* ------------------------------------------------------------------ */

/**
 * Replay a capture of DTLS 1.3 records against fresh receive state.
 *
 * @param {object}   opts
 * @param {number}   opts.initialEpoch  receive epoch of the first record
 * @param {Buffer}   opts.trafficSecret 32-byte application traffic secret
 * @param {Buffer[]} opts.records       captured records in capture order
 * @returns verdict object (JSON-serialisable)
 */
function runAudit({ initialEpoch, trafficSecret, records }) {
  let epoch = initialEpoch;
  let secret = Buffer.from(trafficSecret);
  let keys = deriveRecordKeys(secret);
  let window = new ReplayWindow();

  const results = [];
  let firstViolation = null;

  for (let index = 0; index < records.length; index++) {
    const buf = records[index];
    const rec = {
      index,
      record_bytes: buf.length,
      epoch_bits: null,
      epoch: null,
      seq_bits: null,
      sequence_number: null,
      auth: 'not_reached',
      adjudication: null,
      window_before: window.snapshot(),
      window_after: null,
      content_type: null,
      content_type_name: null,
      app_data_sha256: null,
      key_update: false,
      epoch_after: null,
      violation: null,
    };

    try {
      const hdr = parseUnifiedHeader(buf);
      rec.epoch_bits = hdr.epochBits;
      rec.seq_bits = hdr.seqBits;

      // --- state: epoch adjudication (before touching any secret) ---
      if (hdr.epochBits !== (epoch & 3)) {
        const kind = hdr.epochBits === ((epoch - 1) & 3) ? 'old_epoch' : 'unexpected_epoch';
        throw new AuditViolation(
          'state',
          0,
          `${kind}: record epoch bits ${hdr.epochBits}, receive epoch is ${epoch}`
        );
      }
      rec.epoch = epoch;

      // --- sequence number recovery from the raw header ---
      const seq = reconstructSeq(window.maxSeq, hdr.seqBits, hdr.seqLow);
      if (seq > MAX_SEQ) {
        throw new AuditViolation('state', 1, 'reconstructed sequence number exceeds 48-bit space');
      }
      rec.sequence_number = seq.toString();

      // --- AEAD authentication (key/IV derived per DTLS labels) ---
      const nonce = computeNonce(keys.iv, seq);
      const plaintext = aeadDecrypt(keys.key, nonce, hdr.aad, hdr.ciphertext);
      if (plaintext === null) {
        rec.auth = 'failed';
        throw new AuditViolation(
          'auth',
          hdr.headerLen + hdr.ciphertext.length - AEAD_TAG_LEN,
          'AEAD authentication failed (AES-128-GCM tag mismatch)'
        );
      }
      rec.auth = 'ok';

      // --- replay adjudication on the per-epoch window ---
      const adjudication = window.check(seq);
      rec.adjudication = adjudication;
      if (adjudication === 'duplicate') {
        throw new AuditViolation('state', 1, `duplicate record: sequence ${seq} already received`);
      }
      if (adjudication === 'too_old') {
        throw new AuditViolation(
          'state',
          1,
          `sequence ${seq} fell off the 64-bit replay window (max ${window.maxSeq})`
        );
      }

      // --- only now unwrap the inner content type ---
      const { contentType, content } = unwrapInnerContent(plaintext, hdr.headerLen);
      rec.content_type = contentType;
      rec.content_type_name = CONTENT_TYPES[contentType];

      let keyUpdate = false;
      if (contentType === 23) {
        rec.app_data_sha256 = crypto.createHash('sha256').update(content).digest('hex');
      } else if (contentType === 22) {
        keyUpdate = inspectHandshake(content, hdr.headerLen).keyUpdate;
      }

      // --- all checks passed: commit receive state ---
      window.accept(seq);
      rec.window_after = window.snapshot();

      // --- authenticated KeyUpdate: derive next epoch, reset window ---
      if (keyUpdate) {
        if (epoch >= MAX_EPOCH) {
          throw new AuditViolation('state', 0, 'KeyUpdate would overflow the 16-bit epoch space');
        }
        secret = nextTrafficSecret(secret);
        keys = deriveRecordKeys(secret);
        epoch += 1;
        window = new ReplayWindow();
        rec.key_update = true;
        rec.epoch_after = epoch;
      }
    } catch (err) {
      if (!(err instanceof AuditViolation)) throw err;
      rec.violation = err.toJSON();
      rec.window_after = window.snapshot(); // unchanged: violations never advance state
      if (firstViolation === null) {
        firstViolation = { record_index: index, ...rec.violation };
      }
    }

    results.push(rec);
  }

  return {
    status: firstViolation === null ? 'accepted' : 'rejected',
    initial_epoch: initialEpoch,
    final_epoch: epoch,
    records_total: records.length,
    records_accepted: results.filter((r) => r.violation === null).length,
    violation: firstViolation,
    records: results,
  };
}

module.exports = {
  AEAD_KEY_LEN,
  AEAD_IV_LEN,
  AEAD_TAG_LEN,
  MAX_EPOCH,
  MAX_SEQ,
  CONTENT_TYPES,
  AuditViolation,
  ReplayWindow,
  hkdfExpand,
  hkdfExpandLabel,
  deriveRecordKeys,
  nextTrafficSecret,
  computeNonce,
  aeadDecrypt,
  parseUnifiedHeader,
  reconstructSeq,
  unwrapInnerContent,
  inspectHandshake,
  runAudit,
};

'use strict';
/*
 * Test prober: crafts DTLS 1.3 records (and KeyUpdate handshakes) so the
 * review-rule tests and HTTP smoke tests can exercise the audit engine
 * over realistic wire data. Used only by the verify container.
 */

const crypto = require('crypto');
const {
  deriveRecordKeys,
  nextTrafficSecret,
  computeNonce,
} = require('../src/dtls13');

function aeadEncrypt(key, nonce, aad, plaintext) {
  const cipher = crypto.createCipheriv('aes-128-gcm', key, nonce);
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}

/**
 * Build one unified-header (no CID) DTLS 1.3 record.
 *
 * @param {object} o
 * @param {number} o.epoch       full epoch (low 2 bits go on the wire)
 * @param {bigint|number} o.seq  full 48-bit sequence number
 * @param {Buffer} o.trafficSecret 32-byte traffic secret for that epoch
 * @param {number} [o.seqBits]   8 or 16 transmitted sequence bits
 * @param {boolean} [o.withLength] include the 16-bit length field
 * @param {number} [o.contentType] inner content type (default 23)
 * @param {Buffer} [o.content]   inner content (default: 'telemetry')
 * @param {number} [o.padZeros]  trailing zero padding inside the AEAD
 */
function buildRecord(o) {
  const seqBits = o.seqBits ?? 16;
  const withLength = o.withLength ?? true;
  const contentType = o.contentType ?? 23;
  const content = o.content ?? Buffer.from('telemetry');
  const pad = Buffer.alloc(o.padZeros ?? 0);
  const seq = BigInt(o.seq);

  const { key, iv } = deriveRecordKeys(o.trafficSecret);

  const first =
    0x20 | (seqBits === 16 ? 0x08 : 0x00) | (withLength ? 0x04 : 0x00) | (o.epoch & 3);
  const seqLow = Number(seq & (seqBits === 16 ? 0xffffn : 0xffn));
  const seqField = Buffer.alloc(seqBits / 8);
  seqField.writeUIntBE(seqLow, 0, seqBits / 8);

  const inner = Buffer.concat([content, Buffer.from([contentType]), pad]);
  const ciphertextLen = inner.length + 16;

  let header;
  if (withLength) {
    const lenField = Buffer.alloc(2);
    lenField.writeUInt16BE(ciphertextLen, 0);
    header = Buffer.concat([Buffer.from([first]), seqField, lenField]);
  } else {
    header = Buffer.concat([Buffer.from([first]), seqField]);
  }

  const nonce = computeNonce(iv, seq);
  const ciphertext = aeadEncrypt(key, nonce, header, inner);
  return Buffer.concat([header, ciphertext]);
}

/** Build a KeyUpdate handshake message body wrapped as handshake content. */
function buildKeyUpdateContent(requestUpdate = 0, messageSeq = 0) {
  const hs = Buffer.alloc(13);
  hs[0] = 24; // key_update
  hs.writeUIntBE(1, 1, 3); // length
  hs.writeUInt16BE(messageSeq, 4);
  hs.writeUIntBE(0, 6, 3); // fragment_offset
  hs.writeUIntBE(1, 9, 3); // fragment_length
  hs[12] = requestUpdate;
  return hs;
}

function buildKeyUpdateRecord(o) {
  return buildRecord({
    ...o,
    contentType: 22,
    content: buildKeyUpdateContent(o.requestUpdate ?? 0, o.messageSeq ?? 0),
  });
}

/** Flip one bit of a record's final byte (inside the GCM tag). */
function corruptTag(record) {
  const bad = Buffer.from(record);
  bad[bad.length - 1] ^= 0x01;
  return bad;
}

const b64 = (buf) => buf.toString('base64');

module.exports = {
  buildRecord,
  buildKeyUpdateRecord,
  buildKeyUpdateContent,
  corruptTag,
  b64,
  nextTrafficSecret,
};

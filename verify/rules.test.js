'use strict';
/*
 * Review-rule tests for the DTLS 1.3 audit engine:
 * key schedule KATs, AEAD sanity, sequence-number recovery, the 64-bit
 * replay window, KeyUpdate advancement and replay-boundary adjudication.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const {
  ReplayWindow,
  deriveRecordKeys,
  nextTrafficSecret,
  reconstructSeq,
  computeNonce,
  aeadDecrypt,
  runAudit,
} = require('../src/dtls13');
const {
  buildRecord,
  buildKeyUpdateRecord,
  corruptTag,
} = require('./craft');

const SECRET = Buffer.from(Array.from({ length: 32 }, (_, i) => i)); // 0001…1f

/* ---------------- key schedule (vectors computed independently) ----- */

test('dtls13 HKDF labels derive record key/IV (KAT)', () => {
  const { key, iv } = deriveRecordKeys(SECRET);
  assert.equal(key.toString('hex'), '86fdbabe3d8ebcd5980e13209168108d');
  assert.equal(iv.toString('hex'), '7115d9a8935df9e9580a0692');
});

test('traffic upd advances the secret (KAT)', () => {
  const next = nextTrafficSecret(SECRET);
  assert.equal(
    next.toString('hex'),
    '09fd7e4d01cf3e9ac6adeaa908bdc7571f79236d3e91d5ed3b13492f2ed7a577'
  );
  const { key, iv } = deriveRecordKeys(next);
  assert.equal(key.toString('hex'), 'b6f134bf4ed759b12562529b3cfd3c0a');
  assert.equal(iv.toString('hex'), '0c9d073adec4ff0ed7252d32');
});

test('AES-128-GCM matches the NIST zero vector', () => {
  // NIST GCM test vector: key=0, iv=0, pt=0^128
  const key = Buffer.alloc(16);
  const iv = Buffer.alloc(12);
  const ct = Buffer.from('0388dace60b6a392f328c2b971b2fe78', 'hex');
  const tag = Buffer.from('ab6e47d42cec13bdf53a67b21257bddf', 'hex');
  const pt = aeadDecrypt(key, iv, Buffer.alloc(0), Buffer.concat([ct, tag]));
  assert.deepEqual(pt, Buffer.alloc(16));
  assert.equal(aeadDecrypt(key, iv, Buffer.alloc(0), Buffer.concat([ct, corruptTag(tag)])), null);
});

/* ---------------- sequence number reconstruction -------------------- */

test('sequence recovery from raw header low bits', () => {
  assert.equal(reconstructSeq(-1n, 16, 0), 0n);
  assert.equal(reconstructSeq(0n, 16, 1), 1n);
  assert.equal(reconstructSeq(250n, 8, 3), 259n); // next expected
  assert.equal(reconstructSeq(250n, 8, 200), 200n); // recent past, closer below
  assert.equal(reconstructSeq(250n, 8, 100), 356n); // closer above
  assert.equal(reconstructSeq(255n, 8, 0), 256n); // 8-bit wrap forward
  assert.equal(reconstructSeq(256n, 8, 255), 255n); // reordered past record
  assert.equal(reconstructSeq(65535n, 16, 0), 65536n); // 16-bit wrap forward
  assert.equal(reconstructSeq(5n, 8, 250), 250n); // small max, large low bits
});

/* ---------------- replay window -------------------------------------- */

test('64-bit window adjudicates new / duplicate / too_old', () => {
  const w = new ReplayWindow();
  assert.equal(w.check(5n), 'new');
  w.accept(5n);
  assert.equal(w.check(5n), 'duplicate');
  assert.equal(w.check(4n), 'new');
  w.accept(4n);
  assert.equal(w.check(4n), 'duplicate');
  assert.equal(w.snapshot().bitmap, '0x0000000000000003');

  // jump ahead by 65 slots: the whole window slides past, old bits fall off
  w.accept(70n);
  assert.equal(w.snapshot().bitmap, '0x0000000000000001');
  assert.equal(w.check(70n), 'duplicate');
  assert.equal(w.check(6n), 'too_old'); // 70-6 = 64: fell off
  assert.equal(w.check(7n), 'new'); // 70-7 = 63: oldest tracked slot
  w.accept(7n);
  assert.equal(w.check(7n), 'duplicate');
  assert.equal(w.snapshot().max_seq, '70');
  assert.equal(w.snapshot().bitmap, '0x8000000000000001');
});

test('window jumps of >=64 reset the bitmap to the new head', () => {
  const w = new ReplayWindow();
  w.accept(0n);
  w.accept(1000n);
  assert.equal(w.snapshot().bitmap, '0x0000000000000001');
  assert.equal(w.check(999n), 'new');
  assert.equal(w.check(936n), 'too_old');
});

/* ---------------- engine: happy path --------------------------------- */

test('valid capture is accepted with per-record evidence', () => {
  const payloads = [Buffer.from('telemetry-0'), Buffer.from('telemetry-1')];
  const records = payloads.map((p, i) =>
    buildRecord({ epoch: 2, seq: i, trafficSecret: SECRET, content: p })
  );
  const v = runAudit({ initialEpoch: 2, trafficSecret: SECRET, records });
  assert.equal(v.status, 'accepted');
  assert.equal(v.violation, null);
  assert.equal(v.final_epoch, 2);
  assert.equal(v.records.length, 2);
  const r0 = v.records[0];
  assert.equal(r0.epoch, 2);
  assert.equal(r0.sequence_number, '0');
  assert.equal(r0.auth, 'ok');
  assert.equal(r0.adjudication, 'new');
  assert.equal(r0.window_before.max_seq, null);
  assert.equal(r0.window_after.max_seq, '0');
  assert.equal(
    r0.app_data_sha256,
    crypto.createHash('sha256').update(payloads[0]).digest('hex')
  );
  assert.equal(v.records[1].window_after.bitmap, '0x0000000000000003');
});

test('8-bit sequence numbers and no-length records are handled', () => {
  const records = [254, 255, 256, 257].map((s) =>
    buildRecord({ epoch: 0, seq: s, trafficSecret: SECRET, seqBits: 8, withLength: false })
  );
  const v = runAudit({ initialEpoch: 0, trafficSecret: SECRET, records });
  assert.equal(v.status, 'accepted');
  assert.deepEqual(
    v.records.map((r) => r.sequence_number),
    ['254', '255', '256', '257']
  );
});

/* ---------------- engine: replay adjudication ------------------------ */

test('duplicate capture is rejected and never advances the window', () => {
  const rec = buildRecord({ epoch: 0, seq: 5, trafficSecret: SECRET });
  const v = runAudit({ initialEpoch: 0, trafficSecret: SECRET, records: [rec, rec] });
  assert.equal(v.status, 'rejected');
  const dup = v.records[1];
  assert.equal(dup.auth, 'ok'); // authentic, but a replay
  assert.equal(dup.adjudication, 'duplicate');
  assert.equal(dup.violation.kind, 'state');
  assert.equal(dup.violation.offset, 1); // sequence field offset
  assert.deepEqual(dup.window_after, dup.window_before); // no state advance
  assert.equal(v.violation.record_index, 1);
});

test('replay boundary: 64 behind is too_old, 63 behind is new', () => {
  const mk = (s) => buildRecord({ epoch: 0, seq: s, trafficSecret: SECRET });
  const v = runAudit({
    initialEpoch: 0,
    trafficSecret: SECRET,
    records: [mk(100), mk(36), mk(37)],
  });
  assert.equal(v.status, 'rejected');
  assert.equal(v.records[1].adjudication, 'too_old');
  assert.equal(v.records[1].violation.kind, 'state');
  assert.equal(v.records[2].adjudication, 'new');
  assert.equal(v.records[2].violation, null);
  assert.equal(v.records[2].window_after.bitmap, '0x8000000000000001');
});

/* ---------------- engine: KeyUpdate ---------------------------------- */

test('authenticated KeyUpdate derives next epoch and resets the window', () => {
  const next = nextTrafficSecret(SECRET);
  const records = [
    buildRecord({ epoch: 2, seq: 0, trafficSecret: SECRET }),
    buildKeyUpdateRecord({ epoch: 2, seq: 1, trafficSecret: SECRET }),
    buildRecord({ epoch: 3, seq: 0, trafficSecret: next }), // seq reuse is fine post-reset
    buildRecord({ epoch: 3, seq: 1, trafficSecret: next }),
  ];
  const v = runAudit({ initialEpoch: 2, trafficSecret: SECRET, records });
  assert.equal(v.status, 'accepted');
  assert.equal(v.final_epoch, 3);
  const ku = v.records[1];
  assert.equal(ku.key_update, true);
  assert.equal(ku.epoch_after, 3);
  assert.equal(ku.content_type_name, 'handshake');
  const r2 = v.records[2];
  assert.equal(r2.epoch, 3);
  assert.equal(r2.sequence_number, '0');
  assert.equal(r2.adjudication, 'new');
  assert.equal(r2.window_before.max_seq, null); // window was reset
});

test('old-epoch records after KeyUpdate never advance secrets or windows', () => {
  const next = nextTrafficSecret(SECRET);
  const records = [
    buildKeyUpdateRecord({ epoch: 2, seq: 0, trafficSecret: SECRET }),
    buildRecord({ epoch: 3, seq: 0, trafficSecret: next }),
    buildRecord({ epoch: 2, seq: 1, trafficSecret: SECRET }), // stale epoch
  ];
  const v = runAudit({ initialEpoch: 2, trafficSecret: SECRET, records });
  assert.equal(v.status, 'rejected');
  const stale = v.records[2];
  assert.equal(stale.violation.kind, 'state');
  assert.equal(stale.violation.offset, 0); // epoch bits live in header byte 0
  assert.match(stale.violation.detail, /old_epoch/);
  assert.deepEqual(stale.window_after, stale.window_before);
  assert.equal(v.final_epoch, 3);
});

test('forged KeyUpdate fails AEAD and cannot advance secret or epoch', () => {
  const next = nextTrafficSecret(SECRET);
  const forged = corruptTag(buildKeyUpdateRecord({ epoch: 2, seq: 1, trafficSecret: SECRET }));
  const records = [
    buildRecord({ epoch: 2, seq: 0, trafficSecret: SECRET }),
    forged,
    buildRecord({ epoch: 2, seq: 2, trafficSecret: SECRET }), // old keys still valid
    buildRecord({ epoch: 3, seq: 0, trafficSecret: next }), // next epoch not armed
  ];
  const v = runAudit({ initialEpoch: 2, trafficSecret: SECRET, records });
  assert.equal(v.status, 'rejected');
  const f = v.records[1];
  assert.equal(f.auth, 'failed');
  assert.equal(f.violation.kind, 'auth');
  assert.equal(f.violation.offset, forged.length - 16); // GCM tag offset
  assert.equal(v.records[2].violation, null); // secret was not advanced
  assert.equal(v.records[3].violation.kind, 'state'); // epoch was not advanced
  assert.match(v.records[3].violation.detail, /unexpected_epoch/);
  assert.equal(v.final_epoch, 2);
});

test('replayed KeyUpdate is caught in the old epoch and must not re-advance', () => {
  const ku = buildKeyUpdateRecord({ epoch: 2, seq: 0, trafficSecret: SECRET });
  const v = runAudit({ initialEpoch: 2, trafficSecret: SECRET, records: [ku, ku] });
  assert.equal(v.status, 'rejected');
  // the first copy advanced the epoch, so the replayed copy arrives with
  // stale epoch bits and is discarded before it can touch secret or window
  assert.equal(v.records[1].violation.kind, 'state');
  assert.match(v.records[1].violation.detail, /old_epoch/);
  assert.deepEqual(v.records[1].window_after, v.records[1].window_before);
  assert.equal(v.final_epoch, 3); // exactly one advancement, from the first copy
});

/* ---------------- engine: wire-level violations ---------------------- */

test('truncated records report the raw offset of the first missing byte', () => {
  const good = buildRecord({ epoch: 0, seq: 0, trafficSecret: SECRET });
  const cut = good.subarray(0, good.length - 5); // ciphertext short of declared length
  const v = runAudit({ initialEpoch: 0, trafficSecret: SECRET, records: [cut] });
  assert.equal(v.records[0].violation.kind, 'truncation');
  assert.equal(v.records[0].violation.offset, cut.length);

  const oneByte = good.subarray(0, 1); // sequence field truncated
  const v2 = runAudit({ initialEpoch: 0, trafficSecret: SECRET, records: [oneByte] });
  assert.equal(v2.records[0].violation.kind, 'truncation');
  assert.equal(v2.records[0].violation.offset, 1);
});

test('trailing bytes beyond the declared length are a length violation', () => {
  const good = buildRecord({ epoch: 0, seq: 0, trafficSecret: SECRET });
  const bloated = Buffer.concat([good, Buffer.from([0x00])]);
  const v = runAudit({ initialEpoch: 0, trafficSecret: SECRET, records: [bloated] });
  assert.equal(v.records[0].violation.kind, 'length');
  assert.equal(v.records[0].violation.offset, good.length); // first stray byte
});

test('CID-bearing headers are out of scope', () => {
  const good = buildRecord({ epoch: 0, seq: 0, trafficSecret: SECRET });
  const cid = Buffer.from(good);
  cid[0] |= 0x10;
  const v = runAudit({ initialEpoch: 0, trafficSecret: SECRET, records: [cid] });
  assert.equal(v.records[0].violation.kind, 'header');
  assert.equal(v.records[0].violation.offset, 0);
});

test('inner content type is only unwrapped after AEAD authentication', () => {
  const unknown = buildRecord({ epoch: 0, seq: 0, trafficSecret: SECRET, contentType: 99 });
  const v = runAudit({ initialEpoch: 0, trafficSecret: SECRET, records: [unknown] });
  assert.equal(v.records[0].auth, 'ok'); // reached only because auth passed
  assert.equal(v.records[0].violation.kind, 'content');
});

test('malformed KeyUpdate body is a content violation, epoch unchanged', () => {
  const badBody = Buffer.from([24, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0x07]); // request_update=7
  const rec = buildRecord({ epoch: 0, seq: 0, trafficSecret: SECRET, contentType: 22, content: badBody });
  const v = runAudit({ initialEpoch: 0, trafficSecret: SECRET, records: [rec] });
  assert.equal(v.records[0].violation.kind, 'content');
  assert.equal(v.final_epoch, 0);
});

'use strict';
/*
 * HTTP smoke tests against a live service, focused on KeyUpdate handling
 * and replay-window boundaries (plus health, validation and verdict
 * replacement). Exits non-zero on the first failed expectation batch.
 */

const crypto = require('crypto');
const { buildRecord, buildKeyUpdateRecord, corruptTag, b64, nextTrafficSecret } = require('./craft');

const SECRET_HEX = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join('');
const SECRET = Buffer.from(SECRET_HEX, 'hex');
const NEXT = nextTrafficSecret(SECRET);

async function runSmoke(appUrl) {
  const failures = [];
  const runToken = `smoke-${Date.now()}`;
  let seq = 0;
  const nextId = (name) => `${runToken}-${seq++}-${name}`;

  const check = (name, cond, extra = '') => {
    if (cond) console.log(`  [smoke] ok: ${name}`);
    else {
      failures.push(name);
      console.error(`  [smoke] FAIL: ${name} ${extra}`);
    }
  };

  const get = async (p) => {
    const res = await fetch(appUrl + p);
    return { status: res.status, body: await res.json().catch(() => null) };
  };
  const postAudit = async (payload) => {
    const res = await fetch(appUrl + '/api/audits', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return { status: res.status, body: await res.json() };
  };
  const submit = (auditId, epoch, records) =>
    postAudit({ audit_id: auditId, initial_epoch: epoch, traffic_secret: SECRET_HEX, records: records.map(b64) });

  /* ---- health ---- */
  {
    const { status, body } = await get('/healthz');
    check('health endpoint responds ok', status === 200 && body && body.ok === true);
  }

  /* ---- input validation ---- */
  {
    const bad = await postAudit({ audit_id: 'x', initial_epoch: 0, traffic_secret: 'zz', records: [] });
    check('malformed submission is rejected with 400', bad.status === 400);

    const tooMany = await postAudit({
      audit_id: 'x',
      initial_epoch: 0,
      traffic_secret: SECRET_HEX,
      records: Array(49).fill(b64(buildRecord({ epoch: 0, seq: 0, trafficSecret: SECRET }))),
    });
    check('more than 48 records is rejected with 400', tooMany.status === 400);
  }

  /* ---- accepted run + reopen ---- */
  {
    const id = nextId('accepted');
    const payload = Buffer.from('telemetry-frame');
    const recs = [0, 1, 2].map((s) => buildRecord({ epoch: 1, seq: s, trafficSecret: SECRET, content: payload }));
    const { status, body } = await submit(id, 1, recs);
    check('valid capture accepted', status === 200 && body.status === 'accepted');
    check(
      'per-record evidence present',
      body.records.length === 3 &&
        body.records.every((r) => r.auth === 'ok' && r.adjudication === 'new' && r.window_before && r.window_after)
    );
    check(
      'application data digest matches',
      body.records[0].app_data_sha256 === crypto.createHash('sha256').update(payload).digest('hex')
    );
    const reopened = await get(`/api/audits/${id}`);
    check('frozen verdict can be reopened', reopened.status === 200 && reopened.body.audit_id === id);
    check(
      'reopened verdict is identical',
      JSON.stringify(reopened.body) === JSON.stringify(body)
    );
  }

  /* ---- duplicate capture ---- */
  {
    const rec = buildRecord({ epoch: 0, seq: 9, trafficSecret: SECRET });
    const { body } = await submit(nextId('dup'), 0, [rec, rec]);
    check(
      'duplicate capture rejected at sequence field offset',
      body.status === 'rejected' &&
        body.violation.record_index === 1 &&
        body.violation.kind === 'state' &&
        body.violation.offset === 1
    );
    const dup = body.records[1];
    check(
      'duplicate does not advance the window',
      dup.window_after.max_seq === dup.window_before.max_seq &&
        dup.window_after.bitmap === dup.window_before.bitmap
    );
  }

  /* ---- replay window boundary ---- */
  {
    const mk = (s) => buildRecord({ epoch: 0, seq: s, trafficSecret: SECRET });
    const { body } = await submit(nextId('boundary'), 0, [mk(100), mk(36), mk(37)]);
    check(
      'sequence 64 behind max is too_old',
      body.records[1].adjudication === 'too_old' && body.records[1].violation.kind === 'state'
    );
    check(
      'sequence 63 behind max is still accepted',
      body.records[2].violation === null && body.records[2].adjudication === 'new'
    );
    check(
      'window bitmap tracks both edges',
      body.records[2].window_after.bitmap === '0x8000000000000001'
    );
  }

  /* ---- KeyUpdate: advance + reset ---- */
  {
    const recs = [
      buildRecord({ epoch: 2, seq: 0, trafficSecret: SECRET }),
      buildKeyUpdateRecord({ epoch: 2, seq: 1, trafficSecret: SECRET }),
      buildRecord({ epoch: 3, seq: 0, trafficSecret: NEXT }),
      buildRecord({ epoch: 3, seq: 1, trafficSecret: NEXT }),
    ];
    const { body } = await submit(nextId('keyupdate'), 2, recs);
    check(
      'authenticated KeyUpdate accepted and epoch advanced',
      body.status === 'accepted' && body.final_epoch === 3 && body.records[1].key_update === true
    );
    check(
      'window reset after KeyUpdate (seq 0 is new again)',
      body.records[2].sequence_number === '0' &&
        body.records[2].adjudication === 'new' &&
        body.records[2].window_before.max_seq === null
    );
  }

  /* ---- old epoch after KeyUpdate ---- */
  {
    const recs = [
      buildKeyUpdateRecord({ epoch: 2, seq: 0, trafficSecret: SECRET }),
      buildRecord({ epoch: 3, seq: 0, trafficSecret: NEXT }),
      buildRecord({ epoch: 2, seq: 1, trafficSecret: SECRET }),
    ];
    const { body } = await submit(nextId('stale'), 2, recs);
    check(
      'old-epoch record after KeyUpdate rejected at epoch bits offset',
      body.status === 'rejected' &&
        body.violation.record_index === 2 &&
        body.violation.kind === 'state' &&
        body.violation.offset === 0 &&
        /old_epoch/.test(body.violation.detail)
    );
    check('epoch not rolled back by stale record', body.final_epoch === 3);
  }

  /* ---- forged KeyUpdate ---- */
  {
    const forged = corruptTag(buildKeyUpdateRecord({ epoch: 2, seq: 1, trafficSecret: SECRET }));
    const recs = [
      buildRecord({ epoch: 2, seq: 0, trafficSecret: SECRET }),
      forged,
      buildRecord({ epoch: 2, seq: 2, trafficSecret: SECRET }),
      buildRecord({ epoch: 3, seq: 0, trafficSecret: NEXT }),
    ];
    const { body } = await submit(nextId('forged'), 2, recs);
    check(
      'forged KeyUpdate fails AEAD at the tag offset',
      body.violation.record_index === 1 &&
        body.violation.kind === 'auth' &&
        body.violation.offset === forged.length - 16
    );
    check('secret not advanced: old-epoch record still authenticates', body.records[2].violation === null);
    check(
      'epoch not advanced: next-epoch record is a state violation',
      body.records[3].violation && body.records[3].violation.kind === 'state'
    );
  }

  /* ---- truncation offset ---- */
  {
    const good = buildRecord({ epoch: 0, seq: 0, trafficSecret: SECRET });
    const cut = good.subarray(0, good.length - 7);
    const { body } = await submit(nextId('trunc'), 0, [cut]);
    check(
      'truncated record reports raw offset of first missing byte',
      body.violation.kind === 'truncation' && body.violation.offset === cut.length
    );
  }

  /* ---- old success evidence is cleared on resubmission ---- */
  {
    const id = nextId('replace');
    const good = await submit(id, 0, [buildRecord({ epoch: 0, seq: 0, trafficSecret: SECRET })]);
    check('initial run accepted', good.body.status === 'accepted');
    const bad = await submit(id, 0, [Buffer.from('too-short')]);
    check('resubmission with violation succeeds as a request', bad.status === 200);
    const reopened = await get(`/api/audits/${id}`);
    check(
      'previous success evidence cleared and replaced',
      reopened.status === 200 && reopened.body.status === 'rejected'
    );
  }

  return failures;
}

module.exports = { runSmoke };

'use strict';
/*
 * Verify orchestrator: build checks -> review-rule tests -> HTTP smoke
 * (KeyUpdate + replay boundary) against the live service. Exits 0 only
 * when every stage passes; the exit code is the acceptance report.
 */

const { spawnSync } = require('child_process');
const path = require('path');
const { runChecks } = require('./checks');

const APP_URL = (process.env.APP_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');

async function waitForApp(url, attempts = 60) {
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url + '/healthz');
      if (res.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

async function main() {
  let failed = 0;

  console.log('== stage 1/3: build checks ==');
  failed += runChecks().length;

  console.log('== stage 2/3: review-rule tests ==');
  const t = spawnSync(process.execPath, ['--test', path.join(__dirname, 'rules.test.js')], {
    stdio: 'inherit',
  });
  if (t.status !== 0) failed += 1;

  console.log(`== stage 3/3: HTTP smoke against ${APP_URL} ==`);
  if (!(await waitForApp(APP_URL))) {
    console.error('  [smoke] FAIL: service did not become healthy in time');
    failed += 1;
  } else {
    const { runSmoke } = require('./smoke');
    try {
      failed += (await runSmoke(APP_URL)).length;
    } catch (err) {
      console.error('  [smoke] FAIL: unexpected error:', err);
      failed += 1;
    }
  }

  if (failed === 0) {
    console.log('VERIFY RESULT: PASS');
  } else {
    console.error(`VERIFY RESULT: FAIL (${failed} failing check(s))`);
  }
  process.exit(failed === 0 ? 0 : 1);
}

main();

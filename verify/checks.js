'use strict';
/*
 * Build checks: every shipped JavaScript file must parse, the web assets
 * and container files must exist, and package.json must be valid.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

function runChecks() {
  const failures = [];
  const ok = (msg) => console.log(`  [build] ok: ${msg}`);
  const fail = (msg) => {
    failures.push(msg);
    console.error(`  [build] FAIL: ${msg}`);
  };

  const jsFiles = [
    'src/dtls13.js',
    'src/server.js',
    'src/store.js',
    'public/app.js',
    'verify/craft.js',
    'verify/checks.js',
    'verify/rules.test.js',
    'verify/smoke.js',
    'verify/run.js',
  ];
  for (const f of jsFiles) {
    const p = path.join(ROOT, f);
    if (!fs.existsSync(p)) {
      fail(`missing file ${f}`);
      continue;
    }
    try {
      execFileSync(process.execPath, ['--check', p], { stdio: 'pipe' });
      ok(`${f} parses`);
    } catch (err) {
      fail(`${f} does not parse: ${err.stderr || err.message}`);
    }
  }

  for (const f of ['public/index.html', 'public/style.css', 'Dockerfile', 'docker-compose.yml']) {
    if (fs.existsSync(path.join(ROOT, f))) ok(`${f} present`);
    else fail(`missing file ${f}`);
  }

  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    if (pkg.scripts && pkg.scripts.start) ok('package.json valid with start script');
    else fail('package.json missing scripts.start');
  } catch (err) {
    fail(`package.json invalid: ${err.message}`);
  }

  const compose = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
  for (const needle of ['healthcheck', 'verify', 'HOST_PORT']) {
    if (compose.includes(needle)) ok(`compose mentions ${needle}`);
    else fail(`compose missing ${needle}`);
  }

  return failures;
}

module.exports = { runChecks };

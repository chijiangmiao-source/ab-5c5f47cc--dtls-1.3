'use strict';
/* 审计页面逻辑：通过真实 API 提交审计、重新打开冻结裁决。 */

const $ = (id) => document.getElementById(id);

const KIND_LABELS = {
  truncation: '截断',
  length: '长度',
  auth: '认证',
  state: '状态',
  header: '头部',
  content: '内容',
};

const ADJ_LABELS = {
  new: '新到',
  duplicate: '重复',
  too_old: '过旧',
};

function clearVerdict() {
  // 清除该次旧成功证据：新提交/新查询前先清空已展示的裁决
  $('verdict').classList.add('hidden');
  $('records-table').querySelector('tbody').innerHTML = '';
  $('status-banner').innerHTML = '';
  $('violation-banner').classList.add('hidden');
  $('violation-banner').innerHTML = '';
  $('summary').innerHTML = '';
}

function fmtWindow(w) {
  if (!w) return '—';
  return `max=${w.max_seq === null ? '∅' : w.max_seq} ${w.bitmap}`;
}

function renderVerdict(v) {
  clearVerdict();
  $('verdict').classList.remove('hidden');
  $('verdict-id').textContent = v.audit_id;

  const accepted = v.status === 'accepted';
  $('status-banner').innerHTML =
    `<div class="banner ${accepted ? 'ok' : 'bad'}">` +
    `${accepted ? '✔ 全部记录通过认证与状态裁定' : '✘ 裁决：拒绝（存在违规记录）'}</div>`;

  if (v.violation) {
    const f = v.violation;
    $('violation-banner').classList.remove('hidden');
    $('violation-banner').innerHTML =
      `<div class="banner bad">首个违规：记录 #${f.record_index}，` +
      `类型 ${KIND_LABELS[f.kind] || f.kind}，原始偏移 ${f.offset} — ${f.detail}</div>`;
  }

  $('summary').innerHTML =
    `<dt>提交时间</dt><dd>${v.created_at}</dd>` +
    `<dt>初始 epoch</dt><dd>${v.initial_epoch}</dd>` +
    `<dt>最终 epoch</dt><dd>${v.final_epoch}</dd>` +
    `<dt>通过记录</dt><dd>${v.records_accepted} / ${v.records_total}</dd>`;

  const tbody = $('records-table').querySelector('tbody');
  for (const r of v.records) {
    const tr = document.createElement('tr');
    if (r.violation) tr.className = 'row-bad';
    const cells = [
      r.index,
      r.epoch === null ? '—' : `${r.epoch} (bits ${r.epoch_bits})`,
      r.sequence_number === null ? '—' : `${r.sequence_number} (${r.seq_bits}b)`,
      r.auth === 'ok' ? '✔' : r.auth === 'failed' ? '✘ 失败' : '—',
      r.adjudication ? ADJ_LABELS[r.adjudication] : '—',
      fmtWindow(r.window_before),
      fmtWindow(r.window_after),
      r.content_type_name
        ? `${r.content_type_name}${r.key_update ? ' · KeyUpdate→epoch ' + r.epoch_after : ''}`
        : '—',
      r.app_data_sha256 ? r.app_data_sha256.slice(0, 16) + '…' : '—',
      r.violation
        ? `${KIND_LABELS[r.violation.kind] || r.violation.kind} @${r.violation.offset}`
        : '—',
    ];
    for (const c of cells) {
      const td = document.createElement('td');
      td.textContent = c;
      tr.appendChild(td);
    }
    if (r.app_data_sha256) tr.lastChild.previousSibling.previousSibling.title = r.app_data_sha256;
    if (r.violation) tr.lastChild.title = r.violation.detail;
    tbody.appendChild(tr);
  }
}

async function submitAudit(ev) {
  ev.preventDefault();
  $('form-error').textContent = '';
  clearVerdict(); // 提交即清除旧成功证据

  const lines = $('records').value
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (lines.length === 0 || lines.length > 48) {
    $('form-error').textContent = '记录条数须在 1–48 之间';
    return;
  }

  const payload = {
    audit_id: $('audit-id').value.trim(),
    initial_epoch: parseInt($('initial-epoch').value, 10),
    traffic_secret: $('traffic-secret').value.trim(),
    records: lines,
  };

  try {
    const res = await fetch('/api/audits', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      $('form-error').textContent = data.error || `HTTP ${res.status}`;
      return;
    }
    renderVerdict(data);
  } catch (err) {
    $('form-error').textContent = '请求失败：' + err.message;
  }
}

async function reopenVerdict() {
  $('form-error').textContent = '';
  clearVerdict();
  const id = $('audit-id').value.trim();
  if (!id) {
    $('form-error').textContent = '请先填写审计标识';
    return;
  }
  try {
    const res = await fetch('/api/audits/' + encodeURIComponent(id));
    const data = await res.json();
    if (!res.ok) {
      $('form-error').textContent = data.error || `HTTP ${res.status}`;
      return;
    }
    renderVerdict(data);
  } catch (err) {
    $('form-error').textContent = '请求失败：' + err.message;
  }
}

$('audit-form').addEventListener('submit', submitAudit);
$('reopen-btn').addEventListener('click', reopenVerdict);

(() => {
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const CSRF = $('meta[name=csrf]').content;
let LANG = localStorage.getItem('lang') || 'en';
let lastHigh = 0, voiceVoices = [];

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const T = (en, hi) => (LANG === 'hi' && hi) ? hi : en;
const HI = {'High':'ऊँचा','Medium':'मध्यम','Low':'कम','high':'गंभीर','medium':'मध्यम','low':'कम','Unknown':'अज्ञात','Verified':'सत्यापित','Clean':'साफ़','Monitoring':'निगरानी में','Reviewed':'समीक्षित',
 'Review needed':'समीक्षा ज़रूरी','Action needed':'कार्रवाई ज़रूरी','Alert':'अलर्ट','Not assessed':'आकलन नहीं','Stale':'पुराना','Incomplete':'अधूरा','All configured checks healthy':'सभी तय जाँच ठीक',
 'MATCH':'मेल खाता है','MISMATCH':'मेल नहीं','PARTIAL':'आंशिक मेल','NOT UPI':'UPI नहीं','UNABLE TO PARSE':'पढ़ा नहीं गया','MATCHED':'मिला','UNMATCHED':'बेमेल','AMBIGUOUS':'अस्पष्ट','PENDING':'लंबित','FAILED':'असफल',
 'NOT VERIFIED':'सत्यापित नहीं','NEEDS CHECKING':'जाँच ज़रूरी','VERIFIED BY USER IN OFFICIAL APP':'आधिकारिक ऐप में सत्यापित'};
const badge = (txt, cls) => `<span class="badge b-${esc((cls || txt).split(/[ _]/)[0])}">${esc(LANG === 'hi' && HI[txt] ? HI[txt] : txt)}</span>`;

async function api(path, opts = {}) {
  const o = {method: opts.method || 'GET', headers: {'X-CSRF-Token': CSRF}};
  if (opts.json !== undefined) { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(opts.json); o.method = opts.method || 'POST'; }
  if (opts.form) { o.body = opts.form; o.method = 'POST'; }
  const r = await fetch(path, o);
  if (r.status === 401) { location.href = '/login'; return {}; }
  let data = {};
  try { data = await r.json(); } catch (e) { data = {ok: false, error: 'Unexpected response'}; }
  return data;
}

/* ---------- language & voice ---------- */
function applyLang() {
  $$('[data-en]').forEach(el => { el.textContent = T(el.dataset.en, el.dataset.hi); });
  $('#langBtn').textContent = LANG === 'en' ? 'हिंदी' : 'English';
  document.documentElement.lang = LANG;
  loadVoiceGuide(); refreshAll();
}
$('#langBtn').onclick = () => { LANG = LANG === 'en' ? 'hi' : 'en'; localStorage.setItem('lang', LANG); applyLang(); };
if ('speechSynthesis' in window) { speechSynthesis.onvoiceschanged = () => { voiceVoices = speechSynthesis.getVoices(); }; voiceVoices = speechSynthesis.getVoices(); }
function speak(level) {
  // Never speaks pasted text or sensitive details; the written warning is always shown as well.
  if (!$('#voiceOn').checked || !('speechSynthesis' in window)) return;
  const msg = LANG === 'hi' ? 'सावधान! गंभीर जोखिम मिला है। कृपया स्क्रीन पर चेतावनी देखें।' : 'Warning! A high risk was found. Please read the warning on the screen.';
  const u = new SpeechSynthesisUtterance(level === 'High' || level === 'high' ? msg : (LANG === 'hi' ? 'सावधानी रखें।' : 'Please be careful.'));
  u.lang = LANG === 'hi' ? 'hi-IN' : 'en-IN';
  const v = voiceVoices.find(v => v.lang.toLowerCase().startsWith(LANG === 'hi' ? 'hi' : 'en'));
  if (v) u.voice = v;
  speechSynthesis.cancel(); speechSynthesis.speak(u);
}
$('#voiceOn').checked = localStorage.getItem('voice') === '1';
$('#voiceOn').onchange = e => localStorage.setItem('voice', e.target.checked ? '1' : '0');

/* ---------- navigation ---------- */
function go(id) {
  $$('.panel').forEach(p => p.classList.toggle('show', p.id === id));
  $$('#nav button').forEach(b => b.classList.toggle('on', b.dataset.go === id));
  history.replaceState(null, '', '#' + id);
  if (id === 'alerts') loadAlerts();
  if (id === 'overview') refreshOverview();
}
$$('#nav button').forEach(b => b.onclick = () => go(b.dataset.go));

/* ---------- shared renderers ---------- */
function resultBox(level, inner) { return `<div class="result ${esc(String(level).toLowerCase())}">${inner}</div>`; }
function reasons(list) {
  return list.length ? `<ul>${list.map(r => `<li>${esc(T(r.en, r.hi))}<span class="rid">${esc(r.id)}</span></li>`).join('')}</ul>` : '';
}
function alertRow(a, withAck = true) {
  return `<div class="alert ${esc(a.severity)} ${a.ack ? 'ack' : ''}"><div>
    <div>${badge(a.severity, a.severity)} <b>${esc(T(a.title_en, a.title_hi))}</b></div>
    <div class="meta">${esc(a.ts)} · ${esc(a.module)} · ${esc(a.rule_id)} · ${esc(a.source)}</div>
    <div class="meta">Evidence: ${esc(a.evidence)}</div>
    <div>${esc(T(a.action_en, a.action_hi))}</div></div>
    ${withAck && !a.ack ? `<button class="btn small" data-ack="${a.id}">${T('Acknowledge', 'देख लिया')}</button>` : ''}</div>`;
}

/* ---------- overview ---------- */
const STATE_CLS = {'Verified': 'ok', 'Clean': 'ok', 'Monitoring': 'ok', 'Reviewed': 'ok', 'Not assessed': 'idle', 'Stale': 'warn', 'Incomplete': 'warn', 'Review needed': 'warn', 'Action needed': 'bad', 'Alert': 'bad'};
const CLS_COLOR = {ok: 'var(--lo)', warn: 'var(--me)', bad: 'var(--hi)', idle: 'var(--line2)'};
const MODULE_NAME = {message: ['Messages', 'संदेश'], qr: ['QR check', 'QR जाँच'], payments: ['Payments', 'भुगतान'], secret_scan: ['Code scan', 'कोड स्कैन'], login: ['Logins', 'लॉगिन'], factory: ['Factory', 'फ़ैक्टरी'], voice: ['Voice call', 'वॉइस कॉल'], apk: ['App file', 'ऐप फ़ाइल']};
const SEV_RANK = {high: 3, medium: 2, low: 1};
function ringSvg(comps) {
  const n = Math.max(comps.length, 1), cx = 100, cy = 100, r = 78, gap = 6, seg = 360 / n;
  const pt = deg => { const a = (deg - 90) * Math.PI / 180; return [cx + r * Math.cos(a), cy + r * Math.sin(a)]; };
  return comps.map((c, i) => {
    const a0 = i * seg + gap / 2, a1 = (i + 1) * seg - gap / 2, [x0, y0] = pt(a0), [x1, y1] = pt(a1);
    return `<path d="M${x0.toFixed(2)} ${y0.toFixed(2)} A${r} ${r} 0 ${a1 - a0 > 180 ? 1 : 0} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}" fill="none" stroke="${CLS_COLOR[STATE_CLS[c.state] || 'idle']}" stroke-width="14" stroke-linecap="round"/>`;
  }).join('');
}
function barsSvg(rows, max) {
  const W = 320, rowH = 30;
  return `<svg viewBox="0 0 ${W} ${rows.length * rowH}" width="100%" role="img" aria-label="${esc(T('Open alerts by area', 'क्षेत्र के अनुसार खुले अलर्ट'))}">` + rows.map((x, i) => {
    const y = i * rowH, w = Math.max(6, Math.round(180 * x.n / max)), col = x.sev === 'high' ? 'var(--hi)' : x.sev === 'medium' ? 'var(--me)' : 'var(--lo)';
    return `<text x="0" y="${y + 18}" font-size="12.5" fill="var(--ink)">${esc(x.name)}</text><rect x="96" y="${y + 8}" width="190" height="9" rx="4.5" fill="var(--bg2)" stroke="var(--line)"/><rect x="96" y="${y + 8}" width="${w}" height="9" rx="4.5" fill="${col}"/><text x="${W}" y="${y + 18}" font-size="12.5" font-weight="600" text-anchor="end" fill="var(--ink)">${x.n}</text>`;
  }).join('') + '</svg>';
}
async function refreshOverview() {
  const r = await api('/api/readiness');
  if (!r.ok) return;
  const a = await api('/api/alerts?status=open');
  const open = a.alerts || [];
  // KPI: overall status
  const cls = r.overall === 'Action needed' ? 'bad' : r.overall === 'Incomplete' ? 'warn' : 'ok';
  const overallTxt = r.overall === 'All configured checks healthy' ? T('All healthy', 'सब ठीक') : (LANG === 'hi' && HI[r.overall] ? HI[r.overall] : r.overall);
  $('#kStatus').textContent = overallTxt; $('#kStatus').className = 'val ' + cls;
  $('#kStatusSub').textContent = `${r.healthy}/${r.total} ${T('checks healthy', 'जाँच ठीक')}`;
  $('#overall').innerHTML = badge(r.overall, r.overall);
  // KPI: checks run
  const ran = r.components.filter(c => c.state !== 'Not assessed').length;
  $('#kRun').textContent = `${ran}/${r.total}`; $('#kRun').className = 'val ' + (ran === r.total ? 'ok' : ran === 0 ? 'idle' : 'warn');
  $('#kRunSub').textContent = ran === r.total ? T('Every check has run', 'हर जाँच चल चुकी है') : `${r.total - ran} ${T('not assessed yet', 'का आकलन बाकी')}`;
  // readiness ring + legend
  $('#ring').innerHTML = ringSvg(r.components); $('#ringNum').textContent = `${r.healthy}/${r.total}`;
  $('#legend').innerHTML = r.components.map(c => { const k = STATE_CLS[c.state] || 'idle'; return `<div title="${esc(T(c.detail, c.detail_hi))}"><span><i class="d-${k}"></i>${esc(T(c.name_en, c.name_hi))}</span>${badge(c.state, c.state)}</div>`; }).join('');
  // table
  $('#components').innerHTML = `<tr><th>${T('Check', 'जाँच')}</th><th>${T('State', 'स्थिति')}</th><th>${T('Detail', 'विवरण')}</th></tr>` +
    r.components.map(c => `<tr><td>${esc(T(c.name_en, c.name_hi))}</td><td>${badge(c.state, c.state)}</td><td>${esc(T(c.detail, c.detail_hi))}</td></tr>`).join('');
  $('#readyNote').textContent = r.note;
  $('#openHigh').textContent = r.open_high; $('#openTotal').textContent = r.open_total;
  $('#openTotal').className = 'val ' + (r.open_high > 0 ? 'bad' : r.open_total > 0 ? 'warn' : 'idle');
  if (r.open_high > lastHigh) speak('High');
  lastHigh = r.open_high;
  // KPI: latest alert
  if (open.length) { const x = open[0]; $('#kLast').textContent = (x.ts || '').slice(11, 16) || '-'; $('#kLast').className = 'val idle'; $('#kLastSub').textContent = T(x.title_en, x.title_hi); }
  else { $('#kLast').textContent = T('None', 'कोई नहीं'); $('#kLast').className = 'val idle'; $('#kLastSub').textContent = T('Nothing open right now', 'अभी कुछ खुला नहीं'); }
  // bars by module
  const mods = {};
  open.forEach(x => { const m = mods[x.module] || (mods[x.module] = {n: 0, sev: 'low'}); m.n++; if ((SEV_RANK[x.severity] || 0) > SEV_RANK[m.sev]) m.sev = x.severity; });
  const rows = Object.entries(mods).map(([k, v]) => ({name: T(...(MODULE_NAME[k] || [k, k])), n: v.n, sev: v.sev})).sort((p, q) => q.n - p.n).slice(0, 6);
  $('#bars').innerHTML = rows.length ? barsSvg(rows, Math.max(...rows.map(x => x.n))) : `<div class="empty">${T('No open alerts. Run the checks to see results here.', 'कोई खुला अलर्ट नहीं। नतीजे देखने के लिए जाँच चलाएँ।')}</div>`;
  // rule-based next step: highest-severity, newest open alert
  const top = open.slice().sort((p, q) => (SEV_RANK[q.severity] || 0) - (SEV_RANK[p.severity] || 0) || q.id - p.id)[0];
  $('#next').innerHTML = `<b>${T('Suggested next step (rule-based)', 'सुझाया अगला कदम (नियम-आधारित)')}</b>` +
    (top ? `${esc(T(top.title_en, top.title_hi))}: ${esc(T(top.action_en, top.action_hi))}` :
      esc(ran < r.total ? T('Run all automatic checks to fill in the "Not assessed" items.', '"आकलन नहीं" वाली जाँचें भरने के लिए सभी स्वचालित जाँच चलाएँ।') : T('Nothing needs attention right now. This is not a guarantee.', 'अभी किसी चीज़ पर ध्यान ज़रूरी नहीं। यह गारंटी नहीं है।')));
  $('#latest').innerHTML = open.slice(0, 5).map(x => alertRow(x, false)).join('') || `<p class="muted">${T('No open alerts.', 'कोई खुला अलर्ट नहीं।')}</p>`;
}
function refreshAll() { refreshOverview(); loadQR(); loadSales(); }

$('#loadDemo').onclick = async () => { const r = await api('/api/demo/load', {json: {}}); $('#runMsg').textContent = r.ok ? T(`Loaded ${r.sales} sales and ${r.statement_rows} statement rows (synthetic).`, `${r.sales} बिक्री और ${r.statement_rows} स्टेटमेंट पंक्तियाँ लोड हुईं (नकली)।`) : r.error; refreshAll(); };
$('#resetDemo').onclick = async () => { if (!confirm(T('Delete all demo alerts, sales and scans?', 'सभी डेमो अलर्ट, बिक्री और स्कैन हटाएँ?'))) return; await api('/api/demo/reset', {json: {}}); $('#runMsg').textContent = T('Demo reset.', 'डेमो रीसेट हुआ।'); refreshAll(); };
$('#runAll').onclick = async () => {
  $('#runMsg').textContent = T('Running…', 'चल रहा है…');
  const s = await api('/api/scan/secrets', {json: {}});
  const l = await api('/api/logins/run', {json: {}});
  const rc = await api('/api/recon/run');
  $('#runMsg').textContent = `${T('Folder scan', 'फ़ोल्डर स्कैन')}: ${s.ok ? s.findings.length + ' ' + T('findings', 'निष्कर्ष') : s.error} · ${T('Logins', 'लॉगिन')}: ${l.ok ? l.findings.length + ' ' + T('patterns', 'पैटर्न') : l.error} · ${T('Payments', 'भुगतान')}: ${rc.ok ? (rc.summary.UNMATCHED + ' ' + T('unmatched', 'बेमेल')) : rc.error}`;
  refreshOverview();
};

/* ---------- messages ---------- */
$('#sampleScam').onclick = () => $('#msgText').value = 'Dear customer, your KYC is pending and account will be blocked. Refund of Rs 4999 is waiting: enter your UPI PIN to receive the money right now at http://sbi-kyc-update.xyz/verify';
$('#sampleOk').onclick = () => $('#msgText').value = 'Reminder: your electricity bill of Rs 1450 is due on 20 Nov. Pay through the official app. Never share your OTP or PIN with anyone.';
$('#analyzeBtn').onclick = async () => {
  const r = await api('/api/analyze', {json: {text: $('#msgText').value}});
  if (!r.ok) { $('#msgResult').innerHTML = resultBox('un', esc(r.error)); return; }
  $('#msgResult').innerHTML = resultBox(r.level, `<div>${badge(r.level, r.level)} <span class="muted small">${T('score', 'अंक')} ${r.score}/100 · ${esc(r.ruleset)}</span></div>
    ${reasons(r.reasons)}<p><b>${T('What to do:', 'क्या करें:')}</b> ${esc(T(r.next_en, r.next_hi))}</p><p class="muted small">${esc(T(r.note_en, r.note_hi))}</p>`);
  if (r.level === 'High') speak('High'); refreshOverview();
};
$('#apkBtn').onclick = async () => {
  const f = $('#apkFile').files[0]; if (!f) return;
  const fd = new FormData(); fd.append('file', f);
  const r = await api('/api/apk/check', {form: fd});
  $('#apkResult').innerHTML = r.ok ? resultBox(r.level, `${badge(r.level, r.level)} ${T('permissions found', 'अनुमतियाँ')}: ${esc(r.permissions_found.join(', ') || '—')}
    ${reasons(r.reasons)}<p class="muted small">SHA-256: ${esc(r.sha256.slice(0, 24))}… · ${esc(T(r.note_en, r.note_hi))}</p>`) : resultBox('un', esc(r.error));
  if (r.ok && r.level === 'High') speak('High'); refreshOverview();
};

/* ---------- QR ---------- */
async function loadQR() {
  const r = await api('/api/qr/registered');
  $('#qList').innerHTML = (r.registered || []).map(q => `<div class="alert low"><div><b>${esc(q.label)}</b> · ${esc(q.upi_id)}<div class="meta">${esc(q.payee_name)}</div></div><button class="btn small" data-qdel="${q.id}">✕</button></div>`).join('') || `<p class="muted">${T('Nothing registered yet.', 'अभी कुछ पंजीकृत नहीं।')}</p>`;
  const h = await api('/api/qr/history');
  $('#qHist').innerHTML = (h.history || []).slice(0, 5).map(x => `<div class="small">${esc(x.ts)} ${badge(x.status, x.status)} ${esc(x.observed)}</div>`).join('');
}
$('#qAdd').onclick = async () => {
  const r = await api('/api/qr/registered', {json: {label: $('#qLabel').value || 'Main counter', upi_id: $('#qUpi').value, payee_name: $('#qName').value}});
  if (!r.ok) alert(r.error); else { $('#qUpi').value = ''; $('#qName').value = ''; } loadQR();
};
function showQR(r) {
  if (!r.ok) { $('#qResult').innerHTML = resultBox('un', esc(r.error)); return; }
  const lvl = r.status === 'MATCH' ? 'low' : (r.status === 'UNABLE_TO_PARSE' ? 'medium' : 'high');
  $('#qResult').innerHTML = resultBox(lvl, `${badge(r.status.replace(/_/g, ' '), r.status)}<p>${esc(T(r.en, r.hi))}</p>
    <div class="small muted">${T('Expected', 'अपेक्षित')}: ${esc((r.expected || []).join(', '))}<br>${T('Observed', 'पाया गया')}: ${esc(r.observed || '—')} ${r.observed_name ? '(' + esc(r.observed_name) + ')' : ''}</div>`);
  if (lvl === 'high') speak('High'); loadQR(); refreshOverview();
}
$('#qScanFile').onclick = async () => { const f = $('#qFile').files[0]; if (!f) return; const fd = new FormData(); fd.append('image', f); showQR(await api('/api/qr/scan', {form: fd})); };
$('#qScanText').onclick = async () => showQR(await api('/api/qr/scan', {json: {payload: $('#qPayload').value}}));
$('#qCam').onclick = async () => {
  if (!('BarcodeDetector' in window) || !navigator.mediaDevices) { $('#qResult').innerHTML = resultBox('medium', T('Live camera scanning is not supported in this browser. Upload a photo instead.', 'इस ब्राउज़र में कैमरा स्कैन समर्थित नहीं। फ़ोटो अपलोड करें।')); return; }
  const v = $('#qVideo'); v.classList.remove('hidden');
  try {
    const stream = await navigator.mediaDevices.getUserMedia({video: {facingMode: 'environment'}});
    v.srcObject = stream; await v.play();
    const det = new BarcodeDetector({formats: ['qr_code']});
    const tick = async () => {
      if (!v.srcObject) return;
      const codes = await det.detect(v).catch(() => []);
      if (codes.length) { stream.getTracks().forEach(t => t.stop()); v.srcObject = null; v.classList.add('hidden'); showQR(await api('/api/qr/scan', {json: {payload: codes[0].rawValue}})); return; }
      setTimeout(tick, 300);
    };
    tick();
  } catch (e) { v.classList.add('hidden'); $('#qResult').innerHTML = resultBox('medium', T('Camera not available or permission denied.', 'कैमरा उपलब्ध नहीं या अनुमति नहीं मिली।')); }
};
document.addEventListener('click', async e => {
  const d = e.target.closest('[data-qdel]'); if (d) { await api('/api/qr/delete', {json: {id: +d.dataset.qdel}}); loadQR(); }
  const a = e.target.closest('[data-ack]'); if (a) { await api(`/api/alerts/${a.dataset.ack}/ack`, {json: {}}); loadAlerts(); refreshOverview(); }
});

/* ---------- sales & reconciliation ---------- */
async function loadSales() {
  const r = await api('/api/sales');
  $('#sList').innerHTML = `<table class="tbl"><tr><th>${T('Time', 'समय')}</th><th>${T('Amount', 'राशि')}</th><th>Ref</th></tr>` +
    (r.sales || []).slice(0, 8).map(s => `<tr><td>${esc(s.ts)}</td><td>Rs ${(+s.amount).toFixed(2)}</td><td>${esc(s.ref)}</td></tr>`).join('') + '</table>';
}
$('#sAdd').onclick = async () => { const r = await api('/api/sales', {json: {amount: $('#sAmt').value, ref: $('#sRef').value}}); if (!r.ok) alert(r.error); else $('#sAmt').value = ''; loadSales(); };
$('#csvImport').onclick = async () => {
  const f = $('#csvFile').files[0]; if (!f) return; const fd = new FormData(); fd.append('file', f);
  const r = await api('/api/recon/import', {form: fd});
  $('#reconResult').innerHTML = r.ok ? resultBox('low', `${T('Imported', 'आयात')} ${r.imported} ${T('rows', 'पंक्तियाँ')} · ${r.duplicates} ${T('duplicate(s)', 'डुप्लिकेट')} · ${r.rejected.length} ${T('rejected', 'अस्वीकृत')}${r.rejected.map(x => `<div class="small">row ${x.row}: ${esc(x.error)}</div>`).join('')}`) : resultBox('high', esc(r.error) + (r.errors || []).map(x => `<div class="small">${esc(x.error)}</div>`).join(''));
};
$('#reconRun').onclick = async () => {
  const r = await api('/api/recon/run');
  if (!r.ok) { $('#reconResult').innerHTML = resultBox('medium', esc(r.error)); return; }
  const s = r.summary;
  $('#reconResult').innerHTML = `<p class="small muted">${T('Source', 'स्रोत')}: ${esc(r.source)} · ${T('refunds', 'रिफंड')}: ${s.refunds.length} · ${T('duplicates ignored', 'डुप्लिकेट अनदेखे')}: ${s.duplicates.length}</p>
   <table class="tbl"><tr><th>${T('Time', 'समय')}</th><th>${T('Amount', 'राशि')}</th><th>${T('Status', 'स्थिति')}</th><th>${T('Meaning', 'मतलब')}</th></tr>` +
    r.rows.map(x => `<tr><td>${esc(x.ts)}</td><td>Rs ${x.amount.toFixed(2)}</td><td>${badge(x.status, x.status)}</td><td>${esc(T(x.en, x.hi))}${x.txn_id ? ' <span class="small muted">(' + esc(x.txn_id) + ')</span>' : ''}</td></tr>`).join('') + '</table>';
  if (s.UNMATCHED) speak('High'); refreshOverview();
};
$('#vBtn').onclick = async () => {
  const r = await api('/api/payment/verify', {json: {official_app_credit_seen: $('#vApp').checked, amount_matches: $('#vAmt').checked, txn_id_seen: $('#vTxn').checked, only_screenshot: $('#vShot').checked}});
  const lvl = r.status.startsWith('VERIFIED') ? 'low' : r.status === 'NEEDS_CHECKING' ? 'medium' : 'high';
  $('#vResult').innerHTML = resultBox(lvl, `${badge(r.status.replace(/_/g, ' '), r.status)}<p>${esc(T(r.en, r.hi))}</p>`);
};

/* ---------- Linux guard ---------- */
$('#scanBtn').onclick = async () => {
  const r = await api('/api/scan/secrets', {json: {}});
  if (!r.ok) { $('#scanResult').innerHTML = resultBox('high', esc(r.error)); return; }
  $('#scanMeta').textContent = `${r.files_scanned} ${T('files scanned', 'फ़ाइलें स्कैन')} · ${r.files_skipped} ${T('skipped', 'छोड़ी')} · ${r.seconds}s · ${r.ruleset}`;
  $('#scanResult').innerHTML = `<table class="tbl"><tr><th>${T('Severity', 'गंभीरता')}</th><th>${T('Where', 'कहाँ')}</th><th>${T('What', 'क्या')}</th><th>${T('Masked value', 'छिपा मान')}</th><th></th></tr>` +
    r.findings.map(f => `<tr><td>${badge(f.severity, f.severity)}</td><td>${esc(f.file)}:${f.line}</td><td>${esc(T(f.type, f.type_hi))}<div class="small muted">${esc(T(f.advice, f.advice_hi))}</div></td><td><code>${esc(f.masked)}</code></td>
    <td>${f.fixable ? `<button class="btn small" data-fix="${esc(f.file)}|${f.line}">${T('Suggest fix', 'सुधार सुझाएँ')}</button>` : ''}</td></tr>`).join('') + '</table>' +
    (r.findings.length ? '' : `<p class="muted">${T('No configured patterns found (not a guarantee).', 'कोई तय पैटर्न नहीं मिला (गारंटी नहीं)।')}</p>`);
  if (r.findings.some(f => f.severity === 'high')) speak('High'); refreshOverview();
};
document.addEventListener('click', async e => {
  const b = e.target.closest('[data-fix]'); if (!b) return;
  const [file, line] = b.dataset.fix.split('|');
  const r = await api('/api/fix/propose', {json: {file, line: +line}});
  if (!r.ok) { $('#fixBox').innerHTML = resultBox('medium', esc(r.error)); return; }
  $('#fixBox').innerHTML = resultBox('medium', `<b>${T('Proposed change (not applied yet)', 'प्रस्तावित बदलाव (अभी लागू नहीं)')}</b><pre class="diff">${esc(r.diff)}</pre><p class="small">${esc(r.note)}</p>
    <button class="btn primary" data-apply="${esc(file)}|${line}">${T('Approve: back up and apply', 'मंज़ूर: बैकअप लेकर लागू करें')}</button>`);
});
document.addEventListener('click', async e => {
  const b = e.target.closest('[data-apply]'); if (!b) return;
  const [file, line] = b.dataset.apply.split('|');
  const r = await api('/api/fix/apply', {json: {file, line: +line, approve: true}});
  $('#fixBox').innerHTML = r.ok ? resultBox('low', `${T('Applied. Backup saved as', 'लागू हुआ। बैकअप')} <code>${esc(r.backup)}</code>.<pre class="diff">${esc(r.diff)}</pre><p class="small">${esc(r.note)}</p>`) : resultBox('high', esc(r.error));
});
async function runLogins() {
  const r = await api('/api/logins/run', {json: {}});
  const st = {ACTIVE: 'Monitoring real log', DEMO_SAMPLE: 'Using synthetic demo log', PERMISSION_REQUIRED: 'Permission required (using demo log)', UNAVAILABLE: 'NOT active'}[r.status] || r.status;
  $('#loginResult').innerHTML = `<p class="small muted">${badge(st, r.status === 'ACTIVE' ? 'low' : 'medium')} ${esc(r.source || '')} · ${r.events_parsed} ${T('events parsed', 'घटनाएँ')} ${r.hint ? '· ' + esc(r.hint) : ''}</p>` +
    (r.findings.map(f => resultBox(f.severity, `${badge(f.severity, f.severity)} <b>${esc(f.rule_id)}</b> · ${esc(f.source)} · ${esc(f.accounts.join(', '))}<p>${esc(T(f.en, f.hi))}</p><p class="small">${esc(T(f.action_en, f.action_hi))}</p>`)).join('') || `<p class="muted">${T('No threshold alert. A single failed login is not treated as an attack.', 'कोई सीमा अलर्ट नहीं। अकेली विफलता को हमला नहीं माना जाता।')}</p>`);
  if (r.findings.some(f => f.severity === 'high')) speak('High'); refreshOverview();
}
$('#loginRun').onclick = runLogins;
$$('[data-sim]').forEach(b => b.onclick = async () => { await api('/api/logins/simulate', {json: {kind: b.dataset.sim}}); runLogins(); });

/* ---------- factory ---------- */
function drawChart(rows) {
  const svg = $('#chart'); const W = 900, H = 230, pad = 34;
  if (!rows.length) { svg.innerHTML = `<text x="450" y="115" text-anchor="middle" fill="var(--mut)">${T('No data yet', 'अभी डेटा नहीं')}</text>`; return; }
  const ymin = 20, ymax = 110, x = i => pad + (W - 2 * pad) * (rows.length > 1 ? i / (rows.length - 1) : 0), y = v => H - pad - (H - 2 * pad) * (v - ymin) / (ymax - ymin);
  const pts = rows.map((r, i) => `${x(i).toFixed(1)},${y(r.temp).toFixed(1)}`).join(' ');
  const area = `${x(0).toFixed(1)},${H - pad} ${pts} ${x(rows.length - 1).toFixed(1)},${H - pad}`;
  const grid = [20, 50, 80, 110].map(v => `<line x1="${pad}" x2="${W - pad}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line)"/><text x="${pad - 6}" y="${y(v) + 4}" text-anchor="end" font-size="11" fill="var(--mut)">${v}</text>`).join('');
  svg.innerHTML = `<defs><linearGradient id="ga" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#22d3ee" stop-opacity=".35"/><stop offset="1" stop-color="#22d3ee" stop-opacity="0"/></linearGradient></defs>${grid}
  <line x1="${pad}" x2="${W - pad}" y1="${y(85)}" y2="${y(85)}" stroke="var(--hi)" stroke-dasharray="5 4"/><text x="${W - pad}" y="${y(85) - 5}" text-anchor="end" font-size="11" fill="var(--hi)">85 °C limit</text>
  <polygon points="${area}" fill="url(#ga)"/><polyline fill="none" stroke="#22d3ee" stroke-width="2.5" stroke-linejoin="round" points="${pts}"/>` +
    rows.map((r, i) => `<circle cx="${x(i)}" cy="${y(r.temp)}" r="3.5" fill="${r.temp > 85 ? 'var(--hi)' : '#22d3ee'}"/>`).join('');
}
function renderIoT(r) {
  if (!r.assessed) { drawChart([]); $('#iotAlerts').innerHTML = ''; $('#iotTable').innerHTML = ''; return; }
  $('#devName').textContent = r.device + ' · ' + T('last seen', 'अंतिम बार') + ' ' + r.last_seen;
  drawChart(r.readings);
  $('#iotAlerts').innerHTML = r.alerts.map(a => resultBox(a.severity, `${badge(a.severity, a.severity)} <b>${esc(a.rule_id)}</b> ${esc(T(a.en, a.hi))}<div class="small">${esc(T(a.action_en, a.action_hi))}</div>`)).join('') || `<p class="muted">${T('Within configured range.', 'तय सीमा के भीतर।')}</p>`;
  $('#iotTable').innerHTML = `<tr><th>${T('Time', 'समय')}</th><th>°C</th><th>mm/s</th><th>A</th></tr>` + r.readings.slice(-8).reverse().map(x => `<tr><td>${x.t}</td><td>${x.temp}</td><td>${x.vib}</td><td>${x.cur}</td></tr>`).join('');
  if (r.alerts.some(a => a.severity === 'high')) speak('High');
}
async function tick(mode) { const r = await api('/api/iot/tick', {json: {mode}}); renderIoT(r); refreshOverview(); }
$$('[data-tick]').forEach(b => b.onclick = () => tick(b.dataset.tick));
let autoT = null;
$('#autoTick').onchange = e => { clearInterval(autoT); if (e.target.checked) autoT = setInterval(() => tick('normal'), 3000); };

/* ---------- citizen ---------- */
let VG = null;
async function loadVoiceGuide() {
  if (!VG) { const r = await api('/api/voice/guide'); if (!r.ok) return; VG = r; }
  $('#consent').textContent = T(VG.consent_en, VG.consent_hi);
  $('#steps').innerHTML = VG.steps.map(s => `<li>${esc(T(s.en, s.hi))}</li>`).join('');
  const checked = $$('#questions input:checked').map(i => i.value);
  $('#questions').innerHTML = VG.questions.map(q => `<label class="chk"><input type="checkbox" value="${esc(q.id)}" ${checked.includes(q.id) ? 'checked' : ''}> <span>${esc(T(q.en, q.hi))}</span></label>`).join('');
}
$('#voiceCheck').onclick = async () => {
  const answers = {}; $$('#questions input').forEach(i => answers[i.value] = i.checked);
  const r = await api('/api/voice/check', {json: {answers}});
  $('#voiceResult').innerHTML = resultBox(r.level, `${badge(r.level, r.level)}<p>${esc(T(r.en, r.hi))}</p>`);
  if (r.level === 'High') speak('High'); refreshOverview();
};

/* ---------- alerts ---------- */
async function loadAlerts() {
  const q = new URLSearchParams({module: $('#fMod').value, severity: $('#fSev').value, status: $('#fSt').value});
  [...q.keys()].forEach(k => { if (!q.get(k)) q.delete(k); });
  const r = await api('/api/alerts?' + q);
  $('#alertList').innerHTML = (r.alerts || []).map(a => alertRow(a)).join('') || `<p class="muted">${T('No alerts match.', 'कोई अलर्ट नहीं।')}</p>`;
}
['#fMod', '#fSev', '#fSt'].forEach(s => $(s).onchange = loadAlerts);

/* ---------- boot ---------- */
applyLang();
(async () => { const r = await api('/api/iot/status'); if (r.ok) renderIoT(r); })();
const start = location.hash.slice(1); if (start && $('#' + start)) go(start);
})();

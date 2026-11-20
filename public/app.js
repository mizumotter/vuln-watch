import { explain } from './explain.js';

// ---------- state (everything personal stays in localStorage) ----------
const LS = 'vw:';
const load = (k, d) => { try { return JSON.parse(localStorage.getItem(LS + k)) ?? d; } catch { return d; } };
const save = (k, v) => { try { localStorage.setItem(LS + k, JSON.stringify(v)); } catch { /* storage full or blocked */ } };

const S = {
  lang: load('lang', (navigator.language || '').startsWith('ja') ? 'ja' : 'en'),
  follows: new Set(load('follows', [])),
  read: new Set(load('read', [])),
  f: { days: 30, cvss: 0, epss: 0, kev: false, unread: false, product: '', sort: 'priority', ...load('filters', {}) },
  tab: 'feed', catalog: [], meta: null, items: [], kev: [], limit: 50, error: '',
};
if (!S.follows.size) S.tab = 'settings';

const TXT = {
  ja: {
    tagline: 'フォローした製品の脆弱性を、深刻度と悪用予測つきで確認',
    updated: (d) => `データ更新: ${d}`, feed: 'フィード', kevTab: '悪用確認 (KEV)', settings: 'フォロー設定',
    sourceDown: (s) => `一部のデータ元の取得に失敗しています（${s}）。表示は前回取得分です。`,
    loadError: 'データを読み込めませんでした。時間をおいて再読み込みしてください。',
    days: '期間', d7: '7日', d30: '30日', d90: '90日', dAll: 'すべて', anyScore: '指定なし',
    product: '製品', allProducts: 'すべて', kevOnly: 'KEVのみ', unreadOnly: '未読のみ',
    sort: '並び順', sPriority: '優先度（KEV→EPSS→CVSS）', sNew: '新しい順（同じ日は深刻度順）',
    markAll: '表示中をすべて既読にする', showing: (n, u) => `${n} 件（未読 ${u} 件）`, more: 'さらに表示',
    emptyFollow: 'まだ製品をフォローしていません。「フォロー設定」で選んでください。',
    emptyFilter: '条件に合う脆弱性はありません。',
    kevLead: 'CISA が「実際に悪用されている」と確認した脆弱性の新着です（フォロー設定に関係なく全製品）。',
    settingsLead: 'チェックしたい製品を選んでください。選択はこのブラウザだけに保存されます。',
    search: '製品名で絞り込み', following: (n) => `フォロー中 ${n} 件`, toFeed: 'フィードを見る',
    cat: { lang: '言語・ランタイム', web: 'Webサーバ・プロキシ', db: 'データベース', os: 'OS', fw: 'フレームワーク・ライブラリ', infra: 'ミドルウェア・基盤ツール' },
    sev: { CRITICAL: '緊急', HIGH: '重要', MEDIUM: '警告', LOW: '注意', NONE: 'なし' },
    kevBadge: 'KEV 悪用確認', ransom: 'ランサムウェアで悪用', isNew: 'NEW',
    epssTip: (p) => `今後30日以内に悪用される確率の予測。全CVE中の上位 ${p}%`,
    summary: '概要', original: '英語の原文', noJa: '日本語の概要はまだありません（JVN 未掲載）。',
    what: 'どういう脆弱性か', how: '攻撃手法', impact: '想定される被害',
    conditions: '攻撃が成立する条件', effects: '影響の大きさ', versions: '影響を受けるバージョン', fixed: '修正版',
    kevInfo: '悪用の状況', kevAdded: (d) => `KEV 掲載日: ${d}`, kevDue: (d) => `米政府機関の対応期限: ${d}`, action: '求められる対応',
    links: '一次情報', matchCna: '製品の特定は CNA（採番機関）申告の製品名によります（NVD 未分析）。',
    matchOsv: 'パッケージの脆弱性情報（OSV / GitHub Advisory）に基づきます。',
    footer: [
      'CVE・CVSS: NVD（This product uses the NVD API but is not endorsed or certified by the NVD.）',
      'EPSS: FIRST.org ／ KEV: CISA ／ パッケージ情報: OSV.dev ／ 日本語概要: JVN iPedia',
      '解説文は CWE と CVSS から機械的に生成した一般的な説明です。対応の判断は必ず一次情報で確認してください。',
    ],
  },
  en: {
    tagline: 'Vulnerabilities in the products you follow, with severity and exploit prediction',
    updated: (d) => `Data updated: ${d}`, feed: 'Feed', kevTab: 'Exploited (KEV)', settings: 'Follow settings',
    sourceDown: (s) => `Some sources failed to update (${s}). Showing the previous data for them.`,
    loadError: 'Could not load the data. Please reload in a while.',
    days: 'Period', d7: '7 days', d30: '30 days', d90: '90 days', dAll: 'All', anyScore: 'Any',
    product: 'Product', allProducts: 'All', kevOnly: 'KEV only', unreadOnly: 'Unread only',
    sort: 'Sort', sPriority: 'Priority (KEV → EPSS → CVSS)', sNew: 'Newest (by severity within a day)',
    markAll: 'Mark all shown as read', showing: (n, u) => `${n} items (${u} unread)`, more: 'Show more',
    emptyFollow: 'You are not following any product yet. Pick some under "Follow settings".',
    emptyFilter: 'No vulnerabilities match these filters.',
    kevLead: 'Latest vulnerabilities that CISA confirmed as exploited in the wild (all products, regardless of what you follow).',
    settingsLead: 'Choose the products you want to watch. Your selection is stored only in this browser.',
    search: 'Filter by product name', following: (n) => `Following ${n}`, toFeed: 'Open feed',
    cat: { lang: 'Languages & runtimes', web: 'Web servers & proxies', db: 'Databases', os: 'Operating systems', fw: 'Frameworks & libraries', infra: 'Middleware & infrastructure tools' },
    sev: { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', NONE: 'None' },
    kevBadge: 'KEV exploited', ransom: 'Used in ransomware', isNew: 'NEW',
    epssTip: (p) => `Predicted probability of exploitation in the next 30 days. Top ${p}% of all CVEs`,
    summary: 'Summary', original: 'English original', noJa: '',
    what: 'What kind of vulnerability', how: 'Attack technique', impact: 'What an attacker gains',
    conditions: 'Conditions for an attack', effects: 'Impact', versions: 'Affected versions', fixed: 'Fixed in',
    kevInfo: 'Exploitation status', kevAdded: (d) => `Added to KEV: ${d}`, kevDue: (d) => `Deadline for US federal agencies: ${d}`, action: 'Required action',
    links: 'Primary sources', matchCna: 'Product matched by the name declared by the CNA (not yet analyzed by NVD).',
    matchOsv: 'Based on package advisories (OSV / GitHub Advisory).',
    footer: [
      'CVE and CVSS: NVD (This product uses the NVD API but is not endorsed or certified by the NVD.)',
      'EPSS: FIRST.org / KEV: CISA / Package advisories: OSV.dev / Japanese summaries: JVN iPedia',
      'Explanations are generic text generated from CWE and CVSS. Always confirm with the primary sources before acting.',
    ],
  },
};
const t = (k, ...a) => { const v = TXT[S.lang][k]; return typeof v === 'function' ? v(...a) : v; };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const link = (url, text) => (/^https?:\/\//.test(url) ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(text)}</a>` : '');
const SEV_SCORE = { CRITICAL: 9.5, HIGH: 8, MEDIUM: 5.5, LOW: 2 };
const score = (it) => it.cvss?.s ?? SEV_SCORE[it.cvss?.sev] ?? 0;
const fmtDate = (iso) => String(iso || '').slice(0, 10);
const prodName = (id) => S.catalog.find((c) => c.id === id)?.name || id;

// ---------- data ----------
async function getJson(path) {
  const r = await fetch(path, { cache: 'no-cache' });
  if (!r.ok) throw new Error(`${path} ${r.status}`);
  return r.json();
}
async function loadFeed() {
  const ids = [...S.follows].filter((id) => S.catalog.some((c) => c.id === id));
  const lists = await Promise.all(ids.map((id) => getJson(`data/products/${id}.json`).catch(() => [])));
  const map = new Map();
  for (const list of lists) for (const it of list) map.set(it.id, it);
  S.items = [...map.values()];
}
async function loadAll() {
  try {
    [S.meta, S.catalog, S.kev] = await Promise.all([getJson('data/meta.json'), getJson('data/catalog.json'), getJson('data/kev.json')]);
    await loadFeed();
    S.error = '';
  } catch (e) {
    console.error(e);
    S.error = t('loadError');
  }
  render();
}
async function checkUpdate() {
  if (document.hidden) return;
  try {
    const meta = await getJson('data/meta.json');
    if (meta.generatedAt !== S.meta?.generatedAt) await loadAll();
  } catch { /* offline: keep what we have */ }
}

// ---------- feed ----------
function visibleItems() {
  const f = S.f;
  const since = f.days ? Date.now() - f.days * 86400000 : 0;
  const list = S.items.filter((it) =>
    (!since || Date.parse(it.pub) >= since || (it.kev && Date.parse(it.kev.a) >= since))
    && (!f.product || it.p.includes(f.product))
    && (!f.cvss || score(it) >= f.cvss)
    && (!f.epss || (it.epss ?? 0) >= f.epss)
    && (!f.kev || it.kev)
    && (!f.unread || !S.read.has(it.id)));
  const bucket = (it) => Math.round((it.epss ?? 0) * 10);
  // Newest: group by day, then most severe first within the day (KEV, CVSS, EPSS).
  if (f.sort === 'new') list.sort((a, b) => fmtDate(b.pub).localeCompare(fmtDate(a.pub))
    || (!!b.kev - !!a.kev) || (score(b) - score(a)) || ((b.epss ?? 0) - (a.epss ?? 0)) || b.pub.localeCompare(a.pub));
  else list.sort((a, b) => (!!b.kev - !!a.kev) || (bucket(b) - bucket(a)) || (score(b) - score(a)) || b.pub.localeCompare(a.pub));
  return list;
}

function badges(it) {
  const out = [];
  if (it.kev) out.push(`<span class="b kev">${t('kevBadge')}</span>`);
  if (it.kev?.r) out.push(`<span class="b kev">${t('ransom')}</span>`);
  if (it.cvss?.sev) {
    const num = it.cvss.s != null ? ` ${it.cvss.s.toFixed(1)}` : '';
    out.push(`<span class="b s-${esc(it.cvss.sev)}">CVSS${num} ${esc(t('sev')[it.cvss.sev] || it.cvss.sev)}</span>`);
  } else if (!it.vp) out.push('<span class="b plain">CVSS —</span>');
  if (it.epss != null) {
    const top = Math.max((1 - it.pct) * 100, 0.1).toFixed(1);
    out.push(`<span class="b epss${it.epss >= 0.1 ? ' hot' : ''}" title="${esc(t('epssTip', top))}">EPSS ${(it.epss * 100).toFixed(it.epss < 0.1 ? 2 : 1)}%</span>`);
  }
  if (Date.now() - Date.parse(it.pub) < 3 * 86400000) out.push(`<span class="b new">${t('isNew')}</span>`);
  return out.join('');
}

function cardBody(it) {
  const ex = explain(it, S.lang);
  const ja = S.lang === 'ja' ? it.ja : null;
  const h = [];
  h.push(`<h4>${t('summary')}</h4><p>${esc(ja ? ja.d || ja.t : it.en)}</p>`);
  if (ja && it.en) h.push(`<details class="orig"><summary>${t('original')}</summary><p>${esc(it.en)}</p></details>`);
  if (S.lang === 'ja' && !ja && !it.vp) h.push(`<p class="note">${t('noJa')}</p>`);

  h.push(`<h4>${t('what')}</h4>`);
  if (!ex.types.length) h.push(`<p class="note">${esc(ex.noCwe)}</p>`);
  for (const ty of ex.types) {
    const cwe = link(`https://cwe.mitre.org/data/definitions/${ty.id.replace('CWE-', '')}.html`, ty.id);
    if (!ty.how) { h.push(`<p class="note">${cwe} ${esc(ty.name.replace(ty.id, ''))}</p>`); continue; }
    h.push(`<div class="type"><b>${esc(ty.name)}</b> <span class="note">${cwe}</span>`);
    if (ty.how) h.push(`<dl><dt>${t('how')}</dt><dd>${esc(ty.how)}</dd><dt>${t('impact')}</dt><dd>${esc(ty.impact)}</dd></dl>`);
    h.push('</div>');
  }
  if (ex.conditions.length) {
    h.push(`<h4>${t('conditions')}</h4><ul>${ex.conditions.map((c) => `<li>${esc(c)}</li>`).join('')}</ul>`);
  }
  if (ex.effects.length) {
    h.push(`<h4>${t('effects')}</h4><div class="pills">${ex.effects.map(([l, v, code]) => `<span class="pill l-${esc(code)}">${esc(l)}: ${esc(v)}</span>`).join('')}</div>`);
    if (ex.scope) h.push(`<p class="note">${esc(ex.scope)}</p>`);
    if (it.cvss?.v) h.push(`<p class="mono note">${esc(it.cvss.v)}</p>`);
  }
  if (it.aff?.some((a) => a[1])) {
    const by = new Map();
    for (const [id, range] of it.aff) if (range) by.set(id, [...(by.get(id) || []), range]);
    h.push(`<h4>${t('versions')}</h4><ul>${[...by].map(([id, r]) => `<li>${esc(prodName(id))}: <span class="mono">${esc(r.join(' , '))}</span></li>`).join('')}</ul>`);
  }
  if (it.fix?.length) h.push(`<h4>${t('fixed')}</h4><p class="mono">${esc(it.fix.join(' , '))}</p>`);
  if (it.kev) {
    h.push(`<h4>${t('kevInfo')}</h4><ul><li>${esc(t('kevAdded', it.kev.a))}</li>${it.kev.due ? `<li>${esc(t('kevDue', it.kev.due))}</li>` : ''}</ul>`);
    if (it.act) h.push(`<h4>${t('action')}</h4><p>${esc(it.act)}</p>`);
  }
  const links = [];
  if (it.id.startsWith('CVE-')) {
    links.push(link(`https://nvd.nist.gov/vuln/detail/${it.id}`, 'NVD'), link(`https://www.cve.org/CVERecord?id=${it.id}`, 'CVE.org'));
  } else links.push(link(`https://osv.dev/vulnerability/${it.id}`, 'OSV'));
  if (it.ja?.u) links.push(link(it.ja.u, 'JVN iPedia'));
  for (const u of it.refs || []) { try { links.push(link(u, new URL(u).hostname)); } catch { /* skip malformed URL */ } }
  h.push(`<h4>${t('links')}</h4><div class="links">${links.join('')}</div>`);
  if (it.how === 'cna') h.push(`<p class="note">${t('matchCna')}</p>`);
  if (it.how === 'osv') h.push(`<p class="note">${t('matchOsv')}</p>`);
  return h.join('');
}

function card(it) {
  const ja = S.lang === 'ja' ? it.ja : null;
  const en = it.en || '';
  const title = ja?.t || it.t || (en.length > 150 ? en.slice(0, 150).replace(/\s+\S*$/, '') + '…' : en);
  const prods = it.vp ? `<span class="prod">${esc(it.vp)}</span>` : (it.p || []).map((id) => `<span class="prod">${esc(prodName(id))}</span>`).join('');
  return `<details class="card s-${esc(it.cvss?.sev || '')}${S.read.has(it.id) ? '' : ' unread'}" data-id="${esc(it.id)}">
<summary><div class="badges">${badges(it)}</div>
<div class="head"><span class="id">${esc(it.id)}</span>${prods}<time>${esc(fmtDate(it.pub))}</time></div>
<div class="title">${esc(title)}</div></summary>
<div class="body" data-body></div></details>`;
}

function select(key, options) {
  return `<select data-f="${key}">${options.map(([v, label]) => `<option value="${esc(v)}"${String(S.f[key]) === String(v) ? ' selected' : ''}>${esc(label)}</option>`).join('')}</select>`;
}
function feedView() {
  if (!S.follows.size) return `<p class="empty">${t('emptyFollow')}</p>`;
  const list = visibleItems();
  const unread = list.filter((it) => !S.read.has(it.id)).length;
  const followed = S.catalog.filter((c) => S.follows.has(c.id));
  const any = t('anyScore');
  return `<div class="filters">
<label>${t('days')} ${select('days', [[7, t('d7')], [30, t('d30')], [90, t('d90')], [0, t('dAll')]])}</label>
<label>${t('product')} ${select('product', [['', t('allProducts')], ...followed.map((c) => [c.id, c.name])])}</label>
<label>CVSS ${select('cvss', [[0, any], [4, '4.0+'], [7, '7.0+'], [9, '9.0+']])}</label>
<label>EPSS ${select('epss', [[0, any], [0.01, '1%+'], [0.1, '10%+'], [0.5, '50%+']])}</label>
<label><input type="checkbox" data-f="kev"${S.f.kev ? ' checked' : ''}> ${t('kevOnly')}</label>
<label><input type="checkbox" data-f="unread"${S.f.unread ? ' checked' : ''}> ${t('unreadOnly')}</label>
<label>${t('sort')} ${select('sort', [['priority', t('sPriority')], ['new', t('sNew')]])}</label>
</div>
<p class="count"><span id="count">${t('showing', list.length, unread)}</span>${unread ? ` · <button class="btn" data-act="markAll">${t('markAll')}</button>` : ''}</p>
${list.length ? list.slice(0, S.limit).map(card).join('') : `<p class="empty">${t('emptyFilter')}</p>`}
${list.length > S.limit ? `<button class="btn more" data-act="more">${t('more')}</button>` : ''}`;
}
function kevView() {
  return `<p class="lead note">${t('kevLead')}</p>${S.kev.map(card).join('')}`;
}
function settingsView() {
  const cats = Object.keys(t('cat'));
  return `<p class="lead">${t('settingsLead')}</p>
<input class="search" type="search" placeholder="${esc(t('search'))}" data-search>
<p class="count"><span id="following">${t('following', S.follows.size)}</span> · <button class="btn primary" data-act="toFeed">${t('toFeed')}</button></p>
${cats.map((cat) => `<section class="cat"><h3>${esc(t('cat')[cat])}</h3><div class="chips">${S.catalog.filter((c) => c.cat === cat).map((c) =>
    `<label class="chip" data-name="${esc(c.name.toLowerCase())}"><input type="checkbox" data-follow="${esc(c.id)}"${S.follows.has(c.id) ? ' checked' : ''}>${esc(c.name)} <small>${S.meta?.counts?.[c.id] ?? 0}</small></label>`).join('')}</div></section>`).join('')}`;
}

// ---------- shell ----------
const app = document.getElementById('app');
function render() {
  document.documentElement.lang = S.lang;
  const failed = Object.entries(S.meta?.sources || {}).filter(([, v]) => !v.ok).map(([k]) => k.toUpperCase());
  const updated = S.meta ? new Date(S.meta.generatedAt).toLocaleString(S.lang === 'ja' ? 'ja-JP' : 'en-US', { dateStyle: 'medium', timeStyle: 'short' }) : '—';
  const unread = S.items.filter((it) => !S.read.has(it.id)).length;
  const tab = (id, label, n) => `<button role="tab" aria-selected="${S.tab === id}" data-tab="${id}">${label}${n ? `<span class="n">${n}</span>` : ''}</button>`;
  const view = S.error ? `<p class="empty">${esc(S.error)}</p>` : S.tab === 'kev' ? kevView() : S.tab === 'settings' ? settingsView() : feedView();
  app.innerHTML = `<div class="wrap">
<header class="top"><h1>VulnWatch</h1><span class="updated">${esc(t('updated', updated))}</span>
<button class="btn" data-act="lang" aria-label="Switch language">${S.lang === 'ja' ? 'English' : '日本語'}</button></header>
<p class="note lead">${t('tagline')}</p>
${failed.length ? `<div class="banner">${esc(t('sourceDown', failed.join(', ')))}</div>` : ''}
<nav class="tabs" role="tablist">${tab('feed', t('feed'), unread)}${tab('kev', t('kevTab'))}${tab('settings', t('settings'), S.follows.size)}</nav>
<main>${view}</main>
<footer>${t('footer').map((l) => `<p>${esc(l)}</p>`).join('')}</footer></div>`;
}

function markRead(ids) {
  for (const id of ids) S.read.add(id);
  if (S.read.size > 8000) S.read = new Set([...S.read].slice(-8000));
  save('read', [...S.read]);
}
const findItem = (id) => S.items.find((it) => it.id === id) || S.kev.find((it) => it.id === id);

app.addEventListener('click', (e) => {
  const tabBtn = e.target.closest('[data-tab]');
  if (tabBtn) { S.tab = tabBtn.dataset.tab; S.limit = 50; render(); return; }
  const act = e.target.closest('[data-act]')?.dataset.act;
  if (act === 'lang') { S.lang = S.lang === 'ja' ? 'en' : 'ja'; save('lang', S.lang); render(); }
  if (act === 'more') { S.limit += 50; render(); }
  if (act === 'markAll') { markRead(visibleItems().map((it) => it.id)); render(); }
  if (act === 'toFeed') { S.tab = 'feed'; render(); }
});
app.addEventListener('change', async (e) => {
  const el = e.target;
  if (el.dataset.f) {
    const key = el.dataset.f;
    S.f[key] = el.type === 'checkbox' ? el.checked : (typeof S.f[key] === 'number' ? Number(el.value) : el.value);
    save('filters', S.f);
    S.limit = 50;
    render();
  } else if (el.dataset.follow) {
    if (el.checked) S.follows.add(el.dataset.follow); else S.follows.delete(el.dataset.follow);
    save('follows', [...S.follows]);
    if (!S.follows.has(S.f.product)) S.f.product = '';
    document.getElementById('following').textContent = t('following', S.follows.size);
    await loadFeed();
  }
});
app.addEventListener('input', (e) => {
  if (!('search' in e.target.dataset)) return;
  const q = e.target.value.trim().toLowerCase();
  for (const chip of app.querySelectorAll('.chip')) chip.hidden = !!q && !chip.dataset.name.includes(q);
});
// "toggle" does not bubble, so listen in the capture phase. The body is built lazily on first open.
app.addEventListener('toggle', (e) => {
  const el = e.target;
  if (!el.classList?.contains('card') || !el.open) return;
  const it = findItem(el.dataset.id);
  const body = el.querySelector('[data-body]');
  if (it && !body.firstChild) body.innerHTML = cardBody(it);
  if (el.classList.contains('unread')) {
    markRead([el.dataset.id]);
    el.classList.remove('unread');
  }
}, true);

setInterval(checkUpdate, 10 * 60 * 1000);
document.addEventListener('visibilitychange', checkUpdate);
loadAll();

import { explain } from './explain.js';

// ---------- state (everything personal stays in localStorage) ----------
const LS = 'vw:';
const load = (k, d) => { try { return JSON.parse(localStorage.getItem(LS + k)) ?? d; } catch { return d; } };
const save = (k, v) => { try { localStorage.setItem(LS + k, JSON.stringify(v)); } catch { /* storage full or blocked */ } };

const S = {
  lang: load('lang', (navigator.language || '').startsWith('ja') ? 'ja' : 'en'),
  theme: load('theme', matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'),
  follows: new Set(load('follows', [])),
  read: new Set(load('read', [])),
  f: { days: 30, cvss: 0, epss: 0, kev: false, unread: false, products: [], sort: 'priority', ...load('filters', {}) },
  fx: load('fx', true),
  tab: 'feed', catalog: [], meta: null, items: [], kev: [], limit: 50, error: '', failed: [], onlySel: false, howto: null,
};
if (!Array.isArray(S.f.products)) S.f.products = [];
if (!S.follows.size) S.tab = 'settings';

const TXT = {
  ja: {
    tagline: 'フォローした製品の脆弱性を、深刻度と悪用予測つきで確認',
    updated: (d) => `データ更新: ${d}`, feed: 'フィード', kevTab: '悪用確認済み（KEV）', settings: 'フォロー設定',
    sourceDown: (s) => `一部のデータ元の取得に失敗しています（${s}）。表示は前回取得分です。`,
    loadError: 'データを読み込めませんでした。時間をおいて再読み込みしてください。',
    productDown: (s) => `一部の製品のデータを読み込めませんでした（${s}）。自動で再試行します。`,
    days: '期間', d7: '7日', d30: '30日', d90: '90日', dAll: 'すべて', anyScore: '指定なし',
    product: '製品', allProducts: 'すべて', kevOnly: '悪用確認済み（KEV）のみ', unreadOnly: '未読のみ',
    fCvss: '深刻度（CVSS）', fEpss: '悪用予測（EPSS）', noScore: '未評価',
    sort: '並び順', sPriority: '優先度順', sNew: '新しい順',
    sPriorityHint: 'KEV → EPSS → CVSS の順に優先します', sNewHint: '同じ日の中は深刻度の高い順に並べます',
    markAll: (n) => `未読 ${n} 件をすべて既読にする`, markUnread: '未読に戻す',
    showing: (n, u) => `${n} 件（未読 ${u} 件）`, more: 'さらに表示',
    emptyFollow: 'まだ製品をフォローしていません。', toSettings: 'フォロー設定を開く',
    emptyFilter: '条件に合う脆弱性はありません。', applied: '適用中の条件', clearFilters: 'フィルターを解除',
    pubDate: '公開日', kevDate: 'KEV掲載日', glossary: '用語の説明',
    gloss: [
      ['深刻度（CVSS）', '脆弱性そのものの重大さを 0〜10 で表した点数です。9.0 以上が「緊急」、7.0 以上が「重要」です。'],
      ['悪用予測（EPSS）', '今後 30 日以内に実際の攻撃で悪用される確率の予測です。数値が高いほど狙われやすいことを示します。'],
      ['悪用確認済み（KEV）', '米国 CISA が、実際の攻撃で悪用されたと確認した脆弱性の一覧です。掲載されたものは優先して対応します。'],
    ],
    toLight: 'ライト表示', toDark: 'ダーク表示', fxOff: '雷をオフ', fxOn: '雷をオン',
    howto: '使い方', source: 'ソースコード（GitHub・MIT ライセンス）',
    howtoSteps: [
      '「フォロー設定」で、使っている言語・サーバ・フレームワークなどを選びます。',
      '「フィード」に、選んだ製品の脆弱性が深刻度と悪用予測つきで並びます。カードを開くと、攻撃手法・想定される被害・修正版を確認できます。',
      '開いたカードは既読になります。データは定期的に（約30分ごと）自動で更新されます。',
    ],
    privacy: 'フォロー設定・既読・表示の設定は、すべてこのブラウザの中だけに保存されます。アカウント登録は不要で、サーバ側のデータベースには何も保存していません。そのため、別のブラウザや端末には設定が引き継がれません。',
    mtButton: '日本語に翻訳', mtHint: '初回は翻訳データをダウンロードします。翻訳はブラウザ内で行われ、外部には送信されません。',
    mtBusy: (p) => (p == null ? '翻訳中…' : `翻訳データをダウンロード中… ${p}%`),
    mtNote: 'ブラウザの機能による機械翻訳です。正確な内容は原文で確認してください。', mtFail: '翻訳できませんでした。',
    onlySel: '選択中のみ表示', catSel: (n, total) => `選択 ${n} / ${total}`, countLabel: '収録件数',
    kevLead: 'CISA が「実際に悪用されている」と確認した脆弱性の新着です（フォロー設定に関係なく全製品）。',
    settingsLead: 'チェックしたい製品を選んでください。選択はこのブラウザだけに保存されます。製品名の横の数字は収録件数です。',
    search: '製品名で絞り込み', following: (n) => `フォロー中 ${n} 件`, toFeed: 'フィードを見る',
    cat: { lang: '言語・ランタイム', web: 'Webサーバ・プロキシ', db: 'データベース', os: 'OS', fw: 'フレームワーク・ライブラリ', infra: 'ミドルウェア・基盤ツール' },
    sev: { CRITICAL: '緊急', HIGH: '重要', MEDIUM: '警告', LOW: '注意', NONE: 'なし' },
    kevBadge: '悪用確認済み（KEV）', ransom: 'ランサムウェアで悪用', isNew: 'NEW',
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
    updated: (d) => `Data updated: ${d}`, feed: 'Feed', kevTab: 'Known exploited (KEV)', settings: 'Follow settings',
    sourceDown: (s) => `Some sources failed to update (${s}). Showing the previous data for them.`,
    loadError: 'Could not load the data. Please reload in a while.',
    productDown: (s) => `Could not load the data for some products (${s}). Retrying automatically.`,
    days: 'Period', d7: '7 days', d30: '30 days', d90: '90 days', dAll: 'All', anyScore: 'Any',
    product: 'Product', allProducts: 'All', kevOnly: 'Known exploited (KEV) only', unreadOnly: 'Unread only',
    fCvss: 'Severity (CVSS)', fEpss: 'Exploit prediction (EPSS)', noScore: 'not scored',
    sort: 'Sort', sPriority: 'By priority', sNew: 'Newest first',
    sPriorityHint: 'Ranks by KEV, then EPSS, then CVSS', sNewHint: 'Most severe first within each day',
    markAll: (n) => `Mark all ${n} unread as read`, markUnread: 'Mark as unread',
    showing: (n, u) => `${n} items (${u} unread)`, more: 'Show more',
    emptyFollow: 'You are not following any product yet.', toSettings: 'Open follow settings',
    emptyFilter: 'No vulnerabilities match these filters.', applied: 'Active filters', clearFilters: 'Clear filters',
    pubDate: 'Published', kevDate: 'Added to KEV', glossary: 'What these terms mean',
    gloss: [
      ['Severity (CVSS)', 'A 0–10 score for how serious the flaw itself is. 9.0 and above is Critical, 7.0 and above is High.'],
      ['Exploit prediction (EPSS)', 'The predicted probability that the flaw is exploited in real attacks within the next 30 days. Higher means more likely to be targeted.'],
      ['Known exploited (KEV)', 'The CISA list of flaws confirmed to be exploited in real attacks. Listed flaws should be handled first.'],
    ],
    toLight: 'Light mode', toDark: 'Dark mode', fxOff: 'Lightning off', fxOn: 'Lightning on',
    howto: 'How to use', source: 'Source code (GitHub, MIT License)',
    howtoSteps: [
      'Under "Follow settings", pick the languages, servers and frameworks you run.',
      'The "Feed" lists their vulnerabilities with severity and exploit prediction. Open a card for the attack technique, the impact and the fixed versions.',
      'Opened cards are marked as read. The data refreshes automatically, about every 30 minutes.',
    ],
    privacy: 'Your follows, read marks and display settings are stored only inside this browser. There is no account, and nothing is stored in a server-side database, so your settings do not carry over to another browser or device.',
    mtButton: '', mtHint: '', mtBusy: () => '', mtNote: '', mtFail: '',
    onlySel: 'Selected only', catSel: (n, total) => `${n} of ${total} selected`, countLabel: 'Entries',
    kevLead: 'Latest vulnerabilities that CISA confirmed as exploited in the wild (all products, regardless of what you follow).',
    settingsLead: 'Choose the products you want to watch. Your selection is stored only in this browser. The number next to each product is how many entries it has.',
    search: 'Filter by product name', following: (n) => `Following ${n}`, toFeed: 'Open feed',
    cat: { lang: 'Languages & runtimes', web: 'Web servers & proxies', db: 'Databases', os: 'Operating systems', fw: 'Frameworks & libraries', infra: 'Middleware & infrastructure tools' },
    sev: { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', NONE: 'None' },
    kevBadge: 'Known exploited (KEV)', ransom: 'Used in ransomware', isNew: 'NEW',
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
// Colour class per product: catalog order spread over 24 hues, so neighbours differ (inline styles are blocked by the CSP).
const prodClass = (key) => {
  const i = S.catalog.findIndex((c) => c.id === key);
  return `pc-${(i >= 0 ? i * 7 : [...String(key)].reduce((h, c) => (h * 31 + c.charCodeAt(0)) >>> 0, 7)) % 24}`;
};

// ---------- data ----------
async function getJson(path) {
  const r = await fetch(path, { cache: 'no-cache' });
  if (!r.ok) throw new Error(`${path} ${r.status}`);
  return r.json();
}
const cache = new Map(); // product id -> items from its last successful fetch
const stale = new Set(); // product ids whose last fetch failed
let feedGen = 0;
async function loadFeed(refresh) {
  const gen = ++feedGen;
  const ids = [...S.follows].filter((id) => S.catalog.some((c) => c.id === id));
  await Promise.all(ids.map(async (id) => {
    if (!refresh && cache.has(id) && !stale.has(id)) return;
    try {
      cache.set(id, await getJson(`data/products/${id}.json`));
      stale.delete(id);
    } catch (e) {
      // Keep the previous data for this product and retry on the next check.
      console.error(e);
      stale.add(id);
    }
  }));
  if (gen !== feedGen) return; // a newer call owns the result
  const map = new Map();
  for (const id of ids) for (const it of cache.get(id) || []) map.set(it.id, it);
  S.items = [...map.values()];
  S.failed = ids.filter((id) => stale.has(id));
}
async function loadAll() {
  try {
    [S.meta, S.catalog, S.kev] = await Promise.all([getJson('data/meta.json'), getJson('data/catalog.json'), getJson('data/kev.json')]);
    await loadFeed(true);
    S.error = '';
  } catch (e) {
    console.error(e);
    if (!S.meta) S.error = t('loadError'); // keep showing what is already loaded
  }
  render();
}
async function checkUpdate() {
  if (document.hidden) return;
  try {
    const meta = await getJson('data/meta.json');
    if (meta.generatedAt !== S.meta?.generatedAt) await loadAll();
    else if (S.failed.length) { await loadFeed(); render(); }
  } catch { /* offline: keep what we have */ }
}

// ---------- in-browser translation (Translator API in desktop Chrome / Edge; the text never leaves the device) ----------
const MT = { sourceLanguage: 'en', targetLanguage: 'ja' };
const canTranslate = 'Translator' in self;
const translated = new Map(); // item id -> Japanese text
let translator = null; // promise, once created in this page session
const mtDone = (it) => `<p>${esc(translated.get(it.id))}</p><p class="note">${t('mtNote')}</p>
<details class="orig"><summary>${t('original')}</summary><p>${esc(it.en)}</p></details>`;
// `asked` is true for the button; opening a card only translates when no download is needed.
async function translateInto(box, it, asked) {
  const status = box.querySelector('[data-mt-status]');
  try {
    if (!translated.has(it.id)) {
      if (!translator) {
        if (asked) status.textContent = t('mtBusy');
        // Some embedded browsers expose the API but never answer: give up instead of hanging.
        const state = await Promise.race([Translator.availability(MT), new Promise((_, no) => setTimeout(() => no(new Error('Translator timeout')), 8000))]);
        if (state === 'unavailable') { box.querySelector('.mt')?.remove(); return; }
        if (!asked && state !== 'available') return;
        const monitor = (m) => m.addEventListener('downloadprogress', (e) => { status.textContent = t('mtBusy', Math.floor(e.loaded * 100)); });
        translator = Translator.create({ ...MT, monitor });
        translator.catch(() => { translator = null; });
      }
      box.querySelector('button').disabled = true;
      status.textContent = t('mtBusy');
      translated.set(it.id, await (await translator).translate(it.en));
    }
    box.innerHTML = mtDone(it);
  } catch (e) {
    console.error(e);
    if (!box.isConnected || !status.isConnected) return;
    box.querySelector('button').disabled = false;
    // Without a user gesture create() is refused: leave the button for the user to press.
    status.textContent = asked ? t('mtFail') : t('mtHint');
  }
}

// ---------- feed ----------
function visibleItems() {
  const f = S.f;
  const since = f.days ? Date.now() - f.days * 86400000 : 0;
  const list = S.items.filter((it) =>
    (!since || Date.parse(it.pub) >= since || (it.kev && Date.parse(it.kev.a) >= since))
    && (!f.products.length || it.p.some((p) => f.products.includes(p)))
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
    out.push(`<span class="b s-${esc(it.cvss.sev)}">${t('fCvss')}${num} ${esc(t('sev')[it.cvss.sev] || it.cvss.sev)}</span>`);
  } else if (!it.vp) out.push(`<span class="b plain">${t('fCvss')} ${t('noScore')}</span>`);
  if (it.epss != null) {
    const top = Math.max((1 - it.pct) * 100, 0.1).toFixed(1);
    out.push(`<span class="b epss${it.epss >= 0.1 ? ' hot' : ''}" title="${esc(t('epssTip', top))}">${t('fEpss')} ${(it.epss * 100).toFixed(it.epss < 0.1 ? 2 : 1)}%</span>`);
  }
  if (Date.now() - Date.parse(it.pub) < 3 * 86400000) out.push(`<span class="b new">${t('isNew')}</span>`);
  return out.join('');
}

function cardBody(it) {
  const ex = explain(it, S.lang);
  const ja = S.lang === 'ja' ? it.ja : null;
  const h = [];
  const mt = S.lang === 'ja' && !ja && it.en && canTranslate;
  if (mt && translated.has(it.id)) h.push(`<h4>${t('summary')}</h4><div data-mt>${mtDone(it)}</div>`);
  else if (mt) h.push(`<h4>${t('summary')}</h4><div data-mt><p>${esc(it.en)}</p>
<p class="mt"><button class="btn" data-act="translate">${t('mtButton')}</button> <span class="note" data-mt-status>${t('mtHint')}</span></p></div>`);
  else h.push(`<h4>${t('summary')}</h4><p>${esc(ja ? ja.d || ja.t : it.en)}</p>`);
  if (ja && it.en) h.push(`<details class="orig"><summary>${t('original')}</summary><p>${esc(it.en)}</p></details>`);
  if (S.lang === 'ja' && !ja && !it.vp && !mt) h.push(`<p class="note">${t('noJa')}</p>`);

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
  h.push(`<p class="actions"><button class="btn" data-act="unread">${t('markUnread')}</button></p>`);
  return h.join('');
}

function card(it) {
  const ja = S.lang === 'ja' ? it.ja : null;
  const en = it.en || '';
  const title = ja?.t || it.t || (en.length > 150 ? en.slice(0, 150).replace(/\s+\S*$/, '') + '…' : en);
  // Followed products first and prominent; other matched products stay muted.
  const ids = [...(it.p || [])].sort((a, b) => S.follows.has(b) - S.follows.has(a));
  const prods = it.vp ? `<span class="pname ${prodClass(it.vp)}">${esc(it.vp)}</span>`
    : ids.map((id) => `<span class="pname ${S.follows.has(id) ? prodClass(id) : 'other'}">${esc(prodName(id))}</span>`).join('');
  // KEV-tab records only carry the date they were added to KEV.
  const dates = it.vp ? `<time>${t('kevDate')} ${esc(fmtDate(it.kev?.a || it.pub))}</time>`
    : `<time>${t('pubDate')} ${esc(fmtDate(it.pub))}</time>${it.kev ? `<time>${t('kevDate')} ${esc(fmtDate(it.kev.a))}</time>` : ''}`;
  return `<details class="card s-${esc(it.cvss?.sev || '')}${S.read.has(it.id) ? '' : ' unread'}" data-id="${esc(it.id)}">
<summary><div class="prods">${prods}</div>
<div class="badges">${badges(it)}</div>
<div class="head"><span class="id">${esc(it.id)}</span>${dates}</div>
<div class="title">${esc(title)}</div></summary>
<div class="body" data-body></div></details>`;
}

function select(key, options) {
  return `<select data-f="${key}">${options.map(([v, label]) => `<option value="${esc(v)}"${String(S.f[key]) === String(v) ? ' selected' : ''}>${esc(label)}</option>`).join('')}</select>`;
}
const field = (label, control) => `<label class="field"><span>${esc(label)}</span>${control}</label>`;
const glossary = () => `<details class="glossary"><summary>${t('glossary')}</summary><dl>${t('gloss').map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl></details>`;
const DAY_OPTS = () => [[7, t('d7')], [30, t('d30')], [90, t('d90')], [0, t('dAll')]];
// Filters currently narrowing the list, as short labels.
function activeFilters() {
  const f = S.f;
  const out = [];
  if (f.days) out.push(`${t('days')}: ${DAY_OPTS().find(([v]) => v === f.days)?.[1] ?? f.days}`);
  if (f.products.length) out.push(`${t('product')}: ${f.products.map(prodName).join(', ')}`);
  if (f.cvss) out.push(`${t('fCvss')} ${f.cvss.toFixed(1)}+`);
  if (f.epss) out.push(`${t('fEpss')} ${f.epss * 100}%+`);
  if (f.kev) out.push(t('kevOnly'));
  if (f.unread) out.push(t('unreadOnly'));
  return out;
}
function feedView() {
  if (!S.follows.size) return `<div class="empty"><p>${t('emptyFollow')}</p><button class="btn primary" data-tab="settings">${t('toSettings')}</button></div>`;
  const list = visibleItems();
  const unread = list.filter((it) => !S.read.has(it.id)).length;
  const followed = S.catalog.filter((c) => S.follows.has(c.id));
  const any = t('anyScore');
  const active = activeFilters();
  const empty = `<div class="empty"><p>${t('emptyFilter')}</p>${active.length
    ? `<p class="note">${t('applied')}: ${esc(active.join(' / '))}</p><button class="btn primary" data-act="clear">${t('clearFilters')}</button>` : ''}</div>`;
  // Product filter: the followed products as chips; none selected means all.
  const chip = (c) => `<label class="chip"><input type="checkbox" data-fp="${esc(c.id)}"${S.f.products.includes(c.id) ? ' checked' : ''}>${esc(c.name)}</label>`;
  return `<div class="pfilter"><span>${t('product')}</span><div class="chips">
<label class="chip"><input type="checkbox" data-fp=""${S.f.products.length ? '' : ' checked'}>${t('allProducts')}</label>${followed.map(chip).join('')}</div></div>
<div class="filters">
${field(t('days'), select('days', DAY_OPTS()))}
${field(t('fCvss'), select('cvss', [[0, any], [4, '4.0+'], [7, '7.0+'], [9, '9.0+']]))}
${field(t('fEpss'), select('epss', [[0, any], [0.01, '1%+'], [0.1, '10%+'], [0.5, '50%+']]))}
<div class="checks">
<label><input type="checkbox" data-f="kev"${S.f.kev ? ' checked' : ''}> ${t('kevOnly')}</label>
<label><input type="checkbox" data-f="unread"${S.f.unread ? ' checked' : ''}> ${t('unreadOnly')}</label>
</div>
</div>
${glossary()}
<div class="listbar">
<p class="count"><span id="count">${t('showing', list.length, unread)}</span><button class="btn" id="markAll" data-act="markAll"${unread ? '' : ' hidden'}>${t('markAll', unread)}</button></p>
<div class="sortbox">${field(t('sort'), select('sort', [['priority', t('sPriority')], ['new', t('sNew')]]))}
<small class="hint">${t(S.f.sort === 'new' ? 'sNewHint' : 'sPriorityHint')}</small></div>
</div>
${list.length ? list.slice(0, S.limit).map(card).join('') : empty}
${list.length > S.limit ? `<button class="btn more" data-act="more">${t('more')}</button>` : ''}`;
}
function kevView() {
  return `<p class="lead note">${t('kevLead')}</p>${glossary()}${S.kev.map(card).join('')}`;
}
function settingsView() {
  const cats = Object.keys(t('cat'));
  return `<p class="lead">${t('settingsLead')}</p>
<div class="setbar"><input class="search" type="search" placeholder="${esc(t('search'))}" data-search>
<label class="only"><input type="checkbox" data-only${S.onlySel ? ' checked' : ''}> ${t('onlySel')}</label></div>
${cats.map((cat) => `<section class="cat"><h3>${esc(t('cat')[cat])} <small data-catn></small></h3><div class="chips">${S.catalog.filter((c) => c.cat === cat).map((c) => {
    const n = S.meta?.counts?.[c.id] ?? 0;
    return `<label class="chip" data-name="${esc(c.name.toLowerCase())}"><input type="checkbox" data-follow="${esc(c.id)}"${S.follows.has(c.id) ? ' checked' : ''}>${esc(c.name)} <small title="${esc(t('countLabel'))}" aria-label="${esc(t('countLabel'))} ${n}">${n}</small></label>`;
  }).join('')}</div></section>`).join('')}
<div class="stickybar"><span id="following">${t('following', S.follows.size)}</span><button class="btn primary" data-act="toFeed">${t('toFeed')}</button></div>`;
}
// Settings: per-category selection counts, plus search / "selected only" visibility.
function applyChips(visibility = true) {
  const q = (app.querySelector('[data-search]')?.value || '').trim().toLowerCase();
  for (const sec of app.querySelectorAll('.cat')) {
    const chips = [...sec.querySelectorAll('.chip')];
    const on = (chip) => chip.querySelector('input').checked;
    if (visibility) {
      for (const chip of chips) chip.hidden = (!!q && !chip.dataset.name.includes(q)) || (S.onlySel && !on(chip));
      sec.hidden = chips.every((chip) => chip.hidden);
    }
    sec.querySelector('[data-catn]').textContent = t('catSel', chips.filter(on).length, chips.length);
  }
}
// Update the unread numbers in place, without rebuilding the list.
function refreshCounts() {
  const badge = app.querySelector('[data-n="feed"]');
  const n = S.items.filter((it) => !S.read.has(it.id)).length;
  if (badge) { badge.textContent = n; badge.hidden = !n; }
  const count = document.getElementById('count');
  if (!count) return;
  const list = visibleItems();
  const unread = list.filter((it) => !S.read.has(it.id)).length;
  count.textContent = t('showing', list.length, unread);
  const btn = document.getElementById('markAll');
  btn.textContent = t('markAll', unread);
  btn.hidden = !unread;
}

// ---------- shell ----------
const app = document.getElementById('app');
function render() {
  document.documentElement.lang = S.lang;
  const failed = Object.entries(S.meta?.sources || {}).filter(([, v]) => !v.ok).map(([k]) => k.toUpperCase());
  const updated = S.meta ? new Date(S.meta.generatedAt).toLocaleString(S.lang === 'ja' ? 'ja-JP' : 'en-US', { dateStyle: 'medium', timeStyle: 'short' }) : '—';
  const unread = S.items.filter((it) => !S.read.has(it.id)).length;
  const tab = (id, label, n) => `<button role="tab" aria-selected="${S.tab === id}" data-tab="${id}">${label}${n != null ? `<span class="n" data-n="${id}"${n ? '' : ' hidden'}>${n}</span>` : ''}</button>`;
  const view = S.error ? `<p class="empty">${esc(S.error)}</p>` : S.tab === 'kev' ? kevView() : S.tab === 'settings' ? settingsView() : feedView();
  app.innerHTML = `<div class="wrap">
<header class="top"><h1><svg class="bolt" viewBox="0 0 24 24" aria-hidden="true"><path d="M13 2 4 14h6l-1 8 9-12h-6z"/></svg>VulnWatch</h1><span class="updated">${esc(t('updated', updated))}</span>
<button class="btn" data-act="fx" aria-pressed="${S.fx}">⚡ ${t(S.fx ? 'fxOff' : 'fxOn')}</button>
<button class="btn" data-act="theme">${S.theme === 'dark' ? `☀ ${t('toLight')}` : `☾ ${t('toDark')}`}</button>
<button class="btn" data-act="lang" aria-label="Switch language">${S.lang === 'ja' ? 'English' : '日本語'}</button></header>
<p class="note lead">${t('tagline')}</p>
<details class="howto"${(S.howto ?? !S.follows.size) ? ' open' : ''}><summary>${t('howto')}</summary>
<ol>${t('howtoSteps').map((l) => `<li>${esc(l)}</li>`).join('')}</ol><p class="privacy">${esc(t('privacy'))}</p></details>
${failed.length ? `<div class="banner">${esc(t('sourceDown', failed.join(', ')))}</div>` : ''}
${S.failed.length ? `<div class="banner">${esc(t('productDown', S.failed.map(prodName).join(', ')))}</div>` : ''}
<nav class="tabs" role="tablist">${tab('feed', t('feed'), unread)}${tab('kev', t('kevTab'))}${tab('settings', t('settings'), S.follows.size)}</nav>
<main>${view}</main>
<footer>${t('footer').map((l) => `<p>${esc(l)}</p>`).join('')}<p>${link('https://github.com/mizumotter/vuln-watch', t('source'))}</p></footer></div>`;
  if (S.tab === 'settings' && !S.error) applyChips();
}

function markRead(ids) {
  for (const id of ids) S.read.add(id);
  if (S.read.size > 8000) S.read = new Set([...S.read].slice(-8000));
  save('read', [...S.read]);
}
const findItem = (id) => S.items.find((it) => it.id === id) || S.kev.find((it) => it.id === id);

app.addEventListener('click', (e) => {
  // Remember a manual open/close of the how-to box (the click runs before the state flips).
  const howto = e.target.closest('.howto > summary');
  if (howto) S.howto = !howto.parentElement.open;
  const tabBtn = e.target.closest('[data-tab]');
  if (tabBtn) { S.tab = tabBtn.dataset.tab; S.limit = 50; render(); return; }
  const act = e.target.closest('[data-act]')?.dataset.act;
  if (act === 'lang') { S.lang = S.lang === 'ja' ? 'en' : 'ja'; save('lang', S.lang); render(); }
  if (act === 'fx') {
    S.fx = !S.fx;
    save('fx', S.fx);
    document.documentElement.dataset.fx = S.fx ? 'on' : 'off';
    render();
  }
  if (act === 'theme') {
    S.theme = S.theme === 'dark' ? 'light' : 'dark';
    save('theme', S.theme);
    document.documentElement.dataset.theme = S.theme;
    render();
  }
  if (act === 'more') { S.limit += 50; render(); }
  if (act === 'markAll') { markRead(visibleItems().map((it) => it.id)); render(); }
  if (act === 'toFeed') { S.tab = 'feed'; render(); }
  if (act === 'clear') {
    Object.assign(S.f, { days: 0, products: [], cvss: 0, epss: 0, kev: false, unread: false });
    save('filters', S.f);
    S.limit = 50;
    render();
  }
  if (act === 'translate') {
    const cardEl = e.target.closest('.card');
    translateInto(cardEl.querySelector('[data-mt]'), findItem(cardEl.dataset.id), true);
  }
  if (act === 'unread') {
    const cardEl = e.target.closest('.card');
    S.read.delete(cardEl.dataset.id);
    save('read', [...S.read]);
    cardEl.classList.add('unread');
    cardEl.open = false;
    refreshCounts();
  }
});
app.addEventListener('change', async (e) => {
  const el = e.target;
  if (el.dataset.f) {
    const key = el.dataset.f;
    S.f[key] = el.type === 'checkbox' ? el.checked : (typeof S.f[key] === 'number' ? Number(el.value) : el.value);
    save('filters', S.f);
    S.limit = 50;
    render();
  } else if ('fp' in el.dataset) {
    const id = el.dataset.fp;
    if (!id) S.f.products = [];
    else S.f.products = el.checked ? [...S.f.products, id] : S.f.products.filter((p) => p !== id);
    save('filters', S.f);
    S.limit = 50;
    render();
  } else if (el.dataset.follow) {
    if (el.checked) S.follows.add(el.dataset.follow); else S.follows.delete(el.dataset.follow);
    save('follows', [...S.follows]);
    S.f.products = S.f.products.filter((id) => S.follows.has(id));
    save('filters', S.f);
    document.getElementById('following').textContent = t('following', S.follows.size);
    const settingsTab = app.querySelector('[data-n="settings"]');
    settingsTab.textContent = S.follows.size;
    settingsTab.hidden = !S.follows.size;
    applyChips(false); // keep a just-unchecked chip visible so it can be re-checked
    await loadFeed();
    refreshCounts();
  } else if ('only' in el.dataset) {
    S.onlySel = el.checked;
    applyChips();
  }
});
app.addEventListener('input', (e) => {
  if ('search' in e.target.dataset) applyChips();
});
// "toggle" does not bubble, so listen in the capture phase. The body is built lazily on first open.
app.addEventListener('toggle', (e) => {
  const el = e.target;
  if (!el.classList?.contains('card') || !el.open) return;
  const it = findItem(el.dataset.id);
  const body = el.querySelector('[data-body]');
  if (it && !body.firstChild) {
    body.innerHTML = cardBody(it);
    const box = body.querySelector('[data-mt]');
    if (box?.querySelector('.mt')) translateInto(box, it, false);
  }
  if (el.classList.contains('unread')) {
    markRead([el.dataset.id]);
    el.classList.remove('unread');
    refreshCounts();
  }
}, true);

setInterval(checkUpdate, 10 * 60 * 1000);
document.addEventListener('visibilitychange', checkUpdate);
loadAll();

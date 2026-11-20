#!/usr/bin/env node
// Collects vulnerability data from public sources, matches it against catalog.json
// and writes static JSON under public/data/. State lives in cache/db.json.
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';

const ROOT = new URL('..', import.meta.url);
const CACHE = new URL('cache/db.json', ROOT);
const OUT = new URL('public/data/', ROOT);
const BACKFILL_DAYS = Number(process.env.BACKFILL_DAYS) || 60;
const RETAIN_DAYS = 365;
const PER_PRODUCT_CAP = 500;
const DAY = 86400000;
const now = Date.now();
const cutoff = now - RETAIN_DAYS * DAY;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

async function get(url, opts = {}, tries = 4) {
  for (let i = 0; ; i++) {
    try {
      const r = await fetch(url, {
        ...opts,
        headers: { 'user-agent': 'vuln-watch-batch', ...(opts.headers || {}) },
        signal: AbortSignal.timeout(180000),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status} ${String(url).slice(0, 120)}`);
      return r;
    } catch (e) {
      if (i >= tries - 1) throw e;
      log('retry', e.message);
      await sleep(7000 * (i + 1));
    }
  }
}

// ---------- catalog index ----------
const catalog = JSON.parse(await readFile(new URL('catalog.json', ROOT), 'utf8'));
const cpeExact = new Map();
const cpePrefix = [];
const nameExact = new Map();
const namePrefix = [];
const vendorExact = new Map();
const push = (map, k, v) => map.set(k, [...(map.get(k) || []), v]);
for (const c of catalog) {
  for (const p of c.cpe || []) {
    if (p.endsWith('*')) cpePrefix.push([p.slice(0, -1), c]);
    else push(cpeExact, p, c);
  }
  for (const n of c.names || [c.name.toLowerCase()]) {
    if (n.endsWith('*')) namePrefix.push([n.slice(0, -1), c]);
    else push(nameExact, n, c);
  }
  if (c.names && !c.vendorOnly) push(nameExact, c.name.toLowerCase(), c);
  for (const v of c.vendors || []) push(vendorExact, v, c);
}
function lookupCpe(vendor, product) {
  const key = `${vendor}:${product}`;
  const hit = (cpeExact.get(key) || []).map((c) => c.id);
  for (const [pre, c] of cpePrefix) if (key.startsWith(pre)) hit.push(c.id);
  return hit;
}
function lookupName(vendor, product) {
  const v = String(vendor || '').toLowerCase().trim();
  const p = String(product || '').toLowerCase().trim();
  const hit = [...(nameExact.get(p) || [])];
  for (const [pre, c] of namePrefix) if (p.startsWith(pre)) hit.push(c);
  hit.push(...(vendorExact.get(v) || []));
  return hit.filter((c) => !c.vendorOnly || c.vendorOnly === v).map((c) => c.id);
}

// ---------- NVD ----------
function cpeRange(m, parts) {
  const r = [];
  if (m.versionStartIncluding) r.push('>=' + m.versionStartIncluding);
  if (m.versionStartExcluding) r.push('>' + m.versionStartExcluding);
  if (m.versionEndExcluding) r.push('<' + m.versionEndExcluding);
  if (m.versionEndIncluding) r.push('<=' + m.versionEndIncluding);
  const any = (s) => !s || s === '*' || s === '-';
  if (!r.length && !any(parts[5])) r.push(parts[5] + (any(parts[6]) ? '' : ' ' + parts[6]));
  return r.join(' ');
}
function cnaRange(v) {
  const ok = (s) => s && s.length <= 24 && !/^[0-9a-f]{12,}$/.test(s);
  if (v.status !== 'affected' || !ok(v.version)) return '';
  const from = v.version === '0' ? '' : '>=' + v.version;
  if (ok(v.lessThan)) return `${from} <${v.lessThan}`.trim();
  if (v.lessThanOrEqual === '*') return from;
  if (ok(v.lessThanOrEqual)) return `${from} <=${v.lessThanOrEqual}`.trim();
  return v.version === '0' ? '' : v.version;
}
function matchNvd(cve) {
  const prods = new Map(); // product id -> Set(range text)
  const add = (ids, range) => {
    for (const id of ids) {
      if (!prods.has(id)) prods.set(id, new Set());
      if (range) prods.get(id).add(range);
    }
  };
  let how = 'cpe';
  const configs = cve.configurations || [];
  for (const cfg of configs)
    for (const n of cfg.nodes || [])
      for (const m of n.cpeMatch || []) {
        if (!m.vulnerable) continue;
        const parts = m.criteria.split(/(?<!\\):/).map((s) => s.replace(/\\/g, ''));
        add(lookupCpe(parts[3], parts[4]), cpeRange(m, parts));
      }
  if (!configs.length) {
    // Not analyzed by NVD yet: fall back to the product names declared by the CNA.
    how = 'cna';
    for (const a of cve.affected || [])
      for (const d of a.affectedData || []) {
        const ids = lookupName(d.vendor, d.product);
        if (!ids.length) continue;
        add(ids, '');
        for (const v of d.versions || []) add(ids, cnaRange(v));
      }
  }
  const aff = [];
  for (const [id, set] of prods) for (const r of [...set].slice(0, 6)) aff.push([id, r]);
  return { ids: [...prods.keys()], aff: aff.slice(0, 16), how };
}
function pickCvss(metrics = {}) {
  const order = [
    ['cvssMetricV31', 'Primary'], ['cvssMetricV40', 'Primary'], ['cvssMetricV30', 'Primary'],
    ['cvssMetricV40', 'Secondary'], ['cvssMetricV31', 'Secondary'], ['cvssMetricV30', 'Secondary'],
    ['cvssMetricV2', 'Primary'], ['cvssMetricV2', 'Secondary'],
  ];
  for (const [k, t] of order) {
    const m = (metrics[k] || []).find((x) => x.type === t);
    if (!m) continue;
    const d = m.cvssData;
    return { s: d.baseScore, sev: sevOf(d.baseScore), v: d.vectorString, ver: d.version };
  }
  return null;
}
const sevOf = (s) => (s >= 9 ? 'CRITICAL' : s >= 7 ? 'HIGH' : s >= 4 ? 'MEDIUM' : s > 0 ? 'LOW' : 'NONE');
function pickRefs(refs = []) {
  const rank = (r) => {
    const t = r.tags || [];
    return t.includes('Vendor Advisory') ? 0 : t.includes('Patch') ? 1 : t.includes('Release Notes') ? 2 : 3;
  };
  const urls = [...refs].sort((a, b) => rank(a) - rank(b)).map((r) => r.url);
  return [...new Set(urls)].filter((u) => /^https?:\/\//.test(u)).slice(0, 4);
}
const seenNames = new Map(); // DUMP_NAMES=1 writes CNA vendor/product pairs for catalog tuning
function upsertNvd(db, cve) {
  if (process.env.DUMP_NAMES) for (const a of cve.affected || []) for (const d of a.affectedData || []) {
    const k = `${d.vendor} | ${d.product}`; seenNames.set(k, (seenNames.get(k) || 0) + 1);
  }
  const old = db.recs[cve.id];
  if (cve.vulnStatus === 'Rejected' || Date.parse(cve.published + 'Z') < cutoff) {
    if (old) { old.nvdP = []; }
    return;
  }
  const m = matchNvd(cve);
  if (!m.ids.length && !old) return;
  const rec = old || { id: cve.id, osvP: [], fix: [] };
  Object.assign(rec, {
    pub: cve.published + 'Z',
    mod: cve.lastModified + 'Z',
    nvdP: m.ids,
    how: m.ids.length ? m.how : 'osv',
    aff: m.aff,
    cvss: pickCvss(cve.metrics) || rec.cvss || null,
    cwe: [...new Set((cve.weaknesses || []).flatMap((w) => w.description.map((d) => d.value)))]
      .filter((v) => /^CWE-\d+$/.test(v)).slice(0, 3),
    en: (cve.descriptions || []).find((d) => d.lang === 'en')?.value?.slice(0, 1500) || '',
    refs: pickRefs(cve.references),
    osvOnly: false,
  });
  db.recs[cve.id] = rec;
}
async function fetchNvd(params, onCve) {
  const key = process.env.NVD_API_KEY;
  let start = 0, total = Infinity, n = 0;
  while (start < total) {
    const u = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
    u.searchParams.set('resultsPerPage', '2000');
    u.searchParams.set('startIndex', String(start));
    const j = await (await get(u, key ? { headers: { apiKey: key } } : {})).json();
    total = j.totalResults;
    for (const v of j.vulnerabilities || []) { onCve(v.cve); n++; }
    if (!j.vulnerabilities?.length) break;
    start += j.vulnerabilities.length;
    log(`nvd ${start}/${total}`);
    if (start < total) await sleep(key ? 800 : 6500);
  }
  return n;
}
async function runNvd(db) {
  const iso = (t) => new Date(t).toISOString();
  const onCve = (cve) => upsertNvd(db, cve);
  const last = db.lastRun || 0;
  if (now - last > 100 * DAY) {
    // First run (or a very stale cache): backfill by publication date, 100 days per request.
    for (let from = now - BACKFILL_DAYS * DAY; from < now; from += 100 * DAY) {
      await fetchNvd({ pubStartDate: iso(from), pubEndDate: iso(Math.min(from + 100 * DAY, now)) }, onCve);
    }
  } else {
    await fetchNvd({ lastModStartDate: iso(last - 2 * 3600000), lastModEndDate: iso(now) }, onCve);
  }
  db.lastRun = now;
}

// ---------- OSV ----------
function cvss3Score(vec) {
  const m = Object.fromEntries(vec.split('/').slice(1).map((x) => x.split(':')));
  const S = m.S === 'C';
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const PR = { N: 0.85, L: S ? 0.68 : 0.62, H: S ? 0.5 : 0.27 }[m.PR];
  const cia = { H: 0.56, L: 0.22, N: 0 };
  const iss = 1 - (1 - cia[m.C]) * (1 - cia[m.I]) * (1 - cia[m.A]);
  const imp = S ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const exp = 8.22 * AV * AC * PR * UI;
  if (!(imp > 0)) return 0;
  const raw = S ? Math.min(1.08 * (imp + exp), 10) : Math.min(imp + exp, 10);
  return Math.ceil(raw * 10 - 1e-9) / 10;
}
function osvCvss(v) {
  const sev = v.severity || [];
  const v3 = sev.find((s) => s.type === 'CVSS_V3');
  if (v3) {
    const s = cvss3Score(v3.score);
    if (Number.isFinite(s)) return { s, sev: sevOf(s), v: v3.score, ver: v3.score.slice(5, 8) };
  }
  const label = String(v.database_specific?.severity || '').toUpperCase().replace('MODERATE', 'MEDIUM');
  const v4 = sev.find((s) => s.type === 'CVSS_V4');
  if (!label && !v4) return null;
  return { s: null, sev: label || '', v: v4?.score || '', ver: v4 ? '4.0' : '' };
}
async function runOsv(db) {
  const found = new Map(); // key -> {v, ids:Set, fix:Set}
  for (const c of catalog) {
    for (const [ecosystem, name] of c.osv || []) {
      let token;
      do {
        const body = { package: { ecosystem, name }, ...(token ? { page_token: token } : {}) };
        const j = await (await get('https://api.osv.dev/v1/query', { method: 'POST', body: JSON.stringify(body) })).json();
        for (const v of j.vulns || []) {
          if (v.withdrawn || !(Date.parse(v.published) >= cutoff)) continue;
          const key = (v.aliases || []).find((a) => /^CVE-\d+-\d+$/.test(a)) || v.id;
          const f = found.get(key) || { v, ids: new Set(), fix: new Set() };
          f.ids.add(c.id);
          for (const a of v.affected || []) {
            if (a.package?.name !== name) continue;
            for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) f.fix.add(`${name} ${e.fixed}`);
          }
          found.set(key, f);
        }
        token = j.next_page_token;
      } while (token);
    }
  }
  for (const rec of Object.values(db.recs)) { rec.osvP = []; rec.fix = []; }
  for (const [key, f] of found) {
    const v = f.v;
    const rec = db.recs[key] || (db.recs[key] = { id: key, nvdP: [], osvOnly: true, aff: [] });
    rec.osvP = [...f.ids];
    rec.fix = [...f.fix].slice(0, 12);
    if (rec.osvOnly) {
      Object.assign(rec, {
        pub: v.published, mod: v.modified, how: 'osv',
        cvss: osvCvss(v),
        cwe: (v.database_specific?.cwe_ids || []).slice(0, 3),
        en: (v.summary || String(v.details || '').split('\n').find((l) => l.trim() && !l.startsWith('#')) || '').slice(0, 1500),
        refs: (v.references || []).map((r) => r.url).filter((u) => /^https?:\/\//.test(u)).slice(0, 4),
      });
    }
  }
  log(`osv matched ${found.size}`);
}

// ---------- EPSS / KEV / JVN ----------
async function runEpss(db, kevList) {
  const buf = Buffer.from(await (await get('https://epss.empiricalsecurity.com/epss_scores-current.csv.gz')).arrayBuffer());
  const lines = gunzipSync(buf).toString('utf8').split('\n');
  db.epssDate = (lines[0].match(/score_date:([^,\s]+)/) || [])[1] || '';
  const want = new Set([...Object.keys(db.recs), ...kevList.map((k) => k.id)]);
  const map = new Map();
  for (const line of lines) {
    const i = line.indexOf(',');
    if (i < 0 || !want.has(line.slice(0, i))) continue;
    const [, e, p] = line.split(',');
    map.set(line.slice(0, i), [Number(e), Number(p)]);
  }
  for (const rec of [...Object.values(db.recs), ...kevList]) {
    const m = map.get(rec.id);
    if (m) { rec.epss = m[0]; rec.pct = m[1]; }
  }
}
async function runKev(db) {
  const j = await (await get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')).json();
  const kevOf = (k) => ({ a: k.dateAdded, due: k.dueDate, r: k.knownRansomwareCampaignUse === 'Known' });
  const map = new Map(j.vulnerabilities.map((k) => [k.cveID, k]));
  for (const rec of Object.values(db.recs)) {
    const k = map.get(rec.id);
    rec.kev = k ? kevOf(k) : null;
  }
  return [...j.vulnerabilities]
    .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded))
    .slice(0, 80)
    .map((k) => ({
      id: k.cveID, pub: k.dateAdded, t: k.vulnerabilityName, vp: `${k.vendorProject} ${k.product}`,
      en: k.shortDescription, act: k.requiredAction, cwe: (k.cwes || []).filter((c) => /^CWE-\d+$/.test(c)).slice(0, 3),
      kev: kevOf(k),
    }));
}
const decodeXml = (s) => s
  .replace(/&#13;/g, '').replace(/&#(\d+);/g, (_, n) => (Number(n) <= 0x10ffff ? String.fromCodePoint(Number(n)) : ''))
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
function parseJvn(xml, db) {
  // JVN descriptions carry escaped HTML: decode, drop the tags, then decode the entities left inside.
  const tag = (s, n) => decodeXml(decodeXml((s.match(new RegExp(`<${n}>([\\s\\S]*?)</${n}>`)) || [])[1] || '')
    .replace(/<li>/g, ' ').replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();
  let n = 0;
  for (const it of xml.split('<item ').slice(1)) {
    const ja = { t: tag(it, 'title'), d: tag(it, 'description').slice(0, 1200), u: tag(it, 'link') };
    if (!/^https:\/\/jvndb\.jvn\.jp\//.test(ja.u)) continue;
    for (const m of it.matchAll(/<sec:references source="CVE" id="(CVE-\d+-\d+)"/g)) {
      const rec = db.recs[m[1]];
      if (rec) { rec.ja = ja; n++; }
    }
  }
  return n;
}
async function runJvn(db) {
  let n = parseJvn(await (await get('https://jvndb.jvn.jp/ja/rss/jvndb_new.rdf')).text(), db);
  if (!db.jvnBackfilled) {
    // One-time backfill from the yearly feed (about 100 MB, so only when the cache is empty).
    const year = new Date(now).getUTCFullYear();
    n += parseJvn(await (await get(`https://jvndb.jvn.jp/ja/rss/years/jvndb_${year}.rdf`)).text(), db);
    db.jvnBackfilled = true;
  }
  log(`jvn matched ${n}`);
}

// ---------- main ----------
let db = { lastRun: 0, recs: {} };
try { db = JSON.parse(await readFile(CACHE, 'utf8')); } catch { log('no cache: starting a backfill'); }

const sources = {};
async function phase(name, fn) {
  try { const r = await fn(); sources[name] = { ok: true }; return r; }
  catch (e) { sources[name] = { ok: false, err: String(e.message || e).slice(0, 200) }; log(`${name} FAILED`, e.message); }
}
await phase('nvd', () => runNvd(db));
await phase('osv', () => runOsv(db));
for (const [id, rec] of Object.entries(db.recs)) {
  const dead = !(rec.nvdP?.length || rec.osvP?.length) || !(Date.parse(rec.pub) >= cutoff);
  if (dead) delete db.recs[id];
}
const kevList = (await phase('kev', () => runKev(db))) || db.kevList || [];
db.kevList = kevList;
await phase('epss', () => runEpss(db, kevList));
await phase('jvn', () => runJvn(db));

const recs = Object.values(db.recs);
if (!recs.length && !sources.nvd.ok) { console.error('nothing to publish'); process.exit(1); }

const publicRec = (r) => ({
  id: r.id, pub: r.pub, mod: r.mod, p: [...new Set([...(r.nvdP || []), ...(r.osvP || [])])], how: r.how,
  aff: r.aff?.length ? r.aff : undefined, fix: r.fix?.length ? r.fix : undefined,
  cvss: r.cvss || undefined, cwe: r.cwe?.length ? r.cwe : undefined,
  epss: r.epss, pct: r.pct, kev: r.kev || undefined, en: r.en, ja: r.ja, refs: r.refs?.length ? r.refs : undefined,
});
const urgent = (r) => r.kev || (r.cvss?.s ?? 0) >= 7 || (r.epss ?? 0) >= 0.1;
const byPub = (a, b) => b.pub.localeCompare(a.pub);

await rm(OUT, { recursive: true, force: true });
await mkdir(new URL('products/', OUT), { recursive: true });
const counts = {};
for (const c of catalog) {
  let list = recs.filter((r) => r.nvdP?.includes(c.id) || r.osvP?.includes(c.id)).sort(byPub);
  if (list.length > PER_PRODUCT_CAP) {
    // Keep everything urgent, then fill the rest with the most recent entries.
    const keep = new Set(list.filter(urgent).slice(0, PER_PRODUCT_CAP));
    for (const r of list) { if (keep.size >= PER_PRODUCT_CAP) break; keep.add(r); }
    list = list.filter((r) => keep.has(r));
  }
  counts[c.id] = list.length;
  await writeFile(new URL(`products/${c.id}.json`, OUT), JSON.stringify(list.map(publicRec)));
}
await writeFile(new URL('kev.json', OUT), JSON.stringify(kevList));
await writeFile(new URL('catalog.json', OUT), JSON.stringify(catalog.map(({ id, name, cat }) => ({ id, name, cat }))));
await writeFile(new URL('meta.json', OUT), JSON.stringify({
  generatedAt: new Date().toISOString(), epssDate: db.epssDate || '', total: recs.length, counts, sources,
}));
await mkdir(new URL('cache/', ROOT), { recursive: true });
await writeFile(CACHE, JSON.stringify(db));
if (seenNames.size) await writeFile(new URL('cache/names.json', ROOT), JSON.stringify([...seenNames].sort((a, b) => b[1] - a[1])));
log(`done: ${recs.length} records`, JSON.stringify(sources));

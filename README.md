# vuln-watch

フォローした言語・サーバ・フレームワークの脆弱性を、CVSS / EPSS / KEV と解説つきで見る静的サイト。
閲覧者の設定（フォロー製品・言語・既読）はブラウザの localStorage だけに保存する。

## 仕組み

```
GitHub Actions (30分ごと) → scripts/build-data.mjs → public/data/*.json → wrangler deploy
ブラウザ → フォロー中の製品の JSON だけ取得して表示
```

- データ元: NVD API 2.0 / OSV.dev / CISA KEV / FIRST EPSS / JVN iPedia
- 製品の突合: `catalog.json` の CPE（NVD 分析済み）→ CNA 申告の製品名（未分析）→ OSV のパッケージ名
- 解説: `public/explain.js` の CWE 辞書と CVSS ベクタから生成（LLM 不使用）
- 状態: `cache/db.json`（Actions のキャッシュで引き継ぐ。消えたら 60 日分を取り直す）

## ローカル

```bash
npm run data   # 初回は数分（60日分 + JVN 年次フィード約100MB）
npm run dev    # http://localhost:4180
```

`DUMP_NAMES=1 npm run data` で CNA の vendor / product 一覧を `cache/names.json` に出す（カタログ調整用）。

## 公開に必要な設定

- GitHub Secrets: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`（任意で `NVD_API_KEY`）
- 公開先のホスト名は `wrangler.jsonc` の `routes`

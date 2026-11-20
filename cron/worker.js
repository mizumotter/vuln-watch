// Backup trigger: GitHub's own schedule can be delayed or skipped, so a
// Cloudflare Cron Trigger starts the update-data workflow instead.
const URL_DISPATCH =
  'https://api.github.com/repos/mizumotter/vuln-watch/actions/workflows/update.yml/dispatches';

export default {
  async scheduled(_event, env) {
    const res = await fetch(URL_DISPATCH, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${env.GITHUB_TOKEN}`,
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        'user-agent': 'vuln-watch-cron',
      },
      body: JSON.stringify({ ref: 'main' }),
    });
    // Throwing marks the invocation as failed in the Cloudflare dashboard.
    if (!res.ok) throw new Error(`dispatch failed: ${res.status} ${(await res.text()).slice(0, 200)}`);
    console.log('dispatched', res.status);
  },
};

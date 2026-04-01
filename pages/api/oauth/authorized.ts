import type { NextApiRequest, NextApiResponse } from 'next';
import { encodeState, decodeState } from '../../../lib/oauth/state';
import { env } from '../../../lib/variables';

const GITHUB_OAUTH_ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token';
const TOKEN_VALIDITY_PERIOD = 1000 * 60 * 60 * 24 * 365; // 1 year;

export default async function OAuthAuthorizedApi(req: NextApiRequest, res: NextApiResponse) {
  const code = req.query.code as string;
  const state = req.query.state as string;
  const error = req.query.error as string;

  const { client_id, client_secret, encryption_password } = env;

  let appReturnUrl: string;
  try {
    appReturnUrl = await decodeState(state, encryption_password);
  } catch (err) {
    res.status(400).json({ error: err.message });
    return;
  }

  const returnUrl = new URL(appReturnUrl);

  if (error && error === 'access_denied') {
    res.redirect(302, returnUrl.href);
    return;
  }

  if (!code || !state) {
    res.status(400).json({ error: '`code` and `state` are required.' });
    return;
  }

  const init = {
    method: 'POST',
    body: new URLSearchParams({ client_id, client_secret, code, state }),
    headers: {
      Accept: 'application/json',
      'User-Agent': 'giscus',
    },
  };

  let accessToken: string;
  try {
    const response = await fetch(GITHUB_OAUTH_ACCESS_TOKEN_URL, init);
    if (response.ok) {
      const data = await response.json();
      accessToken = data.access_token;
    } else {
      throw new Error(`Access token response had status ${response.status}.`);
    }
  } catch (err) {
    res.status(503).json({ error: err.message });
    return;
  }

  const session = await encodeState(
    accessToken,
    encryption_password,
    Date.now() + TOKEN_VALIDITY_PERIOD,
  );
  // 변경
  const html = `<!DOCTYPE html>
<html>
<head><script>
  const token = ${JSON.stringify(session)};
  const returnUrl = ${JSON.stringify(returnUrl.href)};
  // 부모 탭의 localStorage에 저장
  if (window.opener) {
    window.opener.localStorage.setItem('giscus_token', token);
    window.close();
  } else {
    localStorage.setItem('giscus_token', token);
    location.href = returnUrl;
  }
</script></head>
<body></body>
</html>`;
}

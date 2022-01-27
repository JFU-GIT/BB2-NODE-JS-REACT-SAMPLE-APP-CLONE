import FormData from 'form-data';
import AuthorizationToken from '../entities/AuthorizationToken';
import db from './db';
import config from '../configs/config';
import { generateCodeChallenge, generateRandomState } from './generatePKCE';
import { post, postWithConfig } from './request';

const envConfig = config[db.settings.env];

function getURL(path: string): string {
    return `${envConfig?.bb2BaseUrl.toString() || 'NoBaseURL'}/${db.settings.version || 'NoVersion'}/${path}`;
}

function getClientId(): string {
    return `${envConfig?.bb2ClientId.toString()}`;
}

function getClientSecret(): string {
    return `${envConfig?.bb2ClientSecret.toString()}`;
}

function getCallbackUrl(): string {
    return `${envConfig?.bb2CallbackUrl.toString()}`;
}

export function generateAuthorizeUrl(): string {
  const BB2_AUTH_URL = getURL('o/authorize');

  let pkceParams = '';
  const state = generateRandomState();

  if (db.settings.pkce) {
    const codeChallenge = generateCodeChallenge();
    pkceParams = `${'&code_challenge_method=S256'
            + '&code_challenge='}${codeChallenge.codeChallenge}`;

    db.codeChallenges[state] = codeChallenge;
  }

  return `${BB2_AUTH_URL
  }?client_id=${getClientId()
  }&redirect_uri=${getCallbackUrl()
  }&state=${state
  }&response_type=code${
    pkceParams}`;
}

export async function getAccessToken(code: string, state: string | undefined) {
  const BB2_ACCESS_TOKEN_URL = getURL('o/token/');

  const form = new FormData();
  form.append('client_id', getClientId());
  form.append('client_secret', getClientSecret());
  form.append('code', code);
  form.append('grant_type', 'authorization_code');
  form.append('redirect_uri', getCallbackUrl());

  if (db.settings.pkce && state) {
    const codeChallenge = db.codeChallenges[state];
    form.append('code_verifier', codeChallenge.verifier);
    form.append('code_challenge', codeChallenge.codeChallenge);
  }
  return post(BB2_ACCESS_TOKEN_URL, form, form.getHeaders());
}

export async function refreshAccessToken(refreshToken: string) {
  const BB2_ACCESS_TOKEN_URL = getURL('o/token/');

  const tokenResponse = await postWithConfig({
    method: 'post',
    url: BB2_ACCESS_TOKEN_URL,
    auth: {
      username: getClientId(),
      password: getClientSecret(),
    },
    params: {
      grant_type: 'refresh_token',
      client_id: getClientId(),
      refresh_token: refreshToken,
    },
  });

  return new AuthorizationToken(tokenResponse.data);
}

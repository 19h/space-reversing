#!/usr/bin/env node
// Mint a game-side gRPC JWT by walking the launcher's three-step dance:
//   games/claims -> games/release -> games/token
// Output: the JWT (game auth_token) and the push target host/port.
//
// Env:
//   SESSION_TOKEN  required, X-Rsi-Token (current valid session)
//   DEVICE_TOKEN   required, X-Rsi-Device
//   RSI_UA         override UA (default "RSI Launcher-2.x.x")
//
// Flags:
//   --env prod|ptu|eptu|staging   default prod
//   --game <id>                   default "SC"
//   --channel <id>                default "LIVE"
//   --out <file>                  write {gameToken, release} as JSON
//   --player                      after games/token, call IdentityService.GetCurrentPlayer
//                                 to upgrade to the player-scoped JWT (with player_id claim)
//   --pipe                        print only "<host>:<port> <jwt>" (for shell piping)
//   -v / --verbose                dump every response body

const fs = require('fs');

const argv = process.argv.slice(2);
const flag = (...names) => names.some(n => argv.includes(n));
const opt  = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };

const opts = {
  env:     opt('--env')     || 'prod',
  game:    opt('--game')    || 'SC',
  channel: opt('--channel') || 'LIVE',
  out:     opt('--out'),
  pipe:    flag('--pipe'),
  verbose: flag('-v', '--verbose'),
  player:  flag('--player'),
};

const ENVS = {
  prod:    'https://robertsspaceindustries.com/api/launcher/v3',
  ptu:     'https://ptu.cloudimperiumgames.com/api/launcher/v3',
  eptu:    'https://ptu.cloudimperiumgames.com/api/launcher/v3',
  staging: 'https://staging.cloudimperiumgames.com/api/launcher/v3',
};
const API = ENVS[opts.env] || die(`unknown env: ${opts.env}`);

const SESSION_TOKEN = process.env.SESSION_TOKEN || die('SESSION_TOKEN required');
const DEVICE_TOKEN  = process.env.DEVICE_TOKEN  || die('DEVICE_TOKEN required');
const UA            = process.env.RSI_UA        || 'RSI Launcher-2.x.x';

const log = (...a) => { if (!opts.pipe) console.log(...a); };
const dbg = (...a) => opts.verbose && console.error('  [v]', ...a);

function die(msg, extra) {
  console.error('FATAL:', msg);
  if (extra) console.error(typeof extra === 'string' ? extra : JSON.stringify(extra, null, 2));
  process.exit(1);
}

async function call(endpoint, payload) {
  const r = await fetch(`${API}/${endpoint}`, {
    method:  'POST',
    headers: {
      'User-Agent':   UA,
      'Content-Type': 'application/json',
      'X-Rsi-Token':  SESSION_TOKEN,
      'X-Rsi-Device': DEVICE_TOKEN,
    },
    body: JSON.stringify(payload),
  });
  const body = await r.json().catch(() => ({}));
  dbg(`<- ${endpoint}:`, JSON.stringify(body, null, 2));
  if (body.success !== 1) die(`${endpoint} failed: ${body.code || r.status}`, body);
  return body.data;
}

(async () => {
  log(`\n[1] POST games/claims`);
  const claims = await call('games/claims', {});
  log('    claims acquired');

  log(`\n[2] POST games/release  (gameId=${opts.game}, channelId=${opts.channel})`);
  const release = await call('games/release', {
    claims,
    gameId:    opts.game,
    channelId: opts.channel,
  });
  log(`    version:          ${release.versionLabel || release.version}`);
  log(`    servicesEndpoint: ${release.servicesEndpoint || '(none)'}`);
  log(`    universeHost:     ${release.universeHost}:${release.universePort}`);
  log(`    eacSandbox:       ${release.eacSandbox       || '(none)'}`);

  // gRPC push target is servicesEndpoint; strip scheme to get host:port for grpc-js.
  const pushTarget = (release.servicesEndpoint || '')
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '');
  if (!pushTarget) die('release has no servicesEndpoint; cannot determine push target');

  log(`\n[3] POST games/token  (gameId=${opts.game})`);
  const gameToken = await call('games/token', {
    claims,
    gameId: opts.game,
  });

  const jwt = gameToken.token;
  let claimsDecoded = null;
  try {
    claimsDecoded = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));
  } catch (_) {}

  log(`    JWT acquired (${jwt.length}B)`);
  if (claimsDecoded) {
    log(`    JWT claims:`);
    log(`      iss:        ${claimsDecoded.iss}`);
    log(`      aud:        ${claimsDecoded.aud}`);
    log(`      sub:        ${claimsDecoded.sub}`);
    log(`      account_id: ${claimsDecoded.account_id}`);
    log(`      player_id:  ${claimsDecoded.player_id}`);
    if (claimsDecoded.exp) log(`      exp:        ${new Date(claimsDecoded.exp * 1000).toISOString()}`);
  }

  let outJwt = jwt;
  let player = null;
  if (opts.player) {
    log(`\n[4] gRPC IdentityService.GetCurrentPlayer  (upgrading to player-scoped JWT)`);
    const path = require('path');
    const grpc = require('@grpc/grpc-js');
    const protoLoader = require('@grpc/proto-loader');
    const pkgDef = protoLoader.loadSync(
      path.join(__dirname, 'scproto', 'proto', 'sc', 'external', 'services', 'identity', 'v1', 'api.proto'),
      {
        keepCase: true, longs: String, enums: String, defaults: true, oneofs: true,
        includeDirs: [
          path.join(__dirname, 'scproto', 'proto'),
          path.join(__dirname, 'scproto', 'vendor', 'google', 'api-common-protos'),
          path.join(__dirname, 'scproto', 'vendor', 'grpc-gateway'),
        ],
      });
    const Svc = require('@grpc/grpc-js').loadPackageDefinition(pkgDef).sc.external.services.identity.v1.IdentityService;
    const client = new Svc(pushTarget, grpc.credentials.createSsl(), {});
    const md = new grpc.Metadata();
    md.add('authorization', `Bearer ${jwt}`);
    const resp = await new Promise((resolve, reject) => {
      client.getCurrentPlayer({}, md, { deadline: Date.now() + 8000 }, (err, r) => err ? reject(err) : resolve(r));
    });
    client.close();
    if (!resp.jwt) die('GetCurrentPlayer returned no jwt', resp);
    outJwt = resp.jwt;
    player = resp.player;
    log(`    player.geid:    ${player.geid}`);
    log(`    player.name:    ${player.name}`);
    log(`    player.state:   ${player.state}`);
    log(`    upgraded JWT (${outJwt.length}B), aud=insecure.sc-services.internal`);
  }

  if (opts.out) {
    fs.writeFileSync(opts.out, JSON.stringify({ gameToken, release, claimsDecoded, player, playerJwt: opts.player ? outJwt : undefined }, null, 2));
    log(`\n    wrote ${opts.out}`);
  }

  if (opts.pipe) {
    process.stdout.write(`${pushTarget} ${outJwt}${player ? ' ' + player.geid : ''}\n`);
  } else {
    log(`\nReady to dial. Example:`);
    log(`  RSI_JWT='${jwt.slice(0, 24)}...' node refresh.js --dry-run-grpc \\`);
    log(`    --host ${pushTarget} --budget 30 -v`);
    log(`\n  pipe-mode:`);
    log(`  read HP JWT < <(node gametoken.js --pipe); RSI_JWT="$JWT" node refresh.js --dry-run-grpc --host "$HP" --budget 30 -v`);
  }
})().catch((e) => die('unhandled', e?.stack || e));

#!/usr/bin/env node
// RSI session refresh: connection-flow JWT -> push.gRPC Listen -> auth payload.
//
// Env:
//   DEVICE_TOKEN     persistent _rsi_device id (required unless --dry-run-grpc)
//   SESSION_TOKEN    optional stale X-Rsi-Token; used only by --probe
//   RSI_JWT          required iff --dry-run-grpc
//   RSI_UA           override user-agent (default "RSI Launcher-2.x.x")
//
// Flags:
//   --env prod|ptu|eptu|staging   (default prod)
//   --probe                       hit games/library first to confirm expiry
//   --jwt-only                    fetch+decode JWT, then exit
//   --dry-run-grpc                skip connection-flow; use RSI_JWT
//   --test                        after refresh, prove new session works
//   --out <file>                  write full auth payload JSON to file
//   --host <host[:port]>          override gRPC target host (default: claims.host)
//   --budget <seconds>            override extended_ttl budget for waiting on the auth payload
//   --topic <t>[,<t>...]          override topics to subscribe to (default: claims.topic)
//   --keep                        don't exit on first Any payload; keep streaming until budget
//   -v / --verbose                wire-level frame logging

const path = require('path');
const fs = require('fs');
const { randomUUID } = require('crypto');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const { buildRegistry, decodeAny } = require('./proto-registry');

// ---------- CLI ----------
const argv = process.argv.slice(2);
const flag = (...names) => names.some(n => argv.includes(n));
const opt = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : null;
};
const opts = {
  verbose:     flag('-v', '--verbose'),
  probe:       flag('--probe'),
  dryRunGrpc:  flag('--dry-run-grpc'),
  jwtOnly:     flag('--jwt-only'),
  test:        flag('--test'),
  out:         opt('--out'),
  env:         opt('--env') || 'prod',
  hostOverride: opt('--host'),
  budgetSec:   opt('--budget') ? Number(opt('--budget')) : null,
  topics:      opt('--topic') ? opt('--topic').split(',').map(s => s.trim()).filter(Boolean) : null,
  keep:        flag('--keep'),
};

const ENVS = {
  prod:    { api: 'https://robertsspaceindustries.com/api/launcher/v3', root: 'https://robertsspaceindustries.com' },
  ptu:     { api: 'https://ptu.cloudimperiumgames.com/api/launcher/v3', root: 'https://ptu.cloudimperiumgames.com' },
  eptu:    { api: 'https://ptu.cloudimperiumgames.com/api/launcher/v3', root: 'https://ptu.cloudimperiumgames.com' },
  staging: { api: 'https://staging.cloudimperiumgames.com/api/launcher/v3', root: 'https://staging.cloudimperiumgames.com' },
};
const ENV = ENVS[opts.env] || die(`unknown env: ${opts.env}`);

const SESSION_TOKEN = process.env.SESSION_TOKEN || null;
const DEVICE_TOKEN  = process.env.DEVICE_TOKEN  || null;
const PROVIDED_JWT  = process.env.RSI_JWT       || null;
const UA            = process.env.RSI_UA        || 'RSI Launcher-2.x.x';

if (!DEVICE_TOKEN && !opts.dryRunGrpc) {
  die('DEVICE_TOKEN env var required (or pass --dry-run-grpc with RSI_JWT)');
}

// ---------- logging ----------
const log     = (...a) => console.log(...a);
const verbose = (...a) => opts.verbose && console.error('  [v]', ...a);
const wire    = (dir, label, obj) =>
  opts.verbose && console.error(`  [wire ${dir}] ${label}: ${safeStringify(obj)}`);

function safeStringify(o) {
  return JSON.stringify(o, (_k, v) => Buffer.isBuffer(v) ? `<Buffer ${v.length}B>` : v, 2);
}

function die(msg, extra) {
  console.error('FATAL:', msg);
  if (extra) console.error(extra);
  process.exit(1);
}

// ---------- 1. expiry probe ----------
async function probeExpiry() {
  if (!SESSION_TOKEN) { verbose('no SESSION_TOKEN, skipping expiry probe'); return; }
  log('\n[1] probing /games/library with current session');
  const r = await fetch(`${ENV.api}/games/library`, {
    method:  'POST',
    headers: {
      'User-Agent':   UA,
      'Content-Type': 'application/json',
      'X-Rsi-Token':  SESSION_TOKEN,
      'X-Rsi-Device': DEVICE_TOKEN,
    },
    body: '{}',
  });
  const body = await r.json().catch(() => ({}));
  if (body.code === 'errAuthExpired') log('    session is expired (errAuthExpired)');
  else if (body.success === 1)        log('    session is still valid');
  else                                log('    unexpected response:', body);
  verbose('probe body:', body);
}

// ---------- 2. connection-flow JWT ----------
async function fetchJwt() {
  log('\n[2] POST /connection-flow');
  const r = await fetch(`${ENV.root}/connection-flow`, {
    method:  'POST',
    headers: {
      'User-Agent':          UA,
      'Content-Type':        'application/json',
      'Rsi-connection-flow': '',
      'X-Rsi-Device':        DEVICE_TOKEN,
    },
    body:   '{}',
    signal: AbortSignal.timeout(18000),
  });
  const body = await r.json().catch(() => ({}));
  if (body.success !== 1 || !body.data) die('connection-flow failed', body);
  log('    JWT acquired');
  return body.data;
}

function decodeJwt(jwt) {
  const parts = jwt.split('.');
  if (parts.length !== 3) die('not a JWT');
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
}

// ---------- 3. proto load ----------
function loadPushService() {
  const protoDir  = path.join(__dirname, 'scproto', 'proto');
  const vendorDir = path.join(__dirname, 'scproto', 'vendor', 'google', 'api-common-protos');
  const protoFile = path.join(protoDir, 'sc', 'external', 'services', 'push', 'v1', 'server.proto');
  for (const p of [protoDir, vendorDir, protoFile]) {
    if (!fs.existsSync(p)) die(`missing path: ${p}`);
  }
  const pkgDef = protoLoader.loadSync(protoFile, {
    keepCase:    true,
    longs:       String,
    enums:       String,
    defaults:    true,
    oneofs:      true,
    includeDirs: [protoDir, vendorDir],
  });
  const proto = grpc.loadPackageDefinition(pkgDef);
  const PushService = proto.sc.external.services.push.v1.PushService;
  if (!PushService) die('PushService not found in loaded proto');
  return PushService;
}

// ---------- 4. gRPC Listen ----------
async function runListen(jwt, claims) {
  log('\n[3] dialling gRPC');
  const PushService = loadPushService();

  const registry = buildRegistry({ verbose: opts.verbose });
  verbose(`registry: ${registry.loaded}/${registry.total} protos loaded`);

  const hostSpec = (opts.hostOverride || claims.host).replace(/^https?:\/\//, '').replace(/\/$/, '');
  const [host, port] = hostSpec.split(':');
  const target = `${host}:${port || 443}`;
  verbose('target:', target, 'topic:', claims.topic);
  if (opts.hostOverride) verbose('host override active (JWT claim:', claims.host + ')');

  const client = new PushService(target, grpc.credentials.createSsl(), {
    'grpc.service_config': JSON.stringify({
      loadBalancingConfig: [],
      methodConfig: [{
        name: [{ service: 'sc.external.services.push.v1.PushService' }],
        retryPolicy: {
          maxAttempts:          5,
          initialBackoff:       '0.1s',
          maxBackoff:           '5s',
          backoffMultiplier:    1.5,
          retryableStatusCodes: [
            'UNKNOWN','UNAVAILABLE','RESOURCE_EXHAUSTED','NOT_FOUND',
            'FAILED_PRECONDITION','OUT_OF_RANGE','DEADLINE_EXCEEDED',
            'ABORTED','INTERNAL',
          ],
        },
      }],
    }),
  });

  await new Promise((resolve, reject) => {
    client.waitForReady(Date.now() + 5000, (err) => err ? reject(err) : resolve());
  });
  verbose('channel ready');

  const metadata = new grpc.Metadata();
  metadata.add('Authorization', `Bearer ${jwt}`);

  const call = client.Listen(metadata);
  const subscriptionKey = randomUUID();

  // extended_ttl ceiling (main.js:2204: 1e3 * t.extended_ttl || 3e5)
  const budgetMs = opts.budgetSec != null
    ? opts.budgetSec * 1000
    : (((claims.extended_ttl || 300) * 1000) || 300000);
  let budgetTimer = setTimeout(() => {
    log(`    [!] extended_ttl budget exceeded (${budgetMs}ms), ending stream`);
    try { call.end(); } catch (_) {}
  }, budgetMs);

  return new Promise((resolve, reject) => {
    let authResult = null;
    let settled    = false;
    const settle = (fn, val) => {
      if (settled) return;
      settled = true;
      clearTimeout(budgetTimer);
      try { client.close(); } catch (_) {}
      fn(val);
    };

    call.on('data', (response) => {
      wire('<-', 'ListenResponse', response);
      for (const envelope of response.envelopes || []) {
        for (const msg of envelope.messages || []) {
          if (msg.data === 'control' && msg.control) handleControl(msg.control);
          else if (msg.data === 'any' && msg.any)    handleAny(msg.any);
        }
      }

      function handleControl(control) {
        const cmd = control.command;
        verbose('control:', cmd, control.subscription_event || '');
        if (cmd === 'COMMAND_STREAM_OPENED') {
          const topics = opts.topics || (claims.topic ? [claims.topic] : []);
          if (!topics.length) {
            verbose('no topics to subscribe to (JWT carries none, --topic not set); idling');
          } else {
            const sub = {
              commands: [{ subscribe: { topics, key: subscriptionKey } }],
            };
            wire('->', 'ListenRequest', sub);
            call.write(sub);
          }
        } else if (cmd === 'COMMAND_CLOSE_RECONNECT') {
          verbose('server requested reconnect; ending');
          try { call.end(); } catch (_) {}
        }
      }

      function handleAny(any) {
        const tu = any.type_url;
        const buf = Buffer.isBuffer(any.value) ? any.value : Buffer.from(any.value || []);
        verbose('any type_url:', tu, `(${buf.length}B)`);
        const decoded = decodeAny(registry.root, any);

        if (decoded?.encoding === 'protobuf' && decoded.data) {
          log(`    [event] ${decoded.type}`);
          log(JSON.stringify(decoded.data, null, 2));
          if (opts.keep) return;
          // not an auth payload — treat as informational and continue
          return;
        }
        if (decoded?.encoding === 'json' && decoded.data) {
          // JSON Any — this is the launcher auth flow's session payload.
          authResult = decoded.data;
          if (opts.keep) { log('    [keep] payload received, continuing to listen'); return; }
          const topics = opts.topics || (claims.topic ? [claims.topic] : []);
          if (topics.length) {
            const unsub = { commands: [{ unsubscribe: { topics } }] };
            wire('->', 'ListenRequest', unsub);
            try { call.write(unsub); } catch (_) {}
          }
          try { call.end(); } catch (_) {}
          return;
        }
        // unknown type / decode failure
        log(`    [event?] ${tu} (${buf.length}B, ${decoded?.error || 'undecodable'})`);
      }
    });

    call.on('error', (err) => settle(reject, err));
    call.on('end',   () => {
      if (authResult)  settle(resolve, authResult);
      else if (opts.keep) settle(resolve, { __idle: true });   // listening mode, no payload required
      else             settle(reject, new Error('stream ended with no auth payload'));
    });
  });
}

// ---------- 5. verify new session ----------
async function verifyNewSession(authData) {
  log('\n[4] verifying new session against /games/library');
  const sid = authData?.data?.session_id;
  const did = authData?.data?.device_id || DEVICE_TOKEN;
  if (!sid) { log('    no session_id in payload; skipping verify'); return; }
  const r = await fetch(`${ENV.api}/games/library`, {
    method:  'POST',
    headers: {
      'User-Agent':   UA,
      'Content-Type': 'application/json',
      'X-Rsi-Token':  sid,
      'X-Rsi-Device': did,
    },
    body: '{}',
  });
  const body = await r.json().catch(() => ({}));
  if (body.success === 1) log('    new session works');
  else                    log('    new session FAILED:', body);
  verbose('verify body:', body);
}

// ---------- main ----------
(async () => {
  if (opts.probe) await probeExpiry();

  let jwt;
  if (opts.dryRunGrpc) {
    if (!PROVIDED_JWT) die('--dry-run-grpc requires RSI_JWT');
    jwt = PROVIDED_JWT;
    log('\n[2] using JWT from RSI_JWT');
  } else {
    jwt = await fetchJwt();
  }

  const claims = decodeJwt(jwt);
  log('\n    JWT claims:');
  log(`      host:         ${claims.host}`);
  log(`      topic:        ${claims.topic}`);
  log(`      account_id:   ${claims.account_id}`);
  log(`      player_id:    ${claims.player_id}`);
  log(`      extended_ttl: ${claims.extended_ttl}s`);
  if (claims.exp) log(`      exp:          ${new Date(claims.exp * 1000).toISOString()}`);

  if (opts.jwtOnly) { log('\n[--jwt-only] done'); process.exit(0); }

  const authData = await runListen(jwt, claims);
  if (authData.__idle) {
    log('\n    [listen] budget expired with no JSON auth payload (expected in event-listen mode).');
    process.exit(0);
  }
  log('\n    auth payload received:');
  log(`      success:    ${authData.success}`);
  log(`      session_id: ${authData.data?.session_id ? authData.data.session_id.slice(0, 16) + '...' : '(none)'}`);
  log(`      device_id:  ${authData.data?.device_id}`);
  log(`      account_id: ${authData.data?.account_id}`);

  if (opts.out) {
    fs.writeFileSync(opts.out, JSON.stringify(authData, null, 2));
    log(`\n    wrote ${opts.out}`);
  }

  if (opts.test) await verifyNewSession(authData);

  process.exit(0);
})().catch((e) => die('unhandled error', e?.stack || e));

Then write one that completes the actual flow — dials gRPC, runs `Listen`, captures the auth payload, optionally writes the new session back somewhere. The script you have is a stub of the first half. Below is what a real debugging tool for this would look like, with the bits to keep, drop, or add.

## What "full" means here

A complete refresh debugging script needs to do four things the existing script doesn't:

1. **Dial gRPC** to the JWT's `host`, with TLS, using the JWT as bearer auth.
2. **Run the bidirectional `Listen` RPC**, react to `COMMAND_STREAM_OPENED` with a `SubscribeCommand` carrying the JWT's `topic`.
3. **Receive and decode the `Any` payload**, extract `session_id`, `device_id`, etc.
4. **Optionally write the result** somewhere usable — either print as JSON, or `curl`-test it by hitting an authenticated endpoint with the new session header to prove it works.

Plus useful debugging-script things: verbose mode that prints every wire frame, JWT introspection (you already have that), timeout handling that doesn't just `process.exit(1)`, and a `--dry-run` for the `connection-flow` step so you can paste in an already-obtained JWT and just do the gRPC half.

## Dependencies

You need a gRPC client and the `PushService` proto. Two options:

- **`@grpc/grpc-js` + `@grpc/proto-loader`** — load the proto dynamically from a `.proto` file you keep alongside the script. Cleanest, no vendor dependency on `@sc/*`.
- **`@sc/push-system-client`** directly — if you have the private npm registry access, just import `createPushClient`. Saves you from copying the `.proto` but pulls in `@cig/prelude`, `@schematique/core`, the whole stack.

For a debugging script, option 1 is better: self-contained, no auth to a private registry, works against any environment. The `.proto` you need is `sc/external/services/push/v1/server.proto`. You can either reconstruct it from the .d.ts.map traces (the message shapes are all visible) or grab it from `@sc/push-system-client/lib/proto-types/sc/external/services/push/v1/` if you have it. The minimal shape needed:

```proto
syntax = "proto3";
package sc.external.services.push.v1;
import "google/protobuf/any.proto";

service PushService {
  rpc Listen(stream ListenRequest) returns (stream ListenResponse);
}

message ListenRequest  { repeated PushCommand  commands  = 1; }
message ListenResponse { repeated PushEnvelope envelopes = 1; }

message PushCommand {
  oneof command {
    SubscribeCommand   subscribe   = 1;
    UnsubscribeCommand unsubscribe = 2;
    AckCommand         ack         = 3;
  }
}

message SubscribeCommand   { repeated string topics = 1; string key = 2; }
message UnsubscribeCommand { repeated string topics = 1; }
message AckCommand         { repeated string message_ids = 1; }

message PushEnvelope {
  string id = 1;
  repeated string topics = 3;
  repeated PushMessage messages = 8;
}

message PushMessage {
  oneof data {
    PushControlMessage control = 1;
    google.protobuf.Any any    = 2;
  }
}

message PushControlMessage {
  enum Command {
    UNSPECIFIED            = 0;
    COMMAND_STREAM_OPENED  = 1;
    COMMAND_CLOSE_RECONNECT = 2;
  }
  Command command = 1;
}
```

(Field numbers for `PushEnvelope` past `topics` are guesses; from the .d.ts.map you can see there are fields `sender`, `priority`, etc. between `topics=3` and `messages`. For a debug script that only needs to read `topics` and `messages`, unknown fields are skipped by the protobuf runtime so this minimal definition works for decoding even if numbering is off elsewhere. If you want to be exact, grab the real .proto.)

## Skeleton

```js
#!/usr/bin/env node
// rsi-auth-debug.js
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const path = require('path');
const { randomUUID } = require('crypto');
const fs = require('fs');

// --- CLI ---
const argv = process.argv.slice(2);
const opts = {
  verbose: argv.includes('-v') || argv.includes('--verbose'),
  dryRunGrpc: argv.includes('--dry-run-grpc'),  // skip connection-flow, use JWT from env
  jwtOnly: argv.includes('--jwt-only'),         // stop after JWT fetch
  testNewSession: argv.includes('--test'),      // after refresh, prove session works
  outFile: getOpt('--out'),                     // write result JSON to file
  env: getOpt('--env') || 'prod',
};
function getOpt(flag) {
  const i = argv.indexOf(flag);
  return i >= 0 ? argv[i + 1] : null;
}

const ENV = {
  prod:    { api: 'https://robertsspaceindustries.com/api/launcher/v3', root: 'https://robertsspaceindustries.com' },
  ptu:     { api: 'https://ptu.cloudimperiumgames.com/api/launcher/v3', root: 'https://ptu.cloudimperiumgames.com' },
  eptu:    { api: 'https://ptu.cloudimperiumgames.com/api/launcher/v3', root: 'https://ptu.cloudimperiumgames.com' },
  staging: { api: 'https://staging.cloudimperiumgames.com/api/launcher/v3', root: 'https://staging.cloudimperiumgames.com' },
}[opts.env];
if (!ENV) die(`unknown env ${opts.env}`);

const SESSION_TOKEN = process.env.SESSION_TOKEN;
const DEVICE_TOKEN  = process.env.DEVICE_TOKEN;
const PROVIDED_JWT  = process.env.RSI_JWT;
const UA = process.env.RSI_UA || 'RSI Launcher-2.x.x';

if (!DEVICE_TOKEN && !opts.dryRunGrpc) die('DEVICE_TOKEN required (or pass --dry-run-grpc + RSI_JWT)');

// --- logging ---
const log     = (...a) => console.log(...a);
const verbose = (...a) => opts.verbose && console.error('  [v]', ...a);
const wire    = (dir, label, obj) => opts.verbose && console.error(`  [wire ${dir}] ${label}:`, JSON.stringify(obj, null, 2));
function die(msg, extra) { console.error('FATAL:', msg); if (extra) console.error(extra); process.exit(1); }

// --- 1. demonstrate expiry (optional, informational) ---
async function probeExpiry() {
  if (!SESSION_TOKEN) { verbose('no SESSION_TOKEN, skipping probe'); return; }
  log('\n[1] probing session validity against games/library');
  const r = await fetch(`${ENV.api}/games/library`, {
    method: 'POST',
    headers: {
      'User-Agent': UA,
      'Content-Type': 'application/json',
      'X-Rsi-Token': SESSION_TOKEN,
      'X-Rsi-Device': DEVICE_TOKEN,
    },
    body: '{}',
  });
  const body = await r.json();
  if (body.code === 'errAuthExpired') log('    session expired, as expected');
  else if (body.success === 1)        log('    session is still valid — refresh not needed');
  else                                log('    unexpected response:', body);
  verbose('probe body:', body);
}

// --- 2. fetch JWT ---
async function fetchJwt() {
  log('\n[2] POST /connection-flow');
  const r = await fetch(`${ENV.root}/connection-flow`, {
    method: 'POST',
    headers: {
      'User-Agent': UA,
      'Content-Type': 'application/json',
      'Rsi-connection-flow': '',
      'X-Rsi-Device': DEVICE_TOKEN,
    },
    body: '{}',
    signal: AbortSignal.timeout(18000),
  });
  const body = await r.json();
  if (body.success !== 1 || !body.data) die('connection-flow failed', body);
  log('    JWT acquired');
  return body.data;
}

function decodeJwt(jwt) {
  const [, payload] = jwt.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

// --- 3. gRPC Listen ---
async function runListen(jwt, claims) {
  log('\n[3] dialling gRPC');
  const protoPath = path.join(__dirname, 'server.proto');
  if (!fs.existsSync(protoPath)) die(`missing ${protoPath}`);
  const pkgDef = protoLoader.loadSync(protoPath, {
    keepCase: true, longs: String, enums: String, defaults: true, oneofs: true,
    includeDirs: [__dirname],
  });
  const proto = grpc.loadPackageDefinition(pkgDef);
  const PushService = proto.sc.external.services.push.v1.PushService;

  const [host, port] = claims.host.split(':');
  const target = `${host}:${port || 443}`;
  verbose('target:', target, 'topic:', claims.topic);

  const client = new PushService(target, grpc.credentials.createSsl(), {
    'grpc.service_config': JSON.stringify({
      methodConfig: [{
        name: [{ service: 'sc.external.services.push.v1.PushService' }],
        retryPolicy: {
          maxAttempts: 5,
          initialBackoff: '0.1s',
          maxBackoff: '5s',
          backoffMultiplier: 1.5,
          retryableStatusCodes: ['UNKNOWN','UNAVAILABLE','RESOURCE_EXHAUSTED','NOT_FOUND','FAILED_PRECONDITION','OUT_OF_RANGE','DEADLINE_EXCEEDED','ABORTED','INTERNAL'],
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

  // overall budget from JWT
  const budgetMs = (claims.extended_ttl || 300) * 1000;
  const budgetTimer = setTimeout(() => {
    log(`    [!] extended_ttl budget exceeded (${budgetMs}ms), closing`);
    call.end();
  }, budgetMs);

  return new Promise((resolve, reject) => {
    let authResult = null;

    call.on('data', (response) => {
      wire('←', 'ListenResponse', response);
      for (const envelope of response.envelopes || []) {
        for (const msg of envelope.messages || []) {
          if (msg.data === 'control') {
            const cmd = msg.control.command;
            verbose('control:', cmd);
            if (cmd === 'COMMAND_STREAM_OPENED') {
              const sub = {
                commands: [{ subscribe: { topics: [claims.topic], key: subscriptionKey } }],
              };
              wire('→', 'ListenRequest', sub);
              call.write(sub);
            } else if (cmd === 'COMMAND_CLOSE_RECONNECT') {
              verbose('server asked to reconnect; ending');
              call.end();
            }
          } else if (msg.data === 'any') {
            const tu = msg.any.type_url;
            const valBuf = msg.any.value;
            let parsed;
            try { parsed = JSON.parse(Buffer.from(valBuf).toString('utf8')); }
            catch (e) { verbose('non-JSON Any payload, type_url:', tu); continue; }
            verbose('any payload type_url:', tu);
            authResult = parsed;
            // unsubscribe and close
            const unsub = { commands: [{ unsubscribe: { topics: [claims.topic] } }] };
            wire('→', 'ListenRequest', unsub);
            call.write(unsub);
            call.end();
          }
        }
      }
    });

    call.on('error', (err) => {
      clearTimeout(budgetTimer);
      client.close();
      reject(err);
    });
    call.on('end', () => {
      clearTimeout(budgetTimer);
      client.close();
      if (authResult) resolve(authResult);
      else reject(new Error('stream ended with no auth result'));
    });
  });
}

// --- 4. verify new session works ---
async function verifyNewSession(authData) {
  log('\n[4] verifying new session against games/library');
  const r = await fetch(`${ENV.api}/games/library`, {
    method: 'POST',
    headers: {
      'User-Agent': UA,
      'Content-Type': 'application/json',
      'X-Rsi-Token':  authData.data.session_id,
      'X-Rsi-Device': authData.data.device_id || DEVICE_TOKEN,
    },
    body: '{}',
  });
  const body = await r.json();
  if (body.success === 1) log('    new session works');
  else log('    new session FAILED:', body);
  verbose('verify body:', body);
}

// --- main ---
(async () => {
  await probeExpiry();

  let jwt;
  if (opts.dryRunGrpc) {
    if (!PROVIDED_JWT) die('--dry-run-grpc requires RSI_JWT env var');
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
  log(`      exp:          ${new Date(claims.exp * 1000).toISOString()}`);

  if (opts.jwtOnly) { log('\n[--jwt-only] exiting'); process.exit(0); }

  const authData = await runListen(jwt, claims);
  log('\n    auth payload received:');
  log(`      success:    ${authData.success}`);
  log(`      session_id: ${authData.data?.session_id?.slice(0, 16)}...`);
  log(`      device_id:  ${authData.data?.device_id}`);
  log(`      account_id: ${authData.data?.account_id}`);

  if (opts.outFile) {
    fs.writeFileSync(opts.outFile, JSON.stringify(authData, null, 2));
    log(`\n    wrote ${opts.outFile}`);
  }

  if (opts.testNewSession) await verifyNewSession(authData);

  process.exit(0);
})().catch((e) => die('unhandled:', e.stack || e));
```

## Why each piece is there

- **`probeExpiry`** is informational, not load-bearing. Keep it because when something else breaks you want to know whether the input session was actually stale or whether you broke something earlier. Body is `{}` not `"undefined"`.
- **`fetchJwt`** mirrors the launcher's `getConnectionToken` exactly: same URL, same three headers, 18 s timeout matching `AbortSignal.timeout(18000)` from `i/clients/rsi.ts`.
- **`decodeJwt`** uses `base64url` decoding (Node 16+), which is correct for JWT. Plain `base64` works most of the time but trips on JWTs that contain `-`/`_` characters.
- **`runListen`** is the missing half of your old script. It does what `Ue.startPlatformClient` + `Ne.subscribe` + `DefaultPushClient.readCommands` do, condensed:
  - Loads the proto via `proto-loader`.
  - Creates an SSL gRPC channel.
  - Sets `grpc.service_config` with the same retry policy the launcher uses, so behavior matches under transient failures.
  - `waitForReady(deadline)` matches the SDK's 5 s `initialConnectionTimeout`.
  - Attaches `Authorization: Bearer <jwt>` metadata, matching `getMetadataWithAuthWithToken`.
  - Starts the bidirectional `Listen` call.
  - On `STREAM_OPENED` control message, sends `SubscribeCommand` with `topics: [claims.topic]` and a `randomUUID()` `subscriptionKey` — matching `enqueueSubcribeCommand`.
  - On `any`-typed message, JSON-parses the value bytes — matching the registered decoder for `type.googleapis.com`.
  - Sends `UnsubscribeCommand` and ends the stream — matching `Ne.stopListening`.
  - `extended_ttl` budget from JWT, matching `setTimeout(..., 1e3 * t.extended_ttl || 3e5)` from `main.js:2204`.
- **`verifyNewSession`** is what closes the loop. The old script's biggest sin is "got a JWT, did nothing with it." This one proves the refreshed session works by issuing a real authenticated call.

## Useful CLI flags

- `--env prod|ptu|eptu|staging` — pick environment without editing the script.
- `-v` — wire-level logging of every `ListenRequest`/`ListenResponse` frame, plus channel state transitions. Indispensable when the server starts behaving weird.
- `--dry-run-grpc` — paste a JWT from somewhere else (e.g., captured from launcher logs) into `RSI_JWT` and skip the connection-flow step. Useful for testing gRPC behavior against expired JWTs, replay attacks, or topic-injection experiments.
- `--jwt-only` — stop after fetching+decoding the JWT. Useful when you just want to inspect what the platform issues for a given device.
- `--out auth.json` — dump the full auth payload to a file. Useful for diffing across runs, or for piping into another tool.
- `--test` — run the verification step. Off by default because it issues an extra POST that you might not always want (e.g., if you're rate-limited).

## Things this still doesn't do, by design

- **No MFA branch.** The fallback path when the device isn't recognized (the classic-signin-with-MFA path) is interactive — you'd need to capture a TOTP from somewhere. A debugging script that prompts for MFA codes is fine but goes well past "refresh"; if you want it, add a `--mfa` mode that reads from stdin after an `ErrMultiStepRequired` from a `signin` POST.
- **No persistent state writes.** It doesn't touch the launcher's `userData` store. If you want to inject the refreshed session back into the real launcher, that's a separate concern — you'd have to either run the launcher's main process IPC manually or write the JSON store file directly while the launcher isn't running, neither of which belongs in a debugging script.
- **No reconnect loop.** The SDK's `DefaultPushClient` reconnects forever; this script does one shot and exits. That's the right call for debugging — if the auth result doesn't arrive within `extended_ttl`, you want to know that, not have it silently retry.
- **No JWT signature verification.** Neither does the launcher; the platform's JWT-signing keys aren't published. If you want verification you'd need the JWKS endpoint or a hardcoded public key.

## Things to bolt on if you want more

- A `--capture <file>` mode that writes raw protobuf bytes of every frame to disk, for later analysis with `protoc --decode` or `protobuf-inspector`. Useful when the .proto you have is partial and you want to discover unknown fields.
- A `--inject <topic>` mode that subscribes to additional topics beyond the JWT's. The server will reject any topic the JWT's claims don't authorize, which gives you a probe for what scope a given connection-flow JWT actually has.
- A `--no-ack` mode that omits acks for diagnosing server-side retry behavior.
- A `--metadata k=v,...` flag that adds arbitrary gRPC metadata, for testing what headers the push server inspects.

Throw the old script away, drop this in. The `.proto` you'll need to place next to it can be sourced from the `@sc/push-system-client/lib/proto-types/sc/external/services/push/v1/` directory of the SDK dump you have, or reconstructed from the type definitions there.

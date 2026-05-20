#!/usr/bin/env node
// Probe sc.internal.services.solar_system_shop.v1.SolarSystemShopService
// against a push-services gateway with a game JWT.
//
// Env:
//   RSI_JWT   bearer token (from gametoken.js)
//
// Args (positional):
//   <host:port>           gRPC target (e.g. release.servicesEndpoint without scheme)
//
// Flags:
//   --call <Method>       which RPC to invoke (default: probe several read-only ones)
//   --arg <json>          request payload as JSON (default: empty object)
//   --plaintext           use insecure channel (default: TLS)
//   -v / --verbose

const path = require('path');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const argv = process.argv.slice(2);
const flag = (...names) => names.some(n => argv.includes(n));
const opt  = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };

const positional = argv.filter(a => !a.startsWith('--') && !['-v'].includes(a));
const host = positional[0] || die('usage: shop.js <host:port> [--call Method] [--arg JSON] [-v]');

const opts = {
  call:      opt('--call'),
  arg:       opt('--arg'),
  plaintext: flag('--plaintext'),
  verbose:   flag('-v', '--verbose'),
};

const JWT = process.env.RSI_JWT || die('RSI_JWT env var required');

function die(msg, extra) {
  console.error('FATAL:', msg);
  if (extra) console.error(extra);
  process.exit(1);
}
const dbg = (...a) => opts.verbose && console.error('  [v]', ...a);

// --- proto load ---
const PROTO_ROOT = path.join(__dirname, 'scproto', 'proto');
const INCLUDES = [
  PROTO_ROOT,
  path.join(__dirname, 'scproto', 'vendor', 'google', 'api-common-protos'),
  path.join(__dirname, 'scproto', 'vendor', 'grpc-gateway'),
];
const SHOP_PROTO = path.join(PROTO_ROOT, 'sc', 'internal', 'services', 'solar_system_shop', 'v1', 'api.proto');

const pkgDef = protoLoader.loadSync(SHOP_PROTO, {
  keepCase: true, longs: String, enums: String, defaults: true, oneofs: true,
  includeDirs: INCLUDES,
});
const proto = grpc.loadPackageDefinition(pkgDef);
const ShopService = proto.sc.internal.services.solar_system_shop.v1.SolarSystemShopService;
if (!ShopService) die('SolarSystemShopService not loaded');

const creds = opts.plaintext
  ? grpc.credentials.createInsecure()
  : grpc.credentials.createSsl();
const client = new ShopService(host, creds, {});

const metadata = new grpc.Metadata();
metadata.add('authorization', `Bearer ${JWT}`);

const PROBE_PLAN = [
  { method: 'GetGlobalCommodities',       arg: {} },
  { method: 'GetItemPricesFromAllShops',  arg: { item_ids: [] } },
  { method: 'GetGlobalInventory',         arg: {} },
];

async function callOne(method, arg) {
  const camel = method.charAt(0).toLowerCase() + method.slice(1);
  const fn = client[camel] || client[method];
  if (typeof fn !== 'function') {
    return { status: 'NO_METHOD', method, error: `method ${method} not on client (have: ${Object.keys(client).filter(k => typeof client[k] === 'function').slice(0, 10).join(',')})` };
  }
  dbg(`-> ${method}(${JSON.stringify(arg)})`);
  return await new Promise((resolve) => {
    fn.call(client, arg, metadata, { deadline: Date.now() + 12_000 }, (err, response) => {
      if (err) {
        resolve({
          status: 'ERROR',
          method,
          code: err.code,
          codeName: Object.keys(grpc.status).find(k => grpc.status[k] === err.code),
          details: err.details,
          metadata: err.metadata ? err.metadata.getMap() : undefined,
        });
      } else {
        resolve({ status: 'OK', method, response });
      }
    });
  });
}

(async () => {
  console.log(`Target:  ${host}`);
  console.log(`Channel: ${opts.plaintext ? 'plaintext' : 'TLS'}`);
  console.log(`Service: sc.internal.services.solar_system_shop.v1.SolarSystemShopService`);
  console.log(`JWT:     ${JWT.slice(0, 24)}... (${JWT.length}B)`);
  console.log();

  const plan = opts.call
    ? [{ method: opts.call, arg: opts.arg ? JSON.parse(opts.arg) : {} }]
    : PROBE_PLAN;

  for (const { method, arg } of plan) {
    const r = await callOne(method, arg);
    if (r.status === 'OK') {
      console.log(`  ${method}: OK`);
      console.log(JSON.stringify(r.response, null, 2));
    } else if (r.status === 'ERROR') {
      console.log(`  ${method}: ${r.codeName || r.code} — ${r.details}`);
      if (opts.verbose && r.metadata && Object.keys(r.metadata).length) {
        console.error('    metadata:', r.metadata);
      }
    } else {
      console.log(`  ${method}: ${r.status} — ${r.error}`);
    }
  }
  client.close();
})();

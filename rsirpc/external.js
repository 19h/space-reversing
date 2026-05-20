#!/usr/bin/env node
// Catalogue all RPCs under sc.external.* — the surface the istio-envoy gateway
// at `pub-sc-alpha-*` routes externally. Output: services.txt (markdown table).

const fs = require('fs');
const protobuf = require('protobufjs');
const { buildRegistry } = require('./proto-registry');

const r = buildRegistry();

function* walkServices(ns, prefix = '') {
  for (const c of Object.values(ns.nested || {})) {
    const fq = prefix + c.name;
    if (c instanceof protobuf.Service) yield { fq, svc: c };
    if (c.nested) yield* walkServices(c, fq + '.');
  }
}

const services = [];
for (const { fq, svc } of walkServices(r.root.lookup('sc'), 'sc.')) {
  // sc.external.* and sc.game.* are externally addressable surfaces; sc.internal.* are mesh-only.
  if (!fq.startsWith('sc.external.') && !fq.startsWith('sc.game.')) continue;
  services.push({ fq, svc });
}
services.sort((a, b) => a.fq.localeCompare(b.fq));

const lines = [];
lines.push(`# Externally addressable gRPC RPCs (sc.external.*, sc.game.*)`);
lines.push(`# Source: scproto/proto via proto-registry.js`);
lines.push(`# Format per RPC:`);
lines.push(`#   <stream>  ServiceMethod  (RequestType) -> ResponseType   [http]`);
lines.push(`#     stream: u=unary, ss=server-stream, cs=client-stream, bidi=bidirectional`);
lines.push(`#     [http]  present iff the proto declares a google.api.http annotation`);
lines.push('');

let svcCount = 0, rpcCount = 0;
for (const { fq, svc } of services) {
  const methods = Object.entries(svc.methods);
  if (methods.length === 0) continue;
  svcCount++;
  lines.push(`## ${fq}    (${methods.length} RPC${methods.length === 1 ? '' : 's'})`);
  for (const [name, m] of methods) {
    rpcCount++;
    const cs = m.requestStream  ? 'c' : '';
    const ss = m.responseStream ? 's' : '';
    const stream = cs && ss ? 'bidi' : cs ? 'cs  ' : ss ? 'ss  ' : 'u   ';
    const httpOpt = m.options && (m.options['(google.api.http)'] || m.options['(google.api.http).post'] || m.options['(google.api.http).get']);
    const http = m.options
      ? Object.entries(m.options).find(([k]) => k.includes('google.api.http'))
      : null;
    const httpTag = http ? '  [http]' : '';
    lines.push(`  ${stream}  ${name}  (${m.requestType}) -> ${m.responseType}${httpTag}`);
  }
  lines.push('');
}
lines.push(`# Total: ${svcCount} services, ${rpcCount} RPCs`);

fs.writeFileSync('services.txt', lines.join('\n') + '\n');
console.log(`wrote services.txt: ${svcCount} services, ${rpcCount} RPCs`);

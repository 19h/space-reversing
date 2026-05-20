#!/usr/bin/env node
// Catalogue every streaming RPC in sc.external.* and dump the structure of its
// response payload — so we know what events / records to expect coming back.

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

function describeType(typeName, root, seen = new Set(), depth = 0) {
  // Print field list of a message type. Recurse one level for nested message
  // fields (skip well-known/Any to avoid cycles), and call out oneofs.
  if (depth > 2) return '    (...further nested types elided...)';
  if (seen.has(typeName)) return `    (recursive: ${typeName})`;
  seen = new Set([...seen, typeName]);

  let T;
  try { T = root.lookupType(typeName); }
  catch (_) { return `    (type not in registry: ${typeName})`; }

  const lines = [];
  // collect oneof groups
  const inOneof = {};
  if (T.oneofsArray) for (const o of T.oneofsArray) for (const f of o.oneof) inOneof[f] = o.name;

  for (const f of T.fieldsArray) {
    const card = f.repeated ? 'repeated ' : f.map ? 'map ' : '';
    const ofname = inOneof[f.name] ? ` (oneof ${inOneof[f.name]})` : '';
    const optional = f.optional && !f.repeated && !f.map ? ' optional' : '';
    lines.push(`${'  '.repeat(depth + 1)}- ${f.name}: ${card}${f.type}${optional}${ofname}`);

    // Recurse for message-typed fields that are nested under this proto namespace
    if (f.resolvedType && f.resolvedType.fieldsArray && !f.map) {
      const tName = f.resolvedType.fullName.replace(/^\./, '');
      // Don't dive into well-known wrappers / huge engine types
      if (tName.startsWith('google.protobuf.')) continue;
      if (tName === typeName) continue;
      const inner = describeType(tName, root, seen, depth + 1);
      if (inner && !inner.startsWith('    (')) {
        lines.push(inner);
      }
    }
  }
  return lines.join('\n');
}

const out = [];
out.push('# Streaming RPCs and their response-message shapes (sc.external.*, sc.game.*)');
out.push('# Each entry: Service.Method  (cs|ss|bidi)  Request -> Response');
out.push('# Followed by recursive field listing of the response type (2 levels deep).');
out.push('');

let count = 0;
const services = [];
for (const x of walkServices(r.root.lookup('sc'), 'sc.')) {
  if (!x.fq.startsWith('sc.external.') && !x.fq.startsWith('sc.game.')) continue;
  services.push(x);
}
services.sort((a, b) => a.fq.localeCompare(b.fq));

for (const { fq, svc } of services) {
  for (const [name, m] of Object.entries(svc.methods)) {
    if (!m.requestStream && !m.responseStream) continue;
    count++;
    m.resolve();  // ensure resolvedType set
    const stream = m.requestStream && m.responseStream ? 'bidi'
                 : m.requestStream                     ? 'cs'
                 : 'ss';
    out.push(`## ${fq}.${name}  (${stream})`);
    out.push(`   request:  ${m.requestType}`);
    out.push(`   response: ${m.responseType}`);
    out.push('');
    out.push('   Response fields:');
    out.push(describeType(m.responseType, r.root, new Set(), 0));
    out.push('');
  }
}
out.push(`# Total: ${count} streaming RPCs`);

fs.writeFileSync('stream-types.txt', out.join('\n') + '\n');
console.log(`wrote stream-types.txt (${count} streaming RPCs)`);

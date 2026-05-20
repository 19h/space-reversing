// Walk scproto/ once at startup, build a protobuf.Root of every loadable .proto,
// expose decodeAny() that maps `type.googleapis.com/<full_name>` -> JS object.

const fs = require('fs');
const path = require('path');
const protobuf = require('protobufjs');

const SCPROTO = path.join(__dirname, 'scproto');
const PROTO_DIR = path.join(SCPROTO, 'proto');
// protobufjs ships the google.protobuf.* wellknowns; without these the openapiv2/grpc-gateway
// extensions can't be resolved (extend google.protobuf.MethodOptions etc).
// We want the dir containing `google/`, not `google/protobuf/`. Three dirnames from descriptor.proto.
const PBJS_BUNDLED = path.dirname(path.dirname(path.dirname(require.resolve('protobufjs/google/protobuf/descriptor.proto'))));
const INCLUDES = [
  PROTO_DIR,
  path.join(SCPROTO, 'vendor', 'google', 'api-common-protos'),
  path.join(SCPROTO, 'vendor', 'grpc-gateway'),
  path.join(SCPROTO, 'vendor', 'grpc-proto'),
  path.join(SCPROTO, 'vendor', 'opentelemetry'),
  PBJS_BUNDLED,
];

// Must load before any sc/* proto that imports google.api.* or openapiv2 options.
const PRELOAD = [
  'google/protobuf/descriptor.proto',
  'google/api/http.proto',
  'google/api/annotations.proto',
  'protoc-gen-openapiv2/options/openapiv2.proto',
  'protoc-gen-openapiv2/options/annotations.proto',
];

function findProtos(dir) {
  const out = [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_) { return out; }
  for (const ent of entries) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) out.push(...findProtos(p));
    else if (ent.name.endsWith('.proto')) out.push(p);
  }
  return out;
}

function buildRegistry({ verbose = false } = {}) {
  const root = new protobuf.Root();
  root.resolvePath = (origin, target) => {
    if (path.isAbsolute(target) && fs.existsSync(target)) return target;
    for (const dir of INCLUDES) {
      const candidate = path.join(dir, target);
      if (fs.existsSync(candidate)) return candidate;
    }
    return null;
  };

  for (const p of PRELOAD) {
    try { root.loadSync(p, { keepCase: true }); }
    catch (e) {
      if (verbose) console.error('  [registry] preload failed:', p, '->', e.message.split('\n')[0]);
    }
  }

  const files = findProtos(PROTO_DIR);
  let loaded = 0, failed = 0;
  const failures = [];
  for (const f of files) {
    try {
      root.loadSync(f, { keepCase: true });
      loaded++;
    } catch (e) {
      failed++;
      failures.push({ file: path.relative(PROTO_DIR, f), error: e.message });
    }
  }
  if (verbose && failures.length) {
    console.error(`  [registry] ${failed}/${files.length} protos failed to load. First few:`);
    for (const f of failures.slice(0, 5)) console.error('  ', f.file, '->', f.error);
  }
  return { root, loaded, failed, total: files.length };
}

function decodeAny(root, any) {
  if (!any || !any.type_url) return null;
  const fullName = any.type_url.replace(/^[^/]*\//, '');
  const buf = Buffer.isBuffer(any.value) ? any.value : Buffer.from(any.value || []);

  // Try JSON first — launcher publishes auth payloads as utf8 JSON inside Any.
  if (buf.length > 0 && (buf[0] === 0x7b /* { */ || buf[0] === 0x5b /* [ */)) {
    try {
      const obj = JSON.parse(buf.toString('utf8'));
      return { type: fullName, encoding: 'json', data: obj };
    } catch (_) { /* fall through to binary */ }
  }

  let Type;
  try { Type = root.lookupType(fullName); }
  catch (_) {
    return { type: fullName, encoding: 'unknown', raw: buf, error: 'type-not-in-registry' };
  }
  try {
    const msg = Type.decode(buf);
    const obj = Type.toObject(msg, {
      longs:    String,
      enums:    String,
      bytes:    'base64',
      defaults: false,
      oneofs:   true,
    });
    return { type: fullName, encoding: 'protobuf', data: obj };
  } catch (e) {
    return { type: fullName, encoding: 'protobuf', raw: buf, error: e.message };
  }
}

module.exports = { buildRegistry, decodeAny };

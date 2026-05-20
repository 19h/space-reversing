#!/usr/bin/env node
// Probe every safe-to-call unary RPC under sc.external.* with an empty request.
// Categorizes status codes:
//   OK                  service routed AND request was valid (rare with empty body)
//   INVALID_ARGUMENT    routed, my empty body was wrong  → service IS reachable
//   NOT_FOUND           routed, resource doesn't exist     → service IS reachable
//   PERMISSION_DENIED   routed, JWT lacks scope            → service IS reachable
//   FAILED_PRECONDITION routed, state precondition not met → service IS reachable
//   UNIMPLEMENTED       NOT routed at this gateway
//   UNAUTHENTICATED     auth header rejected (shouldn't happen with valid JWT)
//
// Env:  RSI_JWT  (from gametoken.js)
// Arg:  <host:port>

const path = require('path');
const fs = require('fs');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const HOST = process.argv[2] || die('usage: probe-all.js <host:port>');
const JWT = process.env.RSI_JWT || die('RSI_JWT env var required');

function die(msg) { console.error('FATAL:', msg); process.exit(1); }

const PROTO_ROOT = path.join(__dirname, 'scproto', 'proto');
const INCLUDES = [
  PROTO_ROOT,
  path.join(__dirname, 'scproto', 'vendor', 'google', 'api-common-protos'),
  path.join(__dirname, 'scproto', 'vendor', 'grpc-gateway'),
];

// (service-fq, method, package, file-relative) — write-free reads only.
// Listed explicitly so mutations / sensitive RPCs cannot accidentally be probed.
const PROBES = [
  // service                                                  method                          api.proto
  ['sc.external.services.echo.v1.EchoService',                'Echo',                         'sc/external/services/echo/v1/api.proto'],
  ['sc.external.services.identity.v1.IdentityService',        'GetCurrentPlayer',             'sc/external/services/identity/v1/api.proto'],
  ['sc.external.services.identity.v1.IdentityService',        'GetPlayersNames',              'sc/external/services/identity/v1/api.proto'],
  ['sc.external.services.contacts.v1.ContactsService',        'ListContacts',                 'sc/external/services/contacts/v1/api.proto'],
  ['sc.external.services.contacts.v1.ContactsService',        'ListPendingFriendRequests',    'sc/external/services/contacts/v1/api.proto'],
  ['sc.external.services.contacts.v1.ContactsService',        'GetShardInfo',                 'sc/external/services/contacts/v1/api.proto'],
  ['sc.external.services.friends.v1.FriendService',           'GetFriendList',                'sc/external/services/friends/v1/api.proto'],
  ['sc.external.services.friends.v1.FriendService',           'GetBlockedAccount',            'sc/external/services/friends/v1/api.proto'],
  ['sc.external.services.social.v1.SocialService',            'ListGroups',                   'sc/external/services/social/v1/api.proto'],
  ['sc.external.services.social.v1.SocialService',            'ListPendingInvitations',       'sc/external/services/social/v1/api.proto'],
  ['sc.external.services.social.v1.SocialService',            'GetInstanceInfo',              'sc/external/services/social/v1/api.proto'],
  ['sc.external.services.squad.v1.SquadService',              'Get',                          'sc/external/services/squad/v1/api.proto'],
  ['sc.external.services.chat.v1.ChatService',                'ListMessages',                 'sc/external/services/chat/v1/api.proto'],
  ['sc.external.services.rtc.v1.RTCService',                  'GetChannels',                  'sc/external/services/rtc/v1/api.proto'],
  ['sc.external.services.rtc.v1.RTCService',                  'GetPendingCalls',              'sc/external/services/rtc/v1/api.proto'],
  ['sc.external.services.notifications.v1.NotificationsService','Find',                       'sc/external/services/notifications/v1/api.proto'],
  ['sc.external.services.reputation.v1.ReputationService',    'Get',                          'sc/external/services/reputation/v1/api.proto'],
  ['sc.external.services.reputation.v1.ReputationService',    'QueryReputations',             'sc/external/services/reputation/v1/api.proto'],
  ['sc.external.services.reputation.v1.ReputationService',    'GetPreferences',               'sc/external/services/reputation/v1/api.proto'],
  ['sc.external.services.discipline.v1.DisciplineService',    'QuerySanctions',               'sc/external/services/discipline/v1/api.proto'],
  ['sc.external.services.ledger.v1.LedgerService',            'GetFunds',                     'sc/external/services/ledger/v1/api.proto'],
  ['sc.external.services.configuration.v1.ConfigService',     'QueryConfig',                  'sc/external/services/configuration/v1/api.proto'],
  ['sc.external.services.entitlement.v1.ExternalEntitlementService', 'Query',                 'sc/external/services/entitlement/v1/api.proto'],
  ['sc.external.services.entity_document.v1.ExternalEntityDocumentService', 'Fetch',          'sc/external/services/entity_document/v1/api.proto'],
  ['sc.external.services.entitygraph.v1.EntityGraphService',  'EntityQuery',                  'sc/external/services/entitygraph/v1/api.proto'],
  ['sc.external.services.entitygraph.v1.EntityGraphService',  'GetDatabaseVersion',           'sc/external/services/entitygraph/v1/api.proto'],
  ['sc.external.services.entitygraph.v1.EntityGraphService',  'InventoryQuery',               'sc/external/services/entitygraph/v1/api.proto'],
  ['sc.external.services.instance_manager.v1.InstanceManagerService','GetAvailableInstances', 'sc/external/services/instance_manager/v1/api.proto'],
  ['sc.external.services.land_claim.v1.LandClaimService',     'QueryAreaClaims',              'sc/external/services/land_claim/v1/api.proto'],
  ['sc.external.services.land_claim.v1.LandClaimService',     'QueryOwnedClaims',             'sc/external/services/land_claim/v1/api.proto'],
  ['sc.external.services.match.v1.MatchService',              'Get',                          'sc/external/services/match/v1/api.proto'],
  ['sc.external.services.matchmaking.v1.FrontendService',     'GetLastAssignment',            'sc/external/services/matchmaking/v1/frontend_api.proto'],
  ['sc.external.services.mission_scenario.v1.ScenarioService','QueryScenarioStatus',          'sc/external/services/mission_scenario/v1/api.proto'],
  ['sc.external.services.mission_service.v1.MissionService',  'QueryActiveMissions',          'sc/external/services/mission_service/v1/api.proto'],
  ['sc.external.services.mission_service.v1.MissionService',  'QueryMissions',                'sc/external/services/mission_service/v1/api.proto'],
  ['sc.external.services.mission_token.v1.MissionTokenService','QueryTokens',                 'sc/external/services/mission_token/v1/api.proto'],
  ['sc.external.services.rental.v1.ExternalRentalService',    'QueryRentals',                 'sc/external/services/rental/v1/api.proto'],
  ['sc.external.services.contract_broker.v1.ContractBrokerService','QueryContracts',          'sc/external/services/contract_broker/v1/api.proto'],
  ['sc.external.services.custom_lobby.v1.CustomLobbyService', 'Get',                          'sc/external/services/custom_lobby/v1/api.proto'],
  ['sc.external.services.stats.v1.StatsService',              'FindStats',                    'sc/external/services/stats/v1/api.proto'],
  ['sc.external.services.dynamic_game_assets.v1.DynamicGameAssetsService','GetAssetForScreen','sc/external/services/dynamic_game_assets/v1/api.proto'],
  // baseline known-good
  ['sc.external.services.push.v1.PushService',                'Listen',                       'sc/external/services/push/v1/server.proto'], // SKIP — streaming
];

const SKIP_STREAMING = new Set(['Listen']);
const STATUS = Object.fromEntries(Object.entries(grpc.status).map(([k, v]) => [v, k]));

function loadService(fq, file) {
  const pkgDef = protoLoader.loadSync(path.join(PROTO_ROOT, file), {
    keepCase: true, longs: String, enums: String, defaults: true, oneofs: true,
    includeDirs: INCLUDES,
  });
  const pkg = grpc.loadPackageDefinition(pkgDef);
  const segs = fq.split('.');
  let cur = pkg;
  for (const s of segs) cur = cur[s];
  return cur;
}

function callUnary(ServiceCtor, method, host, jwt) {
  return new Promise((resolve) => {
    const client = new ServiceCtor(host, grpc.credentials.createSsl(), {});
    const md = new grpc.Metadata();
    md.add('authorization', `Bearer ${jwt}`);
    const camel = method.charAt(0).toLowerCase() + method.slice(1);
    const fn = client[camel] || client[method];
    if (typeof fn !== 'function') { client.close(); return resolve({ kind: 'NO_METHOD' }); }
    const deadline = Date.now() + 8_000;
    fn.call(client, {}, md, { deadline }, (err, response) => {
      client.close();
      if (err) {
        resolve({
          kind:    'ERROR',
          code:    err.code,
          codeName: STATUS[err.code] || String(err.code),
          details: err.details,
          meta:    err.metadata ? err.metadata.getMap() : undefined,
        });
      } else {
        resolve({ kind: 'OK', response });
      }
    });
  });
}

(async () => {
  const results = [];
  for (const [fq, method, file] of PROBES) {
    if (SKIP_STREAMING.has(method)) {
      results.push({ fq, method, file, status: 'SKIPPED', detail: 'streaming RPC' });
      continue;
    }
    let Service;
    try { Service = loadService(fq, file); }
    catch (e) {
      results.push({ fq, method, file, status: 'PROTO_LOAD_FAIL', detail: e.message.split('\n')[0] });
      continue;
    }
    if (!Service) {
      results.push({ fq, method, file, status: 'PROTO_LOOKUP_FAIL', detail: 'service not at lookup path' });
      continue;
    }
    const r = await callUnary(Service, method, HOST, JWT);
    if (r.kind === 'OK') {
      results.push({ fq, method, file, status: 'OK', detail: '(empty req returned ok)' });
    } else if (r.kind === 'NO_METHOD') {
      results.push({ fq, method, file, status: 'NO_METHOD', detail: 'method not on stub' });
    } else {
      results.push({
        fq, method, file,
        status:  r.codeName,
        detail:  (r.details || '').slice(0, 120),
        srvMeta: r.meta?.server,
      });
    }
  }

  // group
  const groups = {};
  for (const r of results) (groups[r.status] ??= []).push(r);
  const lines = [];
  lines.push('# Live gateway probe — sc.external.* surface');
  lines.push(`# Target: ${HOST}`);
  lines.push(`# Probes: ${results.length}`);
  lines.push('');
  for (const status of Object.keys(groups).sort()) {
    const tag =
      status === 'UNIMPLEMENTED'    ? 'NOT ROUTED' :
      status === 'INVALID_ARGUMENT' ? 'reachable (bad empty req)' :
      status === 'PERMISSION_DENIED'? 'reachable (no scope)' :
      status === 'NOT_FOUND'        ? 'reachable (no such resource)' :
      status === 'FAILED_PRECONDITION'? 'reachable (precondition)' :
      status === 'OK'               ? 'OK' :
      status;
    lines.push(`## ${status}   — ${tag}   (${groups[status].length})`);
    for (const r of groups[status]) {
      lines.push(`  ${r.fq}/${r.method}    ${r.detail ? '— ' + r.detail : ''}`);
    }
    lines.push('');
  }
  fs.writeFileSync('probe-results.txt', lines.join('\n'));
  console.log(`wrote probe-results.txt (${results.length} probes)`);
})();

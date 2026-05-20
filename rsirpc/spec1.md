# RSI Launcher — Re-Authentication Spec: Cold Start with Stale Session and Valid Device, Through to gRPC-Authenticated Push Subscription

**Scope.** This document specifies the complete sequence of operations executed by the RSI Launcher (Electron app, main + renderer + preload) starting from a state where:
- A `DeviceState` is persisted in the main-process store and is still within its server-side validity window (≤30 days since issuance).
- A `SessionState` is persisted but its server-side TTL has elapsed (sessions are short-lived; this expiry is *not* checked client-side, only the server detects it).
- An `IdentityState` is persisted.
- Network is online; the user is signing back in to consume a third-party-auth or classic-auth result and ultimately to subscribe to the push-system gRPC topic that delivers the new session.

**Out of scope.** Initial install/first-time login; offline mode; PTU-from-PUB cross-environment session acquisition (`signin/claims`); MFA enrollment.

**Conventions.**
- All host names, paths, header names, JSON fields, file paths, and event names below are verbatim from the analyzed bundle and the SDK source under `@sc/push-system-client`, `@sc/grpc-toolkit`, `@sc/push-system-common`.
- Production environment is assumed throughout; substitute `ptu.cloudimperiumgames.com` / `staging.cloudimperiumgames.com` / etc. for non-prod environments per `configuration.env.<env>.{apiUrl,rootUrl}`.
- IPC channels referenced by name (`AUTHENTICATION_PROCESS_*`, `USER_SIGNIN`, etc.) correspond to the keys on `app_shared_1.ipcEvents.*` consumed by both `preload.js` and `main.js`.

---

## 1. Initial State at Cold Start

### 1.1 Persistent state on disk

Stored under the Electron `userData` directory (Windows: `%APPDATA%\RSI Launcher\`, macOS: `~/Library/Application Support/RSI Launcher/`) by the main-process store service (electron-store-style key/value JSON file):

| Key | Type | Example value |
|---|---|---|
| `session` | `SessionState` | `{cookie: "Rsi-Token", key: "X-Rsi-Token", value: "AbCdE.....stale....="}` |
| `device` | `DeviceState` | `{cookie: "_rsi_device", key: "X-Rsi-Device", value: "d7f3a1b2-8e44-4c01-9f12-aa55bb66cc77", duration: "month", expires: 1739812345000}` |
| `identity` | `IdentityState` | `{username: "user@example.com", heapAccountId: "1234567", trackingMetricsId: "...", displayName: "PilotName", nickname: "PilotName", avatar: "https://...", privileged: false}` |

The `expires` on `DeviceState` is a *client-side hint* computed at MFA time as `Date.now() + mapDeviceDurationToTime(duration)`. It is read by the launcher only to decide whether to attempt to send the device header. The authoritative server-side cap is `configuration.authenticationExpiry = 2592000000` ms = 30 days from device issuance, regardless of client-side hint.

`SessionState` has no `expires` field. **The launcher has no client-side mechanism to detect session staleness.** It will always attach the session header until a server response indicates expiry.

### 1.2 Persistent state on the server

The RSI platform retains:
- **Device record** keyed by `device_id`, scoped to `account_id`, valid for 30 days from issuance. Server-side this is what permits the MFA-skip on re-authentication and what permits issuance of a connection-flow JWT addressed to this device.
- **No session record** (the session has expired and been garbage-collected, or the JWT-equivalent session token has passed its `exp`).

---

## 2. Process Boot Sequence

### 2.1 Main process boot

`main.js`. On `app.whenReady()`:

1. `registerSchemesAsPrivileged([{scheme: "file"}, ...c])` where `c` enumerates `["rsi", "launcher", "status", "rsi+local", "rsi+reviewapp", "rsi+qaheap3", "rsi+eptu", "rsi+ptu", "rsi+staging", "rsi+prod", "launcher+local", ..., "launcher+prod"]` — 17 schemes total. Each gets `privileges: {bypassCSP: true, supportFetchAPI: true, corsEnabled: true}`.
2. `protocol.registerHttpProtocol(scheme, g(scheme))` for each scheme. The factory `g(e)` is at `main.js:3834`. For non-suffixed schemes (`rsi`, `launcher`), the environment is taken from `s.environment` (bundle-baked default). For suffixed schemes, the environment is `e.split("+")[1]`.
3. `app.on("ready", ...)` initializes service singletons; relevant to this spec: `gt` (storage service), `pe` (auth-flow listener, class `De`), `j` (session service).
4. Identity hydrates from store synchronously into the main process's global config: `N().identity = u.store.get("identity")`.
5. Sentry main-process integration starts via `T.init({dsn: O.configuration.sentry.dsn, ...})`; crashreporter starts with `submitURL: 'https://sentry.cloudimperiumgames.com/api/47/minidump/?sentry_key=81458b2190d22bef4e778a6512f2649f'`.

### 2.2 Preload bridge attachment

`preload.js`. On `contextBridge.exposeInMainWorld("launcherAPI", exports.launcherAPI)`:
- `launcherAPI.authentication.*` exposes IPC senders/receivers for `AUTHENTICATION_PROCESS_START`, `AUTHENTICATION_PROCESS_CANCEL`, `USER_SIGNIN`, `USER_SIGNOUT`, and listeners for `AUTHENTICATION_PROCESS_START_SUCCESSFUL`, `..._FAILED`, `..._TIMEOUT`, `..._SUCCESSFUL` (the success terminal), `..._FAILED` (the terminal failure).
- `launcherAPI.store.getValueFromStore<T>(key)` exposes a generic store reader bound to `ipcEvents.store.STORE_GET`.
- `launcherAPI.game.getGlobalConfig()` exposes `ipcEvents.config.GET_GLOBAL`, returning `N()` from main (includes `{environment, launcherVersion, identity, ...}`).
- `launcherAPI.window.setOpenExternalWindow(url)` posts `ipcEvents.window.WINDOW_OPEN_EXTERNAL`.

### 2.3 Renderer boot — Launcher API client hydration

`i/clients/launcher.ts`. `Launcher.getInstance()` runs `init()`:

```ts
const [session, device, config] = await Promise.all([
  window.launcherAPI.store.getValueFromStore<SessionState>('session'),
  window.launcherAPI.store.getValueFromStore<DeviceState>('device'),
  window.launcherAPI.game.getGlobalConfig(),
]);
this._session     = session;     // {key: "X-Rsi-Token",  value: "AbCdE.....stale....="}
this._device      = device;      // {key: "X-Rsi-Device", value: "d7f3a1b2-8e44-4c01-9f12-aa55bb66cc77", ...}
this._platformEnv = config.environment;  // e.g. "prod"
```

The `Launcher` instance now carries both credentials in memory. **Crucially, neither is validated.** The launcher proceeds as if logged in.

### 2.4 Renderer boot — store init and route loader

`s/launcherStoreInit.ts`. Sequentially initializes Zustand slices. Relevant subset:
- `user.actions.initialize()` reads identity/sessions/device from main-process store into Zustand `user` slice.
- `authentication.actions.initialize()` resets to `{captcha: null, connectionId: null, provider: null, status: null}`.

`ers/appUiLoader.ts` runs at app-root route. `ers/signInLayoutLoader.ts` runs at `/sign-in`:

```ts
if (userService.isLoggedIn()) {
  return redirect(DEFAULT_GAME_ROUTE);   // e.g. /game-page/SC
}
```

`userService.isLoggedIn()` checks:
```ts
const userSession  = user.sessions[application.platformMaster] ?? session;
const userIdentity = user.identity ?? identity;
return !!userSession && !!userIdentity;
```

Both are populated. **Result: the user is redirected to `/game-page/SC`. The sign-in form is bypassed despite the stale session.**

---

## 3. Detection of Session Expiry (Forced Trigger)

The launcher does not proactively detect staleness. Expiry is observed reactively, when an authenticated call is rejected. Concretely, several callers fire after route mount:

1. **`status.checkStatus()` polling.** Starts on app boot, interval ≈ `60_000 ± 1_000` ms (per `configuration.requestPollingInterval.status`). Internally uses `queryClient.fetchQuery(queries.getStatusQuery())` which posts to the `status` scheme — this endpoint is **unauthenticated** (no session header attached, see `i/clients/status.ts`), so status polling does NOT trigger expiry detection.
2. **`games/library` fetch.** Starts via `library.actions.initialize()`. POSTs `launcher://games/library` with the session and device headers.
3. **`account/check`.** May fire on home route mount.
4. **`content/news`, `content/cards`.** Periodic via `configuration.requestPollingInterval.gamePageContent.base = 600_000` ms.

Whichever fires first against an authenticated launcher endpoint triggers the expiry path.

### 3.1 Wire-level expiry response

Example: `games/library` fetch.

**Renderer-issued URL:** `launcher://games/library` (no env suffix → uses `s.environment` from boot config, e.g. `prod`).

**After main-process protocol-handler rewrite (`g("launcher")` at `main.js:3834`):**
```
POST https://robertsspaceindustries.com/api/launcher/v3/games/library
Content-Type: application/json
X-Rsi-Token: AbCdE.....stale....=
X-Rsi-Device: d7f3a1b2-8e44-4c01-9f12-aa55bb66cc77
User-Agent: RSI Launcher-2.x.x
(Cookie header: deleted by webRequest.onBeforeSendHeaders at main.js:1791)
Body: { }   (or whatever the request requires)
```

**Server response:**
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": 0,
  "code": "errAuthExpired",
  "msg": "Authentication expired",
  "data": {}
}
```

(`HTTP/1.1 200` with `success: 0` is the RSI convention — application errors are signaled in the body, not via HTTP status. HTTP 401/403 are reserved for transport-level denials and surface as `ApiServerDeniedRequest`, a different code path.)

### 3.2 Renderer error mapping

`i/clients/launcher.ts` `Launcher.call()`:

```ts
const result = await this.post<RSIApiResult<unknown>>(endpoint, payload, headers, options);

if (result.code === ApiErrorCodes.DEPRECATED_API) { throw new ApiDeprecated(...); }
if (result.success)                               { return result as T; }

throw rsiApiErrorFactory({ rsiApiResult: result, environment: platformId });
```

`rsiApiErrorFactory` (`i/errors/errorSerializer.ts`) switches on `result.code`:

```ts
case ApiErrorCodes.AUTH_EXPIRED:    // 'errAuthExpired'
  return new RsiAuthExpired(i18n.t('error_session_expired', {ns: 'errors'}), rsiApiResult, environment);
```

`RsiAuthExpired` carries `code = launcherSpecificApiErrorCodes.AUTH_EXPIRED = '1009'`.

The throw propagates back into `Launcher.call()`'s outer catch:

```ts
} catch (err) {
  if (err instanceof RsiAuthExpired) {
    this._session = null;
    this._device  = null;
  }
  throw err;
}
```

**Both in-memory credentials are nulled on the `Launcher` instance.** The persistent store is *not* touched at this point. The error continues to propagate to the React Query `onError` of whatever issued the call.

### 3.3 Route-guard cascade

React Query's error becomes visible to the next route-guard navigation. `s/requireUser.ts` `requireUserSession()`:

```ts
export async function requireUserSession() {
  const { user } = useLauncherStore.getState();
  if (connectionService.isOffline() && !connectionService.isOfflineSessionValid()) {
    await userService.logOutCurrentUser();
  }
  if (!userService.isLoggedIn()) {
    throw redirect(`/${ROUTES.SIGN_IN}`);
  }
  return user.identity;
}
```

`userService.isLoggedIn()` now returns `false` because `Launcher._session` is `null` (Zustand store may still have it transiently, but the next call to `userService.logOutCurrentUser()` clears the Zustand slice too). Redirect to `/sign-in` fires.

### 3.4 Critical detail: device persistence across this transition

`userService.logOutCurrentUser({clearDevice = false})`:

```ts
const isDeviceDurationSession = user.device?.duration === DeviceDuration.SESSION;
const needToClearDevice = isDeviceDurationSession || info?.clearDevice;

try {
  if (mainSession) {
    await rsiApi.authentication.signOut({ clearDevice: needToClearDevice });
  }
} catch (e) { /* ... */ }
finally {
  queryClient.clear();
  authenticationService.resetAuthentication();
  applicationService.resetApplication();
  userService.resetUser(info);   // info.clearDevice forwarded; default = false
  getLauncherAPI().authentication.setSignOut();
}
```

Because `device.duration === "month"` (not `SESSION`) and `info.clearDevice` is default `false`, **`needToClearDevice` is `false`**. The `resetUser({clearDevice: false})` Zustand action wipes `sessions` and `identity` but **preserves `device`** in both the Zustand slice and the persistent store.

Net state at this point:
- `Launcher._session` = `null` (cleared by `RsiAuthExpired` catch)
- `Launcher._device` = `null` (cleared by `RsiAuthExpired` catch — **same null-ing line, in-memory only**)
- Persistent store `session` = cleared by `resetUser`
- Persistent store `device` = **PRESERVED**
- Zustand `user.device` = **PRESERVED**
- Zustand `user.identity` = cleared
- Zustand `user.sessions[platformMaster]` = cleared

This asymmetry — in-memory `_device` null but persistent `device` intact — is the crux of the refresh mechanism.

---

## 4. Re-Authentication Path A: Classic Re-Sign-In with Persistent Device

This is the path triggered if the user submits the sign-in form in the same process where expiry was detected. The in-memory `Launcher._device` is `null`, so the sign-in POST goes out *without* the `X-Rsi-Device` header. The server cannot identify the device, returns `ErrMultiStepRequired`, and the user must complete a full MFA flow. This is the slow path. See §6 for the fast path.

### 4.1 User submits the form

`useSignIn.hook.tsx`. User types email + password, checks "Remember me", clicks submit.

`submitSignIn(formData)` invokes:

```ts
mutateSignIn({
  username: "user@example.com",
  password: "<plaintext>",
  captcha: undefined,
  remember: true,
  launcherVersion: "2.x.x"
});
```

### 4.2 The POST

`RSIApiAuthentication.signIn()` → `Launcher.call()` → main protocol handler:

```
POST https://robertsspaceindustries.com/api/launcher/v3/signin
Content-Type: application/json
User-Agent: RSI Launcher-2.x.x
(No X-Rsi-Token: _session is null)
(No X-Rsi-Device: _device is null in-memory)

Body:
{
  "username": "user@example.com",
  "password": "<plaintext>",
  "captcha": null,
  "remember": true,
  "launcherVersion": "2.x.x"
}
```

`main.js:3884` will log this request via electron-log to `%APPDATA%\RSI Launcher\logs\log.log`, with password elided by the regex `("password")+(:)+(".+")` → `"password":"<HIDDEN>"`. The `username` and other fields are logged in plaintext.

### 4.3 Server response — MFA required

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": 0,
  "code": "ErrMultiStepRequired",
  "msg": "Multi-step authentication required",
  "data": {
    "session_name": "Rsi-Token",
    "session_id": "preAuthSessionXXXXXX",
    "device_header": "X-Rsi-Device",
    "device_id": "newDeviceTrackingId_PreAuth",
    "duration": "session",
    "new_device": true
  }
}
```

The pre-auth session carries the user through the MFA challenge. A pre-auth device_id is allocated (server's intent: if MFA succeeds and user picks a duration > session, this becomes the persisted device).

### 4.4 Renderer captures pre-auth state

`auth.ts:91-97`:

```ts
if (error instanceof RsiMfaRequiredError) {
  this.client.session = sessionMapper(error.payload.data);
  this.client.device  = deviceMapper(
    error.payload.data,
    this.client.device?.value ?? error.payload.data.device_id ?? null,
  );
}
```

After this:
- `Launcher._session = {cookie: "Rsi-Token", key: "X-Rsi-Token", value: "preAuthSessionXXXXXX"}`
- `Launcher._device = {cookie: "_rsi_device", key: "X-Rsi-Device", value: "newDeviceTrackingId_PreAuth", duration: "session", expires: undefined}`

### 4.5 User completes MFA

UI navigates to `/sign-in-mfa`. User enters TOTP code, device name (e.g. "Home PC"), duration (e.g. "month").

`useSignInMfa.hook.tsx` calls `rsiApi.authentication.signInMfa({username, codeMfa: "123456", deviceName: "Home PC", duration: "month"})`. POST:

```
POST https://robertsspaceindustries.com/api/launcher/v3/signin/multiStep
Content-Type: application/json
X-Rsi-Token: preAuthSessionXXXXXX
X-Rsi-Device: newDeviceTrackingId_PreAuth
User-Agent: RSI Launcher-2.x.x

Body:
{
  "code": "123456",
  "device_name": "Home PC",
  "duration": "month",
  "device_type": "computer"
}
```

### 4.6 Server response — success

```
{
  "success": 1,
  "code": "OK",
  "msg": "",
  "data": {
    "session_name": "Rsi-Token",
    "session_id": "freshSessionAfterMfa==",
    "account_id": "1234567",
    "citizen_id": "...",
    "tracking_metrics_id": "...",
    "avatar": "https://cdn.robertsspaceindustries.com/...",
    "nickname": "PilotName",
    "displayname": "PilotName",
    "envs": {...},
    "agreements": [...],
    "roles": [...],
    "badges": {...}
    // device_id, device_header are NOT in this response; client reuses from step 4.4
  }
}
```

### 4.7 Renderer maps and persists

`auth.ts:148-172`:

```ts
const identity = identityMapper(response.data, username);
const session  = sessionMapper(response.data);
const device   = deviceMapper(
  {
    device_id:      this.client.device?.value!,    // "newDeviceTrackingId_PreAuth"
    device_header:  this.client.device?.key!,      // "X-Rsi-Device"
    duration,                                       // "month"
    new_device:     true,
  },
  null,
);

this.client.session = session;
this.client.device  = device;

return { identity, session, device };
```

`handleApiSuccess` writes back:
```ts
const remember = location.state.remember && device.duration !== DeviceDuration.SESSION;
// = true && "month" !== "session" = true

userService.setIdentity({identity, remember: true});
userService.setSession({session,   remember: true});
userService.setDevice({device,     remember: true});

onSignInSuccess({
  accountName: identity.username,
  trackingMetricsId: identity.trackingMetricsId,
  heapAccountId: identity.heapAccountId,
});

navigate(ROUTES.HOME);
```

Persistent store now holds:
- `session` = `{cookie:"Rsi-Token", key:"X-Rsi-Token", value:"freshSessionAfterMfa=="}`
- `device` = `{cookie:"_rsi_device", key:"X-Rsi-Device", value:"newDeviceTrackingId_PreAuth", duration:"month", expires: Date.now() + 30*units.day}`
- `identity` = `{username:"user@example.com", heapAccountId:"1234567", ...}`

Main-process side: `ipcMain.on(USER_SIGNIN, ...)` updates `N().identity` and sets Sentry user context.

---

## 5. Re-Authentication Path A — Continued: Fetching the Push-System JWT

After classic-or-third-party re-auth, the launcher is back in the "logged in" state but has not yet fetched a push-system JWT. In the third-party flow, the JWT is what *started* the auth. In the classic flow, the JWT is fetched only when the launcher needs to subscribe to push topics — typically only as part of the third-party flow, or for in-game push features (entitlement changes, server notifications). 

**For the case in this spec — classic re-auth from an expired session — the launcher will not initiate a JWT fetch unless the user clicks a third-party provider button or some other flow triggers `getConnectionToken`.** If the user simply wants to play, no JWT is needed: the fresh session header alone authenticates all `launcher://*` calls.

The remainder of this spec assumes the user proceeds to launch a game that requires push-system connection, or that the flow described is the third-party variant where the JWT is the entry point. Skip to §6 for the third-party variant, which is more common as the actual "refresh path" because:
1. Many users use third-party providers (Discord, Google, Twitch).
2. The third-party flow uses the persistent device header on `getConnectionToken`, which means the device-trust *is* honored despite in-memory nulling, because `getConnectionToken` reads from a different state path.

---

## 6. Re-Authentication Path B: Third-Party OAuth Re-Sign-In (The Fast Path)

This path uses the persistent device — which survived `RsiAuthExpired` cleanup — to skip the MFA challenge. It produces a JWT, dials the push-system gRPC service, and receives a fresh session via push message.

### 6.1 User clicks a provider button

`SignIn.tsx`. User clicks the Discord button.

```ts
const startAuth = async (providerCode: string) => {
  navigate(`${ROUTES.SIGN_IN_THIRD_PARTY}`);
  await authenticationService.startThirdPartyAuthProcess('discord' as ExternalProviders);
};
```

### 6.2 `startThirdPartyAuthProcess`

`ntication/service.ts`:

```ts
public async startThirdPartyAuthProcess(provider: ExternalProviders) {
  const { authentication, user } = useLauncherStore.getState();
  try {
    authentication.actions.setProvider('discord');
    authentication.actions.setStatus('connecting');
    const device = user.device;                                  // ← reads from Zustand, NOT from Launcher._device
    const connectionToken = await rsiApi.rsiClient.getConnectionToken(device);
    window.launcherAPI.authentication.setAuthenticationProcessStart(connectionToken!);
    this.registerEventListener();
  } catch (_err) { /* ... */ }
}
```

**Note the source of `device`: `useLauncherStore.getState().user.device`, not `Launcher._device`.** Zustand `user.device` was preserved through `logOutCurrentUser({clearDevice: false})` in §3.4. So:

```js
device = {
  cookie:  "_rsi_device",
  key:     "X-Rsi-Device",
  value:   "d7f3a1b2-8e44-4c01-9f12-aa55bb66cc77",
  duration: "month",
  expires:  1739812345000  // hint, still valid
}
```

The device-trust IS honored on this path, even though it was nulled on `Launcher` instance.

### 6.3 `getConnectionToken(device)`

`i/clients/rsi.ts`:

```ts
async getConnectionToken(device?: DeviceState | null): Promise<string> {
  const headers = [{ key: 'Rsi-connection-flow', value: '' }];
  if (device) {
    headers.push({ key: device.key, value: device.value });
  }
  const config = await window.launcherAPI.game.getGlobalConfig();
  this.handleUrl(config.environment);

  const results = await this.post<RSIApiResult<string>>(
    this._endpoints.CONNECTION_FLOW,
    {},
    headers,
    { signal: AbortSignal.timeout(18000) },
  );
  if (!results.success) {
    throw new Error('failed to connect to conneciton flow api');
  }
  return results.data;
}
```

The renderer-issued URL is `rsi://connection-flow` (or `rsi+prod://connection-flow` if environment suffix is being used). After main-process rewrite via `g("rsi")`:

```
POST https://robertsspaceindustries.com/connection-flow
Content-Type: application/json
Rsi-connection-flow: 
X-Rsi-Device: d7f3a1b2-8e44-4c01-9f12-aa55bb66cc77
User-Agent: RSI Launcher-2.x.x

Body: {}
```

Note the URL: it's the `rsi` scheme, which uses `rootUrl` (no `/api/launcher/v3` prefix). So the endpoint is `https://robertsspaceindustries.com/connection-flow`, NOT `https://robertsspaceindustries.com/api/launcher/v3/connection-flow`.

Also note the empty `Rsi-connection-flow:` header — it's a presence flag, value irrelevant. The 18 s `AbortSignal.timeout` bounds this call.

### 6.4 Server response — JWT issuance

The server validates the device header against its device record (account_id, validity within 30 days), confirms the user can initiate a connection flow, and issues a **JWT** as the response data:

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": 1,
  "code": "OK",
  "msg": "",
  "data": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb25uZWN0aW9uX2lkIjoiYWJjZDEyMzQtNTY3OC05MGFiLWNkZWYtMTIzNDU2Nzg5MGFiIiwidG9waWMiOiJhZGRyZXNzOmFjY291bnRfaWQ6MTIzNDU2NyIsImFkZHJlc3MiOiJhZGRyZXNzOmFjY291bnRfaWQ6MTIzNDU2NyIsImhvc3QiOiJwdXNoLnJvYmVydHNzcGFjZWluZHVzdHJpZXMuY29tOjQ0MyIsImFjY291bnRfaWQiOiIxMjM0NTY3IiwiZGlzcGxheW5hbWUiOiJQaWxvdE5hbWUiLCJuaWNrbmFtZSI6IlBpbG90TmFtZSIsInBsYXllcl9pZCI6Ijc2NTQzMjEiLCJleHRlbmRlZF90dGwiOjMwMCwiaWF0IjoxNzM5MDAwMDAwLCJleHAiOjE3MzkwMDA2MDB9.SIGNATURE"
}
```

The JWT payload (base64-decoded second segment), verbatim shape:

```json
{
  "connection_id": "abcd1234-5678-90ab-cdef-1234567890ab",
  "topic":         "address:account_id:1234567",
  "address":       "address:account_id:1234567",
  "host":          "push.robertsspaceindustries.com:443",
  "account_id":    "1234567",
  "displayname":   "PilotName",
  "nickname":      "PilotName",
  "player_id":     "7654321",
  "extended_ttl":  300,
  "iat":           1739000000,
  "exp":           1739000600
}
```

The JWT is signed RS256 by the platform. The launcher never verifies it (no public key configured); it merely decodes it.

### 6.5 Renderer hands off to main

`ntication/service.ts:50`:

```ts
window.launcherAPI.authentication.setAuthenticationProcessStart(connectionToken!);
this.registerEventListener();
```

`preload.js:70`:
```ts
setAuthenticationProcessStart(jwt) {
  electron_1.ipcRenderer.send(
    app_shared_1.ipcEvents.authentication.AUTHENTICATION_PROCESS_START,
    jwt,
  );
}
```

IPC channel: `AUTHENTICATION_PROCESS_START`. Payload: the JWT string.

`registerEventListener` subscribes the renderer to five callback channels: `AUTHENTICATION_PROCESS_START_SUCCESSFUL`, `..._FAILED`, `AUTHENTICATION_PROCESS_SUCCESSFUL`, `AUTHENTICATION_PROCESS_FAILED`, `AUTHENTICATION_PROCESS_TIMEOUT`.

### 6.6 Main process — JWT decode and validation

`main.js:2191-2199` registers the handler on the `De` (auth flow) class. `main.js:2201-2216` handles `startAuthenticationProcess(e)`:

```js
async startAuthenticationProcess(e) {
  try {
    const t = await this.grpcClientService.startPlatformClient(e);
    this.startTimeoutCheck(1e3 * t.extended_ttl || 3e5);
    this.ipcListenerManager.send(
      O.ipcEvents.authentication.AUTHENTICATION_PROCESS_START_SUCCESSFUL,
      t.connection_id,
    );
  } catch (e) {
    this.ipcListenerManager.send(O.ipcEvents.authentication.AUTHENTICATION_PROCESS_START_FAILED);
  }
}
```

`grpcClientService.startPlatformClient(jwt)` is `Ue` at `main.js:2043`. It performs:

1. `const t = Me.jwtDecode.call(void 0, e)` — uses `jwt-decode` package, no signature verification.
2. Validates all required fields are present: `connection_id`, `topic`, `address`, `account_id`, `displayname`, `nickname`, `player_id`, `host`. Each missing field throws.
3. Constructs identity object for the push client:
   ```js
   const i = {
     type: "player",
     claims: {
       displayname: t.displayname,
       nickname:    t.nickname,
       account_id:  t.account_id,
       player_id:   t.player_id,
     },
     subscriptionKey: Re.PushClient.makeSubscriptionKey(),  // randomUUID()
   };
   ```
4. Constructs gRPC configuration:
   ```js
   const n = {
     enabled: true,
     endpoints: {
       default: { endpoint: "local.host",            transportSecurity: false },
       listen:  { endpoint: t.host,                  transportSecurity: true, token: e },
     },
     initialConnectionTimeout: 5000,
   };
   ```
   `t.host` here is `"push.robertsspaceindustries.com:443"`. `token: e` is the raw JWT string.
5. Instantiates `Ne` (push-client wrapper) with `onMessageCallback = this.onMessage.bind(this)`.
6. Calls `this.platformClient.initializeClient([t.topic], i, n)` — registers the topic `"address:account_id:1234567"` and stores identity + config.
7. `await this.promiseWithTimeout(this.platformClient.startListening(), 30000)` — bounds setup at 30 s.

### 6.7 Push-client setup (SDK side)

`@sc/push-system-client/lib/push-client/create-push-client.js`:

```js
function createPushClient(identity, configuration, options) {
  const registry = new DefaultRegistry();
  const { initialConnectionTimeout } = configuration;
  if (!configuration.enabled) {
    return new DummyPushClient(identity, registry, {});
  }
  const endpoint = getPushClientEndpointConfiguration(configuration, 'listen');
  // = { endpoint: "push.robertsspaceindustries.com:443", transportSecurity: true, token: "<jwt>" }
  const client = new GrpcPushClient(endpoint, options);
  return new DefaultPushClient(client, identity, registry, { initialConnectionTimeout: 5000 });
}
```

`GrpcPushClient` extends `GrpcClient(PushService)`. `PushService` is loaded from the embedded proto descriptor for `sc/external/services/push/v1/server.proto`. The native @grpc/grpc-js client is constructed via `GrpcClientBase`:

```js
const clientCredentials = configuration.transportSecurity
  ? credentials.createSsl()
  : credentials.createInsecure();
// = credentials.createSsl()  -- standard Node TLS, system root CA store

const extraOptions = {
  'grpc.service_config': JSON.stringify({
    loadBalancingConfig: [],
    methodConfig: [{
      name: [{ service: "sc.external.services.push.v1.PushService" }],
      retryPolicy: {
        maxAttempts: 5,
        initialBackoff: '0.1s',
        maxBackoff: '5s',
        backoffMultiplier: 1.5,
        retryableStatusCodes: ['UNKNOWN','UNAVAILABLE','RESOURCE_EXHAUSTED','NOT_FOUND','FAILED_PRECONDITION','OUT_OF_RANGE','DEADLINE_EXCEEDED','ABORTED','INTERNAL'],
      },
    }],
  }),
};

this.native = new PushServiceClient("push.robertsspaceindustries.com:443", clientCredentials, extraOptions);
```

### 6.8 `DefaultPushClient` reconnection loop fires

`default-push-client.js`:

```js
constructor(client, identity, registry, options) {
  super(identity, registry, options);
  this.commandQueue = new AsyncQueue();
  this.initialConnectionDeferred = Promise.withResolvers();
  this.client = client;
  this.reconnectionLoop();  // unawaited
}

async reconnectionLoop() {
  while (this._state !== 'shutdown') {
    const metrics = await this.waitForConnection();
    this.initialConnectionDeferred.resolve(metrics);
    await this.readCommands();
  }
}
```

`waitForConnection()` calls `client.waitForReady(deadline)`:

```js
const timeout = 5000;
this._state = 'connecting';
while (this._state !== 'shutdown') {
  try {
    await this.client.waitForReady(Date.now() + timeout);
    this._state = 'connected';
    return { retries, duration: Date.now() - start };
  } catch (e) {
    retries += 1;
    // ...
  }
}
```

This drives the underlying @grpc/grpc-js channel to do: DNS resolve `push.robertsspaceindustries.com`, TCP connect, TLS handshake, HTTP/2 SETTINGS exchange. On success, `state = 'connected'` and the loop proceeds to `readCommands()`.

### 6.9 `readCommands()` — the Listen RPC

```js
async readCommands() {
  let metadata;
  if (this.client.configuration.token) {
    metadata = getMetadataWithAuthWithToken(this.client.configuration.token);
  } else {
    metadata = getMetadataWithAuthUsingIssuer(getJwtIssuer(this.client.configuration.jwt), this.identity.claims);
  }
  const call = this.client.listen(metadata);
  this.commandQueue = new AsyncQueue();
  await readableStreamFromQueue(this.commandQueue)
    .pipeThrough(call)
    .pipeThrough(makePushMessageToCommandTransformStream(this.client, this.registry, this.identity.subscriptionKey))
    .pipeTo(writableStreamToQueue(this.commandQueue));
}
```

Token path is taken. `getMetadataWithAuthWithToken`:

```js
metadata.add('Authorization', `Bearer ${token}`);
```

`this.client.listen(metadata)` invokes the duplex-stream `Listen` RPC.

**HTTP/2 wire bytes (decoded HPACK headers and DATA frames):**

```
[Client → Server, HEADERS frame on stream 1]
:method = POST
:scheme = https
:authority = push.robertsspaceindustries.com:443
:path = /sc.external.services.push.v1.PushService/Listen
te = trailers
content-type = application/grpc
user-agent = grpc-node-js/1.x.x grpc-c/...
grpc-accept-encoding = identity,deflate,gzip
accept-encoding = identity,gzip
authorization = Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9....SIGNATURE
```

Server validates the JWT (signature, exp, that the JWT's `topic`/`account_id` claims are consistent with the subscriber's intent).

### 6.10 Server sends STREAM_OPENED

```
[Server → Client, DATA frame on stream 1]
< 5-byte gRPC length prefix: 0x00 0x00 0x00 0x00 0x12 >
< protobuf-encoded ListenResponse:
  envelopes: [
    {
      messages: [
        {
          control: {
            command: COMMAND_STREAM_OPENED  // enum value 1
          }
        }
      ]
    }
  ]
>
```

### 6.11 Client transformer reacts — sends SubscribeCommand

`push-message-to-command-transformer.js`:

```js
handleControlMessage(controller, message) {
  PushControlMessageCommand.match(
    PushControlMessageCommand.from(message.command),
    {
      COMMAND_STREAM_OPENED: () => {
        sc.logger.info('PushSystemClient', `Stream opened with push server at ${endpoint}`);
        this.enqueueSubcribeCommand(controller);
      },
      COMMAND_CLOSE_RECONNECT: () => {
        controller.terminate();
      },
    }
  );
}

enqueueSubcribeCommand(controller) {
  controller.enqueue({
    commands: [{
      subscribe: {
        topics: this.registry.getSubscriptions(),  // ["address:account_id:1234567"]
        key:    this.subscriptionKey,              // "<the randomUUID from §6.6.3>"
      },
    }],
  });
}
```

Wire-out:

```
[Client → Server, DATA frame on stream 1]
< 5-byte gRPC length prefix: 0x00 0x00 0x00 0x00 0x49 >
< protobuf-encoded ListenRequest:
  commands: [
    {
      subscribe: {
        topics: ["address:account_id:1234567"],
        key:    "f47ac10b-58cc-4372-a567-0e02b2c3d479"
      }
    }
  ]
>
```

Server validates the subscription against the JWT's claims (the JWT specifies `topic: "address:account_id:1234567"` and `account_id: "1234567"`; the subscribe-to topic matches). Subscription is accepted server-side.

### 6.12 The session-issuance message arrives

The platform's auth service, having confirmed the connection via the JWT, publishes the session payload to the topic. The launcher's stream receives:

```
[Server → Client, DATA frame on stream 1]
< gRPC length prefix >
< protobuf-encoded ListenResponse:
  envelopes: [
    {
      topics: ["address:account_id:1234567"],
      sender: {...},
      messages: [
        {
          any: {
            type_url: "type.googleapis.com/sc.platform.auth.v1.AuthResult",
            value: <utf8 bytes of JSON-encoded session payload>
          }
        }
      ]
    }
  ]
>
```

The `any.value` bytes, when utf8-decoded:

```json
{
  "success": true,
  "data": {
    "session_name": "Rsi-Token",
    "session_id":   "freshSessionFromGrpc==",
    "device_header": "X-Rsi-Device",
    "device_id":    "d7f3a1b2-8e44-4c01-9f12-aa55bb66cc77",
    "duration":     "month",
    "new_device":   true,
    "account_id":   "1234567",
    "citizen_id":   "...",
    "tracking_metrics_id": "...",
    "avatar":       "https://cdn.robertsspaceindustries.com/...",
    "nickname":     "PilotName",
    "displayname":  "PilotName",
    "envs":         {...},
    "agreements":   [...],
    "roles":        [...],
    "badges":       {...}
  }
}
```

Note: `device_id` is the SAME id the launcher already had (`d7f3a1b2-8e44-...`). The server reused the device record. `new_device: true` here is the server signalling "treat this as a fresh device assignment in the client mapper" so `deviceMapper` doesn't throw on the missing-prev-id check; the actual id value is the same.

### 6.13 Decoder transforms the Any

`main.js:2017` registered the decoder:

```js
client.registerDecoder("type.googleapis.com", (e) => {
  if (Buffer.isBuffer(e.value)) {
    const t = e.value.toString("utf8");
    return JSON.parse(t);
  }
  return e;
});
```

The `e.value` is the utf8 bytes; output is the JS object shown above.

### 6.14 Handler dispatch

`Ne.subscribe()` registered:

```js
const t = async (e, t) => {
  this.onMessageCallback(e);
};
this.client.subscribeHandler(t, "address:account_id:1234567");
```

`this.onMessageCallback` is `De.onMessage` (passed through `Ue.startPlatformClient` constructor argument).

`De.onMessage` at `main.js:2230`:

```js
onMessage(e) {
  const t = e;
  if (!t.success && t.errorMessage) {
    this.grpcClientService.stopPlatformClient();
    this.clearTimeout();
    return void this.ipcListenerManager.send(O.ipcEvents.authentication.AUTHENTICATION_PROCESS_FAILED);
  }
  if (t.success) {
    if (t.success && !t.data.session_id) {
      this.grpcClientService.stopPlatformClient();
      this.clearTimeout();
      return void this.ipcListenerManager.send(O.ipcEvents.authentication.AUTHENTICATION_PROCESS_FAILED);
    }
    this.grpcClientService.stopPlatformClient();
    this.clearTimeout();
    this.ipcListenerManager.send(
      O.ipcEvents.authentication.AUTHENTICATION_PROCESS_SUCCESSFUL,
      t.data,
    );
  }
}
```

`t.success === true`, `t.data.session_id === "freshSessionFromGrpc=="`. Both checks pass.

### 6.15 gRPC channel teardown

`stopPlatformClient()` → `Ne.stopListening()`:

```js
async stopListening() {
  if (this.isConnected) {
    this.unsubscribe();
    await this.shutdown();
  }
}

unsubscribe() {
  this.unsubscribers.forEach((e) => e());  // each unsubscriber posts an UnsubscribeCommand
  this.client.unregisterFallbackHandler();
}

async shutdown() {
  await this.client.shutdown();
  this.isConnected = false;
}
```

Wire-out final commands:

```
[Client → Server, DATA frame on stream 1]
< gRPC length prefix >
< protobuf-encoded ListenRequest:
  commands: [
    { unsubscribe: { topics: ["address:account_id:1234567"] } }
  ]
>

[Client → Server, HEADERS frame, END_STREAM=1]   -- half-close of stream

[Server → Client, HEADERS frame on stream 1]
grpc-status = 0
grpc-message = OK
```

TCP/TLS connection may stay open in the underlying @grpc/grpc-js pool, but the launcher's logical stream is closed.

### 6.16 IPC back to renderer

`main.js:2253`:

```js
this.ipcListenerManager.send(
  O.ipcEvents.authentication.AUTHENTICATION_PROCESS_SUCCESSFUL,
  t.data,
);
```

The `t.data` object (the parsed JSON from §6.12) is sent across the IPC channel.

### 6.17 Renderer reception and final state write

`ntication/service.ts` listener registered in `registerEventListener()`:

```ts
launcherApi.authentication.onAuthenticationProcessSuccess(this.setAuthenticationSuccessful.bind(this)),
```

`setAuthenticationSuccessful`:

```ts
private async setAuthenticationSuccessful(authData: ThirdPartyAuthDataPackage) {
  const { authentication } = useLauncherStore.getState();
  this.removeEventListener();
  try {
    await this.retrieveUserInfo(authData);
    window.location.hash = generatePath(`${ROUTES.HOME}`);
  } catch (_err) {
    authentication.actions.setStatus('error');
  }
}

private async retrieveUserInfo(authData: ThirdPartyAuthDataPackage) {
  const { identity, session, device } = await rsiApi.authentication.signInThirdParty(authData);
  userService.setSession({ session, remember: true });
  userService.setIdentity({ identity, remember: true });
  userService.setDevice({ device, remember: true });
}
```

`RSIApiAuthentication.signInThirdParty()` is purely local (no network):

```ts
async signInThirdParty(authData): Promise<{identity, session, device}> {
  await this.verifyPolicy(authData);  // RC-build gate, no-op for prod
  const identity = identityMapper(authData, authData.displayname);
  const session  = sessionMapper(authData);
  const device   = deviceMapper({ new_device: true, ...authData }, null);
  this.client.session = session;
  this.client.device  = device;
  return { identity, session, device };
}
```

Mappers produce:

```js
identity = {
  username:           "PilotName",
  heapAccountId:      "1234567",
  trackingMetricsId:  "...",
  displayName:        "PilotName",
  nickname:           "PilotName",
  avatar:             "https://cdn.robertsspaceindustries.com/...",
  privileged:         false
};

session = {
  cookie: "Rsi-Token",
  key:    "X-Rsi-Token",
  value:  "freshSessionFromGrpc=="
};

device = {
  cookie:   "_rsi_device",
  key:      "X-Rsi-Device",
  value:    "d7f3a1b2-8e44-4c01-9f12-aa55bb66cc77",
  duration: "month",
  expires:  Date.now() + 30 * units.day
};
```

`Launcher._session`, `Launcher._device` are re-populated. Persistent store is rewritten with `remember: true`. Zustand `user.identity`, `user.sessions[platformMaster]`, `user.device` are updated.

`onSignInSuccess({accountName, trackingMetricsId, heapAccountId})` IPC-notifies main, which writes Sentry user context and emits analytics event `APP_SIGNEDIN`.

`navigate(ROUTES.HOME)` redirects to home.

### 6.18 Subsequent calls

The next authenticated call to e.g. `launcher://games/library`:

```
POST https://robertsspaceindustries.com/api/launcher/v3/games/library
Content-Type: application/json
X-Rsi-Token: freshSessionFromGrpc==
X-Rsi-Device: d7f3a1b2-8e44-4c01-9f12-aa55bb66cc77
User-Agent: RSI Launcher-2.x.x

Body: { ... }

→ HTTP/1.1 200 OK
{ "success": 1, "code": "OK", "data": {...library...} }
```

The user is fully re-authenticated.

---

## 7. Timing Summary

| Stage | Bound | Source |
|---|---|---|
| `getConnectionToken` | 18 s | `AbortSignal.timeout(18000)` at `i/clients/rsi.ts:29` |
| `startListening` total | 30 s | `Ue.promiseWithTimeout(..., 30000)` at `main.js:2135` |
| `waitForReady` (TCP+TLS+H2) | 5 s | `initialConnectionTimeout` at `main.js:2128` |
| Whole-flow ceiling after `STREAM_OPENED` | `extended_ttl` seconds from JWT, fallback 5 min | `main.js:2204`: `setTimeout(..., 1e3 * t.extended_ttl \|\| 3e5)` |
| Auth message expected within | (whatever timeout above) | — |

In the example JWT (`extended_ttl: 300`), the launcher gives the auth service 5 minutes to publish the result message after gRPC stream is established. Past that, `AUTHENTICATION_PROCESS_TIMEOUT` fires and the UI shows the timeout state.

---

## 8. Key Invariants and Edge Cases

### 8.1 The device asymmetry

The behavior in §3.4 is essential: when `RsiAuthExpired` is thrown, **the persistent device survives but the in-memory `Launcher._device` is wiped**. This means:
- Any operation that reads `Launcher._device` (`Launcher.call()`'s default `device` parameter) will *not* see the device.
- Any operation that reads `useLauncherStore.getState().user.device` *will* see the device.

`getConnectionToken` reads from Zustand. Classic `signin` POST reads from `Launcher._device`. This is why the third-party flow honors device-trust but the classic flow falls back to MFA in the same process.

### 8.2 Device expiry edge case

If the device has actually expired server-side (>30 days since issuance), the `getConnectionToken` POST returns `{success: 0, code: "<some-device-invalid-code>"}` and the flow fails. The user is bumped to MFA in either flow. The 30-day cap is server-enforced; the launcher's `expires` hint is advisory only and the launcher will attempt to use a device past its `expires` if the field is unchecked (which it is in the code path inspected).

### 8.3 JWT expiry

The JWT carries `exp` ~10 minutes from `iat` (typical). If the launcher's gRPC connect is slow enough that the JWT expires en route, the server rejects with `UNAUTHENTICATED` gRPC status, which is **not** in the retryable status list (`grpc-client-configuration.js`). The `Listen` call fails immediately; `readCommands` catches, logs `Client was disconnected from {endpoint} due to an error`, sets state to `'disconnected'`, the `reconnectionLoop` re-enters `waitForConnection`. But the JWT is the same expired one — every retry will fail the same way until the 30 s `startListening` timeout in `Ue.promiseWithTimeout` triggers `stopPlatformClient` and bubbles up to `AUTHENTICATION_PROCESS_START_FAILED`.

### 8.4 Topic dimension

The example uses `address:account_id:1234567`. Other valid dimensions per `AddressDimensionEnum` (`@sc/push-system-common/lib/types.js`) are `service_id` and `player_id`. The server chooses which dimension addresses this particular connection-flow; the launcher does not inspect or care.

### 8.5 The `any` payload schema is not enforced

The decoder JSON-parses the `value` bytes blindly. If the server changes the payload shape, the renderer's `signInThirdParty` mapper will throw or silently produce malformed state. `De.onMessage` only validates two things: `success` is truthy, and `data.session_id` is present. Everything else (`displayname`, `account_id`, `device_id`) is consumed downstream without main-side validation.

---

## 9. Files Touched, in Order

| Phase | File | Function/section |
|---|---|---|
| Boot | `main.js` | `app.whenReady` → `protocol.registerHttpProtocol(scheme, g(scheme))` for each of 17 schemes |
| Boot | `preload.js` | `contextBridge.exposeInMainWorld("launcherAPI", ...)` |
| Boot | `i/clients/launcher.ts` | `Launcher.init()` reads `session`, `device`, `config` from main-process store via IPC |
| Boot | `s/launcherStoreInit.ts` | Sequential slice initialization |
| Boot | `ers/signInLayoutLoader.ts` | Skip sign-in based on `userService.isLoggedIn()` |
| Trigger | `i/clients/launcher.ts` | `Launcher.call()` outer catch on `RsiAuthExpired` nulls `_session`, `_device` |
| Trigger | `i/errors/errorSerializer.ts` | `case AUTH_EXPIRED → new RsiAuthExpired(...)` |
| Trigger | `s/requireUser.ts` | `requireUserSession()` redirects to `/sign-in` |
| Trigger | `service.ts` (user) | `logOutCurrentUser({clearDevice: false})` preserves persistent device |
| Refresh start | `n/SignIn.tsx` | User clicks provider button |
| Refresh start | `ntication/service.ts` | `startThirdPartyAuthProcess('discord')` reads `user.device` from Zustand |
| Refresh start | `i/clients/rsi.ts` | `getConnectionToken(device)` POSTs `rsi://connection-flow` |
| Refresh start | `main.js:3834` | `g("rsi")` rewrites to `https://robertsspaceindustries.com/connection-flow` |
| JWT handoff | `preload.js:70` | `setAuthenticationProcessStart(jwt)` IPC |
| Main-side | `main.js:2191` | `De.startAuthenticationProcess(jwt)` |
| Main-side | `main.js:2043 / Ue` | `jwt-decode` parses, validates required fields, constructs gRPC config |
| SDK | `@sc/push-system-client/lib/push-client/create-push-client.js` | `createPushClient` |
| SDK | `@sc/grpc-toolkit/lib/client/grpc-client-base.js` | `GrpcClientBase` constructor → @grpc/grpc-js native channel |
| SDK | `@sc/push-system-client/lib/push-client/default-push-client.js` | `reconnectionLoop` → `waitForConnection` → `readCommands` |
| SDK | `@sc/grpc-toolkit/lib/auth/requests.js` | `getMetadataWithAuthWithToken(jwt)` → `Authorization: Bearer <jwt>` |
| Wire | gRPC HTTP/2 stream to `push.robertsspaceindustries.com:443` | `Listen` duplex RPC, subscribe to topic |
| SDK | `@sc/push-system-client/lib/push-client/push-message-to-command-transformer.js` | Reacts to `STREAM_OPENED` with subscribe command, dispatches `any` payloads |
| Decoder | `main.js:2017` | Registered decoder for `type.googleapis.com` JSON-parses utf8 bytes |
| Handler | `main.js:2230` | `De.onMessage` validates `success` + `data.session_id`, emits IPC success |
| Result | `ntication/service.ts` | `setAuthenticationSuccessful(authData)` |
| Result | `i/requesters/auth.ts` | `signInThirdParty(authData)` runs mappers locally |
| Result | `i/utils.ts` | `sessionMapper`, `identityMapper`, `deviceMapper` |
| Result | `service.ts` (user) | `userService.setSession/setIdentity/setDevice` with `remember: true` |
| Result | `main.js:3923` | `ipcMain.on(USER_SIGNIN, ...)` writes Sentry user, fires `APP_SIGNEDIN` analytics |

---

## 10. Net State After Successful Refresh

In-memory:
- `Launcher._session` = `{key:"X-Rsi-Token", value:"freshSessionFromGrpc=="}`
- `Launcher._device` = `{key:"X-Rsi-Device", value:"d7f3a1b2-...", duration:"month", expires: t+30d}`

Zustand:
- `user.identity` populated
- `user.sessions[platformMaster]` populated
- `user.device` populated

Persistent store on disk:
- `session`, `device`, `identity` written (because `remember: true`)

Server-side:
- New session record bound to `account_id` and `device_id`
- Device record's last-use timestamp updated; 30-day window resets per server policy

Sentry main-process context:
- `T.setUser({ip_address: "{{auto}}", id: <heapAccountId>, ...})` set

The launcher is fully operational. Subsequent authenticated calls succeed with the new session header. No further network or interactive work is required until the new session also expires, at which point this same flow re-runs.

#!/usr/bin/env node

/**
 * 
 * Usage:
 *   SESSION_TOKEN="<expired_hex>" DEVICE_TOKEN="<uuid_or_hex>" node rsi-auth.js
 * 
 * Optional:
 *   RSI_USERNAME="email@example.com" RSI_PASSWORD="password" SESSION_TOKEN="..." DEVICE_TOKEN="..." node rsi-auth.js
 */

const SESSION_TOKEN = process.env.SESSION_TOKEN;
const DEVICE_TOKEN = process.env.DEVICE_TOKEN;
const USERNAME = process.env.RSI_USERNAME;
const PASSWORD = process.env.RSI_PASSWORD;

if (!DEVICE_TOKEN) {
  console.error("❌ Error: DEVICE_TOKEN environment variable is required.");
  console.error("Usage: DEVICE_TOKEN=\"<token>\" SESSION_TOKEN=\"<token>\" node rsi-auth.js");
  process.exit(1);
}

// Constants
const USER_AGENT = 'RSI Launcher-2.x.x';
const API_URL = 'https://robertsspaceindustries.com/api/launcher/v3';
const ROOT_URL = 'https://robertsspaceindustries.com';

async function checkExpiredSession() {
  console.log("\n--- 1. Checking Session ---");
  
  const headers = {
    'User-Agent': USER_AGENT,
    'Content-Type': 'application/json',
    'X-Rsi-Device': DEVICE_TOKEN
  };
  
  if (SESSION_TOKEN) {
    headers['X-Rsi-Token'] = SESSION_TOKEN;
  } else {
    console.log("⚠️ No SESSION_TOKEN provided, skipping session check.");
    return;
  }

  // Spec §2.4: The body is literally the string "undefined"
  const res = await fetch(`${API_URL}/games/library`, {
    method: 'POST',
    headers,
    body: "undefined" 
  });

  const data = await res.json();
  console.log("Response:", JSON.stringify(data));

  if (data.code === 'errAuthExpired') {
    console.log("✅ Result: Session is expired.");
  }
}

async function getPushSystemJwt() {
  console.log("\n--- 2. Requesting Push-System JWT ---");
  
  const headers = {
    'User-Agent': USER_AGENT,
    'Content-Type': 'application/json',
    'Rsi-connection-flow': '',
    'X-Rsi-Device': DEVICE_TOKEN
  };

  const res = await fetch(`${ROOT_URL}/connection-flow`, {
    method: 'POST',
    headers,
    body: JSON.stringify({})
  });

  const data = await res.json();
  
  if (data.success === 1 && data.data) {
    console.log("✅ Result: Successfully obtained JWT!");
    return data.data;
  } else {
    console.error("❌ Failed to get JWT:", data);
    process.exit(1);
  }
}

function decodeJwt(token) {
  console.log("\n--- 3. Decoding JWT Payload ---");
  try {
    // Standard base64url decode of the JWT payload (middle segment)
    const payloadBase64 = token.split('.')[1];
    const payloadBuffer = Buffer.from(payloadBase64, 'base64');
    const payload = JSON.parse(payloadBuffer.toString('utf-8'));
    
    console.log(JSON.stringify(payload, null, 2));
    console.log(`\n🔌 gRPC Connection Details:`);
    console.log(`   Host:  ${payload.host}`);
    console.log(`   Topic: ${payload.topic}`);
    console.log(`   TTL:   ${payload.extended_ttl} seconds`);
  } catch (e) {
    console.error("❌ Could not decode JWT:", e.message);
  }
}

async function classicSignIn() {
  console.log("\n--- 4. Classic Sign-In ---");
  console.log("Attempting to sign in while retaining the device token...");

  const headers = {
    'User-Agent': USER_AGENT,
    'Content-Type': 'application/json',
    'X-Rsi-Device': DEVICE_TOKEN
  };

  const payload = {
    username: USERNAME,
    password: PASSWORD,
    captcha: null,
    remember: true,
    launcherVersion: "2.x.x"
  };

  const res = await fetch(`${API_URL}/signin`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload)
  });

  const data = await res.json();
  
  if (data.success === 1) {
    console.log("✅ Result: Successfully signed in!");
    console.log(`   New Session Token: ${data.data.session_id}`);
  } else if (data.code === 'ErrMultiStepRequired') {
    console.log("⚠️ Result: MFA Required. The device token was not recognized or is too old.");
  } else {
    console.log("❌ Result: Sign in failed.", data);
  }
}

async function main() {
  // 1. Demonstrate the expired session
  await checkExpiredSession();

  // 2. Get the JWT for the gRPC push system
  const jwt = await getPushSystemJwt();
  
  // 3. Decode and display the JWT claims
  decodeJwt(jwt);

  // 4. (Optional) Demonstrate the fixed classic sign-in
  if (USERNAME && PASSWORD) {
    await classicSignIn();
  } else {
    console.log("\nℹ️  Skipping classic sign-in. Provide RSI_USERNAME and RSI_PASSWORD env vars to test.");
  }
}

main();

/**
 * Cox Killer - TP-Link BE10000 Router API
 * Implements the TP-Link LuCI encrypted protocol:
 *   - AES-128-CBC with 16 decimal-digit keys (UTF-8 bytes)
 *   - RSA PKCS#1 v1.5 with chunked signing for 512-bit auth key
 *   - Separate 1024-bit RSA key for password encryption
 *   - Inner payload is URL-encoded (not JSON)
 */
import crypto from 'crypto';
import http from 'http';

const ROUTER = '192.168.0.1';
const BASE = `/cgi-bin/luci/;stok=`;

// ============================================================
// HTTP (with cookie jar for session persistence)
// ============================================================

const cookies = {};

function httpPost(path, body, contentType = 'application/x-www-form-urlencoded') {
  return new Promise((resolve, reject) => {
    const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    const headers = {
      'Content-Type': contentType,
      'Content-Length': Buffer.byteLength(body),
      'Referer': `http://${ROUTER}/webpages/index.html`,
    };
    if (cookieHeader) headers['Cookie'] = cookieHeader;

    const opts = { hostname: ROUTER, port: 80, method: 'POST', path, headers };
    const req = http.request(opts, (res) => {
      // Store cookies from Set-Cookie headers
      const setCookies = res.headers['set-cookie'];
      if (setCookies) {
        for (const c of setCookies) {
          const [pair] = c.split(';');
          const [name, ...valParts] = pair.split('=');
          cookies[name.trim()] = valParts.join('=').trim();
        }
      }
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve({ raw: data, statusCode: res.statusCode }); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ============================================================
// AES-128-CBC (key/IV are 16 decimal-digit strings, used as UTF-8 bytes)
// ============================================================

function generateDigits(len) {
  let result = '';
  const bytes = crypto.randomBytes(len);
  for (let i = 0; i < len; i++) {
    result += (bytes[i] % 10).toString();
  }
  return result;
}

function aesEncrypt(plaintext, keyStr, ivStr) {
  const key = Buffer.from(keyStr, 'utf-8');
  const iv = Buffer.from(ivStr, 'utf-8');
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  let enc = cipher.update(plaintext, 'utf-8', 'base64');
  enc += cipher.final('base64');
  return enc;
}

function aesDecrypt(ciphertext, keyStr, ivStr) {
  const key = Buffer.from(keyStr, 'utf-8');
  const iv = Buffer.from(ivStr, 'utf-8');
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  let dec = decipher.update(ciphertext, 'base64', 'utf-8');
  dec += decipher.final('utf-8');
  return dec;
}

// ============================================================
// RSA (PKCS#1 v1.5 Type 2 padding, with chunking for small keys)
// ============================================================

function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % mod;
    exp = exp / 2n;
    base = (base * base) % mod;
  }
  return result;
}

function rsaEncryptBlock(msgBuf, nHex, eHex) {
  const n = BigInt('0x' + nHex);
  const e = BigInt('0x' + eHex);
  const keyBytes = Math.ceil(n.toString(16).length / 2);

  const psLen = keyBytes - msgBuf.length - 3;
  if (psLen < 8) throw new Error(`Message too long (${msgBuf.length}) for key size (${keyBytes})`);
  const ps = crypto.randomBytes(psLen).map(b => b === 0 ? 0x42 : b);
  const padded = Buffer.concat([Buffer.from([0x00, 0x02]), ps, Buffer.from([0x00]), msgBuf]);

  let m = BigInt('0x' + padded.toString('hex'));
  let c = modPow(m, e, n);
  return c.toString(16).padStart(keyBytes * 2, '0');
}

/**
 * RSA encrypt a string, chunking into (keySize - 11) byte blocks.
 * This matches the TP-Link JS: substring(m, m+53) for 512-bit key.
 */
function rsaEncryptChunked(messageStr, nHex, eHex) {
  const n = BigInt('0x' + nHex);
  const keyBytes = Math.ceil(n.toString(16).length / 2);
  const chunkSize = keyBytes - 11;

  // TP-Link JS uses string.substring(), so we chunk by characters (ASCII = bytes)
  let result = '';
  for (let i = 0; i < messageStr.length; i += chunkSize) {
    const chunk = messageStr.substring(i, i + chunkSize);
    result += rsaEncryptBlock(Buffer.from(chunk, 'utf-8'), nHex, eHex);
  }
  return result;
}

/**
 * RSA encrypt a short string (single block). Used for password with 1024-bit key.
 */
function rsaEncrypt(messageStr, nHex, eHex) {
  return rsaEncryptBlock(Buffer.from(messageStr, 'utf-8'), nHex, eHex);
}

// ============================================================
// Payload serialization (URL-encoded, matching TP-Link's Sa() function)
// ============================================================

function serializePayload(obj) {
  const parts = [];
  for (const [key, val] of Object.entries(obj)) {
    if (val === undefined || val === null) continue;
    parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(val)}`);
  }
  return parts.join('&');
}

// ============================================================
// Login
// ============================================================

async function login(password) {
  // 1. Get auth RSA key (512-bit) + sequence
  const auth = await httpPost(`${BASE}/login?form=auth`, 'operation=read');
  if (!auth.success) { console.error('Auth failed:', auth); return null; }

  const rsaN = auth.data.key[0];
  const rsaE = auth.data.key[1];
  const seq = auth.data.seq;

  // 2. Get password RSA key (1024-bit)
  const keys = await httpPost(`${BASE}/login?form=keys`, 'operation=read');
  if (!keys.success) { console.error('Keys failed:', keys); return null; }

  const pwdN = keys.data.password[0];
  const pwdE = keys.data.password[1];

  // 3. Generate AES-128 key: 16 random decimal digits (used as UTF-8 bytes)
  const aesKey = generateDigits(16);
  const aesIV = generateDigits(16);

  // 4. Hash = MD5("admin" + password) — US region uses MD5, not SHA256
  const hash = crypto.createHash('md5').update('admin' + password).digest('hex');

  // 5. RSA encrypt the RAW PASSWORD with password key (not the hash)
  const encPwd = rsaEncrypt(password, pwdN, pwdE);

  // 6. Build login payload as URL-encoded (matching TP-Link's Sa() serializer)
  const payloadStr = serializePayload({ operation: 'login', password: encPwd });

  // 7. AES encrypt the payload
  const encData = aesEncrypt(payloadStr, aesKey, aesIV);

  // 8. Build signature and RSA encrypt with auth key (512-bit, chunked at 53 chars)
  const signContent = `k=${aesKey}&i=${aesIV}&h=${hash}&s=${seq + encData.length}`;
  const signEnc = rsaEncryptChunked(signContent, rsaN, rsaE);

  // 9. Send
  const body = `sign=${signEnc}&data=${encodeURIComponent(encData)}`;
  const result = await httpPost(`${BASE}/login?form=login`, body);

  // 10. Decrypt response
  let data = result.data;
  if (typeof data === 'string' && data.length > 0) {
    try { data = JSON.parse(aesDecrypt(data, aesKey, aesIV)); }
    catch { /* keep raw */ }
  }

  // Response is nested: {success, data: {stok}}
  const stok = data?.stok || data?.data?.stok;
  if (stok) {
    return { stok, aesKey, aesIV, rsaN, rsaE, seq, hash };
  }

  const ec = data?.errorcode || data?.data?.errorcode;
  if (ec) console.error(`  Login error: ${ec}`);

  console.error('\nLogin failed');
  return null;
}

// ============================================================
// Authenticated API requests
// ============================================================

async function apiRequest(session, path, payload = { operation: 'read' }) {
  const payloadStr = serializePayload(payload);
  const encData = aesEncrypt(payloadStr, session.aesKey, session.aesIV);
  const signContent = `h=${session.hash}&s=${session.seq + encData.length}`;
  const signEnc = rsaEncryptChunked(signContent, session.rsaN, session.rsaE);

  const body = `sign=${signEnc}&data=${encodeURIComponent(encData)}`;
  const result = await httpPost(`${BASE}${session.stok}${path}`, body);

  if (typeof result.data === 'string' && result.data.length > 0) {
    try { result.data = JSON.parse(aesDecrypt(result.data, session.aesKey, session.aesIV)); }
    catch { /* keep raw */ }
  }
  return result;
}

async function apiWrite(session, path, data) {
  return apiRequest(session, path, { operation: 'write', ...data });
}

// ============================================================
// Main
// ============================================================

// ============================================================
// CLI
// ============================================================

// Password resolution: CLI arg > env var > stdin (for subprocess piping)
let password = process.argv[2] || process.env.ROUTER_PASSWORD;
let cmd;

if (password && ['read','apply','get','set','status'].includes(password)) {
  // First arg is actually a command, not a password — need stdin or env
  cmd = password;
  password = process.env.ROUTER_PASSWORD;
} else {
  cmd = process.argv[3] || 'read';
}

if (!password) {
  // Try reading from stdin (non-interactive, for piped input)
  if (!process.stdin.isTTY) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    password = Buffer.concat(chunks).toString().trim();
  }
}

if (!password) {
  console.error('Usage: node router_login.mjs <password> [command]');
  console.error('   or: ROUTER_PASSWORD=xxx node router_login.mjs [command]');
  console.error('   or: echo "$password" | node router_login.mjs [command]');
  process.exit(1);
}

if (cmd !== 'status') {
  console.log(`Cox Killer - TP-Link BE10000 Router Control`);
  console.log(`Connecting to ${ROUTER}...`);
}
const session = await login(password);

if (!session) {
  console.error('Authentication failed.');
  process.exit(1);
}
if (cmd !== 'status') console.log('Authenticated.\n');

if (cmd === 'read') {
  const endpoints = [
    'smart_connect', 'wireless_2g', 'wireless_5g', 'wireless_5g_2',
    'wireless_6g', 'guest_2g', 'guest_5g'
  ];
  const settings = {};
  for (const ep of endpoints) {
    const r = await apiRequest(session, `/admin/wireless?form=${ep}`);
    if (r.data?.success !== false) settings[ep] = r.data?.data || r.data || r;
  }
  const fc = await apiRequest(session, '/admin/network?form=wan_fc');
  if (fc.data?.success !== false) settings['flow_controller'] = fc.data?.data || fc.data || fc;

  // Summary
  const sc = settings.smart_connect;
  const w2 = settings.wireless_2g;
  const w5 = settings.wireless_5g;
  const w6 = settings.wireless_6g;
  const fc_data = settings.flow_controller;

  console.log('=== Current Router Settings ===\n');
  console.log(`Smart Connect:  ${sc?.smart_enable || 'N/A'}`);
  console.log(`Flow Controller: TX=${fc_data?.tx_enable}, RX=${fc_data?.rx_enable}`);
  console.log();
  console.log(`2.4GHz: ch=${w2?.current_channel} width=${w2?.htmode} ssid="${w2?.ssid}"`);
  console.log(`5GHz:   ch=${w5?.current_channel} width=${w5?.htmode} ssid="${w5?.ssid}"`);
  console.log(`6GHz:   ch=${w6?.current_channel} width=${w6?.htmode} ssid="${w6?.ssid}"`);
  console.log();

  // Diagnose issues
  const issues = [];
  if (sc?.smart_enable === 'on') issues.push('Smart Connect ON → causes band-hopping, disable it');
  if (fc_data?.tx_enable || fc_data?.rx_enable) issues.push('Flow Controller ON → throttles bandwidth, disable it');
  if (w5?.htmode === '160') issues.push('5GHz at 160MHz → DFS channels may cause drops, try 80MHz');
  if (w2?.htmode === 'auto') issues.push('2.4GHz width auto → set to 20MHz for stability');

  if (issues.length) {
    console.log('=== Cox Killer Recommendations ===\n');
    issues.forEach((iss, i) => console.log(`  ${i + 1}. ${iss}`));
    console.log('\nRun with "apply" to fix these automatically.');
  } else {
    console.log('All settings look good!');
  }

  if (process.argv.includes('--json')) {
    console.log('\n' + JSON.stringify(settings, null, 2));
  }

} else if (cmd === 'apply') {
  console.log('Applying Cox Killer optimizations...\n');

  // 1. Disable Smart Connect
  console.log('1. Disabling Smart Connect...');
  let r = await apiWrite(session, '/admin/wireless?form=smart_connect', { smart_enable: 'off' });
  let d = r.data?.data || r.data;
  console.log(`   ${d?.success !== false ? 'OK' : 'FAILED: ' + JSON.stringify(d)}`);

  // 2. Disable Flow Controller
  console.log('2. Disabling Flow Controller...');
  r = await apiWrite(session, '/admin/network?form=wan_fc', { tx_enable: false, rx_enable: false });
  d = r.data?.data || r.data;
  console.log(`   ${d?.success !== false ? 'OK' : 'FAILED: ' + JSON.stringify(d)}`);

  // 3. Reduce 5GHz to 80MHz
  console.log('3. Setting 5GHz to 80MHz...');
  r = await apiWrite(session, '/admin/wireless?form=wireless_5g', { htmode: '80' });
  d = r.data?.data || r.data;
  console.log(`   ${d?.success !== false ? 'OK' : 'FAILED: ' + JSON.stringify(d)}`);

  // 4. Set 2.4GHz to 20MHz
  console.log('4. Setting 2.4GHz to 20MHz...');
  r = await apiWrite(session, '/admin/wireless?form=wireless_2g', { htmode: '20' });
  d = r.data?.data || r.data;
  console.log(`   ${d?.success !== false ? 'OK' : 'FAILED: ' + JSON.stringify(d)}`);

  console.log('\nDone. Monitor Cox Killer dashboard for 30 min to measure improvement.');

} else if (cmd === 'get') {
  const form = process.argv[4] || 'smart_connect';
  const section = process.argv[5] || 'wireless';
  const r = await apiRequest(session, `/admin/${section}?form=${form}`);
  console.log(JSON.stringify(r.data, null, 2));

} else if (cmd === 'set') {
  // Usage: node router_login.mjs PASSWORD set form key=value [section]
  const form = process.argv[4];
  const kvStr = process.argv[5];
  const section = process.argv[6] || 'wireless';
  if (!form || !kvStr) {
    console.log('Usage: node router_login.mjs PASSWORD set FORM key=value [section]');
    process.exit(1);
  }
  const [key, val] = kvStr.split('=');
  let parsedVal = val;
  if (val === 'true') parsedVal = true;
  else if (val === 'false') parsedVal = false;
  else if (!isNaN(val)) parsedVal = Number(val);

  console.log(`Setting ${section}.${form}: ${key}=${parsedVal}`);
  const r = await apiWrite(session, `/admin/${section}?form=${form}`, { [key]: parsedVal });
  console.log(JSON.stringify(r.data, null, 2));

} else if (cmd === 'status') {
  const results = {};
  const internet = await apiRequest(session, '/admin/status?form=internet');
  results.internet = internet.data?.data || internet.data || {};
  for (const band of ['wireless_2g', 'wireless_5g', 'wireless_5g_2', 'wireless_6g']) {
    const r = await apiRequest(session, `/admin/wireless?form=${band}`);
    if (r.data?.success !== false) results[band] = r.data?.data || r.data || {};
  }
  const devInfo = await apiRequest(session, '/admin/status?form=router');
  results.device = devInfo.data?.data || devInfo.data || {};
  console.log(JSON.stringify(results));

} else {
  console.log('Commands: read, apply, get FORM [section], set FORM key=value [section], status');
}

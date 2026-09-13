/**
 * ============================================================
 *  CAPELLA — Cloudflare Worker (single-file bundle, v9)
 * ============================================================
 *  v9: Sessions effectively never expire for active users. Every
 *  API response now may carry an X-Renewed-Token header — a fresh
 *  30-day token, issued silently whenever the current one is within
 *  7 days of expiring. CLIENT INTEGRATION NEEDED: check for this
 *  header on every response and overwrite the stored token if
 *  present. Only an account genuinely untouched for 30+ days will
 *  need to log in again.
 *
 *  v8: GET /admin/wallet returns lockedReserve as a separate figure
 *  from totalRevenue.
 *
 *  v7: GET /admin/wallet — Capella's total earnings for the admin panel.
 *
 *  v6: Affiliate marketplace — direct-to-bank model. Business lists
 *  a product + bank details. Worker creates a link with their own
 *  bank details + added commission. Customer sees ONE combined price.
 *
 *  v5: Admin settings endpoint (GET/POST /admin/settings).
 *  v4: CORS fix for file uploads (x-mime-type header).
 *  v3: Song listings with releaseDate auto-expiry.
 *
 *  Bindings required (dashboard Settings > Bindings):
 *    - D1 database binding named "DB" -> capella-db
 *
 *  Secrets required (dashboard Settings > "Runtime variables and
 *  secrets" — NOT the Build section's variables):
 *    - PAYSTACK_SECRET_KEY
 *    - AUTH_SECRET
 *
 *  Cron Trigger required (dashboard Settings > Trigger events):
 *    - 0 * * * *
 * ============================================================
 */


// ============================================================
// FROM: auth.js
// ============================================================

const auth = (function() {
/**
 * Capella — Real Authentication (Cloudflare Workers + D1)
 * -----------------------------------------------------------
 * Replaces the temporary x-capella-user-id header (which anyone could
 * fake) with real password auth + signed session tokens, built entirely
 * on Web Crypto — no external auth service needed.
 *
 *   - Passwords: PBKDF2-SHA256, 100,000 iterations, random 16-byte salt
 *     per user. Never store or log plaintext passwords.
 *   - Sessions: a compact signed token (like a JWT, hand-rolled since
 *     Workers don't ship a JWT library by default) — base64url(header)
 *     + "." + base64url(payload) + "." + base64url(HMAC-SHA256
 *     signature). Payload carries { uid, exp }. Verifying recomputes
 *     the signature and checks expiry — nobody can forge a token
 *     without env.AUTH_SECRET (set via `wrangler secret put AUTH_SECRET`).
 *   - Token lifetime: 30 days, but sessions effectively never expire for
 *     anyone actively using the app: see maybeRenewToken below — every
 *     API response quietly includes a fresh token once the current one
 *     is within 7 days of expiring, so the client can swap it in
 *     without the user ever noticing or re-entering a password. Only
 *     an account untouched for 30+ full days actually needs to log in
 *     again — a genuinely inactive session, not an active user getting
 *     kicked out.
 *
 * Every other module's requireAuth(request, env) (see auth-helpers.js)
 * now runs through verifyToken() here instead of trusting a header.
 *
 * Routes (mounted in worker.js):
 *   POST /auth/register   { email?, phone?, password, referredBy? }
 *   POST /auth/login      { identifier, password }   (identifier = email or phone)
 *
 * Client integration note for the silent-renewal mechanism: every
 * response from the Worker may carry an `X-Renewed-Token` header. If
 * present, the client should overwrite its stored token with that
 * value immediately — it's a fresh 30-day token for the same account,
 * issued because the old one was getting close to expiring.
 */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}

const TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const PBKDF2_ITERATIONS = 100000;

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes.buffer;
}
function b64url(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new TextEncoder().encode(buf);
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecodeToString(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return atob(str);
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBuf(saltHex) : crypto.getRandomValues(new Uint8Array(16)).buffer;
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return { hash: bufToHex(bits), salt: saltHex || bufToHex(salt) };
}

async function verifyPassword(password, storedHashHex, saltHex) {
  const { hash } = await hashPassword(password, saltHex);
  // constant-time-ish compare
  if (hash.length !== storedHashHex.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ storedHashHex.charCodeAt(i);
  return diff === 0;
}

async function hmac(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", key, enc.encode(data));
}

async function signToken(uid, secret) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS;
  const payload = b64url(JSON.stringify({ uid, exp }));
  const signature = b64url(await hmac(`${header}.${payload}`, secret));
  return `${header}.${payload}.${signature}`;
}

// Shared by verifyToken and maybeRenewToken — decodes and checks the
// signature, but does NOT check expiry itself (callers decide what to
// do with an expired-but-validly-signed token).
async function decodeValidToken(token, secret) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts;
  const expectedSig = b64url(await hmac(`${header}.${payload}`, secret));
  if (signature !== expectedSig) return null;
  try {
    const data = JSON.parse(b64urlDecodeToString(payload));
    if (!data.uid || !data.exp) return null;
    return data;
  } catch {
    return null;
  }
}

async function verifyToken(token, secret) {
  const data = await decodeValidToken(token, secret);
  if (!data) return null;
  if (data.exp < Math.floor(Date.now() / 1000)) return null;
  return data.uid;
}

// Within this many seconds of expiring, a still-valid token gets
// silently replaced with a fresh 30-day one on every request. 7 days
// gives plenty of margin for someone who opens the app roughly weekly.
const RENEWAL_WINDOW_SECONDS = 7 * 24 * 60 * 60;

// Returns a fresh signed token if the request's current one is valid
// but getting close to expiring, otherwise null (nothing to renew —
// either no token was sent, it's already expired, or it's not due yet).
async function maybeRenewToken(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;

  const data = await decodeValidToken(match[1], env.AUTH_SECRET);
  if (!data) return null;

  const now = Math.floor(Date.now() / 1000);
  if (data.exp < now) return null; // already expired — must log in again, not renewed
  if (data.exp - now > RENEWAL_WINDOW_SECONDS) return null; // not due yet

  return signToken(data.uid, env.AUTH_SECRET);
}

// Called by every other module instead of reading x-capella-user-id directly.
async function requireAuth(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  return verifyToken(match[1], env.AUTH_SECRET);
}

// ---------------------------------------------------------------------
// POST /auth/register
// ---------------------------------------------------------------------
async function register(request, env) {
  const db = env.DB;
  const { email, phone, password, referredBy } = await request.json();

  if (!password || password.length < 8) {
    return json({ success: false, message: "Password must be at least 8 characters." }, 400);
  }
  if (!email && !phone) {
    return json({ success: false, message: "Provide an email or phone number." }, 400);
  }
  const cleanEmail = email ? String(email).trim().toLowerCase() : null;
  const cleanPhone = phone ? String(phone).trim() : null;

  if (cleanEmail) {
    const existing = await db.prepare("SELECT uid FROM users WHERE email = ?").bind(cleanEmail).first();
    if (existing) return json({ success: false, message: "An account with this email already exists." });
  }
  if (cleanPhone) {
    const existing = await db.prepare("SELECT uid FROM users WHERE phone = ?").bind(cleanPhone).first();
    if (existing) return json({ success: false, message: "An account with this phone number already exists." });
  }

  const uid = crypto.randomUUID();
  const { hash, salt } = await hashPassword(password);
  const now = new Date().toISOString();

  await db
    .prepare(
      `INSERT INTO users (uid, email, phone, passwordHash, passwordSalt, referredBy, status, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`
    )
    .bind(uid, cleanEmail, cleanPhone, hash, salt, referredBy || null, now)
    .run();

  const token = await signToken(uid, env.AUTH_SECRET);
  return json({ success: true, uid, token });
}

// ---------------------------------------------------------------------
// POST /auth/login
// ---------------------------------------------------------------------
async function login(request, env) {
  const db = env.DB;
  const { identifier, password } = await request.json();
  if (!identifier || !password) {
    return json({ success: false, message: "identifier and password are required." }, 400);
  }
  const clean = String(identifier).trim().toLowerCase();

  const user = await db.prepare("SELECT * FROM users WHERE email = ? OR phone = ?").bind(clean, identifier.trim()).first();
  if (!user) return json({ success: false, message: "Invalid credentials." }, 401);

  const ok = await verifyPassword(password, user.passwordHash, user.passwordSalt);
  if (!ok) return json({ success: false, message: "Invalid credentials." }, 401);

  const token = await signToken(user.uid, env.AUTH_SECRET);
  return json({ success: true, uid: user.uid, token });
}

  return { register, login, requireAuth, maybeRenewToken, signToken, verifyToken, hashPassword, verifyPassword };
})();


// ============================================================
// FROM: withdrawal.js
// ============================================================

const withdrawal = (function() {
/**
 * Capella — Withdrawal Endpoints (Cloudflare Workers + D1)
 * ----------------------------------------------------------
 * Ported from functions/withdrawal.js. Same behavior, different plumbing:
 *
 *   - Firestore transactions -> D1 doesn't have multi-row transactions the
 *     same way, so each "atomic" step is done as a single UPDATE with a
 *     WHERE guard (e.g. WHERE availableBalance >= ?) so two simultaneous
 *     requests can't both succeed. We check `meta.changes` after the write
 *     to know if the guard passed.
 *   - admin.firestore.FieldValue.increment(-amt) -> plain SQL arithmetic
 *     in the UPDATE statement itself.
 *   - Firestore auto IDs -> crypto.randomUUID().
 *   - Cloud Function secrets -> Worker secrets (env.PAYSTACK_SECRET_KEY),
 *     set via `wrangler secret put PAYSTACK_SECRET_KEY`.
 *   - onCall auth (request.auth.uid) -> the uid comes from a verified
 *     session token (see auth.js), passed as "Authorization: Bearer <token>".
 *
 * Routes handled here (mounted in worker.js):
 *   GET  /banks
 *   POST /banks/resolve
 *   POST /withdrawals
 *   POST /admin/reserve-withdrawals
 *   POST /webhooks/paystack-transfer
 */


const DEFAULT_MIN_WITHDRAWAL = 500; // NGN fallback if platform_settings has none

async function isAdmin(db, uid) {
  const row = await db.prepare("SELECT uid FROM admin_roles WHERE uid = ?").bind(uid).first();
  return !!row;
}

async function getMinWithdrawal(db) {
  const row = await db.prepare("SELECT minWithdrawal FROM platform_settings WHERE id = 'config'").first();
  return row?.minWithdrawal ?? DEFAULT_MIN_WITHDRAWAL;
}

async function paystackFetch(path, secret, options = {}) {
  const res = await fetch(`https://api.paystack.co${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${secret}`,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const json = await res.json();
  if (!res.ok || json.status === false) {
    throw new Error(json.message || "Paystack request failed");
  }
  return json;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ---------------------------------------------------------------------
// 1. List banks — cached in D1 for a day instead of Firestore's _cache
//    collection. Table: platform_settings isn't right for this since
//    it's not per-key; use a tiny dedicated cache table instead.
//    (Create once: CREATE TABLE IF NOT EXISTS kv_cache (key TEXT PRIMARY
//    KEY, value TEXT, fetchedAt TEXT); — add this if not already present.)
// ---------------------------------------------------------------------
async function listBanks(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const ONE_DAY_MS = 24 * 60 * 60 * 1000;
  const cached = await env.DB.prepare("SELECT value, fetchedAt FROM kv_cache WHERE key = 'ngnBanks'").first();
  if (cached && Date.now() - new Date(cached.fetchedAt).getTime() < ONE_DAY_MS) {
    return json({ banks: JSON.parse(cached.value) });
  }

  const res = await paystackFetch("/bank?country=nigeria&currency=NGN", env.PAYSTACK_SECRET_KEY);
  const banks = (res.data || []).map((b) => ({ name: b.name, code: b.code }));
  await env.DB.prepare(
    "INSERT INTO kv_cache (key, value, fetchedAt) VALUES ('ngnBanks', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, fetchedAt = excluded.fetchedAt"
  ).bind(JSON.stringify(banks), new Date().toISOString()).run();

  return json({ banks });
}

// ---------------------------------------------------------------------
// 2. Resolve account number -> account name
// ---------------------------------------------------------------------
async function resolveBankAccount(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { accountNumber, bankCode } = await request.json();
  if (!accountNumber || !bankCode) {
    return json({ message: "accountNumber and bankCode are required." }, 400);
  }

  try {
    const res = await paystackFetch(
      `/bank/resolve?account_number=${encodeURIComponent(accountNumber)}&bank_code=${encodeURIComponent(bankCode)}`,
      env.PAYSTACK_SECRET_KEY
    );
    return json({ accountName: res.data.account_name });
  } catch (err) {
    return json({ message: err.message }, 400);
  }
}

// ---------------------------------------------------------------------
// 3. Request withdrawal
//    Step 1 (guarded UPDATE) replaces the Firestore transaction: the
//    WHERE availableBalance >= ? clause means the row only updates if
//    there's enough money, and D1 reports back how many rows changed —
//    that's our success/failure signal, atomically, no race condition.
// ---------------------------------------------------------------------
async function requestWithdrawal(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { amount, bankCode, bankName, accountNumber, accountName } = await request.json();
  const amt = Math.floor(Number(amount));
  const db = env.DB;

  const minWithdrawal = await getMinWithdrawal(db);
  if (!amt || amt < minWithdrawal) {
    return json({ success: false, message: `Minimum withdrawal is ₦${minWithdrawal}.` });
  }
  if (!bankCode || !accountNumber || !accountName) {
    return json({ success: false, message: "Missing bank account details." });
  }

  const withdrawalId = crypto.randomUUID();
  const now = new Date().toISOString();

  // Guarded deduction: only succeeds if availableBalance >= amt.
  const deduction = await db
    .prepare(
      "UPDATE wallets SET availableBalance = availableBalance - ?, pendingBalance = pendingBalance + ? WHERE uid = ? AND availableBalance >= ?"
    )
    .bind(amt, amt, uid, amt)
    .run();

  if (deduction.meta.changes === 0) {
    return json({ success: false, message: "Insufficient balance." });
  }

  await db
    .prepare(
      `INSERT INTO withdrawals (id, userId, amount, provider, bankCode, bankName, accountNumber, accountName, status, requestedAt)
       VALUES (?, ?, ?, 'paystack', ?, ?, ?, ?, 'processing', ?)`
    )
    .bind(withdrawalId, uid, amt, bankCode, bankName || null, accountNumber, accountName, now)
    .run();

  // Step 2: talk to Paystack. On any failure, roll back step 1 exactly
  // like the original — give the money back to available balance.
  try {
    const recipientRes = await paystackFetch("/transferrecipient", env.PAYSTACK_SECRET_KEY, {
      method: "POST",
      body: JSON.stringify({
        type: "nuban",
        name: accountName,
        account_number: accountNumber,
        bank_code: bankCode,
        currency: "NGN",
      }),
    });
    const recipientCode = recipientRes.data.recipient_code;

    const transferRes = await paystackFetch("/transfer", env.PAYSTACK_SECRET_KEY, {
      method: "POST",
      body: JSON.stringify({
        source: "balance",
        amount: amt * 100, // kobo
        recipient: recipientCode,
        reason: "Capella worker withdrawal",
        reference: withdrawalId,
      }),
    });

    await db
      .prepare("UPDATE withdrawals SET providerRef = ?, paystackStatus = ? WHERE id = ?")
      .bind(transferRes.data.transfer_code, transferRes.data.status, withdrawalId)
      .run();

    if (transferRes.data.status === "otp") {
      return json({
        success: true,
        message: "Withdrawal is queued and needs manual approval — you'll be notified once it's sent.",
      });
    }
    return json({ success: true });
  } catch (err) {
    await db
      .prepare(
        "UPDATE wallets SET availableBalance = availableBalance + ?, pendingBalance = pendingBalance - ? WHERE uid = ?"
      )
      .bind(amt, amt, uid)
      .run();
    await db
      .prepare("UPDATE withdrawals SET status = 'failed', processedAt = ?, failureReason = ? WHERE id = ?")
      .bind(new Date().toISOString(), err.message, withdrawalId)
      .run();
    return json({ success: false, message: "Could not initiate transfer: " + err.message });
  }
}

// ---------------------------------------------------------------------
// 4. Admin reserve withdrawal
// ---------------------------------------------------------------------
async function requestReserveWithdrawal(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const { amount, bankCode, bankName, accountNumber, accountName, reason } = await request.json();
  const amt = Math.floor(Number(amount));
  if (!amt || amt <= 0) return json({ success: false, message: "Enter a valid reserve withdrawal amount." });
  if (!bankCode || !accountNumber || !accountName || !reason?.trim()) {
    return json({ success: false, message: "Amount, bank details and a reason are required." });
  }

  const reserveId = crypto.randomUUID();
  const now = new Date().toISOString();

  const lock = await db
    .prepare("UPDATE platform_treasury SET lockedReserve = lockedReserve - ?, updatedAt = ? WHERE id = 'main' AND lockedReserve >= ?")
    .bind(amt, now, amt)
    .run();

  if (lock.meta.changes === 0) {
    return json({ success: false, message: "Insufficient locked reserve." });
  }

  await db
    .prepare(
      `INSERT INTO reserve_withdrawals (id, amount, bankCode, bankName, accountNumber, accountName, reason, status, requestedBy, requestedAt, provider)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'processing', ?, ?, 'paystack')`
    )
    .bind(reserveId, amt, bankCode, bankName || null, accountNumber, accountName, reason.trim(), uid, now)
    .run();

  await db
    .prepare(
      `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, relatedId, reason, createdAt)
       VALUES (?, 'platformTreasury', 'platform', 'reserve_withdrawal_hold', ?, ?, ?, ?)`
    )
    .bind(crypto.randomUUID(), -amt, reserveId, reason.trim(), now)
    .run();

  try {
    const recipientRes = await paystackFetch("/transferrecipient", env.PAYSTACK_SECRET_KEY, {
      method: "POST",
      body: JSON.stringify({ type: "nuban", name: accountName, account_number: accountNumber, bank_code: bankCode, currency: "NGN" }),
    });
    const transferRes = await paystackFetch("/transfer", env.PAYSTACK_SECRET_KEY, {
      method: "POST",
      body: JSON.stringify({
        source: "balance",
        amount: amt * 100,
        recipient: recipientRes.data.recipient_code,
        reason: "Capella reserve withdrawal",
        reference: reserveId,
      }),
    });
    await db
      .prepare("UPDATE reserve_withdrawals SET providerRef = ?, paystackStatus = ? WHERE id = ?")
      .bind(transferRes.data.transfer_code, transferRes.data.status, reserveId)
      .run();
    return json({ success: true, status: transferRes.data.status, reference: reserveId });
  } catch (err) {
    const rollbackTime = new Date().toISOString();
    await db
      .prepare("UPDATE platform_treasury SET lockedReserve = lockedReserve + ?, updatedAt = ? WHERE id = 'main'")
      .bind(amt, rollbackTime)
      .run();
    await db
      .prepare("UPDATE reserve_withdrawals SET status = 'failed', processedAt = ?, failureReason = ? WHERE id = ?")
      .bind(rollbackTime, err.message, reserveId)
      .run();
    await db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, relatedId, createdAt)
         VALUES (?, 'platformTreasury', 'platform', 'reserve_withdrawal_rollback', ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), amt, reserveId, rollbackTime)
      .run();
    return json({ success: false, message: "Could not initiate reserve transfer: " + err.message });
  }
}

// ---------------------------------------------------------------------
// 5. Paystack transfer webhook — same signature check, same "webhook is
//    the real source of truth" logic, now against D1 rows instead of
//    Firestore docs.
// ---------------------------------------------------------------------
async function transferWebhook(request, env) {
  const rawBody = await request.text();
  const signature = request.headers.get("x-paystack-signature");

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(env.PAYSTACK_SECRET_KEY),
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"]
  );
  const sigBuffer = await crypto.subtle.sign("HMAC", key, encoder.encode(rawBody));
  const expected = [...new Uint8Array(sigBuffer)].map((b) => b.toString(16).padStart(2, "0")).join("");

  if (signature !== expected) {
    return new Response("Invalid signature", { status: 401 });
  }

  const event = JSON.parse(rawBody);
  const db = env.DB;

  if (["transfer.success", "transfer.failed", "transfer.reversed"].includes(event.event)) {
    const reference = event.data.reference;
    const now = new Date().toISOString();

    // Check reserve withdrawals first
    const reserveRow = await db.prepare("SELECT * FROM reserve_withdrawals WHERE id = ?").bind(reference).first();
    if (reserveRow) {
      if (reserveRow.status !== "processing") return new Response("OK (already handled)", { status: 200 });

      if (event.event === "transfer.success") {
        await db.prepare("UPDATE reserve_withdrawals SET status = 'completed', processedAt = ? WHERE id = ?").bind(now, reference).run();
      } else {
        await db
          .prepare("UPDATE platform_treasury SET lockedReserve = lockedReserve + ?, updatedAt = ? WHERE id = 'main'")
          .bind(reserveRow.amount, now)
          .run();
        await db
          .prepare("UPDATE reserve_withdrawals SET status = 'failed', processedAt = ?, failureReason = ? WHERE id = ?")
          .bind(now, event.data.failure_reason || event.event, reference)
          .run();
        await db
          .prepare(
            `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, relatedId, createdAt)
             VALUES (?, 'platformTreasury', 'platform', 'reserve_withdrawal_rollback', ?, ?, ?)`
          )
          .bind(crypto.randomUUID(), reserveRow.amount, reference, now)
          .run();
      }
      return new Response("OK", { status: 200 });
    }

    // Otherwise a normal worker withdrawal
    const withdrawal = await db.prepare("SELECT * FROM withdrawals WHERE id = ?").bind(reference).first();
    if (!withdrawal) return new Response("OK (unknown reference, ignored)", { status: 200 });
    if (withdrawal.status !== "processing") return new Response("OK (already handled)", { status: 200 });

    if (event.event === "transfer.success") {
      await db.prepare("UPDATE wallets SET pendingBalance = pendingBalance - ? WHERE uid = ?").bind(withdrawal.amount, withdrawal.userId).run();
      await db.prepare("UPDATE withdrawals SET status = 'completed', processedAt = ? WHERE id = ?").bind(now, reference).run();
      await db
        .prepare(
          `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
           VALUES (?, ?, 'withdrawal_completed', 'Withdrawal completed', ?, ?, 0, ?)`
        )
        .bind(crypto.randomUUID(), withdrawal.userId, `₦${withdrawal.amount} was sent to your bank account.`, reference, now)
        .run();
    } else {
      await db
        .prepare("UPDATE wallets SET availableBalance = availableBalance + ?, pendingBalance = pendingBalance - ? WHERE uid = ?")
        .bind(withdrawal.amount, withdrawal.amount, withdrawal.userId)
        .run();
      await db
        .prepare("UPDATE withdrawals SET status = 'failed', processedAt = ?, failureReason = ? WHERE id = ?")
        .bind(now, event.data.failure_reason || event.event, reference)
        .run();
      await db
        .prepare(
          `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
           VALUES (?, ?, 'withdrawal_failed', 'Withdrawal failed', ?, ?, 0, ?)`
        )
        .bind(
          crypto.randomUUID(),
          withdrawal.userId,
          `Your ₦${withdrawal.amount} withdrawal didn't go through — the amount is back in your available balance.`,
          reference,
          now
        )
        .run();
    }
  }

  return new Response("OK", { status: 200 });
}

  return { listBanks, resolveBankAccount, requestWithdrawal, requestReserveWithdrawal, transferWebhook };
})();


// ============================================================
// FROM: finance.js
// ============================================================

const finance = (function() {
/**
 * Capella — Finance Endpoints (Cloudflare Workers + D1)
 * -------------------------------------------------------
 * Ported from functions/finance.js. This is the money-split core of the
 * platform, so the porting rules here matter:
 *
 *   - Firestore db.runTransaction(...) -> env.DB.batch([...]) . D1's
 *     batch() runs every statement in one real SQL transaction: either
 *     all of them commit or none do. That gives us the same all-or-
 *     nothing guarantee Firestore transactions gave us.
 *   - Because batch() can't branch mid-way (no "read a value, then decide
 *     what to write" inside the batch itself), every precondition is
 *     checked with plain SELECTs *before* building the batch, exactly
 *     like the tx.get() calls at the top of each Firestore transaction.
 *     The batch itself then also carries WHERE guards (e.g.
 *     availableBalance >= ?) so a race between two requests still can't
 *     overdraw anything, even though the pre-check already looked safe.
 *   - FieldValue.increment(x) -> "col = col + x" in the UPDATE.
 *   - FieldValue.serverTimestamp() -> new Date().toISOString(), computed
 *     once per request so every row in the batch shares the same time.
 *   - Firestore auto IDs -> crypto.randomUUID().
 *
 * Routes handled here (mounted in worker.js):
 *   POST /campaigns                (createCampaign)
 *   POST /campaigns/:id/cancel     (cancelCampaign)
 *   POST /admin/submissions/:id/approve
 *   POST /admin/submissions/:id/reject
 */


function n(v) {
  const x = Number(v);
  return Number.isFinite(x) ? x : 0;
}
function safeText(v) {
  return typeof v === "string" ? v.slice(0, 5000) : "";
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
async function isAdmin(db, uid) {
  const row = await db.prepare("SELECT uid FROM admin_roles WHERE uid = ?").bind(uid).first();
  return !!row;
}

// ---------------------------------------------------------------------
// createCampaign — business funds a campaign from its wallet
// ---------------------------------------------------------------------
async function createCampaign(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const d = await request.json();
  const taskTypeId = String(d.taskTypeId || "");
  const qty = Math.floor(n(d.quantity));
  const requirements = safeText(d.requirements).trim();
  const platform = d.platform ? safeText(d.platform).trim() : null;

  if (!taskTypeId || qty < 1 || !requirements) {
    return json({ success: false, message: "Task, quantity and requirements are required." });
  }

  const [user, task, wallet] = await Promise.all([
    db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first(),
    db.prepare("SELECT * FROM task_catalogue WHERE id = ?").bind(taskTypeId).first(),
    db.prepare("SELECT * FROM business_wallets WHERE uid = ?").bind(uid).first(),
  ]);

  if (!user || !user.accountActivated || !user.roleBusiness) {
    return json({ success: false, message: "Business access is not activated." });
  }
  if (!task || task.active === 0) {
    return json({ success: false, message: "Task type is unavailable." });
  }

  const minQty = Math.max(1, Math.floor(n(task.minCampaignSize)));
  if (qty < minQty) return json({ success: false, message: `Minimum campaign size is ${minQty}.` });

  const workerReward = Math.floor(n(task.workerReward));
  const businessPrice = Math.floor(n(task.businessPrice));
  if (businessPrice <= 0 || workerReward <= 0 || workerReward !== Math.floor(businessPrice * 0.7)) {
    return json({ success: false, message: "This task pricing is not configured for the 70/15/5/10 split." });
  }

  const total = qty * businessPrice;
  const available = n(wallet?.availableBalance);
  if (available < total) {
    return json({ success: false, message: `Insufficient wallet balance. You need ₦${total.toLocaleString()}.` });
  }

  const campaignId = crypto.randomUUID();
  const now = new Date().toISOString();
  const title = task.name + (platform ? ` — ${platform}` : "");

  const statements = [
    db
      .prepare(
        "UPDATE business_wallets SET availableBalance = availableBalance - ?, reservedFunds = reservedFunds + ? WHERE uid = ? AND availableBalance >= ?"
      )
      .bind(total, total, uid, total),
    db
      .prepare(
        `INSERT INTO campaigns (id, businessId, taskTypeId, title, requirements, targetAudience, platform, category, quantityTarget, quantityCompleted, quantityRejected, workerRewardSnapshot, businessPriceSnapshot, totalDeposit, remainingBudget, status, createdAt, launchedAt)
         VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, 0, 0, ?, ?, ?, ?, 'active', ?, ?)`
      )
      .bind(campaignId, uid, taskTypeId, title, requirements, platform, task.category, qty, workerReward, businessPrice, total, total, now, now),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
         VALUES (?, ?, 'business', 'campaign_funding', ?, ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), uid, -total, available - total, campaignId, now),
  ];

  const results = await db.batch(statements);
  if (results[0].meta.changes === 0) {
    return json({ success: false, message: "Insufficient wallet balance (balance changed, please retry)." });
  }

  return json({ success: true, campaignId, total });
}

// ---------------------------------------------------------------------
// cancelCampaign — refund remaining budget back to available balance
// ---------------------------------------------------------------------
async function cancelCampaign(request, env, campaignId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  if (!campaignId) return json({ success: false, message: "campaignId is required." });

  const camp = await db.prepare("SELECT * FROM campaigns WHERE id = ?").bind(campaignId).first();
  if (!camp) return json({ success: false, message: "Campaign not found." });
  if (camp.businessId !== uid) return json({ success: false, message: "Not your campaign." });
  if (camp.status !== "active") return json({ success: false, message: "Only active campaigns can be cancelled." });

  const refund = Math.max(0, n(camp.remainingBudget));
  const wallet = await db.prepare("SELECT * FROM business_wallets WHERE uid = ?").bind(uid).first();
  if (!wallet) return json({ success: false, message: "Business wallet not found." });
  if (n(wallet.reservedFunds) < refund) {
    return json({ success: false, message: "Reserved funds are inconsistent; cancellation blocked." });
  }

  const now = new Date().toISOString();
  const statements = [
    db
      .prepare("UPDATE campaigns SET status = 'cancelled', completedAt = ? WHERE id = ? AND status = 'active'")
      .bind(now, campaignId),
  ];

  if (refund > 0) {
    statements.push(
      db
        .prepare(
          "UPDATE business_wallets SET availableBalance = availableBalance + ?, reservedFunds = reservedFunds - ? WHERE uid = ? AND reservedFunds >= ?"
        )
        .bind(refund, refund, uid, refund),
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
           VALUES (?, ?, 'business', 'refund', ?, ?, ?, ?)`
        )
        .bind(crypto.randomUUID(), uid, refund, n(wallet.availableBalance) + refund, campaignId, now)
    );
  }

  statements.push(
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         VALUES (?, ?, 'campaign_cancelled', 'Campaign cancelled', ?, ?, 0, ?)`
      )
      .bind(
        crypto.randomUUID(),
        uid,
        `Your campaign was cancelled. ₦${refund.toLocaleString()} was returned to your available wallet.`,
        campaignId,
        now
      )
  );

  const results = await db.batch(statements);
  if (results[0].meta.changes === 0) {
    return json({ success: false, message: "Campaign state changed, please retry." });
  }

  return json({ success: true, refund });
}

// ---------------------------------------------------------------------
// reviewSubmission — the 70/15/5/10 split payout on approval, or a
// rejection that updates the worker's track record.
// ---------------------------------------------------------------------
async function reviewSubmission(request, env, submissionId, approve) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);
  if (!submissionId) return json({ success: false, message: "submissionId is required." });

  const sub = await db.prepare("SELECT * FROM submissions WHERE id = ?").bind(submissionId).first();
  if (!sub) return json({ success: false, message: "Submission not found." });
  if (!["pending", "needs_review"].includes(sub.status)) {
    return json({ success: false, message: "Submission has already been reviewed." });
  }

  const now = new Date().toISOString();

  // ---- Rejection path ----
  if (!approve) {
    const prof = await db.prepare("SELECT * FROM worker_profiles WHERE uid = ?").bind(sub.workerId).first();
    const rejected = n(prof?.tasksRejected) + 1;
    const completed = n(prof?.tasksCompleted);
    const rate = completed + rejected ? Math.round((completed / (completed + rejected)) * 100) : 100;

    const statements = [
      db
        .prepare("UPDATE submissions SET status = 'rejected', verificationMode = 'human', verifiedAt = ?, rewardPaid = 0 WHERE id = ? AND status IN ('pending','needs_review')")
        .bind(now, submissionId),
      db
        .prepare(
          `INSERT INTO worker_profiles (uid, tasksRejected, successRatePct) VALUES (?, ?, ?)
           ON CONFLICT(uid) DO UPDATE SET tasksRejected = ?, successRatePct = ?`
        )
        .bind(sub.workerId, rejected, rate, rejected, rate),
      db
        .prepare(
          `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
           VALUES (?, ?, 'submission_rejected', 'Task rejected', 'Your task submission was rejected. You may raise a dispute if you believe this was a mistake.', ?, 0, ?)`
        )
        .bind(crypto.randomUUID(), sub.workerId, submissionId, now),
    ];

    const results = await db.batch(statements);
    if (results[0].meta.changes === 0) return json({ success: false, message: "Submission state changed, please retry." });
    return json({ success: true, status: "rejected" });
  }

  // ---- Approval path ----
  const [task, camp] = await Promise.all([
    db.prepare("SELECT * FROM task_catalogue WHERE id = ?").bind(sub.taskTypeId).first(),
    db.prepare("SELECT * FROM campaigns WHERE id = ?").bind(sub.campaignId).first(),
  ]);
  if (!task || !camp) return json({ success: false, message: "Task or campaign is missing." });
  if (camp.status !== "active") return json({ success: false, message: "Campaign is no longer active." });

  const workerReward = Math.floor(n(sub.workerRewardSnapshot ?? task.workerReward));
  const businessPrice = Math.floor(n(sub.businessPriceSnapshot ?? camp.businessPriceSnapshot ?? task.businessPrice));
  if (workerReward <= 0 || businessPrice <= 0 || workerReward !== Math.floor(businessPrice * 0.7)) {
    return json({ success: false, message: "Invalid 70/15/5/10 campaign pricing." });
  }
  if (n(camp.remainingBudget) < businessPrice) {
    return json({ success: false, message: "Campaign has insufficient remaining funds." });
  }

  const [workerWallet, bizWallet, treasury] = await Promise.all([
    db.prepare("SELECT * FROM wallets WHERE uid = ?").bind(sub.workerId).first(),
    db.prepare("SELECT * FROM business_wallets WHERE uid = ?").bind(camp.businessId).first(),
    db.prepare("SELECT * FROM platform_treasury WHERE id = 'main'").first(),
  ]);
  if (!bizWallet || n(bizWallet.reservedFunds) < businessPrice) {
    return json({ success: false, message: "Business reserved funds are inconsistent; payout blocked." });
  }

  const referrerId = sub.referrerId || null;
  const referralAmount = referrerId ? Math.floor(businessPrice * 0.1) : 0;
  const reserveAmount = Math.floor(businessPrice * 0.05);
  const platformAmount = businessPrice - workerReward - referralAmount - reserveAmount;

  const completed = n(camp.quantityCompleted) + 1;
  const rejected = n(camp.quantityRejected);
  const target = n(camp.quantityTarget);
  const exhausted = completed + rejected >= target;
  const remaining = n(camp.remainingBudget) - businessPrice;

  const wAvail = n(workerWallet?.availableBalance);
  const bwAvail = n(bizWallet.availableBalance);

  const statements = [
    db
      .prepare(
        "UPDATE submissions SET status = 'approved', verificationMode = 'human', verifiedAt = ?, rewardPaid = 1 WHERE id = ? AND status IN ('pending','needs_review')"
      )
      .bind(now, submissionId),
    db
      .prepare(
        `INSERT INTO wallets (uid, availableBalance, totalEarned, todayEarnings, breakdownTaskEarnings) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(uid) DO UPDATE SET availableBalance = availableBalance + ?, totalEarned = totalEarned + ?, todayEarnings = todayEarnings + ?, breakdownTaskEarnings = breakdownTaskEarnings + ?`
      )
      .bind(sub.workerId, workerReward, workerReward, workerReward, workerReward, workerReward, workerReward, workerReward, workerReward),
    db
      .prepare(
        `INSERT INTO worker_profiles (uid, tasksCompleted) VALUES (?, 1)
         ON CONFLICT(uid) DO UPDATE SET tasksCompleted = tasksCompleted + 1`
      )
      .bind(sub.workerId),
    db
      .prepare(
        `UPDATE campaigns SET quantityCompleted = quantityCompleted + 1, remainingBudget = remainingBudget - ?, status = ?, completedAt = ? WHERE id = ? AND remainingBudget >= ?`
      )
      .bind(businessPrice, exhausted ? "completed" : camp.status, exhausted ? now : camp.completedAt, sub.campaignId, businessPrice),
    db
      .prepare(
        `UPDATE business_wallets SET reservedFunds = reservedFunds - ?${exhausted && remaining > 0 ? ", availableBalance = availableBalance + ?" : ""} WHERE uid = ? AND reservedFunds >= ?`
      )
      .bind(...(exhausted && remaining > 0 ? [businessPrice, remaining, camp.businessId, businessPrice] : [businessPrice, camp.businessId, businessPrice])),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, verificationMode, createdAt)
         VALUES (?, ?, 'worker', 'task_reward', ?, ?, ?, 'human', ?)`
      )
      .bind(crypto.randomUUID(), sub.workerId, workerReward, wAvail + workerReward, submissionId, now),
    db
      .prepare(
        `INSERT INTO platform_revenue (id, type, amount, grossAmount, workerAmount, referralAmount, reserveAmount, netPlatformRevenue, unassignedReferralAmount, businessId, workerId, campaignId, submissionId, verificationMode, createdAt)
         VALUES (?, 'campaign_service_revenue', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'human', ?)`
      )
      .bind(
        crypto.randomUUID(),
        platformAmount,
        businessPrice,
        workerReward,
        referralAmount,
        reserveAmount,
        platformAmount,
        referrerId ? 0 : Math.floor(businessPrice * 0.1),
        camp.businessId,
        sub.workerId,
        sub.campaignId,
        submissionId,
        now
      ),
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         VALUES (?, ?, 'submission_approved', 'Task approved', ?, ?, 0, ?)`
      )
      .bind(crypto.randomUUID(), sub.workerId, `Your submission was approved — ₦${workerReward.toLocaleString()} added to your wallet.`, submissionId, now),
  ];

  if (reserveAmount) {
    statements.push(
      db
        .prepare(
          `INSERT INTO platform_treasury (id, lockedReserve, updatedAt) VALUES ('main', ?, ?)
           ON CONFLICT(id) DO UPDATE SET lockedReserve = lockedReserve + ?, updatedAt = ?`
        )
        .bind(reserveAmount, now, reserveAmount, now),
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, relatedId, createdAt)
           VALUES (?, 'platformTreasury', 'platform', 'reserve_allocation', ?, ?, ?)`
        )
        .bind(crypto.randomUUID(), reserveAmount, submissionId, now)
    );
  }

  if (referrerId) {
    const refWallet = await db.prepare("SELECT * FROM wallets WHERE uid = ?").bind(referrerId).first();
    const pending = n(refWallet?.pendingBalance);
    statements.push(
      db
        .prepare(
          `INSERT INTO wallets (uid, pendingBalance) VALUES (?, ?)
           ON CONFLICT(uid) DO UPDATE SET pendingBalance = ?`
        )
        .bind(referrerId, pending + referralAmount, pending + referralAmount),
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
           VALUES (?, ?, 'worker', 'referral_commission_pending', ?, ?, ?, ?)`
        )
        .bind(crypto.randomUUID(), referrerId, referralAmount, pending + referralAmount, submissionId, now)
    );
  }

  if (exhausted && remaining > 0) {
    statements.push(
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, reason, createdAt)
           VALUES (?, ?, 'business', 'refund', ?, ?, ?, 'unused_campaign_budget', ?)`
        )
        .bind(crypto.randomUUID(), camp.businessId, remaining, bwAvail + remaining, sub.campaignId, now)
    );
  }

  const results = await db.batch(statements);
  if (results[0].meta.changes === 0) {
    return json({ success: false, message: "Submission state changed, please retry." });
  }
  if (results[3].meta.changes === 0) {
    return json({ success: false, message: "Campaign budget changed concurrently — payout aborted, please retry the review." });
  }

  return json({ success: true, status: "approved", reward: workerReward, referralAmount, reserveAmount, platformAmount });
}

  return { createCampaign, cancelCampaign, reviewSubmission };
})();


// ============================================================
// FROM: activation.js
// ============================================================

const activation = (function() {
/**
 * Capella — Activation Endpoint (Cloudflare Workers + D1)
 * -----------------------------------------------------------
 * Ported from functions/activation.js. Same security-critical rule as
 * the original: never trust amount/status from the client. This
 * endpoint re-verifies the transaction directly with Paystack using the
 * secret key before writing anything.
 *
 * Route (mounted in worker.js):
 *   POST /activations/verify   { reference }
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
const DEFAULT_REGISTRATION_FEE = 5000; // NGN

async function getRegistrationFee(db) {
  const row = await db.prepare("SELECT registrationFee FROM platform_settings WHERE id = 'config'").first();
  return row?.registrationFee ?? DEFAULT_REGISTRATION_FEE;
}

async function verifyActivationPayment(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "You must be signed in." }, 401);
  const db = env.DB;

  const { reference } = await request.json();
  if (!reference || typeof reference !== "string") {
    return json({ success: false, message: "Missing payment reference." }, 400);
  }

  // Idempotency: same as the Firestore version — if we've already
  // processed this reference, don't do it again.
  const existing = await db.prepare("SELECT id FROM activations WHERE id = ?").bind(reference).first();
  if (existing) return json({ success: true, alreadyProcessed: true });

  const user = await db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first();
  if (!user) return json({ success: false, message: "User record not found." }, 404);
  if (user.accountActivated) return json({ success: true, alreadyProcessed: true });

  const expectedAmountNaira = await getRegistrationFee(db);
  const expectedAmountKobo = expectedAmountNaira * 100;

  // ---- The real check: ask Paystack directly, don't trust the client ----
  const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}` },
  });
  const verifyJson = await verifyRes.json();

  if (!verifyRes.ok || !verifyJson.status) {
    return json({ success: false, message: "Could not reach Paystack to verify payment." }, 502);
  }
  const txn = verifyJson.data;
  if (txn.status !== "success") {
    return json({ success: false, message: `Payment was not successful (status: ${txn.status}).` });
  }
  if (txn.currency !== "NGN") {
    return json({ success: false, message: "Unexpected currency on transaction." });
  }
  if (txn.amount !== expectedAmountKobo) {
    return json({
      success: false,
      message: `Amount mismatch: expected ₦${expectedAmountNaira}, Paystack shows ₦${txn.amount / 100}.`,
    });
  }
  if (txn.metadata?.userId && txn.metadata.userId !== uid) {
    return json({ message: "This payment reference belongs to a different account." }, 403);
  }

  // ---- Verified. Now write the actual state changes, atomically. ----
  const now = new Date().toISOString();
  const statements = [
    db
      .prepare(
        `INSERT INTO activations (id, userId, role, amount, provider, providerRef, status, createdAt)
         VALUES (?, ?, 'account', ?, 'paystack', ?, 'success', ?)`
      )
      .bind(reference, uid, expectedAmountNaira, reference, now),
    db
      .prepare(
        `UPDATE users SET accountActivated = 1, accountActivatedAt = ?, workerActivated = 1, workerActivatedAt = ?, businessActivated = 1, businessActivatedAt = ? WHERE uid = ? AND accountActivated = 0`
      )
      .bind(now, now, now, uid),
    db
      .prepare(
        `INSERT INTO platform_revenue (id, type, amount, userId, relatedId, createdAt)
         VALUES (?, 'registration_fee', ?, ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), expectedAmountNaira, uid, reference, now),
    db
      .prepare(
        `INSERT INTO worker_profiles (uid, level, tasksCompleted, tasksRejected, successRatePct, accuracyPct, reputationScore, kycStatus)
         VALUES (?, 1, 0, 0, 100, 100, 0, 'none')
         ON CONFLICT(uid) DO NOTHING`
      )
      .bind(uid),
    db
      .prepare(
        `INSERT INTO business_wallets (uid, availableBalance, reservedFunds, campaignFunds) VALUES (?, 0, 0, 0)
         ON CONFLICT(uid) DO NOTHING`
      )
      .bind(uid),
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         VALUES (?, ?, 'activation_success', 'Account activated', ?, ?, 0, ?)`
      )
      .bind(
        crypto.randomUUID(),
        uid,
        `Your ₦${expectedAmountNaira.toLocaleString()} one-time activation was verified. Worker and Business modes are now unlocked.`,
        reference,
        now
      ),
  ];

  const results = await db.batch(statements);
  // If the user row didn't actually flip (e.g. a concurrent request already
  // activated the account between our check and now), treat as already done
  // rather than erroring — same spirit as the Firestore idempotency check.
  if (results[1].meta.changes === 0) {
    return json({ success: true, alreadyProcessed: true });
  }

  return json({ success: true });
}

  return { verifyActivationPayment };
})();


// ============================================================
// FROM: task.js
// ============================================================

const task = (function() {
/**
 * Capella — Task Submission + Auto-Verification (Cloudflare Workers + D1)
 * ---------------------------------------------------------------------------
 * Ported from functions/task.js — with one real architectural change:
 *
 *   Firestore had onDocumentCreated('submissions/{id}') fire automatically
 *   the instant a worker wrote a submission doc. Cloudflare has no
 *   equivalent — there's no "run this when a row appears" hook for D1.
 *   So the client now calls ONE endpoint, POST /submissions, which both
 *   creates the submission AND runs the exact same verification logic
 *   the trigger used to run, in the same request. From the client's
 *   point of view the behavior is identical (submit -> get back
 *   approved/needs_review); it just happens synchronously now instead
 *   of via a background trigger.
 *
 * Two bugs in the original source were NOT carried over:
 *   1. approveAtomically() referenced `tx` without ever receiving it as
 *      a parameter — would have thrown at runtime.
 *   2. `capellaGross` was used but never defined (should have been
 *      businessPrice). This port uses businessPrice, matching the
 *      70/15/5/10 split used everywhere else (see finance.js).
 *
 * Route (mounted in worker.js):
 *   POST /submissions   { campaignId, taskTypeId, proofData, verificationResult? }
 */


function n(v) {
  const x = Number(v);
  return Number.isFinite(x) ? x : 0;
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
function levelFor(completed) {
  if (completed >= 100) return { level: 5, progressPct: 100 };
  if (completed >= 50) return { level: 4, progressPct: Math.round(((completed - 50) / 50) * 100) };
  if (completed >= 20) return { level: 3, progressPct: Math.round(((completed - 20) / 30) * 100) };
  if (completed >= 5) return { level: 2, progressPct: Math.round(((completed - 5) / 15) * 100) };
  return { level: 1, progressPct: Math.round((completed / 5) * 100) };
}

async function createSubmission(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const d = await request.json();
  const campaignId = String(d.campaignId || "");
  const taskTypeId = String(d.taskTypeId || "");
  const proofData = d.proofData ?? null;
  const verificationResult = d.verificationResult ?? null; // only meaningful if it came from a trusted server-side adapter

  if (!campaignId || !taskTypeId) {
    return json({ success: false, message: "campaignId and taskTypeId are required." });
  }

  const [task, campaign] = await Promise.all([
    db.prepare("SELECT * FROM task_catalogue WHERE id = ?").bind(taskTypeId).first(),
    db.prepare("SELECT * FROM campaigns WHERE id = ?").bind(campaignId).first(),
  ]);

  const submissionId = `${campaignId}_${uid}`;
  const now = new Date().toISOString();

  if (!task || !campaign) {
    await db
      .prepare(
        `INSERT INTO submissions (id, workerId, campaignId, taskTypeId, status, proofData, verificationMode, verificationReason, verificationCheckedAt, createdAt)
         VALUES (?, ?, ?, ?, 'rejected', ?, 'automatic', 'Missing task or campaign.', ?, ?)
         ON CONFLICT(id) DO NOTHING`
      )
      .bind(submissionId, uid, campaignId, taskTypeId, JSON.stringify(proofData), now, now)
      .run();
    return json({ success: false, status: "rejected", message: "Missing task or campaign." });
  }

  // Deterministic precondition checks — same list as the original trigger.
  const reasons = [];
  if (campaign.status !== "active") reasons.push("campaign_not_active");
  if (campaign.businessId == null) reasons.push("campaign_owner_missing");
  const businessPriceSnapshot = n(campaign.businessPriceSnapshot ?? task.businessPrice);
  if (n(campaign.remainingBudget) < businessPriceSnapshot) reasons.push("insufficient_campaign_funding");
  if (proofData == null) reasons.push("missing_proof");

  const workerRewardSnapshot = n(task.workerReward);

  if (reasons.length) {
    await db
      .prepare(
        `INSERT INTO submissions (id, workerId, campaignId, taskTypeId, status, proofData, workerRewardSnapshot, businessPriceSnapshot, verificationMode, verificationReason, verificationCheckedAt, createdAt)
         VALUES (?, ?, ?, ?, 'needs_review', ?, ?, ?, 'automatic', ?, ?, ?)
         ON CONFLICT(id) DO NOTHING`
      )
      .bind(
        submissionId,
        uid,
        campaignId,
        taskTypeId,
        JSON.stringify(proofData),
        workerRewardSnapshot,
        businessPriceSnapshot,
        reasons.join(", "),
        now,
        now
      )
      .run();
    return json({ success: true, status: "needs_review", reason: reasons.join(", ") });
  }

  const method = String(task.verificationMethod || "screenshot").toLowerCase();

  // proofData.proofFileId points at a row this worker actually uploaded via
  // POST /task-proofs (see storage.js). We verify it's real and theirs, then
  // tag it with this submission so admin review can pull it up later.
  let hasScreenshot = false;
  if (proofData?.type === "screenshot" && proofData.proofFileId) {
    const proofRow = await db
      .prepare("SELECT id FROM task_proof_files WHERE id = ? AND workerId = ?")
      .bind(proofData.proofFileId, uid)
      .first();
    if (proofRow) {
      hasScreenshot = true;
      await db.prepare("UPDATE task_proof_files SET submissionId = ? WHERE id = ?").bind(submissionId, proofData.proofFileId).run();
    }
  }
  const hasForm = proofData?.type === "form_response" && typeof proofData.text === "string" && proofData.text.trim().length >= 3;
  const trustedAdapterPassed = verificationResult?.trusted === true && verificationResult?.passed === true;

  const formAuto = method.includes("form submission") && task.aiVerifiable === "yes" && hasForm;
  const trustedAuto = method.includes("automated check") && trustedAdapterPassed;

  if (!formAuto && !trustedAuto) {
    // Screenshot / ambiguous tasks always go to human review — same rule
    // as the original: a file existing is not proof the action happened.
    await db
      .prepare(
        `INSERT INTO submissions (id, workerId, campaignId, taskTypeId, status, proofData, workerRewardSnapshot, businessPriceSnapshot, verificationMode, verificationReason, verificationCheckedAt, createdAt)
         VALUES (?, ?, ?, ?, 'needs_review', ?, ?, ?, 'automatic', ?, ?, ?)
         ON CONFLICT(id) DO NOTHING`
      )
      .bind(
        submissionId,
        uid,
        campaignId,
        taskTypeId,
        JSON.stringify(proofData),
        workerRewardSnapshot,
        businessPriceSnapshot,
        hasScreenshot ? "Screenshot requires semantic verification or human review." : "Task evidence requires human review.",
        now,
        now
      )
      .run();
    return json({ success: true, status: "needs_review" });
  }

  // ---- Auto-approve path: same 70/15/5/10 split as human review ----
  if (businessPriceSnapshot <= 0 || workerRewardSnapshot <= 0 || workerRewardSnapshot !== Math.floor(businessPriceSnapshot * 0.7)) {
    await db
      .prepare(
        `INSERT INTO submissions (id, workerId, campaignId, taskTypeId, status, proofData, workerRewardSnapshot, businessPriceSnapshot, verificationMode, verificationReason, verificationCheckedAt, createdAt)
         VALUES (?, ?, ?, ?, 'needs_review', ?, ?, ?, 'automatic', 'Invalid 70/15/5/10 campaign pricing.', ?, ?)
         ON CONFLICT(id) DO NOTHING`
      )
      .bind(submissionId, uid, campaignId, taskTypeId, JSON.stringify(proofData), workerRewardSnapshot, businessPriceSnapshot, now, now)
      .run();
    return json({ success: true, status: "needs_review", reason: "invalid_pricing" });
  }

  const [workerWallet, workerProfile, bizWallet] = await Promise.all([
    db.prepare("SELECT * FROM wallets WHERE uid = ?").bind(uid).first(),
    db.prepare("SELECT * FROM worker_profiles WHERE uid = ?").bind(uid).first(),
    db.prepare("SELECT * FROM business_wallets WHERE uid = ?").bind(campaign.businessId).first(),
  ]);

  if (!bizWallet || n(bizWallet.reservedFunds) < businessPriceSnapshot) {
    await db
      .prepare(
        `INSERT INTO submissions (id, workerId, campaignId, taskTypeId, status, proofData, workerRewardSnapshot, businessPriceSnapshot, verificationMode, verificationReason, verificationCheckedAt, createdAt)
         VALUES (?, ?, ?, ?, 'needs_review', ?, ?, ?, 'automatic', 'Business reserved funds inconsistent.', ?, ?)
         ON CONFLICT(id) DO NOTHING`
      )
      .bind(submissionId, uid, campaignId, taskTypeId, JSON.stringify(proofData), workerRewardSnapshot, businessPriceSnapshot, now, now)
      .run();
    return json({ success: true, status: "needs_review", reason: "insufficient_reserved_funds" });
  }

  const referrerId = null; // task.js's auto-verify path had no referrer wiring in the original either
  const reserveAmount = Math.floor(businessPriceSnapshot * 0.05);
  const netPlatformRevenue = businessPriceSnapshot - workerRewardSnapshot - reserveAmount;

  const completed = n(workerProfile?.tasksCompleted) + 1;
  const rejected = n(workerProfile?.tasksRejected);
  const level = levelFor(completed);
  const successRatePct = completed + rejected ? Math.round((completed / (completed + rejected)) * 100) : 100;

  const newCompleted = n(campaign.quantityCompleted) + 1;
  const newRemaining = n(campaign.remainingBudget) - businessPriceSnapshot;
  const exhausted = newCompleted + n(campaign.quantityRejected) >= n(campaign.quantityTarget);

  const wAvail = n(workerWallet?.availableBalance);
  const bwAvail = n(bizWallet.availableBalance);
  const verificationMeta = JSON.stringify({ reason: formAuto ? "deterministic_form_validation" : "trusted_automated_adapter" });

  const statements = [
    db
      .prepare(
        `INSERT INTO submissions (id, workerId, campaignId, taskTypeId, status, proofData, verificationResult, verificationMode, verificationMeta, verifiedAt, rewardPaid, workerRewardSnapshot, businessPriceSnapshot, createdAt)
         VALUES (?, ?, ?, ?, 'approved', ?, ?, 'automatic', ?, ?, 1, ?, ?, ?)`
      )
      .bind(
        submissionId,
        uid,
        campaignId,
        taskTypeId,
        JSON.stringify(proofData),
        JSON.stringify(verificationResult),
        verificationMeta,
        now,
        workerRewardSnapshot,
        businessPriceSnapshot,
        now
      ),
    db
      .prepare(
        `INSERT INTO wallets (uid, availableBalance, totalEarned, todayEarnings, breakdownTaskEarnings) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(uid) DO UPDATE SET availableBalance = availableBalance + ?, totalEarned = totalEarned + ?, todayEarnings = todayEarnings + ?, breakdownTaskEarnings = breakdownTaskEarnings + ?`
      )
      .bind(
        uid,
        workerRewardSnapshot,
        workerRewardSnapshot,
        workerRewardSnapshot,
        workerRewardSnapshot,
        workerRewardSnapshot,
        workerRewardSnapshot,
        workerRewardSnapshot,
        workerRewardSnapshot
      ),
    db
      .prepare(
        `INSERT INTO worker_profiles (uid, level, levelProgressPct, tasksCompleted, successRatePct, tasksRejected, accuracyPct, reputationScore, kycStatus)
         VALUES (?, ?, ?, 1, ?, 0, 100, 0, 'none')
         ON CONFLICT(uid) DO UPDATE SET level = ?, levelProgressPct = ?, tasksCompleted = tasksCompleted + 1, successRatePct = ?`
      )
      .bind(uid, level.level, level.progressPct, successRatePct, level.level, level.progressPct, successRatePct),
    db
      .prepare(
        `UPDATE campaigns SET quantityCompleted = quantityCompleted + 1, remainingBudget = remainingBudget - ?, status = ?, completedAt = ? WHERE id = ? AND remainingBudget >= ?`
      )
      .bind(businessPriceSnapshot, exhausted ? "completed" : campaign.status, exhausted ? now : campaign.completedAt, campaignId, businessPriceSnapshot),
    db
      .prepare(
        `UPDATE business_wallets SET reservedFunds = reservedFunds - ?${exhausted && newRemaining > 0 ? ", availableBalance = availableBalance + ?" : ""} WHERE uid = ? AND reservedFunds >= ?`
      )
      .bind(...(exhausted && newRemaining > 0 ? [businessPriceSnapshot, newRemaining, campaign.businessId, businessPriceSnapshot] : [businessPriceSnapshot, campaign.businessId, businessPriceSnapshot])),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, verificationMode, createdAt)
         VALUES (?, ?, 'worker', 'task_reward', ?, ?, ?, 'automatic', ?)`
      )
      .bind(crypto.randomUUID(), uid, workerRewardSnapshot, wAvail + workerRewardSnapshot, submissionId, now),
    db
      .prepare(
        `INSERT INTO platform_revenue (id, type, amount, grossAmount, workerAmount, referralAmount, reserveAmount, netPlatformRevenue, businessId, workerId, campaignId, submissionId, verificationMode, createdAt)
         VALUES (?, 'campaign_service_revenue', ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, 'automatic', ?)`
      )
      .bind(
        crypto.randomUUID(),
        netPlatformRevenue,
        businessPriceSnapshot,
        workerRewardSnapshot,
        reserveAmount,
        netPlatformRevenue,
        campaign.businessId,
        uid,
        campaignId,
        submissionId,
        now
      ),
  ];

  if (reserveAmount > 0) {
    statements.push(
      db
        .prepare(
          `INSERT INTO platform_treasury (id, lockedReserve, updatedAt) VALUES ('main', ?, ?)
           ON CONFLICT(id) DO UPDATE SET lockedReserve = lockedReserve + ?, updatedAt = ?`
        )
        .bind(reserveAmount, now, reserveAmount, now),
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, relatedId, verificationMode, createdAt)
           VALUES (?, 'platformTreasury', 'platform', 'reserve_allocation', ?, ?, 'automatic', ?)`
        )
        .bind(crypto.randomUUID(), reserveAmount, submissionId, now)
    );
  }

  if (exhausted && newRemaining > 0) {
    statements.push(
      db
        .prepare(
          `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, reason, createdAt)
           VALUES (?, ?, 'business', 'refund', ?, ?, ?, 'unused_campaign_budget', ?)`
        )
        .bind(crypto.randomUUID(), campaign.businessId, newRemaining, bwAvail + newRemaining, campaignId, now)
    );
  }

  const results = await db.batch(statements);
  if (results[3].meta.changes === 0) {
    // Campaign budget moved between our check and now — fail safe to
    // needs_review rather than risk a bad payout. (The submission insert
    // above already committed as 'approved' inside the batch, so undo it.)
    await db
      .prepare(
        "UPDATE submissions SET status = 'needs_review', verificationReason = 'Campaign budget changed concurrently.' WHERE id = ?"
      )
      .bind(submissionId)
      .run();
    return json({ success: true, status: "needs_review", reason: "concurrent_budget_change" });
  }

  return json({ success: true, status: "approved", reward: workerRewardSnapshot });
}

  return { createSubmission };
})();


// ============================================================
// FROM: topup.js
// ============================================================

const topup = (function() {
/**
 * Capella — Business Wallet Top-Up (Cloudflare Workers + D1)
 * ---------------------------------------------------------------
 * Ported from functions/topup.js. Same Paystack-verify-then-credit
 * pattern as activation.js, just against business_wallets instead of
 * the user's activation flag.
 *
 * Route (mounted in worker.js):
 *   POST /wallet/topup   { reference }
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
const MIN_TOPUP = 500; // NGN

async function topUpBusinessWallet(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "You must be signed in." }, 401);
  const db = env.DB;

  const { reference } = await request.json();
  if (!reference || typeof reference !== "string") {
    return json({ success: false, message: "Missing payment reference." }, 400);
  }

  const existing = await db.prepare("SELECT id FROM deposits WHERE id = ?").bind(reference).first();
  if (existing) return json({ success: true, alreadyProcessed: true });

  const user = await db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first();
  if (!user) return json({ success: false, message: "User record not found." }, 404);
  if (!user.roleBusiness) {
    return json({ message: "Only accounts with business access set up can top up a campaign wallet." }, 403);
  }
  if (!user.accountActivated) {
    return json({ success: false, message: "Activate your business account before adding funds." });
  }

  const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}` },
  });
  const verifyJson = await verifyRes.json();
  if (!verifyRes.ok || !verifyJson.status) {
    return json({ success: false, message: "Could not reach Paystack to verify payment." }, 502);
  }
  const txn = verifyJson.data;
  if (txn.status !== "success") return json({ success: false, message: `Payment was not successful (status: ${txn.status}).` });
  if (txn.currency !== "NGN") return json({ success: false, message: "Unexpected currency on transaction." });

  const amountNaira = txn.amount / 100;
  if (amountNaira < MIN_TOPUP) return json({ success: false, message: `Minimum top-up is ₦${MIN_TOPUP}.` });
  if (txn.metadata?.userId && txn.metadata.userId !== uid) {
    return json({ message: "This payment reference belongs to a different account." }, 403);
  }

  const wallet = await db.prepare("SELECT * FROM business_wallets WHERE uid = ?").bind(uid).first();
  const currentBalance = wallet?.availableBalance ?? 0;
  const newBalance = currentBalance + amountNaira;
  const now = new Date().toISOString();

  const statements = [
    db
      .prepare(
        `INSERT INTO deposits (id, businessId, amount, provider, providerRef, status, createdAt)
         VALUES (?, ?, ?, 'paystack', ?, 'success', ?)`
      )
      .bind(reference, uid, amountNaira, reference, now),
    db
      .prepare(
        `INSERT INTO business_wallets (uid, availableBalance, reservedFunds, campaignFunds) VALUES (?, ?, 0, 0)
         ON CONFLICT(uid) DO UPDATE SET availableBalance = availableBalance + ?`
      )
      .bind(uid, amountNaira, amountNaira),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
         VALUES (?, ?, 'business', 'deposit', ?, ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), uid, amountNaira, newBalance, reference, now),
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         VALUES (?, ?, 'wallet_topup', 'Wallet funded', ?, ?, 0, ?)`
      )
      .bind(crypto.randomUUID(), uid, `₦${amountNaira.toLocaleString()} was added to your campaign wallet.`, reference, now),
  ];

  await db.batch(statements);
  return json({ success: true, amount: amountNaira });
}

  return { topUpBusinessWallet };
})();


// ============================================================
// FROM: otp.js
// ============================================================

const otp = (function() {
/**
 * Capella — OTP Transfer Finalization (Cloudflare Workers + D1)
 * -----------------------------------------------------------------
 * Ported from functions/otp.js. Admin-only: Paystack sends the OTP to
 * whoever holds the Paystack account, so an admin has to type it in
 * manually to release transfers above your dashboard's OTP threshold.
 *
 * Routes (mounted in worker.js):
 *   GET  /admin/otp-transfers            (listPendingOtpTransfers)
 *   POST /admin/otp-transfers/finalize   { withdrawalId, otp }
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
async function requireAdmin(db, uid) {
  const row = await db.prepare("SELECT uid FROM admin_roles WHERE uid = ?").bind(uid).first();
  return !!row;
}

async function listPendingOtpTransfers(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await requireAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const { results } = await db
    .prepare(
      `SELECT id, amount, accountName, accountNumber, bankName, requestedAt, providerRef
       FROM withdrawals
       WHERE status = 'processing' AND paystackStatus = 'otp'
       ORDER BY requestedAt DESC
       LIMIT 30`
    )
    .all();

  return json({
    withdrawals: results.map((w) => ({
      id: w.id,
      amount: w.amount,
      accountDetails: { accountName: w.accountName, accountNumber: w.accountNumber, bankName: w.bankName },
      requestedAt: w.requestedAt,
      providerRef: w.providerRef,
    })),
  });
}

async function finalizeTransferOtp(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await requireAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const { withdrawalId, otp } = await request.json();
  if (!withdrawalId || !otp) return json({ message: "withdrawalId and otp are required." }, 400);

  const withdrawal = await db.prepare("SELECT * FROM withdrawals WHERE id = ?").bind(withdrawalId).first();
  if (!withdrawal) return json({ message: "Withdrawal not found." }, 404);
  if (withdrawal.paystackStatus !== "otp") {
    return json({ success: false, message: "This withdrawal isn't waiting on OTP." });
  }

  const res = await fetch("https://api.paystack.co/transfer/finalize_transfer", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ transfer_code: withdrawal.providerRef, otp }),
  });
  const resJson = await res.json();
  if (!res.ok || resJson.status === false) {
    return json({ success: false, message: resJson.message || "Paystack rejected the OTP." });
  }

  await db
    .prepare("UPDATE withdrawals SET paystackStatus = ?, otpSubmittedAt = ?, otpSubmittedBy = ? WHERE id = ?")
    .bind(resJson.data.status || "pending", new Date().toISOString(), uid, withdrawalId)
    .run();

  return json({ success: true });
}

  return { listPendingOtpTransfers, finalizeTransferOtp };
})();


// ============================================================
// FROM: music.js
// ============================================================

const music = (function() {
/**
 * Capella — Unreleased Music Marketplace (Cloudflare Workers + D1)
 * ---------------------------------------------------------------------
 * Purchase logic ported from functions/music.js. Listing creation is new
 * — the original had no server-side function for it at all (musicians
 * likely wrote listings straight to Firestore from the client). Since
 * clients can't talk to D1 directly, this fills that gap.
 *
 * Every listing requires a releaseDate. Once that date passes, the
 * hourly cleanup Cron Trigger (see cleanup.js) marks the listing
 * 'expired' and deletes the actual audio bytes from song_files — the
 * idea being that by the official release date, the track is on real
 * streaming platforms and doesn't need to keep taking up storage here.
 * Past purchasers simply lose in-app playback after that point, same
 * as the song leaving the "unreleased" marketplace makes sense to.
 *
 * File upload and serving live in storage.js (D1 BLOBs, since R2 needs
 * a card on file to enable). See storage.js for uploadSongFile /
 * streamSongFile.
 *
 * Routes (mounted in worker.js):
 *   POST /musicians/songs       { title, description?, price, releaseDate }
 *   POST /music/purchase        { reference, songId }
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
const DEFAULT_MUSIC_FEE_PCT = 10;

async function getMusicFeePct(db) {
  const row = await db.prepare("SELECT musicPlatformFeePct FROM platform_settings WHERE id = 'config'").first();
  return typeof row?.musicPlatformFeePct === "number" && row.musicPlatformFeePct >= 0 ? row.musicPlatformFeePct : DEFAULT_MUSIC_FEE_PCT;
}

async function createSongListing(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { title, description, price, releaseDate } = await request.json();
  const cleanTitle = typeof title === "string" ? title.trim() : "";
  const cleanPrice = Math.floor(Number(price));

  if (!cleanTitle) return json({ success: false, message: "Song title is required." }, 400);
  if (!cleanPrice || cleanPrice <= 0) return json({ success: false, message: "Enter a valid price." }, 400);
  if (!releaseDate) return json({ success: false, message: "Select the official release date for this song." }, 400);

  const releaseDateObj = new Date(releaseDate);
  if (isNaN(releaseDateObj.getTime())) return json({ success: false, message: "That release date isn't valid." }, 400);
  if (releaseDateObj.getTime() <= Date.now()) {
    return json({ success: false, message: "Release date must be in the future — this marketplace is for unreleased tracks only." }, 400);
  }

  const songId = crypto.randomUUID();
  const now = new Date().toISOString();

  // Musicians don't need a separate signup step — the first listing they
  // create establishes their musicians profile row.
  await db
    .prepare(`INSERT INTO musicians (uid, name, bio, createdAt) VALUES (?, NULL, NULL, ?) ON CONFLICT(uid) DO NOTHING`)
    .bind(uid, now)
    .run();

  await db
    .prepare(
      `INSERT INTO unreleased_songs (id, musicianId, title, description, price, previewUrl, status, totalSales, totalRevenue, createdAt, releaseDate)
       VALUES (?, ?, ?, ?, ?, NULL, 'active', 0, 0, ?, ?)`
    )
    .bind(songId, uid, cleanTitle, description ? String(description).trim() : null, cleanPrice, now, releaseDateObj.toISOString())
    .run();

  // Client should follow up with POST /musicians/songs/{songId}/file to
  // actually upload the audio bytes (see storage.js).
  return json({ success: true, songId });
}

async function purchaseSong(request, env) {
  const fanId = await auth.requireAuth(request, env);
  if (!fanId) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const { reference, songId } = await request.json();
  if (!reference || !songId) return json({ message: "reference and songId are required." }, 400);

  const existing = await db.prepare("SELECT id FROM song_purchases WHERE id = ?").bind(reference).first();
  if (existing) return json({ success: true, alreadyProcessed: true });

  const song = await db.prepare("SELECT * FROM unreleased_songs WHERE id = ?").bind(songId).first();
  if (!song) return json({ message: "Song not found." }, 404);
  if (song.status !== "active") return json({ success: false, message: "This song isn't available for purchase right now — it may already be officially released." });
  if (song.musicianId === fanId) return json({ success: false, message: "You can't buy your own song — you already have access." });

  const expectedAmountKobo = Math.round(song.price * 100);

  const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}` },
  });
  const verifyJson = await verifyRes.json();
  if (!verifyRes.ok || !verifyJson.status) return json({ message: "Could not reach Paystack to verify payment." }, 502);

  const txn = verifyJson.data;
  if (txn.status !== "success") return json({ success: false, message: `Payment was not successful (status: ${txn.status}).` });
  if (txn.currency !== "NGN") return json({ success: false, message: "Unexpected currency on transaction." });
  if (txn.amount !== expectedAmountKobo) {
    return json({
      success: false,
      message: `Amount mismatch: expected ₦${song.price}, Paystack shows ₦${txn.amount / 100}. The song's price may have changed after checkout opened.`,
    });
  }
  if (txn.metadata?.fanId && txn.metadata.fanId !== fanId) {
    return json({ message: "This payment reference belongs to a different account." }, 403);
  }

  const feePct = await getMusicFeePct(db);
  const platformFee = Math.round(song.price * (feePct / 100));
  const musicianPayout = song.price - platformFee;

  const wallet = await db.prepare("SELECT * FROM wallets WHERE uid = ?").bind(song.musicianId).first();
  const currentBalance = wallet?.availableBalance ?? 0;
  const newBalance = currentBalance + musicianPayout;
  const now = new Date().toISOString();

  const statements = [
    db
      .prepare(
        `INSERT INTO song_purchases (id, songId, musicianId, fanId, amount, platformFeePct, platformFee, musicianPayout, provider, providerRef, status, createdAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'paystack', ?, 'success', ?)`
      )
      .bind(reference, songId, song.musicianId, fanId, song.price, feePct, platformFee, musicianPayout, reference, now),
    db.prepare("UPDATE unreleased_songs SET totalSales = totalSales + 1, totalRevenue = totalRevenue + ? WHERE id = ?").bind(song.price, songId),
    db
      .prepare(
        `INSERT INTO wallets (uid, availableBalance, pendingBalance, totalEarned, todayEarnings, breakdownMusicSales)
         VALUES (?, ?, 0, ?, ?, ?)
         ON CONFLICT(uid) DO UPDATE SET availableBalance = availableBalance + ?, totalEarned = totalEarned + ?, todayEarnings = todayEarnings + ?, breakdownMusicSales = breakdownMusicSales + ?`
      )
      .bind(
        song.musicianId,
        musicianPayout,
        musicianPayout,
        musicianPayout,
        musicianPayout,
        musicianPayout,
        musicianPayout,
        musicianPayout,
        musicianPayout
      ),
    db
      .prepare(
        `INSERT INTO ledger_transactions (id, walletId, walletType, type, amount, balanceAfter, relatedId, createdAt)
         VALUES (?, ?, 'worker', 'music_sale', ?, ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), song.musicianId, musicianPayout, newBalance, reference, now),
    db
      .prepare(
        `INSERT INTO platform_revenue (id, type, amount, userId, relatedId, createdAt)
         VALUES (?, 'music_platform_fee', ?, ?, ?, ?)`
      )
      .bind(crypto.randomUUID(), platformFee, song.musicianId, reference, now),
    db
      .prepare(
        `INSERT INTO notifications (id, userId, type, title, message, relatedId, read, createdAt)
         VALUES (?, ?, 'song_sale', 'Someone unlocked your song', ?, ?, 0, ?)`
      )
      .bind(
        crypto.randomUUID(),
        song.musicianId,
        `"${song.title}" sold for ₦${song.price.toLocaleString()} — ₦${musicianPayout.toLocaleString()} was added to your wallet.`,
        songId,
        now
      ),
  ];

  await db.batch(statements);
  return json({ success: true, musicianPayout, platformFee });
}

  return { createSongListing, purchaseSong };
})();


// ============================================================
// FROM: storage.js
// ============================================================

const storage = (function() {
/**
 * Capella — File Storage (D1 BLOBs, no R2)
 * --------------------------------------------
 * R2 needs a card on file to even enable (Cloudflare's dashboard blocks
 * API access to it otherwise), so files live directly in D1 as BLOB
 * columns instead. Two very different retention needs, two tables:
 *
 *   task_proof_files — screenshots proving a worker did a task. These
 *   are meant to be short-lived: cleanup.js deletes any row older than
 *   24 hours, every hour, via a Cron Trigger. Ties to submissions via
 *   proofData.proofFileId (see task.js).
 *
 *   song_files — a musician's actual audio file for sale. These must
 *   persist forever (it's the product being sold), so nothing ever
 *   auto-deletes them. Because D1's free tier is 5GB total, keep an
 *   eye on this table specifically as more songs get uploaded — this
 *   is the one place worth moving to R2 first, once a card is available.
 *
 * Upload size caps below are deliberately conservative given the
 * shared 5GB ceiling — raise them once you have real usage data.
 *
 * Routes (mounted in worker.js):
 *   POST /task-proofs                      (raw binary body, header: x-mime-type)
 *   POST /musicians/songs/:songId/file      (raw binary body, header: x-mime-type)
 *   GET  /music/file/:songId                (streams the audio bytes back)
 */


const MAX_PROOF_BYTES = 5 * 1024 * 1024; // 5MB per screenshot
const MAX_SONG_BYTES = 15 * 1024 * 1024; // 15MB per song file

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}

async function uploadTaskProof(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const mimeType = request.headers.get("x-mime-type") || "application/octet-stream";
  const bytes = await request.arrayBuffer();
  if (!bytes.byteLength) return json({ success: false, message: "Empty upload." }, 400);
  if (bytes.byteLength > MAX_PROOF_BYTES) {
    return json({ success: false, message: `Screenshot too large — max ${MAX_PROOF_BYTES / 1024 / 1024}MB.` }, 413);
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await env.DB.prepare(
    "INSERT INTO task_proof_files (id, submissionId, workerId, mimeType, sizeBytes, data, createdAt) VALUES (?, NULL, ?, ?, ?, ?, ?)"
  )
    .bind(id, uid, mimeType, bytes.byteLength, bytes, now)
    .run();

  // Client attaches this id as proofData.proofFileId when it calls POST /submissions.
  return json({ success: true, proofFileId: id });
}

async function uploadSongFile(request, env, songId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const song = await db.prepare("SELECT musicianId FROM unreleased_songs WHERE id = ?").bind(songId).first();
  if (!song) return json({ message: "Song not found." }, 404);
  if (song.musicianId !== uid) return json({ message: "Only the musician who owns this song can upload its file." }, 403);

  const mimeType = request.headers.get("x-mime-type") || "audio/mpeg";
  const bytes = await request.arrayBuffer();
  if (!bytes.byteLength) return json({ success: false, message: "Empty upload." }, 400);
  if (bytes.byteLength > MAX_SONG_BYTES) {
    return json({ success: false, message: `File too large — max ${MAX_SONG_BYTES / 1024 / 1024}MB.` }, 413);
  }

  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO song_files (songId, mimeType, sizeBytes, data) VALUES (?, ?, ?, ?)
       ON CONFLICT(songId) DO UPDATE SET mimeType = ?, sizeBytes = ?, data = ?`
    )
    .bind(songId, mimeType, bytes.byteLength, bytes, mimeType, bytes.byteLength, bytes)
    .run();

  return json({ success: true });
}

async function streamSongFile(request, env, songId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const song = await db.prepare("SELECT musicianId FROM unreleased_songs WHERE id = ?").bind(songId).first();
  if (!song) return json({ message: "Song not found." }, 404);

  let authorized = song.musicianId === uid;
  if (!authorized) {
    const purchase = await db
      .prepare("SELECT id FROM song_purchases WHERE songId = ? AND fanId = ? AND status = 'success' LIMIT 1")
      .bind(songId, uid)
      .first();
    authorized = !!purchase;
  }
  if (!authorized) return json({ message: "You haven't unlocked this song yet." }, 403);

  const file = await db.prepare("SELECT data, mimeType, sizeBytes FROM song_files WHERE songId = ?").bind(songId).first();
  if (!file || !file.data) return json({ message: "This song's file hasn't been uploaded yet." }, 404);

  return new Response(file.data, {
    status: 200,
    headers: {
      "Content-Type": file.mimeType || "audio/mpeg",
      "Content-Length": String(file.sizeBytes || file.data.byteLength),
      "Cache-Control": "private, max-age=0, no-store",
    },
  });
}

  return { uploadTaskProof, uploadSongFile, streamSongFile, MAX_PROOF_BYTES, MAX_SONG_BYTES };
})();


// ============================================================
// FROM: cleanup.js
// ============================================================

const cleanup = (function() {
/**
 * Capella — Retention Cleanup (Cloudflare Workers Cron Trigger)
 * -----------------------------------------------------------------
 * Runs hourly via a Cron Trigger, configured in wrangler.toml:
 *
 *   [triggers]
 *   crons = ["0 * * * *"]
 *
 * and wired up via the `scheduled` handler exported from worker.js.
 *
 * Two independent cleanup jobs live here:
 *
 *   1. Task-proof screenshots (ported from functions/cleanup.js).
 *      Screenshots live as BLOBs in D1 (see storage.js) rather than R2
 *      — R2 needs a card on file to enable at all — so this deletes
 *      expired rows from task_proof_files directly. Submission rows
 *      themselves are NOT touched: only the image bytes are deleted,
 *      the row (and the fact that a proof once existed) stays for audit.
 *
 *   2. Unreleased-song expiry (new). Once a song's releaseDate has
 *      passed, it's presumably out on real streaming platforms now, so
 *      there's no reason to keep hosting the audio file here. This
 *      marks the listing 'expired' (removing it from the marketplace)
 *      and deletes the actual audio bytes from song_files to reclaim
 *      storage. The unreleased_songs row itself stays, same spirit as
 *      the screenshot cleanup — sales history and totals are kept.
 */

const RETENTION_MS = 24 * 60 * 60 * 1000; // 24 hours

async function deleteExpiredTaskProofs(env) {
  const cutoff = new Date(Date.now() - RETENTION_MS).toISOString();
  const result = await env.DB.prepare("DELETE FROM task_proof_files WHERE createdAt < ?").bind(cutoff).run();
  console.log(`Capella proof cleanup: deleted ${result.meta.changes} expired screenshot row(s).`);
}

async function expireReleasedSongs(env) {
  const now = new Date().toISOString();
  const db = env.DB;

  const expired = await db
    .prepare("UPDATE unreleased_songs SET status = 'expired' WHERE status = 'active' AND releaseDate <= ? RETURNING id")
    .bind(now)
    .all();

  const ids = (expired.results || []).map((r) => r.id);
  if (ids.length === 0) {
    console.log("Capella song expiry: no songs past their release date.");
    return;
  }

  const placeholders = ids.map(() => "?").join(",");
  const fileResult = await db.prepare(`DELETE FROM song_files WHERE songId IN (${placeholders})`).bind(...ids).run();
  console.log(`Capella song expiry: expired ${ids.length} listing(s), cleared ${fileResult.meta.changes} audio file row(s).`);
}

  return { deleteExpiredTaskProofs, expireReleasedSongs };
})();


// ============================================================
// FROM: affiliate.js
// ============================================================

const affiliate = (function() {
/**
 * Capella — Affiliate Marketplace (Cloudflare Workers + D1)
 * -----------------------------------------------------------------
 * New functionality — the original Firebase codebase never implemented
 * this. Built from scratch, direct-to-bank model (no in-app wallet
 * holding, no pre-funding):
 *
 *   1. A business creates a listing: product amount + their OWN bank
 *      account details (required upfront — no listing without a
 *      payout destination). The listing stays live until the business
 *      deletes it — no budget, nothing to run out.
 *   2. A worker picks a listing and creates a link: their OWN bank
 *      details for THIS specific link, plus whatever commission amount
 *      they want to add on top of the product price. Different links
 *      (even for the same listing) can have different banks/commissions
 *      — a worker might run several campaigns differently.
 *   3. A customer only ever sees ONE price — productAmount +
 *      workerCommission, added together server-side before checkout.
 *      They never see the breakdown; only the worker (and, for their
 *      own side, the business) knows how it's composed.
 *   4. The customer pays that single combined price through Paystack.
 *      The instant that payment is verified (same server-side
 *      verify-with-Paystack pattern used everywhere else in Capella —
 *      never trust the client's word for a payment), Capella:
 *        - keeps its cut, a % of productAmount only (never touches the
 *          worker's commission) — platform_settings.affiliatePlatformFeePct,
 *          default 5%, editable via /admin/settings
 *        - transfers (productAmount - platformFee) straight to the
 *          business's bank
 *        - transfers the full workerCommission straight to the
 *          worker's bank
 *      Both transfers reuse the exact recipient+transfer code already
 *      built and proven for withdrawal.js — no new Paystack primitive
 *      introduced (deliberately not using Paystack's native "Split
 *      Payment" feature here: for a 3-way split with amounts that
 *      differ on every single sale, Paystack requires creating a new
 *      split configuration object per transaction, which is real added
 *      complexity for no benefit over just sending two transfers
 *      ourselves — see PAYSTACK_SPLIT_DECISION note below.).
 *   5. Everything is logged in affiliate_sales regardless of payout
 *      outcome, so businesses and workers can always see their sales
 *      history in-app even though funds never sit in an internal wallet.
 *      If one of the two transfers fails while the other succeeds
 *      (Paystack transfers can fail independently), that sale is
 *      marked 'needs_attention' rather than silently lost — nobody has
 *      built a retry UI for this yet, so for now it just needs a human
 *      to notice and act via the transfer webhook/logs.
 *
 * PAYSTACK_SPLIT_DECISION: Paystack's Transaction Split API is built
 * for exactly this kind of multi-party payout, but it's optimized for
 * splits that stay the same across many transactions (dashboard-
 * configured percentage/flat splits) or accept the overhead of creating
 * a fresh split object per charge for dynamic amounts. Since every
 * single sale here has a different worker commission, we'd be creating
 * a new split object on every sale anyway — no simpler than just
 * calling the transfer API twice, which we already have working code
 * for. Revisit this if transfer volume gets high enough that Paystack's
 * settlement-time batching becomes worth the added complexity.
 *
 * Routes (mounted in worker.js):
 *   POST /affiliate/listings                    (business creates a listing)
 *   DELETE /affiliate/listings/:id               (business deletes — soft delete)
 *   GET  /affiliate/listings                     (browse active listings — no bank details exposed)
 *   GET  /affiliate/listings/mine/sales          (business's own sales history)
 *   POST /affiliate/links                        (worker creates a link — sets bank + commission)
 *   GET  /affiliate/links/mine                   (worker's own links)
 *   GET  /affiliate/links/mine/sales             (worker's own sales history)
 *   GET  /affiliate/checkout/:code               (customer preview — single combined price only)
 *   POST /affiliate/purchase                     { reference, code } — verifies payment, pays out both sides
 */


function n(v) {
  const x = Number(v);
  return Number.isFinite(x) ? x : 0;
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
async function getAffiliateFeePct(db) {
  const row = await db.prepare("SELECT affiliatePlatformFeePct FROM platform_settings WHERE id = 'config'").first();
  return typeof row?.affiliatePlatformFeePct === "number" && row.affiliatePlatformFeePct >= 0 ? row.affiliatePlatformFeePct : 5;
}
function randomCode() {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 10).toUpperCase();
}
async function paystackFetch(path, secret, options = {}) {
  const res = await fetch(`https://api.paystack.co${path}`, {
    ...options,
    headers: { Authorization: `Bearer ${secret}`, "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const j = await res.json();
  if (!res.ok || j.status === false) throw new Error(j.message || "Paystack request failed");
  return j;
}
async function sendTransfer(secret, { amount, accountNumber, bankCode, accountName, reason, reference }) {
  const recipientRes = await paystackFetch("/transferrecipient", secret, {
    method: "POST",
    body: JSON.stringify({ type: "nuban", name: accountName, account_number: accountNumber, bank_code: bankCode, currency: "NGN" }),
  });
  const transferRes = await paystackFetch("/transfer", secret, {
    method: "POST",
    body: JSON.stringify({ source: "balance", amount: amount * 100, recipient: recipientRes.data.recipient_code, reason, reference }),
  });
  return { transferCode: transferRes.data.transfer_code, status: transferRes.data.status };
}

// ---------------------------------------------------------------------
// createListing — business lists a product. Bank details are required
// up front: "no listing without a payout destination" is the whole
// point of setting this up before anything can be sold.
// ---------------------------------------------------------------------
async function createListing(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const d = await request.json();
  const title = typeof d.title === "string" ? d.title.trim() : "";
  const description = typeof d.description === "string" ? d.description.trim() : null;
  const productAmount = Math.floor(n(d.productAmount));
  const { bankCode, bankName, accountNumber, accountName } = d;

  if (!title) return json({ success: false, message: "Title is required." }, 400);
  if (!productAmount || productAmount <= 0) return json({ success: false, message: "Enter a valid product amount." }, 400);
  if (!bankCode || !accountNumber || !accountName) {
    return json({ success: false, message: "Bank account details are required before you can list a product — this is where your share of every sale gets paid." }, 400);
  }

  const user = await db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first();
  if (!user || !user.accountActivated || !user.roleBusiness) {
    return json({ success: false, message: "Business access is not activated." });
  }

  const feePct = await getAffiliateFeePct(db);
  const platformFee = Math.floor(productAmount * (feePct / 100));
  const businessReceives = productAmount - platformFee;

  const listingId = crypto.randomUUID();
  const now = new Date().toISOString();

  await db
    .prepare(
      `INSERT INTO affiliate_listings (id, businessId, title, description, productAmount, bankCode, bankName, accountNumber, accountName, status, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`
    )
    .bind(listingId, uid, title, description, productAmount, bankCode, bankName || null, accountNumber, accountName, now)
    .run();

  // Tell the business up front exactly what they'll net per sale —
  // "any percentage set by admin should automatically get explained."
  return json({
    success: true,
    listingId,
    productAmount,
    platformFeePct: feePct,
    platformFeeAmount: platformFee,
    youWillReceivePerSale: businessReceives,
  });
}

// ---------------------------------------------------------------------
// deleteListing — soft delete, business only. Existing links to it
// simply stop being purchasable (checked at purchase time).
// ---------------------------------------------------------------------
async function deleteListing(request, env, listingId) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!listingId) return json({ success: false, message: "listingId is required." });

  const listing = await db.prepare("SELECT * FROM affiliate_listings WHERE id = ?").bind(listingId).first();
  if (!listing) return json({ success: false, message: "Listing not found." });
  if (listing.businessId !== uid) return json({ success: false, message: "Not your listing." });
  if (listing.status !== "active") return json({ success: false, message: "This listing is already deleted." });

  const now = new Date().toISOString();
  await db.prepare("UPDATE affiliate_listings SET status = 'deleted', deletedAt = ? WHERE id = ? AND status = 'active'").bind(now, listingId).run();
  return json({ success: true });
}

// ---------------------------------------------------------------------
// listActiveListings — browse (workers looking for products to promote).
// Bank details never go in this response — those are private.
// ---------------------------------------------------------------------
async function listActiveListings(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare(
      `SELECT id, title, description, productAmount, createdAt
       FROM affiliate_listings WHERE status = 'active' ORDER BY createdAt DESC LIMIT 50`
    )
    .all();

  return json({ listings: results });
}

// ---------------------------------------------------------------------
// business's own sales history
// ---------------------------------------------------------------------
async function myListingSales(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare(
      `SELECT s.id, s.listingId, al.title, s.totalAmount, s.businessPayout, s.businessTransferStatus, s.status, s.createdAt
       FROM affiliate_sales s JOIN affiliate_listings al ON al.id = s.listingId
       WHERE s.businessId = ? ORDER BY s.createdAt DESC LIMIT 100`
    )
    .bind(uid)
    .all();

  return json({ sales: results });
}

// ---------------------------------------------------------------------
// createLink — worker sets up their own bank + commission for a listing
// ---------------------------------------------------------------------
async function createLink(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;

  const d = await request.json();
  const { listingId, bankCode, bankName, accountNumber, accountName } = d;
  const commission = Math.floor(n(d.commission));

  if (!listingId) return json({ success: false, message: "listingId is required." }, 400);
  if (!commission || commission <= 0) return json({ success: false, message: "Enter the commission you want to add." }, 400);
  if (!bankCode || !accountNumber || !accountName) {
    return json({ success: false, message: "Bank account details are required before you can share this link — this is where your commission gets paid." }, 400);
  }

  const user = await db.prepare("SELECT * FROM users WHERE uid = ?").bind(uid).first();
  if (!user || !user.accountActivated || !user.roleWorker) {
    return json({ success: false, message: "Worker access is not activated." });
  }

  const listing = await db.prepare("SELECT * FROM affiliate_listings WHERE id = ?").bind(listingId).first();
  if (!listing || listing.status !== "active") return json({ success: false, message: "This listing isn't available." });

  const linkId = crypto.randomUUID();
  const code = randomCode();
  const now = new Date().toISOString();

  await db
    .prepare(
      `INSERT INTO affiliate_links (id, workerId, listingId, code, commission, bankCode, bankName, accountNumber, accountName, status, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`
    )
    .bind(linkId, uid, listingId, code, commission, bankCode, bankName || null, accountNumber, accountName, now)
    .run();

  return json({ success: true, linkId, code, totalCustomerPrice: n(listing.productAmount) + commission });
}

// ---------------------------------------------------------------------
// worker's own links + sales history
// ---------------------------------------------------------------------
async function myLinks(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare(
      `SELECT l.id as linkId, l.code, l.listingId, l.commission, l.status, l.createdAt, al.title, al.productAmount,
              (al.productAmount + l.commission) as totalCustomerPrice
       FROM affiliate_links l JOIN affiliate_listings al ON al.id = l.listingId
       WHERE l.workerId = ? ORDER BY l.createdAt DESC`
    )
    .bind(uid)
    .all();

  return json({ links: results });
}

async function myLinkSales(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);

  const { results } = await env.DB
    .prepare(
      `SELECT s.id, s.listingId, al.title, s.totalAmount, s.workerCommission, s.workerTransferStatus, s.status, s.createdAt
       FROM affiliate_sales s JOIN affiliate_listings al ON al.id = s.listingId
       WHERE s.workerId = ? ORDER BY s.createdAt DESC LIMIT 100`
    )
    .bind(uid)
    .all();

  return json({ sales: results });
}

// ---------------------------------------------------------------------
// checkoutPreview — what a customer sees before paying: ONE price,
// never the breakdown. This is the only endpoint here that doesn't
// require a Capella account, since the customer clicking a shared link
// may not be a Capella user at all.
// ---------------------------------------------------------------------
async function checkoutPreview(request, env, code) {
  if (!code) return json({ message: "code is required." }, 400);
  const db = env.DB;

  const link = await db.prepare("SELECT * FROM affiliate_links WHERE code = ?").bind(String(code).trim().toUpperCase()).first();
  if (!link || link.status !== "active") return json({ message: "This link is no longer valid." }, 404);

  const listing = await db.prepare("SELECT * FROM affiliate_listings WHERE id = ?").bind(link.listingId).first();
  if (!listing || listing.status !== "active") return json({ message: "This product is no longer available." }, 404);

  // Single combined price only — no productAmount/commission breakdown here.
  return json({
    title: listing.title,
    description: listing.description,
    price: n(listing.productAmount) + n(link.commission),
  });
}

// ---------------------------------------------------------------------
// purchase — the customer pays, we verify with Paystack, then pay both
// the business and the worker directly. No wallet crediting at all.
// ---------------------------------------------------------------------
async function purchase(request, env) {
  const db = env.DB;
  const { reference, code } = await request.json();
  if (!reference || !code) return json({ success: false, message: "reference and code are required." }, 400);

  const existing = await db.prepare("SELECT id FROM affiliate_sales WHERE paymentRef = ?").bind(reference).first();
  if (existing) return json({ success: true, alreadyProcessed: true });

  const link = await db.prepare("SELECT * FROM affiliate_links WHERE code = ?").bind(String(code).trim().toUpperCase()).first();
  if (!link || link.status !== "active") return json({ success: false, message: "This link is no longer valid." }, 404);

  const listing = await db.prepare("SELECT * FROM affiliate_listings WHERE id = ?").bind(link.listingId).first();
  if (!listing || listing.status !== "active") return json({ success: false, message: "This product is no longer available." }, 404);

  const productAmount = n(listing.productAmount);
  const workerCommission = n(link.commission);
  const totalAmount = productAmount + workerCommission;
  const expectedAmountKobo = totalAmount * 100;

  // ---- Verify the payment directly with Paystack — never trust the client ----
  const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}` },
  });
  const verifyJson = await verifyRes.json();
  if (!verifyRes.ok || !verifyJson.status) return json({ success: false, message: "Could not reach Paystack to verify payment." }, 502);

  const txn = verifyJson.data;
  if (txn.status !== "success") return json({ success: false, message: `Payment was not successful (status: ${txn.status}).` });
  if (txn.currency !== "NGN") return json({ success: false, message: "Unexpected currency on transaction." });
  if (txn.amount !== expectedAmountKobo) {
    return json({ success: false, message: `Amount mismatch: expected ₦${totalAmount}, Paystack shows ₦${txn.amount / 100}.` });
  }

  const feePct = await getAffiliateFeePct(db);
  const platformFee = Math.floor(productAmount * (feePct / 100));
  const businessPayout = productAmount - platformFee;

  const saleId = crypto.randomUUID();
  const now = new Date().toISOString();

  // Log the sale as 'processing' BEFORE attempting transfers, so a sale
  // is never lost even if something goes wrong sending the money out.
  await db
    .prepare(
      `INSERT INTO affiliate_sales (id, linkId, listingId, workerId, businessId, totalAmount, productAmount, workerCommission, platformFeePct, platformFee, businessPayout, provider, paymentRef, status, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'paystack', ?, 'processing', ?)`
    )
    .bind(saleId, link.id, listing.id, link.workerId, listing.businessId, totalAmount, productAmount, workerCommission, feePct, platformFee, businessPayout, reference, now)
    .run();

  await db
    .prepare(
      `INSERT INTO platform_revenue (id, type, amount, businessId, workerId, relatedId, createdAt)
       VALUES (?, 'affiliate_platform_fee', ?, ?, ?, ?, ?)`
    )
    .bind(crypto.randomUUID(), platformFee, listing.businessId, link.workerId, saleId, now)
    .run();

  // ---- Two independent transfers. Each can fail on its own. ----
  let businessTransfer = null;
  let businessError = null;
  try {
    businessTransfer = await sendTransfer(env.PAYSTACK_SECRET_KEY, {
      amount: businessPayout,
      accountNumber: listing.accountNumber,
      bankCode: listing.bankCode,
      accountName: listing.accountName,
      reason: `Capella affiliate sale — ${listing.title}`,
      reference: `${saleId}-biz`,
    });
  } catch (err) {
    businessError = err.message;
  }

  let workerTransfer = null;
  let workerError = null;
  try {
    workerTransfer = await sendTransfer(env.PAYSTACK_SECRET_KEY, {
      amount: workerCommission,
      accountNumber: link.accountNumber,
      bankCode: link.bankCode,
      accountName: link.accountName,
      reason: `Capella affiliate commission — ${listing.title}`,
      reference: `${saleId}-worker`,
    });
  } catch (err) {
    workerError = err.message;
  }

  const bothOk = businessTransfer && workerTransfer;
  const finalStatus = bothOk ? "completed" : "needs_attention";

  await db
    .prepare(
      `UPDATE affiliate_sales SET
         businessTransferRef = ?, businessTransferStatus = ?,
         workerTransferRef = ?, workerTransferStatus = ?,
         status = ?, completedAt = ?
       WHERE id = ?`
    )
    .bind(
      businessTransfer?.transferCode || null,
      businessTransfer?.status || `failed: ${businessError}`,
      workerTransfer?.transferCode || null,
      workerTransfer?.status || `failed: ${workerError}`,
      finalStatus,
      new Date().toISOString(),
      saleId
    )
    .run();

  return json({
    success: true,
    saleId,
    status: finalStatus,
    businessTransfer: businessTransfer ? businessTransfer.status : `failed: ${businessError}`,
    workerTransfer: workerTransfer ? workerTransfer.status : `failed: ${workerError}`,
  });
}

  return {
  createListing,
  deleteListing,
  listActiveListings,
  myListingSales,
  createLink,
  myLinks,
  myLinkSales,
  checkoutPreview,
  purchase,
};
})();


// ============================================================
// FROM: admin.js
// ============================================================

const admin = (function() {
/**
 * Capella — Admin Settings (Cloudflare Workers + D1)
 * -----------------------------------------------------------
 * Every platform-wide number (registration fee, fee percentages,
 * minimum withdrawal) lives in the single-row platform_settings table.
 * Until now nothing ever wrote to it after the initial seed — this
 * gives admins an actual way to change those values without touching
 * the database directly.
 *
 * Routes (mounted in worker.js):
 *   GET  /admin/settings   — view current values
 *   POST /admin/settings   — update one or more values
 *   GET  /admin/wallet     — Capella's total earnings, for the admin panel
 */


function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}

async function isAdmin(db, uid) {
  const row = await db.prepare("SELECT uid FROM admin_roles WHERE uid = ?").bind(uid).first();
  return !!row;
}

// Every editable field, with the bounds worth enforcing. Money fields
// (registrationFee, minWithdrawal) just need to be non-negative
// integers; percentage fields need to stay within 0-100.
const EDITABLE_FIELDS = {
  registrationFee: { type: "int", min: 0 },
  referralPlatformSharePct: { type: "pct" },
  reservePctOfPlatformRevenue: { type: "pct" },
  minWithdrawal: { type: "int", min: 0 },
  musicPlatformFeePct: { type: "pct" },
  affiliatePlatformFeePct: { type: "pct" },
};

async function getSettings(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const row = await db.prepare("SELECT * FROM platform_settings WHERE id = 'config'").first();
  if (!row) return json({ message: "Settings row not found." }, 500);
  return json({ settings: row });
}

async function updateSettings(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const body = await request.json();
  const setClauses = [];
  const values = [];
  const errors = [];

  for (const [field, rule] of Object.entries(EDITABLE_FIELDS)) {
    if (!(field in body)) continue;
    const raw = body[field];
    const num = Number(raw);
    if (!Number.isFinite(num)) {
      errors.push(`${field} must be a number.`);
      continue;
    }
    if (rule.type === "pct" && (num < 0 || num > 100)) {
      errors.push(`${field} must be between 0 and 100.`);
      continue;
    }
    if (rule.type === "int" && num < (rule.min ?? -Infinity)) {
      errors.push(`${field} must be at least ${rule.min}.`);
      continue;
    }
    setClauses.push(`${field} = ?`);
    values.push(Math.floor(num));
  }

  if (errors.length) return json({ success: false, message: errors.join(" ") }, 400);
  if (setClauses.length === 0) return json({ success: false, message: "No recognized settings fields were provided." }, 400);

  values.push("config");
  await db.prepare(`UPDATE platform_settings SET ${setClauses.join(", ")} WHERE id = ?`).bind(...values).run();

  const updated = await db.prepare("SELECT * FROM platform_settings WHERE id = 'config'").first();
  return json({ success: true, settings: updated });
}

// ---------------------------------------------------------------------
// getWallet — Capella's total earnings across every revenue source.
// This is a read-only dashboard number: the money itself already sits
// in Capella's own Paystack balance automatically (every payout flow
// only ever transfers OUT the other parties' shares, never Capella's
// own cut), so this doesn't move any money — it just adds up the
// platform_revenue ledger so there's something to look at in-app
// instead of only checking the Paystack dashboard directly.
// ---------------------------------------------------------------------
async function getWallet(request, env) {
  const uid = await auth.requireAuth(request, env);
  if (!uid) return json({ message: "Sign in required." }, 401);
  const db = env.DB;
  if (!(await isAdmin(db, uid))) return json({ message: "Admin access required." }, 403);

  const totalRow = await db.prepare("SELECT COALESCE(SUM(amount), 0) as total FROM platform_revenue").first();

  const { results: byType } = await db
    .prepare(
      `SELECT type, COUNT(*) as count, COALESCE(SUM(amount), 0) as total
       FROM platform_revenue GROUP BY type ORDER BY total DESC`
    )
    .all();

  const { results: recent } = await db
    .prepare("SELECT id, type, amount, createdAt FROM platform_revenue ORDER BY createdAt DESC LIMIT 20")
    .all();

  // Kept as a separate figure from totalRevenue on purpose: the reserve
  // is money set aside from task payouts (see finance.js / task.js),
  // not freely-earned revenue — merging the two would make it look like
  // more money is available to spend than actually is. Pull it out via
  // POST /admin/reserve-withdrawals (withdrawal.js), same as always.
  const treasuryRow = await db.prepare("SELECT lockedReserve, updatedAt FROM platform_treasury WHERE id = 'main'").first();

  return json({
    totalRevenue: totalRow?.total ?? 0,
    breakdown: byType,
    recent,
    lockedReserve: treasuryRow?.lockedReserve ?? 0,
    lockedReserveUpdatedAt: treasuryRow?.updatedAt ?? null,
  });
}

  return { getSettings, updateSettings, getWallet };
})();


// ============================================================
// FROM: worker.js (entry point)
// ============================================================

/**
 * Capella — Cloudflare Worker entry point
 * -----------------------------------------
 * Binds: DB (D1 database "capella-db")
 * Secrets: PAYSTACK_SECRET_KEY, AUTH_SECRET (wrangler secret put ...)
 *
 * This file is just a router. Each feature area lives in its own module
 * under src/ (withdrawal.js, finance.js, activation.js, task.js,
 * topup.js, otp.js, music.js, storage.js, cleanup.js, auth.js).
 */


function withCORS(response, renewedToken) {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", "*"); // tighten to your real domain before launch
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-mime-type");
  headers.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  // Silent session renewal (see auth.js maybeRenewToken) — present on
  // almost every response once a token is within 7 days of expiring.
  // Client should overwrite its stored token with this value if present.
  if (renewedToken) headers.set("X-Renewed-Token", renewedToken);
  return new Response(response.body, { status: response.status, headers });
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return withCORS(new Response(null, { status: 204 }));
    }

    const url = new URL(request.url);
    const { pathname } = url;
    // Computed once per request so every route below can attach it to
    // its response without each individual handler needing to know
    // about renewal at all.
    const renewedToken = await auth.maybeRenewToken(request, env);

    try {
      // ---- auth ----
      if (pathname === "/auth/register" && request.method === "POST") {
        return withCORS(await auth.register(request, env), renewedToken);
      }
      if (pathname === "/auth/login" && request.method === "POST") {
        return withCORS(await auth.login(request, env), renewedToken);
      }

      // ---- withdrawals ----
      if (pathname === "/banks" && request.method === "GET") {
        return withCORS(await withdrawal.listBanks(request, env), renewedToken);
      }
      if (pathname === "/banks/resolve" && request.method === "POST") {
        return withCORS(await withdrawal.resolveBankAccount(request, env), renewedToken);
      }
      if (pathname === "/withdrawals" && request.method === "POST") {
        return withCORS(await withdrawal.requestWithdrawal(request, env), renewedToken);
      }
      if (pathname === "/admin/reserve-withdrawals" && request.method === "POST") {
        return withCORS(await withdrawal.requestReserveWithdrawal(request, env), renewedToken);
      }
      if (pathname === "/webhooks/paystack-transfer" && request.method === "POST") {
        // no CORS needed — Paystack calls this server-to-server
        return await withdrawal.transferWebhook(request, env);
      }

      // ---- finance / campaigns ----
      if (pathname === "/campaigns" && request.method === "POST") {
        return withCORS(await finance.createCampaign(request, env), renewedToken);
      }
      const cancelMatch = pathname.match(/^\/campaigns\/([^/]+)\/cancel$/);
      if (cancelMatch && request.method === "POST") {
        return withCORS(await finance.cancelCampaign(request, env, cancelMatch[1]), renewedToken);
      }
      const approveMatch = pathname.match(/^\/admin\/submissions\/([^/]+)\/approve$/);
      if (approveMatch && request.method === "POST") {
        return withCORS(await finance.reviewSubmission(request, env, approveMatch[1], true), renewedToken);
      }
      const rejectMatch = pathname.match(/^\/admin\/submissions\/([^/]+)\/reject$/);
      if (rejectMatch && request.method === "POST") {
        return withCORS(await finance.reviewSubmission(request, env, rejectMatch[1], false), renewedToken);
      }

      // ---- activation ----
      if (pathname === "/activations/verify" && request.method === "POST") {
        return withCORS(await activation.verifyActivationPayment(request, env), renewedToken);
      }

      // ---- task submission + auto-verification ----
      if (pathname === "/submissions" && request.method === "POST") {
        return withCORS(await task.createSubmission(request, env), renewedToken);
      }

      // ---- wallet top-up ----
      if (pathname === "/wallet/topup" && request.method === "POST") {
        return withCORS(await topup.topUpBusinessWallet(request, env), renewedToken);
      }

      // ---- OTP transfer finalization (admin) ----
      if (pathname === "/admin/otp-transfers" && request.method === "GET") {
        return withCORS(await otp.listPendingOtpTransfers(request, env), renewedToken);
      }
      if (pathname === "/admin/otp-transfers/finalize" && request.method === "POST") {
        return withCORS(await otp.finalizeTransferOtp(request, env), renewedToken);
      }

      // ---- music marketplace ----
      if (pathname === "/musicians/songs" && request.method === "POST") {
        return withCORS(await music.createSongListing(request, env), renewedToken);
      }
      if (pathname === "/music/purchase" && request.method === "POST") {
        return withCORS(await music.purchaseSong(request, env), renewedToken);
      }

      // ---- file storage (D1 BLOBs — see storage.js) ----
      if (pathname === "/task-proofs" && request.method === "POST") {
        return withCORS(await storage.uploadTaskProof(request, env), renewedToken);
      }
      const songUploadMatch = pathname.match(/^\/musicians\/songs\/([^/]+)\/file$/);
      if (songUploadMatch && request.method === "POST") {
        return withCORS(await storage.uploadSongFile(request, env, songUploadMatch[1]), renewedToken);
      }
      const songStreamMatch = pathname.match(/^\/music\/file\/([^/]+)$/);
      if (songStreamMatch && request.method === "GET") {
        // no withCORS wrapper needed for the JSON error paths inside this
        // function either, but audio tags fetch cross-origin too, so keep it
        return withCORS(await storage.streamSongFile(request, env, songStreamMatch[1]), renewedToken);
      }

      // ---- affiliate marketplace ----
      if (pathname === "/affiliate/listings" && request.method === "POST") {
        return withCORS(await affiliate.createListing(request, env), renewedToken);
      }
      if (pathname === "/affiliate/listings" && request.method === "GET") {
        return withCORS(await affiliate.listActiveListings(request, env), renewedToken);
      }
      if (pathname === "/affiliate/listings/mine/sales" && request.method === "GET") {
        return withCORS(await affiliate.myListingSales(request, env), renewedToken);
      }
      const deleteListingMatch = pathname.match(/^\/affiliate\/listings\/([^/]+)$/);
      if (deleteListingMatch && request.method === "DELETE") {
        return withCORS(await affiliate.deleteListing(request, env, deleteListingMatch[1]), renewedToken);
      }
      if (pathname === "/affiliate/links" && request.method === "POST") {
        return withCORS(await affiliate.createLink(request, env), renewedToken);
      }
      if (pathname === "/affiliate/links/mine" && request.method === "GET") {
        return withCORS(await affiliate.myLinks(request, env), renewedToken);
      }
      if (pathname === "/affiliate/links/mine/sales" && request.method === "GET") {
        return withCORS(await affiliate.myLinkSales(request, env), renewedToken);
      }
      const checkoutMatch = pathname.match(/^\/affiliate\/checkout\/([^/]+)$/);
      if (checkoutMatch && request.method === "GET") {
        // Customer-facing, no auth required — they may not be a Capella user.
        return withCORS(await affiliate.checkoutPreview(request, env, checkoutMatch[1]), renewedToken);
      }
      if (pathname === "/affiliate/purchase" && request.method === "POST") {
        return withCORS(await affiliate.purchase(request, env), renewedToken);
      }

      // ---- admin settings ----
      if (pathname === "/admin/settings" && request.method === "GET") {
        return withCORS(await admin.getSettings(request, env), renewedToken);
      }
      if (pathname === "/admin/settings" && request.method === "POST") {
        return withCORS(await admin.updateSettings(request, env), renewedToken);
      }
      if (pathname === "/admin/wallet" && request.method === "GET") {
        return withCORS(await admin.getWallet(request, env), renewedToken);
      }

      return withCORS(new Response(JSON.stringify({ message: "Not found" }), { status: 404 }), renewedToken);
    } catch (err) {
      return withCORS(
        new Response(JSON.stringify({ message: "Internal error", detail: err.message }), { status: 500 }),
        renewedToken
      );
    }
  },

  // Cloudflare Cron Trigger entry point — configured via [triggers].crons
  // in wrangler.toml. Replaces Firebase's onSchedule('every 1 hours').
  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanup.deleteExpiredTaskProofs(env));
    ctx.waitUntil(cleanup.expireReleasedSongs(env));
  },
};

// EVERYDAY Multi-User Cloudflare Worker
// KV Binding: EVERYDAY (Cloudflare KV Namespace)
// Secret: TOKEN_SECRET (env variable, e.g. a random 64-char string)

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

// --- Crypto Helpers ---

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  return new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
}

async function createToken(username, secret) {
  const enc = new TextEncoder();
  const payload = JSON.stringify({ sub: username, iat: Date.now(), exp: Date.now() + 90 * 24 * 60 * 60 * 1000 }); // 90 days
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  return btoa(payload) + "." + toHex(sig);
}

async function verifyToken(token, secret) {
  try {
    const [payloadB64, sigHex] = token.split(".");
    if (!payloadB64 || !sigHex) return null;
    const enc = new TextEncoder();
    const payload = atob(payloadB64);
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("HMAC", key, fromHex(sigHex), enc.encode(payload));
    if (!valid) return null;
    const data = JSON.parse(payload);
    if (data.exp && data.exp < Date.now()) return null;
    return data;
  } catch (e) {
    return null;
  }
}

// --- Route Handlers ---

async function handleRegister(request, env) {
  const { username, password, displayName } = await request.json();
  if (!username || !password) return json({ error: "Benutzername und Passwort erforderlich" }, 400);
  if (username.length < 3) return json({ error: "E-Mail muss min. 3 Zeichen lang sein" }, 400);
  if (password.length < 6) return json({ error: "Passwort muss min. 6 Zeichen lang sein" }, 400);
  if (!/^[a-zA-Z0-9_.@+-]+$/.test(username)) return json({ error: "Ungültige E-Mail-Adresse" }, 400);

  const key = "user:" + username.toLowerCase();
  const existing = await env.EVERYDAY_KV.get(key);
  if (existing) return json({ error: "Benutzername bereits vergeben" }, 409);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(password, salt);

  await env.EVERYDAY_KV.put(key, JSON.stringify({
    username: username.toLowerCase(),
    displayName: displayName || username,
    hash: toHex(hash),
    salt: toHex(salt),
    created: new Date().toISOString(),
  }));

  const token = await createToken(username.toLowerCase(), env.TOKEN_SECRET || "everyday-default-secret-change-me");
  return json({ ok: true, token, username: username.toLowerCase(), displayName: displayName || username });
}

async function handleLogin(request, env) {
  const { username, password } = await request.json();
  if (!username || !password) return json({ error: "Benutzername und Passwort erforderlich" }, 400);

  const key = "user:" + username.toLowerCase();
  const raw = await env.EVERYDAY_KV.get(key);
  if (!raw) return json({ error: "Benutzername oder Passwort falsch" }, 401);

  const user = JSON.parse(raw);
  const hash = await hashPassword(password, fromHex(user.salt));
  if (toHex(hash) !== user.hash) return json({ error: "Benutzername oder Passwort falsch" }, 401);

  const token = await createToken(username.toLowerCase(), env.TOKEN_SECRET || "everyday-default-secret-change-me");
  return json({ ok: true, token, username: user.username, displayName: user.displayName });
}

async function handleGetData(request, env, username) {
  const raw = await env.EVERYDAY_KV.get("data:" + username);
  if (!raw) return json(null);
  return new Response(raw, {
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

async function handlePostData(request, env, username) {
  const body = await request.text();
  // Limit: 25MB per user
  if (body.length > 25 * 1024 * 1024) return json({ error: "Daten zu gross (max 25MB)" }, 413);
  await env.EVERYDAY_KV.put("data:" + username, body);
  return json({ ok: true, saved: new Date().toISOString() });
}

async function handleChangePassword(request, env, username) {
  const { oldPassword, newPassword } = await request.json();
  if (!oldPassword || !newPassword) return json({ error: "Altes und neues Passwort erforderlich" }, 400);
  if (newPassword.length < 6) return json({ error: "Neues Passwort muss min. 6 Zeichen lang sein" }, 400);

  const key = "user:" + username;
  const raw = await env.EVERYDAY_KV.get(key);
  if (!raw) return json({ error: "Benutzer nicht gefunden" }, 404);

  const user = JSON.parse(raw);
  const hash = await hashPassword(oldPassword, fromHex(user.salt));
  if (toHex(hash) !== user.hash) return json({ error: "Altes Passwort falsch" }, 401);

  const newSalt = crypto.getRandomValues(new Uint8Array(16));
  const newHash = await hashPassword(newPassword, newSalt);
  user.hash = toHex(newHash);
  user.salt = toHex(newSalt);
  await env.EVERYDAY_KV.put(key, JSON.stringify(user));

  return json({ ok: true });
}

async function handleAdminUsers(request, env, username) {
  // Only the developer account can access this
  if (username !== "luka.gc@icloud.com") return json({ error: "Kein Zugriff" }, 403);
  const list = await env.EVERYDAY_KV.list({ prefix: "user:" });
  const users = [];
  for (const key of list.keys) {
    const raw = await env.EVERYDAY_KV.get(key.name);
    if (raw) {
      const u = JSON.parse(raw);
      const dataRaw = await env.EVERYDAY_KV.get("data:" + u.username);
      let dataSize = 0, entries = {};
      if (dataRaw) {
        dataSize = dataRaw.length;
        try {
          const d = JSON.parse(dataRaw);
          entries = {
            appointments: (d.appointments || []).length,
            expenses: (d.expenses || []).length,
            dailyExp: (d.dailyExp || []).length,
            todos: (d.todos || []).length,
            notes: (d.notes || []).length,
          };
        } catch (e) {}
      }
      users.push({
        username: u.username,
        displayName: u.displayName,
        created: u.created,
        dataSize,
        entries,
      });
    }
  }
  return json({ ok: true, users, count: users.length });
}

async function handleAdminUserData(request, env, username) {
  if (username !== "luka.gc@icloud.com") return json({ error: "Kein Zugriff" }, 403);
  const url = new URL(request.url);
  const target = url.searchParams.get("user");
  if (!target) return json({ error: "user Parameter fehlt" }, 400);
  const raw = await env.EVERYDAY_KV.get("data:" + target.toLowerCase());
  if (!raw) return json(null);
  return new Response(raw, { headers: { "Content-Type": "application/json", ...CORS_HEADERS } });
}

async function handleGetChangelog(request, env) {
  const raw = await env.EVERYDAY_KV.get("app:changelog");
  if (!raw) return json({ updates: [] });
  return new Response(raw, { headers: { "Content-Type": "application/json", ...CORS_HEADERS } });
}

async function handlePostChangelog(request, env, username) {
  if (username !== "luka.gc@icloud.com") return json({ error: "Kein Zugriff" }, 403);
  const body = await request.text();
  if (body.length > 100 * 1024) return json({ error: "Zu gross" }, 413);
  await env.EVERYDAY_KV.put("app:changelog", body);
  return json({ ok: true });
}

// --- Calendar sharing ---

async function handleSetShares(request, env, username) {
  const { shareWith } = await request.json();
  if (!Array.isArray(shareWith)) return json({ error: "shareWith muss eine Liste sein" }, 400);
  const clean = shareWith.map(e => String(e).toLowerCase().trim()).filter(e => e.length && e !== username);
  await env.EVERYDAY_KV.put("shares:" + username, JSON.stringify(clean));
  return json({ ok: true, shareWith: clean });
}

async function handleGetShares(request, env, username) {
  const raw = await env.EVERYDAY_KV.get("shares:" + username);
  const shareWith = raw ? JSON.parse(raw) : [];
  return json({ ok: true, shareWith });
}

async function handleGetSharedCalendars(request, env, username) {
  const list = await env.EVERYDAY_KV.list({ prefix: "shares:" });
  const shared = [];
  for (const key of list.keys) {
    const ownerEmail = key.name.slice("shares:".length);
    if (ownerEmail === username) continue;
    const raw = await env.EVERYDAY_KV.get(key.name);
    if (!raw) continue;
    const shareList = JSON.parse(raw);
    if (shareList.includes(username)) {
      const dataRaw = await env.EVERYDAY_KV.get("data:" + ownerEmail);
      const userRaw = await env.EVERYDAY_KV.get("user:" + ownerEmail);
      let displayName = ownerEmail;
      if (userRaw) { try { displayName = JSON.parse(userRaw).displayName || ownerEmail; } catch (e) {} }
      let appointments = [];
      if (dataRaw) {
        try {
          const d = JSON.parse(dataRaw);
          appointments = (d.appointments || []).map(a => ({
            id: a.id, title: a.title, date: a.date, start: a.start, end: a.end,
            allDay: a.allDay, cat: a.cat, series: a.series
          }));
        } catch (e) {}
      }
      shared.push({ owner: ownerEmail, displayName, appointments });
    }
  }
  return json({ ok: true, calendars: shared });
}

// --- SOCIAL: Friends ---

async function getUserDisplay(env, email) {
  const raw = await env.EVERYDAY_KV.get("user:" + email);
  if (!raw) return email;
  try { return JSON.parse(raw).displayName || email; } catch (e) { return email; }
}

// friends:<email> = { friends:[email...], incoming:[email...], outgoing:[email...] }
async function getFriendData(env, email) {
  const raw = await env.EVERYDAY_KV.get("friends:" + email);
  if (!raw) return { friends: [], incoming: [], outgoing: [] };
  try { return JSON.parse(raw); } catch (e) { return { friends: [], incoming: [], outgoing: [] }; }
}
async function saveFriendData(env, email, data) {
  await env.EVERYDAY_KV.put("friends:" + email, JSON.stringify(data));
}

async function handleFriendRequest(request, env, username) {
  const { to } = await request.json();
  const target = String(to || "").toLowerCase().trim();
  if (!target) return json({ error: "Keine E-Mail angegeben" }, 400);
  if (target === username) return json({ error: "Du kannst dich nicht selbst hinzufügen" }, 400);
  const targetUser = await env.EVERYDAY_KV.get("user:" + target);
  if (!targetUser) return json({ error: "Kein Benutzer mit dieser E-Mail gefunden" }, 404);

  const mine = await getFriendData(env, username);
  const theirs = await getFriendData(env, target);
  if (mine.friends.includes(target)) return json({ error: "Ihr seid bereits befreundet" }, 409);
  if (mine.outgoing.includes(target)) return json({ error: "Anfrage bereits gesendet" }, 409);

  // If they already sent me a request, accept automatically
  if (mine.incoming.includes(target)) {
    mine.incoming = mine.incoming.filter(e => e !== target);
    mine.friends.push(target);
    theirs.outgoing = theirs.outgoing.filter(e => e !== username);
    theirs.friends.push(username);
    await saveFriendData(env, username, mine);
    await saveFriendData(env, target, theirs);
    return json({ ok: true, status: "friends" });
  }

  mine.outgoing.push(target);
  theirs.incoming.push(username);
  await saveFriendData(env, username, mine);
  await saveFriendData(env, target, theirs);
  return json({ ok: true, status: "sent" });
}

async function handleFriendRespond(request, env, username) {
  const { from, accept } = await request.json();
  const src = String(from || "").toLowerCase().trim();
  const mine = await getFriendData(env, username);
  const theirs = await getFriendData(env, src);
  if (!mine.incoming.includes(src)) return json({ error: "Keine Anfrage von dieser Person" }, 404);
  mine.incoming = mine.incoming.filter(e => e !== src);
  theirs.outgoing = theirs.outgoing.filter(e => e !== username);
  if (accept) {
    mine.friends.push(src);
    theirs.friends.push(username);
  }
  await saveFriendData(env, username, mine);
  await saveFriendData(env, src, theirs);
  return json({ ok: true });
}

async function handleFriendRemove(request, env, username) {
  const { friend } = await request.json();
  const f = String(friend || "").toLowerCase().trim();
  const mine = await getFriendData(env, username);
  const theirs = await getFriendData(env, f);
  mine.friends = mine.friends.filter(e => e !== f);
  theirs.friends = theirs.friends.filter(e => e !== username);
  await saveFriendData(env, username, mine);
  await saveFriendData(env, f, theirs);
  return json({ ok: true });
}

async function handleGetFriends(request, env, username) {
  const data = await getFriendData(env, username);
  const enrich = async (arr) => {
    const out = [];
    for (const e of arr) out.push({ email: e, displayName: await getUserDisplay(env, e) });
    return out;
  };
  return json({
    ok: true,
    friends: await enrich(data.friends),
    incoming: await enrich(data.incoming),
    outgoing: await enrich(data.outgoing),
  });
}

// --- SOCIAL: Chat ---
// chat:<emailA>|<emailB> (sorted) = [ {from, type, text, ts, ...} ]

function chatKey(a, b) {
  return "chat:" + [a, b].sort().join("|");
}

async function handleGetMessages(request, env, username) {
  const url = new URL(request.url);
  const withUser = String(url.searchParams.get("with") || "").toLowerCase().trim();
  if (!withUser) return json({ error: "with fehlt" }, 400);
  // Must be friends
  const mine = await getFriendData(env, username);
  if (!mine.friends.includes(withUser)) return json({ error: "Ihr seid nicht befreundet" }, 403);
  const raw = await env.EVERYDAY_KV.get(chatKey(username, withUser));
  const messages = raw ? JSON.parse(raw) : [];
  return json({ ok: true, messages });
}

async function handleSendMessage(request, env, username) {
  const { to, type, text, appointment, file } = await request.json();
  const target = String(to || "").toLowerCase().trim();
  const mine = await getFriendData(env, username);
  if (!mine.friends.includes(target)) return json({ error: "Ihr seid nicht befreundet" }, 403);
  const key = chatKey(username, target);
  const raw = await env.EVERYDAY_KV.get(key);
  const messages = raw ? JSON.parse(raw) : [];
  const msg = { from: username, ts: Date.now(), type: type || "text" };
  if (type === "appointment") msg.appointment = appointment;
  else if (type === "file") msg.file = file;
  else msg.text = String(text || "").slice(0, 4000);
  messages.push(msg);
  // Keep last 500 messages, cap size
  const trimmed = messages.slice(-500);
  const payload = JSON.stringify(trimmed);
  if (payload.length > 4 * 1024 * 1024) {
    // If too big (large files), drop oldest until under limit
    while (JSON.stringify(trimmed).length > 4 * 1024 * 1024 && trimmed.length > 1) trimmed.shift();
  }
  await env.EVERYDAY_KV.put(key, JSON.stringify(trimmed));
  return json({ ok: true, message: msg });
}

// --- Main Router ---

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // Public routes
    if (path === "/api/register" && request.method === "POST") {
      return handleRegister(request, env);
    }
    if (path === "/api/login" && request.method === "POST") {
      return handleLogin(request, env);
    }

    // Health check
    if (path === "/api/health") {
      return json({ status: "ok", time: new Date().toISOString() });
    }

    // Public: changelog (all users can read)
    if (path === "/api/changelog" && request.method === "GET") {
      return handleGetChangelog(request, env);
    }

    // --- Authenticated routes ---
    const auth = request.headers.get("Authorization");
    if (!auth || !auth.startsWith("Bearer ")) {
      return json({ error: "Nicht authentifiziert" }, 401);
    }

    const token = auth.slice(7);
    const payload = await verifyToken(token, env.TOKEN_SECRET || "everyday-default-secret-change-me");
    if (!payload) return json({ error: "Token ungültig oder abgelaufen" }, 401);

    const username = payload.sub;

    if (path === "/api/data" && request.method === "GET") {
      return handleGetData(request, env, username);
    }
    if (path === "/api/data" && request.method === "POST") {
      return handlePostData(request, env, username);
    }
    if (path === "/api/password" && request.method === "POST") {
      return handleChangePassword(request, env, username);
    }
    if (path === "/api/me") {
      const raw = await env.EVERYDAY_KV.get("user:" + username);
      if (!raw) return json({ error: "Benutzer nicht gefunden" }, 404);
      const user = JSON.parse(raw);
      return json({ username: user.username, displayName: user.displayName, created: user.created });
    }
    if (path === "/api/admin/users" && request.method === "GET") {
      return handleAdminUsers(request, env, username);
    }
    if (path === "/api/admin/userdata" && request.method === "GET") {
      return handleAdminUserData(request, env, username);
    }
    if (path === "/api/changelog" && request.method === "POST") {
      return handlePostChangelog(request, env, username);
    }
    if (path === "/api/shares" && request.method === "GET") {
      return handleGetShares(request, env, username);
    }
    if (path === "/api/shares" && request.method === "POST") {
      return handleSetShares(request, env, username);
    }
    if (path === "/api/shared-calendars" && request.method === "GET") {
      return handleGetSharedCalendars(request, env, username);
    }
    if (path === "/api/friends" && request.method === "GET") {
      return handleGetFriends(request, env, username);
    }
    if (path === "/api/friends/request" && request.method === "POST") {
      return handleFriendRequest(request, env, username);
    }
    if (path === "/api/friends/respond" && request.method === "POST") {
      return handleFriendRespond(request, env, username);
    }
    if (path === "/api/friends/remove" && request.method === "POST") {
      return handleFriendRemove(request, env, username);
    }
    if (path === "/api/messages" && request.method === "GET") {
      return handleGetMessages(request, env, username);
    }
    if (path === "/api/messages" && request.method === "POST") {
      return handleSendMessage(request, env, username);
    }

    return json({ error: "Nicht gefunden" }, 404);
  },
};

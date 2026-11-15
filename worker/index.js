const encoder = new TextEncoder();
const sessionSeconds = 8 * 60 * 60;
const actions = new Map([
  ["getDashboard", 0],
  ["getJournal", 1],
  ["saveReading", 1],
  ["exportJournalPdf", 1],
]);

function reply(status, payload, headers) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers,
    },
  });
}

async function signingKey(env) {
  const material = encoder.encode(JSON.stringify(["koktem-session-v1", env.GAS_API_SECRET, env.APP_PASSWORD]));
  const key = await crypto.subtle.digest("SHA-256", material);
  return crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function createSession(key) {
  const expires = Math.floor(Date.now() / 1000) + sessionSeconds;
  const payload = expires + "." + crypto.randomUUID();
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  return payload + "." + btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function hasSession(key, token) {
  if (typeof token !== "string" || !/^\d{10}\.[a-f0-9-]{36}\.[A-Za-z0-9+/]{43}=$/.test(token)) return false;
  const [expires, nonce, signature] = token.split(".");
  if (Number(expires) <= Math.floor(Date.now() / 1000)) return false;
  return crypto.subtle.verify("HMAC", key, Uint8Array.from(atob(signature), c => c.charCodeAt(0)), encoder.encode(expires + "." + nonce));
}

async function readInput(request) {
  const reader = request.body?.getReader();
  if (!reader) throw Error("Missing body");
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let size = 0;
  let json = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 25000) {
      await reader.cancel();
      throw Error("Request too large");
    }
    json += decoder.decode(value, { stream: true });
  }
  return JSON.parse(json + decoder.decode());
}

async function forwardToGas(env, action, args) {
  const url = new URL(env.GAS_URL);
  if (url.origin !== "https://script.google.com" || !/^\/macros\/s\/[\w-]+\/exec$/.test(url.pathname) ||
      url.username || url.password || url.search || url.hash) throw Error("Invalid GAS URL");

  let upstream = await fetch(url, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify({ secret: env.GAS_API_SECRET, action, args }),
  });

  if ([301, 302, 303].includes(upstream.status)) {
    const destination = new URL(upstream.headers.get("Location"), url);
    if (destination.origin !== "https://script.googleusercontent.com" || destination.username || destination.password)
      throw Error("Unexpected GAS redirect");
    upstream = await fetch(destination, { redirect: "error" });
  }
  if (!upstream.ok) throw Error("GAS request failed");
  return upstream.json();
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const allowed = Boolean(env.ALLOWED_ORIGIN && origin === env.ALLOWED_ORIGIN);
    const headers = allowed ? {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin",
    } : {};
    if (request.method === "OPTIONS") {
      return allowed ? new Response(null, { status: 204, headers }) : new Response(null, { status: 403 });
    }
    if (request.method !== "POST") return reply(405, { error: "Method not allowed" }, headers);
    if (!allowed) return reply(403, { error: "Доступ запрещён" }, headers);
    if (!env.APP_PASSWORD || !env.GAS_URL || !env.GAS_API_SECRET || !env.LOGIN_RATE_LIMIT)
      return reply(503, { error: "Подключение к журналам ещё настраивается" }, headers);

    let input;
    try { input = await readInput(request); } catch { return reply(400, { error: "Некорректный запрос" }, headers); }
    if (!input || typeof input !== "object") return reply(400, { error: "Некорректный запрос" }, headers);

    try {
      if (input.action === "login") {
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const { success } = await env.LOGIN_RATE_LIMIT.limit({ key: "login:" + ip });
        if (!success) return reply(429, { error: "Много попыток входа. Подождите минуту." }, headers);
        if (typeof input.password !== "string" || input.password.length > 256)
          return reply(401, { error: "Неверный пароль" }, headers);
        const [provided, expected] = await Promise.all(
          [input.password, env.APP_PASSWORD].map(password => crypto.subtle.digest("SHA-256", encoder.encode(password)))
        );
        if (!crypto.subtle.timingSafeEqual(provided, expected))
          return reply(401, { error: "Неверный пароль" }, headers);
        const token = await createSession(await signingKey(env));
        return reply(200, { result: { token } }, headers);
      }

      if (typeof input.token !== "string" || !(await hasSession(await signingKey(env), input.token)))
        return reply(401, { error: "Войдите в приложение снова" }, headers);
      if (!actions.has(input.action) || !Array.isArray(input.args) || input.args.length !== actions.get(input.action))
        return reply(400, { error: "Некорректная операция" }, headers);

      const result = await forwardToGas(env, input.action, input.args);
      return result.ok
        ? reply(200, { result: result.result }, headers)
        : reply(400, { error: result.error || "Ошибка обработки" }, headers);
    } catch {
      return reply(502, { error: "Сервер журналов недоступен. Попробуйте позже." }, headers);
    }
  },
};

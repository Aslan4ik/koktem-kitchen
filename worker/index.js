/**
 * Koktem Kitchen API gateway (Cloudflare Worker).
 * Secrets: GOOGLE_CLIENT_ID, ALLOWED_EMAILS, GAS_URL, GAS_API_SECRET, ALLOWED_ORIGIN
 * No patient/staff data is cached or logged.
 */
function cors(origin, env) {
  const permitted = origin === env.ALLOWED_ORIGIN;
  return permitted ? {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  } : {};
}
function reply(status, payload, headers) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...headers }
  });
}
export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const headers = cors(origin, env);
    if (request.method === "OPTIONS") {
      return origin === env.ALLOWED_ORIGIN
        ? new Response(null, { status: 204, headers: { ...headers, "Access-Control-Max-Age": "600" } })
        : new Response(null, { status: 403 });
    }
    if (request.method !== "POST") return reply(405, { error: "Method not allowed" }, headers);
    if (origin !== env.ALLOWED_ORIGIN) return reply(403, { error: "Origin not allowed" });
    if (![env.GOOGLE_CLIENT_ID, env.ALLOWED_EMAILS, env.GAS_URL, env.GAS_API_SECRET].every(Boolean))
      return reply(503, { error: "Сервер не настроен" }, headers);
    let input;
    try { input = await request.json(); } catch { return reply(400, { error: "Неверный JSON" }, headers); }
    if (!input || typeof input.token !== "string" || input.token.length > 5000)
      return reply(401, { error: "Требуется вход через Google" }, headers);
    const allowedMethods = new Set(["getDashboard", "getJournal", "saveReading", "exportJournalPdf"]);
    if (!allowedMethods.has(input.action)) return reply(400, { error: "Неизвестная операция" }, headers);
    const allowed = env.ALLOWED_EMAILS.split(",").map(x => x.trim().toLowerCase()).filter(Boolean);
    if (!allowed.length) return reply(503, { error: "Список пользователей пуст" }, headers);
    try {
      const tokenResponse = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(input.token), {
        method: "GET", headers: { "Accept": "application/json" }
      });
      if (!tokenResponse.ok) return reply(401, { error: "Сеанс Google истёк. Войдите снова." }, headers);
      const identity = await tokenResponse.json();
      if (identity.aud !== env.GOOGLE_CLIENT_ID || identity.email_verified !== "true" ||
          !allowed.includes(String(identity.email || "").toLowerCase()))
        return reply(403, { error: "У этого аккаунта нет доступа к журналам" }, headers);
      const args = Array.isArray(input.args) ? input.args : [];
      if (args.length > 2 || JSON.stringify(args).length > 20000) return reply(400, { error: "Запрос слишком большой" }, headers);
      const upstream = await fetch(env.GAS_URL, {
        method: "POST",
        redirect: "follow",
        headers: { "Content-Type": "text/plain;charset=utf-8" },
        body: JSON.stringify({ secret: env.GAS_API_SECRET, action: input.action, args })
      });
      if (!upstream.ok) return reply(502, { error: "Сервер журналов недоступен" }, headers);
      const body = await upstream.text();
      let result;
      try { result = JSON.parse(body); } catch { return reply(502, { error: "Некорректный ответ сервера журналов" }, headers); }
      return reply(result.ok ? 200 : 400, result.ok ? { result: result.result } : { error: result.error || "Ошибка обработки" }, headers);
    } catch {
      return reply(502, { error: "Ошибка связи с сервером. Попробуйте позже." }, headers);
    }
  }
};

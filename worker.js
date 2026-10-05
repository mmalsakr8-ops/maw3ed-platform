const COOKIE_NAME = "maw3ed_session";
const SESSION_DAYS = 30;
const TRIAL_DAYS = 14;
const PLATFORM_FOOTER = "© 2026 MAW3ED — موعد<br>جميع الحقوق محفوظة بواسطة M/mohamed abdalaziem";

const enc = new TextEncoder();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store",
      ...headers
    }
  });
}

function redirect(url, status = 302) {
  return new Response(null, {
    status,
    headers: {
      Location: url,
      "cache-control": "no-store"
    }
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=UTF-8",
      "cache-control": "no-store"
    }
  });
}

function nowISO() {
  return new Date().toISOString();
}

function addDays(date, days) {
  const d = new Date(date);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString();
}

function randomToken(bytes = 24) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map(x => x.toString(16).padStart(2, "0")).join("");
}

async function sha256(value) {
  const data = await crypto.subtle.digest(
    "SHA-256",
    enc.encode(String(value))
  );

  return [...new Uint8Array(data)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function hashPassword(password) {
  const salt = randomToken(16);

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  const hash = [...new Uint8Array(bits)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");

  return `${salt}:${hash}`;
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.includes(":")) return false;

  const [salt, expected] = stored.split(":");

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  const actual = [...new Uint8Array(bits)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");

  return actual === expected;
}

function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const result = {};

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    result[key] = decodeURIComponent(value);
  }

  return result;
}

function sessionCookie(token) {
  return [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${SESSION_DAYS * 86400}`
  ].join("; ");
}

function clearSessionCookie() {
  return [
    `${COOKIE_NAME}=`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    "Max-Age=0"
  ].join("; ");
}

async function bodyJSON(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function slugify(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[أإآ]/g, "ا")
    .replace(/ة/g, "ه")
    .replace(/ى/g, "ي")
    .replace(/ؤ/g, "و")
    .replace(/ئ/g, "ي")
    .replace(/ء/g, "")
    .replace(/[\u064B-\u065F\u0670]/g, "")
    .replace(/[^\p{L}\p{N}]+/gu, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "restaurant";
}

async function uniqueSlug(db, name, ignoreId = null) {
  const base = slugify(name);

  let slug = base;
  let counter = 2;

  while (true) {
    const row = await db
      .prepare(
        "SELECT id FROM sites WHERE slug = ?1 AND (?2 IS NULL OR id != ?2)"
      )
      .bind(slug, ignoreId)
      .first();

    if (!row) return slug;

    slug = `${base}-${counter++}`;
  }
}

function expired(site) {
  if (!site) return true;
  if (site.status !== "active") return true;

  if (site.subscription_type === "permanent") {
    return false;
  }

  if (site.subscription_ends_at) {
    return new Date(site.subscription_ends_at).getTime() <= Date.now();
  }

  if (site.trial_ends_at) {
    return new Date(site.trial_ends_at).getTime() <= Date.now();
  }

  return true;
}

function daysLeft(site) {
  if (!site || expired(site)) return 0;

  if (site.subscription_type === "permanent") {
    return null;
  }

  const end =
    site.subscription_ends_at ||
    site.trial_ends_at;

  if (!end) return 0;

  return Math.max(
    0,
    Math.ceil(
      (new Date(end).getTime() - Date.now()) / 86400000
    )
  );
}

async function currentUser(request, env) {
  const cookies = parseCookies(request);
  const token = cookies[COOKIE_NAME];

  if (!token) return null;

  const tokenHash = await sha256(token);

  const row = await env.DB
    .prepare(`
      SELECT
        u.id,
        u.name,
        u.phone,
        u.email,
        CASE WHEN lower(u.email) = 'mmalsakr8@gmail.com' THEN 'admin' ELSE u.role END AS role,
        u.status,
        u.created_at
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
        AND s.expires_at > ?
        AND u.status = 'active'
      LIMIT 1
    `)
    .bind(tokenHash, nowISO())
    .first();

  return row || null;
}

async function requireUser(request, env) {
  const user = await currentUser(request, env);

  if (!user) {
    throw new Response(
      JSON.stringify({
        error: "يجب تسجيل الدخول أولاً"
      }),
      {
        status: 401,
        headers: {
          "content-type": "application/json; charset=UTF-8"
        }
      }
    );
  }

  return user;
}

async function getSiteForUser(env, userId) {
  return await env.DB
    .prepare("SELECT * FROM sites WHERE user_id = ? LIMIT 1")
    .bind(userId)
    .first();
}

async function requireSite(env, userId) {
  const site = await getSiteForUser(env, userId);

  if (!site) {
    throw new Response(
      JSON.stringify({
        error: "لم يتم إنشاء المطعم بعد"
      }),
      {
        status: 404,
        headers: {
          "content-type": "application/json; charset=UTF-8"
        }
      }
    );
  }

  return site;
}

function publicSiteData(site) {
  return {
    id: site.id,
    name: site.name,
    slug: site.slug,
    phone: site.phone,
    address: site.address,
    working_hours: site.working_hours,
    description: site.description,
    business_type: site.business_type || "restaurant",
    logo_url: site.logo_url,
    cover_url: site.cover_url,
    design: site.design,
    status: site.status,
    subscription_type: site.subscription_type,
    subscription_ends_at: site.subscription_ends_at,
    trial_ends_at: site.trial_ends_at,
    expired: expired(site),
    days_left: daysLeft(site)
  };
}

/* =========================
   REGISTER
========================= */

async function register(request, env) {
  const data = await bodyJSON(request);

  const name = String(data.name || "").trim();
  const phone = String(data.phone || "").trim();
  const email = String(data.email || "").trim().toLowerCase();
  const password = String(data.password || "");

  if (!name || !phone || !email || !password) {
    return json(
      { error: "من فضلك أكمل جميع البيانات" },
      400
    );
  }

  if (password.length < 6) {
    return json(
      { error: "كلمة المرور يجب أن تكون 6 أحرف على الأقل" },
      400
    );
  }

  const exists = await env.DB
    .prepare(
      "SELECT id FROM users WHERE email = ?1 OR phone = ?2 LIMIT 1"
    )
    .bind(email, phone)
    .first();

  if (exists) {
    return json(
      { error: "البريد الإلكتروني أو رقم الهاتف مستخدم بالفعل" },
      409
    );
  }

  const admin = await env.DB
    .prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    .first();

  const userId = randomToken(16);
  const passwordHash = await hashPassword(password);
  const role = admin ? "customer" : "admin";

  await env.DB
    .prepare(`
      INSERT INTO users
      (id, name, phone, email, password_hash, role, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
    `)
    .bind(
      userId,
      name,
      phone,
      email,
      passwordHash,
      role,
      nowISO()
    )
    .run();

  const token = randomToken(32);
  const tokenHash = await sha256(token);

  await env.DB
    .prepare(`
      INSERT INTO sessions
      (id, user_id, token_hash, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `)
    .bind(
      randomToken(16),
      userId,
      tokenHash,
      addDays(new Date(), SESSION_DAYS),
      nowISO()
    )
    .run();

  return json(
    {
      ok: true,
      user: {
        id: userId,
        name,
        phone,
        email,
        role
      }
    },
    201,
    {
      "Set-Cookie": sessionCookie(token)
    }
  );
}

/* =========================
   LOGIN
========================= */

async function login(request, env) {
  const data = await bodyJSON(request);

  const identifier = String(
    data.identifier ??
    data.login ??
    data.email ??
    data.phone ??
    ""
  )
    .trim()
    .toLowerCase();

  const password = String(data.password || "");

  if (!identifier || !password) {
    return json(
      { error: "أدخل بيانات تسجيل الدخول" },
      400
    );
  }

  const user = await env.DB
    .prepare(`
      SELECT *
      FROM users
      WHERE lower(email) = ?1
         OR lower(phone) = ?1
      LIMIT 1
    `)
    .bind(identifier)
    .first();

  if (!user) {
    return json(
      { error: "بيانات الدخول غير صحيحة" },
      401
    );
  }

  if (user.status !== "active") {
    return json(
      { error: "الحساب موقوف" },
      403
    );
  }

  const valid = await verifyPassword(
    password,
    user.password_hash
  );

  if (!valid) {
    return json(
      { error: "بيانات الدخول غير صحيحة" },
      401
    );
  }

  const token = randomToken(32);
  const tokenHash = await sha256(token);

  await env.DB
    .prepare(`
      INSERT INTO sessions
      (id, user_id, token_hash, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `)
    .bind(
      randomToken(16),
      user.id,
      tokenHash,
      addDays(new Date(), SESSION_DAYS),
      nowISO()
    )
    .run();

  return json(
    {
      ok: true,
      user: {
        id: user.id,
        name: user.name,
        phone: user.phone,
        email: user.email,
        role: user.role
      }
    },
    200,
    {
      "Set-Cookie": sessionCookie(token)
    }
  );
}

/* =========================
   LOGOUT
========================= */

async function logout(request, env) {
  const cookies = parseCookies(request);
  const token = cookies[COOKIE_NAME];

  if (token) {
    const tokenHash = await sha256(token);

    await env.DB
      .prepare("DELETE FROM sessions WHERE token_hash = ?")
      .bind(tokenHash)
      .run();
  }

  return json(
    { ok: true },
    200,
    {
      "Set-Cookie": clearSessionCookie()
    }
  );
}

/* =========================
   ME
========================= */

async function me(request, env) {
  const user = await currentUser(request, env);

  if (!user) {
    return json(
      { user: null },
      401
    );
  }

  const site = await getSiteForUser(env, user.id);

  return json({
    user,
    site: site
      ? {
          id: site.id,
          name: site.name,
          slug: site.slug,
          business_type: site.business_type || "restaurant",
          status: site.status,
          phone: site.phone || "",
          address: site.address || "",
          working_hours: site.working_hours || "",
          description: site.description || "",
          logo_url: site.logo_url || "",
          cover_url: site.cover_url || "",
          design: site.design || "default",
          subscription_type: site.subscription_type,
          subscription_ends_at: site.subscription_ends_at,
          trial_ends_at: site.trial_ends_at,
          expired: expired(site),
          days_left: daysLeft(site)
        }
      : null
  });
}

/* =========================
   SITE
========================= */

async function ensureSiteColumns(env) {
  const required = [
    ["business_type", "TEXT DEFAULT 'restaurant'"],
    ["cover_url", "TEXT DEFAULT ''"],
    ["design", "TEXT DEFAULT 'default'"]
  ];
  const info = await env.DB.prepare("PRAGMA table_info(sites)").all();
  const columns = new Set((info.results || []).map(r => r.name));
  for (const [name, definition] of required) {
    if (columns.has(name)) continue;
    try {
      await env.DB.prepare(`ALTER TABLE sites ADD COLUMN ${name} ${definition}`).run();
    } catch (error) {
      const check = await env.DB.prepare("PRAGMA table_info(sites)").all();
      const names = new Set((check.results || []).map(r => r.name));
      if (!names.has(name)) throw error;
    }
  }
}

async function siteAPI(request, env, user) {
  try {
    await ensureSiteColumns(env);

  if (request.method === "GET") {
    const site = await getSiteForUser(env, user.id);

    return json({
      site: site ? publicSiteData(site) : null
    });
  }

  if (request.method === "POST") {
    const existing = await getSiteForUser(env, user.id);

    if (existing) {
      return json(
        { error: "لديك مطعم بالفعل" },
        409
      );
    }

    const data = await bodyJSON(request);

    const name = String(data.name || "").trim();

    if (!name) {
      return json(
        { error: "اسم المكان مطلوب" },
        400
      );
    }

    const id = randomToken(16);
    const slug = await uniqueSlug(env.DB, name);

    const trialStarted = nowISO();
    const trialEnds = addDays(
      new Date(),
      TRIAL_DAYS
    );

    await env.DB
      .prepare(`
        INSERT INTO sites
        (
          id,
          user_id,
          name,
          slug,
          business_type,
          phone,
          address,
          working_hours,
          description,
          logo_url,
          cover_url,
          design,
          status,
          trial_started_at,
          trial_ends_at,
          subscription_type,
          subscription_ends_at,
          created_at,
          updated_at
        )
        VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, 'trial', NULL, ?, ?)
      `)
      .bind(
        id,
        user.id,
        name,
        slug,
        ["restaurant","cafe"].includes(data.business_type) ? data.business_type : "restaurant",
        String(data.phone || user.phone || ""),
        String(data.address || ""),
        String(data.working_hours || ""),
        String(data.description || ""),
        String(data.logo_url || ""),
        String(data.cover_url || ""),
        String(data.design || "default"),
        trialStarted,
        trialEnds,
        trialStarted,
        trialStarted
      )
      .run();

    return json(
      {
        ok: true,
        site: await getSiteForUser(env, user.id)
      },
      201
    );
  }

  if (request.method === "PUT") {
    const data = await bodyJSON(request);
    let site = await getSiteForUser(env, user.id);

    // Be tolerant of a stale dashboard state: if the browser sends PUT
    // before the site exists, create it instead of returning 404.
    if (!site) {
      const name = String(data.name || "").trim();
      if (!name) return json({ error: "اسم المكان مطلوب" }, 400);

      const id = randomToken(16);
      const slug = await uniqueSlug(env.DB, name);
      const started = nowISO();
      const ends = addDays(new Date(), TRIAL_DAYS);

      await env.DB.prepare(`
        INSERT INTO sites
        (id,user_id,name,slug,business_type,phone,address,working_hours,description,logo_url,cover_url,design,status,trial_started_at,trial_ends_at,subscription_type,subscription_ends_at,created_at,updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, 'trial', NULL, ?, ?)
      `).bind(
        id,
        user.id,
        name,
        slug,
        ["restaurant","cafe"].includes(data.business_type) ? data.business_type : "restaurant",
        String(data.phone || user.phone || ""),
        String(data.address || ""),
        String(data.working_hours || ""),
        String(data.description || ""),
        String(data.logo_url || ""),
        String(data.cover_url || ""),
        String(data.design || "default"),
        started,
        ends,
        started,
        started
      ).run();

      site = await getSiteForUser(env, user.id);
      return json({ ok: true, created: true, site: site ? publicSiteData(site) : null }, 201);
    }

    const name = data.name !== undefined ? String(data.name).trim() : site.name;
    if (!name) return json({ error: "اسم المكان مطلوب" }, 400);

    let slug = site.slug;
    if (name !== site.name) slug = await uniqueSlug(env.DB, name, site.id);

    await env.DB.prepare(`
      UPDATE sites
      SET name=?, slug=?, business_type=?, phone=?, address=?, working_hours=?, description=?, logo_url=?, cover_url=?, design=?, updated_at=?
      WHERE id=?
    `).bind(
      name,
      slug,
      ["restaurant","cafe"].includes(data.business_type) ? data.business_type : (site.business_type || "restaurant"),
      data.phone !== undefined ? String(data.phone) : (site.phone || ""),
      data.address !== undefined ? String(data.address) : (site.address || ""),
      data.working_hours !== undefined ? String(data.working_hours) : (site.working_hours || ""),
      data.description !== undefined ? String(data.description) : (site.description || ""),
      data.logo_url !== undefined ? String(data.logo_url) : (site.logo_url || ""),
      data.cover_url !== undefined ? String(data.cover_url) : (site.cover_url || ""),
      data.design !== undefined ? String(data.design) : (site.design || "default"),
      nowISO(),
      site.id
    ).run();

    return json({ ok: true, created: false, site: await getSiteForUser(env, user.id) });
  }

    return json(
      { error: "Method Not Allowed" },
      405
    );
  } catch (error) {
    if (error instanceof Response) return error;
    console.error("MAW3ED /api/site ERROR:", error);
    return json({
      error: "تعذر حفظ بيانات المطعم",
      detail: String(error?.message || error || "Unknown error")
    }, 500);
  }
}

/* =========================
   CATEGORIES
========================= */

async function categoriesAPI(request, env, user, id = null) {
  const site = await requireSite(env, user.id);

  if (request.method === "GET") {
    const result = await env.DB
      .prepare(`
        SELECT *
        FROM categories
        WHERE site_id = ?
        ORDER BY sort_order ASC, created_at ASC
      `)
      .bind(site.id)
      .all();

    return json({
      categories: result.results || []
    });
  }

  if (siteExpiredResponse(site)) {
    return siteExpiredResponse(site);
  }

  if (request.method === "POST") {
    const data = await bodyJSON(request);
    const name = String(data.name || "").trim();

    if (!name) {
      return json(
        { error: "اسم القسم مطلوب" },
        400
      );
    }

    const max = await env.DB
      .prepare(`
        SELECT COALESCE(MAX(sort_order), 0) AS max_order
        FROM categories
        WHERE site_id = ?
      `)
      .bind(site.id)
      .first();

    const categoryId = randomToken(16);

    await env.DB
      .prepare(`
        INSERT INTO categories
        (id, site_id, name, sort_order, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `)
      .bind(
        categoryId,
        site.id,
        name,
        Number(max?.max_order || 0) + 1,
        nowISO(),
        nowISO()
      )
      .run();

    return json(
      {
        ok: true,
        id: categoryId
      },
      201
    );
  }

  if (!id) {
    return json(
      { error: "معرف القسم مطلوب" },
      400
    );
  }

  const category = await env.DB
    .prepare(`
      SELECT *
      FROM categories
      WHERE id = ? AND site_id = ?
    `)
    .bind(id, site.id)
    .first();

  if (!category) {
    return json(
      { error: "القسم غير موجود" },
      404
    );
  }

  if (request.method === "PUT") {
    const data = await bodyJSON(request);

    await env.DB
      .prepare(`
        UPDATE categories
        SET name = ?, sort_order = ?, updated_at = ?
        WHERE id = ? AND site_id = ?
      `)
      .bind(
        data.name !== undefined
          ? String(data.name).trim()
          : category.name,
        data.sort_order !== undefined
          ? Number(data.sort_order)
          : category.sort_order,
        nowISO(),
        id,
        site.id
      )
      .run();

    return json({ ok: true });
  }

  if (request.method === "DELETE") {
    await env.DB
      .prepare(`
        UPDATE menu_items
        SET category_id = NULL, updated_at = ?
        WHERE category_id = ? AND site_id = ?
      `)
      .bind(nowISO(), id, site.id)
      .run();

    await env.DB
      .prepare(`
        DELETE FROM categories
        WHERE id = ? AND site_id = ?
      `)
      .bind(id, site.id)
      .run();

    return json({ ok: true });
  }

  return json(
    { error: "Method Not Allowed" },
    405
  );
}

/* =========================
   MENU ITEMS
========================= */

async function menuItemsAPI(request, env, user, id = null) {
  const site = await requireSite(env, user.id);

  // Reading the menu must remain available even when the subscription
  // is expired; only write operations are blocked.
  if (request.method === "GET") {
    const result = await env.DB
      .prepare(`
        SELECT
          m.*,
          c.name AS category_name
        FROM menu_items m
        LEFT JOIN categories c
          ON c.id = m.category_id
         AND c.site_id = m.site_id
        WHERE m.site_id = ?
        ORDER BY
          COALESCE(c.sort_order, 999999) ASC,
          m.sort_order ASC,
          m.created_at ASC
      `)
      .bind(site.id)
      .all();

    return json({
      items: result.results || []
    });
  }

  if (siteExpiredResponse(site)) {
    return siteExpiredResponse(site);
  }

  if (request.method === "POST") {
    const data = await bodyJSON(request);

    const name = String(data.name || "").trim();

    if (!name) {
      return json(
        { error: "اسم الصنف مطلوب" },
        400
      );
    }

    if (data.category_id) {
      const category = await env.DB
        .prepare(`
          SELECT id
          FROM categories
          WHERE id = ? AND site_id = ?
        `)
        .bind(data.category_id, site.id)
        .first();

      if (!category) {
        return json(
          { error: "القسم غير موجود" },
          400
        );
      }
    }

    const max = await env.DB
      .prepare(`
        SELECT COALESCE(MAX(sort_order), 0) AS max_order
        FROM menu_items
        WHERE site_id = ?
      `)
      .bind(site.id)
      .first();

    const itemId = randomToken(16);

    await env.DB
      .prepare(`
        INSERT INTO menu_items
        (
          id,
          site_id,
          category_id,
          name,
          description,
          price,
          image_url,
          sort_order,
          available,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        itemId,
        site.id,
        data.category_id || null,
        name,
        String(data.description || ""),
        Number(data.price || 0),
        String(data.image_url || ""),
        Number(max?.max_order || 0) + 1,
        data.available === false ? 0 : 1,
        nowISO(),
        nowISO()
      )
      .run();

    return json(
      {
        ok: true,
        id: itemId
      },
      201
    );
  }

  if (!id) {
    return json(
      { error: "معرف الصنف مطلوب" },
      400
    );
  }

  const item = await env.DB
    .prepare(`
      SELECT *
      FROM menu_items
      WHERE id = ? AND site_id = ?
    `)
    .bind(id, site.id)
    .first();

  if (!item) {
    return json(
      { error: "الصنف غير موجود" },
      404
    );
  }

  if (request.method === "PUT") {
    const data = await bodyJSON(request);

    const categoryId =
      data.category_id !== undefined
        ? data.category_id || null
        : item.category_id;

    if (categoryId) {
      const category = await env.DB
        .prepare(`
          SELECT id
          FROM categories
          WHERE id = ? AND site_id = ?
        `)
        .bind(categoryId, site.id)
        .first();

      if (!category) {
        return json(
          { error: "القسم غير موجود" },
          400
        );
      }
    }

    await env.DB
      .prepare(`
        UPDATE menu_items
        SET
          category_id = ?,
          name = ?,
          description = ?,
          price = ?,
          image_url = ?,
          sort_order = ?,
          available = ?,
          updated_at = ?
        WHERE id = ? AND site_id = ?
      `)
      .bind(
        categoryId,
        data.name !== undefined
          ? String(data.name).trim()
          : item.name,
        data.description !== undefined
          ? String(data.description)
          : item.description,
        data.price !== undefined
          ? Number(data.price)
          : item.price,
        data.image_url !== undefined
          ? String(data.image_url)
          : item.image_url,
        data.sort_order !== undefined
          ? Number(data.sort_order)
          : item.sort_order,
        data.available !== undefined
          ? (data.available ? 1 : 0)
          : item.available,
        nowISO(),
        id,
        site.id
      )
      .run();

    return json({ ok: true });
  }

  if (request.method === "DELETE") {
    await env.DB
      .prepare(`
        DELETE FROM menu_items
        WHERE id = ? AND site_id = ?
      `)
      .bind(id, site.id)
      .run();

    return json({ ok: true });
  }

  return json(
    { error: "Method Not Allowed" },
    405
  );
}

/* =========================
   TABLES
========================= */

async function tablesAPI(request, env, user, id = null) {
  const site = await requireSite(env, user.id);

  if (request.method === "GET") {
    const result = await env.DB
      .prepare(`
        SELECT *
        FROM restaurant_tables
        WHERE site_id = ?
        ORDER BY name ASC
      `)
      .bind(site.id)
      .all();

    return json({
      tables: result.results || []
    });
  }

  if (siteExpiredResponse(site)) {
    return siteExpiredResponse(site);
  }

  if (request.method === "POST") {
    const data = await bodyJSON(request);

    const name = String(data.name || "").trim();
    const capacity = Number(data.capacity || 0);

    if (!name || capacity < 1) {
      return json(
        { error: "أدخل اسم الترابيزة والسعة" },
        400
      );
    }

    const tableId = randomToken(16);

    await env.DB
      .prepare(`
        INSERT INTO restaurant_tables
        (id, site_id, name, capacity, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'available', ?, ?)
      `)
      .bind(
        tableId,
        site.id,
        name,
        capacity,
        nowISO(),
        nowISO()
      )
      .run();

    return json(
      {
        ok: true,
        id: tableId
      },
      201
    );
  }

  if (!id) {
    return json(
      { error: "معرف الترابيزة مطلوب" },
      400
    );
  }

  const table = await env.DB
    .prepare(`
      SELECT *
      FROM restaurant_tables
      WHERE id = ? AND site_id = ?
    `)
    .bind(id, site.id)
    .first();

  if (!table) {
    return json(
      { error: "الترابيزة غير موجودة" },
      404
    );
  }

  if (request.method === "PUT") {
    const data = await bodyJSON(request);

    await env.DB
      .prepare(`
        UPDATE restaurant_tables
        SET
          name = ?,
          capacity = ?,
          status = ?,
          updated_at = ?
        WHERE id = ? AND site_id = ?
      `)
      .bind(
        data.name !== undefined
          ? String(data.name).trim()
          : table.name,
        data.capacity !== undefined
          ? Number(data.capacity)
          : table.capacity,
        data.status === "disabled"
          ? "disabled"
          : "available",
        nowISO(),
        id,
        site.id
      )
      .run();

    return json({ ok: true });
  }

  if (request.method === "DELETE") {
    const used = await env.DB
      .prepare(`
        SELECT COUNT(*) AS count
        FROM reservations
        WHERE table_id = ? AND site_id = ?
      `)
      .bind(id, site.id)
      .first();

    if (Number(used?.count || 0) > 0) {
      return json(
        {
          error:
            "لا يمكن حذف هذه الطاولة لأنها مرتبطة بحجوزات سابقة. يمكنك تعطيلها بدلًا من حذفها."
        },
        409
      );
    }

    await env.DB
      .prepare(`
        DELETE FROM restaurant_tables
        WHERE id = ? AND site_id = ?
      `)
      .bind(id, site.id)
      .run();

    return json({ ok: true });
  }

  return json(
    { error: "Method Not Allowed" },
    405
  );
}

/* =========================
   PUBLIC MENU
========================= */

async function publicMenu(env, slug) {
  const site = await env.DB
    .prepare(`
      SELECT *
      FROM sites
      WHERE slug = ?
      LIMIT 1
    `)
    .bind(slug)
    .first();

  if (!site) {
    return json(
      { error: "المطعم غير موجود" },
      404
    );
  }

  if (expired(site)) {
    return json(
      {
        error: "هذا المطعم غير متاح حالياً",
        expired: true
      },
      403
    );
  }

  const categories = await env.DB
    .prepare(`
      SELECT *
      FROM categories
      WHERE site_id = ?
      ORDER BY sort_order ASC, created_at ASC
    `)
    .bind(site.id)
    .all();

  const items = await env.DB
    .prepare(`
      SELECT *
      FROM menu_items
      WHERE site_id = ? AND available = 1
      ORDER BY sort_order ASC, created_at ASC
    `)
    .bind(site.id)
    .all();

  return json({
    site: publicSiteData(site),
    categories: categories.results || [],
    items: items.results || []
  });
}

/* =========================
   PUBLIC SITE
========================= */

async function publicSite(env, slug) {
  const site = await env.DB
    .prepare(`
      SELECT *
      FROM sites
      WHERE slug = ?
      LIMIT 1
    `)
    .bind(slug)
    .first();

  if (!site) {
    return json(
      { error: "المطعم غير موجود" },
      404
    );
  }

  if (expired(site)) {
    return json(
      {
        error: "هذا المطعم غير متاح حالياً",
        expired: true
      },
      403
    );
  }

  const categories = await env.DB
    .prepare(`
      SELECT *
      FROM categories
      WHERE site_id = ?
      ORDER BY sort_order ASC, created_at ASC
    `)
    .bind(site.id)
    .all();

  return json({
    site: publicSiteData(site),
    categories: categories.results || []
  });
}

async function ensurePlatformSchema(env) {
  await ensureSiteColumns(env);
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS platform_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    deposit_enabled INTEGER DEFAULT 0,
    deposit_amount REAL DEFAULT 0,
    deposit_currency TEXT DEFAULT 'جنيه',
    deposit_method TEXT DEFAULT 'تحويل بنكي',
    deposit_recipient TEXT DEFAULT '',
    deposit_account TEXT DEFAULT '',
    deposit_instructions TEXT DEFAULT '',
    updated_at TEXT
  )`).run();
  await env.DB.prepare(`INSERT OR IGNORE INTO platform_settings (id, updated_at) VALUES (1, ?)`).bind(nowISO()).run();
  const info = await env.DB.prepare("PRAGMA table_info(reservations)").all();
  const columns = new Set((info.results || []).map(r => r.name));
  const required = [
    ["deposit_required", "INTEGER DEFAULT 0"],
    ["deposit_amount", "REAL DEFAULT 0"],
    ["deposit_proof", "TEXT DEFAULT ''"],
    ["deposit_status", "TEXT DEFAULT 'not_required'"]
  ];
  for (const [name, def] of required) {
    if (columns.has(name)) continue;
    try { await env.DB.prepare(`ALTER TABLE reservations ADD COLUMN ${name} ${def}`).run(); }
    catch (e) {
      const check = await env.DB.prepare("PRAGMA table_info(reservations)").all();
      const names = new Set((check.results || []).map(r => r.name));
      if (!names.has(name)) throw e;
    }
  }
}

async function getDepositSettings(env) {
  await ensurePlatformSchema(env);
  return await env.DB.prepare("SELECT * FROM platform_settings WHERE id = 1").first();
}

async function adminDepositSettings(request, env) {
  await requireAdmin(request, env);
  await ensurePlatformSchema(env);
  if (request.method === "GET") return json({ settings: await getDepositSettings(env) });
  if (request.method !== "PUT") return json({ error: "Method Not Allowed" }, 405);
  const data = await bodyJSON(request);
  const enabled = data.deposit_enabled ? 1 : 0;
  const amount = Math.max(0, Number(data.deposit_amount || 0));
  await env.DB.prepare(`UPDATE platform_settings SET deposit_enabled=?, deposit_amount=?, deposit_currency=?, deposit_method=?, deposit_recipient=?, deposit_account=?, deposit_instructions=?, updated_at=? WHERE id=1`)
    .bind(enabled, amount, String(data.deposit_currency || "جنيه"), String(data.deposit_method || "تحويل بنكي"), String(data.deposit_recipient || ""), String(data.deposit_account || ""), String(data.deposit_instructions || ""), nowISO()).run();
  return json({ ok: true, settings: await getDepositSettings(env) });
}

async function adminSiteDetail(request, env, siteId) {
  await requireAdmin(request, env);
  const site = await env.DB.prepare("SELECT * FROM sites WHERE id=?").bind(siteId).first();
  if (!site) return json({ error: "المطعم غير موجود" }, 404);
  if (request.method === "GET") {
    const [cats, items, tables] = await Promise.all([
      env.DB.prepare("SELECT * FROM categories WHERE site_id=? ORDER BY sort_order, created_at").bind(siteId).all(),
      env.DB.prepare("SELECT * FROM menu_items WHERE site_id=? ORDER BY sort_order, created_at").bind(siteId).all(),
      env.DB.prepare("SELECT * FROM restaurant_tables WHERE site_id=? ORDER BY created_at").bind(siteId).all()
    ]);
    return json({ site, categories: cats.results || [], items: items.results || [], tables: tables.results || [] });
  }
  if (request.method === "PUT") {
    const d = await bodyJSON(request);
    const name = String(d.name ?? site.name).trim();
    if (!name) return json({ error: "اسم المكان مطلوب" }, 400);
    const slug = name !== site.name ? await uniqueSlug(env.DB, name, site.id) : site.slug;
    const type = ["restaurant","cafe"].includes(d.business_type) ? d.business_type : (site.business_type || "restaurant");
    await env.DB.prepare(`UPDATE sites SET name=?, slug=?, business_type=?, phone=?, address=?, working_hours=?, description=?, logo_url=?, cover_url=?, design=?, updated_at=? WHERE id=?`)
      .bind(name, slug, type, String(d.phone ?? site.phone ?? ""), String(d.address ?? site.address ?? ""), String(d.working_hours ?? site.working_hours ?? ""), String(d.description ?? site.description ?? ""), String(d.logo_url ?? site.logo_url ?? ""), String(d.cover_url ?? site.cover_url ?? ""), String(d.design ?? site.design ?? "default"), nowISO(), siteId).run();
    return json({ ok: true, site: await env.DB.prepare("SELECT * FROM sites WHERE id=?").bind(siteId).first() });
  }
  return json({ error: "Method Not Allowed" }, 405);
}

async function adminMenu(request, env, siteId) {
  await requireAdmin(request, env);
  const site = await env.DB.prepare("SELECT id FROM sites WHERE id=?").bind(siteId).first();
  if (!site) return json({ error: "المكان غير موجود" }, 404);
  if (request.method === "GET") {
    const [c,i] = await Promise.all([
      env.DB.prepare("SELECT * FROM categories WHERE site_id=? ORDER BY sort_order, created_at").bind(siteId).all(),
      env.DB.prepare("SELECT * FROM menu_items WHERE site_id=? ORDER BY sort_order, created_at").bind(siteId).all()
    ]);
    return json({ categories:c.results||[], items:i.results||[] });
  }
  const d = await bodyJSON(request);
  const type = String(d.type || "item");
  if (type === "category") {
    if (request.method === "POST") {
      const id=randomToken(16); await env.DB.prepare("INSERT INTO categories (id,site_id,name,sort_order,created_at,updated_at) VALUES (?,?,?,?,?,?)").bind(id,siteId,String(d.name||"قسم"),Number(d.sort_order||0),nowISO(),nowISO()).run(); return json({ok:true,id},201);
    }
    if (request.method === "PUT" && d.id) { await env.DB.prepare("UPDATE categories SET name=?,updated_at=? WHERE id=? AND site_id=?").bind(String(d.name||"قسم"),nowISO(),d.id,siteId).run(); return json({ok:true}); }
    if (request.method === "DELETE" && d.id) { await env.DB.prepare("DELETE FROM categories WHERE id=? AND site_id=?").bind(d.id,siteId).run(); return json({ok:true}); }
  }
  if (type === "item") {
    if (request.method === "POST") {
      const id=randomToken(16); await env.DB.prepare(`INSERT INTO menu_items (id,site_id,category_id,name,description,price,image_url,available,sort_order,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`).bind(id,siteId,d.category_id||null,String(d.name||"صنف"),String(d.description||""),Number(d.price||0),String(d.image_url||""),d.available===false?0:1,Number(d.sort_order||0),nowISO(),nowISO()).run(); return json({ok:true,id},201);
    }
    if (request.method === "PUT" && d.id) { await env.DB.prepare(`UPDATE menu_items SET category_id=?,name=?,description=?,price=?,image_url=?,available=?,updated_at=? WHERE id=? AND site_id=?`).bind(d.category_id||null,String(d.name||"صنف"),String(d.description||""),Number(d.price||0),String(d.image_url||""),d.available===false?0:1,nowISO(),d.id,siteId).run(); return json({ok:true}); }
    if (request.method === "DELETE" && d.id) { await env.DB.prepare("DELETE FROM menu_items WHERE id=? AND site_id=?").bind(d.id,siteId).run(); return json({ok:true}); }
  }
  return json({error:"طلب المنيو غير صحيح"},400);
}

/* =========================
   PUBLIC BOOKING
========================= */

async function publicBooking(request, env, slug) {
  if (request.method !== "POST") {
    return json(
      { error: "Method Not Allowed" },
      405
    );
  }

  const site = await env.DB
    .prepare(`
      SELECT *
      FROM sites
      WHERE slug = ?
      LIMIT 1
    `)
    .bind(slug)
    .first();

  if (!site) {
    return json(
      { error: "المطعم غير موجود" },
      404
    );
  }

  if (expired(site)) {
    return json(
      { error: "الحجز غير متاح حالياً" },
      403
    );
  }

  const deposit = await getDepositSettings(env);
  const data = await bodyJSON(request);

  const customerName = String(
    data.customer_name ||
    data.name ||
    ""
  ).trim();

  const customerPhone = String(
    data.customer_phone ||
    data.phone ||
    ""
  ).trim();

  const reservationDate = String(
    data.reservation_date ||
    data.date ||
    ""
  ).trim();

  const reservationTime = String(
    data.reservation_time ||
    data.time ||
    ""
  ).trim();

  const partySize = Number(
    data.party_size ||
    data.guests ||
    0
  );

  const notes = String(data.notes || "").trim();
  const depositProof = String(data.deposit_proof || "");

  if (!customerName || !customerPhone || !reservationDate || !reservationTime || partySize < 1) {
    return json(
      { error: "من فضلك أكمل بيانات الحجز" },
      400
    );
  }

  if (!/^\d{4}-\d{2}-\d{2}$/.test(reservationDate)) {
    return json(
      { error: "تاريخ الحجز غير صحيح" },
      400
    );
  }

  if (!/^\d{2}:\d{2}$/.test(reservationTime)) {
    return json(
      { error: "وقت الحجز غير صحيح" },
      400
    );
  }

  let tableId = data.table_id || null;

  if (tableId) {
    const table = await env.DB
      .prepare(`
        SELECT *
        FROM restaurant_tables
        WHERE id = ?
          AND site_id = ?
          AND status = 'available'
          AND capacity >= ?
      `)
      .bind(
        tableId,
        site.id,
        partySize
      )
      .first();

    if (!table) {
      return json(
        { error: "الترابيزة المختارة غير متاحة" },
        409
      );
    }

    const conflict = await env.DB
      .prepare(`
        SELECT id
        FROM reservations
        WHERE site_id = ?
          AND table_id = ?
          AND reservation_date = ?
          AND reservation_time = ?
          AND status IN ('pending', 'confirmed')
        LIMIT 1
      `)
      .bind(
        site.id,
        tableId,
        reservationDate,
        reservationTime
      )
      .first();

    if (conflict) {
      return json(
        { error: "الترابيزة محجوزة في هذا الموعد" },
        409
      );
    }
  } else {
    const tables = await env.DB
      .prepare(`
        SELECT *
        FROM restaurant_tables
        WHERE site_id = ?
          AND status = 'available'
          AND capacity >= ?
        ORDER BY capacity ASC
      `)
      .bind(site.id, partySize)
      .all();

    for (const table of tables.results || []) {
      const conflict = await env.DB
        .prepare(`
          SELECT id
          FROM reservations
          WHERE site_id = ?
            AND table_id = ?
            AND reservation_date = ?
            AND reservation_time = ?
            AND status IN ('pending', 'confirmed')
          LIMIT 1
        `)
        .bind(
          site.id,
          table.id,
          reservationDate,
          reservationTime
        )
        .first();

      if (!conflict) {
        tableId = table.id;
        break;
      }
    }

    if (!tableId) {
      return json(
        { error: "لا توجد ترابيزة متاحة لهذا الموعد" },
        409
      );
    }
  }

  const depositRequired = Number(deposit?.deposit_enabled || 0) === 1;
  if (depositRequired) {
    if (!depositProof || !/^data:image\/(png|jpe?g|webp);base64,/i.test(depositProof)) return json({error:"صورة إثبات التحويل مطلوبة"},400);
    if (depositProof.length > 1800000) return json({error:"صورة التحويل كبيرة جدًا، اختر صورة أصغر"},413);
  }

  const reservationId = randomToken(16);

  await env.DB
    .prepare(`
      INSERT INTO reservations
      (
        id,
        site_id,
        table_id,
        customer_name,
        customer_phone,
        reservation_date,
        reservation_time,
        party_size,
        notes,
        status,
        deposit_required,
        deposit_amount,
        deposit_proof,
        deposit_status,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)
    `)
    .bind(
      reservationId,
      site.id,
      tableId,
      customerName,
      customerPhone,
      reservationDate,
      reservationTime,
      partySize,
      notes,
      depositRequired ? 1 : 0,
      depositRequired ? Number(deposit.deposit_amount || 0) : 0,
      depositRequired ? depositProof : "",
      depositRequired ? "submitted" : "not_required",
      nowISO(),
      nowISO()
    )
    .run();

  return json(
    {
      ok: true,
      reservation_id: reservationId,
      message: depositRequired ? "تم إرسال طلب الحجز وإثبات التحويل للمراجعة" : "تم إرسال طلب الحجز بنجاح"
    },
    201
  );
}

/* =========================
   RESERVATIONS
========================= */

async function reservationsAPI(request, env, user, id = null) {
  const site = await requireSite(env, user.id);

  if (request.method === "GET") {
    const url = new URL(request.url);

    const date = url.searchParams.get("date");
    const status = url.searchParams.get("status");

    let sql = `
      SELECT
        r.*,
        t.name AS table_name,
        t.capacity AS table_capacity
      FROM reservations r
      LEFT JOIN restaurant_tables t
        ON t.id = r.table_id
      WHERE r.site_id = ?
    `;

    const params = [site.id];

    if (date) {
      sql += " AND r.reservation_date = ?";
      params.push(date);
    }

    if (status) {
      sql += " AND r.status = ?";
      params.push(status);
    }

    sql += `
      ORDER BY
        r.reservation_date ASC,
        r.reservation_time ASC,
        r.created_at DESC
    `;

    const result = await env.DB
      .prepare(sql)
      .bind(...params)
      .all();

    return json({
      reservations: result.results || []
    });
  }

  if (siteExpiredResponse(site)) {
    return siteExpiredResponse(site);
  }

  if (!id) {
    return json(
      { error: "معرف الحجز مطلوب" },
      400
    );
  }

  const reservation = await env.DB
    .prepare(`
      SELECT *
      FROM reservations
      WHERE id = ? AND site_id = ?
    `)
    .bind(id, site.id)
    .first();

  if (!reservation) {
    return json(
      { error: "الحجز غير موجود" },
      404
    );
  }

  if (request.method === "PUT") {
    const data = await bodyJSON(request);

    const allowed = [
      "pending",
      "confirmed",
      "completed",
      "cancelled",
      "rejected"
    ];

    const status = String(
      data.status || reservation.status
    );

    if (!allowed.includes(status)) {
      return json(
        { error: "حالة الحجز غير صحيحة" },
        400
      );
    }

    await env.DB
      .prepare(`
        UPDATE reservations
        SET
          status = ?,
          notes = ?,
          updated_at = ?
        WHERE id = ? AND site_id = ?
      `)
      .bind(
        status,
        data.notes !== undefined
          ? String(data.notes)
          : reservation.notes,
        nowISO(),
        id,
        site.id
      )
      .run();

    return json({ ok: true });
  }

  return json(
    { error: "Method Not Allowed" },
    405
  );
}

/* =========================
   ADMIN
========================= */

async function requireAdmin(request, env) {
  const user = await requireUser(request, env);

  if (user.role !== "admin") {
    throw new Response(
      JSON.stringify({
        error: "غير مصرح"
      }),
      {
        status: 403,
        headers: {
          "content-type": "application/json; charset=UTF-8"
        }
      }
    );
  }

  return user;
}

async function adminSites(request, env) {
  await requireAdmin(request, env);

  const result = await env.DB
    .prepare(`
      SELECT
        s.*,
        u.name AS owner_name,
        u.phone AS owner_phone,
        u.email AS owner_email
      FROM sites s
      JOIN users u ON u.id = s.user_id
      ORDER BY s.created_at DESC
    `)
    .all();

  const sites = (result.results || []).map(site => ({
    ...site,
    days_left: daysLeft(site)
  }));

  return json({ sites });
}

async function adminRenew(request, env, siteId) {
  await requireAdmin(request, env);

  const data = await bodyJSON(request);
  const type = String(
    data.subscription_type ||
    data.type ||
    ""
  );

  if (
    !["3_months", "1_year", "permanent"].includes(type)
  ) {
    return json(
      { error: "نوع الاشتراك غير صحيح" },
      400
    );
  }

  const site = await env.DB
    .prepare("SELECT * FROM sites WHERE id = ?")
    .bind(siteId)
    .first();

  if (!site) {
    return json(
      { error: "المطعم غير موجود" },
      404
    );
  }

  let end = null;

  if (type === "3_months") {
    const base =
      site.subscription_ends_at &&
      new Date(site.subscription_ends_at).getTime() > Date.now()
        ? new Date(site.subscription_ends_at)
        : new Date();

    end = addDays(base, 90);
  }

  if (type === "1_year") {
    const base =
      site.subscription_ends_at &&
      new Date(site.subscription_ends_at).getTime() > Date.now()
        ? new Date(site.subscription_ends_at)
        : new Date();

    end = addDays(base, 365);
  }

  await env.DB
    .prepare(`
      UPDATE sites
      SET
        status = 'active',
        subscription_type = ?,
        subscription_ends_at = ?,
        updated_at = ?
      WHERE id = ?
    `)
    .bind(
      type,
      end,
      nowISO(),
      siteId
    )
    .run();

  return json({
    ok: true,
    site: await env.DB
      .prepare("SELECT * FROM sites WHERE id = ?")
      .bind(siteId)
      .first()
  });
}

async function adminStatus(request, env, siteId) {
  await requireAdmin(request, env);

  const data = await bodyJSON(request);
  const status =
    data.status === "suspended"
      ? "suspended"
      : "active";

  const result = await env.DB
    .prepare(`
      UPDATE sites
      SET status = ?, updated_at = ?
      WHERE id = ?
    `)
    .bind(
      status,
      nowISO(),
      siteId
    )
    .run();

  if (!result.meta?.changes) {
    return json(
      { error: "المطعم غير موجود" },
      404
    );
  }

  return json({
    ok: true,
    status
  });
}

/* =========================
   ADMIN USER STATUS
========================= */

async function adminUserStatus(request, env, userId) {
  const admin = await requireAdmin(request, env);

  if (admin.id === userId) {
    return json(
      { error: "لا يمكنك إيقاف حساب الإدارة الحالي" },
      400
    );
  }

  const data = await bodyJSON(request);

  const status =
    data.status === "suspended"
      ? "suspended"
      : "active";

  const result = await env.DB
    .prepare(`
      UPDATE users
      SET status = ?
      WHERE id = ?
    `)
    .bind(status, userId)
    .run();

  if (!result.meta?.changes) {
    return json(
      { error: "المستخدم غير موجود" },
      404
    );
  }

  return json({
    ok: true,
    status
  });
}

/* =========================
   QR
========================= */

async function qrAPI(request, env, user) {
  const site = await requireSite(env, user.id);

  if (siteExpiredResponse(site)) {
    return siteExpiredResponse(site);
  }

  if (request.method !== "GET") {
    return json(
      { error: "Method Not Allowed" },
      405
    );
  }

  const result = await env.DB
    .prepare(`
      SELECT *
      FROM qr_codes
      WHERE site_id = ?
      ORDER BY created_at DESC
    `)
    .bind(site.id)
    .all();

  return json({
    qr_codes: result.results || []
  });
}

/* =========================
   HEALTH
========================= */

async function health(env) {
  try {
    await env.DB
      .prepare("SELECT 1 AS ok")
      .first();

    return json({
      ok: true,
      service: "maw3ed-platform",
      database: true,
      time: nowISO()
    });
  } catch (error) {
    return json(
      {
        ok: false,
        database: false,
        error: String(error?.message || error)
      },
      500
    );
  }
}

/* =========================
   EXPIRED RESPONSE
========================= */

function siteExpiredResponse(site) {
  if (!site || expired(site)) {
    return json(
      {
        error: "انتهت صلاحية الاشتراك",
        expired: true
      },
      403
    );
  }

  return null;
}

/* =========================
   ROUTER
========================= */

async function apiRouter(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/api/health") {
    return health(env);
  }

  if (path === "/api/register" && request.method === "POST") {
    return register(request, env);
  }

  if (path === "/api/login" && request.method === "POST") {
    return login(request, env);
  }

  if (path === "/api/logout") {
    return logout(request, env);
  }

  if (path === "/api/me") {
    return me(request, env);
  }

  let user;

  try {
    user = await requireUser(request, env);
  } catch (response) {
    return response;
  }

  if (path === "/api/site") {
    try {
      return await siteAPI(request, env, user);
    } catch (error) {
      if (error instanceof Response) return error;
      console.error("MAW3ED apiRouter /api/site ERROR:", error);
      return json({
        error: "تعذر تنفيذ طلب المطعم",
        detail: String(error?.message || error || "Unknown error")
      }, 500);
    }
  }

  if (path === "/api/categories") {
    return categoriesAPI(request, env, user);
  }

  let match = path.match(
    /^\/api\/categories\/([^/]+)$/
  );

  if (match) {
    return categoriesAPI(
      request,
      env,
      user,
      decodeURIComponent(match[1])
    );
  }

  if (path === "/api/menu-items") {
    return menuItemsAPI(request, env, user);
  }

  match = path.match(
    /^\/api\/menu-items\/([^/]+)$/
  );

  if (match) {
    return menuItemsAPI(
      request,
      env,
      user,
      decodeURIComponent(match[1])
    );
  }

  if (path === "/api/tables") {
    return tablesAPI(request, env, user);
  }

  match = path.match(
    /^\/api\/tables\/([^/]+)$/
  );

  if (match) {
    return tablesAPI(
      request,
      env,
      user,
      decodeURIComponent(match[1])
    );
  }

  if (path === "/api/reservations") {
    return reservationsAPI(request, env, user);
  }

  match = path.match(
    /^\/api\/reservations\/([^/]+)$/
  );

  if (match) {
    return reservationsAPI(
      request,
      env,
      user,
      decodeURIComponent(match[1])
    );
  }

  if (path === "/api/qr") {
    return qrAPI(request, env, user);
  }

  if (path === "/api/admin/sites") {
    return adminSites(request, env);
  }

  match = path.match(
    /^\/api\/admin\/site\/([^/]+)\/renew$/
  );

  if (match) {
    return adminRenew(
      request,
      env,
      decodeURIComponent(match[1])
    );
  }

  match = path.match(
    /^\/api\/admin\/site\/([^/]+)\/status$/
  );

  if (match) {
    return adminStatus(
      request,
      env,
      decodeURIComponent(match[1])
    );
  }

  if (path === "/api/admin/deposit-settings") {
    return adminDepositSettings(request, env);
  }

  match = path.match(/^\/api\/admin\/site\/([^/]+)$/);
  if (match) {
    return adminSiteDetail(request, env, decodeURIComponent(match[1]));
  }

  match = path.match(/^\/api\/admin\/site\/([^/]+)\/menu$/);
  if (match) {
    return adminMenu(request, env, decodeURIComponent(match[1]));
  }

  match = path.match(
    /^\/api\/admin\/user\/([^/]+)\/status$/
  );

  if (match) {
    return adminUserStatus(
      request,
      env,
      decodeURIComponent(match[1])
    );
  }

  return json(
    {
      error: "API endpoint not found"
    },
    404
  );
}

/* =========================
   DASHBOARD PAGE
========================= */

function dashboardPage() {
  return `<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>موعد MAW3ED — لوحة التحكم</title>
<style>
:root{
  --bg:#f5f0e8;--card:#fffdf9;--ink:#211d19;--muted:#81786d;
  --line:#e5ddd1;--accent:#b88345;--dark:#211d19;--ok:#28734b;
  --danger:#b33b32;--soft:#f0e8dc;--shadow:0 12px 35px rgba(46,35,25,.07)
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Tahoma,Arial,sans-serif}
button,input,textarea,select{font:inherit}
button{cursor:pointer}
.top{position:sticky;top:0;z-index:30;background:rgba(255,253,249,.94);backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}
.topin{width:min(1180px,calc(100% - 28px));height:72px;margin:auto;display:flex;align-items:center;gap:13px}
.menu-btn{border:1px solid var(--line);background:#fff;border-radius:13px;width:44px;height:44px;font-size:22px}
.brand{display:flex;align-items:center;gap:10px}.mark{width:42px;height:42px;border-radius:13px;background:var(--dark);color:#fff;display:grid;place-items:center;font-size:22px;font-weight:900}.brand strong{display:block;font-size:20px}.brand small{display:block;color:var(--muted);font-size:9px;letter-spacing:1.5px;margin-top:2px}
.wrap{width:min(1180px,calc(100% - 28px));margin:22px auto 45px}
.hero{background:linear-gradient(135deg,#2a241e,#554331);color:#fff;border-radius:28px;padding:30px;box-shadow:var(--shadow)}
.eyebrow{opacity:.72;font-size:12px;font-weight:800;margin-bottom:7px}.hero h1{margin:0;font-size:31px}.hero p{margin:10px 0 18px;color:#e9dfd3;line-height:1.8}.hero-actions{display:flex;gap:9px;flex-wrap:wrap}
.primary,.secondary,.open,.danger-btn,.ghost,.mini{border:0;border-radius:12px;padding:11px 15px;font-weight:800}.primary{background:#fff;color:var(--dark)}.secondary{background:rgba(255,255,255,.12);color:#fff;border:1px solid rgba(255,255,255,.22)}.open{background:var(--dark);color:#fff}.danger-btn{background:#fae8e5;color:var(--danger)}.ghost{background:#f5f0e8;color:var(--ink);border:1px solid var(--line)}.mini{padding:8px 10px;background:#f4eee5;color:var(--ink);font-size:12px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:14px 0}.stat{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:16px;box-shadow:var(--shadow)}.stat span{display:block;color:var(--muted);font-size:12px;margin-bottom:7px}.stat b{font-size:18px}.ok{color:var(--ok)}.bad{color:var(--danger)}
.section{margin-top:18px}.section-title{display:flex;justify-content:space-between;align-items:center;gap:12px}.section-title h2,.section-title h3{margin:0}.section-title p{margin:5px 0 0;color:var(--muted);font-size:12px}
.actions{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:12px}.action{display:block;text-decoration:none;color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:18px;padding:17px;box-shadow:var(--shadow)}.action:hover{transform:translateY(-1px)}.action .ico{font-size:26px;display:block;margin-bottom:12px}.action b{display:block}.action small{display:block;color:var(--muted);line-height:1.6;margin-top:4px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.card{background:var(--card);border:1px solid var(--line);border-radius:22px;padding:20px;box-shadow:var(--shadow)}.card h3{margin:0 0 6px;font-size:18px}.muted{color:var(--muted);line-height:1.8;font-size:13px}
.form{display:grid;gap:10px;margin-top:15px}.form input,.form textarea,.form select{width:100%;border:1px solid #ded5c9;background:#fff;border-radius:13px;padding:12px 13px;outline:none}.form input:focus,.form textarea:focus,.form select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(184,131,69,.1)}.form textarea{min-height:90px;resize:vertical}.check{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--muted);padding:3px 2px}.check input{width:auto}.msg{min-height:22px;margin-top:8px;font-size:13px}.msg.error{color:var(--danger)}.msg.ok{color:var(--ok)}
.field-label{font-weight:800;margin-top:2px}.business-type-box{border:2px solid var(--line);border-radius:18px;padding:14px;background:#fffdf9}.business-type-box .field-label span{display:block;font-size:12px;color:var(--muted);font-weight:500;margin-top:4px}.business-types{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}.business-type{border:2px solid var(--line);background:#fff;border-radius:14px;padding:14px 10px;font-weight:800;display:flex;flex-direction:column;align-items:center;gap:4px;min-height:92px}.business-type strong{font-size:16px}.business-type small{font-size:11px;color:var(--muted);font-weight:500}.business-type.selected{border-color:var(--accent);box-shadow:0 0 0 3px rgba(184,131,69,.15);background:var(--soft)}
.sitebox{display:flex;justify-content:space-between;align-items:center;gap:12px;border:1px solid var(--line);background:#faf7f1;border-radius:16px;padding:13px;margin-top:14px}.site-name{font-weight:900}.slug{color:var(--muted);font-size:11px;word-break:break-all;margin-top:3px}
.empty{padding:25px 15px;text-align:center;border:1px dashed #d8cbbb;border-radius:18px;background:#fbf8f2}.empty .big{font-size:38px}.empty h3{margin:8px 0}.empty p{color:var(--muted);margin:0 0 16px;line-height:1.8}
.list{display:grid;gap:9px;margin-top:14px}.row{border:1px solid var(--line);border-radius:15px;padding:13px;background:#fff}.row-main{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.row strong{font-size:14px}.row-meta{color:var(--muted);font-size:12px;line-height:1.8;margin-top:4px}.row-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}.row-actions button,.row-actions select{border:1px solid var(--line);background:#fff;border-radius:9px;padding:8px 9px;font-size:12px}.badge{display:inline-block;border-radius:999px;padding:5px 8px;font-size:10px;font-weight:900;background:#eee5d8;color:#735329}.badge.ok{background:#e3f2e9;color:var(--ok)}.badge.off{background:#f8e5e2;color:var(--danger)}
.filters{display:grid;grid-template-columns:1fr 1fr auto;gap:8px;margin-top:12px}.filters input,.filters select{border:1px solid var(--line);border-radius:12px;padding:11px;background:#fff}
.drawer-bg{position:fixed;inset:0;background:rgba(0,0,0,.42);z-index:40;display:none}.drawer-bg.show{display:block}.drawer{position:fixed;right:0;top:0;bottom:0;width:min(360px,88vw);background:#fffdf9;z-index:41;transform:translateX(105%);transition:.25s;padding:20px;box-shadow:-20px 0 50px rgba(0,0,0,.15);overflow:auto}.drawer.show{transform:translateX(0)}.drawer-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}.drawer-head h2{margin:0;font-size:20px}.close{border:1px solid var(--line);background:#fff;border-radius:11px;width:40px;height:40px}.nav{display:grid;gap:7px}.nav a,.nav button{border:0;background:#f7f3ec;border-radius:14px;padding:14px;text-align:right;color:var(--ink);font-weight:800;text-decoration:none}.nav a:hover,.nav button:hover{background:#eee5d8}.nav .admin{background:#211d19;color:#fff}.nav .logout{margin-top:8px;background:#f9e9e7;color:var(--danger)}
.admin{margin-top:22px}.admin-head{display:flex;justify-content:space-between;align-items:center;gap:10px}.admin-badge{font-size:11px;background:#eee2d1;color:#775126;padding:7px 10px;border-radius:999px;font-weight:800}.admin-list{display:grid;gap:10px;margin-top:14px}.admin-row{border:1px solid var(--line);border-radius:16px;padding:15px}.admin-row strong{font-size:16px}.admin-meta{color:var(--muted);font-size:12px;line-height:1.8;margin-top:4px}.admin-controls{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}.admin-controls select,.admin-controls button{border:1px solid var(--line);background:#fff;border-radius:10px;padding:9px 10px}.admin-controls .renew{background:var(--dark);color:#fff}.admin-controls .suspend{color:var(--danger)}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:60;display:none;place-items:center;padding:16px}.modal-bg.show{display:grid}.modal{width:min(560px,100%);max-height:90vh;overflow:auto;background:var(--card);border-radius:24px;padding:20px;box-shadow:0 25px 80px rgba(0,0,0,.2)}.modal-head{display:flex;justify-content:space-between;gap:10px;align-items:center}.modal-head h3{margin:0}.modal-close{border:0;background:#f2ede5;border-radius:11px;width:40px;height:40px}.footer{text-align:center;color:#8c8378;font-size:11px;margin-top:28px}
@media(max-width:950px){.stats{grid-template-columns:repeat(2,1fr)}.actions{grid-template-columns:repeat(3,1fr)}.grid{grid-template-columns:1fr}}
@media(max-width:620px){.topin,.wrap{width:min(100% - 20px,1180px)}.topin{height:66px}.brand strong{font-size:18px}.hero{padding:22px;border-radius:23px}.hero h1{font-size:27px}.actions{grid-template-columns:1fr 1fr}.action{min-height:118px;padding:15px}.sitebox{align-items:flex-start;flex-direction:column}.sitebox .open,.sitebox button{width:100%}.filters{grid-template-columns:1fr}.row-main{flex-direction:column}.stats{gap:8px}.stat{padding:13px}}
</style>
</head>
<body>
<header class="top"><div class="topin">
  <button class="menu-btn" onclick="openDrawer()" aria-label="القائمة">☰</button>
  <div class="brand"><div class="mark">م</div><div><strong>موعد MAW3ED</strong><small>RESTAURANT RESERVATIONS</small></div></div>
</div></header>

<main class="wrap">
<section class="hero">
  <div class="eyebrow">لوحة التحكم</div>
  <h1 id="welcome">أهلاً بك 👋</h1>
  <p>إدارة مطعمك أو كافيهك، المنيو، الطاولات والحجوزات من مكان واحد.</p>
  <div class="hero-actions">
    <button class="primary" onclick="document.getElementById('setup').scrollIntoView({behavior:'smooth'})">ابدأ إعداد مطعمك</button>
    <button class="secondary" id="heroOpen" style="display:none" onclick="openSite()">🌐 فتح صفحة المطعم</button>
  </div>
</section>

<section class="stats">
  <div class="stat"><span>حالة المطعم</span><b id="sStatus">—</b></div>
  <div class="stat"><span>الباقة</span><b id="sSub">—</b></div>
  <div class="stat"><span>الأيام المتبقية</span><b id="sDays">—</b></div>
  <div class="stat"><span>الحجوزات</span><b id="sBookings">—</b></div>
</section>

<section class="section">
  <div class="section-title"><div><h2>إدارة مطعمك</h2><p>اختصارات سريعة</p></div></div>
  <div class="actions">
    <a class="action" href="#reservations"><span class="ico">📅</span><b>الحجوزات</b><small>فلترة ومتابعة وتحديث الحالة</small></a>
    <a class="action" href="#restaurant"><span class="ico">✏️</span><b>المطعم</b><small>تعديل بيانات المطعم والرابط</small></a>
    <a class="action" href="#menu"><span class="ico">📋</span><b>Menu</b><small>أقسام وأصناف وأسعار</small></a>
    <a class="action" href="#tables"><span class="ico">🪑</span><b>الطاولات</b><small>إضافة وتعديل وتعطيل وحذف</small></a>
    <a class="action" href="#share"><span class="ico">🔗</span><b>صفحة المطعم</b><small>فتح ونسخ رابط الحجز</small></a>
  </div>
</section>

<section class="section grid" id="setup">
  <div class="card" id="restaurant">
    <h3 id="placeDataTitle">🏪 بيانات المكان <span style="font-size:11px;color:var(--muted);font-weight:500">MAW3ED v2</span></h3>
    <div class="muted" id="restaurantHint">أنشئ بيانات المكان مرة واحدة، وبعدها تقدر تعدّلها في أي وقت.</div>
    <div id="siteView"></div>
    <form class="form" id="siteForm" style="display:none" onsubmit="saveSite(event)">
      <input id="fName" placeholder="اسم المكان" required>
      <div class="business-type-box">
        <div class="field-label">🏪 نوع المكان <span>اختر نوع نشاطك</span></div>
        <div class="business-types" id="businessTypes">
          <button type="button" class="business-type" data-type="restaurant" onclick="selectBusinessType('restaurant')">🍽️ <strong>مطعم</strong><small>مطعم وحجوزات طاولات</small></button>
          <button type="button" class="business-type" data-type="cafe" onclick="selectBusinessType('cafe')">☕ <strong>كافيه</strong><small>كافيه وحجوزات طاولات</small></button>
        </div>
      </div>
      <input id="fPhone" placeholder="رقم الهاتف">
      <input id="fAddress" placeholder="العنوان">
      <input id="fHours" placeholder="مواعيد العمل">
      <textarea id="fDesc" placeholder="نبذة قصيرة عن المكان"></textarea>
      <input id="fLogo" placeholder="رابط الشعار (اختياري)">
      <input id="fCover" placeholder="رابط الغلاف (اختياري)">
      <select id="fDesign"><option value="default">افتراضي</option><option value="modern">مودرن</option><option value="classic">كلاسيك</option><option value="dark">داكن</option></select>
      <button class="open" type="submit">حفظ بيانات المطعم</button>
      <button class="ghost" type="button" onclick="cancelSiteEdit()">إلغاء</button>
      <div id="siteMsg" class="msg"></div>
    </form>
  </div>

  <div class="card" id="share">
    <h3>🌐 صفحة المطعم</h3>
    <div class="muted">هذا هو الرابط الذي سيصل إليه العملاء لمشاهدة المكان والحجز.</div>
    <div class="sitebox">
      <div><div class="site-name" id="shareName">—</div><div class="slug" id="shareUrl">لم يتم إنشاء المطعم بعد</div></div>
      <button class="open" id="copyBtn" style="display:none" onclick="copyUrl()">نسخ الرابط</button>
    </div>
    <button class="open" id="shareOpen" style="display:none;margin-top:10px;width:100%" onclick="openSite()">فتح صفحة المطعم</button>
  </div>
</section>

<section class="section grid">
  <div class="card" id="tables">
    <h3>🪑 الطاولات</h3>
    <div class="muted">أضف الطاولات وحدد السعة. تقدر تعدّلها أو تعطلها لاحقًا.</div>
    <form class="form" onsubmit="addTable(event)">
      <input id="tableName" placeholder="مثال: طاولة 1" required>
      <input id="tableCap" type="number" min="1" max="100" value="4" placeholder="السعة">
      <button class="open" type="submit">+ إضافة طاولة</button>
      <div id="tableMsg" class="msg"></div>
    </form>
    <div id="tablesList" class="list"></div>
  </div>

  <div class="card" id="menu">
    <h3>📋 Menu</h3>
    <div class="muted">أضف الأقسام والأصناف والأسعار والصور، وحدد ما إذا كان الصنف متاحًا للعميل.</div>

    <form class="form" onsubmit="addCategory(event)">
      <input id="categoryName" placeholder="اسم قسم جديد — مثال: بيتزا" required>
      <button class="ghost" type="submit">+ إضافة قسم</button>
      <div id="categoryMsg" class="msg"></div>
    </form>

    <div id="categoriesList" class="list"></div>

    <form class="form" id="itemForm" onsubmit="saveItem(event)">
      <input type="hidden" id="itemId">
      <select id="itemCategory"><option value="">بدون قسم</option></select>
      <input id="itemName" placeholder="اسم الصنف" required>
      <textarea id="itemDesc" placeholder="وصف الصنف"></textarea>
      <input id="itemPrice" type="number" min="0" step="0.01" placeholder="السعر">
      <input id="itemImage" placeholder="رابط صورة الصنف (اختياري)">
      <label class="check"><input id="itemAvailable" type="checkbox" checked> الصنف متاح للطلب</label>
      <button class="open" type="submit" id="itemSaveBtn">+ إضافة صنف</button>
      <button class="ghost" type="button" id="itemCancelBtn" style="display:none" onclick="cancelItemEdit()">إلغاء التعديل</button>
      <div id="itemMsg" class="msg"></div>
    </form>

    <div id="itemsList" class="list"></div>
  </div>
</section>

<section class="section">
  <div class="card" id="reservations">
    <div class="section-title">
      <div><h3>📅 الحجوزات</h3><p>فلترة الحجوزات حسب التاريخ والحالة وتحديثها مباشرة.</p></div>
      <button class="ghost" onclick="loadReservations()">↻ تحديث</button>
    </div>
    <div class="filters">
      <input type="date" id="resDate" onchange="loadReservations()">
      <select id="resStatus" onchange="loadReservations()">
        <option value="">كل الحالات</option>
        <option value="pending">قيد المراجعة</option>
        <option value="confirmed">مؤكد</option>
        <option value="completed">مكتمل</option>
        <option value="cancelled">ملغي</option>
        <option value="rejected">مرفوض</option>
      </select>
      <button class="open" onclick="clearReservationFilters()">مسح الفلاتر</button>
    </div>
    <div id="reservationsList" class="list"><div class="muted">جاري تحميل الحجوزات...</div></div>
  </div>
</section>

<section class="section admin" id="adminSection" style="display:none">
  <div class="card">
    <div class="admin-head">
      <div><h3>🛡️ إدارة المنصة</h3><div class="muted">إدارة المطاعم والاشتراكات وحالة كل مطعم.</div></div>
      <span class="admin-badge">SUPER ADMIN</span>
    </div>
    <div id="adminList" class="admin-list">جاري تحميل المطاعم...</div><div class="card" style="margin-top:14px;background:#fbf8f2"><h3>💳 إعدادات تأمين الحجز</h3><div class="muted">هذه الإعدادات تتحكم فيها الإدارة فقط وتظهر للزبون في صفحة الحجز.</div><form class="form" id="depositForm" onsubmit="saveDeposit(event)"><label class="check"><input id="depEnabled" type="checkbox"> طلب تأمين قبل تأكيد الحجز</label><input id="depAmount" type="number" min="0" step="0.01" placeholder="مبلغ التأمين"><input id="depCurrency" placeholder="العملة — مثال: جنيه"><input id="depMethod" placeholder="طريقة التحويل — مثال: فودافون كاش / تحويل بنكي"><input id="depRecipient" placeholder="اسم المستلم"><input id="depAccount" placeholder="رقم المحفظة / الحساب"><textarea id="depInstructions" placeholder="تعليمات التحويل"></textarea><button class="open" type="submit">حفظ إعدادات التأمين</button><div id="depMsg" class="msg"></div></form></div>
  </div>
</section>

<div class="footer">${PLATFORM_FOOTER}</div>
</main>

<div class="drawer-bg" id="drawerBg" onclick="closeDrawer()"></div>
<aside class="drawer" id="drawer">
  <div class="drawer-head"><h2>القائمة الرئيسية</h2><button class="close" onclick="closeDrawer()">×</button></div>
  <div class="nav">
    <a href="#setup" onclick="closeDrawer()">🏠 الرئيسية</a>
    <a href="#restaurant" onclick="closeDrawer()">🏪 المطعم</a>
    <a href="#menu" onclick="closeDrawer()">📋 Menu</a>
    <a href="#tables" onclick="closeDrawer()">🪑 الطاولات</a>
    <a href="#reservations" onclick="closeDrawer()">📅 الحجوزات</a>
    <a href="#share" onclick="closeDrawer()">🌐 صفحة المطعم</a>
    <button id="adminNav" class="admin" style="display:none" onclick="closeDrawer();document.getElementById('adminSection').scrollIntoView({behavior:'smooth'})">🛡️ إدارة المنصة</button>
    <button class="logout" onclick="logout()">🚪 تسجيل الخروج</button>
  </div>
</aside>

<div class="modal-bg" id="modal">
  <div class="modal">
    <div class="modal-head"><h3 id="modalTitle">تنبيه</h3><button class="modal-close" onclick="closeModal()">×</button></div>
    <div id="modalBody" style="margin-top:12px"></div>
  </div>
</div>

<script>
let ME=null,SITE=null,BASE=location.origin,CATEGORIES=[],ITEMS=[];

const $=id=>document.getElementById(id);
function openDrawer(){$('drawer').classList.add('show');$('drawerBg').classList.add('show')}
function closeDrawer(){$('drawer').classList.remove('show');$('drawerBg').classList.remove('show')}
function modal(title,body){$('modalTitle').textContent=title;$('modalBody').innerHTML=body;$('modal').classList.add('show')}
function closeModal(){$('modal').classList.remove('show')}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function api(url,opt={}){
  const headers={...(opt.headers||{})};
  if(opt.body!==undefined)headers['content-type']='application/json';
  const r=await fetch(url,{credentials:'same-origin',...opt,headers});
  let d={};try{d=await r.json()}catch{}
  if(!r.ok)throw Error(d.error||'تعذر تنفيذ الطلب');
  return d;
}
function statusText(s){return s==='active'?'يعمل':s==='suspended'?'موقوف':'غير متاح'}
function subText(s){if(!s)return '—';return s==='trial'?'تجربة مجانية':s==='3_months'?'3 شهور':s==='1_year'?'سنة':s==='permanent'?'دائم':'—'}
function reservationText(s){return s==='pending'?'قيد المراجعة':s==='confirmed'?'مؤكد':s==='completed'?'مكتمل':s==='cancelled'?'ملغي':s==='rejected'?'مرفوض':s||'—'}
function openSite(){if(SITE?.slug)location.href=BASE+'/r/'+encodeURIComponent(SITE.slug)}
function copyUrl(){
  if(!SITE?.slug)return;
  const u=BASE+'/r/'+encodeURIComponent(SITE.slug);
  navigator.clipboard?.writeText(u).then(()=>{$('copyBtn').textContent='تم النسخ ✓';setTimeout(()=>$('copyBtn').textContent='نسخ الرابط',1400)}).catch(()=>modal('رابط المطعم','<div style="word-break:break-all">'+esc(u)+'</div>'));
}
let selectedBusinessType = "restaurant";
function selectBusinessType(type){
  selectedBusinessType = ["restaurant","cafe"].includes(type) ? type : "restaurant";
  document.querySelectorAll("#businessTypes .business-type").forEach(b => b.classList.toggle("selected", b.dataset.type === selectedBusinessType));
}

function renderSite(){
  if(!SITE){
    $('siteView').innerHTML='<div class="empty"><div class="big">🍽️</div><h3>مكانك لسه ما اتعملش</h3><p>ابدأ بإنشاء المطعم، وبعدها هتقدر تضيف المنيو والطاولات وتستقبل الحجوزات.</p><button class="open" onclick="startCreate()">إنشاء مكاني الآن</button></div>';
    $('siteForm').style.display='none';$('shareName').textContent='—';$('shareUrl').textContent='لم يتم إنشاء المطعم بعد';$('copyBtn').style.display='none';$('shareOpen').style.display='none';$('heroOpen').style.display='none';
    return;
  }
  $('siteView').innerHTML='<div class="sitebox"><div><div class="site-name">'+esc(SITE.name)+'</div><div class="slug">/'+esc(SITE.slug)+'</div></div><button class="open" onclick="editSite()">✏️ تعديل</button></div>';
  $('siteForm').style.display='none';$('shareName').textContent=SITE.name||'—';$('shareUrl').textContent=BASE+'/r/'+encodeURIComponent(SITE.slug);$('copyBtn').style.display='block';$('shareOpen').style.display='block';$('heroOpen').style.display='block';
  $('fName').value=SITE.name||'';selectBusinessType(SITE.business_type||'restaurant');$('fPhone').value=SITE.phone||'';$('fAddress').value=SITE.address||'';$('fHours').value=SITE.working_hours||'';$('fDesc').value=SITE.description||'';$('fLogo').value=SITE.logo_url||'';$('fCover').value=SITE.cover_url||'';$('fDesign').value=SITE.design||'default';
}
function startCreate(){$('siteForm').style.display='grid';$('restaurantHint').textContent='اكتب اسم المكان واحفظ. سننشئ لك رابطًا خاصًا تلقائيًا.';$('fName').focus();$('restaurant').scrollIntoView({behavior:'smooth'})}
function editSite(){$('siteForm').style.display='grid';$('restaurantHint').textContent='عدّل البيانات ثم اضغط حفظ.';$('restaurant').scrollIntoView({behavior:'smooth'})}
function cancelSiteEdit(){renderSite();$('siteMsg').textContent=''}
async function saveSite(e){
  e.preventDefault();
  const msg=$('siteMsg');msg.className='msg';msg.textContent='جارٍ الحفظ...';
  try{
    const body={name:$('fName').value.trim(),business_type:selectedBusinessType,phone:$('fPhone').value.trim(),address:$('fAddress').value.trim(),working_hours:$('fHours').value.trim(),description:$('fDesc').value.trim(),logo_url:$('fLogo').value.trim(),cover_url:$('fCover').value.trim(),design:$('fDesign').value};
    const d=await api('/api/site',{method:SITE?'PUT':'POST',body:JSON.stringify(body)});
    SITE=d.site||d;renderSite();refreshStats();await loadMenu();msg.className='msg ok';msg.textContent='تم حفظ بيانات المطعم ✓';
  }catch(err){msg.className='msg error';msg.textContent=err.message}
}

async function loadTables(){
  if(!SITE){$('tablesList').innerHTML='<div class="muted">أنشئ المطعم أولًا.</div>';return}
  try{
    const d=await api('/api/tables');const rows=d.tables||[];
    if(!rows.length){$('tablesList').innerHTML='<div class="muted">لا توجد طاولات بعد.</div>';return}
    $('tablesList').innerHTML=rows.map(t=>'<div class="row"><div class="row-main"><div><strong>🪑 '+esc(t.name)+'</strong><div class="row-meta">السعة: '+esc(t.capacity)+' أشخاص</div></div><span class="badge '+(t.status==='available'?'ok':'off')+'">'+(t.status==='available'?'متاحة':'معطلة')+'</span></div><div class="row-actions"><button onclick="editTable(\\''+esc(t.id)+'\\')">✏️ تعديل</button><button onclick="toggleTable(\\''+esc(t.id)+'\\',\\''+(t.status==='available'?'disabled':'available')+'\\')">'+(t.status==='available'?'تعطيل':'تشغيل')+'</button><button class="danger-btn" onclick="deleteTable(\\''+esc(t.id)+'\\')">حذف</button></div></div>').join('');
  }catch(err){$('tablesList').innerHTML='<div class="msg error">'+esc(err.message)+'</div>'}
}
async function addTable(e){
  e.preventDefault();$('tableMsg').className='msg';$('tableMsg').textContent='جارٍ الإضافة...';
  try{await api('/api/tables',{method:'POST',body:JSON.stringify({name:$('tableName').value.trim(),capacity:Number($('tableCap').value)})});$('tableName').value='';$('tableCap').value=4;$('tableMsg').className='msg ok';$('tableMsg').textContent='تمت إضافة الطاولة ✓';await loadTables()}catch(err){$('tableMsg').className='msg error';$('tableMsg').textContent=err.message}
}
async function editTable(id){
  const name=prompt('اسم الطاولة الجديد:');if(name===null)return;
  const capacity=prompt('سعة الطاولة:', '4');if(capacity===null)return;
  if(!name.trim()||Number(capacity)<1){modal('بيانات غير صحيحة','اكتب اسمًا وسعة صحيحة للطاولة.');return}
  try{await api('/api/tables/'+encodeURIComponent(id),{method:'PUT',body:JSON.stringify({name:name.trim(),capacity:Number(capacity)})});await loadTables()}catch(err){modal('تعذر تعديل الطاولة',esc(err.message))}
}
async function toggleTable(id,status){
  try{await api('/api/tables/'+encodeURIComponent(id),{method:'PUT',body:JSON.stringify({status})});await loadTables()}catch(err){modal('تعذر تغيير حالة الطاولة',esc(err.message))}
}
async function deleteTable(id){
  if(!confirm('هل تريد حذف هذه الطاولة؟'))return;
  try{await api('/api/tables/'+encodeURIComponent(id),{method:'DELETE'});await loadTables()}catch(err){modal('تعذر حذف الطاولة',esc(err.message))}
}

async function loadMenu(){
  if(!SITE){
    $('categoriesList').innerHTML='<div class="muted">أنشئ المطعم أولًا.</div>';$('itemsList').innerHTML='';return;
  }
  try{
    const [c,i]=await Promise.all([api('/api/categories'),api('/api/menu-items')]);
    CATEGORIES=c.categories||[];ITEMS=i.items||[];renderCategories();fillItemCategories();renderItems();
  }catch(err){
    $('categoriesList').innerHTML='<div class="msg error">'+esc(err.message)+'</div>';
    $('itemsList').innerHTML='';
  }
}
function renderCategories(){
  if(!CATEGORIES.length){$('categoriesList').innerHTML='<div class="muted">لا توجد أقسام. أضف أول قسم للمنيو.</div>';return}
  $('categoriesList').innerHTML=CATEGORIES.map(c=>'<div class="row"><div class="row-main"><div><strong>📂 '+esc(c.name)+'</strong><div class="row-meta">'+ITEMS.filter(i=>i.category_id===c.id).length+' صنف</div></div></div><div class="row-actions"><button onclick="editCategory(\\''+esc(c.id)+'\\')">✏️ تعديل</button><button class="danger-btn" onclick="deleteCategory(\\''+esc(c.id)+'\\')">حذف</button></div></div>').join('');
}
function fillItemCategories(){
  $('itemCategory').innerHTML='<option value="">بدون قسم</option>'+CATEGORIES.map(c=>'<option value="'+esc(c.id)+'">'+esc(c.name)+'</option>').join('');
}
function renderItems(){
  if(!ITEMS.length){$('itemsList').innerHTML='<div class="muted">لا توجد أصناف بعد.</div>';return}
  $('itemsList').innerHTML=ITEMS.map(i=>{
    const cat=i.category_name||CATEGORIES.find(c=>c.id===i.category_id)?.name||'بدون قسم';
    const price=Number(i.price||0).toFixed(2);
    return '<div class="row"><div class="row-main"><div><strong>'+esc(i.name)+'</strong><div class="row-meta">'+esc(cat)+' · '+esc(price)+' جنيه'+(i.description?' · '+esc(i.description):'')+'</div></div><span class="badge '+(Number(i.available)?'ok':'off')+'">'+(Number(i.available)?'متاح':'مخفي')+'</span></div><div class="row-actions"><button onclick="editItem(\\''+esc(i.id)+'\\')">✏️ تعديل</button><button onclick="toggleItem(\\''+esc(i.id)+'\\','+(Number(i.available)?'false':'true')+')">'+(Number(i.available)?'إخفاء':'إظهار')+'</button><button class="danger-btn" onclick="deleteItem(\\''+esc(i.id)+'\\')">حذف</button></div></div>';
  }).join('');
}
async function addCategory(e){
  e.preventDefault();$('categoryMsg').className='msg';$('categoryMsg').textContent='جارٍ الإضافة...';
  try{await api('/api/categories',{method:'POST',body:JSON.stringify({name:$('categoryName').value.trim()})});$('categoryName').value='';$('categoryMsg').className='msg ok';$('categoryMsg').textContent='تمت إضافة القسم ✓';await loadMenu()}catch(err){$('categoryMsg').className='msg error';$('categoryMsg').textContent=err.message}
}
async function editCategory(id){
  const c=CATEGORIES.find(x=>x.id===id);if(!c)return;
  const name=prompt('اسم القسم الجديد:',c.name);if(name===null)return;
  if(!name.trim())return;
  try{await api('/api/categories/'+encodeURIComponent(id),{method:'PUT',body:JSON.stringify({name:name.trim()})});await loadMenu()}catch(err){modal('تعذر تعديل القسم',esc(err.message))}
}
async function deleteCategory(id){
  const c=CATEGORIES.find(x=>x.id===id);if(!c)return;
  if(!confirm('حذف القسم "'+c.name+'"؟ الأصناف ستبقى بدون قسم.'))return;
  try{await api('/api/categories/'+encodeURIComponent(id),{method:'DELETE'});await loadMenu()}catch(err){modal('تعذر حذف القسم',esc(err.message))}
}
function resetItemForm(){
  $('itemId').value='';$('itemCategory').value='';$('itemName').value='';$('itemDesc').value='';$('itemPrice').value='';$('itemImage').value='';$('itemAvailable').checked=true;$('itemSaveBtn').textContent='+ إضافة صنف';$('itemCancelBtn').style.display='none';$('itemMsg').textContent='';
}
function editItem(id){
  const i=ITEMS.find(x=>x.id===id);if(!i)return;
  $('itemId').value=i.id;$('itemCategory').value=i.category_id||'';$('itemName').value=i.name||'';$('itemDesc').value=i.description||'';$('itemPrice').value=i.price??'';$('itemImage').value=i.image_url||'';$('itemAvailable').checked=Number(i.available)!==0;$('itemSaveBtn').textContent='حفظ تعديل الصنف';$('itemCancelBtn').style.display='block';$('itemMsg').textContent='';$('itemName').focus();$('itemForm').scrollIntoView({behavior:'smooth',block:'center'});
}
function cancelItemEdit(){resetItemForm()}
async function saveItem(e){
  e.preventDefault();$('itemMsg').className='msg';$('itemMsg').textContent='جارٍ الحفظ...';
  try{
    const id=$('itemId').value;
    const body={category_id:$('itemCategory').value||null,name:$('itemName').value.trim(),description:$('itemDesc').value,price:Number($('itemPrice').value||0),image_url:$('itemImage').value.trim(),available:$('itemAvailable').checked};
    if(id)await api('/api/menu-items/'+encodeURIComponent(id),{method:'PUT',body:JSON.stringify(body)});
    else await api('/api/menu-items',{method:'POST',body:JSON.stringify(body)});
    resetItemForm();$('itemMsg').className='msg ok';$('itemMsg').textContent='تم حفظ الصنف ✓';await loadMenu();
  }catch(err){$('itemMsg').className='msg error';$('itemMsg').textContent=err.message}
}
async function toggleItem(id,available){
  try{await api('/api/menu-items/'+encodeURIComponent(id),{method:'PUT',body:JSON.stringify({available})});await loadMenu()}catch(err){modal('تعذر تغيير حالة الصنف',esc(err.message))}
}
async function deleteItem(id){
  if(!confirm('هل تريد حذف هذا الصنف؟'))return;
  try{await api('/api/menu-items/'+encodeURIComponent(id),{method:'DELETE'});await loadMenu()}catch(err){modal('تعذر حذف الصنف',esc(err.message))}
}

async function loadReservations(){
  if(!SITE){$('reservationsList').innerHTML='<div class="muted">أنشئ المكان أولًا.</div>';$('sBookings').textContent='0';return}
  try{
    const qs=new URLSearchParams();
    if($('resDate').value)qs.set('date',$('resDate').value);
    if($('resStatus').value)qs.set('status',$('resStatus').value);
    const d=await api('/api/reservations'+(qs.toString()?'?'+qs.toString():''));const rows=d.reservations||[];
    $('sBookings').textContent=String(rows.length);
    if(!rows.length){$('reservationsList').innerHTML='<div class="muted">لا توجد حجوزات مطابقة للفلاتر الحالية.</div>';return}
    $('reservationsList').innerHTML=rows.map(r=>{
      const dt=esc(r.reservation_date||'—')+' '+esc(r.reservation_time||'');
      const badge=r.status==='confirmed'||r.status==='completed'?'ok':(r.status==='cancelled'||r.status==='rejected'?'off':'');
      const proof=r.deposit_proof?'<button onclick="modal(\\'إثبات التحويل\\',\\'<img src=\\\"'+esc(r.deposit_proof)+'\\\" style=\\\"max-width:100%;border-radius:14px\\\">\\')">📷 إثبات التحويل</button>':'';
      return '<div class="row"><div class="row-main"><div><strong>👤 '+esc(r.customer_name||r.name||'عميل')+'</strong><div class="row-meta">📅 '+dt+' · 🪑 '+esc(r.table_name||'بدون طاولة')+' · 👥 '+esc(r.party_size||'—')+'</div>'+(r.customer_phone?'<div class="row-meta">📞 '+esc(r.customer_phone)+'</div>':'')+'</div><span class="badge '+badge+'">'+reservationText(r.status)+'</span></div><div class="row-actions"><select onchange="changeReservation(\\''+esc(r.id)+'\\',this.value)"><option value="pending" '+(r.status==='pending'?'selected':'')+'>قيد المراجعة</option><option value="confirmed" '+(r.status==='confirmed'?'selected':'')+'>مؤكد</option><option value="completed" '+(r.status==='completed'?'selected':'')+'>مكتمل</option><option value="cancelled" '+(r.status==='cancelled'?'selected':'')+'>ملغي</option><option value="rejected" '+(r.status==='rejected'?'selected':'')+'>مرفوض</option></select>'+proof+'</div></div>';
    }).join('');
  }catch(err){$('reservationsList').innerHTML='<div class="msg error">'+esc(err.message)+'</div>'}
}
function clearReservationFilters(){$('resDate').value='';$('resStatus').value='';loadReservations()}
async function changeReservation(id,status){
  try{await api('/api/reservations/'+encodeURIComponent(id),{method:'PUT',body:JSON.stringify({status})});await loadReservations()}catch(err){modal('تعذر تحديث الحجز',esc(err.message))}
}

async function loadAdmin(){
  if(ME?.role!=='admin')return;
  $('adminSection').style.display='block';$('adminNav').style.display='block';
  try{
    const d=await api('/api/admin/sites');const rows=d.sites||[];
    await loadDeposit();
    if(!rows.length){$('adminList').innerHTML='<div class="muted">لا توجد أماكن مسجلة حتى الآن.</div>';return}
    $('adminList').innerHTML=rows.map(s=>'<div class="admin-row"><strong>🏪 '+esc(s.name)+'</strong><div class="admin-meta">المالك: '+esc(s.owner_name||'—')+'<br>البريد: '+esc(s.owner_email||'—')+'<br>النوع: '+(s.business_type==='cafe'?'☕ كافيه':'🍽️ مطعم')+'<br>الحالة: '+esc(statusText(s.status))+' · الاشتراك: '+esc(subText(s.subscription_type))+' · الأيام: '+(s.subscription_type==='permanent'?'∞':(s.days_left??'—'))+'</div><div class="admin-controls"><select id="sub-'+esc(s.id)+'"><option value="3_months">3 شهور</option><option value="1_year">سنة</option><option value="permanent">دائم</option></select><button class="renew" onclick="renewSite(\\''+esc(s.id)+'\\')">تجديد</button><button onclick="editAdminSite(\\''+esc(s.id)+'\\')">تعديل</button><button onclick="editAdminMenu(\\''+esc(s.id)+'\\')">Menu</button><button class="suspend" onclick="toggleSite(\\''+esc(s.id)+'\\',\\''+(s.status==='active'?'suspended':'active')+'\\')">'+(s.status==='active'?'إيقاف':'تشغيل')+'</button></div></div>').join('');
  }catch(err){$('adminList').innerHTML='<div class="msg error">'+esc(err.message)+'</div>'}
}
async function loadDeposit(){try{const d=await api('/api/admin/deposit-settings');const s=d.settings||{};$('depEnabled').checked=Number(s.deposit_enabled)===1;$('depAmount').value=s.deposit_amount||'';$('depCurrency').value=s.deposit_currency||'جنيه';$('depMethod').value=s.deposit_method||'';$('depRecipient').value=s.deposit_recipient||'';$('depAccount').value=s.deposit_account||'';$('depInstructions').value=s.deposit_instructions||''}catch(e){$('depMsg').textContent=e.message}}
async function saveDeposit(e){e.preventDefault();$('depMsg').className='msg';$('depMsg').textContent='جارٍ الحفظ...';try{await api('/api/admin/deposit-settings',{method:'PUT',body:JSON.stringify({deposit_enabled:$('depEnabled').checked,deposit_amount:Number($('depAmount').value||0),deposit_currency:$('depCurrency').value,deposit_method:$('depMethod').value,deposit_recipient:$('depRecipient').value,deposit_account:$('depAccount').value,deposit_instructions:$('depInstructions').value})});$('depMsg').className='msg ok';$('depMsg').textContent='تم حفظ إعدادات التأمين ✓'}catch(e){$('depMsg').className='msg error';$('depMsg').textContent=e.message}}
async function editAdminSite(id){try{const d=await api('/api/admin/site/'+encodeURIComponent(id));const s=d.site;const body='<form id="asf" class="form"><input id="asName" value="'+esc(s.name||'')+'" placeholder="اسم المكان"><select id="asType"><option value="restaurant" '+(s.business_type==='restaurant'?'selected':'')+'>مطعم</option><option value="cafe" '+(s.business_type==='cafe'?'selected':'')+'>كافيه</option></select><input id="asPhone" value="'+esc(s.phone||'')+'" placeholder="الهاتف"><input id="asAddress" value="'+esc(s.address||'')+'" placeholder="العنوان"><input id="asHours" value="'+esc(s.working_hours||'')+'" placeholder="مواعيد العمل"><textarea id="asDesc" placeholder="الوصف">'+esc(s.description||'')+'</textarea><input id="asLogo" value="'+esc(s.logo_url||'')+'" placeholder="رابط الشعار"><input id="asCover" value="'+esc(s.cover_url||'')+'" placeholder="رابط الغلاف"><button type="submit" class="open">حفظ</button></form>';modal('تعديل المكان',body);setTimeout(()=>document.getElementById('asf').onsubmit=async e=>{e.preventDefault();try{await api('/api/admin/site/'+encodeURIComponent(id),{method:'PUT',body:JSON.stringify({name:asName.value,business_type:asType.value,phone:asPhone.value,address:asAddress.value,working_hours:asHours.value,description:asDesc.value,logo_url:asLogo.value,cover_url:asCover.value})});closeModal();await loadAdmin();modal('تم','تم تعديل بيانات المكان ✓')}catch(x){alert(x.message)}},0)}catch(e){modal('خطأ',esc(e.message))}}
async function editAdminMenu(id){try{const d=await api('/api/admin/site/'+encodeURIComponent(id)+'/menu');const rows=(d.items||[]).map(i=>'<div style="border-bottom:1px solid #eee;padding:10px 0"><b>'+esc(i.name)+'</b> — '+Number(i.price||0).toFixed(2)+' جنيه<br><button onclick="adminItemEdit(\\''+esc(id)+'\\',\\''+esc(i.id)+'\\')">تعديل</button></div>').join('');modal('منيو المكان','<div class="muted">يمكنك تعديل الأصناف الحالية.</div><div style="margin-top:10px">'+(rows||'لا توجد أصناف')+'</div>');}catch(e){modal('خطأ',esc(e.message))}}
async function adminItemEdit(siteId,itemId){try{const d=await api('/api/admin/site/'+encodeURIComponent(siteId)+'/menu');const i=(d.items||[]).find(x=>x.id===itemId);if(!i)return;modal('تعديل الصنف','<form id="aif" class="form"><input id="aiName" value="'+esc(i.name||'')+'"><input id="aiPrice" type="number" step="0.01" value="'+Number(i.price||0)+'"><textarea id="aiDesc">'+esc(i.description||'')+'</textarea><input id="aiImage" value="'+esc(i.image_url||'')+'"><label class="check"><input id="aiAvail" type="checkbox" '+(Number(i.available)?'checked':'')+'> متاح</label><button class="open">حفظ</button></form>');setTimeout(()=>document.getElementById('aif').onsubmit=async e=>{e.preventDefault();try{await api('/api/admin/site/'+encodeURIComponent(siteId)+'/menu',{method:'PUT',body:JSON.stringify({type:'item',id:itemId,name:aiName.value,price:Number(aiPrice.value||0),description:aiDesc.value,image_url:aiImage.value,available:aiAvail.checked})});await editAdminMenu(siteId)}catch(x){alert(x.message)}},0)}catch(e){modal('خطأ',esc(e.message))}}

async function renewSite(id){try{const type=$('sub-'+id).value;await api('/api/admin/site/'+encodeURIComponent(id)+'/renew',{method:'POST',body:JSON.stringify({subscription_type:type})});await loadAdmin();modal('تم التجديد','تم تحديث اشتراك المطعم بنجاح ✓')}catch(err){modal('تعذر التجديد',esc(err.message))}}
async function toggleSite(id,status){try{await api('/api/admin/site/'+encodeURIComponent(id)+'/status',{method:'POST',body:JSON.stringify({status})});await loadAdmin()}catch(err){modal('تعذر تغيير الحالة',esc(err.message))}}

function refreshStats(){
  if(!SITE){$('sStatus').textContent='لم يبدأ بعد';$('sStatus').className='';$('sSub').textContent='—';$('sDays').textContent='—';return}
  const expired=SITE.expired===true;
  $('sStatus').textContent=expired?'غير متاح':statusText(SITE.status);$('sStatus').className=expired?'bad':'ok';
  $('sSub').textContent=subText(SITE.subscription_type);$('sDays').textContent=SITE.days_left===null?'∞':String(SITE.days_left??0);
}
async function refresh(){
  try{
    const d=await api('/api/me');ME=d.user;SITE=d.site;
    $('welcome').textContent='أهلاً بك، '+(ME.name||'')+' 👋';
    renderSite();refreshStats();
    await Promise.all([loadTables(),loadMenu(),loadReservations()]);
    if(ME.role==='admin')await loadAdmin();
  }catch(err){
    if(err.message.includes('الدخول'))location.href='/login';
    else modal('حدث خطأ',esc(err.message));
  }
}
async function logout(){try{await api('/api/logout',{method:'POST'});location.href='/login'}catch{location.href='/login'}}
refresh();
</script>
</body>
</html>`;
}

function publicFooter(){ return `<footer style="text-align:center;padding:24px 16px;color:#8c8378;font-size:12px">${PLATFORM_FOOTER}</footer>`; }

async function publicMenuPage(env, slug) {
  try {
    const site=await env.DB.prepare("SELECT * FROM sites WHERE slug=? LIMIT 1").bind(slug).first();
    if(!site) return html("<main dir='rtl' style='font-family:Arial;padding:30px;text-align:center'><h2>المكان غير موجود</h2></main>",404);
    if(expired(site)) return html("<main dir='rtl' style='font-family:Arial;padding:30px;text-align:center'><h2>هذا المكان غير متاح حالياً</h2></main>",403);
    const [cats,items]=await Promise.all([
      env.DB.prepare("SELECT * FROM categories WHERE site_id=? ORDER BY sort_order,created_at").bind(site.id).all(),
      env.DB.prepare("SELECT * FROM menu_items WHERE site_id=? AND available=1 ORDER BY sort_order,created_at").bind(site.id).all()
    ]);
    const categoryMap=new Map((cats.results||[]).map(c=>[c.id,c.name]));
    const grouped={}; for(const i of (items.results||[])){const key=i.category_id||"__general";(grouped[key]??=[]).push(i)}
    const sections=Object.entries(grouped).map(([key,list])=>`<section style="margin-top:22px"><h2 style="font-size:20px">${escapeHtml(categoryMap.get(key)||"منيو")}</h2>${list.map(i=>`<article style="display:flex;gap:12px;padding:14px 0;border-bottom:1px solid #eee;align-items:center">${i.image_url?`<img src="${escapeHtml(i.image_url)}" style="width:76px;height:76px;object-fit:cover;border-radius:16px">`:``}<div style="flex:1"><strong>${escapeHtml(i.name)}</strong>${i.description?`<div style="color:#777;font-size:13px;margin-top:5px">${escapeHtml(i.description)}</div>`:``}</div><b>${Number(i.price||0).toFixed(2)} جنيه</b></article>`).join("")}</section>`).join("");
    const kind=site.business_type==="cafe"?"☕ كافيه":"🍽️ مطعم";
    return html(`<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>منيو ${escapeHtml(site.name)}</title><style>body{margin:0;background:#f7f3ed;color:#211d19;font-family:Arial,sans-serif}.wrap{max-width:760px;margin:auto;background:#fff;min-height:100vh;padding:22px;box-sizing:border-box}.btn{display:block;text-decoration:none;text-align:center;padding:14px;border-radius:14px;background:#211d19;color:#fff;font-weight:800;margin:10px 0}</style></head><body><main class="wrap"><a href="/r/${encodeURIComponent(slug)}" style="text-decoration:none;color:#777">← صفحة المكان</a><h1>منيو</h1><div style="color:#777">${kind} · ${escapeHtml(site.name)}</div>${sections||"<div style='padding:35px 0;text-align:center;color:#777'>لم تتم إضافة أصناف إلى المنيو بعد.</div>"}<a class="btn" href="/book/${encodeURIComponent(slug)}">📅 احجز طاولة</a>${publicFooter()}</main></body></html>`);
  } catch(e){ console.error("PUBLIC MENU PAGE",e); return html("<main dir='rtl' style='font-family:Arial;padding:30px;text-align:center'><h2>تعذر فتح المنيو</h2><p>حاول مرة أخرى.</p></main>",500); }
}

async function publicBookingPage(env, slug) {
  const site=await env.DB.prepare("SELECT * FROM sites WHERE slug=? LIMIT 1").bind(slug).first();
  if(!site) return html("<main dir='rtl' style='font-family:Arial;padding:30px;text-align:center'><h2>المكان غير موجود</h2></main>",404);
  if(expired(site)) return html("<main dir='rtl' style='font-family:Arial;padding:30px;text-align:center'><h2>الحجز غير متاح حالياً</h2></main>",403);
  await ensurePlatformSchema(env); const dep=await getDepositSettings(env);
  const tables=await env.DB.prepare("SELECT id,name,capacity FROM restaurant_tables WHERE site_id=? AND status='available' ORDER BY capacity,name").bind(site.id).all();
  const options=(tables.results||[]).map(t=>`<option value="${escapeHtml(t.id)}">${escapeHtml(t.name)} — ${escapeHtml(t.capacity)} أشخاص</option>`).join("");
  const kind=site.business_type==="cafe"?"☕ كافيه":"🍽️ مطعم";
  const depositHtml=Number(dep?.deposit_enabled||0)?`<div style="background:#fff8eb;border:1px solid #ead4aa;border-radius:16px;padding:15px;margin-top:12px"><b>تأمين لتأكيد الحجز</b><p style="margin:8px 0;color:#6e5b40">المبلغ: ${Number(dep.deposit_amount||0).toFixed(2)} ${escapeHtml(dep.deposit_currency||"جنيه")}<br>طريقة التحويل: ${escapeHtml(dep.deposit_method||"")}<br>اسم المستلم: ${escapeHtml(dep.deposit_recipient||"")}<br>الحساب/الرقم: ${escapeHtml(dep.deposit_account||"")}<br>${escapeHtml(dep.deposit_instructions||"")}</p><label>صورة سكرين شوت التحويل</label><input id="proof" type="file" accept="image/png,image/jpeg,image/webp" required style="display:block;width:100%;margin-top:8px"></div>`:"";
  return html(`<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>حجز — ${escapeHtml(site.name)}</title><style>body{margin:0;background:#f7f3ed;font-family:Arial,sans-serif;color:#211d19}.wrap{max-width:620px;margin:auto;background:#fff;min-height:100vh;padding:22px;box-sizing:border-box}.form{display:grid;gap:10px;margin-top:18px}.form input,.form select,.form textarea{padding:13px;border:1px solid #ddd;border-radius:13px;font:inherit}.btn{border:0;background:#211d19;color:#fff;border-radius:14px;padding:14px;font-weight:800;font:inherit}.msg{margin-top:12px;padding:12px;border-radius:12px}.ok{background:#edf8f0;color:#24643d}.err{background:#fff0ee;color:#a52e24}</style></head><body><main class="wrap"><a href="/r/${encodeURIComponent(slug)}" style="text-decoration:none;color:#777">← ${escapeHtml(site.name)}</a><h1>حجز طاولة</h1><div style="color:#777">${kind}</div>${depositHtml}<form class="form" id="f"><input id="name" placeholder="الاسم" required><input id="phone" placeholder="رقم الهاتف" required><input id="date" type="date" required><input id="time" type="time" required><input id="guests" type="number" min="1" value="2" placeholder="عدد الأشخاص" required><select id="table"><option value="">اختيار الطاولة تلقائيًا</option>${options}</select><textarea id="notes" placeholder="ملاحظات إضافية"></textarea><button class="btn">إرسال طلب الحجز</button><div id="msg"></div></form>${publicFooter()}</main><script>
const f=document.getElementById('f'),msg=document.getElementById('msg');
async function proof(){const el=document.getElementById('proof');if(!el)return '';const file=el.files?.[0];if(!file)return '';if(file.size>1200000)throw Error('اختر صورة أصغر من 1.2 ميجابايت');return await new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(r.result);r.onerror=rej;r.readAsDataURL(file)})}
f.addEventListener('submit',async e=>{e.preventDefault();msg.className='msg';msg.textContent='جارٍ إرسال الحجز...';try{const data={customer_name:document.getElementById('name').value.trim(),customer_phone:document.getElementById('phone').value.trim(),reservation_date:document.getElementById('date').value,reservation_time:document.getElementById('time').value,party_size:Number(document.getElementById('guests').value),table_id:document.getElementById('table').value||null,notes:document.getElementById('notes').value.trim(),deposit_proof:await proof()};const r=await fetch('/api/book/${encodeURIComponent(slug)}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(data)});const d=await r.json();if(!r.ok)throw Error(d.error||'تعذر إرسال الحجز');msg.className='msg ok';msg.textContent=d.message||'تم إرسال الحجز ✓';f.reset()}catch(x){msg.className='msg err';msg.textContent=x.message||'حدث خطأ'}});
</script></body></html>`);
}

/* =========================
   PUBLIC RESTAURANT FALLBACK
========================= */

async function publicRestaurantFallback(env, slug) {
  try {
    const site = await env.DB.prepare(`
      SELECT * FROM sites WHERE slug = ? LIMIT 1
    `).bind(slug).first();

    if (!site) return json({ error: "المطعم غير موجود" }, 404);
    if (expired(site)) {
      return html(`<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(site.name || "المطعم")}</title><body style="font-family:Arial,sans-serif;background:#f7f3ed;padding:30px;text-align:center"><h2>هذا المطعم غير متاح حالياً</h2></body></html>`);
    }

    const d = publicSiteData(site);
    const title = escapeHtml(d.name || "المطعم");
    const desc = escapeHtml(d.description || "");
    const address = escapeHtml(d.address || "");
    const phone = escapeHtml(d.phone || "");
    const logo = d.logo_url ? `<img src="${escapeHtml(d.logo_url)}" alt="${title}" style="width:92px;height:92px;object-fit:cover;border-radius:24px;border:4px solid #fff;box-shadow:0 8px 30px #0002">` : `<div style="font-size:52px">${d.business_type === "cafe" ? "☕" : "🍽️"}</div>`;
    const cover = d.cover_url ? `<div style="height:190px;background:url('${escapeHtml(d.cover_url)}') center/cover"></div>` : `<div style="height:150px;background:linear-gradient(135deg,#222,#8a6a3b)"></div>`;
    return html(`<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>body{margin:0;background:#f7f3ed;color:#201b16;font-family:Arial,sans-serif}.wrap{max-width:760px;margin:auto;background:#fff;min-height:100vh}.cover{position:relative}.logo{position:absolute;right:24px;bottom:-46px}.content{padding:64px 22px 30px}.muted{color:#777}.btn{display:block;text-decoration:none;text-align:center;padding:15px;border-radius:14px;margin:10px 0;font-weight:800}.primary{background:#201b16;color:#fff}.secondary{background:#f0e8dc;color:#201b16}.card{background:#faf8f5;border-radius:18px;padding:18px;margin-top:18px}</style></head><body><main class="wrap"><div class="cover">${cover}<div class="logo">${logo}</div></div><section class="content"><h1>${title}</h1><div class="muted">${d.business_type === "cafe" ? "☕ كافيه" : "🍽️ مطعم"}</div>${desc ? `<p>${desc}</p>` : ""}<a class="btn primary" href="/menu/${encodeURIComponent(slug)}">📖 عرض المنيو</a><a class="btn secondary" href="/book/${encodeURIComponent(slug)}">📅 احجز طاولة</a><div class="card">${address ? `<div>📍 ${address}</div>` : ""}${phone ? `<div style="margin-top:10px">📞 ${phone}</div>` : ""}</div></section>${publicFooter()}</main></body></html>`);
  } catch (error) {
    console.error("MAW3ED public fallback ERROR:", error);
    return json({ error: "تعذر فتح صفحة المطعم", detail: String(error?.message || error || "Unknown error") }, 500);
  }
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;","\"":"&quot;"}[ch]));
}

/* =========================
   STATIC ROUTES
========================= */

async function staticRequest(request, env) {
  const url = new URL(request.url);

  if (request.method === "GET" && url.pathname === "/dashboard") {
    const user = await currentUser(request, env);
    if (!user) return redirect("/login");
    return html(dashboardPage());
  }

  if (request.method !== "GET") {
    return env.ASSETS.fetch(request);
  }

  let match = url.pathname.match(
    /^\/r\/([^/]+)$/
  );

  if (match) {
    const slug = decodeURIComponent(match[1]);
    return publicRestaurantFallback(env, slug);
  }

  match = url.pathname.match(
    /^\/restaurant\/([^/]+)$/
  );

  if (match) {
    const slug = decodeURIComponent(match[1]);
    return publicRestaurantFallback(env, slug);
  }

  match = url.pathname.match(/^\/menu\/([^/]+)$/);
  if (match) return publicMenuPage(env, decodeURIComponent(match[1]));

  match = url.pathname.match(/^\/public-menu\/([^/]+)$/);
  if (match) return publicMenuPage(env, decodeURIComponent(match[1]));

  match = url.pathname.match(/^\/book\/([^/]+)$/);
  if (match) return publicBookingPage(env, decodeURIComponent(match[1]));

  return env.ASSETS.fetch(request);
}

/* =========================
   FETCH
========================= */

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if (url.pathname === "/health") {
        return health(env);
      }

      if (url.pathname.startsWith("/api/public/site/") || url.pathname.startsWith("/api/public/menu/") || url.pathname.startsWith("/api/book/")) {
        await ensurePlatformSchema(env);
      }

      if (url.pathname.startsWith("/api/public/site/")) {
        const slug = decodeURIComponent(
          url.pathname.slice("/api/public/site/".length)
        );

        if (request.method !== "GET") {
          return json(
            { error: "Method Not Allowed" },
            405
          );
        }

        return publicSite(env, slug);
      }

      if (url.pathname.startsWith("/api/public/menu/")) {
        const slug = decodeURIComponent(
          url.pathname.slice("/api/public/menu/".length)
        );

        if (request.method !== "GET") {
          return json(
            { error: "Method Not Allowed" },
            405
          );
        }

        return publicMenu(env, slug);
      }

      if (url.pathname.startsWith("/api/book/")) {
        const slug = decodeURIComponent(
          url.pathname.slice("/api/book/".length)
        );

        return publicBooking(
          request,
          env,
          slug
        );
      }

      if (url.pathname.startsWith("/api/")) {
        return apiRouter(request, env);
      }

      return staticRequest(request, env);

    } catch (error) {
      if (error instanceof Response) {
        return error;
      }

      console.error("MAW3ED ERROR:", error);

      return json(
        {
          error: "حدث خطأ داخلي",
          detail: String(
            error?.message || error
          )
        },
        500
      );
    }
  }
};
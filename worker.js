const COOKIE_NAME = "maw3ed_session";
const SESSION_DAYS = 30;
const TRIAL_DAYS = 14;

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
          status: site.status,
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

async function siteAPI(request, env, user) {
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
        { error: "اسم المطعم مطلوب" },
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
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, 'trial', NULL, ?, ?)
      `)
      .bind(
        id,
        user.id,
        name,
        slug,
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
    const site = await requireSite(env, user.id);
    const data = await bodyJSON(request);

    const name =
      data.name !== undefined
        ? String(data.name).trim()
        : site.name;

    if (!name) {
      return json(
        { error: "اسم المطعم مطلوب" },
        400
      );
    }

    let slug = site.slug;

    if (name !== site.name) {
      slug = await uniqueSlug(
        env.DB,
        name,
        site.id
      );
    }

    await env.DB
      .prepare(`
        UPDATE sites
        SET
          name = ?,
          slug = ?,
          phone = ?,
          address = ?,
          working_hours = ?,
          description = ?,
          logo_url = ?,
          cover_url = ?,
          design = ?,
          updated_at = ?
        WHERE id = ?
      `)
      .bind(
        name,
        slug,
        data.phone !== undefined
          ? String(data.phone)
          : site.phone,
        data.address !== undefined
          ? String(data.address)
          : site.address,
        data.working_hours !== undefined
          ? String(data.working_hours)
          : site.working_hours,
        data.description !== undefined
          ? String(data.description)
          : site.description,
        data.logo_url !== undefined
          ? String(data.logo_url)
          : site.logo_url,
        data.cover_url !== undefined
          ? String(data.cover_url)
          : site.cover_url,
        data.design !== undefined
          ? String(data.design)
          : site.design,
        nowISO(),
        site.id
      )
      .run();

    return json({
      ok: true,
      site: await getSiteForUser(env, user.id)
    });
  }

  return json(
    { error: "Method Not Allowed" },
    405
  );
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

  const notes = String(
    data.notes || ""
  ).trim();

  if (
    !customerName ||
    !customerPhone ||
    !reservationDate ||
    !reservationTime ||
    partySize < 1
  ) {
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
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
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
      nowISO(),
      nowISO()
    )
    .run();

  return json(
    {
      ok: true,
      reservation_id: reservationId,
      message: "تم إرسال طلب الحجز بنجاح"
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

  return json({
    sites: result.results || []
  });
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
    return siteAPI(request, env, user);
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
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>موعد MAW3ED | لوحة التحكم</title>
<style>
:root{--bg:#f5f1e9;--card:#fffdf9;--ink:#201c18;--muted:#756d63;--line:#e9e1d6;--accent:#b88345;--accent2:#8f6030;--dark:#211d19;--ok:#24734b;--danger:#b44336;--shadow:0 16px 45px rgba(35,27,18,.08)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font-family:Arial,Tahoma,sans-serif}button,input,textarea,select{font:inherit}button{cursor:pointer}a{text-decoration:none;color:inherit}
.top{position:sticky;top:0;z-index:20;background:rgba(255,253,249,.94);backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
.topin{width:min(1180px,calc(100% - 28px));margin:auto;height:72px;display:flex;align-items:center;justify-content:space-between;gap:14px}
.brand{display:flex;align-items:center;gap:10px}.mark{width:42px;height:42px;border-radius:13px;background:var(--dark);color:#dcb47e;display:grid;place-items:center;font-size:22px;font-weight:900}.brand strong{font-size:20px}.brand small{display:block;color:var(--muted);font-size:10px;margin-top:2px;letter-spacing:1.6px}
.menu-btn{border:1px solid var(--line);background:#fff;border-radius:13px;width:46px;height:46px;font-size:22px;color:var(--dark)}
.wrap{width:min(1180px,calc(100% - 28px));margin:auto;padding:28px 0 70px}.hero{background:linear-gradient(135deg,#29231f,#171411);color:#fff;border-radius:28px;padding:28px;box-shadow:var(--shadow);position:relative;overflow:hidden}.hero:after{content:"";position:absolute;width:230px;height:230px;border-radius:50%;background:rgba(216,176,111,.12);left:-80px;top:-100px}.hero .eyebrow{color:#dfbd8a;font-size:12px;font-weight:800}.hero h1{margin:8px 0 7px;font-size:32px}.hero p{margin:0;color:#ddd3c8;line-height:1.8}.hero-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px}.primary,.secondary{border:0;border-radius:14px;padding:12px 17px;font-weight:800}.primary{background:#d9ad70;color:#241d17}.secondary{background:rgba(255,255,255,.1);color:#fff;border:1px solid rgba(255,255,255,.16)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:14px}.stat{background:var(--card);border:1px solid var(--line);border-radius:19px;padding:17px;box-shadow:0 8px 25px rgba(35,27,18,.04)}.stat span{display:block;color:var(--muted);font-size:12px;margin-bottom:7px}.stat b{font-size:20px}.stat .ok{color:var(--ok)}.stat .bad{color:var(--danger)}
.section{margin-top:22px}.section-title{display:flex;align-items:end;justify-content:space-between;gap:12px;margin-bottom:12px}.section-title h2{margin:0;font-size:21px}.section-title p{margin:0;color:var(--muted);font-size:12px}
.actions{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}.action{background:var(--card);border:1px solid var(--line);border-radius:19px;padding:18px;min-height:130px;transition:.2s;box-shadow:0 8px 25px rgba(35,27,18,.04)}.action:hover{transform:translateY(-2px);box-shadow:var(--shadow)}.action .ico{font-size:27px}.action b{display:block;margin-top:12px}.action small{display:block;color:var(--muted);margin-top:5px;line-height:1.5}
.grid{display:grid;grid-template-columns:1.2fr .8fr;gap:14px}.card{background:var(--card);border:1px solid var(--line);border-radius:22px;padding:20px;box-shadow:0 8px 25px rgba(35,27,18,.04)}.card h3{margin:0 0 7px}.muted{color:var(--muted);font-size:13px;line-height:1.7}.sitebox{display:flex;align-items:center;justify-content:space-between;gap:15px;padding:14px;background:#f8f3eb;border-radius:16px;margin-top:15px}.site-name{font-size:18px;font-weight:900}.slug{color:var(--muted);font-size:12px;margin-top:4px;word-break:break-all}.open{background:var(--dark);color:#fff;border:0;border-radius:12px;padding:11px 14px;font-weight:800;white-space:nowrap}
.empty{padding:28px 15px;text-align:center;border:1px dashed #d8cbbb;border-radius:18px;background:#fbf8f2}.empty .big{font-size:38px}.empty h3{margin:8px 0}.empty p{color:var(--muted);margin:0 0 16px;line-height:1.8}
.form{display:grid;gap:10px;margin-top:15px}.form input,.form textarea,.form select{width:100%;border:1px solid #ded5c9;background:#fff;border-radius:13px;padding:12px 13px;outline:none}.form input:focus,.form textarea:focus,.form select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(184,131,69,.1)}.form textarea{min-height:90px;resize:vertical}.msg{min-height:22px;margin-top:8px;font-size:13px}.msg.error{color:var(--danger)}.msg.ok{color:var(--ok)}
.drawer-bg{position:fixed;inset:0;background:rgba(0,0,0,.42);z-index:40;display:none}.drawer-bg.show{display:block}.drawer{position:fixed;right:0;top:0;bottom:0;width:min(360px,88vw);background:#fffdf9;z-index:41;transform:translateX(105%);transition:.25s;padding:20px;box-shadow:-20px 0 50px rgba(0,0,0,.15);overflow:auto}.drawer.show{transform:translateX(0)}.drawer-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}.drawer-head h2{margin:0;font-size:20px}.close{border:1px solid var(--line);background:#fff;border-radius:11px;width:40px;height:40px}.nav{display:grid;gap:7px}.nav a,.nav button{border:0;background:#f7f3ec;border-radius:14px;padding:14px;text-align:right;color:var(--ink);font-weight:800}.nav a:hover,.nav button:hover{background:#eee5d8}.nav .admin{background:#211d19;color:#fff}.nav .logout{margin-top:8px;background:#f9e9e7;color:var(--danger)}
.admin{margin-top:22px}.admin-head{display:flex;justify-content:space-between;align-items:center;gap:10px}.admin-badge{font-size:11px;background:#eee2d1;color:#775126;padding:7px 10px;border-radius:999px;font-weight:800}.admin-list{display:grid;gap:10px;margin-top:14px}.admin-row{border:1px solid var(--line);border-radius:16px;padding:15px}.admin-row strong{font-size:16px}.admin-meta{color:var(--muted);font-size:12px;line-height:1.8;margin-top:4px}.admin-controls{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}.admin-controls select,.admin-controls button{border:1px solid var(--line);background:#fff;border-radius:10px;padding:9px 10px}.admin-controls .renew{background:var(--dark);color:#fff}.admin-controls .suspend{color:var(--danger)}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:60;display:none;place-items:center;padding:16px}.modal-bg.show{display:grid}.modal{width:min(520px,100%);background:var(--card);border-radius:24px;padding:20px;box-shadow:0 25px 80px rgba(0,0,0,.2)}.modal-head{display:flex;justify-content:space-between;gap:10px;align-items:center}.modal-head h3{margin:0}.modal-close{border:0;background:#f2ede5;border-radius:11px;width:40px;height:40px}.footer{text-align:center;color:#8c8378;font-size:11px;margin-top:28px}
@media(max-width:900px){.stats{grid-template-columns:repeat(2,1fr)}.actions{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}}
@media(max-width:520px){.topin,.wrap{width:min(100% - 20px,1180px)}.topin{height:66px}.brand strong{font-size:18px}.hero{padding:22px;border-radius:23px}.hero h1{font-size:27px}.stats{grid-template-columns:repeat(2,1fr)}.stat{padding:14px}.actions{grid-template-columns:1fr 1fr}.action{min-height:120px;padding:15px}.sitebox{align-items:flex-start;flex-direction:column}.open{width:100%}}
</style>
</head>
<body>
<header class="top"><div class="topin"><button class="menu-btn" onclick="openDrawer()" aria-label="القائمة">☰</button><div class="brand"><div class="mark">م</div><div><strong>موعد MAW3ED</strong><small>RESTAURANT RESERVATIONS</small></div></div></div></header>

<main class="wrap">
<section class="hero">
<div class="eyebrow">لوحة التحكم</div>
<h1 id="welcome">أهلاً بك 👋</h1>
<p>كل أدوات مطعمك في مكان واحد — الموقع، المنيو، الطاولات والحجوزات.</p>
<div class="hero-actions"><button class="primary" onclick="document.getElementById('setup').scrollIntoView()">ابدأ إعداد مطعمك</button><button class="secondary" id="heroOpen" style="display:none" onclick="openSite()">🌐 فتح صفحة المطعم</button></div>
</section>

<section class="stats">
<div class="stat"><span>حالة المطعم</span><b id="sStatus">—</b></div>
<div class="stat"><span>الباقة</span><b id="sSub">—</b></div>
<div class="stat"><span>الأيام المتبقية</span><b id="sDays">—</b></div>
<div class="stat"><span>الحجوزات</span><b id="sBookings">—</b></div>
</section>

<section class="section"><div class="section-title"><div><h2>إدارة مطعمك</h2><p>اختصارات سريعة لأهم المهام</p></div></div>
<div class="actions">
<a class="action" href="#reservations"><span class="ico">📅</span><b>الحجوزات</b><small>تابع الطلبات وحدّث حالتها</small></a>
<a class="action" href="#restaurant"><span class="ico">✏️</span><b>بيانات المطعم</b><small>عدّل الاسم والهاتف والعنوان</small></a>
<a class="action" href="#menu"><span class="ico">📋</span><b>المنيو</b><small>الأقسام والأصناف والأسعار</small></a>
<a class="action" href="#tables"><span class="ico">🪑</span><b>الطاولات</b><small>السعة وحالة كل طاولة</small></a>
<a class="action" href="#share"><span class="ico">🔗</span><b>صفحة المطعم</b><small>شارك الرابط مع عملائك</small></a>
</div></section>

<section class="section grid" id="setup">
<div class="card" id="restaurant"><h3>🏪 بيانات المطعم</h3><div class="muted" id="restaurantHint">أنشئ بيانات مطعمك مرة واحدة، وبعدها تقدر تعدّلها في أي وقت.</div><div id="siteView"></div><form class="form" id="siteForm" style="display:none" onsubmit="saveSite(event)"><input id="fName" placeholder="اسم المطعم" required><input id="fPhone" placeholder="رقم الهاتف"><input id="fAddress" placeholder="العنوان"><input id="fHours" placeholder="مواعيد العمل"><textarea id="fDesc" placeholder="نبذة قصيرة عن المطعم"></textarea><input id="fLogo" placeholder="رابط الشعار (اختياري)"><button class="open" type="submit">حفظ بيانات المطعم</button><div id="siteMsg" class="msg"></div></form></div>
<div class="card" id="share"><h3>🌐 صفحة المطعم</h3><div class="muted">هذا هو الرابط الذي سيصل إليه العملاء لحجز طاولة.</div><div class="sitebox"><div><div class="site-name" id="shareName">—</div><div class="slug" id="shareUrl">لم يتم إنشاء المطعم بعد</div></div><button class="open" id="copyBtn" style="display:none" onclick="copyUrl()">نسخ الرابط</button></div><button class="open" id="shareOpen" style="display:none;margin-top:10px;width:100%" onclick="openSite()">فتح صفحة المطعم</button></div>
</section>

<section class="section grid">
<div class="card" id="tables"><h3>🪑 الطاولات</h3><div class="muted">أضف الطاولات وحدد عدد الأشخاص لكل طاولة.</div><form class="form" onsubmit="addTable(event)"><input id="tableName" placeholder="مثال: طاولة 1" required><input id="tableCap" type="number" min="1" max="100" value="4" placeholder="السعة"><button class="open" type="submit">+ إضافة طاولة</button></form><div id="tablesList" class="admin-list"></div></div>
<div class="card" id="menu"><h3>📋 المنيو</h3><div class="muted">أضف الأقسام والأصناف من هنا، وستظهر للعميل داخل صفحة المطعم.</div><div class="sitebox"><div><div class="site-name">إدارة المنيو</div><div class="slug">الأقسام والأصناف والأسعار</div></div><button class="open" onclick="showMenuInfo()">فتح الإدارة</button></div><div id="menuInfo" class="muted" style="margin-top:12px"></div></div>
</section>

<section class="section"><div class="card" id="reservations"><div class="section-title"><div><h3>📅 الحجوزات</h3><p>آخر الحجوزات المسجلة على مطعمك</p></div></div><div id="reservationsList" class="muted">جاري تحميل الحجوزات...</div></div></section>

<section class="section admin" id="adminSection" style="display:none"><div class="card"><div class="admin-head"><div><h3>🛡️ إدارة المنصة</h3><div class="muted">من نفس لوحة التحكم تقدر تدير المطاعم والاشتراكات.</div></div><span class="admin-badge">SUPER ADMIN</span></div><div id="adminList" class="admin-list">جاري تحميل المطاعم...</div></div></section>
<div class="footer">موعد MAW3ED — إدارة المطعم والحجوزات بسهولة</div>
</main>

<div class="drawer-bg" id="drawerBg" onclick="closeDrawer()"></div><aside class="drawer" id="drawer"><div class="drawer-head"><h2>القائمة الرئيسية</h2><button class="close" onclick="closeDrawer()">×</button></div><div class="nav"><a href="#setup" onclick="closeDrawer()">🏠 الرئيسية</a><a href="#restaurant" onclick="closeDrawer()">🏪 المطعم</a><a href="#menu" onclick="closeDrawer()">📋 المنيو</a><a href="#tables" onclick="closeDrawer()">🪑 الطاولات</a><a href="#reservations" onclick="closeDrawer()">📅 الحجوزات</a><a href="#share" onclick="closeDrawer()">🌐 صفحة المطعم</a><button id="adminNav" class="admin" style="display:none" onclick="closeDrawer();document.getElementById('adminSection').scrollIntoView()">🛡️ إدارة المنصة</button><button class="logout" onclick="logout()">🚪 تسجيل الخروج</button></div></aside>

<div class="modal-bg" id="modal"><div class="modal"><div class="modal-head"><h3 id="modalTitle">تنبيه</h3><button class="modal-close" onclick="closeModal()">×</button></div><div id="modalBody" class="muted" style="margin-top:12px"></div></div></div>
<script>
let ME=null,SITE=null,BASE=location.origin;
const $=id=>document.getElementById(id);
function openDrawer(){$('drawer').classList.add('show');$('drawerBg').classList.add('show')}function closeDrawer(){$('drawer').classList.remove('show');$('drawerBg').classList.remove('show')}
function modal(title,body){$('modalTitle').textContent=title;$('modalBody').innerHTML=body;$('modal').classList.add('show')}function closeModal(){$('modal').classList.remove('show')}
async function api(url,opt={}){const r=await fetch(url,{credentials:'same-origin',...opt,headers:{'content-type':'application/json',...(opt.headers||{})}});let d={};try{d=await r.json()}catch{}if(!r.ok)throw Error(d.error||'تعذر تنفيذ الطلب');return d}
function statusText(s){return s==='active'?'يعمل':s==='suspended'?'موقوف':'غير متاح'}
function subText(s){if(!s)return '—';return s==='trial'?'تجربة مجانية':s==='3_months'?'3 شهور':s==='1_year'?'سنة':s==='permanent'?'دائم':'—'}
function openSite(){if(SITE?.slug)location.href=BASE+'/restaurant/'+encodeURIComponent(SITE.slug)}
function copyUrl(){if(!SITE?.slug)return;const u=BASE+'/restaurant/'+encodeURIComponent(SITE.slug);navigator.clipboard?.writeText(u).then(()=>{ $('copyBtn').textContent='تم النسخ ✓';setTimeout(()=>$('copyBtn').textContent='نسخ الرابط',1400)}).catch(()=>modal('رابط المطعم','<div style="word-break:break-all">'+u+'</div>'))}
function renderSite(){
 if(!SITE){$('siteView').innerHTML='<div class="empty"><div class="big">🍽️</div><h3>مطعمك لسه ما اتعملش</h3><p>ابدأ بإنشاء مطعمك، وبعدها هتقدر تضيف المنيو والطاولات وتستقبل الحجوزات.</p><button class="open" onclick="startCreate()">إنشاء مطعمي الآن</button></div>';$('siteForm').style.display='none';$('shareName').textContent='—';$('shareUrl').textContent='لم يتم إنشاء المطعم بعد';$('copyBtn').style.display='none';$('shareOpen').style.display='none';$('heroOpen').style.display='none';return}
 $('siteView').innerHTML='<div class="sitebox"><div><div class="site-name">'+esc(SITE.name)+'</div><div class="slug">/'+esc(SITE.slug)+'</div></div><button class="open" onclick="editSite()">✏️ تعديل</button></div>';$('siteForm').style.display='none';$('shareName').textContent=SITE.name;$('shareUrl').textContent=BASE+'/restaurant/'+SITE.slug;$('copyBtn').style.display='block';$('shareOpen').style.display='block';$('heroOpen').style.display='block';
 $('fName').value=SITE.name||'';$('fPhone').value=SITE.phone||'';$('fAddress').value=SITE.address||'';$('fHours').value=SITE.working_hours||'';$('fDesc').value=SITE.description||'';$('fLogo').value=SITE.logo_url||'';
}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function startCreate(){ $('siteForm').style.display='grid'; $('fName').focus(); $('restaurantHint').textContent='اكتب اسم المطعم واحفظ. سننشئ لك رابطًا خاصًا تلقائيًا.';document.getElementById('restaurant').scrollIntoView({behavior:'smooth'}) }
function editSite(){ $('siteForm').style.display='grid';$('restaurantHint').textContent='عدّل البيانات ثم اضغط حفظ. الرابط المختصر يتحدث تلقائيًا إذا تغيّر اسم المطعم.';document.getElementById('restaurant').scrollIntoView({behavior:'smooth'}) }
async function saveSite(e){e.preventDefault();const msg=$('siteMsg');msg.className='msg';msg.textContent='جارٍ الحفظ...';try{const body={name:$('fName').value,phone:$('fPhone').value,address:$('fAddress').value,working_hours:$('fHours').value,description:$('fDesc').value,logo_url:$('fLogo').value};const d=await api('/api/site',{method:SITE?'PUT':'POST',body:JSON.stringify(body)});SITE=d.site;msg.className='msg ok';msg.textContent='تم حفظ بيانات المطعم بنجاح ✓';renderSite();await refresh();setTimeout(()=>{msg.textContent=''},1800)}catch(err){msg.className='msg error';msg.textContent=err.message}}
async function addTable(e){e.preventDefault();if(!SITE)return modal('أنشئ المطعم أولاً','أنشئ مطعمك ثم أضف الطاولات.');try{await api('/api/tables',{method:'POST',body:JSON.stringify({name:$('tableName').value,capacity:Number($('tableCap').value)})});$('tableName').value='';await loadTables()}catch(err){modal('تعذر إضافة الطاولة',esc(err.message))}}
async function loadTables(){if(!SITE){$('tablesList').innerHTML='<div class="muted">أنشئ المطعم أولاً.</div>';return}try{const d=await api('/api/tables');if(!d.tables?.length){$('tablesList').innerHTML='<div class="muted">لا توجد طاولات حتى الآن.</div>';return}$('tablesList').innerHTML=d.tables.map(t=>'<div class="admin-row"><strong>🪑 '+esc(t.name)+'</strong><div class="admin-meta">السعة: '+t.capacity+' أشخاص · الحالة: '+(t.status==='available'?'متاحة':'غير متاحة')+'</div></div>').join('')}catch(err){$('tablesList').innerHTML='<div class="msg error">'+esc(err.message)+'</div>'}}
async function loadReservations(){if(!SITE){$('reservationsList').innerHTML='أنشئ المطعم أولاً.';return}try{const d=await api('/api/reservations');const rows=d.reservations||[];$('sBookings').textContent=rows.length?String(rows.length):'0';if(!rows.length){$('reservationsList').innerHTML='<div class="empty"><div class="big">📅</div><h3>لسه مفيش حجوزات</h3><p>أول ما العملاء يبدأوا الحجز، هتظهر الطلبات هنا.</p></div>';return}$('reservationsList').innerHTML=rows.slice(0,12).map(r=>'<div class="admin-row"><strong>'+esc(r.customer_name)+'</strong><div class="admin-meta">'+esc(r.reservation_date)+' · '+esc(r.reservation_time)+' · '+r.party_size+' أشخاص · '+esc(r.table_name||'طاولة تلقائية')+'<br>الهاتف: '+esc(r.customer_phone)+'</div><div class="admin-controls"><select onchange="changeReservation(\''+r.id+'\',this.value)"><option value="pending" '+(r.status==='pending'?'selected':'')+'>قيد المراجعة</option><option value="confirmed" '+(r.status==='confirmed'?'selected':'')+'>مؤكد</option><option value="completed" '+(r.status==='completed'?'selected':'')+'>مكتمل</option><option value="cancelled" '+(r.status==='cancelled'?'selected':'')+'>ملغي</option><option value="rejected" '+(r.status==='rejected'?'selected':'')+'>مرفوض</option></select></div></div>').join('')}catch(err){$('reservationsList').innerHTML='<div class="msg error">'+esc(err.message)+'</div>'}}
async function changeReservation(id,status){try{await api('/api/reservations/'+encodeURIComponent(id),{method:'PUT',body:JSON.stringify({status})});await loadReservations()}catch(err){modal('تعذر تحديث الحجز',esc(err.message))}}
function showMenuInfo(){if(!SITE){modal('المنيو','أنشئ مطعمك أولاً، وبعدها نفتح لك إدارة الأقسام والأصناف.');return}modal('إدارة المنيو','المنيو مرتبطة بمطعمك وجاهزة للربط مع صفحة المطعم. تقدر تضيف الأقسام والأصناف من لوحة المنيو عند تجهيز واجهة المنيو.');}
async function loadAdmin(){if(ME?.role!=='admin')return;$('adminSection').style.display='block';$('adminNav').style.display='block';try{const d=await api('/api/admin/sites');const rows=d.sites||[];if(!rows.length){$('adminList').innerHTML='<div class="muted">لا توجد مطاعم مسجلة حتى الآن.</div>';return}$('adminList').innerHTML=rows.map(s=>'<div class="admin-row"><strong>🏪 '+esc(s.name)+'</strong><div class="admin-meta">صاحب المطعم: '+esc(s.owner_name||'—')+'<br>البريد: '+esc(s.owner_email||'—')+'<br>الحالة: '+esc(statusText(s.status))+' · الاشتراك: '+esc(subText(s.subscription_type))+' · الأيام: '+(s.subscription_type==='permanent'?'∞':(s.days_left??'—'))+'</div><div class="admin-controls"><select id="sub-'+s.id+'"><option value="3_months">3 شهور</option><option value="1_year">سنة</option><option value="permanent">دائم</option></select><button class="renew" onclick="renewSite(\''+s.id+'\')">تجديد</button><button class="suspend" onclick="toggleSite(\''+s.id+'\',\''+(s.status==='active'?'suspended':'active')+'\')">'+(s.status==='active'?'إيقاف':'تشغيل')+'</button></div></div>').join('')}catch(err){$('adminList').innerHTML='<div class="msg error">'+esc(err.message)+'</div>'}}
async function renewSite(id){try{const type=$('sub-'+id).value;await api('/api/admin/site/'+encodeURIComponent(id)+'/renew',{method:'POST',body:JSON.stringify({subscription_type:type})});await loadAdmin();modal('تم التجديد','تم تحديث اشتراك المطعم بنجاح ✓')}catch(err){modal('تعذر التجديد',esc(err.message))}}
async function toggleSite(id,status){try{await api('/api/admin/site/'+encodeURIComponent(id)+'/status',{method:'POST',body:JSON.stringify({status})});await loadAdmin()}catch(err){modal('تعذر تغيير الحالة',esc(err.message))}}
function refreshStats(){if(!SITE){$('sStatus').textContent='لم يبدأ بعد';$('sStatus').className='';$('sSub').textContent='—';$('sDays').textContent='—';return}const expired=SITE.expired===true;$('sStatus').textContent=expired?'غير متاح':statusText(SITE.status);$('sStatus').className=expired?'bad':'ok';$('sSub').textContent=subText(SITE.subscription_type);$('sDays').textContent=SITE.days_left===null?'∞':String(SITE.days_left??0)}
async function refresh(){try{const d=await api('/api/me');ME=d.user;SITE=d.site; $('welcome').textContent='أهلاً بك، '+(ME.name||'')+' 👋';renderSite();refreshStats();await Promise.all([loadTables(),loadReservations()]);if(ME.role==='admin')await loadAdmin()}catch(err){if(err.message.includes('الدخول'))location.href='/login';else modal('حدث خطأ',esc(err.message))}}
async function logout(){try{await api('/api/logout',{method:'POST'});location.href='/login'}catch{location.href='/login'}}
refresh();
</script>
</body></html>`;
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
    url.pathname = "/restaurant.html";
    url.search = `?slug=${encodeURIComponent(
      decodeURIComponent(match[1])
    )}`;

    return env.ASSETS.fetch(
      new Request(url.toString(), request)
    );
  }

  match = url.pathname.match(
    /^\/restaurant\/([^/]+)$/
  );

  if (match) {
    url.pathname = "/restaurant.html";
    url.search = `?slug=${encodeURIComponent(
      decodeURIComponent(match[1])
    )}`;

    return env.ASSETS.fetch(
      new Request(url.toString(), request)
    );
  }

  match = url.pathname.match(
    /^\/menu\/([^/]+)$/
  );

  if (match) {
    url.pathname = "/public-menu.html";
    url.search = `?slug=${encodeURIComponent(
      decodeURIComponent(match[1])
    )}`;

    return env.ASSETS.fetch(
      new Request(url.toString(), request)
    );
  }

  match = url.pathname.match(
    /^\/public-menu\/([^/]+)$/
  );

  if (match) {
    url.pathname = "/public-menu.html";
    url.search = `?slug=${encodeURIComponent(
      decodeURIComponent(match[1])
    )}`;

    return env.ASSETS.fetch(
      new Request(url.toString(), request)
    );
  }

  match = url.pathname.match(
    /^\/book\/([^/]+)$/
  );

  if (match) {
    url.pathname = "/booking.html";
    url.search = `?slug=${encodeURIComponent(
      decodeURIComponent(match[1])
    )}`;

    return env.ASSETS.fetch(
      new Request(url.toString(), request)
    );
  }

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
      console.error("MAW3ED ERROR:", error);

      if (error instanceof Response) {
        return error;
      }

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
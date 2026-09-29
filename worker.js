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
        u.role,
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
   STATIC ROUTES
========================= */

async function staticRequest(request, env) {
  const url = new URL(request.url);

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
const COOKIE_NAME = "maw3ed_session";
const SESSION_DAYS = 30;
const TRIAL_DAYS = 14;

const enc = new TextEncoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
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

function redirect(url) {
  return new Response(null, {
    status: 302,
    headers: { Location: url }
  });
}

async function sha256(value) {
  const buffer = await crypto.subtle.digest(
    "SHA-256",
    enc.encode(value)
  );

  return [...new Uint8Array(buffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomToken(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);

  return [...data]
    .map(b => b.toString(16).padStart(2, "0"))
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
      iterations: 120000,
      hash: "SHA-256"
    },
    key,
    256
  );

  const hash = [...new Uint8Array(bits)]
    .map(b => b.toString(16).padStart(2, "0"))
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
      iterations: 120000,
      hash: "SHA-256"
    },
    key,
    256
  );

  const actual = [...new Uint8Array(bits)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  return actual === expected;
}

function cookieValue(request) {
  const header = request.headers.get("Cookie") || "";

  for (const part of header.split(";")) {
    const [name, ...rest] = part.trim().split("=");

    if (name === COOKIE_NAME) {
      return rest.join("=");
    }
  }

  return null;
}

function setSessionCookie(token) {
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}

function clearSessionCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function slugifyArabic(value) {
  const cleaned = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, "-")
    .replace(/^-+|-+$/g, "");

  return cleaned || `restaurant-${randomToken(5)}`;
}

async function uniqueSlug(db, name) {
  let base = slugifyArabic(name);
  let slug = base;
  let counter = 2;

  while (true) {
    const found = await db
      .prepare("SELECT id FROM sites WHERE slug = ? LIMIT 1")
      .bind(slug)
      .first();

    if (!found) return slug;

    slug = `${base}-${counter++}`;
  }
}

function addDays(date, days) {
  const d = new Date(date);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString();
}

function isExpired(site) {
  if (!site) return true;

  if (site.status !== "active") return true;

  if (site.subscription_type === "permanent") {
    return false;
  }

  if (site.subscription_ends_at) {
    return new Date(site.subscription_ends_at) <= new Date();
  }

  if (site.trial_ends_at) {
    return new Date(site.trial_ends_at) <= new Date();
  }

  return true;
}

async function currentUser(request, env) {
  const token = cookieValue(request);

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
        s.id AS session_id,
        s.expires_at
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
      LIMIT 1
    `)
    .bind(tokenHash)
    .first();

  if (!row) return null;

  if (row.status !== "active") return null;

  if (new Date(row.expires_at) <= new Date()) {
    await env.DB
      .prepare("DELETE FROM sessions WHERE id = ?")
      .bind(row.session_id)
      .run();

    return null;
  }

  return {
    id: row.id,
    name: row.name,
    phone: row.phone,
    email: row.email,
    role: row.role
  };
}

async function requireUser(request, env) {
  const user = await currentUser(request, env);

  if (!user) {
    return {
      error: json(
        {
          ok: false,
          error: "يجب تسجيل الدخول أولًا"
        },
        401
      )
    };
  }

  return { user };
}

async function getSiteForUser(env, userId) {
  return env.DB
    .prepare(`
      SELECT *
      FROM sites
      WHERE user_id = ?
      LIMIT 1
    `)
    .bind(userId)
    .first();
}

async function handleRegister(request, env) {
  let data;

  try {
    data = await request.json();
  } catch {
    return json({ ok: false, error: "بيانات غير صحيحة" }, 400);
  }

  const name = String(data.name || "").trim();
  const phone = String(data.phone || "").trim();
  const email = String(data.email || "").trim().toLowerCase();
  const password = String(data.password || "");

  if (!name || !phone || !email || !password) {
    return json(
      {
        ok: false,
        error: "جميع البيانات المطلوبة يجب إدخالها"
      },
      400
    );
  }

  if (password.length < 6) {
    return json(
      {
        ok: false,
        error: "كلمة المرور يجب ألا تقل عن 6 أحرف"
      },
      400
    );
  }

  const duplicate = await env.DB
    .prepare(`
      SELECT id
      FROM users
      WHERE email = ? OR phone = ?
      LIMIT 1
    `)
    .bind(email, phone)
    .first();

  if (duplicate) {
    return json(
      {
        ok: false,
        error: "البريد الإلكتروني أو رقم الهاتف مستخدم بالفعل"
      },
      409
    );
  }

  const countRow = await env.DB
    .prepare("SELECT COUNT(*) AS count FROM users")
    .first();

  const role = Number(countRow?.count || 0) === 0
    ? "admin"
    : "customer";

  const passwordHash = await hashPassword(password);

  const result = await env.DB
    .prepare(`
      INSERT INTO users
        (name, phone, email, password_hash, role)
      VALUES
        (?, ?, ?, ?, ?)
    `)
    .bind(
      name,
      phone,
      email,
      passwordHash,
      role
    )
    .run();

  return json({
    ok: true,
    user_id: result.meta.last_row_id,
    role
  }, 201);
}

async function handleLogin(request, env) {
  let data;

  try {
    data = await request.json();
  } catch {
    return json({ ok: false, error: "بيانات غير صحيحة" }, 400);
  }

  const identifier = String(data.identifier || "").trim();
  const password = String(data.password || "");

  if (!identifier || !password) {
    return json(
      {
        ok: false,
        error: "أدخل البريد أو الهاتف وكلمة المرور"
      },
      400
    );
  }

  const user = await env.DB
    .prepare(`
      SELECT *
      FROM users
      WHERE email = ? OR phone = ?
      LIMIT 1
    `)
    .bind(identifier.toLowerCase(), identifier)
    .first();

  if (!user) {
    return json(
      {
        ok: false,
        error: "بيانات الدخول غير صحيحة"
      },
      401
    );
  }

  if (user.status !== "active") {
    return json(
      {
        ok: false,
        error: "الحساب موقوف"
      },
      403
    );
  }

  const valid = await verifyPassword(
    password,
    user.password_hash
  );

  if (!valid) {
    return json(
      {
        ok: false,
        error: "بيانات الدخول غير صحيحة"
      },
      401
    );
  }

  const token = randomToken(32);
  const tokenHash = await sha256(token);
  const expiresAt = addDays(new Date(), SESSION_DAYS);

  await env.DB
    .prepare(`
      INSERT INTO sessions
        (user_id, token_hash, expires_at)
      VALUES
        (?, ?, ?)
    `)
    .bind(
      user.id,
      tokenHash,
      expiresAt
    )
    .run();

  return new Response(
    JSON.stringify({
      ok: true,
      user: {
        id: user.id,
        name: user.name,
        phone: user.phone,
        email: user.email,
        role: user.role
      }
    }),
    {
      status: 200,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store",
        "Set-Cookie": setSessionCookie(token)
      }
    }
  );
}

async function handleLogout(request, env) {
  const token = cookieValue(request);

  if (token) {
    const tokenHash = await sha256(token);

    await env.DB
      .prepare("DELETE FROM sessions WHERE token_hash = ?")
      .bind(tokenHash)
      .run();
  }

  return new Response(
    JSON.stringify({ ok: true }),
    {
      status: 200,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "Set-Cookie": clearSessionCookie()
      }
    }
  );
}

async function handleMe(request, env) {
  const user = await currentUser(request, env);

  if (!user) {
    return json({
      ok: true,
      authenticated: false
    });
  }

  const site = await getSiteForUser(env, user.id);

  return json({
    ok: true,
    authenticated: true,
    user,
    site: site || null
  });
}

async function handleCreateSite(request, env, user) {
  const existing = await getSiteForUser(env, user.id);

  if (existing) {
    return json(
      {
        ok: false,
        error: "لديك مطعم بالفعل"
      },
      409
    );
  }

  let data;

  try {
    data = await request.json();
  } catch {
    return json({ ok: false, error: "بيانات غير صحيحة" }, 400);
  }

  const name = String(data.name || "").trim();

  if (!name) {
    return json(
      {
        ok: false,
        error: "اسم المطعم مطلوب"
      },
      400
    );
  }

  const slug = await uniqueSlug(env.DB, name);

  const now = new Date();
  const trialEnds = addDays(now, TRIAL_DAYS);

  const result = await env.DB
    .prepare(`
      INSERT INTO sites
        (
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
          subscription_type
        )
      VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, 'trial')
    `)
    .bind(
      user.id,
      name,
      slug,
      String(data.phone || "").trim() || null,
      String(data.address || "").trim() || null,
      String(data.working_hours || "").trim() || null,
      String(data.description || "").trim() || null,
      String(data.logo_url || "").trim() || null,
      String(data.cover_url || "").trim() || null,
      String(data.design || "design-01"),
      now.toISOString(),
      trialEnds
    )
    .run();

  return json({
    ok: true,
    site: {
      id: result.meta.last_row_id,
      name,
      slug,
      trial_ends_at: trialEnds
    }
  }, 201);
}

async function handleUpdateSite(request, env, user) {
  const site = await getSiteForUser(env, user.id);

  if (!site) {
    return json(
      {
        ok: false,
        error: "لم يتم إنشاء المطعم بعد"
      },
      404
    );
  }

  if (isExpired(site)) {
    return json(
      {
        ok: false,
        error: "انتهت مدة الاشتراك أو التجربة"
      },
      403
    );
  }

  let data;

  try {
    data = await request.json();
  } catch {
    return json({ ok: false, error: "بيانات غير صحيحة" }, 400);
  }

  const name = String(data.name ?? site.name).trim();

  if (!name) {
    return json(
      {
        ok: false,
        error: "اسم المطعم مطلوب"
      },
      400
    );
  }

  await env.DB
    .prepare(`
      UPDATE sites
      SET
        name = ?,
        phone = ?,
        address = ?,
        working_hours = ?,
        description = ?,
        logo_url = ?,
        cover_url = ?,
        design = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND user_id = ?
    `)
    .bind(
      name,
      String(data.phone ?? site.phone ?? "").trim() || null,
      String(data.address ?? site.address ?? "").trim() || null,
      String(data.working_hours ?? site.working_hours ?? "").trim() || null,
      String(data.description ?? site.description ?? "").trim() || null,
      String(data.logo_url ?? site.logo_url ?? "").trim() || null,
      String(data.cover_url ?? site.cover_url ?? "").trim() || null,
      String(data.design ?? site.design ?? "design-01"),
      site.id,
      user.id
    )
    .run();

  return json({
    ok: true,
    site: await getSiteForUser(env, user.id)
  });
}

async function handlePublicSite(request, env, slug) {
  const site = await env.DB
    .prepare(`
      SELECT
        id,
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
        trial_ends_at,
        subscription_type,
        subscription_ends_at
      FROM sites
      WHERE slug = ?
      LIMIT 1
    `)
    .bind(slug)
    .first();

  if (!site) {
    return json(
      {
        ok: false,
        error: "المطعم غير موجود"
      },
      404
    );
  }

  if (isExpired(site)) {
    return json(
      {
        ok: false,
        error: "هذا الموقع غير متاح حاليًا"
      },
      403
    );
  }

  const categories = await env.DB
    .prepare(`
      SELECT *
      FROM categories
      WHERE site_id = ?
      ORDER BY sort_order ASC, id ASC
    `)
    .bind(site.id)
    .all();

  const items = await env.DB
    .prepare(`
      SELECT *
      FROM menu_items
      WHERE site_id = ? AND available = 1
      ORDER BY sort_order ASC, id ASC
    `)
    .bind(site.id)
    .all();

  const tables = await env.DB
    .prepare(`
      SELECT id, name, capacity
      FROM restaurant_tables
      WHERE site_id = ? AND status = 'available'
      ORDER BY id ASC
    `)
    .bind(site.id)
    .all();

  return json({
    ok: true,
    site,
    categories: categories.results || [],
    menu_items: items.results || [],
    tables: tables.results || []
  });
}

async function handleCreateCategory(request, env, user) {
  const site = await getSiteForUser(env, user.id);

  if (!site || isExpired(site)) {
    return json(
      {
        ok: false,
        error: "الموقع غير متاح"
      },
      403
    );
  }

  const data = await request.json();
  const name = String(data.name || "").trim();

  if (!name) {
    return json(
      {
        ok: false,
        error: "اسم القسم مطلوب"
      },
      400
    );
  }

  const result = await env.DB
    .prepare(`
      INSERT INTO categories
        (site_id, name, sort_order)
      VALUES
        (?, ?, ?)
    `)
    .bind(
      site.id,
      name,
      Number(data.sort_order || 0)
    )
    .run();

  return json({
    ok: true,
    id: result.meta.last_row_id
  }, 201);
}

async function handleCreateMenuItem(request, env, user) {
  const site = await getSiteForUser(env, user.id);

  if (!site || isExpired(site)) {
    return json(
      {
        ok: false,
        error: "الموقع غير متاح"
      },
      403
    );
  }

  const data = await request.json();

  const name = String(data.name || "").trim();
  const price = Number(data.price);

  if (!name) {
    return json(
      {
        ok: false,
        error: "اسم الصنف مطلوب"
      },
      400
    );
  }

  if (!Number.isFinite(price) || price < 0) {
    return json(
      {
        ok: false,
        error: "السعر غير صحيح"
      },
      400
    );
  }

  const categoryId = data.category_id
    ? Number(data.category_id)
    : null;

  const result = await env.DB
    .prepare(`
      INSERT INTO menu_items
        (
          site_id,
          category_id,
          name,
          description,
          price,
          image_url,
          sort_order,
          available
        )
      VALUES
        (?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .bind(
      site.id,
      categoryId,
      name,
      String(data.description || "").trim() || null,
      price,
      String(data.image_url || "").trim() || null,
      Number(data.sort_order || 0),
      data.available === false ? 0 : 1
    )
    .run();

  return json({
    ok: true,
    id: result.meta.last_row_id
  }, 201);
}

async function handleCreateTable(request, env, user) {
  const site = await getSiteForUser(env, user.id);

  if (!site || isExpired(site)) {
    return json(
      {
        ok: false,
        error: "الموقع غير متاح"
      },
      403
    );
  }

  const data = await request.json();

  const name = String(data.name || "").trim();
  const capacity = Number(data.capacity);

  if (!name || !Number.isInteger(capacity) || capacity < 1) {
    return json(
      {
        ok: false,
        error: "اسم الترابيزة والسعة مطلوبان"
      },
      400
    );
  }

  const result = await env.DB
    .prepare(`
      INSERT INTO restaurant_tables
        (site_id, name, capacity)
      VALUES
        (?, ?, ?)
    `)
    .bind(
      site.id,
      name,
      capacity
    )
    .run();

  return json({
    ok: true,
    id: result.meta.last_row_id
  }, 201);
}

async function handleCreateReservation(request, env, slug) {
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
      {
        ok: false,
        error: "المطعم غير موجود"
      },
      404
    );
  }

  if (isExpired(site)) {
    return json(
      {
        ok: false,
        error: "الحجز غير متاح حاليًا"
      },
      403
    );
  }

  const data = await request.json();

  const customerName = String(data.customer_name || "").trim();
  const customerPhone = String(data.customer_phone || "").trim();
  const reservationDate = String(data.reservation_date || "").trim();
  const reservationTime = String(data.reservation_time || "").trim();
  const partySize = Number(data.party_size);
  const tableId = data.table_id ? Number(data.table_id) : null;
  const notes = String(data.notes || "").trim() || null;

  if (
    !customerName ||
    !customerPhone ||
    !reservationDate ||
    !reservationTime ||
    !Number.isInteger(partySize) ||
    partySize < 1
  ) {
    return json(
      {
        ok: false,
        error: "أكمل بيانات الحجز"
      },
      400
    );
  }

  let selectedTable = null;

  if (tableId) {
    selectedTable = await env.DB
      .prepare(`
        SELECT *
        FROM restaurant_tables
        WHERE id = ?
          AND site_id = ?
          AND status = 'available'
        LIMIT 1
      `)
      .bind(tableId, site.id)
      .first();

    if (!selectedTable) {
      return json(
        {
          ok: false,
          error: "الترابيزة غير متاحة"
        },
        400
      );
    }

    if (selectedTable.capacity < partySize) {
      return json(
        {
          ok: false,
          error: "سعة الترابيزة لا تكفي عدد الأشخاص"
        },
        400
      );
    }

    const conflict = await env.DB
      .prepare(`
        SELECT id
        FROM reservations
        WHERE table_id = ?
          AND reservation_date = ?
          AND reservation_time = ?
          AND status IN ('pending', 'confirmed')
        LIMIT 1
      `)
      .bind(
        tableId,
        reservationDate,
        reservationTime
      )
      .first();

    if (conflict) {
      return json(
        {
          ok: false,
          error: "هذه الترابيزة محجوزة في هذا الموعد"
        },
        409
      );
    }
  }

  const result = await env.DB
    .prepare(`
      INSERT INTO reservations
        (
          site_id,
          table_id,
          customer_name,
          customer_phone,
          reservation_date,
          reservation_time,
          party_size,
          notes,
          status
        )
      VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `)
    .bind(
      site.id,
      tableId,
      customerName,
      customerPhone,
      reservationDate,
      reservationTime,
      partySize,
      notes
    )
    .run();

  return json({
    ok: true,
    reservation_id: result.meta.last_row_id,
    status: "pending"
  }, 201);
}

async function handleMyReservations(request, env, user) {
  const site = await getSiteForUser(env, user.id);

  if (!site) {
    return json({
      ok: true,
      reservations: []
    });
  }

  const rows = await env.DB
    .prepare(`
      SELECT
        r.*,
        t.name AS table_name,
        t.capacity AS table_capacity
      FROM reservations r
      LEFT JOIN restaurant_tables t
        ON t.id = r.table_id
      WHERE r.site_id = ?
      ORDER BY
        r.reservation_date ASC,
        r.reservation_time ASC,
        r.id DESC
    `)
    .bind(site.id)
    .all();

  return json({
    ok: true,
    reservations: rows.results || []
  });
}

async function handleUpdateReservation(request, env, user, id) {
  const site = await getSiteForUser(env, user.id);

  if (!site) {
    return json(
      {
        ok: false,
        error: "المطعم غير موجود"
      },
      404
    );
  }

  const data = await request.json();

  const allowed = [
    "pending",
    "confirmed",
    "completed",
    "cancelled",
    "rejected"
  ];

  const status = String(data.status || "");

  if (!allowed.includes(status)) {
    return json(
      {
        ok: false,
        error: "حالة الحجز غير صحيحة"
      },
      400
    );
  }

  const result = await env.DB
    .prepare(`
      UPDATE reservations
      SET
        status = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND site_id = ?
    `)
    .bind(
      status,
      Number(id),
      site.id
    )
    .run();

  return json({
    ok: true,
    changed: result.meta.changes || 0
  });
}

async function handleAdminSites(request, env, user) {
  if (user.role !== "admin") {
    return json(
      {
        ok: false,
        error: "غير مصرح"
      },
      403
    );
  }

  const rows = await env.DB
    .prepare(`
      SELECT
        s.*,
        u.name AS owner_name,
        u.email AS owner_email,
        u.phone AS owner_phone
      FROM sites s
      JOIN users u ON u.id = s.user_id
      ORDER BY s.id DESC
    `)
    .all();

  return json({
    ok: true,
    sites: rows.results || []
  });
}

async function handleAdminRenew(request, env, user, siteId) {
  if (user.role !== "admin") {
    return json(
      {
        ok: false,
        error: "غير مصرح"
      },
      403
    );
  }

  const data = await request.json();
  const type = String(data.type || "");

  let subscriptionType;
  let endDate = null;

  if (type === "3_months") {
    subscriptionType = "3_months";
    endDate = addDays(new Date(), 90);
  } else if (type === "1_year") {
    subscriptionType = "1_year";
    endDate = addDays(new Date(), 365);
  } else if (type === "permanent") {
    subscriptionType = "permanent";
    endDate = null;
  } else {
    return json(
      {
        ok: false,
        error: "نوع التجديد غير صحيح"
      },
      400
    );
  }

  const result = await env.DB
    .prepare(`
      UPDATE sites
      SET
        subscription_type = ?,
        subscription_ends_at = ?,
        status = 'active',
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `)
    .bind(
      subscriptionType,
      endDate,
      Number(siteId)
    )
    .run();

  return json({
    ok: true,
    changed: result.meta.changes || 0,
    subscription_type: subscriptionType,
    subscription_ends_at: endDate
  });
}

async function handlePublicMenu(request, env, slug) {
  const site = await env.DB
    .prepare(`
      SELECT
        id,
        name,
        slug,
        description,
        logo_url,
        cover_url,
        design,
        status,
        trial_ends_at,
        subscription_type,
        subscription_ends_at
      FROM sites
      WHERE slug = ?
      LIMIT 1
    `)
    .bind(slug)
    .first();

  if (!site) {
    return json(
      {
        ok: false,
        error: "المنيو غير موجودة"
      },
      404
    );
  }

  if (isExpired(site)) {
    return json(
      {
        ok: false,
        error: "المنيو غير متاحة حاليًا"
      },
      403
    );
  }

  const categories = await env.DB
    .prepare(`
      SELECT *
      FROM categories
      WHERE site_id = ?
      ORDER BY sort_order ASC, id ASC
    `)
    .bind(site.id)
    .all();

  const items = await env.DB
    .prepare(`
      SELECT *
      FROM menu_items
      WHERE site_id = ?
        AND available = 1
      ORDER BY sort_order ASC, id ASC
    `)
    .bind(site.id)
    .all();

  return json({
    ok: true,
    site,
    categories: categories.results || [],
    menu_items: items.results || []
  });
}

async function api(request, env, url) {
  const path = url.pathname;

  if (path === "/api/health") {
    return json({
      ok: true,
      service: "MAW3ED",
      time: new Date().toISOString()
    });
  }

  if (path === "/api/register" && request.method === "POST") {
    return handleRegister(request, env);
  }

  if (path === "/api/login" && request.method === "POST") {
    return handleLogin(request, env);
  }

  if (path === "/api/logout" && request.method === "POST") {
    return handleLogout(request, env);
  }

  if (path === "/api/me" && request.method === "GET") {
    return handleMe(request, env);
  }

  if (path === "/api/site" && request.method === "POST") {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;

    return handleCreateSite(
      request,
      env,
      auth.user
    );
  }

  if (path === "/api/site" && request.method === "PUT") {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;

    return handleUpdateSite(
      request,
      env,
      auth.user
    );
  }

  if (path === "/api/categories" && request.method === "POST") {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;

    return handleCreateCategory(
      request,
      env,
      auth.user
    );
  }

  if (path === "/api/menu-items" && request.method === "POST") {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;

    return handleCreateMenuItem(
      request,
      env,
      auth.user
    );
  }

  if (path === "/api/tables" && request.method === "POST") {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;

    return handleCreateTable(
      request,
      env,
      auth.user
    );
  }

  if (
    path.startsWith("/api/reservations/") &&
    request.method === "PUT"
  ) {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;

    const id = path.split("/").pop();

    return handleUpdateReservation(
      request,
      env,
      auth.user,
      id
    );
  }

  if (
    path === "/api/reservations" &&
    request.method === "GET"
  ) {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;

    return handleMyReservations(
      request,
      env,
      auth.user
    );
  }

  if (
    path.startsWith("/api/book/") &&
    request.method === "POST"
  ) {
    const slug = decodeURIComponent(
      path.substring("/api/book/".length)
    );

    return handleCreateReservation(
      request,
      env,
      slug
    );
  }

  if (
    path.startsWith("/api/public/site/")
  ) {
    const slug = decodeURIComponent(
      path.substring("/api/public/site/".length)
    );

    return handlePublicSite(
      request,
      env,
      slug
    );
  }

  if (
    path.startsWith("/api/public/menu/")
  ) {
    const slug = decodeURIComponent(
      path.substring("/api/public/menu/".length)
    );

    return handlePublicMenu(
      request,
      env,
      slug
    );
  }

  if (
    path === "/api/admin/sites" &&
    request.method === "GET"
  ) {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;

    return handleAdminSites(
      request,
      env,
      auth.user
    );
  }

  if (
    path.startsWith("/api/admin/renew/") &&
    request.method === "POST"
  ) {
    const auth = await requireUser(request, env);
    if (auth.error) return auth.error;

    const siteId = path.split("/").pop();

    return handleAdminRenew(
      request,
      env,
      auth.user,
      siteId
    );
  }

  return json(
    {
      ok: false,
      error: "API endpoint not found"
    },
    404
  );
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname.startsWith("/api/")) {
        return await api(request, env, url);
      }

      if (url.pathname === "/health") {
        return json({
          ok: true,
          service: "MAW3ED",
          status: "running"
        });
      }

      /*
       * الواجهة الأمامية سيتم وضعها داخل public/
       * في الخطوة التالية.
       */
      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return html(`
        <!doctype html>
        <html lang="ar" dir="rtl">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>موعد | MAW3ED</title>
        </head>
        <body>
          <h1>موعد</h1>
          <p>MAW3ED is running.</p>
        </body>
        </html>
      `);
    } catch (error) {
      console.error(error);

      return json(
        {
          ok: false,
          error: "حدث خطأ داخلي"
        },
        500
      );
    }
  }
};

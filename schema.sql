PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer'
    CHECK (role IN ('customer', 'admin')),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'suspended')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_token
ON sessions(token_hash);

CREATE INDEX IF NOT EXISTS idx_sessions_user
ON sessions(user_id);

CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  phone TEXT,
  address TEXT,
  working_hours TEXT,
  description TEXT,
  logo_url TEXT,
  cover_url TEXT,
  design TEXT NOT NULL DEFAULT 'design-01',
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'suspended')),
  trial_started_at TEXT NOT NULL,
  trial_ends_at TEXT NOT NULL,
  subscription_type TEXT NOT NULL DEFAULT 'trial'
    CHECK (subscription_type IN ('trial', '3_months', '1_year', 'permanent')),
  subscription_ends_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sites_slug
ON sites(slug);

CREATE INDEX IF NOT EXISTS idx_sites_user
ON sites(user_id);

CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_categories_site
ON categories(site_id);

CREATE TABLE IF NOT EXISTS menu_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL,
  category_id INTEGER,
  name TEXT NOT NULL,
  description TEXT,
  price REAL NOT NULL DEFAULT 0,
  image_url TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0,
  available INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE,
  FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_menu_items_site
ON menu_items(site_id);

CREATE INDEX IF NOT EXISTS idx_menu_items_category
ON menu_items(category_id);

CREATE TABLE IF NOT EXISTS restaurant_tables (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  capacity INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'available'
    CHECK (status IN ('available', 'disabled')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_restaurant_tables_site
ON restaurant_tables(site_id);

CREATE TABLE IF NOT EXISTS reservations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL,
  table_id INTEGER,
  customer_name TEXT NOT NULL,
  customer_phone TEXT NOT NULL,
  reservation_date TEXT NOT NULL,
  reservation_time TEXT NOT NULL,
  party_size INTEGER NOT NULL,
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'confirmed', 'completed', 'cancelled', 'rejected')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE,
  FOREIGN KEY (table_id) REFERENCES restaurant_tables(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_reservations_site
ON reservations(site_id);

CREATE INDEX IF NOT EXISTS idx_reservations_table_date
ON reservations(table_id, reservation_date, reservation_time);

CREATE INDEX IF NOT EXISTS idx_reservations_date
ON reservations(site_id, reservation_date);

CREATE TABLE IF NOT EXISTS qr_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL,
  type TEXT NOT NULL
    CHECK (type IN ('site', 'menu', 'booking')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_qr_codes_site
ON qr_codes(site_id);

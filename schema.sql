-- Production V1 database schema
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','driver')),
  name TEXT NOT NULL,
  phone TEXT,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  on_duty BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS customers (
  id BIGSERIAL PRIMARY KEY,
  customer_code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  phone TEXT,
  whatsapp_number TEXT,
  address TEXT NOT NULL,
  area TEXT,
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  delivery_window_start TIME,
  delivery_window_end TIME,
  instructions TEXT,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS recurring_deliveries (
  id BIGSERIAL PRIMARY KEY,
  customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  driver_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  meal_type TEXT NOT NULL DEFAULT 'Lunch',
  delivery_time TIME,
  days_of_week SMALLINT[] NOT NULL DEFAULT ARRAY[1,2,3,4,5,6],
  active BOOLEAN NOT NULL DEFAULT TRUE,
  paused_until DATE,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS deliveries (
  id BIGSERIAL PRIMARY KEY,
  delivery_code TEXT UNIQUE NOT NULL,
  customer_id BIGINT NOT NULL REFERENCES customers(id),
  driver_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  recurring_delivery_id BIGINT REFERENCES recurring_deliveries(id) ON DELETE SET NULL,
  delivery_date DATE NOT NULL,
  planned_time TIME,
  route_order INTEGER,
  status TEXT NOT NULL DEFAULT 'Pending',
  empty_photo_data TEXT,
  empty_photo_at TIMESTAMPTZ,
  empty_latitude DOUBLE PRECISION,
  empty_longitude DOUBLE PRECISION,
  delivery_photo_data TEXT,
  delivery_photo_at TIMESTAMPTZ,
  delivery_latitude DOUBLE PRECISION,
  delivery_longitude DOUBLE PRECISION,
  delivered_at TIMESTAMPTZ,
  whatsapp_status TEXT,
  whatsapp_message_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(customer_id, delivery_date)
);
CREATE TABLE IF NOT EXISTS leaves (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  leave_date DATE NOT NULL,
  reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, leave_date)
);
CREATE INDEX IF NOT EXISTS idx_deliveries_date_driver ON deliveries(delivery_date, driver_id);
CREATE INDEX IF NOT EXISTS idx_recurring_active ON recurring_deliveries(active);
CREATE INDEX IF NOT EXISTS idx_customers_active ON customers(active);

# -- Таблица пользователей
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    telegram_id BIGINT UNIQUE,
    uuid VARCHAR(36) UNIQUE,
    device_limit INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

# -- Таблица устройств
CREATE TABLE devices (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    fingerprint VARCHAR(64),
    ip_address VARCHAR(45),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    is_blocked BOOLEAN DEFAULT FALSE,
    UNIQUE(user_id, fingerprint)
);

# -- Таблица покупок
CREATE TABLE purchases (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    device_slots INTEGER,
    amount DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
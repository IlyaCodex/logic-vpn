# -- Таблица устройств с типом ОС
CREATE TABLE user_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id VARCHAR(36) NOT NULL,
    os_type VARCHAR(20) NOT NULL,
    device_fingerprint VARCHAR(64) UNIQUE,
    ip_address VARCHAR(45),
    tls_signature TEXT,
    tcp_signature TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    is_blocked BOOLEAN DEFAULT FALSE,
    UNIQUE(user_id, os_type)  -- Один пользователь = одно устройство на ОС
);

# -- Таблица лимитов по ОС
CREATE TABLE user_os_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id VARCHAR(36) NOT NULL,
    os_type VARCHAR(20) NOT NULL,
    device_limit INTEGER DEFAULT 1,
    purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, os_type)
);

# -- Индексы для быстрого поиска
CREATE INDEX idx_user_devices ON user_devices(user_id, os_type);
CREATE INDEX idx_active_devices ON user_devices(user_id, is_active);
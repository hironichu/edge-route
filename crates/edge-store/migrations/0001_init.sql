CREATE TABLE IF NOT EXISTS mappings (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_ip TEXT,
    oci_public_ip_ocid TEXT,
    edge_private_ip TEXT NOT NULL,
    oci_private_ip_ocid TEXT,
    target_ip TEXT NOT NULL,
    public_port INTEGER,
    target_port INTEGER,
    protocol TEXT NOT NULL DEFAULT 'all',
    mode TEXT NOT NULL DEFAULT 'one_to_one_snat',
    backend TEXT NOT NULL DEFAULT 'nft',
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'pending',
    last_error TEXT,
    health_status TEXT,
    last_checked_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS edge_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS generations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status TEXT NOT NULL,
    nftables_config TEXT NOT NULL,
    created_at TEXT NOT NULL,
    applied_at TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    data TEXT,
    created_at TEXT NOT NULL
);

CREATE SCHEMA IF NOT EXISTS onion_controller;

CREATE TABLE IF NOT EXISTS onion_controller.identities (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    port TEXT NOT NULL,
    address TEXT NOT NULL,
    last_updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);


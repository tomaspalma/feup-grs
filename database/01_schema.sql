CREATE SCHEMA IF NOT EXISTS onion_controller;

CREATE TABLE IF NOT EXISTS onion_controller.identities (
    address TEXT NOT NULL,
    port TEXT NOT NULL,
    public_key TEXT NOT NULL,
    last_updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (address, port)
);


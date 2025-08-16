CREATE TABLE app_state_mutation_macs (
    name TEXT NOT NULL,
    version BIGINT NOT NULL,
    index_mac BLOB NOT NULL,
    value_mac BLOB NOT NULL,
    PRIMARY KEY (name, index_mac)
);
CREATE INDEX idx_app_state_mutation_macs_name_version ON app_state_mutation_macs(name, version);

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("serialization/deserialization error")]
    Serialization(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Validation failure with a descriptive message and no underlying typed
    /// source — e.g. "Invalid foo length: 17". Prefer `Serialization` or a
    /// dedicated typed variant if a real source exists.
    #[error("data validation failed: {0}")]
    Validation(String),

    #[error("database connection error")]
    Connection(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("database operation error")]
    Database(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("database operation '{op}' exhausted retries")]
    RetriesExhausted { op: String },

    #[error("migration error")]
    Migration(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("store configuration is invalid: {0}")]
    InvalidConfig(String),

    #[error("device with ID {0} not found")]
    DeviceNotFound(i32),
}

impl StoreError {
    /// Walks the error source chain and returns true if any layer's `Display`
    /// indicates a SQLite busy/locked condition. Used by retry layers that
    /// can't depend on a specific backend (Diesel, libsql, etc.) directly.
    ///
    /// Substring matching is necessary because SQLite reports BUSY/LOCKED
    /// through `sqlite3_errmsg()` strings; the error code itself is mapped
    /// to `Diesel::DatabaseError(Unknown, _)` (or similar) without further
    /// discrimination.
    pub fn is_database_busy_or_locked(&self) -> bool {
        let mut layer: &dyn std::error::Error = self;
        loop {
            let s = layer.to_string().to_lowercase();
            if s.contains("locked") || s.contains("busy") {
                return true;
            }
            match layer.source() {
                Some(inner) => layer = inner,
                None => return false,
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("synthetic backend error: {0}")]
    struct DummyBackendError(&'static str);

    #[test]
    fn database_preserves_typed_source_via_downcast() {
        let inner = DummyBackendError("bang");
        let se = StoreError::Database(Box::new(inner));
        let src = std::error::Error::source(&se).expect("source preserved");
        let downcast = src
            .downcast_ref::<DummyBackendError>()
            .expect("downcasts to DummyBackendError");
        assert_eq!(downcast.0, "bang");
    }

    #[test]
    fn is_busy_or_locked_walks_chain() {
        let inner = DummyBackendError("database is locked");
        let se = StoreError::Database(Box::new(inner));
        assert!(se.is_database_busy_or_locked());
    }

    #[test]
    fn is_busy_or_locked_negative() {
        let inner = DummyBackendError("permission denied");
        let se = StoreError::Database(Box::new(inner));
        assert!(!se.is_database_busy_or_locked());
    }

    #[test]
    fn is_busy_or_locked_is_case_insensitive() {
        // SQLite drivers in different ecosystems vary on casing for these
        // diagnostic strings ("database is LOCKED", "Busy", etc.). The check
        // must not depend on the exact casing the underlying driver chose.
        for msg in [
            "database is LOCKED",
            "SQLITE_BUSY: write contention",
            "Busy",
            "Locked",
        ] {
            let se = StoreError::Database(Box::new(DummyBackendError(msg)));
            assert!(
                se.is_database_busy_or_locked(),
                "expected {msg:?} to be detected"
            );
        }
    }
}

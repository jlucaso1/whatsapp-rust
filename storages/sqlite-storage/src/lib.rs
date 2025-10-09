//! SQLite storage backend for whatsapp-rust
//!
//! This crate provides a SQLite-based storage implementation for the whatsapp-rust library.
//! It implements all the required storage traits from wacore::store::traits.

mod schema;
mod sqlite_store;
mod device_aware_store;

pub use sqlite_store::SqliteStore;
pub use device_aware_store::DeviceAwareSqliteStore;

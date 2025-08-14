use crate::store::schema::*;
use crate::store::traits::*;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use libsignal_protocol::Direction;
use prost::Message;
use wacore::appstate::hash::HashState;
use wacore::signal;
use wacore::store::error::{Result, StoreError};
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

use super::SerializableDevice;

// Embed migrations into the binary
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

type SqlitePool = Pool<ConnectionManager<SqliteConnection>>;
type SignalStoreError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub async fn new(database_url: &str) -> std::result::Result<Self, StoreError> {
        let manager = ConnectionManager::<SqliteConnection>::new(database_url);
        let pool = Pool::builder()
            .build(manager)
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        // Run migrations
        {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            conn.run_pending_migrations(MIGRATIONS)
                .map_err(|e| StoreError::Migration(e.to_string()))?;
        }

        Ok(Self { pool })
    }

    fn get_connection(&self) -> std::result::Result<diesel::r2d2::PooledConnection<ConnectionManager<SqliteConnection>>, StoreError> {
        self.pool
            .get()
            .map_err(|e| StoreError::Connection(e.to_string()))
    }

    pub async fn save_device_data(&self, device_data: &SerializableDevice) -> Result<()> {
        // For SQLite store, we store device data as a special record in app_state_versions
        let data = bincode::serde::encode_to_vec(device_data, bincode::config::standard())
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        
        let mut conn = self.get_connection()?;
        
        diesel::insert_into(app_state_versions::table)
            .values((
                app_state_versions::name.eq("__device_data__"),
                app_state_versions::state_data.eq(&data),
            ))
            .on_conflict(app_state_versions::name)
            .do_update()
            .set(app_state_versions::state_data.eq(&data))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub async fn load_device_data(&self) -> Result<Option<SerializableDevice>> {
        let mut conn = self.get_connection()?;
        
        let result: Option<Vec<u8>> = app_state_versions::table
            .select(app_state_versions::state_data)
            .filter(app_state_versions::name.eq("__device_data__"))
            .first(&mut conn)
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        if let Some(data) = result {
            let (device_data, _) = bincode::serde::decode_from_slice(&data, bincode::config::standard())
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            Ok(Some(device_data))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl IdentityStore for SqliteStore {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()> {
        let mut conn = self.get_connection()?;
        
        diesel::insert_into(identities::table)
            .values((
                identities::address.eq(address),
                identities::key.eq(&key[..]),
            ))
            .on_conflict(identities::address)
            .do_update()
            .set(identities::key.eq(&key[..]))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        let mut conn = self.get_connection()?;
        
        diesel::delete(identities::table.filter(identities::address.eq(address)))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    async fn is_trusted_identity(
        &self,
        _address: &str,
        _key: &[u8; 32],
        _direction: Direction,
    ) -> Result<bool> {
        // For now, we trust all identities like in FileStore
        Ok(true)
    }

    async fn load_identity(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.get_connection()?;
        
        let result: Option<Vec<u8>> = identities::table
            .select(identities::key)
            .filter(identities::address.eq(address))
            .first(&mut conn)
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(result)
    }
}

#[async_trait]
impl SessionStore for SqliteStore {
    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.get_connection()?;
        
        let result: Option<Vec<u8>> = sessions::table
            .select(sessions::record)
            .filter(sessions::address.eq(address))
            .first(&mut conn)
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(result)
    }

    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()> {
        let mut conn = self.get_connection()?;
        
        diesel::insert_into(sessions::table)
            .values((
                sessions::address.eq(address),
                sessions::record.eq(session),
            ))
            .on_conflict(sessions::address)
            .do_update()
            .set(sessions::record.eq(session))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    async fn delete_session(&self, address: &str) -> Result<()> {
        let mut conn = self.get_connection()?;
        
        diesel::delete(sessions::table.filter(sessions::address.eq(address)))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    async fn has_session(&self, address: &str) -> Result<bool> {
        let mut conn = self.get_connection()?;
        
        let count: i64 = sessions::table
            .filter(sessions::address.eq(address))
            .count()
            .get_result(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(count > 0)
    }
}

#[async_trait(?Send)]
impl signal::store::PreKeyStore for SqliteStore {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<Option<PreKeyRecordStructure>, SignalStoreError> {
        let mut conn = self.get_connection()?;
        
        let result: Option<Vec<u8>> = prekeys::table
            .select(prekeys::record)
            .filter(prekeys::id.eq(prekey_id as i32))
            .first(&mut conn)
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        if let Some(data) = result {
            let record = PreKeyRecordStructure::decode(data.as_slice())
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> std::result::Result<(), SignalStoreError> {
        let mut conn = self.get_connection()?;
        let data = record.encode_to_vec();
        
        diesel::insert_into(prekeys::table)
            .values((
                prekeys::id.eq(prekey_id as i32),
                prekeys::record.eq(&data),
            ))
            .on_conflict(prekeys::id)
            .do_update()
            .set(prekeys::record.eq(&data))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    async fn contains_prekey(&self, prekey_id: u32) -> std::result::Result<bool, SignalStoreError> {
        let mut conn = self.get_connection()?;
        
        let count: i64 = prekeys::table
            .filter(prekeys::id.eq(prekey_id as i32))
            .count()
            .get_result(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(count > 0)
    }

    async fn remove_prekey(&self, prekey_id: u32) -> std::result::Result<(), SignalStoreError> {
        let mut conn = self.get_connection()?;
        
        diesel::delete(prekeys::table.filter(prekeys::id.eq(prekey_id as i32)))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(())
    }
}

#[async_trait]
impl SenderKeyStoreHelper for SqliteStore {
    async fn put_sender_key(&self, address: &str, record: &[u8]) -> Result<()> {
        let mut conn = self.get_connection()?;
        
        diesel::insert_into(sender_keys::table)
            .values((
                sender_keys::address.eq(address),
                sender_keys::record.eq(record),
            ))
            .on_conflict(sender_keys::address)
            .do_update()
            .set(sender_keys::record.eq(record))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(())
    }

    async fn get_sender_key(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.get_connection()?;
        
        let result: Option<Vec<u8>> = sender_keys::table
            .select(sender_keys::record)
            .filter(sender_keys::address.eq(address))
            .first(&mut conn)
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(result)
    }

    async fn delete_sender_key(&self, address: &str) -> Result<()> {
        let mut conn = self.get_connection()?;
        
        diesel::delete(sender_keys::table.filter(sender_keys::address.eq(address)))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(())
    }
}

#[async_trait(?Send)]
impl signal::store::SignedPreKeyStore for SqliteStore {
    async fn load_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> std::result::Result<Option<SignedPreKeyRecordStructure>, SignalStoreError> {
        // For now, return None like FileStore
        Ok(None)
    }

    async fn load_signed_prekeys(
        &self,
    ) -> std::result::Result<Vec<SignedPreKeyRecordStructure>, SignalStoreError> {
        // For now, return empty vector like FileStore
        Ok(Vec::new())
    }

    async fn store_signed_prekey(
        &self,
        _signed_prekey_id: u32,
        _record: SignedPreKeyRecordStructure,
    ) -> std::result::Result<(), SignalStoreError> {
        // For now, do nothing like FileStore
        Ok(())
    }

    async fn contains_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> std::result::Result<bool, SignalStoreError> {
        // For now, return false like FileStore
        Ok(false)
    }

    async fn remove_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> std::result::Result<(), SignalStoreError> {
        // For now, do nothing like FileStore
        Ok(())
    }
}

#[async_trait]
impl AppStateKeyStore for SqliteStore {
    async fn get_app_state_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        let mut conn = self.get_connection()?;
        
        let result: Option<Vec<u8>> = app_state_keys::table
            .select(app_state_keys::key_data)
            .filter(app_state_keys::key_id.eq(key_id))
            .first(&mut conn)
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        if let Some(data) = result {
            let (key, _) = bincode::serde::decode_from_slice(&data, bincode::config::standard())
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }

    async fn set_app_state_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        let mut conn = self.get_connection()?;
        let data = bincode::serde::encode_to_vec(&key, bincode::config::standard())
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        
        diesel::insert_into(app_state_keys::table)
            .values((
                app_state_keys::key_id.eq(key_id),
                app_state_keys::key_data.eq(&data),
            ))
            .on_conflict(app_state_keys::key_id)
            .do_update()
            .set(app_state_keys::key_data.eq(&data))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(())
    }
}

#[async_trait]
impl AppStateStore for SqliteStore {
    async fn get_app_state_version(&self, name: &str) -> Result<HashState> {
        let mut conn = self.get_connection()?;
        
        let result: Option<Vec<u8>> = app_state_versions::table
            .select(app_state_versions::state_data)
            .filter(app_state_versions::name.eq(name))
            .first(&mut conn)
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        if let Some(data) = result {
            let (state, _) = bincode::serde::decode_from_slice(&data, bincode::config::standard())
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            Ok(state)
        } else {
            Ok(HashState::default())
        }
    }

    async fn set_app_state_version(&self, name: &str, state: HashState) -> Result<()> {
        let mut conn = self.get_connection()?;
        let data = bincode::serde::encode_to_vec(&state, bincode::config::standard())
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        
        diesel::insert_into(app_state_versions::table)
            .values((
                app_state_versions::name.eq(name),
                app_state_versions::state_data.eq(&data),
            ))
            .on_conflict(app_state_versions::name)
            .do_update()
            .set(app_state_versions::state_data.eq(&data))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        
        Ok(())
    }
}
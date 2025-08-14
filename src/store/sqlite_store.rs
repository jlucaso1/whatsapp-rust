use crate::store::schema::*;
use crate::store::traits::*;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use libsignal_protocol::{Direction, KeyPair, PrivateKey, PublicKey};
use prost::Message;
use std::collections::VecDeque;
use wacore::appstate::hash::HashState;
use wacore::signal;
use wacore::store::error::{Result, StoreError};
use waproto::whatsapp::{self as wa, PreKeyRecordStructure, SignedPreKeyRecordStructure};

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

    fn get_connection(
        &self,
    ) -> std::result::Result<
        diesel::r2d2::PooledConnection<ConnectionManager<SqliteConnection>>,
        StoreError,
    > {
        self.pool
            .get()
            .map_err(|e| StoreError::Connection(e.to_string()))
    }

    // Helper methods for KeyPair serialization/deserialization
    fn serialize_keypair(&self, key_pair: &KeyPair) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&key_pair.private_key.serialize());
        bytes.extend_from_slice(key_pair.public_key.public_key_bytes());
        Ok(bytes)
    }

    fn deserialize_keypair(&self, bytes: &[u8]) -> Result<KeyPair> {
        if bytes.len() != 64 {
            return Err(StoreError::Serialization(format!(
                "Invalid KeyPair length: {}",
                bytes.len()
            )));
        }

        let private_key = PrivateKey::deserialize(&bytes[0..32])
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        let public_key = PublicKey::from_djb_public_key_bytes(&bytes[32..64])
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        Ok(KeyPair::new(public_key, private_key))
    }

    pub async fn save_device_data(&self, device_data: &SerializableDevice) -> Result<()> {
        let mut conn = self.get_connection()?;

        // Serialize KeyPairs and other complex data
        let noise_key_data = self.serialize_keypair(&device_data.noise_key)?;
        let identity_key_data = self.serialize_keypair(&device_data.identity_key)?;
        let signed_pre_key_data = self.serialize_keypair(&device_data.signed_pre_key)?;

        // Serialize account if present
        let account_data = device_data.account.as_ref().map(|account| account.encode_to_vec());

        // Serialize processed messages
        let processed_messages_data = if !device_data.processed_messages.is_empty() {
            Some(
                bincode::serde::encode_to_vec(
                    &device_data.processed_messages,
                    bincode::config::standard(),
                )
                .map_err(|e| StoreError::Serialization(e.to_string()))?,
            )
        } else {
            None
        };

        diesel::insert_into(device::table)
            .values((
                device::id.eq(1), // Single device per database
                device::jid.eq(device_data.id.as_ref().map(|j| j.to_string())),
                device::lid.eq(device_data.lid.as_ref().map(|j| j.to_string())),
                device::registration_id.eq(device_data.registration_id as i32),
                device::noise_key.eq(&noise_key_data),
                device::identity_key.eq(&identity_key_data),
                device::signed_pre_key.eq(&signed_pre_key_data),
                device::signed_pre_key_id.eq(device_data.signed_pre_key_id as i32),
                device::signed_pre_key_signature.eq(&device_data.signed_pre_key_signature[..]),
                device::adv_secret_key.eq(&device_data.adv_secret_key[..]),
                device::account.eq(account_data.as_deref()),
                device::push_name.eq(&device_data.push_name),
                device::processed_messages
                    .eq(processed_messages_data.as_deref()),
            ))
            .on_conflict(device::id)
            .do_update()
            .set((
                device::jid.eq(device_data.id.as_ref().map(|j| j.to_string())),
                device::lid.eq(device_data.lid.as_ref().map(|j| j.to_string())),
                device::registration_id.eq(device_data.registration_id as i32),
                device::noise_key.eq(&noise_key_data),
                device::identity_key.eq(&identity_key_data),
                device::signed_pre_key.eq(&signed_pre_key_data),
                device::signed_pre_key_id.eq(device_data.signed_pre_key_id as i32),
                device::signed_pre_key_signature.eq(&device_data.signed_pre_key_signature[..]),
                device::adv_secret_key.eq(&device_data.adv_secret_key[..]),
                device::account.eq(account_data.as_deref()),
                device::push_name.eq(&device_data.push_name),
                device::processed_messages
                    .eq(processed_messages_data.as_deref()),
            ))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    pub async fn load_device_data(&self) -> Result<Option<SerializableDevice>> {
        let mut conn = self.get_connection()?;

        let result = device::table
            .filter(device::id.eq(1))
            .first::<(
                Option<i32>,     // id
                Option<String>,  // jid
                Option<String>,  // lid
                i32,             // registration_id
                Vec<u8>,         // noise_key
                Vec<u8>,         // identity_key
                Vec<u8>,         // signed_pre_key
                i32,             // signed_pre_key_id
                Vec<u8>,         // signed_pre_key_signature
                Vec<u8>,         // adv_secret_key
                Option<Vec<u8>>, // account
                String,          // push_name
                Option<Vec<u8>>, // processed_messages
            )>(&mut conn)
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        if let Some((
            _id,
            jid_str,
            lid_str,
            registration_id,
            noise_key_data,
            identity_key_data,
            signed_pre_key_data,
            signed_pre_key_id,
            signed_pre_key_signature_data,
            adv_secret_key_data,
            account_data,
            push_name,
            processed_messages_data,
        )) = result
        {
            // Parse JIDs
            let id = if let Some(jid_str) = jid_str {
                jid_str.parse().ok()
            } else {
                None
            };

            let lid = if let Some(lid_str) = lid_str {
                lid_str.parse().ok()
            } else {
                None
            };

            // Deserialize KeyPairs
            let noise_key = self.deserialize_keypair(&noise_key_data)?;
            let identity_key = self.deserialize_keypair(&identity_key_data)?;
            let signed_pre_key = self.deserialize_keypair(&signed_pre_key_data)?;

            // Deserialize signature (ensure it's exactly 64 bytes)
            let mut signed_pre_key_signature = [0u8; 64];
            if signed_pre_key_signature_data.len() == 64 {
                signed_pre_key_signature.copy_from_slice(&signed_pre_key_signature_data);
            } else {
                return Err(StoreError::Serialization(
                    "Invalid signature length".to_string(),
                ));
            }

            // Deserialize secret key (ensure it's exactly 32 bytes)
            let mut adv_secret_key = [0u8; 32];
            if adv_secret_key_data.len() == 32 {
                adv_secret_key.copy_from_slice(&adv_secret_key_data);
            } else {
                return Err(StoreError::Serialization(
                    "Invalid secret key length".to_string(),
                ));
            }

            // Deserialize account if present
            let account = if let Some(account_data) = account_data {
                Some(
                    wa::AdvSignedDeviceIdentity::decode(account_data.as_slice())
                        .map_err(|e| StoreError::Serialization(e.to_string()))?,
                )
            } else {
                None
            };

            // Deserialize processed messages if present
            let processed_messages = if let Some(processed_messages_data) = processed_messages_data
            {
                let (messages, _) = bincode::serde::decode_from_slice(
                    &processed_messages_data,
                    bincode::config::standard(),
                )
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
                messages
            } else {
                VecDeque::new()
            };

            Ok(Some(SerializableDevice {
                id,
                lid,
                registration_id: registration_id as u32,
                noise_key,
                identity_key,
                signed_pre_key,
                signed_pre_key_id: signed_pre_key_id as u32,
                signed_pre_key_signature,
                adv_secret_key,
                account,
                push_name,
                processed_messages,
            }))
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
            .values((sessions::address.eq(address), sessions::record.eq(session)))
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
            .values((prekeys::id.eq(prekey_id as i32), prekeys::record.eq(&data)))
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

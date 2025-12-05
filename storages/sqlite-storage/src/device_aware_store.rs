use super::sqlite_store::SqliteStore;
use crate::schema::*;
use async_trait::async_trait;
use diesel::prelude::*;
use prost::Message;
use std::sync::Arc;
use wacore::appstate::hash::HashState;
use wacore::appstate::processor::AppStateMutationMAC;
use wacore::store::error::Result;
use wacore::store::traits::*;

/// A device-aware wrapper around SqliteStore that ensures all operations
/// are scoped to a specific device_id for proper multi-account isolation.
#[derive(Clone)]
pub struct DeviceAwareSqliteStore {
    store: Arc<SqliteStore>,
    device_id: i32,
}

impl DeviceAwareSqliteStore {
    pub fn new(store: Arc<SqliteStore>, device_id: i32) -> Self {
        Self { store, device_id }
    }
}

#[async_trait]
impl IdentityStore for DeviceAwareSqliteStore {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()> {
        self.store
            .put_identity_for_device(address, key, self.device_id)
            .await
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        self.store
            .delete_identity_for_device(address, self.device_id)
            .await
    }

    async fn is_trusted_identity(
        &self,
        address: &str,
        key: &[u8; 32],
        _direction: wacore::libsignal::protocol::Direction,
    ) -> Result<bool> {
        // For now, we'll trust all identities as per the original implementation
        // but we should load and check against stored identity
        match self.load_identity(address).await? {
            Some(stored_key) => Ok(stored_key == key.to_vec()),
            None => Ok(true), // Trust on first use
        }
    }

    async fn load_identity(&self, address: &str) -> Result<Option<Vec<u8>>> {
        self.store
            .load_identity_for_device(address, self.device_id)
            .await
    }
}

#[async_trait]
impl SessionStore for DeviceAwareSqliteStore {
    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        self.store
            .get_session_for_device(address, self.device_id)
            .await
    }

    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()> {
        self.store
            .put_session_for_device(address, session, self.device_id)
            .await
    }

    async fn delete_session(&self, address: &str) -> Result<()> {
        self.store
            .delete_session_for_device(address, self.device_id)
            .await
    }

    async fn has_session(&self, address: &str) -> Result<bool> {
        self.store
            .has_session_for_device(address, self.device_id)
            .await
    }
}

#[async_trait]
impl SenderKeyStoreHelper for DeviceAwareSqliteStore {
    async fn put_sender_key(&self, address: &str, record: &[u8]) -> Result<()> {
        self.store
            .put_sender_key_for_device(address, record, self.device_id)
            .await
    }

    async fn get_sender_key(&self, address: &str) -> Result<Option<Vec<u8>>> {
        self.store
            .get_sender_key_for_device(address, self.device_id)
            .await
    }

    async fn delete_sender_key(&self, address: &str) -> Result<()> {
        self.store
            .delete_sender_key_for_device(address, self.device_id)
            .await
    }
}

#[async_trait]
impl AppStateKeyStore for DeviceAwareSqliteStore {
    async fn get_app_state_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        self.store
            .get_app_state_sync_key_for_device(key_id, self.device_id)
            .await
    }

    async fn set_app_state_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        self.store
            .set_app_state_sync_key_for_device(key_id, key, self.device_id)
            .await
    }
}

#[async_trait]
impl AppStateStore for DeviceAwareSqliteStore {
    async fn get_app_state_version(&self, name: &str) -> Result<HashState> {
        self.store
            .get_app_state_version_for_device(name, self.device_id)
            .await
    }

    async fn set_app_state_version(&self, name: &str, state: HashState) -> Result<()> {
        self.store
            .set_app_state_version_for_device(name, state, self.device_id)
            .await
    }

    async fn put_app_state_mutation_macs(
        &self,
        name: &str,
        version: u64,
        mutations: &[AppStateMutationMAC],
    ) -> Result<()> {
        self.store
            .put_app_state_mutation_macs_for_device(name, version, mutations, self.device_id)
            .await
    }

    async fn delete_app_state_mutation_macs(
        &self,
        name: &str,
        index_macs: &[Vec<u8>],
    ) -> Result<()> {
        self.store
            .delete_app_state_mutation_macs_for_device(name, index_macs, self.device_id)
            .await
    }

    async fn get_app_state_mutation_mac(
        &self,
        name: &str,
        index_mac: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        self.store
            .get_app_state_mutation_mac_for_device(name, index_mac, self.device_id)
            .await
    }
}

// Implement libsignal::store traits by delegating to the original SqliteStore
// but with device_id filtering for the prekey operations
#[async_trait]
impl wacore::libsignal::store::PreKeyStore for DeviceAwareSqliteStore {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<
        Option<waproto::whatsapp::PreKeyRecordStructure>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let pool = self.store.pool.clone();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(move || -> std::result::Result<Option<waproto::whatsapp::PreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
            let mut conn = pool.get()?;

            let key_data: Option<Vec<u8>> = prekeys::table
                .select(prekeys::key)
                .filter(prekeys::id.eq(prekey_id as i32))
                .filter(prekeys::device_id.eq(device_id))
                .first(&mut conn)
                .optional()?;

                match key_data {
                Some(data) => {
                    let record = waproto::whatsapp::PreKeyRecordStructure::decode(&data[..])?;
                    Ok(Some(record))
                }
                None => Ok(None),
            }
        })
        .await?
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: waproto::whatsapp::PreKeyRecordStructure,
        uploaded: bool,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pool = self.store.pool.clone();
        let device_id = self.device_id;
        let key_data = record.encode_to_vec();

        tokio::task::spawn_blocking(
            move || -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let mut conn = pool.get()?;

                diesel::insert_into(prekeys::table)
                    .values((
                        prekeys::id.eq(prekey_id as i32),
                        prekeys::key.eq(&key_data),
                        prekeys::device_id.eq(device_id),
                        prekeys::uploaded.eq(uploaded),
                    ))
                    .on_conflict((prekeys::id, prekeys::device_id))
                    .do_update()
                    .set((prekeys::key.eq(&key_data), prekeys::uploaded.eq(uploaded)))
                    .execute(&mut conn)?;
                Ok(())
            },
        )
        .await?
    }

    async fn contains_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let pool = self.store.pool.clone();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(
            move || -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
                let mut conn = pool.get()?;

                let count: i64 = prekeys::table
                    .filter(prekeys::id.eq(prekey_id as i32))
                    .filter(prekeys::device_id.eq(device_id))
                    .count()
                    .get_result(&mut conn)?;

                Ok(count > 0)
            },
        )
        .await?
    }

    async fn remove_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pool = self.store.pool.clone();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(
            move || -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let mut conn = pool.get()?;

                diesel::delete(
                    prekeys::table
                        .filter(prekeys::id.eq(prekey_id as i32))
                        .filter(prekeys::device_id.eq(device_id)),
                )
                .execute(&mut conn)?;
                Ok(())
            },
        )
        .await?
    }
}

#[async_trait]
impl wacore::libsignal::store::SignedPreKeyStore for DeviceAwareSqliteStore {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<
        Option<waproto::whatsapp::SignedPreKeyRecordStructure>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let pool = self.store.pool.clone();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(move || -> std::result::Result<Option<waproto::whatsapp::SignedPreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
            let mut conn = pool.get()?;

            let record_data: Option<Vec<u8>> = signed_prekeys::table
                .select(signed_prekeys::record)
                .filter(signed_prekeys::id.eq(signed_prekey_id as i32))
                .filter(signed_prekeys::device_id.eq(device_id))
                .first(&mut conn)
                .optional()?;

                match record_data {
                Some(data) => {
                    let record = waproto::whatsapp::SignedPreKeyRecordStructure::decode(&data[..])?;
                    Ok(Some(record))
                }
                None => Ok(None),
            }
        })
        .await?
    }

    async fn load_signed_prekeys(
        &self,
    ) -> std::result::Result<
        Vec<waproto::whatsapp::SignedPreKeyRecordStructure>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let pool = self.store.pool.clone();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(move || -> std::result::Result<Vec<waproto::whatsapp::SignedPreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
            let mut conn = pool.get()?;

            let records_data: Vec<Vec<u8>> = signed_prekeys::table
                .select(signed_prekeys::record)
                .filter(signed_prekeys::device_id.eq(device_id))
                .load(&mut conn)?;

            let mut records = Vec::new();
            for data in records_data {
                let record = waproto::whatsapp::SignedPreKeyRecordStructure::decode(&data[..])?;
                records.push(record);
            }
            Ok(records)
        })
        .await?
    }

    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: waproto::whatsapp::SignedPreKeyRecordStructure,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pool = self.store.pool.clone();
        let device_id = self.device_id;
        let record_data = record.encode_to_vec();

        tokio::task::spawn_blocking(
            move || -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let mut conn = pool.get()?;

                diesel::insert_into(signed_prekeys::table)
                    .values((
                        signed_prekeys::id.eq(signed_prekey_id as i32),
                        signed_prekeys::record.eq(&record_data),
                        signed_prekeys::device_id.eq(device_id),
                    ))
                    .on_conflict((signed_prekeys::id, signed_prekeys::device_id))
                    .do_update()
                    .set(signed_prekeys::record.eq(&record_data))
                    .execute(&mut conn)?;
                Ok(())
            },
        )
        .await?
    }

    async fn contains_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let pool = self.store.pool.clone();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(
            move || -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
                let mut conn = pool.get()?;

                let count: i64 = signed_prekeys::table
                    .filter(signed_prekeys::id.eq(signed_prekey_id as i32))
                    .filter(signed_prekeys::device_id.eq(device_id))
                    .count()
                    .get_result(&mut conn)?;

                Ok(count > 0)
            },
        )
        .await?
    }

    async fn remove_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pool = self.store.pool.clone();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(
            move || -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let mut conn = pool.get()?;

                diesel::delete(
                    signed_prekeys::table
                        .filter(signed_prekeys::id.eq(signed_prekey_id as i32))
                        .filter(signed_prekeys::device_id.eq(device_id)),
                )
                .execute(&mut conn)?;
                Ok(())
            },
        )
        .await?
    }
}

#[async_trait]
impl wacore::store::traits::DevicePersistence for DeviceAwareSqliteStore {
    async fn save_device_data(
        &self,
        device_data: &wacore::store::Device,
    ) -> wacore::store::error::Result<()> {
        self.store.save_device_data(device_data).await
    }

    async fn save_device_data_for_device(
        &self,
        device_id: i32,
        device_data: &wacore::store::Device,
    ) -> wacore::store::error::Result<()> {
        self.store
            .save_device_data_for_device(device_id, device_data)
            .await
    }

    async fn load_device_data(
        &self,
    ) -> wacore::store::error::Result<Option<wacore::store::Device>> {
        self.store.load_device_data().await
    }

    async fn load_device_data_for_device(
        &self,
        device_id: i32,
    ) -> wacore::store::error::Result<Option<wacore::store::Device>> {
        self.store.load_device_data_for_device(device_id).await
    }

    async fn device_exists(&self, device_id: i32) -> wacore::store::error::Result<bool> {
        self.store.device_exists(device_id).await
    }

    async fn create_new_device(&self) -> wacore::store::error::Result<i32> {
        self.store.create_new_device().await
    }
}

#[async_trait]
impl SenderKeyDistributionStore for DeviceAwareSqliteStore {
    async fn get_skdm_recipients(&self, group_jid: &str) -> Result<Vec<String>> {
        self.store
            .get_skdm_recipients_for_device(group_jid, self.device_id)
            .await
    }

    async fn add_skdm_recipients(&self, group_jid: &str, device_jids: &[String]) -> Result<()> {
        self.store
            .add_skdm_recipients_for_device(group_jid, device_jids, self.device_id)
            .await
    }

    async fn clear_skdm_recipients(&self, group_jid: &str) -> Result<()> {
        self.store
            .clear_skdm_recipients_for_device(group_jid, self.device_id)
            .await
    }
}

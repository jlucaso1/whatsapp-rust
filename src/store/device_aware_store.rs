use super::sqlite_store::SqliteStore;
use crate::store::schema::*;
use async_trait::async_trait;
use bincode;
use diesel::prelude::*;
use prost::Message;
use std::sync::Arc;
use wacore::appstate::hash::HashState;
use wacore::store::error::{Result, StoreError};
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
        let pool = self.store.pool.clone();
        let address = address.to_string();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            diesel::insert_into(identities::table)
                .values((
                    identities::address.eq(&address),
                    identities::key.eq(&key[..]),
                    identities::device_id.eq(device_id),
                ))
                .on_conflict((identities::address, identities::device_id))
                .do_update()
                .set(identities::key.eq(&key[..]))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        let pool = self.store.pool.clone();
        let address = address.to_string();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            diesel::delete(
                identities::table
                    .filter(identities::address.eq(&address))
                    .filter(identities::device_id.eq(device_id)),
            )
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
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
        let pool = self.store.pool.clone();
        let address = address.to_string();
        let device_id = self.device_id;

        let result = tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            let res: Option<Vec<u8>> = identities::table
                .select(identities::key)
                .filter(identities::address.eq(&address))
                .filter(identities::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(res)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        Ok(result)
    }
}

#[async_trait]
impl SessionStore for DeviceAwareSqliteStore {
    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let pool = self.store.pool.clone();
        let address = address.to_string();
        let device_id = self.device_id;

        let result = tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            let res: Option<Vec<u8>> = sessions::table
                .select(sessions::record)
                .filter(sessions::address.eq(&address))
                .filter(sessions::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(res)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        Ok(result)
    }

    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()> {
        let pool = self.store.pool.clone();
        let address = address.to_string();
        let session = session.to_vec();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            diesel::insert_into(sessions::table)
                .values((
                    sessions::address.eq(&address),
                    sessions::record.eq(&session),
                    sessions::device_id.eq(device_id),
                ))
                .on_conflict((sessions::address, sessions::device_id))
                .do_update()
                .set(sessions::record.eq(&session))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn delete_session(&self, address: &str) -> Result<()> {
        let pool = self.store.pool.clone();
        let address = address.to_string();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            diesel::delete(
                sessions::table
                    .filter(sessions::address.eq(&address))
                    .filter(sessions::device_id.eq(device_id)),
            )
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn has_session(&self, address: &str) -> Result<bool> {
        Ok(self.get_session(address).await?.is_some())
    }
}

#[async_trait]
impl SenderKeyStoreHelper for DeviceAwareSqliteStore {
    async fn put_sender_key(&self, address: &str, record: &[u8]) -> Result<()> {
        let pool = self.store.pool.clone();
        let address = address.to_string();
        let record = record.to_vec();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            diesel::insert_into(sender_keys::table)
                .values((
                    sender_keys::address.eq(&address),
                    sender_keys::record.eq(&record),
                    sender_keys::device_id.eq(device_id),
                ))
                .on_conflict((sender_keys::address, sender_keys::device_id))
                .do_update()
                .set(sender_keys::record.eq(&record))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn get_sender_key(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let pool = self.store.pool.clone();
        let address = address.to_string();
        let device_id = self.device_id;

        let result = tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            let res: Option<Vec<u8>> = sender_keys::table
                .select(sender_keys::record)
                .filter(sender_keys::address.eq(&address))
                .filter(sender_keys::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(res)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        Ok(result)
    }

    async fn delete_sender_key(&self, address: &str) -> Result<()> {
        let pool = self.store.pool.clone();
        let address = address.to_string();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            diesel::delete(
                sender_keys::table
                    .filter(sender_keys::address.eq(&address))
                    .filter(sender_keys::device_id.eq(device_id)),
            )
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }
}

#[async_trait]
impl AppStateKeyStore for DeviceAwareSqliteStore {
    async fn get_app_state_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        let pool = self.store.pool.clone();
        let key_id = key_id.to_vec();
        let device_id = self.device_id;

        let result = tokio::task::spawn_blocking(move || -> Result<Option<AppStateSyncKey>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            let res: Option<Vec<u8>> = app_state_keys::table
                .select(app_state_keys::key_data)
                .filter(app_state_keys::key_id.eq(&key_id))
                .filter(app_state_keys::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;

            Ok(res.map(|key_data| AppStateSyncKey {
                key_data,
                fingerprint: Vec::new(), // TODO: store fingerprint separately if needed
                timestamp: 0,            // TODO: store timestamp separately if needed
            }))
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        Ok(result)
    }

    async fn set_app_state_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        let pool = self.store.pool.clone();
        let key_id = key_id.to_vec();
        let key_data = key.key_data;
        let device_id = self.device_id;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            diesel::insert_into(app_state_keys::table)
                .values((
                    app_state_keys::key_id.eq(&key_id),
                    app_state_keys::key_data.eq(&key_data),
                    app_state_keys::device_id.eq(device_id),
                ))
                .on_conflict((app_state_keys::key_id, app_state_keys::device_id))
                .do_update()
                .set(app_state_keys::key_data.eq(&key_data))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }
}

#[async_trait]
impl AppStateStore for DeviceAwareSqliteStore {
    async fn get_app_state_version(&self, name: &str) -> Result<HashState> {
        let pool = self.store.pool.clone();
        let name = name.to_string();
        let device_id = self.device_id;

        let result = tokio::task::spawn_blocking(move || -> Result<HashState> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            let res: Option<Vec<u8>> = app_state_versions::table
                .select(app_state_versions::state_data)
                .filter(app_state_versions::name.eq(&name))
                .filter(app_state_versions::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;

            match res {
                Some(data) => {
                    let (state, _) =
                        bincode::serde::decode_from_slice(&data, bincode::config::standard())
                            .map_err(|e| StoreError::Serialization(e.to_string()))?;
                    Ok(state)
                }
                None => Ok(HashState::default()),
            }
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        Ok(result)
    }

    async fn set_app_state_version(&self, name: &str, state: HashState) -> Result<()> {
        let pool = self.store.pool.clone();
        let name = name.to_string();
        let device_id = self.device_id;
        let state_data = bincode::serde::encode_to_vec(&state, bincode::config::standard())
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            diesel::insert_into(app_state_versions::table)
                .values((
                    app_state_versions::name.eq(&name),
                    app_state_versions::state_data.eq(&state_data),
                    app_state_versions::device_id.eq(device_id),
                ))
                .on_conflict((app_state_versions::name, app_state_versions::device_id))
                .do_update()
                .set(app_state_versions::state_data.eq(&state_data))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn put_app_state_mutation_macs(
        &self,
        name: &str,
        version: u64,
        mutations: &[AppStateMutationMAC],
    ) -> Result<()> {
        if mutations.is_empty() {
            return Ok(());
        }

        let pool = self.store.pool.clone();
        let name = name.to_string();
        let device_id = self.device_id;
        let mutations: Vec<AppStateMutationMAC> = mutations.to_vec();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            for m in mutations {
                diesel::insert_into(app_state_mutation_macs::table)
                    .values((
                        app_state_mutation_macs::name.eq(&name),
                        app_state_mutation_macs::version.eq(version as i64),
                        app_state_mutation_macs::index_mac.eq(&m.index_mac),
                        app_state_mutation_macs::value_mac.eq(&m.value_mac),
                        app_state_mutation_macs::device_id.eq(device_id),
                    ))
                    .on_conflict((
                        app_state_mutation_macs::name,
                        app_state_mutation_macs::index_mac,
                        app_state_mutation_macs::device_id,
                    ))
                    .do_update()
                    .set((
                        app_state_mutation_macs::version.eq(version as i64),
                        app_state_mutation_macs::value_mac.eq(&m.value_mac),
                    ))
                    .execute(&mut conn)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn delete_app_state_mutation_macs(
        &self,
        name: &str,
        index_macs: &[Vec<u8>],
    ) -> Result<()> {
        if index_macs.is_empty() {
            return Ok(());
        }

        let pool = self.store.pool.clone();
        let name = name.to_string();
        let device_id = self.device_id;
        let index_macs: Vec<Vec<u8>> = index_macs.to_vec();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            for index_mac in index_macs {
                diesel::delete(
                    app_state_mutation_macs::table
                        .filter(app_state_mutation_macs::name.eq(&name))
                        .filter(app_state_mutation_macs::index_mac.eq(&index_mac))
                        .filter(app_state_mutation_macs::device_id.eq(device_id)),
                )
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            }
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn get_app_state_mutation_mac(
        &self,
        name: &str,
        index_mac: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let pool = self.store.pool.clone();
        let name = name.to_string();
        let index_mac = index_mac.to_vec();
        let device_id = self.device_id;

        let result = tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            let res: Option<Vec<u8>> = app_state_mutation_macs::table
                .select(app_state_mutation_macs::value_mac)
                .filter(app_state_mutation_macs::name.eq(&name))
                .filter(app_state_mutation_macs::index_mac.eq(&index_mac))
                .filter(app_state_mutation_macs::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(res)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        Ok(result)
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
    async fn save_device_data(&self, device_data: &wacore::store::Device) -> wacore::store::error::Result<()> {
        self.store.save_device_data(device_data).await
    }
    
    async fn save_device_data_for_device(&self, device_id: i32, device_data: &wacore::store::Device) -> wacore::store::error::Result<()> {
        self.store.save_device_data_for_device(device_id, device_data).await
    }
    
    async fn load_device_data(&self) -> wacore::store::error::Result<Option<wacore::store::Device>> {
        self.store.load_device_data().await
    }
    
    async fn load_device_data_for_device(&self, device_id: i32) -> wacore::store::error::Result<Option<wacore::store::Device>> {
        self.store.load_device_data_for_device(device_id).await
    }
}

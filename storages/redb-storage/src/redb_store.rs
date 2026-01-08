use async_trait::async_trait;
use prost::Message;
use redb::{
    Builder, Database, ReadableDatabase, ReadableTable, TableError, backends::InMemoryBackend,
};
use std::path::Path;
use std::sync::Arc;
use wacore::appstate::hash::HashState;
use wacore::appstate::processor::AppStateMutationMAC;
use wacore::store::Device as CoreDevice;
use wacore::store::error::{Result, StoreError, db_err};
use wacore::store::traits::*;
use waproto::whatsapp as wa;

use crate::keys::{KeyBuilder, decode, deserialize_keypair, encode, serialize_keypair};
use crate::schema::*;
use crate::types::SerializableDevice;

macro_rules! open_table_or_default {
    ($txn:expr, $table:expr, $default:expr) => {
        match $txn.open_table($table) {
            Ok(t) => t,
            Err(TableError::TableDoesNotExist(_)) => return Ok($default),
            Err(e) => return Err(StoreError::Database(e.to_string())),
        }
    };
}

#[derive(Clone)]
pub struct RedbStore {
    db: Arc<Database>,
    device_id: i32,
}

impl RedbStore {
    pub async fn new<P: AsRef<Path> + Send + 'static>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        let db = tokio::task::spawn_blocking(move || -> Result<Database> {
            Database::create(&path).map_err(db_err)
        })
        .await
        .map_err(db_err)??;

        Ok(Self {
            db: Arc::new(db),
            device_id: 1,
        })
    }

    pub async fn new_for_device<P: AsRef<Path> + Send + 'static>(
        path: P,
        device_id: i32,
    ) -> Result<Self> {
        let mut store = Self::new(path).await?;
        store.device_id = device_id;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self> {
        let db = Builder::new()
            .create_with_backend(InMemoryBackend::new())
            .map_err(db_err)?;

        Ok(Self {
            db: Arc::new(db),
            device_id: 1,
        })
    }

    pub fn in_memory_for_device(device_id: i32) -> Result<Self> {
        let db = Builder::new()
            .create_with_backend(InMemoryBackend::new())
            .map_err(db_err)?;

        Ok(Self {
            db: Arc::new(db),
            device_id,
        })
    }

    pub fn device_id(&self) -> i32 {
        self.device_id
    }

    #[inline]
    fn keys(&self) -> KeyBuilder {
        KeyBuilder::new(self.device_id)
    }
}

#[async_trait]
impl SignalStore for RedbStore {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()> {
        let db = self.db.clone();
        let key_str = self.keys().key1(address);
        let key_data = key.to_vec();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(IDENTITIES).map_err(db_err)?;
                table
                    .insert(key_str.as_str(), key_data.as_slice())
                    .map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn load_identity(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let db = self.db.clone();
        let key_str = self.keys().key1(address);

        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, IDENTITIES, None);

            match table.get(key_str.as_str()) {
                Ok(Some(guard)) => Ok(Some(guard.value().to_vec())),
                Ok(None) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        let db = self.db.clone();
        let key_str = self.keys().key1(address);

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(IDENTITIES).map_err(db_err)?;
                table.remove(key_str.as_str()).map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let db = self.db.clone();
        let key_str = self.keys().key1(address);

        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, SESSIONS, None);

            match table.get(key_str.as_str()) {
                Ok(Some(guard)) => Ok(Some(guard.value().to_vec())),
                Ok(None) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()> {
        let db = self.db.clone();
        let key_str = self.keys().key1(address);
        let session_data = session.to_vec();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(SESSIONS).map_err(db_err)?;
                table
                    .insert(key_str.as_str(), session_data.as_slice())
                    .map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn delete_session(&self, address: &str) -> Result<()> {
        let db = self.db.clone();
        let key_str = self.keys().key1(address);

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(SESSIONS).map_err(db_err)?;
                table.remove(key_str.as_str()).map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn store_prekey(&self, id: u32, record: &[u8], uploaded: bool) -> Result<()> {
        let db = self.db.clone();
        let packed_key = self.keys().pack_id(id);
        let record_data = record.to_vec();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut prekey_table = write_txn.open_table(PREKEYS).map_err(db_err)?;
                prekey_table
                    .insert(packed_key, record_data.as_slice())
                    .map_err(db_err)?;

                let mut uploaded_table = write_txn.open_table(PREKEYS_UPLOADED).map_err(db_err)?;
                uploaded_table
                    .insert(packed_key, uploaded)
                    .map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn load_prekey(&self, id: u32) -> Result<Option<Vec<u8>>> {
        let db = self.db.clone();
        let packed_key = self.keys().pack_id(id);

        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, PREKEYS, None);

            match table.get(packed_key) {
                Ok(Some(guard)) => Ok(Some(guard.value().to_vec())),
                Ok(None) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn remove_prekey(&self, id: u32) -> Result<()> {
        let db = self.db.clone();
        let packed_key = self.keys().pack_id(id);

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut prekey_table = write_txn.open_table(PREKEYS).map_err(db_err)?;
                prekey_table.remove(packed_key).map_err(db_err)?;

                let mut uploaded_table = write_txn.open_table(PREKEYS_UPLOADED).map_err(db_err)?;
                uploaded_table.remove(packed_key).map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn store_signed_prekey(&self, id: u32, record: &[u8]) -> Result<()> {
        let db = self.db.clone();
        let packed_key = self.keys().pack_id(id);
        let record_data = record.to_vec();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(SIGNED_PREKEYS).map_err(db_err)?;
                table
                    .insert(packed_key, record_data.as_slice())
                    .map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn load_signed_prekey(&self, id: u32) -> Result<Option<Vec<u8>>> {
        let db = self.db.clone();
        let packed_key = self.keys().pack_id(id);

        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, SIGNED_PREKEYS, None);

            match table.get(packed_key) {
                Ok(Some(guard)) => Ok(Some(guard.value().to_vec())),
                Ok(None) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn load_all_signed_prekeys(&self) -> Result<Vec<(u32, Vec<u8>)>> {
        let db = self.db.clone();
        let range = self.keys().pack_id_range();

        tokio::task::spawn_blocking(move || -> Result<Vec<(u32, Vec<u8>)>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, SIGNED_PREKEYS, Vec::new());

            let mut results = Vec::new();
            let iter = table.range(range).map_err(db_err)?;

            for entry in iter {
                let (key_guard, value_guard) = entry.map_err(db_err)?;
                let packed = key_guard.value();
                let prekey_id = (packed & 0xFFFFFFFF) as u32;
                results.push((prekey_id, value_guard.value().to_vec()));
            }

            Ok(results)
        })
        .await
        .map_err(db_err)?
    }

    async fn remove_signed_prekey(&self, id: u32) -> Result<()> {
        let db = self.db.clone();
        let packed_key = self.keys().pack_id(id);

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(SIGNED_PREKEYS).map_err(db_err)?;
                table.remove(packed_key).map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn put_sender_key(&self, address: &str, record: &[u8]) -> Result<()> {
        let db = self.db.clone();
        let key_str = self.keys().key1(address);
        let record_data = record.to_vec();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(SENDER_KEYS).map_err(db_err)?;
                table
                    .insert(key_str.as_str(), record_data.as_slice())
                    .map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn get_sender_key(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let db = self.db.clone();
        let key_str = self.keys().key1(address);

        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, SENDER_KEYS, None);

            match table.get(key_str.as_str()) {
                Ok(Some(guard)) => Ok(Some(guard.value().to_vec())),
                Ok(None) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn delete_sender_key(&self, address: &str) -> Result<()> {
        let db = self.db.clone();
        let key_str = self.keys().key1(address);

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(SENDER_KEYS).map_err(db_err)?;
                table.remove(key_str.as_str()).map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }
}

#[async_trait]
impl AppSyncStore for RedbStore {
    async fn get_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        let db = self.db.clone();
        let full_key = self.keys().app_state_key(key_id);

        tokio::task::spawn_blocking(move || -> Result<Option<AppStateSyncKey>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, APP_STATE_KEYS, None);

            match table.get(full_key.as_slice()) {
                Ok(Some(guard)) => {
                    let key: AppStateSyncKey = decode(guard.value())?;
                    Ok(Some(key))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn set_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        let db = self.db.clone();
        let full_key = self.keys().app_state_key(key_id);
        let data = encode(&key)?;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(APP_STATE_KEYS).map_err(db_err)?;
                table
                    .insert(full_key.as_slice(), data.as_slice())
                    .map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn get_version(&self, name: &str) -> Result<HashState> {
        let db = self.db.clone();
        let key_str = self.keys().key1(name);

        tokio::task::spawn_blocking(move || -> Result<HashState> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, APP_STATE_VERSIONS, HashState::default());

            match table.get(key_str.as_str()) {
                Ok(Some(guard)) => {
                    let state: HashState = decode(guard.value())?;
                    Ok(state)
                }
                Ok(None) => Ok(HashState::default()),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn set_version(&self, name: &str, state: HashState) -> Result<()> {
        let db = self.db.clone();
        let key_str = self.keys().key1(name);
        let data = encode(&state)?;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(APP_STATE_VERSIONS).map_err(db_err)?;
                table
                    .insert(key_str.as_str(), data.as_slice())
                    .map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn put_mutation_macs(
        &self,
        name: &str,
        _version: u64,
        mutations: &[AppStateMutationMAC],
    ) -> Result<()> {
        if mutations.is_empty() {
            return Ok(());
        }

        let db = self.db.clone();
        let device_id = self.device_id;
        let name = name.to_string();
        let mutations = mutations.to_vec();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(MUTATION_MACS).map_err(db_err)?;

                for m in mutations {
                    let key = format!("{}:{}:{}", device_id, name, hex::encode(&m.index_mac));
                    table
                        .insert(key.as_str(), m.value_mac.as_slice())
                        .map_err(db_err)?;
                }
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn get_mutation_mac(&self, name: &str, index_mac: &[u8]) -> Result<Option<Vec<u8>>> {
        let db = self.db.clone();
        let key = self.keys().key2(name, &hex::encode(index_mac));

        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, MUTATION_MACS, None);

            match table.get(key.as_str()) {
                Ok(Some(guard)) => Ok(Some(guard.value().to_vec())),
                Ok(None) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn delete_mutation_macs(&self, name: &str, index_macs: &[Vec<u8>]) -> Result<()> {
        if index_macs.is_empty() {
            return Ok(());
        }

        let db = self.db.clone();
        let device_id = self.device_id;
        let name = name.to_string();
        let index_macs = index_macs.to_vec();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(MUTATION_MACS).map_err(db_err)?;

                for index_mac in index_macs {
                    let key = format!("{}:{}:{}", device_id, name, hex::encode(&index_mac));
                    table.remove(key.as_str()).map_err(db_err)?;
                }
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }
}

#[async_trait]
impl ProtocolStore for RedbStore {
    async fn get_skdm_recipients(&self, group_jid: &str) -> Result<Vec<String>> {
        let db = self.db.clone();
        let key_str = self.keys().key1(group_jid);

        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, SKDM_RECIPIENTS, Vec::new());

            match table.get(key_str.as_str()) {
                Ok(Some(guard)) => {
                    let recipients: Vec<String> = decode(guard.value())?;
                    Ok(recipients)
                }
                Ok(None) => Ok(Vec::new()),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn add_skdm_recipients(&self, group_jid: &str, device_jids: &[String]) -> Result<()> {
        if device_jids.is_empty() {
            return Ok(());
        }

        let db = self.db.clone();
        let key_str = self.keys().key1(group_jid);
        let new_jids = device_jids.to_vec();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(SKDM_RECIPIENTS).map_err(db_err)?;

                let mut recipients: Vec<String> = match table.get(key_str.as_str()) {
                    Ok(Some(guard)) => decode(guard.value())?,
                    Ok(None) => Vec::new(),
                    Err(e) => return Err(db_err(e)),
                };

                for jid in new_jids {
                    if !recipients.contains(&jid) {
                        recipients.push(jid);
                    }
                }

                let data = encode(&recipients)?;
                table
                    .insert(key_str.as_str(), data.as_slice())
                    .map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn clear_skdm_recipients(&self, group_jid: &str) -> Result<()> {
        let db = self.db.clone();
        let key_str = self.keys().key1(group_jid);

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(SKDM_RECIPIENTS).map_err(db_err)?;
                table.remove(key_str.as_str()).map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn get_lid_mapping(&self, lid: &str) -> Result<Option<LidPnMappingEntry>> {
        let db = self.db.clone();
        let key_str = self.keys().key1(lid);

        tokio::task::spawn_blocking(move || -> Result<Option<LidPnMappingEntry>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, LID_PN_MAPPING, None);

            match table.get(key_str.as_str()) {
                Ok(Some(guard)) => {
                    let entry: LidPnMappingEntry = decode(guard.value())?;
                    Ok(Some(entry))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn get_pn_mapping(&self, phone: &str) -> Result<Option<LidPnMappingEntry>> {
        let db = self.db.clone();
        let key_str = self.keys().key1(phone);

        tokio::task::spawn_blocking(move || -> Result<Option<LidPnMappingEntry>> {
            let read_txn = db.begin_read().map_err(db_err)?;

            let index_table = open_table_or_default!(read_txn, PN_LID_INDEX, None);

            let lid_key = match index_table.get(key_str.as_str()) {
                Ok(Some(guard)) => guard.value().to_string(),
                Ok(None) => return Ok(None),
                Err(e) => return Err(db_err(e)),
            };

            let mapping_table = open_table_or_default!(read_txn, LID_PN_MAPPING, None);

            match mapping_table.get(lid_key.as_str()) {
                Ok(Some(guard)) => {
                    let entry: LidPnMappingEntry = decode(guard.value())?;
                    Ok(Some(entry))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn put_lid_mapping(&self, entry: &LidPnMappingEntry) -> Result<()> {
        let db = self.db.clone();
        let lid_key = self.keys().key1(&entry.lid);
        let pn_key = self.keys().key1(&entry.phone_number);
        let data = encode(entry)?;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut mapping_table = write_txn.open_table(LID_PN_MAPPING).map_err(db_err)?;
                mapping_table
                    .insert(lid_key.as_str(), data.as_slice())
                    .map_err(db_err)?;

                let mut index_table = write_txn.open_table(PN_LID_INDEX).map_err(db_err)?;
                index_table
                    .insert(pn_key.as_str(), lid_key.as_str())
                    .map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn get_all_lid_mappings(&self) -> Result<Vec<LidPnMappingEntry>> {
        let db = self.db.clone();
        let prefix = self.keys().prefix();

        tokio::task::spawn_blocking(move || -> Result<Vec<LidPnMappingEntry>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, LID_PN_MAPPING, Vec::new());

            let mut results = Vec::new();
            let range = table.range::<&str>(..).map_err(db_err)?;

            for entry in range {
                let (key_guard, value_guard) = entry.map_err(db_err)?;

                if key_guard.value().starts_with(&prefix) {
                    let mapping: LidPnMappingEntry = decode(value_guard.value())?;
                    results.push(mapping);
                }
            }

            Ok(results)
        })
        .await
        .map_err(db_err)?
    }

    async fn save_base_key(&self, address: &str, message_id: &str, base_key: &[u8]) -> Result<()> {
        let db = self.db.clone();
        let key_str = self.keys().key2(address, message_id);
        let base_key = base_key.to_vec();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(BASE_KEYS).map_err(db_err)?;
                table
                    .insert(key_str.as_str(), base_key.as_slice())
                    .map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn has_same_base_key(
        &self,
        address: &str,
        message_id: &str,
        current_base_key: &[u8],
    ) -> Result<bool> {
        let db = self.db.clone();
        let key_str = self.keys().key2(address, message_id);
        let current_base_key = current_base_key.to_vec();

        tokio::task::spawn_blocking(move || -> Result<bool> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, BASE_KEYS, false);

            match table.get(key_str.as_str()) {
                Ok(Some(guard)) => Ok(guard.value() == current_base_key.as_slice()),
                Ok(None) => Ok(false),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn delete_base_key(&self, address: &str, message_id: &str) -> Result<()> {
        let db = self.db.clone();
        let key_str = self.keys().key2(address, message_id);

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(BASE_KEYS).map_err(db_err)?;
                table.remove(key_str.as_str()).map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn update_device_list(&self, record: DeviceListRecord) -> Result<()> {
        let db = self.db.clone();
        let key_str = self.keys().key1(&record.user);
        let data = encode(&record)?;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(DEVICE_REGISTRY).map_err(db_err)?;
                table
                    .insert(key_str.as_str(), data.as_slice())
                    .map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn get_devices(&self, user: &str) -> Result<Option<DeviceListRecord>> {
        let db = self.db.clone();
        let key_str = self.keys().key1(user);

        tokio::task::spawn_blocking(move || -> Result<Option<DeviceListRecord>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, DEVICE_REGISTRY, None);

            match table.get(key_str.as_str()) {
                Ok(Some(guard)) => {
                    let record: DeviceListRecord = decode(guard.value())?;
                    Ok(Some(record))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn mark_forget_sender_key(&self, group_jid: &str, participant: &str) -> Result<()> {
        let db = self.db.clone();
        let key_str = self.keys().key1(group_jid);
        let participant = participant.to_string();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(SENDER_KEY_STATUS).map_err(db_err)?;

                let mut participants: Vec<String> = match table.get(key_str.as_str()) {
                    Ok(Some(guard)) => decode(guard.value())?,
                    Ok(None) => Vec::new(),
                    Err(e) => return Err(db_err(e)),
                };

                if !participants.contains(&participant) {
                    participants.push(participant);
                }

                let data = encode(&participants)?;
                table
                    .insert(key_str.as_str(), data.as_slice())
                    .map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn consume_forget_marks(&self, group_jid: &str) -> Result<Vec<String>> {
        let db = self.db.clone();
        let key_str = self.keys().key1(group_jid);

        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let write_txn = db.begin_write().map_err(db_err)?;

            let participants: Vec<String>;
            {
                let mut table = write_txn.open_table(SENDER_KEY_STATUS).map_err(db_err)?;

                participants = match table.get(key_str.as_str()) {
                    Ok(Some(guard)) => decode(guard.value())?,
                    Ok(None) => Vec::new(),
                    Err(e) => return Err(db_err(e)),
                };

                table.remove(key_str.as_str()).map_err(db_err)?;
            }

            write_txn.commit().map_err(db_err)?;

            Ok(participants)
        })
        .await
        .map_err(db_err)?
    }
}

#[async_trait]
impl DeviceStore for RedbStore {
    async fn save(&self, device: &CoreDevice) -> Result<()> {
        let db = self.db.clone();
        let device_id = self.device_id;

        let serializable = SerializableDevice {
            lid: device.lid.as_ref().map(|j| j.to_string()),
            pn: device.pn.as_ref().map(|j| j.to_string()),
            registration_id: device.registration_id,
            noise_key: serialize_keypair(&device.noise_key),
            identity_key: serialize_keypair(&device.identity_key),
            signed_pre_key: serialize_keypair(&device.signed_pre_key),
            signed_pre_key_id: device.signed_pre_key_id,
            signed_pre_key_signature: device.signed_pre_key_signature.to_vec(),
            adv_secret_key: device.adv_secret_key.to_vec(),
            account: device.account.as_ref().map(|a| a.encode_to_vec()),
            push_name: device.push_name.clone(),
            app_version_primary: device.app_version_primary,
            app_version_secondary: device.app_version_secondary,
            app_version_tertiary: device.app_version_tertiary,
            app_version_last_fetched_ms: device.app_version_last_fetched_ms,
            edge_routing_info: device.edge_routing_info.clone(),
        };

        let data = encode(&serializable)?;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = write_txn.open_table(DEVICE_DATA).map_err(db_err)?;
                table.insert(device_id, data.as_slice()).map_err(db_err)?;
            }
            write_txn.commit().map_err(db_err)?;
            Ok(())
        })
        .await
        .map_err(db_err)??;

        Ok(())
    }

    async fn load(&self) -> Result<Option<CoreDevice>> {
        let db = self.db.clone();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(move || -> Result<Option<CoreDevice>> {
            let read_txn = db.begin_read().map_err(db_err)?;
            let table = open_table_or_default!(read_txn, DEVICE_DATA, None);

            let data = match table.get(device_id) {
                Ok(Some(guard)) => guard.value().to_vec(),
                Ok(None) => return Ok(None),
                Err(e) => return Err(db_err(e)),
            };

            let serializable: SerializableDevice = decode(&data)?;

            let noise_key = deserialize_keypair(&serializable.noise_key)?;
            let identity_key = deserialize_keypair(&serializable.identity_key)?;
            let signed_pre_key = deserialize_keypair(&serializable.signed_pre_key)?;

            let signed_pre_key_signature: [u8; 64] = serializable
                .signed_pre_key_signature
                .try_into()
                .map_err(|_| {
                    StoreError::Serialization("Invalid signed_pre_key_signature length".to_string())
                })?;

            let adv_secret_key: [u8; 32] =
                serializable.adv_secret_key.try_into().map_err(|_| {
                    StoreError::Serialization("Invalid adv_secret_key length".to_string())
                })?;

            let account = serializable
                .account
                .map(|data| {
                    wa::AdvSignedDeviceIdentity::decode(&data[..])
                        .map_err(|e| StoreError::Serialization(e.to_string()))
                })
                .transpose()?;

            let lid = serializable.lid.and_then(|s| s.parse().ok());
            let pn = serializable.pn.and_then(|s| s.parse().ok());

            Ok(Some(CoreDevice {
                pn,
                lid,
                registration_id: serializable.registration_id,
                noise_key,
                identity_key,
                signed_pre_key,
                signed_pre_key_id: serializable.signed_pre_key_id,
                signed_pre_key_signature,
                adv_secret_key,
                account,
                push_name: serializable.push_name,
                app_version_primary: serializable.app_version_primary,
                app_version_secondary: serializable.app_version_secondary,
                app_version_tertiary: serializable.app_version_tertiary,
                app_version_last_fetched_ms: serializable.app_version_last_fetched_ms,
                device_props: {
                    use wacore::store::device::DEVICE_PROPS;
                    DEVICE_PROPS.clone()
                },
                edge_routing_info: serializable.edge_routing_info,
            }))
        })
        .await
        .map_err(db_err)?
    }

    async fn exists(&self) -> Result<bool> {
        let db = self.db.clone();
        let device_id = self.device_id;

        tokio::task::spawn_blocking(move || -> Result<bool> {
            let read_txn = db.begin_read().map_err(db_err)?;

            let table = match read_txn.open_table(DEVICE_DATA) {
                Ok(t) => t,
                Err(TableError::TableDoesNotExist(_)) => return Ok(false),
                Err(e) => return Err(db_err(e)),
            };

            match table.get(device_id) {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(e) => Err(db_err(e)),
            }
        })
        .await
        .map_err(db_err)?
    }

    async fn create(&self) -> Result<i32> {
        let db = self.db.clone();

        tokio::task::spawn_blocking(move || -> Result<i32> {
            let write_txn = db.begin_write().map_err(db_err)?;

            let new_device_id: i32;
            {
                let mut counter_table = write_txn.open_table(DEVICE_COUNTER).map_err(db_err)?;

                let current = match counter_table.get("next_id") {
                    Ok(Some(guard)) => guard.value(),
                    Ok(None) => 1,
                    Err(e) => return Err(db_err(e)),
                };

                new_device_id = current;

                counter_table
                    .insert("next_id", current + 1)
                    .map_err(db_err)?;

                let new_device = wacore::store::Device::new();

                let serializable = SerializableDevice {
                    lid: None,
                    pn: None,
                    registration_id: new_device.registration_id,
                    noise_key: serialize_keypair(&new_device.noise_key),
                    identity_key: serialize_keypair(&new_device.identity_key),
                    signed_pre_key: serialize_keypair(&new_device.signed_pre_key),
                    signed_pre_key_id: new_device.signed_pre_key_id,
                    signed_pre_key_signature: new_device.signed_pre_key_signature.to_vec(),
                    adv_secret_key: new_device.adv_secret_key.to_vec(),
                    account: None,
                    push_name: new_device.push_name,
                    app_version_primary: new_device.app_version_primary,
                    app_version_secondary: new_device.app_version_secondary,
                    app_version_tertiary: new_device.app_version_tertiary,
                    app_version_last_fetched_ms: new_device.app_version_last_fetched_ms,
                    edge_routing_info: None,
                };

                let data = encode(&serializable)?;

                let mut device_table = write_txn.open_table(DEVICE_DATA).map_err(db_err)?;
                device_table
                    .insert(new_device_id, data.as_slice())
                    .map_err(db_err)?;
            }

            write_txn.commit().map_err(db_err)?;

            Ok(new_device_id)
        })
        .await
        .map_err(db_err)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_store() -> RedbStore {
        RedbStore::in_memory().expect("Failed to create test store")
    }

    #[tokio::test]
    async fn test_identity_store() {
        let store = create_test_store();

        let address = "test@s.whatsapp.net";
        let key = [42u8; 32];

        store.put_identity(address, key).await.unwrap();

        let loaded = store.load_identity(address).await.unwrap();
        assert_eq!(loaded, Some(key.to_vec()));

        store.delete_identity(address).await.unwrap();
        let loaded = store.load_identity(address).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_session_store() {
        let store = create_test_store();

        let address = "test@s.whatsapp.net";
        let session = vec![1, 2, 3, 4, 5];

        store.put_session(address, &session).await.unwrap();

        let loaded = store.get_session(address).await.unwrap();
        assert_eq!(loaded, Some(session));

        store.delete_session(address).await.unwrap();
        let loaded = store.get_session(address).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_prekey_store() {
        let store = create_test_store();

        let id = 123u32;
        let record = vec![1, 2, 3, 4, 5];

        store.store_prekey(id, &record, true).await.unwrap();

        let loaded = store.load_prekey(id).await.unwrap();
        assert_eq!(loaded, Some(record));

        store.remove_prekey(id).await.unwrap();
        let loaded = store.load_prekey(id).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_device_store() {
        let store = create_test_store();

        assert!(!store.exists().await.unwrap());

        let device_id = store.create().await.unwrap();
        assert_eq!(device_id, 1);

        assert!(store.exists().await.unwrap());

        let device = store.load().await.unwrap();
        assert!(device.is_some());
    }

    #[tokio::test]
    async fn test_skdm_recipients() {
        let store = create_test_store();

        let group = "group@g.us";
        let recipients = vec!["user1@s.whatsapp.net".to_string()];

        store.add_skdm_recipients(group, &recipients).await.unwrap();

        let loaded = store.get_skdm_recipients(group).await.unwrap();
        assert_eq!(loaded, recipients);

        store.clear_skdm_recipients(group).await.unwrap();
        let loaded = store.get_skdm_recipients(group).await.unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn test_sender_key_status() {
        let store = create_test_store();

        let group = "group@g.us";
        let participant = "user@s.whatsapp.net";

        store
            .mark_forget_sender_key(group, participant)
            .await
            .unwrap();

        let marks = store.consume_forget_marks(group).await.unwrap();
        assert_eq!(marks.len(), 1);
        assert!(marks.contains(&participant.to_string()));

        let marks = store.consume_forget_marks(group).await.unwrap();
        assert!(marks.is_empty());
    }

    #[tokio::test]
    async fn test_first_run_empty_reads() {
        let store = create_test_store();

        assert!(
            store
                .load_identity("test@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_session("test@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.load_prekey(1).await.unwrap().is_none());
        assert!(store.load_signed_prekey(1).await.unwrap().is_none());
        assert!(store.load_all_signed_prekeys().await.unwrap().is_empty());
        assert!(
            store
                .get_sender_key("group:sender")
                .await
                .unwrap()
                .is_none()
        );

        assert!(store.get_sync_key(&[1, 2, 3]).await.unwrap().is_none());
        let version = store.get_version("critical_block").await.unwrap();
        assert_eq!(version.version, 0);
        assert!(
            store
                .get_mutation_mac("test", &[1, 2, 3])
                .await
                .unwrap()
                .is_none()
        );

        assert!(
            store
                .get_skdm_recipients("group@g.us")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .get_lid_mapping("123456789@lid")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_pn_mapping("123456789@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.get_all_lid_mappings().await.unwrap().is_empty());
        assert!(
            store
                .get_devices("test@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .consume_forget_marks("group@g.us")
                .await
                .unwrap()
                .is_empty()
        );

        assert!(!store.exists().await.unwrap());
        assert!(store.load().await.unwrap().is_none());
    }
}

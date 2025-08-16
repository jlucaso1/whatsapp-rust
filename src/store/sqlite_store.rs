use crate::store::schema::*;
use crate::store::traits::*;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use prost::Message;
use std::collections::VecDeque;
use wacore::appstate::hash::HashState;
use wacore::libsignal::protocol::{Direction, KeyPair, PrivateKey, PublicKey};
use wacore::signal;
use wacore::store::error::{Result, StoreError};
use wacore::store::traits::AppStateMutationMAC;
use waproto::whatsapp::{self as wa, PreKeyRecordStructure, SignedPreKeyRecordStructure};

use wacore::store::Device as CoreDevice;

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = chat_conversations)]
struct ChatConversationChanges<'a> {
    pub id: &'a str,
    pub name: Option<&'a str>,
    pub display_name: Option<&'a str>,
    pub last_msg_timestamp: Option<i32>,
    pub unread_count: Option<i32>,
    pub archived: Option<i32>,
    pub pinned: Option<i32>,
    pub created_at: Option<i32>,
}

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

        {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            conn.run_pending_migrations(MIGRATIONS)
                .map_err(|e| StoreError::Migration(e.to_string()))?;
            // Reduce 'database is locked' errors during concurrent history/app state sync writes
            let _ = diesel::sql_query("PRAGMA busy_timeout = 5000;").execute(&mut conn);
        }

        Ok(Self { pool })
    }

    pub fn begin_transaction(
        &self,
    ) -> Result<diesel::r2d2::PooledConnection<ConnectionManager<SqliteConnection>>> {
        let mut conn = self.get_connection()?;
        diesel::sql_query("BEGIN IMMEDIATE TRANSACTION;")
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(conn)
    }
    pub fn commit_transaction(
        &self,
        conn: &mut diesel::r2d2::PooledConnection<ConnectionManager<SqliteConnection>>,
    ) -> Result<()> {
        diesel::sql_query("COMMIT;")
            .execute(conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }
    pub fn rollback_transaction(
        &self,
        conn: &mut diesel::r2d2::PooledConnection<ConnectionManager<SqliteConnection>>,
    ) -> Result<()> {
        diesel::sql_query("ROLLBACK;")
            .execute(conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
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

    pub async fn save_device_data(&self, device_data: &CoreDevice) -> Result<()> {
        let mut conn = self.get_connection()?;

        let noise_key_data = self.serialize_keypair(&device_data.noise_key)?;
        let identity_key_data = self.serialize_keypair(&device_data.identity_key)?;
        let signed_pre_key_data = self.serialize_keypair(&device_data.signed_pre_key)?;

        let account_data = device_data
            .account
            .as_ref()
            .map(|account| account.encode_to_vec());

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
                device::id.eq(1),
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
                device::processed_messages.eq(processed_messages_data.as_deref()),
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
                device::processed_messages.eq(processed_messages_data.as_deref()),
            ))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    pub async fn load_device_data(&self) -> Result<Option<CoreDevice>> {
        let mut conn = self.get_connection()?;

        let result = device::table
            .filter(device::id.eq(1))
            .first::<(
                Option<i32>,
                Option<String>,
                Option<String>,
                i32,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                i32,
                Vec<u8>,
                Vec<u8>,
                Option<Vec<u8>>,
                String,
                Option<Vec<u8>>,
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

            let noise_key = self.deserialize_keypair(&noise_key_data)?;
            let identity_key = self.deserialize_keypair(&identity_key_data)?;
            let signed_pre_key = self.deserialize_keypair(&signed_pre_key_data)?;

            let mut signed_pre_key_signature = [0u8; 64];
            if signed_pre_key_signature_data.len() == 64 {
                signed_pre_key_signature.copy_from_slice(&signed_pre_key_signature_data);
            } else {
                return Err(StoreError::Serialization(
                    "Invalid signature length".to_string(),
                ));
            }

            let mut adv_secret_key = [0u8; 32];
            if adv_secret_key_data.len() == 32 {
                adv_secret_key.copy_from_slice(&adv_secret_key_data);
            } else {
                return Err(StoreError::Serialization(
                    "Invalid secret key length".to_string(),
                ));
            }

            let account = if let Some(account_data) = account_data {
                Some(
                    wa::AdvSignedDeviceIdentity::decode(account_data.as_slice())
                        .map_err(|e| StoreError::Serialization(e.to_string()))?,
                )
            } else {
                None
            };

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

            Ok(Some(CoreDevice {
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

    pub async fn save_conversation_raw(&self, id: &str, data: &[u8]) -> Result<()> {
        let mut conn = self.get_connection()?;
        diesel::insert_into(conversations::table)
            .values((conversations::id.eq(id), conversations::data.eq(data)))
            .on_conflict(conversations::id)
            .do_update()
            .set(conversations::data.eq(data))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }

    fn upsert_conversation_normalized(
        &self,
        conn: &mut SqliteConnection,
        conv: &wa::Conversation,
    ) -> Result<()> {
        // Basic metadata extraction
        let last_ts_i32 = conv.last_msg_timestamp.map(|v| v as i32);
        let unread = conv.unread_count.map(|v| v as i32);
        let archived = conv.archived.unwrap_or(false) as i32;
        let pinned = conv.pinned.map(|v| v as i32);
        let created_at_i32 = conv.created_at.map(|v| v as i32);
        let meta = ChatConversationChanges {
            id: conv.id.as_str(),
            name: conv.name.as_deref(),
            display_name: conv.display_name.as_deref(),
            last_msg_timestamp: last_ts_i32,
            unread_count: unread,
            archived: Some(archived),
            pinned,
            created_at: created_at_i32,
        };
        diesel::insert_into(chat_conversations::table)
            .values(&meta)
            .on_conflict(chat_conversations::id)
            .do_update()
            .set(&meta)
            .execute(conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Participants
        if !conv.participant.is_empty() {
            // For simplicity, delete existing participants then insert new
            diesel::delete(
                chat_participants::table
                    .filter(chat_participants::conversation_id.eq(conv.id.as_str())),
            )
            .execute(conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
            for part in &conv.participant {
                let jid = part.user_jid.as_str();
                let is_admin = part.rank.map(|r| if r > 0 { 1 } else { 0 });
                diesel::insert_into(chat_participants::table)
                    .values((
                        chat_participants::conversation_id.eq(conv.id.as_str()),
                        chat_participants::jid.eq(jid),
                        chat_participants::is_admin.eq(is_admin),
                    ))
                    .execute(conn)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
        }

        // Messages: we only persist message metadata and blob for HistorySyncMsg.message if present
        if !conv.messages.is_empty() {
            for msg in &conv.messages {
                if let Some(wmi) = &msg.message {
                    let key = &wmi.key; // required field
                    let message_id = key.id.as_deref().unwrap_or("");
                    if message_id.is_empty() {
                        continue;
                    }
                    let server_ts_i32 = wmi.message_timestamp.map(|v| v as i32);
                    let sender = key.remote_jid.as_deref();
                    let blob = wmi.encode_to_vec();
                    use diesel::sql_types::{
                        Binary as SqlBinType, Integer as SqlIntType, Nullable, Text as SqlTextType,
                    };
                    diesel::sql_query("INSERT INTO chat_messages (conversation_id,message_id,server_timestamp,sender_jid,message_blob) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(conversation_id,message_id) DO UPDATE SET server_timestamp=excluded.server_timestamp,sender_jid=excluded.sender_jid,message_blob=excluded.message_blob;")
                        .bind::<SqlTextType,_>(conv.id.as_str())
                        .bind::<SqlTextType,_>(message_id)
                        .bind::<Nullable<SqlIntType>,_>(server_ts_i32)
                        .bind::<Nullable<SqlTextType>,_>(sender)
                        .bind::<SqlBinType,_>(&blob)
                        .execute(conn)
                        .map_err(|e| StoreError::Database(e.to_string()))?;
                }
            }
        }
        Ok(())
    }

    pub fn save_conversation_normalized_in_conn(
        &self,
        conn: &mut SqliteConnection,
        conv: &wa::Conversation,
    ) -> Result<()> {
        self.upsert_conversation_normalized(conn, conv)
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
        address: &str,
        key: &[u8; 32],
        _direction: Direction,
    ) -> Result<bool> {
        let mut conn = self.get_connection()?;

        let result: Option<Vec<u8>> = identities::table
            .select(identities::key)
            .filter(identities::address.eq(address))
            .first(&mut conn)
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match result {
            Some(stored_key) => Ok(stored_key.as_slice() == key),
            None => Ok(true),
        }
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
            .select(prekeys::key)
            .filter(prekeys::id.eq(prekey_id as i32))
            .first(&mut conn)
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        if let Some(key_data) = result {
            if let Ok(private_key) = PrivateKey::deserialize(&key_data) {
                if let Ok(public_key) = private_key.public_key() {
                    let key_pair = KeyPair::new(public_key, private_key);
                    let record =
                        wacore::signal::state::record::new_pre_key_record(prekey_id, &key_pair);
                    Ok(Some(record))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
        uploaded: bool,
    ) -> std::result::Result<(), SignalStoreError> {
        let mut conn = self.get_connection()?;

        let private_key_bytes = record.private_key.unwrap_or_default();

        diesel::insert_into(prekeys::table)
            .values((
                prekeys::id.eq(prekey_id as i32),
                prekeys::key.eq(&private_key_bytes),
                prekeys::uploaded.eq(uploaded),
            ))
            .on_conflict(prekeys::id)
            .do_update()
            .set((
                prekeys::key.eq(&private_key_bytes),
                prekeys::uploaded.eq(uploaded),
            ))
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
        signed_prekey_id: u32,
    ) -> std::result::Result<Option<SignedPreKeyRecordStructure>, SignalStoreError> {
        let mut conn = self.get_connection()?;

        let result: Option<Vec<u8>> = signed_prekeys::table
            .select(signed_prekeys::record)
            .filter(signed_prekeys::id.eq(signed_prekey_id as i32))
            .first(&mut conn)
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        if let Some(data) = result {
            let record = SignedPreKeyRecordStructure::decode(data.as_slice())
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    async fn load_signed_prekeys(
        &self,
    ) -> std::result::Result<Vec<SignedPreKeyRecordStructure>, SignalStoreError> {
        let mut conn = self.get_connection()?;

        let results: Vec<Vec<u8>> = signed_prekeys::table
            .select(signed_prekeys::record)
            .load(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut records = Vec::new();
        for data in results {
            let record = SignedPreKeyRecordStructure::decode(data.as_slice())
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            records.push(record);
        }

        Ok(records)
    }

    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> std::result::Result<(), SignalStoreError> {
        let mut conn = self.get_connection()?;
        let data = record.encode_to_vec();

        diesel::insert_into(signed_prekeys::table)
            .values((
                signed_prekeys::id.eq(signed_prekey_id as i32),
                signed_prekeys::record.eq(&data),
            ))
            .on_conflict(signed_prekeys::id)
            .do_update()
            .set(signed_prekeys::record.eq(&data))
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn contains_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<bool, SignalStoreError> {
        let mut conn = self.get_connection()?;

        let count: i64 = signed_prekeys::table
            .filter(signed_prekeys::id.eq(signed_prekey_id as i32))
            .count()
            .get_result(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(count > 0)
    }

    async fn remove_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<(), SignalStoreError> {
        let mut conn = self.get_connection()?;

        diesel::delete(
            signed_prekeys::table.filter(signed_prekeys::id.eq(signed_prekey_id as i32)),
        )
        .execute(&mut conn)
        .map_err(|e| StoreError::Database(e.to_string()))?;

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

    async fn put_app_state_mutation_macs(
        &self,
        name: &str,
        version: u64,
        mutations: &[AppStateMutationMAC],
    ) -> Result<()> {
        use crate::store::schema::app_state_mutation_macs;
        if mutations.is_empty() {
            return Ok(());
        }
        let mut conn = self.get_connection()?;
        for m in mutations {
            diesel::insert_into(app_state_mutation_macs::table)
                .values((
                    app_state_mutation_macs::name.eq(name),
                    app_state_mutation_macs::version.eq(version as i64),
                    app_state_mutation_macs::index_mac.eq(&m.index_mac),
                    app_state_mutation_macs::value_mac.eq(&m.value_mac),
                ))
                .on_conflict((
                    app_state_mutation_macs::name,
                    app_state_mutation_macs::index_mac,
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
    }

    async fn delete_app_state_mutation_macs(
        &self,
        name: &str,
        index_macs: &[Vec<u8>],
    ) -> Result<()> {
        use crate::store::schema::app_state_mutation_macs;
        if index_macs.is_empty() {
            return Ok(());
        }
        let mut conn = self.get_connection()?;
        for idx in index_macs {
            diesel::delete(
                app_state_mutation_macs::table.filter(
                    app_state_mutation_macs::name
                        .eq(name)
                        .and(app_state_mutation_macs::index_mac.eq(idx)),
                ),
            )
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        }
        Ok(())
    }

    async fn get_app_state_mutation_mac(
        &self,
        name: &str,
        index_mac: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        use crate::store::schema::app_state_mutation_macs;
        let mut conn = self.get_connection()?;
        let result: Option<(i64, Vec<u8>)> = app_state_mutation_macs::table
            .select((
                app_state_mutation_macs::version,
                app_state_mutation_macs::value_mac,
            ))
            .filter(
                app_state_mutation_macs::name
                    .eq(name)
                    .and(app_state_mutation_macs::index_mac.eq(index_mac)),
            )
            .order(app_state_mutation_macs::version.desc())
            .first(&mut conn)
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(result.map(|r| r.1))
    }
}

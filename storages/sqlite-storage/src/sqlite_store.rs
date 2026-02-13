use crate::schema::*;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sql_query;
use diesel::sqlite::SqliteConnection;
use diesel::upsert::excluded;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use log::warn;
use prost::Message;
use std::sync::Arc;
use wacore::appstate::hash::HashState;
use wacore::appstate::processor::AppStateMutationMAC;
use wacore::libsignal::protocol::{KeyPair, PrivateKey, PublicKey};
use wacore::store::Device as CoreDevice;
use wacore::store::error::{Result, StoreError};
use wacore::store::traits::*;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

type SqlitePool = Pool<ConnectionManager<SqliteConnection>>;
type DeviceRow = (
    i32,
    String,
    String,
    i32,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i32,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    String,
    i32,
    i32,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<String>,
);

#[derive(Clone)]
pub struct SqliteStore {
    pub(crate) pool: SqlitePool,
    pub(crate) db_semaphore: Arc<tokio::sync::Semaphore>,
    pub(crate) database_path: String,
    device_id: i32,
}

#[derive(Debug, Clone, Copy)]
struct ConnectionOptions;

impl diesel::r2d2::CustomizeConnection<SqliteConnection, diesel::r2d2::Error>
    for ConnectionOptions
{
    fn on_acquire(
        &self,
        conn: &mut SqliteConnection,
    ) -> std::result::Result<(), diesel::r2d2::Error> {
        diesel::sql_query("PRAGMA busy_timeout = 30000;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        diesel::sql_query("PRAGMA synchronous = NORMAL;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        diesel::sql_query("PRAGMA cache_size = 512;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        diesel::sql_query("PRAGMA temp_store = memory;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        diesel::sql_query("PRAGMA foreign_keys = ON;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;
        Ok(())
    }
}

fn parse_database_path(database_url: &str) -> Result<String> {
    // Reject in-memory databases
    if database_url == ":memory:" {
        return Err(StoreError::Database(
            "Snapshot not supported for in-memory databases".to_string(),
        ));
    }

    // Strip query string and fragment
    let path = database_url
        .split(['?', '#'])
        .next()
        .unwrap_or(database_url);

    // Remove sqlite:// prefix if present
    let path = path.trim_start_matches("sqlite://");

    // Check if the resulting path looks like an in-memory marker
    if path == ":memory:" || path.starts_with(":memory:?") {
        return Err(StoreError::Database(
            "Snapshot not supported for in-memory databases".to_string(),
        ));
    }

    Ok(path.to_string())
}

impl SqliteStore {
    pub async fn new(database_url: &str) -> std::result::Result<Self, StoreError> {
        let manager = ConnectionManager::<SqliteConnection>::new(database_url);

        let pool_size = 2;

        let pool = Pool::builder()
            .max_size(pool_size)
            .connection_customizer(Box::new(ConnectionOptions))
            .build(manager)
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        let pool_clone = pool.clone();
        tokio::task::spawn_blocking(move || -> std::result::Result<(), StoreError> {
            let mut conn = pool_clone
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            diesel::sql_query("PRAGMA journal_mode = WAL;")
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            conn.run_pending_migrations(MIGRATIONS)
                .map_err(|e| StoreError::Migration(e.to_string()))?;

            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        let database_path = parse_database_path(database_url)?;

        Ok(Self {
            pool,
            db_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
            database_path,
            device_id: 1,
        })
    }

    pub async fn new_for_device(
        database_url: &str,
        device_id: i32,
    ) -> std::result::Result<Self, StoreError> {
        let mut store = Self::new(database_url).await?;
        store.device_id = device_id;
        Ok(store)
    }

    pub fn device_id(&self) -> i32 {
        self.device_id
    }

    async fn with_semaphore<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let permit = self
            .db_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| StoreError::Database(format!("Semaphore error: {}", e)))?;
        let result = tokio::task::spawn_blocking(move || {
            let res = f();
            drop(permit);
            res
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(result)
    }

    fn serialize_keypair(&self, key_pair: &KeyPair) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(key_pair.private_key.serialize());
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

    pub async fn save_device_data_for_device(
        &self,
        device_id: i32,
        device_data: &CoreDevice,
    ) -> Result<()> {
        let pool = self.pool.clone();
        let noise_key_data = self.serialize_keypair(&device_data.noise_key)?;
        let identity_key_data = self.serialize_keypair(&device_data.identity_key)?;
        let signed_pre_key_data = self.serialize_keypair(&device_data.signed_pre_key)?;
        let account_data = device_data
            .account
            .as_ref()
            .map(|account| account.encode_to_vec());
        let registration_id = device_data.registration_id as i32;
        let signed_pre_key_id = device_data.signed_pre_key_id as i32;
        let signed_pre_key_signature: Vec<u8> = device_data.signed_pre_key_signature.to_vec();
        let adv_secret_key: Vec<u8> = device_data.adv_secret_key.to_vec();
        let push_name = device_data.push_name.clone();
        let app_version_primary = device_data.app_version_primary as i32;
        let app_version_secondary = device_data.app_version_secondary as i32;
        let app_version_tertiary = device_data.app_version_tertiary as i64;
        let app_version_last_fetched_ms = device_data.app_version_last_fetched_ms;
        let edge_routing_info = device_data.edge_routing_info.clone();
        let props_hash = device_data.props_hash.clone();
        let new_lid = device_data
            .lid
            .as_ref()
            .map(|j| j.to_string())
            .unwrap_or_default();
        let new_pn = device_data
            .pn
            .as_ref()
            .map(|j| j.to_string())
            .unwrap_or_default();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            diesel::insert_into(device::table)
                .values((
                    device::id.eq(device_id),
                    device::lid.eq(&new_lid),
                    device::pn.eq(&new_pn),
                    device::registration_id.eq(registration_id),
                    device::noise_key.eq(&noise_key_data),
                    device::identity_key.eq(&identity_key_data),
                    device::signed_pre_key.eq(&signed_pre_key_data),
                    device::signed_pre_key_id.eq(signed_pre_key_id),
                    device::signed_pre_key_signature.eq(&signed_pre_key_signature[..]),
                    device::adv_secret_key.eq(&adv_secret_key[..]),
                    device::account.eq(account_data.clone()),
                    device::push_name.eq(&push_name),
                    device::app_version_primary.eq(app_version_primary),
                    device::app_version_secondary.eq(app_version_secondary),
                    device::app_version_tertiary.eq(app_version_tertiary),
                    device::app_version_last_fetched_ms.eq(app_version_last_fetched_ms),
                    device::edge_routing_info.eq(edge_routing_info.clone()),
                    device::props_hash.eq(props_hash.clone()),
                ))
                .on_conflict(device::id)
                .do_update()
                .set((
                    device::lid.eq(&new_lid),
                    device::pn.eq(&new_pn),
                    device::registration_id.eq(registration_id),
                    device::noise_key.eq(&noise_key_data),
                    device::identity_key.eq(&identity_key_data),
                    device::signed_pre_key.eq(&signed_pre_key_data),
                    device::signed_pre_key_id.eq(signed_pre_key_id),
                    device::signed_pre_key_signature.eq(&signed_pre_key_signature[..]),
                    device::adv_secret_key.eq(&adv_secret_key[..]),
                    device::account.eq(account_data.clone()),
                    device::push_name.eq(&push_name),
                    device::app_version_primary.eq(app_version_primary),
                    device::app_version_secondary.eq(app_version_secondary),
                    device::app_version_tertiary.eq(app_version_tertiary),
                    device::app_version_last_fetched_ms.eq(app_version_last_fetched_ms),
                    device::edge_routing_info.eq(edge_routing_info),
                    device::props_hash.eq(props_hash),
                ))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        Ok(())
    }

    pub async fn create_new_device(&self) -> Result<i32> {
        use crate::schema::device;

        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> Result<i32> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            let new_device = wacore::store::Device::new();

            let noise_key_data = {
                let mut bytes = Vec::with_capacity(64);
                bytes.extend_from_slice(new_device.noise_key.private_key.serialize());
                bytes.extend_from_slice(new_device.noise_key.public_key.public_key_bytes());
                bytes
            };
            let identity_key_data = {
                let mut bytes = Vec::with_capacity(64);
                bytes.extend_from_slice(new_device.identity_key.private_key.serialize());
                bytes.extend_from_slice(new_device.identity_key.public_key.public_key_bytes());
                bytes
            };
            let signed_pre_key_data = {
                let mut bytes = Vec::with_capacity(64);
                bytes.extend_from_slice(new_device.signed_pre_key.private_key.serialize());
                bytes.extend_from_slice(new_device.signed_pre_key.public_key.public_key_bytes());
                bytes
            };

            diesel::insert_into(device::table)
                .values((
                    device::lid.eq(""),
                    device::pn.eq(""),
                    device::registration_id.eq(new_device.registration_id as i32),
                    device::noise_key.eq(&noise_key_data),
                    device::identity_key.eq(&identity_key_data),
                    device::signed_pre_key.eq(&signed_pre_key_data),
                    device::signed_pre_key_id.eq(new_device.signed_pre_key_id as i32),
                    device::signed_pre_key_signature.eq(&new_device.signed_pre_key_signature[..]),
                    device::adv_secret_key.eq(&new_device.adv_secret_key[..]),
                    device::account.eq(None::<Vec<u8>>),
                    device::push_name.eq(&new_device.push_name),
                    device::app_version_primary.eq(new_device.app_version_primary as i32),
                    device::app_version_secondary.eq(new_device.app_version_secondary as i32),
                    device::app_version_tertiary.eq(new_device.app_version_tertiary as i64),
                    device::app_version_last_fetched_ms.eq(new_device.app_version_last_fetched_ms),
                    device::edge_routing_info.eq(None::<Vec<u8>>),
                    device::props_hash.eq(None::<String>),
                ))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            use diesel::sql_types::Integer;

            #[derive(QueryableByName)]
            struct LastInsertedId {
                #[diesel(sql_type = Integer)]
                last_insert_rowid: i32,
            }

            let device_id: i32 = sql_query("SELECT last_insert_rowid() as last_insert_rowid")
                .get_result::<LastInsertedId>(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?
                .last_insert_rowid;

            Ok(device_id)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    pub async fn device_exists(&self, device_id: i32) -> Result<bool> {
        use crate::schema::device;

        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            let count: i64 = device::table
                .filter(device::id.eq(device_id))
                .count()
                .get_result(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            Ok(count > 0)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    pub async fn load_device_data_for_device(&self, device_id: i32) -> Result<Option<CoreDevice>> {
        use crate::schema::device;

        let pool = self.pool.clone();
        let row = tokio::task::spawn_blocking(move || -> Result<Option<DeviceRow>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let result = device::table
                .filter(device::id.eq(device_id))
                .first::<DeviceRow>(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(result)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        if let Some((
            _device_id,
            lid_str,
            pn_str,
            registration_id,
            noise_key_data,
            identity_key_data,
            signed_pre_key_data,
            signed_pre_key_id,
            signed_pre_key_signature_data,
            adv_secret_key_data,
            account_data,
            push_name,
            app_version_primary,
            app_version_secondary,
            app_version_tertiary,
            app_version_last_fetched_ms,
            edge_routing_info,
            props_hash,
        )) = row
        {
            let id = if !pn_str.is_empty() {
                pn_str.parse().ok()
            } else {
                None
            };
            let lid = if !lid_str.is_empty() {
                lid_str.parse().ok()
            } else {
                None
            };

            let noise_key = self.deserialize_keypair(&noise_key_data)?;
            let identity_key = self.deserialize_keypair(&identity_key_data)?;
            let signed_pre_key = self.deserialize_keypair(&signed_pre_key_data)?;

            let signed_pre_key_signature: [u8; 64] =
                signed_pre_key_signature_data.try_into().map_err(|_| {
                    StoreError::Serialization("Invalid signed_pre_key_signature length".to_string())
                })?;

            let adv_secret_key: [u8; 32] = adv_secret_key_data.try_into().map_err(|_| {
                StoreError::Serialization("Invalid adv_secret_key length".to_string())
            })?;

            let account = account_data
                .map(|data| {
                    wa::AdvSignedDeviceIdentity::decode(&data[..])
                        .map_err(|e| StoreError::Serialization(e.to_string()))
                })
                .transpose()?;

            Ok(Some(CoreDevice {
                pn: id,
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
                app_version_primary: app_version_primary as u32,
                app_version_secondary: app_version_secondary as u32,
                app_version_tertiary: app_version_tertiary.try_into().unwrap_or(0u32),
                app_version_last_fetched_ms,
                device_props: {
                    use wacore::store::device::DEVICE_PROPS;
                    DEVICE_PROPS.clone()
                },
                edge_routing_info,
                props_hash,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn put_identity_for_device(
        &self,
        address: &str,
        key: [u8; 32],
        device_id: i32,
    ) -> Result<()> {
        let pool = self.pool.clone();
        let db_semaphore = self.db_semaphore.clone();
        let address_owned = address.to_string();
        let key_vec = key.to_vec();

        const MAX_RETRIES: u32 = 5;

        for attempt in 0..=MAX_RETRIES {
            let permit =
                db_semaphore.clone().acquire_owned().await.map_err(|e| {
                    StoreError::Database(format!("Failed to acquire semaphore: {}", e))
                })?;

            let pool_clone = pool.clone();
            let address_clone = address_owned.clone();
            let key_clone = key_vec.clone();

            let result = tokio::task::spawn_blocking(move || -> Result<()> {
                let mut conn = pool_clone
                    .get()
                    .map_err(|e| StoreError::Connection(e.to_string()))?;
                diesel::insert_into(identities::table)
                    .values((
                        identities::address.eq(address_clone),
                        identities::key.eq(&key_clone[..]),
                        identities::device_id.eq(device_id),
                    ))
                    .on_conflict((identities::address, identities::device_id))
                    .do_update()
                    .set(identities::key.eq(&key_clone[..]))
                    .execute(&mut conn)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                Ok(())
            })
            .await;

            drop(permit);

            match result {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => {
                    let error_msg = e.to_string();
                    if (error_msg.contains("locked") || error_msg.contains("busy"))
                        && attempt < MAX_RETRIES
                    {
                        let delay_ms = 10 * 2u64.pow(attempt);
                        warn!(
                            "Identity write failed (attempt {}/{}): {}. Retrying in {}ms...",
                            attempt + 1,
                            MAX_RETRIES + 1,
                            error_msg,
                            delay_ms
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(e);
                }
                Err(e) => return Err(StoreError::Database(format!("Task join error: {}", e))),
            }
        }

        Err(StoreError::Database(format!(
            "Identity write failed after {} attempts",
            MAX_RETRIES + 1
        )))
    }

    pub async fn delete_identity_for_device(&self, address: &str, device_id: i32) -> Result<()> {
        let pool = self.pool.clone();
        let address_owned = address.to_string();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::delete(
                identities::table
                    .filter(identities::address.eq(address_owned))
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

    pub async fn load_identity_for_device(
        &self,
        address: &str,
        device_id: i32,
    ) -> Result<Option<Vec<u8>>> {
        let pool = self.pool.clone();
        let address = address.to_string();
        let result = self
            .with_semaphore(move || -> Result<Option<Vec<u8>>> {
                let mut conn = pool
                    .get()
                    .map_err(|e| StoreError::Connection(e.to_string()))?;
                let res: Option<Vec<u8>> = identities::table
                    .select(identities::key)
                    .filter(identities::address.eq(address))
                    .filter(identities::device_id.eq(device_id))
                    .first(&mut conn)
                    .optional()
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                Ok(res)
            })
            .await?;

        Ok(result)
    }

    pub async fn get_session_for_device(
        &self,
        address: &str,
        device_id: i32,
    ) -> Result<Option<Vec<u8>>> {
        let pool = self.pool.clone();
        let address_for_query = address.to_string();
        let result = self
            .with_semaphore(move || -> Result<Option<Vec<u8>>> {
                let mut conn = pool
                    .get()
                    .map_err(|e| StoreError::Connection(e.to_string()))?;
                let res: Option<Vec<u8>> = sessions::table
                    .select(sessions::record)
                    .filter(sessions::address.eq(address_for_query.clone()))
                    .filter(sessions::device_id.eq(device_id))
                    .first(&mut conn)
                    .optional()
                    .map_err(|e| StoreError::Database(e.to_string()))?;

                Ok(res)
            })
            .await?;

        Ok(result)
    }

    pub async fn put_session_for_device(
        &self,
        address: &str,
        session: &[u8],
        device_id: i32,
    ) -> Result<()> {
        let pool = self.pool.clone();
        let db_semaphore = self.db_semaphore.clone();
        let address_owned = address.to_string();
        let session_vec = session.to_vec();

        const MAX_RETRIES: u32 = 5;

        for attempt in 0..=MAX_RETRIES {
            let permit =
                db_semaphore.clone().acquire_owned().await.map_err(|e| {
                    StoreError::Database(format!("Failed to acquire semaphore: {}", e))
                })?;

            let pool_clone = pool.clone();
            let address_clone = address_owned.clone();
            let session_clone = session_vec.clone();

            let result = tokio::task::spawn_blocking(move || -> Result<()> {
                let mut conn = pool_clone
                    .get()
                    .map_err(|e| StoreError::Connection(e.to_string()))?;
                diesel::insert_into(sessions::table)
                    .values((
                        sessions::address.eq(address_clone),
                        sessions::record.eq(&session_clone),
                        sessions::device_id.eq(device_id),
                    ))
                    .on_conflict((sessions::address, sessions::device_id))
                    .do_update()
                    .set(sessions::record.eq(&session_clone))
                    .execute(&mut conn)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                Ok(())
            })
            .await;

            drop(permit);

            match result {
                Ok(Ok(())) => {
                    return Ok(());
                }
                Ok(Err(e)) => {
                    let error_msg = e.to_string();
                    if (error_msg.contains("locked") || error_msg.contains("busy"))
                        && attempt < MAX_RETRIES
                    {
                        let delay_ms = 10 * 2u64.pow(attempt);
                        warn!(
                            "Session write failed (attempt {}/{}): {}. Retrying in {}ms...",
                            attempt + 1,
                            MAX_RETRIES + 1,
                            error_msg,
                            delay_ms
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(e);
                }
                Err(e) => return Err(StoreError::Database(format!("Task join error: {}", e))),
            }
        }

        Err(StoreError::Database(format!(
            "Session write failed after {} attempts",
            MAX_RETRIES + 1
        )))
    }

    pub async fn delete_session_for_device(&self, address: &str, device_id: i32) -> Result<()> {
        let pool = self.pool.clone();
        let address_owned = address.to_string();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::delete(
                sessions::table
                    .filter(sessions::address.eq(address_owned))
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

    pub async fn put_sender_key_for_device(
        &self,
        address: &str,
        record: &[u8],
        device_id: i32,
    ) -> Result<()> {
        let pool = self.pool.clone();
        let address = address.to_string();
        let record_vec = record.to_vec();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(sender_keys::table)
                .values((
                    sender_keys::address.eq(address),
                    sender_keys::record.eq(&record_vec),
                    sender_keys::device_id.eq(device_id),
                ))
                .on_conflict((sender_keys::address, sender_keys::device_id))
                .do_update()
                .set(sender_keys::record.eq(&record_vec))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    pub async fn get_sender_key_for_device(
        &self,
        address: &str,
        device_id: i32,
    ) -> Result<Option<Vec<u8>>> {
        let pool = self.pool.clone();
        let address = address.to_string();
        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let res: Option<Vec<u8>> = sender_keys::table
                .select(sender_keys::record)
                .filter(sender_keys::address.eq(address))
                .filter(sender_keys::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(res)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    pub async fn delete_sender_key_for_device(&self, address: &str, device_id: i32) -> Result<()> {
        let pool = self.pool.clone();
        let address = address.to_string();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::delete(
                sender_keys::table
                    .filter(sender_keys::address.eq(address))
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

    pub async fn get_app_state_sync_key_for_device(
        &self,
        key_id: &[u8],
        device_id: i32,
    ) -> Result<Option<AppStateSyncKey>> {
        let pool = self.pool.clone();
        let key_id = key_id.to_vec();
        let res: Option<Vec<u8>> =
            tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
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
                Ok(res)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))??;

        if let Some(data) = res {
            let (key, _) = bincode::serde::decode_from_slice(&data, bincode::config::standard())
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }

    pub async fn set_app_state_sync_key_for_device(
        &self,
        key_id: &[u8],
        key: AppStateSyncKey,
        device_id: i32,
    ) -> Result<()> {
        let pool = self.pool.clone();
        let key_id = key_id.to_vec();
        let data = bincode::serde::encode_to_vec(&key, bincode::config::standard())
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(app_state_keys::table)
                .values((
                    app_state_keys::key_id.eq(&key_id),
                    app_state_keys::key_data.eq(&data),
                    app_state_keys::device_id.eq(device_id),
                ))
                .on_conflict((app_state_keys::key_id, app_state_keys::device_id))
                .do_update()
                .set(app_state_keys::key_data.eq(&data))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    pub async fn get_app_state_version_for_device(
        &self,
        name: &str,
        device_id: i32,
    ) -> Result<HashState> {
        let pool = self.pool.clone();
        let name = name.to_string();
        let res: Option<Vec<u8>> =
            tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
                let mut conn = pool
                    .get()
                    .map_err(|e| StoreError::Connection(e.to_string()))?;
                let res: Option<Vec<u8>> = app_state_versions::table
                    .select(app_state_versions::state_data)
                    .filter(app_state_versions::name.eq(name))
                    .filter(app_state_versions::device_id.eq(device_id))
                    .first(&mut conn)
                    .optional()
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                Ok(res)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))??;

        if let Some(data) = res {
            let (state, _) = bincode::serde::decode_from_slice(&data, bincode::config::standard())
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            Ok(state)
        } else {
            Ok(HashState::default())
        }
    }

    pub async fn set_app_state_version_for_device(
        &self,
        name: &str,
        state: HashState,
        device_id: i32,
    ) -> Result<()> {
        let pool = self.pool.clone();
        let name = name.to_string();
        let data = bincode::serde::encode_to_vec(&state, bincode::config::standard())
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(app_state_versions::table)
                .values((
                    app_state_versions::name.eq(&name),
                    app_state_versions::state_data.eq(&data),
                    app_state_versions::device_id.eq(device_id),
                ))
                .on_conflict((app_state_versions::name, app_state_versions::device_id))
                .do_update()
                .set(app_state_versions::state_data.eq(&data))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    pub async fn put_app_state_mutation_macs_for_device(
        &self,
        name: &str,
        version: u64,
        mutations: &[AppStateMutationMAC],
        device_id: i32,
    ) -> Result<()> {
        if mutations.is_empty() {
            return Ok(());
        }
        let pool = self.pool.clone();
        let name = name.to_string();
        let mutations: Vec<AppStateMutationMAC> = mutations.to_vec();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            let records: Vec<_> = mutations
                .iter()
                .map(|m| {
                    (
                        app_state_mutation_macs::name.eq(&name),
                        app_state_mutation_macs::version.eq(version as i64),
                        app_state_mutation_macs::index_mac.eq(&m.index_mac),
                        app_state_mutation_macs::value_mac.eq(&m.value_mac),
                        app_state_mutation_macs::device_id.eq(device_id),
                    )
                })
                .collect();

            // SQLite variable limit is typically 999 or 32766.
            // Each row has 5 columns. 100 rows * 5 = 500 params, which is safe.
            const CHUNK_SIZE: usize = 100;

            for chunk in records.chunks(CHUNK_SIZE) {
                diesel::insert_into(app_state_mutation_macs::table)
                    .values(chunk)
                    .on_conflict((
                        app_state_mutation_macs::name,
                        app_state_mutation_macs::index_mac,
                        app_state_mutation_macs::device_id,
                    ))
                    .do_update()
                    .set((
                        app_state_mutation_macs::version
                            .eq(excluded(app_state_mutation_macs::version)),
                        app_state_mutation_macs::value_mac
                            .eq(excluded(app_state_mutation_macs::value_mac)),
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

    pub async fn delete_app_state_mutation_macs_for_device(
        &self,
        name: &str,
        index_macs: &[Vec<u8>],
        device_id: i32,
    ) -> Result<()> {
        if index_macs.is_empty() {
            return Ok(());
        }
        let pool = self.pool.clone();
        let name = name.to_string();
        let index_macs: Vec<Vec<u8>> = index_macs.to_vec();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            // SQLite variable limit is usually 999 or higher.
            // We use a safe chunk size to stay well within limits.
            const CHUNK_SIZE: usize = 500;

            for chunk in index_macs.chunks(CHUNK_SIZE) {
                diesel::delete(
                    app_state_mutation_macs::table.filter(
                        app_state_mutation_macs::name
                            .eq(&name)
                            .and(app_state_mutation_macs::index_mac.eq_any(chunk))
                            .and(app_state_mutation_macs::device_id.eq(device_id)),
                    ),
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

    pub async fn get_app_state_mutation_mac_for_device(
        &self,
        name: &str,
        index_mac: &[u8],
        device_id: i32,
    ) -> Result<Option<Vec<u8>>> {
        let pool = self.pool.clone();
        let name = name.to_string();
        let index_mac = index_mac.to_vec();
        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
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
        .map_err(|e| StoreError::Database(e.to_string()))?
    }
}

#[async_trait]
impl SignalStore for SqliteStore {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()> {
        self.put_identity_for_device(address, key, self.device_id)
            .await
    }

    async fn load_identity(&self, address: &str) -> Result<Option<Vec<u8>>> {
        self.load_identity_for_device(address, self.device_id).await
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        self.delete_identity_for_device(address, self.device_id)
            .await
    }

    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        self.get_session_for_device(address, self.device_id).await
    }

    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()> {
        self.put_session_for_device(address, session, self.device_id)
            .await
    }

    async fn delete_session(&self, address: &str) -> Result<()> {
        self.delete_session_for_device(address, self.device_id)
            .await
    }

    async fn store_prekey(&self, id: u32, record: &[u8], uploaded: bool) -> Result<()> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let record = record.to_vec();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(prekeys::table)
                .values((
                    prekeys::id.eq(id as i32),
                    prekeys::key.eq(&record),
                    prekeys::uploaded.eq(uploaded),
                    prekeys::device_id.eq(device_id),
                ))
                .on_conflict((prekeys::id, prekeys::device_id))
                .do_update()
                .set((prekeys::key.eq(&record), prekeys::uploaded.eq(uploaded)))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn load_prekey(&self, id: u32) -> Result<Option<Vec<u8>>> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let res: Option<Vec<u8>> = prekeys::table
                .select(prekeys::key)
                .filter(prekeys::id.eq(id as i32))
                .filter(prekeys::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(res)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    async fn remove_prekey(&self, id: u32) -> Result<()> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::delete(
                prekeys::table
                    .filter(prekeys::id.eq(id as i32))
                    .filter(prekeys::device_id.eq(device_id)),
            )
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn store_signed_prekey(&self, id: u32, record: &[u8]) -> Result<()> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let record = record.to_vec();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(signed_prekeys::table)
                .values((
                    signed_prekeys::id.eq(id as i32),
                    signed_prekeys::record.eq(&record),
                    signed_prekeys::device_id.eq(device_id),
                ))
                .on_conflict((signed_prekeys::id, signed_prekeys::device_id))
                .do_update()
                .set(signed_prekeys::record.eq(&record))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn load_signed_prekey(&self, id: u32) -> Result<Option<Vec<u8>>> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let res: Option<Vec<u8>> = signed_prekeys::table
                .select(signed_prekeys::record)
                .filter(signed_prekeys::id.eq(id as i32))
                .filter(signed_prekeys::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(res)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    async fn load_all_signed_prekeys(&self) -> Result<Vec<(u32, Vec<u8>)>> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        tokio::task::spawn_blocking(move || -> Result<Vec<(u32, Vec<u8>)>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let results: Vec<(i32, Vec<u8>)> = signed_prekeys::table
                .select((signed_prekeys::id, signed_prekeys::record))
                .filter(signed_prekeys::device_id.eq(device_id))
                .load(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(results
                .into_iter()
                .map(|(id, record)| (id as u32, record))
                .collect())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    async fn remove_signed_prekey(&self, id: u32) -> Result<()> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::delete(
                signed_prekeys::table
                    .filter(signed_prekeys::id.eq(id as i32))
                    .filter(signed_prekeys::device_id.eq(device_id)),
            )
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn put_sender_key(&self, address: &str, record: &[u8]) -> Result<()> {
        self.put_sender_key_for_device(address, record, self.device_id)
            .await
    }

    async fn get_sender_key(&self, address: &str) -> Result<Option<Vec<u8>>> {
        self.get_sender_key_for_device(address, self.device_id)
            .await
    }

    async fn delete_sender_key(&self, address: &str) -> Result<()> {
        self.delete_sender_key_for_device(address, self.device_id)
            .await
    }
}

#[async_trait]
impl AppSyncStore for SqliteStore {
    async fn get_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        self.get_app_state_sync_key_for_device(key_id, self.device_id)
            .await
    }

    async fn set_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        self.set_app_state_sync_key_for_device(key_id, key, self.device_id)
            .await
    }

    async fn get_version(&self, name: &str) -> Result<HashState> {
        self.get_app_state_version_for_device(name, self.device_id)
            .await
    }

    async fn set_version(&self, name: &str, state: HashState) -> Result<()> {
        self.set_app_state_version_for_device(name, state, self.device_id)
            .await
    }

    async fn put_mutation_macs(
        &self,
        name: &str,
        version: u64,
        mutations: &[AppStateMutationMAC],
    ) -> Result<()> {
        self.put_app_state_mutation_macs_for_device(name, version, mutations, self.device_id)
            .await
    }

    async fn get_mutation_mac(&self, name: &str, index_mac: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_app_state_mutation_mac_for_device(name, index_mac, self.device_id)
            .await
    }

    async fn delete_mutation_macs(&self, name: &str, index_macs: &[Vec<u8>]) -> Result<()> {
        self.delete_app_state_mutation_macs_for_device(name, index_macs, self.device_id)
            .await
    }
}

#[async_trait]
impl ProtocolStore for SqliteStore {
    async fn get_skdm_recipients(&self, group_jid: &str) -> Result<Vec<Jid>> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let group_jid = group_jid.to_string();
        tokio::task::spawn_blocking(move || -> Result<Vec<Jid>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let recipients: Vec<String> = skdm_recipients::table
                .select(skdm_recipients::device_jid)
                .filter(skdm_recipients::group_jid.eq(&group_jid))
                .filter(skdm_recipients::device_id.eq(device_id))
                .load(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            let jids: Vec<Jid> = recipients
                .iter()
                .filter_map(|s| match s.parse::<Jid>() {
                    Ok(jid) => Some(jid),
                    Err(e) => {
                        warn!("Failed to parse SKDM recipient '{}': {}", s, e);
                        None
                    }
                })
                .collect();
            Ok(jids)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    async fn add_skdm_recipients(&self, group_jid: &str, device_jids: &[Jid]) -> Result<()> {
        if device_jids.is_empty() {
            return Ok(());
        }
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let group_jid = group_jid.to_string();
        let device_jid_strs: Vec<String> = device_jids.iter().map(|j| j.to_string()).collect();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            let values: Vec<_> = device_jid_strs
                .iter()
                .map(|device_jid| {
                    (
                        skdm_recipients::group_jid.eq(&group_jid),
                        skdm_recipients::device_jid.eq(device_jid),
                        skdm_recipients::device_id.eq(device_id),
                        skdm_recipients::created_at.eq(now),
                    )
                })
                .collect();

            const CHUNK_SIZE: usize = 200; // SQLite variable limit ~999, 4 cols/row

            for chunk in values.chunks(CHUNK_SIZE) {
                diesel::insert_into(skdm_recipients::table)
                    .values(chunk)
                    .on_conflict((
                        skdm_recipients::group_jid,
                        skdm_recipients::device_jid,
                        skdm_recipients::device_id,
                    ))
                    .do_nothing()
                    .execute(&mut conn)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn clear_skdm_recipients(&self, group_jid: &str) -> Result<()> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let group_jid = group_jid.to_string();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::delete(
                skdm_recipients::table
                    .filter(skdm_recipients::group_jid.eq(&group_jid))
                    .filter(skdm_recipients::device_id.eq(device_id)),
            )
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn get_lid_mapping(&self, lid: &str) -> Result<Option<LidPnMappingEntry>> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let lid = lid.to_string();
        tokio::task::spawn_blocking(move || -> Result<Option<LidPnMappingEntry>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let row: Option<(String, String, i64, String, i64)> = lid_pn_mapping::table
                .select((
                    lid_pn_mapping::lid,
                    lid_pn_mapping::phone_number,
                    lid_pn_mapping::created_at,
                    lid_pn_mapping::learning_source,
                    lid_pn_mapping::updated_at,
                ))
                .filter(lid_pn_mapping::lid.eq(&lid))
                .filter(lid_pn_mapping::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(row.map(
                |(lid, phone_number, created_at, learning_source, updated_at)| LidPnMappingEntry {
                    lid,
                    phone_number,
                    created_at,
                    updated_at,
                    learning_source,
                },
            ))
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    async fn get_pn_mapping(&self, phone: &str) -> Result<Option<LidPnMappingEntry>> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let phone = phone.to_string();
        tokio::task::spawn_blocking(move || -> Result<Option<LidPnMappingEntry>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let row: Option<(String, String, i64, String, i64)> = lid_pn_mapping::table
                .select((
                    lid_pn_mapping::lid,
                    lid_pn_mapping::phone_number,
                    lid_pn_mapping::created_at,
                    lid_pn_mapping::learning_source,
                    lid_pn_mapping::updated_at,
                ))
                .filter(lid_pn_mapping::phone_number.eq(&phone))
                .filter(lid_pn_mapping::device_id.eq(device_id))
                .order(lid_pn_mapping::updated_at.desc())
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(row.map(
                |(lid, phone_number, created_at, learning_source, updated_at)| LidPnMappingEntry {
                    lid,
                    phone_number,
                    created_at,
                    updated_at,
                    learning_source,
                },
            ))
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    async fn put_lid_mapping(&self, entry: &LidPnMappingEntry) -> Result<()> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let entry = entry.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(lid_pn_mapping::table)
                .values((
                    lid_pn_mapping::lid.eq(&entry.lid),
                    lid_pn_mapping::phone_number.eq(&entry.phone_number),
                    lid_pn_mapping::created_at.eq(entry.created_at),
                    lid_pn_mapping::learning_source.eq(&entry.learning_source),
                    lid_pn_mapping::updated_at.eq(entry.updated_at),
                    lid_pn_mapping::device_id.eq(device_id),
                ))
                .on_conflict((lid_pn_mapping::lid, lid_pn_mapping::device_id))
                .do_update()
                .set((
                    lid_pn_mapping::phone_number.eq(&entry.phone_number),
                    lid_pn_mapping::learning_source.eq(&entry.learning_source),
                    lid_pn_mapping::updated_at.eq(entry.updated_at),
                ))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn get_all_lid_mappings(&self) -> Result<Vec<LidPnMappingEntry>> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        tokio::task::spawn_blocking(move || -> Result<Vec<LidPnMappingEntry>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let rows: Vec<(String, String, i64, String, i64)> = lid_pn_mapping::table
                .select((
                    lid_pn_mapping::lid,
                    lid_pn_mapping::phone_number,
                    lid_pn_mapping::created_at,
                    lid_pn_mapping::learning_source,
                    lid_pn_mapping::updated_at,
                ))
                .filter(lid_pn_mapping::device_id.eq(device_id))
                .load(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(rows
                .into_iter()
                .map(
                    |(lid, phone_number, created_at, learning_source, updated_at)| {
                        LidPnMappingEntry {
                            lid,
                            phone_number,
                            created_at,
                            updated_at,
                            learning_source,
                        }
                    },
                )
                .collect())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    async fn save_base_key(&self, address: &str, message_id: &str, base_key: &[u8]) -> Result<()> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let address = address.to_string();
        let message_id = message_id.to_string();
        let base_key = base_key.to_vec();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(base_keys::table)
                .values((
                    base_keys::address.eq(&address),
                    base_keys::message_id.eq(&message_id),
                    base_keys::base_key.eq(&base_key),
                    base_keys::device_id.eq(device_id),
                    base_keys::created_at.eq(now),
                ))
                .on_conflict((
                    base_keys::address,
                    base_keys::message_id,
                    base_keys::device_id,
                ))
                .do_update()
                .set(base_keys::base_key.eq(&base_key))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn has_same_base_key(
        &self,
        address: &str,
        message_id: &str,
        current_base_key: &[u8],
    ) -> Result<bool> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let address = address.to_string();
        let message_id = message_id.to_string();
        let current_base_key = current_base_key.to_vec();
        tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let stored_key: Option<Vec<u8>> = base_keys::table
                .select(base_keys::base_key)
                .filter(base_keys::address.eq(&address))
                .filter(base_keys::message_id.eq(&message_id))
                .filter(base_keys::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(stored_key.as_ref() == Some(&current_base_key))
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    async fn delete_base_key(&self, address: &str, message_id: &str) -> Result<()> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let address = address.to_string();
        let message_id = message_id.to_string();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::delete(
                base_keys::table
                    .filter(base_keys::address.eq(&address))
                    .filter(base_keys::message_id.eq(&message_id))
                    .filter(base_keys::device_id.eq(device_id)),
            )
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn update_device_list(&self, record: DeviceListRecord) -> Result<()> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let devices_json = serde_json::to_string(&record.devices)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(device_registry::table)
                .values((
                    device_registry::user_id.eq(&record.user),
                    device_registry::devices_json.eq(&devices_json),
                    device_registry::timestamp.eq(record.timestamp as i32),
                    device_registry::phash.eq(&record.phash),
                    device_registry::device_id.eq(device_id),
                    device_registry::updated_at.eq(now),
                ))
                .on_conflict((device_registry::user_id, device_registry::device_id))
                .do_update()
                .set((
                    device_registry::devices_json.eq(&devices_json),
                    device_registry::timestamp.eq(record.timestamp as i32),
                    device_registry::phash.eq(&record.phash),
                    device_registry::updated_at.eq(now),
                ))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn get_devices(&self, user: &str) -> Result<Option<DeviceListRecord>> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let user = user.to_string();
        tokio::task::spawn_blocking(move || -> Result<Option<DeviceListRecord>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let row: Option<(String, String, i32, Option<String>)> = device_registry::table
                .select((
                    device_registry::user_id,
                    device_registry::devices_json,
                    device_registry::timestamp,
                    device_registry::phash,
                ))
                .filter(device_registry::user_id.eq(&user))
                .filter(device_registry::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            match row {
                Some((user, devices_json, timestamp, phash)) => {
                    let devices: Vec<DeviceInfo> = serde_json::from_str(&devices_json)
                        .map_err(|e| StoreError::Serialization(e.to_string()))?;
                    Ok(Some(DeviceListRecord {
                        user,
                        devices,
                        timestamp: timestamp as i64,
                        phash,
                    }))
                }
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    async fn mark_forget_sender_key(&self, group_jid: &str, participant: &str) -> Result<()> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let group_jid = group_jid.to_string();
        let participant = participant.to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i32;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(sender_key_status::table)
                .values((
                    sender_key_status::group_jid.eq(&group_jid),
                    sender_key_status::participant.eq(&participant),
                    sender_key_status::device_id.eq(device_id),
                    sender_key_status::marked_at.eq(now),
                ))
                .on_conflict((
                    sender_key_status::group_jid,
                    sender_key_status::participant,
                    sender_key_status::device_id,
                ))
                .do_update()
                .set(sender_key_status::marked_at.eq(now))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn consume_forget_marks(&self, group_jid: &str) -> Result<Vec<String>> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let group_jid = group_jid.to_string();
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let participants: Vec<String> = sender_key_status::table
                .select(sender_key_status::participant)
                .filter(sender_key_status::group_jid.eq(&group_jid))
                .filter(sender_key_status::device_id.eq(device_id))
                .load(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            diesel::delete(
                sender_key_status::table
                    .filter(sender_key_status::group_jid.eq(&group_jid))
                    .filter(sender_key_status::device_id.eq(device_id)),
            )
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(participants)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    async fn get_tc_token(&self, jid: &str) -> Result<Option<TcTokenEntry>> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let jid = jid.to_string();
        tokio::task::spawn_blocking(move || -> Result<Option<TcTokenEntry>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let row: Option<(Vec<u8>, i64, Option<i64>)> = tc_tokens::table
                .select((
                    tc_tokens::token,
                    tc_tokens::token_timestamp,
                    tc_tokens::sender_timestamp,
                ))
                .filter(tc_tokens::jid.eq(&jid))
                .filter(tc_tokens::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(
                row.map(|(token, token_timestamp, sender_timestamp)| TcTokenEntry {
                    token,
                    token_timestamp,
                    sender_timestamp,
                }),
            )
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    async fn put_tc_token(&self, jid: &str, entry: &TcTokenEntry) -> Result<()> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let jid = jid.to_string();
        let entry = entry.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(tc_tokens::table)
                .values((
                    tc_tokens::jid.eq(&jid),
                    tc_tokens::token.eq(&entry.token),
                    tc_tokens::token_timestamp.eq(entry.token_timestamp),
                    tc_tokens::sender_timestamp.eq(entry.sender_timestamp),
                    tc_tokens::device_id.eq(device_id),
                    tc_tokens::updated_at.eq(now),
                ))
                .on_conflict((tc_tokens::jid, tc_tokens::device_id))
                .do_update()
                .set((
                    tc_tokens::token.eq(&entry.token),
                    tc_tokens::token_timestamp.eq(entry.token_timestamp),
                    tc_tokens::sender_timestamp.eq(entry.sender_timestamp),
                    tc_tokens::updated_at.eq(now),
                ))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn delete_tc_token(&self, jid: &str) -> Result<()> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        let jid = jid.to_string();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::delete(
                tc_tokens::table
                    .filter(tc_tokens::jid.eq(&jid))
                    .filter(tc_tokens::device_id.eq(device_id)),
            )
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn get_all_tc_token_jids(&self) -> Result<Vec<String>> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let jids: Vec<String> = tc_tokens::table
                .select(tc_tokens::jid)
                .filter(tc_tokens::device_id.eq(device_id))
                .load(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(jids)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    async fn delete_expired_tc_tokens(&self, cutoff_timestamp: i64) -> Result<u32> {
        let pool = self.pool.clone();
        let device_id = self.device_id;
        tokio::task::spawn_blocking(move || -> Result<u32> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let deleted = diesel::delete(
                tc_tokens::table
                    .filter(tc_tokens::token_timestamp.lt(cutoff_timestamp))
                    .filter(tc_tokens::device_id.eq(device_id)),
            )
            .execute(&mut conn)
            .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(deleted as u32)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }
}

#[async_trait]
impl DeviceStore for SqliteStore {
    async fn save(&self, device: &CoreDevice) -> Result<()> {
        SqliteStore::save_device_data_for_device(self, self.device_id, device).await
    }

    async fn load(&self) -> Result<Option<CoreDevice>> {
        SqliteStore::load_device_data_for_device(self, self.device_id).await
    }

    async fn exists(&self) -> Result<bool> {
        SqliteStore::device_exists(self, self.device_id).await
    }

    async fn create(&self) -> Result<i32> {
        SqliteStore::create_new_device(self).await
    }

    async fn snapshot_db(&self, name: &str, extra_content: Option<&[u8]>) -> Result<()> {
        fn sanitize_snapshot_name(name: &str) -> Result<String> {
            const MAX_LENGTH: usize = 100;

            let sanitized: String = name
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();

            let sanitized = sanitized
                .split('.')
                .filter(|part| !part.is_empty() && *part != "..")
                .collect::<Vec<_>>()
                .join(".");

            let sanitized = sanitized.trim_matches(['/', '\\', '.']);

            if sanitized.is_empty() {
                return Err(StoreError::Database(
                    "Snapshot name cannot be empty after sanitization".to_string(),
                ));
            }

            if sanitized.len() > MAX_LENGTH {
                return Err(StoreError::Database(format!(
                    "Snapshot name exceeds maximum length of {} characters",
                    MAX_LENGTH
                )));
            }

            Ok(sanitized.to_string())
        }

        let sanitized_name = sanitize_snapshot_name(name)?;

        let pool = self.pool.clone();
        let db_path = self.database_path.clone();
        let extra_data = extra_content.map(|b| b.to_vec());

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Construct target path: db_path.snapshot-TIMESTAMP-SANITIZED_NAME
            let target_path = format!("{}.snapshot-{}-{}", db_path, timestamp, sanitized_name);

            // Use VACUUM INTO to create a consistent backup
            // Note: We escape single quotes in the path just in case
            let query = format!("VACUUM INTO '{}'", target_path.replace("'", "''"));

            diesel::sql_query(query)
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            // Save extra content if provided
            if let Some(data) = extra_data {
                let extra_path = format!("{}.json", target_path);
                std::fs::write(&extra_path, data).map_err(|e| {
                    StoreError::Database(format!("Failed to write snapshot extra content: {}", e))
                })?;
            }

            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_store() -> SqliteStore {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let db_name = format!("file:memdb_test_{}?mode=memory&cache=shared", timestamp);
        SqliteStore::new(&db_name)
            .await
            .expect("Failed to create test store")
    }

    #[test]
    fn test_parse_database_path_regular_path() {
        let path = "/var/lib/whatsapp/database.db";
        let result = parse_database_path(path).unwrap();
        assert_eq!(result, "/var/lib/whatsapp/database.db");
    }

    #[test]
    fn test_parse_database_path_with_sqlite_prefix() {
        let path = "sqlite:///var/lib/whatsapp/database.db";
        let result = parse_database_path(path).unwrap();
        assert_eq!(result, "/var/lib/whatsapp/database.db");
    }

    #[test]
    fn test_parse_database_path_with_query_params() {
        let path = "file:database.db?mode=memory&cache=shared";
        let result = parse_database_path(path).unwrap();
        assert_eq!(result, "file:database.db");
    }

    #[test]
    fn test_parse_database_path_with_fragment() {
        let path = "file:database.db#fragment";
        let result = parse_database_path(path).unwrap();
        assert_eq!(result, "file:database.db");
    }

    #[test]
    fn test_parse_database_path_with_both_query_and_fragment() {
        let path = "sqlite:///var/lib/database.db?mode=ro#backup";
        let result = parse_database_path(path).unwrap();
        assert_eq!(result, "/var/lib/database.db");
    }

    #[test]
    fn test_parse_database_path_in_memory_rejected() {
        let result = parse_database_path(":memory:");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not supported"));
    }

    #[test]
    fn test_parse_database_path_in_memory_with_query_rejected() {
        let result = parse_database_path(":memory:?cache=shared");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not supported"));
    }

    #[tokio::test]
    async fn test_device_registry_save_and_get() {
        let store = create_test_store().await;

        let record = DeviceListRecord {
            user: "1234567890".to_string(),
            devices: vec![
                DeviceInfo {
                    device_id: 0,
                    key_index: None,
                },
                DeviceInfo {
                    device_id: 1,
                    key_index: Some(42),
                },
            ],
            timestamp: 1234567890,
            phash: Some("2:abcdef".to_string()),
        };

        store.update_device_list(record).await.expect("save failed");
        let loaded = store
            .get_devices("1234567890")
            .await
            .expect("get failed")
            .expect("record should exist");

        assert_eq!(loaded.user, "1234567890");
        assert_eq!(loaded.devices.len(), 2);
        assert_eq!(loaded.devices[0].device_id, 0);
        assert_eq!(loaded.devices[1].device_id, 1);
        assert_eq!(loaded.devices[1].key_index, Some(42));
        assert_eq!(loaded.phash, Some("2:abcdef".to_string()));
    }

    #[tokio::test]
    async fn test_device_registry_update_existing() {
        let store = create_test_store().await;

        let record1 = DeviceListRecord {
            user: "1234567890".to_string(),
            devices: vec![DeviceInfo {
                device_id: 0,
                key_index: None,
            }],
            timestamp: 1000,
            phash: Some("2:old".to_string()),
        };
        store
            .update_device_list(record1)
            .await
            .expect("save1 failed");

        let record2 = DeviceListRecord {
            user: "1234567890".to_string(),
            devices: vec![
                DeviceInfo {
                    device_id: 0,
                    key_index: None,
                },
                DeviceInfo {
                    device_id: 2,
                    key_index: None,
                },
            ],
            timestamp: 2000,
            phash: Some("2:new".to_string()),
        };
        store
            .update_device_list(record2)
            .await
            .expect("save2 failed");

        let loaded = store
            .get_devices("1234567890")
            .await
            .expect("get failed")
            .expect("record should exist");

        assert_eq!(loaded.devices.len(), 2);
        assert_eq!(loaded.phash, Some("2:new".to_string()));
    }

    #[tokio::test]
    async fn test_device_registry_get_nonexistent() {
        let store = create_test_store().await;
        let result = store.get_devices("nonexistent").await.expect("get failed");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_sender_key_status_mark_and_consume() {
        let store = create_test_store().await;

        let group = "group123@g.us";
        let participant = "user1@s.whatsapp.net";

        store
            .mark_forget_sender_key(group, participant)
            .await
            .expect("mark failed");

        let consumed = store
            .consume_forget_marks(group)
            .await
            .expect("consume failed");
        assert_eq!(consumed.len(), 1);
        assert!(consumed.contains(&participant.to_string()));

        let consumed = store
            .consume_forget_marks(group)
            .await
            .expect("consume failed");
        assert!(consumed.is_empty());
    }

    #[tokio::test]
    async fn test_sender_key_status_consume_multiple() {
        let store = create_test_store().await;

        let group = "group123@g.us";

        store
            .mark_forget_sender_key(group, "user1@s.whatsapp.net")
            .await
            .expect("mark failed");
        store
            .mark_forget_sender_key(group, "user2@s.whatsapp.net")
            .await
            .expect("mark failed");

        let consumed = store
            .consume_forget_marks(group)
            .await
            .expect("consume failed");
        assert_eq!(consumed.len(), 2);
        assert!(consumed.contains(&"user1@s.whatsapp.net".to_string()));
        assert!(consumed.contains(&"user2@s.whatsapp.net".to_string()));

        let consumed = store
            .consume_forget_marks(group)
            .await
            .expect("consume failed");
        assert!(consumed.is_empty());
    }

    #[tokio::test]
    async fn test_tc_token_put_and_get() {
        let store = create_test_store().await;

        let entry = TcTokenEntry {
            token: vec![1, 2, 3, 4, 5],
            token_timestamp: 1707000000,
            sender_timestamp: Some(1707000100),
        };

        store
            .put_tc_token("user@lid", &entry)
            .await
            .expect("put failed");

        let loaded = store
            .get_tc_token("user@lid")
            .await
            .expect("get failed")
            .expect("should exist");

        assert_eq!(loaded.token, vec![1, 2, 3, 4, 5]);
        assert_eq!(loaded.token_timestamp, 1707000000);
        assert_eq!(loaded.sender_timestamp, Some(1707000100));
    }

    #[tokio::test]
    async fn test_tc_token_upsert() {
        let store = create_test_store().await;

        let entry1 = TcTokenEntry {
            token: vec![1, 2, 3],
            token_timestamp: 1000,
            sender_timestamp: None,
        };
        store.put_tc_token("user@lid", &entry1).await.unwrap();

        let entry2 = TcTokenEntry {
            token: vec![4, 5, 6],
            token_timestamp: 2000,
            sender_timestamp: Some(1500),
        };
        store.put_tc_token("user@lid", &entry2).await.unwrap();

        let loaded = store.get_tc_token("user@lid").await.unwrap().unwrap();
        assert_eq!(loaded.token, vec![4, 5, 6]);
        assert_eq!(loaded.token_timestamp, 2000);
        assert_eq!(loaded.sender_timestamp, Some(1500));
    }

    #[tokio::test]
    async fn test_tc_token_delete() {
        let store = create_test_store().await;

        let entry = TcTokenEntry {
            token: vec![1, 2, 3],
            token_timestamp: 1000,
            sender_timestamp: None,
        };
        store.put_tc_token("user@lid", &entry).await.unwrap();
        store.delete_tc_token("user@lid").await.unwrap();

        let result = store.get_tc_token("user@lid").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_tc_token_get_all_jids() {
        let store = create_test_store().await;

        let entry = TcTokenEntry {
            token: vec![1],
            token_timestamp: 1000,
            sender_timestamp: None,
        };
        store.put_tc_token("user1@lid", &entry).await.unwrap();
        store.put_tc_token("user2@lid", &entry).await.unwrap();
        store.put_tc_token("user3@lid", &entry).await.unwrap();

        let mut jids = store.get_all_tc_token_jids().await.unwrap();
        jids.sort();
        assert_eq!(jids, vec!["user1@lid", "user2@lid", "user3@lid"]);
    }

    #[tokio::test]
    async fn test_tc_token_delete_expired() {
        let store = create_test_store().await;

        let old = TcTokenEntry {
            token: vec![1],
            token_timestamp: 1000,
            sender_timestamp: None,
        };
        let recent = TcTokenEntry {
            token: vec![2],
            token_timestamp: 5000,
            sender_timestamp: None,
        };
        store.put_tc_token("old@lid", &old).await.unwrap();
        store.put_tc_token("recent@lid", &recent).await.unwrap();

        let deleted = store.delete_expired_tc_tokens(3000).await.unwrap();
        assert_eq!(deleted, 1);

        assert!(store.get_tc_token("old@lid").await.unwrap().is_none());
        assert!(store.get_tc_token("recent@lid").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_tc_token_get_nonexistent() {
        let store = create_test_store().await;
        let result = store.get_tc_token("nonexistent@lid").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_sender_key_status_different_groups() {
        let store = create_test_store().await;

        let group1 = "group1@g.us";
        let group2 = "group2@g.us";
        let participant = "user@s.whatsapp.net";

        store
            .mark_forget_sender_key(group1, participant)
            .await
            .expect("mark failed");

        let consumed = store.consume_forget_marks(group1).await.unwrap();
        assert_eq!(consumed.len(), 1);

        let consumed = store.consume_forget_marks(group2).await.unwrap();
        assert!(consumed.is_empty());
    }
}

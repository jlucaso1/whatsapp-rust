use crate::store::schema::*;
use crate::store::traits::*;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sql_query;
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use prost::Message;
use wacore::appstate::hash::HashState;
use wacore::libsignal;
use wacore::libsignal::protocol::{Direction, KeyPair, PrivateKey, PublicKey};
use wacore::store::error::{Result, StoreError};
use wacore::store::traits::AppStateMutationMAC;
use waproto::whatsapp::{self as wa, PreKeyRecordStructure, SignedPreKeyRecordStructure};

use wacore::store::Device as CoreDevice;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

type SqlitePool = Pool<ConnectionManager<SqliteConnection>>;
type SignalStoreError = Box<dyn std::error::Error + Send + Sync>;
type DeviceRow = (
    i32,             // id (new primary key)
    String,          // lid
    String,          // pn
    i32,             // registration_id
    Vec<u8>,         // noise_key
    Vec<u8>,         // identity_key
    Vec<u8>,         // signed_pre_key
    i32,             // signed_pre_key_id
    Vec<u8>,         // signed_pre_key_signature
    Vec<u8>,         // adv_secret_key
    Option<Vec<u8>>, // account
    String,          // push_name
    i32,             // app_version_primary
    i32,             // app_version_secondary
    i64,             // app_version_tertiary
    i64,             // app_version_last_fetched_ms
);

#[derive(Clone)]
pub struct SqliteStore {
    pub(crate) pool: SqlitePool,
}

impl SqliteStore {
    pub async fn new(database_url: &str) -> std::result::Result<Self, StoreError> {
        let manager = ConnectionManager::<SqliteConnection>::new(database_url);
        let pool = Pool::builder()
            .build(manager)
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        let pool_clone = pool.clone();
        tokio::task::spawn_blocking(move || -> std::result::Result<(), StoreError> {
            let mut conn = pool_clone
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            conn.run_pending_migrations(MIGRATIONS)
                .map_err(|e| StoreError::Migration(e.to_string()))?;
            let _ = diesel::sql_query("PRAGMA journal_mode=WAL;").execute(&mut conn);
            let _ = diesel::sql_query("PRAGMA synchronous=NORMAL;").execute(&mut conn);
            let _ = diesel::sql_query("PRAGMA busy_timeout = 15000;").execute(&mut conn);
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        Ok(Self { pool })
    }

    pub fn begin_transaction(
        &self,
    ) -> Result<diesel::r2d2::PooledConnection<ConnectionManager<SqliteConnection>>> {
        let mut conn = self.get_connection()?;
        diesel::sql_query("BEGIN DEFERRED TRANSACTION;")
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

    pub(crate) fn get_connection(
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

            // In single-device mode, find the first device or default to ID 1.
            let device_id: i32 = device::table
                .select(device::id)
                .first::<i32>(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?
                .unwrap_or(1);

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
                ))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        Ok(())
    }

    /// Save device data for a specific device ID (multi-account mode)
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
                ))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        Ok(())
    }

    pub async fn load_device_data(&self) -> Result<Option<CoreDevice>> {
        let pool = self.pool.clone();
        let row = tokio::task::spawn_blocking(move || -> Result<Option<DeviceRow>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let result = device::table
                .first::<DeviceRow>(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(result)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;

        if let Some((
            _device_id, // We don't use this in the CoreDevice (id is just for DB organization)
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
            }))
        } else {
            Ok(None)
        }
    }

    /// Create a new device entry in the database and return its ID
    pub async fn create_new_device(&self) -> Result<i32> {
        use crate::store::schema::device;

        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> Result<i32> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            // Create a new CoreDevice with default values
            let new_device = wacore::store::Device::new();

            // Serialize the device data
            let noise_key_data = {
                let mut bytes = Vec::with_capacity(64);
                bytes.extend_from_slice(&new_device.noise_key.private_key.serialize());
                bytes.extend_from_slice(new_device.noise_key.public_key.public_key_bytes());
                bytes
            };
            let identity_key_data = {
                let mut bytes = Vec::with_capacity(64);
                bytes.extend_from_slice(&new_device.identity_key.private_key.serialize());
                bytes.extend_from_slice(new_device.identity_key.public_key.public_key_bytes());
                bytes
            };
            let signed_pre_key_data = {
                let mut bytes = Vec::with_capacity(64);
                bytes.extend_from_slice(&new_device.signed_pre_key.private_key.serialize());
                bytes.extend_from_slice(new_device.signed_pre_key.public_key.public_key_bytes());
                bytes
            };

            // Insert the new device
            diesel::insert_into(device::table)
                .values((
                    device::lid.eq(""), // Empty initially, will be set during pairing
                    device::pn.eq(""),  // Empty initially, will be set during pairing
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
                ))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            // Get the last inserted row ID
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

    /// Check if a device with the given ID exists
    pub async fn device_exists(&self, device_id: i32) -> Result<bool> {
        use crate::store::schema::device;

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

    /// List all device IDs in the database
    pub async fn list_device_ids(&self) -> Result<Vec<i32>> {
        use crate::store::schema::device;

        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<i32>> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            let ids: Vec<i32> = device::table
                .select(device::id)
                .load(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            Ok(ids)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    /// Delete a device and all its associated data
    pub async fn delete_device(&self, device_id: i32) -> Result<()> {
        use crate::store::schema::*;

        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;

            // Start a transaction to ensure all deletes succeed or fail together
            conn.transaction::<_, diesel::result::Error, _>(|conn| {
                // Delete all associated data first (foreign key children)
                diesel::delete(identities::table.filter(identities::device_id.eq(device_id)))
                    .execute(conn)?;

                diesel::delete(sessions::table.filter(sessions::device_id.eq(device_id)))
                    .execute(conn)?;

                diesel::delete(prekeys::table.filter(prekeys::device_id.eq(device_id)))
                    .execute(conn)?;

                diesel::delete(
                    signed_prekeys::table.filter(signed_prekeys::device_id.eq(device_id)),
                )
                .execute(conn)?;

                diesel::delete(sender_keys::table.filter(sender_keys::device_id.eq(device_id)))
                    .execute(conn)?;

                diesel::delete(
                    app_state_keys::table.filter(app_state_keys::device_id.eq(device_id)),
                )
                .execute(conn)?;

                diesel::delete(
                    app_state_versions::table.filter(app_state_versions::device_id.eq(device_id)),
                )
                .execute(conn)?;

                diesel::delete(
                    app_state_mutation_macs::table
                        .filter(app_state_mutation_macs::device_id.eq(device_id)),
                )
                .execute(conn)?;

                // Finally delete the device itself
                let deleted_rows =
                    diesel::delete(device::table.filter(device::id.eq(device_id))).execute(conn)?;

                if deleted_rows == 0 {
                    return Err(diesel::result::Error::NotFound);
                }

                Ok(())
            })
            .map_err(|e| match e {
                diesel::result::Error::NotFound => StoreError::DeviceNotFound(device_id),
                _ => StoreError::Database(e.to_string()),
            })?;

            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    /// Load device data for a specific device ID
    pub async fn load_device_data_for_device(&self, device_id: i32) -> Result<Option<CoreDevice>> {
        use crate::store::schema::device;

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
            _device_id, // We already know the device_id
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
        )) = row
        {
            // Same parsing logic as load_device_data
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
            }))
        } else {
            Ok(None)
        }
    }

    // ---- Device-parameterized helpers (to deduplicate code) ----
    pub async fn put_identity_for_device(
        &self,
        address: &str,
        key: [u8; 32],
        device_id: i32,
    ) -> Result<()> {
        let pool = self.pool.clone();
        let address = address.to_string();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(identities::table)
                .values((
                    identities::address.eq(address),
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

    pub async fn delete_identity_for_device(&self, address: &str, device_id: i32) -> Result<()> {
        let pool = self.pool.clone();
        let address = address.to_string();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::delete(
                identities::table
                    .filter(identities::address.eq(address))
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
        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
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
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    pub async fn get_session_for_device(
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
            let res: Option<Vec<u8>> = sessions::table
                .select(sessions::record)
                .filter(sessions::address.eq(address))
                .filter(sessions::device_id.eq(device_id))
                .first(&mut conn)
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(res)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?
    }

    pub async fn put_session_for_device(
        &self,
        address: &str,
        session: &[u8],
        device_id: i32,
    ) -> Result<()> {
        let pool = self.pool.clone();
        let address = address.to_string();
        let session = session.to_vec();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(sessions::table)
                .values((
                    sessions::address.eq(address),
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

    pub async fn delete_session_for_device(&self, address: &str, device_id: i32) -> Result<()> {
        let pool = self.pool.clone();
        let address = address.to_string();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::delete(
                sessions::table
                    .filter(sessions::address.eq(address))
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

    pub async fn has_session_for_device(&self, address: &str, device_id: i32) -> Result<bool> {
        Ok(self
            .get_session_for_device(address, device_id)
            .await?
            .is_some())
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
            for idx in index_macs {
                diesel::delete(
                    app_state_mutation_macs::table.filter(
                        app_state_mutation_macs::name
                            .eq(&name)
                            .and(app_state_mutation_macs::index_mac.eq(&idx))
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
impl IdentityStore for SqliteStore {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()> {
        self.put_identity_for_device(address, key, 1).await
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        self.delete_identity_for_device(address, 1).await
    }

    async fn is_trusted_identity(
        &self,
        address: &str,
        key: &[u8; 32],
        _direction: Direction,
    ) -> Result<bool> {
        match self.load_identity(address).await? {
            Some(stored_key) => Ok(stored_key.as_slice() == key),
            None => Ok(true),
        }
    }

    async fn load_identity(&self, address: &str) -> Result<Option<Vec<u8>>> {
        self.load_identity_for_device(address, 1).await
    }
}

#[async_trait]
impl SessionStore for SqliteStore {
    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        self.get_session_for_device(address, 1).await
    }

    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()> {
        self.put_session_for_device(address, session, 1).await
    }

    async fn delete_session(&self, address: &str) -> Result<()> {
        self.delete_session_for_device(address, 1).await
    }

    async fn has_session(&self, address: &str) -> Result<bool> {
        self.has_session_for_device(address, 1).await
    }
}

#[async_trait]
impl libsignal::store::PreKeyStore for SqliteStore {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<Option<PreKeyRecordStructure>, SignalStoreError> {
        let pool = self.pool.clone();
        let result: Option<Vec<u8>> =
            tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
                let mut conn = pool
                    .get()
                    .map_err(|e| StoreError::Connection(e.to_string()))?;
                let res: Option<Vec<u8>> = prekeys::table
                    .select(prekeys::key)
                    .filter(prekeys::id.eq(prekey_id as i32))
                    .filter(prekeys::device_id.eq(1))
                    .first(&mut conn)
                    .optional()
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                Ok(res)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))??;

        if let Some(key_data) = result {
            if let Ok(private_key) = PrivateKey::deserialize(&key_data) {
                if let Ok(public_key) = private_key.public_key() {
                    let key_pair = KeyPair::new(public_key, private_key);
                    let record = wacore::libsignal::store::record_helpers::new_pre_key_record(
                        prekey_id, &key_pair,
                    );
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
        let pool = self.pool.clone();
        let private_key_bytes = record.private_key.unwrap_or_default();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(prekeys::table)
                .values((
                    prekeys::id.eq(prekey_id as i32),
                    prekeys::key.eq(&private_key_bytes),
                    prekeys::uploaded.eq(uploaded),
                    prekeys::device_id.eq(1),
                ))
                .on_conflict((prekeys::id, prekeys::device_id))
                .do_update()
                .set((
                    prekeys::key.eq(&private_key_bytes),
                    prekeys::uploaded.eq(uploaded),
                ))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn contains_prekey(&self, prekey_id: u32) -> std::result::Result<bool, SignalStoreError> {
        let pool = self.pool.clone();
        let count: i64 = tokio::task::spawn_blocking(move || -> Result<i64> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let cnt: i64 = prekeys::table
                .filter(prekeys::id.eq(prekey_id as i32))
                .filter(prekeys::device_id.eq(1))
                .count()
                .get_result(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(cnt)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(count > 0)
    }

    async fn remove_prekey(&self, prekey_id: u32) -> std::result::Result<(), SignalStoreError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::delete(
                prekeys::table
                    .filter(prekeys::id.eq(prekey_id as i32))
                    .filter(prekeys::device_id.eq(1)),
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
impl SenderKeyStoreHelper for SqliteStore {
    async fn put_sender_key(&self, address: &str, record: &[u8]) -> Result<()> {
        self.put_sender_key_for_device(address, record, 1).await
    }

    async fn get_sender_key(&self, address: &str) -> Result<Option<Vec<u8>>> {
        self.get_sender_key_for_device(address, 1).await
    }

    async fn delete_sender_key(&self, address: &str) -> Result<()> {
        self.delete_sender_key_for_device(address, 1).await
    }
}

#[async_trait]
impl libsignal::store::SignedPreKeyStore for SqliteStore {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<Option<SignedPreKeyRecordStructure>, SignalStoreError> {
        let pool = self.pool.clone();
        let result: Option<Vec<u8>> =
            tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
                let mut conn = pool
                    .get()
                    .map_err(|e| StoreError::Connection(e.to_string()))?;
                let res: Option<Vec<u8>> = signed_prekeys::table
                    .select(signed_prekeys::record)
                    .filter(signed_prekeys::id.eq(signed_prekey_id as i32))
                    .filter(signed_prekeys::device_id.eq(1))
                    .first(&mut conn)
                    .optional()
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                Ok(res)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))??;

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
            .filter(signed_prekeys::device_id.eq(1))
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
        let pool = self.pool.clone();
        let data = record.encode_to_vec();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::insert_into(signed_prekeys::table)
                .values((
                    signed_prekeys::id.eq(signed_prekey_id as i32),
                    signed_prekeys::record.eq(&data),
                    signed_prekeys::device_id.eq(1),
                ))
                .on_conflict((signed_prekeys::id, signed_prekeys::device_id))
                .do_update()
                .set(signed_prekeys::record.eq(&data))
                .execute(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(())
    }

    async fn contains_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<bool, SignalStoreError> {
        let pool = self.pool.clone();
        let count: i64 = tokio::task::spawn_blocking(move || -> Result<i64> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            let cnt: i64 = signed_prekeys::table
                .filter(signed_prekeys::id.eq(signed_prekey_id as i32))
                .filter(signed_prekeys::device_id.eq(1))
                .count()
                .get_result(&mut conn)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            Ok(cnt)
        })
        .await
        .map_err(|e| StoreError::Database(e.to_string()))??;
        Ok(count > 0)
    }

    async fn remove_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<(), SignalStoreError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut conn = pool
                .get()
                .map_err(|e| StoreError::Connection(e.to_string()))?;
            diesel::delete(
                signed_prekeys::table
                    .filter(signed_prekeys::id.eq(signed_prekey_id as i32))
                    .filter(signed_prekeys::device_id.eq(1)),
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
impl AppStateKeyStore for SqliteStore {
    async fn get_app_state_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        self.get_app_state_sync_key_for_device(key_id, 1).await
    }

    async fn set_app_state_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        self.set_app_state_sync_key_for_device(key_id, key, 1).await
    }
}

#[async_trait]
impl AppStateStore for SqliteStore {
    async fn get_app_state_version(&self, name: &str) -> Result<HashState> {
        self.get_app_state_version_for_device(name, 1).await
    }

    async fn set_app_state_version(&self, name: &str, state: HashState) -> Result<()> {
        self.set_app_state_version_for_device(name, state, 1).await
    }

    async fn put_app_state_mutation_macs(
        &self,
        name: &str,
        version: u64,
        mutations: &[AppStateMutationMAC],
    ) -> Result<()> {
        self.put_app_state_mutation_macs_for_device(name, version, mutations, 1)
            .await
    }

    async fn delete_app_state_mutation_macs(
        &self,
        name: &str,
        index_macs: &[Vec<u8>],
    ) -> Result<()> {
        self.delete_app_state_mutation_macs_for_device(name, index_macs, 1)
            .await
    }

    async fn get_app_state_mutation_mac(
        &self,
        name: &str,
        index_mac: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        self.get_app_state_mutation_mac_for_device(name, index_mac, 1)
            .await
    }
}

#[async_trait]
impl wacore::store::traits::DevicePersistence for SqliteStore {
    async fn save_device_data(
        &self,
        device_data: &wacore::store::Device,
    ) -> wacore::store::error::Result<()> {
        // Single-device mode always targets device_id = 1
        self.save_device_data_for_device(1, device_data).await
    }

    async fn save_device_data_for_device(
        &self,
        device_id: i32,
        device_data: &wacore::store::Device,
    ) -> wacore::store::error::Result<()> {
        SqliteStore::save_device_data_for_device(self, device_id, device_data).await
    }

    async fn load_device_data(
        &self,
    ) -> wacore::store::error::Result<Option<wacore::store::Device>> {
        // Single-device mode always targets device_id = 1
        self.load_device_data_for_device(1).await
    }

    async fn load_device_data_for_device(
        &self,
        device_id: i32,
    ) -> wacore::store::error::Result<Option<wacore::store::Device>> {
        SqliteStore::load_device_data_for_device(self, device_id).await
    }

    async fn device_exists(&self, device_id: i32) -> wacore::store::error::Result<bool> {
        SqliteStore::device_exists(self, device_id).await
    }

    async fn create_new_device(&self) -> wacore::store::error::Result<i32> {
        SqliteStore::create_new_device(self).await
    }
}

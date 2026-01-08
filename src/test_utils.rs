use std::sync::Arc;

use crate::Client;
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::store::persistence_manager::PersistenceManager;
use crate::store::traits::Backend;
use crate::transport::mock::MockTransportFactory;

// =============================================================================
// Test Backend Abstraction
// =============================================================================
//
// To switch between storage backends for tests, change ONLY this section.
// All tests use `create_test_backend()` which returns an in-memory backend.
//
// Current: RedbStore (in-memory)
// Alternative: SqliteStore (in-memory) - uncomment the sqlite section below

// --- RedbStore Configuration (current) ---
use whatsapp_rust_redb_storage::RedbStore;

/// Creates an in-memory test backend.
/// This is the single point of change to swap between storage backends.
pub fn create_test_backend() -> Arc<dyn Backend> {
    Arc::new(RedbStore::in_memory().expect("test backend should initialize"))
}

/// Creates an in-memory test backend for a specific device ID.
/// Used for multi-device testing scenarios.
pub fn create_test_backend_for_device(device_id: i32) -> Arc<dyn Backend> {
    Arc::new(RedbStore::in_memory_for_device(device_id).expect("test backend should initialize"))
}

// --- SqliteStore Configuration (alternative) ---
// Uncomment this section and comment out the RedbStore section above to use SQLite
//
// use whatsapp_rust_sqlite_storage::SqliteStore;
// use std::sync::atomic::{AtomicU64, Ordering};
// static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
//
// /// Creates an in-memory test backend using SQLite.
// pub async fn create_test_backend() -> Arc<dyn Backend> {
//     let unique_id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
//     let db_name = format!(
//         "file:memdb_test_{}_{}?mode=memory&cache=shared",
//         unique_id,
//         std::process::id()
//     );
//     Arc::new(SqliteStore::new(&db_name).await.expect("test backend should initialize"))
// }
// =============================================================================

#[derive(Debug, Clone, Default)]
pub struct MockHttpClient;

#[async_trait::async_trait]
impl HttpClient for MockHttpClient {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        Ok(HttpResponse {
            status_code: 200,
            body: Vec::new(),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct FailingMockHttpClient;

#[async_trait::async_trait]
impl HttpClient for FailingMockHttpClient {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        Err(anyhow::anyhow!("Not implemented"))
    }
}

pub async fn create_test_client() -> Arc<Client> {
    let pm = Arc::new(
        PersistenceManager::new(create_test_backend())
            .await
            .expect("persistence manager should initialize"),
    );

    let (client, _rx) = Client::new(
        pm,
        Arc::new(MockTransportFactory::new()),
        Arc::new(MockHttpClient),
        None,
    )
    .await;

    client
}

pub async fn create_test_client_with_failing_http() -> Arc<Client> {
    let pm = Arc::new(
        PersistenceManager::new(create_test_backend())
            .await
            .expect("persistence manager should initialize"),
    );

    let (client, _rx) = Client::new(
        pm,
        Arc::new(MockTransportFactory::new()),
        Arc::new(FailingMockHttpClient),
        None,
    )
    .await;

    client
}

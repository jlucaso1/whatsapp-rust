use std::sync::Arc;

use crate::Client;
use wacore_binary::{Node, OwnedNodeRef};

/// Marshal a `Node` into an `Arc<OwnedNodeRef>` for use in tests.
pub fn node_to_owned_ref(node: &Node) -> Arc<OwnedNodeRef> {
    let bytes = wacore_binary::marshal::marshal(node).expect("marshal should succeed");
    // marshal() prepends a leading format byte; OwnedNodeRef::new expects raw protocol bytes
    {
        let mut bytes = bytes;
        bytes.remove(0);
        Arc::new(OwnedNodeRef::new(bytes).expect("OwnedNodeRef::new should succeed"))
    }
}
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::runtime_impl::TokioRuntime;
use crate::store::SqliteStore;
use crate::store::persistence_manager::PersistenceManager;
use crate::store::traits::Backend;
use crate::transport::mock::MockTransportFactory;

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
    create_test_client_with_name("default").await
}

pub async fn create_test_client_with_name(name: &str) -> Arc<Client> {
    use portable_atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let db_name = format!(
        "file:memdb_{}_{}_{}?mode=memory&cache=shared",
        name,
        unique_id,
        std::process::id()
    );

    let backend = Arc::new(
        SqliteStore::new(&db_name)
            .await
            .expect("test backend should initialize"),
    ) as Arc<dyn Backend>;

    let pm = Arc::new(
        PersistenceManager::new(backend)
            .await
            .expect("persistence manager should initialize"),
    );

    let (client, _rx) = Client::new(
        Arc::new(TokioRuntime),
        pm,
        Arc::new(MockTransportFactory::new()),
        Arc::new(MockHttpClient),
        None,
    )
    .await;

    client
}

pub async fn create_test_client_with_failing_http(name: &str) -> Arc<Client> {
    use portable_atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let db_name = format!(
        "file:memdb_fail_{}_{}_{}?mode=memory&cache=shared",
        name,
        unique_id,
        std::process::id()
    );

    let backend = Arc::new(
        SqliteStore::new(&db_name)
            .await
            .expect("test backend should initialize"),
    ) as Arc<dyn Backend>;

    let pm = Arc::new(
        PersistenceManager::new(backend)
            .await
            .expect("persistence manager should initialize"),
    );

    let (client, _rx) = Client::new(
        Arc::new(TokioRuntime),
        pm,
        Arc::new(MockTransportFactory::new()),
        Arc::new(FailingMockHttpClient),
        None,
    )
    .await;

    client
}

use std::sync::Mutex;
use wacore::types::events::{Event, EventHandler};

#[derive(Default)]
pub struct TestEventCollector {
    events: Mutex<Vec<Arc<Event>>>,
}

impl EventHandler for TestEventCollector {
    fn handle_event(&self, event: Arc<Event>) {
        self.events
            .lock()
            .expect("collector mutex should not be poisoned")
            .push(event);
    }
}

impl TestEventCollector {
    pub fn events(&self) -> Vec<Arc<Event>> {
        self.events
            .lock()
            .expect("collector mutex should not be poisoned")
            .clone()
    }
}

pub async fn create_test_backend() -> Arc<dyn Backend> {
    use portable_atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let db_name = format!(
        "file:memdb_backend_{}_{}?mode=memory&cache=shared",
        unique_id,
        std::process::id()
    );

    Arc::new(
        SqliteStore::new(&db_name)
            .await
            .expect("test backend should initialize"),
    ) as Arc<dyn Backend>
}

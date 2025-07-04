use std::collections::HashMap;
use std::hash::Hash;
use tokio::sync::Mutex;

#[derive(Default)]
pub struct GenericMemoryStore<K, V>
where
    K: Eq + Hash + Send,
    V: Clone + Send,
{
    store: Mutex<HashMap<K, V>>,
}

impl<K, V> GenericMemoryStore<K, V>
where
    K: Eq + Hash + Send + Clone + Sync,
    V: Clone + Send + Sync,
{
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }

    pub async fn get(&self, key: &K) -> Option<V> {
        self.store.lock().await.get(key).cloned()
    }

    pub async fn put(&self, key: K, value: V) {
        self.store.lock().await.insert(key, value);
    }

    pub async fn contains(&self, key: &K) -> bool {
        self.store.lock().await.contains_key(key)
    }

    pub async fn remove(&self, key: &K) -> Option<V> {
        self.store.lock().await.remove(key)
    }

    pub async fn values(&self) -> Vec<V> {
        self.store.lock().await.values().cloned().collect()
    }
}

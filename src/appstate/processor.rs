// Re-export types from core
pub use wacore::appstate::{
    errors::{AppStateError, Result},
    hash::HashState,
    processor::{Mutation, PatchList, ProcessorUtils},
};

use crate::store::traits::{AppStateKeyStore, AppStateStore};
use std::sync::Arc;

pub struct Processor {
    #[allow(dead_code)] // TODO: This will be used when hash calculation is implemented
    store: Arc<dyn AppStateStore>,
    key_store: Arc<dyn AppStateKeyStore>,
}

impl Processor {
    pub fn new(store: Arc<dyn AppStateStore>, key_store: Arc<dyn AppStateKeyStore>) -> Self {
        Self { store, key_store }
    }

    pub async fn decode_patches(
        &self,
        list: &PatchList,
        initial_state: HashState,
    ) -> Result<(Vec<Mutation>, HashState)> {
        // Create a key lookup closure that uses our async key store
        let _key_store = self.key_store.clone();

        let key_lookup = |_key_id: &[u8]| -> Option<Vec<u8>> {
            // For this sync version, we'll need to use a different approach
            // since we can't use async closures easily
            // For now, return None to trigger missing keys error
            // The calling code will handle the missing keys
            None
        };

        // Use core processor logic
        ProcessorUtils::decode_patches_core(list, initial_state, key_lookup)
    }

    pub async fn decode_mutation(
        &self,
        keys: &wacore::appstate::keys::ExpandedAppStateKeys,
        mutation: &waproto::whatsapp::SyncdMutation,
        out: &mut Vec<Mutation>,
    ) -> Result<()> {
        ProcessorUtils::decode_mutation(keys, mutation, out)
    }
}

// @generated automatically by Diesel CLI.

diesel::table! {
    app_state_keys (key_id) {
        key_id -> Binary,
        key_data -> Binary,
    }
}

diesel::table! {
    app_state_versions (name) {
        name -> Text,
        state_data -> Binary,
    }
}

diesel::table! {
    identities (address) {
        address -> Text,
        key -> Binary,
    }
}

diesel::table! {
    prekeys (id) {
        id -> Integer,
        record -> Binary,
    }
}

diesel::table! {
    sender_keys (address) {
        address -> Text,
        record -> Binary,
    }
}

diesel::table! {
    sessions (address) {
        address -> Text,
        record -> Binary,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    app_state_keys,
    app_state_versions,
    identities,
    prekeys,
    sender_keys,
    sessions,
);

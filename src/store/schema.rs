// @generated automatically by Diesel CLI.

diesel::table! {
    app_state_keys (key_id) {
        key_id -> Binary,
        key_data -> Binary,
    }
}

diesel::table! {
    app_state_mutation_macs (name, index_mac) {
        name -> Text,
        version -> BigInt,
        index_mac -> Binary,
        value_mac -> Binary,
    }
}

diesel::table! {
    app_state_versions (name) {
        name -> Text,
        state_data -> Binary,
    }
}

diesel::table! {
    device (lid) {
        lid -> Text,
        pn -> Text,
        registration_id -> Integer,
        noise_key -> Binary,
        identity_key -> Binary,
        signed_pre_key -> Binary,
        signed_pre_key_id -> Integer,
        signed_pre_key_signature -> Binary,
        adv_secret_key -> Binary,
        account -> Nullable<Binary>,
        push_name -> Text,
        app_version_primary -> Integer,
        app_version_secondary -> Integer,
        app_version_tertiary -> BigInt,
        app_version_last_fetched_ms -> BigInt,
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
        key -> Binary,
        uploaded -> Bool,
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

diesel::table! {
    signed_prekeys (id) {
        id -> Integer,
        record -> Binary,
    }
}

diesel::table! {
    lid_pn_mappings (lid_user) {
        lid_user -> Text,
        pn_user -> Text,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    app_state_keys,
    app_state_mutation_macs,
    app_state_versions,
    device,
    identities,
    prekeys,
    sender_keys,
    sessions,
    signed_prekeys,
    lid_pn_mappings,
);

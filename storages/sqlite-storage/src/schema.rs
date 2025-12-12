// @generated automatically by Diesel CLI.

diesel::table! {
    app_state_keys (key_id, device_id) {
        key_id -> Binary,
        key_data -> Binary,
        device_id -> Integer,
    }
}

diesel::table! {
    app_state_mutation_macs (name, index_mac, device_id) {
        name -> Text,
        version -> BigInt,
        index_mac -> Binary,
        value_mac -> Binary,
        device_id -> Integer,
    }
}

diesel::table! {
    app_state_versions (name, device_id) {
        name -> Text,
        state_data -> Binary,
        device_id -> Integer,
    }
}

diesel::table! {
    device (id) {
        id -> Integer,
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
        edge_routing_info -> Nullable<Binary>,
    }
}

diesel::table! {
    identities (address, device_id) {
        address -> Text,
        key -> Binary,
        device_id -> Integer,
    }
}

diesel::table! {
    lid_pn_mapping (lid, device_id) {
        lid -> Text,
        phone_number -> Text,
        created_at -> BigInt,
        learning_source -> Text,
        updated_at -> BigInt,
        device_id -> Integer,
    }
}

diesel::table! {
    prekeys (id, device_id) {
        id -> Integer,
        key -> Binary,
        uploaded -> Bool,
        device_id -> Integer,
    }
}

diesel::table! {
    sender_keys (address, device_id) {
        address -> Text,
        record -> Binary,
        device_id -> Integer,
    }
}

diesel::table! {
    sessions (address, device_id) {
        address -> Text,
        record -> Binary,
        device_id -> Integer,
    }
}

diesel::table! {
    signed_prekeys (id, device_id) {
        id -> Integer,
        record -> Binary,
        device_id -> Integer,
    }
}

diesel::table! {
    skdm_recipients (group_jid, device_jid, device_id) {
        group_jid -> Text,
        device_jid -> Text,
        device_id -> Integer,
        created_at -> Integer,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    app_state_keys,
    app_state_mutation_macs,
    app_state_versions,
    device,
    identities,
    lid_pn_mapping,
    prekeys,
    sender_keys,
    sessions,
    signed_prekeys,
    skdm_recipients,
);

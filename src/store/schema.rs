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
    conversations (id) {
        id -> Text,
        data -> Binary,
    }
}

diesel::table! {
    device (id) {
        id -> Nullable<Integer>,
        jid -> Nullable<Text>,
        lid -> Nullable<Text>,
        registration_id -> Integer,
        noise_key -> Binary,
        identity_key -> Binary,
        signed_pre_key -> Binary,
        signed_pre_key_id -> Integer,
        signed_pre_key_signature -> Binary,
        adv_secret_key -> Binary,
        account -> Nullable<Binary>,
        push_name -> Text,
        processed_messages -> Nullable<Binary>,
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

diesel::allow_tables_to_appear_in_same_query!(
    app_state_keys,
    app_state_versions,
    conversations,
    device,
    identities,
    prekeys,
    sender_keys,
    sessions,
    signed_prekeys,
);

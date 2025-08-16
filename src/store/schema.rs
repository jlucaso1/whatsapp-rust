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
    chat_conversations (id) {
        id -> Text,
        name -> Nullable<Text>,
        display_name -> Nullable<Text>,
        last_msg_timestamp -> Nullable<Integer>,
        unread_count -> Nullable<Integer>,
        archived -> Nullable<Integer>,
        pinned -> Nullable<Integer>,
        created_at -> Nullable<Integer>,
    }
}

diesel::table! {
    chat_messages (conversation_id, message_id) {
        conversation_id -> Text,
        message_id -> Text,
        server_timestamp -> Nullable<Integer>,
        sender_jid -> Nullable<Text>,
        message_blob -> Binary,
    }
}

diesel::table! {
    chat_participants (conversation_id, jid) {
        conversation_id -> Text,
        jid -> Text,
        is_admin -> Nullable<Integer>,
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

diesel::joinable!(chat_messages -> chat_conversations (conversation_id));
diesel::joinable!(chat_participants -> chat_conversations (conversation_id));

diesel::allow_tables_to_appear_in_same_query!(
    app_state_keys,
    app_state_mutation_macs,
    app_state_versions,
    chat_conversations,
    chat_messages,
    chat_participants,
    conversations,
    device,
    identities,
    prekeys,
    sender_keys,
    sessions,
    signed_prekeys,
);

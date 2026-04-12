window.BENCHMARK_DATA = {
  "lastUpdate": 1776010634134,
  "repoUrl": "https://github.com/jlucaso1/whatsapp-rust",
  "entries": {
    "whatsapp-rust benchmarks": [
      {
        "commit": {
          "author": {
            "email": "jlucaso@hotmail.com",
            "name": "João Lucas",
            "username": "jlucaso1"
          },
          "committer": {
            "email": "jlucaso@hotmail.com",
            "name": "João Lucas",
            "username": "jlucaso1"
          },
          "distinct": true,
          "id": "a8aa930f6cc08da0e7a2fe24d459b110bd315a66",
          "message": "ci: replace Bencher with github-action-benchmark (#504)\n\nReplace Bencher (SaaS) with github-action-benchmark (self-hosted)\nfor continuous benchmarking. Keeps iai-callgrind as the harness.\n\n- Parser script converts iai-callgrind Instructions to JSON\n- Push to main stores baseline + updates gh-pages trend charts\n- PRs get collapsed comment: regressions/improvements visible,\n  unchanged benchmarks in accordion\n- Only compile crates with benchmarks (wacore, wacore-binary,\n  wacore-libsignal) instead of full workspace\n- No external service dependency, no API tokens",
          "timestamp": "2026-04-07T17:47:31-03:00",
          "tree_id": "9f20281cf0e86de06c78e58b70e074fe45cb81e4",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/a8aa930f6cc08da0e7a2fe24d459b110bd315a66"
        },
        "date": 1775595212877,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11851,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43398,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 69139,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 77229,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5939,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 181267,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192731,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 899449,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 1010386,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1617649,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2820727,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10507105,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 50228114,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12421580,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 98703,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 98731,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 118631,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 108446,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 98803,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15928,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15955,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 18004,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533456,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 533017,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534447,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 14815128,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 14813634,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 28200750,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal small:setup_small_marshaled()",
            "value": 2716,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal large:setup_large_marshaled()",
            "value": 41989,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_uncompressed",
            "value": 773,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556090,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 6199,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7431,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 91558,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7454,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 91589,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8966,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 107134,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 523708,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 20910,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17333745,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 162318,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5512366,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 163047,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 713228,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12587278,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27618542,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126206363,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 47033,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5116228,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 298844,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14247117,
            "unit": "instructions"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "3955907+mcaldas@users.noreply.github.com",
            "name": "Mathias Caldas",
            "username": "mcaldas"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3a335e9e29d0b44b17867dfb83d3cbc6dab2867f",
          "message": "fix: handle <unavailable> messages via PDO instead of silently dropping (#506)\n\nCo-authored-by: João Lucas <jlucaso@hotmail.com>",
          "timestamp": "2026-04-08T11:21:34-03:00",
          "tree_id": "8467a4a0d6a6f094ce54e0fd043dc0473a20e85e",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/3a335e9e29d0b44b17867dfb83d3cbc6dab2867f"
        },
        "date": 1775658491294,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11851,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43398,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 69139,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 77229,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5939,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 180987,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192731,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 899453,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 1010323,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1617566,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2820082,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10506514,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 50073372,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12663944,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 98703,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 98731,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 118631,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 108446,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 98803,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15928,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15955,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 18004,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533456,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 533017,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534447,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 14815128,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 14813634,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 28200750,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal small:setup_small_marshaled()",
            "value": 2716,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal large:setup_large_marshaled()",
            "value": 41989,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_uncompressed",
            "value": 773,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556090,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 6199,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7431,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 91558,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7454,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 91589,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8966,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 107134,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 523708,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 20910,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17179281,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 162318,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5512366,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 163047,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 713228,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12591337,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27571102,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126164713,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 47033,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5116228,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 298844,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14247117,
            "unit": "instructions"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "55464917+jlucaso1@users.noreply.github.com",
            "name": "João Lucas",
            "username": "jlucaso1"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "71df4f019d6a3fc778d0fea826a522876ce0f0fc",
          "message": "fix: PDO cache key mismatch and add response guards (#509)",
          "timestamp": "2026-04-08T18:55:14-03:00",
          "tree_id": "6523244b56eeb788bb171c8a0340e9781227f3ef",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/71df4f019d6a3fc778d0fea826a522876ce0f0fc"
        },
        "date": 1775685669147,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11851,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43398,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 69139,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 77229,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5939,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 180886,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192731,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 898759,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 1010330,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1617694,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2820502,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10475816,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 50067534,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12619329,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 98703,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 98731,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 118631,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 108446,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 98803,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15928,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15955,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 18004,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533456,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 533017,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534447,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 14815128,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 14813634,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 28200750,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal small:setup_small_marshaled()",
            "value": 2716,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal large:setup_large_marshaled()",
            "value": 41989,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_uncompressed",
            "value": 773,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556090,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 6199,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7431,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 91558,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7454,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 91589,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8966,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 107134,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 523708,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 20910,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17298362,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 162318,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5512366,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 163047,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 713228,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12579116,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27653737,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 125785493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 47033,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5116228,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 298844,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14247117,
            "unit": "instructions"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "55464917+jlucaso1@users.noreply.github.com",
            "name": "João Lucas",
            "username": "jlucaso1"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "80db1bb6fa003929a2e1f0cdb1b82999a2fdf604",
          "message": "perf: lazy ciphertext in SignalMessage, eliminate redundant allocation (#510)",
          "timestamp": "2026-04-09T12:15:37-03:00",
          "tree_id": "f5317b1f798513fa17fa9836ab410c4a219182db",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/80db1bb6fa003929a2e1f0cdb1b82999a2fdf604"
        },
        "date": 1775748132239,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11851,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43398,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 69139,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 77229,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5939,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 181125,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 193266,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 899445,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 1010388,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1617127,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2818495,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10498575,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 50198093,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12694922,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 98703,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 98731,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 118631,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 108446,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 98803,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15928,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15955,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 18004,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533456,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 533017,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534447,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 14815128,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 14813634,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 28200750,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal small:setup_small_marshaled()",
            "value": 2716,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal large:setup_large_marshaled()",
            "value": 41989,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_uncompressed",
            "value": 773,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556090,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 6199,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7431,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 91558,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7454,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 91589,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8966,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 107134,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 523708,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 20910,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17340525,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 162069,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5512660,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 163085,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 713231,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12545485,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27392177,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 124732113,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46970,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5119851,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 299173,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14247117,
            "unit": "instructions"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "55464917+jlucaso1@users.noreply.github.com",
            "name": "João Lucas",
            "username": "jlucaso1"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "0eda689e1f679832fc6d4fc6d045dcb6da6b5aa4",
          "message": "fix: codebase audit with bug fixes, race condition mitigations, and perf improvements (#511)",
          "timestamp": "2026-04-11T01:58:10-03:00",
          "tree_id": "7668d80c2aa1b7f27cb65f4815538b7bc21294fd",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/0eda689e1f679832fc6d4fc6d045dcb6da6b5aa4"
        },
        "date": 1775883824194,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11851,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43398,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 69139,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 77229,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5939,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 180707,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 193266,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 898761,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 1010396,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1617583,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2813120,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10499586,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 50031964,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12501341,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 98703,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 98731,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 118631,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 108446,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 98803,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15928,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15955,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 18004,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533456,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 533017,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534447,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 14815128,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 14813634,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 28200750,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal small:setup_small_marshaled()",
            "value": 2716,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal large:setup_large_marshaled()",
            "value": 41989,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_uncompressed",
            "value": 773,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556090,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 6199,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7431,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 91558,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7454,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 91589,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8966,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 107134,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 523708,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 20910,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17448610,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 162069,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5512660,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 163085,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 713231,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12388471,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27494810,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 123513473,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46970,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5119851,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 299173,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14247117,
            "unit": "instructions"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "55464917+jlucaso1@users.noreply.github.com",
            "name": "João Lucas",
            "username": "jlucaso1"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "0c24b5edd392d74628f367c584737d43ed58d705",
          "message": "perf!: use CompactString for NodeValue, NodeContent, and Jid.user (#512)",
          "timestamp": "2026-04-11T04:03:05-03:00",
          "tree_id": "cf61bddde419ba19fa482f1faee5cfd357269734",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/0c24b5edd392d74628f367c584737d43ed58d705"
        },
        "date": 1775891319901,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11851,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43398,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68822,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76789,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5939,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 179770,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 193146,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 894920,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 997331,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1552797,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2790271,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10328303,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 49426381,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12693442,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95389,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95422,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 115722,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 105315,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95489,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15706,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17798,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533097,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532663,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534118,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13379449,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13379193,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26860794,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal small:setup_small_marshaled()",
            "value": 2716,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal large:setup_large_marshaled()",
            "value": 40257,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_uncompressed",
            "value": 773,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556090,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 6008,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7431,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 89832,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7454,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 89863,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8966,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 105408,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 498603,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 17414,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17375559,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 162069,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5512660,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 163085,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 713231,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12583400,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27247322,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 125393753,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46970,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5119851,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 299173,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14247117,
            "unit": "instructions"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "55464917+jlucaso1@users.noreply.github.com",
            "name": "João Lucas",
            "username": "jlucaso1"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "bfe434acae0ac74574a6dec36e89b42b7eb13702",
          "message": "perf!: yoke zero-copy node decoding and Jid Server enum (#513)",
          "timestamp": "2026-04-12T10:25:45-03:00",
          "tree_id": "70be24e002fff785f24e58d2a33c3b4d76a1c020",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/bfe434acae0ac74574a6dec36e89b42b7eb13702"
        },
        "date": 1776000711078,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11851,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43398,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68814,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76781,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5939,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 179581,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 193123,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 893158,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 994413,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1537293,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2772530,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10309024,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 49166273,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12463773,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 93109,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 93142,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 113496,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102873,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 93209,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15416,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15460,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17558,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 532934,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532500,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 533970,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13085769,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13030095,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26573210,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal small:setup_small_marshaled()",
            "value": 2621,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal large:setup_large_marshaled()",
            "value": 37886,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_uncompressed",
            "value": 773,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556090,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5382,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7345,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 87464,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7368,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 87495,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8881,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 102993,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 475970,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 15731,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17379778,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 162069,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5512660,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 163085,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 713231,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12657691,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27614141,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 124988273,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46970,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5119851,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 299173,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14247117,
            "unit": "instructions"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "55464917+jlucaso1@users.noreply.github.com",
            "name": "João Lucas",
            "username": "jlucaso1"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "61d6ed22c3dcf1f438684ac181e12ece63833c71",
          "message": "perf!: replace Cow<str> with NodeStr for inline decoded strings (#514)",
          "timestamp": "2026-04-12T11:42:00-03:00",
          "tree_id": "4513b47a4a208e9f81e14a897f32f7f994c66e65",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/61d6ed22c3dcf1f438684ac181e12ece63833c71"
        },
        "date": 1776005239053,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11851,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43398,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68814,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76781,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5939,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 179616,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 193123,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 893733,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 995927,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1537871,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2783890,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10296447,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 49255112,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12548658,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95585,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95618,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 113974,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102895,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95685,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15762,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17592,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533122,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532688,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534046,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13413012,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13357245,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26652528,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal small:setup_small_marshaled()",
            "value": 2498,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal large:setup_large_marshaled()",
            "value": 38500,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_uncompressed",
            "value": 773,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556090,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5039,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7484,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90824,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7511,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90860,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104670,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 475970,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17114570,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 162069,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5512660,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 163085,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 713231,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12585959,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27578826,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126557903,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46970,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5119851,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 299173,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14247117,
            "unit": "instructions"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "55464917+jlucaso1@users.noreply.github.com",
            "name": "João Lucas",
            "username": "jlucaso1"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d0f4e057cb20a51bcc5015a1b19d9b766fefd575",
          "message": "perf!: Arc<Event> event bus to eliminate deep clones on dispatch (#515)",
          "timestamp": "2026-04-12T13:11:43-03:00",
          "tree_id": "dbd9edc70fd66b546ae3bd12a2ef065e7af5ad99",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/d0f4e057cb20a51bcc5015a1b19d9b766fefd575"
        },
        "date": 1776010633723,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11851,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43398,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68814,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76781,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5939,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 180020,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 193123,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 893733,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 995695,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1537807,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2783488,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10325574,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 49254245,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12618341,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95585,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95618,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 113974,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102895,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95685,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15762,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17592,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533122,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532688,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534046,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13413012,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13357245,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26652528,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal small:setup_small_marshaled()",
            "value": 2498,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unmarshal_group::bench_unmarshal large:setup_large_marshaled()",
            "value": 38500,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_uncompressed",
            "value": 773,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556090,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5039,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7484,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90824,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7511,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90860,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104670,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 475970,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17260534,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 162069,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5512660,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 163085,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 713231,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12549285,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27578706,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126110423,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46970,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5119851,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 299173,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14247117,
            "unit": "instructions"
          }
        ]
      }
    ]
  }
}
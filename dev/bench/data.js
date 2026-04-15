window.BENCHMARK_DATA = {
  "lastUpdate": 1776219451056,
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
          "id": "d367c35da1eb3ed8d6b05a9f51e8061765257a03",
          "message": "perf!: merge message_enqueue_locks + message_queues into ChatLane (#516)",
          "timestamp": "2026-04-12T13:56:07-03:00",
          "tree_id": "834dd9f50ce270ceb8470b0195143ee0a7cad7fb",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/d367c35da1eb3ed8d6b05a9f51e8061765257a03"
        },
        "date": 1776013315661,
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
            "value": 180028,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 193123,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 893033,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 995928,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1537870,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2783255,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10327559,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 49242205,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12647877,
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
            "value": 17301034,
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
            "value": 12659018,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27425879,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 124270023,
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
          "id": "100767645c1b464ada880cc859e14bfde6015cb7",
          "message": "perf: single-buffer ProtocolAddress + reusable hot-loop address construction (#518)",
          "timestamp": "2026-04-12T15:20:03-03:00",
          "tree_id": "dad27a8abf53b13008bfeb802be9a217085a5308",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/100767645c1b464ada880cc859e14bfde6015cb7"
        },
        "date": 1776018352464,
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
            "value": 177971,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191870,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 888986,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 980188,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1465398,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2744114,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10141275,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 48311928,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12685242,
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
            "value": 17187816,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 160994,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511244,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 161731,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12455803,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27610863,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 125771623,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5105272,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 297627,
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
          "id": "291ab58fcd955ec5a34900c0ca818a601bd11228",
          "message": "perf!: reduce hot-path allocations in receipt, send, and signal paths (#519)",
          "timestamp": "2026-04-12T16:43:48-03:00",
          "tree_id": "cbd29a21a503240135ea641e3e6cadccb0b493ff",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/291ab58fcd955ec5a34900c0ca818a601bd11228"
        },
        "date": 1776023353288,
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
            "value": 177971,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191870,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 888988,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 979477,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1464707,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2727788,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10025768,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 47880208,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12685187,
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
            "value": 17331403,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 160994,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511244,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 161731,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12696591,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27238692,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 124961413,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830493,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5105272,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 297627,
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
          "id": "eef4c2757d71098d91c527b285715c9daa80e7fe",
          "message": "perf!: Arc<MessageInfo> across message, retry, and PDO paths (#520)",
          "timestamp": "2026-04-12T17:34:16-03:00",
          "tree_id": "e86d1e08d27c4f98eaeaf52e318ee528a1b6397a",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/eef4c2757d71098d91c527b285715c9daa80e7fe"
        },
        "date": 1776026411075,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 177554,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191792,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 888232,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 980400,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1464714,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2728189,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10025493,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 47875352,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12614590,
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
            "value": 17227151,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 160994,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511244,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 161731,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12584399,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27314552,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126517103,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5105272,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 297627,
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
          "id": "d2a12c155cb598d55dd1b3ab900d963c3ab208b3",
          "message": "fix: suppress ack errors for all transport-unavailable conditions (#521)",
          "timestamp": "2026-04-12T18:27:57-03:00",
          "tree_id": "aa397c1dbec12a2615e8db32a3ebc649af10a42f",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/d2a12c155cb598d55dd1b3ab900d963c3ab208b3"
        },
        "date": 1776029610841,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 177557,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191792,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 888296,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 980401,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1465410,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2721567,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 10025166,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 47872527,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12732699,
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
            "value": 17146004,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 160994,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511231,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 161731,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712819,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12624806,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27532434,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 124283213,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5105272,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 297627,
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
          "id": "2194547ec4e63cbacbf6a36274637447346a207d",
          "message": "perf!: zero-copy receive pipeline and take-ownership session cache (#522)",
          "timestamp": "2026-04-12T23:23:54-03:00",
          "tree_id": "c9002b6b7bccf9ad63a24d90a47501752bccab9b",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/2194547ec4e63cbacbf6a36274637447346a207d"
        },
        "date": 1776047378458,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 177845,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192402,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 889621,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 980792,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1466047,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2672732,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9789529,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 46481411,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12534848,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95603,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 113983,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102682,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95670,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15768,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15812,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17601,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533124,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532690,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534051,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13407227,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13351504,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26652502,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90807,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90843,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104677,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 475970,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13477,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17187072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 161375,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511833,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 162112,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712819,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12577623,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27613161,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 125663293,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5106732,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 317585,
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
          "id": "ddda56098b40b92c9ff0052b8834d08ee04e4acb",
          "message": "feat!: comprehensive group feature improvements (#527)",
          "timestamp": "2026-04-13T17:56:56-03:00",
          "tree_id": "aa898dc48577d0b22d04187ebe8452ae38549892",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/ddda56098b40b92c9ff0052b8834d08ee04e4acb"
        },
        "date": 1776114139308,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 178336,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192488,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 889609,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 980991,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1466130,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2666388,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9788901,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 46491411,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12612015,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95603,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 113983,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102682,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95670,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15768,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15812,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17601,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533124,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532690,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534051,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13407227,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13351504,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26652502,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90807,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90843,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104677,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 475970,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13477,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17217947,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 161375,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511833,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 162112,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12540997,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27423511,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126166693,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5106732,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 317585,
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
          "id": "ab5c4c13104a2cdbd70a9f1c6c22d5b0197bbff4",
          "message": "perf!: reduce startup allocations by ~21% and peak heap by ~31% (#525)",
          "timestamp": "2026-04-13T17:57:36-03:00",
          "tree_id": "6732ab06735ebd5a68f973044146785c44eead3c",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/ab5c4c13104a2cdbd70a9f1c6c22d5b0197bbff4"
        },
        "date": 1776114216224,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 178330,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192480,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 889615,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 980994,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1466113,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2673238,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9789022,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 46496852,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12652705,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95603,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 113983,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102682,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95670,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15768,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15812,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17601,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533124,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532690,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534051,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13407227,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13351504,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26652502,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90807,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90843,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104677,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 475970,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13477,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17193736,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 161375,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511833,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 162112,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12653268,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27531805,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 124703853,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5106732,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 317585,
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
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "28117bb4bb726ac1fcb9d4cc4f0e00a7ad0dad79",
          "message": "chore(deps): bump rustls from 0.23.37 to 0.23.38 (#530)\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-04-13T20:49:52-03:00",
          "tree_id": "206cd19074527dca3dce45df131ce02816e37fdd",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/28117bb4bb726ac1fcb9d4cc4f0e00a7ad0dad79"
        },
        "date": 1776124517902,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 178330,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192395,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 888954,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 980804,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1466140,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2673412,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9790011,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 46485315,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12579586,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95603,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 113983,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102682,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95670,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15768,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15812,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17601,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533124,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532690,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534051,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13407227,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13351504,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26652502,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90807,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90843,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104677,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 475970,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13477,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17296800,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 161375,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511833,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 162112,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298289,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12542198,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27602237,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126463243,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830474,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5106732,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 317585,
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
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c6b1ec4e166cb0762f212b9b3fcac58bbb00ba80",
          "message": "chore(deps): bump rand from 0.10.0 to 0.10.1 (#531)\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-04-13T20:49:41-03:00",
          "tree_id": "dcafe854651b054440c2b78d7d0f57cb02416875",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/c6b1ec4e166cb0762f212b9b3fcac58bbb00ba80"
        },
        "date": 1776124537170,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 177925,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192481,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 889638,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 981009,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1466140,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2667208,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9788159,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 46318011,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12648662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95603,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 113983,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102682,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95670,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15768,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15812,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17601,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533124,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532690,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534051,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13407227,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13351504,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26652502,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90807,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90843,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104677,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 475970,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13477,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17303701,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 161375,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511833,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 162112,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712819,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12661456,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27610479,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 124676213,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830474,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5106732,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 317585,
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
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a94884a6c79b904c1565dfffadc0d630c4b6afb5",
          "message": "chore(deps): bump compact_str from 0.8.1 to 0.9.0 (#528)\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-04-13T20:50:09-03:00",
          "tree_id": "59790f3461439851976df11087c37cc92a462319",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/a94884a6c79b904c1565dfffadc0d630c4b6afb5"
        },
        "date": 1776124549396,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 178328,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192382,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 889631,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 981012,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1466140,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2666458,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9788853,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 46482698,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12687714,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95742,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95775,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114155,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102854,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15748,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17581,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423541,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26668743,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90828,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17110056,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 161375,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511833,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 162112,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12466511,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27458744,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 123443623,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830474,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5106732,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 317585,
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
          "id": "f856c859f8843dad2831176e3107d8d49a5857e8",
          "message": "fix: WA Web-compliant DM multi-device fanout with phash validation (#524)\n\nCo-authored-by: Mathias Caldas <mathiascaldas@gmail.com>",
          "timestamp": "2026-04-13T21:28:10-03:00",
          "tree_id": "fbdebd47b00e3d1a71a62773621aaebfd1cd77bd",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/f856c859f8843dad2831176e3107d8d49a5857e8"
        },
        "date": 1776126836131,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 177919,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192395,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 889632,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 981012,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1466136,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2666504,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9755061,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 46316771,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12575512,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95742,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95775,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114155,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102854,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15748,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17581,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423541,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26668743,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90828,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17331883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 161375,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511833,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 162112,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12688545,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27533191,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 125124143,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830474,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5106732,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 317585,
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
            "email": "107017350+Salientekill@users.noreply.github.com",
            "name": "Salientekill",
            "username": "Salientekill"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "cf1f0c67d80fe02028267382dfe5bb31d9a64b12",
          "message": "fix: centralize timestamp handling via wacore::time and fix signed parsing (#532)\n\nCo-authored-by: João Lucas <jlucaso@hotmail.com>",
          "timestamp": "2026-04-13T22:39:36-03:00",
          "tree_id": "9d8f930d774a5c1699fbbbb3c24b94271d4568b6",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/cf1f0c67d80fe02028267382dfe5bb31d9a64b12"
        },
        "date": 1776131125552,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 178334,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192481,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 889623,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 981011,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1466139,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2666987,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9790200,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 46486374,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12693307,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95742,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95775,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114155,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102854,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15748,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17581,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423541,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26668743,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90828,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17296698,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 161375,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511833,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 162112,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12577549,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27523601,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 123811173,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830474,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5106732,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 317585,
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
          "id": "5cf1eb8b5e4d7a4880bc441cabb590948b8f210b",
          "message": "feat!: replace history sync events with lazy blob + perf optimizations (#533)",
          "timestamp": "2026-04-14T01:25:35-03:00",
          "tree_id": "edfce739fffa6871ab64d76ec2baa9b96c43873a",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/5cf1eb8b5e4d7a4880bc441cabb590948b8f210b"
        },
        "date": 1776141066149,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 177917,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192395,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 889631,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 980948,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1466100,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2673227,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9756038,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 46317146,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12772719,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95742,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95775,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114155,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102854,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15748,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17581,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423541,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26668743,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90828,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17157393,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 161375,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511833,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 162112,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298289,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12650603,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27569844,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126070323,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830474,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5106732,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 317585,
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
            "email": "107017350+Salientekill@users.noreply.github.com",
            "name": "Salientekill",
            "username": "Salientekill"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "bac98a78fe98a81bc4523213f0d2ae5ab7bd25ca",
          "message": "feat(groups): add typed membership request variants (correct wire format) (#534)",
          "timestamp": "2026-04-14T01:35:18-03:00",
          "tree_id": "6b2bcdeec63f80945a8a92ed0c585b9ad860649b",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/bac98a78fe98a81bc4523213f0d2ae5ab7bd25ca"
        },
        "date": 1776141640285,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 177917,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192395,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 888939,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 981010,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1465453,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2666992,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9755333,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 46318773,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12692089,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95742,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95775,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114155,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102854,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15748,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17581,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423541,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26668743,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90828,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17039567,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 161375,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511833,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 162112,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12507117,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27338183,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 124661203,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830474,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5106732,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 317585,
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
          "id": "c70b936ccde767cc365ea1544937f5e8f6c8c484",
          "message": "fix(ci): support fork PRs in Claude review and benchmark workflows\n\nGitHub restricts OIDC tokens and write access for pull_request events\nfrom forks, breaking both the Claude code review (no OIDC) and benchmark\ncomment posting (403 on write).\n\n- claude-code-review: switch to pull_request_target + explicit\n  github_token to bypass OIDC exchange\n- benchmark: split comment posting into a workflow_run-triggered\n  workflow that runs in base repo context with write access",
          "timestamp": "2026-04-14T01:47:14-03:00",
          "tree_id": "869278f6383734405a2b100e825a79c90284ef08",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/c70b936ccde767cc365ea1544937f5e8f6c8c484"
        },
        "date": 1776142375268,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3879,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11855,
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
            "value": 76785,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2214,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 178334,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 192481,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 889566,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 981010,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1466074,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2673376,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9789303,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 46487340,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12395422,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95742,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95775,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114155,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102854,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15748,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17581,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423541,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26668743,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90828,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17373810,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 161375,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511833,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 162112,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 712883,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12543501,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27575274,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 125340303,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830474,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5106732,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 317585,
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
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "40bc538ee5b8a526db8ba0d3e0b93a468b89fe91",
          "message": "chore(deps): bump aes from 0.8.4 to 0.9.0 (#529)\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>\nCo-authored-by: João Lucas <jlucaso@hotmail.com>",
          "timestamp": "2026-04-14T10:18:23-03:00",
          "tree_id": "4a253e0d4d46df05d6c342a023567b7d7ed4a925",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/40bc538ee5b8a526db8ba0d3e0b93a468b89fe91"
        },
        "date": 1776173060956,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3882,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11867,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43401,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68820,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76800,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2217,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5951,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 174800,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191637,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 885506,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 977568,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1462756,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2629913,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9586679,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 45464647,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12317325,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95742,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95775,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114155,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102854,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15748,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17581,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423541,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26668743,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90828,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17341374,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157773,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511012,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158602,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 709311,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12768848,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27445000,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 123066693,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5089072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316826,
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
          "id": "79af72e1de5aa478a1c4b85de3367ad1bc2a300c",
          "message": "feat: add extension points for proxy and custom TLS support (#536)",
          "timestamp": "2026-04-14T10:50:28-03:00",
          "tree_id": "75054e747f6dccf8539c075cb08389f6301b974f",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/79af72e1de5aa478a1c4b85de3367ad1bc2a300c"
        },
        "date": 1776174978980,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3882,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11867,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43401,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68820,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76800,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2217,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5951,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 174797,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191785,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 886186,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 977512,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1462712,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2636801,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9620054,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 45465595,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12620462,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95742,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95775,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114155,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102854,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15748,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17581,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423541,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26668743,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90828,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17183021,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157773,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511012,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158602,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 709311,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12614603,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27521027,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 124649053,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5089072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316826,
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
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "880b08c4ed2a23cfea52d60a27da259c4774097e",
          "message": "chore(deps): bump libsqlite3-sys from 0.35.0 to 0.36.0 (#431)\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-04-14T11:22:53-03:00",
          "tree_id": "83fa0582d961b83ef2ecb43a46b59147a01dd922",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/880b08c4ed2a23cfea52d60a27da259c4774097e"
        },
        "date": 1776176904767,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3882,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11867,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43401,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68820,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76800,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2217,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5951,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 174391,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191785,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 886226,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 976732,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1462712,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2630734,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9619305,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 45465149,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12646720,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95742,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95775,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114155,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102854,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15748,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17581,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423541,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26668743,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90828,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17253326,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157773,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511012,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158602,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298289,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 709247,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12465639,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27638725,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 125379343,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5089072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316826,
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
          "id": "5bd021127e699fccda94e4b3a17e4cf5b52f0f42",
          "message": "fix: replace tokio timeout with runtime-agnostic timeout in phash validation (#537)",
          "timestamp": "2026-04-14T11:36:41-03:00",
          "tree_id": "08a0ef8096bfe4c348345f6244521c7b2c126e5f",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/5bd021127e699fccda94e4b3a17e4cf5b52f0f42"
        },
        "date": 1776177757654,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3882,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11867,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43401,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68820,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76800,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2217,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5951,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 174364,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191785,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 886226,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 977539,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1462762,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2636761,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9619907,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 45638388,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12614471,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95742,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95775,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114155,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102854,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15748,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17581,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423541,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26668743,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90828,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17293807,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157773,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511012,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158602,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 709311,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12584905,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27526352,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 123866173,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5089072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316826,
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
          "id": "ce620a25784e2cc7dcd5d5f4cb38f9a2eaddbdda",
          "message": "feat(wacore-binary): zero-copy Serialize for NodeRef type family (#539)",
          "timestamp": "2026-04-14T12:22:54-03:00",
          "tree_id": "ad181f54c92958e2d2065d733042029efc3c733a",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/ce620a25784e2cc7dcd5d5f4cb38f9a2eaddbdda"
        },
        "date": 1776180530280,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3882,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11867,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43401,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68820,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76800,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2217,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5951,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 174391,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191785,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 885517,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 977582,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1462750,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2636713,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9620311,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 45638636,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12614046,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95742,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95775,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114155,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102854,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15748,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17581,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423541,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26668743,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90828,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17300841,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157773,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511012,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158602,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298289,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 709311,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12537696,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27634560,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 124353053,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5089072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316826,
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
            "email": "github@aldo.pw",
            "name": "Aldo",
            "username": "aldoeliacim"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "60f2ba424098c220a5f0853930684eab1fb61826",
          "message": "feat(prekeys): expose public refresh_prekeys() for device migration (#538)",
          "timestamp": "2026-04-14T12:48:28-03:00",
          "tree_id": "5bc318c4ad59e69af393f3d5008731b52c457ee9",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/60f2ba424098c220a5f0853930684eab1fb61826"
        },
        "date": 1776182035265,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3882,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11867,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43401,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68820,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76800,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2217,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5951,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 174194,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191637,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 886177,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 976738,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1462676,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2637072,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9619931,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 45638899,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12806337,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95742,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95775,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114155,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102854,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15748,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17581,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423541,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367806,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26668743,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90792,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90828,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104662,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17215298,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157773,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511012,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158602,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 298353,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 709311,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12498475,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27714401,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126531153,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5089072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316826,
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
          "id": "8f6291587991d3b7d081db7ee6aeee1887f72869",
          "message": "perf: eliminate fmt::Write dispatch from JID string formatting (#540)",
          "timestamp": "2026-04-14T14:41:08-03:00",
          "tree_id": "1a778f005112c241ea2acc9617126af456cb6fe8",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/8f6291587991d3b7d081db7ee6aeee1887f72869"
        },
        "date": 1776188823804,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3882,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11867,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43401,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68406,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76386,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2217,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5951,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 174400,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191637,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 881268,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 972777,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1457794,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2614375,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9532194,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 45398374,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12725905,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95720,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95753,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114133,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102832,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95820,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15756,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15800,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17589,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423657,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367957,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26669024,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90801,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90837,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104671,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 16957047,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157773,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511012,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158602,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 296675,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 706993,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12385617,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27213692,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126503753,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5089072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316826,
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
          "id": "71b6ef5b41295fa7476e34ce1687aae9a0897c73",
          "message": "feat(status): add send_reaction for status likes (#541)",
          "timestamp": "2026-04-14T15:08:15-03:00",
          "tree_id": "a10f59fcf4fedc76676c4b3b51ad551be8f5bcbc",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/71b6ef5b41295fa7476e34ce1687aae9a0897c73"
        },
        "date": 1776190469916,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3882,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11867,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43401,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68406,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76386,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2217,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5951,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 174362,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191785,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 882017,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 972719,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1457173,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2620339,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9567135,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 45398223,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12569130,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 95720,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 95753,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114133,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102832,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 95820,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 15756,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 15800,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 17589,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533115,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532681,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534042,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13423657,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13367957,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26669024,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7483,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 90801,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7510,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 90837,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8838,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 104671,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17077446,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157773,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511012,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158602,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 296675,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 706993,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12457309,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27592528,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126910293,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5089072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316826,
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
          "id": "f41be17d2573d996e9ae380d28cf371b9e12f2de",
          "message": "perf: skip string classification for strings longer than PACKED_MAX (#542)",
          "timestamp": "2026-04-14T15:40:36-03:00",
          "tree_id": "08392c6eeab5d24c2023e46cc558c94cf3bfe3a5",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/f41be17d2573d996e9ae380d28cf371b9e12f2de"
        },
        "date": 1776192353375,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3882,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11867,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43401,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68406,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76386,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2217,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5951,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 174471,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191785,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 882117,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 972010,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1457941,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2620898,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9569508,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 45413671,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12424390,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 96218,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 96251,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 114683,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 102981,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 96318,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 10665,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 10709,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 12417,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 533153,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 532719,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 534080,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 13481842,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 13426142,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 26776648,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 7504,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 91100,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7531,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 91136,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8896,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 105299,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13468,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17327650,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157773,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511012,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158602,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 296675,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 706993,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12583195,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27592575,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 123065593,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5089072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316826,
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
          "id": "5a20483532ad10153a0d0b1632756b6ce950f8ad",
          "message": "perf: unify single/double-byte token maps into single PHF lookup (#543)",
          "timestamp": "2026-04-14T15:43:17-03:00",
          "tree_id": "15f44abb90d6e2b0ab6a39f00add9b6c941d95b2",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/5a20483532ad10153a0d0b1632756b6ce950f8ad"
        },
        "date": 1776192525255,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3882,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11867,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43401,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68406,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76386,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2217,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5951,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 173522,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191645,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 878779,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 970143,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1455402,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2611772,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9535294,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 45252310,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12553026,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 88027,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 88060,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 107366,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 94790,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 88127,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 9301,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 9345,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 11053,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 531897,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 531463,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 532824,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 11108699,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 11052975,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 22343327,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5028,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 6989,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 83328,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 7016,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 83364,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 8381,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 98447,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 13276,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17189812,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157773,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511012,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158602,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 296675,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 706993,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12430501,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27593997,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 125786743,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5089072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316826,
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
          "id": "9db21cb2c13ab058eee5d0c553c074242755e2ad",
          "message": "perf!: replace PHF+SipHash token lookup with hashify PTHash (FNV-1a) (#544)",
          "timestamp": "2026-04-14T17:52:16-03:00",
          "tree_id": "96bc7ff3257e8562e0c154a1a345d7fc09f639f5",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/9db21cb2c13ab058eee5d0c553c074242755e2ad"
        },
        "date": 1776200291609,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3882,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11863,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43401,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68406,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76382,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2217,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5947,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 170348,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191645,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 874753,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 966096,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1451306,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2583228,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9411859,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 44642651,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12351223,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 70913,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 70946,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 97966,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 77676,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 71013,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 7499,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 7543,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 9251,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 530504,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 530070,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 531431,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 8506994,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 8451227,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 19678704,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5031,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 5330,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 66219,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 5357,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 66255,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 6722,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 89618,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 479370,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 11612,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17282898,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157773,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511012,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158602,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 296675,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 706993,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12573585,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27401606,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 125434263,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5089072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316826,
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
          "id": "0797fe96bd3b9df4f534e6646808f99aca9dbe24",
          "message": "perf: avoid unnecessary clone and pre-allocate Vecs in hot paths (#545)",
          "timestamp": "2026-04-14T19:55:01-03:00",
          "tree_id": "396b9d6feab4e473107dee242ed99c68dcc05326",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/0797fe96bd3b9df4f534e6646808f99aca9dbe24"
        },
        "date": 1776207639323,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3882,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 11863,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43401,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68406,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76382,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2217,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5947,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 170357,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191785,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 875435,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 966245,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1451368,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2583388,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9412352,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 44642038,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12804585,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 70913,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 70946,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 97966,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 77676,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 71013,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 7499,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 7543,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 9251,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 530504,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 530070,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 531431,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 8506994,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 8451227,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 19678704,
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
            "value": 785,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556214,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5031,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 5330,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 66219,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 5357,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 66255,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 6722,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 89618,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 479370,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 11612,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17333215,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157773,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511012,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158602,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 296675,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 706929,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12690103,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27451732,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 125041613,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5089072,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316826,
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
          "id": "a49da92471553a747c9ccf7d4f0b9d9b509d5435",
          "message": "perf: trim unused features, deps, and gate prost-build behind feature (#547)",
          "timestamp": "2026-04-14T21:47:10-03:00",
          "tree_id": "e1e954c397eeca5095736d53178872d110c21bed",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/a49da92471553a747c9ccf7d4f0b9d9b509d5435"
        },
        "date": 1776214329352,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3933,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 12038,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43414,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68478,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76578,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2230,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5988,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 170162,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191742,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 875926,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 966937,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1453314,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2585751,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9422595,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 44694729,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12612112,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 71207,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 71240,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 98328,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 78762,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 71307,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 7518,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 7562,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 9274,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 530499,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 530066,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 531423,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 8507096,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 8451427,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 19679084,
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
            "value": 788,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556229,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 5330,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 66315,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 5357,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 66351,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 6734,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 89630,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 11599,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17227742,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157923,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511084,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158737,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 296767,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 707098,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12732084,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27597071,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126963193,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830498,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5090932,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316987,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14254317,
            "unit": "instructions"
          }
        ]
      },
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
          "id": "77716a737b99f56994cc32810c9a94433829cf75",
          "message": "chore: update packages to latest",
          "timestamp": "2026-04-14T21:48:30-03:00",
          "tree_id": "b0f57747679cf85fff56aebfb381169bd2c370e1",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/77716a737b99f56994cc32810c9a94433829cf75"
        },
        "date": 1776214471877,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3933,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 12038,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43414,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68478,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76578,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2230,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5988,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 170591,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191890,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 875880,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 966197,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1453314,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2579743,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9422992,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 44519130,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12569479,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 71207,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 71240,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 98328,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 78762,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 71307,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 7518,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 7562,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 9274,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 530499,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 530066,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 531423,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 8507096,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 8451427,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 19679084,
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
            "value": 788,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556229,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 5330,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 66315,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 5357,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 66351,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 6734,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 89630,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 11599,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17215432,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157923,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511084,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158737,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 296767,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 707098,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12655092,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27406398,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 125718133,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5090932,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316987,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14254317,
            "unit": "instructions"
          }
        ]
      },
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
          "id": "1290b4d28419f2f918ccd253c9bc785b736c8d31",
          "message": "ci: use Blacksmith 4vcpu runner for Copilot setup steps",
          "timestamp": "2026-04-14T22:36:45-03:00",
          "tree_id": "b207c575db10ac70967610e599367f8b1cf3cc1f",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/1290b4d28419f2f918ccd253c9bc785b736c8d31"
        },
        "date": 1776217399895,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3933,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 12038,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43414,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68478,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76578,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2230,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5988,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 170156,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191742,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 875870,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 966943,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1453314,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2585807,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9389194,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 44693376,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12568084,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 71207,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 71240,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 98328,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 78762,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 71307,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 7518,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 7562,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 9274,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 530499,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 530066,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 531423,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 8507096,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 8451427,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 19679084,
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
            "value": 788,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556229,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 5330,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 66315,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 5357,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 66351,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 6734,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 89630,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 11599,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17187009,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157923,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511084,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158737,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 296767,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 707098,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12555025,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27603962,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 125838993,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5090932,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316987,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14254317,
            "unit": "instructions"
          }
        ]
      },
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
          "id": "77716a737b99f56994cc32810c9a94433829cf75",
          "message": "chore: update packages to latest",
          "timestamp": "2026-04-14T21:48:30-03:00",
          "tree_id": "b0f57747679cf85fff56aebfb381169bd2c370e1",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/77716a737b99f56994cc32810c9a94433829cf75"
        },
        "date": 1776217521455,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3933,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 12038,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43414,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68478,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76578,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2230,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5988,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 170144,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191742,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 875225,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 966922,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1454026,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2585761,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9423160,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 44502512,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12731635,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 71207,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 71240,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 98328,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 78762,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 71307,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 7518,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 7562,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 9274,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 530499,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 530066,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 531423,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 8507096,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 8451427,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 19679084,
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
            "value": 788,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556229,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 5330,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 66315,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 5357,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 66351,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 6734,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 89630,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 11599,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17105929,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157923,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511084,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158737,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 296699,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 707098,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12583507,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27562167,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126177433,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5090932,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316987,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14254317,
            "unit": "instructions"
          }
        ]
      },
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
          "id": "d02dabc022ade5ea64b9b3755cc99c67605378fe",
          "message": "chore: downgrade noisy log levels for routine protocol operations\n\nSignal protocol internals (prekey processing, chain creation, sender\nkey creation, session trimming) and keepalive pings moved from info\nto debug. Decrypt-retry flows (missing sender key, no session,\ninvalid prekey ID) and retry receipt sending moved from warn to debug\nto match WA Web behavior where these are normal self-healing flows.\nUnavailable/PDO placeholder moved from warn to info, matching WA Web\nLOG level.",
          "timestamp": "2026-04-14T23:05:48-03:00",
          "tree_id": "8053e469dca73955b5cfa9eb3879b2d4d261874b",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/d02dabc022ade5ea64b9b3755cc99c67605378fe"
        },
        "date": 1776219096873,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3933,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 12038,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43414,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68478,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76578,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2230,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5988,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 170566,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191742,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 875947,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 967088,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1453257,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2579261,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9423278,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 44695201,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12597850,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 71207,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 71240,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 98328,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 78762,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 71307,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 7518,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 7562,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 9274,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 530499,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 530066,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 531423,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 8507096,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 8451427,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 19679084,
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
            "value": 788,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556229,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 5330,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 66315,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 5357,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 66351,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 6734,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 89630,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 11599,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17136959,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157923,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511084,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158737,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 296767,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 707098,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12623789,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27605320,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 123849903,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5090932,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316987,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14254317,
            "unit": "instructions"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "198982749+Copilot@users.noreply.github.com",
            "name": "Copilot",
            "username": "Copilot"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ce3344267a77250ea8e6fbc01d0effe7c7f30682",
          "message": "refactor: targeted single-device DM retry (matches WA Web) (#549)\n\nCo-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>\nCo-authored-by: jlucaso1 <55464917+jlucaso1@users.noreply.github.com>",
          "timestamp": "2026-04-14T23:11:58-03:00",
          "tree_id": "d3f960f1f9404d6d345d3ffffa0343bb60f4d5b1",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/ce3344267a77250ea8e6fbc01d0effe7c7f30682"
        },
        "date": 1776219450728,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction simple:setup_simple_message()",
            "value": 3933,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::content_extraction_group::bench_content_extraction extended:setup_extended_message()",
            "value": 12038,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::key_derivation_group::bench_key_derivation",
            "value": 43414,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::token_calculation_group::bench_token_calculation",
            "value": 19365,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation simple:setup_full_gen_simple()",
            "value": 68478,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::full_generation_group::bench_full_token_generation extended:setup_full_gen_extended()",
            "value": 76578,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding simple:setup_simple_message()",
            "value": 2230,
            "unit": "instructions"
          },
          {
            "name": "reporting_token_benchmark::message_encoding_group::bench_message_encoding extended:setup_extended_message()",
            "value": 5988,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_send::bench_dm_send text:setup_dm_send()",
            "value": 170585,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::dm_recv::bench_dm_recv text:setup_dm_recv()",
            "value": 191890,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_10:setup_group_send_10()",
            "value": 875959,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_50:setup_group_send_50()",
            "value": 966140,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send::bench_group_send group_256:setup_group_send_256()",
            "value": 1454014,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_10:setup_group_skdm_10()",
            "value": 2585803,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_50:setup_group_skdm_50()",
            "value": 9422885,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_send_skdm::bench_group_send_skdm skdm_256:setup_group_skdm_256()",
            "value": 44693724,
            "unit": "instructions"
          },
          {
            "name": "send_receive_benchmark::group_recv::bench_group_recv text:setup_group_recv()",
            "value": 12459604,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_allocating",
            "value": 71207,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_allocating",
            "value": 71240,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_allocating",
            "value": 98328,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer",
            "value": 78762,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_reusing_buffer_vec_writer",
            "value": 71307,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_long_string",
            "value": 7518,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_long_string",
            "value": 7562,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_long_string",
            "value": 9274,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_huge_bytes_allocating",
            "value": 530499,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_huge_bytes_allocating",
            "value": 530066,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_huge_bytes_allocating",
            "value": 531423,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_many_children_allocating",
            "value": 8507096,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_auto_many_children_allocating",
            "value": 8451427,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::marshal_group::bench_marshal_exact_many_children_allocating",
            "value": 19679084,
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
            "value": 788,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::unpack_group::bench_unpack_compressed",
            "value": 556229,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::attr_parser_group::bench_attr_parser attr_lookup:setup_attr_marshaled()",
            "value": 5024,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip small:setup_small_marshaled()",
            "value": 5330,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip large:setup_large_marshaled()",
            "value": 66315,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto small:setup_small_marshaled()",
            "value": 5357,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_auto large:setup_large_marshaled()",
            "value": 66351,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact small:setup_small_marshaled()",
            "value": 6734,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::roundtrip_group::bench_roundtrip_exact large:setup_large_marshaled()",
            "value": 89630,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::child_iteration_group::bench_get_children_by_tag",
            "value": 477570,
            "unit": "instructions"
          },
          {
            "name": "binary_benchmark::jid_optimization_group::bench_jid_to_owned_access jid_access:setup_jid_heavy_marshaled()",
            "value": 11599,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_session_establishment setup:setup_dm_users()",
            "value": 17417140,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_first_message first_msg:setup_dm_session()",
            "value": 157923,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_decrypt_first_message decrypt_prekey:setup_dm_with_first_message()",
            "value": 5511084,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::dm_group::bench_dm_encrypt_subsequent_message subsequent:setup_established_dm_session()",
            "value": 158737,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_create_distribution_message create:setup_group_sender()",
            "value": 296767,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_encrypt_message encrypt:setup_group_with_distribution()",
            "value": 707098,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::group_messaging_group::bench_group_decrypt_message decrypt:setup_group_with_encrypted_message()",
            "value": 12495104,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::conversation_group::bench_full_dm_conversation full:setup_conversation_data()",
            "value": 27672983,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_creation sign:setup_keypair_with_message()",
            "value": 3467011,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_signature_verification verify:setup_keypair_with_message()",
            "value": 126613343,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::signature_group::bench_key_generation keygen",
            "value": 2830452,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_decrypt_with_previous_session previous_session:setup_with_archived_sessions()",
            "value": 46003,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_out_of_order_decryption out_of_order:setup_out_of_order_messages()",
            "value": 5090932,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_promote_matching_session promote:setup_promote_matching_session()",
            "value": 316987,
            "unit": "instructions"
          },
          {
            "name": "libsignal_benchmark::session_optimization_group::bench_message_key_eviction eviction:setup_message_key_eviction()",
            "value": 14254317,
            "unit": "instructions"
          }
        ]
      }
    ]
  }
}
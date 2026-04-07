window.BENCHMARK_DATA = {
  "lastUpdate": 1775595213420,
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
      }
    ]
  }
}
window.BENCHMARK_DATA = {
  "lastUpdate": 1776522249339,
  "repoUrl": "https://github.com/oxidezap/whatsapp-rust",
  "entries": {
    "whatsapp-rust integration benchmarks": [
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
          "id": "264174306e2850f2b52d941b43c791ed2744c40f",
          "message": "perf: integration benchmarks + allocation optimizations (#551)",
          "timestamp": "2026-04-15T13:53:49-03:00",
          "tree_id": "b49ea26f48ebb02c686f2c63f2b1fb7c3556c57a",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/264174306e2850f2b52d941b43c791ed2744c40f"
        },
        "date": 1776272203549,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 12203,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3796940,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 395,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 248,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 41050,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 450,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 108118,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 402,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 99721,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 497,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 121168,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 51,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1305,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 497286,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5093,
            "unit": "milliseconds"
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
          "id": "0c506d594c8f1b922a3604068f388653029c5f4f",
          "message": "perf: zero-copy frame send, direct prekey encoding, covariant AttrsRef (#552)",
          "timestamp": "2026-04-15T16:27:03-03:00",
          "tree_id": "21bb1736ae7406acf82469f5f9123f609287afad",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/0c506d594c8f1b922a3604068f388653029c5f4f"
        },
        "date": 1776281389053,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9705,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3531530,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 393,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 251,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 40990,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 446,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 103994,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 646,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 147769,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 492,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 120362,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 51,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1529,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 531129,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5528,
            "unit": "milliseconds"
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
          "id": "619483a43496b420979dff32714bb0e29422d152",
          "message": "perf: split notification handler, boxed-slice children, interest-based props (#553)",
          "timestamp": "2026-04-15T17:59:59-03:00",
          "tree_id": "c08691dc310d5cef6272b8535350e4154884ebf8",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/619483a43496b420979dff32714bb0e29422d152"
        },
        "date": 1776286926140,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9740,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3399597,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 394,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 248,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 40837,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 312,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 63202,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 424,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 105469,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 494,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 120429,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 39,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1544,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 536929,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5049,
            "unit": "milliseconds"
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
          "id": "19a3f168eaf6f7248aae291259d551b48a28ef93",
          "message": "perf: signal store hot path - lightweight PN, cache-first identity, reusable flush buffer (#554)",
          "timestamp": "2026-04-15T18:53:00-03:00",
          "tree_id": "c2e64a7f226646ca8b3024f74b4260a1b809fc49",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/19a3f168eaf6f7248aae291259d551b48a28ef93"
        },
        "date": 1776290107361,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9561,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3283915,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 425,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 230,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 38020,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 387,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 91481,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 381,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 96986,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 434,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 107995,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 37,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1427,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 507296,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5241,
            "unit": "milliseconds"
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
          "id": "88a5145e8dd28ada9b7b6e52ac38a6de2f8000da",
          "message": "perf: pre-encode acks, Bytes for sessions, [u8;32] for identities (#555)",
          "timestamp": "2026-04-15T20:01:35-03:00",
          "tree_id": "0de98068da01e7c8b966f6c34e6f019718cece59",
          "url": "https://github.com/jlucaso1/whatsapp-rust/commit/88a5145e8dd28ada9b7b6e52ac38a6de2f8000da"
        },
        "date": 1776294223263,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9528,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3244876,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 390,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 515,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 79270,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 351,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 76555,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 366,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 93245,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 431,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 102454,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 31,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1464,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 504687,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5430,
            "unit": "milliseconds"
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
          "id": "fac5b581f84ccc9246ef7cac27f5728272ada6c6",
          "message": "WA Web compliance: retry flow + group/status session rebuild (#559)",
          "timestamp": "2026-04-17T01:58:24-03:00",
          "tree_id": "7cb0f2e9244d5174bbf2ff9a655b93e98b95bd4a",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/fac5b581f84ccc9246ef7cac27f5728272ada6c6"
        },
        "date": 1776402043826,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9514,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3214459,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 395,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 234,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 38331,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 323,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 69880,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 362,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 93189,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 432,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 102996,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 43,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1466,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 506279,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5098,
            "unit": "milliseconds"
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
          "id": "79d964ea270579209cb6d67db878f93faafd287e",
          "message": "Graceful shutdown for detached tasks (fixes WASM setTimeout leaks) (#560)",
          "timestamp": "2026-04-17T03:35:29-03:00",
          "tree_id": "e546e2a0c0b4c42ee9d0d23c32b58bcc0111e2f5",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/79d964ea270579209cb6d67db878f93faafd287e"
        },
        "date": 1776407862827,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9556,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3229807,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 399,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 229,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37738,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 232,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 38973,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 362,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 93118,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 436,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 105237,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 59,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1488,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 507118,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5299,
            "unit": "milliseconds"
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
          "id": "bd698accd87315cdef79df1280eaf56d659ec41e",
          "message": "feat: pluggable SignalCryptoProvider for AES-CBC/GCM + HMAC-SHA256 (#561)",
          "timestamp": "2026-04-17T14:31:04-03:00",
          "tree_id": "69f966df3bea2481eda74cba7823b2d940c0e875",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/bd698accd87315cdef79df1280eaf56d659ec41e"
        },
        "date": 1776447185596,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9868,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3316021,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 436,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 230,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37986,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 329,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 68345,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 377,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 94167,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 433,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 104109,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 45,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1240,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 471879,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5060,
            "unit": "milliseconds"
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
          "id": "7801b22f35914c3a3c3b4fbd4d3e9295c13873d7",
          "message": "feat: incoming call events + member label update (#562)",
          "timestamp": "2026-04-17T20:34:47-03:00",
          "tree_id": "c3d44b2132f9193fe134e637e0f9b4d1c2a14481",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/7801b22f35914c3a3c3b4fbd4d3e9295c13873d7"
        },
        "date": 1776469008589,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9515,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3214097,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 402,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 225,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37577,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 399,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 94593,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 371,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 94399,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 432,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 102981,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 33,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1485,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 504184,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 4916,
            "unit": "milliseconds"
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
          "id": "0c52f5999849deebdc8dd794a274f3c804348295",
          "message": "fix: status reactions via send_message with correct E2EE wire format (#563)",
          "timestamp": "2026-04-17T22:18:20-03:00",
          "tree_id": "121f4a20a2d3162716036bb54c4eac3ca9a475c6",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/0c52f5999849deebdc8dd794a274f3c804348295"
        },
        "date": 1776475219805,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9495,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3265197,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 390,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 230,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 38052,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 390,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 91683,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 386,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 97065,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 426,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 101638,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 18,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1478,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 504374,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 4877,
            "unit": "milliseconds"
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
          "id": "6fd9f132cb3b8b5bbfe89484331556cff7d8b144",
          "message": "fix: participant change success check + phone/username mixins (#564)",
          "timestamp": "2026-04-17T23:00:26-03:00",
          "tree_id": "b1d162c505d078faa1cfacd647ba32cb562518d3",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/6fd9f132cb3b8b5bbfe89484331556cff7d8b144"
        },
        "date": 1776477758812,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9496,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3263441,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 391,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 230,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 38045,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 399,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 92619,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 374,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 93641,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 430,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 103463,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 45,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1466,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 503447,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5393,
            "unit": "milliseconds"
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
          "id": "0289b14b60f264d1751d28e74638576c56791980",
          "message": "fix: cache-aside fallback in get_lid_pn_entry (#565)",
          "timestamp": "2026-04-18T01:25:51-03:00",
          "tree_id": "2dc4950ce748d8bda493eeb950998c982b8cf45a",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/0289b14b60f264d1751d28e74638576c56791980"
        },
        "date": 1776486462388,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9437,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3192829,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 395,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 230,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37844,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 246,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 44628,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 366,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 93965,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 436,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 105061,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 57,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1481,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 504415,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 4617,
            "unit": "milliseconds"
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
          "id": "a6930b154c79962816b2bf9b61bc42b6328a87f0",
          "message": "Align enum JSON discriminators with wire tags via StringEnum (#566)",
          "timestamp": "2026-04-18T09:55:32-03:00",
          "tree_id": "fd07764ae1b77d97d008d8d816bed0b853a85ca4",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/a6930b154c79962816b2bf9b61bc42b6328a87f0"
        },
        "date": 1776517063682,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9500,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3265285,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 391,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 230,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 38057,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 417,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 100538,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 366,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 93282,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 433,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 104141,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 43,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1407,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 494740,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 4610,
            "unit": "milliseconds"
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
          "id": "af5ef34f72a22970e2f131c833c41c1db7a72c99",
          "message": "Unify enum wire-tag derives under #[derive(WireEnum)] (#567)",
          "timestamp": "2026-04-18T11:22:11-03:00",
          "tree_id": "c36999737d226218a08cdeffc3bc2cde9dc57a50",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/af5ef34f72a22970e2f131c833c41c1db7a72c99"
        },
        "date": 1776522248848,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9854,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3310733,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 392,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 229,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37736,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 398,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 94365,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 368,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 93834,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 427,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 101886,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 24,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1480,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 504557,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 4685,
            "unit": "milliseconds"
          }
        ]
      }
    ]
  }
}
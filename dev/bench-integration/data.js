window.BENCHMARK_DATA = {
  "lastUpdate": 1777322976575,
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
          "id": "dfdfc9520e71873da66d6223d8ea9738beb42bd7",
          "message": "fix(status): use LID addressing, skip unresolvable recipients (#568)",
          "timestamp": "2026-04-18T13:35:14-03:00",
          "tree_id": "de78e950e0aa3d00e1c57f9ef32e5dc143696a43",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/dfdfc9520e71873da66d6223d8ea9738beb42bd7"
        },
        "date": 1776530228485,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9491,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3217145,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 430,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 229,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37735,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 388,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 89432,
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
            "value": 93750,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 429,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 103202,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 39,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1474,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 502155,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 4691,
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
          "id": "5b05e227c084be66237caeb55c6ae9dab02fa775",
          "message": "fix(status): drop <meta status_setting> on reactions and revokes (#569)",
          "timestamp": "2026-04-18T15:12:57-03:00",
          "tree_id": "15671f3470b4a28fe99c2f08182fea3cd8cf1b36",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/5b05e227c084be66237caeb55c6ae9dab02fa775"
        },
        "date": 1776536122773,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9496,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3219429,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 391,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 233,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 38141,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 394,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 91985,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 369,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 93385,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 429,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 102032,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 16,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1482,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 504694,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 4940,
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
          "id": "4db92be17310e628c9e46eb43fc041ee5e3fdee7",
          "message": "perf: 11 allocation trims from hot-path audit (#570)",
          "timestamp": "2026-04-18T16:19:43-03:00",
          "tree_id": "1ac3718f5817f695ad33ee8482ade3755a390d7e",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/4db92be17310e628c9e46eb43fc041ee5e3fdee7"
        },
        "date": 1776540102651,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9520,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3165589,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 390,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 225,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37436,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 382,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 91330,
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
            "value": 94887,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 423,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 103830,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 41,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1471,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 503475,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 4765,
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
          "id": "3a47b2897b5d44ecf157641177a0c906dd3555d0",
          "message": "fix(receipt): flush in-flight delivery receipts on disconnect (#573)",
          "timestamp": "2026-04-20T01:09:55-03:00",
          "tree_id": "449e3dd491577fa20a063f5df5c2931017d81c2f",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/3a47b2897b5d44ecf157641177a0c906dd3555d0"
        },
        "date": 1776658312187,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9496,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3264007,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 388,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 229,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37907,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 342,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 76142,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 489,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 111577,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 423,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 103183,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 39,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1425,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 497189,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5522,
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
          "id": "cbe7df2f1039aa05f6fdabef4d37df0feb46b920",
          "message": "feat(mex): notification dispatcher + consolidated doc-id registry (#574)",
          "timestamp": "2026-04-20T01:10:48-03:00",
          "tree_id": "5717af32991178d32c6ab0b1dadc0441ffdd4b48",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/cbe7df2f1039aa05f6fdabef4d37df0feb46b920"
        },
        "date": 1776658368030,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9467,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3264733,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 398,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 229,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37698,
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
            "value": 92518,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 358,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 93372,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 425,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 105242,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 61,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1435,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 497917,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 4867,
            "unit": "milliseconds"
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
          "id": "151da74ca7ecf25b1921afd72f7da386be636644",
          "message": "test(receipt): regression guards for disconnect timing\n\nTwo timing assertions tied to PR #573:\n- Cold disconnect (no pending receipts) — completes in ms, not the\n  5s drain cap.\n- Hot disconnect (5-message burst received, immediate disconnect) —\n  drain finishes well under 1s.\n\nCatches a class of regression where the receipt-flush path could\nsilently start padding every disconnect with the full 5s timeout\n(spawn handle never decremented, listener never notified, etc.).\nBoth guards pass on cbe7df2.",
          "timestamp": "2026-04-20T01:52:54-03:00",
          "tree_id": "fdda539109b97c8688981060c54ffbb4487679e8",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/151da74ca7ecf25b1921afd72f7da386be636644"
        },
        "date": 1776660855737,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9462,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3218648,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 390,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 229,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37703,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 296,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 62599,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 356,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 93203,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 421,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 101907,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 18,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1428,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 497863,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5460,
            "unit": "milliseconds"
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
          "id": "fc499e03d94059334dcf07b0775bc96e39d30774",
          "message": "chore: format",
          "timestamp": "2026-04-20T01:54:58-03:00",
          "tree_id": "31ed31bab1bf25f4ce6afaa81a35ff8dadef9622",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/fc499e03d94059334dcf07b0775bc96e39d30774"
        },
        "date": 1776660992965,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9595,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3280644,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 391,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 494,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 75924,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 365,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 87380,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 358,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 94768,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 420,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 101864,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 23,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1475,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 504250,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5108,
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
          "id": "783be4c7ce49dfa8db10332a7bdb687588d2cd82",
          "message": "refactor(receipt): extract FlushScope primitive; fix PDO leak via shutdown signal (#576)",
          "timestamp": "2026-04-20T13:48:55-03:00",
          "tree_id": "17925b7974b12339aaa63ff97cf6ae04d61178db",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/783be4c7ce49dfa8db10332a7bdb687588d2cd82"
        },
        "date": 1776703849959,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9475,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3212407,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 394,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 228,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37798,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 383,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 91580,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 363,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 95155,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 420,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 103422,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 39,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1113,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 454099,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5281,
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
          "id": "e0dd1c801e5fd2ee07ed0a74e05fa23cf29ec875",
          "message": "fix: concurrent disconnect hang (flush_scope counter leak + cleanup_connection_state socket teardown) (#577)",
          "timestamp": "2026-04-20T15:36:05-03:00",
          "tree_id": "0e554171ebad05a1105cc7c8eaee50b716b3d43f",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/e0dd1c801e5fd2ee07ed0a74e05fa23cf29ec875"
        },
        "date": 1776710291709,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9462,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3217818,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 431,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 229,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37914,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 381,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 89639,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 365,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 94920,
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
            "value": 106472,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 71,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1257,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 477065,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5248,
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
          "id": "726e64d35d1be281cd5ad93f73df7f155fb822b6",
          "message": "perf(message): off-load LID-PN persist + migrations from the decrypt hot path (#578)",
          "timestamp": "2026-04-20T17:17:58-03:00",
          "tree_id": "612a260f1659e7af200478bd51adfe105a28d9ad",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/726e64d35d1be281cd5ad93f73df7f155fb822b6"
        },
        "date": 1776716396829,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9669,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3252458,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 392,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 225,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37472,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 392,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 97195,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 357,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 94817,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 423,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 105885,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 31,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1186,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 462831,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5158,
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
          "id": "113f9eb675582f066ac44a407465651a343f4f6c",
          "message": "fix(send): close LID↔PN zombie path for group prekey 406 latency spikes (#579)",
          "timestamp": "2026-04-20T20:34:08-03:00",
          "tree_id": "3017a03673ef77fccb19a95649c74c1c85927e12",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/113f9eb675582f066ac44a407465651a343f4f6c"
        },
        "date": 1776728181530,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9546,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3282811,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 432,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 223,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37298,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 370,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 85925,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 363,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 96750,
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
            "value": 106280,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 35,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1239,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 472806,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5498,
            "unit": "milliseconds"
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
          "id": "b1123625e070fbb0c9c9f09fb29ed7da0a5c4439",
          "message": "chore: update packages",
          "timestamp": "2026-04-23T09:39:29-03:00",
          "tree_id": "09c16f4aae37ff38c4f97e44ce108a1111fd61b1",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/b1123625e070fbb0c9c9f09fb29ed7da0a5c4439"
        },
        "date": 1776948145624,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9498,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3276765,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 386,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 314,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 52468,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 375,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 90922,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 370,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 97717,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 424,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 106697,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 47,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1250,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 476356,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5206,
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
          "id": "8bf0d1f1734f15cee7fc93cf240c2ab77b7e40e2",
          "message": "chore: audit follow-ups (perf, cleanup, helpers) (#584)",
          "timestamp": "2026-04-23T12:41:04-03:00",
          "tree_id": "a264d16ab03878efabe2fc60e0b429caafb54d61",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/8bf0d1f1734f15cee7fc93cf240c2ab77b7e40e2"
        },
        "date": 1776959020288,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9466,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3229249,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 432,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 1136,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 94397,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 406,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 101332,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 376,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 97812,
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
            "value": 106172,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 37,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1474,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 504063,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5160,
            "unit": "milliseconds"
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
          "id": "f1e545dd0776e88584b4346b6cd7d5413dd6eb3f",
          "message": "chore(deps): bump yoke from 0.7.5 to 0.8.2 (#583)\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-04-23T12:43:10-03:00",
          "tree_id": "683ecf48df6e482d0374feb9ba01344837c7997a",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/f1e545dd0776e88584b4346b6cd7d5413dd6eb3f"
        },
        "date": 1776959111373,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9522,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3342060,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 389,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 229,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37903,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 365,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 84984,
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
            "value": 97381,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 428,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 107264,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 53,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1471,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 503562,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5031,
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
          "id": "4dd4994bc2cfd3982b2e85c8929c46dd47a9a422",
          "message": "fix(pdo): align PDO recovery + UndecryptableMessage dispatch with WA Web (#585)",
          "timestamp": "2026-04-23T15:12:27-03:00",
          "tree_id": "d6655f532b5e5850159e5ac0340f02f11e188100",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/4dd4994bc2cfd3982b2e85c8929c46dd47a9a422"
        },
        "date": 1776968065790,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9566,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3291610,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 394,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 229,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37906,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 346,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 78528,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 372,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 97527,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 425,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 105785,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 33,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1443,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 498078,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 4685,
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
          "id": "cb8d260611704d2ea20297849ab86e8e255f4f56",
          "message": "feat(device)!: DevicePropsOverride builder, align DEVICE_PROPS with WA Web (#586)",
          "timestamp": "2026-04-24T15:58:11-03:00",
          "tree_id": "a8e8dbe71423a9d6d6968dff8e254456de13935d",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/cb8d260611704d2ea20297849ab86e8e255f4f56"
        },
        "date": 1777057209307,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9550,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3274445,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 391,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 228,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37796,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 388,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 97096,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 353,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 97489,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 429,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 108830,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 67,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1486,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 505493,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 4936,
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
          "id": "b5c21ed61c6859de61d02bb3adc20b09bc64261a",
          "message": "fix(http): raise UreqHttpClient body cap from ureq's 10 MiB default (#587)",
          "timestamp": "2026-04-24T16:17:42-03:00",
          "tree_id": "7312d45a0cb5ba73d5b4b0c8d3259b91dca03c0a",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/b5c21ed61c6859de61d02bb3adc20b09bc64261a"
        },
        "date": 1777058350829,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9545,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3209631,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 433,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 223,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37370,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 354,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 81337,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 370,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 97720,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 424,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 105482,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 29,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1459,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 502708,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 4738,
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
          "id": "00a9be1970308f2f8700c3bcf4b86b4cb6ae52ca",
          "message": "fix(time): route all now() calls through wacore::time; enforce via clippy (#588)",
          "timestamp": "2026-04-24T17:21:59-03:00",
          "tree_id": "9c08b23b96e3829cb79e7928eda13686e9fad3af",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/00a9be1970308f2f8700c3bcf4b86b4cb6ae52ca"
        },
        "date": 1777062251710,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9540,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3263511,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 391,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 229,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37897,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 382,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 91575,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 359,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 96436,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 1,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 422,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 105210,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 27,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1470,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 501783,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5159,
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
          "id": "6cd8e3c262ec65ab95b32b0bf8c33b51f8b20d35",
          "message": "fix(decrypt): fall through when <unavailable> comes alongside <enc> (#589)",
          "timestamp": "2026-04-24T19:09:48-03:00",
          "tree_id": "fefbc1944d78940c85ccfd1414db312b811bd840",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/6cd8e3c262ec65ab95b32b0bf8c33b51f8b20d35"
        },
        "date": 1777068711306,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9491,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3308734,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 386,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 346,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 56275,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 396,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 99333,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 356,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 95017,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 425,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 105598,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 31,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1480,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 504161,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5189,
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
          "id": "eb1ba9a004784cfd2ea84b0ad0bacc6538761f04",
          "message": "perf: reduce cache and channel pre-allocations (#590)",
          "timestamp": "2026-04-24T19:36:57-03:00",
          "tree_id": "7ddebcc28037163e544614e5abb6db54a8e08c27",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/eb1ba9a004784cfd2ea84b0ad0bacc6538761f04"
        },
        "date": 1777070351404,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9544,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3172550,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 392,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 225,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37248,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 233,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 39120,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 367,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 98130,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 420,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 104602,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 18,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1473,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 456781,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 5371,
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
          "id": "c1b600ddae0ce5b94544553695d4a3304e718534",
          "message": "fix: e2e reconnect and receipt flakes (#591)",
          "timestamp": "2026-04-24T20:43:10-03:00",
          "tree_id": "fe10c6dec5a906a2484c2b02d532ebd411b919f7",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/c1b600ddae0ce5b94544553695d4a3304e718534"
        },
        "date": 1777074308483,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9544,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3221861,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 390,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 228,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37897,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 1,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 387,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 94608,
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
            "value": 96892,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 1,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 428,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 107980,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 57,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1476,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 450502,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 49,
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
          "id": "63210f7f515ba7c15af5e815e3012607180d3b8b",
          "message": "fix(pair-code)!: derive companion_platform_{id,display} from DeviceProps (#592)",
          "timestamp": "2026-04-24T20:48:21-03:00",
          "tree_id": "b7a39cf600411a5da94a08f45ad801e85e242376",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/63210f7f515ba7c15af5e815e3012607180d3b8b"
        },
        "date": 1777074624752,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9478,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3166332,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 392,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 227,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37760,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 1,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 231,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 38990,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 360,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 96656,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 423,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 105991,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 37,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1473,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 450679,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 49,
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
          "id": "2d82f2ca0f363e824c958709f26eeb9c074c3c4e",
          "message": "fix(pair): WA Web compliant pairing QR + companion_platform_{id,display} (#593)",
          "timestamp": "2026-04-25T01:37:00-03:00",
          "tree_id": "6b960b21df54780055168cd49c9535d971218461",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/2d82f2ca0f363e824c958709f26eeb9c074c3c4e"
        },
        "date": 1777091935480,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9509,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3237269,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 391,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 229,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 38013,
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
            "value": 94050,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 351,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 96342,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 424,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 105059,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 20,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1472,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 450343,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 49,
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
          "id": "06809e17ab41731f28f2042ace0daba4faa90b9a",
          "message": "fix(pair,props): enforce ADV HMAC verify and round-trip <prop> children (#594)",
          "timestamp": "2026-04-25T21:44:00-03:00",
          "tree_id": "d73dc751ef434bfab0516606cbb837bfdb0508d1",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/06809e17ab41731f28f2042ace0daba4faa90b9a"
        },
        "date": 1777164369526,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9579,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3307837,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 381,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 230,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 38022,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 1,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 327,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 71796,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 524,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 119103,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 429,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 109315,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 69,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1485,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 457790,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 48,
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
          "id": "c6603a58041bc786810380813b410a3669005530",
          "message": "fix(pair): emit empirically correct companion_platform_id for Android (#595)",
          "timestamp": "2026-04-25T23:51:43-03:00",
          "tree_id": "d9981747b9ee49c61f2f057222e10063f0fa45cf",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/c6603a58041bc786810380813b410a3669005530"
        },
        "date": 1777172028810,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9679,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3288792,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 391,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 231,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37930,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 383,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 93506,
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
            "value": 98310,
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
            "value": 108582,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 59,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1353,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 435567,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 49,
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
          "id": "897e6b5c6b1208dc9f9360371993d1b62e016263",
          "message": "feat(client): add ClientProfile for noise-handshake identity (#596)",
          "timestamp": "2026-04-26T00:13:57-03:00",
          "tree_id": "cde0a1b53c2682dc9b65e4aac74b86664778a479",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/897e6b5c6b1208dc9f9360371993d1b62e016263"
        },
        "date": 1777173367781,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9768,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3335239,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 391,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 235,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37857,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 1,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 405,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 97967,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 561,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 125664,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 1,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 430,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 106430,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 41,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1528,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 457811,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 48,
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
          "id": "0b785d1e318f3610b65b4f060a5edf4564ac302e",
          "message": "refactor!: preserve typed error sources across the workspace (#597)",
          "timestamp": "2026-04-26T02:38:35-03:00",
          "tree_id": "bc82e806f05d7619361d027c6e903709a64ef644",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/0b785d1e318f3610b65b4f060a5edf4564ac302e"
        },
        "date": 1777182038367,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9711,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3326121,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 385,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 237,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 38255,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 361,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 82193,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 358,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 96955,
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
            "value": 108907,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 61,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1527,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 462026,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 48,
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
          "id": "158da6d22b51f8bade54393de65aec44003bcfde",
          "message": "feat(noise): implement Noise_IK + XXfallback for WA-Web parity (#598)",
          "timestamp": "2026-04-27T11:43:20-03:00",
          "tree_id": "f8add181506200c0d123fdcaf042745fe0b085b9",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/158da6d22b51f8bade54393de65aec44003bcfde"
        },
        "date": 1777301128356,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9714,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3281816,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 396,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 235,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 38242,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 406,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 98393,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 372,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 97731,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 1,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 436,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 109029,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 69,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1532,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 461082,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 50,
            "unit": "milliseconds"
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
          "id": "b79a9c588f90c77ddd7fa6e45367b2db1a517867",
          "message": "feat(call): detect group calls via offer_notice and group-jid attrs (#599)\n\nCo-authored-by: João Lucas <jlucaso@hotmail.com>\nCo-authored-by: João Lucas <55464917+jlucaso1@users.noreply.github.com>",
          "timestamp": "2026-04-27T11:58:38-03:00",
          "tree_id": "02b51a9f45e3941d4b0f04bf1eac963ff2d4c5ae",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/b79a9c588f90c77ddd7fa6e45367b2db1a517867"
        },
        "date": 1777302032207,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9684,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3268446,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 381,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 231,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 37667,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 379,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 88621,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 361,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 96186,
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
            "value": 104762,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 12,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1530,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 465329,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 48,
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
          "id": "4b8835b50a6e70bbedc3d6a987dc27157299ab2d",
          "message": "fix(pair)!: map Android PlatformType to Chrome, drop Unknown variant (#601)",
          "timestamp": "2026-04-27T17:47:29-03:00",
          "tree_id": "5d85877d6c8453a161f4900db06f140f494c097b",
          "url": "https://github.com/oxidezap/whatsapp-rust/commit/4b8835b50a6e70bbedc3d6a987dc27157299ab2d"
        },
        "date": 1777322976009,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "integration::connect_to_ready::alloc_count",
            "value": 9715,
            "unit": "allocations"
          },
          {
            "name": "integration::connect_to_ready::alloc_bytes",
            "value": 3345492,
            "unit": "bytes"
          },
          {
            "name": "integration::connect_to_ready::wall_ms",
            "value": 394,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message::alloc_count",
            "value": 349,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message::alloc_bytes",
            "value": 62084,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_count",
            "value": 239,
            "unit": "allocations"
          },
          {
            "name": "integration::send_message_x20_amortized::alloc_bytes",
            "value": 39450,
            "unit": "bytes"
          },
          {
            "name": "integration::send_message_x20_amortized::wall_ms",
            "value": 0,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_message::alloc_count",
            "value": 370,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_message::alloc_bytes",
            "value": 97691,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_message::wall_ms",
            "value": 1,
            "unit": "milliseconds"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_count",
            "value": 430,
            "unit": "allocations"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::alloc_bytes",
            "value": 105942,
            "unit": "bytes"
          },
          {
            "name": "integration::send_and_receive_x20_amortized::wall_ms",
            "value": 27,
            "unit": "milliseconds"
          },
          {
            "name": "integration::reconnect::alloc_count",
            "value": 1321,
            "unit": "allocations"
          },
          {
            "name": "integration::reconnect::alloc_bytes",
            "value": 426335,
            "unit": "bytes"
          },
          {
            "name": "integration::reconnect::wall_ms",
            "value": 50,
            "unit": "milliseconds"
          }
        ]
      }
    ]
  }
}
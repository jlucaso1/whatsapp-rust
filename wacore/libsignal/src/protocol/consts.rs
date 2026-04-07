//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub const MAX_FORWARD_JUMPS: usize = 25_000;
pub const MAX_MESSAGE_KEYS: usize = 2000;
pub const MAX_RECEIVER_CHAINS: usize = 5;
pub const ARCHIVED_STATES_MAX_LENGTH: usize = 40;
pub const MAX_SENDER_KEY_STATES: usize = 5;

/// Threshold for amortized message key eviction.
/// Eviction only triggers when buffer exceeds MAX_MESSAGE_KEYS + PRUNE_THRESHOLD,
/// reducing O(n) drain() calls from every insert to once every PRUNE_THRESHOLD inserts.
pub const MESSAGE_KEY_PRUNE_THRESHOLD: usize = 50;

//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub(crate) fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    crate::crypto::hmac_sha256(key, input)
}

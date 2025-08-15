//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub(crate) fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hmac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 should accept any size key");
    hmac.update(input);
    hmac.finalize().into_bytes().into()
}

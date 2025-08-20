//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod address;
// Not exporting the members because they have overly-generic names.
pub mod curve;

pub use address::{
    Aci, DeviceId, Pni, ProtocolAddress, ServiceId, ServiceIdFixedWidthBinaryBytes, ServiceIdKind,
    WrongKindOfServiceIdError,
};

/// Simple wrapper that invokes a lambda.
///
/// Once try-blocks are stabilized
/// (https://github.com/rust-lang/rust/issues/31436), usages of this function
/// can be removed and replaced with the new syntax.
#[inline]
#[track_caller]
pub fn try_scoped<T, E>(f: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    f()
}

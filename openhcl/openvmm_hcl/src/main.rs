// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Root binary crate for builds of OpenVMM-HCL.

#![deny(unsafe_code)]

// Link resources.
#[cfg(target_os = "linux")]
use openvmm_hcl_resources as _;

// OpenVMM-HCL only needs libcrypto from openssl, not libssl.
#[cfg(target_os = "linux")]
openssl_crypto_only::openssl_crypto_only!();

#[cfg(all(not(test), target_os = "linux"))]
crypto::ensure_single_backend!();

#[cfg(not(target_os = "linux"))]
fn main() {
    unimplemented!("openvmm_hcl only runs on Linux");
}

#[cfg(target_os = "linux")]
// UNSAFETY: Supplies single-threaded startup guarantees to invitation capture.
#[expect(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // SAFETY: no threads have been started or inherited mesh resource adopted.
    // A mesh invitation, when present, is supplied by our trusted launcher.
    unsafe { underhill_entry::underhill_main() }?;
    Ok(())
}

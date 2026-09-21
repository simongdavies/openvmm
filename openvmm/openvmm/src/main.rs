// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Root binary crate for OpenVMM.

#![deny(unsafe_code)]

// Ensure openvmm_resources and openvmm_hypervisors get linked.
extern crate openvmm_hypervisors as _;
extern crate openvmm_resources as _;

#[cfg(not(test))]
crypto::ensure_single_backend!();

// UNSAFETY: Supplies single-threaded startup guarantees to invitation capture.
#[expect(unsafe_code)]
fn main() {
    // SAFETY: no threads have been started or inherited mesh resource adopted.
    // A mesh invitation, when present, is supplied by our trusted launcher.
    unsafe { openvmm_entry::openvmm_main() }
}

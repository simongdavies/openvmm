// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows security API wrappers.

use std::ffi::c_void;
use std::fmt::Debug;
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::windows::prelude::*;
use std::ptr::NonNull;
use std::ptr::null_mut;
use std::str::FromStr;
use widestring::U16CStr;
use widestring::U16CString;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::Authorization::SDDL_REVISION_1;
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SE_KERNEL_OBJECT,
    SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::DeriveCapabilitySidsFromName;
use windows_sys::Win32::Security::GROUP_SECURITY_INFORMATION;
use windows_sys::Win32::Security::GetSecurityDescriptorDacl;
use windows_sys::Win32::Security::GetSecurityDescriptorLength;
use windows_sys::Win32::Security::GetSecurityDescriptorOwner;
use windows_sys::Win32::Security::GetSecurityDescriptorSacl;
use windows_sys::Win32::Security::IsValidSid;
use windows_sys::Win32::Security::LABEL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::Security::SACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;
use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;

const MAX_SUBAUTHORITY_COUNT: usize = 15;

/// A Windows SID.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Sid<T: ?Sized = [u32]> {
    revision: u8,
    sub_authority_count: u8,
    identifier_authority: [u8; 6],
    sub_authorities: T,
}

/// A SID that can contain the maximum number of subauthorities.
///
/// Parsing accepts canonical `S-...` strings, not SDDL abbreviations.
pub type MaximumSid = Sid<[u32; MAX_SUBAUTHORITY_COUNT]>;

impl<const N: usize> Sid<[u32; N]> {
    /// Creates a new SID.
    pub fn new(identifier_authority: [u8; 6], sub_authorities: [u32; N]) -> Self {
        assert!(N <= MAX_SUBAUTHORITY_COUNT);
        Self {
            revision: 1,
            sub_authority_count: N as u8,
            identifier_authority,
            sub_authorities,
        }
    }
}

impl<T: ?Sized> Debug for Sid<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(&self.to_string_sid())
    }
}

impl<T: ?Sized> Sid<T> {
    /// Returns a `PSID` pointer for use with Win32 APIs.
    pub fn as_ptr(&self) -> PSID {
        std::ptr::from_ref(self) as PSID
    }

    /// Constructs the string representation of a SID.
    pub fn to_string_sid(&self) -> String {
        // SAFETY: calling Win32 APIs according to doc.
        unsafe {
            let mut s16 = null_mut();
            if ConvertSidToStringSidW(self.as_ptr(), &mut s16) == 0 {
                panic!(
                    "ConvertSidToStringSidW failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let s = U16CStr::from_ptr_str(s16).to_string().unwrap();
            LocalFree(s16.cast());
            s
        }
    }
}

impl AsRef<Sid> for Sid {
    fn as_ref(&self) -> &Sid {
        self
    }
}

impl<const N: usize> AsRef<Sid> for Sid<[u32; N]> {
    fn as_ref(&self) -> &Sid {
        self
    }
}

impl From<&Sid> for MaximumSid {
    fn from(sid: &Sid) -> Self {
        let n = sid.sub_authority_count;
        assert!(n <= 15);
        let mut this = Self {
            revision: 1,
            sub_authority_count: n,
            identifier_authority: sid.identifier_authority,
            sub_authorities: [0; 15],
        };
        this.sub_authorities[..n.into()].copy_from_slice(&sid.sub_authorities[..n.into()]);
        this
    }
}

impl FromStr for MaximumSid {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sid: LocalSid = s.parse()?;
        Ok(Self::from(sid.as_ref()))
    }
}

/// A SID that has been allocated with LocalAlloc.
///
/// Parsing accepts canonical `S-...` strings, not SDDL abbreviations.
///
// This is mostly useful for interacting with Win32 APIs that allocate SIDs.
#[repr(transparent)]
pub struct LocalSid(NonNull<Sid>);

impl Debug for LocalSid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self.as_ref(), f)
    }
}

impl LocalSid {
    pub fn from_capability_name(name: &str) -> std::io::Result<Self> {
        // SAFETY: calling Win32 APIs according to doc.
        unsafe {
            let mut group_count = 0;
            let mut count = 0;
            let mut group_sid_array = null_mut();
            let mut sid_array = null_mut();
            if DeriveCapabilitySidsFromName(
                U16CString::from_str(name).unwrap().as_ptr(),
                &mut group_sid_array,
                &mut group_count,
                &mut sid_array,
                &mut count,
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }

            // Free all the group SIDs (unused).
            let group_sids = std::slice::from_raw_parts_mut(group_sid_array, group_count as usize);
            for sid in group_sids {
                LocalFree(*sid);
            }
            LocalFree(group_sid_array.cast());

            // Take just the first SID (there should really never be more than one).
            let sids = std::slice::from_raw_parts_mut(sid_array, count as usize);
            let cap_sid = Self::from_raw_sid(sids[0]);
            for sid in &sids[1..] {
                LocalFree(*sid);
            }
            LocalFree(sid_array.cast());
            Ok(cap_sid)
        }
    }

    /// Takes ownership of a `PSID` pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `sid` has been allocated with `LocalAlloc`
    /// and is exclusively owned.
    pub unsafe fn from_raw_sid(sid: PSID) -> Self {
        unsafe {
            let auth_count = (*(sid as *const Sid<[u32; 0]>)).sub_authority_count;
            let slice = std::slice::from_raw_parts_mut(sid, auth_count.into());
            std::mem::transmute(slice)
        }
    }
}

impl FromStr for LocalSid {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('\0') {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "SID strings must not contain null characters",
            ));
        }
        let text =
            U16CString::from_str(s).map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;
        // SAFETY: The API validates the input and allocates the SID with
        // LocalAlloc. Ownership transfers to LocalSid only on success.
        unsafe {
            let mut sid = null_mut();
            if ConvertStringSidToSidW(text.as_ptr(), &mut sid) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            if IsValidSid(sid) == 0 {
                LocalFree(sid.cast());
                return Err(std::io::Error::new(ErrorKind::InvalidInput, "invalid SID"));
            }
            let sid = Self::from_raw_sid(sid);
            // The Windows parser accepts overflowing numeric components.
            // Require an exact round trip rather than silently changing identity.
            if sid.to_string_sid() != s {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "SID string is not canonical",
                ));
            }
            Ok(sid)
        }
    }
}

impl AsRef<Sid> for LocalSid {
    fn as_ref(&self) -> &Sid {
        self
    }
}

impl Deref for LocalSid {
    type Target = Sid;

    fn deref(&self) -> &Self::Target {
        // SAFETY: the pointer is guaranteed to be valid.
        unsafe { &*self.0.as_ptr() }
    }
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        // SAFETY: the pointer is guaranteed to be valid.
        unsafe {
            LocalFree(self.as_ptr());
        }
    }
}

/// A Windows security descriptor allocated with `LocalAlloc`.
///
/// Guaranteed to be in self-relative form.
#[derive(Clone)]
pub struct LocalSecurityDescriptor(NonNull<c_void>, usize);

impl Debug for LocalSecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self.deref(), f)
    }
}

impl Deref for LocalSecurityDescriptor {
    type Target = SecurityDescriptor;

    fn deref(&self) -> &Self::Target {
        // SAFETY: the pointer and length are guaranteed to be valid for the
        // lifetime of self.
        unsafe {
            std::mem::transmute(std::slice::from_raw_parts(
                self.0.as_ptr() as *const u8,
                self.1,
            ))
        }
    }
}

impl FromStr for LocalSecurityDescriptor {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // SAFETY: calling Win32 API according to doc and taking ownership of
        // the allocated buffer.
        unsafe {
            let mut ptr = null_mut();
            let mut len = 0;
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                U16CString::from_str(s)
                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?
                    .as_ptr(),
                SDDL_REVISION_1,
                &mut ptr,
                &mut len,
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self(NonNull::new(ptr).unwrap(), len as usize))
        }
    }
}

impl LocalSecurityDescriptor {
    /// Reads the owner, group, DACL and mandatory label of a kernel object.
    pub fn from_kernel_object(handle: BorrowedHandle<'_>) -> std::io::Result<Self> {
        // SAFETY: The API returns a self-relative LocalAlloc descriptor.
        unsafe {
            let mut descriptor = null_mut();
            let status = GetSecurityInfo(
                handle.as_raw_handle(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | LABEL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            );
            if status != 0 {
                return Err(std::io::Error::from_raw_os_error(status as i32));
            }
            let pointer = NonNull::new(descriptor).ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidData, "missing security descriptor")
            })?;
            Ok(Self(
                pointer,
                GetSecurityDescriptorLength(descriptor) as usize,
            ))
        }
    }
}

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer is guaranteed to be valid and owned.
        unsafe {
            LocalFree(self.0.as_ptr().cast());
        }
    }
}

/// A security descriptor buffer.
///
/// Guaranteed to be in self-relative form.
#[repr(transparent)]
pub struct SecurityDescriptor([u8]);

impl Debug for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(sddl) = self.to_sddl() {
            f.pad(&sddl)
        } else {
            write!(f, "{:?}", &self.0)
        }
    }
}

impl SecurityDescriptor {
    /// Converts the security descriptor to SDDL string format.
    pub fn to_sddl(&self) -> std::io::Result<String> {
        // SAFETY: calling Win32 API according to doc.
        unsafe {
            let mut s16 = null_mut();
            if ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.as_ptr(),
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | SACL_SECURITY_INFORMATION
                    | LABEL_SECURITY_INFORMATION,
                &mut s16,
                null_mut(),
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let s = U16CStr::from_ptr_str(s16).to_string().unwrap();
            LocalFree(s16.cast::<c_void>());
            Ok(s)
        }
    }

    /// Returns a `PSECURITY_DESCRIPTOR` pointer for use with Win32 APIs.
    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0.as_ptr() as _
    }
}

/// Returns an owned copy of the current process token's user SID.
pub fn current_process_user_sid() -> std::io::Result<MaximumSid> {
    use windows_sys::Win32::Security::GetTokenInformation;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::Security::TOKEN_USER;
    use windows_sys::Win32::Security::TokenUser;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    // SAFETY: The token and aligned buffer remain owned through all queries.
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let token = OwnedHandle::from_raw_handle(token);
        let mut buffer = [0usize; 32];
        let mut returned = 0;
        if GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size_of_val(&buffer) as u32,
            &mut returned,
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut text = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let sid = U16CStr::from_ptr_str(text)
            .to_string()
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
            .and_then(|text| text.parse());
        LocalFree(text.cast());
        sid
    }
}

/// Adds an exact-SID grant and a low-integrity, no-write-up label to a kernel
/// object, preserving existing DACL entries and non-label SACL information.
///
/// The caller must own the object and serialize security updates to its handle.
/// A null DACL is rejected rather than silently converting unrestricted access.
/// Returns an owned copy of the object's owner SID.
pub fn grant_low_integrity_kernel_object_access(
    handle: BorrowedHandle<'_>,
    sid: &Sid,
    access: u32,
) -> std::io::Result<MaximumSid> {
    let descriptor = LocalSecurityDescriptor::from_kernel_object(handle)?;
    let label: LocalSecurityDescriptor = "S:(ML;;NW;;;LW)".parse()?;
    // SAFETY: Descriptor and SID buffers remain live throughout the calls.
    unsafe {
        let mut owner = null_mut();
        let mut defaulted = 0;
        if GetSecurityDescriptorOwner(descriptor.as_ptr(), &mut owner, &mut defaulted) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if owner.is_null() || IsValidSid(owner) == 0 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "missing owner SID",
            ));
        }
        let mut owner_text = null_mut();
        if ConvertSidToStringSidW(owner, &mut owner_text) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let owner = U16CStr::from_ptr_str(owner_text)
            .to_string()
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
            .and_then(|text| text.parse());
        LocalFree(owner_text.cast());
        let owner = owner?;

        let mut present = 0;
        let mut dacl = null_mut();
        if GetSecurityDescriptorDacl(descriptor.as_ptr(), &mut present, &mut dacl, &mut defaulted)
            == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if present == 0 || dacl.is_null() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "kernel object has a null DACL",
            ));
        }
        let mut sacl = null_mut();
        if GetSecurityDescriptorSacl(label.as_ptr(), &mut present, &mut sacl, &mut defaulted) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: access,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: sid.as_ptr().cast(),
            },
        };
        let mut updated = null_mut();
        let status = SetEntriesInAclW(1, &entry, dacl, &mut updated);
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        let status = SetSecurityInfo(
            handle.as_raw_handle(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            updated,
            sacl,
        );
        LocalFree(updated.cast());
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        Ok(owner)
    }
}

#[link(
    name = "api-ms-win-security-base-private-l1-1-1.dll",
    kind = "raw-dylib",
    modifiers = "+verbatim"
)]
unsafe extern "C" {
    fn CreateAppContainerToken(
        token: HANDLE,
        caps: *mut SECURITY_CAPABILITIES,
        new_token: *mut HANDLE,
    ) -> windows_sys::core::BOOL;
}

#[repr(transparent)]
struct SidAndAttributes<'a>(SID_AND_ATTRIBUTES, PhantomData<&'a Sid>);

impl<'a> SidAndAttributes<'a> {
    pub fn new(sid: &'a Sid, attributes: u32) -> Self {
        Self(
            SID_AND_ATTRIBUTES {
                Sid: sid.as_ptr(),
                Attributes: attributes,
            },
            PhantomData,
        )
    }
}

/// Creates an app container token for `sid` with `capabilities`.
pub fn create_app_container_token<'a, I, T>(
    sid: &Sid,
    capabilities: I,
) -> std::io::Result<OwnedHandle>
where
    I: IntoIterator<Item = &'a T>,
    T: 'a + AsRef<Sid>,
{
    let mut caps_and_attrs: Vec<_> = capabilities
        .into_iter()
        .map(|c| SidAndAttributes::new(c.as_ref(), SE_GROUP_ENABLED as u32))
        .collect();
    let mut caps = SECURITY_CAPABILITIES {
        AppContainerSid: sid.as_ptr(),
        Capabilities: caps_and_attrs.as_mut_ptr().cast(),
        CapabilityCount: caps_and_attrs
            .len()
            .try_into()
            .expect("too many capabilities"),
        Reserved: 0,
    };
    // SAFETY: calling Win32 API according to doc and taking ownership of the
    // handle.
    unsafe {
        let mut new_token = null_mut();
        if CreateAppContainerToken(null_mut(), &mut caps, &mut new_token) == 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(OwnedHandle::from_raw_handle(new_token))
    }
}

#[cfg(test)]
mod tests {
    use super::LocalSecurityDescriptor;
    use super::LocalSid;
    use super::MaximumSid;
    use super::SecurityDescriptor;
    use super::Sid;
    use super::grant_low_integrity_kernel_object_access;
    use std::os::windows::prelude::*;
    use test_with_tracing::test;

    #[test]
    fn parse_owned_sid() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MaximumSid>();
        let text = "S-1-15-2-1-2-3-4-5-6-7";
        let local: LocalSid = text.parse().unwrap();
        let owned: MaximumSid = text.parse().unwrap();
        assert_eq!(local.to_string_sid(), text);
        assert_eq!(owned.to_string_sid(), text);
    }

    #[test]
    fn reject_invalid_sid_strings() {
        for text in [
            "",
            "not a SID",
            "S-1-15-2-1\0",
            "S-1-15-4294967296",
            "S-2-15-1",
            "S-1-15-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
        ] {
            assert!(text.parse::<LocalSid>().is_err(), "{text:?}");
            assert!(text.parse::<MaximumSid>().is_err(), "{text:?}");
        }
    }

    fn restricted_access(descriptor: &SecurityDescriptor, sid: &Sid, access: u32) -> bool {
        use windows_sys::Win32::Security::*;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        use windows_sys::Win32::System::Threading::OpenProcessToken;

        // SAFETY: Tokens are derived from this process and all buffers remain
        // owned for the calls. No impersonation or process creation is performed.
        unsafe {
            let mut token = std::ptr::null_mut();
            assert_ne!(
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut token
                ),
                0
            );
            let token = OwnedHandle::from_raw_handle(token);
            let restriction = SID_AND_ATTRIBUTES {
                Sid: sid.as_ptr(),
                Attributes: 0,
            };
            let mut restricted = std::ptr::null_mut();
            assert_ne!(
                CreateRestrictedToken(
                    token.as_raw_handle(),
                    DISABLE_MAX_PRIVILEGE,
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    1,
                    &restriction,
                    &mut restricted,
                ),
                0,
                "{}",
                std::io::Error::last_os_error()
            );
            let restricted = OwnedHandle::from_raw_handle(restricted);
            let mut impersonation = std::ptr::null_mut();
            assert_ne!(
                DuplicateToken(
                    restricted.as_raw_handle(),
                    SecurityImpersonation,
                    &mut impersonation
                ),
                0
            );
            let impersonation = OwnedHandle::from_raw_handle(impersonation);
            let mapping = GENERIC_MAPPING {
                GenericRead: 1,
                GenericWrite: 12,
                GenericExecute: 2,
                GenericAll: 0xf000f,
            };
            let mut privileges = [0u64; 32];
            let mut privileges_size = size_of_val(&privileges) as u32;
            let mut granted = 0;
            let mut allowed = 0;
            assert_ne!(
                AccessCheck(
                    descriptor.as_ptr(),
                    impersonation.as_raw_handle(),
                    access,
                    &mapping,
                    privileges.as_mut_ptr().cast(),
                    &mut privileges_size,
                    &mut granted,
                    &mut allowed,
                ),
                0,
                "{}",
                std::io::Error::last_os_error()
            );
            allowed != 0
        }
    }

    #[test]
    fn kernel_object_grants_preserve_siblings_and_deny_other_sid() {
        let directory = crate::windows::create_object_directory(
            &crate::windows::ObjectAttributes::new(),
            0xf000f,
        )
        .unwrap();
        // CreateRestrictedToken rejects package SIDs. These normal restricting
        // SIDs exercise this generic ACL helper, not AppContainer isolation.
        let first: MaximumSid = "S-1-5-21-12345-23456-34567-1001".parse().unwrap();
        let second: MaximumSid = "S-1-5-21-12345-23456-34567-1002".parse().unwrap();
        let other: MaximumSid = "S-1-5-21-12345-23456-34567-1003".parse().unwrap();
        grant_low_integrity_kernel_object_access(directory.as_handle(), first.as_ref(), 6).unwrap();
        grant_low_integrity_kernel_object_access(directory.as_handle(), second.as_ref(), 6)
            .unwrap();
        let descriptor =
            LocalSecurityDescriptor::from_kernel_object(directory.as_handle()).unwrap();
        assert!(restricted_access(&descriptor, first.as_ref(), 6));
        assert!(restricted_access(&descriptor, second.as_ref(), 6));
        assert!(!restricted_access(&descriptor, other.as_ref(), 6));
        assert!(!restricted_access(&descriptor, first.as_ref(), 8));
    }
}

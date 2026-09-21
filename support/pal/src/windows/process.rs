// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::BorrowedHandleExt;
use super::Process;
use super::job::Job;
use super::security::MaximumSid;
use super::security::Sid;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
use std::mem::zeroed;
use std::os::windows::prelude::*;
use std::ptr::null;
use std::ptr::null_mut;
use widestring::U16CString;
use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
use windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT;
use windows_sys::Win32::Foundation::SetHandleInformation;
use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
use windows_sys::Win32::System::Console::GetStdHandle;
use windows_sys::Win32::System::Console::STD_ERROR_HANDLE;
use windows_sys::Win32::System::Console::STD_INPUT_HANDLE;
use windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE;
use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
use windows_sys::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT;
use windows_sys::Win32::System::Threading::CreateProcessAsUserW;
use windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList;
use windows_sys::Win32::System::Threading::EXTENDED_STARTUPINFO_PRESENT;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::InitializeProcThreadAttributeList;
use windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST;
use windows_sys::Win32::System::Threading::STARTF_USESTDHANDLES;
use windows_sys::Win32::System::Threading::STARTUPINFOEXW;
use windows_sys::Win32::System::Threading::STARTUPINFOW;
use windows_sys::Win32::System::Threading::TerminateProcess;
use windows_sys::Win32::System::Threading::UpdateProcThreadAttribute;

const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: u32 = 0x00020002;
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: u32 = 0x000020007;
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: u32 = 0x00020009;
const PROC_THREAD_ATTRIBUTE_JOB_LIST: u32 = 0x0002000d;
const PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY: u32 = 0x00002000e;
const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: u32 = 0x00002000f;

const PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: u32 = 0x01;

const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 1;

const PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE: u64 = 0x01;
const PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE: u64 = 0x02;
const PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE: u64 = 0x04;

struct MitigationPolicyType {
    index: usize,
    mask: u64,
    shift: u8,
}

const PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 8,
    };

const PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 12,
    };

const PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 16,
    };

const PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 20,
    };

const PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 24,
    };

const PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 28,
    };

const PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 32,
    };

const PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 36,
    };

const PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 40,
    };

const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 44,
    };

const PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 48,
    };

const PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 52,
    };

const PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 56,
    };

const PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32: MitigationPolicyType =
    MitigationPolicyType {
        index: 0,
        mask: 0x00000003,
        shift: 60,
    };

const PROCESS_CREATION_MITIGATION_POLICY2_LOADER_INTEGRITY_CONTINUITY: MitigationPolicyType =
    MitigationPolicyType {
        index: 1,
        mask: 0x00000003,
        shift: 4,
    };

const PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD: MitigationPolicyType =
    MitigationPolicyType {
        index: 1,
        mask: 0x00000003,
        shift: 8,
    };

const PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION: MitigationPolicyType =
    MitigationPolicyType {
        index: 1,
        mask: 0x00000003,
        shift: 12,
    };

const PROCESS_CREATION_MITIGATION_POLICY2_RESTRICT_INDIRECT_BRANCH_PREDICTION:
    MitigationPolicyType = MitigationPolicyType {
    index: 1,
    mask: 0x00000003,
    shift: 16,
};

const PROCESS_CREATION_MITIGATION_POLICY2_ALLOW_DOWNGRADE_DYNAMIC_CODE_POLICY:
    MitigationPolicyType = MitigationPolicyType {
    index: 1,
    mask: 0x00000003,
    shift: 20,
};

const PROCESS_CREATION_MITIGATION_POLICY2_SPECULATIVE_STORE_BYPASS_DISABLE: MitigationPolicyType =
    MitigationPolicyType {
        index: 1,
        mask: 0x00000003,
        shift: 24,
    };

const PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS: MitigationPolicyType =
    MitigationPolicyType {
        index: 1,
        mask: 0x00000003,
        shift: 28,
    };

const PROCESS_CREATION_MITIGATION_POLICY2_USER_CET_SET_CONTEXT_IP_VALIDATION: MitigationPolicyType =
    MitigationPolicyType {
        index: 1,
        mask: 0x00000003,
        shift: 32,
    };

const PROCESS_CREATION_MITIGATION_POLICY2_BLOCK_NON_CET_BINARIES: MitigationPolicyType =
    MitigationPolicyType {
        index: 1,
        mask: 0x00000003,
        shift: 36,
    };

const PROCESS_CREATION_MITIGATION_POLICY2_XTENDED_CONTROL_FLOW_GUARD: MitigationPolicyType =
    MitigationPolicyType {
        index: 1,
        mask: 0x00000003,
        shift: 40,
    };

const PROCESS_CREATION_MITIGATION_POLICY2_CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY: MitigationPolicyType =
    MitigationPolicyType {
        index: 1,
        mask: 0x00000003,
        shift: 48,
    };

/// A process-creation mitigation policy.
///
/// Specifies the mitigation policies to apply to a new process.
#[derive(Debug, Copy, Clone, Default)]
#[must_use]
pub struct MitigationPolicy([u64; 2]);

impl MitigationPolicy {
    /// Initializes an empty policy.
    pub const fn new() -> Self {
        Self([0, 0])
    }

    const fn set(mut self, ty: &MitigationPolicyType, action: u64) -> Self {
        self.0[ty.index] &= !(ty.mask << ty.shift);
        self.0[ty.index] |= action << ty.shift;
        self
    }

    /// Enables DEP.
    pub const fn dep(mut self, enable: bool) -> Self {
        if enable {
            self.0[0] |= PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE;
        } else {
            self.0[0] &= !PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE;
        }
        self
    }

    /// Enables NX ATL thunks.
    pub const fn dep_atl_thunk(mut self, enable: bool) -> Self {
        if enable {
            self.0[0] |= PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE;
        } else {
            self.0[0] &= !PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE;
        }
        self
    }

    /// Enables SEH override protection.
    pub const fn sehop(mut self, enable: bool) -> Self {
        if enable {
            self.0[0] |= PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE;
        } else {
            self.0[0] &= !PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE;
        }
        self
    }

    /// Define mandatory ASLR options.  Mandatory ASLR forcibly rebases images
    /// that are not dynamic base compatible by acting as though there were an
    /// image base collision at load time.
    ///
    /// The alternate policy is 'require relocations' mode, which refuses load
    /// of images that do not have a base relocation section.
    pub const fn force_relocate_images(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES,
            action as u64,
        )
    }

    //
    /// Define heap terminate on corruption options.
    ///
    /// Note that 'always off' does
    /// not override the default opt-in for binaries with current subsystem versions
    /// set in the image header.
    ///
    /// Heap terminate on corruption is user mode enforced.
    pub const fn heap_terminate(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE,
            action as u64,
        )
    }

    /// Define bottom up randomization (includes stack randomization) options,
    /// i.e. randomization of the lowest user address.
    pub const fn bottom_up_aslr(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR,
            action as u64,
        )
    }

    /// Define high entropy bottom up randomization.
    ///
    /// Note that high entropy bottom up randomization is effective if and only if
    /// bottom up ASLR is also enabled.
    ///
    /// N.B.  High entropy mode is only meaningful for native 64-bit processes.  in
    ///       high entropy mode, up to 1TB of bottom up variance is enabled.
    pub const fn high_entropy_aslr(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR,
            action as u64,
        )
    }

    /// Define handle checking enforcement options.  Handle checking enforcement
    /// causes an exception to be raised immediately on a bad handle reference,
    /// versus simply returning a failure status from the handle reference.
    pub const fn strict_handle_checks(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS,
            action as u64,
        )
    }

    /// Define win32k system call disable options.  Win32k system call disable
    /// prevents a process from making Win32k calls.
    pub const fn win32k_system_call_disable(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE,
            action as u64,
        )
    }

    /// Define the extension point disable options.  Extension point disable allows
    /// a process to opt-out of loading various arbitrary extension point DLLs.
    pub const fn extension_point_disable(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE,
            action as u64,
        )
    }

    /// Define dynamic code options.
    ///
    /// The alternate policy allows opt out by a broker process.
    pub const fn prohibit_dynamic_code(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE,
            action as u64,
        )
    }

    /// Define Control Flow Guard (CFG) mitigation policy options.  Control Flow
    /// Guard allows indirect control transfers to be checked at runtime.
    ///
    /// The alternate policy is "export suppression".
    pub const fn control_flow_guard(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD,
            action as u64,
        )
    }

    /// Define module signature options.  When enabled, this option will
    /// block mapping of non-microsoft binaries.
    ///
    /// The alternate policy is "allow store".
    pub const fn block_non_microsoft_binaries(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES,
            action as u64,
        )
    }

    /// Define Font Disable Policy.  When enabled, this option will
    /// block loading Non System Fonts.
    ///
    /// The alternate policy is "audit nonsystem fonts".
    pub const fn font_disable(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE,
            action as u64,
        )
    }

    /// Define remote image load options.  When enabled, this option will
    /// block mapping of images from remote devices.
    pub const fn image_load_no_remote(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE,
            action as u64,
        )
    }

    /// Define low IL image load options.  When enabled, this option will
    /// block mapping of images that have the low mandatory label.
    pub const fn image_load_no_low_label(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL,
            action as u64,
        )
    }

    /// Define image load options to prefer System32 images compared to
    /// the same images in application directory. When enabled, this option
    /// will prefer loading images from system32 folder.
    pub const fn image_load_prefer_system32(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32,
            action as u64,
        )
    }

    /// Define Loader Integrity Continuity mitigation policy options.  This mitigation
    /// enforces OS signing levels for dependent module loads.
    ///
    /// The alternate policy is "audit".
    pub const fn loader_integrity_continuity(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY2_LOADER_INTEGRITY_CONTINUITY,
            action as u64,
        )
    }

    /// Define the strict Control Flow Guard (CFG) mitigation policy options. This mitigation
    /// requires all images that load in the process to be instrumented by CFG.
    pub const fn strict_control_flow_guard(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD,
            action as u64,
        )
    }

    /// Define the module tampering mitigation policy options.
    ///
    /// The alternate policy is "noinherit".
    pub const fn module_tampering_protection(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION,
            action as u64,
        )
    }

    /// Define the restricted indirect branch prediction mitigation policy options.
    pub const fn restrict_indirect_branch_prediction(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY2_RESTRICT_INDIRECT_BRANCH_PREDICTION,
            action as u64,
        )
    }

    /// Define the policy option that allows a broker to downgrade the dynamic code policy for a process.
    pub const fn allow_downgrade_dynamic_code_policy(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY2_ALLOW_DOWNGRADE_DYNAMIC_CODE_POLICY,
            action as u64,
        )
    }

    /// Define the Memory Disambiguation Disable mitigation policy options.
    pub const fn speculative_store_bypass_disable(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY2_SPECULATIVE_STORE_BYPASS_DISABLE,
            action as u64,
        )
    }

    /// Define the user-mode shadow stack mitigation policy options.
    ///
    /// The alternate policy is "strict mode".
    pub const fn cet_user_shadow_stacks(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS,
            action as u64,
        )
    }

    /// Define the user-mode CET set context instruction pointer validation mitigation policy options.
    ///
    /// The alternate policy is "relaxed mode".
    pub const fn user_cet_set_context_ip_validation(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY2_USER_CET_SET_CONTEXT_IP_VALIDATION,
            action as u64,
        )
    }

    /// Define the block non-CET/non-EHCONT binaries mitigation policy options.
    ///
    /// The alternate policy is "non-ehcont".
    pub const fn block_non_cet_binaries(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY2_BLOCK_NON_CET_BINARIES,
            action as u64,
        )
    }

    /// Define the XFG mitigation policy options.
    pub const fn xtended_control_flow_guard(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY2_XTENDED_CONTROL_FLOW_GUARD,
            action as u64,
        )
    }

    /// Define the CET-related dynamic code validation data APIs out-of-proc mitigation policy options.
    pub const fn cet_dynamic_apis_out_of_proc_only(self, action: MitigationPolicyAction) -> Self {
        self.set(
            &PROCESS_CREATION_MITIGATION_POLICY2_CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY,
            action as u64,
        )
    }
}

/// The configuration action to take for an individual policy.
#[derive(Debug, Copy, Clone)]
#[repr(u64)]
pub enum MitigationPolicyAction {
    /// Defer to the default policy.
    Defer = 0,
    /// Enable the mitigation.
    AlwaysOn = 1,
    /// Disable the mitigation.
    AlwaysOff = 2,
    /// Use the mitigation-specific alternate policy.
    Alternate = 3,
}

#[derive(Debug, Copy, Clone)]
/// The child process creation policy.
pub enum ChildProcessPolicy {
    /// Allow the process to create child processes.
    Allow,
    /// Disallow the process from creating child processes.
    Disallow,
}

#[derive(Debug)]
pub enum Stdio<'a> {
    Inherit,
    Null,
    Handle(BorrowedHandle<'a>),
}

enum HandleOrRef {
    Handle(OwnedHandle),
    Ref(RawHandle),
}

impl AsRawHandle for HandleOrRef {
    fn as_raw_handle(&self) -> RawHandle {
        match self {
            HandleOrRef::Handle(h) => h.as_raw_handle(),
            HandleOrRef::Ref(h) => *h,
        }
    }
}

impl Stdio<'_> {
    fn eval(self, index: u32) -> io::Result<HandleOrRef> {
        match self {
            Stdio::Inherit => unsafe { Ok(HandleOrRef::Ref(GetStdHandle(index))) },
            Stdio::Null => {
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("nul")?;
                let handle = OwnedHandle::from(f);
                // Make the handle inheritable since this is for use with the
                // child process.
                unsafe {
                    if SetHandleInformation(
                        handle.as_raw_handle(),
                        HANDLE_FLAG_INHERIT,
                        HANDLE_FLAG_INHERIT,
                    ) == 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(HandleOrRef::Handle(handle))
            }
            Stdio::Handle(h) => {
                // Duplicate the handle to make it inheritable.
                Ok(HandleOrRef::Handle(h.as_handle().duplicate(true, None)?))
            }
        }
    }
}

#[derive(Debug)]
enum JobHandle<'a> {
    Borrowed(BorrowedHandle<'a>),
    Owned(OwnedHandle),
}

impl AsHandle for JobHandle<'_> {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        match self {
            Self::Borrowed(handle) => handle.as_handle(),
            Self::Owned(handle) => handle.as_handle(),
        }
    }
}

#[derive(Debug)]
pub struct Builder<'a> {
    creation_flags: u32,
    command_line: Vec<u16>,
    application_name: Option<Vec<u16>>,
    current_directory: Option<Vec<u16>>,
    handles: Vec<BorrowedHandle<'a>>,
    jobs: Vec<JobHandle<'a>>,
    stdin: Stdio<'a>,
    stdout: Stdio<'a>,
    stderr: Stdio<'a>,
    env: BTreeMap<OsString, Option<OsString>>,
    clear_env: bool,
    token: Option<BorrowedHandle<'a>>,
    app_container: Option<MaximumSid>,
    disable_all_application_packages: bool,
    mitigation_policy: Option<MitigationPolicy>,
    child_process_policy: ChildProcessPolicy,
}

fn wstr(s: &OsStr) -> Vec<u16> {
    s.encode_wide().collect()
}

/// Null terminates a wide string, ensuring that there are no internal null characters.
fn null_terminate(v: Vec<u16>) -> Result<U16CString, io::Error> {
    U16CString::from_vec(v)
        .map_err(|_| io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32))
}

fn ensure_no_null(v: &OsStr) -> Result<(), io::Error> {
    if v.encode_wide().all(|x| x != 0) {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32))
    }
}

fn ptr_or_null<T, U>(v: &Option<U>) -> *const T
where
    U: AsRef<[T]>,
{
    v.as_ref().map(|v| v.as_ref().as_ptr()).unwrap_or(null())
}

struct AttrList(Vec<u8>);

impl AttrList {
    fn new(n: u32) -> Self {
        unsafe {
            let mut size = 0;
            InitializeProcThreadAttributeList(null_mut(), n, 0, &mut size);
            let mut v = vec![0; size];
            assert!(InitializeProcThreadAttributeList(v.as_mut_ptr().cast(), n, 0, &mut size) != 0);
            Self(v)
        }
    }

    fn as_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.0.as_mut_ptr().cast()
    }

    fn update<'a, T: ?Sized>(&'a mut self, flags: u32, attr: u32, value: &'a T) -> io::Result<()> {
        unsafe {
            if UpdateProcThreadAttribute(
                self.as_ptr(),
                flags,
                attr as usize,
                std::ptr::from_ref(value) as *mut _,
                size_of_val(value),
                null_mut(),
                null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

impl Drop for AttrList {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) }
    }
}

impl<'a> Builder<'a> {
    pub fn from_args<I, S>(application_name: impl AsRef<OsStr>, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command_line = application_name.as_ref().to_owned();
        for arg in args {
            command_line.push(" ");
            command_line.push(arg.as_ref()); // TODO: quote
        }
        let mut builder = Self::new(&command_line);
        builder.application_name(application_name);
        builder
    }

    pub fn new(command_line: impl AsRef<OsStr>) -> Self {
        Self {
            creation_flags: 0,
            command_line: wstr(command_line.as_ref()),
            application_name: None,
            current_directory: None,
            handles: Vec::new(),
            jobs: Vec::new(),
            stdin: Stdio::Inherit,
            stdout: Stdio::Inherit,
            stderr: Stdio::Inherit,
            env: BTreeMap::new(),
            clear_env: false,
            token: None,
            app_container: None,
            disable_all_application_packages: false,
            mitigation_policy: None,
            child_process_policy: ChildProcessPolicy::Allow,
        }
    }

    pub fn application_name(&mut self, path: impl AsRef<OsStr>) -> &mut Self {
        self.application_name = Some(wstr(path.as_ref()));
        self
    }

    /// Sets an owned working directory for the child instead of inheriting it.
    ///
    /// Sandboxed callers should select a trusted, accessible directory rather
    /// than exposing the parent's working directory to the child.
    pub fn current_directory(&mut self, path: impl AsRef<OsStr>) -> &mut Self {
        self.current_directory = Some(wstr(path.as_ref()));
        self
    }

    pub fn handle(&mut self, handle: &'a impl AsHandle) -> &mut Self {
        self.handles.push(handle.as_handle());
        self
    }

    pub fn stdin(&mut self, stdin: Stdio<'a>) -> &mut Self {
        self.stdin = stdin;
        self
    }

    pub fn stdout(&mut self, stdout: Stdio<'a>) -> &mut Self {
        self.stdout = stdout;
        self
    }

    pub fn stderr(&mut self, stderr: Stdio<'a>) -> &mut Self {
        self.stderr = stderr;
        self
    }

    /// Adds all (key, val) pairs from `additional_env` to the environment.
    pub fn extend_env<I>(&mut self, additional_env: I) -> &mut Self
    where
        I: IntoIterator,
        I::Item: Into<(OsString, OsString)>,
    {
        self.env.extend(additional_env.into_iter().map(|i| {
            let i = i.into();
            (i.0, Some(i.1))
        }));
        self
    }

    /// Sets the environment variable `key` to `val`.
    pub fn env<K, V>(&mut self, key: K, val: V) -> &mut Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.env
            .insert(key.as_ref().to_owned(), Some(val.as_ref().to_owned()));
        self
    }

    /// Removes the environment variable `key`.
    pub fn env_remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Self {
        self.env.insert(key.as_ref().to_owned(), None);
        self
    }

    /// Clears all environment variables.
    pub fn env_clear(&mut self) -> &mut Self {
        self.env.clear();
        self.clear_env = true;
        self
    }

    /// Sets whether the child inherits the parent's environment (default: true).
    ///
    /// Unlike [`Self::env_clear`], this preserves explicit `env` and `env_remove`
    /// entries. When inheritance is disabled, only explicit entries populate
    /// the child's environment.
    pub fn inherit_env(&mut self, inherit: bool) -> &mut Self {
        self.clear_env = !inherit;
        self
    }

    /// Set the token to launch the process with.
    pub fn token(&mut self, token: BorrowedHandle<'a>) -> &mut Self {
        self.token = Some(token);
        self
    }

    /// Add a job to the initial job list.
    pub fn job(&mut self, job: BorrowedHandle<'a>) -> &mut Self {
        self.jobs.push(JobHandle::Borrowed(job));
        self
    }

    /// Adds an owned job handle to the initial job list.
    ///
    /// Like [`Self::job`], this attaches the process during creation, before
    /// any child code can run. Jobs retain the order in which they were added.
    /// The builder retains this handle until creation completes. Keep another
    /// handle alive if the job is configured to terminate on its last close.
    pub fn owned_job(&mut self, job: OwnedHandle) -> &mut Self {
        self.jobs.push(JobHandle::Owned(job));
        self
    }

    /// Creates the process in the specified AppContainer, with no capabilities.
    ///
    /// Copies the SID so the caller need not keep it alive until [`Self::spawn`].
    /// This uses the supported process security-capabilities attribute; it does
    /// not create a profile or grant the container access to any objects.
    /// The caller must supply a unique AppContainer SID and provision access to
    /// the executable and any required resources separately. The corresponding
    /// AppContainer profile must already have been provisioned by the caller.
    pub fn app_container(&mut self, sid: &Sid) -> &mut Self {
        self.app_container = Some(MaximumSid::from(sid));
        self
    }

    /// Returns the AppContainer SID configured for process creation, if any.
    pub fn app_container_sid(&self) -> Option<&Sid> {
        self.app_container.as_ref().map(AsRef::as_ref)
    }

    /// When running as an AppContainer, disable the ALL APPLICATION PACKAGES
    /// SID.
    ///
    /// This configuration is what is known as an LPAC, or less-privileged
    /// AppContainer.
    pub fn disable_all_application_packages(&mut self, disable: bool) -> &mut Self {
        self.disable_all_application_packages = disable;
        self
    }

    /// Sets the security mitigation policies for the new process.
    pub fn mitigation_policy(&mut self, mitigation_policy: MitigationPolicy) -> &mut Self {
        self.mitigation_policy = Some(mitigation_policy);
        self
    }

    /// Sets the child process policy for the new process.
    pub fn child_process_policy(&mut self, policy: ChildProcessPolicy) -> &mut Self {
        self.child_process_policy = policy;
        self
    }

    /// Sets the process to be suspended at launch.
    pub fn suspended(&mut self, suspended: bool) -> &mut Self {
        self.creation_flags &= !CREATE_SUSPENDED;
        if suspended {
            self.creation_flags |= CREATE_SUSPENDED;
        }
        self
    }

    /// Spawns the process.
    pub fn spawn(mut self) -> io::Result<Process> {
        unsafe {
            let mut list = AttrList::new(6);

            let stdin = self.stdin.eval(STD_INPUT_HANDLE)?;
            let stdout = self.stdout.eval(STD_OUTPUT_HANDLE)?;
            let stderr = self.stderr.eval(STD_ERROR_HANDLE)?;

            let startup_info = STARTUPINFOEXW {
                StartupInfo: STARTUPINFOW {
                    cb: size_of::<STARTUPINFOEXW>() as u32,
                    dwFlags: STARTF_USESTDHANDLES,
                    hStdInput: stdin.as_raw_handle(),
                    hStdOutput: stdout.as_raw_handle(),
                    hStdError: stderr.as_raw_handle(),
                    ..zeroed()
                },
                lpAttributeList: list.as_ptr(),
            };

            // Inherit the stdio handles as well.
            self.handles
                .push(BorrowedHandle::borrow_raw(stdin.as_raw_handle()));
            self.handles
                .push(BorrowedHandle::borrow_raw(stdout.as_raw_handle()));
            self.handles
                .push(BorrowedHandle::borrow_raw(stderr.as_raw_handle()));
            list.update(
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                self.handles.as_slice(),
            )?;

            let jobs: Vec<_> = self.jobs.iter().map(AsHandle::as_handle).collect();
            if !jobs.is_empty() {
                list.update(0, PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs.as_slice())?;
            }

            let security_capabilities =
                self.app_container
                    .as_ref()
                    .map(|sid| SECURITY_CAPABILITIES {
                        AppContainerSid: sid.as_ptr(),
                        Capabilities: null_mut(),
                        CapabilityCount: 0,
                        Reserved: 0,
                    });
            if let Some(capabilities) = &security_capabilities {
                list.update(0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, capabilities)?;
            }

            if self.disable_all_application_packages {
                list.update(
                    0,
                    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                    &PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
                )?;
            }

            // Set the mitigation policy, if provided.
            if let Some(mitigation_policy) = &self.mitigation_policy {
                // Only pass both u64 values if necessary since older versions
                // of Windows only support a single u64 value.
                let len = if mitigation_policy.0[1] != 0 { 2 } else { 1 };
                list.update(
                    0,
                    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                    &mitigation_policy.0[..len],
                )?;
            }

            // Set the child process policy.
            let child_process_policy;
            match self.child_process_policy {
                ChildProcessPolicy::Allow => {
                    // No need to set the attribute.
                }
                ChildProcessPolicy::Disallow => {
                    child_process_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
                    list.update(
                        0,
                        PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                        &child_process_policy,
                    )?;
                }
            }

            // Construct an environment block if is different from the current
            // one.
            let mut env_block = None;
            if self.clear_env || !self.env.is_empty() {
                let mut env: BTreeMap<OsString, OsString> = BTreeMap::new();
                if !self.clear_env {
                    env = std::env::vars_os().collect();
                }
                for (key, val) in self.env.into_iter() {
                    match val {
                        Some(val) => {
                            env.insert(key, val);
                        }
                        None => {
                            env.remove(&key);
                        }
                    }
                }
                let mut block = Vec::new();
                for (key, val) in env {
                    ensure_no_null(&key)?;
                    block.extend(key.encode_wide());
                    block.push('=' as u16);
                    ensure_no_null(&val)?;
                    block.extend(val.encode_wide());
                    block.push(0);
                }
                if block.is_empty() {
                    block.push(0);
                }
                block.push(0);
                env_block = Some(block);
            }

            // Null terminate the input strings, validating that there are no internal null characters.
            let application_name = self.application_name.map(null_terminate).transpose()?;
            let current_directory = self.current_directory.map(null_terminate).transpose()?;
            // The command line buffer must be mutable, so convert it back into a Vec.
            let mut command_line = null_terminate(self.command_line)?.into_vec_with_nul();

            let mut process_info = zeroed();
            if CreateProcessAsUserW(
                self.token.map(|h| h.as_raw_handle()).unwrap_or(null_mut()),
                ptr_or_null(&application_name),
                command_line.as_mut_ptr(),
                null_mut(),
                null_mut(),
                true.into(),
                self.creation_flags | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                ptr_or_null(&env_block) as *mut _,
                ptr_or_null(&current_directory),
                &startup_info.StartupInfo,
                &mut process_info,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let process = OwnedHandle::from_raw_handle(process_info.hProcess);
            let _thread = OwnedHandle::from_raw_handle(process_info.hThread);
            Ok(process.into())
        }
    }
}

/// Process and owning job object returned by `empty_process`.
///
/// For convenience, its [`AsHandle`] implementation returns the process handle.
pub struct EmptyProcess {
    pub process: Process,
    pub job: Job,
}

impl AsHandle for EmptyProcess {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.process.as_handle()
    }
}

/// Creates a suspended, (nearly) empty process, hosted in a new job object. It will
/// terminate when the job object is closed.
pub fn empty_process() -> io::Result<EmptyProcess> {
    // Create a job object to hold the empty process.
    let job = Job::new()?;
    // Configure the job so that it terminates all containing processes when its
    // last handle is closed.
    job.set_terminate_on_close()?;

    // Create a suspended process with a thread. Use the current exe since
    // it's guaranteed to exist. Put it in the new job at creation time.
    let mut builder = Builder::new("empty");
    builder
        .application_name(std::env::current_exe()?)
        .env_clear()
        .stdin(Stdio::Null)
        .stdout(Stdio::Null)
        .stderr(Stdio::Null)
        .job(job.as_handle())
        .suspended(true);
    let process = builder.spawn()?;

    Ok(EmptyProcess { process, job })
}

/// Terminates the process immediately.
pub(crate) fn terminate(exit_code: i32) -> ! {
    // SAFETY: there are no safety requirements for calling this function.
    unsafe {
        TerminateProcess(GetCurrentProcess(), exit_code as u32);
    }
    std::process::abort()
}

#[cfg(test)]
mod tests {
    use super::Builder;
    use super::ChildProcessPolicy;
    use super::EmptyProcess;
    use super::MitigationPolicy;
    use super::Stdio;
    use super::empty_process;
    use crate::windows::job::Job;
    use crate::windows::security::MaximumSid;
    use crate::windows::security::Sid;
    use std::os::windows::prelude::*;
    use test_with_tracing::test;
    use windows_sys::Win32::Security::EqualSid;
    use windows_sys::Win32::Security::GetTokenInformation;
    use windows_sys::Win32::Security::TOKEN_APPCONTAINER_INFORMATION;
    use windows_sys::Win32::Security::TOKEN_GROUPS;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::Security::TokenAppContainerSid;
    use windows_sys::Win32::Security::TokenCapabilities;
    use windows_sys::Win32::Security::TokenIsAppContainer;
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    #[test]
    fn test_empty() {
        let EmptyProcess { process, job } = empty_process().unwrap();
        drop(job);
        process.wait();
        assert_eq!(process.exit_code(), 0);
    }

    #[test]
    fn initial_owned_and_borrowed_jobs() {
        let parent_job = Job::new().unwrap();
        parent_job.set_terminate_on_close().unwrap();
        let child_job = Job::new().unwrap();
        child_job.set_terminate_on_close().unwrap();
        let executable = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
        let mut builder = Builder::from_args(executable, ["/c", "exit", "0"]);
        builder
            .stdin(Stdio::Null)
            .stdout(Stdio::Null)
            .stderr(Stdio::Null)
            .job(parent_job.as_handle())
            .owned_job(child_job.as_handle().try_clone_to_owned().unwrap())
            .mitigation_policy(MitigationPolicy::default())
            .child_process_policy(ChildProcessPolicy::Disallow)
            .suspended(true);
        let process = builder.spawn().unwrap();
        // SAFETY: The process and both job handles remain live for the queries.
        unsafe {
            for job in [&parent_job, &child_job] {
                let mut member = 0;
                assert_ne!(
                    IsProcessInJob(
                        process.as_handle().as_raw_handle(),
                        job.as_handle().as_raw_handle(),
                        &mut member,
                    ),
                    0
                );
                assert_ne!(member, 0);
            }
        }
        drop(child_job);
        process.wait();
    }

    #[test]
    fn app_container_sid_is_owned() {
        let mut builder = Builder::new("unused");
        assert!(builder.app_container_sid().is_none());
        let expected_sid = {
            let mut sub_authorities = [0u32; 8];
            sub_authorities[0] = 2;
            for value in &mut sub_authorities[1..] {
                let mut bytes = [0; 4];
                getrandom::fill(&mut bytes).unwrap();
                *value = u32::from_ne_bytes(bytes);
            }
            let sid = Sid::new([0, 0, 0, 0, 0, 15], sub_authorities);
            builder.app_container(sid.as_ref());
            MaximumSid::from(sid.as_ref())
        };
        assert_eq!(
            builder.app_container_sid().unwrap().to_string_sid(),
            expected_sid.to_string_sid()
        );
    }

    #[test]
    fn owned_current_directory() {
        struct RemoveDirectory(std::path::PathBuf);
        impl Drop for RemoveDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir(&self.0);
            }
        }

        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let staged_directory = std::env::current_dir()
            .unwrap()
            .join(format!(".pal-cwd-{:016x}", u64::from_ne_bytes(random)));
        std::fs::create_dir(&staged_directory).unwrap();
        let cleanup = RemoveDirectory(staged_directory.clone());
        let job = Job::new().unwrap();
        job.set_terminate_on_close().unwrap();
        let system_directory =
            std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32");
        let command = format!(
            "if /I \"%CD%\"==\"{}\" (exit /b 73) else (exit /b 74)",
            staged_directory.display()
        );
        let mut builder =
            Builder::from_args(system_directory.join("cmd.exe"), ["/d", "/c", &command]);
        builder
            .stdin(Stdio::Null)
            .stdout(Stdio::Null)
            .stderr(Stdio::Null)
            .job(job.as_handle())
            .current_directory(&staged_directory);
        let path = staged_directory.clone();
        drop(staged_directory);
        let process = builder.spawn().unwrap();
        process.wait();
        assert_eq!(process.exit_code(), 73);
        drop(cleanup);
        assert!(!path.exists());
    }

    #[test]
    fn missing_current_directory_prevents_spawn() {
        let job = Job::new().unwrap();
        job.set_terminate_on_close().unwrap();
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let missing_directory = std::env::current_dir().unwrap().join(format!(
            ".pal-missing-cwd-{:016x}",
            u64::from_ne_bytes(random)
        ));
        assert!(!missing_directory.exists());
        let executable = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
        let mut builder = Builder::from_args(executable, ["/d", "/c", "exit", "0"]);
        builder
            .stdin(Stdio::Null)
            .stdout(Stdio::Null)
            .stderr(Stdio::Null)
            .job(job.as_handle())
            .current_directory(missing_directory);
        let error = builder.spawn().unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(windows_sys::Win32::Foundation::ERROR_DIRECTORY as i32)
        );
    }

    #[test]
    #[ignore = "requires a provisioned unique PAL_TEST_APPCONTAINER_SID with executable access"]
    fn app_container_token_has_no_capabilities() {
        let expected_sid: MaximumSid = std::env::var("PAL_TEST_APPCONTAINER_SID")
            .expect("set PAL_TEST_APPCONTAINER_SID to a provisioned unique AppContainer SID")
            .parse()
            .unwrap();
        let job = Job::new().unwrap();
        job.set_terminate_on_close().unwrap();
        let executable = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
        let mut builder = Builder::from_args(executable, ["/c", "exit", "0"]);
        builder
            .stdin(Stdio::Null)
            .stdout(Stdio::Null)
            .stderr(Stdio::Null)
            .owned_job(job.as_handle().try_clone_to_owned().unwrap())
            .app_container(expected_sid.as_ref())
            .disable_all_application_packages(true)
            .mitigation_policy(MitigationPolicy::default())
            .child_process_policy(ChildProcessPolicy::Disallow)
            .suspended(true);
        builder.current_directory(
            std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32"),
        );
        let process = builder.spawn().unwrap();
        // SAFETY: All handles and buffers remain live throughout these queries.
        unsafe {
            let mut token = std::ptr::null_mut();
            assert_ne!(
                OpenProcessToken(process.as_handle().as_raw_handle(), TOKEN_QUERY, &mut token),
                0
            );
            let token = OwnedHandle::from_raw_handle(token);
            let mut returned = 0;
            let mut is_app_container = 0u32;
            assert_ne!(
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenIsAppContainer,
                    std::ptr::from_mut(&mut is_app_container).cast(),
                    size_of_val(&is_app_container) as u32,
                    &mut returned,
                ),
                0
            );
            assert_eq!(is_app_container, 1);
            let mut buffer = [0usize; 32];
            assert_ne!(
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenAppContainerSid,
                    buffer.as_mut_ptr().cast(),
                    size_of_val(&buffer) as u32,
                    &mut returned,
                ),
                0
            );
            let info = &*buffer.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>();
            assert_ne!(EqualSid(info.TokenAppContainer, expected_sid.as_ptr()), 0);
            assert_ne!(
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenCapabilities,
                    buffer.as_mut_ptr().cast(),
                    size_of_val(&buffer) as u32,
                    &mut returned,
                ),
                0
            );
            let groups = &*buffer.as_ptr().cast::<TOKEN_GROUPS>();
            assert_eq!(groups.GroupCount, 0);
        }
        drop(job);
        process.wait();
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Linux process spawning.

use super::Builder;
use super::Child;
use super::FdOp;
use super::SandboxFailureMode;
use super::SpawnError;
use crate::unix::SyscallResult;
use crate::unix::errno;
use caps::CapsHashSet;
use landlock::RulesetCreated;
use seccompiler::SeccompFilter;
use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::os::unix::prelude::*;

struct CloneContext<'a> {
    executable: &'a CStr,
    argv: &'a [*const libc::c_char],
    envp: &'a [*const libc::c_char],
    result: Option<i32>,
    // TODO: refactor this to contain BorrowedFds
    fd_ops: &'a mut [(i32, FdOp)],
    sandbox_failure_mode: SandboxFailureMode,
    setsid: bool,
    controlling_terminal: Option<BorrowedFd<'a>>,
    uid: Option<libc::uid_t>,
    gid: Option<libc::uid_t>,
    permitted_capabilities: Option<CapsHashSet>,
    effective_capabilities: Option<CapsHashSet>,
    ambient_capabilities: Option<CapsHashSet>,
    inheritable_capabilities: Option<CapsHashSet>,
    bounding_capabilities: Option<CapsHashSet>,
    landlock_rules: Option<RulesetCreated>,
    seccomp_filter: Option<SeccompFilter>,
    cgroup_procs: Option<BorrowedFd<'a>>,
    close_fds: bool,
}

impl Builder<'_> {
    pub(super) fn spawn_internal(
        &self,
        envp: &[CString],
        fd_ops: &mut [(i32, FdOp)],
    ) -> Result<Child, SpawnError> {
        let cgroup_procs = self
            .linux_builder
            .cgroup_procs
            .as_ref()
            .map(|fd| fd.as_fd());
        if (cgroup_procs.is_some() || self.linux_builder.close_fds)
            && (!self.linux_builder.vfork
                || self.linux_builder.clone_flags & (libc::CLONE_FILES | libc::CLONE_THREAD) != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "descriptor isolation requires vfork and independent process/descriptor ownership",
            )
            .into());
        }
        if let Some(fd) = cgroup_procs {
            if fd_ops
                .iter()
                .any(|(_, op)| matches!(op, FdOp::Dup(source) if *source == fd.as_raw_fd()))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the cgroup enrollment descriptor must not be mapped into the workload",
                )
                .into());
            }
        }
        let mut landlock_rules = None;
        if let Some(lr) = &self.linux_builder.landlock_rules {
            landlock_rules = Some(lr.try_clone()?);
        }

        // Build the null-terminated arrays for exec.
        let argv = super::c_slice_to_pointers(&self.argv);
        let envp = super::c_slice_to_pointers(envp);

        let mut context = CloneContext {
            executable: &self.executable,
            argv: &argv,
            envp: &envp,
            result: None,
            fd_ops: &mut *fd_ops,
            sandbox_failure_mode: self.linux_builder.sandbox_failure_mode,
            setsid: self.linux_builder.setsid,
            controlling_terminal: self.linux_builder.controlling_terminal,
            uid: self.uid,
            gid: self.gid,
            permitted_capabilities: self.linux_builder.permitted_capabilities.clone(),
            effective_capabilities: self.linux_builder.effective_capabilities.clone(),
            inheritable_capabilities: self.linux_builder.inheritable_capabilities.clone(),
            ambient_capabilities: self.linux_builder.ambient_capabilities.clone(),
            bounding_capabilities: self.linux_builder.bounding_capabilities.clone(),
            landlock_rules,
            seccomp_filter: self.linux_builder.seccomp_filter.clone(),
            cgroup_procs,
            close_fds: self.linux_builder.close_fds,
        };

        // Use CLONE_VM and CLONE_VFORK so that the new process will share the
        // current address space and will block this thread until it either
        // exits or calls exec.
        //
        // Use CLONE_PIDFD to get an fd back to use for polling.
        let mut flags = self.linux_builder.clone_flags | libc::CLONE_PIDFD | libc::SIGCHLD;

        if self.linux_builder.vfork {
            flags |= libc::CLONE_VM | libc::CLONE_VFORK;
        }

        // SAFETY: sysconf has no safety requirements.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;

        // Common page sizes are 4KiB, 16KiB, and 64KiB. The stack size must be a multiple
        // of the page size.
        let stack_len: usize = std::cmp::max(16 * 1024, page_size);
        assert!(stack_len.is_multiple_of(page_size));

        // Create a stack with one guard page.
        let stack_len = stack_len + page_size;
        // SAFETY: creating a new mapping, which has no safety requirements.
        let stack = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                stack_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if stack == libc::MAP_FAILED {
            return Err(io::Error::from(errno()).into());
        }
        let mmap_guard = ChildStackGuard(stack, stack_len);
        // SAFETY: The stack has been checked to be valid, and its length is more than one page.
        unsafe { libc::mprotect(stack, page_size, libc::PROT_NONE) }
            .syscall_result()
            .map_err(io::Error::from)?;
        let mut pidfd: libc::pid_t = -1;

        // SAFETY: The stack is valid for stack len, if the child goes off the
        // stack they'll hit our guard page, the flags include PIDFD so passing
        // pidfd is valid, and clone_cb takes a CloneContext pointer as its only
        // argument.
        let pid = unsafe {
            libc::clone(
                clone_cb,
                stack.add(stack_len),
                flags,
                std::ptr::from_mut(&mut context).cast(),
                &mut pidfd,
            )
        }
        .syscall_result()
        .map_err(io::Error::from)?;
        drop(mmap_guard);

        // SAFETY: We set the PIDFD flag, and clone returned successfully, so pidfd is now valid.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        let mut child = Child {
            pid,
            pidfd,
            status: None,
        };

        // This can only be done if we are vforking, without sharing another
        // type of status object we can't determine if the execve failed or
        // the process failed during early initialization.
        if self.linux_builder.vfork && context.result != Some(0) {
            // The new process failed without successfully calling execve. Reap
            // it and return the associated error code (which may come from
            // context or from the exit code).
            let status = child.wait();
            return Err(captured_startup_error(child, context.result, status));
        }

        Ok(child)
    }
}

fn captured_startup_error(
    child: Child,
    result: Option<i32>,
    status: io::Result<std::process::ExitStatus>,
) -> SpawnError {
    let error = match status {
        Ok(status) => startup_error(result, status),
        Err(error) => error,
    };
    SpawnError {
        error,
        child: Some(child),
    }
}

fn startup_error(result: Option<i32>, status: std::process::ExitStatus) -> io::Error {
    match result.or(status.code()) {
        Some(errno) => io::Error::from_raw_os_error(errno),
        None => io::Error::other(format!("child terminated during process setup: {status}")),
    }
}

struct ChildStackGuard(*mut libc::c_void, usize);

impl Drop for ChildStackGuard {
    fn drop(&mut self) {
        // SAFETY: We know the pointer is valid and the length is correct at
        // construction, and we know the child is not running anymore, so it's
        // safe to unmap the stack.
        unsafe { libc::munmap(self.0, self.1) }
            .syscall_result()
            .unwrap();
    }
}

fn record_vfork_error(context: &mut CloneContext<'_>, error: i32) -> libc::c_int {
    // Preserve the errno rather than truncating it to an eight-bit exit code.
    context.result = Some(error);
    255
}

/// Runs in the cloned process to set up the process environment and exec the
/// new binary.
///
/// This function must not use the heap or call any functions that might. It
/// also has only a small amount of stack space available. It should avoid using
/// OS functionality via the std crate and should use libc directly.
///
/// Returns the exit code for the new process. If this function does not update
/// context's result, then the exit code will be the Linux errno value
/// associated with the error.
//
// N.B. this should be unsafe but the libc crate neglected to mark the clone
// callback appropriately.
extern "C" fn clone_cb(context: *mut libc::c_void) -> libc::c_int {
    // SAFETY: Context is temporarily owned by this function, and we know
    // we were passed a valid pointer.
    let context = unsafe { &mut *(context.cast::<CloneContext<'_>>()) };

    if let Some(fd) = context.cgroup_procs {
        loop {
            // SAFETY: the descriptor is retained by the parent and the buffer
            // is a static byte. No allocation or Rust ownership changes occur.
            let written = unsafe { libc::write(fd.as_raw_fd(), b"0".as_ptr().cast(), 1) };
            if written == 1 {
                break;
            }
            if written < 0 {
                let error = errno().0;
                if error == libc::EINTR {
                    continue;
                }
                return record_vfork_error(context, error);
            }
            return record_vfork_error(context, libc::EIO);
        }
        // SAFETY: clone created a separate descriptor table. Only its copy is
        // closed, before fd mappings can reuse this descriptor number.
        if unsafe { libc::close(fd.as_raw_fd()) } < 0 {
            return record_vfork_error(context, errno().0);
        }
    }

    if context.close_fds {
        // SAFETY: clone created an independent descriptor table. Marking these
        // descriptors does not close setup resources before the trusted exec.
        if unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        } < 0
        {
            return record_vfork_error(context, errno().0);
        }
    }

    if context.setsid {
        // SAFETY: setsid has no safety requirements.
        if unsafe { libc::setsid() } < 0 {
            return errno().0;
        }
    }

    if let Some(fd) = context.controlling_terminal {
        // SAFETY: fd is guaranteed to be valid.
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSCTTY, 0) } < 0 {
            return errno().0;
        }
    }

    // Find the maximum newfd, needed below.
    let maxfd = context.fd_ops.iter().map(|(fd, _)| *fd).max();

    if let Some(maxfd) = maxfd {
        let Some(min_temporary_fd) = maxfd.checked_add(1) else {
            return record_vfork_error(context, libc::EINVAL);
        };
        for (newfd, op) in &mut *context.fd_ops {
            match op {
                FdOp::Close => {}
                FdOp::Dup(oldfd) => {
                    // Ensure oldfd is above the maximum newfd. This is
                    // necessary to ensure that another operation does not close
                    // an oldfd targeted by this operation.
                    if oldfd != newfd && *oldfd <= maxfd {
                        // SAFETY: fd is guaranteed to be valid
                        let new_oldfd =
                            unsafe { libc::fcntl(*oldfd, libc::F_DUPFD_CLOEXEC, min_temporary_fd) };
                        if new_oldfd < 0 {
                            return errno().0;
                        }
                        *oldfd = new_oldfd;
                    }
                }
            }
        }

        for (newfd, op) in &*context.fd_ops {
            match op {
                FdOp::Close => {
                    // SAFETY: fd is guaranteed to be valid
                    if unsafe { libc::close(*newfd) } < 0 {
                        return errno().0;
                    }
                }
                FdOp::Dup(oldfd) => {
                    if *newfd == *oldfd {
                        // SAFETY: fd is guaranteed to be valid
                        if unsafe {
                            libc::fcntl(
                                *oldfd,
                                libc::F_SETFD,
                                libc::fcntl(*oldfd, libc::F_GETFD) & !libc::FD_CLOEXEC,
                            )
                        } < 0
                        {
                            return errno().0;
                        }
                    } else {
                        // SAFETY: fds are guaranteed to be valid
                        if unsafe { libc::dup2(*oldfd, *newfd) } < 0 {
                            return errno().0;
                        }
                    }
                }
            }
        }
    }

    macro_rules! handle_sandbox_failure {
        ($m:expr, $r:expr) => {
            match context.sandbox_failure_mode {
                SandboxFailureMode::Silent => {}
                SandboxFailureMode::Warn => {
                    tracing::warn!($m);
                }
                SandboxFailureMode::Error => {
                    tracing::error!($m);
                    return $r;
                }
            }
        };
    }

    if let Some(landlock_rules) = context.landlock_rules.take() {
        if landlock_rules.restrict_self().is_err() {
            handle_sandbox_failure!("failed to apply landlock ruleset", libc::ENOTSUP);
        }
    }

    if let Some(gid) = context.gid {
        // SAFETY: setresgid has no safety requirements.
        if unsafe { libc::setresgid(gid, gid, gid) } < 0 {
            handle_sandbox_failure!("failed to change group id", libc::ENOTSUP);
        }
    }

    if let Some(uid) = context.uid {
        // SAFETY: setresuid has no safety requirements.
        if unsafe { libc::setresuid(uid, uid, uid) } < 0 {
            handle_sandbox_failure!("failed to change user id", libc::ENOTSUP);
        }
    }

    macro_rules! set_capabilities {
        ($t:expr, $v:ident) => {
            if let Some($v) = &context.$v {
                if caps::set(None, $t, &$v).is_err() {
                    handle_sandbox_failure!(
                        std::concat!("failed to apply ", stringify!($t), " capabilities"),
                        libc::ENOTSUP
                    );
                }
            }
        };
    }

    set_capabilities!(caps::CapSet::Bounding, bounding_capabilities);
    set_capabilities!(caps::CapSet::Permitted, permitted_capabilities);
    set_capabilities!(caps::CapSet::Ambient, ambient_capabilities);
    set_capabilities!(caps::CapSet::Inheritable, inheritable_capabilities);
    set_capabilities!(caps::CapSet::Effective, effective_capabilities);

    if let Some(seccomp_filter) = context.seccomp_filter.take() {
        if let Ok(bpf_program) = TryInto::<seccompiler::BpfProgram>::try_into(seccomp_filter) {
            if seccompiler::apply_filter(&bpf_program).is_err() {
                handle_sandbox_failure!("failed to apply seccomp profile", libc::ENOTSUP);
            }
        }
    }

    // Update the result indicating success in case execvpe does not return.
    context.result = Some(0);
    // N.B. This will only return on error.
    // SAFETY: Arguments in the context are valid CStrings, and the two arrays
    // are properly null terminated.
    unsafe {
        libc::execvpe(
            context.executable.as_ptr(),
            context.argv.as_ptr(),
            context.envp.as_ptr(),
        )
    };
    // Update the result with the failure code.
    context.result = Some(errno().0);
    255
}

impl AsFd for Child {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }
}

#[cfg(test)]
mod enrollment_tests {
    use super::*;
    use crate::unix::process::Stdio;
    use std::fs::File;
    use std::io::Read;
    use std::io::Seek;
    use std::io::Write;
    use std::os::fd::BorrowedFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use test_with_tracing::test;

    fn memfile() -> File {
        // SAFETY: the name is a static C string; the successful fd is newly owned.
        let fd = unsafe { libc::memfd_create(c"pal-enrollment-test".as_ptr(), libc::MFD_CLOEXEC) }
            .syscall_result()
            .unwrap();
        // SAFETY: memfd_create returned a new owned descriptor.
        unsafe { File::from_raw_fd(fd) }
    }

    fn contents(file: &File) -> Vec<u8> {
        let mut reader = file.try_clone().unwrap();
        reader.rewind().unwrap();
        let mut contents = Vec::new();
        reader.read_to_end(&mut contents).unwrap();
        contents
    }

    fn duplicate_at_least(fd: BorrowedFd<'_>, minimum: i32) -> OwnedFd {
        // SAFETY: the borrowed source remains valid and fcntl creates a new fd.
        let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) }
            .syscall_result()
            .unwrap();
        // SAFETY: fcntl returned a new descriptor owned by this test.
        unsafe { OwnedFd::from_raw_fd(duplicate) }
    }

    fn spawn_mode(builder: &Builder<'_>, captured: bool) -> Child {
        if captured {
            builder.spawn_captured().unwrap()
        } else {
            builder.spawn().unwrap()
        }
    }

    #[test]
    fn fd_mapping_preserves_source_at_highest_destination() {
        for captured in [false, true] {
            for close_fds in [false, true] {
                let output = memfile();
                let mapped = memfile();
                let destination = output.as_raw_fd();
                let command =
                    format!("printf output && printf mapped > /proc/self/fd/{destination}");
                let mut builder = Builder::new("/bin/sh");
                builder
                    .args(["-c", &command])
                    .inherit_env(false)
                    .stdin(Stdio::Null)
                    .stdout(Stdio::Fd(output.as_fd()))
                    .stderr(Stdio::Null)
                    .dup_fd(mapped.as_fd(), destination)
                    .set_close_fds(close_fds);
                assert!(spawn_mode(&builder, captured).wait().unwrap().success());
                assert_eq!(contents(&output), b"output");
                assert_eq!(contents(&mapped), b"mapped");
            }
        }
    }

    #[test]
    fn fd_mapping_temporary_is_above_vacated_highest_destination() {
        for captured in [false, true] {
            for close_fds in [false, true] {
                let mut input = memfile();
                input.write_all(b"input").unwrap();
                input.rewind().unwrap();
                let output = memfile();
                let enrollment = memfile();
                let mut mapped = memfile();
                mapped.write_all(b"wrong").unwrap();
                mapped.rewind().unwrap();
                let maximum = [&input, &output, &enrollment, &mapped]
                    .map(AsRawFd::as_raw_fd)
                    .into_iter()
                    .max()
                    .unwrap();
                let enrollment_fd = Arc::new(duplicate_at_least(
                    enrollment.as_fd(),
                    maximum.checked_add(1).unwrap(),
                ));
                let destination = enrollment_fd.as_raw_fd();
                let mapped_fd =
                    duplicate_at_least(mapped.as_fd(), destination.checked_add(1).unwrap());
                let mut builder = Builder::new("/bin/cat");
                builder
                    .inherit_env(false)
                    .stdin(Stdio::Fd(input.as_fd()))
                    .stdout(Stdio::Fd(output.as_fd()))
                    .stderr(Stdio::Null)
                    .dup_fd(mapped_fd.as_fd(), destination)
                    .set_cgroup_procs(enrollment_fd)
                    .set_close_fds(close_fds);
                // Enrollment vacates the highest destination before relocation.
                // Its later mapping must not overwrite a temporary stdin copy.
                assert!(spawn_mode(&builder, captured).wait().unwrap().success());
                assert_eq!(contents(&enrollment), b"0");
                assert_eq!(contents(&output), b"input");
                assert_eq!(contents(&mapped), b"wrong");
            }
        }
    }

    #[test]
    fn fd_mapping_rejects_relocation_overflow() {
        let source = memfile();
        let mut builder = Builder::new("/bin/true");
        builder.dup_fd(source.as_fd(), i32::MAX);
        assert_eq!(
            builder.spawn().unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        let (error, child) = builder.spawn_captured().unwrap_err().into_parts();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        let mut child = child.expect("descriptor setup failed after clone");
        let status = child.status.expect("failed setup was reaped");
        assert!(!status.success());
        assert_eq!(child.wait().unwrap(), status);
    }

    #[test]
    fn spawn_captured_validation_has_no_child() {
        let mut builder = Builder::new("/bin/true");
        builder.env("PAL_CAPTURED", "invalid\0value");
        let (error, child) = builder.spawn_captured().unwrap_err().into_parts();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(child.is_none());

        let mut builder = Builder::new("/bin/true");
        builder.set_close_fds(true).set_vfork(false);
        let (error, child) = builder.spawn_captured().unwrap_err().into_parts();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(child.is_none());
    }

    #[test]
    fn spawn_captured_clone_failure_has_no_child() {
        let mut builder = Builder::new("/bin/true");
        builder.set_vfork(false);
        // CLONE_SIGHAND without CLONE_VM is rejected before creating a child.
        builder.linux_builder.clone_flags = libc::CLONE_SIGHAND;
        let (error, child) = builder.spawn_captured().unwrap_err().into_parts();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        assert!(child.is_none());
    }

    #[test]
    fn spawn_captured_exec_error_retains_reaped_child() {
        let builder = Builder::new("/proc/self/fd/-1");
        let (error, child) = builder.spawn_captured().unwrap_err().into_parts();
        assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
        let mut child = child.expect("exec failed after clone created a child");
        let status = child.status.expect("pre-exec failure was reaped");
        assert_eq!(status.code(), Some(255));
        assert_eq!(child.wait().unwrap(), status);
        assert_eq!(child.try_wait().unwrap(), Some(status));
        let mut pollfd = libc::pollfd {
            fd: child.as_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the original pidfd is still owned; polling is nonblocking.
        let ready =
            crate::unix::while_eintr(|| unsafe { libc::poll(&mut pollfd, 1, 0) }.syscall_result())
                .unwrap();
        assert_eq!(ready, 1);
        assert_ne!(pollfd.revents & libc::POLLIN, 0);
        assert_eq!(
            builder.spawn().unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    #[test]
    fn spawn_captured_enrollment_error_retains_child_and_parent_fds() {
        let read_only = Arc::new(OwnedFd::from(File::open("/dev/null").unwrap()));
        let output = memfile();
        for mode in [
            SandboxFailureMode::Silent,
            SandboxFailureMode::Warn,
            SandboxFailureMode::Error,
        ] {
            let mut builder = Builder::new("/bin/sh");
            builder
                .args(["-c", "printf must-not-execute"])
                .stdout(Stdio::Fd(output.as_fd()))
                .set_sandbox_failure_mode(mode)
                .set_cgroup_procs(read_only.clone())
                .set_close_fds(true);
            let (error, child) = builder.spawn_captured().unwrap_err().into_parts();
            assert_eq!(error.raw_os_error(), Some(libc::EBADF));
            let mut child = child.expect("enrollment failed in the created child");
            let status = child.status.expect("enrollment failure was reaped");
            assert_eq!(status.code(), Some(255));
            assert_eq!(child.wait().unwrap(), status);
            assert_eq!(Arc::strong_count(&read_only), 2);
            // SAFETY: the original parent descriptor is still owned.
            assert!(unsafe { libc::fcntl(read_only.as_raw_fd(), libc::F_GETFD) } >= 0);
        }
        assert!(contents(&output).is_empty());
        assert_eq!(Arc::strong_count(&read_only), 1);
    }

    #[test]
    fn spawn_captured_wait_error_retains_identity_for_retry() {
        let child = Builder::new("/bin/true").spawn_captured().unwrap();
        let pid = child.id();
        let pidfd = child.as_fd().as_raw_fd();
        assert!(child.status.is_none());
        // Inject only the failed wait result. The child/pidfd is real, and the
        // retry below performs the actual OS wait without changing global state.
        let failure = captured_startup_error(
            child,
            Some(libc::ENOENT),
            Err(io::Error::from_raw_os_error(libc::EIO)),
        );
        let (error, child) = failure.into_parts();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        let mut child = child.unwrap();
        assert_eq!(child.id(), pid);
        assert_eq!(child.as_fd().as_raw_fd(), pidfd);
        assert!(child.status.is_none());
        let status = child.wait().unwrap();
        assert!(status.success());
        assert_eq!(child.try_wait().unwrap(), Some(status));
    }

    #[test]
    fn spawn_captured_success_shares_environment_and_fd_preparation() {
        for captured in [false, true] {
            let output = memfile();
            let mapped = memfile();
            let mut builder = Builder::new("/bin/sh");
            builder
                .args([
                    "-c",
                    "test \"$PAL_CAPTURED\" = expected && printf output && printf mapped >&3",
                ])
                .inherit_env(false)
                .env("PAL_CAPTURED", "expected")
                .stdin(Stdio::Null)
                .stdout(Stdio::Fd(output.as_fd()))
                .stderr(Stdio::Null)
                .dup_fd(mapped.as_fd(), 3)
                .set_close_fds(true);
            let mut child = spawn_mode(&builder, captured);
            assert!(child.wait().unwrap().success());
            assert_eq!(contents(&output), b"output");
            assert_eq!(contents(&mapped), b"mapped");
        }
    }

    #[test]
    fn cgroup_write_precedes_fd_mapping_and_exec() {
        // A regular anonymous file observes the write ordering without claiming
        // kernel cgroup qualification or requiring a delegated cgroup.
        let enrollment = memfile();
        let fd = Arc::new(OwnedFd::from(enrollment.try_clone().unwrap()));
        let output = memfile();
        let command = format!("printf X > /proc/self/fd/{}", fd.as_raw_fd());
        let mut builder = Builder::new("/bin/sh");
        builder
            .args(["-c", &command])
            .set_cgroup_procs(fd.clone())
            .dup_fd(output.as_fd(), fd.as_raw_fd());
        let mut child = builder.spawn().unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(contents(&enrollment), b"0");
        assert_eq!(contents(&output), b"X");
        // The parent still owns its original descriptor after the child closed
        // its copy, and no child-side Arc decrement occurred.
        assert_eq!(Arc::strong_count(&fd), 2);
        // SAFETY: the Arc retains this parent descriptor.
        assert!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } >= 0);
    }

    #[test]
    fn cgroup_descriptor_closed_before_exec() {
        let enrollment = memfile();
        let fd = Arc::new(OwnedFd::from(enrollment.try_clone().unwrap()));
        // SAFETY: this test owns the descriptor. Make its anonymous test file
        // inheritable so that exec's CLOEXEC handling cannot mask a missing close.
        assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) }, 0);
        let command = format!("test ! -e /proc/self/fd/{}", fd.as_raw_fd());
        let mut builder = Builder::new("/bin/sh");
        builder.args(["-c", &command]).set_cgroup_procs(fd.clone());
        let mut child = builder.spawn().unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(contents(&enrollment), b"0");
        // SAFETY: the parent still owns this descriptor, with its flags unchanged.
        assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) }, 0);
    }

    #[test]
    fn cgroup_write_errors_abort_before_exec_in_all_failure_modes() {
        let read_only = Arc::new(OwnedFd::from(File::open("/dev/null").unwrap()));
        let output = memfile();
        for mode in [
            SandboxFailureMode::Silent,
            SandboxFailureMode::Warn,
            SandboxFailureMode::Error,
        ] {
            let mut builder = Builder::new("/bin/sh");
            builder
                .args(["-c", "printf must-not-execute"])
                .stdout(Stdio::Fd(output.as_fd()))
                .set_sandbox_failure_mode(mode)
                .set_cgroup_procs(read_only.clone());
            assert_eq!(
                builder.spawn().unwrap_err().raw_os_error(),
                Some(libc::EBADF)
            );
        }
        assert!(contents(&output).is_empty());
        // SAFETY: the Arc retains a valid read-only descriptor in the parent.
        assert!(unsafe { libc::fcntl(read_only.as_raw_fd(), libc::F_GETFD) } >= 0);
        let full = Arc::new(OwnedFd::from(
            File::options().write(true).open("/dev/full").unwrap(),
        ));
        let mut builder = Builder::new("/bin/true");
        builder.set_cgroup_procs(full);
        assert_eq!(
            builder.spawn().unwrap_err().raw_os_error(),
            Some(libc::ENOSPC)
        );
    }

    #[test]
    fn cgroup_rejects_unreportable_startup_and_capability_mapping() {
        let enrollment = memfile();
        let fd = Arc::new(OwnedFd::from(enrollment.try_clone().unwrap()));
        let mut builder = Builder::new("/bin/true");
        builder.set_cgroup_procs(fd.clone()).set_vfork(false);
        assert_eq!(
            builder.spawn().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        builder.set_vfork(true);
        for flags in [libc::CLONE_FILES, libc::CLONE_THREAD] {
            builder.linux_builder.clone_flags = flags;
            assert_eq!(
                builder.spawn().unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
        builder.linux_builder.clone_flags = 0;
        builder.dup_fd(fd.as_fd(), 7);
        assert_eq!(
            builder.spawn().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let mut builder = Builder::new("/bin/true");
        builder
            .set_cgroup_procs(fd.clone())
            .stdout(Stdio::Fd(fd.as_fd()));
        assert_eq!(
            builder.spawn().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(contents(&enrollment).is_empty());
    }

    #[test]
    fn cgroup_startup_signal_is_an_error() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::ExitStatus;

        let error = startup_error(None, ExitStatus::from_raw(libc::SIGKILL));
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("signal: 9"));
        assert_eq!(
            startup_error(None, ExitStatus::from_raw(libc::EIO << 8)).raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(
            startup_error(Some(libc::EACCES), ExitStatus::from_raw(255 << 8)).raw_os_error(),
            Some(libc::EACCES)
        );
        assert_eq!(
            startup_error(Some(0x1234), ExitStatus::from_raw(255 << 8)).raw_os_error(),
            Some(0x1234)
        );
    }

    #[test]
    fn fd_boundary_preserves_mappings_stdio_and_parent_resources() {
        let inheritable = |fd: BorrowedFd<'_>| {
            // SAFETY: duplicate a borrowed descriptor outside all mapping targets.
            let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD, 128) }
                .syscall_result()
                .unwrap();
            // SAFETY: fcntl returned a fresh descriptor.
            unsafe { File::from_raw_fd(raw) }
        };
        let canary = inheritable(memfile().as_fd());
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let mut socket = inheritable(socket.as_fd());
        let mut absent = Vec::new();
        let mut present = Vec::new();
        for file in [&canary, &socket] {
            assert_eq!(
                // SAFETY: the test owns each descriptor and deliberately makes
                // only these anonymous canaries inheritable.
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) },
                0
            );
            let metadata = file.metadata().unwrap();
            let identity = format!("{}:{}", metadata.dev(), metadata.ino());
            let probe = format!(
                "$(stat -Lc '%d:%i' /proc/self/fd/{} 2>/dev/null)",
                file.as_raw_fd()
            );
            absent.push(format!("test \"{probe}\" != '{identity}'"));
            present.push(format!("test \"{probe}\" = '{identity}'"));
        }
        let mapped = memfile();
        let self_mapped = memfile();
        // SAFETY: duplicate a valid descriptor into a fresh high-numbered slot,
        // avoiding the explicit fd3 mapping and the standard streams.
        let raw = unsafe { libc::fcntl(self_mapped.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) }
            .syscall_result()
            .unwrap();
        // SAFETY: fcntl returned a fresh descriptor.
        let self_fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut input = memfile();
        input.write_all(b"input\n").unwrap();
        input.rewind().unwrap();
        let output = memfile();
        let error = memfile();
        let enrollment = memfile();
        let mut commands = absent;
        commands.extend([
            "read -r line && test \"$line\" = input".to_owned(),
            "printf mapped >&3".to_owned(),
            format!("printf self > /proc/self/fd/{raw}"),
            "printf output".to_owned(),
            "printf error >&2".to_owned(),
        ]);
        let command = commands.join(" && ");
        let mut builder = Builder::new("/bin/sh");
        builder
            .args(["-c", &command])
            .stdin(Stdio::Fd(input.as_fd()))
            .stdout(Stdio::Fd(output.as_fd()))
            .stderr(Stdio::Fd(error.as_fd()))
            .set_cgroup_procs(Arc::new(OwnedFd::from(enrollment.try_clone().unwrap())))
            .set_close_fds(true)
            .dup_fd(mapped.as_fd(), 3)
            .dup_fd(self_fd.as_fd(), raw);
        assert!(builder.spawn().unwrap().wait().unwrap().success());
        assert_eq!(contents(&mapped), b"mapped");
        assert_eq!(contents(&self_mapped), b"self");
        assert_eq!(contents(&output), b"output");
        assert_eq!(contents(&error), b"error");
        assert_eq!(contents(&enrollment), b"0");
        for file in [&canary, &socket] {
            // SAFETY: each parent descriptor is still owned by this test.
            assert_eq!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) }, 0);
        }
        peer.write_all(b"S").unwrap();
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"S");

        let command = present.join(" && ");
        let mut sibling = Builder::new("/bin/sh");
        sibling.args(["-c", &command]);
        assert!(sibling.spawn().unwrap().wait().unwrap().success());
        sibling.set_close_fds(true).set_close_fds(false);
        assert!(sibling.spawn().unwrap().wait().unwrap().success());
    }

    #[test]
    fn fd_boundary_rejects_unreportable_or_shared_descriptor_startup() {
        let mut builder = Builder::new("/bin/true");
        builder.set_close_fds(true).set_vfork(false);
        assert_eq!(
            builder.spawn().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        builder.set_vfork(true);
        for flags in [libc::CLONE_FILES, libc::CLONE_THREAD] {
            builder.linux_builder.clone_flags = flags;
            assert_eq!(
                builder.spawn().unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
    }
}

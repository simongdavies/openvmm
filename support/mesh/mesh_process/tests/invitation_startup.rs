// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A harness-free executable so invitation capture really runs before threads.
//!
//! Windows runtime qualification is opt-in: pass `appcontainer-qualification`
//! with `MESH_AC_TEST_SID_1`/`_2`, `MESH_AC_TEST_EXE_1`/`_2`, and
//! `MESH_AC_TEST_DIR_1`/`_2`. The caller supplies distinct package SIDs and
//! current copies of this executable in task-owned, exact-SID-accessible staging
//! directories. The fixture never provisions profiles or modifies filesystem ACLs.
//! `appcontainer-star-qualification` uses worker 1 as hub and workers 2 and 3
//! as leaves. `MESH_AC_TEST_LEAF_COUNT` optionally selects more leaves, with the
//! same SID/EXE/DIR inputs continuing through index `leaf_count + 1`.
//! Keep every external profile/staging guard alive until the mode exits:
//! worker 2 is replaced using the same SID and immutable staged image.
//! `trusted-host-star-qualification` instead uses ordinary-user role 1
//! (`EXE_1`/`DIR_1`, no `SID_1`) and confined roles 2, 3, and 4 (each with
//! SID/EXE/DIR inputs). Roles 2 and 3 are allowed workers; role 4 is a
//! distinct denied peer. All negatives follow successful token-verified
//! initialization and exercise fresh peer endpoints, not bootstrap failure.
//! Replacement proves root exit only; the external containment owner must
//! separately establish old-job emptiness before reusing a worker identity.

// UNSAFETY: Exercises startup capture and queries live IPC resources using OS APIs.
#![expect(unsafe_code)]

#[cfg(any(windows, target_os = "linux"))]
mod tests {
    use anyhow::Context;
    use base64::Engine;
    use futures_concurrency::future::Race;
    use mesh::MeshPayload;
    use mesh::payload::Protobuf;
    use mesh_process::Mesh;
    use mesh_process::OwnedInvitation;
    use mesh_process::ProcessConfig;
    use mesh_process::SandboxProfile;
    #[cfg(unix)]
    use pal::unix::pipe;
    #[cfg(unix)]
    use pal::unix::process::Builder as ProcessBuilder;
    #[cfg(windows)]
    use pal::windows::pipe;
    #[cfg(windows)]
    use pal::windows::process::Builder as ProcessBuilder;
    use pal_async::DefaultDriver;
    use pal_async::DefaultPool;
    use pal_async::timer::PolledTimer;
    use std::process::Command;
    use std::time::Duration;

    const ENV: &str = "MESH_WORKER_INVITATION";
    const TEST_NAME: &str = "invitation_startup";
    const AMBIENT: &str = "MESH_TEST_AMBIENT";
    const EXPLICIT: &str = "MESH_TEST_EXPLICIT";
    const REMOVED: &str = "MESH_TEST_REMOVED";
    const STDOUT_MARKER: &[u8] = b"owned Mesh stdout\n";
    const STDERR_MARKER: &[u8] = b"owned Mesh stderr\n";
    #[cfg(target_os = "linux")]
    const FD_PROBE: &str = "MESH_TEST_FD_IDENTITIES";

    struct NoAmbient;

    impl SandboxProfile for NoAmbient {
        fn apply(&mut self, builder: &mut ProcessBuilder<'_>) {
            builder.inherit_env(false);
            #[cfg(target_os = "linux")]
            builder.set_close_fds(true);
        }
    }

    struct RejectProfile;

    impl SandboxProfile for RejectProfile {
        fn apply(&mut self, _: &mut ProcessBuilder<'_>) {
            panic!("fallible setup must not fall back to apply");
        }

        fn try_apply(&mut self, _: &mut ProcessBuilder<'_>) -> anyhow::Result<()> {
            anyhow::bail!("fixture profile setup rejected")
        }
    }

    #[cfg(windows)]
    struct BroadAppContainerProfile;

    #[cfg(windows)]
    impl SandboxProfile for BroadAppContainerProfile {
        fn apply(&mut self, builder: &mut ProcessBuilder<'_>) {
            let sid = pal::windows::security::Sid::new([0, 0, 0, 0, 0, 15], [2, 1]);
            builder.app_container(sid.as_ref());
        }
    }

    #[derive(Protobuf)]
    struct WireInvitation {
        node_name: String,
        #[cfg(windows)]
        credentials: mesh_remote::windows::AlpcInvitationCredentials,
        #[cfg(unix)]
        address: mesh_remote::InvitationAddress,
        #[cfg(windows)]
        directory_handle: usize,
        #[cfg(unix)]
        socket_fd: i32,
    }

    #[derive(MeshPayload)]
    struct Init {
        value: u64,
        spawn_grandchild: bool,
        ready: mesh::OneshotSender<u64>,
    }

    #[cfg(windows)]
    #[derive(Protobuf)]
    struct WireCredentials {
        address: mesh_remote::InvitationAddress,
        mesh_secret: Vec<u8>,
    }

    fn resource_is_open(raw: usize) -> bool {
        #[cfg(unix)]
        {
            // SAFETY: F_GETFD validates the number without adopting ownership.
            unsafe { libc::fcntl(raw as i32, libc::F_GETFD) != -1 }
        }
        #[cfg(windows)]
        {
            let mut flags = 0;
            // SAFETY: the API validates the number; flags is writable.
            unsafe {
                windows_sys::Win32::Foundation::GetHandleInformation(raw as *mut _, &mut flags) != 0
            }
        }
    }

    fn raw_resource(wire: &WireInvitation) -> usize {
        #[cfg(unix)]
        {
            wire.socket_fd as usize
        }
        #[cfg(windows)]
        {
            wire.directory_handle
        }
    }

    #[cfg(unix)]
    fn socket_identity(raw: usize) -> std::io::Result<(u64, u64)> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat validates the fd and writes the stat on success.
        if unsafe { libc::fstat(raw as i32, stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fstat successfully initialized the structure.
        let stat = unsafe { stat.assume_init() };
        Ok((stat.st_dev, stat.st_ino))
    }

    #[cfg(target_os = "linux")]
    fn check_unrelated_fds() -> anyhow::Result<()> {
        let Some(spec) = std::env::var_os(FD_PROBE) else {
            return Ok(());
        };
        let spec = spec
            .into_string()
            .map_err(|_| anyhow::anyhow!("invalid fd probe"))?;
        let (presence, resources) = spec.split_once(';').context("missing fd policy")?;
        anyhow::ensure!(matches!(presence, "present" | "absent"));
        for resource in resources.split(',') {
            let fields: Vec<_> = resource.split(':').collect();
            anyhow::ensure!(fields.len() == 3);
            let fd = fields[0].parse()?;
            let expected = (fields[1].parse()?, fields[2].parse()?);
            let inherited = match socket_identity(fd) {
                Ok(identity) => identity == expected,
                Err(error) if error.raw_os_error() == Some(libc::EBADF) => false,
                Err(error) => return Err(error.into()),
            };
            anyhow::ensure!(
                inherited == (presence == "present"),
                "fd {fd} has unexpected resource identity under {presence} policy"
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    struct InheritableResources {
        file: std::fs::File,
        socket: std::os::unix::net::UnixStream,
        peer: std::os::unix::net::UnixStream,
    }

    #[cfg(target_os = "linux")]
    impl InheritableResources {
        fn new() -> anyhow::Result<Self> {
            use std::os::fd::AsFd;
            use std::os::fd::AsRawFd;
            use std::os::fd::FromRawFd;

            fn inheritable(
                fd: std::os::fd::BorrowedFd<'_>,
            ) -> std::io::Result<std::os::fd::OwnedFd> {
                // SAFETY: fd is live. F_DUPFD creates a new inheritable descriptor,
                // above the Mesh fd3 mapping and standard runtime descriptors.
                let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD, 64) };
                if raw < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // SAFETY: F_DUPFD returned a new descriptor with exclusive ownership.
                Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) })
            }

            let file = std::fs::File::open(std::env::current_exe()?)?;
            let (socket, peer) = std::os::unix::net::UnixStream::pair()?;
            peer.set_read_timeout(Some(Duration::from_secs(2)))?;
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
            Ok(Self {
                file: inheritable(file.as_fd())?.into(),
                socket: inheritable(socket.as_fd())?.into(),
                peer,
            })
        }

        fn identities(&self) -> anyhow::Result<String> {
            use std::os::fd::AsRawFd;

            let mut entries = Vec::new();
            for fd in [self.file.as_raw_fd(), self.socket.as_raw_fd()] {
                let (device, inode) = socket_identity(fd as usize)?;
                entries.push(format!("{fd}:{device}:{inode}"));
            }
            Ok(entries.join(","))
        }

        fn verify_usable(&mut self) -> anyhow::Result<()> {
            use std::io::Read;
            use std::io::Seek;
            use std::io::Write;
            use std::os::fd::AsRawFd;

            self.file.rewind()?;
            let mut magic = [0; 4];
            self.file.read_exact(&mut magic)?;
            anyhow::ensure!(magic == *b"\x7fELF");
            self.socket.write_all(b"out")?;
            let mut message = [0; 3];
            self.peer.read_exact(&mut message)?;
            anyhow::ensure!(&message == b"out");
            self.peer.write_all(b"ack")?;
            self.socket.read_exact(&mut message)?;
            anyhow::ensure!(&message == b"ack");
            for fd in [self.file.as_raw_fd(), self.socket.as_raw_fd()] {
                // SAFETY: both resources remain owned and live.
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                anyhow::ensure!(flags >= 0 && flags & libc::FD_CLOEXEC == 0);
            }
            Ok(())
        }
    }

    #[cfg(windows)]
    fn duplicate_probe_handle(
        process: std::os::windows::io::RawHandle,
        raw: usize,
    ) -> std::io::Result<Option<std::os::windows::io::OwnedHandle>> {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS;
        use windows_sys::Win32::Foundation::DuplicateHandle;
        use windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut duplicate = std::ptr::null_mut();
        // SAFETY: the API validates the source number, the process handles are
        // live, and duplicate is writable. No source ownership is adopted.
        if unsafe {
            DuplicateHandle(
                process,
                raw as *mut _,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_INVALID_HANDLE as i32) {
                return Ok(None);
            }
            return Err(error);
        }
        // SAFETY: successful duplication returned a new, exclusively owned handle.
        Ok(Some(unsafe {
            std::os::windows::io::OwnedHandle::from_raw_handle(duplicate)
        }))
    }

    fn ordinary_probe(raw: usize) -> anyhow::Result<()> {
        anyhow::ensure!(std::env::var_os(ENV).is_none(), "credential leaked to exec");
        #[cfg(target_os = "linux")]
        check_unrelated_fds()?;
        #[cfg(unix)]
        {
            let device = std::env::args().nth(3).context("missing device")?.parse()?;
            let inode = std::env::args().nth(4).context("missing inode")?.parse()?;
            match socket_identity(raw) {
                Ok(identity) => {
                    anyhow::ensure!(
                        identity != (device, inode),
                        "invitation socket leaked to exec"
                    );
                }
                Err(error) if error.raw_os_error() == Some(libc::EBADF) => {}
                Err(error) => return Err(error.into()),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use std::os::windows::io::FromRawHandle;
            use std::os::windows::io::OwnedHandle;
            use windows_sys::Win32::Foundation::CompareObjectHandles;
            use windows_sys::Win32::System::Threading::GetCurrentProcess;
            use windows_sys::Win32::System::Threading::OpenProcess;
            use windows_sys::Win32::System::Threading::PROCESS_DUP_HANDLE;

            // Snapshot the candidate before allocating any reference handles:
            // the runtime may have reused its number for an unrelated object.
            // SAFETY: GetCurrentProcess returns a borrowed pseudo-handle.
            let candidate = duplicate_probe_handle(unsafe { GetCurrentProcess() }, raw)?;
            let parent_pid = std::env::args()
                .nth(3)
                .context("missing parent pid")?
                .parse()?;
            // SAFETY: OpenProcess validates the pid and returns a new handle.
            let process = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, parent_pid) };
            anyhow::ensure!(!process.is_null(), "{}", std::io::Error::last_os_error());
            // SAFETY: successful OpenProcess returned exclusive ownership.
            let process = unsafe { OwnedHandle::from_raw_handle(process) };
            // Explicitly duplicate a reference only after snapshotting the
            // possible inheritance. This is not an inherited reference.
            let reference = duplicate_probe_handle(process.as_raw_handle(), raw)?
                .context("parent invitation resource disappeared")?;
            if let Some(candidate) = candidate {
                // SAFETY: both owned handles remain live throughout comparison.
                let same = unsafe {
                    CompareObjectHandles(candidate.as_raw_handle(), reference.as_raw_handle())
                };
                anyhow::ensure!(same == 0, "invitation directory leaked to exec");
            }
        }
        Ok(())
    }

    fn child(mode: &str) -> anyhow::Result<()> {
        #[cfg(windows)]
        if mode == "appcontainer-qualification" {
            return app_container_qualification::run();
        }
        #[cfg(windows)]
        if mode == "appcontainer-star-qualification" {
            return app_container_qualification::run_star();
        }
        #[cfg(windows)]
        if mode == "trusted-host-star-qualification" {
            return app_container_qualification::run_trusted_host_star();
        }
        #[cfg(windows)]
        if mode == "appcontainer-worker" {
            // SAFETY: this standalone entry path has not started threads or
            // adopted the trusted launcher's inherited invitation.
            return unsafe { app_container_qualification::worker() };
        }
        #[cfg(windows)]
        if mode == "appcontainer-wrong-sid" {
            // SAFETY: this standalone entry path has not started threads or
            // adopted the trusted test launcher's inherited invitation.
            return unsafe { app_container_qualification::wrong_sid_worker() };
        }
        if mode == "profile-workload" {
            use std::io::Write;
            std::io::stdout().write_all(b"rejected workload executed")?;
            return Ok(());
        }
        if mode == "default-diagnostics-suite" {
            return DefaultPool::run_with(async |driver| {
                launch_child(&driver, "joined-default-diagnostics", false, None).await
            });
        }
        #[cfg(target_os = "linux")]
        if mode == "close-range-denied" {
            let errno = std::env::args()
                .nth(2)
                .context("missing denial errno")?
                .parse()?;
            return close_range_denial(errno);
        }
        #[cfg(target_os = "linux")]
        if mode == "close-range-workload" {
            use std::io::Write;
            std::io::stdout().write_all(b"workload executed")?;
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        if matches!(mode, "fd3-helper" | "fd3-probe" | "fd3-exec-probe") {
            return fd3_helper(mode);
        }
        if mode == "env-suite" {
            return environment_suite();
        }
        if mode == "env-probe" {
            return environment_probe(&std::env::args().nth(2).context("missing probe mode")?);
        }
        if mode == "ordinary-probe" {
            let raw = std::env::args()
                .nth(2)
                .context("missing resource")?
                .parse()?;
            return ordinary_probe(raw);
        }
        if matches!(mode, "joined-filtered" | "joined-inherited") {
            anyhow::ensure!(std::env::var(EXPLICIT)? == "explicit");
            if mode == "joined-filtered" {
                anyhow::ensure!(std::env::var_os(AMBIENT).is_none());
            } else {
                anyhow::ensure!(std::env::var(AMBIENT)? == "ambient");
            }
            #[cfg(target_os = "linux")]
            {
                anyhow::ensure!(
                    std::env::var_os(FD_PROBE).is_some(),
                    "missing fd identity policy"
                );
                check_unrelated_fds()?;
            }
        }
        let mut wire: Option<WireInvitation> = if matches!(
            mode,
            "joined"
                | "joined-filtered"
                | "joined-inherited"
                | "joined-diagnostics"
                | "joined-default-diagnostics"
                | "drop"
                | "join-failure"
        ) {
            Some(mesh::payload::decode(
                &base64::engine::general_purpose::STANDARD.decode(std::env::var(ENV)?)?,
            )?)
        } else {
            None
        };
        if mode == "join-failure" {
            let invitation = wire.as_mut().context("missing wire invitation")?;
            #[cfg(unix)]
            {
                // SAFETY: shutdown does not close or take ownership of this valid
                // inherited socket; capture will still receive a live socket.
                let result = unsafe { libc::shutdown(invitation.socket_fd, libc::SHUT_RDWR) };
                anyhow::ensure!(result == 0);
                // The inviter may already have queued the transport handshake.
                // Drain it so joining itself fails, rather than successfully
                // joining and failing later while receiving the typed message.
                let mut buffer = [0u8; 4096];
                loop {
                    // SAFETY: the inherited socket remains live, and buffer is
                    // writable for the supplied length. No ownership is adopted.
                    let received = unsafe {
                        libc::recv(
                            invitation.socket_fd,
                            buffer.as_mut_ptr().cast(),
                            buffer.len(),
                            libc::MSG_DONTWAIT,
                        )
                    };
                    if received == 0 {
                        break;
                    }
                    if received < 0 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        return Err(error).context("failed to drain shut-down invitation socket");
                    }
                }
            }
            #[cfg(windows)]
            {
                let mut credentials: WireCredentials =
                    mesh::payload::decode(&mesh::payload::encode(invitation.credentials.clone()))?;
                // A live directory with an already-bound local ALPC name makes
                // joining fail without supplying any invalid handle.
                credentials.address.local_addr.node = credentials.address.remote_addr.node;
                invitation.credentials =
                    mesh::payload::decode(&mesh::payload::encode(credentials))?;
                // SAFETY: the standalone child has not started any threads.
                unsafe {
                    std::env::set_var(
                        ENV,
                        base64::engine::general_purpose::STANDARD
                            .encode(mesh::payload::encode(wire.take().unwrap())),
                    );
                }
                wire = Some(mesh::payload::decode(
                    &base64::engine::general_purpose::STANDARD.decode(std::env::var(ENV)?)?,
                )?);
            }
        }
        // SAFETY: this standalone main has not started threads or adopted any
        // resource. Valid invitations come exclusively from the test's Mesh.
        let captured = unsafe { OwnedInvitation::capture_from_environment() };
        anyhow::ensure!(std::env::var_os(ENV).is_none(), "credentials not removed");
        // SAFETY: still single-threaded, and there is no environment invitation.
        let recaptured = unsafe { OwnedInvitation::capture_from_environment() };
        anyhow::ensure!(recaptured.is_err(), "second capture was accepted");
        match mode {
            "absent" => anyhow::ensure!(captured?.is_none(), "unexpected invitation"),
            "malformed" | "non-unicode" => {
                let error = captured.err().context("invalid invitation was accepted")?;
                let expected = if mode == "malformed" {
                    "failed to base64 decode invitation"
                } else {
                    "mesh invitation is not Unicode"
                };
                anyhow::ensure!(error.to_string() == expected, "{error:#}");
            }
            "joined"
            | "joined-filtered"
            | "joined-inherited"
            | "joined-diagnostics"
            | "joined-default-diagnostics"
            | "drop"
            | "join-failure" => {
                let invitation = captured?.context("missing invitation")?;
                let wire = wire.context("missing wire invitation")?;
                let raw = raw_resource(&wire);
                #[cfg(target_os = "linux")]
                if mode == "joined-filtered" {
                    anyhow::ensure!(wire.socket_fd == 3, "Mesh invitation must be mapped to fd3");
                }
                #[cfg(unix)]
                {
                    // SAFETY: invitation exclusively owns this live fd.
                    let flags = unsafe { libc::fcntl(wire.socket_fd, libc::F_GETFD) };
                    anyhow::ensure!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
                }
                if !mode.starts_with("joined") {
                    #[cfg(unix)]
                    let duplicate = {
                        use std::os::fd::BorrowedFd;
                        // SAFETY: invitation owns the live socket during duplication.
                        unsafe { BorrowedFd::borrow_raw(raw as i32) }.try_clone_to_owned()?
                    };
                    #[cfg(windows)]
                    let duplicate = {
                        use std::os::windows::io::BorrowedHandle;
                        // SAFETY: invitation owns the live directory during duplication.
                        unsafe { BorrowedHandle::borrow_raw(raw as *mut _) }.try_clone_to_owned()?
                    };
                    if mode == "drop" {
                        drop(invitation);
                    } else {
                        let error = mesh_process::run_mesh_host(
                            invitation,
                            "join-failure",
                            async |_: Init| -> anyhow::Result<()> {
                                anyhow::bail!("handler must not run after failed join")
                            },
                        )
                        .expect_err("broken transport joined successfully");
                        anyhow::ensure!(error.to_string() == "failed to join mesh", "{error:#}");
                    }
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    while resource_is_open(raw) {
                        anyhow::ensure!(
                            std::time::Instant::now() < deadline,
                            "owned invitation resource was not closed"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    #[cfg(unix)]
                    let duplicate_raw = {
                        use std::os::fd::AsRawFd;
                        duplicate.as_raw_fd() as usize
                    };
                    #[cfg(windows)]
                    let duplicate_raw = {
                        use std::os::windows::io::AsRawHandle;
                        duplicate.as_raw_handle() as usize
                    };
                    anyhow::ensure!(
                        resource_is_open(duplicate_raw),
                        "cleanup closed a separately owned resource"
                    );
                    return Ok(());
                }
                // Deliberately inherit the ambient environment without filtering.
                let mut probe = Command::new(std::env::current_exe()?);
                probe.args(["ordinary-probe", &raw.to_string()]);
                #[cfg(unix)]
                {
                    let (device, inode) = socket_identity(raw)?;
                    probe.args([device.to_string(), inode.to_string()]);
                }
                #[cfg(windows)]
                probe.arg(std::process::id().to_string());
                wait_child(probe, "ordinary-probe")?;
                #[cfg(windows)]
                {
                    let mut flags = 0;
                    // SAFETY: invitation owns this live handle; flags is writable.
                    let result = unsafe {
                        windows_sys::Win32::Foundation::GetHandleInformation(
                            wire.directory_handle as *mut _,
                            &mut flags,
                        )
                    };
                    anyhow::ensure!(result != 0);
                    anyhow::ensure!(
                        flags & windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT == 0
                    );
                }
                let (started, running) = std::sync::mpsc::channel();
                let _thread = std::thread::spawn(move || {
                    started.send(()).unwrap();
                    loop {
                        std::thread::park();
                    }
                });
                running.recv()?;
                mesh_process::run_mesh_host(invitation, "invitation-test", async |init: Init| {
                    anyhow::ensure!(init.value == 0x1234);
                    if matches!(mode, "joined-diagnostics" | "joined-default-diagnostics") {
                        use std::io::Write;
                        std::io::stdout().write_all(STDOUT_MARKER)?;
                        std::io::stdout().flush()?;
                        std::io::stderr().write_all(STDERR_MARKER)?;
                        std::io::stderr().flush()?;
                    }
                    if init.spawn_grandchild {
                        let (_, driver) = DefaultPool::spawn_on_thread("grandchild-test");
                        launch_child(&driver, "joined", false, None).await?;
                    }
                    init.ready.send(init.value + 1);
                    Ok(())
                })?;
                anyhow::bail!("successful mesh host returned instead of exiting");
            }
            _ => anyhow::bail!("unknown child mode {mode}"),
        }
        Ok(())
    }

    fn run_child(mode: &str, value: Option<std::ffi::OsString>) -> anyhow::Result<()> {
        let mut command = Command::new(std::env::current_exe()?);
        command.arg(mode).env_remove(ENV);
        if let Some(value) = value {
            command.env(ENV, value);
        }
        wait_child(command, mode)
    }

    fn wait_child(mut command: Command, mode: &str) -> anyhow::Result<()> {
        let mut child = command.spawn()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait()? {
                anyhow::ensure!(status.success(), "{mode}: {status}");
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                anyhow::bail!("{mode} child timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn capture_output(
        mut file: std::fs::File,
    ) -> std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>> {
        use std::io::Read;
        let (send, recv) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = file.read_to_end(&mut bytes).map(|_| bytes);
            let _ = send.send(result);
        });
        recv
    }

    fn expect_output(
        recv: std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
        expected: &[u8],
    ) -> anyhow::Result<()> {
        let bytes = recv
            .recv_timeout(Duration::from_secs(5))
            .context("diagnostic output did not close")??;
        anyhow::ensure!(bytes == expected, "incorrect diagnostic stream: {bytes:?}");
        Ok(())
    }

    fn default_diagnostics() -> anyhow::Result<()> {
        let (stdout_read, stdout_write) = pipe::pair()?;
        let (stderr_read, stderr_write) = pipe::pair()?;
        let stdout = capture_output(stdout_read);
        let stderr = capture_output(stderr_read);
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("default-diagnostics-suite")
            .env_remove(ENV)
            .stdout(stdout_write)
            .stderr(stderr_write);
        wait_child(command, "default-diagnostics-suite")?;
        expect_output(stdout, b"")?;
        expect_output(stderr, STDERR_MARKER)
    }

    async fn rejected_profile(
        driver: &DefaultDriver,
        profile: impl Fn() -> Box<dyn SandboxProfile + Sync>,
        expected_error: &str,
    ) -> anyhow::Result<()> {
        for owned in [false, true] {
            let mesh = Mesh::new("rejected-profile".into())?;
            let (read, write) = pipe::pair()?;
            let output = capture_output(read);
            let config = ProcessConfig::new_with_sandbox("rejected-profile", profile())
                .process_name(std::env::current_exe()?)
                .args(["profile-workload"])
                .skip_worker_arg(true)
                .stdout(Some(write));
            let result = (
                async {
                    Some(if owned {
                        mesh.launch_host_owned(config, ()).await.map(|_| ())
                    } else {
                        mesh.launch_host(config, ()).await.map(|_| ())
                    })
                },
                async {
                    PolledTimer::new(driver)
                        .sleep(Duration::from_secs(15))
                        .await;
                    None
                },
            )
                .race()
                .await;
            mesh.shutdown().await;
            let error = result
                .context("profile rejection timed out")?
                .err()
                .context("rejected profile unexpectedly spawned a process")?;
            anyhow::ensure!(
                format!("{error:#}").contains(expected_error),
                "incorrect profile rejection: {error:#}"
            );
            expect_output(output, b"")?;
        }
        Ok(())
    }

    #[cfg(windows)]
    mod app_container_qualification {
        use super::*;
        use futures::FutureExt;
        use futures::future::BoxFuture;
        use mesh_process::OwnedHost;
        use pal::windows::security::MaximumSid;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::ffi::OsStringExt;
        use std::os::windows::io::AsHandle;
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::io::FromRawHandle;
        use std::os::windows::io::OwnedHandle;
        use std::path::PathBuf;
        use unicycle::FuturesUnordered;

        struct Profile {
            sid: MaximumSid,
            directory: PathBuf,
        }

        impl SandboxProfile for Profile {
            fn apply(&mut self, builder: &mut ProcessBuilder<'_>) {
                builder
                    .current_directory(&self.directory)
                    .app_container(self.sid.as_ref())
                    .inherit_env(false);
            }

            fn try_apply(&mut self, builder: &mut ProcessBuilder<'_>) -> anyhow::Result<()> {
                self.apply(builder);
                for name in ["SystemRoot", "LOCALAPPDATA"] {
                    let value = std::env::var_os(name)
                        .with_context(|| format!("qualification parent has no {name}"))?;
                    let directory = PathBuf::from(&value);
                    anyhow::ensure!(directory.is_absolute() && directory.is_dir());
                    builder.env(name, value);
                }
                Ok(())
            }
        }

        struct TrustedProfile {
            directory: PathBuf,
        }

        impl SandboxProfile for TrustedProfile {
            fn apply(&mut self, builder: &mut ProcessBuilder<'_>) {
                builder
                    .current_directory(&self.directory)
                    .inherit_env(false);
            }

            fn try_apply(&mut self, builder: &mut ProcessBuilder<'_>) -> anyhow::Result<()> {
                self.apply(builder);
                for name in ["SystemRoot", "LOCALAPPDATA"] {
                    let value = std::env::var_os(name)
                        .with_context(|| format!("qualification parent has no {name}"))?;
                    let directory = PathBuf::from(&value);
                    anyhow::ensure!(directory.is_absolute() && directory.is_dir());
                    builder.env(name, value);
                }
                Ok(())
            }
        }

        fn read_image(index: usize) -> anyhow::Result<(PathBuf, PathBuf)> {
            let executable = PathBuf::from(
                std::env::var_os(format!("MESH_AC_TEST_EXE_{index}"))
                    .context("provide task-owned staged fixture executables")?,
            );
            let directory = PathBuf::from(
                std::env::var_os(format!("MESH_AC_TEST_DIR_{index}"))
                    .context("provide exact-SID-accessible staged working directories")?,
            );
            anyhow::ensure!(executable.is_absolute() && executable.is_file());
            anyhow::ensure!(directory.is_absolute() && directory.is_dir());
            anyhow::ensure!(
                std::path::absolute(
                    executable
                        .parent()
                        .context("staged executable has no parent")?
                )? == std::path::absolute(&directory)?,
                "working directory must be the staged executable's directory"
            );
            Ok((executable, directory))
        }

        #[derive(Clone)]
        struct Inputs {
            sid: MaximumSid,
            executable: PathBuf,
            directory: PathBuf,
        }

        impl Inputs {
            fn read(index: usize) -> anyhow::Result<Self> {
                let sid = std::env::var(format!("MESH_AC_TEST_SID_{index}"))
                    .context("provide externally provisioned unique package SIDs")?
                    .parse()?;
                let (executable, directory) = read_image(index)?;
                Ok(Self {
                    sid,
                    executable,
                    directory,
                })
            }
        }

        #[derive(MeshPayload)]
        struct Init {
            expected_sid: Option<String>,
            ready: mesh::OneshotSender<()>,
            requests: mesh::Receiver<Request>,
            expected_directory: Vec<u16>,
        }

        #[derive(MeshPayload)]
        enum Request {
            Echo {
                value: u64,
                reply: mesh::OneshotSender<u64>,
            },
            ExercisePeer {
                endpoint: mesh::Sender<PeerRequest>,
                complete: mesh::OneshotSender<Result<(), String>>,
            },
            GetPeerEndpoint(mesh::OneshotSender<mesh::Sender<PeerRequest>>),
            GetFreshPeerEndpoint(mesh::OneshotSender<mesh::Sender<PeerRequest>>),
            ExpectPeerDenied {
                endpoint: mesh::Sender<PeerRequest>,
                complete: mesh::OneshotSender<Result<String, String>>,
            },
        }

        #[derive(MeshPayload)]
        struct PeerRequest {
            value: u64,
            reply: mesh::OneshotSender<u64>,
        }

        struct Worker {
            host: OwnedHost,
            requests: mesh::Sender<Request>,
            stdout: std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
            stderr: std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
        }

        async fn bounded<T>(
            driver: &DefaultDriver,
            future: impl Future<Output = T>,
        ) -> anyhow::Result<T> {
            (async { Some(future.await) }, async {
                PolledTimer::new(driver)
                    .sleep(Duration::from_secs(20))
                    .await;
                None
            })
                .race()
                .await
                .context("AppContainer runtime qualification timed out")
        }

        fn verify_token(expected_sid: &str) -> anyhow::Result<()> {
            verify_role_token(Some(expected_sid))
        }

        fn verify_role_token(expected_sid: Option<&str>) -> anyhow::Result<()> {
            use windows_sys::Win32::Security::EqualSid;
            use windows_sys::Win32::Security::GetTokenInformation;
            use windows_sys::Win32::Security::TOKEN_APPCONTAINER_INFORMATION;
            use windows_sys::Win32::Security::TOKEN_GROUPS;
            use windows_sys::Win32::Security::TOKEN_QUERY;
            use windows_sys::Win32::Security::TokenAppContainerSid;
            use windows_sys::Win32::Security::TokenCapabilities;
            use windows_sys::Win32::Security::TokenIsAppContainer;
            use windows_sys::Win32::System::Threading::GetCurrentProcess;
            use windows_sys::Win32::System::Threading::OpenProcessToken;

            let mut raw = std::ptr::null_mut();
            // SAFETY: the pseudo process handle is live and raw is writable.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
                return Err(std::io::Error::last_os_error()).context("opening worker token");
            }
            // SAFETY: successful OpenProcessToken returned exclusive ownership.
            let token = unsafe { OwnedHandle::from_raw_handle(raw) };
            let mut bytes = 0;
            let mut app_container = 0u32;
            // SAFETY: the token and writable output buffers are valid.
            if unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenIsAppContainer,
                    std::ptr::from_mut(&mut app_container).cast(),
                    size_of_val(&app_container) as u32,
                    &mut bytes,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error()).context("querying AppContainer state");
            }
            let Some(expected_sid) = expected_sid else {
                anyhow::ensure!(
                    app_container == 0,
                    "trusted ordinary-user hub unexpectedly has an AppContainer token"
                );
                return Ok(());
            };
            let expected: MaximumSid = expected_sid.parse()?;
            anyhow::ensure!(app_container == 1, "worker is not an AppContainer");
            let mut buffer = [0usize; 64];
            // SAFETY: the token is live and the buffer is aligned and writable.
            if unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenAppContainerSid,
                    buffer.as_mut_ptr().cast(),
                    size_of_val(&buffer) as u32,
                    &mut bytes,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error()).context("querying worker package SID");
            }
            // SAFETY: the successful query supplied a valid information record
            // and SID within the live buffer; expected owns a valid SID.
            let same_sid = unsafe {
                let info = &*buffer.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>();
                EqualSid(info.TokenAppContainer, expected.as_ptr())
            };
            anyhow::ensure!(same_sid != 0, "worker has the wrong package SID");
            // SAFETY: the token is live and the buffer is aligned and writable.
            if unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenCapabilities,
                    buffer.as_mut_ptr().cast(),
                    size_of_val(&buffer) as u32,
                    &mut bytes,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("querying worker capabilities");
            }
            // SAFETY: the successful query supplied a TOKEN_GROUPS record.
            let capabilities = unsafe { (*buffer.as_ptr().cast::<TOKEN_GROUPS>()).GroupCount };
            anyhow::ensure!(capabilities == 0, "worker has ambient token capabilities");
            Ok(())
        }

        async fn denied_peer(endpoint: mesh::Sender<PeerRequest>) -> anyhow::Result<String> {
            use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

            let (reply, _recv) = mesh::oneshot();
            endpoint.send(PeerRequest {
                value: 0xd3_11ed,
                reply,
            });
            let port: mesh::local_node::Port = endpoint.into();
            let driver = pal_async::windows::TpPool::system();
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            loop {
                match port.is_closed() {
                    Err(error) => {
                        let error = anyhow::Error::new(error);
                        anyhow::ensure!(
                            error.chain().any(|cause| {
                                cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
                                    error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32)
                                })
                            }),
                            "fresh peer failed without native access-denied evidence: {error:#}"
                        );
                        return Ok(format!("fresh peer ALPC access denied: {error:#}"));
                    }
                    Ok(true) => anyhow::bail!(
                        "fresh peer closed without access-denied evidence; closure is not denial"
                    ),
                    Ok(false) => {}
                }
                anyhow::ensure!(
                    std::time::Instant::now() < deadline,
                    "fresh peer did not produce a bounded native denial"
                );
                PolledTimer::new(&driver)
                    .sleep(Duration::from_millis(10))
                    .await;
            }
        }

        /// # Safety
        ///
        /// Must run before threads, with exclusive environment access and
        /// ownership of the trusted Mesh launcher's inherited invitation.
        pub unsafe fn worker() -> anyhow::Result<()> {
            // SAFETY: the standalone entry path supplies the capture guarantees.
            let invitation = unsafe { OwnedInvitation::capture_from_environment() }?
                .context("AppContainer worker has no invitation")?;
            mesh_process::run_mesh_host(
                invitation,
                "appcontainer-qualification",
                async |mut init: Init| {
                    verify_role_token(init.expected_sid.as_deref())?;
                    anyhow::ensure!(
                        std::path::absolute(std::env::current_dir()?)?
                            == std::ffi::OsString::from_wide(&init.expected_directory),
                        "AppContainer worker did not observe the staged image directory"
                    );
                    let (endpoint, mut peer_requests) = mesh::channel::<PeerRequest>();
                    let mut probes: FuturesUnordered<BoxFuture<'static, ()>> =
                        FuturesUnordered::new();
                    init.ready.send(());
                    enum Incoming {
                        Control(Option<Request>),
                        Peer(Option<PeerRequest>),
                        ProbeFinished,
                    }
                    loop {
                        let incoming = (
                            async { Incoming::Control(init.requests.recv().await.ok()) },
                            async { Incoming::Peer(peer_requests.recv().await.ok()) },
                            async {
                                if probes.is_empty() {
                                    std::future::pending::<()>().await;
                                }
                                probes.next().await;
                                Incoming::ProbeFinished
                            },
                        )
                            .race()
                            .await;
                        match incoming {
                            Incoming::Control(Some(Request::Echo { value, reply })) => {
                                reply.send(value.wrapping_add(1));
                            }
                            Incoming::Control(Some(Request::GetPeerEndpoint(reply))) => {
                                reply.send(endpoint.clone());
                            }
                            Incoming::Control(Some(Request::GetFreshPeerEndpoint(reply))) => {
                                let (endpoint, mut receiver) = mesh::channel::<PeerRequest>();
                                // Each transferred probe has its own receiver:
                                // a denied remote cannot fail a healthy channel.
                                probes.push(
                                    async move {
                                        if let Ok(request) = receiver.recv().await {
                                            request.reply.send(request.value.wrapping_add(1));
                                        }
                                    }
                                    .boxed(),
                                );
                                reply.send(endpoint);
                            }
                            Incoming::Control(Some(Request::ExpectPeerDenied {
                                endpoint,
                                complete,
                            })) => {
                                complete.send(
                                    denied_peer(endpoint)
                                        .await
                                        .map_err(|error| format!("{error:#}")),
                                );
                            }
                            Incoming::Control(Some(Request::ExercisePeer {
                                endpoint,
                                complete,
                            })) => {
                                // Application payload and reply exist only in the
                                // two children. Root transfers endpoints and gets
                                // a completion result, never the application data.
                                let (reply, recv) = mesh::oneshot();
                                endpoint.send(PeerRequest {
                                    value: 0xa11ce,
                                    reply,
                                });
                                let result = match recv.await {
                                    Ok(0xa11cf) => Ok(()),
                                    Ok(_) => Err("incorrect direct peer reply".to_owned()),
                                    Err(error) => Err(format!("direct peer reply failed: {error}")),
                                };
                                complete.send(result);
                            }
                            Incoming::Peer(Some(PeerRequest { value, reply })) => {
                                reply.send(value.wrapping_add(1));
                            }
                            Incoming::Control(None) => break,
                            Incoming::Peer(None) => anyhow::bail!("direct peer receiver closed"),
                            Incoming::ProbeFinished => {}
                        }
                    }
                    Ok(())
                },
            )
        }

        /// # Safety
        ///
        /// Must run before threads with exclusive environment access and
        /// ownership of the valid inherited invitation from the test launcher.
        pub unsafe fn wrong_sid_worker() -> anyhow::Result<()> {
            use std::io::Write;
            use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

            // SAFETY: the standalone entry path supplies the capture guarantees.
            let invitation = unsafe { OwnedInvitation::capture_from_environment() }?
                .context("wrong-SID worker has no invitation")?;
            let expected_sid = std::env::args()
                .nth(2)
                .context("missing actual package SID")?;
            verify_token(&expected_sid)?;
            std::io::stdout().write_all(b"wrong-sid-token-verified\n")?;
            std::io::stdout().flush()?;
            let error = mesh_process::run_mesh_host(
                invitation,
                "wrong-sid-qualification",
                async |_: ()| -> anyhow::Result<()> {
                    anyhow::bail!("wrong-SID worker unexpectedly received host initialization")
                },
            )
            .expect_err("wrong-SID worker unexpectedly completed");
            anyhow::ensure!(
                error.to_string() == "failed to join mesh",
                "wrong-SID failure was not at mesh join: {error:#}"
            );
            anyhow::ensure!(
                error.chain().any(|cause| {
                    cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
                        error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32)
                    })
                }),
                "wrong-SID join did not report ERROR_ACCESS_DENIED: {error:#}"
            );
            std::io::stderr()
                .write_all(format!("wrong-SID denial stage: {error:#}\n").as_bytes())?;
            std::io::stderr().flush()?;
            std::io::stdout().write_all(b"wrong-sid-mesh-join-access-denied\n")?;
            std::io::stdout().flush()?;
            Ok(())
        }

        async fn wait_process(
            driver: &DefaultDriver,
            process: &pal::windows::Process,
        ) -> anyhow::Result<u32> {
            loop {
                if let Some(status) = process.try_wait()? {
                    return Ok(status);
                }
                PolledTimer::new(driver)
                    .sleep(Duration::from_millis(10))
                    .await;
            }
        }

        async fn wrong_sid_denial(
            driver: &DefaultDriver,
            allowed_sid: &MaximumSid,
            actual: &Inputs,
            allowed_peer: Option<&MaximumSid>,
        ) -> anyhow::Result<()> {
            use pal::windows::process::Stdio;

            let node = mesh_remote::windows::AlpcNode::new(driver.clone())?;
            let (invited_port, held_port) = mesh::local_node::Port::new_pair();
            let (invitation, invitation_handle) = if let Some(peer) = allowed_peer {
                node.invite_app_container_with_peer(
                    invited_port,
                    allowed_sid.as_ref(),
                    peer.as_ref(),
                )?
            } else {
                node.invite_app_container(invited_port, allowed_sid.as_ref())?
            };
            let (credentials, directory) = invitation.into_parts();
            let encoded = base64::engine::general_purpose::STANDARD.encode(mesh::payload::encode(
                WireInvitation {
                    node_name: "wrong-sid-qualification".into(),
                    credentials,
                    directory_handle: directory.as_raw_handle() as usize,
                },
            ));
            let result = async {
                let job = pal::windows::job::Job::new()?;
                job.set_terminate_on_close()?;
                let (stdout_read, stdout_write) = pipe::pair()?;
                let (stderr_read, stderr_write) = pipe::pair()?;
                let stdout = capture_output(stdout_read);
                let stderr = capture_output(stderr_read);
                let mut command = std::ffi::OsString::from("\"");
                command.push(&actual.executable);
                command.push("\" appcontainer-wrong-sid ");
                command.push(actual.sid.to_string_sid());
                let mut builder = ProcessBuilder::new(command);
                builder
                    .application_name(&actual.executable)
                    .stdin(Stdio::Null)
                    .stdout(Stdio::Handle(stdout_write.as_handle()))
                    .stderr(Stdio::Handle(stderr_write.as_handle()))
                    .job(job.as_handle());
                Profile {
                    sid: actual.sid,
                    directory: actual.directory.clone(),
                }
                .try_apply(&mut builder)?;
                builder.handle(&directory).env(ENV, encoded);
                let process =
                    std::thread::scope(|scope| scope.spawn(move || builder.spawn()).join())
                        .map_err(|_| anyhow::anyhow!("wrong-SID process spawn thread panicked"))?
                        .context("wrong-SID process creation failed, not an ALPC denial")?;
                drop(stdout_write);
                drop(stderr_write);
                let status = match bounded(driver, wait_process(driver, &process)).await {
                    Ok(status) => status?,
                    Err(error) => {
                        process.kill(1)?;
                        bounded(driver, wait_process(driver, &process)).await??;
                        return Err(error)
                            .context("wrong-SID join did not produce a bounded denial");
                    }
                };
                let stdout = stdout.recv_timeout(Duration::from_secs(5))??;
                let stderr = stderr.recv_timeout(Duration::from_secs(5))??;
                anyhow::ensure!(
                    status == 0,
                    "wrong-SID child failed before proving denial: stdout={}, stderr={}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );
                anyhow::ensure!(
                    stdout == b"wrong-sid-token-verified\nwrong-sid-mesh-join-access-denied\n",
                    "wrong-SID child did not prove actual token and join denial"
                );
                print!("{}", String::from_utf8_lossy(&stderr));
                drop(job);
                Ok(())
            }
            .await;
            drop(invitation_handle);
            drop(held_port);
            bounded(driver, node.shutdown()).await?;
            result
        }

        async fn launch(
            mesh: &Mesh,
            driver: &DefaultDriver,
            inputs: Inputs,
            peer_sids: &[MaximumSid],
        ) -> anyhow::Result<Worker> {
            let expected_sid = inputs.sid.to_string_sid();
            let directory = inputs.directory.clone();
            let mut config = ProcessConfig::new_with_sandbox(
                "appcontainer-worker",
                Box::new(Profile {
                    sid: inputs.sid,
                    directory: inputs.directory,
                }),
            )
            .process_name(inputs.executable)
            .args(["appcontainer-worker"])
            .skip_worker_arg(true);
            for peer in peer_sids {
                config = config.app_container_peer(peer.as_ref());
            }
            launch_config(mesh, driver, config, Some(expected_sid), directory).await
        }

        async fn launch_trusted(
            mesh: &Mesh,
            driver: &DefaultDriver,
            executable: PathBuf,
            directory: PathBuf,
            peers: &[MaximumSid],
        ) -> anyhow::Result<Worker> {
            let mut config = ProcessConfig::new_with_sandbox(
                "trusted-ordinary-hub",
                Box::new(TrustedProfile {
                    directory: directory.clone(),
                }),
            )
            .process_name(executable)
            .args(["appcontainer-worker"])
            .skip_worker_arg(true);
            for peer in peers {
                config = config.trusted_host_app_container_peer(peer.as_ref());
            }
            launch_config(mesh, driver, config, None, directory).await
        }

        async fn launch_config(
            mesh: &Mesh,
            driver: &DefaultDriver,
            config: ProcessConfig,
            expected_sid: Option<String>,
            directory: PathBuf,
        ) -> anyhow::Result<Worker> {
            let (requests, recv) = mesh::channel();
            let (ready, ready_recv) = mesh::oneshot();
            let (stdout_read, stdout_write) = pipe::pair()?;
            let (stderr_read, stderr_write) = pipe::pair()?;
            let stdout = capture_output(stdout_read);
            let stderr = capture_output(stderr_read);
            let expected_directory = std::path::absolute(&directory)?
                .as_os_str()
                .encode_wide()
                .collect();
            let mut pending = mesh.begin_launch_host_owned(
                config.stdout(Some(stdout_write)).stderr(Some(stderr_write)),
                Init {
                    expected_sid,
                    ready,
                    requests: recv,
                    expected_directory,
                },
            );
            let host = match bounded(driver, pending.wait_host())
                .await
                .and_then(std::convert::identity)
            {
                Ok(host) => host,
                Err(error) => {
                    pending
                        .cancel()
                        .context("cancelling failed fixture launch")?;
                    let completion = bounded(driver, pending.wait_completion()).await??;
                    return Err(error).with_context(|| {
                        format!("fixture launch failed; root-only completion: {completion:?}")
                    });
                }
            };
            let mut worker = Worker {
                host,
                requests,
                stdout,
                stderr,
            };
            match bounded(driver, ready_recv)
                .await
                .and_then(|result| result.map_err(anyhow::Error::from))
            {
                Ok(()) => {}
                Err(error) => {
                    worker.host.terminate_root()?;
                    bounded(driver, worker.host.wait_root()).await??;
                    let stderr = worker.stderr.recv_timeout(Duration::from_secs(5))??;
                    anyhow::bail!(
                        "actual qualification worker failed: {error:#}; stderr: {}",
                        String::from_utf8_lossy(&stderr)
                    );
                }
            }
            Ok(worker)
        }

        async fn echo(driver: &DefaultDriver, worker: &Worker, value: u64) -> anyhow::Result<()> {
            let (reply, recv) = mesh::oneshot();
            worker.requests.send(Request::Echo { value, reply });
            anyhow::ensure!(bounded(driver, recv).await?? == value + 1);
            Ok(())
        }

        async fn direct_peer(
            driver: &DefaultDriver,
            source: &Worker,
            destination: &Worker,
        ) -> anyhow::Result<()> {
            let (send_endpoint, recv_endpoint) = mesh::oneshot();
            destination
                .requests
                .send(Request::GetPeerEndpoint(send_endpoint));
            let endpoint = bounded(driver, recv_endpoint).await??;
            let (complete, recv) = mesh::oneshot();
            source
                .requests
                .send(Request::ExercisePeer { endpoint, complete });
            bounded(driver, recv)
                .await??
                .map_err(anyhow::Error::msg)
                .context("child-to-child Mesh exchange without root application relay")?;
            Ok(())
        }

        async fn fresh_endpoint(
            driver: &DefaultDriver,
            destination: &Worker,
        ) -> anyhow::Result<mesh::Sender<PeerRequest>> {
            let (send, recv) = mesh::oneshot();
            destination
                .requests
                .send(Request::GetFreshPeerEndpoint(send));
            bounded(driver, recv).await?.map_err(anyhow::Error::from)
        }

        async fn direct_fresh_peer(
            driver: &DefaultDriver,
            source: &Worker,
            destination: &Worker,
        ) -> anyhow::Result<()> {
            let endpoint = fresh_endpoint(driver, destination).await?;
            let (complete, recv) = mesh::oneshot();
            source
                .requests
                .send(Request::ExercisePeer { endpoint, complete });
            bounded(driver, recv)
                .await??
                .map_err(anyhow::Error::msg)
                .context("fresh child-to-child exchange without root application relay")
        }

        async fn expect_fresh_peer_denial(
            driver: &DefaultDriver,
            source: &Worker,
            destination: &Worker,
            label: &str,
        ) -> anyhow::Result<()> {
            // Both workers have already joined their own valid invitation,
            // checked their token and directory, and acknowledged initialization.
            echo(driver, source, 70).await?;
            echo(driver, destination, 80).await?;
            let endpoint = fresh_endpoint(driver, destination).await?;
            let (complete, recv) = mesh::oneshot();
            source
                .requests
                .send(Request::ExpectPeerDenied { endpoint, complete });
            let evidence = bounded(driver, recv)
                .await??
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("{label}: no native peer-denial evidence"))?;
            println!("{label}: {evidence}");
            echo(driver, source, 90).await?;
            echo(driver, destination, 100).await?;
            Ok(())
        }

        async fn check_trusted_star(
            driver: &DefaultDriver,
            hub: &Worker,
            first: &Worker,
            second: &Worker,
        ) -> anyhow::Result<()> {
            echo(driver, hub, 10).await?;
            for worker in [first, second] {
                echo(driver, worker, 20).await?;
                direct_fresh_peer(driver, hub, worker).await?;
                direct_fresh_peer(driver, worker, hub).await?;
            }
            Ok(())
        }

        async fn stop_worker(driver: &DefaultDriver, mut worker: Worker) -> anyhow::Result<()> {
            let terminated = worker.host.terminate_root();
            let exited = bounded(driver, worker.host.wait_root()).await;
            terminated?;
            exited??;
            expect_output(worker.stdout, b"")?;
            expect_output(worker.stderr, b"")?;
            Ok(())
        }

        pub fn run_trusted_host_star() -> anyhow::Result<()> {
            // Role 1 is explicitly an ordinary process: never read SID_1 or
            // synthesize a package identity for its endpoint.
            let (hub_executable, hub_directory) = read_image(1)?;
            let first_inputs = Inputs::read(2)?;
            let second_inputs = Inputs::read(3)?;
            let rogue_inputs = Inputs::read(4)?;
            let mut unique = std::collections::HashSet::new();
            for inputs in [&first_inputs, &second_inputs, &rogue_inputs] {
                anyhow::ensure!(
                    unique.insert(inputs.sid.to_string_sid()),
                    "confined roles 2, 3, and 4 must have distinct package SIDs"
                );
            }
            let allowed = [first_inputs.sid, second_inputs.sid];
            let replacement_inputs = first_inputs.clone();
            DefaultPool::run_with(async |driver| {
                let mesh = Mesh::new("actual-trusted-host-star".into())?;
                let mut workers = Vec::new();
                let result: anyhow::Result<()> = async {
                    workers.push(
                        launch_trusted(
                            &mesh,
                            &driver,
                            hub_executable,
                            hub_directory,
                            &allowed,
                        )
                        .await?,
                    );
                    // Ordinary current-user reverse connection is already
                    // authorized by each real worker's own-SID invitation.
                    // No worker receives a fictitious hub package SID.
                    for inputs in [first_inputs, second_inputs, rogue_inputs] {
                        workers.push(launch(&mesh, &driver, inputs, &[]).await?);
                    }
                    println!(
                        "trusted hub verified non-AppContainer; confined roles 2/3/4 verified exact SID, zero capabilities, staged directory, and valid Mesh initialization"
                    );
                    check_trusted_star(&driver, &workers[0], &workers[1], &workers[2])
                        .await?;
                    expect_fresh_peer_denial(
                        &driver,
                        &workers[1],
                        &workers[2],
                        "confined worker 2 -> confined worker 3",
                    )
                    .await?;
                    check_trusted_star(&driver, &workers[0], &workers[1], &workers[2])
                        .await?;
                    expect_fresh_peer_denial(
                        &driver,
                        &workers[3],
                        &workers[0],
                        "confined wrong-SID role 4 -> ordinary trusted hub",
                    )
                    .await?;
                    check_trusted_star(&driver, &workers[0], &workers[1], &workers[2])
                        .await?;

                    workers[1].host.terminate_root()?;
                    bounded(&driver, workers[1].host.wait_root()).await??;
                    echo(&driver, &workers[0], 110).await?;
                    direct_fresh_peer(&driver, &workers[0], &workers[2]).await?;
                    direct_fresh_peer(&driver, &workers[2], &workers[0]).await?;

                    // The retained external profile/image is reused only
                    // after root exit. Whole-job emptiness is NOT proven here.
                    let replacement =
                        launch(&mesh, &driver, replacement_inputs, &[]).await?;
                    // SAFETY: both retained process handles remain live; the
                    // old one refers to the process whose OS exit was observed.
                    let same_process = unsafe {
                        windows_sys::Win32::Foundation::CompareObjectHandles(
                            workers[1].host.as_handle().as_raw_handle(),
                            replacement.host.as_handle().as_raw_handle(),
                        )
                    };
                    // Register cleanup ownership before any assertion can fail.
                    workers.push(replacement);
                    anyhow::ensure!(same_process == 0, "replacement reused the old process object");
                    check_trusted_star(&driver, &workers[0], &workers[4], &workers[2])
                        .await?;
                    echo(&driver, &workers[3], 120).await?;
                    Ok(())
                }
                .await;
                let mut errors = Vec::new();
                if let Err(error) = result {
                    errors.push(format!("{error:#}"));
                }
                // Attempt cleanup of every exact owned root even if an earlier
                // assertion or another root's cleanup failed.
                for worker in workers {
                    if let Err(error) = stop_worker(&driver, worker).await {
                        errors.push(format!("owned fixture root cleanup: {error:#}"));
                    }
                }
                if let Err(error) = bounded(&driver, mesh.shutdown()).await {
                    errors.push(format!("fixture mesh shutdown: {error:#}"));
                }
                anyhow::ensure!(errors.is_empty(), "{}", errors.join("\n"));
                println!(
                    "trusted ordinary hub and both exact-SID workers exchanged direct typed data/replies; same-SID worker root replacement passed (root-exit proof only)"
                );
                Ok(())
            })
        }

        pub fn run() -> anyhow::Result<()> {
            let first_inputs = Inputs::read(1)?;
            let second_inputs = Inputs::read(2)?;
            anyhow::ensure!(
                first_inputs.sid.to_string_sid() != second_inputs.sid.to_string_sid(),
                "qualification requires two distinct package SIDs"
            );
            DefaultPool::run_with(async |driver| {
                let mesh = Mesh::new("actual-appcontainer-runtime".into())?;
                let result = async {
                    let allowed_sid = first_inputs.sid;
                    let wrong_sid_inputs = second_inputs.clone();
                    let first =
                        launch(&mesh, &driver, first_inputs, &[wrong_sid_inputs.sid]).await?;
                    let mut second = launch(&mesh, &driver, second_inputs, &[allowed_sid]).await?;
                    echo(&driver, &first, 10).await?;
                    echo(&driver, &second, 20).await?;
                    direct_peer(&driver, &first, &second).await?;
                    direct_peer(&driver, &second, &first).await?;
                    wrong_sid_denial(&driver, &allowed_sid, &wrong_sid_inputs, None).await?;
                    echo(&driver, &second, 25).await?;
                    let observer =
                        pal::windows::Process::from(first.host.as_handle().try_clone_to_owned()?);
                    drop(first);
                    bounded(&driver, async {
                        while observer.try_wait()?.is_none() {
                            PolledTimer::new(&driver)
                                .sleep(Duration::from_millis(10))
                                .await;
                        }
                        anyhow::Ok(())
                    })
                    .await??;
                    echo(&driver, &second, 30).await?;
                    second.host.terminate_root()?;
                    bounded(&driver, second.host.wait_root()).await??;
                    expect_output(second.stdout, b"")?;
                    expect_output(second.stderr, b"")?;
                    anyhow::Ok(())
                }
                .await;
                bounded(&driver, mesh.shutdown()).await?;
                result
            })?;
            println!(
                "actual AppContainer token, root control, direct two-SID child Mesh data/reply, wrong-SID join denial, and sibling survival passed"
            );
            Ok(())
        }

        pub fn run_star() -> anyhow::Result<()> {
            let leaf_count = match std::env::var("MESH_AC_TEST_LEAF_COUNT") {
                Ok(value) => value.parse::<usize>()?,
                Err(std::env::VarError::NotPresent) => 2,
                Err(error) => return Err(error.into()),
            };
            anyhow::ensure!(
                leaf_count >= 2,
                "star qualification requires at least two leaves"
            );
            let last_index = leaf_count.checked_add(1).context("too many star leaves")?;
            let hub_inputs = Inputs::read(1)?;
            let leaf_inputs = (2..=last_index)
                .map(Inputs::read)
                .collect::<anyhow::Result<Vec<_>>>()?;
            let hub_sid = hub_inputs.sid;
            let leaf_sids: Vec<_> = leaf_inputs.iter().map(|inputs| inputs.sid).collect();
            let mut unique = std::collections::HashSet::new();
            unique.insert(hub_sid.to_string_sid());
            for sid in &leaf_sids {
                anyhow::ensure!(
                    unique.insert(sid.to_string_sid()),
                    "every star role must have a distinct package SID"
                );
            }
            let denied_leaf = leaf_inputs[1].clone();
            let denied_endpoint_owner = leaf_sids[0];
            let replacement_inputs = leaf_inputs[0].clone();
            DefaultPool::run_with(async |driver| {
                let mesh = Mesh::new("actual-appcontainer-star".into())?;
                let result = async {
                    let mut hub = launch(&mesh, &driver, hub_inputs, &leaf_sids).await?;
                    let mut leaves = Vec::new();
                    for inputs in leaf_inputs {
                        // A leaf receives exactly its hub's SID, never another leaf.
                        leaves.push(launch(&mesh, &driver, inputs, &[hub_sid]).await?);
                    }
                    for leaf in &leaves {
                        echo(&driver, leaf, 10).await?;
                        direct_peer(&driver, &hub, leaf).await?;
                        direct_peer(&driver, leaf, &hub).await?;
                    }
                    // Verify an actual leaf-B2 token cannot join an invitation
                    // authorizing leaf-B1 plus hub-A. This is join/bootstrap
                    // denial, not a claim about an isolated PORT_CONNECT check.
                    wrong_sid_denial(
                        &driver,
                        &denied_endpoint_owner,
                        &denied_leaf,
                        Some(&hub_sid),
                    )
                    .await?;
                    let mut first = leaves.remove(0);
                    first.host.terminate_root()?;
                    bounded(&driver, first.host.wait_root()).await??;
                    expect_output(first.stdout, b"")?;
                    expect_output(first.stderr, b"")?;
                    for leaf in &leaves {
                        direct_peer(&driver, &hub, leaf).await?;
                        direct_peer(&driver, leaf, &hub).await?;
                    }
                    // The external profile/image guard remains owned by the
                    // qualifier. Only the old root is proven exited here;
                    // this does not assert descendant/domain-wide cleanup.
                    let mut replacement =
                        launch(&mesh, &driver, replacement_inputs, &[hub_sid]).await?;
                    // SAFETY: both retained process handles are live, including
                    // the old process handle retained after confirmed OS exit.
                    let same_process = unsafe {
                        windows_sys::Win32::Foundation::CompareObjectHandles(
                            first.host.as_handle().as_raw_handle(),
                            replacement.host.as_handle().as_raw_handle(),
                        )
                    };
                    anyhow::ensure!(
                        same_process == 0,
                        "replacement reused the old process object"
                    );
                    drop(first.host);
                    drop(first.requests);
                    direct_peer(&driver, &hub, &replacement).await?;
                    direct_peer(&driver, &replacement, &hub).await?;
                    for leaf in &leaves {
                        direct_peer(&driver, &hub, leaf).await?;
                        direct_peer(&driver, leaf, &hub).await?;
                    }
                    replacement.host.terminate_root()?;
                    bounded(&driver, replacement.host.wait_root()).await??;
                    expect_output(replacement.stdout, b"")?;
                    expect_output(replacement.stderr, b"")?;
                    for mut leaf in leaves {
                        leaf.host.terminate_root()?;
                        bounded(&driver, leaf.host.wait_root()).await??;
                        expect_output(leaf.stdout, b"")?;
                        expect_output(leaf.stderr, b"")?;
                    }
                    hub.host.terminate_root()?;
                    bounded(&driver, hub.host.wait_root()).await??;
                    expect_output(hub.stdout, b"")?;
                    expect_output(hub.stderr, b"")?;
                    anyhow::Ok(())
                }
                .await;
                bounded(&driver, mesh.shutdown()).await?;
                result
            })?;
            println!(
                "actual AppContainer star: {leaf_count} leaves, direct hub/leaf data+reply, cross-leaf join denial, same-SID root replacement, and sibling survival passed (root-exit proof only)"
            );
            Ok(())
        }
    }

    fn environment_probe(mode: &str) -> anyhow::Result<()> {
        let (ambient, explicit, removed) = match mode {
            "default" | "clear-reenable" => (
                Some("ambient"),
                Some("ambient-explicit"),
                Some("ambient-removed"),
            ),
            "empty" | "clear" => (None, None, None),
            "preserve" | "clear-explicit" => (None, Some("explicit"), None),
            "reenable" => (Some("ambient"), Some("explicit"), None),
            _ => anyhow::bail!("unknown environment probe {mode}"),
        };
        for (name, expected) in [(AMBIENT, ambient), (EXPLICIT, explicit), (REMOVED, removed)] {
            anyhow::ensure!(
                std::env::var_os(name).as_deref() == expected.map(std::ffi::OsStr::new),
                "{mode}: unexpected {name}"
            );
        }
        Ok(())
    }

    fn pal_environment_child(mode: &str) -> anyhow::Result<()> {
        let exe = std::env::current_exe()?;
        #[cfg(unix)]
        let mut builder = {
            let mut builder = ProcessBuilder::new(&exe);
            builder.args(["env-probe", mode]);
            builder
        };
        #[cfg(windows)]
        let mut builder = {
            let mut command = std::ffi::OsString::from("\"");
            command.push(&exe);
            command.push("\" env-probe ");
            command.push(mode);
            let mut builder = ProcessBuilder::new(command);
            builder.application_name(&exe);
            builder
        };
        match mode {
            "default" => {}
            "empty" => {
                builder.inherit_env(false);
            }
            "preserve" | "reenable" | "clear" | "clear-reenable" => {
                builder.env(EXPLICIT, "explicit").env_remove(REMOVED);
                if mode.starts_with("clear") {
                    builder.env_clear();
                } else {
                    builder.inherit_env(false);
                }
                if matches!(mode, "reenable" | "clear-reenable") {
                    builder.inherit_env(true);
                }
            }
            "clear-explicit" => {
                builder.env_clear().env(EXPLICIT, "explicit");
            }
            _ => anyhow::bail!("unknown environment setup {mode}"),
        }
        wait_pal_child(builder, mode)
    }

    fn wait_pal_child(builder: ProcessBuilder<'_>, mode: &str) -> anyhow::Result<()> {
        #[cfg(unix)]
        let mut child = builder.spawn()?;
        #[cfg(windows)]
        let child = builder.spawn()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait()? {
                #[cfg(unix)]
                anyhow::ensure!(status.success(), "{mode}: {status}");
                #[cfg(windows)]
                anyhow::ensure!(status == 0, "{mode}: {status}");
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                #[cfg(unix)]
                {
                    child.kill()?;
                    child.wait()?;
                }
                #[cfg(windows)]
                {
                    child.kill(1)?;
                    child.wait();
                }
                anyhow::bail!("{mode} PAL child timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn environment_suite() -> anyhow::Result<()> {
        environment_probe("default")?;
        #[cfg(target_os = "linux")]
        let mut resources = InheritableResources::new()?;
        #[cfg(target_os = "linux")]
        let identities = resources.identities()?;
        for mode in [
            "default",
            "empty",
            "preserve",
            "reenable",
            "clear",
            "clear-reenable",
            "clear-explicit",
        ] {
            pal_environment_child(mode)?;
        }
        #[cfg(target_os = "linux")]
        {
            resources.verify_usable()?;
            fd3_mapping_case(&identities)?;
            resources.verify_usable()?;
        }
        #[cfg(target_os = "linux")]
        let probe = Some(identities.as_str());
        #[cfg(windows)]
        let probe = None;
        DefaultPool::run_with(async |driver| {
            launch_child(&driver, "joined-filtered", false, probe).await?;
            #[cfg(target_os = "linux")]
            resources.verify_usable()?;
            launch_child(&driver, "joined-inherited", false, probe).await?;
            #[cfg(target_os = "linux")]
            resources.verify_usable()?;
            anyhow::Ok(())
        })
    }

    #[cfg(target_os = "linux")]
    fn fd3_mapping_case(identities: &str) -> anyhow::Result<()> {
        use std::os::fd::AsFd;
        use std::os::fd::AsRawFd;

        let (source, _peer) = std::os::unix::net::UnixStream::pair()?;
        let (device, inode) = socket_identity(source.as_raw_fd() as usize)?;
        let mut builder = ProcessBuilder::new(std::env::current_exe()?);
        builder
            .args(["fd3-helper", &device.to_string(), &inode.to_string()])
            .env(FD_PROBE, format!("absent;{identities}"))
            .dup_fd(source.as_fd(), 3);
        wait_pal_child(builder, "fd3-helper")
    }

    #[cfg(target_os = "linux")]
    fn fd3_helper(mode: &str) -> anyhow::Result<()> {
        use std::os::fd::AsFd;
        use std::os::fd::FromRawFd;

        let device = std::env::args()
            .nth(2)
            .context("missing fd3 device")?
            .parse()?;
        let inode = std::env::args()
            .nth(3)
            .context("missing fd3 inode")?
            .parse()?;
        anyhow::ensure!(socket_identity(3)? == (device, inode));
        if matches!(mode, "fd3-probe" | "fd3-exec-probe") {
            anyhow::ensure!(
                std::env::var_os(FD_PROBE).is_some(),
                "missing fd identity policy"
            );
            check_unrelated_fds()?;
            anyhow::ensure!(std::env::var(EXPLICIT)? == "explicit");
            anyhow::ensure!(std::env::var_os(AMBIENT).is_none());
            anyhow::ensure!(std::env::var_os(ENV).is_none());
            if mode == "fd3-exec-probe" {
                return Ok(());
            }
            let mut probe = Command::new(std::env::current_exe()?);
            probe.args(["fd3-exec-probe", &device.to_string(), &inode.to_string()]);
            return wait_child(probe, "fd3-exec-probe");
        }
        // SAFETY: our dedicated launcher mapped this live socket to fd3 and
        // transferred ownership to this standalone, single-threaded helper.
        let source = unsafe { std::os::fd::OwnedFd::from_raw_fd(3) };
        let mut builder = ProcessBuilder::new(std::env::current_exe()?);
        builder
            .args(["fd3-probe", &device.to_string(), &inode.to_string()])
            .set_close_fds(true)
            .inherit_env(false)
            .env(EXPLICIT, "explicit")
            .env(FD_PROBE, std::env::var(FD_PROBE)?)
            .dup_fd(source.as_fd(), 3);
        wait_pal_child(builder, "fd3-probe")
    }

    #[cfg(target_os = "linux")]
    fn close_range_denial(errno: i32) -> anyhow::Result<()> {
        use pal::unix::process::SandboxFailureMode;
        use pal::unix::process::Stdio;
        use std::io::Read;
        use std::io::Seek;
        use std::os::fd::AsFd;
        use std::os::fd::FromRawFd;

        anyhow::ensure!(matches!(errno, libc::ENOSYS | libc::EPERM | 256));
        // SAFETY: the name is NUL-terminated and the flags are valid.
        let raw =
            unsafe { libc::memfd_create(c"mesh-close-range-denial".as_ptr(), libc::MFD_CLOEXEC) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()).context("creating execution marker");
        }
        // SAFETY: memfd_create returned a new descriptor with exclusive ownership.
        let mut marker = unsafe { std::fs::File::from_raw_fd(raw) };
        let exe = std::env::current_exe()?;
        let mut filter = [
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 0, // seccomp_data.nr
            },
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: libc::SYS_close_range as u32,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | errno as u32,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: this dedicated single-threaded subprocess changes only its own
        // privilege state. No caller/harness process or machine policy is changed.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error()).context("setting no_new_privs");
        }
        // SAFETY: program references a live, valid BPF array for this syscall.
        // This test filter deliberately denies only close_range, not a sandbox.
        if unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                std::ptr::from_ref(&program),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("installing close_range test denial");
        }

        // Control: the filter still permits exec and the marker detects execution.
        let mut control = ProcessBuilder::new(&exe);
        control
            .arg("close-range-workload")
            .stdout(Stdio::Fd(marker.as_fd()));
        anyhow::ensure!(control.spawn()?.wait()?.success());
        marker.rewind()?;
        let mut output = Vec::new();
        marker.read_to_end(&mut output)?;
        anyhow::ensure!(output == b"workload executed");
        marker.set_len(0)?;
        marker.rewind()?;

        for mode in [
            SandboxFailureMode::Silent,
            SandboxFailureMode::Warn,
            SandboxFailureMode::Error,
        ] {
            let mut builder = ProcessBuilder::new(&exe);
            builder
                .arg("close-range-workload")
                .stdout(Stdio::Fd(marker.as_fd()))
                .set_close_fds(true)
                .set_sandbox_failure_mode(mode);
            match builder.spawn() {
                Err(error) => anyhow::ensure!(
                    error.raw_os_error() == Some(errno),
                    "close_range denial returned {error}, expected errno {errno}"
                ),
                Ok(mut child) => {
                    child.wait()?;
                    anyhow::bail!("close_range denial did not prevent workload spawn");
                }
            }
            anyhow::ensure!(marker.metadata()?.len() == 0, "denied workload executed");
        }
        Ok(())
    }

    async fn launch_child(
        driver: &DefaultDriver,
        mode: &str,
        spawn_grandchild: bool,
        fd_probe: Option<&str>,
    ) -> anyhow::Result<()> {
        let mesh = Mesh::new("invitation-startup-test".into())?;
        let (ready, recv) = mesh::oneshot();
        let config = if matches!(
            mode,
            "joined-filtered" | "joined-diagnostics" | "joined-default-diagnostics"
        ) {
            ProcessConfig::new_with_sandbox("invitation-child", Box::new(NoAmbient))
        } else {
            ProcessConfig::new("invitation-child")
        };
        let config = if matches!(mode, "joined-filtered" | "joined-inherited") {
            config.env([(EXPLICIT.into(), "explicit".into())])
        } else {
            config
        };
        #[cfg(target_os = "linux")]
        let config = if let Some(identities) = fd_probe {
            let policy = if mode == "joined-filtered" {
                "absent"
            } else {
                "present"
            };
            config.env([(FD_PROBE.into(), format!("{policy};{identities}").into())])
        } else {
            config
        };
        #[cfg(windows)]
        let _ = fd_probe;
        let (config, diagnostics) = if mode == "joined-diagnostics" {
            let (stdout_read, stdout_write) = pipe::pair()?;
            let (stderr_read, stderr_write) = pipe::pair()?;
            (
                config.stdout(Some(stdout_write)).stderr(Some(stderr_write)),
                Some((capture_output(stdout_read), capture_output(stderr_read))),
            )
        } else {
            (config.stdout(None).stderr(None), None)
        };
        let mut host = mesh
            .launch_host_owned(
                config
                    .process_name(std::env::current_exe()?)
                    .args([mode])
                    .skip_worker_arg(true),
                Init {
                    value: 0x1234,
                    spawn_grandchild,
                    ready,
                },
            )
            .await?;
        let result = (
            async {
                if mode.starts_with("joined") {
                    anyhow::ensure!(recv.await? == 0x1235, "typed init was not received");
                }
                let status = host.wait_root().await?;
                #[cfg(unix)]
                anyhow::ensure!(status.success(), "mesh host failed: {status:?}");
                #[cfg(windows)]
                anyhow::ensure!(status == 0, "mesh host failed: {status}");
                anyhow::Ok(())
            },
            async {
                PolledTimer::new(driver)
                    .sleep(Duration::from_secs(30))
                    .await;
                anyhow::bail!("mesh host timed out");
            },
        )
            .race()
            .await;
        if result.is_err() {
            host.terminate_root()?;
            host.wait_root().await?;
        }
        mesh.shutdown().await;
        result?;
        if let Some((stdout, stderr)) = diagnostics {
            expect_output(stdout, STDOUT_MARKER)?;
            expect_output(stderr, STDERR_MARKER)?;
        }
        Ok(())
    }

    fn selected_by_harness() -> anyhow::Result<bool> {
        let mut args = std::env::args().skip(1);
        let mut list = false;
        let mut exact = false;
        let mut ignored = false;
        let mut filters = Vec::new();
        let mut skips = Vec::new();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--list" => list = true,
                "--exact" => exact = true,
                "--ignored" => ignored = true,
                "--skip" => skips.push(args.next().context("--skip needs a filter")?),
                "--format" | "--color" | "--test-threads" => {
                    args.next()
                        .with_context(|| format!("{arg} needs a value"))?;
                }
                "--nocapture" | "--show-output" | "--include-ignored" | "--test" | "--quiet"
                | "-q" => {}
                _ if arg.starts_with('-') => anyhow::bail!("unsupported test argument {arg}"),
                _ => filters.push(arg),
            }
        }
        let matches = |filter: &String| {
            if exact {
                TEST_NAME == filter
            } else {
                TEST_NAME.contains(filter)
            }
        };
        let selected = !ignored
            && (filters.is_empty() || filters.iter().any(matches))
            && !skips.iter().any(matches);
        if list && selected {
            println!("{TEST_NAME}: test");
        }
        Ok(selected && !list)
    }

    pub fn main() -> anyhow::Result<()> {
        if let Some(mode) = std::env::args().nth(1)
            && matches!(
                mode.as_str(),
                "absent"
                    | "malformed"
                    | "non-unicode"
                    | "joined"
                    | "joined-filtered"
                    | "joined-inherited"
                    | "joined-diagnostics"
                    | "joined-default-diagnostics"
                    | "drop"
                    | "join-failure"
                    | "ordinary-probe"
                    | "env-suite"
                    | "env-probe"
                    | "fd3-helper"
                    | "fd3-probe"
                    | "fd3-exec-probe"
                    | "close-range-denied"
                    | "close-range-workload"
                    | "default-diagnostics-suite"
                    | "profile-workload"
                    | "appcontainer-qualification"
                    | "appcontainer-star-qualification"
                    | "trusted-host-star-qualification"
                    | "appcontainer-worker"
                    | "appcontainer-wrong-sid"
            )
        {
            return child(&mode);
        }
        if !selected_by_harness()? {
            return Ok(());
        }
        run_child("absent", None)?;
        run_child("malformed", Some("!".into()))?;
        #[cfg(unix)]
        let non_unicode = {
            use std::os::unix::ffi::OsStringExt;
            std::ffi::OsString::from_vec(vec![0xff])
        };
        #[cfg(windows)]
        let non_unicode = {
            use std::os::windows::ffi::OsStringExt;
            std::ffi::OsString::from_wide(&[0xd800])
        };
        run_child("non-unicode", Some(non_unicode))?;
        let mut environment = Command::new(std::env::current_exe()?);
        environment
            .arg("env-suite")
            .env_remove(ENV)
            .env(AMBIENT, "ambient")
            .env(EXPLICIT, "ambient-explicit")
            .env(REMOVED, "ambient-removed");
        wait_child(environment, "env-suite")?;
        default_diagnostics()?;
        #[cfg(target_os = "linux")]
        for errno in [libc::ENOSYS, libc::EPERM, 256] {
            let mut denial = Command::new(std::env::current_exe()?);
            denial
                .args(["close-range-denied", &errno.to_string()])
                .env_remove(ENV);
            wait_child(denial, "close-range-denied")?;
        }

        DefaultPool::run_with(async |driver| {
            rejected_profile(
                &driver,
                || Box::new(RejectProfile),
                "fixture profile setup rejected",
            )
            .await?;
            #[cfg(windows)]
            rejected_profile(
                &driver,
                || Box::new(BroadAppContainerProfile),
                "expected a unique package SID",
            )
            .await?;
            launch_child(&driver, "drop", false, None).await?;
            launch_child(&driver, "join-failure", false, None).await?;
            launch_child(&driver, "joined-diagnostics", false, None).await?;
            launch_child(&driver, "joined", true, None).await
        })?;
        println!(
            "invitation startup: capture, drop, join-failure cleanup, exec isolation, Mesh grandchild, threaded join, environment and descriptor policies passed"
        );
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    #[cfg(any(windows, target_os = "linux"))]
    tests::main()?;
    Ok(())
}

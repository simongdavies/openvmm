// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Owned root-process lifetime, separate from Mesh transport lifetime.

use futures::FutureExt;
use futures::future::BoxFuture;
use futures::future::Shared;
use parking_lot::Condvar;
use parking_lot::Mutex;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, BorrowedFd};
#[cfg(windows)]
use std::os::windows::io::{AsHandle, BorrowedHandle};
use std::sync::Arc;

#[cfg(unix)]
type Child = pal::unix::process::Child;
#[cfg(windows)]
type Child = pal::windows::Process;
#[cfg(unix)]
type Identity = pal::unix::process::ProcessHandle;
#[cfg(windows)]
type Identity = pal::windows::Process;

/// Actual root OS exit status, not a transport or worker-protocol notification.
#[cfg(unix)]
pub type RootExit = std::process::ExitStatus;
/// Actual root OS exit code, not a transport or worker-protocol notification.
#[cfg(windows)]
pub type RootExit = u32;

pub(crate) type ExitFuture = Shared<BoxFuture<'static, Result<RootExit, Arc<io::Error>>>>;

enum ReapCommand {
    NoChild,
    Child { child: Child, terminate: bool },
}

struct ReaperMailbox {
    command: Mutex<Option<ReapCommand>>,
    ready: Condvar,
}

/// Reserve the independent waiter before creating any native root.
pub(crate) struct PreparedRoot {
    mailbox: Option<Arc<ReaperMailbox>>,
    exit: ExitFuture,
}

impl PreparedRoot {
    pub(crate) fn new() -> io::Result<Self> {
        let mailbox = Arc::new(ReaperMailbox {
            command: Mutex::new(None),
            ready: Condvar::new(),
        });
        let waiter = mailbox.clone();
        let (send, recv) = mesh::oneshot();
        std::thread::Builder::new()
            .name("mesh-owned-reaper".into())
            .spawn(move || {
                let command = {
                    let mut command = waiter.command.lock();
                    while command.is_none() {
                        waiter.ready.wait(&mut command);
                    }
                    command.take().unwrap()
                };
                let ReapCommand::Child {
                    mut child,
                    terminate: should_terminate,
                } = command
                else {
                    return;
                };
                if should_terminate && let Err(error) = terminate(&child) {
                    tracing::error!(%error, "owned mesh rollback termination failed");
                }
                let result = match wait(&mut child) {
                    Ok(status) => Ok(status),
                    Err(error) => {
                        tracing::error!(%error, "owned mesh OS wait failed");
                        // A failed observation is not permission to discard the
                        // original child. The shared error retains its ownership.
                        Err(io::Error::new(
                            error.kind(),
                            RetainedWaitError {
                                error,
                                _child: child,
                            },
                        ))
                    }
                };
                send.send(result);
            })?;
        let exit = async move {
            recv.await
                .map_err(|_| io::Error::other("mesh OS exit waiter stopped"))?
        }
        .map(|result| result.map_err(Arc::new))
        .boxed()
        .shared();
        Ok(Self {
            mailbox: Some(mailbox),
            exit,
        })
    }

    pub(crate) fn exit(&self) -> ExitFuture {
        self.exit.clone()
    }

    pub(crate) fn reap(mut self, child: Child, terminate: bool) {
        let mailbox = self.mailbox.take().unwrap();
        *mailbox.command.lock() = Some(ReapCommand::Child { child, terminate });
        mailbox.ready.notify_one();
    }

    pub(crate) fn finish(
        self,
        child: Child,
        #[cfg(windows)] job: pal::windows::job::Job,
    ) -> io::Result<OwnedHost> {
        #[cfg(windows)]
        let pid = child.id() as i32;
        #[cfg(unix)]
        let pid = child.id();
        #[cfg(unix)]
        let identity = child.termination_handle();
        #[cfg(windows)]
        let identity = child
            .as_handle()
            .try_clone_to_owned()
            .map(pal::windows::Process::from);
        let identity = match identity {
            Ok(identity) => identity,
            Err(error) => {
                self.reap(child, true);
                return Err(error);
            }
        };
        let exit = self.exit();
        self.reap(child, false);
        Ok(OwnedHost {
            pid,
            identity,
            exit,
            termination_requested: Mutex::new(false),
            #[cfg(windows)]
            job,
        })
    }
}

impl Drop for PreparedRoot {
    fn drop(&mut self) {
        if let Some(mailbox) = self.mailbox.take() {
            *mailbox.command.lock() = Some(ReapCommand::NoChild);
            mailbox.ready.notify_one();
        }
    }
}

struct RetainedWaitError {
    error: io::Error,
    _child: Child,
}

impl std::fmt::Debug for RetainedWaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RetainedWaitError")
            .field(&self.error)
            .finish()
    }
}

impl std::fmt::Display for RetainedWaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for RetainedWaitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Exclusive launch ownership of a root process.
///
/// Dropping this object requests root termination. Call [`Self::wait_root`]
/// for actual OS exit and Unix reap evidence. Neither operation proves that
/// descendants have exited. Whole-domain cleanup requires an external,
/// independently owned containment backend; it is not implemented here.
///
/// The pid is diagnostic only. Termination uses a retained pidfd, process handle,
/// or the macOS child's synchronized reap lock.
pub struct OwnedHost {
    pid: i32,
    identity: Identity,
    exit: ExitFuture,
    termination_requested: Mutex<bool>,
    // Keep the per-host job alive after root exit: an adapter may still need to
    // inspect/terminate the domain. Closing it requests descendant termination,
    // but is not an observation that the job is empty.
    #[cfg(windows)]
    job: pal::windows::job::Job,
}

impl OwnedHost {
    /// Returns the root PID for diagnostics, not an authorization identity.
    pub fn id(&self) -> i32 {
        self.pid
    }

    /// Requests root termination without asking the child to poll or cooperate.
    /// Repeated requests, including after observed exit, are harmless.
    pub fn terminate_root(&self) -> io::Result<()> {
        let mut requested = self.termination_requested.lock();
        if *requested {
            return Ok(());
        }
        #[cfg(unix)]
        self.identity.kill()?;
        #[cfg(windows)]
        if let Err(error) = self.identity.kill(1) {
            if self.identity.try_wait()?.is_none() {
                return Err(error);
            }
        }
        *requested = true;
        Ok(())
    }

    /// Waits for actual root OS exit and Unix reaping. Cancellation and
    /// repeated waits do not consume the recorded result.
    pub async fn wait_root(&mut self) -> io::Result<RootExit> {
        self.exit
            .clone()
            .await
            .map_err(|error| io::Error::new(error.kind(), error))
    }

    /// Whole-domain cleanup is deliberately unsupported by this root API.
    pub fn terminate_domain(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "whole-domain cleanup requires an owned containment backend",
        ))
    }

    /// Borrows the per-host job for a Windows containment adapter. Root exit
    /// alone is not evidence that this job contains no active processes.
    #[cfg(windows)]
    pub fn job(&self) -> BorrowedHandle<'_> {
        self.job.as_handle()
    }

    pub(crate) fn exit(&self) -> ExitFuture {
        self.exit.clone()
    }
}

#[cfg(target_os = "linux")]
impl AsFd for OwnedHost {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.identity.as_fd()
    }
}

#[cfg(windows)]
impl AsHandle for OwnedHost {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.identity.as_handle()
    }
}

impl Drop for OwnedHost {
    fn drop(&mut self) {
        if let Err(error) = self.terminate_root() {
            tracing::error!(pid = self.pid, %error, "failed to terminate owned mesh root");
        }
    }
}

fn wait(child: &mut Child) -> io::Result<RootExit> {
    #[cfg(unix)]
    {
        loop {
            match child.wait() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result,
            }
        }
    }
    #[cfg(windows)]
    {
        child.wait_for_exit()
    }
}

fn terminate(child: &Child) -> io::Result<()> {
    #[cfg(unix)]
    child.kill()?;
    #[cfg(windows)]
    if let Err(error) = child.kill(1) {
        if child.try_wait()?.is_none() {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::Mesh;
    use crate::ProcessConfig;
    use futures_concurrency::future::Race;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pal_async::timer::PolledTimer;
    use std::time::Duration;
    use test_with_tracing::test;

    // This child deliberately never captures/joins Mesh. The owner must remain
    // usable even if native worker startup never polls a single Mesh request.
    #[test]
    #[ignore]
    fn blocking_child() {
        let path = std::env::var_os("MESH_OWNED_READY_FILE").unwrap();
        std::fs::write(path, b"ready").unwrap();
        if std::env::var_os("MESH_OWNED_TEST_EXIT").is_some() {
            std::process::exit(7);
        }
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    #[test]
    #[ignore]
    fn capability_probe_child() {
        #[cfg(target_os = "linux")]
        for entry in std::fs::read_dir("/proc/self/fd").unwrap() {
            let path = entry.unwrap().path();
            if let Ok(target) = std::fs::read_link(path) {
                assert_ne!(target, std::path::Path::new("anon_inode:[pidfd]"));
            }
        }
        #[cfg(windows)]
        {
            let raw: usize = std::env::var("MESH_TEST_ROOT_HANDLE")
                .unwrap()
                .parse()
                .unwrap();
            let pid: u32 = std::env::var("MESH_TEST_ROOT_PID")
                .unwrap()
                .parse()
                .unwrap();
            // SAFETY: GetProcessId validates the numeric handle; no ownership is adopted.
            let inherited_pid =
                unsafe { windows_sys::Win32::System::Threading::GetProcessId(raw as *mut _) };
            assert_ne!(inherited_pid, pid);
        }
    }

    pub(crate) fn config(path: &std::path::Path) -> ProcessConfig {
        ProcessConfig::new("owned-test")
            .process_name(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "owned_host::tests::blocking_child",
                "--ignored",
                "--nocapture",
            ])
            .skip_worker_arg(true)
            .env([("MESH_OWNED_READY_FILE".into(), path.as_os_str().to_owned())])
    }

    pub(crate) async fn bounded<T>(driver: &DefaultDriver, future: impl Future<Output = T>) -> T {
        (async { Some(future.await) }, async {
            PolledTimer::new(driver)
                .sleep(Duration::from_secs(15))
                .await;
            None
        })
            .race()
            .await
            .expect("owned process operation timed out")
    }

    pub(crate) async fn ready(driver: &DefaultDriver, path: &std::path::Path) {
        bounded(driver, async {
            while !path.exists() {
                PolledTimer::new(driver)
                    .sleep(Duration::from_millis(10))
                    .await;
            }
        })
        .await;
    }

    #[async_test]
    async fn blocked_startup_termination_reap_and_sibling_survival(driver: DefaultDriver) {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        let mesh = Mesh::new("owned-lifecycle-test".into()).unwrap();
        let mut host = bounded(&driver, mesh.launch_host_owned(config(&first), ()))
            .await
            .unwrap();
        let mut sibling = bounded(&driver, mesh.launch_host_owned(config(&second), ()))
            .await
            .unwrap();
        ready(&driver, &first).await;
        ready(&driver, &second).await;
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: the live pidfd is borrowed throughout this query.
            let flags = unsafe { libc::fcntl(host.as_fd().as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0);
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
        let mut probe = std::process::Command::new(std::env::current_exe().unwrap());
        probe.args([
            "--exact",
            "owned_host::tests::capability_probe_child",
            "--ignored",
            "--nocapture",
        ]);
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let raw = host.as_handle().as_raw_handle();
            let mut flags = 0;
            // SAFETY: querying our retained process handle with a valid output pointer.
            let result =
                unsafe { windows_sys::Win32::Foundation::GetHandleInformation(raw, &mut flags) };
            assert_ne!(result, 0);
            assert_eq!(
                flags & windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT,
                0
            );
            probe
                .env("MESH_TEST_ROOT_HANDLE", (raw as usize).to_string())
                .env("MESH_TEST_ROOT_PID", host.id().to_string());
        }
        assert!(probe.status().unwrap().success());
        assert_eq!(
            host.terminate_domain().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        host.terminate_root().unwrap();
        host.terminate_root().unwrap();
        // A grace timeout may abandon this wait without abandoning OS reaping.
        assert!(sibling.wait_root().now_or_never().is_none());
        let status = bounded(&driver, host.wait_root()).await.unwrap();
        assert_eq!(host.wait_root().await.unwrap(), status);
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(libc::SIGKILL));
            let mut raw_status = 0;
            // SAFETY: only checking our exited child, with a valid status pointer.
            let result = unsafe { libc::waitpid(host.id(), &mut raw_status, libc::WNOHANG) };
            assert_eq!(result, -1);
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        }
        #[cfg(windows)]
        assert_eq!(status, 1);

        // Exercise the stale identity after reap while an unrelated child lives.
        for _ in 0..8 {
            host.terminate_root().unwrap();
        }
        let mut exited = bounded(
            &driver,
            mesh.launch_host_owned(
                config(&dir.path().join("exited"))
                    .env([("MESH_OWNED_TEST_EXIT".into(), "1".into())]),
                (),
            ),
        )
        .await
        .unwrap();
        let natural_status = bounded(&driver, exited.wait_root()).await.unwrap();
        #[cfg(unix)]
        assert_eq!(natural_status.code(), Some(7));
        #[cfg(windows)]
        assert_eq!(natural_status, 7);
        // Unlike `host`, this owner has not previously requested termination.
        // Its first signal must still target the old OS identity after reap.
        exited.terminate_root().unwrap();
        assert!(sibling.exit().now_or_never().is_none());
        sibling.terminate_root().unwrap();
        bounded(&driver, sibling.wait_root()).await.unwrap();
        bounded(&driver, mesh.shutdown()).await;
    }

    #[async_test]
    async fn sibling_owners_share_ports_and_shutdown_independently(driver: DefaultDriver) {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        let parent = Mesh::new("sibling-parent".into()).unwrap();
        let first_mesh = parent.new_sibling("first-owner".into()).unwrap();
        let second_mesh = parent.new_sibling("second-owner".into()).unwrap();
        let (sender, _receiver) = mesh::channel::<u32>();
        let mut first_host = bounded(
            &driver,
            first_mesh.launch_host_owned(config(&first), sender.clone()),
        )
        .await
        .unwrap();
        let mut second_host = bounded(
            &driver,
            second_mesh.launch_host_owned(config(&second), sender),
        )
        .await
        .unwrap();
        ready(&driver, &first).await;
        ready(&driver, &second).await;
        bounded(&driver, parent.shutdown()).await;
        first_host.terminate_root().unwrap();
        bounded(&driver, first_host.wait_root()).await.unwrap();
        bounded(&driver, first_mesh.shutdown()).await;
        assert!(second_host.wait_root().now_or_never().is_none());
        second_host.terminate_root().unwrap();
        bounded(&driver, second_host.wait_root()).await.unwrap();
        bounded(&driver, second_mesh.shutdown()).await;
    }

    #[async_test]
    async fn startup_failure_and_drop_rollback(driver: DefaultDriver) {
        let dir = tempfile::tempdir().unwrap();
        let mesh = Mesh::new("owned-rollback-test".into()).unwrap();
        for key in ["MESH_WORKER_INVITATION", "MESH_WORKER_INVITATION=ignored"] {
            let reserved = mesh
                .launch_host_owned(
                    ProcessConfig::new("invalid-env").env([(key.into(), "untrusted".into())]),
                    (),
                )
                .await;
            assert!(reserved.is_err());
        }
        assert!(
            mesh.launch_host_owned(
                ProcessConfig::new("missing").process_name(dir.path().join("missing-program")),
                (),
            )
            .await
            .is_err()
        );
        let marker = dir.path().join("ready");
        let host = bounded(&driver, mesh.launch_host_owned(config(&marker), ()))
            .await
            .unwrap();
        ready(&driver, &marker).await;
        let exit = host.exit();
        drop(host);
        bounded(&driver, exit).await.unwrap();
        bounded(&driver, mesh.shutdown()).await;
    }

    #[async_test]
    async fn mesh_drop_preserves_owned_root_reaping(driver: DefaultDriver) {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ready");
        let mesh = Mesh::new("owned-mesh-drop-test".into()).unwrap();
        let mut host = bounded(&driver, mesh.launch_host_owned(config(&marker), ()))
            .await
            .unwrap();
        ready(&driver, &marker).await;
        let (send, recv) = mesh::oneshot();
        let dropper = std::thread::spawn(move || {
            drop(mesh);
            send.send(());
        });
        bounded(&driver, recv).await.unwrap();
        dropper.join().unwrap();
        host.terminate_root().unwrap();
        bounded(&driver, host.wait_root()).await.unwrap();
    }

    #[async_test]
    async fn cancelled_launch_rolls_back_without_readiness(driver: DefaultDriver) {
        let dir = tempfile::tempdir().unwrap();
        let mesh = Mesh::new("owned-cancelled-launch-test".into()).unwrap();
        // Poll once to submit the launch, then discard either the pending
        // response or an already-returned owner. Neither may orphan the root.
        drop(
            mesh.launch_host_owned(config(&dir.path().join("ready")), ())
                .now_or_never(),
        );
        bounded(&driver, mesh.shutdown()).await;
    }
}

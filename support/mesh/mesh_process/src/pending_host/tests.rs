// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::LaunchCompletion;
use super::LaunchTestHooks;
use crate::Mesh;
use crate::ProcessBuilder;
use crate::SandboxProfile;
use crate::owned_host::tests::{bounded, config};
use futures::FutureExt;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pal_async::timer::PolledTimer;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use test_with_tracing::test;

struct ReadyFile(PathBuf);

impl ReadyFile {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::current_dir().unwrap();
        for _ in 0..128 {
            let path = directory.join(format!(
                ".mesh-pending-ready-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("creating owned readiness file: {error}"),
            }
        }
        panic!("could not reserve a unique readiness file");
    }

    async fn wait(&self, driver: &DefaultDriver) {
        bounded(driver, async {
            while std::fs::read(&self.0).unwrap() != b"ready" {
                PolledTimer::new(driver)
                    .sleep(Duration::from_millis(10))
                    .await;
            }
        })
        .await;
    }
}

impl Drop for ReadyFile {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.0) {
            tracing::error!(%error, path = ?self.0, "removing owned readiness file");
        }
    }
}

fn hooks() -> LaunchTestHooks {
    LaunchTestHooks {
        before_spawn: None,
        native_entry: None,
        before_handoff: None,
        fail_before_handoff: false,
    }
}

#[async_test]
async fn abandoned_waiters_can_retry_successful_handoff(driver: DefaultDriver) {
    let marker = ReadyFile::new();
    let mesh = Mesh::new("retry-successful-handoff".into()).unwrap();
    let (before_spawn, spawn_entered) = mesh::oneshot();
    let (release_spawn, spawn_gate) = mesh::oneshot();
    let (before_handoff, handoff_entered) = mesh::oneshot();
    let (release_handoff, handoff_gate) = mesh::oneshot();
    let mut test_hooks = hooks();
    test_hooks.before_spawn = Some((before_spawn, spawn_gate));
    test_hooks.before_handoff = Some((before_handoff, handoff_gate));
    let mut pending = mesh.begin_owned(config(&marker.0), (), Some(test_hooks));

    bounded(&driver, spawn_entered).await.unwrap();
    for _ in 0..3 {
        assert!(pending.wait_host().now_or_never().is_none());
        assert!(pending.wait_completion().now_or_never().is_none());
    }
    assert!(std::fs::read(&marker.0).unwrap().is_empty());
    release_spawn.send(());

    bounded(&driver, handoff_entered).await.unwrap();
    marker.wait(&driver).await;
    for _ in 0..3 {
        assert!(pending.wait_host().now_or_never().is_none());
        assert!(pending.wait_completion().now_or_never().is_none());
    }
    release_handoff.send(());
    let mut host = bounded(&driver, pending.wait_host()).await.unwrap();
    assert_eq!(
        pending.cancel().unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(pending.wait_completion().now_or_never().is_none());
    assert!(host.wait_root().now_or_never().is_none());
    host.terminate_root().unwrap();
    let status = bounded(&driver, host.wait_root()).await.unwrap();
    for _ in 0..3 {
        assert_eq!(
            bounded(&driver, pending.wait_completion()).await.unwrap(),
            LaunchCompletion::RootExited(status)
        );
    }
    bounded(&driver, mesh.shutdown()).await;
}

#[async_test]
async fn injected_failure_after_ready_child_preserves_exit(driver: DefaultDriver) {
    let marker = ReadyFile::new();
    let mesh = Mesh::new("ready-handoff-error".into()).unwrap();
    let (entered, waiting) = mesh::oneshot();
    let (resume, gate) = mesh::oneshot();
    let mut test_hooks = hooks();
    test_hooks.before_handoff = Some((entered, gate));
    test_hooks.fail_before_handoff = true;
    let mut pending = mesh.begin_owned(config(&marker.0), (), Some(test_hooks));
    bounded(&driver, waiting).await.unwrap();
    marker.wait(&driver).await;
    assert!(pending.wait_completion().now_or_never().is_none());
    resume.send(());
    let error = bounded(&driver, pending.wait_host()).await.err().unwrap();
    assert!(
        format!("{error:#}").contains("injected pre-handoff failure"),
        "{error:#}"
    );
    let completion = bounded(&driver, pending.wait_completion()).await.unwrap();
    let LaunchCompletion::RootExited(status) = completion else {
        panic!("ready child was incorrectly reported as never spawned");
    };
    #[cfg(windows)]
    assert_eq!(status, 1);
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }
    assert_eq!(
        bounded(&driver, pending.wait_completion()).await.unwrap(),
        completion
    );
    bounded(&driver, mesh.shutdown()).await;
}

#[async_test]
async fn rejecting_profile_proves_never_spawned(driver: DefaultDriver) {
    struct Reject;

    impl SandboxProfile for Reject {
        fn apply(&mut self, _: &mut ProcessBuilder<'_>) {
            panic!("fallible profile must not fall back to infallible apply");
        }

        fn try_apply(&mut self, _: &mut ProcessBuilder<'_>) -> anyhow::Result<()> {
            anyhow::bail!("pending launch test profile rejected")
        }
    }

    let marker = ReadyFile::new();
    let mesh = Mesh::new("pending-profile-rejection".into()).unwrap();
    let mut configuration = config(&marker.0);
    configuration.sandbox_profile = Some(Box::new(Reject));
    let mut pending = mesh.begin_launch_host_owned(configuration, ());
    let error = bounded(&driver, pending.wait_host()).await.err().unwrap();
    assert!(
        format!("{error:#}").contains("pending launch test profile rejected"),
        "{error:#}"
    );
    assert_eq!(
        bounded(&driver, pending.wait_completion()).await.unwrap(),
        LaunchCompletion::NeverSpawned
    );
    assert!(std::fs::read(&marker.0).unwrap().is_empty());
    bounded(&driver, mesh.shutdown()).await;
}

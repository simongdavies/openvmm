// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::Mesh;
use crate::ProcessConfig;
use crate::owned_host::tests::{bounded, config, ready};
use pal_async::DefaultDriver;
use pal_async::async_test;
use test_with_tracing::test;

fn hooks() -> LaunchTestHooks {
    LaunchTestHooks {
        before_spawn: None,
        native_entry: None,
        before_handoff: None,
        fail_before_handoff: false,
    }
}

#[async_test]
async fn queued_cancellation_cannot_spawn_later(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let healthy_path = directory.path().join("healthy");
    let cancelled_path = directory.path().join("cancelled");
    let mesh = Mesh::new("queued-cancel".into()).unwrap();
    let (entered, waiting) = mesh::oneshot();
    let (resume, gate) = mesh::oneshot();
    let mut test_hooks = hooks();
    test_hooks.before_spawn = Some((entered, gate));
    let mut healthy = mesh.begin_owned(config(&healthy_path), (), Some(test_hooks));
    bounded(&driver, waiting).await.unwrap();
    let mut cancelled = mesh.begin_launch_host_owned(config(&cancelled_path), ());
    cancelled.cancel().unwrap();
    assert!(cancelled.wait_completion().now_or_never().is_none());
    resume.send(());
    let mut host = bounded(&driver, healthy.wait_host()).await.unwrap();
    ready(&driver, &healthy_path).await;
    assert!(bounded(&driver, cancelled.wait_host()).await.is_err());
    assert_eq!(
        bounded(&driver, cancelled.wait_completion()).await.unwrap(),
        LaunchCompletion::NeverSpawned
    );
    assert!(!cancelled_path.exists());
    assert!(host.wait_root().now_or_never().is_none());
    host.terminate_root().unwrap();
    bounded(&driver, host.wait_root()).await.unwrap();
    bounded(&driver, mesh.shutdown()).await;
}

#[async_test]
async fn captured_root_cancellation_and_waiter_retry(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("root");
    let sibling_path = directory.path().join("sibling");
    let mesh = Mesh::new("captured-cancel".into()).unwrap();
    let mut sibling = bounded(&driver, mesh.launch_host_owned(config(&sibling_path), ()))
        .await
        .unwrap();
    ready(&driver, &sibling_path).await;
    let (entered, waiting) = mesh::oneshot();
    let (resume, gate) = mesh::oneshot();
    let mut test_hooks = hooks();
    test_hooks.before_handoff = Some((entered, gate));
    let mut pending = mesh.begin_owned(config(&path), (), Some(test_hooks));
    bounded(&driver, waiting).await.unwrap();
    ready(&driver, &path).await;
    assert!(pending.wait_host().now_or_never().is_none());
    assert!(pending.wait_completion().now_or_never().is_none());
    pending.cancel().unwrap();
    let completion = bounded(&driver, pending.wait_completion()).await.unwrap();
    assert!(matches!(completion, LaunchCompletion::RootExited(_)));
    assert_eq!(pending.wait_completion().await.unwrap(), completion);
    assert!(sibling.wait_root().now_or_never().is_none());
    resume.send(());
    assert!(bounded(&driver, pending.wait_host()).await.is_err());
    sibling.terminate_root().unwrap();
    bounded(&driver, sibling.wait_root()).await.unwrap();
    bounded(&driver, mesh.shutdown()).await;
}

#[async_test]
async fn pre_handoff_error_keeps_original_root_completion(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let mesh = Mesh::new("handoff-error".into()).unwrap();
    let mut test_hooks = hooks();
    test_hooks.fail_before_handoff = true;
    let mut pending =
        mesh.begin_owned(config(&directory.path().join("root")), (), Some(test_hooks));
    let error = bounded(&driver, pending.wait_host()).await.err().unwrap();
    assert!(format!("{error:#}").contains("injected pre-handoff failure"));
    assert!(matches!(
        bounded(&driver, pending.wait_completion()).await.unwrap(),
        LaunchCompletion::RootExited(_)
    ));
    bounded(&driver, mesh.shutdown()).await;
}

#[async_test]
async fn disconnected_handoff_keeps_receipt_and_sibling(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("root");
    let sibling_path = directory.path().join("sibling");
    let mesh = Mesh::new("disconnected-handoff".into()).unwrap();
    let mut sibling = bounded(&driver, mesh.launch_host_owned(config(&sibling_path), ()))
        .await
        .unwrap();
    ready(&driver, &sibling_path).await;
    let (entered, waiting) = mesh::oneshot();
    let (_resume, gate) = mesh::oneshot();
    let mut test_hooks = hooks();
    test_hooks.before_handoff = Some((entered, gate));
    let mut pending = mesh.begin_owned(config(&path), (), Some(test_hooks));
    bounded(&driver, waiting).await.unwrap();
    ready(&driver, &path).await;
    drop(mesh);
    assert!(bounded(&driver, pending.wait_host()).await.is_err());
    pending.cancel().unwrap();
    assert!(matches!(
        bounded(&driver, pending.wait_completion()).await.unwrap(),
        LaunchCompletion::RootExited(_)
    ));
    assert!(sibling.wait_root().now_or_never().is_none());
    sibling.terminate_root().unwrap();
    bounded(&driver, sibling.wait_root()).await.unwrap();
}

#[async_test]
async fn receipt_drop_preserves_detached_completion_observer(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("root");
    let mesh = Mesh::new("dropped-receipt".into()).unwrap();
    let (entered, waiting) = mesh::oneshot();
    let (resume, gate) = mesh::oneshot();
    let mut test_hooks = hooks();
    test_hooks.before_handoff = Some((entered, gate));
    let pending = mesh.begin_owned(config(&path), (), Some(test_hooks));
    bounded(&driver, waiting).await.unwrap();
    ready(&driver, &path).await;
    let completion = pending.wait_completion();
    drop(pending);
    assert!(matches!(
        bounded(&driver, completion).await.unwrap(),
        LaunchCompletion::RootExited(_)
    ));
    resume.send(());
    bounded(&driver, mesh.shutdown()).await;
}

#[async_test]
async fn handoff_preserves_root_owner_and_completion(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("root");
    let mesh = Mesh::new("successful-handoff".into()).unwrap();
    let mut pending = mesh.begin_launch_host_owned(config(&path), ());
    let mut host = bounded(&driver, pending.wait_host()).await.unwrap();
    ready(&driver, &path).await;
    assert_eq!(
        pending.cancel().unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(pending.wait_host().await.is_err());
    let completion = pending.wait_completion();
    drop(pending);
    assert!(host.wait_root().now_or_never().is_none());
    host.terminate_root().unwrap();
    let status = bounded(&driver, host.wait_root()).await.unwrap();
    assert_eq!(
        bounded(&driver, completion).await.unwrap(),
        LaunchCompletion::RootExited(status)
    );
    bounded(&driver, mesh.shutdown()).await;
}

#[async_test]
async fn native_creation_failure_reports_actual_birth_state(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let mesh = Mesh::new("creation-error".into()).unwrap();
    let mut pending = mesh.begin_launch_host_owned(
        ProcessConfig::new("missing-executable").process_name(directory.path().join("not-present")),
        (),
    );
    assert!(bounded(&driver, pending.wait_host()).await.is_err());
    let completion = bounded(&driver, pending.wait_completion()).await.unwrap();
    #[cfg(windows)]
    assert_eq!(completion, LaunchCompletion::NeverSpawned);
    #[cfg(target_os = "linux")]
    assert!(matches!(completion, LaunchCompletion::RootExited(_)));
    bounded(&driver, mesh.shutdown()).await;
}

#[async_test]
async fn validation_failure_is_proven_never_spawned(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("root");
    let mesh = Mesh::new("validation-error".into()).unwrap();
    let mut pending = mesh.begin_launch_host_owned(
        config(&path).env([("MESH_WORKER_INVITATION".into(), "not-allowed".into())]),
        (),
    );
    assert!(bounded(&driver, pending.wait_host()).await.is_err());
    assert_eq!(
        bounded(&driver, pending.wait_completion()).await.unwrap(),
        LaunchCompletion::NeverSpawned
    );
    assert!(!path.exists());
    bounded(&driver, mesh.shutdown()).await;
}

#[async_test]
async fn cancellation_after_native_gate_captures_future_root(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let mesh = Mesh::new("native-gate-cancel".into()).unwrap();
    let (entered, waiting) = mesh::oneshot();
    let (resume, gate) = std::sync::mpsc::channel();
    let mut test_hooks = hooks();
    test_hooks.native_entry = Some((entered, gate));
    let mut pending =
        mesh.begin_owned(config(&directory.path().join("root")), (), Some(test_hooks));
    bounded(&driver, waiting).await.unwrap();
    pending.cancel().unwrap();
    assert!(pending.wait_completion().now_or_never().is_none());
    resume.send(()).unwrap();
    assert!(bounded(&driver, pending.wait_host()).await.is_err());
    assert!(matches!(
        bounded(&driver, pending.wait_completion()).await.unwrap(),
        LaunchCompletion::RootExited(_)
    ));
    bounded(&driver, mesh.shutdown()).await;
}

#[async_test]
async fn cancel_racing_native_creation_keeps_completion(driver: DefaultDriver) {
    let directory = tempfile::tempdir().unwrap();
    let mesh = Mesh::new("spawn-cancel-race".into()).unwrap();
    for iteration in 0..12 {
        let (entered, waiting) = mesh::oneshot();
        let (resume, gate) = mesh::oneshot();
        let mut test_hooks = hooks();
        test_hooks.before_spawn = Some((entered, gate));
        let mut pending = mesh.begin_owned(
            config(&directory.path().join(format!("root-{iteration}"))),
            (),
            Some(test_hooks),
        );
        bounded(&driver, waiting).await.unwrap();
        let (resumed, go) = std::sync::mpsc::channel();
        let release = std::thread::spawn(move || {
            resume.send(());
            resumed.send(()).unwrap();
        });
        if iteration % 2 == 0 {
            go.recv().unwrap();
        }
        pending.cancel().unwrap();
        release.join().unwrap();
        assert!(bounded(&driver, pending.wait_host()).await.is_err());
        let completion = bounded(&driver, pending.wait_completion()).await.unwrap();
        assert!(matches!(
            completion,
            LaunchCompletion::NeverSpawned | LaunchCompletion::RootExited(_)
        ));
        assert_eq!(pending.wait_completion().await.unwrap(), completion);
    }
    bounded(&driver, mesh.shutdown()).await;
}

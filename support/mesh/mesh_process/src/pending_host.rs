// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cancellation and root completion for an owned launch before handoff.

use crate::OwnedHost;
use crate::RootExit;
use crate::owned_host::ExitFuture;
use futures::FutureExt;
use futures::future::BoxFuture;
use futures::future::Shared;
use parking_lot::Mutex;
use std::io;
use std::sync::Arc;

/// The root-only completion evidence for one owned launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchCompletion {
    /// No root was created, and this request cannot create one later.
    NeverSpawned,
    /// The original root exited and, on Linux, was reaped.
    RootExited(RootExit),
}

type CompletionFuture = Shared<BoxFuture<'static, Result<LaunchCompletion, Arc<io::Error>>>>;

enum Assignment {
    NeverSpawned,
    Root(ExitFuture),
}

#[derive(Clone, Copy)]
enum Phase {
    BeforeNative,
    Native,
    Root,
    NoRoot,
}

struct State {
    phase: Phase,
    cancelled: bool,
    handed_off: bool,
    host: Option<OwnedHost>,
    completion: Option<mesh::OneshotSender<io::Result<Assignment>>>,
}

impl State {
    fn complete(&mut self, result: io::Result<Assignment>) {
        if let Some(send) = self.completion.take() {
            send.send(result);
        }
    }

    fn cancel(&mut self, reject_handoff: bool) -> io::Result<()> {
        if self.handed_off {
            return if reject_handoff {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "root ownership was handed off; terminate the OwnedHost instead",
                ))
            } else {
                Ok(())
            };
        }
        self.cancelled = true;
        if let Some(host) = &self.host {
            host.terminate_root()?;
        }
        Ok(())
    }
}

/// Owns an in-flight launch and its independently observable root completion.
///
/// Obtain this receipt with [`crate::Mesh::begin_launch_host_owned`] before
/// waiting for launch. Dropping a `wait_host` or `wait_completion` future leaves
/// the receipt and its ownership intact. Dropping the receipt requests
/// cancellation, but does not wait for cleanup.
///
/// Keep prepared resources alive until [`Self::wait_completion`] succeeds AND
/// the separately owned containment backend proves the domain empty. An error
/// is not cleanup evidence. This receipt never proves descendant cleanup.
pub struct PendingHostLaunch {
    state: Arc<Mutex<State>>,
    result: Option<BoxFuture<'static, anyhow::Result<()>>>,
    completion: CompletionFuture,
}

impl PendingHostLaunch {
    pub(crate) fn new() -> (Self, LaunchGuard) {
        let (send, recv) = mesh::oneshot();
        let state = Arc::new(Mutex::new(State {
            phase: Phase::BeforeNative,
            cancelled: false,
            handed_off: false,
            host: None,
            completion: Some(send),
        }));
        let completion = async move {
            match recv
                .await
                .map_err(|_| Arc::new(io::Error::other("launch completion observer stopped")))?
                .map_err(Arc::new)?
            {
                Assignment::NeverSpawned => Ok(LaunchCompletion::NeverSpawned),
                Assignment::Root(exit) => exit.await.map(LaunchCompletion::RootExited),
            }
        }
        .boxed()
        .shared();
        (
            Self {
                state: state.clone(),
                result: None,
                completion,
            },
            LaunchGuard {
                state,
                finished: false,
                #[cfg(test)]
                native_gate: Mutex::new(None),
            },
        )
    }

    pub(crate) fn set_result(&mut self, result: BoxFuture<'static, anyhow::Result<()>>) {
        self.result = Some(result);
    }

    /// Requests cancellation before ownership handoff.
    ///
    /// A queued request is prevented from spawning. If native creation has
    /// started, its original root is captured and termination is requested.
    /// Success here acknowledges the request, not OS exit. A later creation or
    /// termination failure can still be reported by `wait_host` or completion.
    /// After successful handoff, use the returned `OwnedHost` instead.
    pub fn cancel(&self) -> io::Result<()> {
        self.state.lock().cancel(true)
    }

    /// Waits for exclusive root ownership. Cancelling this wait does not cancel
    /// or consume the launch. The result can be taken only once.
    ///
    /// On error, retain the receipt and use `wait_completion`; an error alone
    /// does not prove whether a native root was created or reaped.
    pub async fn wait_host(&mut self) -> anyhow::Result<OwnedHost> {
        let result = self
            .result
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("launch result was already consumed"))?
            .await;
        self.result = None;
        if let Err(error) = result {
            if let Err(cancel_error) = self.state.lock().cancel(false) {
                return Err(error.context(format!(
                    "root termination request also failed: {cancel_error}"
                )));
            }
            return Err(error);
        }
        let mut state = self.state.lock();
        anyhow::ensure!(!state.cancelled, "owned launch was cancelled");
        let host = state
            .host
            .take()
            .ok_or_else(|| anyhow::anyhow!("owned launch completed without a root"))?;
        state.handed_off = true;
        Ok(host)
    }

    /// Waits for proven no-spawn or actual original-root exit/reap.
    ///
    /// This remains usable after launch errors, result-channel disconnection,
    /// cancellation, or ownership handoff. Cancelling and retrying this wait
    /// does not consume its result. It does not initiate cancellation itself.
    /// The returned observer owns its state and may outlive the receipt.
    pub fn wait_completion(
        &self,
    ) -> impl Future<Output = io::Result<LaunchCompletion>> + Send + 'static + use<> {
        let completion = self.completion.clone();
        async move {
            completion
                .await
                .map_err(|error| io::Error::new(error.kind(), error))
        }
    }
}

impl Drop for PendingHostLaunch {
    fn drop(&mut self) {
        if let Err(error) = self.state.lock().cancel(false) {
            tracing::error!(%error, "failed to cancel pending owned launch");
        }
    }
}

/// Follows the request, including rejection by a closed request channel.
pub(crate) struct LaunchGuard {
    state: Arc<Mutex<State>>,
    finished: bool,
    #[cfg(test)]
    native_gate: Mutex<Option<NativeLaunchGate>>,
}

impl LaunchGuard {
    #[cfg(test)]
    pub(crate) fn set_native_gate(&self, gate: Option<NativeLaunchGate>) {
        *self.native_gate.lock() = gate;
    }

    pub(crate) fn check_cancelled(&self) -> io::Result<()> {
        if self.state.lock().cancelled {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "owned launch was cancelled before preparation",
            ));
        }
        Ok(())
    }

    pub(crate) fn enter_native(&self) -> io::Result<()> {
        let mut state = self.state.lock();
        if state.cancelled {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "owned launch was cancelled before native creation",
            ));
        }
        assert!(matches!(state.phase, Phase::BeforeNative));
        state.phase = Phase::Native;
        drop(state);
        #[cfg(test)]
        if let Some((entered, resume)) = self.native_gate.lock().take() {
            entered.send(());
            resume
                .recv()
                .map_err(|_| io::Error::other("native entry test gate closed"))?;
        }
        Ok(())
    }

    /// The native API failed without returning an owned child.
    pub(crate) fn no_root(&self) {
        let mut state = self.state.lock();
        assert!(matches!(state.phase, Phase::BeforeNative | Phase::Native));
        state.phase = Phase::NoRoot;
    }

    pub(crate) fn observe_root(&self, exit: ExitFuture) {
        let mut state = self.state.lock();
        assert!(matches!(state.phase, Phase::Native));
        state.phase = Phase::Root;
        state.complete(Ok(Assignment::Root(exit)));
    }

    pub(crate) fn publish(&self, host: OwnedHost) -> io::Result<()> {
        let mut state = self.state.lock();
        assert!(matches!(state.phase, Phase::Root));
        assert!(state.host.is_none());
        state.host = Some(host);
        if state.cancelled {
            state.cancel(false)?;
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "owned launch was cancelled before handoff",
            ));
        }
        Ok(())
    }

    pub(crate) fn finish(mut self, success: bool) {
        self.finish_inner(success);
        self.finished = true;
    }

    fn finish_inner(&self, success: bool) {
        let mut state = self.state.lock();
        if !success && let Err(error) = state.cancel(false) {
            tracing::error!(%error, "failed to terminate interrupted owned launch");
        }
        match state.phase {
            Phase::BeforeNative | Phase::NoRoot => {
                state.complete(Ok(Assignment::NeverSpawned));
            }
            Phase::Native => {
                state.complete(Err(io::Error::other(
                    "native launch stopped before its root ownership could be captured",
                )));
            }
            Phase::Root => {}
        }
    }
}

impl Drop for LaunchGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.finish_inner(false);
        }
    }
}

#[cfg(test)]
type NativeLaunchGate = (mesh::OneshotSender<()>, std::sync::mpsc::Receiver<()>);

#[cfg(test)]
pub(crate) struct LaunchTestHooks {
    pub before_spawn: Option<(mesh::OneshotSender<()>, mesh::OneshotReceiver<()>)>,
    pub native_entry: Option<NativeLaunchGate>,
    pub before_handoff: Option<(mesh::OneshotSender<()>, mesh::OneshotReceiver<()>)>,
    pub fail_before_handoff: bool,
}

#[cfg(test)]
#[path = "pending_host/receipt_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "pending_host/tests.rs"]
mod supplemental_tests;

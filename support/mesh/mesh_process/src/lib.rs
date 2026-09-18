// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Infrastructure to create a multi-process mesh and spawn child processes
//! within it.
//!
//! Call [`Mesh::new()`] to create a process group. Workers launched on the mesh
//! can run in child processes connected by the platform IPC transport
//! (`mesh_remote`): Unix domain sockets on Linux, ALPC on Windows.
//!
//! The child process receives an invitation via an environment variable and
//! calls [`try_run_mesh_host()`] early in `main()` to join the mesh. Once
//! joined, ports (and the resources they carry) flow transparently between
//! parent and child.
//!
//! This crate is used by OpenVMM to launch worker processes and by OpenHCL to
//! run device emulators in isolated child processes.

// UNSAFETY: Needed to accept a raw Fd/Handle from our spawning process.
#![expect(unsafe_code)]

use anyhow::Context;
use base64::Engine;
use debug_ptr::DebugPtr;
use futures::FutureExt;
use futures::Stream;
use futures::StreamExt;
use futures::executor::block_on;
use futures_concurrency::future::Race;
use inspect::Inspect;
use inspect::SensitivityLevel;
use mesh::MeshPayload;
use mesh::OneshotReceiver;
use mesh::OneshotSender;
use mesh::local_node::Port;
use mesh::message::MeshField;
use mesh::payload::Protobuf;
use mesh::rpc::FailableRpc;
use mesh::rpc::RpcSend;
#[cfg(unix)]
use mesh_remote::InvitationAddress;
#[cfg(unix)]
use pal::unix::process::Builder as ProcessBuilder;
#[cfg(windows)]
use pal::windows::process;
#[cfg(windows)]
use pal::windows::process::Builder as ProcessBuilder;
#[cfg(unix)]
use pal_async::DefaultPool;
use pal_async::task::Spawn;
use pal_async::task::Task;
use slab::Slab;
use std::borrow::Cow;
use std::ffi::OsString;
use std::fs::File;
#[cfg(unix)]
use std::os::unix::prelude::*;
#[cfg(windows)]
use std::os::windows::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;
use tracing::Instrument;
use tracing::instrument;
use unicycle::FuturesUnordered;

#[cfg(windows)]
mod plat {
    pub type IpcNode = mesh_remote::windows::AlpcNode;
    pub type IpcNodeDriver = pal_async::windows::TpPool;
}

#[cfg(unix)]
mod plat {
    pub type IpcNode = mesh_remote::unix::UnixNode;
    pub type IpcNodeDriver = pal_async::DefaultDriver;
}

use plat::IpcNode;
use plat::IpcNodeDriver;

#[cfg(unix)]
const IPC_FD: i32 = 3;

/// The environment variable for passing the mesh IPC invitation information to
/// a child process. This is passed through the environment instead of a command
/// line argument so that other processes cannot steal the invitation details
/// and use it to break into the mesh.
const INVITATION_ENV_NAME: &str = "MESH_WORKER_INVITATION";
const CHECKED_STARTUP_ENV_NAME: &str = "MESH_WORKER_CHECKED_STARTUP";
const HOST_PROTOCOL_VERSION: u32 = 1;
const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Protobuf)]
struct Invitation {
    node_name: String,
    #[cfg(windows)]
    credentials: mesh_remote::windows::AlpcInvitationCredentials,
    #[cfg(unix)]
    address: InvitationAddress,
    #[cfg(windows)]
    directory_handle: usize,
    #[cfg(unix)]
    socket_fd: i32,
}

static PROCESS_NAME: DebugPtr<String> = DebugPtr::new();

/// Runs a mesh host in the current thread, then exits the process, if this
/// process was launched by [`Mesh::launch_host`].
///
/// The mesh invitation is provided via environment variables. If a mesh
/// invitation is not available this function will return immediately with `Ok`.
/// If a mesh invitation is available, this function joins the mesh and runs the
/// future returned by `f` until `f` returns or the parent process shuts down
/// the mesh.
pub fn try_run_mesh_host<U, F, T>(base_name: &str, f: F) -> anyhow::Result<()>
where
    U: 'static + MeshPayload + Send,
    F: AsyncFnOnce(U) -> anyhow::Result<T>,
{
    block_on(async {
        if let Some(r) = node_from_environment().await? {
            let NodeResult {
                node_name,
                node,
                initial_port,
            } = r;
            PROCESS_NAME.store(&node_name);
            set_program_name(&format!("{base_name}-{node_name}"));
            let init = OneshotReceiver::<InitialMessage<U>>::from(initial_port)
                .await
                .context("failed to receive initial message")?;
            let _drop = (
                f(init.init_message).map(Some),
                handle_host_requests(init.requests).map(|()| None),
            )
                .race()
                .await
                .transpose()?;

            tracing::debug!("waiting to shut down node");
            node.shutdown().await;
            drop(_drop);
            std::process::exit(0);
        }
        Ok(())
    })
}

/// Runs a checked mesh host without child-side sandbox finalization.
pub fn try_run_mesh_host_checked<U, F, T>(base_name: &str, f: F) -> anyhow::Result<()>
where
    U: 'static + MeshPayload + Send,
    F: AsyncFnOnce(U) -> anyhow::Result<T>,
{
    try_run_mesh_host_checked_inner(base_name, None, f)
}

/// Runs a mesh host and applies `finalize` before accepting its initial message.
///
/// Use this with [`ProcessConfig::new_with_checked_sandbox`] when the sandbox
/// requires child-side setup.
pub fn try_run_mesh_host_with_finalize<U, F, T, C>(
    base_name: &str,
    finalize: C,
    f: F,
) -> anyhow::Result<()>
where
    U: 'static + MeshPayload + Send,
    F: AsyncFnOnce(U) -> anyhow::Result<T>,
    C: FnOnce(&InheritedResourceManifest) -> anyhow::Result<()> + 'static,
{
    try_run_mesh_host_checked_inner(base_name, Some(Box::new(finalize)), f)
}

/// Runs a checked mesh host using a child-local sandbox profile.
pub fn try_run_mesh_host_with_profile<U, F, T, P>(
    base_name: &str,
    mut profile: P,
    f: F,
) -> anyhow::Result<()>
where
    U: 'static + MeshPayload + Send,
    F: AsyncFnOnce(U) -> anyhow::Result<T>,
    P: SandboxProfile + 'static,
{
    try_run_mesh_host_with_finalize(
        base_name,
        move |inherited_resources| profile.finalize_checked(inherited_resources),
        f,
    )
}

type ChildFinalize = Box<dyn FnOnce(&InheritedResourceManifest) -> anyhow::Result<()>>;

fn try_run_mesh_host_checked_inner<U, F, T>(
    base_name: &str,
    finalize: Option<ChildFinalize>,
    f: F,
) -> anyhow::Result<()>
where
    U: 'static + MeshPayload + Send,
    F: AsyncFnOnce(U) -> anyhow::Result<T>,
{
    let checked_startup = match checked_startup_from_environment()? {
        Some(config) => config,
        None => return Ok(()),
    };
    anyhow::ensure!(
        checked_startup.protocol_version == HOST_PROTOCOL_VERSION,
        "unsupported host protocol version {}",
        checked_startup.protocol_version
    );

    let finalize_callback_completed = finalize.is_some();
    if let Some(finalize) = finalize {
        finalize(&checked_startup.inherited_resources)
            .context("failed to finalize child sandbox")?;
    }

    block_on(async {
        if let Some(r) = node_from_environment().await? {
            let NodeResult {
                node_name,
                node,
                initial_port,
            } = r;
            PROCESS_NAME.store(&node_name);
            set_program_name(&format!("{base_name}-{node_name}"));
            let bootstrap = OneshotReceiver::<BootstrapMessage>::from(initial_port)
                .await
                .context("failed to receive bootstrap message")?;
            bootstrap.startup.send(StartupStatus::Ready {
                protocol_version: HOST_PROTOCOL_VERSION,
                finalize_callback_completed,
            });

            let init_message = OneshotReceiver::<U>::from(bootstrap.initial_message)
                .await
                .context("failed to receive initial message")?;
            let _drop = (
                f(init_message).map(Some),
                handle_host_requests(bootstrap.requests).map(|()| None),
            )
                .race()
                .await
                .transpose()?;

            tracing::debug!("waiting to shut down node");
            node.shutdown().await;
            drop(_drop);
            std::process::exit(0);
        }
        Ok(())
    })
}

fn checked_startup_from_environment() -> anyhow::Result<Option<CheckedStartupConfig>> {
    let config = match std::env::var(CHECKED_STARTUP_ENV_NAME) {
        Ok(config) => config,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(error) => return Err(error).context("failed to read checked startup configuration"),
    };

    // SAFETY: Mesh host entry points run before application threads start.
    unsafe {
        std::env::remove_var(CHECKED_STARTUP_ENV_NAME);
    }

    mesh::payload::decode(
        &base64::engine::general_purpose::STANDARD
            .decode(config)
            .context("failed to base64 decode checked startup configuration")?,
    )
    .context("failed to decode checked startup configuration")
    .map(Some)
}

async fn handle_host_requests(mut recv: mesh::Receiver<HostRequest>) {
    while let Some(req) = recv.next().await {
        match req {
            HostRequest::Inspect(deferred) => {
                deferred.respond(inspect_host);
            }
            HostRequest::Crash => panic!("explicit panic request"),
        }
    }
}

fn set_program_name(name: &str) {
    let _ = name;
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::write("/proc/self/comm", name);
    }
}

struct NodeResult {
    node_name: String,
    node: IpcNode,
    initial_port: Port,
}

/// Create an IPC node from an invitation provided via the process environment.
///
/// Returns `None` if the invitation is not present in the environment.
async fn node_from_environment() -> anyhow::Result<Option<NodeResult>> {
    // return early with no node if the invitation is not present in the environment.
    let invitation_str = match std::env::var(INVITATION_ENV_NAME) {
        Ok(str) => str,
        Err(_) => return Ok(None),
    };

    // Clear the string to avoid leaking the invitation information into child
    // processes.
    //
    // TODO: this function is unsafe because
    // it can cause UB if non-Rust code is concurrently accessing the
    // environment in another thread. To be completely sound,
    // either this function and its callers need to become
    // `unsafe`, or we need to avoid using the environment to propagate the
    // invitation so that we can avoid this call.
    //
    // SAFETY: Seems to work so far.
    unsafe {
        std::env::remove_var(INVITATION_ENV_NAME);
    }

    let invitation: Invitation = mesh::payload::decode(
        &base64::engine::general_purpose::STANDARD
            .decode(invitation_str)
            .context("failed to base64 decode invitation")?,
    )
    .context("failed to protobuf decode invitation")?;

    let (left, right) = Port::new_pair();

    let node;
    #[cfg(windows)]
    {
        // SAFETY: trusting the initiating process to pass a valid handle. A
        // malicious process could pass a bad handle here, but a malicious
        // process could also just corrupt our memory arbitrarily, so...
        let directory =
            unsafe { OwnedHandle::from_raw_handle(invitation.directory_handle as RawHandle) };

        let invitation =
            mesh_remote::windows::AlpcInvitation::new(invitation.credentials, directory);

        // join the node w/ the provided invitation and the send port of the channel.
        node = mesh_remote::windows::AlpcNode::join(
            pal_async::windows::TpPool::system(),
            invitation,
            left,
        )
        .context("failed to join mesh")?;
    }

    #[cfg(unix)]
    {
        // SAFETY: trusting the initiating process to pass a valid fd. A
        // malicious process could pass a bad fd here, but a malicious
        // process could also just corrupt our memory arbitrarily, so...
        let fd = unsafe { OwnedFd::from_raw_fd(invitation.socket_fd) };
        let invitation = mesh_remote::unix::UnixInvitation {
            address: invitation.address,
            fd,
        };

        // FUTURE: use pool provided by the caller.
        let (_, driver) = DefaultPool::spawn_on_thread("mesh-worker-pool");
        node = mesh_remote::unix::UnixNode::join(driver, invitation, left)
            .await
            .context("failed to join mesh")?;
    }

    Ok(Some(NodeResult {
        node_name: invitation.node_name,
        node,
        initial_port: right,
    }))
}

/// Represents a mesh::Node with the ability to spawn new processes that can
/// communicate with any other process belonging to the same mesh.
///
/// # Process creation
/// A `Mesh` instance can spawn new processes with an initial communication
/// channel associated with the mesh. All processes originating from the same
/// mesh can potentially communicate and exchange channels with each other.
///
/// Each spawned process can be configured differently via [`ProcessConfig`].
/// Processes are created with [`Mesh::launch_host`].
///
/// ```no_run
/// # use mesh_process::{Mesh, ProcessConfig};
/// # futures::executor::block_on(async {
/// let mesh = Mesh::new("remote_mesh".to_string()).unwrap();
/// let (send, recv) = mesh::channel();
/// mesh.launch_host(ProcessConfig::new("test"), recv).await.unwrap();
/// send.send(String::from("message for new process"));
/// # })
/// ```
#[derive(Inspect)]
pub struct Mesh {
    #[inspect(rename = "name")]
    mesh_name: String,
    #[inspect(flatten, send = "MeshRequest::Inspect")]
    request: mesh::Sender<MeshRequest>,
    #[inspect(skip)]
    task: Task<()>,
}

/// A resource intentionally inherited by a checked mesh host.
#[derive(Clone, Debug, Protobuf, PartialEq, Eq)]
pub struct InheritedResource {
    name: String,
    target: InheritedResourceTarget,
}

impl InheritedResource {
    /// Returns the resource's stable profile-defined name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the resource's child-side target.
    pub fn target(&self) -> &InheritedResourceTarget {
        &self.target
    }
}

/// The child-side identifier for an inherited resource.
#[derive(Clone, Debug, Protobuf, PartialEq, Eq)]
pub enum InheritedResourceTarget {
    /// Standard input.
    StandardInput,
    /// Standard output.
    StandardOutput,
    /// Standard error.
    StandardError,
    /// A Unix file descriptor number.
    FileDescriptor(i32),
    /// A Windows handle value.
    Handle(usize),
}

/// Resources intentionally inherited by a checked mesh host.
///
/// Sandbox profiles must declare every resource they add to the process
/// builder.
#[derive(Clone, Debug, Default, Protobuf, PartialEq, Eq)]
pub struct InheritedResourceManifest {
    resources: Vec<InheritedResource>,
}

impl InheritedResourceManifest {
    /// Declares an inherited resource.
    pub fn declare(
        &mut self,
        name: impl Into<String>,
        target: InheritedResourceTarget,
    ) -> anyhow::Result<()> {
        let name = name.into();
        anyhow::ensure!(!name.is_empty(), "inherited resource name cannot be empty");
        anyhow::ensure!(
            !self.resources.iter().any(|resource| resource.name == name),
            "inherited resource name '{name}' is already declared"
        );
        anyhow::ensure!(
            !self
                .resources
                .iter()
                .any(|resource| resource.target == target),
            "inherited resource target {target:?} is already declared"
        );
        self.resources.push(InheritedResource { name, target });
        Ok(())
    }

    /// Returns the declared inherited resources.
    pub fn resources(&self) -> &[InheritedResource] {
        &self.resources
    }

    /// Returns a declared resource by name.
    pub fn get(&self, name: &str) -> Option<&InheritedResourceTarget> {
        self.resources
            .iter()
            .find(|resource| resource.name == name)
            .map(|resource| &resource.target)
    }
}

/// Sandbox profile trait used for mesh hosts.
pub trait SandboxProfile: Send {
    /// Apply executes in the parent context and configures any sandbox
    /// features that will be applied to the newly created process via
    /// the pal builder object.
    fn apply(&mut self, _builder: &mut ProcessBuilder<'_>) {}

    /// Prepares the process builder and declares inherited resources.
    ///
    /// The default preserves the legacy infallible [`Self::apply`] behavior.
    fn prepare(
        &mut self,
        builder: &mut ProcessBuilder<'_>,
        inherited_resources: &mut InheritedResourceManifest,
    ) -> anyhow::Result<()> {
        let _ = inherited_resources;
        self.apply(builder);
        Ok(())
    }

    /// Returns whether checked launch requires child-side finalization.
    ///
    /// The parent verifies the child's acknowledgement. This detects
    /// misconfigured trusted workers, not a malicious worker.
    fn requires_child_finalize(&self) -> bool {
        false
    }

    /// Finalizes the sandbox in the child process.
    ///
    /// Existing profiles may call this from their child bootstrap. Checked
    /// hosts should use [`try_run_mesh_host_with_finalize`] to acknowledge it.
    fn finalize(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Finalizes a checked sandbox with its inherited resource manifest.
    fn finalize_checked(
        &mut self,
        inherited_resources: &InheritedResourceManifest,
    ) -> anyhow::Result<()> {
        let _ = inherited_resources;
        self.finalize()
    }
}

/// Configuration for launching a new process in the mesh.
pub struct ProcessConfig {
    name: String,
    process_name: Option<PathBuf>,
    process_args: Vec<OsString>,
    stderr: Option<File>,
    skip_worker_arg: bool,
    sandbox_profile: Option<Box<dyn SandboxProfile + Sync>>,
    env_vars: Vec<(OsString, OsString)>,
    checked_startup: bool,
    startup_timeout: Duration,
}

impl ProcessConfig {
    /// Returns new process configuration using the current process as the
    /// process name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            process_name: None,
            process_args: Vec::new(),
            stderr: None,
            skip_worker_arg: false,
            sandbox_profile: None,
            env_vars: Vec::new(),
            checked_startup: false,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
        }
    }

    /// Returns a new process configuration using the current process as the
    /// process name.
    pub fn new_with_sandbox(
        name: impl Into<String>,
        sandbox_profile: Box<dyn SandboxProfile + Sync>,
    ) -> Self {
        Self {
            name: name.into(),
            process_name: None,
            process_args: Vec::new(),
            stderr: None,
            skip_worker_arg: false,
            sandbox_profile: Some(sandbox_profile),
            env_vars: Vec::new(),
            checked_startup: false,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
        }
    }

    /// Returns process configuration with checked sandbox startup.
    ///
    /// The launch waits for a compatible child readiness response and any
    /// required child-side finalization before delivering the initial message.
    pub fn new_with_checked_sandbox(
        name: impl Into<String>,
        sandbox_profile: Box<dyn SandboxProfile + Sync>,
    ) -> Self {
        Self {
            name: name.into(),
            process_name: None,
            process_args: Vec::new(),
            stderr: None,
            skip_worker_arg: false,
            sandbox_profile: Some(sandbox_profile),
            env_vars: Vec::new(),
            checked_startup: true,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
        }
    }

    /// Sets the process name.
    pub fn process_name(mut self, name: impl Into<PathBuf>) -> Self {
        self.process_name = Some(name.into());
        self
    }

    /// Specifies whether to  appending `<node name>` to the process's command
    /// line.
    ///
    /// This is done by default to make it easier to identify the process in
    /// task lists, but if your process parses the command line then this may
    /// get in the way.
    pub fn skip_worker_arg(mut self, skip: bool) -> Self {
        self.skip_worker_arg = skip;
        self
    }

    /// Adds arguments to the process command line.
    pub fn args<I>(mut self, args: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<OsString>,
    {
        self.process_args.extend(args.into_iter().map(|x| x.into()));
        self
    }

    /// Adds environment variables when launching the process.
    pub fn env<I>(mut self, env_vars: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<(OsString, OsString)>,
    {
        self.env_vars.extend(env_vars.into_iter().map(|x| x.into()));
        self
    }

    /// Sets the process's stderr to `file`.
    pub fn stderr(mut self, file: Option<File>) -> Self {
        self.stderr = file;
        self
    }

    /// Sets the maximum time allowed for checked child startup.
    pub fn startup_timeout(mut self, timeout: Duration) -> Self {
        self.startup_timeout = timeout;
        self
    }
}

struct MeshInner {
    requests: mesh::Receiver<MeshRequest>,
    hosts: Slab<MeshHostInner>,
    startups: FuturesUnordered<Task<StartupCompletion>>,
    /// Handles for spawned host processes.
    waiters: FuturesUnordered<Task<usize>>,
    /// Mesh node for host process communication.
    node: IpcNode,
    /// IO driver for the mesh node, used for listener accept loops,
    /// handshakes, and general async task spawning. This is the same
    /// driver that was passed to the node on creation.
    node_driver: IpcNodeDriver,
    /// Name for this mesh instance, used for tracing/debugging.
    mesh_name: String,
    /// Job object. When closed, it will terminate all the child processes. This
    /// is used to ensure the child processes don't outlive the parent.
    #[cfg(windows)]
    job: pal::windows::job::Job,
}

struct MeshHostInner {
    name: String,
    pid: i32,
    node_id: mesh::NodeId,
    send: mesh::Sender<HostRequest>,
}

#[cfg(windows)]
type MeshChild = pal_async::windows::PolledProcess;
#[cfg(unix)]
type MeshChild = pal_async::process::PolledChild<pal::unix::process::Child>;

struct StartingHost {
    child: MeshChild,
    name: String,
    pid: i32,
    node_id: mesh::NodeId,
    request_send: mesh::Sender<HostRequest>,
    checked_startup: Option<CheckedStartup>,
    requires_child_finalize: bool,
    startup_timeout: Duration,
    #[cfg(windows)]
    connection: mesh_remote::windows::AlpcInvitationHandle,
}

struct StartedHost {
    child: MeshChild,
    name: String,
    pid: i32,
    node_id: mesh::NodeId,
    request_send: mesh::Sender<HostRequest>,
}

struct StartupCompletion {
    rpc: FailableRpc<(), i32>,
    result: anyhow::Result<StartedHost>,
}

enum MeshRequest {
    NewHost(FailableRpc<NewHostParams, i32>),
    Listen(FailableRpc<ListenParams, Task<()>>),
    Inspect(inspect::Deferred),
    Crash(i32),
}

struct ListenParams {
    path: PathBuf,
    port_factory: Box<dyn Fn() -> Port + Send>,
}

struct NewHostParams {
    config: ProcessConfig,
    recv: Port,
    request_send: mesh::Sender<HostRequest>,
    checked_startup: Option<CheckedStartup>,
}

struct CheckedStartup {
    startup: OneshotReceiver<StartupStatus>,
    send_bootstrap: Box<dyn FnOnce() + Send>,
}

impl Mesh {
    /// Creates a new mesh with the given name.
    pub fn new(mesh_name: String) -> anyhow::Result<Self> {
        #[cfg(windows)]
        let job = {
            let job = pal::windows::job::Job::new().context("failed to create job object")?;
            job.set_terminate_on_close()
                .context("failed to set job object terminate on close")?;
            job
        };

        #[cfg(windows)]
        let (node, node_driver) = {
            let driver = pal_async::windows::TpPool::system();
            // Use new_named so that the ALPC directory has a path in the Ob
            // namespace. This is required for listen() — the listener handshake
            // creates named invitations, which need a named directory.
            let node = mesh_remote::windows::AlpcNode::new_named(driver.clone())
                .context("AlpcNode creation failure")?;
            (node, driver)
        };
        #[cfg(unix)]
        let (node, node_driver) = {
            // FUTURE: use pool provided by the caller.
            let (_, driver) = DefaultPool::spawn_on_thread("mesh-worker-pool");
            let node = mesh_remote::unix::UnixNode::new(driver.clone());
            (node, driver)
        };

        let (request, requests) = mesh::channel();

        let mut inner = MeshInner {
            requests,
            hosts: Default::default(),
            startups: Default::default(),
            waiters: Default::default(),
            node,
            node_driver: node_driver.clone(),
            mesh_name: mesh_name.clone(),
            #[cfg(windows)]
            job,
        };

        let task = node_driver.spawn(
            format!("mesh-{}", mesh_name),
            async move { inner.run().await },
        );

        Ok(Self {
            request,
            mesh_name,
            task,
        })
    }

    /// Spawns a new host in the mesh with the provided configuration and
    /// initial message.
    ///
    /// The initial message will be provided to the closure passed to
    /// [`try_run_mesh_host()`].
    ///
    /// Returns the process ID of the launched host.
    pub async fn launch_host<T: 'static + MeshField + Send>(
        &self,
        config: ProcessConfig,
        initial_message: T,
    ) -> anyhow::Result<i32> {
        let (request_send, request_recv) = mesh::channel();
        let mut initial_message = Some(initial_message);

        let (recv, checked_startup, initial_send) = if config.checked_startup {
            let (startup_send, startup_recv) = mesh::oneshot();
            let (initial_send, initial_recv) = mesh::oneshot();
            let (bootstrap_send, bootstrap_recv) = mesh::oneshot();
            let send_bootstrap = Box::new(move || {
                bootstrap_send.send(BootstrapMessage {
                    requests: request_recv,
                    startup: startup_send,
                    initial_message: initial_recv.into(),
                });
            });
            (
                bootstrap_recv.into(),
                Some(CheckedStartup {
                    startup: startup_recv,
                    send_bootstrap,
                }),
                Some(initial_send),
            )
        } else {
            let (init_send, init_recv) = mesh::oneshot::<InitialMessage<T>>();
            init_send.send(InitialMessage {
                requests: request_recv,
                init_message: initial_message.take().unwrap(),
            });
            (init_recv.into(), None, None)
        };

        let pid = self
            .request
            .call_failable(
                MeshRequest::NewHost,
                NewHostParams {
                    config,
                    recv,
                    request_send,
                    checked_startup,
                },
            )
            .await
            .context("failed to launch new host")?;

        if let Some(initial_send) = initial_send {
            initial_send.send(initial_message.take().unwrap());
        }
        Ok(pid)
    }

    /// Shutdown the mesh and wait for any spawned processes to exit.
    ///
    /// The `Mesh` instance is no longer usable after `shutdown`.
    pub async fn shutdown(self) {
        let span = tracing::span!(
            tracing::Level::INFO,
            "mesh_shutdown",
            name = self.mesh_name.as_str(),
        );

        async {
            drop(self.request);
            self.task.await;
        }
        .instrument(span)
        .await;
    }

    /// Crashes the child process with the given process ID.
    pub fn crash(&self, pid: i32) {
        self.request.send(MeshRequest::Crash(pid));
    }

    /// Listen for mesh connections on a Unix socket.
    ///
    /// Returns a [`Listener<T>`] that yields items from connecting clients.
    /// Each client gets a `Sender<T>` bridged to this listener's queue.
    /// Dropping the [`Listener`] stops accepting new connections.
    ///
    /// # Security
    ///
    /// The socket at `path` is an external entry point for other local
    /// processes to join the mesh. On Unix, `path` must reside in a
    /// directory accessible only to the intended user (e.g. mode `0700`).
    /// On Windows, the socket's parent directory should be ACL'd to
    /// restrict access. Any local user who can connect to the socket can
    /// join the mesh.
    pub async fn listen<T: 'static + MeshField + Send>(
        &self,
        path: &Path,
    ) -> anyhow::Result<Listener<T>> {
        let (send, recv) = mesh::channel::<T>();
        let port_factory: Box<dyn Fn() -> Port + Send> = Box::new(move || send.clone().into());

        let task = self
            .request
            .call_failable(
                MeshRequest::Listen,
                ListenParams {
                    path: path.to_owned(),
                    port_factory,
                },
            )
            .await
            .context("listen failed")?;

        Ok(Listener { recv, _task: task })
    }
}

/// A listener for incoming mesh connections.
///
/// Each connecting client gets a `Sender<T>` bridged into this listener's
/// queue. When the client sends a `T`, it appears in the stream.
///
/// Implements [`Stream`]`<Item = T>`. Dropping the listener stops accepting
/// new connections.
pub struct Listener<T> {
    recv: mesh::Receiver<T>,
    _task: Task<()>,
}

impl<T: 'static + MeshField + Send> Stream for Listener<T> {
    type Item = T;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.recv.poll_next_unpin(cx)
    }
}

/// Connect to a mesh listener at `path`.
///
/// Returns a [`mesh::Sender<T>`] for sending messages to the listener, and a
/// [`Connection`] that keeps the underlying IPC node alive. Drop
/// [`Connection`] to disconnect.
pub async fn connect<T: 'static + MeshField + Send>(
    driver: impl pal_async::driver::Driver + Spawn + Clone,
    path: &Path,
) -> anyhow::Result<(mesh::Sender<T>, Connection)> {
    let (send, recv) = mesh::channel::<T>();

    #[cfg(windows)]
    let node = mesh_remote::windows::AlpcNode::join_by_socket(driver, path, recv.into())
        .await
        .context("failed to connect to mesh listener")?;

    #[cfg(unix)]
    let node = mesh_remote::unix::UnixNode::join_by_path(driver, path, recv.into())
        .await
        .context("failed to connect to mesh listener")?;

    Ok((send, Connection { node }))
}

/// An active connection to a mesh listener.
///
/// Keeps the underlying IPC node alive. Drop to disconnect.
pub struct Connection {
    node: IpcNode,
}

impl Connection {
    /// Gracefully shut down the connection, waiting for pending messages to be
    /// delivered.
    pub async fn shutdown(self) {
        self.node.shutdown().await;
    }
}

#[derive(Debug, MeshPayload)]
enum StartupStatus {
    Ready {
        protocol_version: u32,
        finalize_callback_completed: bool,
    },
}

#[derive(Protobuf)]
struct CheckedStartupConfig {
    protocol_version: u32,
    inherited_resources: InheritedResourceManifest,
}

#[derive(MeshPayload)]
struct InitialMessage<T> {
    requests: mesh::Receiver<HostRequest>,
    init_message: T,
}

#[derive(MeshPayload)]
struct BootstrapMessage {
    requests: mesh::Receiver<HostRequest>,
    startup: OneshotSender<StartupStatus>,
    initial_message: Port,
}

#[derive(Debug, MeshPayload)]
enum HostRequest {
    #[mesh(transparent)]
    Inspect(inspect::Deferred),
    Crash,
}

fn inspect_host(resp: &mut inspect::Response<'_>) {
    resp.field("tasks", inspect_task::inspect_task_list());
}

#[derive(Inspect)]
struct HostInspect<'a> {
    #[inspect(safe)]
    name: &'a str,
    #[inspect(debug, safe)]
    node_id: mesh::NodeId,
    #[cfg(target_os = "linux")]
    #[inspect(safe)]
    rlimit: inspect_rlimit::InspectRlimit,
}

impl MeshInner {
    async fn run(&mut self) {
        enum Event {
            Request(MeshRequest),
            Startup(StartupCompletion),
            Done(usize),
        }

        loop {
            let event = futures::select! { // merge semantics
                request = self.requests.select_next_some() => Event::Request(request),
                startup = self.startups.select_next_some() => Event::Startup(startup),
                n = self.waiters.select_next_some() => Event::Done(n),
                complete => break,
            };

            match event {
                Event::Request(request) => match request {
                    MeshRequest::NewHost(rpc) => {
                        let (params, rpc) = rpc.split();
                        match self.start_process(params).await {
                            Ok(starting) => {
                                let driver = self.node_driver.clone();
                                self.startups.push(self.node_driver.spawn(
                                    format!("start-mesh-child-{}", starting.pid),
                                    async move {
                                        StartupCompletion {
                                            rpc,
                                            result: starting.finish(&driver).await,
                                        }
                                    },
                                ));
                            }
                            Err(error) => rpc.fail(error),
                        }
                    }
                    MeshRequest::Listen(rpc) => {
                        rpc.handle_failable(async |params| self.start_listener(params))
                            .await
                    }
                    MeshRequest::Inspect(deferred) => {
                        deferred.respond(|resp| {
                            resp.sensitivity_child("hosts", SensitivityLevel::Safe, |req| {
                                let mut resp = req.respond();
                                for host in self.hosts.iter().map(|(_, host)| host) {
                                    resp.sensitivity_field_mut(
                                        &host.pid.to_string(),
                                        SensitivityLevel::Safe,
                                        &mut inspect::adhoc(|req| {
                                            req.respond()
                                                .merge(&HostInspect {
                                                    name: &host.name,
                                                    node_id: host.node_id,
                                                    #[cfg(target_os = "linux")]
                                                    rlimit: inspect_rlimit::InspectRlimit::for_pid(
                                                        host.pid,
                                                    ),
                                                })
                                                .merge(inspect::send(
                                                    &host.send,
                                                    HostRequest::Inspect,
                                                ));
                                        }),
                                    );
                                }
                            })
                            .sensitivity_field_mut(
                                &format!("hosts/{}", std::process::id()),
                                SensitivityLevel::Safe,
                                &mut inspect::adhoc(|req| {
                                    let mut resp = req.respond();
                                    resp.merge(&HostInspect {
                                        name: &self.mesh_name,
                                        node_id: self.node.id(),
                                        #[cfg(target_os = "linux")]
                                        rlimit: inspect_rlimit::InspectRlimit::new(),
                                    });
                                    inspect_host(&mut resp);
                                }),
                            );
                        });
                    }
                    MeshRequest::Crash(pid) => {
                        if pid == std::process::id() as i32 {
                            panic!("explicit panic request");
                        }

                        let mut found = false;
                        for (_, host) in &self.hosts {
                            if host.pid == pid {
                                host.send.send(HostRequest::Crash);
                                found = true;
                                break;
                            }
                        }

                        if !found {
                            tracing::error!("failed to crash process, pid {pid} not found");
                        }
                    }
                },
                Event::Startup(StartupCompletion { rpc, result }) => match result {
                    Ok(started) => {
                        let pid = started.pid;
                        self.register_started_host(started);
                        rpc.complete(Ok(pid));
                    }
                    Err(error) => rpc.fail(error),
                },
                Event::Done(id) => {
                    self.hosts.remove(id);
                }
            }
        }
    }

    fn register_started_host(&mut self, started: StartedHost) {
        let StartedHost {
            child,
            name,
            pid,
            node_id,
            request_send,
        } = started;
        let id = self.hosts.insert(MeshHostInner {
            name: name.clone(),
            pid,
            node_id,
            send: request_send,
        });
        let task = self
            .node_driver
            .spawn(format!("wait-mesh-child-{pid}"), async move {
                wait_mesh_child(child, &name, pid).await;
                id
            });
        self.waiters.push(task);
    }

    fn start_listener(&self, params: ListenParams) -> anyhow::Result<Task<()>> {
        // Remove a stale socket file if one exists, so that bind doesn't fail.
        if let Ok(true) = Self::is_socket(&params.path) {
            let _ = std::fs::remove_file(&params.path);
        }

        let mut listener = self
            .node
            .listen(&self.node_driver, &params.path)
            .context("failed to bind mesh listener")?;

        let driver = self.node_driver.clone();
        let port_factory = params.port_factory;

        let task = self.node_driver.spawn("mesh-listener", async move {
            loop {
                match listener.accept(&driver).await {
                    Ok(pending) => {
                        let port = port_factory();
                        driver
                            .spawn("mesh-listener-handshake", async move {
                                if let Err(e) = pending.finish(port).await {
                                    tracing::warn!(
                                        error = &e as &dyn std::error::Error,
                                        "mesh listener handshake failed",
                                    );
                                }
                            })
                            .detach();
                    }
                    Err(e) => {
                        tracing::error!(
                            error = &e as &dyn std::error::Error,
                            "mesh listener accept failed",
                        );
                        break;
                    }
                }
            }
        });

        Ok(task)
    }

    /// Checks whether `path` is a socket file.
    #[cfg(unix)]
    fn is_socket(path: &Path) -> std::io::Result<bool> {
        use std::os::unix::fs::FileTypeExt;
        Ok(std::fs::symlink_metadata(path)?.file_type().is_socket())
    }

    /// Checks whether `path` is a socket file.
    #[cfg(windows)]
    fn is_socket(path: &Path) -> std::io::Result<bool> {
        pal::windows::fs::is_unix_socket(path)
    }

    /// Spawns a new process with a mesh channel associated with this `Mesh` instance.
    #[instrument(name = "mesh_spawn_process", skip(self, params), fields(mesh_name = self.mesh_name.as_str(), pid = tracing::field::Empty))]
    async fn start_process(&mut self, params: NewHostParams) -> anyhow::Result<StartingHost> {
        let NewHostParams {
            config,
            recv,
            request_send,
            checked_startup,
        } = params;

        let pid;
        let node_id;
        let mut inherited_resources = InheritedResourceManifest::default();
        let mut requires_child_finalize = false;
        let startup_timeout = config.startup_timeout;
        let checked = checked_startup.is_some();
        #[cfg(windows)]
        let connection;
        if checked {
            inherited_resources.declare("stdin", InheritedResourceTarget::StandardInput)?;
            inherited_resources.declare("stdout", InheritedResourceTarget::StandardOutput)?;
            inherited_resources.declare("stderr", InheritedResourceTarget::StandardError)?;
        }

        // If no process name was passed, use the current executable path to
        // ensure we get the right file, but set arg0 to match how this process
        // was launched.
        let (arg0, process_name) = if let Some(n) = &config.process_name {
            (None, Cow::Borrowed(n))
        } else {
            (
                std::env::args_os().next(),
                Cow::Owned(std::env::current_exe().context("failed to get current exe path")?),
            )
        };

        let name = config.name.clone();

        #[cfg(windows)]
        let child = {
            let (invitation, invitation_connection) =
                self.node.invite(recv).context("mesh node invite error")?;
            connection = invitation_connection;
            node_id = invitation.node_id();
            let (credentials, directory) = invitation.into_parts();
            if checked {
                inherited_resources.declare(
                    "mesh-ipc",
                    InheritedResourceTarget::Handle(directory.as_raw_handle() as usize),
                )?;
            }

            let invitation_env = base64::engine::general_purpose::STANDARD.encode(
                mesh::payload::encode(Invitation {
                    node_name: name.clone(),
                    credentials,
                    directory_handle: directory.as_raw_handle() as usize,
                }),
            );

            let mut args = config.process_args;
            if !config.skip_worker_arg {
                args.push(name.clone().into());
            }

            let mut builder = process::Builder::from_args(
                arg0.as_ref()
                    .map_or_else(|| process_name.as_os_str(), |x| x.as_os_str()),
                &args,
            );
            if arg0.is_some() {
                builder.application_name(process_name.as_path());
            }
            builder
                .stdin(process::Stdio::Null)
                .stdout(process::Stdio::Null)
                .handle(&directory)
                .env(INVITATION_ENV_NAME, invitation_env)
                .extend_env(config.env_vars)
                .job(self.job.as_handle());

            if let Some(log_file) = config.stderr.as_ref() {
                builder.stderr(process::Stdio::Handle(log_file.as_handle()));
            }

            if let Some(mut sandbox_profile) = config.sandbox_profile {
                requires_child_finalize = sandbox_profile.requires_child_finalize();
                anyhow::ensure!(
                    checked || !requires_child_finalize,
                    "sandbox profile requires checked child finalization"
                );
                sandbox_profile
                    .prepare(&mut builder, &mut inherited_resources)
                    .context("failed to prepare sandbox profile")?;
            }
            if checked {
                builder.env(
                    CHECKED_STARTUP_ENV_NAME,
                    encode_checked_startup(&inherited_resources),
                );
            }

            // Launch the child process on a separate thread to isolate
            // the CreateProcess call from other IO pools.
            let child = std::thread::scope(|s| s.spawn(|| builder.spawn()).join().unwrap())
                .context("failed to launch mesh process")?;
            let child = pal_async::windows::PolledProcess::new(&self.node_driver, child)
                .expect("failed to create process wait");
            pid = child.get().id() as i32;
            tracing::Span::current().record("pid", pid);

            child
        };
        #[cfg(unix)]
        let child = {
            use pal::unix::process;

            let invitation = self
                .node
                .invite(recv)
                .await
                .context("mesh node invite error")?;

            node_id = invitation.address.local_addr.node;
            if checked {
                inherited_resources
                    .declare("mesh-ipc", InheritedResourceTarget::FileDescriptor(IPC_FD))?;
            }

            let invitation_env = base64::engine::general_purpose::STANDARD.encode(
                mesh::payload::encode(Invitation {
                    node_name: name.clone(),
                    address: invitation.address,
                    socket_fd: IPC_FD,
                }),
            );

            let mut command = process::Builder::new(process_name.into_owned());
            if let Some(arg0) = arg0 {
                command.arg0(arg0);
            }
            command
                .args(&config.process_args)
                .stdin(process::Stdio::Null)
                .stdout(process::Stdio::Null)
                .dup_fd(invitation.fd.as_fd(), IPC_FD)
                .env(INVITATION_ENV_NAME, invitation_env);

            for (key, value) in &config.env_vars {
                command.env(key, value);
            }

            if !config.skip_worker_arg {
                command.arg(&name);
            }

            if let Some(log_file) = config.stderr.as_ref() {
                command.stderr(process::Stdio::Fd(log_file.as_fd()));
            }

            if let Some(mut sandbox_profile) = config.sandbox_profile {
                requires_child_finalize = sandbox_profile.requires_child_finalize();
                anyhow::ensure!(
                    checked || !requires_child_finalize,
                    "sandbox profile requires checked child finalization"
                );
                sandbox_profile
                    .prepare(&mut command, &mut inherited_resources)
                    .context("failed to prepare sandbox profile")?;
            }
            if checked {
                command.env(
                    CHECKED_STARTUP_ENV_NAME,
                    encode_checked_startup(&inherited_resources),
                );
            }

            // Launch the child process on a separate thread to isolate
            // the fork() call from other IO pools.
            let child = std::thread::scope(|s| s.spawn(|| command.spawn()).join().unwrap())
                .context("failed to launch mesh process")?;
            pid = child.id();
            tracing::Span::current().record("pid", pid);

            pal_async::process::PolledChild::<process::Child>::new(&self.node_driver, child)
                .expect("failed to create process wait")
        };

        Ok(StartingHost {
            child,
            name,
            pid,
            node_id,
            request_send,
            checked_startup,
            requires_child_finalize,
            startup_timeout,
            #[cfg(windows)]
            connection,
        })
    }
}

impl StartingHost {
    async fn finish(mut self, driver: &IpcNodeDriver) -> anyhow::Result<StartedHost> {
        #[cfg(windows)]
        if self.checked_startup.is_none() {
            self.connection.await;
        }

        if let Some(CheckedStartup {
            startup,
            send_bootstrap,
        }) = self.checked_startup
        {
            send_bootstrap();
            let startup_result =
                wait_for_startup(driver, &mut self.child, startup, self.startup_timeout)
                    .await
                    .and_then(|status| match status {
                        StartupStatus::Ready {
                            protocol_version,
                            finalize_callback_completed,
                        } => {
                            anyhow::ensure!(
                                protocol_version == HOST_PROTOCOL_VERSION,
                                "mesh host protocol mismatch: expected {HOST_PROTOCOL_VERSION}, got {protocol_version}"
                            );
                            anyhow::ensure!(
                                !self.requires_child_finalize || finalize_callback_completed,
                                "mesh host did not complete required child sandbox finalization"
                            );
                            Ok(())
                        }
                    });

            if let Err(startup_error) = startup_result {
                if let Err(cleanup_error) = terminate_starting_child(&mut self.child).await {
                    return Err(startup_error.context(format!(
                        "failed to terminate mesh child after startup failure: {cleanup_error:#}"
                    )));
                }
                return Err(startup_error);
            }
        }

        Ok(StartedHost {
            child: self.child,
            name: self.name,
            pid: self.pid,
            node_id: self.node_id,
            request_send: self.request_send,
        })
    }
}

fn encode_checked_startup(inherited_resources: &InheritedResourceManifest) -> String {
    base64::engine::general_purpose::STANDARD.encode(mesh::payload::encode(CheckedStartupConfig {
        protocol_version: HOST_PROTOCOL_VERSION,
        inherited_resources: inherited_resources.clone(),
    }))
}

enum StartupWait {
    Status(anyhow::Result<StartupStatus>),
    Timeout,
    Exited(anyhow::Result<String>),
}

#[cfg(windows)]
async fn wait_for_startup(
    driver: &IpcNodeDriver,
    child: &mut MeshChild,
    startup: OneshotReceiver<StartupStatus>,
    timeout: Duration,
) -> anyhow::Result<StartupStatus> {
    let mut timer = pal_async::timer::PolledTimer::new(driver);
    let startup = startup
        .map(|result| StartupWait::Status(result.context("mesh child closed the startup channel")));
    let timeout = timer.sleep(timeout).map(|_| StartupWait::Timeout);
    let exited = child.wait().map(|result| {
        StartupWait::Exited(
            result
                .map(|code| format!("exit code {code}"))
                .context("failed to wait for mesh child during startup"),
        )
    });
    match (startup, timeout, exited).race().await {
        StartupWait::Status(Ok(status)) => Ok(status),
        StartupWait::Status(Err(channel_error)) => {
            Err(channel_error).context("mesh child closed startup channel before readiness")
        }
        StartupWait::Timeout => anyhow::bail!("mesh child startup timed out"),
        StartupWait::Exited(status) => {
            anyhow::bail!("mesh child exited before startup readiness: {}", status?)
        }
    }
}

#[cfg(unix)]
async fn wait_for_startup(
    driver: &IpcNodeDriver,
    child: &mut MeshChild,
    startup: OneshotReceiver<StartupStatus>,
    timeout: Duration,
) -> anyhow::Result<StartupStatus> {
    let mut timer = pal_async::timer::PolledTimer::new(driver);
    let startup = startup
        .map(|result| StartupWait::Status(result.context("mesh child closed the startup channel")));
    let timeout = timer.sleep(timeout).map(|_| StartupWait::Timeout);
    let exited = child.wait().map(|result| {
        StartupWait::Exited(
            result
                .map(|status| status.to_string())
                .context("failed to wait for mesh child during startup"),
        )
    });
    match (startup, timeout, exited).race().await {
        StartupWait::Status(Ok(status)) => Ok(status),
        StartupWait::Status(Err(channel_error)) => {
            Err(channel_error).context("mesh child closed startup channel before readiness")
        }
        StartupWait::Timeout => anyhow::bail!("mesh child startup timed out"),
        StartupWait::Exited(status) => {
            anyhow::bail!("mesh child exited before startup readiness: {}", status?)
        }
    }
}

#[cfg(windows)]
async fn terminate_starting_child(
    child: &mut pal_async::windows::PolledProcess,
) -> anyhow::Result<()> {
    if let Err(error) = child.get().kill(1) {
        const ERROR_ACCESS_DENIED: i32 = 5;
        if error.raw_os_error() != Some(ERROR_ACCESS_DENIED) {
            return Err(error).context("failed to terminate mesh child");
        }
    }
    child
        .wait()
        .await
        .context("failed to wait for terminated mesh child")?;
    Ok(())
}

#[cfg(unix)]
async fn terminate_starting_child(
    child: &mut pal_async::process::PolledChild<pal::unix::process::Child>,
) -> anyhow::Result<()> {
    child
        .get_mut()
        .kill()
        .context("failed to terminate mesh child")?;
    child
        .wait()
        .await
        .context("failed to wait for terminated mesh child")?;
    Ok(())
}

#[cfg(windows)]
async fn wait_mesh_child(mut child: pal_async::windows::PolledProcess, name: &str, pid: i32) {
    match child.wait().await {
        Ok(0) => {
            tracing::info!(pid, name, "mesh child exited successfully");
        }
        Ok(code) => {
            tracing::error!(pid, name, code, "mesh child abnormal exit");
        }
        Err(e) => {
            tracing::error!(
                pid,
                name,
                error = &e as &dyn std::error::Error,
                "mesh child wait failed"
            );
        }
    }
}

#[cfg(unix)]
async fn wait_mesh_child(
    mut child: pal_async::process::PolledChild<pal::unix::process::Child>,
    name: &str,
    pid: i32,
) {
    match child.wait().await {
        Ok(status) if status.code() == Some(0) => {
            tracing::info!(pid, name, "mesh child exited successfully");
        }
        Ok(exit_status) => {
            tracing::error!(pid, name, %exit_status, "mesh child abnormal exit");
        }
        Err(e) => {
            tracing::error!(
                pid,
                name,
                error = &e as &dyn std::error::Error,
                "mesh child wait failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pal_async::task::Spawn;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use test_with_tracing::test;

    struct TestProfile {
        fail_prepare: bool,
        requires_finalize: bool,
    }

    #[derive(MeshPayload)]
    struct TestMessage {
        value: u32,
    }

    impl SandboxProfile for TestProfile {
        fn prepare(
            &mut self,
            _builder: &mut ProcessBuilder<'_>,
            _inherited_resources: &mut InheritedResourceManifest,
        ) -> anyhow::Result<()> {
            anyhow::ensure!(!self.fail_prepare, "test profile preparation failed");
            Ok(())
        }

        fn requires_child_finalize(&self) -> bool {
            self.requires_finalize
        }
    }

    fn checked_config(child_test: &str, profile: TestProfile) -> ProcessConfig {
        ProcessConfig::new_with_checked_sandbox("checked", Box::new(profile))
            .process_name(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", child_test, "--nocapture"])
            .skip_worker_arg(true)
            .startup_timeout(Duration::from_secs(10))
    }

    #[test]
    #[ignore]
    fn checked_child() {
        try_run_mesh_host_checked("mesh-process-test", |message: TestMessage| async move {
            anyhow::ensure!(message.value == 42, "unexpected initial value");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore]
    fn finalized_child() {
        static FINALIZED: AtomicBool = AtomicBool::new(false);
        try_run_mesh_host_with_finalize(
            "mesh-process-test",
            |resources| {
                #[cfg(unix)]
                anyhow::ensure!(
                    resources.get("mesh-ipc")
                        == Some(&InheritedResourceTarget::FileDescriptor(IPC_FD)),
                    "mesh IPC descriptor is missing from inherited resource manifest"
                );
                #[cfg(windows)]
                anyhow::ensure!(
                    matches!(
                        resources.get("mesh-ipc"),
                        Some(InheritedResourceTarget::Handle(_))
                    ),
                    "mesh IPC handle is missing from inherited resource manifest"
                );
                FINALIZED.store(true, Ordering::Release);
                Ok(())
            },
            |message: TestMessage| async move {
                anyhow::ensure!(FINALIZED.load(Ordering::Acquire), "sandbox not finalized");
                anyhow::ensure!(message.value == 42, "unexpected initial value");
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    fn wrong_version_child() {
        block_on(async {
            if let Some(node) = node_from_environment().await.unwrap() {
                let bootstrap = OneshotReceiver::<BootstrapMessage>::from(node.initial_port)
                    .await
                    .unwrap();
                bootstrap.startup.send(StartupStatus::Ready {
                    protocol_version: HOST_PROTOCOL_VERSION + 1,
                    finalize_callback_completed: false,
                });
                std::future::pending::<()>().await;
            }
        });
    }

    #[test]
    #[ignore]
    fn stalled_child() {
        if checked_startup_from_environment().unwrap().is_some() {
            block_on(std::future::pending::<()>());
        }
    }

    #[test]
    #[ignore]
    fn exited_child() {
        if checked_startup_from_environment().unwrap().is_some() {
            std::process::exit(7);
        }
    }

    #[async_test]
    async fn test_checked_launch() {
        let mesh = Mesh::new("checked-launch".to_string()).unwrap();
        let pid = mesh
            .launch_host(
                checked_config(
                    "tests::finalized_child",
                    TestProfile {
                        fail_prepare: false,
                        requires_finalize: true,
                    },
                ),
                TestMessage { value: 42 },
            )
            .await
            .unwrap();
        assert_ne!(pid, 0);
        mesh.shutdown().await;
    }

    #[async_test]
    async fn test_checked_launch_requires_finalize() {
        let mesh = Mesh::new("checked-finalize".to_string()).unwrap();
        let error = mesh
            .launch_host(
                checked_config(
                    "tests::checked_child",
                    TestProfile {
                        fail_prepare: false,
                        requires_finalize: true,
                    },
                ),
                TestMessage { value: 42 },
            )
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("did not complete required child sandbox finalization")
        );
        mesh.shutdown().await;
    }

    #[async_test]
    async fn test_checked_launch_rejects_protocol_mismatch() {
        let mesh = Mesh::new("checked-version".to_string()).unwrap();
        let error = mesh
            .launch_host(
                checked_config(
                    "tests::wrong_version_child",
                    TestProfile {
                        fail_prepare: false,
                        requires_finalize: false,
                    },
                ),
                TestMessage { value: 42 },
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("mesh host protocol mismatch"));
        mesh.shutdown().await;
    }

    #[async_test]
    async fn test_checked_launch_reports_prepare_failure() {
        let mesh = Mesh::new("checked-prepare".to_string()).unwrap();
        let error = mesh
            .launch_host(
                checked_config(
                    "tests::checked_child",
                    TestProfile {
                        fail_prepare: true,
                        requires_finalize: false,
                    },
                ),
                TestMessage { value: 42 },
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("test profile preparation failed"));
        mesh.shutdown().await;
    }

    #[async_test]
    async fn test_checked_launch_times_out() {
        let mesh = Mesh::new("checked-timeout".to_string()).unwrap();
        let error = mesh
            .launch_host(
                checked_config(
                    "tests::stalled_child",
                    TestProfile {
                        fail_prepare: false,
                        requires_finalize: false,
                    },
                )
                .startup_timeout(Duration::from_millis(50)),
                TestMessage { value: 42 },
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("startup timed out"));
        mesh.shutdown().await;
    }

    #[async_test]
    async fn test_checked_launch_reports_early_exit() {
        let mesh = Mesh::new("checked-exit".to_string()).unwrap();
        let error = mesh
            .launch_host(
                checked_config(
                    "tests::exited_child",
                    TestProfile {
                        fail_prepare: false,
                        requires_finalize: false,
                    },
                ),
                TestMessage { value: 42 },
            )
            .await
            .unwrap_err();
        let error = format!("{error:#}");
        assert!(
            error.contains("exited before startup readiness")
                || error.contains("closed startup channel before readiness")
        );
        mesh.shutdown().await;
    }

    #[async_test]
    async fn test_checked_startup_does_not_block_mesh(driver: DefaultDriver) {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("mesh-responsive.sock");
        let mesh = Mesh::new("checked-responsive".to_string()).unwrap();
        {
            let mut launch = std::pin::pin!(
                mesh.launch_host(
                    checked_config(
                        "tests::stalled_child",
                        TestProfile {
                            fail_prepare: false,
                            requires_finalize: false,
                        },
                    )
                    .startup_timeout(Duration::from_millis(200)),
                    TestMessage { value: 42 },
                )
                .fuse()
            );
            let mut listen = std::pin::pin!(mesh.listen::<String>(&sock_path).fuse());

            let mut timer = pal_async::timer::PolledTimer::new(&driver);
            let mut timeout = std::pin::pin!(timer.sleep(Duration::from_millis(100)).fuse());
            futures::select! {
                result = listen => {
                    drop(result.unwrap());
                }
                _ = timeout => panic!("mesh control loop blocked during checked startup"),
                result = launch => panic!("checked launch completed unexpectedly: {result:?}"),
            }
            assert!(launch.await.is_err());
        }
        mesh.shutdown().await;
    }

    #[async_test]
    async fn test_unchecked_launch_rejects_required_finalize() {
        let mesh = Mesh::new("unchecked-finalize".to_string()).unwrap();
        let error = mesh
            .launch_host(
                ProcessConfig::new_with_sandbox(
                    "unchecked",
                    Box::new(TestProfile {
                        fail_prepare: false,
                        requires_finalize: true,
                    }),
                )
                .process_name(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "tests::checked_child",
                    "--nocapture",
                ])
                .skip_worker_arg(true),
                TestMessage { value: 42 },
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("requires checked child finalization"));
        mesh.shutdown().await;
    }

    #[test]
    fn inherited_resource_manifest_rejects_duplicates() {
        let mut manifest = InheritedResourceManifest::default();
        manifest
            .declare("first", InheritedResourceTarget::FileDescriptor(4))
            .unwrap();
        assert!(
            manifest
                .declare("first", InheritedResourceTarget::FileDescriptor(5))
                .is_err()
        );
        assert!(
            manifest
                .declare("second", InheritedResourceTarget::FileDescriptor(4))
                .is_err()
        );
    }

    #[async_test]
    async fn test_listen(driver: DefaultDriver) {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("mesh-listen.sock");

        let mesh = Mesh::new("test-listen".to_string()).unwrap();
        let mut listener = mesh.listen::<String>(&sock_path).await.unwrap();

        // Spawn a client task that connects and sends a message.
        let client_driver = driver.clone();
        let client_path = sock_path.clone();
        let client_task = driver.spawn("client", async move {
            let (sender, conn) = connect::<String>(client_driver, &client_path)
                .await
                .unwrap();
            sender.send("hello from client".to_string());
            // Return the connection to keep the node alive until the server
            // has received the message. Shutting down immediately can race
            // with the server establishing a back-connection for port
            // bridging on Windows (ALPC).
            conn
        });

        // Receive the message via the listener stream.
        let msg = listener.next().await.unwrap();
        assert_eq!(msg, "hello from client");

        client_task.await.shutdown().await;

        // Drop the listener and verify the accept loop stops.
        drop(listener);

        mesh.shutdown().await;
    }
}

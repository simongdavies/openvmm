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
//! captures an [`OwnedInvitation`] before starting threads, then passes it to
//! [`run_mesh_host()`] to join the mesh. Once joined, ports (and the resources
//! they carry) flow transparently between parent and child.
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
use tracing::Instrument;
use tracing::instrument;
use unicycle::FuturesUnordered;

#[cfg(any(windows, target_os = "linux"))]
mod owned_host;
#[cfg(any(windows, target_os = "linux"))]
pub use owned_host::{OwnedHost, RootExit};
#[cfg(any(windows, target_os = "linux"))]
mod pending_host;
#[cfg(any(windows, target_os = "linux"))]
pub use pending_host::{LaunchCompletion, PendingHostLaunch};

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

static INVITATION_CAPTURED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// An invitation that exclusively owns its inherited IPC resource.
///
/// Capture this before starting threads or tracing. It can then be moved to
/// [`run_mesh_host`] after other initialization, or dropped to close the resource.
pub struct OwnedInvitation {
    node_name: String,
    #[cfg(unix)]
    invitation: mesh_remote::unix::UnixInvitation,
    #[cfg(windows)]
    invitation: mesh_remote::windows::AlpcInvitation,
}

impl OwnedInvitation {
    /// Takes the invitation from the process environment, if present.
    ///
    /// This may be called only once, including when the invitation is absent or
    /// malformed. The environment entry is removed before decoding; invalid or
    /// non-Unicode entries are errors, not an absent invitation. The inherited
    /// resource is made non-inheritable before returning.
    ///
    /// # Safety
    ///
    /// The caller must have exclusive access to the process environment:
    /// no other thread or foreign code may read or write it during this call.
    /// Call this at process startup before starting threads (including tracing).
    ///
    /// If the entry decodes, it must have come from a trusted mesh launcher and
    /// identify a valid inherited socket fd (Unix) or directory handle
    /// (Windows). The caller must transfer exclusive ownership of that resource:
    /// it must not already have an owner, be closed, or be used concurrently.
    /// No process may be spawned concurrently before inheritance is disabled.
    pub unsafe fn capture_from_environment() -> anyhow::Result<Option<Self>> {
        claim_invitation(&INVITATION_CAPTURED)?;
        let Some(value) = std::env::var_os(INVITATION_ENV_NAME) else {
            return Ok(None);
        };
        // SAFETY: exclusive environment access is required by the caller contract.
        unsafe { std::env::remove_var(INVITATION_ENV_NAME) };
        let invitation = decode_invitation(value)?;
        // SAFETY: the caller transfers exclusive ownership of the decoded resource.
        unsafe { Self::from_inherited(invitation) }.map(Some)
    }

    /// Takes exclusive ownership of the inherited IPC resource.
    ///
    /// # Safety
    ///
    /// The invitation must name a valid inherited socket fd or directory
    /// handle with no existing owner or concurrent users. No process may be
    /// spawned concurrently before this function disables inheritance.
    unsafe fn from_inherited(invitation: Invitation) -> anyhow::Result<Self> {
        #[cfg(unix)]
        let owned = {
            // SAFETY: the caller guarantees a valid, exclusively owned socket fd.
            let fd = unsafe { OwnedFd::from_raw_fd(invitation.socket_fd) };
            // SAFETY: fcntl operates on our live fd and takes no pointer arguments.
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            if flags == -1 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to read invitation fd flags");
            }
            // SAFETY: fd is live and flags contains the existing descriptor flags.
            if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1
            {
                return Err(std::io::Error::last_os_error())
                    .context("failed to make invitation fd close-on-exec");
            }
            mesh_remote::unix::UnixInvitation {
                address: invitation.address,
                fd,
            }
        };
        #[cfg(windows)]
        let owned = {
            // SAFETY: the caller transfers a valid, exclusively owned directory handle.
            let directory =
                unsafe { OwnedHandle::from_raw_handle(invitation.directory_handle as RawHandle) };
            // SAFETY: directory owns a live handle throughout this call.
            if unsafe {
                windows_sys::Win32::Foundation::SetHandleInformation(
                    directory.as_raw_handle(),
                    windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT,
                    0,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("failed to make invitation handle non-inheritable");
            }
            mesh_remote::windows::AlpcInvitation::new(invitation.credentials, directory)
        };
        Ok(Self {
            node_name: invitation.node_name,
            invitation: owned,
        })
    }
}

fn claim_invitation(captured: &std::sync::atomic::AtomicBool) -> anyhow::Result<()> {
    captured
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .map_err(|_| anyhow::anyhow!("mesh invitation has already been captured"))?;
    Ok(())
}

fn decode_invitation(value: OsString) -> anyhow::Result<Invitation> {
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("mesh invitation is not Unicode"))?;
    mesh::payload::decode(
        &base64::engine::general_purpose::STANDARD
            .decode(value)
            .context("failed to base64 decode invitation")?,
    )
    .context("failed to protobuf decode invitation")
}

/// Runs a mesh host in the current thread, then exits the process, if this
/// process was launched by [`Mesh::launch_host`].
///
/// The mesh invitation is provided via environment variables. If a mesh
/// invitation is not available this function will return immediately with `Ok`.
/// If a mesh invitation is available, this function joins the mesh and runs the
/// future returned by `f` until `f` returns or the parent process shuts down
/// the mesh.
///
/// This compatibility entry point is now unsafe. Prefer capturing an
/// [`OwnedInvitation`] at startup and calling [`run_mesh_host`] later.
///
/// # Safety
///
/// The caller must meet all the environment-access and inherited-resource
/// ownership requirements of [`OwnedInvitation::capture_from_environment`].
pub unsafe fn try_run_mesh_host<U, F, T>(base_name: &str, f: F) -> anyhow::Result<()>
where
    U: 'static + MeshPayload + Send,
    F: AsyncFnOnce(U) -> anyhow::Result<T>,
{
    // SAFETY: this function has the same capture contract.
    if let Some(invitation) = unsafe { OwnedInvitation::capture_from_environment() }? {
        run_mesh_host(invitation, base_name, f)?;
    }
    Ok(())
}

/// Consumes an owned invitation, joins the mesh, runs the host, and exits.
///
/// This does not access or mutate the invitation environment variable, or
/// adopt any raw resource. It is safe to call after starting other threads.
/// Returns only if joining, initialization, or the host future fails.
pub fn run_mesh_host<U, F, T>(
    invitation: OwnedInvitation,
    base_name: &str,
    f: F,
) -> anyhow::Result<()>
where
    U: 'static + MeshPayload + Send,
    F: AsyncFnOnce(U) -> anyhow::Result<T>,
{
    block_on(async {
        let NodeResult {
            node_name,
            node,
            initial_port,
        } = node_from_invitation(invitation).await?;
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
    })
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

async fn node_from_invitation(invitation: OwnedInvitation) -> anyhow::Result<NodeResult> {
    let (left, right) = Port::new_pair();

    let node;
    #[cfg(windows)]
    {
        // join the node w/ the provided invitation and the send port of the channel.
        node = mesh_remote::windows::AlpcNode::join(
            pal_async::windows::TpPool::system(),
            invitation.invitation,
            left,
        )
        .context("failed to join mesh")?;
    }

    #[cfg(unix)]
    {
        // FUTURE: use pool provided by the caller.
        let (_, driver) = DefaultPool::spawn_on_thread("mesh-worker-pool");
        node = mesh_remote::unix::UnixNode::join(driver, invitation.invitation, left)
            .await
            .context("failed to join mesh")?;
    }

    Ok(NodeResult {
        node_name: invitation.node_name,
        node,
        initial_port: right,
    })
}

#[cfg(test)]
mod invitation_tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use test_with_tracing::test;

    #[test]
    fn capture_claim_is_consumed_once() {
        let captured = AtomicBool::new(false);
        claim_invitation(&captured).unwrap();
        assert!(claim_invitation(&captured).is_err());
    }

    #[test]
    fn concurrent_capture_claims_have_one_winner() {
        let captured = AtomicBool::new(false);
        let successes = std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| claim_invitation(&captured).is_ok()))
                .collect();
            tasks
                .into_iter()
                .map(|task| usize::from(task.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(successes, 1);
        assert!(claim_invitation(&captured).is_err());
    }

    #[test]
    fn malformed_invitation_is_not_absence() {
        let err = decode_invitation("!".into()).err().unwrap();
        assert_eq!(err.to_string(), "failed to base64 decode invitation");
        let err = decode_invitation(
            base64::engine::general_purpose::STANDARD
                .encode([0xff])
                .into(),
        )
        .err()
        .unwrap();
        assert_eq!(err.to_string(), "failed to protobuf decode invitation");
    }

    #[test]
    fn non_unicode_invitation_is_not_absence() {
        #[cfg(unix)]
        let value = OsString::from_vec(vec![0xff]);
        #[cfg(windows)]
        let value = OsString::from_wide(&[0xd800]);
        let err = decode_invitation(value).err().unwrap();
        assert_eq!(err.to_string(), "mesh invitation is not Unicode");
    }
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

/// Sandbox profile trait used for mesh hosts.
pub trait SandboxProfile: Send {
    /// Apply executes in the parent context and configures any sandbox
    /// features that will be applied to the newly created process via
    /// the pal builder object.
    fn apply(&mut self, builder: &mut ProcessBuilder<'_>);

    /// Configures the child before creation, aborting launch on failure.
    ///
    /// Existing profiles retain their infallible behavior. Profiles with
    /// fallible setup should override this method rather than silently launch
    /// with only part of their requested confinement.
    ///
    /// On Windows, the builder's AppContainer SID is also used to provision
    /// exact-SID ALPC access before process creation. Any ACL setup failure
    /// aborts launch rather than falling back to an unrestricted token.
    fn try_apply(&mut self, builder: &mut ProcessBuilder<'_>) -> anyhow::Result<()> {
        self.apply(builder);
        Ok(())
    }

    /// Finalize is intended to execute in the child process context after
    /// application specific initialization is complete. It's optional as not
    /// every sandbox profile will need to perform additional sandboxing.
    /// In addition, the child will need to be aware enough to instantiate its
    /// sandbox profile and invoke this method.
    fn finalize(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Configuration for launching a new process in the mesh.
pub struct ProcessConfig {
    name: String,
    process_name: Option<PathBuf>,
    process_args: Vec<OsString>,
    stdout: Option<File>,
    stderr: Option<File>,
    skip_worker_arg: bool,
    sandbox_profile: Option<Box<dyn SandboxProfile + Sync>>,
    env_vars: Vec<(OsString, OsString)>,
    #[cfg(windows)]
    app_container_peers: Vec<pal::windows::security::MaximumSid>,
    #[cfg(windows)]
    peer_endpoint_mode: PeerEndpointMode,
}

#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum PeerEndpointMode {
    AppContainer,
    TrustedHost,
    Conflicting,
}

impl ProcessConfig {
    /// Returns new process configuration using the current process as the
    /// process name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            process_name: None,
            process_args: Vec::new(),
            stdout: None,
            stderr: None,
            skip_worker_arg: false,
            sandbox_profile: None,
            env_vars: Vec::new(),
            #[cfg(windows)]
            app_container_peers: Vec::new(),
            #[cfg(windows)]
            peer_endpoint_mode: PeerEndpointMode::AppContainer,
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
            stdout: None,
            stderr: None,
            skip_worker_arg: false,
            sandbox_profile: Some(sandbox_profile),
            env_vars: Vec::new(),
            #[cfg(windows)]
            app_container_peers: Vec::new(),
            #[cfg(windows)]
            peer_endpoint_mode: PeerEndpointMode::AppContainer,
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
    ///
    /// Launch fails if these override the reserved `MESH_WORKER_INVITATION`
    /// variable, whose resource ownership is established by Mesh.
    pub fn env<I>(mut self, env_vars: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<(OsString, OsString)>,
    {
        self.env_vars.extend(env_vars.into_iter().map(|x| x.into()));
        self
    }

    /// Sets the process's stdout to `file`, or the null device if `None`.
    pub fn stdout(mut self, file: Option<File>) -> Self {
        self.stdout = file;
        self
    }

    /// Sets the process's stderr to `file`.
    pub fn stderr(mut self, file: Option<File>) -> Self {
        self.stderr = file;
        self
    }

    /// Adds an exact AppContainer peer allowed to connect to this child's Mesh
    /// endpoint. The SID is copied; repeated identities are deduplicated.
    ///
    /// The trusted parent configures reciprocal grants before launch. For a
    /// star, add every spoke SID to the hub, but only the hub SID to each spoke.
    /// No peers are inferred from other invitations. All supplied SIDs are
    /// validated before invitation setup; broad package-group SIDs and the
    /// child's own identity are rejected. Launch also fails if the sandbox
    /// profile does not configure an AppContainer. Do not combine this method
    /// with [`Self::trusted_host_app_container_peer`].
    ///
    /// Before the first launch, the trusted caller must prepare the whole
    /// topology and retain owned registered profiles for each logical worker in
    /// one fresh sandbox lifetime. Concurrently isolated workers require
    /// distinct SIDs. The invitation carries only transient, private ACL
    /// metadata in an immutable launch-time snapshot, not profile ownership.
    /// There is no post-launch grant or revocation API.
    ///
    /// Reuse a retained profile for a replacement generation only after its old
    /// root is reaped and its old job is empty. Fresh sandbox reconstruction
    /// requires new owned profiles and SIDs. Serialized SID text, names, or
    /// digests cannot recreate ownership; never share profiles between
    /// independent sandbox lifetimes.
    #[cfg(windows)]
    pub fn app_container_peer(mut self, sid: &pal::windows::security::Sid) -> Self {
        self.add_app_container_peer(sid, PeerEndpointMode::AppContainer);
        self
    }

    /// Explicitly permits an exact AppContainer peer to connect to a trusted
    /// ordinary-user child's Mesh endpoint.
    ///
    /// This selects a trusted-host endpoint, not an AppContainer fallback.
    /// The caller must separately authorize trusting this child, which must
    /// run as the current user without an AppContainer. This method does not
    /// change its token, privileges, Job limits, or hypervisor permissions.
    /// A configured AppContainer or mixing this method with
    /// [`Self::app_container_peer`] rejects launch.
    ///
    /// SIDs are copied, appended, deduplicated, and validated before invitation
    /// setup. The child endpoint grants only PORT_CONNECT to these exact SIDs,
    /// with a low-integrity label; no synthetic identity is assigned to the
    /// child. Peers must join this mesh through their own AppContainer
    /// invitations, which establish their directory access. This method does
    /// not grant peers access to the parent's endpoint or directory.
    ///
    /// The current-user grant already on each confined peer's endpoint allows
    /// the reverse connection from this trusted host. Peer profile ownership,
    /// lifetime and replacement requirements are as for
    /// [`Self::app_container_peer`].
    #[cfg(windows)]
    pub fn trusted_host_app_container_peer(mut self, sid: &pal::windows::security::Sid) -> Self {
        self.add_app_container_peer(sid, PeerEndpointMode::TrustedHost);
        self
    }

    #[cfg(windows)]
    fn add_app_container_peer(
        &mut self,
        sid: &pal::windows::security::Sid,
        mode: PeerEndpointMode,
    ) {
        self.peer_endpoint_mode =
            if !self.app_container_peers.is_empty() && self.peer_endpoint_mode != mode {
                PeerEndpointMode::Conflicting
            } else {
                mode
            };
        let text = sid.to_string_sid();
        if !self
            .app_container_peers
            .iter()
            .any(|peer| peer.to_string_sid() == text)
        {
            self.app_container_peers
                .push(pal::windows::security::MaximumSid::from(sid));
        }
    }
}

struct MeshInner {
    requests: mesh::Receiver<MeshRequest>,
    hosts: Slab<MeshHostInner>,
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

enum MeshRequest {
    NewHost(FailableRpc<Box<NewHostParams>, LaunchedHost>),
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
    owned: bool,
    #[cfg(any(windows, target_os = "linux"))]
    launch: Option<pending_host::LaunchGuard>,
    #[cfg(all(test, any(windows, target_os = "linux")))]
    test_hooks: Option<pending_host::LaunchTestHooks>,
}

enum LaunchedHost {
    Legacy(i32),
    #[cfg(any(windows, target_os = "linux"))]
    Owned(OwnedHost),
    #[cfg(any(windows, target_os = "linux"))]
    Pending,
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
        match self
            .launch_host_inner(config, initial_message, false)
            .await?
        {
            LaunchedHost::Legacy(pid) => Ok(pid),
            #[cfg(any(windows, target_os = "linux"))]
            LaunchedHost::Owned(_) | LaunchedHost::Pending => {
                unreachable!("requested legacy launch")
            }
        }
    }

    /// Launches a root process and returns exclusive OS lifecycle ownership.
    ///
    /// Returns after OS creation, before the child joins Mesh or acknowledges
    /// readiness. This permits rollback even when child startup blocks. Dropping
    /// the result requests termination; [`OwnedHost::wait_root`] proves root OS
    /// exit/reap, not descendant cleanup. Cancellation of the launch future also
    /// requests cancellation. Use [`Self::begin_launch_host_owned`] to retain
    /// completion evidence after cancelling launch or receiving an error.
    #[cfg(any(windows, target_os = "linux"))]
    pub async fn launch_host_owned<T: 'static + MeshField + Send>(
        &self,
        config: ProcessConfig,
        initial_message: T,
    ) -> anyhow::Result<OwnedHost> {
        self.begin_launch_host_owned(config, initial_message)
            .wait_host()
            .await
    }

    /// Starts an owned launch and returns its cancellation/completion receipt.
    ///
    /// The receipt is established before dispatch. Keep it across deadlines
    /// and errors, request cancellation, and observe its root completion before
    /// releasing prepared resources. Domain-empty evidence is separate.
    #[cfg(any(windows, target_os = "linux"))]
    pub fn begin_launch_host_owned<T: 'static + MeshField + Send>(
        &self,
        config: ProcessConfig,
        initial_message: T,
    ) -> PendingHostLaunch {
        self.begin_owned(
            config,
            initial_message,
            #[cfg(test)]
            None,
        )
    }

    #[cfg(any(windows, target_os = "linux"))]
    fn begin_owned<T: 'static + MeshField + Send>(
        &self,
        config: ProcessConfig,
        initial_message: T,
        #[cfg(test)] test_hooks: Option<pending_host::LaunchTestHooks>,
    ) -> PendingHostLaunch {
        let (mut pending, launch) = PendingHostLaunch::new();
        let (request_send, request_recv) = mesh::channel();
        let (init_send, init_recv) = mesh::oneshot::<InitialMessage<T>>();
        init_send.send(InitialMessage {
            requests: request_recv,
            init_message: initial_message,
        });
        let result = self.request.call_failable(
            MeshRequest::NewHost,
            Box::new(NewHostParams {
                config,
                recv: init_recv.into(),
                request_send,
                owned: true,
                launch: Some(launch),
                #[cfg(test)]
                test_hooks,
            }),
        );
        pending.set_result(
            async move {
                match result.await.context("failed to launch new host")? {
                    LaunchedHost::Pending => Ok(()),
                    _ => anyhow::bail!("owned launch returned an unexpected handoff"),
                }
            }
            .boxed(),
        );
        pending
    }

    async fn launch_host_inner<T: 'static + MeshField + Send>(
        &self,
        config: ProcessConfig,
        initial_message: T,
        owned: bool,
    ) -> anyhow::Result<LaunchedHost> {
        let (request_send, request_recv) = mesh::channel();

        let (init_send, init_recv) = mesh::oneshot::<InitialMessage<T>>();
        init_send.send(InitialMessage {
            requests: request_recv,
            init_message: initial_message,
        });

        self.request
            .call_failable(
                MeshRequest::NewHost,
                Box::new(NewHostParams {
                    config,
                    recv: init_recv.into(),
                    request_send,
                    owned,
                    #[cfg(any(windows, target_os = "linux"))]
                    launch: None,
                    #[cfg(all(test, any(windows, target_os = "linux")))]
                    test_hooks: None,
                }),
            )
            .await
            .context("failed to launch new host")
    }

    /// Shutdown the mesh and wait for any spawned processes to exit.
    ///
    /// The `Mesh` instance is no longer usable after `shutdown`.
    /// This does not force processes to exit. In particular, if an owned root
    /// cannot be terminated, this wait can remain pending indefinitely. Observe
    /// each owned root's exit result before treating cleanup as successful.
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

#[derive(MeshPayload)]
struct InitialMessage<T> {
    requests: mesh::Receiver<HostRequest>,
    init_message: T,
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
            Done(usize),
        }

        loop {
            let event = futures::select! { // merge semantics
                request = self.requests.select_next_some() => Event::Request(request),
                n = self.waiters.select_next_some() => Event::Done(n),
                complete => break,
            };

            match event {
                Event::Request(request) => match request {
                    MeshRequest::NewHost(rpc) => {
                        rpc.handle_failable(async |params| self.launch_request(*params).await)
                            .await
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
                Event::Done(id) => {
                    self.hosts.remove(id);
                }
            }
        }
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

    async fn launch_request(&mut self, params: NewHostParams) -> anyhow::Result<LaunchedHost> {
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            self.spawn_process(params).await
        }
        #[cfg(any(windows, target_os = "linux"))]
        {
            let mut params = params;
            let launch = params.launch.take();
            #[cfg(test)]
            let mut hooks = params.test_hooks.take();
            #[cfg(test)]
            if let Some(launch) = &launch {
                launch.set_native_gate(hooks.as_mut().and_then(|hooks| hooks.native_entry.take()));
            }
            let result = async {
                if let Some(launch) = &launch {
                    launch.check_cancelled()?;
                }
                #[cfg(test)]
                if let Some((entered, resume)) =
                    hooks.as_mut().and_then(|hooks| hooks.before_spawn.take())
                {
                    entered.send(());
                    resume.await.context("pre-spawn test gate closed")?;
                }
                if let Some(launch) = &launch {
                    launch.check_cancelled()?;
                }
                match self.spawn_process(params, launch.as_ref()).await? {
                    LaunchedHost::Owned(host) => {
                        launch
                            .as_ref()
                            .expect("owned launches carry a receipt")
                            .publish(host)?;
                        #[cfg(test)]
                        {
                            if let Some((entered, resume)) =
                                hooks.as_mut().and_then(|hooks| hooks.before_handoff.take())
                            {
                                entered.send(());
                                resume.await.context("pre-handoff test gate closed")?;
                            }
                            if hooks.is_some_and(|hooks| hooks.fail_before_handoff) {
                                anyhow::bail!("injected pre-handoff failure");
                            }
                        }
                        Ok(LaunchedHost::Pending)
                    }
                    result => Ok(result),
                }
            }
            .await;
            if let Some(launch) = launch {
                launch.finish(result.is_ok());
            }
            result
        }
    }

    /// Spawns a new process with a mesh channel associated with this `Mesh` instance.
    #[instrument(name = "mesh_spawn_process", skip_all, fields(mesh_name = self.mesh_name.as_str(), pid = tracing::field::Empty))]
    async fn spawn_process(
        &mut self,
        params: NewHostParams,
        #[cfg(any(windows, target_os = "linux"))] launch: Option<&pending_host::LaunchGuard>,
    ) -> anyhow::Result<LaunchedHost> {
        let NewHostParams {
            config,
            recv,
            request_send,
            owned,
            #[cfg(any(windows, target_os = "linux"))]
                launch: _,
            #[cfg(all(test, any(windows, target_os = "linux")))]
                test_hooks: _,
        } = params;
        anyhow::ensure!(
            !config.env_vars.iter().any(|(key, _)| {
                let key = key.as_encoded_bytes();
                let end = key
                    .iter()
                    .position(|&byte| byte == b'=')
                    .unwrap_or(key.len());
                let key = &key[..end];
                #[cfg(windows)]
                {
                    key.eq_ignore_ascii_case(INVITATION_ENV_NAME.as_bytes())
                }
                #[cfg(unix)]
                {
                    key == INVITATION_ENV_NAME.as_bytes()
                }
            }),
            "process configuration must not override the Mesh invitation"
        );
        #[cfg(not(any(windows, target_os = "linux")))]
        let _ = owned;

        let pid;
        let node_id;

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
            let host_job = if owned {
                let job =
                    pal::windows::job::Job::new().context("failed to create owned host job")?;
                job.set_terminate_on_close()
                    .context("failed to set owned host job terminate on close")?;
                Some(job)
            } else {
                None
            };
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
                .extend_env(config.env_vars);
            if let Some(job) = &host_job {
                builder.job(job.as_handle());
            } else {
                builder.job(self.job.as_handle());
            }

            if let Some(log_file) = config.stdout.as_ref() {
                builder.stdout(process::Stdio::Handle(log_file.as_handle()));
            }
            if let Some(log_file) = config.stderr.as_ref() {
                builder.stderr(process::Stdio::Handle(log_file.as_handle()));
            }

            if let Some(mut sandbox_profile) = config.sandbox_profile {
                sandbox_profile
                    .try_apply(&mut builder)
                    .context("failed to apply mesh sandbox profile")?;
            }

            let (invitation, handle) = match (
                builder.app_container_sid(),
                config.app_container_peers.as_slice(),
                config.peer_endpoint_mode,
            ) {
                (_, _, PeerEndpointMode::Conflicting) => {
                    anyhow::bail!("trusted-host and AppContainer peer modes cannot be combined")
                }
                (Some(_), _, PeerEndpointMode::TrustedHost) => {
                    anyhow::bail!("trusted-host peer endpoint must not configure an AppContainer")
                }
                (Some(sid), peers, PeerEndpointMode::AppContainer) => {
                    self.node.invite_app_container_with_peers(recv, sid, peers)
                }
                (None, peers, PeerEndpointMode::TrustedHost) => {
                    self.node.invite_with_app_container_peers(recv, peers)
                }
                (None, [], PeerEndpointMode::AppContainer) => self.node.invite(recv),
                (None, _, PeerEndpointMode::AppContainer) => {
                    anyhow::bail!("AppContainer peer requires an AppContainer sandbox profile")
                }
            }
            .context("mesh node invite error")?;
            node_id = invitation.node_id();
            let (credentials, directory) = invitation.into_parts();
            let invitation_env = base64::engine::general_purpose::STANDARD.encode(
                mesh::payload::encode(Invitation {
                    node_name: name.clone(),
                    credentials,
                    directory_handle: directory.as_raw_handle() as usize,
                }),
            );
            builder
                .handle(&directory)
                .env(INVITATION_ENV_NAME, invitation_env);

            // Launch the child process on a separate thread to isolate
            // the CreateProcess call from other IO pools.
            let prepared = owned
                .then(owned_host::PreparedRoot::new)
                .transpose()
                .context("failed to reserve root reaper")?;
            let result = std::thread::scope(|scope| {
                let thread = std::thread::Builder::new().spawn_scoped(scope, || {
                    if let Some(launch) = launch {
                        launch.enter_native()?;
                    }
                    builder.spawn()
                })?;
                thread
                    .join()
                    .map_err(|_| std::io::Error::other("mesh native creation thread panicked"))
            })
            .context("failed to run native creation thread")?;
            let child = match result {
                Ok(child) => child,
                Err(error) => {
                    if let Some(launch) = launch {
                        launch.no_root();
                    }
                    return Err(error).context("failed to launch mesh process");
                }
            };
            if let Some(job) = host_job {
                let prepared = prepared.expect("owned launch reserved a reaper");
                launch
                    .expect("owned launch has a receipt")
                    .observe_root(prepared.exit());
                let host = prepared
                    .finish(child, job)
                    .context("failed to own mesh root")?;
                self.track_owned_host(&host, name, node_id, request_send, handle);
                return Ok(LaunchedHost::Owned(host));
            }
            // Wait for the child to connect to the mesh. TODO: timeout
            handle.await;
            pid = child.id() as i32;
            tracing::Span::current().record("pid", pid);

            pal_async::windows::PolledProcess::new(&self.node_driver, child)
                .expect("failed to create process wait")
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

            if let Some(log_file) = config.stdout.as_ref() {
                command.stdout(process::Stdio::Fd(log_file.as_fd()));
            }
            if let Some(log_file) = config.stderr.as_ref() {
                command.stderr(process::Stdio::Fd(log_file.as_fd()));
            }

            if let Some(mut sandbox_profile) = config.sandbox_profile {
                sandbox_profile
                    .try_apply(&mut command)
                    .context("failed to apply mesh sandbox profile")?;
            }

            // Launch the child process on a separate thread to isolate
            // the fork() call from other IO pools.
            #[cfg(target_os = "linux")]
            let prepared = owned
                .then(owned_host::PreparedRoot::new)
                .transpose()
                .context("failed to reserve root reaper")?;
            let result = std::thread::scope(|scope| {
                let thread = std::thread::Builder::new().spawn_scoped(scope, || {
                    #[cfg(target_os = "linux")]
                    {
                        if let Some(launch) = launch {
                            launch.enter_native().map_err(|error| (error, None))?;
                        }
                        if owned {
                            return command
                                .spawn_captured()
                                .map_err(process::SpawnError::into_parts);
                        }
                    }
                    command.spawn().map_err(|error| (error, None))
                })?;
                thread
                    .join()
                    .map_err(|_| std::io::Error::other("mesh native creation thread panicked"))
            })
            .context("failed to run native creation thread")?;
            let child = match result {
                Ok(child) => child,
                Err((error, failed_child)) => {
                    #[cfg(target_os = "linux")]
                    if let Some(launch) = launch {
                        if let Some(child) = failed_child {
                            let prepared = prepared.expect("owned launch reserved a reaper");
                            launch.observe_root(prepared.exit());
                            prepared.reap(child, true);
                        } else {
                            launch.no_root();
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    let _: Option<process::Child> = failed_child;
                    return Err(error).context("failed to launch mesh process");
                }
            };
            #[cfg(target_os = "linux")]
            if owned {
                let prepared = prepared.expect("owned launch reserved a reaper");
                launch
                    .expect("owned launch has a receipt")
                    .observe_root(prepared.exit());
                let host = prepared.finish(child).context("failed to own mesh root")?;
                self.track_owned_host(&host, name, node_id, request_send);
                return Ok(LaunchedHost::Owned(host));
            }
            pid = child.id();
            tracing::Span::current().record("pid", pid);

            pal_async::process::PolledChild::<process::Child>::new(&self.node_driver, child)
                .expect("failed to create process wait")
        };

        let id = self.hosts.insert(MeshHostInner {
            name: config.name,
            pid,
            node_id,
            send: request_send,
        });

        let task = self
            .node_driver
            .spawn(format!("wait-mesh-child-{}", pid), async move {
                wait_mesh_child(child, &name, pid).await;
                id
            });

        self.waiters.push(task);
        Ok(LaunchedHost::Legacy(pid))
    }

    #[cfg(any(windows, target_os = "linux"))]
    fn track_owned_host(
        &mut self,
        host: &OwnedHost,
        name: String,
        node_id: mesh::NodeId,
        send: mesh::Sender<HostRequest>,
        #[cfg(windows)] invitation: mesh_remote::windows::AlpcInvitationHandle,
    ) {
        let pid = host.id();
        tracing::Span::current().record("pid", pid);
        let id = self.hosts.insert(MeshHostInner {
            name,
            pid,
            node_id,
            send,
        });
        let exit = host.exit();
        self.waiters.push(self.node_driver.spawn(
            format!("wait-owned-mesh-child-{pid}"),
            async move {
                // Keep the invitation valid until the child joins or exits;
                // never wait for a handshake before returning launch ownership.
                #[cfg(windows)]
                let _invitation = invitation;
                match exit.await {
                    Ok(status) => tracing::info!(pid, ?status, "owned mesh root exited"),
                    Err(error) => tracing::error!(pid, %error, "owned mesh root wait failed"),
                }
                id
            },
        ));
    }
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
    use test_with_tracing::test;

    #[test]
    fn sandbox_profile_try_apply_preserves_legacy_apply() {
        struct Profile(bool);
        impl SandboxProfile for Profile {
            fn apply(&mut self, _: &mut ProcessBuilder<'_>) {
                self.0 = true;
            }
        }

        let mut profile = Profile(false);
        profile
            .try_apply(&mut ProcessBuilder::new("unused"))
            .unwrap();
        assert!(profile.0);
    }

    #[async_test]
    async fn sandbox_profile_failure_prevents_spawn(_driver: DefaultDriver) {
        struct Profile;
        impl SandboxProfile for Profile {
            fn apply(&mut self, _: &mut ProcessBuilder<'_>) {
                panic!("fallible profiles must not fall back to apply");
            }

            fn try_apply(&mut self, _: &mut ProcessBuilder<'_>) -> anyhow::Result<()> {
                anyhow::bail!("test profile setup failed")
            }
        }

        let mesh = Mesh::new("profile-failure".into()).unwrap();
        let config = || {
            ProcessConfig::new_with_sandbox("profile-failure", Box::new(Profile))
                .process_name("nonexistent-mesh-profile-test-executable")
        };
        let error = mesh.launch_host(config(), ()).await.err().unwrap();
        assert!(
            format!("{error:#}").contains("test profile setup failed"),
            "{error:#}"
        );
        #[cfg(any(windows, target_os = "linux"))]
        {
            let error = mesh.launch_host_owned(config(), ()).await.err().unwrap();
            assert!(
                format!("{error:#}").contains("test profile setup failed"),
                "{error:#}"
            );
        }
        mesh.shutdown().await;
    }

    #[cfg(windows)]
    #[async_test]
    async fn sandbox_profile_app_container_rejects_broad_sid(_driver: DefaultDriver) {
        struct Profile;
        impl SandboxProfile for Profile {
            fn apply(&mut self, builder: &mut ProcessBuilder<'_>) {
                let sid = pal::windows::security::Sid::new([0, 0, 0, 0, 0, 15], [2, 1]);
                builder.app_container(sid.as_ref());
            }
        }

        let mesh = Mesh::new("app-container-rejection".into()).unwrap();
        let config = || {
            ProcessConfig::new_with_sandbox("app-container-rejection", Box::new(Profile))
                .process_name("nonexistent-mesh-profile-test-executable")
        };
        let error = mesh.launch_host(config(), ()).await.err().unwrap();
        assert!(
            format!("{error:#}").contains("expected a unique package SID"),
            "{error:#}"
        );
        let error = mesh.launch_host_owned(config(), ()).await.err().unwrap();
        assert!(
            format!("{error:#}").contains("expected a unique package SID"),
            "{error:#}"
        );
        mesh.shutdown().await;
    }

    #[cfg(windows)]
    #[test]
    fn app_container_peers_are_owned_appended_and_deduplicated() {
        use pal::windows::security::MaximumSid;

        let mut config = ProcessConfig::new("star");
        let identities = ["S-1-15-2-1-2-3-4-5-6-7", "S-1-15-2-8-9-10-11-12-13-14"];
        for text in identities.into_iter().chain(identities) {
            {
                let sid: MaximumSid = text.parse().unwrap();
                config = config.app_container_peer(sid.as_ref());
            }
        }
        assert_eq!(
            config
                .app_container_peers
                .iter()
                .map(|sid| sid.to_string_sid())
                .collect::<Vec<_>>(),
            identities
        );
    }

    #[cfg(windows)]
    #[test]
    fn trusted_host_peers_are_owned_appended_and_deduplicated() {
        use pal::windows::security::MaximumSid;

        let mut config = ProcessConfig::new("trusted-host");
        let identities = ["S-1-15-2-1-2-3-4-5-6-7", "S-1-15-2-8-9-10-11-12-13-14"];
        for text in identities.into_iter().chain(identities) {
            let sid: MaximumSid = text.parse().unwrap();
            config = config.trusted_host_app_container_peer(sid.as_ref());
        }
        assert!(matches!(
            config.peer_endpoint_mode,
            PeerEndpointMode::TrustedHost
        ));
        assert_eq!(
            config
                .app_container_peers
                .iter()
                .map(|sid| sid.to_string_sid())
                .collect::<Vec<_>>(),
            identities
        );
    }

    #[cfg(windows)]
    #[async_test]
    async fn trusted_host_peer_launch_does_not_require_app_container(driver: DefaultDriver) {
        use owned_host::tests::{bounded, config, ready};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trusted-host");
        let sid: pal::windows::security::MaximumSid = "S-1-15-2-1-2-3-4-5-6-7".parse().unwrap();
        let mesh = Mesh::new("trusted-peer-launch".into()).unwrap();
        let mut host = bounded(
            &driver,
            mesh.launch_host_owned(
                config(&path).trusted_host_app_container_peer(sid.as_ref()),
                (),
            ),
        )
        .await
        .unwrap();
        ready(&driver, &path).await;
        host.terminate_root().unwrap();
        bounded(&driver, host.wait_root()).await.unwrap();
        bounded(&driver, mesh.shutdown()).await;
    }

    #[cfg(windows)]
    #[async_test]
    async fn trusted_host_peer_rejects_invalid_sid_before_spawn(driver: DefaultDriver) {
        use owned_host::tests::bounded;
        use pal::windows::security::MaximumSid;

        let valid: MaximumSid = "S-1-15-2-1-2-3-4-5-6-7".parse().unwrap();
        let mesh = Mesh::new("trusted-invalid-peer".into()).unwrap();
        for invalid in [
            "S-1-1-0",
            "S-1-15-2-1",
            "S-1-15-2-1-2-3",
            "S-1-15-3-1-2-3-4-5-6-7",
        ] {
            let invalid: MaximumSid = invalid.parse().unwrap();
            let config = || {
                ProcessConfig::new("trusted-invalid-peer")
                    .process_name("nonexistent-mesh-profile-test-executable")
                    .trusted_host_app_container_peer(valid.as_ref())
                    .trusted_host_app_container_peer(invalid.as_ref())
            };
            let error = bounded(&driver, mesh.launch_host(config(), ()))
                .await
                .err()
                .unwrap();
            assert!(
                format!("{error:#}").contains("expected a unique package SID"),
                "{error:#}"
            );
            let mut pending = mesh.begin_launch_host_owned(config(), ());
            let error = bounded(&driver, pending.wait_host()).await.err().unwrap();
            assert!(
                format!("{error:#}").contains("expected a unique package SID"),
                "{error:#}"
            );
            assert_eq!(
                bounded(&driver, pending.wait_completion()).await.unwrap(),
                LaunchCompletion::NeverSpawned
            );
        }
        bounded(&driver, mesh.shutdown()).await;
    }

    #[cfg(windows)]
    #[async_test]
    async fn trusted_host_peer_rejects_conflicting_modes_before_spawn(driver: DefaultDriver) {
        use owned_host::tests::bounded;
        use pal::windows::security::MaximumSid;

        struct Profile;
        impl SandboxProfile for Profile {
            fn apply(&mut self, builder: &mut ProcessBuilder<'_>) {
                let sid: MaximumSid = "S-1-15-2-1-2-3-4-5-6-7".parse().unwrap();
                builder.app_container(sid.as_ref());
            }
        }
        let sid: MaximumSid = "S-1-15-2-8-9-10-11-12-13-14".parse().unwrap();
        let mesh = Mesh::new("trusted-peer-conflict".into()).unwrap();
        for mode in 0..3 {
            let config = || {
                let config = if mode == 2 {
                    ProcessConfig::new_with_sandbox("trusted-peer-conflict", Box::new(Profile))
                } else {
                    ProcessConfig::new("trusted-peer-conflict")
                }
                .process_name("nonexistent-mesh-profile-test-executable");
                match mode {
                    0 => config
                        .app_container_peer(sid.as_ref())
                        .trusted_host_app_container_peer(sid.as_ref())
                        .app_container_peer(sid.as_ref()),
                    1 => config
                        .trusted_host_app_container_peer(sid.as_ref())
                        .app_container_peer(sid.as_ref())
                        .trusted_host_app_container_peer(sid.as_ref()),
                    _ => config.trusted_host_app_container_peer(sid.as_ref()),
                }
            };
            let expected = if mode == 2 {
                "trusted-host peer endpoint must not configure an AppContainer"
            } else {
                "trusted-host and AppContainer peer modes cannot be combined"
            };
            let error = bounded(&driver, mesh.launch_host(config(), ()))
                .await
                .err()
                .unwrap();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
            let mut pending = mesh.begin_launch_host_owned(config(), ());
            let error = bounded(&driver, pending.wait_host()).await.err().unwrap();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
            assert_eq!(
                bounded(&driver, pending.wait_completion()).await.unwrap(),
                LaunchCompletion::NeverSpawned
            );
        }
        bounded(&driver, mesh.shutdown()).await;
    }

    #[cfg(windows)]
    #[async_test]
    async fn app_container_peer_requires_profile(_driver: DefaultDriver) {
        let sid: pal::windows::security::MaximumSid = "S-1-15-2-1-2-3-4-5-6-7".parse().unwrap();
        let mesh = Mesh::new("peer-without-profile".into()).unwrap();
        let config = || {
            ProcessConfig::new("peer-without-profile")
                .app_container_peer(sid.as_ref())
                .process_name("nonexistent-mesh-profile-test-executable")
        };
        for error in [
            mesh.launch_host(config(), ()).await.err().unwrap(),
            mesh.launch_host_owned(config(), ()).await.err().unwrap(),
        ] {
            assert!(
                format!("{error:#}")
                    .contains("AppContainer peer requires an AppContainer sandbox profile"),
                "{error:#}"
            );
        }
        mesh.shutdown().await;
    }

    #[cfg(windows)]
    #[async_test]
    async fn app_container_peer_list_rejects_broad_before_spawn(_driver: DefaultDriver) {
        use pal::windows::security::MaximumSid;

        struct Profile;
        impl SandboxProfile for Profile {
            fn apply(&mut self, builder: &mut ProcessBuilder<'_>) {
                let sid: MaximumSid = "S-1-15-2-1-2-3-4-5-6-7".parse().unwrap();
                builder.app_container(sid.as_ref());
            }
        }

        let valid: MaximumSid = "S-1-15-2-8-9-10-11-12-13-14".parse().unwrap();
        let broad: MaximumSid = "S-1-15-2-1".parse().unwrap();
        let mesh = Mesh::new("invalid-peer-list".into()).unwrap();
        let config = || {
            ProcessConfig::new_with_sandbox("invalid-peer-list", Box::new(Profile))
                .app_container_peer(valid.as_ref())
                .app_container_peer(broad.as_ref())
                .process_name("nonexistent-mesh-profile-test-executable")
        };
        for error in [
            mesh.launch_host(config(), ()).await.err().unwrap(),
            mesh.launch_host_owned(config(), ()).await.err().unwrap(),
        ] {
            assert!(
                format!("{error:#}").contains("expected a unique package SID"),
                "{error:#}"
            );
        }
        mesh.shutdown().await;
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

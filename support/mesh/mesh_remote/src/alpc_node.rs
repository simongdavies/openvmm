// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows ALPC-based mesh node implementation.

#![cfg(windows)]
// UNSAFETY: Needed to implement the Buffer trait.
#![expect(unsafe_code)]

use crate::common::InvitationAddress;
use crate::protocol;
use constant_time_eq::constant_time_eq_32;
use futures::FutureExt;
use futures::StreamExt;
use futures::channel::mpsc;
use futures::future::AbortHandle;
use futures::future::abortable;
use mesh_node::common::Address;
use mesh_node::common::NodeId;
use mesh_node::common::PortId;
use mesh_node::common::Uuid;
use mesh_node::local_node::Connect;
use mesh_node::local_node::LocalNode;
use mesh_node::local_node::OutgoingEvent;
use mesh_node::local_node::Port;
use mesh_node::local_node::RemoteNodeHandle;
use mesh_node::local_node::SendEvent;
use mesh_node::resource::OsResource;
use mesh_node::resource::Resource;
use mesh_protobuf::Protobuf;
use mesh_protobuf::buffer::Buffer;
use pal::windows::BorrowedHandleExt;
use pal::windows::ObjectAttributes;
use pal::windows::OwnedSocketExt;
use pal::windows::UnicodeString;
use pal::windows::alpc;
use pal::windows::alpc::PortSection;
use pal::windows::alpc::SendMessage;
use pal::windows::create_object_directory;
use pal::windows::open_object_directory;
use pal::windows::security::LocalSecurityDescriptor;
use pal::windows::security::MaximumSid;
use pal::windows::security::SecurityDescriptor;
use pal::windows::security::Sid;
use pal::windows::security::current_process_user_sid;
use pal::windows::security::grant_low_integrity_kernel_object_access;
use pal_async::driver::Driver;
use pal_async::task::Spawn;
use pal_async::task::Task;
use pal_async::wait::PolledWait;
use parking_lot::Mutex;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::ops::Deref;
use std::os::windows::prelude::*;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use tracing_helpers::ErrorValueExt;
use unicycle::FuturesUnordered;
use windows_sys::Wdk::System::SystemServices::DIRECTORY_CREATE_OBJECT;
use windows_sys::Wdk::System::SystemServices::DIRECTORY_CREATE_SUBDIRECTORY;
use windows_sys::Wdk::System::SystemServices::DIRECTORY_QUERY;
use windows_sys::Wdk::System::SystemServices::DIRECTORY_TRAVERSE;
use windows_sys::Win32::Storage::FileSystem::STANDARD_RIGHTS_REQUIRED;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

/// A 256-bit mesh secret used to authenticate ALPC connections.
///
/// Implements constant-time comparison and redacted `Debug` output.
#[derive(Clone, Copy, Protobuf, FromBytes, IntoBytes, Immutable)]
#[mesh(transparent)]
#[repr(transparent)]
pub(crate) struct MeshSecret(
    #[mesh(encoding = "mesh_protobuf::encoding::ZeroCopyEncoding")] [u8; 32],
);

impl MeshSecret {
    /// Generate a new random mesh secret.
    fn new() -> Self {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).unwrap();
        Self(secret)
    }
}

impl PartialEq for MeshSecret {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_32(&self.0, &other.0)
    }
}

impl Eq for MeshSecret {}

impl Debug for MeshSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MeshSecret([REDACTED])")
    }
}

/// Errors from internal node setup (`with_id`).
#[derive(Debug, thiserror::Error)]
pub enum NodeSetupError {
    #[error("failed to retain ALPC security handle")]
    SecurityHandle(#[source] io::Error),
    #[error("failed to create ALPC port for node {node:?}")]
    CreateAlpcPort {
        node: NodeId,
        #[source]
        source: io::Error,
    },
    #[error("failed to create polled wait for node {node:?}")]
    CreatePolledWait {
        node: NodeId,
        #[source]
        source: io::Error,
    },
}

/// Errors from [`AlpcNode::new`] and [`AlpcNode::new_named`].
#[derive(Debug, thiserror::Error)]
#[expect(missing_docs)]
pub enum NewNodeError {
    #[error("failed to create object directory")]
    CreateDirectory(#[source] io::Error),
    #[error("invalid directory path")]
    InvalidDirectoryPath,
    #[error(transparent)]
    Setup(#[from] NodeSetupError),
}

/// Errors from [`AlpcNode::join`] and [`AlpcNode::join_named`].
#[derive(Debug, thiserror::Error)]
#[expect(missing_docs)]
pub enum JoinError {
    #[error("invalid endpoint security descriptor")]
    SecurityDescriptor(#[source] io::Error),
    #[error("invalid directory path")]
    InvalidDirectoryPath,
    #[error("failed to open object directory {path}")]
    OpenDirectory {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Setup(#[from] NodeSetupError),
}

/// Errors from inviting a node to the mesh.
#[derive(Debug, thiserror::Error)]
#[expect(missing_docs)]
pub enum InviteError {
    #[error("node shut down")]
    NodeShutDown,
    #[error("named invitations require a named directory node")]
    NamedInvitationNotSupported,
    #[error(transparent)]
    Io(#[from] io::Error),
}

type InvitationMap =
    Arc<Mutex<HashMap<NodeId, (RemoteNodeHandle, mesh_channel::OneshotSender<()>)>>>;

/// Shared state needed to create invitations.
#[derive(Clone)]
struct InviteContext {
    directory: Arc<OwnedHandle>,
    local_node: Arc<LocalNode>,
    invitations: InvitationMap,
    mesh_secret: MeshSecret,
}

impl InviteContext {
    /// Shared setup for creating an invitation (without spawning).
    ///
    /// Returns the invitation address, an `InvitationHandle`, and the
    /// init port receiver.
    fn invite_setup(
        &self,
    ) -> Result<
        (
            InvitationAddress,
            InvitationHandle,
            mesh_channel::OneshotReceiver<InitialMessage>,
        ),
        InviteError,
    > {
        let local_addr = Address {
            node: self.local_node.id(),
            port: PortId::new(),
        };
        let remote_addr = Address {
            node: NodeId::new(),
            port: PortId::new(),
        };
        let (invitation_done_send, invitation_done_recv) = mesh_channel::oneshot();
        let handle = self.local_node.add_remote(remote_addr.node);
        self.invitations
            .lock()
            .insert(remote_addr.node, (handle, invitation_done_send));

        let init_recv = <mesh_channel::OneshotReceiver<InitialMessage>>::from(
            self.local_node.add_port(local_addr.port, remote_addr),
        );

        let address = InvitationAddress {
            local_addr: remote_addr,
            remote_addr: local_addr,
        };
        let invitation_handle = InvitationHandle {
            local_id: local_addr.node,
            remote_id: remote_addr.node,
            invitations: self.invitations.clone(),
            invitation_done: invitation_done_recv,
        };

        Ok((address, invitation_handle, init_recv))
    }

    /// Common logic for creating an invitation: runs `invite_setup`, spawns
    /// the `wait_for_invite` task, and builds `InvitationCredentials`.
    ///
    /// If `dup_directory` is true, an inheritable copy of the directory handle
    /// is returned (needed for handle-based invitations). Otherwise `None`.
    fn process_invite(
        &self,
        driver: &impl Spawn,
        port: Port,
        dup_directory: bool,
        directory_access: u32,
    ) -> Result<(InvitationCredentials, Option<OwnedHandle>, InvitationHandle), InviteError> {
        // Duplicate the handle first (fallible) before mutating shared state.
        let dir = if dup_directory {
            Some(
                self.directory
                    .as_handle()
                    .duplicate(true, Some(directory_access))?,
            )
        } else {
            None
        };
        let (addr, handle, init_recv) = self.invite_setup()?;
        driver
            .spawn(
                "mesh alpc invitation",
                Self::wait_for_invite(init_recv, addr.remote_addr, addr.local_addr, port),
            )
            .detach();
        Ok((
            InvitationCredentials {
                address: addr,
                mesh_secret: self.mesh_secret,
                endpoint_security: None,
            },
            dir,
            handle,
        ))
    }

    /// Async task that waits for the init message and bridges ports.
    async fn wait_for_invite(
        mut init_recv: mesh_channel::OneshotReceiver<InitialMessage>,
        local_addr: Address,
        remote_addr: Address,
        port: Port,
    ) {
        match (&mut init_recv).await {
            Ok(init_message) => {
                tracing::trace!(
                    node = ?local_addr.node,
                    remote_node = ?remote_addr.node,
                    "received initial message",
                );
                init_message.user_port.bridge(port);
            }
            Err(err) => {
                tracing::error!(
                    node = ?local_addr.node,
                    remote_node = ?remote_addr.node,
                    error = err.as_error(),
                    "invitation initial message failed",
                );
                Port::from(init_recv).bridge(port);
            }
        }
    }

    /// Runs the invite handler task, processing invite requests from
    /// `AlpcMeshInviter` handles.
    async fn run_invite_handler(
        self,
        mut invite_request_recv: mesh_channel::Receiver<AlpcInviteRequest>,
        directory_path: Option<String>,
        driver: impl Spawn,
    ) {
        while let Ok(request) = invite_request_recv.recv().await {
            match request {
                AlpcInviteRequest::InviteNamed(rpc) => {
                    let Some(ref dir_path) = directory_path else {
                        rpc.complete(Err(InviteError::NamedInvitationNotSupported));
                        continue;
                    };
                    let dir_path = dir_path.clone();
                    rpc.handle_sync(|port| {
                        let (creds, _, handle) = self.process_invite(&driver, port, false, 0)?;
                        Ok((
                            NamedInvitation {
                                credentials: creds,
                                directory_path: dir_path,
                            },
                            handle,
                        ))
                    });
                }
            }
        }
    }
}

/// The maximum ALPC message size to use. Messages larger than this will be
/// transferred in secure views.
///
/// This value was chosen arbitrarily and has not been performance tested.
const MAX_MESSAGE_SIZE: usize = 0x1000;
const MAX_SMALL_EVENT_SIZE: usize = MAX_MESSAGE_SIZE - size_of::<protocol::PacketHeader>();
const DIRECTORY_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED
    | DIRECTORY_QUERY
    | DIRECTORY_TRAVERSE
    | DIRECTORY_CREATE_OBJECT
    | DIRECTORY_CREATE_SUBDIRECTORY;

/// ALPC connection data — sent as the connection message payload.
/// Uses zerocopy for safe transmutation to/from bytes.
#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct AlpcConnectionData {
    node_id: [u8; 16],
    mesh_secret: MeshSecret,
}

/// The serializable portion of an invitation: address, mesh secret and optional
/// endpoint security.
/// Derives `Protobuf` so callers (e.g., `mesh_process`) can easily
/// encode/decode it for passing to child processes.
#[derive(Debug, Clone, Protobuf)]
pub struct InvitationCredentials {
    /// The invitation address.
    pub(crate) address: InvitationAddress,
    /// The mesh secret for ALPC connection auth.
    pub(crate) mesh_secret: MeshSecret,
    /// Optional security descriptor for the joining node's server endpoint.
    /// This is transient, private bootstrap ACL metadata, not persistent
    /// AppContainer profile ownership or a way to recreate it from SID text.
    endpoint_security: Option<String>,
}

/// Invitation for connecting already-running processes — pure data.
/// Composes `InvitationCredentials` with a directory path.
/// Derives `Protobuf` for wire serialization over the invitation socket.
#[derive(Debug, Protobuf)]
pub struct NamedInvitation {
    credentials: InvitationCredentials,
    directory_path: String,
}

/// A node within a mesh that uses Windows ALPC to communicate.
///
/// Each node within the mesh has an ALPC server port for incoming data and
/// multiple ALPC client ports for sending data to other nodes. ALPC port
/// communication is half duplex to simplify connection establishment and
/// lifetime management.
///
/// Since ALPC ports cannot be sent cross-process, the server ports are named
/// and exist within the Ob namespace. To prevent processes from outside the
/// mesh connecting to one of the ALPC ports, the server ports reside in an
/// anonymous Ob directory whose handle is duplicated into processes within the
/// mesh.
pub struct AlpcNode {
    driver: Box<dyn InvitationDriver>,
    invite_ctx: InviteContext,
    // Invitation handlers can outlive shutdown and must not retain the listener.
    server_security: Mutex<OwnedHandle>,
    recv_abort: AbortHandle,
    recv_task: Task<()>,
    connect_task: Task<()>,
    connect_send: mpsc::UnboundedSender<(NodeId, RemoteNodeHandle)>,
    /// Sender for invite requests (used by `AlpcMeshInviter`).
    invite_request_send: mesh_channel::Sender<AlpcInviteRequest>,
}

trait InvitationDriver: Spawn + Send {}

impl<T> InvitationDriver for T where T: Spawn + Send {}

use mesh_channel::rpc::Rpc;
use mesh_channel::rpc::RpcSend;

/// Request types for the invite handler task.
enum AlpcInviteRequest {
    InviteNamed(Rpc<Port, Result<(NamedInvitation, InvitationHandle), InviteError>>),
}

/// A Clone + Send handle for creating mesh invitations.
///
/// Extracted from an [`AlpcNode`] via [`AlpcNode::inviter()`]. This delegates
/// invitation requests to the node's invite handler task.
///
/// This allows creating invitations from any async task without holding a
/// reference to the node.
#[derive(Clone)]
pub(crate) struct AlpcMeshInviter {
    request_send: mesh_channel::Sender<AlpcInviteRequest>,
}

impl AlpcMeshInviter {
    /// Create a named invitation (for named-directory nodes only).
    /// Returns error if the node uses an anonymous directory.
    pub async fn invite_named(
        &self,
        port: Port,
    ) -> Result<(NamedInvitation, InvitationHandle), InviteError> {
        self.request_send
            .call(AlpcInviteRequest::InviteNamed, port)
            .await
            .map_err(|_| InviteError::NodeShutDown)?
    }
}

/// A handle for an invitation, created by [`AlpcNode::invite`]. It can be
/// awaited to wait for the invitation to be accepted. When dropped, it will
/// cancel the invitation if it has not already been accepted.
#[derive(Debug)]
pub struct InvitationHandle {
    invitations: InvitationMap,
    local_id: NodeId,
    remote_id: NodeId,
    invitation_done: mesh_channel::OneshotReceiver<()>,
}

impl Future for InvitationHandle {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.invitation_done.poll_unpin(cx).map(|_| ())
    }
}

impl Drop for InvitationHandle {
    fn drop(&mut self) {
        let invitation = self.invitations.lock().remove(&self.remote_id);
        if let Some((handle, _invitation_done)) = invitation {
            tracing::warn!(
                node = ?self.local_id,
                remote_node = ?self.remote_id,
                "invitation dropped without connection",
            );
            // Invalidate the remote node.
            drop(handle);
        }
    }
}

/// An invitation allowing another process to join the mesh.
/// For child process spawning — credentials + directory handle.
#[derive(Debug)]
pub struct Invitation {
    credentials: InvitationCredentials,
    directory: OwnedHandle,
}

impl Invitation {
    /// Create an invitation from its credentials and directory handle.
    pub fn new(credentials: InvitationCredentials, directory: OwnedHandle) -> Self {
        Self {
            credentials,
            directory,
        }
    }

    /// The node ID assigned to the joining process.
    pub fn node_id(&self) -> NodeId {
        self.credentials.address.local_addr.node
    }

    /// Consume the invitation into its credentials and directory handle.
    pub fn into_parts(self) -> (InvitationCredentials, OwnedHandle) {
        (self.credentials, self.directory)
    }
}

#[derive(Debug, Protobuf)]
#[mesh(resource = "Resource")]
struct InitialMessage {
    user_port: Port,
}

/// The relative NT path to a server ALPC port within the anonymous directory.
fn node_path(node_id: NodeId) -> UnicodeString {
    format!("{:?}", node_id).try_into().unwrap()
}

fn invitation_endpoint_security<'a>(
    own_sid: Option<&Sid>,
    peer_sids: impl IntoIterator<Item = &'a Sid>,
) -> io::Result<String> {
    fn package_sid_text(sid: &Sid) -> io::Result<String> {
        let text = sid.to_string_sid();
        if !text.starts_with("S-1-15-2-") || text.split('-').count() != 11 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a unique package SID",
            ));
        }
        Ok(text)
    }

    let own_sid = own_sid.map(package_sid_text).transpose()?;
    let mut peers = BTreeSet::new();
    for peer_sid in peer_sids {
        let peer_text = package_sid_text(peer_sid)?;
        if own_sid.as_deref() == Some(peer_text.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AppContainer peer SID must differ from its own SID",
            ));
        }
        peers.insert(peer_text);
    }
    let mut access = String::new();
    if let Some(own_sid) = own_sid {
        access.push_str(&format!("(A;;GA;;;{own_sid})"));
    }
    for peer in peers {
        access.push_str(&format!("(A;;0x1;;;{peer})"));
    }
    // The default object owner can be Administrators for an elevated parent.
    // The user SID still participates in the child's token.
    let user = current_process_user_sid()?;
    Ok(format!(
        "D:P(A;;GA;;;{})(A;;GA;;;SY){access}S:(ML;;NW;;;LW)",
        user.to_string_sid()
    ))
}

impl AlpcNode {
    /// Creates a node within a new mesh, with an anonymous Ob directory.
    ///
    /// The directory handle is inherited by child processes. A mesh secret
    /// is generated for ALPC connection authentication.
    pub fn new(driver: impl Driver + Spawn + Clone) -> Result<Self, NewNodeError> {
        Self::new_mesh(driver, None)
    }

    /// Creates a node within a new mesh, with a named Ob directory.
    ///
    /// The directory is created at `\BaseNamedObjects\mesh-<node-id>`
    /// (where `<node-id>` is the UUID of the node) with the default DACL
    /// (current user + SYSTEM). A 256-bit mesh secret is generated for
    /// ALPC connection authentication.
    ///
    /// Use this when other already-running processes need to connect to this
    /// mesh (via socket invitations). For child process spawning, use
    /// `new()` instead.
    pub fn new_named(driver: impl Driver + Spawn + Clone) -> Result<Self, NewNodeError> {
        let id = NodeId::new();
        let path_string = format!(r"\BaseNamedObjects\mesh-{}", id.0);
        Self::new_mesh(driver, Some(path_string))
    }

    /// Shared implementation for `new` and `new_named`: creates the Ob
    /// directory, generates a mesh secret, and creates the node.
    fn new_mesh(
        driver: impl Driver + Spawn + Clone,
        directory_path: Option<String>,
    ) -> Result<Self, NewNodeError> {
        let path;
        let mut attr = ObjectAttributes::new();
        if let Some(ref dir_path) = directory_path {
            path = UnicodeString::try_from(dir_path.as_str())
                .map_err(|_| NewNodeError::InvalidDirectoryPath)?;
            attr.name(&path);
        }
        let directory = create_object_directory(&attr, DIRECTORY_ALL_ACCESS)
            .map_err(NewNodeError::CreateDirectory)?;

        // Generate a 256-bit mesh secret for ALPC connection authentication.
        // Every connecting node must present this secret to be accepted.
        let secret = MeshSecret::new();
        Ok(Self::with_id(
            driver,
            NodeId::new(),
            directory,
            secret,
            directory_path,
            None,
        )?)
    }

    /// Gets the node ID. This is mostly useful for diagnostics.
    pub fn id(&self) -> NodeId {
        self.invite_ctx.local_node.id()
    }

    /// Extract an [`AlpcMeshInviter`] handle. Cheap — clones the sender.
    pub(crate) fn inviter(&self) -> AlpcMeshInviter {
        AlpcMeshInviter {
            request_send: self.invite_request_send.clone(),
        }
    }

    /// Creates a node with the specified ID within an existing mesh.
    fn with_id(
        driver: impl Driver + Spawn + Clone,
        local_id: NodeId,
        directory: OwnedHandle,
        mesh_secret: MeshSecret,
        directory_path: Option<String>,
        security_descriptor: Option<&SecurityDescriptor>,
    ) -> Result<Self, NodeSetupError> {
        let directory = Arc::new(directory);
        let name = node_path(local_id);
        let mut attributes = ObjectAttributes::new();
        attributes.root(directory.as_handle()).name(&name);
        if let Some(descriptor) = security_descriptor {
            attributes.security_descriptor(descriptor);
        }
        let port = alpc::PortConfig::new()
            .max_message_len(MAX_MESSAGE_SIZE)
            .waitable(true)
            .create(&attributes)
            .map_err(|e| NodeSetupError::CreateAlpcPort {
                node: local_id,
                source: e,
            })?;
        let server_security = Mutex::new(
            port.as_handle()
                .try_clone_to_owned()
                .map_err(NodeSetupError::SecurityHandle)?,
        );
        let port =
            PolledWait::new(&driver, port).map_err(|e| NodeSetupError::CreatePolledWait {
                node: local_id,
                source: e,
            })?;

        let invitations: InvitationMap = Default::default();
        #[expect(clippy::disallowed_methods)] // TODO
        let (connect_send, connect_recv) = mpsc::unbounded();
        let local_node = Arc::new(LocalNode::with_id(
            local_id,
            Box::new(AlpcConnector {
                connect_send: connect_send.clone(),
            }),
        ));

        let invite_ctx = InviteContext {
            directory,
            local_node,
            invitations,
            mesh_secret,
        };

        // Start the connect task for handling connecting to remote nodes.
        let connect_task = driver.spawn("mesh alpc connect", {
            let directory = invite_ctx.directory.clone();
            let driver = driver.clone();
            async move {
                Self::process_connects(&driver, local_id, directory, connect_recv, mesh_secret)
                    .await
            }
        });

        // Start a receive task, which will be aborted in shutdown().
        let (fut, recv_abort) = abortable(Self::process_recv(
            local_id,
            invite_ctx.local_node.clone(),
            port,
            Arc::clone(&invite_ctx.invitations),
            connect_send.clone(),
            mesh_secret,
        ));
        let recv_task = driver.spawn("mesh alpc recv", fut.map(drop));

        // Create the invite handler channel and task.
        let (invite_request_send, invite_request_recv) =
            mesh_channel::channel::<AlpcInviteRequest>();
        {
            let ctx = invite_ctx.clone();
            let driver_clone = driver.clone();
            driver
                .spawn(
                    "mesh alpc invite handler",
                    ctx.run_invite_handler(invite_request_recv, directory_path, driver_clone),
                )
                .detach();
        }

        Ok(Self {
            driver: Box::new(driver),
            invite_ctx,
            server_security,
            recv_abort,
            recv_task,
            connect_task,
            connect_send,
            invite_request_send,
        })
    }

    /// Async function for processing outgoing connection requests from the
    /// local node.
    async fn process_connects(
        driver: &(impl ?Sized + Driver),
        local_id: NodeId,
        directory: Arc<OwnedHandle>,
        mut connect_recv: mpsc::UnboundedReceiver<(NodeId, RemoteNodeHandle)>,
        mesh_secret: MeshSecret,
    ) {
        let teardowns: Mutex<HashMap<NodeId, mesh_channel::OneshotSender<()>>> = Default::default();
        let mut connect_tasks = FuturesUnordered::new();
        loop {
            // Receive a new request or drive any in-progress connection tasks
            // forward.
            let (remote_id, handle) = futures::select! { // merge semantics
                msg = connect_recv.next().fuse() => {
                    match msg {
                        Some(msg) => msg,
                        None => break,
                    }
                }
                _ = connect_tasks.next() => continue,
            };

            let (teardown_send, teardown_recv) = mesh_channel::oneshot();
            teardowns.lock().insert(remote_id, teardown_send);
            connect_tasks.push(Self::process_one_connect(
                driver,
                local_id,
                remote_id,
                handle,
                &directory,
                teardown_recv,
                &teardowns,
                &mesh_secret,
            ));
        }

        // Signal connections to tear down and wait for them to be aborted.
        teardowns.lock().clear();
        while connect_tasks.next().await.is_some() {}
    }

    /// Makes a connection to the ALPC port for `remote_id`, returning the port
    /// after it has successfully connected.
    async fn connect_alpc(
        driver: &(impl ?Sized + Driver),
        directory: &OwnedHandle,
        local_id: NodeId,
        remote_id: NodeId,
        mesh_secret: &MeshSecret,
    ) -> io::Result<PolledWait<AlpcPort>> {
        let data = AlpcConnectionData {
            node_id: (local_id.0).0,
            mesh_secret: *mesh_secret,
        };
        let config = alpc::PortConfig::new()
            .max_message_len(MAX_MESSAGE_SIZE)
            .waitable(true);
        let port = config.connect(
            ObjectAttributes::new()
                .root(directory.as_handle())
                .name(&node_path(remote_id)),
            data.as_bytes(),
        )?;

        let mut port = PolledWait::new(driver, AlpcPort(Arc::new(port)))?;
        port.wait().await?;
        let mut message = alpc::RecvMessageBuffer::new(0);
        let message = port
            .get()
            .try_recv(&mut message)?
            .expect("message should be available");
        match message.message_type() {
            alpc::MessageType::ConnectionReply | alpc::MessageType::Canceled => {
                // Canceled would indicate that the server has gone away after
                // accepting the offer. Since this is a race, act as though the
                // offer were successful--it will be failed soon.
            }
            ty => panic!("unexpected type {:?}", ty),
        }
        if message.needs_reply() {
            port.get().reply(message, &[])?;
        } else {
            drop(message);
        }
        Ok(port)
    }

    async fn process_one_connect(
        driver: &(impl ?Sized + Driver),
        local_id: NodeId,
        remote_id: NodeId,
        handle: RemoteNodeHandle,
        directory: &OwnedHandle,
        teardown_recv: mesh_channel::OneshotReceiver<()>,
        teardowns: &Mutex<HashMap<NodeId, mesh_channel::OneshotSender<()>>>,
        mesh_secret: &MeshSecret,
    ) {
        tracing::debug!(node = ?local_id, remote_node = ?remote_id, "connecting to node");
        match Self::connect_alpc(driver, directory, local_id, remote_id, mesh_secret).await {
            Ok(mut port) => {
                let (failed_send, failed_recv) = mesh_channel::oneshot();
                handle.connect(Connection {
                    local_id,
                    remote_id,
                    port: port.get().clone(),
                    failed_send: Mutex::new(Some(failed_send)),
                });
                tracing::debug!(node = ?local_id, remote_node = ?remote_id, "connected to node");

                // Wait for the ALPC port to be closed by the other endpoint, or
                // for a teardown request, or for a send to fail.
                //
                // N.B. when shutdown() is called, this await will be aborted.
                let result = futures::select! { // race semantics
                    _ = port.wait().fuse() => {
                        tracing::debug!(node = ?local_id, remote_node = ?remote_id, "remote node disconnection");
                        Ok(false)
                    }
                    r = failed_recv.fuse() => {
                        if let Ok(err) = r {
                            tracing::error!(
                                node = ?local_id,
                                remote_node = ?remote_id,
                                error = &err as &dyn std::error::Error,
                                "disconnecting from node due to failure");

                            Err(err)
                        } else {
                            // The node was disconnected in the receive path.
                            Ok(false)
                        }
                    }
                    _ = teardown_recv.fuse() => Ok(true),
                };
                match result {
                    Ok(true) => {
                        tracing::trace!(
                            node = ?local_id,
                            remote_node = ?remote_id,
                            "tearing down, sending flush request",
                        );
                        match port.get().request(&[]) {
                            Ok(_) => port.wait().await.expect("wait on handle cannot fail"),
                            Err(error) => {
                                // ERROR_INVALID_HANDLE is returned if the server
                                // disconnected the node before the flush, which is
                                // expected to occur sometimes depending on the
                                // order of teardown.
                                if error.raw_os_error() != Some(6 /* ERROR_INVALID_HANDLE */) {
                                    tracing::error!(
                                        node = ?local_id,
                                        remote_node = ?remote_id,
                                        error = error.as_error(),
                                        "failed to send node flush",
                                    );
                                }
                            }
                        }
                        tracing::debug!(node = ?local_id, remote_node = ?remote_id, "disconnected from remote node");
                        handle.disconnect();
                    }
                    Ok(false) => {
                        handle.disconnect();
                    }
                    Err(err) => {
                        handle.fail(err);
                    }
                }
                teardowns.lock().remove(&remote_id);
            }
            Err(err) => {
                tracing::error!(
                    node = ?local_id,
                    remote_node = ?remote_id,
                    error = err.as_error(),
                    "node connection failed"
                );
                handle.fail(err);
            }
        }
    }

    /// Invites a new node to join the mesh, returning information to be passed
    /// to the new process and to be passed to [`AlpcNode::join`]. Bridges
    /// `port` with the initial port.
    pub fn invite(&self, port: Port) -> Result<(Invitation, InvitationHandle), InviteError> {
        let (creds, dup_dir, invite_handle) =
            self.invite_ctx
                .process_invite(&self.driver, port, true, 0)?;
        Ok((
            Invitation {
                credentials: creds,
                directory: dup_dir.expect("requested"),
            },
            invite_handle,
        ))
    }

    /// Invites a trusted ordinary-user child whose endpoint accepts only the
    /// supplied exact AppContainer peers in addition to the user and SYSTEM.
    ///
    /// This is an explicit trusted-host policy, not AppContainer confinement.
    /// The child must run as the current user. Each peer receives PORT_CONNECT
    /// access and the endpoint has a low-integrity label. SIDs are validated
    /// and deduplicated before invitation setup; no child package SID is
    /// invented. An empty list preserves [`Self::invite`] behavior.
    ///
    /// The inherited directory handle is attenuated to traverse/create-object.
    /// No peer grants are added to this node's directory or endpoint here:
    /// peers join the same mesh through their own AppContainer invitations.
    /// Their endpoints' existing current-user grant permits the reverse
    /// connection. Identity ownership and replacement requirements from
    /// [`Self::invite_app_container_with_peers`] still apply to those peers.
    pub fn invite_with_app_container_peers(
        &self,
        port: Port,
        peer_sids: &[MaximumSid],
    ) -> Result<(Invitation, InvitationHandle), InviteError> {
        if peer_sids.is_empty() {
            return self.invite(port);
        }
        let security = invitation_endpoint_security(None, peer_sids.iter().map(AsRef::as_ref))?;
        self.invite_with_endpoint_security(port, security)
    }

    /// Invites an AppContainer through exact-SID grants on this mesh's owned
    /// directory and server port, with low-integrity endpoint labels.
    ///
    /// Grants are accumulated for the lifetime of this node. Serialized
    /// read-modify-write updates preserve earlier siblings' access. The joining
    /// endpoint grants its own package SID and the parent user access, allowing
    /// the reverse connection without an ALL APPLICATION PACKAGES grant.
    /// This authorizes communication with the parent, not direct connections
    /// between differently identified AppContainers.
    /// The inherited directory handle is also attenuated to traverse and
    /// create-object access: it carries no security-management or delete rights.
    pub fn invite_app_container(
        &self,
        port: Port,
        sid: &Sid,
    ) -> Result<(Invitation, InvitationHandle), InviteError> {
        self.invite_app_container_inner(port, sid, std::iter::empty())
    }

    /// Invites an AppContainer whose endpoint also accepts one exact peer
    /// package SID with PORT_CONNECT access.
    ///
    /// See [`Self::invite_app_container_with_peers`] for topology and identity
    /// lifetime requirements.
    pub fn invite_app_container_with_peer(
        &self,
        port: Port,
        sid: &Sid,
        peer_sid: &Sid,
    ) -> Result<(Invitation, InvitationHandle), InviteError> {
        self.invite_app_container_inner(port, sid, std::iter::once(peer_sid))
    }

    /// Invites an AppContainer with an owned launch-time endpoint descriptor
    /// granting PORT_CONNECT only to the supplied exact peer package SIDs.
    ///
    /// All identities are validated and duplicates removed before ACL updates.
    /// No peers are inferred from other invitations. Configure reciprocal
    /// grants: a star hub accepts every spoke SID, while each spoke accepts only
    /// the hub SID. Transferred Mesh ports establish new named ALPC connections,
    /// rather than transferring authorized kernel connection handles.
    ///
    /// The descriptor is transient, private invitation ACL metadata: an
    /// immutable launch-time snapshot, not persistent profile ownership. Before
    /// the first launch, the trusted caller must prepare the entire topology
    /// and retain owned registered profiles with distinct SIDs for concurrently
    /// isolated logical workers in one fresh sandbox lifetime. There is no
    /// post-launch grant or revocation API.
    ///
    /// A retained profile may serve a replacement generation only after the old
    /// root is reaped and its job is empty. Fresh sandbox reconstruction requires
    /// new owned profiles and SIDs; neither serialized SID text nor a name or
    /// digest recreates ownership. Never share profiles across independent
    /// sandbox lifetimes.
    pub fn invite_app_container_with_peers(
        &self,
        port: Port,
        sid: &Sid,
        peer_sids: &[MaximumSid],
    ) -> Result<(Invitation, InvitationHandle), InviteError> {
        self.invite_app_container_inner(port, sid, peer_sids.iter().map(AsRef::as_ref))
    }

    fn invite_app_container_inner<'a>(
        &self,
        port: Port,
        sid: &Sid,
        peer_sids: impl IntoIterator<Item = &'a Sid>,
    ) -> Result<(Invitation, InvitationHandle), InviteError> {
        let security = invitation_endpoint_security(Some(sid), peer_sids)?;
        {
            let server = self.server_security.lock();
            grant_low_integrity_kernel_object_access(
                self.invite_ctx.directory.as_handle(),
                sid,
                DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT,
            )?;
            // ALPC ports require PORT_CONNECT (0x1) for a connection.
            grant_low_integrity_kernel_object_access(server.as_handle(), sid, 1)?;
        }
        self.invite_with_endpoint_security(port, security)
    }

    fn invite_with_endpoint_security(
        &self,
        port: Port,
        security: String,
    ) -> Result<(Invitation, InvitationHandle), InviteError> {
        let (mut credentials, directory, handle) = self.invite_ctx.process_invite(
            &self.driver,
            port,
            true,
            DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT,
        )?;
        credentials.endpoint_security = Some(security);
        Ok((
            Invitation {
                credentials,
                directory: directory.expect("requested"),
            },
            handle,
        ))
    }

    /// Joins the ALPC mesh using the invitation from [`AlpcNode::invite`],
    /// bridging `port` with the initial port.
    pub fn join(
        driver: impl Driver + Spawn + Clone,
        invitation: Invitation,
        port: Port,
    ) -> Result<Self, JoinError> {
        let mesh_secret = invitation.credentials.mesh_secret;
        let security_descriptor = invitation
            .credentials
            .endpoint_security
            .as_deref()
            .map(str::parse::<LocalSecurityDescriptor>)
            .transpose()
            .map_err(JoinError::SecurityDescriptor)?;
        let node = Self::with_id(
            driver,
            invitation.credentials.address.local_addr.node,
            invitation.directory,
            mesh_secret,
            None,
            security_descriptor.as_deref(),
        )?;
        let init_port = mesh_channel::OneshotSender::<InitialMessage>::from(
            node.invite_ctx.local_node.add_port(
                invitation.credentials.address.local_addr.port,
                invitation.credentials.address.remote_addr,
            ),
        );

        // Notify the inviter that this node is ready by sending the initial port.
        init_port.send(InitialMessage { user_port: port });
        Ok(node)
    }

    /// Joins the ALPC mesh using a named invitation.
    pub fn join_named(
        driver: impl Driver + Spawn + Clone,
        invitation: NamedInvitation,
        port: Port,
    ) -> Result<Self, JoinError> {
        let mesh_secret = invitation.credentials.mesh_secret;
        let path: UnicodeString = invitation
            .directory_path
            .as_str()
            .try_into()
            .map_err(|_| JoinError::InvalidDirectoryPath)?;
        let directory = open_object_directory(
            ObjectAttributes::new().name(&path),
            DIRECTORY_TRAVERSE | DIRECTORY_QUERY | DIRECTORY_CREATE_OBJECT,
        )
        .map_err(|e| JoinError::OpenDirectory {
            path: invitation.directory_path.clone(),
            source: e,
        })?;
        let node = Self::with_id(
            driver,
            invitation.credentials.address.local_addr.node,
            directory,
            mesh_secret,
            Some(invitation.directory_path),
            None,
        )?;
        let init_port = mesh_channel::OneshotSender::<InitialMessage>::from(
            node.invite_ctx.local_node.add_port(
                invitation.credentials.address.local_addr.port,
                invitation.credentials.address.remote_addr,
            ),
        );

        // Notify the inviter that this node is ready by sending the initial port.
        init_port.send(InitialMessage { user_port: port });
        Ok(node)
    }

    /// Shuts down the node, waiting for any sent messages to be sent to their
    /// destination.
    ///
    /// After this call, any active ports will no longer be able to receive
    /// messages.
    ///
    /// It is essential to call this before exiting a mesh process; until this
    /// returns, data loss could occur for other mesh nodes.
    pub async fn shutdown(self) {
        self.invite_ctx.local_node.wait_for_ports(false).await;
        self.connect_send.close_channel();
        self.connect_task.await;
        self.recv_abort.abort();
        self.recv_task.await;
    }

    /// Asynchronously processes incoming ALPC messages from remote nodes.
    async fn process_recv(
        local_id: NodeId,
        local_node: Arc<LocalNode>,
        mut port: PolledWait<alpc::Port>,
        invitations: InvitationMap,
        connect_send: mpsc::UnboundedSender<(NodeId, RemoteNodeHandle)>,
        mesh_secret: MeshSecret,
    ) -> io::Result<()> {
        struct Connection {
            comm: alpc::Port,
            handle: RemoteNodeHandle,
        }

        let mut message = alpc::RecvMessageBuffer::new(MAX_MESSAGE_SIZE);
        let mut connections = HashMap::<_, Connection>::new();
        let mut next_id: usize = 1;
        let mut handles = Vec::new();
        let mut resources = Vec::new();
        loop {
            port.wait().await?;
            let mut message = port
                .get()
                .try_recv(&mut message)
                .inspect_err(|error| {
                    tracing::error!(
                        node = ?local_id,
                        error = error.as_error(),
                        "alpc error"
                    );
                })?
                .expect("port should have a message");
            let buf = message.data();
            match message.message_type() {
                alpc::MessageType::Datagram => {
                    message
                        .handles(port.get(), &mut handles)
                        .inspect_err(|error| {
                            tracing::error!(
                                node = ?local_id,
                                error = error.as_error(),
                                "alpc error getting handles"
                            );
                        })?;
                    // It's not easy to distinguish a socket from other file
                    // handles, so don't attempt to. `Resource::socket()`
                    // will convert from a handle as necessary.
                    resources.extend(handles.drain(..).map(OsResource::Handle));

                    let connection = connections
                        .get(&message.context())
                        .expect("port must exist");

                    match protocol::PacketHeader::read_from_prefix(buf) {
                        Ok((header, _)) => match header.packet_type {
                            // TODO: zerocopy: use-rest-of-range (https://github.com/microsoft/openvmm/issues/759)
                            protocol::PacketType::EVENT => {
                                local_node.event(
                                    connection.handle.id(),
                                    &buf[size_of_val(&header)..],
                                    &mut resources,
                                );
                            }
                            protocol::PacketType::LARGE_EVENT => {
                                if let Some(view) = message.secure_view() {
                                    local_node.event(connection.handle.id(), &view, &mut resources);
                                } else {
                                    tracing::error!(node = ?local_id, "missing secure view");
                                }
                            }
                            packet_type => {
                                tracing::error!(node = ?local_id, ?packet_type, "unknown packet type");
                            }
                        },
                        Err(_) => {
                            // TODO: zerocopy: err (https://github.com/microsoft/openvmm/issues/759)
                            tracing::error!(node = ?local_id, "invalid message");
                        }
                    }
                    resources.clear();
                    if message.needs_reply() {
                        port.get().reply(message, &[])?;
                    }
                }
                alpc::MessageType::ConnectionRequest => {
                    let Some(conn_data) = AlpcConnectionData::read_from_bytes(buf).ok() else {
                        tracing::warn!(
                            node = ?local_id,
                            len = buf.len(),
                            "rejected connection: invalid data"
                        );
                        let _ = port.get().reject(message);
                        continue;
                    };
                    let node_id = NodeId(Uuid(conn_data.node_id));
                    if mesh_secret != conn_data.mesh_secret {
                        tracing::warn!(
                            node = ?local_id,
                            "rejected connection: invalid mesh secret"
                        );
                        let _ = port.get().reject(message);
                        continue;
                    }

                    let handle = if let Some((handle, _invitation_done)) =
                        invitations.lock().remove(&node_id)
                    {
                        // If this is a connection from a node that was invited,
                        // then it's now safe to connect to the node. Send the
                        // deferred connection to the connection task.
                        let _ = connect_send.unbounded_send((node_id, handle.clone()));
                        handle
                    } else {
                        // Otherwise, establish a connection now to get a
                        // handle in case something goes wrong.
                        local_node.get_remote_handle(node_id)
                    };

                    // Accept the ALPC connection.
                    match port.get().accept(
                        alpc::PortConfig::new().max_message_len(MAX_MESSAGE_SIZE),
                        message,
                        next_id,
                        &mut SendMessage::new(),
                    ) {
                        Ok(comm) => {
                            tracing::trace!(node = ?local_id, remote_node = ?node_id, "accepted connection");
                            connections.insert(next_id, Connection { comm, handle });
                            next_id += 1;
                        }
                        Err(err) => {
                            tracing::error!(
                                node = ?local_id,
                                remote_node = ?node_id,
                                error = err.as_error(),
                                "failed to accept connection"
                            );
                            handle.fail(err);
                        }
                    };
                }
                alpc::MessageType::PortClosed => {
                    assert!(!message.needs_reply());
                    let connection = connections
                        .remove(&message.context())
                        .expect("port must exist");

                    connection.handle.disconnect();
                }
                alpc::MessageType::ConnectionReply | alpc::MessageType::Reply => unreachable!(),
                alpc::MessageType::Canceled => {
                    assert!(!message.needs_reply());
                }
                alpc::MessageType::Request => {
                    // This is a flush request to make sure all datagram
                    // messages have been received.
                    let connection = connections
                        .get(&message.context())
                        .expect("port must exist");
                    let _ = connection.comm.reply(message, &[]);
                }
            }
        }
    }
}

/// Connector for connecting to remote ALPC nodes.
#[derive(Debug)]
struct AlpcConnector {
    connect_send: mpsc::UnboundedSender<(NodeId, RemoteNodeHandle)>,
}

impl Connect for AlpcConnector {
    fn connect(&self, remote_id: NodeId, handle: RemoteNodeHandle) {
        // Send the handle to the connect task.
        let _ = self.connect_send.unbounded_send((remote_id, handle));
    }
}

/// An ALPC connection to a remote node's server port.
#[derive(Debug)]
struct Connection {
    local_id: NodeId,
    remote_id: NodeId,
    port: AlpcPort,
    failed_send: Mutex<Option<mesh_channel::OneshotSender<io::Error>>>,
}

struct AlpcMessageBuffer<'a>(&'a mut SendMessage);

impl Buffer for AlpcMessageBuffer<'_> {
    unsafe fn unwritten(&mut self) -> &mut [std::mem::MaybeUninit<u8>] {
        self.0.spare_capacity_mut()
    }

    unsafe fn extend_written(&mut self, len: usize) {
        // SAFETY: guaranteed by caller.
        unsafe {
            self.0.set_len(self.0.len() + len);
        }
    }
}

impl Connection {
    fn send_event(&self, event: OutgoingEvent<'_>) -> io::Result<()> {
        let mut message;
        let mut resources = Vec::new();
        let mut section_view = None;
        let section;
        if event.len() > MAX_SMALL_EVENT_SIZE {
            message = SendMessage::from(
                protocol::PacketHeader {
                    packet_type: protocol::PacketType::LARGE_EVENT,
                    ..FromZeros::new_zeroed()
                }
                .as_bytes(),
            );
            section = PortSection::new_secure(&self.port, event.len())?;
            let mut view = section.alloc_view(event.len())?;
            let mut b = io::Cursor::new(&mut *view);
            event.write_to(&mut b, &mut resources);
            section_view = Some(view);
        } else {
            let cap = size_of::<protocol::PacketHeader>() + event.len();
            message = SendMessage::with_capacity(cap);
            message.extend(
                protocol::PacketHeader {
                    packet_type: protocol::PacketType::EVENT,
                    ..FromZeros::new_zeroed()
                }
                .as_bytes(),
            );
            event.write_to(&mut AlpcMessageBuffer(&mut message), &mut resources);
        }

        let mut op = self.port.start_send(&mut message);
        for resource in resources.iter_mut() {
            match resource {
                OsResource::Handle(handle) => op.add_handle((*handle).as_handle()),
                OsResource::Socket(socket) => op.add_handle(socket.prepare_to_send()?),
            };
        }
        if let Some(view) = section_view {
            op.set_view(view.into_inner(), true);
        }
        op.send()?;
        Ok(())
    }
}

impl SendEvent for Connection {
    fn event(&self, event: OutgoingEvent<'_>) {
        let len = event.len();
        match self.send_event(event) {
            Ok(_) => (),
            Err(err) => {
                tracing::error!(
                    node = ?self.local_id,
                    remote_node = ?self.remote_id,
                    error = err.as_error(),
                    len,
                    "error sending packet"
                );
                // Notify the connection task of the failure.
                let send = self.failed_send.lock().take();
                if let Some(send) = send {
                    send.send(err);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct AlpcPort(Arc<alpc::Port>);

impl AsHandle for AlpcPort {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.as_handle()
    }
}

impl Deref for AlpcPort {
    type Target = alpc::Port;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::AlpcNode;
    use mesh_channel::RecvError;
    use mesh_channel::channel;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pal_event::Event;
    use std::io::Read;
    use std::io::Write;
    use test_with_tracing::test;
    use unix_socket::UnixStream;

    async fn bounded<T>(driver: &DefaultDriver, future: impl Future<Output = T>) -> T {
        use futures_concurrency::future::Race;
        use pal_async::timer::PolledTimer;
        use std::time::Duration;

        (async { Some(future.await) }, async {
            PolledTimer::new(driver).sleep(Duration::from_secs(5)).await;
            None
        })
            .race()
            .await
            .expect("ALPC test timed out")
    }

    fn node_security(node: &AlpcNode) -> [String; 2] {
        use pal::windows::security::LocalSecurityDescriptor;
        use std::os::windows::io::AsHandle;

        let server = node.server_security.lock();
        [node.invite_ctx.directory.as_handle(), server.as_handle()].map(|handle| {
            LocalSecurityDescriptor::from_kernel_object(handle)
                .unwrap()
                .to_sddl()
                .unwrap()
        })
    }

    fn handle_access(handle: std::os::windows::io::BorrowedHandle<'_>) -> u32 {
        use std::os::windows::io::AsRawHandle;

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryObject(
                handle: *mut std::ffi::c_void,
                information_class: i32,
                information: *mut std::ffi::c_void,
                length: u32,
                returned: *mut u32,
            ) -> i32;
        }

        // PUBLIC_OBJECT_BASIC_INFORMATION contains four ULONG fields followed
        // by ten reserved ULONGs. Its second field is the effective access mask.
        let mut information = [0u32; 14];
        // SAFETY: The handle remains borrowed and the output buffer matches the
        // documented ObjectBasicInformation layout and size.
        let status = unsafe {
            NtQueryObject(
                handle.as_raw_handle(),
                0,
                information.as_mut_ptr().cast(),
                size_of_val(&information) as u32,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(status, 0, "NtQueryObject status {status:#x}");
        information[1]
    }

    #[async_test]
    async fn retained_inviter_does_not_keep_server_after_shutdown(driver: DefaultDriver) {
        use futures_concurrency::future::Race;
        use pal::windows::ObjectAttributes;
        use pal::windows::alpc;
        use pal_async::timer::PolledTimer;
        use std::os::windows::io::AsHandle;
        use std::sync::Arc;
        use std::time::Duration;

        let node = AlpcNode::new_named(driver.clone()).unwrap();
        let inviter = node.inviter();
        let directory = Arc::clone(&node.invite_ctx.directory);
        let name = super::node_path(node.id());
        let mut attributes = ObjectAttributes::new();
        attributes.root(directory.as_handle()).name(&name);
        let create_server = || {
            alpc::PortConfig::new()
                .max_message_len(super::MAX_MESSAGE_SIZE)
                .waitable(true)
                .create(&attributes)
        };
        assert!(create_server().is_err(), "live listener must own its name");
        (node.shutdown(), async {
            PolledTimer::new(&driver)
                .sleep(Duration::from_secs(5))
                .await;
            panic!("ALPC shutdown timed out");
        })
            .race()
            .await;

        // Probe name reuse without connecting to a receiver-less listener.
        let replacement = create_server()
            .expect("retained inviter must not retain the shut-down server endpoint");
        drop((replacement, inviter));
    }

    #[async_test]
    async fn test_two(driver: DefaultDriver) {
        use std::os::windows::io::AsHandle;

        let (send, recv) = channel::<u32>();
        let node1 = AlpcNode::new(driver.clone()).unwrap();
        let (invitation, _handle) = node1.invite(recv.into()).unwrap();
        assert_eq!(handle_access(invitation.directory.as_handle()), 0);

        let (send2, mut recv2) = channel::<u32>();
        let node2 = AlpcNode::join(driver, invitation, send2.into()).unwrap();

        send.send(5);
        assert_eq!(recv2.recv().await.unwrap(), 5);
        drop(send);
        drop(recv2);
        node1.shutdown().await;
        node2.shutdown().await;
    }

    #[async_test]
    async fn test_app_container_grants_preserve_siblings(driver: DefaultDriver) {
        use pal::windows::security::LocalSecurityDescriptor;
        use pal::windows::security::MaximumSid;
        use std::os::windows::io::AsHandle;

        let first_sid: MaximumSid = "S-1-15-2-1-2-3-4-5-6-7".parse().unwrap();
        let second_sid: MaximumSid = "S-1-15-2-8-9-10-11-12-13-14".parse().unwrap();
        let parent = AlpcNode::new(driver.clone()).unwrap();
        let (first_send, first_port) = channel::<(u32, mesh_channel::Sender<u32>)>();
        let (invitation, _first_handle) = parent
            .invite_app_container(first_port.into(), first_sid.as_ref())
            .unwrap();
        assert_eq!(
            handle_access(invitation.directory.as_handle()),
            super::DIRECTORY_TRAVERSE | super::DIRECTORY_CREATE_OBJECT
        );
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Security::Authorization::SE_KERNEL_OBJECT;
            use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
            use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
            use windows_sys::Win32::Security::GetSecurityDescriptorDacl;

            let descriptor = LocalSecurityDescriptor::from_kernel_object(
                parent.invite_ctx.directory.as_handle(),
            )
            .unwrap();
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl = std::ptr::null_mut();
            // SAFETY: The descriptor and handles remain live. The attempted
            // update is the unchanged DACL, and must fail on the limited handle.
            unsafe {
                assert_ne!(
                    GetSecurityDescriptorDacl(
                        descriptor.as_ptr(),
                        &mut present,
                        &mut dacl,
                        &mut defaulted
                    ),
                    0
                );
                assert_eq!(
                    SetSecurityInfo(
                        invitation.directory.as_raw_handle(),
                        SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        dacl,
                        std::ptr::null_mut(),
                    ),
                    windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED
                );
            }
        }
        let (first_local, mut first_recv) = channel::<(u32, mesh_channel::Sender<u32>)>();
        let first = AlpcNode::join(driver.clone(), invitation, first_local.into()).unwrap();

        let (second_send, second_port) = channel::<(u32, mesh_channel::Sender<u32>)>();
        let (invitation, _second_handle) = parent
            .invite_app_container(second_port.into(), second_sid.as_ref())
            .unwrap();
        assert_eq!(
            handle_access(invitation.directory.as_handle()),
            super::DIRECTORY_TRAVERSE | super::DIRECTORY_CREATE_OBJECT
        );
        let (second_local, mut second_recv) = channel::<(u32, mesh_channel::Sender<u32>)>();
        let second = AlpcNode::join(driver, invitation, second_local.into()).unwrap();

        {
            let server = parent.server_security.lock();
            for handle in [parent.invite_ctx.directory.as_handle(), server.as_handle()] {
                let descriptor = LocalSecurityDescriptor::from_kernel_object(handle)
                    .unwrap()
                    .to_sddl()
                    .unwrap();
                assert!(
                    descriptor.contains(&first_sid.to_string_sid()),
                    "{descriptor}"
                );
                assert!(
                    descriptor.contains(&second_sid.to_string_sid()),
                    "{descriptor}"
                );
                assert!(descriptor.contains("(ML;;NW;;;LW)"), "{descriptor}");
                assert!(!descriptor.contains(";;;AC)"), "{descriptor}");
                assert!(!descriptor.contains(";;;WD)"), "{descriptor}");
            }
        }

        // These nodes run under the test's ordinary token. This verifies the
        // live ACLs and both transport directions, not AppContainer execution.
        for (send, recv, value) in [
            (&first_send, &mut first_recv, 31),
            (&second_send, &mut second_recv, 41),
        ] {
            let (reply, mut response) = channel();
            send.send((value, reply));
            let (value, reply) = recv.recv().await.unwrap();
            reply.send(value + 1);
            assert_eq!(response.recv().await.unwrap(), value + 1);
        }
        drop(first_send);
        drop(first_recv);
        first.shutdown().await;
        let (reply, mut response) = channel();
        second_send.send((51, reply));
        let (value, reply) = second_recv.recv().await.unwrap();
        reply.send(value + 1);
        assert_eq!(response.recv().await.unwrap(), 52);
        drop(second_send);
        drop(second_recv);
        second.shutdown().await;
        parent.shutdown().await;
    }

    fn endpoint_sid_access(node: &AlpcNode, sid: &pal::windows::security::Sid) -> u32 {
        use pal::windows::security::LocalSecurityDescriptor;
        use std::os::windows::io::AsHandle;
        use windows_sys::Win32::Security::ACCESS_ALLOWED_ACE;
        use windows_sys::Win32::Security::ACE_HEADER;
        use windows_sys::Win32::Security::EqualSid;
        use windows_sys::Win32::Security::GetAce;
        use windows_sys::Win32::Security::GetSecurityDescriptorDacl;

        let server = node.server_security.lock();
        let descriptor = LocalSecurityDescriptor::from_kernel_object(server.as_handle()).unwrap();
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = std::ptr::null_mut();
        let mut access = 0;
        // SAFETY: The kernel-returned descriptor owns the validated ACL and
        // ACE storage throughout enumeration; each ACE's type is checked.
        unsafe {
            assert_ne!(
                GetSecurityDescriptorDacl(
                    descriptor.as_ptr(),
                    &mut present,
                    &mut dacl,
                    &mut defaulted
                ),
                0
            );
            assert_ne!(present, 0);
            assert!(!dacl.is_null());
            for index in 0..(*dacl).AceCount {
                let mut ace = std::ptr::null_mut();
                assert_ne!(GetAce(dacl, u32::from(index), &mut ace), 0);
                if (*ace.cast::<ACE_HEADER>()).AceType == 0 {
                    let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
                    if EqualSid(std::ptr::addr_of_mut!((*ace).SidStart).cast(), sid.as_ptr()) != 0 {
                        access |= (*ace).Mask;
                    }
                }
            }
        }
        access
    }

    #[async_test]
    async fn test_app_container_paired_endpoint_transfer(driver: DefaultDriver) {
        use pal::windows::security::MaximumSid;

        type Message = (u32, mesh_channel::Sender<u32>);

        let first_sid: MaximumSid = "S-1-15-2-1-2-3-4-5-6-7".parse().unwrap();
        let second_sid: MaximumSid = "S-1-15-2-8-9-10-11-12-13-14".parse().unwrap();
        let unrelated_sid: MaximumSid = "S-1-15-2-15-16-17-18-19-20-21".parse().unwrap();
        let broad_sid: MaximumSid = "S-1-15-2-1".parse().unwrap();
        let everyone: MaximumSid = "S-1-1-0".parse().unwrap();
        let parent = AlpcNode::new(driver.clone()).unwrap();

        let (first_send, first_port) = channel::<mesh_channel::Sender<Message>>();
        let (invitation, _first_handle) = parent
            .invite_app_container_with_peer(
                first_port.into(),
                first_sid.as_ref(),
                second_sid.as_ref(),
            )
            .unwrap();
        let (first_local, mut first_recv) = channel::<mesh_channel::Sender<Message>>();
        let first = AlpcNode::join(driver.clone(), invitation, first_local.into()).unwrap();

        let (second_send, second_port) = channel::<mesh_channel::Receiver<Message>>();
        let (invitation, _second_handle) = parent
            .invite_app_container_with_peer(
                second_port.into(),
                second_sid.as_ref(),
                first_sid.as_ref(),
            )
            .unwrap();
        let (second_local, mut second_recv) = channel::<mesh_channel::Receiver<Message>>();
        let second = AlpcNode::join(driver.clone(), invitation, second_local.into()).unwrap();

        let (unrelated_send, unrelated_port) = channel::<()>();
        let (invitation, _unrelated_handle) = parent
            .invite_app_container(unrelated_port.into(), unrelated_sid.as_ref())
            .unwrap();
        let (unrelated_local, unrelated_recv) = channel::<()>();
        let unrelated = AlpcNode::join(driver, invitation, unrelated_local.into()).unwrap();

        assert_eq!(endpoint_sid_access(&first, second_sid.as_ref()), 1);
        assert_eq!(endpoint_sid_access(&second, first_sid.as_ref()), 1);
        for node in [&first, &second] {
            for sid in [&unrelated_sid, &broad_sid, &everyone] {
                assert_eq!(endpoint_sid_access(node, sid.as_ref()), 0);
            }
        }
        assert_eq!(endpoint_sid_access(&unrelated, first_sid.as_ref()), 0);
        assert_eq!(endpoint_sid_access(&unrelated, second_sid.as_ref()), 0);

        let (send, recv) = channel::<Message>();
        first_send.send(send);
        second_send.send(recv);
        let direct_send = first_recv.recv().await.unwrap();
        let mut direct_recv = second_recv.recv().await.unwrap();
        drop((first_send, first_recv, second_send, second_recv));
        drop((unrelated_send, unrelated_recv));
        unrelated.shutdown().await;
        parent.shutdown().await;

        // Ordinary-token transport and live ACL qualification only. The
        // parent is gone, so request/reply cannot rely on an application relay.
        let (reply, mut response) = channel();
        direct_send.send((71, reply));
        let (value, reply) = direct_recv.recv().await.unwrap();
        reply.send(value + 1);
        assert_eq!(response.recv().await.unwrap(), 72);
        drop((direct_send, direct_recv, response));
        first.shutdown().await;
        second.shutdown().await;
    }

    #[async_test]
    async fn test_trusted_host_endpoint_scopes_exact_peers(driver: DefaultDriver) {
        use pal::windows::security::MaximumSid;
        use std::os::windows::io::AsHandle;

        type Message = (u32, mesh_channel::Sender<u32>);
        let peers: [MaximumSid; 2] = [
            "S-1-15-2-1-2-3-4-5-6-7".parse().unwrap(),
            "S-1-15-2-8-9-10-11-12-13-14".parse().unwrap(),
        ];
        let parent = AlpcNode::new(driver.clone()).unwrap();
        let before = node_security(&parent);
        let (send, port) = channel::<Message>();
        let mut supplied = vec![peers[0], peers[1], peers[0]];
        let (invitation, _handle) = parent
            .invite_with_app_container_peers(port.into(), &supplied)
            .unwrap();
        supplied.clear();
        let security = invitation.credentials.endpoint_security.as_ref().unwrap();
        for sid in &peers {
            assert_eq!(security.matches(&sid.to_string_sid()).count(), 1);
        }
        assert!(security.starts_with("D:P"));
        assert!(security.contains("S:(ML;;NW;;;LW)"));
        assert_eq!(
            handle_access(invitation.directory.as_handle()),
            super::DIRECTORY_TRAVERSE | super::DIRECTORY_CREATE_OBJECT
        );
        let (local, mut recv) = channel::<Message>();
        let child = AlpcNode::join(driver.clone(), invitation, local.into()).unwrap();
        assert_eq!(before, node_security(&parent));
        for peer in &peers {
            assert_eq!(endpoint_sid_access(&child, peer.as_ref()), 1);
        }
        for excluded in ["S-1-1-0", "S-1-15-2-1", "S-1-15-2-15-16-17-18-19-20-21"] {
            let sid: MaximumSid = excluded.parse().unwrap();
            assert_eq!(endpoint_sid_access(&child, sid.as_ref()), 0);
        }
        let (reply, mut response) = channel();
        send.send((93, reply));
        let (value, reply) = bounded(&driver, recv.recv()).await.unwrap();
        reply.send(value + 1);
        assert_eq!(bounded(&driver, response.recv()).await.unwrap(), 94);
        drop((send, recv, response));
        bounded(&driver, child.shutdown()).await;
        bounded(&driver, parent.shutdown()).await;
    }

    #[async_test]
    async fn test_trusted_host_peer_validation_precedes_invitation(driver: DefaultDriver) {
        use pal::windows::security::MaximumSid;
        use std::os::windows::io::AsHandle;

        let valid: MaximumSid = "S-1-15-2-1-2-3-4-5-6-7".parse().unwrap();
        let parent = AlpcNode::new(driver.clone()).unwrap();
        let before = node_security(&parent);
        for invalid in [
            "S-1-1-0",
            "S-1-15-2-1",
            "S-1-15-2-1-2-3",
            "S-1-15-3-1-2-3-4-5-6-7",
        ] {
            let invalid: MaximumSid = invalid.parse().unwrap();
            let (_, port) = channel::<()>();
            let error = parent
                .invite_with_app_container_peers(port.into(), &[valid, invalid])
                .err()
                .unwrap();
            assert_eq!(error.to_string(), "expected a unique package SID");
            assert!(parent.invite_ctx.invitations.lock().is_empty());
            assert_eq!(before, node_security(&parent));
        }
        let (send, port) = channel::<()>();
        let (invitation, handle) = parent
            .invite_with_app_container_peers(port.into(), &[])
            .unwrap();
        assert!(invitation.credentials.endpoint_security.is_none());
        assert_eq!(handle_access(invitation.directory.as_handle()), 0);
        assert_eq!(before, node_security(&parent));
        drop((invitation, handle, send));
        bounded(&driver, parent.shutdown()).await;
    }

    #[async_test]
    async fn test_app_container_peer_rejects_invalid_identity(driver: DefaultDriver) {
        use pal::windows::security::LocalSecurityDescriptor;
        use pal::windows::security::MaximumSid;
        use std::os::windows::io::AsHandle;

        let sid: MaximumSid = "S-1-15-2-1-2-3-4-5-6-7".parse().unwrap();
        let valid_peer: MaximumSid = "S-1-15-2-8-9-10-11-12-13-14".parse().unwrap();
        let broad: MaximumSid = "S-1-15-2-1".parse().unwrap();
        let parent = AlpcNode::new(driver).unwrap();
        let before =
            LocalSecurityDescriptor::from_kernel_object(parent.invite_ctx.directory.as_handle())
                .unwrap()
                .to_sddl()
                .unwrap();
        for (peer, error) in [
            (&sid, "AppContainer peer SID must differ from its own SID"),
            (&broad, "expected a unique package SID"),
        ] {
            let (_, port) = channel::<()>();
            let result = parent
                .invite_app_container_with_peer(port.into(), sid.as_ref(), peer.as_ref())
                .err()
                .unwrap();
            assert_eq!(result.to_string(), error);
            let (_, port) = channel::<()>();
            let result = parent
                .invite_app_container_with_peers(port.into(), sid.as_ref(), &[valid_peer, *peer])
                .err()
                .unwrap();
            assert_eq!(result.to_string(), error);
        }
        let after =
            LocalSecurityDescriptor::from_kernel_object(parent.invite_ctx.directory.as_handle())
                .unwrap()
                .to_sddl()
                .unwrap();
        assert_eq!(before, after);
        parent.shutdown().await;
    }

    #[async_test]
    async fn test_app_container_star_endpoint_transfer(driver: DefaultDriver) {
        bounded(&driver, star_endpoint_transfer(driver.clone(), false)).await;
    }

    #[async_test]
    async fn test_trusted_host_star_endpoint_transfer(driver: DefaultDriver) {
        bounded(&driver, star_endpoint_transfer(driver.clone(), true)).await;
    }

    async fn star_endpoint_transfer(driver: DefaultDriver, trusted_host: bool) {
        use pal::windows::security::MaximumSid;

        type Message = (u32, mesh_channel::Sender<u32>);

        let hub_sid: MaximumSid = "S-1-15-2-1-2-3-4-5-6-7".parse().unwrap();
        let spoke_sids: [MaximumSid; 2] = [
            "S-1-15-2-8-9-10-11-12-13-14".parse().unwrap(),
            "S-1-15-2-15-16-17-18-19-20-21".parse().unwrap(),
        ];
        let unrelated_sid: MaximumSid = "S-1-15-2-22-23-24-25-26-27-28".parse().unwrap();
        let broad_sid: MaximumSid = "S-1-15-2-1".parse().unwrap();
        let everyone: MaximumSid = "S-1-1-0".parse().unwrap();
        let parent = AlpcNode::new(driver.clone()).unwrap();

        let (hub_send, hub_port) = channel::<Vec<mesh_channel::Sender<Message>>>();
        let mut supplied_peers = vec![spoke_sids[0], spoke_sids[1], spoke_sids[0]];
        let (invitation, _hub_handle) = if trusted_host {
            parent.invite_with_app_container_peers(hub_port.into(), &supplied_peers)
        } else {
            parent.invite_app_container_with_peers(
                hub_port.into(),
                hub_sid.as_ref(),
                &supplied_peers,
            )
        }
        .unwrap();
        supplied_peers.clear();
        for sid in &spoke_sids {
            assert_eq!(
                invitation
                    .credentials
                    .endpoint_security
                    .as_ref()
                    .unwrap()
                    .matches(&sid.to_string_sid())
                    .count(),
                1
            );
        }
        let (hub_local, mut hub_recv) = channel::<Vec<mesh_channel::Sender<Message>>>();
        let hub = AlpcNode::join(driver.clone(), invitation, hub_local.into()).unwrap();

        let mut spokes = Vec::new();
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        let spoke_peers = if trusted_host {
            Vec::new()
        } else {
            vec![hub_sid]
        };
        for sid in &spoke_sids {
            let (control_send, control_port) = channel::<mesh_channel::Receiver<Message>>();
            let (invitation, _handle) = parent
                .invite_app_container_with_peers(control_port.into(), sid.as_ref(), &spoke_peers)
                .unwrap();
            let (local, mut control_recv) = channel::<mesh_channel::Receiver<Message>>();
            let spoke = AlpcNode::join(driver.clone(), invitation, local.into()).unwrap();
            let (send, recv) = channel::<Message>();
            control_send.send(recv);
            receivers.push(control_recv.recv().await.unwrap());
            senders.push(send);
            spokes.push(spoke);
        }
        hub_send.send(senders);
        let senders = hub_recv.recv().await.unwrap();
        drop((hub_send, hub_recv));

        for (index, spoke) in spokes.iter().enumerate() {
            assert_eq!(endpoint_sid_access(&hub, spoke_sids[index].as_ref()), 1);
            assert_eq!(
                endpoint_sid_access(spoke, hub_sid.as_ref()),
                if trusted_host { 0 } else { 1 }
            );
            assert_eq!(
                endpoint_sid_access(spoke, spoke_sids[1 - index].as_ref()),
                0
            );
        }
        if trusted_host {
            assert_eq!(endpoint_sid_access(&hub, hub_sid.as_ref()), 0);
        }
        for node in std::iter::once(&hub).chain(&spokes) {
            for sid in [&unrelated_sid, &broad_sid, &everyone] {
                assert_eq!(endpoint_sid_access(node, sid.as_ref()), 0);
            }
        }
        parent.shutdown().await;

        // Ordinary-token transport and exact endpoint ACLs, not an assertion
        // that AppContainer tokens were used by these in-process nodes.
        for (send, recv) in senders.iter().zip(&mut receivers) {
            let (reply, mut response) = channel();
            send.send((81, reply));
            let (value, reply) = recv.recv().await.unwrap();
            reply.send(value + 1);
            assert_eq!(response.recv().await.unwrap(), 82);
        }
        drop((senders, receivers));
        hub.shutdown().await;
        for spoke in spokes {
            spoke.shutdown().await;
        }
    }

    #[async_test]
    async fn test_huge_message(driver: DefaultDriver) {
        let (send, recv) = channel::<Vec<u8>>();
        let node1 = AlpcNode::new(driver.clone()).unwrap();
        let (invitation, _handle) = node1.invite(recv.into()).unwrap();

        let (send2, mut recv2) = channel::<Vec<u8>>();
        let node2 = AlpcNode::join(driver, invitation, send2.into()).unwrap();

        let v = vec![0xcd; 8 << 20];
        send.send(v.clone());
        assert_eq!(recv2.recv().await.unwrap(), v);
        drop(send);
        drop(recv2);
        node1.shutdown().await;
        node2.shutdown().await;
    }

    #[async_test]
    async fn test_message_sizes(driver: DefaultDriver) {
        let (p1, p2) = mesh_node::local_node::Port::new_pair();
        let (p3, p4) = mesh_node::local_node::Port::new_pair();
        let node1 = AlpcNode::new(driver.clone()).unwrap();
        let (invitation, _handle) = node1.invite(p2).unwrap();
        let _node2 = AlpcNode::join(driver.clone(), invitation, p3).unwrap();

        crate::test_common::test_message_sizes(p1, p4, 0..=super::MAX_SMALL_EVENT_SIZE + 0x1000)
            .await;
    }

    #[async_test]
    async fn test_three(driver: DefaultDriver) {
        let (p1, p2) = channel::<u32>();
        let (p3, mut p4) = channel::<u32>();
        let (p5, p6) = channel::<u32>();
        let (p7, p8) = channel::<u32>();

        let node1 = AlpcNode::new(driver.clone()).unwrap();

        let (invitation, _handle) = node1.invite(p2.into()).unwrap();
        let node2 = AlpcNode::join(driver.clone(), invitation, p3.into()).unwrap();

        let (invitation, _handle) = node1.invite(p5.into()).unwrap();
        let node3 = AlpcNode::join(driver, invitation, p8.into()).unwrap();

        p1.bridge(p6);

        p7.send(5);

        assert_eq!(p4.recv().await.unwrap(), 5);
        drop(p4);
        drop(p7);
        node1.shutdown().await;
        node2.shutdown().await;
        node3.shutdown().await;
    }

    #[async_test]
    async fn test_handle(driver: DefaultDriver) {
        let (send, irecv) = channel::<Event>();
        let (isend, mut recv) = channel::<Event>();
        let node1 = AlpcNode::new(driver.clone()).unwrap();
        let (invitation, _handle) = node1.invite(irecv.into()).unwrap();
        let node2 = AlpcNode::join(driver, invitation, isend.into()).unwrap();
        let e = Event::new();
        send.send(e.clone());
        let e2 = recv.recv().await.unwrap();

        e.signal();
        e2.wait();
        drop(send);
        drop(recv);
        node1.shutdown().await;
        node2.shutdown().await;
    }

    #[async_test]
    async fn test_socket(driver: DefaultDriver) {
        let (send, irecv) = channel::<UnixStream>();
        let (isend, mut recv) = channel::<UnixStream>();
        let node1 = AlpcNode::new(driver.clone()).unwrap();
        let (invitation, _handle) = node1.invite(irecv.into()).unwrap();
        let _node2 = AlpcNode::join(driver, invitation, isend.into()).unwrap();
        let (mut s1, s2) = UnixStream::pair().unwrap();
        send.send(s2);
        let mut s2 = recv.recv().await.unwrap();

        s1.write_all(b"abc").unwrap();
        drop(s1);
        let mut buf = Vec::new();
        s2.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"abc");
    }

    #[async_test]
    async fn test_failed_invitation(driver: DefaultDriver) {
        let node = AlpcNode::new(driver).unwrap();
        let (send, mut recv) = channel::<()>();
        node.invite(send.into()).unwrap();
        assert!(matches!(
            recv.recv().await.unwrap_err(),
            RecvError::Error(_)
        ));
        drop(recv);
        node.shutdown().await;
    }

    #[async_test]
    async fn test_failed_node(driver: DefaultDriver) {
        let (_send, irecv) = channel::<()>();
        let (isend, _recv) = channel::<()>();
        let node1 = AlpcNode::new(driver.clone()).unwrap();
        let (invitation, _handle) = node1.invite(irecv.into()).unwrap();
        let node2 = AlpcNode::join(driver, invitation, isend.into()).unwrap();
        drop(node1);
        node2.shutdown().await;
    }

    #[async_test]
    async fn test_handoff_invitation(driver: DefaultDriver) {
        let (p1, p2) = channel::<mesh_channel::Sender<()>>();
        let (p3, mut p4) = channel::<mesh_channel::Sender<()>>();
        let (p5, p6) = channel::<()>();
        let (p7, mut p8) = channel::<()>();

        let node1 = AlpcNode::new(driver.clone()).unwrap();
        let (invitation, _handle) = node1.invite(p2.into()).unwrap();
        let node2 = AlpcNode::join(driver.clone(), invitation, p3.into()).unwrap();

        let (invitation, _handle) = node1.invite(p6.into()).unwrap();
        p1.send(p5);
        let p5p = p4.recv().await.unwrap();

        let node3 = AlpcNode::join(driver, invitation, p7.into()).unwrap();
        p5p.send(());
        p8.recv().await.unwrap();

        drop((p1, p4, p5p, p8));
        node1.shutdown().await;
        node2.shutdown().await;
        node3.shutdown().await;
    }

    #[async_test]
    async fn test_named_directory(driver: DefaultDriver) {
        let node1 = AlpcNode::new_named(driver.clone()).unwrap();
        let (send, recv) = channel::<u32>();

        let inviter = node1.inviter();
        let (invitation, handle) = inviter.invite_named(recv.into()).await.unwrap();

        let (send2, mut recv2) = channel::<u32>();
        let node2 = AlpcNode::join_named(driver, invitation, send2.into()).unwrap();
        handle.await;

        send.send(42);
        assert_eq!(recv2.recv().await.unwrap(), 42);
        drop(send);
        drop(recv2);
        node1.shutdown().await;
        node2.shutdown().await;
    }
}

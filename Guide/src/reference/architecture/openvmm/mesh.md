# mesh

mesh is a channel-based communication framework for Rust. It provides typed
channels (`Sender<T>` / `Receiver<T>`) that work the same way whether the
two ends are in the same process or in different processes. Components that
communicate through mesh channels can be moved between processes without
changing their source code.

OpenVMM and OpenHCL use mesh as their primary communication mechanism. In
OpenHCL, the [paravisor, VM worker, diagnostics server, and device
workers](../../architecture/openhcl/processes.md) are all separate
processes connected by mesh channels.

**Source code:**
[support/mesh](https://github.com/microsoft/openvmm/tree/main/support/mesh) |
**Docs:**
[mesh rustdoc](https://openvmm.dev/rustdoc/linux/mesh/index.html)

## Contents

- **[Using mesh](mesh/usage.md)** — channels, serialization, workers, and
  other things you need to know to write code that uses mesh.
- **[How mesh works](mesh/internals.md)** — crate structure, ports and
  nodes, encoding, cross-process transport. For people working on mesh
  itself or reviewing mesh infrastructure changes.

## Host process ownership

On Linux and Windows, use `mesh_process::Mesh::launch_host_owned` when you
need to roll back failed or stalled worker startup. It returns a
non-cloneable `OwnedHost` after OS process creation, without waiting for
the child to join Mesh. Keep the `Mesh` alive alongside the owned hosts.

Send an ordinary worker stop request first when possible. If the worker
does not stop within your deadline, call `OwnedHost::terminate_root`, then
await `OwnedHost::wait_root`. The latter reports actual OS exit and, on
Linux, reaping, rather than channel closure or a worker acknowledgment.
Its wait is cancellation-safe and repeatable. Dropping `OwnedHost` requests
termination; it does not wait for it. Each owned host has a dedicated OS
waiter thread so that reaping survives dropped consumer futures.
`Mesh::shutdown` waits for the hosts; it does not force termination and can
remain pending if a live root cannot be terminated. Report termination or
wait errors as incomplete cleanup, not as successful shutdown.

Termination uses the original process identity: a clone-created pidfd on
Linux or a retained process handle on Windows. The numeric `id()` is for
diagnostics, not for reopening a process. Windows also retains a per-host
kill-on-close Job, exposed by a borrowed handle for containment adapters.
The existing `launch_host` PID API retains its previous lifecycle behavior.

### Cancelling launch without losing completion evidence

For startup deadlines, call `Mesh::begin_launch_host_owned` first and retain
its `PendingHostLaunch`. Await `wait_host()` to obtain the normal `OwnedHost`.
Cancelling that wait does not consume the receipt or discard a captured root.
On timeout or launch error, request `cancel()` and await `wait_completion()`.
The completion is either `NeverSpawned` (the request cannot later create a
root) or `RootExited` (actual OS exit, including Linux reaping). The completion
observer is repeatable and can outlive the receipt. Dropping the receipt only
requests cancellation; it is not completion evidence.

The OS waiter is reserved before native process creation. Post-creation
startup failures retain the original child and its exit observation, rather
than being reported as never-spawned. A completion error is not successful
cleanup. Keep prepared images and identities alive until root completion and
the separate containment backend's final domain-empty observation both
succeed; an earlier empty-domain observation can race an in-flight spawn.
After successful ownership handoff, terminate through `OwnedHost`, not the
pending receipt. Neither receipt completion nor `Mesh::shutdown` substitutes
for the separate domain barrier.

### Capturing the startup invitation

Capture a worker's invitation once, before tracing or any other threads,
using `unsafe { OwnedInvitation::capture_from_environment() }`. This
startup operation requires exclusive environment access and exclusive
ownership of the trusted launcher's inherited IPC resource. It removes the
environment credentials and checks that close-on-exec or non-inheritance
is restored on the resource. Missing credentials return `None`; malformed
credentials and a second capture return errors.

When capture returns `Some(invitation)`, you can start threads and later
call the safe `run_mesh_host(invitation, name, handler)`. It consumes the
non-cloneable invitation, receives the typed initialization message, and
exits the process with code zero after successful host execution. Errors
return to the caller. The compatibility `try_run_mesh_host` is now unsafe;
its callers must satisfy the same startup ownership and environment
contract. Do not defer ambient capture until after tracing initialization.

### Preparing a constrained child

`SandboxProfile::try_apply` sees the configured environment entries. On Unix,
Mesh also sets the invitation first. On Windows, Mesh adds the invitation
after applying the profile so it can select endpoint access using the
resulting AppContainer configuration. The default implementation calls the
existing `apply` method. Override `try_apply` for fallible preparation; errors
propagate before OS process creation rather than silently weakening the profile.
A profile can use the PAL builder's
`inherit_env(false)` to suppress ambient environment inheritance while
preserving those entries. `env_clear()` instead removes explicit entries too,
including the Unix invitation; do not use it when those entries are needed.

Use `ProcessConfig::stdout(Some(file))` and `stderr(Some(file))` to supply owned
diagnostic pipe writers or files before the profile is applied. Without an
override, stdout remains the null device and stderr remains inherited; stdin
is the null device. A constrained launcher should explicitly supply both
diagnostic outputs rather than inheriting an arbitrary terminal.

On Windows, a profile can use the PAL builder's `app_container(&Sid)` to
configure zero additional capabilities through the process-creation security
attribute. SID storage is owned by the builder. `owned_job(OwnedHandle)` retains
an additional, preconfigured Job for initial process attachment, and
`current_directory(path)` selects a caller-prepared directory instead of the
host's working directory. Use `try_apply` to propagate handle-duplication or
other preparation failures.

Mesh prepares exact-package-SID ALPC access and low-integrity endpoint labels
before launching an AppContainer host, preserving existing sibling grants.
Broad package/world SIDs are rejected. These APIs do not provision AppContainer
profiles or prepare executable/runtime filesystem access; the containment
adapter owns that setup and its cleanup. Kernel ACL tests alone do not qualify
actual AppContainer execution or whole-domain containment.

For direct typed-endpoint exchange between AppContainer worker roles with
different SIDs, append each exact peer with
`ProcessConfig::app_container_peer(&Sid)` before launching the topology. For a
star, the VM host grants its function workers; each function worker grants only
the VM host, not other function workers or unrelated sandbox owners. Each grant
authorizes connection only to that invited child's ALPC endpoint. Transferring
a typed endpoint still requires a fresh named peer connection;
parent-to-worker roundtrips alone do not qualify this topology.

For a separately authorized, trusted ordinary-user host with confined
AppContainer peers, use
`ProcessConfig::trusted_host_app_container_peer(&Sid)` for each exact worker
SID instead. This explicitly selects an ordinary host endpoint; it is not an
automatic fallback when an AppContainer profile is missing. Mixing the two
peer configuration methods, or configuring an AppContainer on the trusted
host, rejects launch.

The trusted host's endpoint grants the current user and SYSTEM access, and
only `PORT_CONNECT` to each named package SID, with a low-integrity label.
No synthetic host package identity is created. No peer grants are added to
the parent's endpoint or directory by this configuration. Workers join the
same mesh through their own AppContainer invitations; those establish their
directory access. The existing current-user grant on each worker's endpoint
allows the ordinary host to connect back. Unrelated workers are not inferred
from other invitations.

This API configures endpoint access, not the host's trust decision, token,
privileges, resource limits, or hypervisor access. The caller must authorize
the ordinary host separately and retain the confined workers' profile
ownership. Component ACL/transport tests are not proof of actual confined
peer execution; qualify both directions and denied peers using real tokens.

Peer grants are fixed for the endpoint's lifetime. The owning adapter can
retain each logical worker's registered profile across nonoverlapping process
generations within one sandbox lifetime. Reap the old root and verify its Job
is empty before replacement. A reconstructed or independent sandbox needs new
profiles; a serialized SID is not registration ownership or recovery authority.

On Linux, `set_cgroup_procs(Arc<OwnedFd>)` accepts an already-open, validated
delegated cgroup's `cgroup.procs` descriptor. The caller owns the cgroup and must
configure and verify budgets before launch. PAL writes ASCII `0` for the current
child before descriptor remapping, sandbox setup, or any helper/workload exec,
then closes the child's descriptor copy. It does not migrate a numeric PID from
the parent, configure budgets, or prove domain cleanup.

Enrollment errors, including short writes, always abort startup regardless of
the sandbox failure mode. This path requires vfork so the parent can observe
startup failure; non-vfork enrollment and mappings that would expose the
enrollment descriptor to the workload are rejected. This is a trusted pre-exec
boundary, not atomic clone-time placement: the child runs the clone trampoline
and enters the PAL callback before enrollment. The parent retains its ownership;
the child performs no allocation or shared-ownership operations for enrollment.

Linux profiles can also opt into `set_close_fds(true)`. After enrollment closes
its descriptor, PAL marks all inherited descriptors numbered 3 and above
close-on-exec, before applying explicit descriptor mappings. Mapped descriptors
(including self-mappings) survive exec; standard streams keep their configured
policies. Unmapped inherited descriptors do not reach the helper or workload.
This uses `close_range(CLOSE_RANGE_CLOEXEC)` in the independent child descriptor
table without allocating or enumerating the parent's descriptors. Unsupported
kernels or any syscall error abort startup, regardless of sandbox failure mode.
The default remains unchanged. Descriptors are still present in the trusted
pre-exec code until exec: this is not a fork-only containment guarantee.

```admonish warning
Root exit does not prove that descendants have exited. This API explicitly
rejects whole-domain termination through `terminate_domain`. A separate,
owned and qualified containment backend is required for descendant cleanup,
including Linux helpers or cgroups. Closing a Windows Job requests cleanup
but is not evidence that the Job is empty. `Mesh::crash` is a cooperative
panic request, not forced OS termination.
Invitation close-on-exec prevents ordinary exec inheritance, not inheritance
by fork-only descendants.
```

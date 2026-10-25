# Network containment: security audit

This document lists the network findings of the security audit. The scope is
the network containment of pent on Linux: the proxy (`pent-proxy`), the
network namespace setup (`pent-sandbox`) and the CLI wiring.

The threat model: the sandboxed program is hostile. It wants to send data to,
or get commands from, a host that the profile does not allow. It also wants to
reach services on the host or on the local network.

Each finding has a test. A test that passes proves a defense. A test that
fails proves a vulnerability. The failing test keeps the secure assertion and
has the mark `#[ignore = "OPEN VULN NET-<n>: ..."]`.

Test files:

- `crates/pent-proxy/tests/security_network.rs` — proxy-level tests. They use
  a fake upstream DNS server and local listeners. They need no internet.
- `crates/pent/tests/security_network_e2e.rs` — end-to-end tests. They run the
  real `pent` binary with an isolated HOME and XDG. They skip when the sandbox
  or a host socket is absent.

## Findings

| ID | Severity | One line | State | Test |
|----|----------|----------|-------|------|
| NET-1 | Critical | The Tailscale daemon socket is not masked; its `ts-dial` call gives full network egress past the proxy. | Fixed | `tailscale_localapi_socket_is_masked` |
| NET-2 | High | The system D-Bus socket is reachable; it resolves names and reaches network services past the proxy. | Fixed | `system_dbus_socket_is_masked` |
| NET-3 | High | One profile path below a private directory restores the whole subtree above it, so the sibling sockets of the host come back. | Fixed by `dedaf2e` | `a_profile_path_below_a_private_dir_keeps_its_siblings_hidden` |
| NET-4 | Medium | Pent refuses each address of the Unix family, so a program cannot use its own abstract socket. | Fixed by `bfac3e0` | `child_cannot_reach_a_host_abstract_unix_socket`, `the_default_profile_refuses_a_path_but_keeps_the_unix_family` |
| NET-5 | Medium | On a host where `/etc/resolv.conf` is a symbolic link into `/run`, the child reads no resolver at all, so no name resolves in the sandbox. | Fixed | `child_sees_proxy_resolv_conf`, `test_proxy_only_passes_the_listeners`, `test_resolv_bind_makes_the_chain_inside_the_tmpfs` |

### NET-1 — the Tailscale daemon socket gives full egress (Critical)

**State: fixed.** An empty tmpfs covers `/run` in the mount namespace of the
child, so the socket is not there. The socket is also in `RESOLVER_SOCKETS`,
the mask list that pent applies when the network is not `Unrestricted`. See
`docs/security/linux-sandbox.md` (LS-1 and LS-2).

**Attack.** The child connects to the Unix socket
`/run/tailscale/tailscaled.sock`. This socket is the Tailscale LocalAPI. The
API has a `ts-dial` upgrade. The child sends one HTTP request with the headers
`Upgrade: ts-dial`, `Dial-Host`, `Dial-Port` and `Dial-Network`. The daemon
opens a TCP connection to that host and port. The daemon joins the two
streams. The child then reads and writes the remote host directly.

The child reaches any host on the tailnet this way. The child also reaches the
public internet through an exit node or a subnet route. The proxy never sees
this traffic. The domain allowlist has no effect.

**Evidence.** The test `tailscale_localapi_socket_is_masked` runs a child that
connects to the socket and calls `/localapi/v0/status`. The child gets the
answer `HTTP/1.1 200 OK`. The audit also confirmed, by hand, that a `ts-dial`
request to `1.1.1.1:80` returns a live HTTP response from the public internet
and that a `ts-dial` request to a local victim on the tailnet address reaches
the victim.

**Why pent does not stop this.** Landlock does not control `connect(2)` on a
Unix socket that has a path. pent hides a fixed list of dangerous sockets with
a bind mount of `/dev/null`: the container sockets (`ESCAPE_SOCKETS`) and the
host resolver sockets (`RESOLVER_SOCKETS`) in `crates/pent-sandbox/src/linux.rs`.
The Tailscale socket is a network-egress socket, like the resolver sockets,
but it is not on the list.

**Recommended fix.** Add the Tailscale daemon socket to the masked set, like
the resolver sockets, when the network mode is not `Unrestricted`:

- `/run/tailscale/tailscaled.sock`
- `/var/run/tailscale/tailscaled.sock`

A better fix covers the general class. Any host daemon that offers a "dial" or
"proxy" service on a Unix socket is an egress path. pent cannot know each one.
pent must say this limit in the documentation and let the user name more
sockets to mask.

### NET-2 — the system D-Bus socket is reachable (High)

**State: fixed.** The same tmpfs over `/run` removes the socket, and the
socket is in `ESCAPE_SOCKETS`. See `docs/security/linux-sandbox.md`.

**Attack.** The child connects to `/run/dbus/system_bus_socket`. The system
bus reaches host services. Two examples:

- `org.freedesktop.resolve1` (systemd-resolved) resolves a name with the
  method `ResolveHostname`. The child learns the address of a host that the
  allowlist does not have. The query goes past the proxy DNS.
- `org.freedesktop.NetworkManager` and `org.freedesktop.systemd1` give
  information about the host and, with the right policy, change its state.

The resolve1 path is a DNS resolver that the proxy does not control. The
address alone does not open a connection, because the child has no route out
of its namespace. But the resolver leaks which names exist, and it is a second
channel next to the proxy DNS.

**Evidence.** The test `system_dbus_socket_is_masked` runs a child that
connects to the system bus socket. The connection succeeds. On a host that
runs systemd-resolved, the method `ResolveHostname` returns an address for a
name that the allowlist does not have.

**Why pent does not stop this.** The README says that the system D-Bus socket
stays reachable. This is a known limit. The network consequence (a second
resolver, past the proxy) is the same class as the resolver sockets that pent
already masks.

**Recommended fix.** Mask the system bus socket when the network mode is not
`Unrestricted`, like the resolver sockets. If a profile needs the system bus,
the user names the socket path, and pent then does not mask it. At least,
mask the systemd-resolved socket, which the audit confirmed is already on the
mask list, and say clearly in the documentation that the system bus is a
resolver and an egress path.

### NET-3 — a profile path below a private directory restores its siblings (High)

**State: fixed by `dedaf2e`.** `bind_back_paths` in
`crates/pent-sandbox/src/linux.rs` gives the paths that the configuration
names itself, without the traversal paths. The plan binds the named path
(a file over a file, a directory over a directory) and makes the
directories above it inside the private tmpfs with `mount_point_parents`.
The test `a_profile_path_below_a_private_dir_keeps_its_siblings_hidden`
in `crates/pent/tests/security_network_e2e.rs` has no `#[ignore]` any
more. The connect control of LS-1 already refused the sibling socket, so
the test also lists the parent directory: with the bug the listing holds
each sibling of the host, with the fix only the named directory.

**Attack.** The user gives the profile one path below a private directory,
for example `read_write = ["/run/user/1000/myapp"]` or a directory below
`/tmp`. `plan_private_dirs` in `crates/pent-sandbox/src/linux.rs` builds the
list `keep` from the configured paths. `configured_paths` gives the traversal
paths too, thus the list holds each parent directory of the rule. The plan
then binds only "the outermost path of each subtree", so it binds
`/run/user/1000` — the whole runtime directory of the user, with the message
bus, the agent sockets and each other control socket in it. The tmpfs of
`/run` is then empty of effect for that subtree, and NET-1 and NET-2 come
back for every profile that names one path below `/run`.

The same holds for `/tmp` and `/var/tmp`: a rule for `/tmp/build/out`
restores all of `/tmp/build`. A rule for a direct child of a private
directory (`/tmp/x`) is safe, because the `keep` list drops the covered
directory itself.

**Evidence.** The output of the failing test:

```
ALLOWED REACHED b'PENT_ALLOWED_BANNER'
VICTIM REACHED b'PENT_VICTIM_SECRET'
```

The profile named only the directory of `ALLOWED`. `VICTIM` is a sibling of
it, and the child read its content.

**The fix.** `plan_private_dirs` does not take the traversal paths of a
configured path any more. It binds the configured path itself and makes
only the directories above it with `mount_point_parents`, which the plan
already did for a path that does not exist.

## NET-4 — pent refuses each address of the Unix family

**Severity: medium (it limits the use of pent, it does not open it).
State: fixed by `bfac3e0`.**

The fix of LS-1 made the supervisor perform each permitted connection to
a Unix socket. Two parts of that fix were wider than they needed to be.

1. When the profile named no Unix socket, the filter refused
   `socket(AF_UNIX, ...)` itself. The child then could not make a socket
   of that family at all, not even one that it used only with itself.
2. The supervisor refused each abstract address. The network namespace of
   the child already separates the abstract names of the sandbox from the
   names of the host, so an abstract address of the child is harmless.

Together they stopped a program from using its own abstract socket, which
some runtimes need.

The reason for part 1 was real: a datagram socket sends to a path with
`sendto(2)`, with no `connect(2)`, so the control of `connect` alone does
not cover it (finding CT-2 in `docs/security/containment.md` measured
it).

**The fix.** The supervisor controls each call that carries an address,
and the filter permits the family again:

- `connect(2)`, `sendto(2)` and `sendmsg(2)`: the supervisor performs the
  call for a path that the profile names, and refuses every other path
  with `EACCES`. A message with ancillary data gets `EOPNOTSUPP`,
  because the supervisor cannot pass the descriptors of the child.
- `sendmmsg(2)`: one call carries several messages, so the supervisor
  refuses a path address instead of performing the call.
- A call with no address, and a call on a socket of another family, keep
  their behaviour. The filter tests the address argument of `sendto(2)`
  in the BPF program, so a `send(2)` costs no notification.
- An abstract address follows the network namespace: the supervisor
  makes the call on the socket of the child when the child has its own
  namespace, and the child gets `EACCES` with `--network unrestricted`,
  where the names of the host are in reach.

Each decision makes the same event as the connect path, so watch mode
proposes the socket and `pent run --trace` reports the denial. The tests
are `child_cannot_reach_a_host_abstract_unix_socket`,
`the_default_profile_refuses_a_path_but_keeps_the_unix_family` and
`an_abstract_address_is_refused_without_a_network_namespace` in
`crates/pent/tests/security_network_e2e.rs`, and the unit tests of
`crates/pent-sandbox/src/linux_watch.rs` and
`crates/pent-sandbox/src/linux_unixconn.rs`.

**What the fix costs.** The child cannot hand the seccomp listener over
with `SCM_RIGHTS` any more, because the filter traps `sendmsg(2)` and
the supervisor cannot answer a notification before it holds the
listener. The child sends a pidfd of itself first and the supervisor
takes the listener with `pidfd_getfd(2)`. Each `sendmsg(2)` on a
datagram socket of the Unix family now costs one notification.

### NET-5 — the `resolv.conf` of the child behind a symbolic link (Medium)

**State: fixed.**

**What pent gives the child.** In proxy mode pent writes one file with the
single line `nameserver 127.0.0.1` in its runtime directory
(`linux_proxynet::resolv_conf`), and the child binds that file read-only at
the place where the C library reads the resolver. The file holds that line
and nothing else, so the child reaches only the DNS server of pent on
`127.0.0.1:53`. A program with a fixed resolver (for example `8.8.8.8`)
has no route out of the network namespace and resolves no name.

**The bug.** The bind used the canonical path of `/etc/resolv.conf`, and the
Landlock rules did not name it. On a host where `/etc/resolv.conf` is a
plain file (NixOS, and the Debian image of the Docker suite) the file sits
in `/etc`, which `SYSTEM_PATHS` grants, and the child reads it. On a host
with `systemd-resolved` — Ubuntu, Fedora and most other distributions —
`/etc/resolv.conf` is a symbolic link into `/run`, for example to
`/run/systemd/resolve/stub-resolv.conf`. The child gets an empty tmpfs over
`/run`, and no rule of the ruleset covers a path below it. The child then
got `EACCES` for `/etc/resolv.conf` and resolved no name at all. Every host
of the test matrix hid the bug: the host of the author is NixOS, and the
Docker image of the e2e suite is Debian with a plain file. The first run of
the pipeline on `ubuntu-latest` found it.

**The fix.** Three parts, in `crates/pent-sandbox/src/linux.rs`:

1. The parent reads the symbolic link chain of `/etc/resolv.conf` before the
   tmpfs hides the target (`resolv_link_target`). It follows up to
   `RESOLV_LINK_LIMIT` (eight) links and keeps the last path.
2. The child makes the directory chain of that path inside the tmpfs, makes
   an empty file at the end of it, and binds the file of pent onto it
   (`resolv_bind`). The directories get the mode `0755` and the mount point
   the mode `0644`, whatever the umask of the parent is, so that every
   program of the child can read the file.
3. `add_ruleset_rules` adds a Landlock read rule for that path. The child
   adds its rules after the mounts, so the rule binds to the inode of the
   file of pent, and the path below the tmpfs becomes readable.

A target outside a private directory needs no chain: the bind goes straight
onto the existing file, as before.

**Two states give the child no resolver.** Pent writes a warning in each,
because the state must be a decision and not an accident:

- A link inside `/run` or `/tmp` that points out of every private
  directory, or a chain of more than eight links. Pent owns only its own
  tmpfs; it must not put the resolver of the sandbox at a path of the host
  that it does not control.
- A host with no `/etc/resolv.conf`. Pent does not write in the `/etc` of
  the host, so the path stays absent.

In both states each name lookup of the child fails. This is the closed
state and it is correct, and a program that needs a name reports an error.

**The tests.** `test_resolv_target_follows_a_link_into_run`,
`test_resolv_bind_makes_the_chain_inside_the_tmpfs`,
`test_resolv_bind_of_a_plain_file_needs_no_chain`,
`test_resolv_target_follows_two_links_and_keeps_a_limit` and
`test_resolv_target_refuses_a_link_out_of_a_private_dir` in
`crates/pent-sandbox/src/linux.rs` give the layout of the host as data, so
they reproduce the layout of Ubuntu on a host of any layout.
`test_proxy_only_passes_the_listeners` in the same file and
`child_sees_proxy_resolv_conf` in
`crates/pent/tests/security_network_e2e.rs` read the real file in a real
sandbox, and they pass on a host of either layout.

## Verified defenses

Each item below has a test that passes. The test stays as a regression test.

Proxy level (`crates/pent-proxy/tests/security_network.rs`):

- A disallowed name gets NXDOMAIN. The proxy does not forward it upstream.
  (`disallowed_name_gets_nxdomain_and_is_not_forwarded_upstream`)
- A SOCKS5 connection to a disallowed domain gets the code
  "connection not allowed". (`socks5_connect_to_disallowed_domain_is_refused`)
- An HTTP CONNECT to a disallowed domain gets 403.
  (`http_connect_to_disallowed_domain_is_forbidden`)
- A plain HTTP proxy request (an absolute-URI `GET`) does not work. The proxy
  supports only CONNECT and SOCKS5.
  (`non_connect_http_proxy_request_is_rejected`)
- A direct IP connection to the cloud metadata address 169.254.169.254 is
  blocked. (`socks5_ip_literal_to_cloud_metadata_is_blocked`)
- A name that resolves to loopback is blocked (DNS rebinding to the host).
  (`allowed_name_that_resolves_to_loopback_is_blocked`)
- A direct IP connection to a private address is blocked.
  (`socks5_ip_literal_to_private_is_blocked`)
- An IPv4-mapped IPv6 loopback literal (`::ffff:127.0.0.1`) is blocked.
  (`socks5_ipv6_mapped_loopback_literal_is_blocked`)
- A public IP literal that no allowed name resolved to is blocked in enforce
  mode. (`socks5_ip_literal_not_in_cache_is_blocked`)
- A decimal IP string (`2130706433`) does not reach loopback. The proxy treats
  it as a name, which the allowlist refuses.
  (`http_connect_decimal_ip_form_is_not_resolved_to_loopback`)

End to end (`crates/pent/tests/security_network_e2e.rs`):

- The child cannot reach a daemon socket of the host below `/run`, `/tmp` or
  `/var/tmp`. The test binds its own socket in a private directory, and it
  also probes the real socket when the host has one.
  (`tailscale_localapi_socket_is_masked` for NET-1,
  `system_dbus_socket_is_masked` for NET-2)
- The child cannot reach a service on the host loopback.
  (`child_cannot_reach_a_host_loopback_service`)
- The child cannot reach a host abstract Unix socket, and it does reach
  its own. The new network namespace isolates the abstract socket
  namespace. (`child_cannot_reach_a_host_abstract_unix_socket`)
- With `--network unrestricted` the child gets `EACCES` for each
  abstract address: it shares the names of the host there.
  (`an_abstract_address_is_refused_without_a_network_namespace`)
- The default profile keeps the Unix family and refuses each path that
  it does not name, with `connect` and with a datagram `sendto`.
  (`the_default_profile_refuses_a_path_but_keeps_the_unix_family`)
- A profile path below a private directory does not bring the siblings
  of the host back.
  (`a_profile_path_below_a_private_dir_keeps_its_siblings_hidden`)
- The child has no raw UDP egress out of the namespace.
  (`child_has_no_raw_udp_egress`)
- The child cannot bind the proxy port again, with `SO_REUSEPORT` or not, to
  steal the connections of other processes in the sandbox.
  (`child_cannot_steal_the_proxy_port_with_reuseport`)
- The child's `/etc/resolv.conf` names only the loopback proxy. The test
  passes on a host where that path is a plain file and on a host where it
  is a symbolic link into `/run` (NET-5).
  (`child_sees_proxy_resolv_conf`)

The audit also confirmed, by hand, that the child cannot make an ICMP socket,
and that a nested `unshare(CLONE_NEWUSER)` gives the child capabilities only
over its own new namespace. The nested namespace does not remove the mounts of
the sandbox and does not add a route out of the network namespace.

## Inherent limits

These limits come from the design of a domain allowlist and a TLS proxy. pent
cannot fix them. pent must document them. Each has a test with the name prefix
`inherent_`.

- **Subdomain exfiltration under a wildcard.** A wildcard rule such as
  `*.example.com` lets the child put arbitrary data in the labels of a
  subdomain, for example `<data>.example.com`. The proxy forwards the query to
  the upstream name server, where an attacker reads the data. The query itself
  is the channel. (`inherent_dns_subdomain_exfil_under_allowed_wildcard`)
- **A TXT record is a receive channel.** A TXT query for an allowed name is
  forwarded, and the answer returns. An attacker name server for an allowed
  domain sends commands in a TXT record.
  (`inherent_txt_record_for_allowed_name_is_a_receive_channel`)
- **No host inspection on ports other than 443 and 80.** The proxy reads the
  TLS SNI or the HTTP Host header only on port 443 and port 80. On any other
  port of an allowed domain, the child sends arbitrary bytes with no host
  check. The traffic still goes only to the resolved address of the allowed
  domain. (`inherent_ports_other_than_443_and_80_get_no_host_inspection`)
- **Domain fronting inside TLS.** The child sends an allowed SNI and then a
  different HTTP Host header inside the encrypted session. The proxy cannot
  read the encrypted data. The README names this limit in `inspect.rs`.
- **Encrypted Client Hello (ECH).** ECH hides the real SNI. The outer SNI is a
  public name of the content delivery network. The README names this limit.

## Recommended fixes, in priority order

1. **NET-1 and NET-2: done.** An empty tmpfs covers `/run` in the mount
   namespace of the child, so no control socket of a host daemon is
   reachable. A fixed list of sockets can never be complete, so pent hides
   the directory, not the name. The mask lists in
   `crates/pent-sandbox/src/linux.rs` stay as the second layer, and as the
   data that a user setting can extend later.
2. **NET-3: done** (`dedaf2e`). `plan_private_dirs` binds the configured
   path itself, not the outermost traversal path above it.
3. **NET-4: done** (`bfac3e0`). The supervisor controls each call that
   carries an address, and the child keeps the Unix family and its own
   abstract names.
4. **Documentation.** Add the inherent limits above to the README, next to the
   limits that it already names.

## What stays open

Each finding of this report is fixed. The limits that stay are the
inherent ones above, and these:

- `sendmmsg(2)` with a path address gets `EACCES`, also for a path that
  the profile names. A program that must reach a named socket uses
  `sendto(2)`, `sendmsg(2)`, or a `connect(2)` and then a send with no
  address.
- A message with ancillary data (`SCM_RIGHTS`, `SCM_CREDENTIALS`) to a
  named path on a datagram socket gets `EOPNOTSUPP`: the supervisor
  sends the message itself and cannot pass the descriptors or the
  credentials of the child. A stream socket is not affected.
- A performed send comes from a socket of the supervisor, which has no
  name, so an answer of the server reaches nobody. A notification
  protocol works; a datagram protocol that waits for an answer does not.

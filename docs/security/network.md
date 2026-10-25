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

| ID | Severity | One line | Test |
|----|----------|----------|------|
| NET-1 | Critical | The Tailscale daemon socket is not masked; its `ts-dial` call gives full network egress past the proxy. | `tailscale_localapi_socket_is_masked` |
| NET-2 | High | The system D-Bus socket is reachable; it resolves names and reaches network services past the proxy. | `system_dbus_socket_is_masked` |

### NET-1 — the Tailscale daemon socket gives full egress (Critical)

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

- The child cannot reach a service on the host loopback.
  (`child_cannot_reach_a_host_loopback_service`)
- The child cannot reach a host abstract Unix socket. The new network
  namespace isolates the abstract socket namespace.
  (`child_cannot_reach_a_host_abstract_unix_socket`)
- The child has no raw UDP egress out of the namespace.
  (`child_has_no_raw_udp_egress`)
- The child cannot bind the proxy port again, with `SO_REUSEPORT` or not, to
  steal the connections of other processes in the sandbox.
  (`child_cannot_steal_the_proxy_port_with_reuseport`)
- The child's `/etc/resolv.conf` names only the loopback proxy.
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

1. **NET-1.** Mask the Tailscale daemon socket when the network mode is not
   `Unrestricted`. Add the socket to the masked set in
   `crates/pent-sandbox/src/linux.rs`. Give the user a setting to name more
   egress sockets to mask.
2. **NET-2.** Mask the system D-Bus socket when the network mode is not
   `Unrestricted`, or at least say in the documentation that it is a resolver
   and an egress path. Let a profile name the socket to keep it.
3. **Documentation.** Add the inherent limits above to the README, next to the
   limits that it already names.

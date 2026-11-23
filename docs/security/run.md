# The rules in `pent run`

Status: the branch `next`, phase 3 of `PLAN.md` (steps 3.1 to 3.5, 2026-11-23). This report
lists the security properties of the rules in `pent run`: the key, the
chain of deciders, the grants that the rules give to the static layers,
and the events of a run. It gives the test of each property, and the
properties that later steps must add.

## Scope

- `crates/pent/src/commands/run.rs`: the key, the start of a run, and the
  events of a run.
- `crates/pent/src/commands/decide.rs`: the chain of deciders (`Decider`),
  the rules of the flags (`FlagLists`) and the grants (`Grants`).
- `crates/pent-profile/src/rule.rs`, `RuleSet::whole_allows`: the allow
  rules that hold on their whole width.
- `crates/pent-profile/src/class.rs`, `Classifier::subtree_holds_guard`.
- `crates/pent/src/daemon/client.rs`: the events, the flush and the number
  of a question at its deadline.
- `crates/pent-proxy/src/lib.rs` (`DomainDecider`, `DomainVerdict`,
  `SharedState::decide_domain`), `proxy.rs` and `dns.rs`: the questions of
  the proxy (step 3.2) and of DNS (step 3.3).
- `crates/pent-sandbox/src/config.rs` (`AccessDecider`),
  `linux_watch.rs` (`ask_unix`, `ask_port`, `defer_job`) and
  `linux_unixconn.rs` (`UnixPolicy::askable`): the questions of the
  supervisor (step 3.4).

## The state of phase 3

`pent run` reads the rules of its key, and it no longer reads a profile or
the trust store. The rules go into the static layers at the start
(Landlock, the list of the proxy, the list of the sockets and the list of
the ports).

Since step 3.2 the proxy asks: a CONNECT or SOCKS request for a name that
its list does not hold goes through the chain of deciders, and it can wait
for a question. Since step 3.3 a DNS query asks in the same way, and since
step 3.4 a connection to a Unix socket or to a port of the host. The files
ask from phase 5. Until then, a file access with no rule and no flag gets a
refusal of the base.

## Threat model

The program is hostile. It cannot write the rules: the sandbox hides the
state directory of pent (`~/.local/state/pent`), and pentd is the only
writer. But a rule can be wider than its author meant, by a hand edit or by
a wide answer, and the static layers cannot make a hole in a grant. Thus:

- A grant must never give more than the rules give. When a static layer
  cannot hold a rule exactly, the rule waits for a question.
- A sensitive path (a credential, a file that runs code later) and the
  files of pent must never come from a wider rule.
- An event must name the true cause of a decision, because the human reads
  `pent denials` to choose the next rules.

## How to run the tests

```bash
cargo test -p pent --bin pent decide
cargo test -p pent-profile rule
cargo test -p pent --test pentd pent_denials_shows_the_refusals_of_a_real_run
```

## The properties

| ID | Property | Test |
|---|---|---|
| RN-1 | The key is `--key NAME`, else the file name of the command. A name that is not a valid key stops the run, and the message names `--key NAME`. A key from a shell or an interpreter gives a warning, because all the programs that run through it share its rules. | `run::tests::a_key_comes_from_the_flag_or_the_command` |
| RN-2 | `pent run` reads only the rules of its key. It reads no profile and no trust store. With no rule file, the program gets only the base. A rule file that is not valid, or a link at its path, stops the run before the program starts, with an error that names the file. | `linux::run_without_rules_has_only_the_base`, `test_run_with_a_bad_rule_file_names_the_file`, `p5_cli_run_refuses_a_rule_file_that_is_not_valid` |
| RN-3 | An allow rule goes into a static layer only when no deny rule wins over it at a point inside its width. The check takes each deny rule with the allow rule alone, so a third rule that wins at one point does not hide a hole below it. The check covers each kind that the sandbox gives: Landlock gives a write grant the right to run a file, so a write rule must also hold as an exec rule. An exec rule goes into the read list too, because the execute list of the sandbox gives no read and an exec rule includes the read. | `rule::tests::a_deny_inside_an_allow_takes_the_allow_out_of_the_whole_allows`, `a_deny_inside_a_domain_or_on_a_socket_makes_a_hole`, `decide::tests::the_grants_hold_back_what_a_static_layer_cannot_hold`, `fs_table::a_deny_rule_inside_an_allow_rule_wins`, `decide::tests::a_static_grant_holds_each_kind_that_the_sandbox_gives` |
| RN-4 | An exact file rule on a path that is a directory does not go into Landlock, because Landlock gives the whole tree below a directory. A path that is not UTF-8, or that ends with `*`, does not go into Landlock either: the sandbox takes a path as text and reads a trailing `*` as a pattern, so it would give another path. | `the_grants_hold_back_what_a_static_layer_cannot_hold`, `fs_table::an_exact_rule_on_a_directory_gives_no_child`, `a_static_grant_holds_each_kind_that_the_sandbox_gives` |
| RN-5 | A file rule on a path of the pent class does not go into Landlock. A subtree rule whose base is sensitive, or that covers a location of the guard list (a credential, a file that runs code later, a directory of pent), does not go into Landlock either. The check looks at the kind of the rule, as the class of one access does: a read rule may cover `~/bin`, where the guard stops only a write, and a write rule may not. Without the home directory, no subtree rule goes into Landlock. Each rule that pent holds back gives a warning that names it. | `the_grants_hold_back_what_a_static_layer_cannot_hold`, `fs_table::a_rule_on_the_whole_home_directory_is_not_applied`, `fs_table::the_rules_and_the_kernel_agree` (the rows of `~`), `a_flag_that_names_a_parent_does_not_bring_back_the_socket_of_pentd` |
| RN-6 | The chain asks in this order: the pent class (`ENOENT` for a file, a refusal for another access), the flags, the rules, the answers of this run, and last a question to pentd. The pent class includes the runtime directory of pentd. | `decide::tests::the_chain_asks_the_pent_class_then_the_flags_then_the_rules`, `classes::tests::each_name_of_a_file_of_pent_is_in_the_pent_class` (the runtime directory, also through a link) |
| RN-7 | Only an exact rule or an exact answer allows a sensitive access. A wider allow that contains it does not count, and the access asks. A deny of any width refuses it. | `decide::tests::only_an_exact_rule_allows_a_sensitive_access` |
| RN-8 | Without pentd, an access that needs a question gets a refusal of the base at once. | `decide::tests::without_pentd_an_open_access_is_a_refusal_of_the_base` |
| RN-9 | An answer applies at once for the rest of the run, also to another access inside its width, with no new question. A deadline does not: the next access asks again. | `decide::tests::an_answer_decides_and_covers_the_rest_of_its_width`, `a_deadline_names_its_question` |
| RN-10 | An event names its cause: the flag, the rule or the answer with the same decision, else the base. A rule that allows an access that a static layer refused does not show as the cause. An event of a deadline names the code of its question. For a sensitive access, an event names an exact answer, never a wider answer that does not count. | `decide::tests::a_static_event_names_its_cause`, `a_deadline_names_its_question`, `a_sensitive_access_names_its_exact_answer`, `client::tests::a_deadline_names_the_number_of_its_question` |
| RN-11 | An event that cannot name a request gives no event: an IP address at the proxy, an abstract Unix socket. Thus an event never carries a target that a rule file refuses (PR-4). | `decide::tests::a_static_event_names_its_cause` |
| RN-12 | A real run sends its events to pentd, and they leave before `pent run` exits. `pent denials` shows each refusal with its cause. | `pent_denials_shows_the_refusals_of_a_real_run` |
| RN-13 | At most 4096 events wait in the queue of a session. A later event goes nowhere, so a pentd that reads slowly cannot make `pent run` use memory without a limit. No decision depends on an event. | `client::tests::the_queue_of_events_has_a_limit` |
| RN-14 | The trace log of `pent run --trace` has the name of the key, so a key with `+`, `@` or `~` (`g++`) gets its log. | `store::tests::trace_log_is_private_and_does_not_follow_links` |
| RN-15 | A CONNECT or SOCKS request for a name off the list of the proxy waits for the chain of deciders, at most 20 s (`PROXY_DEADLINE`). An "allow" lets the connection go through; a "deny" or the deadline refuses it. A name of the list connects with no question, and `pent watch` (observe mode) never asks. | `proxy::tests::a_name_off_the_allowlist_waits_for_the_decider`, `the_allowlist_and_observe_mode_do_not_ask`, `a_proxy_question_waits_for_a_deny`, `a_proxy_question_waits_for_an_allow` |
| RN-16 | A TLS SNI or HTTP `Host` name never waits for a question: the tunnel is open already, and the client waits for the server. The name of the request, or a name that the DNS server resolved to the address of the request, has its decision. Another name (domain fronting) needs the list or a decision that the chain knows (a rule, a flag, an answer of this run); else the proxy refuses it. | `proxy::tests::a_sni_name_never_waits_for_a_question`, `test_check_requested_host_sni` |
| RN-17 | The proxy sends one event for each connection, and the event takes the cause of the hook decision for the same name and decision: the answer or the deadline of the question. A hook decision waits at most 10 s for its event (`HOOKED_LIFE`), and at most 1024 wait; an older one names no later event, which then takes the cause of the chain. With a decider, a refusal of the proxy or of DNS says that the domain is denied and names `pent denials`, not `--allow`. | `decide::tests::a_deadline_names_its_question`, `an_old_hook_decision_names_no_later_event`, `an_answer_decides_and_covers_the_rest_of_its_width`, `run::tests::a_denied_domain_names_pent_denials_not_allow`, `a_proxy_question_waits_for_a_deny` |
| RN-18 | A DNS query for a name off the list of the proxy waits for the chain of deciders, at most 4 s (`DNS_DEADLINE`), because glibc waits 5 s. Nothing goes upstream before an "allow". A "deny" gives `REFUSED`, and the deadline gives `SERVFAIL` ("cannot answer now"); the question stays open. A refusal is never `NXDOMAIN`, so pent never says that a name that exists does not exist. | `dns::tests::a_name_off_the_allowlist_goes_upstream_only_after_an_allow`, `disallowed_name_gets_refused_and_is_not_forwarded_upstream`, `a_dns_question_waits_for_a_deny` |
| RN-19 | A verdict that comes after the deadline of its access still reaches the chain: the session keeps each verdict (at most 4096), and the chain takes them before it decides. Thus the next try of the program gets the answer with no new question. | `decide::tests::a_late_answer_applies_to_the_next_access`, `a_late_dns_answer_applies_to_the_next_try` |
| RN-20 | A `connect(2)` to a Unix socket off the list goes to the chain. A rule, a flag or an answer of this run decides at once in the supervisor, with no worker; the chain sees the canonical path and the path as the program wrote it, and a deny of either form wins. Else a worker waits for the question, at most 120 s (`FILE_DEADLINE`), and checks the notification again before it connects, so a task that went gets no connection on the host. After an "allow" the supervisor connects on the host and gives the socket to the child; after a "deny" or the deadline the child gets `EACCES`. A sensitive socket (Docker, `ssh-agent`) takes only an exact answer of the human (RN-7, QU-5). | `a_unix_socket_question_decides_the_connection`, `a_known_decision_of_a_socket_asks_no_question` |
| RN-21 | A TCP connection to a port of the host off the list asks only when the host serves the port: the supervisor reads the listening sockets of the host, at most one time in each second. Nothing serves it: the call stays in the namespace of the child, with no question and no read of the sockets of the child, so a server that the program runs itself needs no question either. A known decision decides at once; else a worker asks as in RN-20. A "deny" or the deadline gives `ECONNREFUSED`. | `a_port_question_decides_the_connection`, `a_port_that_the_host_does_not_serve_asks_no_question`, `linux_loopback::tests::the_host_tables_show_a_listener_of_the_host`, `child_cannot_reach_a_host_loopback_service` |
| RN-22 | A worker thread waits for each question, so one question does not stop the other calls of the program. A decision that the chain knows needs no worker. At most 64 workers wait at one time; a question above this limit gets the refusal at once. | `a_question_does_not_stop_the_other_connections`, `a_slow_host_port_does_not_stop_other_connections`, `a_known_decision_of_a_socket_asks_no_question` |
| RN-23 | No question asks for a socket below the runtime directory of pent, for a path that does not exist, or for an abstract name. In its own network namespace the child gets no question for a resolver socket (`nscd`, `systemd-resolved`): such a socket reaches the network past the proxy, and glibc tries it on each lookup. | `linux_unixconn::tests::a_question_asks_only_for_an_existing_path_outside_pent` |
| RN-24 | `--network blocked` refuses a Unix socket, a port and a name off the lists with no question. It starts no proxy and no DNS server. | `network_blocked_asks_no_question_for_a_socket` |
| RN-26 | Without `--network`, a run is in proxy mode, with or without a domain rule, so DNS, the proxy, the Unix sockets and the ports ask. `--network` takes only `blocked` and `unrestricted`; `unrestricted` gives the network of the host and asks nothing for the network. | `run::tests::the_default_is_the_proxy_which_asks`, `network_flag_wins_over_everything`, `a_proxy_question_waits_for_a_deny`, `a_dns_question_waits_for_a_deny` |
| RN-25 | The supervisor sends the event of each question also without `--trace`, so `pent denials` shows the refusal and names the answer. | `a_unix_socket_question_decides_the_connection` |

## The limits

- **A deny rule and the base.** The static layers cannot refuse a path that
  the base gives. A deny rule for a path in `/usr` or `/etc` has no effect
  until phase 5. A deny rule inside the workspace has no effect until
  step 4.2 makes the workspace a flag.
- **A flag wins over a rule.** The user gives a flag for this run, so a flag
  wins over a deny rule, and a flag allows a sensitive path. Pent does not
  check a flag against the pent class or the guard list.
- **The rules of the start.** `pent run` reads the rules one time. A rule
  that pentd writes during the run (an answer with the scope "remember")
  applies to the questions of this run at once, but it goes into the
  static layers only at the next run.
- **A held-back rule.** A domain rule that pent holds back applies
  through the chain at the proxy (step 3.2). A held-back file rule has no
  effect until phase 5: the access gets a refusal of the base.
- **The clock of DNS.** A question waits at most 4 s for each query. A
  human rarely answers in 4 s, so the first try of a program often gets
  `SERVFAIL`, and the program must try again (glibc does, a few times).
  The grants before the start (section 8.4 of the design) make this rare.
- **A SNI name is matched to the event of its request.** When the SNI name
  differs from the name of the request, the event of the connection names
  the request, and the hook decision of the SNI name can wait unused. The
  limit of 1024 drops the oldest one.
- **A listing.** The defaults of the sandbox give the traversal of `/`,
  and Landlock gives the right to list each directory below a traversal
  grant. So the program can list the names in a sensitive directory (for
  example `~/.password-store`), also with a list deny rule. The grants of
  the parents of a rule add nothing to this. Phase 5 (FUSE) decides each
  listing.
- **A lost event.** When pentd is slow and the queue is full (RN-13), an
  event goes nowhere, and `pent denials` does not show that refusal.
- **A send with an address.** Only `connect(2)` asks. A `sendto(2)` or
  `sendmsg(2)` to a Unix socket off the list gets `EACCES` with no
  question, also after an "allow" for a `connect(2)` to the same path.
- **A test of a static refusal** keeps pentd away (`block_pentd` in the
  tests), so the refusal comes at once (RN-8).
- **A new server of the host.** The supervisor reads the listening
  sockets of the host at most one time in each second. A connection to a
  server that started less than one second before can stay in the
  namespace of the child, with no question, and get `ECONNREFUSED`.
- **The program of a network event.** The proxy does not know the process
  of a connection, so a network event names the key.

## The properties that later steps add

| Step | Property |
|---|---|
| 4.2 | The workspace is a flag, so a deny rule inside it applies. |
| 5.4 | The files of pent give `ENOENT` in each mode, also for a flag. |

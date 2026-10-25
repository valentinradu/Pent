# Hardening review: watch mode and profiles

Status: review of commit `4ac06fe` (2026-10-25). This document lists the
security properties of the profile pipeline, the result of each check, the
tests, and the open items.

## Scope

The review covers the profile pipeline of watch mode:

- `crates/pent-profile/**`: the summary and the grouping, the public suffix
  subset (`psl`), the renderers, the review, the profile file (`doc`), the
  profile name and the guard list.
- `crates/pent-settings/src/store.rs` and `crates/pent-settings/src/trust.rs`.
- `crates/pent/src/commands/review_flow.rs`, `trust.rs` and `watch.rs`.

The review does not cover the recorders and the sandbox backends
(`pent-sandbox`) or the proxy (`pent-proxy`).

## Threat model

The recorded program controls the content of each event: the paths, the
process names, the Unix socket targets, the DNS names and the TCP hosts. Thus
all event data is untrusted. The program can try to:

- change the terminal of the user (escape sequences) or hide text in the
  review (bidi characters);
- add a rule or a table to the draft;
- make the summary propose a rule that is wider than necessary;
- write to the files of pent, or make pent write to other files.

The user decides in the review. Thus the review must show the true rules,
and the defaults must be safe.

## How to run the tests

```
cargo test -p pent-profile --test hardening_profile
cargo test -p pent-settings --test hardening_store
cargo test -p pent --test hardening_pipeline
```

A test for a property that holds is a normal test. A test for a property that
does not hold has `#[ignore = "OPEN H-<n>: ..."]` or
`#[ignore = "GAP G-<n>: ..."]`. Its assertion fails. To see the failures, add
`-- --include-ignored`. When a fix lands, remove the `ignore` mark from the
related tests.

The files:

- `crates/pent-profile/tests/hardening_profile.rs` (public API of
  `pent-profile`).
- `crates/pent-settings/tests/hardening_store.rs` (public API of
  `pent-settings`).
- `crates/pent/tests/hardening_pipeline.rs` (the `pent` binary, with its own
  `HOME` and XDG directories below `CARGO_TARGET_TMPDIR`).

## Summary of the results

| Property | Result |
|---|---|
| 1. Output safety | Partly holds. Pent escapes C0, DEL and C1. Pent does not remove bidi characters (H-1). |
| 2. Draft integrity | Holds for event data. A bare CR in a comment of an earlier draft makes the next draft invalid (H-6). |
| 3. Grouping limits | Does not hold. One access gives a rule on `/`, `~` or `~/.config` (H-2). Reads in `~/.ssh` give a rule on `~/.ssh` (H-3). A create next to the workspace gives a rule on the workspace parent (H-4). The PSL subset misses common services (H-5). |
| 4. Guard coverage | Holds for the named locations. Ten groups of common locations are missing (G-1 to G-10). |
| 5. Store and trust safety | Partly holds. See H-7 to H-12. |
| 6. Review input handling | Holds. |

## Property 1: output safety

Each string from an event that reaches the output must be free of control
characters (C0, DEL, C1) and of the bidi characters U+202A to U+202E and
U+2066 to U+2069.

The renderers use `safe()` (terminal) and `toml_string()` and
`comment_text()` (draft). These functions use `char::is_control`, which
covers C0, DEL and C1. They do not cover the bidi characters, because these
characters are Unicode format characters (category Cf), not control
characters. The summary drops each DNS name and TCP host with a character
outside `[a-z0-9._-]`, and it shows only parsed IP addresses. Thus domains
and IP hosts are safe.

`pent trust` and `pent profile show` print the raw text of the draft or the
profile file, not `render_profile`. The draft escapes control characters in
the TOML strings, so the raw text has no control characters. The draft keeps
the bidi characters.

| Output | Control characters | Bidi characters |
|---|---|---|
| Terminal summary (`render_header`, `render_terminal`) | Pass: `p1_terminal_summary_has_no_control_characters` | Fail (H-1): `p1_terminal_summary_has_no_bidi_characters` |
| Review prompts (`review`) | Pass: `p1_review_prompts_have_no_control_characters` | Fail (H-1): `p1_review_prompts_have_no_bidi_characters` |
| Draft rules and comments (`render_draft`) | Pass: `p1_draft_has_no_control_characters` | Fail (H-1): `p1_draft_has_no_bidi_characters` |
| `render_profile` | Pass: `p1_render_profile_has_no_control_characters` | Fail (H-1): `p1_render_profile_has_no_bidi_characters` |
| `pent trust NAME --review` without a terminal | Pass: `p1_cli_review_summary_has_no_control_characters` | Fail (H-1): `p1_cli_review_summary_has_no_bidi_characters` |
| `pent trust NAME` and `pent profile show NAME` | Pass: `p1_cli_trust_and_show_have_no_control_characters` | Fail (H-1): `p1_cli_trust_and_show_have_no_bidi_characters` |
| Domains and IP hosts | Pass: `p1_domains_and_ip_hosts_drop_payloads` | Pass (same test) |

The test `p1_crafted_events_reach_each_output_field` makes sure that the
crafted text reaches the paths, the reasons of the blocked items and the
Unix socket list.

## Property 2: draft integrity

The output of `render_draft` and `render_draft_with` must parse back with
`ProfileDoc::parse` to exactly the selected doc. A crafted path must never add
a rule or a table.

The tests use paths with quotes, backslashes, CR and LF, `]`, `#`, TOML table
headers, `'''`, `"""`, Unicode, U+2028, NUL, ESC, C1, bidi characters and
U+FFFD (the result of a lossy conversion). Each draft parses back to the
selected doc. A path that is not valid UTF-8 gives no rule.

| Check | Result | Test |
|---|---|---|
| Crafted paths in each list, one payload for each draft | Pass | `p2_crafted_paths_round_trip_through_the_draft` |
| All payloads in one draft | Pass | `p2_all_payloads_in_one_draft_round_trip` |
| `render_draft_with` with any rule text, and reasons from an earlier draft | Pass | `p2_render_draft_with_arbitrary_rules_round_trips` |
| A non-UTF-8 path gives no rule | Pass | `p2_non_utf8_paths_give_no_rule` |
| A bare CR or ESC in a comment of the earlier draft | Fail (H-6) | `p2_reasons_from_an_earlier_draft_keep_the_draft_valid` |

## Property 3: grouping limits

The summary must never propose a rule on `/`, `~`, `~/.config`, `~/.local`,
`~/.local/share`, `~/.local/state`, `~/.cache`, `~/.ssh` (as a directory),
the workspace parent, or a path with a `..` component. It must never make a
wildcard on a public suffix.

| Check | Result | Test |
|---|---|---|
| 300 files and directories below each broad directory, with each operation | Pass | `p3_many_entries_below_broad_dirs_do_not_widen` |
| 64 generated mixed sessions | Pass | `p3_mixed_generated_sessions_do_not_widen` |
| Reads and writes in the workspace parent | Pass | `p3_reads_and_writes_in_workspace_parent_do_not_group` |
| No rule has a `..` component | Pass | `p3_rules_never_have_parent_components` |
| No wildcard on the suffixes in the subset | Pass | `p3_no_wildcard_on_public_suffixes_in_the_subset` |
| No wildcard on a TLD | Pass | `p3_no_wildcard_on_a_tld` |
| One access on the broad directory itself | Fail (H-2) | `p3_one_access_on_a_broad_dir_gives_no_rule` |
| Four reads in `~/.ssh` | Fail (H-3) | `p3_reads_in_ssh_dir_do_not_widen_to_the_dir` |
| 300 entries in `~/.ssh` | Fail (H-3) | `p3_many_entries_in_ssh_dir_do_not_widen` |
| One create or delete in the workspace parent | Fail (H-4) | `p3_create_in_workspace_parent_gives_no_parent_rule` |
| No wildcard on common public suffix services | Fail (H-5) | `p3_no_wildcard_on_common_public_suffix_services` |

The test for H-5 lists these suffixes from the private section of the public
suffix list. The subset does not have them: `trycloudflare.com`, `loca.lt`,
`ngrok.dev`, `ngrok-free.dev`, `duckdns.org`, `ddns.net`, `hopto.org`,
`dynv6.net`, `mooo.com`, `gitpod.io`, `app.github.dev`, `githubpreview.dev`,
`csb.app`, `webcontainer.io`, `replit.dev`, `hf.space`, `streamlit.app`,
`myshopify.com`, `ts.net`, `supabase.co`, `amplifyapp.com`, `on.aws`,
`azurecontainer.io`, `freetls.fastly.net`, `edgecompute.app`,
`neocities.org`, `codeberg.page`, `srht.site`, `gitbook.io`,
`translate.goog`. Compare the list with the current
<https://publicsuffix.org/list/> before a fix.

## Property 4: guard coverage

The test `p4_guard_covers_the_named_locations` holds. It checks each
location that the design and `guard_rules` name: the SSH keys `id_*`, the
cloud and registry credentials, the keyrings, the browser profiles, the
shell rc files, `authorized_keys`, the autostart and systemd user
directories, `~/.local/bin`, the launch agents, the files of pent, and the
privilege escalation tools.

These common locations are missing. Each gap has one ignored test.

| ID | Severity | Missing locations | Test |
|---|---|---|---|
| G-1 | Medium | `~/.config/git/credentials` (the XDG location of the git credential store) | `p4_gap_xdg_git_credentials` |
| G-2 | Medium | `~/.terraform.d/credentials.tfrc.json`, `~/.vault-token` | `p4_gap_terraform_and_vault_tokens` |
| G-3 | High | SSH private keys with a name that does not start with `id_` (`~/.ssh/github_rsa`, `~/.ssh/*.pem`, `~/.ssh/deploy_key`), and keys in a subdirectory (`~/.ssh/keys/id_ed25519`) | `p4_gap_ssh_keys_with_other_names` |
| G-4 | Medium | `~/.config/op`, `~/.config/containers/auth.json`, `~/.config/rclone/rclone.conf`, `~/.pgpass`, `~/.my.cnf`, `~/.s3cfg`, `~/.oci/config`, `~/.config/sops/age/keys.txt`, `~/.config/hub`, `~/.config/glab-cli/config.yml` | `p4_gap_other_credential_stores` |
| G-5 | Low | Shell history (`~/.bash_history`, `~/.zsh_history`, `~/.local/share/fish/fish_history`, `~/.python_history`, `~/.psql_history`). A guard on these files can stop a normal shell, so this is a trade-off. | `p4_gap_shell_history` |
| G-6 | Medium | `~/.bash_aliases` (the default `~/.bashrc` of Debian and Ubuntu reads it), `~/.zlogout`, `~/.config/nushell`, `~/.xonshrc`, `~/.kshrc`, `~/.mkshrc`, `~/.tcshrc`, `~/.cshrc`, `$ZDOTDIR` files | `p4_gap_other_shell_rc_files` |
| G-7 | Medium | `~/.pam_environment`, `~/.xprofile`, `~/.xinitrc`, `~/.xsession`, `~/.xsessionrc`, `~/.ssh/environment` | `p4_gap_session_startup_files` |
| G-8 | High | PATH directories other than `~/.local/bin`: `~/bin`, `~/.cargo/bin`, `~/go/bin`, `~/.npm-global/bin`. A binary in one of them (for example `git`) runs later outside of the sandbox. | `p4_gap_other_path_directories` |
| G-9 | Medium | Files that run code when a tool starts: the Python user site (`usercustomize.py`, `*.pth`), `~/.vimrc`, `~/.config/nvim`, `~/.emacs.d`, `~/.cargo/config.toml`, `~/.npmrc` (write), `~/.git-templates`, `~/.config/git/hooks`, `~/.config/direnv/direnvrc` | `p4_gap_tool_configs_that_run_code` |
| G-10 | Medium | Schedulers without a file in the home directory: `crontab`, `at`, `systemd-run --user` (through the user D-Bus). The `GuardClass::Persistence` documentation names crontab, but no rule matches it. | `p4_gap_schedulers` |

## Property 5: store and trust safety

| Check | Result | Test |
|---|---|---|
| Draft, profile, trust store and logs have the mode 0600. New directories of the store have the mode 0700. | Pass | `p5_store_files_are_0600_and_new_dirs_are_0700` |
| `TrustStore::save` makes a missing directory with the mode 0700 | Fail (H-7) | `p5_trust_store_save_makes_a_private_dir` |
| A symlink at the draft path is replaced, not followed | Pass | `p5_symlink_at_draft_path_is_replaced_not_followed` |
| A symlink at the profile path is replaced, not followed | Pass | `p5_symlink_at_profile_path_is_replaced_not_followed` |
| A symlink at the trust store path is replaced, not followed | Pass | `p5_symlink_at_trust_store_path_is_replaced_not_followed` |
| A symlink at the temporary file of the atomic write is not followed | Fail (H-8) | `p5_symlink_at_temporary_file_is_not_followed` |
| A symlink at an event log path is not followed | Fail (H-9) | `p5_symlink_at_event_log_is_not_followed` |
| `trust` records the hash of exactly the bytes that it moves | Pass | `p5_trust_records_the_hash_of_the_moved_bytes` |
| A profile that changed after the trust is not applied (library) | Pass | `p5_profile_that_changed_after_trust_is_not_applied`, `p5_profile_replaced_by_a_symlink_is_not_applied` |
| `pent run` refuses a profile that changed after the trust (CLI) | Pass | `p5_cli_run_refuses_a_profile_that_changed_after_trust` |
| `pent trust` trusts the bytes that it showed | Fail (H-10) | `p5_trust_moves_the_bytes_that_the_user_saw` |
| The guard protects the files of pent when the XDG variables are set | Fail (H-11) | `p5_guard_protects_pent_files_in_xdg_dirs` |
| Profile names reject `/`, `\`, `..`, a leading dot, control characters, bidi characters and non-ASCII text | Pass | `p5_profile_names_reject_unsafe_text`, `p5_store_paths_stay_in_their_directories`, `p5_list_skips_files_with_invalid_names` |
| The JSONL logs keep one event per line for text with newlines | Pass | `p5_event_logs_keep_one_event_per_line`, `p5_event_log_skips_a_broken_line` |
| The JSONL logs accept a non-UTF-8 path | Fail (H-12) | `p5_event_log_accepts_non_utf8_paths` |

## Property 6: review input handling

| Check | Result | Test |
|---|---|---|
| EOF and empty lines keep the blocked items unselected | Pass | `p6_eof_and_empty_lines_keep_blocked_items_unselected` |
| Invalid input (`y`, `0`, `-1`, `2-1`, `1-999999999`, numbers above `usize::MAX`, non-UTF-8 bytes, NUL, ESC) keeps the blocked items unselected | Pass | `p6_invalid_input_keeps_blocked_items_unselected` |
| Only an explicit answer selects a blocked item | Pass | `p6_explicit_selection_selects_blocked_items` |
| Huge ranges and a line with 200,000 numbers are fast and use little memory | Pass | `p6_huge_ranges_are_fast_and_rejected` |
| Without a terminal, `pent trust --review` keeps the blocked items out of the profile | Pass | `p6_cli_review_without_terminal_keeps_blocked_items_out` |

The parser rejects a range when its end is more than the number of items, so
it never makes a large set.

## Open items

| ID | Severity | Description | Tests |
|---|---|---|---|
| H-1 | Medium | The renderers and `pent trust` keep the bidi characters U+202A to U+202E and U+2066 to U+2069 from paths, process names and socket targets. A crafted path can show a different order of text in the review, for example to hide a credential path. | `p1_*_has_no_bidi_characters` (6 tests) |
| H-2 | High | One access on a broad directory itself gives a rule on it: `open("/home/u", O_DIRECTORY)` gives `read ~`, `open("/")` gives `read /`, `mkdir ~/.config` gives `read_write ~/.config`, an exec of such a path gives an execute rule on it. The review selects normal items by default, and without a terminal pent selects all of them. | `p3_one_access_on_a_broad_dir_gives_no_rule` |
| H-3 | High | Four reads in `~/.ssh` (`config`, `known_hosts`, `known_hosts.old`, `id_ed25519.pub`) give `read ~/.ssh`. This rule includes the private keys that the guard blocked during the watch run. Writes give `read_write ~/.ssh`. | `p3_reads_in_ssh_dir_do_not_widen_to_the_dir`, `p3_many_entries_in_ssh_dir_do_not_widen` |
| H-4 | Medium | One create or delete of a file in the workspace parent (for example `../app.orig`) gives `read_write` on the parent. This rule includes all sibling repositories. | `p3_create_in_workspace_parent_gives_no_parent_rule` |
| H-5 | Medium | The PSL subset misses common tunnel and hosting suffixes (30 in the test). Three names below one of them give a wildcard such as `*.trycloudflare.com`, which allows all other customers of the service. | `p3_no_wildcard_on_common_public_suffix_services` |
| H-6 | Low | `Reasons::from_draft` keeps a bare CR or ESC from a comment of the earlier draft or profile. `render_draft_with` writes it, the new draft does not parse, and `write_draft` fails. Only a hand edit can put such a comment in the file. | `p2_reasons_from_an_earlier_draft_keep_the_draft_valid` |
| H-7 | Low | `TrustStore::save` (public) makes a missing parent directory with `create_dir_all`, thus with the umask mode (0755), not 0700. `ProfileStore::trust` makes the directory first with 0700, so the CLI is not affected. | `p5_trust_store_save_makes_a_private_dir` |
| H-8 | Medium | `write_atomic_private` opens the temporary file `.<name>.<pid>.tmp` with `create` and `truncate`, without `O_EXCL` and without `O_NOFOLLOW`. A symlink at that name sends the content and the `chmod 0600` to the target. A process with write access to the pent directories can overwrite any file of the user. With H-11, the watched program has this access. | `p5_symlink_at_temporary_file_is_not_followed` |
| H-9 | Low | The event logs (`watch/<name>/<run>.jsonl`, `denied/<name>.jsonl`) are opened with `O_APPEND` and `O_CREAT` without `O_NOFOLLOW`. A symlink at the log path makes pent append JSON lines to its target. | `p5_symlink_at_event_log_is_not_followed` |
| H-10 | Low | `pent trust NAME` reads the draft, shows it, asks, and then `ProfileStore::trust` reads the draft again. A change between the two reads is trusted, and the user did not see it. | `p5_trust_moves_the_bytes_that_the_user_saw` |
| H-11 | High | `guard_rules(home)` protects only `~/.config/pent` and `~/.local/state/pent`. When `XDG_CONFIG_HOME` or `XDG_STATE_HOME` points to another directory, the watched program can write the profiles, the drafts and the trust store. It can write a profile and its hash, and `pent run` then applies that profile. The same problem applies to the other guard rules below `~/.config` (fish, autostart, systemd, git). | `p5_guard_protects_pent_files_in_xdg_dirs` |
| H-12 | Medium | `serde_json` cannot encode a non-UTF-8 `PathBuf`, so `EventLog::append` fails. `pent watch` then stops to write events for the rest of the run (`write_failed`). One crafted `open()` hides all later accesses from the review, also the blocked attempts. | `p5_event_log_accepts_non_utf8_paths` |

## Recommended fixes

- **H-1.** In `safe()`, `toml_string()` and `comment_text()`, also escape
  the bidi characters (U+202A to U+202E, U+2066 to U+2069) and the other
  invisible format characters (U+200B to U+200F, U+061C, U+FEFF). In
  `toml_string()`, write them as `\uXXXX`. In `pent trust` and
  `pent profile show`, filter the raw text with the same function, or print
  `render_profile` of the parsed doc.
- **H-2.** In `fs_items`, apply the limit to each final rule, not only to
  the grouping. Drop a rule whose path is `/`, a top-level directory, the
  home directory or a parent of it, or a broad home directory. For a read of
  a broad directory itself, make no rule. Apply the same check in
  `Env::exec_dir` and for the blocked items.
- **H-3.** Never group into a directory that contains a guard target of the
  class `Credential` (use `guard_rules` in the summary). At least, add
  `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker` and `.config/gcloud` to the
  directories that never get a grouped rule.
- **H-4.** In the create and delete branch of `fs_items`, use
  `Env::can_group(dir)` instead of only `Env::is_broad(dir)`. When the
  directory is the workspace or a parent of it, make the rule on the file.
- **H-5.** Use the full public suffix list (for example an embedded copy
  that the release process updates), or add the missing entries to the
  subset. Mark a wildcard in the review when the subset does not know the
  suffix.
- **H-6.** Apply `comment_text()` to each comment in `render_draft_with`,
  also to the reasons that come from `Reasons::from_draft`.
- **H-7.** In `write_atomic_private`, make the parent directory with
  `DirBuilder` and the mode 0700 (the same code as `create_private_dir`).
- **H-8.** Make the temporary file with `create_new(true)` (`O_EXCL`) and
  `O_NOFOLLOW`, with a random name, for example with
  `tempfile::NamedTempFile::new_in(dir)` and `persist`.
- **H-9.** Open the logs with `O_NOFOLLOW` (`custom_flags`). After the open,
  check that the file is a regular file and that the user owns it.
- **H-10.** Add a store function that trusts only the bytes that the caller
  shows, for example `ProfileStore::trust_exact(name, shown: &[u8])`. It
  compares the draft bytes with `shown` and refuses a change. `pent trust`
  calls it with the bytes that it printed.
- **H-11.** Make the `PentFiles` guard rules from `PentDirs` (the real
  config and state directories), for example `guard_rules(home, &dirs)`. Make
  the rules below `~/.config` from `$XDG_CONFIG_HOME` too.
- **H-12.** Encode a non-UTF-8 path without loss (for example a byte array
  or an escaped form in a second field). Also, in `pent watch`, do not stop
  the log after an encode error: skip the one event, count the skipped
  events, and show the count in the summary.

## Other observations (no test)

- **O-1.** The review reads `/dev/tty` after the child exits, but a process
  of the command can still run (pent shows a warning). On a kernel that
  permits `TIOCSTI`, that process can put text in the terminal input and
  answer the review and the trust question. Recommended fix: call
  `tcflush(TCIFLUSH)` before each question, and do not start the review
  while a process of the command still runs.
- **O-2.** `pent profile show` prints the profile file without a parse. A
  changed or hand-edited file can contain control characters, and pent
  prints them. This text does not come from events.
- **O-3.** The module documentation of `render.rs` tells that `pent trust`
  and `pent profile show` print `render_profile`. They print the raw file
  text. Update the documentation or the code.
- **O-4.** Without a terminal, `pent watch` and `pent trust --review` select
  all items that the guard did not block. Thus the wide rules of H-2, H-3
  and H-4 go into the draft without a question. The user still runs
  `pent trust`, which shows the draft.

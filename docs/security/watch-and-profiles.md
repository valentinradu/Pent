# Hardening review: watch mode and profiles

Status: review of commit `4ac06fe` (2026-10-25). This document lists the
security properties of the profile pipeline, the result of each check, the
tests, and the open items.

Each item of the review has a fix (2026-10-25). The table "Fixed items"
names the commit of each fix. The tests of the fixed items have no `ignore`
mark any more, so they run in the normal suite.

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

Each test of this document runs in the normal suite: the fixes landed, so no
test has an `ignore` mark any more. A new finding gets a test with
`#[ignore = "OPEN H-<n>: ..."]` or `#[ignore = "GAP G-<n>: ..."]`, and the
fix removes that mark.

The files:

- `crates/pent-profile/tests/hardening_profile.rs` (public API of
  `pent-profile`).
- `crates/pent-settings/tests/hardening_store.rs` (public API of
  `pent-settings`).
- `crates/pent/tests/hardening_pipeline.rs` (the `pent` binary, with its own
  `HOME` and XDG directories below `CARGO_TARGET_TMPDIR`).

## Summary of the results

| Property | Result after the fixes |
|---|---|
| 1. Output safety | Holds. Pent escapes C0, DEL, C1 and the Unicode format characters (H-1). |
| 2. Draft integrity | Holds. `render_draft_with` cleans each comment (H-6). |
| 3. Grouping limits | Holds. Every rule keeps the limit (H-2, H-3, H-4). The public suffix subset has the common services (H-5). |
| 4. Guard coverage | Holds for the named locations and for G-1 to G-10. The kernel enforces less than the SSH key rules and the Python user site rules say; see "Open items". |
| 5. Store and trust safety | Holds. See the table "Fixed items" for H-7 to H-12. |
| 6. Review input handling | Holds. Pent discards the queued terminal input before each question (O-1). |

## Fixed items

| ID | Commit subject |
|---|---|
| H-3 | Fixed before this round, in the summary of `pent-profile`. |
| H-2, H-4 | `fix(profile): drop a rule on a broad path, also from one access` |
| G-1 to G-10, H-11 | `feat(profile): close the guard gaps and follow the XDG directories` |
| H-1, H-6 | `fix(profile): escape the Unicode format characters in each output` |
| H-5 | `fix(profile): add the missing public suffixes of common services` |
| H-7, H-8, H-9, H-10 | `fix(settings): make the atomic write and the event logs safe for links` |
| H-12 | `fix(profile): log a path that is not valid UTF-8, and never stop the log` |
| O-1 | `fix(cli): discard the queued terminal input before each question` |

## Property 1: output safety

Each string from an event that reaches the output must be free of control
characters (C0, DEL, C1) and of the bidi characters U+202A to U+202E and
U+2066 to U+2069.

The renderers use `safe()` (terminal) and `toml_string()` and
`comment_text()` (draft). These functions escape each control character and
each character of the Unicode category Cf, plus U+2028 and U+2029. The
summary drops each DNS name and TCP host with a character outside
`[a-z0-9._-]`, and it shows only parsed IP addresses. Thus domains and IP
hosts are safe.

`pent trust` and `pent profile show` print the text of the draft or the
profile file, not `render_profile`. They run `safe_lines()` on it, which
escapes the same characters but keeps the newline. Thus a hand-edited file
cannot change the terminal either.

| Output | Control characters | Bidi characters |
|---|---|---|
| Terminal summary (`render_header`, `render_terminal`) | Pass: `p1_terminal_summary_has_no_control_characters` | Pass: `p1_terminal_summary_has_no_bidi_characters` |
| Review prompts (`review`) | Pass: `p1_review_prompts_have_no_control_characters` | Pass: `p1_review_prompts_have_no_bidi_characters` |
| Draft rules and comments (`render_draft`) | Pass: `p1_draft_has_no_control_characters` | Pass: `p1_draft_has_no_bidi_characters` |
| `render_profile` | Pass: `p1_render_profile_has_no_control_characters` | Pass: `p1_render_profile_has_no_bidi_characters` |
| `pent trust NAME --review` without a terminal | Pass: `p1_cli_review_summary_has_no_control_characters` | Pass: `p1_cli_review_summary_has_no_bidi_characters` |
| `pent trust NAME` and `pent profile show NAME` | Pass: `p1_cli_trust_and_show_have_no_control_characters` | Pass: `p1_cli_trust_and_show_have_no_bidi_characters` |
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
| A bare CR or ESC in a comment of the earlier draft | Pass | `p2_reasons_from_an_earlier_draft_keep_the_draft_valid` |

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
| One access on the broad directory itself | Pass | `p3_one_access_on_a_broad_dir_gives_no_rule` |
| Four reads in `~/.ssh` | Pass | `p3_reads_in_ssh_dir_do_not_widen_to_the_dir` |
| 300 entries in `~/.ssh` | Pass | `p3_many_entries_in_ssh_dir_do_not_widen` |
| One create or delete in the workspace parent | Pass | `p3_create_in_workspace_parent_gives_no_parent_rule` |
| No wildcard on common public suffix services | Pass | `p3_no_wildcard_on_common_public_suffix_services` |

The test for H-5 lists these suffixes. The subset has them now: `trycloudflare.com`, `loca.lt`,
`ngrok.dev`, `ngrok-free.dev`, `duckdns.org`, `ddns.net`, `hopto.org`,
`dynv6.net`, `mooo.com`, `gitpod.io`, `app.github.dev`, `githubpreview.dev`,
`csb.app`, `webcontainer.io`, `replit.dev`, `hf.space`, `streamlit.app`,
`myshopify.com`, `ts.net`, `supabase.co`, `amplifyapp.com`, `on.aws`,
`azurecontainer.io`, `freetls.fastly.net`, `edgecompute.app`,
`neocities.org`, `codeberg.page`, `srht.site`, `gitbook.io`,
`translate.goog`.

The fix compared each name with the list of 2026-10-22 (commit `8437e52`).
Six names are no longer in that list: `loca.lt`, `mooo.com`, `gitpod.io`,
`app.github.dev`, `webcontainer.io` and `neocities.org`. Each service still
gives one name to each customer, so `psl::FORMER_SUFFIXES` keeps them. The
list writes `replit.dev`, `azurecontainer.io` and `on.aws` with a wildcard
rule; the subset has no wildcard form, so `psl::NO_WILDCARD_BELOW` holds
them. Compare the subset with the current
<https://publicsuffix.org/list/public_suffix_list.dat> from time to time.

## Property 4: guard coverage

The test `p4_guard_covers_the_named_locations` holds. It checks each
location that the design and `guard_rules` name: the SSH keys `id_*`, the
cloud and registry credentials, the keyrings, the browser profiles, the
shell rc files, `authorized_keys`, the autostart and systemd user
directories, `~/.local/bin`, the launch agents, the files of pent, and the
privilege escalation tools.

The guard list covers these common locations now. Each row has one test.

| ID | Severity | Locations | Test |
|---|---|---|---|
| G-1 | Medium (fixed) | `~/.config/git/credentials` (the XDG location of the git credential store) | `p4_gap_xdg_git_credentials` |
| G-2 | Medium (fixed) | `~/.terraform.d/credentials.tfrc.json`, `~/.vault-token` | `p4_gap_terraform_and_vault_tokens` |
| G-3 | High (fixed) | SSH private keys with a name that does not start with `id_` (`~/.ssh/github_rsa`, `~/.ssh/*.pem`, `~/.ssh/deploy_key`), and keys in a subdirectory (`~/.ssh/keys/id_ed25519`) | `p4_gap_ssh_keys_with_other_names` |
| G-4 | Medium (fixed) | `~/.config/op`, `~/.config/containers/auth.json`, `~/.config/rclone/rclone.conf`, `~/.pgpass`, `~/.my.cnf`, `~/.s3cfg`, `~/.oci/config`, `~/.config/sops/age/keys.txt`, `~/.config/hub`, `~/.config/glab-cli/config.yml` | `p4_gap_other_credential_stores` |
| G-5 | Low (fixed) | Shell history (`~/.bash_history`, `~/.zsh_history`, `~/.local/share/fish/fish_history`, `~/.python_history`, `~/.psql_history`). A guard on these files can stop a normal shell, so this is a trade-off. | `p4_gap_shell_history` |
| G-6 | Medium (fixed) | `~/.bash_aliases` (the default `~/.bashrc` of Debian and Ubuntu reads it), `~/.zlogout`, `~/.config/nushell`, `~/.xonshrc`, `~/.kshrc`, `~/.mkshrc`, `~/.tcshrc`, `~/.cshrc`, `$ZDOTDIR` files | `p4_gap_other_shell_rc_files` |
| G-7 | Medium (fixed) | `~/.pam_environment`, `~/.xprofile`, `~/.xinitrc`, `~/.xsession`, `~/.xsessionrc`, `~/.ssh/environment` | `p4_gap_session_startup_files` |
| G-8 | High (fixed) | PATH directories other than `~/.local/bin`: `~/bin`, `~/.cargo/bin`, `~/go/bin`, `~/.npm-global/bin`, `~/.yarn/bin`. A binary in one of them (for example `git`) runs later outside of the sandbox. | `p4_gap_other_path_directories` |
| G-9 | Medium (fixed) | Files that run code when a tool starts: the Python user site (`usercustomize.py`, `*.pth`), `~/.vimrc`, `~/.config/nvim`, `~/.emacs.d`, `~/.cargo/config.toml`, `~/.npmrc` (write), `~/.git-templates`, `~/.config/git/hooks`, `~/.config/direnv/direnvrc` | `p4_gap_tool_configs_that_run_code` |
| G-10 | Medium (fixed) | Schedulers without a file in the home directory: `crontab`, `at`, `batch`, `systemd-run --user` (through the user D-Bus), and `~/.config/cron`. | `p4_gap_schedulers` |

### What the kernel enforces

A private SSH key has no fixed name, and the Python user site is below a
directory with a version in its name. `GuardTarget::FilesInDir` therefore
takes a file name prefix, or a file name suffix with a leading `*`, and it
matches a file at any depth below the directory.

`classify` uses the full rule, so the summary always puts such an access in
the blocked section and the review does not select it. The two kernel
backends enforce less:

- Linux (`plan_guard`) masks only the direct children of the directory that
  exist when the child starts. A key in `~/.ssh/keys/` is not masked.
- macOS builds one regular expression from the prefix. A pattern with a
  leading `*` matches no file there, thus these rules have no effect on
  macOS yet.

A follow-up in `pent-sandbox` must give both backends the pattern form and
the depth. Until then, pent records and shows the access, but the kernel
does not stop it.

## Property 5: store and trust safety

| Check | Result | Test |
|---|---|---|
| Draft, profile, trust store and logs have the mode 0600. New directories of the store have the mode 0700. | Pass | `p5_store_files_are_0600_and_new_dirs_are_0700` |
| `TrustStore::save` makes a missing directory with the mode 0700 | Pass | `p5_trust_store_save_makes_a_private_dir` |
| A symlink at the draft path is replaced, not followed | Pass | `p5_symlink_at_draft_path_is_replaced_not_followed` |
| A symlink at the profile path is replaced, not followed | Pass | `p5_symlink_at_profile_path_is_replaced_not_followed` |
| A symlink at the trust store path is replaced, not followed | Pass | `p5_symlink_at_trust_store_path_is_replaced_not_followed` |
| A symlink at the temporary file of the atomic write is not followed | Pass | `p5_symlink_at_temporary_file_is_not_followed` |
| A symlink at an event log path is not followed | Pass | `p5_symlink_at_event_log_is_not_followed` |
| `trust` records the hash of exactly the bytes that it moves | Pass | `p5_trust_records_the_hash_of_the_moved_bytes` |
| A profile that changed after the trust is not applied (library) | Pass | `p5_profile_that_changed_after_trust_is_not_applied`, `p5_profile_replaced_by_a_symlink_is_not_applied` |
| `pent run` refuses a profile that changed after the trust (CLI) | Pass | `p5_cli_run_refuses_a_profile_that_changed_after_trust` |
| `pent trust` trusts the bytes that it showed | Pass | `p5_trust_moves_the_bytes_that_the_user_saw` |
| The guard protects the files of pent when the XDG variables are set | Pass | `p5_guard_protects_pent_files_in_xdg_dirs` |
| Profile names reject `/`, `\`, `..`, a leading dot, control characters, bidi characters and non-ASCII text | Pass | `p5_profile_names_reject_unsafe_text`, `p5_store_paths_stay_in_their_directories`, `p5_list_skips_files_with_invalid_names` |
| The JSONL logs keep one event per line for text with newlines | Pass | `p5_event_logs_keep_one_event_per_line`, `p5_event_log_skips_a_broken_line` |
| The JSONL logs accept a non-UTF-8 path | Pass | `p5_event_log_accepts_non_utf8_paths` |

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

## The items of the review and their fixes

Each row names the finding of the review, the fix, and the tests. The tests
run in the normal suite.

| ID | Severity | Finding and fix | Tests |
|---|---|---|---|
| H-1 | Medium | The renderers and `pent trust` kept the bidi characters U+202A to U+202E and U+2066 to U+2069 from paths, process names and socket targets. **Fix:** `safe`, `toml_string` and `comment_text` escape each character of the Unicode category Cf, plus U+2028 and U+2029. The new `safe_lines` does the same for a whole file text, and `pent trust` and `pent profile show` use it. | `p1_*_has_no_bidi_characters` (6 tests) |
| H-2 | High | One access on a broad directory gave a rule on it: `open("/home/u", O_DIRECTORY)` gave `read ~`, and `mkdir ~/.config` gave `read_write ~/.config`. **Fix:** `Env::is_too_wide` runs on each final rule, not only when the summary groups. A file directly in a broad directory keeps its own rule. | `p3_one_access_on_a_broad_dir_gives_no_rule` |
| H-3 | High | Four reads in `~/.ssh` gave `read ~/.ssh`, which includes the private keys. **Fix:** the summary knows the directories that a guard rule protects and never groups into one of them. | `p3_reads_in_ssh_dir_do_not_widen_to_the_dir`, `p3_many_entries_in_ssh_dir_do_not_widen` |
| H-4 | Medium | One create or delete of a file in the workspace parent gave `read_write` on the parent, thus on each sibling repository. **Fix:** the create and delete branch uses `Env::can_group_for_write`, which keeps the workspace and its parents out. | `p3_create_in_workspace_parent_gives_no_parent_rule` |
| H-5 | Medium | The public suffix subset missed common tunnel and hosting suffixes, so three names below one of them gave a wildcard such as `*.trycloudflare.com`. **Fix:** the subset has them, from the list of 2026-10-22. | `p3_no_wildcard_on_common_public_suffix_services` |
| H-6 | Low | `Reasons::from_draft` kept a bare CR or ESC from a comment of an earlier draft, so the next draft did not parse. **Fix:** `render_draft_with` runs `comment_text` on each reason. | `p2_reasons_from_an_earlier_draft_keep_the_draft_valid` |
| H-7 | Low | `TrustStore::save` made a missing parent directory with `create_dir_all`, thus with the umask mode 0755. **Fix:** `write_atomic_private` uses `DirBuilder` with the mode 0700. | `p5_trust_store_save_makes_a_private_dir` |
| H-8 | Medium | `write_atomic_private` opened the temporary file `.<name>.<pid>.tmp` without `O_EXCL` and without `O_NOFOLLOW`, so a symbolic link at that name took the content and the mode 0600. **Fix:** the temporary file has a name with a number from the clock, and pent opens it with `create_new` and `O_NOFOLLOW`, with a retry. | `p5_symlink_at_temporary_file_is_not_followed` |
| H-9 | Low | The event logs were opened without `O_NOFOLLOW`, so a symbolic link at the log path took the JSON lines. **Fix:** `EventLog::open_append` uses `open_log_nofollow`. | `p5_symlink_at_event_log_is_not_followed` |
| H-10 | Low | `pent trust NAME` read the draft, showed it, asked, and read it again, so a change between the two reads went into the profile. **Fix:** `ProfileStore::trust_exact(name, shown)` writes and trusts the bytes that the caller showed; `pent trust` calls it. | `p5_trust_moves_the_bytes_that_the_user_saw` |
| H-11 | High | `guard_rules(home)` protected only `~/.config/pent` and `~/.local/state/pent`, so with `$XDG_CONFIG_HOME` or `$XDG_STATE_HOME` the watched program could write the profiles and the trust store. **Fix:** `guard_rules_with(home, pent_dirs)` adds one rule for each real directory, and `pent watch` gives it the directories of the store. | `p5_guard_protects_pent_files_in_xdg_dirs` |
| H-12 | Medium | `serde_json` cannot encode a non-UTF-8 `PathBuf`, so one crafted `open()` stopped the log for the rest of the run. **Fix:** the path has a byte-array form in JSON, and `pent watch` skips a bad event, counts it, and warns one time. | `p5_event_log_accepts_non_utf8_paths` |
| G-1 to G-10 | High to Low | The guard list missed common credential and persistence locations. **Fix:** see "Property 4". | `p4_gap_*` (10 tests) |
| O-1 | Low | A process of the command could put text in the terminal input and answer the review. **Fix:** `Tty::confirm` and `Tty::split` call `tcflush(TCIFLUSH)` first. | No test: the test needs a controlling terminal. |

## Open items

| ID | Severity | Description |
|---|---|---|
| H-13 | Medium | The kernel enforces less than the new guard rules with a file name pattern say. See "What the kernel enforces" in Property 4. The fix belongs in `pent-sandbox`. |
| H-14 | Low | `guard_rules_with` moves only the `PentFiles` rules to the real directories. The other rules below `~/.config` (fish, nushell, autostart, systemd, git, direnv, nvim) still use `~/.config`. `$XDG_CONFIG_HOME` does not move them. |

## Other observations (no test)

- **O-2.** `pent profile show` prints the profile file without a parse. The
  command now runs `safe_lines` on the text, so a control character or a
  format character from a hand edit cannot change the terminal.
- **O-3.** The module documentation of `render.rs` tells which function
  each command prints. `pent trust` and `pent profile show` print the file
  text through `safe_lines`, not `render_profile`.
- **O-4.** Without a terminal, `pent watch` and `pent trust --review`
  select all items that the guard did not block. The wide rules of H-2,
  H-3 and H-4 are gone, so these items are narrow now. The user still runs
  `pent trust`, which shows the draft.

# The rules and the rule files

Status: the branch `next`, steps 1.1 and 1.2 of `PLAN.md` (2026-11-22).
This report lists the security properties of the rule model and of the rule
files, the test of each property, and the properties that later steps must
add.

`pent run` does not read the rules yet. On `next`, `pent run` still uses the
profiles and the trust store of version 0.2.x (see
[watch-and-profiles.md](watch-and-profiles.md)). Step 3.1 changes this.

## Scope

- `crates/pent-profile/src/rule.rs`: the rule, the key, the widths and the
  decision of a set of rules.
- `crates/pent-profile/src/rule_file.rs`: the TOML form of a set of rules.
- `crates/pent-settings/src/store.rs`, the type `RuleStore`: the files in
  `~/.local/state/pent/rules/`.

## Threat model

A rule decides what a program can do in each later run, without a
question. Thus:

- A rule must cover only the accesses that its answer named. A rule that is
  wider than the answer gives the program access that nobody gave.
- The program must not write a rule. Later steps hide the rule files from
  the sandbox (the pent class, step 1.3) and make pentd the only writer
  (step 2.2). Until then, nothing in the sandbox reads or writes them.
- A user edits a rule file by hand. A bad edit must give an error that
  names the problem, never a rule that differs from the text.
- Another process of the user can put a link, a FIFO or a very large file at
  the path. Pent must not follow the link, block, or read without a limit.

## How to run the tests

```bash
cargo test -p pent-profile rule
cargo test -p pent-settings store::tests::rules

cd crates/pent-profile
cargo +nightly fuzz run rule_file -- -max_total_time=150 -rss_limit_mb=4096
```

## The rule model

| ID | Property | Test |
|---|---|---|
| RU-1 | When more than one rule matches, the most specific rule wins: an exact path before a subtree, a deeper subtree before a shallower one, an exact domain before a wildcard. On a tie, `Deny` wins. | `rule::tests::the_most_specific_rule_wins`, `deny_wins_a_tie` |
| RU-2 | A rule covers only its kind. A list rule gives the names, not the content. A read rule does not permit a write. A write or an exec rule includes reads, and each rule includes the listings inside its width. | `each_file_kind_covers_the_expected_kinds`, `an_exact_list_rule_covers_only_that_directory`, `a_subtree_covers_the_paths_below_it_and_not_its_siblings` |
| RU-3 | A subtree compares whole path components: `~/.cargo/registry` does not cover `~/.cargo/registry-old`. | `a_subtree_covers_the_paths_below_it_and_not_its_siblings` |
| RU-4 | A rule path is absolute and has no `.` or `..` component, so a path cannot leave its width. | `a_rule_path_is_absolute_and_normal`, `rule_file::tests::bad_values_are_errors` |
| RU-5 | The domain forms follow the proxy. `*.base` is one more label, `**.base` is any depth, and neither covers `base`. A wildcard compares whole labels: `*.npmjs.org` does not cover `evilnpmjs.org`. | `domain_widths_follow_the_proxy`, `a_domain_width_parses_the_form_of_the_proxy` |
| RU-6 | A wildcard cannot cover a public suffix (`*.com`, `*.co.uk`, `*.github.io`), also in a file that a user edits. | `a_wildcard_cannot_cover_a_public_suffix`, `rule_file::tests::bad_values_are_errors` |
| RU-7 | A socket rule and a port rule match exactly, and a file rule never answers a socket access. | `sockets_and_ports_match_exactly` |
| RU-8 | A key has 1 to 64 characters from `[A-Za-z0-9._-]` and does not start with `.`, so a key is always a safe file name in the rule directory. | `a_key_comes_from_the_file_name_of_the_command` |

## The rule files

| ID | Property | Test |
|---|---|---|
| RF-1 | The parser is strict. An unknown field, a missing field, a field of another kind and an unknown value give an error that names the field. | `rule_file::tests::an_unknown_field_is_an_error_that_names_it`, `a_field_of_another_kind_or_a_missing_field_is_an_error`, `store::tests::rules::a_bad_file_is_an_error_that_names_the_file_and_the_field` |
| RF-2 | Pent reads the version before the fields. A file of a newer version gives the version error, not an unknown field. | `the_version_must_be_known` |
| RF-3 | A date must be a full date and time with an offset, from 1970 to 9999 in UTC. Pent drops a fraction of a second on the load, so a load, a save and a load give the same rule. | `bad_values_are_errors`, `a_fraction_of_a_second_is_dropped_on_the_load`, `a_time_out_of_range_cannot_be_written` |
| RF-4 | The file has the mode `0600`, the directory `0700` and the lock file `0600`. | `store::tests::rules::the_rules_survive_a_round_trip_in_a_private_file` |
| RF-5 | Pent reads a rule file with `O_NOFOLLOW`. A symbolic link at the path is an error, also when its target is valid, and the target does not change. | `a_symbolic_link_at_the_path_is_not_followed` |
| RF-6 | The write is a rename of a new file with a name that nobody can guess (`write_atomic_private`). A link that appears at the path after the read is replaced, and its target does not change. | `a_link_that_appears_during_an_update_is_replaced` |
| RF-7 | Pent reads only a regular file of at most 4 MiB. A directory and a FIFO give an error at once (`O_NONBLOCK`), and a larger file gives an error. `RuleStore::keys` lists only regular files. | `a_directory_or_a_fifo_at_the_path_is_refused_at_once`, `a_file_above_the_limit_is_refused`, `a_file_with_a_name_that_is_not_a_key_or_not_a_file_is_skipped` |
| RF-8 | A change holds a lock on the key (`flock`) from the read to the write, so parallel changes lose no rule. The test fails when the lock is removed. | `parallel_updates_lose_no_rule` |
| RF-9 | A change reads the file again, so it keeps an edit of the user that came after an earlier load. Pent does not write over a file that it cannot read. | `an_update_sees_an_edit_that_came_after_a_load`, `rule_file::tests::an_update_refuses_a_file_that_is_not_valid` |
| RF-10 | A change keeps the comments and the form of each rule that stays. A removed rule loses its table and the comment above it. | `an_update_keeps_the_comments_and_the_form_of_each_kept_rule`, `an_update_with_no_change_gives_the_same_text`, `store::tests::rules::a_save_keeps_the_comments_of_the_user` |
| RF-11 | A file that the parser accepts gives the same rules after a new render, and after an update that keeps, removes or adds a rule. | The fuzz target `rule_file`: 1,833,666 inputs in 151 seconds, no finding (2026-11-22). |

## The limits

- **The editor of the user.** The lock holds against other pent processes,
  not against a text editor. An editor that saves during the write of pent
  can lose the change of pent, or pent can lose the edit. The window is the
  time of one write.
- **Duplicate rules.** A file can hold two equal rules. They give the same
  decision, and an update keeps one table for each copy that stays in the
  set.

## The properties that later steps add

| Step | Property |
|---|---|
| 1.3, 5.4 | The rule directory is in the pent class, and the program gets `ENOENT` for it. |
| 2.2 | pentd is the only writer of the rules. A late answer becomes a rule for the next run. |
| 3.1 | `pent run` decides each access from the rules of its key before it asks. |

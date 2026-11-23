# The rules, the classes and the rule files

Status: the branch `next`, steps 1.1 to 1.3 of `PLAN.md` (2026-11-22).
This report lists the security properties of the rule model, of the classes
and the width menu, and of the rule files, the test of each property, and
the properties that later steps must add.

`pent run` reads the rules of its key since step 3.1. [run.md](run.md) has
the properties of the rules in `pent run`.

## Scope

- `crates/pent-profile/src/rule.rs`: the rule, the key, the widths and the
  decision of a set of rules.
- `crates/pent-profile/src/rule_file.rs`: the TOML form of a set of rules.
- `crates/pent-profile/src/class.rs`: the class of an access and the width
  menu of a question.
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
- An answer must not be wider than the question. The width menu is the
  only source of the targets of an answer, so the model and the human pick
  a number, and nobody writes a path.
- A user edits a rule file by hand. A bad edit must give an error that
  names the problem, never a rule that differs from the text.
- Another process of the user can put a link, a FIFO or a very large file at
  the path. Pent must not follow the link, block, or read without a limit.

## How to run the tests

```bash
cargo test -p pent-profile rule
cargo test -p pent-profile class
cargo test -p pent-settings store::tests::rules

cd crates/pent-profile
cargo +nightly fuzz run rule_file -- -max_total_time=150 -rss_limit_mb=4096
```

## The rule model

| ID | Property | Test |
|---|---|---|
| RU-1 | When more than one rule matches, the most specific rule wins: an exact path before a subtree, a deeper subtree before a shallower one, an exact domain before a wildcard. On a tie, `Deny` wins. | `rule::tests::the_most_specific_rule_wins`, `deny_wins_a_tie` |
| RU-2 | A rule covers only its kind. A list rule gives the names, not the content. A read rule does not permit a write. An allow of a write or an exec includes reads, and each allow includes the listings inside its width. A deny goes the other way: a deny of a kind also refuses each kind that includes it (a deny of a read refuses the write and the exec, because they read the file), and a deny of a write does not refuse a read. | `each_file_kind_covers_the_expected_kinds`, `a_deny_refuses_its_kind_and_the_wider_kinds_only`, `deny_wins_a_tie`, `an_exact_list_rule_covers_only_that_directory`, `a_subtree_covers_the_paths_below_it_and_not_its_siblings` |
| RU-3 | A subtree compares whole path components: `~/.cargo/registry` does not cover `~/.cargo/registry-old`. | `a_subtree_covers_the_paths_below_it_and_not_its_siblings` |
| RU-4 | A rule path is absolute and has no `..` component and no NUL byte, so a path cannot leave its width. A path has one normal form (`//a//b/` becomes `/a/b`), so one rule has one text in a question and in a rule file. | `a_rule_path_is_absolute_and_normal`, `a_rule_path_has_one_normal_form_and_no_nul`, `rule_file::tests::bad_values_are_errors` |
| RU-5 | The domain forms follow the proxy. `*.base` is one more label, `**.base` is any depth, and neither covers `base`. A wildcard compares whole labels: `*.npmjs.org` does not cover `evilnpmjs.org`. | `domain_widths_follow_the_proxy`, `a_domain_width_parses_the_form_of_the_proxy` |
| RU-6 | A wildcard cannot cover a public suffix (`*.com`, `*.co.uk`, `*.github.io`), also in a file that a user edits. | `a_wildcard_cannot_cover_a_public_suffix`, `rule_file::tests::bad_values_are_errors` |
| RU-7 | A socket rule and a port rule match exactly, and a file rule never answers a socket access. | `sockets_and_ports_match_exactly` |
| RU-8 | A key has 1 to 64 characters from `[A-Za-z0-9._+@~-]` and does not start with `.`, so a key is always a safe file name in the rule directory, and the well-known names fit (`g++`, `clang++`, `x86_64-linux-gnu-gcc`). A space, a `/`, a `:`, a shell character and a non-ASCII letter are refused. When the name of the program is not a valid key, `pent run` stops and names `--key NAME` (RN-1 in [run.md](run.md)). | `a_key_comes_from_the_file_name_of_the_command`, `run::tests::a_key_comes_from_the_flag_or_the_command` |

## The classes and the width menu

| ID | Property | Test |
|---|---|---|
| CL-1 | Each path in a directory of pent is in the pent class, for each kind: `~/.config/pent`, `~/.local/state/pent`, `~/.local/share/pent`, the real XDG directories and the directory of `pentd.sock`. A sibling with a longer name (`~/.config/pentagon`) is not. | `class::tests::the_files_of_pent_are_in_the_pent_class_for_each_kind` |
| CL-2 | A credential of the guard list is sensitive to a read, a list, a write and an exec. A write is sensitive because it can create or replace a token (`gh auth login`). | `a_credential_is_sensitive_to_read_list_write_and_exec` |
| CL-3 | A file of the guard list that runs code later is sensitive to a write. An exec of a tool that gives more privilege is sensitive. | `a_start_file_is_sensitive_to_write_only` |
| CL-4 | Each socket of `ESCAPE_SOCKETS`, `RESOLVER_SOCKETS` and `HOME_AGENT_SOCKETS`, and each port of `CONTROL_PORTS`, is sensitive. The three socket lists moved from `pent-sandbox` to `class.rs`, so the sandbox masks and the classes use one list. | `the_sockets_of_the_lists_are_sensitive`, `a_control_port_is_sensitive_and_a_domain_is_normal` |
| CL-5 | A sensitive access gets only the exact target in its menu, and a pent access gets an empty menu. | `a_sensitive_access_gets_only_the_exact_target_and_pent_gets_none` |
| CL-6 | A file menu has no subtree on `/`, on a directory directly below `/`, on the home directory or on a parent of it, or on a directory that holds a directory of pent or a location of the guard list (for example `~/.config/**`, `~/.local/**`, `~/.cargo/**`). | `a_file_menu_goes_up_to_the_home_directory`, `a_file_menu_outside_home_stops_below_the_root`, `a_list_menu_starts_with_the_directory_itself`, `a_file_menu_offers_no_subtree_that_holds_pent_or_a_credential` |
| CL-7 | A domain menu stops at the registrable domain, and no wildcard covers a public suffix or a shared host (`*.github.io`). | `a_domain_menu_stops_at_the_registrable_domain` |
| CL-8 | Each entry of a menu covers the access that made the menu, so an answer always answers its question. | `each_menu_entry_covers_the_access` |

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
| RF-11 | A file that the parser accepts gives the same rules after a new render and after an update with no change. After an update that removes or adds a rule, the file holds the same rules with the same count of each rule. | The fuzz target `rule_file`: 2,014,385 inputs in 151 seconds, no finding (2026-11-22). An earlier run found that the order can change when a file has equal rules; the property now says "the same rules", and `an_update_with_equal_rules_keeps_the_first_copies` holds the case. |

## The limits

- **The editor of the user.** The lock holds against other pent processes,
  not against a text editor. An editor that saves during the write of pent
  can lose the change of pent, or pent can lose the edit. The window is the
  time of one write.
- **Duplicate rules.** A file can hold two equal rules. They give the same
  decision, and an update keeps one table for each copy that stays in the
  set: the first copies in the file. Thus the order of the rules can change,
  and the order has no effect on a decision.

## The properties that later steps add

| Step | Property |
|---|---|
| 5.4 | A sensitive access is answered only by an exact rule also in the FUSE server (RN-5 and RN-7 in [run.md](run.md) hold it for the static layers and the chain). |
| 5.4 | The program gets `ENOENT` for each path of the pent class (CL-1). |
| 2.5, 7.2 | `pent monitor` and the judge take the targets of an answer only from the width menu. |
| 2.2 | pentd is the only writer of the rules. A late answer becomes a rule for the next run. |

# The rules in `pent run`

Status: the branch `next`, step 3.1 of `PLAN.md` (2026-11-23). This report
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

## The state of step 3.1

`pent run` reads the rules of its key, and it no longer reads a profile or
the trust store. The hooks do not ask yet: the proxy asks from step 3.2,
DNS from step 3.3, the Unix sockets and the ports from step 3.4, and the
files from phase 5. Until then, the rules go into the static layers at the
start (Landlock, the list of the proxy, the list of the sockets and the
list of the ports), and an access that no rule and no flag gives gets a
refusal of the base. The chain of deciders and the questions exist, with
their tests, but no hook calls them yet.

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
| RN-3 | An allow rule goes into a static layer only when no deny rule wins over it at a point inside its width. The check takes each deny rule with the allow rule alone, so a third rule that wins at one point does not hide a hole below it. | `rule::tests::a_deny_inside_an_allow_takes_the_allow_out_of_the_whole_allows`, `a_deny_inside_a_domain_or_on_a_socket_makes_a_hole`, `decide::tests::the_grants_hold_back_what_a_static_layer_cannot_hold`, `fs_table::a_deny_rule_inside_an_allow_rule_wins` |
| RN-4 | An exact file rule on a path that is a directory does not go into Landlock, because Landlock gives the whole tree below a directory. | `the_grants_hold_back_what_a_static_layer_cannot_hold`, `fs_table::an_exact_rule_on_a_directory_gives_no_child` |
| RN-5 | A file rule on a path of the pent class does not go into Landlock. A subtree rule whose base is sensitive, or that covers a location of the guard list (a credential, a file that runs code later, a directory of pent), does not go into Landlock either. The check looks at the kind of the rule, as the class of one access does: a read rule may cover `~/bin`, where the guard stops only a write, and a write rule may not. Without the home directory, no subtree rule goes into Landlock. Each rule that pent holds back gives a warning that names it. | `the_grants_hold_back_what_a_static_layer_cannot_hold`, `fs_table::a_rule_on_the_whole_home_directory_is_not_applied`, `fs_table::the_rules_and_the_kernel_agree` (the rows of `~`), `a_flag_that_names_a_parent_does_not_bring_back_the_socket_of_pentd` |
| RN-6 | The chain asks in this order: the pent class (`ENOENT` for a file, a refusal for another access), the flags, the rules, the answers of this run, and last a question to pentd. The pent class includes the runtime directory of pentd. | `decide::tests::the_chain_asks_the_pent_class_then_the_flags_then_the_rules`, `classes::tests::each_name_of_a_file_of_pent_is_in_the_pent_class` (the runtime directory, also through a link) |
| RN-7 | Only an exact rule or an exact answer allows a sensitive access. A wider allow that contains it does not count, and the access asks. A deny of any width refuses it. | `decide::tests::only_an_exact_rule_allows_a_sensitive_access` |
| RN-8 | Without pentd, an access that needs a question gets a refusal of the base at once. | `decide::tests::without_pentd_an_open_access_is_a_refusal_of_the_base` |
| RN-9 | An answer applies at once for the rest of the run, also to another access inside its width, with no new question. A deadline does not: the next access asks again. | `decide::tests::an_answer_decides_and_covers_the_rest_of_its_width`, `a_deadline_names_its_question` |
| RN-10 | An event names its cause: the flag, the rule or the answer with the same decision, else the base. A rule that allows an access that a static layer refused does not show as the cause. An event of a deadline names the code of its question. | `decide::tests::a_static_event_names_its_cause`, `a_deadline_names_its_question`, `client::tests::a_deadline_names_the_number_of_its_question` |
| RN-11 | An event that cannot name a request gives no event: an IP address at the proxy, an abstract Unix socket. Thus an event never carries a target that a rule file refuses (PR-4). | `decide::tests::a_static_event_names_its_cause` |
| RN-12 | A real run sends its events to pentd, and they leave before `pent run` exits. `pent denials` shows each refusal with its cause. | `pent_denials_shows_the_refusals_of_a_real_run` |

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
- **A held-back rule.** Until the hooks ask, a rule that pent holds back
  has no effect: the access gets a refusal of the base.
- **The program of a network event.** The proxy does not know the process
  of a connection, so a network event names the key.

## The properties that later steps add

| Step | Property |
|---|---|
| 3.2, 3.3, 3.4 | Each hook asks through the chain of deciders, and a held-back rule applies through it. |
| 4.2 | The workspace is a flag, so a deny rule inside it applies. |
| 5.4 | The files of pent give `ENOENT` in each mode, also for a flag. |

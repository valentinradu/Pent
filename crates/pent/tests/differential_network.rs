//! D. The three layers of the network.
//!
//! A name has three verdicts: the answer of the DNS server, the decision
//! of the proxy, and the rule in the profile. The three must agree.
//!
//! The table [`differential::NET_CASES`] holds one row for each shape: a
//! name that the profile allows, a name that it does not allow, a name
//! below a wildcard, the domain of the wildcard itself, an address written
//! as a number, and a name that the profile allows but that resolves to a
//! loopback or to a private address.
//!
//! The rows run on Linux only. On macOS the system resolver answers each
//! query, so the DNS layer has no verdict there; `docs/security/macos.md`
//! holds that difference.
//!
//! Every row that asserts a refusal has a row that asserts a connection in
//! the same table, and each probe prints `PENT_CHILD_RAN` first.
//!
//! A test skips (it prints `SKIP` and passes) when the sandbox, a tool or
//! the internet is absent. Set `PENT_REQUIRE_ALL_TESTS=1` to make each
//! skip a failure.
//!
//! ```text
//! cargo test -p pent --test differential_network -- --include-ignored --nocapture
//! ```

mod common;

#[path = "common/differential.rs"]
mod differential;

#[cfg(target_os = "linux")]
mod net_table {
    use super::common::e2e::{
        have_tools, internet, sandbox_ready, stderr, stdout, BoxError, TestEnv, TestResult,
    };
    use super::differential::{net_closed, NetCase, Verdict, RAN};

    /// The probe. `$1` is the name to resolve and `$2` is the URL.
    ///
    /// `getent hosts` uses the resolver of the system, which the sandbox
    /// points at the DNS server of pent. `curl` uses the proxy, which pent
    /// names in `HTTPS_PROXY`.
    const PROBE: &str = r#"printf 'PENT_CHILD_RAN\n'
if getent hosts "$1" > /dev/null 2>&1; then printf 'DNS=yes\n'; else printf 'DNS=no\n'; fi
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$2" 2>&1)
printf 'CURL=%s\n' "$?"
printf 'CODE=%s\n' "$code"
"#;

    /// The profile text of a row.
    fn profile(case: &NetCase) -> String {
        let list: Vec<String> = case.domains.iter().map(|d| format!("{d:?}")).collect();
        format!("[network]\ndomains = [{}]\n", list.join(", "))
    }

    /// The HTTP code that the proxy answered, from either shape of the
    /// output of curl: the field `%{http_code}`, or the text that curl
    /// prints when the proxy refuses the tunnel.
    fn proxy_answer(text: &str) -> Option<u16> {
        let field = text
            .lines()
            .find_map(|l| l.strip_prefix("CODE="))
            .map(str::trim)
            .unwrap_or_default();
        if let Ok(code) = field.parse::<u16>() {
            if (100..600).contains(&code) {
                return Some(code);
            }
        }
        // "curl: (7) CONNECT tunnel failed, response 403"
        let rest = field.split("response ").nth(1)?;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits
            .parse::<u16>()
            .ok()
            .filter(|c| (100..600).contains(c))
    }

    /// The verdict of the two layers for one row.
    fn layers(case: &NetCase) -> Result<(Verdict, Option<Verdict>, String), BoxError> {
        let env = TestEnv::new()?;
        env.install_profile("p", &profile(case))?;
        let out = env.pent(&[
            "run",
            "--profile",
            "p",
            "--trace",
            "--",
            "sh",
            "-c",
            PROBE,
            "pent-probe",
            case.host,
            case.url,
        ])?;
        let text = format!("{}{}", stdout(&out), stderr(&out));
        assert!(
            text.contains(RAN),
            "{}: the child did not run, so the row proves nothing:\n{text}",
            case.id
        );
        let dns = if text.contains("DNS=yes") {
            Verdict::Allow
        } else {
            Verdict::Deny
        };
        // The proxy answers with an HTTP code, and that answer is its
        // decision. Curl shows the code in two shapes: the field
        // `%{http_code}` when the request went through the tunnel, and the
        // text "response <code>" when the proxy refused the tunnel itself
        // and curl stopped with the status 7. Read both.
        //
        // With no answer at all the request never reached the proxy, and
        // the row says nothing about the policy: the network of the
        // machine failed. An earlier version read each missing field as a
        // denial, so a network that hiccupped looked like a disagreement
        // of the three layers.
        let answer = proxy_answer(&text);
        let connect = match answer {
            Some(code) if (200..400).contains(&code) => Some(Verdict::Allow),
            Some(_) => Some(Verdict::Deny),
            None => None,
        };
        Ok((dns, connect, text))
    }

    /// Return true when the host can run every row.
    fn ready(test: &str) -> bool {
        have_tools(test, &["sh", "curl", "getent"]) && sandbox_ready(test) && internet(test)
    }

    /// The DNS answer, the decision of the proxy and the rule of the
    /// profile agree for each row of the table.
    #[test]
    fn the_three_layers_of_the_network_agree() -> TestResult {
        let test = "net_three_layers";
        if !ready(test) {
            return Ok(());
        }
        let mut wrong = Vec::new();
        let mut no_answer = Vec::new();
        for case in net_closed() {
            // The network of a machine can fail for a moment. A row whose
            // request never reached the proxy says nothing about the
            // policy, so the row runs again before the test gives up.
            let mut attempt = 0;
            let (dns, connect, text) = loop {
                let got = layers(case)?;
                attempt += 1;
                if got.1.is_some() || attempt == 3 {
                    break got;
                }
            };
            let Some(connect) = connect else {
                no_answer.push(format!(
                    "  {}: the request never reached the proxy in {attempt} tries, \
                     so the row says nothing about the policy\n{text}",
                    case.id
                ));
                continue;
            };
            if dns != case.dns {
                wrong.push(format!(
                    "  {}: the profile says the DNS layer must {}, it does {}\n{text}",
                    case.id,
                    case.dns.word(),
                    dns.word()
                ));
            }
            if connect != case.connect {
                wrong.push(format!(
                    "  {}: the profile says the proxy must {}, it does {}\n{text}",
                    case.id,
                    case.connect.word(),
                    connect.word()
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "{test}: the three layers disagree:\n{}",
            wrong.join("\n")
        );
        assert!(
            no_answer.is_empty(),
            "{test}: the network of this machine did not answer, so the test \
             proves nothing. This is not a disagreement of the layers:\n{}",
            no_answer.join("\n")
        );
        Ok(())
    }

    /// DIFF-8. The proxy must tell pent about every connection that it
    /// refuses.
    ///
    /// A domain that the allowlist does not hold reaches the trace log and
    /// the list of the denied accesses. Before the fix a destination that
    /// is not public reached neither, because a client sends an `http://`
    /// URL as a plain proxy request and the proxy answered 400 before any
    /// check of the destination.
    #[test]
    fn diff_8_a_refused_destination_is_not_recorded() -> TestResult {
        let test = "net_diff_8_silent_refusal";
        if !ready(test) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.install_profile(
            "p",
            "[network]\ndomains = [\"www.iana.org\", \"10-0-0-1.sslip.io\"]\n",
        )?;
        let out = env.pent(&[
            "run",
            "--profile",
            "p",
            "--trace",
            "--",
            "sh",
            "-c",
            "printf 'PENT_CHILD_RAN\\n'\n\
             curl -sS -o /dev/null --max-time 20 https://example.com/ 2>&1 | head -1\n\
             curl -sS -o /dev/null --max-time 20 http://10-0-0-1.sslip.io/ 2>&1 | head -1\n",
            "pent-probe",
        ])?;
        let text = format!("{}{}", stdout(&out), stderr(&out));
        assert!(text.contains(RAN), "the child did not run:\n{text}");
        let log = std::fs::read_to_string(env.denied_log("p")).unwrap_or_default();
        // The positive control: a domain outside the allowlist is in the
        // log, so an empty log means "not recorded", not "no recorder".
        assert!(
            log.contains("example.com"),
            "the positive control failed: pent did not record the refusal \
             of a domain outside the allowlist\n{text}\nlog: {log}"
        );
        assert!(
            log.contains("10-0-0-1.sslip.io"),
            "the proxy refused the connection to an allowed name that \
             resolves to a private address, and recorded nothing. The user \
             sees no denial and `pent trust p --review` shows nothing.\n\
             {text}\nlog: {log}"
        );
        Ok(())
    }

    /// Each disagreement of the table has an ignored test in this file.
    #[test]
    fn every_open_row_has_a_test() {
        let ids: Vec<&str> = super::differential::NET_CASES
            .iter()
            .filter_map(|c| c.open)
            .collect();
        assert!(
            ids.is_empty(),
            "a row of NET_CASES names a disagreement without an ignored \
             test in this file: {ids:?}"
        );
    }
}

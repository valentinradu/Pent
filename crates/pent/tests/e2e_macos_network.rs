//! The network containment of pent on macOS, end to end.
//!
//! macOS has no network namespace. The Seatbelt profile of proxy mode
//! denies each outbound connection and allows only the proxy port on
//! loopback, the system resolver socket and the Unix sockets in the
//! writable paths. Pent sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and
//! `NO_PROXY`, so a proxy-aware program sends its traffic through the
//! proxy.
//!
//! This part of the macOS backend never ran. Each test holds one claim of
//! the README. See `docs/security/macos.md`.
//!
//! A test skips (it prints `SKIP` and passes) when the sandbox, a tool or
//! the internet is absent. Set `PENT_REQUIRE_ALL_TESTS=1` to make each skip
//! a failure.
//!
//! ```text
//! cargo test -p pent --test e2e_macos_network -- --nocapture
//! ```

mod common;

#[cfg(target_os = "macos")]
mod macos {
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    use super::common::e2e::{
        have_tools, internet, rules, sandbox_ready, set, stderr, stdout, TestEnv, TestResult,
    };
    use super::common::macos::have_files;

    /// The shell of each test.
    const SH: &str = "/bin/sh";

    /// The profile of the network tests: one allowed domain.
    const NET_PROFILE: &str = "[network]\ndomains = [\"example.com\"]\n";

    /// Return true if the test can run.
    fn ready(test: &str) -> bool {
        have_files(test, &[SH]) && have_tools(test, &["curl"]) && sandbox_ready(test)
    }

    /// The arguments of a silent `curl` that prints only the HTTP status.
    fn curl(url: &str) -> Vec<String> {
        [
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "30",
            url,
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    /// Run `pent run --profile net -- <args>`.
    fn run(env: &TestEnv, args: &[String]) -> std::io::Result<std::process::Output> {
        let mut all = vec!["run", "--profile", "net", "--"];
        all.extend(args.iter().map(String::as_str));
        env.pent(&all)
    }

    /// With a profile that allows one domain, a request to that domain
    /// works and a request to another domain does not.
    #[test]
    fn an_allowed_domain_works_and_another_domain_fails() -> TestResult {
        if !ready("allowed_domain") || !internet("allowed_domain") {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.install_profile("net", NET_PROFILE)?;

        let out = run(&env, &curl("https://example.com"))?;
        let code = stdout(&out);
        assert!(
            code.len() == 3 && code != "000",
            "the allowed domain is not reachable (http code {code:?}). \
             On macOS the traffic must go through the proxy variables.\nstderr: {}",
            stderr(&out)
        );

        let out = run(&env, &curl("https://example.org"))?;
        assert!(
            !out.status.success(),
            "the proxy must refuse a domain that the profile does not allow"
        );
        assert_eq!(stdout(&out), "000", "stderr: {}", stderr(&out));
        Ok(())
    }

    /// A direct connection that does not use the proxy fails. The Seatbelt
    /// profile denies each outbound connection except the proxy port.
    #[test]
    fn a_direct_connection_without_the_proxy_fails() -> TestResult {
        if !ready("direct_connection") || !internet("direct_connection") {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.install_profile("net", NET_PROFILE)?;

        // The positive control: the same request through the proxy works.
        // Without it, a broken curl or a sandbox that does not start gives
        // the same result as the denial below.
        let out = run(&env, &curl("https://example.com"))?;
        let code = stdout(&out);
        assert!(
            code.len() == 3 && code != "000",
            "the request through the proxy must work, else this run proves \
             no denial (http code {code:?})\nstderr: {}",
            stderr(&out)
        );

        // `--noproxy '*'` makes curl ignore the proxy variables, so the
        // request goes straight to the address of the host.
        let mut args = curl("https://example.com");
        args.insert(1, "--noproxy".to_string());
        args.insert(2, "*".to_string());
        let out = run(&env, &args)?;
        assert!(
            !out.status.success(),
            "a direct connection to an allowed domain must fail: the \
             Seatbelt profile allows only the proxy port\nstdout: {}\nstderr: {}",
            stdout(&out),
            stderr(&out)
        );
        assert_eq!(
            stdout(&out),
            "000",
            "curl must report no answer for the direct connection\nstderr: {}",
            stderr(&out)
        );
        Ok(())
    }

    /// The proxy variables are in the environment of the child, and
    /// `NO_PROXY` names the loopback addresses.
    ///
    /// The second half keeps the other README claim honest: on macOS the
    /// child cannot reach the other loopback ports of the host. The
    /// connection stays direct (`NO_PROXY`), so the proxy never sees it and
    /// the denied log stays without it.
    #[test]
    fn the_proxy_variables_are_in_the_environment_of_the_child() -> TestResult {
        if !ready("proxy_variables") {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.install_profile("net", NET_PROFILE)?;

        let out = run(
            &env,
            &[
                SH.to_string(),
                "-c".to_string(),
                "echo \"HTTP_PROXY=$HTTP_PROXY\"; echo \"HTTPS_PROXY=$HTTPS_PROXY\"; \
                 echo \"ALL_PROXY=$ALL_PROXY\"; echo \"NO_PROXY=$NO_PROXY\""
                    .to_string(),
            ],
        )?;
        let text = stdout(&out);
        let value = |key: &str| -> String {
            text.lines()
                .find_map(|l| l.strip_prefix(&format!("{key}=")))
                .unwrap_or_default()
                .to_string()
        };
        let http = value("HTTP_PROXY");
        assert!(
            http.starts_with("http://127.0.0.1:"),
            "HTTP_PROXY is {http:?}\nstdout: {text}\nstderr: {}",
            stderr(&out)
        );
        assert_eq!(value("HTTPS_PROXY"), http, "stdout: {text}");
        assert!(
            value("ALL_PROXY").starts_with("socks5h://127.0.0.1:"),
            "ALL_PROXY is {:?}\nstdout: {text}",
            value("ALL_PROXY")
        );
        assert_eq!(
            value("NO_PROXY"),
            "localhost,127.0.0.1,::1",
            "stdout: {text}"
        );

        // A listener of the host on loopback. `NO_PROXY` keeps the request
        // direct, and the Seatbelt profile then denies it.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let server = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nHELLO");
            }
        });
        let out = run(&env, &curl(&format!("http://127.0.0.1:{port}/")))?;
        assert!(
            !out.status.success(),
            "the child reached a loopback service of the host; the README \
             says that it cannot\nstdout: {}\nstderr: {}",
            stdout(&out),
            stderr(&out)
        );
        // Unblock the thread when the child never connected.
        drop(std::net::TcpStream::connect(("127.0.0.1", port)));
        let _ = server.join();

        let denied = fs::read_to_string(env.denied_log("net")).unwrap_or_default();
        assert!(
            !denied.contains("127.0.0.1"),
            "the loopback request went to the proxy; NO_PROXY must keep it \
             direct:\n{denied}"
        );
        Ok(())
    }

    /// A denied domain goes into the denied log, and
    /// `pent trust NAME --review --yes` adds it to the profile.
    ///
    /// The proxy refuses the domain before any connection, so this test
    /// needs no internet.
    #[test]
    fn a_denied_domain_reaches_the_log_and_the_review() -> TestResult {
        if !ready("denied_domain_review") {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.install_profile("net", NET_PROFILE)?;

        let out = run(&env, &curl("https://denied.example"))?;
        assert!(!out.status.success(), "the domain must be denied");
        assert!(
            stderr(&out).contains("review it: pent trust net --review")
                || stderr(&out).contains("review them: pent trust net --review"),
            "pent must tell the user about the denial:\n{}",
            stderr(&out)
        );

        let denied = fs::read_to_string(env.denied_log("net"))?;
        assert!(
            denied.contains("denied.example"),
            "the denied log has no domain:\n{denied}"
        );

        let out = env.pent_ok(&["trust", "net", "--review", "--yes"])?;
        assert!(
            stderr(&out).contains("denied.example"),
            "the review must show the domain:\n{}",
            stderr(&out)
        );
        let profile = fs::read_to_string(env.profile_path("net"))?;
        assert_eq!(
            rules(&profile, "network", "domains")?,
            set(&["denied.example", "example.com"]),
            "the review must add the domain:\n{profile}"
        );
        assert!(
            !env.denied_log("net").exists(),
            "the review must consume the denied log"
        );
        Ok(())
    }
}

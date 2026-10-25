//! A compact subset of the public suffix list.
//!
//! The summary uses this module to find the registrable domain of a name
//! (`npmjs.org` for `registry.npmjs.org`). Pent never makes a wildcard on a
//! public suffix, because `*.co.uk` or `*.github.io` allows many unrelated
//! owners.
//!
//! This is NOT the full list from <https://publicsuffix.org>. It has the
//! common multi-label suffixes (country second-level domains and the large
//! hosting platforms). For a name that the subset does not know, the public
//! suffix is the last label (`com`, `org`, `dev`, ...). Thus an unknown
//! multi-label suffix can give a registrable domain that is too wide. The
//! review shows each wildcard to the user, so the user can reject it.

/// Multi-label public suffixes. Single-label suffixes (`com`, `uk`, ...) do
/// not need an entry: the last label is always a public suffix.
const MULTI_LABEL_SUFFIXES: &[&str] = &[
    // Country second-level domains.
    "ac.uk",
    "co.uk",
    "gov.uk",
    "ltd.uk",
    "me.uk",
    "net.uk",
    "nhs.uk",
    "org.uk",
    "plc.uk",
    "sch.uk",
    "com.au",
    "edu.au",
    "gov.au",
    "id.au",
    "net.au",
    "org.au",
    "co.nz",
    "net.nz",
    "org.nz",
    "govt.nz",
    "ac.jp",
    "co.jp",
    "go.jp",
    "ne.jp",
    "or.jp",
    "ac.kr",
    "co.kr",
    "or.kr",
    "com.br",
    "net.br",
    "org.br",
    "gov.br",
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "edu.cn",
    "com.hk",
    "org.hk",
    "com.tw",
    "org.tw",
    "com.sg",
    "edu.sg",
    "com.my",
    "co.id",
    "or.id",
    "co.in",
    "net.in",
    "org.in",
    "gov.in",
    "co.il",
    "org.il",
    "co.za",
    "org.za",
    "com.mx",
    "org.mx",
    "com.ar",
    "com.tr",
    "org.tr",
    "com.ua",
    "com.pl",
    "net.pl",
    "org.pl",
    "co.th",
    "in.th",
    "com.vn",
    "com.ph",
    "com.pk",
    "com.eg",
    "com.sa",
    "com.co",
    "co.ke",
    "com.ng",
    "com.pe",
    "com.ve",
    "com.uy",
    "com.es",
    "co.at",
    "or.at",
    "com.gr",
    "com.ru",
    "co.ve",
    // Hosting platforms (private suffixes).
    "github.io",
    "githubusercontent.com",
    "gitlab.io",
    "bitbucket.io",
    "herokuapp.com",
    "herokudns.com",
    "cloudfront.net",
    "amazonaws.com",
    "s3.amazonaws.com",
    "elasticbeanstalk.com",
    "awsapprunner.com",
    "azurewebsites.net",
    "azureedge.net",
    "azurestaticapps.net",
    "cloudapp.net",
    "trafficmanager.net",
    "blob.core.windows.net",
    "web.core.windows.net",
    "vercel.app",
    "now.sh",
    "netlify.app",
    "pages.dev",
    "workers.dev",
    "r2.dev",
    "appspot.com",
    "web.app",
    "firebaseapp.com",
    "cloudfunctions.net",
    "run.app",
    "blogspot.com",
    "fly.dev",
    "onrender.com",
    "railway.app",
    "deno.dev",
    "replit.app",
    "repl.co",
    "glitch.me",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "readthedocs.io",
    "surge.sh",
    "pythonanywhere.com",
    "digitaloceanspaces.com",
    "ondigitalocean.app",
];

/// Domains below which pent never makes a wildcard, at any depth. The
/// platform gives names at many levels to unrelated customers (for example
/// `bucket.s3.us-east-1.amazonaws.com`), and the subset cannot list them all.
const NO_WILDCARD_BELOW: &[&str] = &["amazonaws.com"];

/// Return the byte offsets where each suffix of `name` starts: 0, then the
/// offset after each dot.
fn suffix_starts(name: &str) -> impl Iterator<Item = usize> + '_ {
    std::iter::once(0).chain(name.match_indices('.').map(|(i, _)| i.saturating_add(1)))
}

/// Return the public suffix of `name`, for example `co.uk` for
/// `www.example.co.uk`, or `com` for `example.com`.
///
/// `name` must be a normalized domain name (lowercase ASCII, no trailing
/// dot).
#[must_use]
pub fn public_suffix(name: &str) -> &str {
    // The first match is the longest suffix, because the offsets grow.
    suffix_starts(name)
        .filter_map(|start| name.get(start..))
        .find(|suffix| MULTI_LABEL_SUFFIXES.contains(suffix))
        .unwrap_or_else(|| name.rsplit('.').next().unwrap_or(name))
}

/// Return true if `name` is a public suffix (for example `co.uk`, `com` or
/// `github.io`).
#[must_use]
pub fn is_public_suffix(name: &str) -> bool {
    public_suffix(name) == name
}

/// Return the registrable domain of `name`: the public suffix and one more
/// label (`example.co.uk` for `www.example.co.uk`). Return `None` when `name`
/// is a public suffix itself.
#[must_use]
pub fn registrable_domain(name: &str) -> Option<&str> {
    let suffix = public_suffix(name);
    if suffix.len() >= name.len() {
        return None;
    }
    // The byte before the suffix is the dot that separates it.
    let suffix_start = name.len().checked_sub(suffix.len())?;
    let before = name.get(..suffix_start.checked_sub(1)?)?;
    let start = before.rfind('.').map_or(0, |i| i.saturating_add(1));
    let registrable = name.get(start..)?;
    // An empty label (`.example.com`) is not a valid name.
    if registrable.starts_with('.') || registrable.is_empty() {
        return None;
    }
    Some(registrable)
}

/// Return true if the summary can make the wildcard `*.domain`.
#[must_use]
pub fn wildcard_allowed(domain: &str) -> bool {
    if domain.is_empty() || !domain.contains('.') || is_public_suffix(domain) {
        return false;
    }
    !NO_WILDCARD_BELOW.iter().any(|d| {
        domain == *d
            || domain
                .strip_suffix(d)
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domains() {
        assert_eq!(registrable_domain("registry.npmjs.org"), Some("npmjs.org"));
        assert_eq!(registrable_domain("npmjs.org"), Some("npmjs.org"));
        assert_eq!(
            registrable_domain("a.b.example.co.uk"),
            Some("example.co.uk")
        );
        assert_eq!(registrable_domain("user.github.io"), Some("user.github.io"));
        assert_eq!(
            registrable_domain("x.user.github.io"),
            Some("user.github.io")
        );
        assert_eq!(registrable_domain("co.uk"), None);
        assert_eq!(registrable_domain("github.io"), None);
        assert_eq!(registrable_domain("com"), None);
        assert_eq!(registrable_domain(""), None);
        assert_eq!(registrable_domain(".com"), None);
    }

    #[test]
    fn public_suffixes() {
        assert!(is_public_suffix("co.uk"));
        assert!(is_public_suffix("com"));
        assert!(is_public_suffix("s3.amazonaws.com"));
        assert!(!is_public_suffix("example.com"));
        assert_eq!(public_suffix("bucket.s3.amazonaws.com"), "s3.amazonaws.com");
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_allowed("npmjs.org"));
        assert!(!wildcard_allowed("co.uk"));
        assert!(!wildcard_allowed("github.io"));
        assert!(!wildcard_allowed("com"));
        assert!(!wildcard_allowed("bucket.s3.amazonaws.com"));
        assert!(!wildcard_allowed("x.amazonaws.com"));
        assert!(wildcard_allowed("notamazonaws.com"));
    }
}

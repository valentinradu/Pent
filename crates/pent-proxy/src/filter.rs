//! Domain allowlist filtering with wildcard support.
#![allow(unreachable_pub)]
//!
//! Matches domains against a configured allowlist. Supports:
//! - Exact matches: `api.anthropic.com`
//! - Wildcard subdomains: `*.github.com` (matches `api.github.com`, `raw.github.com`)
//! - Multiple wildcards: `*.*.example.com` (matches `a.b.example.com`)
//!
//! # Matching Rules
//!
//! | Pattern | Matches | Does Not Match |
//! |---------|---------|----------------|
//! | `example.com` | `example.com` | `sub.example.com`, `www.example.com` |
//! | `*.example.com` | `sub.example.com`, `www.example.com` | `example.com`, `a.b.example.com` |
//! | `**.example.com` | `a.b.example.com`, `x.y.z.example.com` | `example.com` |
//!

use std::collections::HashSet;

/// The maximum length of a domain name in its text form, without the trailing dot.
const MAX_NAME_LEN: usize = 253;

/// The maximum length of one label in a domain name.
const MAX_LABEL_LEN: usize = 63;

/// An error for a domain name or a domain pattern that is not valid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainNameError {
    /// The name is empty.
    #[error("the domain name is empty")]
    Empty,

    /// The name contains characters that are not ASCII.
    ///
    /// The proxy does not include an IDNA library. Write internationalized
    /// names in their punycode (`xn--`) form.
    #[error("the domain name {0:?} contains non-ASCII characters; use the punycode (xn--) form")]
    NonAscii(String),

    /// The name contains a character that is not permitted in a host name.
    #[error("the domain name {name:?} contains the character {ch:?}, which is not permitted")]
    InvalidCharacter {
        /// The name that has the problem.
        name: String,
        /// The character that is not permitted.
        ch: char,
    },

    /// The name contains an empty label (for example `a..b`).
    #[error("the domain name {0:?} contains an empty label")]
    EmptyLabel(String),

    /// A label in the name is longer than 63 bytes.
    #[error("the domain name {0:?} contains a label that is longer than 63 bytes")]
    LabelTooLong(String),

    /// The name is longer than 253 bytes.
    #[error("the domain name {0:?} is longer than 253 bytes")]
    TooLong(String),

    /// A wildcard is in a position that is not permitted.
    #[error("the pattern {0:?} has a wildcard in a position that is not permitted")]
    InvalidWildcard(String),
}

/// Lowercase the ASCII name and remove one trailing dot.
///
/// Returns an error if the name contains characters that are not ASCII.
fn fold_name(name: &str) -> Result<String, DomainNameError> {
    if !name.is_ascii() {
        return Err(DomainNameError::NonAscii(name.to_string()));
    }
    let lower = name.to_ascii_lowercase();
    let folded = lower.strip_suffix('.').unwrap_or(&lower);
    if folded.is_empty() {
        return Err(DomainNameError::Empty);
    }
    if folded.len() > MAX_NAME_LEN {
        return Err(DomainNameError::TooLong(folded.to_string()));
    }
    Ok(folded.to_string())
}

/// Validate one label of a host name that is already in lowercase.
fn check_label(name: &str, label: &str) -> Result<(), DomainNameError> {
    if label.is_empty() {
        return Err(DomainNameError::EmptyLabel(name.to_string()));
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(DomainNameError::LabelTooLong(name.to_string()));
    }
    if let Some(ch) = label
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '_'))
    {
        return Err(DomainNameError::InvalidCharacter {
            name: name.to_string(),
            ch,
        });
    }
    Ok(())
}

/// Normalize a host name for the allowlist check and for resolution.
///
/// The function lowercases ASCII letters and removes one trailing dot.
/// It rejects names that are not ASCII, empty labels, labels longer than
/// 63 bytes, names longer than 253 bytes, and characters other than letters,
/// digits, `-` and `_`.
///
/// The proxy checks and resolves the same normalized string. Thus the
/// allowlist decision always applies to the name that the proxy resolves.
///
/// # Errors
/// Returns a [`DomainNameError`] if the name is not a valid host name.
pub fn normalize_hostname(name: &str) -> Result<String, DomainNameError> {
    let folded = fold_name(name)?;
    for label in folded.split('.') {
        check_label(&folded, label)?;
    }
    Ok(folded)
}

/// Normalize an allowlist pattern.
///
/// The rules are the same as for [`normalize_hostname`], but the function also
/// removes the whitespace at the two ends. The first label can be `*` or `**`.
fn normalize_pattern(pattern: &str) -> Result<String, DomainNameError> {
    let folded = fold_name(pattern.trim())?;
    if folded == "*" {
        return Ok(folded);
    }
    for (index, label) in folded.split('.').enumerate() {
        if index == 0 && (label == "*" || label == "**") {
            continue;
        }
        if label.contains('*') {
            return Err(DomainNameError::InvalidWildcard(folded.clone()));
        }
        check_label(&folded, label)?;
    }
    Ok(folded)
}

/// Result of a domain match check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainMatch {
    /// Domain exactly matches an allowlist entry.
    Exact(String),

    /// Domain matches a wildcard pattern.
    Wildcard {
        /// The matched domain.
        domain: String,
        /// The pattern that matched.
        pattern: String,
    },

    /// Domain is not in the allowlist.
    Blocked,
}

impl DomainMatch {
    /// Returns `true` if the domain is allowed (exact or wildcard match).
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        !matches!(self, Self::Blocked)
    }

    /// Returns the matched domain if allowed.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        match self {
            Self::Exact(d) => Some(d),
            Self::Wildcard { domain, .. } => Some(domain),
            Self::Blocked => None,
        }
    }
}

/// Compiled domain pattern for efficient matching.
#[derive(Debug, Clone)]
pub struct DomainPattern {
    /// Normalized pattern string.
    pattern: String,

    /// Pattern type for matching.
    kind: PatternKind,
}

/// Type of domain pattern.
#[derive(Debug, Clone)]
enum PatternKind {
    /// Exact domain match.
    Exact,

    /// Single-level wildcard (`*.example.com`).
    SingleWildcard {
        /// The suffix after the wildcard (e.g., `.example.com`).
        suffix: String,
    },

    /// Multi-level wildcard (`**.example.com`).
    MultiWildcard {
        /// The suffix after the wildcard.
        suffix: String,
    },
}

impl DomainPattern {
    /// Parse a pattern string into a compiled pattern.
    ///
    /// # Arguments
    /// * `pattern` - Pattern string (e.g., `*.github.com`)
    ///
    /// # Errors
    /// Returns a [`DomainNameError`] if the pattern is not a valid domain
    /// pattern (for example, if it contains characters that are not ASCII).
    pub fn parse(pattern: &str) -> Result<Self, DomainNameError> {
        let normalized = normalize_pattern(pattern)?;

        let kind = if let Some(rest) = normalized.strip_prefix("**") {
            PatternKind::MultiWildcard {
                suffix: rest.to_string(), // includes the leading dot
            }
        } else if let Some(rest) = normalized.strip_prefix('*') {
            // `rest` is empty for the "*" pattern.
            PatternKind::SingleWildcard {
                suffix: rest.to_string(), // includes the leading dot
            }
        } else {
            PatternKind::Exact
        };

        Ok(Self {
            pattern: normalized,
            kind,
        })
    }

    /// Check if a domain matches this pattern.
    ///
    /// # Arguments
    /// * `domain` - Domain to check (e.g., `api.github.com`)
    ///
    /// # Returns
    /// `true` if the domain matches the pattern
    #[cfg(test)]
    pub fn matches(&self, domain: &str) -> bool {
        normalize_hostname(domain).is_ok_and(|normalized| self.matches_normalized(&normalized))
    }

    /// Check a domain that [`normalize_hostname`] has normalized.
    fn matches_normalized(&self, normalized: &str) -> bool {
        match &self.kind {
            PatternKind::Exact => normalized == self.pattern,
            PatternKind::SingleWildcard { suffix } => {
                if suffix.is_empty() {
                    // "*" matches any single-label domain
                    !normalized.contains('.')
                } else {
                    // *.example.com matches sub.example.com but not a.b.example.com
                    normalized
                        .strip_suffix(suffix.as_str())
                        .is_some_and(|rest| !rest.is_empty() && !rest.contains('.'))
                }
            }
            PatternKind::MultiWildcard { suffix } => {
                // **.example.com matches any subdomain depth
                normalized
                    .strip_suffix(suffix.as_str())
                    .is_some_and(|rest| !rest.is_empty())
            }
        }
    }

    /// Get the normalized pattern string.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Returns true if this is an exact match pattern.
    #[must_use]
    pub const fn is_exact(&self) -> bool {
        matches!(self.kind, PatternKind::Exact)
    }
}

/// Domain filter with compiled allowlist patterns.
///
/// Efficiently checks domains against a list of allowed patterns.
/// Thread-safe and can be shared across async tasks.
pub struct DomainFilter {
    /// Compiled patterns for matching.
    patterns: Vec<DomainPattern>,

    /// Set of normalized exact match domains for O(1) lookup.
    exact_matches: HashSet<String>,
}

impl DomainFilter {
    /// Create a new domain filter from an allowlist.
    ///
    /// The filter skips patterns that are not valid and logs a warning for
    /// each of them. Use [`DomainFilter::try_new`] to get an error instead.
    ///
    /// # Arguments
    /// * `allowlist` - List of allowed domain patterns
    ///
    /// # Example
    /// ```
    /// use pent_proxy::{DomainFilter, DomainMatch};
    ///
    /// let filter = DomainFilter::new(&[
    ///     "api.anthropic.com".to_string(),
    ///     "*.github.com".to_string(),
    /// ]);
    /// assert!(matches!(
    ///     filter.matches("api.anthropic.com"),
    ///     DomainMatch::Exact(_)
    /// ));
    /// assert!(matches!(
    ///     filter.matches("raw.github.com"),
    ///     DomainMatch::Wildcard { .. }
    /// ));
    /// assert!(matches!(filter.matches("example.com"), DomainMatch::Blocked));
    /// ```
    #[must_use]
    pub fn new(allowlist: &[String]) -> Self {
        let mut filter = Self::empty();
        for entry in allowlist {
            if let Err(e) = filter.push(entry.clone()) {
                tracing::warn!(pattern = %entry, error = %e, "skip the allowlist pattern that is not valid");
            }
        }
        filter
    }

    /// Create a new domain filter from an allowlist, and reject patterns that
    /// are not valid.
    ///
    /// # Errors
    /// Returns the first [`DomainNameError`] if a pattern is not valid.
    pub fn try_new(allowlist: &[String]) -> Result<Self, DomainNameError> {
        let mut filter = Self::empty();
        for entry in allowlist {
            filter.push(entry.clone())?;
        }
        Ok(filter)
    }

    /// Create a filter with no patterns.
    fn empty() -> Self {
        Self {
            patterns: Vec::new(),
            exact_matches: HashSet::new(),
        }
    }

    /// Check if a domain matches the allowlist.
    ///
    /// The filter normalizes the domain with the same rules as the patterns.
    /// A domain that is not a valid host name is blocked.
    ///
    /// # Arguments
    /// * `domain` - Domain to check
    ///
    /// # Returns
    /// * `DomainMatch::Exact` - Domain exactly matches an entry
    /// * `DomainMatch::Wildcard` - Domain matches a wildcard pattern
    /// * `DomainMatch::Blocked` - Domain is not allowed
    #[must_use]
    pub fn matches(&self, domain: &str) -> DomainMatch {
        let Ok(normalized) = normalize_hostname(domain) else {
            return DomainMatch::Blocked;
        };

        // Check exact matches first (O(1) lookup)
        if self.exact_matches.contains(&normalized) {
            return DomainMatch::Exact(normalized);
        }

        // Check wildcard patterns
        for pattern in &self.patterns {
            if !pattern.is_exact() && pattern.matches_normalized(&normalized) {
                return DomainMatch::Wildcard {
                    domain: normalized,
                    pattern: pattern.pattern().to_string(),
                };
            }
        }

        DomainMatch::Blocked
    }

    /// Returns `true` if the domain is allowed.
    ///
    /// Convenience method equivalent to `filter.matches(domain).is_allowed()`.
    #[must_use]
    pub fn is_allowed(&self, domain: &str) -> bool {
        self.matches(domain).is_allowed()
    }

    /// Get the number of patterns in the filter.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Get all patterns as strings.
    #[must_use]
    pub fn patterns(&self) -> Vec<&str> {
        self.patterns.iter().map(DomainPattern::pattern).collect()
    }

    /// Create a new filter with an additional domain.
    ///
    /// Returns a new `DomainFilter` with the domain added to the allowlist.
    /// The original filter is unchanged. If the domain is not a valid
    /// pattern, the new filter does not contain it.
    #[must_use]
    pub fn with_domain(&self, domain: String) -> Self {
        let mut domains: Vec<String> = self
            .patterns
            .iter()
            .map(|p| p.pattern().to_string())
            .collect();
        domains.push(domain);
        Self::new(&domains)
    }

    /// Add a domain pattern to this filter in-place.
    ///
    /// More efficient than [`with_domain`](Self::with_domain) for runtime additions
    /// because it avoids cloning all existing patterns. The `HashSet` and `Vec` are
    /// updated directly in O(1) amortized time.
    ///
    /// # Errors
    /// Returns a [`DomainNameError`] if the pattern is not valid. The filter
    /// does not change in this case.
    pub fn push(&mut self, domain: String) -> Result<(), DomainNameError> {
        let pattern = DomainPattern::parse(&domain)?;
        if pattern.is_exact() {
            // Index the normalized form, because `matches` looks up the
            // normalized form of the queried domain.
            self.exact_matches.insert(pattern.pattern().to_string());
        }
        self.patterns.push(pattern);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // DomainPattern Tests
    // ========================================================================

    #[test]
    fn test_pattern_parse_exact() -> Result<(), DomainNameError> {
        let pattern = DomainPattern::parse("example.com")?;
        assert!(pattern.is_exact());
        assert_eq!(pattern.pattern(), "example.com");
        Ok(())
    }

    /// An exact pattern matches its own name and no other name.
    #[test]
    fn an_exact_pattern_matches_only_its_own_name() -> Result<(), DomainNameError> {
        let pattern = DomainPattern::parse("example.com")?;
        assert!(pattern.matches("example.com"));
        assert!(!pattern.matches("other.com"));
        assert!(!pattern.matches("sub.example.com"));
        Ok(())
    }

    /// The limit is 253 bytes: a name of 253 bytes is valid, and a name of
    /// 254 bytes is not.
    #[test]
    fn the_name_length_limit_is_253_bytes() {
        let name_253 = make_name(MAX_NAME_LEN);
        assert_eq!(name_253.len(), MAX_NAME_LEN);
        assert_eq!(normalize_hostname(&name_253), Ok(name_253.clone()));
        let name_254 = make_name(MAX_NAME_LEN + 1);
        assert_eq!(
            normalize_hostname(&name_254),
            Err(DomainNameError::TooLong(name_254))
        );
    }

    /// A host name of exactly `len` bytes, with labels of 31 bytes.
    fn make_name(len: usize) -> String {
        let mut name = String::new();
        while name.len() < len {
            if !name.is_empty() {
                name.push('.');
            }
            let room = len.saturating_sub(name.len()).min(31);
            name.push_str(&"a".repeat(room));
        }
        name
    }

    #[test]
    fn test_pattern_parse_single_wildcard() -> Result<(), DomainNameError> {
        let pattern = DomainPattern::parse("*.example.com")?;
        assert!(!pattern.is_exact());
        assert!(pattern.matches("sub.example.com"));
        assert!(!pattern.matches("a.b.example.com"));
        Ok(())
    }

    #[test]
    fn test_pattern_parse_multi_wildcard() -> Result<(), DomainNameError> {
        let pattern = DomainPattern::parse("**.example.com")?;
        assert!(!pattern.is_exact());
        assert!(pattern.matches("a.b.example.com"));
        assert!(pattern.matches("sub.example.com"));
        Ok(())
    }

    #[test]
    fn test_pattern_parse_wildcard_only() -> Result<(), DomainNameError> {
        let pattern = DomainPattern::parse("*")?;
        assert!(!pattern.is_exact());
        assert!(pattern.matches("localhost"));
        assert!(!pattern.matches("sub.domain"));
        Ok(())
    }

    // ========================================================================
    // Exact Match Tests
    // ========================================================================

    #[test]
    fn test_exact_match_same() {
        let filter = DomainFilter::new(&["example.com".to_string()]);
        assert!(filter.is_allowed("example.com"));
    }

    #[test]
    fn test_exact_match_no_subdomain() {
        let filter = DomainFilter::new(&["example.com".to_string()]);
        assert!(!filter.is_allowed("sub.example.com"));
        assert!(!filter.is_allowed("www.example.com"));
    }

    #[test]
    fn test_exact_match_no_parent() {
        let filter = DomainFilter::new(&["sub.example.com".to_string()]);
        assert!(!filter.is_allowed("example.com"));
    }

    #[test]
    fn test_exact_match_different_tld() {
        let filter = DomainFilter::new(&["example.com".to_string()]);
        assert!(!filter.is_allowed("example.org"));
        assert!(!filter.is_allowed("example.net"));
    }

    // ========================================================================
    // Single Wildcard Tests (*.example.com)
    // ========================================================================

    #[test]
    fn test_single_wildcard_one_level() {
        let filter = DomainFilter::new(&["*.example.com".to_string()]);
        assert!(filter.is_allowed("sub.example.com"));
        assert!(filter.is_allowed("www.example.com"));
        assert!(filter.is_allowed("api.example.com"));
    }

    #[test]
    fn test_single_wildcard_not_base() {
        // *.example.com should NOT match example.com
        let filter = DomainFilter::new(&["*.example.com".to_string()]);
        assert!(!filter.is_allowed("example.com"));
    }

    #[test]
    fn test_single_wildcard_not_multi_level() {
        // *.example.com should NOT match a.b.example.com
        let filter = DomainFilter::new(&["*.example.com".to_string()]);
        assert!(!filter.is_allowed("a.b.example.com"));
        assert!(!filter.is_allowed("x.y.z.example.com"));
    }

    #[test]
    fn test_single_wildcard_different_suffix() {
        let filter = DomainFilter::new(&["*.example.com".to_string()]);
        assert!(!filter.is_allowed("sub.example.org"));
        assert!(!filter.is_allowed("sub.notexample.com"));
    }

    // ========================================================================
    // Multi Wildcard Tests (**.example.com)
    // ========================================================================

    #[test]
    fn test_multi_wildcard_two_levels() {
        let filter = DomainFilter::new(&["**.example.com".to_string()]);
        assert!(filter.is_allowed("a.b.example.com"));
    }

    #[test]
    fn test_multi_wildcard_many_levels() {
        let filter = DomainFilter::new(&["**.example.com".to_string()]);
        assert!(filter.is_allowed("a.b.c.d.e.example.com"));
    }

    #[test]
    fn test_multi_wildcard_one_level() {
        // ** should also match single level subdomain
        let filter = DomainFilter::new(&["**.example.com".to_string()]);
        assert!(filter.is_allowed("sub.example.com"));
    }

    #[test]
    fn test_multi_wildcard_not_base() {
        // **.example.com should NOT match example.com
        let filter = DomainFilter::new(&["**.example.com".to_string()]);
        assert!(!filter.is_allowed("example.com"));
    }

    // ========================================================================
    // Case Sensitivity Tests
    // ========================================================================

    #[test]
    fn test_case_insensitive_exact() {
        let filter = DomainFilter::new(&["Example.COM".to_string()]);
        assert!(filter.is_allowed("example.com"));
        assert!(filter.is_allowed("EXAMPLE.COM"));
        assert!(filter.is_allowed("ExAmPlE.cOm"));
    }

    #[test]
    fn test_case_insensitive_wildcard() {
        let filter = DomainFilter::new(&["*.GitHub.COM".to_string()]);
        assert!(filter.is_allowed("api.github.com"));
        assert!(filter.is_allowed("API.GITHUB.COM"));
    }

    // ========================================================================
    // Normalization Tests
    // ========================================================================

    #[test]
    fn test_trailing_dot_ignored() {
        // DNS names can have trailing dot (FQDN)
        let filter = DomainFilter::new(&["example.com".to_string()]);
        assert!(filter.is_allowed("example.com."));
    }

    #[test]
    fn test_whitespace_trimmed() {
        let filter = DomainFilter::new(&["  example.com  ".to_string()]);
        assert!(filter.is_allowed("example.com"));
    }

    #[test]
    fn test_empty_domain_not_allowed() {
        let filter = DomainFilter::new(&["example.com".to_string()]);
        assert!(!filter.is_allowed(""));
    }

    // ========================================================================
    // DomainMatch Type Tests
    // ========================================================================

    #[test]
    fn test_domain_match_exact_type() {
        let filter = DomainFilter::new(&["exact.com".to_string()]);
        let result = filter.matches("exact.com");
        assert!(matches!(result, DomainMatch::Exact(_)));
        assert_eq!(result.domain(), Some("exact.com"));
    }

    #[test]
    fn test_domain_match_wildcard_type() {
        let filter = DomainFilter::new(&["*.wild.com".to_string()]);
        let result = filter.matches("sub.wild.com");
        assert!(matches!(result, DomainMatch::Wildcard { .. }));
        assert_eq!(result.domain(), Some("sub.wild.com"));
    }

    #[test]
    fn test_domain_match_blocked_type() {
        let filter = DomainFilter::new(&["allowed.com".to_string()]);
        let result = filter.matches("blocked.com");
        assert!(matches!(result, DomainMatch::Blocked));
        assert_eq!(result.domain(), None);
        assert!(!result.is_allowed());
    }

    // ========================================================================
    // Multiple Patterns Tests
    // ========================================================================

    #[test]
    fn test_multiple_exact_patterns() {
        let filter = DomainFilter::new(&[
            "a.com".to_string(),
            "b.com".to_string(),
            "c.com".to_string(),
        ]);
        assert!(filter.is_allowed("a.com"));
        assert!(filter.is_allowed("b.com"));
        assert!(filter.is_allowed("c.com"));
        assert!(!filter.is_allowed("d.com"));
    }

    #[test]
    fn test_mixed_patterns() {
        let filter = DomainFilter::new(&[
            "exact.com".to_string(),
            "*.single.com".to_string(),
            "**.multi.com".to_string(),
        ]);
        assert!(filter.is_allowed("exact.com"));
        assert!(filter.is_allowed("sub.single.com"));
        assert!(filter.is_allowed("a.b.c.multi.com"));
        assert!(!filter.is_allowed("other.com"));
    }

    #[test]
    fn test_overlapping_patterns() {
        // Both exact and wildcard match - exact should take precedence
        let filter = DomainFilter::new(&["api.github.com".to_string(), "*.github.com".to_string()]);
        let result = filter.matches("api.github.com");
        // Should prefer exact match
        assert!(matches!(result, DomainMatch::Exact(_)));
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_empty_allowlist() {
        let filter = DomainFilter::new(&[]);
        assert!(!filter.is_allowed("any.com"));
        assert_eq!(filter.pattern_count(), 0);
    }

    #[test]
    fn test_single_label_domain() {
        // "localhost" is a valid domain
        let filter = DomainFilter::new(&["localhost".to_string()]);
        assert!(filter.is_allowed("localhost"));
    }

    #[test]
    fn test_very_long_domain() {
        // Max label is 63 chars, max domain is 253 chars
        let long_label = "a".repeat(63);
        let domain = format!("{long_label}.example.com");
        let filter = DomainFilter::new(&["*.example.com".to_string()]);
        assert!(filter.is_allowed(&domain));
    }

    #[test]
    fn test_numeric_subdomain() {
        let filter = DomainFilter::new(&["*.example.com".to_string()]);
        assert!(filter.is_allowed("123.example.com"));
        assert!(filter.is_allowed("192-168-1-1.example.com"));
    }

    #[test]
    fn test_hyphen_in_domain() {
        let filter = DomainFilter::new(&["my-domain.example.com".to_string()]);
        assert!(filter.is_allowed("my-domain.example.com"));
    }

    #[test]
    fn test_punycode_domain() {
        // Internationalized domains use punycode (xn--...)
        let filter = DomainFilter::new(&["*.example.com".to_string()]);
        assert!(filter.is_allowed("xn--nxasmq5b.example.com"));
    }

    // ========================================================================
    // Real-world Patterns
    // ========================================================================

    #[test]
    fn test_github_patterns() {
        let filter = DomainFilter::new(&[
            "github.com".to_string(),
            "*.github.com".to_string(),
            "*.githubusercontent.com".to_string(),
        ]);
        assert!(filter.is_allowed("github.com"));
        assert!(filter.is_allowed("api.github.com"));
        assert!(filter.is_allowed("raw.githubusercontent.com"));
        assert!(filter.is_allowed("avatars.githubusercontent.com"));
    }

    #[test]
    fn test_api_patterns() {
        let filter = DomainFilter::new(&[
            "api.anthropic.com".to_string(),
            "api.openai.com".to_string(),
        ]);
        assert!(filter.is_allowed("api.anthropic.com"));
        assert!(filter.is_allowed("api.openai.com"));
        assert!(!filter.is_allowed("anthropic.com"));
        assert!(!filter.is_allowed("openai.com"));
    }

    // ========================================================================
    // Normalization and Validation Tests
    // ========================================================================

    #[test]
    fn test_push_normalizes_exact_pattern() -> Result<(), DomainNameError> {
        let mut filter = DomainFilter::new(&[]);
        filter.push("Example.COM.".to_string())?;
        assert!(filter.is_allowed("example.com"));
        assert!(filter.is_allowed("EXAMPLE.com."));
        assert!(matches!(
            filter.matches("example.com"),
            DomainMatch::Exact(_)
        ));
        Ok(())
    }

    #[test]
    fn test_push_rejects_non_ascii_pattern() {
        let mut filter = DomainFilter::new(&[]);
        let result = filter.push("b\u{fc}cher.example".to_string());
        assert!(matches!(result, Err(DomainNameError::NonAscii(_))));
        assert_eq!(filter.pattern_count(), 0);
    }

    #[test]
    fn test_push_rejects_bad_wildcard() {
        let mut filter = DomainFilter::new(&[]);
        assert!(matches!(
            filter.push("api.*.example.com".to_string()),
            Err(DomainNameError::InvalidWildcard(_))
        ));
    }

    #[test]
    fn test_try_new_rejects_invalid_pattern() {
        let result = DomainFilter::try_new(&["ok.com".to_string(), "bad domain.com".to_string()]);
        assert!(matches!(
            result,
            Err(DomainNameError::InvalidCharacter { ch: ' ', .. })
        ));
    }

    #[test]
    fn test_new_skips_invalid_pattern() {
        let filter = DomainFilter::new(&["ok.com".to_string(), "\u{e9}.com".to_string()]);
        assert_eq!(filter.pattern_count(), 1);
        assert!(filter.is_allowed("ok.com"));
    }

    #[test]
    fn test_lookup_rejects_unicode_case_folding() {
        // The Kelvin sign (U+212A) lowercases to "k" with Unicode rules.
        // The filter must not treat it as "k".
        let filter = DomainFilter::new(&["kelvin.com".to_string()]);
        assert!(!filter.is_allowed("\u{212a}elvin.com"));
    }

    #[test]
    fn test_normalize_hostname_rules() {
        assert_eq!(
            normalize_hostname("API.GitHub.com."),
            Ok("api.github.com".to_string())
        );
        assert_eq!(
            normalize_hostname("_dmarc.example.com"),
            Ok("_dmarc.example.com".to_string())
        );
        assert_eq!(normalize_hostname(""), Err(DomainNameError::Empty));
        assert_eq!(normalize_hostname("."), Err(DomainNameError::Empty));
        assert!(matches!(
            normalize_hostname("a..b"),
            Err(DomainNameError::EmptyLabel(_))
        ));
        assert!(matches!(
            normalize_hostname(&"a".repeat(64)),
            Err(DomainNameError::LabelTooLong(_))
        ));
        assert!(matches!(
            normalize_hostname(&["a"; 130].join(".")),
            Err(DomainNameError::TooLong(_))
        ));
        assert!(matches!(
            normalize_hostname("evil.com\0.ok.com"),
            Err(DomainNameError::InvalidCharacter { .. })
        ));
        assert!(matches!(
            normalize_hostname("*.example.com"),
            Err(DomainNameError::InvalidCharacter { ch: '*', .. })
        ));
    }
}

/// Property tests of the host normalization and of the domain filter.
///
/// The name comes from the hostile program, and the pattern comes from the
/// profile. The same properties run as a `cargo fuzz` target in
/// `crates/pent-proxy/fuzz`; this module repeats them with a fixed seed, so
/// that the stable toolchain also checks them. See
/// `docs/testing/fuzzing-and-coverage.md`.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)] // the generator uses only literals
mod filter_properties {
    use super::*;
    use crate::test_support::{rounds, Rng};

    /// The number of names that each property test reads by default.
    const ROUNDS: usize = 200_000;

    /// The characters that the generator puts in a name.
    const ALPHABET: &[u8] = b"ab.-_*0\x00 \x7fA\xc3\xa9";

    /// Build a name or a pattern.
    fn gen_name(rng: &mut Rng) -> String {
        let len = rng.below(20);
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                let at = rng.below(ALPHABET.len());
                *ALPHABET.get(at).unwrap_or(&b'a')
            })
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// A normalized name follows the rules of the documentation, and the
    /// normalization is idempotent. The proxy normalizes a name more than
    /// one time (the request, then the server name of the TLS session), and
    /// the second run must not change the decision.
    #[test]
    fn a_normalized_name_follows_the_rules() {
        let mut rng = Rng::new(0x5EED_0501);
        let total = rounds(ROUNDS);
        let mut checked = 0usize;
        for _ in 0..total {
            let text = gen_name(&mut rng);
            let Ok(name) = normalize_hostname(&text) else {
                continue;
            };
            checked = checked.saturating_add(1);
            assert!(name.is_ascii(), "the name {name:?} is not ASCII");
            assert!(!name.is_empty(), "the name is empty");
            assert!(name.len() <= MAX_NAME_LEN, "the name {name:?} is too long");
            assert_eq!(name, name.to_ascii_lowercase(), "the name is not lowercase");
            for label in name.split('.') {
                assert!(!label.is_empty(), "the name {name:?} has an empty label");
                assert!(label.len() <= MAX_LABEL_LEN, "a label is too long");
            }
            assert_eq!(
                normalize_hostname(&name).ok().as_deref(),
                Some(name.as_str()),
                "the normalization is not idempotent for {name:?}"
            );
        }
        assert!(
            checked > total / 100,
            "only {checked} of {total} inputs were a name; the test proves little"
        );
    }

    /// Build a pattern and a name that are often related, so that the
    /// filter really matches them. A pair of two names that have nothing in
    /// common proves nothing about the wildcard rules.
    fn gen_pair(rng: &mut Rng) -> (String, String) {
        const LABELS: [&str; 5] = ["a", "b", "example", "com", "x-y"];
        let label = |rng: &mut Rng| LABELS.get(rng.below(LABELS.len())).copied().unwrap_or("a");
        let depth = 1usize.saturating_add(rng.below(3));
        let base: Vec<&str> = (0..depth).map(|_| label(rng)).collect();
        let base = base.join(".");
        let pattern = match rng.below(4) {
            0 => format!("*.{base}"),
            1 => format!("**.{base}"),
            2 => base.clone(),
            _ => {
                // A pattern that is not valid, or a catch-all.
                let odd = ["*", "**", "*.*", "a..b", &base];
                odd.get(rng.below(odd.len()))
                    .copied()
                    .unwrap_or("*")
                    .to_string()
            }
        };
        let extra = rng.below(3);
        let mut name = String::new();
        for _ in 0..extra {
            name.push_str(label(rng));
            name.push('.');
        }
        name.push_str(&base);
        if rng.one_in(6) {
            name.push_str(".other");
        }
        if rng.one_in(8) {
            name = name.to_ascii_uppercase();
        }
        if rng.one_in(8) {
            name = gen_name(rng);
        }
        (pattern, name)
    }

    /// A wildcard pattern matches only a name below its suffix.
    #[test]
    fn a_wildcard_matches_only_below_its_suffix() {
        let mut rng = Rng::new(0x5EED_0502);
        let total = rounds(ROUNDS);
        let mut matched = 0usize;
        for _ in 0..total {
            let (pattern_text, name) = gen_pair(&mut rng);
            let Ok(pattern) = DomainPattern::parse(&pattern_text) else {
                continue;
            };
            let Ok(normalized) = normalize_hostname(&name) else {
                continue;
            };
            if !pattern.matches_normalized(&normalized) {
                continue;
            }
            matched = matched.saturating_add(1);
            let text = pattern.pattern();
            if pattern.is_exact() {
                assert_eq!(normalized, text, "an exact pattern matched another name");
                continue;
            }
            let suffix = text.trim_start_matches('*');
            if suffix.is_empty() {
                // "*" matches a name of one label; "**" matches every name.
                if !text.starts_with("**") {
                    assert!(
                        !normalized.contains('.'),
                        "the pattern \"*\" matched {normalized:?}"
                    );
                }
                continue;
            }
            let head = normalized.strip_suffix(suffix).unwrap_or_else(|| {
                panic!("{text:?} matched {normalized:?}, which is not below it")
            });
            assert!(!head.is_empty(), "the wildcard matched the bare domain");
            if !text.starts_with("**") {
                assert!(
                    !head.contains('.'),
                    "the single wildcard {text:?} matched more than one label"
                );
            }
        }
        assert!(
            matched > total / 1000,
            "only {matched} of {total} pairs matched; the test proves little"
        );
    }

    /// The catch-all patterns. The table of the module documentation does
    /// not name them, so this test writes the behaviour down: `*` allows
    /// every name of one label, and `**` allows every name.
    #[test]
    fn the_catch_all_patterns_allow_everything_below_them() {
        let star = DomainFilter::new(&["*".to_string()]);
        assert!(star.is_allowed("localhost"), "\"*\" must allow one label");
        assert!(
            !star.is_allowed("example.com"),
            "\"*\" must not allow two labels"
        );
        let double = DomainFilter::new(&["**".to_string()]);
        assert!(
            double.is_allowed("evil.example.com"),
            "\"**\" allows every name"
        );
        assert!(double.is_allowed("localhost"), "\"**\" allows every name");
        assert!(
            !double.is_allowed("not a name"),
            "a name that is not valid stays blocked"
        );
    }

    /// FUZZ-3. The documentation of this module names the form
    /// `*.*.example.com`, and says that it matches `a.b.example.com`. The
    /// code accepts a wildcard only in the first label, so it rejects the
    /// form. `DomainFilter::new` then drops the pattern and logs a
    /// warning, and the name stays blocked. The behaviour is fail-closed;
    /// the documentation is wrong.
    #[test]
    fn a_pattern_with_two_wildcards_is_rejected() {
        assert!(
            matches!(
                DomainPattern::parse("*.*.example.com"),
                Err(DomainNameError::InvalidWildcard(_))
            ),
            "the parser now accepts two wildcards; update FUZZ-3"
        );
        let filter = DomainFilter::new(&["*.*.example.com".to_string()]);
        assert_eq!(
            filter.pattern_count(),
            0,
            "the filter kept a pattern that it cannot parse"
        );
        assert!(
            !filter.is_allowed("a.b.example.com"),
            "the dropped pattern must allow no name"
        );
    }
}

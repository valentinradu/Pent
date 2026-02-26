//! Domain allowlist filtering with wildcard support.
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
    pub fn is_allowed(&self) -> bool {
        !matches!(self, DomainMatch::Blocked)
    }

    /// Returns the matched domain if allowed.
    pub fn domain(&self) -> Option<&str> {
        match self {
            DomainMatch::Exact(d) => Some(d),
            DomainMatch::Wildcard { domain, .. } => Some(domain),
            DomainMatch::Blocked => None,
        }
    }
}

/// Compiled domain pattern for efficient matching.
#[derive(Debug, Clone)]
pub struct DomainPattern {
    /// Original pattern string.
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
    /// # Returns
    /// Compiled pattern for matching
    pub fn parse(pattern: &str) -> Self {
        let normalized = normalize_domain(pattern);

        let kind = if normalized.starts_with("**.") {
            PatternKind::MultiWildcard {
                suffix: normalized[2..].to_string(), // includes the leading dot
            }
        } else if normalized.starts_with("*.") {
            PatternKind::SingleWildcard {
                suffix: normalized[1..].to_string(), // includes the leading dot
            }
        } else if normalized == "*" {
            PatternKind::SingleWildcard {
                suffix: String::new(),
            }
        } else {
            PatternKind::Exact
        };

        Self {
            pattern: normalized,
            kind,
        }
    }

    /// Check if a domain matches this pattern.
    ///
    /// # Arguments
    /// * `domain` - Domain to check (e.g., `api.github.com`)
    ///
    /// # Returns
    /// `true` if the domain matches the pattern
    pub fn matches(&self, domain: &str) -> bool {
        let normalized = normalize_domain(domain);
        if normalized.is_empty() {
            return false;
        }

        match &self.kind {
            PatternKind::Exact => normalized == self.pattern,
            PatternKind::SingleWildcard { suffix } => {
                if suffix.is_empty() {
                    // "*" matches any single-label domain
                    !normalized.contains('.')
                } else {
                    // *.example.com matches sub.example.com but not a.b.example.com
                    if let Some(rest) = normalized.strip_suffix(suffix) {
                        !rest.is_empty() && !rest.contains('.')
                    } else {
                        false
                    }
                }
            }
            PatternKind::MultiWildcard { suffix } => {
                // **.example.com matches any subdomain depth
                if let Some(rest) = normalized.strip_suffix(suffix) {
                    !rest.is_empty()
                } else {
                    false
                }
            }
        }
    }

    /// Get the original pattern string.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Returns true if this is an exact match pattern.
    pub fn is_exact(&self) -> bool {
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

    /// Set of exact match domains for O(1) lookup.
    exact_matches: HashSet<String>,
}

impl DomainFilter {
    /// Create a new domain filter from an allowlist.
    ///
    /// # Arguments
    /// * `allowlist` - List of allowed domain patterns
    ///
    /// # Example
    /// ```ignore
    /// let filter = DomainFilter::new(vec![
    ///     "api.anthropic.com".to_string(),
    ///     "*.github.com".to_string(),
    /// ]);
    /// ```
    pub fn new(allowlist: Vec<String>) -> Self {
        let patterns: Vec<DomainPattern> =
            allowlist.iter().map(|s| DomainPattern::parse(s)).collect();

        let exact_matches: HashSet<String> = patterns
            .iter()
            .filter(|p| p.is_exact())
            .map(|p| p.pattern().to_string())
            .collect();

        Self {
            patterns,
            exact_matches,
        }
    }

    /// Check if a domain matches the allowlist.
    ///
    /// # Arguments
    /// * `domain` - Domain to check
    ///
    /// # Returns
    /// * `DomainMatch::Exact` - Domain exactly matches an entry
    /// * `DomainMatch::Wildcard` - Domain matches a wildcard pattern
    /// * `DomainMatch::Blocked` - Domain is not allowed
    pub fn matches(&self, domain: &str) -> DomainMatch {
        let normalized = normalize_domain(domain);
        if normalized.is_empty() {
            return DomainMatch::Blocked;
        }

        // Check exact matches first (O(1) lookup)
        if self.exact_matches.contains(&normalized) {
            return DomainMatch::Exact(normalized);
        }

        // Check wildcard patterns
        for pattern in &self.patterns {
            if !pattern.is_exact() && pattern.matches(&normalized) {
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
    pub fn is_allowed(&self, domain: &str) -> bool {
        self.matches(domain).is_allowed()
    }

    /// Get the number of patterns in the filter.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Get all patterns as strings.
    pub fn patterns(&self) -> Vec<&str> {
        self.patterns.iter().map(|p| p.pattern()).collect()
    }

    /// Create a new filter with an additional domain.
    ///
    /// Returns a new DomainFilter with the domain added to the allowlist.
    /// The original filter is unchanged.
    pub fn with_domain(&self, domain: String) -> Self {
        let mut domains: Vec<String> = self
            .patterns
            .iter()
            .map(|p| p.pattern().to_string())
            .collect();
        domains.push(domain);
        Self::new(domains)
    }

    /// Add a domain pattern to this filter in-place.
    ///
    /// More efficient than [`with_domain`](Self::with_domain) for runtime additions
    /// because it avoids cloning all existing patterns. The HashSet and Vec are
    /// updated directly in O(1) amortized time.
    pub fn push(&mut self, domain: String) {
        let pattern = DomainPattern::parse(&domain);
        if pattern.is_exact() {
            // Index in exact_matches for O(1) lookup; the pattern also goes
            // into self.patterns so patterns() and with_domain() see it.
            self.exact_matches.insert(domain);
        }
        self.patterns.push(pattern);
    }
}

/// Normalize a domain for matching.
///
/// - Converts to lowercase
/// - Removes trailing dot if present
/// - Trims whitespace
fn normalize_domain(domain: &str) -> String {
    let trimmed = domain.trim().to_lowercase();
    trimmed.strip_suffix('.').unwrap_or(&trimmed).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // DomainPattern Tests
    // ========================================================================

    #[test]
    fn test_pattern_parse_exact() {
        let pattern = DomainPattern::parse("example.com");
        assert!(pattern.is_exact());
        assert_eq!(pattern.pattern(), "example.com");
    }

    #[test]
    fn test_pattern_parse_single_wildcard() {
        let pattern = DomainPattern::parse("*.example.com");
        assert!(!pattern.is_exact());
        assert!(pattern.matches("sub.example.com"));
        assert!(!pattern.matches("a.b.example.com"));
    }

    #[test]
    fn test_pattern_parse_multi_wildcard() {
        let pattern = DomainPattern::parse("**.example.com");
        assert!(!pattern.is_exact());
        assert!(pattern.matches("a.b.example.com"));
        assert!(pattern.matches("sub.example.com"));
    }

    #[test]
    fn test_pattern_parse_wildcard_only() {
        let pattern = DomainPattern::parse("*");
        assert!(!pattern.is_exact());
        assert!(pattern.matches("localhost"));
        assert!(!pattern.matches("sub.domain"));
    }

    // ========================================================================
    // Exact Match Tests
    // ========================================================================

    #[test]
    fn test_exact_match_same() {
        let filter = DomainFilter::new(vec!["example.com".to_string()]);
        assert!(filter.is_allowed("example.com"));
    }

    #[test]
    fn test_exact_match_no_subdomain() {
        let filter = DomainFilter::new(vec!["example.com".to_string()]);
        assert!(!filter.is_allowed("sub.example.com"));
        assert!(!filter.is_allowed("www.example.com"));
    }

    #[test]
    fn test_exact_match_no_parent() {
        let filter = DomainFilter::new(vec!["sub.example.com".to_string()]);
        assert!(!filter.is_allowed("example.com"));
    }

    #[test]
    fn test_exact_match_different_tld() {
        let filter = DomainFilter::new(vec!["example.com".to_string()]);
        assert!(!filter.is_allowed("example.org"));
        assert!(!filter.is_allowed("example.net"));
    }

    // ========================================================================
    // Single Wildcard Tests (*.example.com)
    // ========================================================================

    #[test]
    fn test_single_wildcard_one_level() {
        let filter = DomainFilter::new(vec!["*.example.com".to_string()]);
        assert!(filter.is_allowed("sub.example.com"));
        assert!(filter.is_allowed("www.example.com"));
        assert!(filter.is_allowed("api.example.com"));
    }

    #[test]
    fn test_single_wildcard_not_base() {
        // *.example.com should NOT match example.com
        let filter = DomainFilter::new(vec!["*.example.com".to_string()]);
        assert!(!filter.is_allowed("example.com"));
    }

    #[test]
    fn test_single_wildcard_not_multi_level() {
        // *.example.com should NOT match a.b.example.com
        let filter = DomainFilter::new(vec!["*.example.com".to_string()]);
        assert!(!filter.is_allowed("a.b.example.com"));
        assert!(!filter.is_allowed("x.y.z.example.com"));
    }

    #[test]
    fn test_single_wildcard_different_suffix() {
        let filter = DomainFilter::new(vec!["*.example.com".to_string()]);
        assert!(!filter.is_allowed("sub.example.org"));
        assert!(!filter.is_allowed("sub.notexample.com"));
    }

    // ========================================================================
    // Multi Wildcard Tests (**.example.com)
    // ========================================================================

    #[test]
    fn test_multi_wildcard_two_levels() {
        let filter = DomainFilter::new(vec!["**.example.com".to_string()]);
        assert!(filter.is_allowed("a.b.example.com"));
    }

    #[test]
    fn test_multi_wildcard_many_levels() {
        let filter = DomainFilter::new(vec!["**.example.com".to_string()]);
        assert!(filter.is_allowed("a.b.c.d.e.example.com"));
    }

    #[test]
    fn test_multi_wildcard_one_level() {
        // ** should also match single level subdomain
        let filter = DomainFilter::new(vec!["**.example.com".to_string()]);
        assert!(filter.is_allowed("sub.example.com"));
    }

    #[test]
    fn test_multi_wildcard_not_base() {
        // **.example.com should NOT match example.com
        let filter = DomainFilter::new(vec!["**.example.com".to_string()]);
        assert!(!filter.is_allowed("example.com"));
    }

    // ========================================================================
    // Case Sensitivity Tests
    // ========================================================================

    #[test]
    fn test_case_insensitive_exact() {
        let filter = DomainFilter::new(vec!["Example.COM".to_string()]);
        assert!(filter.is_allowed("example.com"));
        assert!(filter.is_allowed("EXAMPLE.COM"));
        assert!(filter.is_allowed("ExAmPlE.cOm"));
    }

    #[test]
    fn test_case_insensitive_wildcard() {
        let filter = DomainFilter::new(vec!["*.GitHub.COM".to_string()]);
        assert!(filter.is_allowed("api.github.com"));
        assert!(filter.is_allowed("API.GITHUB.COM"));
    }

    // ========================================================================
    // Normalization Tests
    // ========================================================================

    #[test]
    fn test_trailing_dot_ignored() {
        // DNS names can have trailing dot (FQDN)
        let filter = DomainFilter::new(vec!["example.com".to_string()]);
        assert!(filter.is_allowed("example.com."));
    }

    #[test]
    fn test_whitespace_trimmed() {
        let filter = DomainFilter::new(vec!["  example.com  ".to_string()]);
        assert!(filter.is_allowed("example.com"));
    }

    #[test]
    fn test_empty_domain_not_allowed() {
        let filter = DomainFilter::new(vec!["example.com".to_string()]);
        assert!(!filter.is_allowed(""));
    }

    // ========================================================================
    // DomainMatch Type Tests
    // ========================================================================

    #[test]
    fn test_domain_match_exact_type() {
        let filter = DomainFilter::new(vec!["exact.com".to_string()]);
        let result = filter.matches("exact.com");
        assert!(matches!(result, DomainMatch::Exact(_)));
        assert_eq!(result.domain(), Some("exact.com"));
    }

    #[test]
    fn test_domain_match_wildcard_type() {
        let filter = DomainFilter::new(vec!["*.wild.com".to_string()]);
        let result = filter.matches("sub.wild.com");
        assert!(matches!(result, DomainMatch::Wildcard { .. }));
        assert_eq!(result.domain(), Some("sub.wild.com"));
    }

    #[test]
    fn test_domain_match_blocked_type() {
        let filter = DomainFilter::new(vec!["allowed.com".to_string()]);
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
        let filter = DomainFilter::new(vec![
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
        let filter = DomainFilter::new(vec![
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
        let filter = DomainFilter::new(vec![
            "api.github.com".to_string(),
            "*.github.com".to_string(),
        ]);
        let result = filter.matches("api.github.com");
        // Should prefer exact match
        assert!(matches!(result, DomainMatch::Exact(_)));
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_empty_allowlist() {
        let filter = DomainFilter::new(vec![]);
        assert!(!filter.is_allowed("any.com"));
        assert_eq!(filter.pattern_count(), 0);
    }

    #[test]
    fn test_single_label_domain() {
        // "localhost" is a valid domain
        let filter = DomainFilter::new(vec!["localhost".to_string()]);
        assert!(filter.is_allowed("localhost"));
    }

    #[test]
    fn test_very_long_domain() {
        // Max label is 63 chars, max domain is 253 chars
        let long_label = "a".repeat(63);
        let domain = format!("{}.example.com", long_label);
        let filter = DomainFilter::new(vec!["*.example.com".to_string()]);
        assert!(filter.is_allowed(&domain));
    }

    #[test]
    fn test_numeric_subdomain() {
        let filter = DomainFilter::new(vec!["*.example.com".to_string()]);
        assert!(filter.is_allowed("123.example.com"));
        assert!(filter.is_allowed("192-168-1-1.example.com"));
    }

    #[test]
    fn test_hyphen_in_domain() {
        let filter = DomainFilter::new(vec!["my-domain.example.com".to_string()]);
        assert!(filter.is_allowed("my-domain.example.com"));
    }

    #[test]
    fn test_punycode_domain() {
        // Internationalized domains use punycode (xn--...)
        let filter = DomainFilter::new(vec!["*.example.com".to_string()]);
        assert!(filter.is_allowed("xn--nxasmq5b.example.com"));
    }

    // ========================================================================
    // Real-world Patterns
    // ========================================================================

    #[test]
    fn test_github_patterns() {
        let filter = DomainFilter::new(vec![
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
        let filter = DomainFilter::new(vec![
            "api.anthropic.com".to_string(),
            "api.openai.com".to_string(),
        ]);
        assert!(filter.is_allowed("api.anthropic.com"));
        assert!(filter.is_allowed("api.openai.com"));
        assert!(!filter.is_allowed("anthropic.com"));
        assert!(!filter.is_allowed("openai.com"));
    }
}

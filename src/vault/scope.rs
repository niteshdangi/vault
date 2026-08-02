//! Scope patterns for restricting which secrets a caller may resolve.
//!
//! A scope is a list of glob patterns matched against secret names. It is used
//! to give unattended consumers (agents, daemons, CI runners) least-privilege
//! access to the vault instead of all-or-nothing access.
//!
//! # Pattern syntax
//!
//! Secret names are treated as `/`-delimited paths:
//!
//! - `*`  matches any run of characters **except** `/` (one path segment)
//! - `**` matches any run of characters **including** `/` (any depth)
//! - `?`  matches exactly one character, except `/`
//! - all other characters match literally
//!
//! There is deliberately no character-class (`[a-z]`) or brace (`{a,b}`) syntax:
//! secret names may legitimately contain `[`, `]`, `{`, and `}`, and silently
//! reinterpreting them as metacharacters would be a security footgun.
//!
//! # Examples
//!
//! | Pattern        | Matches                        | Does not match          |
//! |----------------|--------------------------------|-------------------------|
//! | `telegram/*`   | `telegram/botToken`            | `telegram/a/b`, `gh/x`  |
//! | `telegram/**`  | `telegram/a`, `telegram/a/b`   | `telegram`, `gh/x`      |
//! | `*`            | `token`                        | `a/b`                   |
//! | `**`           | anything                       | —                       |
//! | `db?`          | `db1`                          | `db`, `db12`            |
//!
//! # Fail-closed
//!
//! An empty scope matches nothing. Callers that want unrestricted access must
//! say so explicitly rather than relying on an empty list meaning "everything".

use anyhow::Result;

/// Maximum number of patterns in a single scope.
///
/// Bounds worst-case matching work for a hostile or careless caller.
pub const MAX_SCOPE_PATTERNS: usize = 64;

/// Maximum length of a single scope pattern, in bytes.
pub const MAX_SCOPE_PATTERN_BYTES: usize = 256;

/// A compiled set of scope patterns.
///
/// Construct via [`Scope::parse`] (restricted) or [`Scope::unrestricted`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    patterns: Vec<String>,
    unrestricted: bool,
}

impl Scope {
    /// A scope that permits every secret name.
    ///
    /// Used when no scope restriction was requested at all. This is distinct
    /// from a scope containing `**`, though the two behave identically for
    /// matching; keeping them separate lets callers report "no scope" and
    /// "scope of `**`" differently in diagnostics.
    pub fn unrestricted() -> Self {
        Self {
            patterns: Vec::new(),
            unrestricted: true,
        }
    }

    /// A scope that permits nothing.
    pub fn empty() -> Self {
        Self {
            patterns: Vec::new(),
            unrestricted: false,
        }
    }

    /// Parse a list of patterns into a scope.
    ///
    /// Rejects empty patterns, over-long patterns, control characters, and
    /// over-large pattern sets. Returns a fail-closed (matches nothing) scope
    /// when `patterns` is empty.
    pub fn parse<I, S>(patterns: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut compiled = Vec::new();
        for pattern in patterns {
            let pattern = pattern.as_ref();
            if pattern.is_empty() {
                anyhow::bail!("scope pattern cannot be empty");
            }
            if pattern.len() > MAX_SCOPE_PATTERN_BYTES {
                anyhow::bail!(
                    "scope pattern exceeds {} bytes: {}",
                    MAX_SCOPE_PATTERN_BYTES,
                    truncate_for_error(pattern)
                );
            }
            if pattern.chars().any(|c| c.is_control()) {
                anyhow::bail!("scope pattern contains control characters");
            }
            if compiled.len() >= MAX_SCOPE_PATTERNS {
                anyhow::bail!("scope contains more than {} patterns", MAX_SCOPE_PATTERNS);
            }
            compiled.push(pattern.to_string());
        }

        Ok(Self {
            patterns: compiled,
            unrestricted: false,
        })
    }

    /// Whether this scope permits every name.
    pub fn is_unrestricted(&self) -> bool {
        self.unrestricted
    }

    /// Whether this scope permits nothing.
    pub fn is_empty(&self) -> bool {
        !self.unrestricted && self.patterns.is_empty()
    }

    /// The patterns backing this scope, for diagnostics.
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    /// Whether `name` is permitted by this scope.
    pub fn allows(&self, name: &str) -> bool {
        if self.unrestricted {
            return true;
        }
        self.patterns.iter().any(|p| glob_match(p, name))
    }

    /// A human-readable description, for error messages.
    pub fn describe(&self) -> String {
        if self.unrestricted {
            return "unrestricted".to_string();
        }
        if self.patterns.is_empty() {
            return "none".to_string();
        }
        self.patterns.join(", ")
    }
}

fn truncate_for_error(s: &str) -> String {
    const LIMIT: usize = 40;
    if s.len() <= LIMIT {
        return s.to_string();
    }
    let mut end = LIMIT;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// Match `name` against a single glob `pattern`.
///
/// Implemented as an iterative backtracking matcher over character vectors, so
/// it is linear in the common case and never recurses (no stack blowup on a
/// hostile pattern). Operates on `char`s so multi-byte UTF-8 names behave
/// predictably with `?`.
fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();

    // Indices into pattern and name.
    let (mut pi, mut ni) = (0usize, 0usize);
    // Backtrack state: where to resume if the current wildcard guess fails.
    let mut star_pi: Option<usize> = None;
    let mut star_ni = 0usize;
    // Whether the wildcard we backtrack to may cross `/`.
    let mut star_crosses_sep = false;

    while ni < n.len() {
        if pi < p.len() && p[pi] == '*' {
            // Collapse a run of `*`. Two or more means "cross separators".
            let start = pi;
            while pi < p.len() && p[pi] == '*' {
                pi += 1;
            }
            let crosses = pi - start >= 2;

            star_pi = Some(pi);
            star_ni = ni;
            star_crosses_sep = crosses;
            continue;
        }

        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            // `?` must not match a path separator.
            if p[pi] == '?' && n[ni] == '/' {
                // Fall through to backtracking below.
            } else {
                pi += 1;
                ni += 1;
                continue;
            }
        }

        // Mismatch: backtrack to the last wildcard, consuming one more char.
        match star_pi {
            Some(resume) => {
                // A single `*` may not consume a path separator.
                if !star_crosses_sep && n[star_ni] == '/' {
                    return false;
                }
                star_ni += 1;
                if star_ni > n.len() {
                    return false;
                }
                pi = resume;
                ni = star_ni;
            }
            None => return false,
        }
    }

    // Name exhausted: any pattern remainder must be `*`s only.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_match() {
        assert!(glob_match("telegram/botToken", "telegram/botToken"));
        assert!(!glob_match("telegram/botToken", "telegram/other"));
        assert!(!glob_match("telegram", "telegram/botToken"));
    }

    #[test]
    fn single_star_stays_within_segment() {
        assert!(glob_match("telegram/*", "telegram/botToken"));
        assert!(!glob_match("telegram/*", "telegram/nested/token"));
        assert!(!glob_match("telegram/*", "github/token"));
        assert!(glob_match("*", "token"));
        assert!(!glob_match("*", "a/b"));
    }

    #[test]
    fn double_star_crosses_segments() {
        assert!(glob_match("telegram/**", "telegram/botToken"));
        assert!(glob_match("telegram/**", "telegram/nested/token"));
        assert!(glob_match("telegram/**", "telegram/a/b/c"));
        assert!(!glob_match("telegram/**", "github/token"));
        assert!(glob_match("**", "anything/at/any/depth"));
        assert!(glob_match("**", "flat"));
    }

    #[test]
    fn double_star_requires_a_child() {
        // `telegram/**` describes children of `telegram`, not `telegram` itself.
        assert!(!glob_match("telegram/**", "telegram"));
    }

    #[test]
    fn question_mark_matches_one_non_separator_char() {
        assert!(glob_match("db?", "db1"));
        assert!(!glob_match("db?", "db"));
        assert!(!glob_match("db?", "db12"));
        assert!(!glob_match("a?b", "a/b"));
    }

    #[test]
    fn star_in_middle() {
        assert!(glob_match("prod/*/password", "prod/mysql/password"));
        assert!(!glob_match("prod/*/password", "prod/mysql/rw/password"));
        assert!(glob_match("prod/**/password", "prod/mysql/rw/password"));
    }

    #[test]
    fn no_character_class_or_brace_syntax() {
        // `[` and `{` are literal, since secret names may contain them.
        assert!(glob_match("a[bc]d", "a[bc]d"));
        assert!(!glob_match("a[bc]d", "abd"));
        assert!(glob_match("x{1,2}", "x{1,2}"));
        assert!(!glob_match("x{1,2}", "x1"));
    }

    #[test]
    fn unicode_names() {
        assert!(glob_match("clé/*", "clé/secret"));
        assert!(glob_match("?", "é"));
        assert!(glob_match("emoji/*", "emoji/🔑"));
    }

    #[test]
    fn empty_name_edge_cases() {
        assert!(glob_match("*", ""));
        assert!(glob_match("**", ""));
        assert!(!glob_match("?", ""));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn pathological_pattern_terminates() {
        // Classic glob backtracking blowup; must not hang or overflow.
        let pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let name = "a".repeat(200);
        assert!(!glob_match(pattern, &name));
    }

    #[test]
    fn scope_empty_matches_nothing() {
        let scope = Scope::parse(Vec::<String>::new()).unwrap();
        assert!(scope.is_empty());
        assert!(!scope.allows("anything"));
    }

    #[test]
    fn scope_unrestricted_matches_everything() {
        let scope = Scope::unrestricted();
        assert!(scope.is_unrestricted());
        assert!(scope.allows("anything/at/all"));
    }

    #[test]
    fn scope_any_pattern_matches() {
        let scope = Scope::parse(["telegram/*", "github/token"]).unwrap();
        assert!(scope.allows("telegram/botToken"));
        assert!(scope.allows("github/token"));
        assert!(!scope.allows("aws/secret"));
        assert!(!scope.allows("telegram/a/b"));
    }

    #[test]
    fn scope_rejects_bad_patterns() {
        assert!(Scope::parse([""]).is_err());
        assert!(Scope::parse(["a\nb"]).is_err());
        assert!(Scope::parse(["a".repeat(MAX_SCOPE_PATTERN_BYTES + 1)]).is_err());
        let too_many: Vec<String> = (0..=MAX_SCOPE_PATTERNS).map(|i| format!("p{i}")).collect();
        assert!(Scope::parse(too_many).is_err());
    }

    #[test]
    fn scope_describe() {
        assert_eq!(Scope::unrestricted().describe(), "unrestricted");
        assert_eq!(Scope::empty().describe(), "none");
        assert_eq!(Scope::parse(["a/*", "b"]).unwrap().describe(), "a/*, b");
    }
}

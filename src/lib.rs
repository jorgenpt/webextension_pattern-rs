//! webextension_pattern implements support for matching URLs with a powerful and intuitive pattern. It's simpler than regular expressions, and specifically tailored to URL matching.
//! It's the format used by Mozilla's WebExtensions for matching URLs, as well as Google Chrome, and you can find their documentation here:
//!
//!  - [Reference on developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Match_patterns)
//!  - [Reference on developer.chrome.com](https://developer.chrome.com/docs/extensions/mv2/match_patterns/)
//!
//! This crate aims to be compatible with Mozilla's implementation, specifically.
//!
//! See [`Pattern`] for information about the format.

use regex::Regex;
use regex_syntax;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt};
use thiserror::Error;
use url::{Position, Url};

type Result<T> = std::result::Result<T, Error>;

/// Error type for parsing a [`Pattern`]
#[derive(Error, Debug)]
pub enum Error {
    /// The given pattern does not contain an URL scheme (not applicable to `relaxed` parsing)
    #[error("could not identify any url scheme component for pattern {0:?}")]
    MissingScheme(String),
    /// The given pattern does not contain a path (not applicable to `relaxed` parsing)
    #[error("could not identify any path component for pattern {0:?}")]
    MissingPath(String),
    /// The regular expression generated from the path pattern failed to compile
    #[error("failed to compile regex {pattern_regex:?} (generated from {pattern_source:?})")]
    RegexCompile {
        /// The `source` given to [`Pattern::new`]
        pattern_source: String,
        /// The regular expression generated from `pattern_source`
        pattern_regex: String,
        /// The exception from `Regex::new`
        #[source]
        source: regex::Error,
    },
}

#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
enum Schemes {
    All,
    Wildcard,
    SpecificScheme(String),
}

impl Schemes {
    fn include(&self, scheme: &str) -> bool {
        match self {
            Schemes::All => true,
            Schemes::Wildcard => WILDCARD_SCHEMES.iter().any(|s| *s == scheme),
            Schemes::SpecificScheme(specific_scheme) => scheme == specific_scheme,
        }
    }
}

#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
enum Hosts {
    All,
    SpecificHost(Option<String>),
    SpecificHostWithSubdomains(String),
}

impl Hosts {
    fn include(&self, host: Option<&str>) -> bool {
        match self {
            Hosts::All => true,
            Hosts::SpecificHost(specific_host) => host == specific_host.as_deref(),
            Hosts::SpecificHostWithSubdomains(specific_host) => {
                if let Some(host) = host {
                    if host.len() > specific_host.len() {
                        let subdomain_offset = host.len() - specific_host.len();
                        if host.chars().nth(subdomain_offset - 1).unwrap() != '.' {
                            return false;
                        }

                        &host[subdomain_offset..] == specific_host
                    } else {
                        host == specific_host
                    }
                } else {
                    false
                }
            }
        }
    }
}

#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
enum Paths {
    All,
    MatchingPattern(Regex),
}

impl Paths {
    fn include(&self, path: &str) -> bool {
        match self {
            Paths::All => true,
            Paths::MatchingPattern(pattern) => pattern.is_match(path),
        }
    }
}

/// A parsed WebExtensions pattern
///
/// # Format
///
/// A strict format looks like `SCHEMA://HOST/PATH`:
/// - `SCHEMA` can be `*` (all schemas), or a specific schema like `http`
/// - `HOST` can be `*` (all hosts), a specific host (no wildcards allowed) like `google.com`, or something starting with `*.` to indicate that the domain itself and any subdomain is valid, like `*.google.com`
/// - `PATH` is a string that is matched against the full path, and `SCHEMA://HOST/` is considered to *only* match the path `/`. It supports wildcards with `*`, which will match any character (including a slash)
///
/// The value `<all_urls>` is a special token that matches all URLs.
///
/// The `relaxed` format is a superset of the strict format, and you can optionally omit the schema and the path -- omitting `SCHEMA://` will match all schemas, and omitting the path (or leaving it as `/`) will match all paths.
///
/// # Examples
///
/// ```
/// use webextension_pattern::Pattern;
/// use url::Url;
/// let p = Pattern::new("*://google.com/foo*bar", false)?;
/// assert!(!p.is_match(&Url::parse("http://google.com/")?));
/// assert!(p.is_match(&Url::parse("https://google.com/foo/baz/bar")?));
/// assert!(p.is_match(&Url::parse("https://google.com/foo_bar")?));
/// assert!(!p.is_match(&Url::parse("https://mail.google.com/foo_bar")?));
///
/// let p = Pattern::new("*.google.com", true)?;
/// assert!(p.is_match(&Url::parse("http://google.com/")?));
/// assert!(p.is_match(&Url::parse("https://google.com/foo_bar")?));
/// assert!(p.is_match(&Url::parse("https://mail.google.com/something_else")?));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct Pattern {
    source: String,
    schemes: Schemes,
    hosts: Hosts,
    paths: Paths,
}

/// The list of schemes that are supported when using *://
static WILDCARD_SCHEMES: &'static [&str] = &["http", "https", "ws", "wss"];

impl Pattern {
    /// Return a pattern that will match any URL
    pub fn wildcard() -> Pattern {
        Self::wildcard_from_source("<all_urls>")
    }

    fn wildcard_from_source(source: &str) -> Pattern {
        Self {
            source: source.to_string(),
            schemes: Schemes::All,
            hosts: Hosts::All,
            paths: Paths::All,
        }
    }

    /// Parse a pattern from the given `source`. If using `relaxed`, it will not adhere to the requirements of the
    /// Mozilla format by allowing the omission of an URL scheme and the omission of an explicit path, causing it
    /// to assume these as wildcards. This mode is intended to be more forgiving for common user patterns.
    pub fn new(source: &str, relaxed: bool) -> Result<Pattern> {
        // This implementation used mozilla::extensions::MatchPattern::Init as a reference (see https://searchfox.org/mozilla-central/source/toolkit/components/extensions/MatchPattern.cpp
        // for the full details) for the non-relaxed parsing.
        if source == "<all_urls>" {
            return Ok(Self::wildcard_from_source(source));
        }

        if source == "*" && relaxed {
            return Ok(Self::wildcard_from_source(source));
        }

        let original_source = source;

        // This means we don't (yet) support schemes without a host locator, like e.g. data:, which
        // don't have a //.
        let end_of_scheme = source.find("://");

        let (source, schemes) = if let Some(end_of_scheme) = end_of_scheme {
            let scheme = &source[..end_of_scheme];
            if scheme == "*" {
                (&source[end_of_scheme + 3..], Schemes::Wildcard)
            } else {
                (
                    &source[end_of_scheme + 3..],
                    Schemes::SpecificScheme(scheme.to_string()),
                )
            }
        } else {
            if !relaxed {
                return Err(Error::MissingScheme(original_source.to_string()));
            }

            (source, Schemes::Wildcard)
        };

        let end_of_host = source.find("/").unwrap_or(source.len());
        let host = &source[..end_of_host];
        let hosts = if host == "*" {
            Hosts::All
        } else if host.starts_with("*.") {
            Hosts::SpecificHostWithSubdomains(host[2..].to_string())
        } else if host.len() > 0 {
            Hosts::SpecificHost(Some(host.to_string()))
        } else {
            Hosts::SpecificHost(None)
        };

        let path = &source[end_of_host..];
        let paths = if path.is_empty() {
            if relaxed {
                Paths::All
            } else {
                return Err(Error::MissingPath(original_source.to_string()));
            }
        } else if relaxed && path == "/" {
            Paths::All
        } else {
            Paths::MatchingPattern(Self::glob_to_regex(path)?)
        };

        Ok(Self {
            source: source.to_string(),
            schemes,
            hosts,
            paths,
        })
    }

    /// Check if the [`Pattern`] matches the `url`.
    pub fn is_match(&self, url: &Url) -> bool {
        self.schemes.include(url.scheme())
            && self.hosts.include(url.host_str())
            && self
                .paths
                .include(&url[Position::BeforePath..Position::AfterQuery])
    }

    /// Convert a glob with asterisks to an anchored regex
    fn glob_to_regex(glob: &str) -> Result<Regex> {
        let mut regex_pattern = String::with_capacity(glob.len() * 2);
        regex_pattern.push('^');
        for c in glob.chars() {
            if c == '*' {
                regex_pattern.push_str(".*");
            } else {
                if regex_syntax::is_meta_character(c) {
                    regex_pattern.push('\\');
                }

                regex_pattern.push(c);
            }
        }
        regex_pattern.push('$');

        Regex::new(&regex_pattern).map_err(|err| Error::RegexCompile {
            pattern_source: glob.to_string(),
            pattern_regex: regex_pattern,
            source: err,
        })
    }
}

impl Into<String> for Pattern {
    fn into(self) -> String {
        self.source
    }
}

impl TryFrom<String> for Pattern {
    type Error = Error;

    fn try_from(raw: String) -> Result<Self> {
        Pattern::new(&raw, true)
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#?}", self.source)
    }
}

// TODO test cases
#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    macro_rules! assert_err {
        ($expression:expr, $($pattern:tt)+) => {
            match $expression {
                $($pattern)+ => (),
                ref e => panic!("expected `{}` but got `{:?}`", stringify!($($pattern)+), e),
            }
        }
    }

    macro_rules! assert_pattern_does_match {
        ($pattern:expr, $matching_urls:expr) => {
            for url in ($matching_urls).iter().map(|u| Url::parse(u)) {
                let url = url?;
                assert!($pattern.is_match(&url), "url = {}", url.to_string());
            }
        };
    }

    macro_rules! assert_pattern_does_not_match {
        ($pattern:expr, $matching_urls:expr) => {
            for url in ($matching_urls).iter().map(|u| Url::parse(u)) {
                let url = url?;
                assert!(!$pattern.is_match(&url), "url = {}", url.to_string());
            }
        };
    }

    // Test data from https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Match_patterns#examples
    mod mozilla_patterns {
        use super::*;

        #[test]
        fn all_urls() -> TestResult {
            let p = Pattern::new("<all_urls>", false)?;

            assert_pattern_does_match!(
                p,
                [
                    "http://example.org/",
                    "https://a.org/some/path/",
                    "ws://sockets.somewhere.org/",
                    "wss://ws.example.com/stuff/",
                    "ftp://files.somewhere.org/",
                    "ftps://files.somewhere.org/",
                ]
            );

            // This is listed as a "not matching" URL in the Mozilla docs, but we don't do any enforcement
            // of protocol when matching against the wildcard.
            // let not_matching_url = Url::parse("resource://a/b/c/")?;
            // assert!(!p.is_match(&not_matching_url));

            Ok(())
        }

        #[test]
        fn all_wildcards() -> TestResult {
            let p = Pattern::new("*://*/*", false)?;

            assert_pattern_does_match!(
                p,
                [
                    "http://example.org/",
                    "https://a.org/some/path/",
                    "ws://sockets.somewhere.org/",
                    "wss://ws.example.com/stuff/",
                ]
            );

            assert_pattern_does_not_match!(
                p,
                [
                    "ftp://ftp.example.org/",  // unmatched scheme
                    "ftps://ftp.example.org/", // unmatched scheme
                    "file:///a/",              // unmatched scheme
                ]
            );

            Ok(())
        }

        #[test]
        fn subdomain_wildcard() -> TestResult {
            let p = Pattern::new("*://*.mozilla.org/*", false)?;

            assert_pattern_does_match!(
                p,
                [
                    "http://mozilla.org/",
                    "https://mozilla.org/",
                    "http://a.mozilla.org/",
                    "http://a.b.mozilla.org/",
                    "https://b.mozilla.org/path/",
                    "ws://ws.mozilla.org/",
                    "wss://secure.mozilla.org/something",
                ]
            );

            assert_pattern_does_not_match!(
                p,
                [
                    "ftp://mozilla.org/",  // unmatched scheme
                    "http://mozilla.com/", // unmatched host
                    "http://firefox.org/", // unmatched host
                ]
            );

            Ok(())
        }

        #[test]
        fn scheme_wildcard() -> TestResult {
            let p = Pattern::new("*://mozilla.org/", false)?;

            assert_pattern_does_match!(
                p,
                [
                    "http://mozilla.org/",
                    "https://mozilla.org/",
                    "ws://mozilla.org/",
                    "wss://mozilla.org/",
                ]
            );

            assert_pattern_does_not_match!(
                p,
                [
                    "ftp://mozilla.org/",    // unmatched scheme
                    "http://a.mozilla.org/", // unmatched host
                    "http://mozilla.org/a",  // unmatched path
                ]
            );

            Ok(())
        }

        #[test]
        fn all_fixed() -> TestResult {
            let p = Pattern::new("ftp://mozilla.org/", false)?;

            assert_pattern_does_match!(p, ["ftp://mozilla.org"]);

            assert_pattern_does_not_match!(
                p,
                [
                    "http://mozilla.org/",    // unmatched scheme
                    "ftp://sub.mozilla.org/", // unmatched host
                    "ftp://mozilla.org/path", // unmatched path
                ]
            );

            Ok(())
        }

        #[test]
        fn wildcard_host() -> TestResult {
            let p = Pattern::new("https://*/path", false)?;

            assert_pattern_does_match!(
                p,
                [
                    "https://mozilla.org/path",
                    "https://a.mozilla.org/path",
                    "https://something.com/path",
                ]
            );

            assert_pattern_does_not_match!(
                p,
                [
                    "http://mozilla.org/path",        // unmatched scheme
                    "https://mozilla.org/path/",      // unmatched path
                    "https://mozilla.org/a",          // unmatched path
                    "https://mozilla.org/",           // unmatched path
                    "https://mozilla.org/path?foo=1", // unmatched path due to URL query string
                ]
            );

            Ok(())
        }

        #[test]
        fn wildcard_host_trailing_slash() -> TestResult {
            let p = Pattern::new("https://*/path/", false)?;

            assert_pattern_does_match!(
                p,
                [
                    "https://mozilla.org/path/",
                    "https://a.mozilla.org/path/",
                    "https://something.com/path/",
                ]
            );

            assert_pattern_does_not_match!(
                p,
                [
                    "http://mozilla.org/path/",        // unmatched scheme
                    "https://mozilla.org/path",        // unmatched path
                    "https://mozilla.org/a",           // unmatched path
                    "https://mozilla.org/",            // unmatched path
                    "https://mozilla.org/path/?foo=1", // unmatched path due to URL query string
                ]
            );

            Ok(())
        }

        #[test]
        fn wildcard_path() -> TestResult {
            let p = Pattern::new("https://mozilla.org/*", false)?;

            assert_pattern_does_match!(
                p,
                [
                    "https://mozilla.org/",
                    "https://mozilla.org/path",
                    "https://mozilla.org/another",
                    "https://mozilla.org/path/to/doc",
                    "https://mozilla.org/path/to/doc?foo=1",
                ]
            );

            assert_pattern_does_not_match!(
                p,
                [
                    "http://mozilla.org/path",  // unmatched scheme
                    "https://mozilla.com/path", // unmatched host
                ]
            );

            Ok(())
        }

        #[test]
        fn all_fixed_http() -> TestResult {
            let p = Pattern::new("https://mozilla.org/a/b/c/", false)?;

            assert_pattern_does_match!(
                p,
                [
                    "https://mozilla.org/a/b/c/",
                    "https://mozilla.org/a/b/c/#section1",
                ]
            );

            Ok(())
        }

        #[test]
        fn multiple_wildcard_path() -> TestResult {
            let p = Pattern::new("https://mozilla.org/*/b/*/", false)?;

            assert_pattern_does_match!(
                p,
                [
                    "https://mozilla.org/a/b/c/",
                    "https://mozilla.org/d/b/f/",
                    "https://mozilla.org/a/b/c/d/",
                    "https://mozilla.org/a/b/c/d/#section1",
                    "https://mozilla.org/a/b/c/d/?foo=/",
                    "https://mozilla.org/a?foo=21314&bar=/b/&extra=c/",
                ]
            );

            assert_pattern_does_not_match!(
                p,
                [
                    "https://mozilla.org/b/*/",             // unmatched path
                    "https://mozilla.org/a/b/",             // unmatched path
                    "https://mozilla.org/a/b/c/d/?foo=bar", // unmatched path due to URL query string
                ]
            );

            Ok(())
        }

        #[test]
        fn file_scheme_path_wildcard() -> TestResult {
            let p = Pattern::new("file:///blah/*", false)?;

            assert_pattern_does_match!(p, ["file:///blah/", "file:///blah/bleh"]);

            assert_pattern_does_not_match!(
                p,
                [
                    "file:///bleh/" // unmatched path
                ]
            );

            Ok(())
        }

        #[test]
        fn parse_errors() {
            // This would fail Mozilla implementation as they filter which schemes are allowed unless you pass a flag: `Pattern::new("resource://path/", false)` -- We don't filter.

            // No path
            assert_err!(
                Pattern::new("https://mozilla.org", false),
                Err(Error::MissingPath(_))
            );

            //	No path, this should be "*://*/*".
            assert_err!(Pattern::new(" *://*", false), Err(Error::MissingPath(_)));

            // No path, this should be "file:///*".
            assert_err!(Pattern::new(" *://*", false), Err(Error::MissingPath(_)));

            // Some that we don't currently implement errors for
            // https://mozilla.*.org/	"*" in host must be at the start.
            // https://*zilla.org/	"*" in host must be the only character or be followed by ".".
            // http*://mozilla.org/	"*" in scheme must be the only character.
            // https://mozilla.org:80/	Host must not include a port number.
        }
    }
}

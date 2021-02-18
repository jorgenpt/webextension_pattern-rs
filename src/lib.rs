//! webextension_pattern implements support for matching URLs with a powerful and intuitive pattern. It's simpler than regular expressions, and specifically tailored to URL matching.
//! It's the format used by Mozilla's WebExtensions for matching URLs, as well as Google Chrome, and you can find their documentation here:
//!
//!  - [Reference on developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Match_patterns)
//!  - [Reference on developer.chrome.com](https://developer.chrome.com/docs/extensions/mv2/match_patterns/)
//!
//! This crate aims to be compatible with Mozilla's implementation, specifically.
//!
//! See [`Pattern::new`] for information about the format.

use regex::Regex;
use regex_syntax;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt};
use thiserror::Error;
use url::Url;

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

/// A parsed WebExtensions pattern
///
/// # Format
///
/// A strict format looks like `SCHEMA://HOST/PATH`:
/// - `SCHEMA` can be `*` (all schemas), or a specific schema like `http`
/// - `HOST` can be `*` (all hosts), a specific host (no wildcards allowed) like `google.com`, or something starting with `*.` to indicate that the domain itself and any subdomain is valid, like `*.google.com`
/// - `PATH` is a string that is matched against the full path, and `SCHEMA://HOST/` is considered to *only* match the path `/`. It supports wildcards with `*`, which will match any character (including a slash)
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
    scheme: Option<String>,
    host: Option<String>,
    match_subdomain: bool,
    path: Option<Regex>,
}

impl Pattern {
    /// Return a pattern that will match any URL
    pub fn wildcard() -> Pattern {
        Self::wildcard_from_source("<all_urls>")
    }

    fn wildcard_from_source(source: &str) -> Pattern {
        Self {
            source: source.to_string(),
            scheme: None,
            host: None,
            match_subdomain: true,
            path: None,
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

        let (source, scheme) = if let Some(end_of_scheme) = end_of_scheme {
            let scheme = &source[..end_of_scheme];
            if scheme == "*" {
                (&source[end_of_scheme + 3..], None)
            } else {
                (&source[end_of_scheme + 3..], Some(scheme.to_string()))
            }
        } else {
            if !relaxed {
                return Err(Error::MissingScheme(original_source.to_string()));
            }

            (source, None)
        };

        let end_of_host = source.find("/").unwrap_or(source.len());
        let host = &source[..end_of_host];
        let (host, match_subdomain) = if host == "*" {
            (None, true)
        } else if host.starts_with("*.") {
            (Some(&host[2..]), true)
        } else {
            (Some(host), false)
        };

        let path = &source[end_of_host..];
        let path = if path.is_empty() {
            if relaxed {
                None
            } else {
                return Err(Error::MissingPath(original_source.to_string()));
            }
        } else if relaxed && path == "/" {
            None
        } else {
            Some(Self::glob_to_regex(path)?)
        };

        Ok(Self {
            source: source.to_string(),
            scheme,
            host: host.map(|h| h.to_string()),
            match_subdomain,
            path: path,
        })
    }

    /// Check if the [`Pattern`] matches the `url`.
    pub fn is_match(&self, url: &Url) -> bool {
        if let Some(scheme) = &self.scheme {
            if url.scheme() != scheme {
                return false;
            }
        }

        if let Some(host) = &self.host {
            if let Some(url_host) = url.host_str() {
                if self.match_subdomain && url_host.len() > host.len() {
                    let subdomain_offset = url_host.len() - host.len();
                    if url_host.chars().nth(subdomain_offset - 1).unwrap() != '.' {
                        return false;
                    }

                    if &url_host[subdomain_offset..] != host {
                        return false;
                    }
                } else if url.host_str() != Some(host) {
                    return false;
                }
            } else {
                return false;
            }
        }

        if let Some(path) = &self.path {
            if !path.is_match(url.path()) {
                return false;
            }
        }

        true
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
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

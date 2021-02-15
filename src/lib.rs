use regex::Regex;
use regex_syntax;
// TODO Serde feature
//use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt};
use thiserror::Error;
use url::Url;

type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("could not identify any url scheme component for pattern {0:?}")]
    MissingScheme(String),
    #[error("could not identify any path component for pattern {0:?}")]
    MissingPath(String),
    #[error("failed to compile regex {pattern_regex:?} (generated from {pattern_source:?})")]
    RegexCompile {
        pattern_source: String,
        pattern_regex: String,
        #[source]
        source: regex::Error,
    },
}

// #[serde(try_from = "String", into = "String")]
// #[derive(Serialize, Deserialize, Debug, Clone)]
#[derive(Debug, Clone)]
pub struct Pattern {
    source: String,
    scheme: Option<String>,
    host: Option<String>,
    match_subdomain: bool,
    path: Option<Regex>,
}

impl Pattern {
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

    pub fn new(source: &str, relaxed: bool) -> Result<Pattern> {
        // https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Match_patterns#browser_compatibility
        // https://searchfox.org/mozilla-central/source/toolkit/components/extensions/MatchPattern.cpp
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
                }
                if url.host_str() != Some(host) {
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

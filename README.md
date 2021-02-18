[![Build status](https://github.com/jorgenpt/webextension_pattern-rs/workflows/Rust/badge.svg)](https://github.com/jorgenpt/webextension_pattern-rs/actions?query=workflow%3ARust)
[![Crate](https://img.shields.io/crates/v/webextension_pattern.svg)](https://crates.io/crates/webextension_pattern)
[![API](https://docs.rs/webextension_pattern/badge.svg)](https://docs.rs/webextension_pattern)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

# webextension\_pattern

webextension\_pattern implements support for matching URLs with a
powerful and intuitive pattern. It's simpler than regular expressions,
and specifically tailored to URL matching.  It's the format used by
Mozilla's WebExtensions for matching URLs, as well as Google Chrome, and
you can find their documentation here:

 - [Reference on
 developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Match_patterns)
 - [Reference on
 developer.chrome.com](https://developer.chrome.com/docs/extensions/mv2/match_patterns/)

This crate aims to be compatible with Mozilla's implementation,
specifically, but also supports a "relaxed" mode that does not strictly
adhere, for user-friendliness.

These patterns end up looking like this:
 - `*://google.com/foo*bar`
 - `https://*.mozilla.org/specific_path?k=1`
 - `*://*/index.php`
 - (_relaxed mode_) `*.facebook.com`


## License

webextension\_pattern is licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

//! Link validation (threats T2 and T9 in `docs/security-model.md`).
//!
//! A job's apply link is checked *before* anything is drafted for it. The
//! parser is deliberately strict and small: HTTPS only, plain ASCII hostnames
//! only, and no tricks.
//!
//! No network access happens here. This validates the *text* of a link; it does
//! not prove the page behind it is genuine.

const MAX_URL_LEN: usize = 2048;

/// Top-level names that never belong to a public employer site.
const LOCAL_TLDS: &[&str] = &[
    "local",
    "localhost",
    "internal",
    "lan",
    "home",
    "corp",
    "intranet",
    "invalid",
    "test",
    "onion",
];

/// Well-known applicant-tracking and job-board platforms.
///
/// "Trusted" means "a real platform", **not** "a real employer": anyone can
/// open a company page on these sites. The user can add their own list.
const DEFAULT_TRUSTED: &[&str] = &[
    "greenhouse.io",
    "lever.co",
    "ashbyhq.com",
    "workable.com",
    "smartrecruiters.com",
    "myworkdayjobs.com",
    "linkedin.com",
    "naukri.com",
    "internshala.com",
    "wellfound.com",
    "indeed.com",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlError {
    Empty,
    TooLong,
    /// Contains a space, control character, or non-ASCII character.
    ForbiddenCharacters,
    NotHttps,
    /// `https://user@host/` style links hide the real host.
    UserInfo,
    BadHost,
    /// A numeric address such as `127.0.0.1`, or `[::1]`.
    IpAddress,
    /// An `xn--` label can be a lookalike of another domain.
    Punycode,
    /// `localhost`, `.local`, `.internal` and similar.
    LocalName,
    BadPort,
}

impl UrlError {
    pub fn explanation(&self) -> &'static str {
        match self {
            Self::Empty => "the apply link is empty",
            Self::TooLong => "the apply link is too long",
            Self::ForbiddenCharacters => "the apply link contains spaces or unusual characters",
            Self::NotHttps => "the apply link is not HTTPS",
            Self::UserInfo => "the apply link hides its real host behind a username",
            Self::BadHost => "the apply link has an invalid host name",
            Self::IpAddress => "the apply link points at a raw IP address",
            Self::Punycode => "the apply link uses a look-alike (punycode) domain",
            Self::LocalName => "the apply link points at a local or internal name",
            Self::BadPort => "the apply link uses an unusual port",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustTier {
    /// On the platform allow-list.
    Trusted,
    /// Valid, but not on the list. The user should check it.
    Unknown,
}

/// A link that passed every check. `normalized` is what gets shown and what
/// approvals are bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeUrl {
    host: String,
    normalized: String,
}

impl SafeUrl {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    pub fn trust(&self, extra_trusted: &[String]) -> TrustTier {
        let matches =
            |domain: &str| self.host == domain || self.host.ends_with(&format!(".{domain}"));
        if DEFAULT_TRUSTED.iter().any(|d| matches(d)) || extra_trusted.iter().any(|d| matches(d)) {
            TrustTier::Trusted
        } else {
            TrustTier::Unknown
        }
    }
}

fn validate_host(host: &str) -> Result<(), UrlError> {
    if host.is_empty() || host.len() > 253 {
        return Err(UrlError::BadHost);
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return Err(UrlError::BadHost);
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err(UrlError::BadHost);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(UrlError::BadHost);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(UrlError::BadHost);
        }
        if label.starts_with("xn--") {
            return Err(UrlError::Punycode);
        }
    }
    let tld = labels[labels.len() - 1];
    if tld.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UrlError::IpAddress);
    }
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_lowercase()) {
        return Err(UrlError::BadHost);
    }
    if LOCAL_TLDS.contains(&tld) {
        return Err(UrlError::LocalName);
    }
    Ok(())
}

pub fn parse_https_url(input: &str) -> Result<SafeUrl, UrlError> {
    if input.is_empty() {
        return Err(UrlError::Empty);
    }
    if input.len() > MAX_URL_LEN {
        return Err(UrlError::TooLong);
    }
    if !input.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(UrlError::ForbiddenCharacters);
    }
    if input.contains('\\') {
        return Err(UrlError::ForbiddenCharacters);
    }
    let Some(scheme) = input.get(..8) else {
        return Err(UrlError::NotHttps);
    };
    if !scheme.eq_ignore_ascii_case("https://") {
        return Err(UrlError::NotHttps);
    }
    let rest = &input[8..];
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_end);

    if authority.contains('@') {
        return Err(UrlError::UserInfo);
    }
    if authority.starts_with('[') {
        return Err(UrlError::IpAddress);
    }
    let host_part = match authority.rsplit_once(':') {
        Some((h, port)) => {
            if port != "443" {
                return Err(UrlError::BadPort);
            }
            h
        }
        None => authority,
    };
    let mut host = host_part.to_ascii_lowercase();
    if host.ends_with('.') {
        host.pop();
    }
    validate_host(&host)?;

    Ok(SafeUrl {
        normalized: format!("https://{host}{tail}"),
        host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> SafeUrl {
        parse_https_url(s).unwrap_or_else(|e| panic!("{s:?} rejected: {e:?}"))
    }

    fn err(s: &str) -> UrlError {
        parse_https_url(s).expect_err(s)
    }

    #[test]
    fn accepts_ordinary_https_links() {
        assert_eq!(
            ok("https://boards.greenhouse.io/acme/jobs/123").host(),
            "boards.greenhouse.io"
        );
        assert_eq!(
            ok("HTTPS://Careers.Example.COM/Jobs?id=1#x").host(),
            "careers.example.com"
        );
        assert_eq!(ok("https://example.com").as_str(), "https://example.com");
        assert_eq!(ok("https://example.com:443/a").host(), "example.com");
    }

    #[test]
    fn normalizes_host_case_and_trailing_dot_but_keeps_the_path() {
        assert_eq!(
            ok("https://Jobs.Example.com./Path/A?x=1").as_str(),
            "https://jobs.example.com/Path/A?x=1"
        );
    }

    #[test]
    fn rejects_non_https() {
        for u in [
            "http://example.com",
            "ftp://example.com",
            "example.com",
            "javascript:alert(1)",
            "https:/example.com",
            "//example.com",
        ] {
            assert_eq!(err(u), UrlError::NotHttps, "{u}");
        }
    }

    #[test]
    fn rejects_empty_and_oversized() {
        assert_eq!(err(""), UrlError::Empty);
        assert_eq!(
            err(&format!("https://example.com/{}", "a".repeat(2100))),
            UrlError::TooLong
        );
    }

    #[test]
    fn rejects_userinfo_tricks() {
        assert_eq!(
            err("https://careers.google.com@evil.com/jobs"),
            UrlError::UserInfo
        );
        assert_eq!(err("https://user:pw@example.com/"), UrlError::UserInfo);
        assert_eq!(err("https://example.com@evil.com"), UrlError::UserInfo);
    }

    #[test]
    fn rejects_ip_addresses() {
        for u in [
            "https://127.0.0.1/",
            "https://192.168.1.10/jobs",
            "https://8.8.8.8",
            "https://[::1]/",
            "https://[2001:db8::1]:443/",
            "https://0x7f.0.0.1/",
            "https://127.1/",
        ] {
            assert_eq!(err(u), UrlError::IpAddress, "{u}");
        }
    }

    #[test]
    fn rejects_local_and_internal_names() {
        for u in [
            "https://localhost/",
            "https://printer.local/",
            "https://intranet.corp/",
            "https://service.internal/",
        ] {
            let e = err(u);
            assert!(
                matches!(e, UrlError::LocalName | UrlError::BadHost),
                "{u}: {e:?}"
            );
        }
        assert_eq!(err("https://host.internal/"), UrlError::LocalName);
    }

    #[test]
    fn rejects_punycode_lookalikes() {
        assert_eq!(err("https://xn--pple-43d.com/"), UrlError::Punycode);
        assert_eq!(err("https://www.xn--80ak6aa92e.com/"), UrlError::Punycode);
    }

    #[test]
    fn rejects_non_ascii_and_whitespace_and_control_characters() {
        for u in [
            "https://exämple.com/",
            "https://example.com/a b",
            "https://example.com/\u{1b}[31m",
            "https://example.com/\n",
            " https://example.com",
            "https://example.com/\u{202E}",
        ] {
            assert_eq!(err(u), UrlError::ForbiddenCharacters, "{u:?}");
        }
    }

    #[test]
    fn rejects_backslash_tricks() {
        assert_eq!(
            err("https://evil.com\\@good.com/"),
            UrlError::ForbiddenCharacters
        );
        assert_eq!(
            err("https://example.com/a\\b"),
            UrlError::ForbiddenCharacters
        );
    }

    #[test]
    fn rejects_unusual_ports() {
        assert_eq!(err("https://example.com:8443/"), UrlError::BadPort);
        assert_eq!(err("https://example.com:80/"), UrlError::BadPort);
        assert_eq!(err("https://example.com:/"), UrlError::BadPort);
    }

    #[test]
    fn rejects_malformed_hosts() {
        for u in [
            "https:///path",
            "https://example/",
            "https://-bad.com/",
            "https://bad-.com/",
            "https://ex..ample.com/",
            "https://.example.com/",
            "https://exa_mple.com/",
            "https://example.c/",
            "https://example.c0m/",
            "https://exam%70le.com/",
        ] {
            let e = err(u);
            assert!(
                matches!(e, UrlError::BadHost | UrlError::ForbiddenCharacters),
                "{u}: {e:?}"
            );
        }
    }

    #[test]
    fn trust_matches_domain_and_subdomains_only() {
        let t = |u: &str| ok(u).trust(&[]);
        assert_eq!(t("https://boards.greenhouse.io/x"), TrustTier::Trusted);
        assert_eq!(t("https://greenhouse.io/x"), TrustTier::Trusted);
        assert_eq!(t("https://acme.lever.co/x"), TrustTier::Trusted);
        // Look-alikes and suffix tricks are NOT trusted.
        assert_eq!(t("https://greenhouse.io.evil.com/x"), TrustTier::Unknown);
        assert_eq!(t("https://evilgreenhouse.io/x"), TrustTier::Unknown);
        assert_eq!(t("https://notlever.co/x"), TrustTier::Unknown);
        assert_eq!(t("https://example.com/x"), TrustTier::Unknown);
    }

    #[test]
    fn user_supplied_trusted_domains_work() {
        let extra = vec!["careers.acme.com".to_string()];
        assert_eq!(
            ok("https://careers.acme.com/jobs/1").trust(&extra),
            TrustTier::Trusted
        );
        assert_eq!(
            ok("https://evil-careers.acme.com.evil.net/").trust(&extra),
            TrustTier::Unknown
        );
    }

    #[test]
    fn never_panics_on_arbitrary_short_inputs() {
        let alphabet: Vec<char> = "ht ps:/@.[]\\-%xn0é".chars().collect();
        let mut state = 12345u64;
        for _ in 0..20_000 {
            let mut s = String::new();
            for _ in 0..(state % 20) {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                s.push(alphabet[((state >> 33) as usize) % alphabet.len()]);
            }
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let _ = parse_https_url(&s);
            let _ = parse_https_url(&format!("https://{s}"));
        }
    }
}

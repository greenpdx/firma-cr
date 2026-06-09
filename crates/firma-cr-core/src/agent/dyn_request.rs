//! Parse an incoming `/dyn/<action>?<query>` request into its action, env, and
//! params. Pure (no I/O, no card) — the executable contract for the agent's
//! routing layer. Protocol per firma-cr-analysis/reports/29:
//!   GET/POST http://127.0.0.1:41231/dyn/<action>?env=<envId>[&k=v…]
//! with keys/values percent-encoded by the browser's `encodeURIComponent`.

use std::collections::BTreeMap;

/// A parsed `/dyn/<action>?<query>` request. `env` is lifted out of the params
/// because every authenticated call carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynRequest {
    pub action: String,
    pub env: Option<String>,
    pub params: BTreeMap<String, String>,
}

impl DynRequest {
    /// Parse a request target of the form `/dyn/<action>[?k=v&…]`. Keys and
    /// values are percent-decoded. Returns `None` if the path isn't under
    /// `/dyn/` or the action is empty.
    pub fn parse(target: &str) -> Option<DynRequest> {
        let path = target.strip_prefix('/').unwrap_or(target);
        let rest = path.strip_prefix("dyn/")?;
        let (action_raw, query) = rest.split_once('?').unwrap_or((rest, ""));
        if action_raw.is_empty() {
            return None;
        }
        let action = percent_decode(action_raw);

        let mut params = BTreeMap::new();
        let mut env = None;
        for pair in query.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode(k);
            let val = percent_decode(v);
            if key == "env" {
                env = Some(val);
            } else {
                params.insert(key, val);
            }
        }
        Some(DynRequest { action, env, params })
    }

    pub fn param(&self, k: &str) -> Option<&str> {
        self.params.get(k).map(String::as_str)
    }
}

/// Percent-decode (`%XX`) per `encodeURIComponent`. A literal `+` is kept as
/// `+` (encodeURIComponent encodes space as `%20`, not `+`), so base64 values
/// survive intact.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            match (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                _ => {}
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_action_env_and_params() {
        let r = DynRequest::parse("/dyn/login?env=ABC123&token=0&pin=0").unwrap();
        assert_eq!(r.action, "login");
        assert_eq!(r.env.as_deref(), Some("ABC123"));
        assert_eq!(r.param("token"), Some("0"));
        assert_eq!(r.param("pin"), Some("0"));
        // env must be lifted out of the generic params:
        assert_eq!(r.param("env"), None);
    }

    #[test]
    fn no_query_means_no_params_no_env() {
        let r = DynRequest::parse("/dyn/get_readers").unwrap();
        assert_eq!(r.action, "get_readers");
        assert_eq!(r.env, None);
        assert!(r.params.is_empty());
    }

    #[test]
    fn percent_decodes_json_param() {
        // files = encodeURIComponent('["a.pdf"]') = %5B%22a.pdf%22%5D
        let r = DynRequest::parse(
            "/dyn/cryptoshell_build?env=E&type=SIGN&files=%5B%22a.pdf%22%5D",
        )
        .unwrap();
        assert_eq!(r.action, "cryptoshell_build");
        assert_eq!(r.param("type"), Some("SIGN"));
        assert_eq!(r.param("files"), Some(r#"["a.pdf"]"#));
    }

    #[test]
    fn preserves_base64_encrypted_pin() {
        // encodeURIComponent of base64 turns + / = into %2B %2F %3D
        let r = DynRequest::parse("/dyn/login?env=E&e=YWJj%2Bd%2F0%3D").unwrap();
        assert_eq!(r.param("e"), Some("YWJj+d/0="));
    }

    #[test]
    fn trailing_equals_is_part_of_value() {
        // base64 padding '=' may also arrive unencoded
        let r = DynRequest::parse("/dyn/login?env=E&e=AAA=").unwrap();
        assert_eq!(r.param("e"), Some("AAA="));
    }

    #[test]
    fn rejects_non_dyn_paths_and_empty_action() {
        assert!(DynRequest::parse("/index.html").is_none());
        assert!(DynRequest::parse("/scripts/token.js").is_none());
        assert!(DynRequest::parse("/dyn/").is_none());
        assert!(DynRequest::parse("/dyn/?env=E").is_none());
    }

    #[test]
    fn tolerates_missing_leading_slash_and_empty_pairs() {
        let r = DynRequest::parse("dyn/connect?env=E&&reader=").unwrap();
        assert_eq!(r.action, "connect");
        assert_eq!(r.env.as_deref(), Some("E"));
        assert_eq!(r.param("reader"), Some(""));
    }

    #[test]
    fn incomplete_percent_escape_is_literal() {
        let r = DynRequest::parse("/dyn/x?env=E&a=50%").unwrap();
        assert_eq!(r.param("a"), Some("50%"));
    }
}

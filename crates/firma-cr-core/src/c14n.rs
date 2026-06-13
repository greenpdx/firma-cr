// SPDX-License-Identifier: GPL-3.0-or-later
//! Exclusive XML Canonicalization 1.0 (RFC 3741 / W3C
//! xml-exc-c14n#).
//!
//! Produces the canonical octet stream the XMLDSig SignedInfo /
//! Reference verifiers expect. Implementation choices:
//!
//!   * UTF-8 throughout — input is expected to be valid UTF-8.
//!   * XML declaration and DOCTYPE stripped.
//!   * Empty-element tags expanded: `<foo/>` → `<foo></foo>`.
//!   * Attribute values quoted with `"`; specials escaped as
//!     `&amp; &lt; &quot;` and whitespace as uppercase-hex character
//!     references `&#x9; &#xA; &#xD;` (text content escapes
//!     `&amp; &lt; &gt; &#xD;`), per the C14N spec.
//!   * Attributes sorted: namespace decls first by local name
//!     ordering, then non-namespace attributes by (namespace URI,
//!     local name).
//!   * Exclusive namespace handling: an element only emits the
//!     namespace declarations actually used by it (its prefix or
//!     unprefixed default) and not those inherited from ancestors,
//!     unless they're listed in `InclusiveNamespaces` PrefixList
//!     (we accept an empty list for now — sufficient for BCCR's
//!     XAdES usage).
//!   * Whitespace inside element content is preserved verbatim.
//!     CDATA sections are inlined as text (the canonical form has
//!     no CDATA).
//!
//! This is a hand-rolled implementation, but it is hardened against
//! adversarial XML (see [`reject_unsafe_xml`]: fails closed on
//! DTD/DOCTYPE and non-predefined entities) and differentially
//! validated against the libxml2 reference (`xmllint --exc-c14n`) by
//! the committed corpus in `tests/c14n_vectors/`. Known remaining
//! gap: it does not emit `xmlns=""` to undeclare an inherited default
//! namespace, which BCCR-shaped XAdES never requires.

use std::collections::BTreeMap;

use xml::reader::{EventReader, XmlEvent};
use xml::name::OwnedName;
use xml::namespace::Namespace;

use crate::error::{Error, Result};

/// Canonicalize an XML fragment using Exclusive C14N 1.0.
/// Returns the octet stream (UTF-8 bytes) the signer feeds into the
/// hash.
/// Fail closed on the adversarial-XML constructs canonicalization must not paper
/// over: a DTD/`DOCTYPE` or entity declaration (the XXE / billion-laughs vector —
/// without a DTD no custom entity can be defined), and any non-predefined entity
/// reference. Only the five predefined entities and numeric character references
/// are allowed; `&` inside comments and CDATA is literal and skipped. This closes
/// the "do NOT use for adversarial XML inputs" gap the hand-rolled c14n had.
fn reject_unsafe_xml(xml: &[u8]) -> Result<()> {
    let contains = |pat: &[u8]| xml.windows(pat.len()).any(|w| w == pat);
    if contains(b"<!DOCTYPE") || contains(b"<!ENTITY") {
        return Err(Error::Xml(
            "DTD/DOCTYPE or entity declaration not allowed in signed XML".into(),
        ));
    }
    let n = xml.len();
    let mut i = 0;
    while i < n {
        if xml[i..].starts_with(b"<!--") {
            // Skip to the end of the comment; `&` inside is literal.
            i = xml[i + 4..]
                .windows(3)
                .position(|w| w == b"-->")
                .map(|p| i + 4 + p + 3)
                .unwrap_or(n);
            continue;
        }
        if xml[i..].starts_with(b"<![CDATA[") {
            i = xml[i + 9..]
                .windows(3)
                .position(|w| w == b"]]>")
                .map(|p| i + 9 + p + 3)
                .unwrap_or(n);
            continue;
        }
        if xml[i] == b'&' {
            let rest = &xml[i + 1..];
            let semi = rest
                .iter()
                .position(|&b| b == b';')
                .ok_or_else(|| Error::Xml("unterminated entity reference".into()))?;
            let name = &rest[..semi];
            let allowed = matches!(name, b"amp" | b"lt" | b"gt" | b"quot" | b"apos")
                || name.first() == Some(&b'#'); // numeric character reference
            if !allowed {
                return Err(Error::Xml(
                    "non-predefined XML entity reference not allowed in signed XML".into(),
                ));
            }
            i += 1 + semi + 1;
            continue;
        }
        i += 1;
    }
    Ok(())
}

pub fn excl_c14n(xml: &[u8]) -> Result<Vec<u8>> {
    reject_unsafe_xml(xml)?;
    let reader = EventReader::new(xml);
    let mut out = Vec::with_capacity(xml.len() + 64);
    // Stack of "namespace (prefix, uri) pairs rendered at each open element" —
    // used to skip re-emitting an inherited declaration at a child, but only
    // when both the prefix AND the URI match (a child that redefines the prefix
    // / default namespace must re-render it).
    let mut rendered_stack: Vec<Vec<(String, String)>> = Vec::new();

    for ev in reader {
        match ev.map_err(|e| Error::Xml(format!("XML parse: {e}")))? {
            XmlEvent::StartElement { name, attributes, namespace } => {
                let rendered_here = emit_open_tag(
                    &mut out,
                    &name,
                    &attributes,
                    &namespace,
                    &rendered_stack,
                )?;
                rendered_stack.push(rendered_here);
            }
            XmlEvent::EndElement { name } => {
                out.extend_from_slice(b"</");
                emit_qname(&mut out, &name);
                out.push(b'>');
                rendered_stack.pop();
            }
            XmlEvent::Characters(text) | XmlEvent::CData(text) => {
                emit_text(&mut out, &text);
            }
            XmlEvent::Whitespace(text) => {
                // Per C14N, significant whitespace inside elements
                // is preserved.
                out.extend_from_slice(text.as_bytes());
            }
            XmlEvent::ProcessingInstruction { name, data } => {
                out.extend_from_slice(b"<?");
                out.extend_from_slice(name.as_bytes());
                if let Some(d) = data {
                    if !d.is_empty() {
                        out.push(b' ');
                        out.extend_from_slice(d.as_bytes());
                    }
                }
                out.extend_from_slice(b"?>");
            }
            XmlEvent::Comment(_) => {
                // c14n: comments NOT included in the default profile
                // (with-comments is a separate algorithm).
            }
            XmlEvent::StartDocument { .. } | XmlEvent::EndDocument => {
                // Discard the XML declaration per c14n.
            }
            _ => {
                // Doctype / future xml-rs variants — ignore for c14n.
            }
        }
    }
    Ok(out)
}

fn emit_open_tag(
    out: &mut Vec<u8>,
    name: &OwnedName,
    attributes: &[xml::attribute::OwnedAttribute],
    namespace: &Namespace,
    rendered_stack: &[Vec<(String, String)>],
) -> Result<Vec<(String, String)>> {
    out.push(b'<');
    emit_qname(out, name);

    // Collect attributes:
    //   bucket A — namespace declarations (xmlns / xmlns:prefix)
    //   bucket B — regular attributes
    // Both buckets sorted per c14n.
    let mut ns_decls: BTreeMap<String, String> = BTreeMap::new();
    let mut attrs: BTreeMap<(String, String), String> = BTreeMap::new();
    for a in attributes {
        let local = a.name.local_name.clone();
        let uri = a.name.namespace.clone().unwrap_or_default();
        attrs.insert((uri, local), a.value.clone());
    }

    // Walk the inherited namespace stack to know what's already
    // rendered (exclusive: only emit prefixes used by this element
    // OR its attributes).
    let mut used_prefixes: Vec<String> = Vec::new();
    if let Some(ref pfx) = name.prefix {
        used_prefixes.push(pfx.clone());
    } else if name.namespace.is_some() {
        used_prefixes.push(String::new()); // default namespace usage
    }
    for a in attributes {
        if let Some(p) = &a.name.prefix {
            used_prefixes.push(p.clone());
        }
    }

    for prefix in &used_prefixes {
        if let Some(uri) = namespace.0.get(prefix.as_str()) {
            if uri.is_empty() {
                continue;
            }
            // Exclusive c14n: emit this namespace node unless the *nearest*
            // output ancestor that rendered the same prefix rendered the same
            // URI. Comparing the prefix alone (the old behavior) wrongly dropped
            // a child's redefinition of an inherited prefix / default namespace.
            let ancestor_uri = rendered_stack
                .iter()
                .rev()
                .find_map(|set| set.iter().find(|(p, _)| p == prefix).map(|(_, u)| u.as_str()));
            if ancestor_uri == Some(uri.as_str()) {
                continue;
            }
            ns_decls.insert(prefix.clone(), uri.clone());
        }
    }

    // Emit ns_decls (sorted by prefix; default namespace `xmlns=""`
    // appears under empty-string key which sorts first).
    for (prefix, uri) in &ns_decls {
        out.push(b' ');
        if prefix.is_empty() {
            out.extend_from_slice(b"xmlns=\"");
        } else {
            out.extend_from_slice(b"xmlns:");
            out.extend_from_slice(prefix.as_bytes());
            out.extend_from_slice(b"=\"");
        }
        emit_attr_value(out, uri);
        out.push(b'"');
    }

    // Regular attributes (sorted).
    for ((ns_uri, local), value) in &attrs {
        out.push(b' ');
        // qname: if attribute belongs to a namespace, we need its
        // prefix. Look it up in the active mapping.
        if !ns_uri.is_empty() {
            // Find the prefix that maps to this URI in our namespace
            // chain (this element + ancestors).
            let pfx = lookup_prefix_for_uri(namespace, ns_uri);
            if !pfx.is_empty() {
                out.extend_from_slice(pfx.as_bytes());
                out.push(b':');
            }
        }
        out.extend_from_slice(local.as_bytes());
        out.extend_from_slice(b"=\"");
        emit_attr_value(out, value);
        out.push(b'"');
    }

    out.push(b'>');

    Ok(ns_decls.into_iter().collect())
}

fn lookup_prefix_for_uri(namespace: &Namespace, uri: &str) -> String {
    for (pfx, u) in namespace.0.iter() {
        if u == uri {
            return pfx.to_string();
        }
    }
    String::new()
}

fn emit_qname(out: &mut Vec<u8>, name: &OwnedName) {
    if let Some(p) = &name.prefix {
        if !p.is_empty() {
            out.extend_from_slice(p.as_bytes());
            out.push(b':');
        }
    }
    out.extend_from_slice(name.local_name.as_bytes());
}

fn emit_attr_value(out: &mut Vec<u8>, v: &str) {
    for c in v.chars() {
        match c {
            // C14N attribute-value escaping: &amp; &lt; &quot; and the
            // whitespace chars as *uppercase hex* character references
            // (&#x9; &#xA; &#xD;), NOT decimal. `>` is not escaped here.
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\t' => out.extend_from_slice(b"&#x9;"),
            '\n' => out.extend_from_slice(b"&#xA;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            _ => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

fn emit_text(out: &mut Vec<u8>, v: &str) {
    for c in v.chars() {
        match c {
            // C14N text-content escaping: &amp; &lt; &gt; and #xD as the
            // uppercase-hex character reference &#xD;. Tab and newline are
            // preserved verbatim in text content.
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            _ => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c14n(input: &str) -> String {
        String::from_utf8(excl_c14n(input.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn xml_decl_stripped() {
        let input = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a/>";
        assert_eq!(c14n(input), "<a></a>");
    }

    #[test]
    fn empty_element_expanded() {
        assert_eq!(c14n("<a/>"), "<a></a>");
    }

    #[test]
    fn text_specials_escaped() {
        let input = "<a>1 &amp; 2 &lt; 3</a>";
        let out = c14n(input);
        assert!(out.contains("&amp;"));
        assert!(out.contains("&lt;"));
    }

    #[test]
    fn attributes_sorted() {
        let input = r#"<a z="1" m="2" a="3"/>"#;
        let out = c14n(input);
        // After canonicalization: a, m, z (sorted by local name).
        assert_eq!(out, r#"<a a="3" m="2" z="1"></a>"#);
    }

    #[test]
    fn namespace_decl_emitted_at_use_site() {
        let input = r#"<root><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></root>"#;
        let out = c14n(input);
        assert!(out.contains("xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""));
    }

    #[test]
    fn comments_dropped() {
        assert_eq!(c14n("<a><!-- x --></a>"), "<a></a>");
    }

    // ---- fail-closed guards against adversarial XML ----

    #[test]
    fn rejects_doctype() {
        assert!(excl_c14n(b"<!DOCTYPE a><a/>").is_err());
    }

    #[test]
    fn rejects_entity_declaration_and_xxe() {
        // billion-laughs / XXE substrate: declaring entities requires a DTD.
        let x = br#"<!DOCTYPE a [ <!ENTITY x "expanded"> ]><a>&x;</a>"#;
        assert!(excl_c14n(x).is_err());
    }

    #[test]
    fn rejects_custom_entity_reference() {
        assert!(excl_c14n(b"<a>&xxe;</a>").is_err());
    }

    #[test]
    fn allows_predefined_and_numeric_entities() {
        assert!(excl_c14n("<a>&amp; &lt; &gt; &#169; &#xA9;</a>".as_bytes()).is_ok());
    }

    #[test]
    fn ampersand_inside_cdata_does_not_trip_guard() {
        // `&` (and even `&custom;`) inside CDATA is literal — the guard must skip
        // it rather than reject the whole document.
        assert!(excl_c14n("<a><![CDATA[ a & b &custom; ]]></a>".as_bytes()).is_ok());
    }

    // ---- W3C Exclusive C14N 1.0 normative behaviors ----

    #[test]
    fn exclusive_drops_unused_ancestor_namespace() {
        // `unused` is declared on the ancestor but visibly utilized by no element
        // in the node-set → Exclusive C14N must NOT render it; only `a` (used by
        // a:b) survives. This is the defining property of *exclusive* c14n.
        let input = r#"<root xmlns:unused="urn:unused"><a:b xmlns:a="urn:a">t</a:b></root>"#;
        let out = c14n(input);
        assert!(!out.contains("unused"), "exclusive c14n must drop the unused ns: {out}");
        assert!(out.contains(r#"xmlns:a="urn:a""#), "used ns must be kept: {out}");
    }

    #[test]
    fn canonical_form_is_idempotent() {
        // The canonical form is a fixed point: canonicalizing it again is identity.
        for x in [
            r#"<?xml version="1.0"?><r z="1" a="2"><c/></r>"#,
            r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Reference URI=""></ds:Reference></ds:SignedInfo>"#,
        ] {
            let once = c14n(x);
            let twice = c14n(&once);
            assert_eq!(once, twice, "c14n not idempotent for input: {x}");
        }
    }
}

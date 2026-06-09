//! Exclusive XML Canonicalization 1.0 (RFC 3741 / W3C
//! xml-exc-c14n#).
//!
//! Produces the canonical octet stream the XMLDSig SignedInfo /
//! Reference verifiers expect. Implementation choices:
//!
//!   * UTF-8 throughout — input is expected to be valid UTF-8.
//!   * XML declaration and DOCTYPE stripped.
//!   * Empty-element tags expanded: `<foo/>` → `<foo></foo>`.
//!   * Attribute values quoted with `"`; the five specials are
//!     escaped (`&amp; &lt; &gt; &quot; &#9; &#10; &#13;` per the
//!     spec).
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
//! This is a hand-rolled implementation; do NOT use it for adversarial
//! XML inputs (no entity expansion guards, no namespace remapping
//! across `xml:base`). For BCCR-shaped signed XML (small, well-
//! formed, no DTDs) it's adequate. A full XML Signature verifier
//! covering every C14N edge case is a fast-follow.

use std::collections::BTreeMap;

use xml::reader::{EventReader, XmlEvent};
use xml::name::OwnedName;
use xml::namespace::Namespace;

use crate::error::{Error, Result};

/// Canonicalize an XML fragment using Exclusive C14N 1.0.
/// Returns the octet stream (UTF-8 bytes) the signer feeds into the
/// hash.
pub fn excl_c14n(xml: &[u8]) -> Result<Vec<u8>> {
    let reader = EventReader::new(xml);
    let mut out = Vec::with_capacity(xml.len() + 64);
    // Stack of "namespace prefixes rendered at each open element" —
    // used to skip re-emitting an inherited prefix at a child.
    let mut rendered_stack: Vec<Vec<String>> = Vec::new();

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
    rendered_stack: &[Vec<String>],
) -> Result<Vec<String>> {
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
            // Skip if already rendered by an ancestor.
            let already = rendered_stack
                .iter()
                .any(|set| set.iter().any(|p| p == prefix));
            if already {
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

    Ok(ns_decls.into_keys().collect())
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
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\t' => out.extend_from_slice(b"&#9;"),
            '\n' => out.extend_from_slice(b"&#10;"),
            '\r' => out.extend_from_slice(b"&#13;"),
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
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '\r' => out.extend_from_slice(b"&#13;"),
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
}

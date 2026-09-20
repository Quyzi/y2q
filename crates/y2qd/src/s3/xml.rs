//! Minimal XML writer and reader for the S3 gateway.
//!
//! Not a general-purpose XML library: the writer emits only the flat
//! `<tag>value</tag>` shapes S3 responses need, and the reader is a tag
//! scanner sufficient for the two XML request bodies S3 actually defines
//! (`DeleteObjects`, `CompleteMultipartUpload`) — it ignores namespaces,
//! tolerates (but does not interpret) attributes, and never recurses beyond
//! the shape the caller asks for.

/// Maximum accepted input size for [`text_elements`]/[`nested_elements`].
/// Any larger request body is almost certainly abuse, not a legitimate
/// `DeleteObjects`/`CompleteMultipartUpload` request (both cap out well
/// under this at their own 1000-key / 10000-part limits).
pub const MAX_XML_BYTES: usize = 1024 * 1024;

/// Errors from the XML tag scanner. Never panics on malformed input.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum XmlError {
    #[error("request body exceeds the maximum XML size (1 MiB)")]
    TooLarge,
    #[error("malformed XML: unterminated <{0}> element")]
    Unterminated(String),
}

/// Append `<?xml version="1.0" encoding="UTF-8"?>` (no trailing newline).
pub fn header(out: &mut String) {
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
}

/// Append `<name>escaped(value)</name>`.
pub fn tag(out: &mut String, name: &str, value: &str) {
    out.push('<');
    out.push_str(name);
    out.push('>');
    out.push_str(&escape(value));
    out.push_str("</");
    out.push_str(name);
    out.push('>');
}

/// Append `<name>value</name>` for any `Display` value that needs no
/// escaping (integers, booleans).
pub fn tag_num<T: std::fmt::Display>(out: &mut String, name: &str, value: T) {
    out.push('<');
    out.push_str(name);
    out.push('>');
    out.push_str(&value.to_string());
    out.push_str("</");
    out.push_str(name);
    out.push('>');
}

/// Escape `& < > " '` for inclusion as XML 1.0 element text. S3 keys are
/// arbitrary UTF-8 and may contain bytes XML 1.0 cannot represent at all
/// (C0 control characters other than tab/LF/CR) — those are replaced with
/// U+FFFD here. A caller whose keys may contain such bytes must instead set
/// `EncodingType=url` and percent-encode the value rather than relying on
/// this function.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(ch),
            c if (c as u32) < 0x20 => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

/// Decode the five predefined XML entities (`&amp; &lt; &gt; &quot; &apos;`)
/// in a single left-to-right pass — never sequential `str::replace` calls,
/// which would double-decode a literal `&amp;lt;` (meaning the text
/// `&lt;`) into `<`.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        if let Some(r) = rest.strip_prefix("&amp;") {
            out.push('&');
            i = s.len() - r.len();
            continue;
        }
        if let Some(r) = rest.strip_prefix("&lt;") {
            out.push('<');
            i = s.len() - r.len();
            continue;
        }
        if let Some(r) = rest.strip_prefix("&gt;") {
            out.push('>');
            i = s.len() - r.len();
            continue;
        }
        if let Some(r) = rest.strip_prefix("&quot;") {
            out.push('"');
            i = s.len() - r.len();
            continue;
        }
        if let Some(r) = rest.strip_prefix("&apos;") {
            out.push('\'');
            i = s.len() - r.len();
            continue;
        }
        let ch = rest
            .chars()
            .next()
            .expect("i < s.len() guarantees a next char");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Find the next `<name ...>` or `<name>` open tag at or after byte offset
/// `from`, tolerating (and skipping) attributes and a self-closing `/`
/// before `>`. Returns `(tag_start, content_start)`: the byte offset of the
/// leading `<` and the byte offset immediately after the tag's closing `>`.
/// Does not match `<nameFoo...>` — the character immediately after `name`
/// must be `>`, whitespace, or `/`.
fn find_open_tag(xml: &str, name: &str, from: usize) -> Result<Option<(usize, usize)>, XmlError> {
    let pat = format!("<{name}");
    let mut search_from = from;
    loop {
        let Some(rel) = xml[search_from..].find(pat.as_str()) else {
            return Ok(None);
        };
        let start = search_from + rel;
        let after_name = start + pat.len();
        let boundary_ok = xml
            .as_bytes()
            .get(after_name)
            .is_some_and(|b| matches!(b, b'>' | b' ' | b'\t' | b'\n' | b'\r' | b'/'));
        if !boundary_ok {
            search_from = start + pat.len();
            continue;
        }
        let Some(gt_rel) = xml[after_name..].find('>') else {
            return Err(XmlError::Unterminated(name.to_owned()));
        };
        return Ok(Some((start, after_name + gt_rel + 1)));
    }
}

/// Extract the raw (not-yet-unescaped) inner text of every top-level
/// `<name>...</name>` occurrence in `xml`, in document order.
fn extract_blocks(xml: &str, name: &str) -> Result<Vec<String>, XmlError> {
    let close = format!("</{name}>");
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some((_, content_start)) = find_open_tag(xml, name, pos)? {
        let end_rel = xml[content_start..]
            .find(close.as_str())
            .ok_or_else(|| XmlError::Unterminated(name.to_owned()))?;
        out.push(xml[content_start..content_start + end_rel].to_owned());
        pos = content_start + end_rel + close.len();
    }
    Ok(out)
}

/// Return the unescaped text content of every `<name>` element in document
/// order. Sufficient for `DeleteObjects`'s `<Delete><Object><Key>k</Key></Object>...</Delete>`.
pub fn text_elements(xml: &str, name: &str) -> Result<Vec<String>, XmlError> {
    if xml.len() > MAX_XML_BYTES {
        return Err(XmlError::TooLarge);
    }
    Ok(extract_blocks(xml, name)?
        .into_iter()
        .map(|s| unescape(&s))
        .collect())
}

/// For each top-level `<outer>...</outer>` element, return the unescaped
/// text of each name in `inner` found as a direct child (in the order
/// `inner` lists them, `None` if that child is absent). Sufficient for
/// `CompleteMultipartUpload`'s `<Part><PartNumber>1</PartNumber><ETag>"..".</ETag></Part>`.
pub fn nested_elements(
    xml: &str,
    outer: &str,
    inner: &[&str],
) -> Result<Vec<Vec<Option<String>>>, XmlError> {
    if xml.len() > MAX_XML_BYTES {
        return Err(XmlError::TooLarge);
    }
    let blocks = extract_blocks(xml, outer)?;
    let mut out = Vec::with_capacity(blocks.len());
    for block in blocks {
        let mut row = Vec::with_capacity(inner.len());
        for name in inner {
            let vals = extract_blocks(&block, name)?;
            row.push(vals.into_iter().next().map(|s| unescape(&s)));
        }
        out.push(row);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_escapes_reserved_characters() {
        let mut out = String::new();
        tag(&mut out, "Key", "a&b<c>d\"e'f");
        assert_eq!(out, "<Key>a&amp;b&lt;c&gt;d&quot;e&apos;f</Key>");
    }

    #[test]
    fn text_elements_unescapes_entities() {
        let xml = "<Delete><Object><Key>a&amp;b</Key></Object><Object><Key>c&lt;d</Key></Object></Delete>";
        let keys = text_elements(xml, "Key").unwrap();
        assert_eq!(keys, vec!["a&b".to_owned(), "c<d".to_owned()]);
    }

    #[test]
    fn text_elements_tolerates_attributes() {
        let xml = r#"<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Object><Key>k</Key></Object></Delete>"#;
        let keys = text_elements(xml, "Key").unwrap();
        assert_eq!(keys, vec!["k".to_owned()]);
    }

    #[test]
    fn text_elements_errors_on_unterminated_tag() {
        let xml = "<Delete><Object><Key>k</Object></Delete>";
        assert_eq!(
            text_elements(xml, "Key"),
            Err(XmlError::Unterminated("Key".to_owned()))
        );
    }

    #[test]
    fn text_elements_errors_on_oversized_body() {
        let big = "x".repeat(MAX_XML_BYTES + 1);
        assert_eq!(text_elements(&big, "Key"), Err(XmlError::TooLarge));
    }

    #[test]
    fn text_elements_handles_amp_lt_literal_sequence() {
        // The literal text "&lt;" (already entity-escaped once) must decode
        // to the four characters `&lt;`, not to `<`.
        let xml = "<Key>&amp;lt;</Key>";
        assert_eq!(text_elements(xml, "Key").unwrap(), vec!["&lt;".to_owned()]);
    }

    #[test]
    fn nested_elements_parses_complete_multipart_upload() {
        let xml = "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"a\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"b\"</ETag></Part></CompleteMultipartUpload>";
        let parts = nested_elements(xml, "Part", &["PartNumber", "ETag"]).unwrap();
        assert_eq!(
            parts,
            vec![
                vec![Some("1".to_owned()), Some("\"a\"".to_owned())],
                vec![Some("2".to_owned()), Some("\"b\"".to_owned())],
            ]
        );
    }

    #[test]
    fn nested_elements_reports_missing_child_as_none() {
        let xml = "<Part><PartNumber>1</PartNumber></Part>";
        let parts = nested_elements(xml, "Part", &["PartNumber", "ETag"]).unwrap();
        assert_eq!(parts, vec![vec![Some("1".to_owned()), None]]);
    }
}

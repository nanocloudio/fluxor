//! `fluxor_contracts::observability`: OpenTelemetry severity numbers and the
//! attribute-key vocabulary.

use fluxor_contracts::observability::*;

#[test]
fn severity_numbers_match_otel() {
    assert_eq!(Severity::Trace.number(), 1);
    assert_eq!(Severity::Debug.number(), 5);
    assert_eq!(Severity::Info.number(), 9);
    assert_eq!(Severity::Warn.number(), 13);
    assert_eq!(Severity::Error.number(), 17);
    assert_eq!(Severity::Fatal.number(), 21);
}

#[test]
fn attribute_keys_are_unique_and_dotted_lowercase() {
    for (i, a) in ATTRIBUTE_KEYS.iter().enumerate() {
        assert!(
            a.contains('.')
                && a.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
            "attribute key {a:?} is not dotted lowercase"
        );
        for b in &ATTRIBUTE_KEYS[i + 1..] {
            assert_ne!(a, b, "duplicate attribute key {a:?}");
        }
    }
}

#[test]
fn fluxor_namespace_and_canonical_keys_validate() {
    assert!(is_valid_attribute_key("http.request.method"));
    assert!(is_valid_attribute_key("fluxor.anything.custom"));
    assert!(!is_valid_attribute_key("made.up.key"));
}

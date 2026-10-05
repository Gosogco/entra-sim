//! Unit tests for the `$filter` parser and evaluator.

use serde_json::json;

use crate::odata::eval::matches;
use crate::odata::filter::{ParseError, parse};

fn holds(filter: &str, object: &serde_json::Value) -> bool {
    let expr = parse(filter).unwrap_or_else(|error| panic!("parsing {filter:?}: {error}"));
    matches(&expr, object)
}

fn user() -> serde_json::Value {
    json!({
        "id": "0a1b",
        "displayName": "Alice Example",
        "userPrincipalName": "alice@contoso.com",
        "accountEnabled": true,
        "jobTitle": null,
        "employeeId": 42,
        "groupTypes": ["Unified"],
        "identities": [
            { "issuer": "contoso.com", "issuerAssignedId": "alice" }
        ],
        "verifiedDomains": { "name": "contoso.com" }
    })
}

#[test]
fn equality_on_a_string_property() {
    assert!(holds("displayName eq 'Alice Example'", &user()));
    assert!(!holds("displayName eq 'Bob Example'", &user()));
}

#[test]
fn string_comparison_ignores_case_as_entra_does() {
    // A client written against the real service relies on this.
    assert!(holds("userPrincipalName eq 'ALICE@CONTOSO.COM'", &user()));
    assert!(holds("startswith(displayName, 'alice')", &user()));
    assert!(holds(
        "endswith(userPrincipalName, '@CONTOSO.com')",
        &user()
    ));
    assert!(holds("contains(displayName, 'EXAMPLE')", &user()));
}

#[test]
fn boolean_and_numeric_comparisons() {
    assert!(holds("accountEnabled eq true", &user()));
    assert!(!holds("accountEnabled eq false", &user()));
    assert!(holds("employeeId gt 41", &user()));
    assert!(holds("employeeId ge 42", &user()));
    assert!(!holds("employeeId lt 42", &user()));
    assert!(holds("employeeId le 42", &user()));
    assert!(holds("employeeId ne 7", &user()));
}

#[test]
fn logical_operators_and_precedence() {
    // `and` binds tighter than `or`, so this holds on the strength of the second clause alone.
    assert!(holds(
        "displayName eq 'nobody' and accountEnabled eq true or employeeId eq 42",
        &user()
    ));
    assert!(!holds(
        "displayName eq 'nobody' or employeeId eq 7",
        &user()
    ));
    // Parentheses override it.
    assert!(!holds(
        "(displayName eq 'nobody' or employeeId eq 42) and accountEnabled eq false",
        &user()
    ));
    assert!(holds("not (employeeId eq 7)", &user()));
}

#[test]
fn an_absent_property_matches_nothing() {
    // Entra returns no results when filtering on a property the object lacks, rather than
    // treating the absence as a non-match that `ne` would then accept.
    assert!(!holds("department eq 'Sales'", &user()));
    assert!(!holds("department ne 'Sales'", &user()));
}

#[test]
fn an_explicit_null_is_distinguishable() {
    assert!(holds("jobTitle eq null", &user()));
    assert!(!holds("jobTitle ne null", &user()));
    assert!(holds("displayName ne null", &user()));
}

#[test]
fn in_lists() {
    assert!(holds("employeeId in (7, 42)", &user()));
    assert!(!holds("employeeId in (7, 8)", &user()));
    assert!(holds(
        "userPrincipalName in ('bob@contoso.com', 'ALICE@contoso.com')",
        &user()
    ));
}

#[test]
fn nested_property_paths() {
    assert!(holds("verifiedDomains/name eq 'contoso.com'", &user()));
    assert!(!holds("verifiedDomains/name eq 'other.com'", &user()));
}

#[test]
fn any_over_a_collection_of_scalars() {
    assert!(holds("groupTypes/any(t:t eq 'Unified')", &user()));
    assert!(!holds(
        "groupTypes/any(t:t eq 'DynamicMembership')",
        &user()
    ));
    // The bare form asks only whether the collection has any element.
    assert!(holds("groupTypes/any()", &user()));
}

#[test]
fn any_over_a_collection_of_objects() {
    // This is the shape the azuread provider uses to find a user by external identity.
    assert!(holds(
        "identities/any(i:i/issuer eq 'contoso.com' and i/issuerAssignedId eq 'alice')",
        &user()
    ));
    assert!(!holds(
        "identities/any(i:i/issuer eq 'contoso.com' and i/issuerAssignedId eq 'bob')",
        &user()
    ));
}

#[test]
fn any_on_a_missing_or_non_collection_property_is_false() {
    assert!(!holds("tags/any(t:t eq 'x')", &user()));
    assert!(!holds("displayName/any(t:t eq 'x')", &user()));
}

#[test]
fn quotes_are_escaped_by_doubling() {
    let object = json!({ "displayName": "O'Brien" });
    assert!(holds("displayName eq 'O''Brien'", &object));
}

#[test]
fn malformed_filters_are_rejected_rather_than_ignored() {
    // A filter that silently matched everything would be far worse than an error.
    for filter in [
        "displayName",
        "displayName eq",
        "displayName equals 'x'",
        "displayName eq 'unterminated",
        "(displayName eq 'x'",
        "displayName eq 'x' and",
        "startswith(displayName)",
        "displayName eq 'x' garbage",
    ] {
        assert!(
            matches!(parse(filter), Err(ParseError(_))),
            "{filter:?} should not parse"
        );
    }
}

#[test]
fn operators_and_keywords_are_case_insensitive() {
    assert!(holds("displayName EQ 'Alice Example'", &user()));
    assert!(holds("accountEnabled eq TRUE", &user()));
    assert!(holds(
        "employeeId eq 42 AND accountEnabled eq true",
        &user()
    ));
    assert!(holds("NOT (employeeId eq 7)", &user()));
}

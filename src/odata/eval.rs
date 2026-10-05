//! Evaluate a parsed `$filter` against a JSON object.
//!
//! String comparisons are case-insensitive. That is not an OData default, it is what Entra
//! does: `userPrincipalName eq 'ALICE@contoso.com'` matches the stored `alice@contoso.com`, and
//! a client written against the real service depends on it.

use std::collections::HashMap;

use serde_json::Value;

use crate::odata::filter::{CompareOp, Expr, Function, Operand};

/// Whether `object` satisfies `expr`.
pub fn matches(expr: &Expr, object: &Value) -> bool {
    let scope = Scope {
        object,
        variables: HashMap::new(),
    };
    evaluate(expr, &scope)
}

/// The object under test, plus any lambda variables currently bound.
struct Scope<'a> {
    object: &'a Value,
    variables: HashMap<&'a str, &'a Value>,
}

fn evaluate(expr: &Expr, scope: &Scope<'_>) -> bool {
    match expr {
        Expr::And(left, right) => evaluate(left, scope) && evaluate(right, scope),
        Expr::Or(left, right) => evaluate(left, scope) || evaluate(right, scope),
        Expr::Not(inner) => !evaluate(inner, scope),
        Expr::Compare { left, op, right } => {
            compare(&resolve(left, scope), *op, &resolve(right, scope))
        }
        Expr::Call { function, args } => {
            let haystack = resolve(&args[0], scope);
            let needle = resolve(&args[1], scope);
            match (as_string(&haystack), as_string(&needle)) {
                (Some(haystack), Some(needle)) => {
                    let haystack = haystack.to_lowercase();
                    let needle = needle.to_lowercase();
                    match function {
                        Function::StartsWith => haystack.starts_with(&needle),
                        Function::EndsWith => haystack.ends_with(&needle),
                        Function::Contains => haystack.contains(&needle),
                    }
                }
                _ => false,
            }
        }
        Expr::In { left, values } => {
            let subject = resolve(left, scope);
            values
                .iter()
                .any(|value| compare(&subject, CompareOp::Eq, &resolve(value, scope)))
        }
        Expr::Any {
            path,
            variable,
            predicate,
        } => {
            let Some(Value::Array(items)) = resolve_path(path, scope) else {
                return false;
            };
            match predicate {
                // `any()` with no predicate asks only whether the collection is non-empty.
                None => !items.is_empty(),
                Some(predicate) => items.iter().any(|item| {
                    let mut variables = scope.variables.clone();
                    variables.insert(variable.as_str(), item);
                    evaluate(
                        predicate,
                        &Scope {
                            object: scope.object,
                            variables,
                        },
                    )
                }),
            }
        }
    }
}

/// A resolved operand. `Missing` is distinct from `Null`: Graph treats an absent property as
/// not matching anything except an explicit `eq null`.
enum Resolved<'a> {
    Found(&'a Value),
    Literal(Value),
    Missing,
}

fn resolve<'a>(operand: &'a Operand, scope: &Scope<'a>) -> Resolved<'a> {
    match operand {
        Operand::Path(path) => match resolve_path(path, scope) {
            Some(value) => Resolved::Found(value),
            None => Resolved::Missing,
        },
        Operand::String(value) => Resolved::Literal(Value::String(value.clone())),
        Operand::Number(value) => Resolved::Literal(
            serde_json::Number::from_f64(*value).map_or(Value::Null, Value::Number),
        ),
        Operand::Bool(value) => Resolved::Literal(Value::Bool(*value)),
        Operand::Null => Resolved::Literal(Value::Null),
    }
}

/// Walk a property path, starting from a bound lambda variable when the first segment names one.
fn resolve_path<'a>(path: &[String], scope: &Scope<'a>) -> Option<&'a Value> {
    let (first, rest) = path.split_first()?;
    let mut current = match scope.variables.get(first.as_str()) {
        Some(bound) => *bound,
        None => scope.object.get(first)?,
    };
    for segment in rest {
        current = current.get(segment)?;
    }
    Some(current)
}

fn value_of<'a>(resolved: &'a Resolved<'a>) -> Option<&'a Value> {
    match resolved {
        Resolved::Found(value) => Some(value),
        Resolved::Literal(value) => Some(value),
        Resolved::Missing => None,
    }
}

fn as_string<'a>(resolved: &'a Resolved<'a>) -> Option<&'a str> {
    value_of(resolved)?.as_str()
}

fn compare(left: &Resolved<'_>, op: CompareOp, right: &Resolved<'_>) -> bool {
    let (Some(left), Some(right)) = (value_of(left), value_of(right)) else {
        // An absent property matches nothing, not even `ne`, which mirrors Entra: filtering on
        // a property the object does not have returns no results rather than all of them.
        return false;
    };

    match (left, right) {
        (Value::String(left), Value::String(right)) => {
            // Entra compares directory strings without regard to case.
            let ordering = left.to_lowercase().cmp(&right.to_lowercase());
            satisfies(ordering, op)
        }
        (Value::Number(left), Value::Number(right)) => match left.as_f64().zip(right.as_f64()) {
            Some((left, right)) => match left.partial_cmp(&right) {
                Some(ordering) => satisfies(ordering, op),
                None => false,
            },
            None => false,
        },
        (Value::Bool(left), Value::Bool(right)) => satisfies(left.cmp(right), op),
        (Value::Null, Value::Null) => matches!(op, CompareOp::Eq | CompareOp::Ge | CompareOp::Le),
        (Value::Null, _) | (_, Value::Null) => matches!(op, CompareOp::Ne),
        // Comparing a collection or object is not something Entra supports either.
        _ => false,
    }
}

fn satisfies(ordering: std::cmp::Ordering, op: CompareOp) -> bool {
    use std::cmp::Ordering::{Equal, Greater, Less};
    match op {
        CompareOp::Eq => ordering == Equal,
        CompareOp::Ne => ordering != Equal,
        CompareOp::Gt => ordering == Greater,
        CompareOp::Ge => matches!(ordering, Greater | Equal),
        CompareOp::Lt => ordering == Less,
        CompareOp::Le => matches!(ordering, Less | Equal),
    }
}

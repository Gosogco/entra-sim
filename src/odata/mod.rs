//! OData query options and collection responses.

pub mod eval;
pub mod filter;

#[cfg(test)]
mod tests;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::graph::error::GraphError;
use crate::odata::filter::Expr;

/// Graph's default page size for directory collections.
pub const DEFAULT_PAGE_SIZE: usize = 100;
/// Graph rejects `$top` above this.
pub const MAX_PAGE_SIZE: usize = 999;

/// The query options the simulator understands, as they arrive on the wire.
///
/// Field names carry the `$` prefix, so this deserialises straight from the query string.
#[derive(Debug, Default, Deserialize)]
pub struct RawQuery {
    #[serde(rename = "$filter")]
    pub filter: Option<String>,
    #[serde(rename = "$select")]
    pub select: Option<String>,
    #[serde(rename = "$orderby")]
    pub orderby: Option<String>,
    #[serde(rename = "$top")]
    pub top: Option<String>,
    #[serde(rename = "$skiptoken")]
    pub skiptoken: Option<String>,
    #[serde(rename = "$count")]
    pub count: Option<String>,
    #[serde(rename = "$expand")]
    pub expand: Option<String>,
    #[serde(rename = "$search")]
    pub search: Option<String>,
}

/// Validated query options.
#[derive(Debug, Default)]
pub struct Query {
    pub filter: Option<Expr>,
    pub select: Option<Vec<String>>,
    pub orderby: Option<Vec<OrderBy>>,
    pub top: usize,
    /// The object ID to resume after, decoded from `$skiptoken`.
    pub skip_after: Option<String>,
    pub count: bool,
    pub expand: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OrderBy {
    pub path: Vec<String>,
    pub descending: bool,
}

impl RawQuery {
    /// Validate the options, rejecting anything malformed the way Graph does.
    pub fn validate(self) -> Result<Query, GraphError> {
        let filter = match &self.filter {
            Some(raw) => Some(filter::parse(raw).map_err(|error| {
                GraphError::new(
                    StatusCode::BAD_REQUEST,
                    "Request_UnsupportedQuery",
                    format!(
                        "Unsupported or invalid query filter clause specified for property. {error}"
                    ),
                )
            })?),
            None => None,
        };

        let top = match &self.top {
            None => DEFAULT_PAGE_SIZE,
            Some(raw) => {
                let parsed: usize = raw
                    .trim()
                    .parse()
                    .map_err(|_| invalid_option("$top", raw))?;
                if parsed == 0 || parsed > MAX_PAGE_SIZE {
                    return Err(GraphError::new(
                        StatusCode::BAD_REQUEST,
                        "Request_BadRequest",
                        format!(
                            "Invalid value specified for property '$top'. Value must be between 1 and {MAX_PAGE_SIZE}."
                        ),
                    ));
                }
                parsed
            }
        };

        let count = match &self.count {
            None => false,
            Some(raw) => match raw.trim() {
                "true" => true,
                "false" => false,
                other => return Err(invalid_option("$count", other)),
            },
        };

        let skip_after = match &self.skiptoken {
            None => None,
            Some(raw) => Some(decode_skiptoken(raw)?),
        };

        if let Some(search) = &self.search {
            // Better to reject than to return unfiltered results that look like a match.
            return Err(GraphError::new(
                StatusCode::BAD_REQUEST,
                "Request_UnsupportedQuery",
                format!(
                    "The '$search' query option is not supported by this simulator: {search:?}"
                ),
            ));
        }

        Ok(Query {
            filter,
            select: self.select.as_deref().map(split_list),
            orderby: self.orderby.as_deref().map(parse_orderby).transpose()?,
            top,
            skip_after,
            count,
            expand: self.expand.as_deref().map(split_list).unwrap_or_default(),
        })
    }
}

fn invalid_option(option: &str, value: &str) -> GraphError {
    GraphError::new(
        StatusCode::BAD_REQUEST,
        "Request_BadRequest",
        format!("Invalid value {value:?} specified for property {option:?}."),
    )
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_orderby(raw: &str) -> Result<Vec<OrderBy>, GraphError> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let mut parts = entry.split_whitespace();
            let path = parts
                .next()
                .ok_or_else(|| invalid_option("$orderby", entry))?;
            let descending = match parts.next() {
                None | Some("asc") => false,
                Some("desc") => true,
                Some(other) => return Err(invalid_option("$orderby", other)),
            };
            if parts.next().is_some() {
                return Err(invalid_option("$orderby", entry));
            }
            Ok(OrderBy {
                path: path.split('/').map(str::to_string).collect(),
                descending,
            })
        })
        .collect()
}

/// `$skiptoken` is opaque to clients, so the simulator uses the last object ID it served,
/// base64url encoded. That keeps paging stable even when objects are added between pages.
pub fn encode_skiptoken(last_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(last_id.as_bytes())
}

fn decode_skiptoken(raw: &str) -> Result<String, GraphError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw.trim())
        .map_err(|_| invalid_option("$skiptoken", raw))?;
    String::from_utf8(bytes).map_err(|_| invalid_option("$skiptoken", raw))
}

/// Keep only the requested properties.
///
/// `id` is always retained: clients need it to address the object, and Graph returns it for
/// directory resources regardless of `$select`. Properties prefixed with `@odata.` are kept too,
/// since they are annotations rather than selectable properties.
pub fn project(object: &Value, select: &[String]) -> Value {
    let Some(fields) = object.as_object() else {
        return object.clone();
    };

    let mut out = Map::new();
    for (key, value) in fields {
        let wanted =
            key == "id" || key.starts_with("@odata.") || select.iter().any(|field| field == key);
        if wanted {
            out.insert(key.clone(), value.clone());
        }
    }
    Value::Object(out)
}

/// A Graph collection response.
#[derive(Debug, Serialize)]
pub struct Collection {
    #[serde(rename = "@odata.context")]
    pub context: String,
    #[serde(rename = "@odata.count", skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    pub value: Vec<Value>,
    #[serde(rename = "@odata.nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}

/// Apply `$filter`, `$orderby`, paging and `$select` to a collection.
///
/// Filtering happens here rather than in each handler so that no resource can forget it: a
/// collection that silently ignored `$filter` would return everything and look like a match.
///
/// `objects` must arrive ordered by object ID, which is how the store yields it; that ordering is
/// what makes `$skiptoken` resumable.
pub fn paginate(
    objects: Vec<Value>,
    query: &Query,
    context: String,
    next_link: impl FnOnce(&str) -> String,
) -> Collection {
    let mut matched = match &query.filter {
        Some(expr) => objects
            .into_iter()
            .filter(|object| eval::matches(expr, object))
            .collect(),
        None => objects,
    };

    // `$count` reports how many objects matched the filter, not how many exist.
    let total = matched.len();

    if let Some(order) = &query.orderby {
        sort_by(&mut matched, order);
    }

    // Resume after the last ID of the previous page. With an explicit `$orderby` the client has
    // asked for a different order, so resume by position within it instead.
    if let Some(after) = &query.skip_after {
        let resume_at = matched
            .iter()
            .position(|object| object["id"].as_str() == Some(after.as_str()))
            .map_or(0, |index| index + 1);
        matched.drain(..resume_at);
    }

    let has_more = matched.len() > query.top;
    matched.truncate(query.top);

    let next = has_more
        .then(|| matched.last().and_then(|object| object["id"].as_str()))
        .flatten()
        .map(next_link);

    if let Some(select) = &query.select {
        matched = matched
            .iter()
            .map(|object| project(object, select))
            .collect();
    }

    Collection {
        context,
        count: query.count.then_some(total),
        value: matched,
        next_link: next,
    }
}

fn sort_by(objects: &mut [Value], order: &[OrderBy]) {
    objects.sort_by(|left, right| {
        for key in order {
            let ordering = compare_at_path(left, right, &key.path);
            let ordering = if key.descending {
                ordering.reverse()
            } else {
                ordering
            };
            if ordering != std::cmp::Ordering::Equal {
                return ordering;
            }
        }
        std::cmp::Ordering::Equal
    });
}

fn compare_at_path(left: &Value, right: &Value, path: &[String]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let pick = |object: &Value| -> Option<Value> {
        let mut current = object;
        for segment in path {
            current = current.get(segment)?;
        }
        Some(current.clone())
    };
    match (pick(left), pick(right)) {
        (Some(Value::String(left)), Some(Value::String(right))) => {
            left.to_lowercase().cmp(&right.to_lowercase())
        }
        (Some(Value::Number(left)), Some(Value::Number(right))) => left
            .as_f64()
            .zip(right.as_f64())
            .and_then(|(left, right)| left.partial_cmp(&right))
            .unwrap_or(Ordering::Equal),
        (Some(Value::Bool(left)), Some(Value::Bool(right))) => left.cmp(&right),
        // Absent values sort last, as they do in Entra.
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        _ => Ordering::Equal,
    }
}

//! JSON batching: several Graph requests in one.
//!
//! Microsoft's JSON batching documentation: `POST /v1.0/$batch` (or `/beta/$batch`) takes
//! `requests`, each with an `id`, a `method`, a relative `url`, optional `headers` and `body`, and
//! optional `dependsOn`; "JSON batch requests are currently limited to 20 individual requests".
//! The answer is `responses`, each with the `id`, a `status`, `headers` and `body`. A malformed
//! batch is a 400; otherwise the batch is a 200 whatever its parts did, and "If an individual
//! request fails, any request that depends on that request fails with status code 424".
//!
//! Each request is run through the same router as a direct call, with the batch's own bearer
//! token, so routing, permission checks and OData behave identically.

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, Request, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use tower::ServiceExt;

use crate::auth::middleware::Caller;
use crate::graph::error::GraphError;
use crate::state::AppState;

/// Microsoft: "JSON batch requests are currently limited to 20 individual requests."
const MAX_REQUESTS: usize = 20;

/// The largest body a response in a batch is read up to.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

pub async fn batch(
    State(state): State<AppState>,
    // The batch itself needs a valid token; each request in it is then checked on its own.
    _caller: Caller,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response, GraphError> {
    let version = if uri.path().starts_with("/beta") {
        "/beta"
    } else {
        "/v1.0"
    };
    let requests = body
        .get("requests")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            GraphError::invalid_request("The batch request must contain a 'requests' array.")
        })?;
    if requests.len() > MAX_REQUESTS {
        return Err(GraphError::invalid_request(format!(
            "The batch contains {} requests; the limit is {MAX_REQUESTS}.",
            requests.len()
        )));
    }

    let parsed: Vec<BatchRequest> = requests
        .iter()
        .map(BatchRequest::parse)
        .collect::<Result<_, _>>()?;
    for (index, request) in parsed.iter().enumerate() {
        // "Must be unique in the batch, otherwise, the batch request fails with a 400 error
        // code." Ids are "Not case-sensitive".
        if parsed[..index]
            .iter()
            .any(|earlier| earlier.id.eq_ignore_ascii_case(&request.id))
        {
            return Err(GraphError::invalid_request(format!(
                "The batch contains the id {:?} more than once.",
                request.id
            )));
        }
    }
    for request in &parsed {
        if let Some(unknown) = request.depends_on.iter().find(|dependency| {
            !parsed
                .iter()
                .any(|known| known.id.eq_ignore_ascii_case(dependency))
        }) {
            return Err(GraphError::invalid_request(format!(
                "The request {:?} depends on {unknown:?}, which is not in the batch.",
                request.id
            )));
        }
    }

    let order = execution_order(&parsed)?;
    let authorization = headers.get(header::AUTHORIZATION).cloned();
    let router = crate::graph::router().with_state(state);
    let mut outcomes: Vec<(usize, u16, Value)> = Vec::with_capacity(parsed.len());

    for index in order {
        let request = &parsed[index];
        let failed_dependency = request.depends_on.iter().any(|dependency| {
            outcomes.iter().any(|(done, status, _)| {
                parsed[*done].id.eq_ignore_ascii_case(dependency) && *status >= 400
            })
        });
        let outcome = if failed_dependency {
            failure(
                &request.id,
                424,
                "FailedDependency",
                "A request this one depends on failed.",
            )
        } else {
            run(&router, version, request, authorization.clone()).await
        };
        outcomes.push((index, outcome.0, outcome.1));
    }

    // Responses come back in request order, which Microsoft allows ("might appear in a different
    // order") and which is the easiest for a reader.
    outcomes.sort_by_key(|(index, _, _)| *index);
    let responses: Vec<Value> = outcomes.into_iter().map(|(_, _, value)| value).collect();
    Ok(Json(json!({ "responses": responses })).into_response())
}

struct BatchRequest {
    id: String,
    method: Method,
    url: String,
    headers: Map<String, Value>,
    body: Option<Value>,
    depends_on: Vec<String>,
}

impl BatchRequest {
    fn parse(value: &Value) -> Result<Self, GraphError> {
        let text = |name: &str| value.get(name).and_then(Value::as_str);
        let id = text("id")
            .ok_or_else(|| GraphError::invalid_request("Every request in a batch needs an 'id'."))?
            .to_string();
        let method = text("method")
            .and_then(|method| Method::from_bytes(method.to_ascii_uppercase().as_bytes()).ok())
            .ok_or_else(|| {
                GraphError::invalid_request(format!("The request {id:?} needs a valid 'method'."))
            })?;
        let url = text("url")
            .ok_or_else(|| {
                GraphError::invalid_request(format!("The request {id:?} needs a 'url'."))
            })?
            .to_string();
        Ok(Self {
            id,
            method,
            url,
            headers: value
                .get("headers")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default(),
            body: value.get("body").cloned(),
            depends_on: value
                .get("dependsOn")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
        })
    }
}

/// An order in which every request runs after the ones it depends on.
fn execution_order(requests: &[BatchRequest]) -> Result<Vec<usize>, GraphError> {
    let mut done: Vec<usize> = Vec::with_capacity(requests.len());
    while done.len() < requests.len() {
        let ready = (0..requests.len()).find(|index| {
            !done.contains(index)
                && requests[*index].depends_on.iter().all(|dependency| {
                    done.iter()
                        .any(|finished| requests[*finished].id.eq_ignore_ascii_case(dependency))
                })
        });
        match ready {
            Some(index) => done.push(index),
            None => {
                return Err(GraphError::invalid_request(
                    "The requests in the batch depend on each other in a cycle.",
                ));
            }
        }
    }
    Ok(done)
}

/// Run one request through the Graph router and describe its response.
async fn run(
    router: &axum::Router,
    version: &str,
    request: &BatchRequest,
    authorization: Option<header::HeaderValue>,
) -> (u16, Value) {
    if request.url.contains("$batch") {
        return failure(
            &request.id,
            400,
            "BadRequest",
            "A batch cannot contain another batch.",
        );
    }
    // "When the body is supplied, a Content-Type header must be included."
    let content_type = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .and_then(|(_, value)| value.as_str());
    if request.body.is_some() && content_type.is_none() {
        return failure(
            &request.id,
            400,
            "BadRequest",
            "A request with a body must have a Content-Type header.",
        );
    }

    // "The relative resource URL for the individual request", with or without its leading slash.
    let path = format!(
        "{version}/{}",
        encode_unsafe(request.url.trim_start_matches('/'))
    );
    let mut builder = Request::builder().method(request.method.clone()).uri(path);
    if let Some(authorization) = authorization {
        builder = builder.header(header::AUTHORIZATION, authorization);
    }
    for (name, value) in &request.headers {
        if let Some(value) = value.as_str() {
            builder = builder.header(name.as_str(), value);
        }
    }
    let body = match &request.body {
        Some(body) => Body::from(body.to_string()),
        None => Body::empty(),
    };
    let Ok(built) = builder.body(body) else {
        return failure(
            &request.id,
            400,
            "BadRequest",
            "The request could not be built from the batch entry.",
        );
    };
    let Ok(response) = router.clone().oneshot(built).await;
    describe(&request.id, response).await
}

/// Percent-encode what a URI cannot carry as it is. Microsoft's own batching example writes
/// `$filter=city eq null` with plain spaces, so a client may send them.
fn encode_unsafe(url: &str) -> String {
    let mut out = String::with_capacity(url.len());
    for character in url.chars() {
        if character.is_ascii_graphic() && !"\"<>\\^`{|}".contains(character) {
            out.push(character);
        } else {
            let mut buffer = [0; 4];
            for byte in character.encode_utf8(&mut buffer).bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

async fn describe(id: &str, response: Response) -> (u16, Value) {
    let status = response.status().as_u16();
    let mut headers = Map::new();
    for (name, value) in response.headers() {
        if let Ok(value) = value.to_str() {
            headers.insert(name.as_str().to_string(), json!(value));
        }
    }
    let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
        .await
        .unwrap_or_default();
    let mut entry = json!({ "id": id, "status": status, "headers": headers });
    if !bytes.is_empty() {
        entry["body"] = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    }
    (status, entry)
}

fn failure(id: &str, status: u16, code: &str, message: &str) -> (u16, Value) {
    (
        status,
        json!({
            "id": id,
            "status": status,
            "headers": { "Content-Type": "application/json" },
            "body": { "error": { "code": code, "message": message } }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaces_and_unsafe_characters_are_encoded() {
        assert_eq!(
            encode_unsafe("users?$filter=city eq null&$top=1"),
            "users?$filter=city%20eq%20null&$top=1"
        );
        assert_eq!(
            encode_unsafe("groups?$search=\"a b\""),
            "groups?$search=%22a%20b%22"
        );
        assert_eq!(encode_unsafe("users/é"), "users/%C3%A9");
    }
}

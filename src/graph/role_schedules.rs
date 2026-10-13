//! Privileged Identity Management for directory roles: eligibilities, and active assignments
//! with a schedule.
//!
//! Per Microsoft's unifiedRoleEligibilityScheduleRequest and unifiedRoleAssignmentScheduleRequest
//! resources, a request's `action` is `adminAssign`, `adminUpdate`, `adminRemove`,
//! `adminExtend`, `adminRenew`, `selfActivate`, `selfDeactivate`, `selfExtend` or `selfRenew`. An
//! administrator makes a principal eligible for a role; the principal then activates it with a
//! `selfActivate` assignment request, which makes the role active for the requested time.
//!
//! A request creates or removes a schedule. As the azuread provider relies on, the schedule a
//! request creates has the same ID as the request. Requests and schedules are kept as Graph's
//! JSON. An active assignment schedule counts as holding the role for as long as it lasts, so it
//! shows in `wids`, in group claims and in conditional access.

use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Map, Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tracing::info;
use uuid::Uuid;

use crate::auth::middleware::Caller;
use crate::graph::directory_roles::templates;
use crate::graph::error::GraphError;
use crate::graph::{collection_response, object_response};
use crate::odata::RawQuery;
use crate::state::AppState;
use crate::store::Directory;
use crate::store::model::DirectoryRole;

/// Entra's default for how long an activation lasts when the request does not say.
const DEFAULT_ACTIVATION_HOURS: i64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Eligibility,
    Assignment,
}

impl Kind {
    fn requests(self) -> &'static str {
        match self {
            Self::Eligibility => "roleManagement/directory/roleEligibilityScheduleRequests",
            Self::Assignment => "roleManagement/directory/roleAssignmentScheduleRequests",
        }
    }

    fn schedules(self) -> &'static str {
        match self {
            Self::Eligibility => "roleManagement/directory/roleEligibilitySchedules",
            Self::Assignment => "roleManagement/directory/roleAssignmentSchedules",
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/roleManagement/directory/roleEligibilityScheduleRequests",
            get(list_eligibility_requests).post(create_eligibility_request),
        )
        .route(
            "/roleManagement/directory/roleEligibilityScheduleRequests/{id}",
            get(read_eligibility_request),
        )
        .route(
            "/roleManagement/directory/roleEligibilityScheduleRequests/{id}/cancel",
            post(cancel_eligibility_request),
        )
        .route(
            "/roleManagement/directory/roleEligibilitySchedules",
            get(list_eligibility_schedules),
        )
        .route(
            "/roleManagement/directory/roleEligibilitySchedules/{id}",
            get(read_eligibility_schedule),
        )
        .route(
            "/roleManagement/directory/roleAssignmentScheduleRequests",
            get(list_assignment_requests).post(create_assignment_request),
        )
        .route(
            "/roleManagement/directory/roleAssignmentScheduleRequests/{id}",
            get(read_assignment_request),
        )
        .route(
            "/roleManagement/directory/roleAssignmentScheduleRequests/{id}/cancel",
            post(cancel_assignment_request),
        )
        .route(
            "/roleManagement/directory/roleAssignmentSchedules",
            get(list_assignment_schedules),
        )
        .route(
            "/roleManagement/directory/roleAssignmentSchedules/{id}",
            get(read_assignment_schedule),
        )
}

fn requests(directory: &Directory, kind: Kind) -> &std::collections::BTreeMap<String, Value> {
    match kind {
        Kind::Eligibility => &directory.role_eligibility_schedule_requests,
        Kind::Assignment => &directory.role_assignment_schedule_requests,
    }
}

fn schedules(directory: &Directory, kind: Kind) -> &std::collections::BTreeMap<String, Value> {
    match kind {
        Kind::Eligibility => &directory.role_eligibility_schedules,
        Kind::Assignment => &directory.role_assignment_schedules,
    }
}

async fn list(
    state: &AppState,
    raw: RawQuery,
    kind: Kind,
    of_requests: bool,
) -> Result<axum::response::Response, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let (collection, entity_set) = if of_requests {
        (requests(&directory, kind), kind.requests())
    } else {
        (schedules(&directory, kind), kind.schedules())
    };
    let objects = collection.values().cloned().collect();
    Ok(collection_response(state, objects, &query, entity_set))
}

async fn read(
    state: &AppState,
    id: &str,
    raw: RawQuery,
    kind: Kind,
    of_requests: bool,
) -> Result<axum::response::Response, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let (collection, entity_set) = if of_requests {
        (requests(&directory, kind), kind.requests())
    } else {
        (schedules(&directory, kind), kind.schedules())
    };
    let object = collection
        .get(id)
        .cloned()
        .ok_or_else(|| GraphError::resource_not_found(id))?;
    Ok(object_response(state, object, &query, entity_set))
}

async fn list_eligibility_requests(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<axum::response::Response, GraphError> {
    list(&state, raw, Kind::Eligibility, true).await
}

async fn read_eligibility_request(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<axum::response::Response, GraphError> {
    read(&state, &id, raw, Kind::Eligibility, true).await
}

async fn list_eligibility_schedules(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<axum::response::Response, GraphError> {
    list(&state, raw, Kind::Eligibility, false).await
}

async fn read_eligibility_schedule(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<axum::response::Response, GraphError> {
    read(&state, &id, raw, Kind::Eligibility, false).await
}

async fn list_assignment_requests(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<axum::response::Response, GraphError> {
    list(&state, raw, Kind::Assignment, true).await
}

async fn read_assignment_request(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<axum::response::Response, GraphError> {
    read(&state, &id, raw, Kind::Assignment, true).await
}

async fn list_assignment_schedules(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<axum::response::Response, GraphError> {
    list(&state, raw, Kind::Assignment, false).await
}

async fn read_assignment_schedule(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<axum::response::Response, GraphError> {
    read(&state, &id, raw, Kind::Assignment, false).await
}

async fn create_eligibility_request(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, GraphError> {
    create(&state, &caller, body, Kind::Eligibility).await
}

async fn create_assignment_request(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, GraphError> {
    create(&state, &caller, body, Kind::Assignment).await
}

async fn cancel_eligibility_request(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, GraphError> {
    cancel(&state, &id, Kind::Eligibility).await
}

async fn cancel_assignment_request(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, GraphError> {
    cancel(&state, &id, Kind::Assignment).await
}

/// Microsoft: cancel works on a request "whose status is Granted". The simulator completes every
/// request at once, so none is ever still Granted and cancelling is always refused.
async fn cancel(state: &AppState, id: &str, kind: Kind) -> Result<StatusCode, GraphError> {
    let directory = state.store.read().await;
    if !requests(&directory, kind).contains_key(id) {
        return Err(GraphError::resource_not_found(id));
    }
    Err(GraphError::invalid_request(
        "Only a request whose status is Granted can be cancelled, and this one has completed.",
    ))
}

async fn create(
    state: &AppState,
    caller: &Caller,
    body: Value,
    kind: Kind,
) -> Result<(StatusCode, Json<Value>), GraphError> {
    let fields = body
        .as_object()
        .ok_or_else(|| GraphError::invalid_request("The request body must be a JSON object."))?;
    let text = |name: &str| fields.get(name).and_then(Value::as_str).map(str::to_string);
    let required = |name: &str| {
        text(name).ok_or_else(|| GraphError::invalid_request(format!("'{name}' is required.")))
    };
    let action = required("action")?;
    let principal_id = required("principalId")?;
    let role_definition_id = required("roleDefinitionId")?;
    let directory_scope_id = text("directoryScopeId").unwrap_or_else(|| "/".to_string());
    let now = OffsetDateTime::now_utc();

    let mut directory = state.store.write().await;
    if !directory.contains_object(&principal_id) {
        return Err(GraphError::new(
            StatusCode::NOT_FOUND,
            "SubjectNotFound",
            format!("The principal {principal_id:?} was not found."),
        ));
    }
    let template = templates()
        .into_iter()
        .find(|template| template.id == role_definition_id)
        .ok_or_else(|| {
            GraphError::new(
                StatusCode::NOT_FOUND,
                "RoleNotFound",
                format!("The role definition {role_definition_id:?} was not found."),
            )
        })?;

    let id = Uuid::new_v4().to_string();
    let matches_existing = |schedule: &Value| {
        schedule["principalId"] == principal_id.as_str()
            && schedule["roleDefinitionId"] == role_definition_id.as_str()
            && schedule["directoryScopeId"] == directory_scope_id.as_str()
    };
    let mut status = "Provisioned";
    let mut target_schedule_id = Some(id.clone());

    match action.as_str() {
        "adminAssign" | "adminUpdate" | "adminExtend" | "adminRenew" | "selfActivate"
        | "selfExtend" | "selfRenew" => {
            if action.starts_with("self") {
                // Microsoft: `selfActivate` is "For users to activate their assignments".
                if caller.claims.oid != principal_id {
                    return Err(GraphError::new(
                        StatusCode::FORBIDDEN,
                        "Authorization_RequestDenied",
                        "A self request must come from the principal it is for.",
                    ));
                }
                if kind == Kind::Assignment
                    && !directory
                        .role_eligibility_schedules
                        .values()
                        .any(|schedule| matches_existing(schedule) && is_current(schedule, now))
                {
                    return Err(GraphError::new(
                        StatusCode::BAD_REQUEST,
                        "RoleAssignmentDoesNotExist",
                        "The principal is not eligible for this role, so it cannot be activated.",
                    ));
                }
            }
            let (start, end) = schedule_window(fields.get("scheduleInfo"), &action, now)?;
            // An update replaces the schedule it changes, keeping one per principal and role.
            let replaced: Vec<String> = schedules(&directory, kind)
                .iter()
                .filter(|(_, schedule)| matches_existing(schedule))
                .map(|(key, _)| key.clone())
                .collect();
            let collection = schedules_mut(&mut directory, kind);
            for key in replaced {
                collection.remove(&key);
            }
            let mut schedule = json!({
                "id": id,
                "principalId": principal_id,
                "roleDefinitionId": role_definition_id,
                "directoryScopeId": directory_scope_id,
                "appScopeId": null,
                "createdUsing": id,
                "createdDateTime": format(now),
                "modifiedDateTime": null,
                "status": "Provisioned",
                "memberType": "Direct",
                "scheduleInfo": {
                    "startDateTime": format(start),
                    "recurrence": null,
                    "expiration": expiration(end)
                }
            });
            if kind == Kind::Assignment {
                schedule["assignmentType"] = json!(if action.starts_with("self") {
                    "Activated"
                } else {
                    "Assigned"
                });
                ensure_role_active(&mut directory, &template);
            }
            schedules_mut(&mut directory, kind).insert(id.clone(), schedule);
        }
        "adminRemove" | "selfDeactivate" => {
            if action == "selfDeactivate" && caller.claims.oid != principal_id {
                return Err(GraphError::new(
                    StatusCode::FORBIDDEN,
                    "Authorization_RequestDenied",
                    "A self request must come from the principal it is for.",
                ));
            }
            let removed: Vec<String> = schedules(&directory, kind)
                .iter()
                .filter(|(_, schedule)| matches_existing(schedule))
                .map(|(key, _)| key.clone())
                .collect();
            if removed.is_empty() {
                return Err(GraphError::new(
                    StatusCode::NOT_FOUND,
                    "RoleAssignmentDoesNotExist",
                    "There is no schedule for this principal, role and scope to remove.",
                ));
            }
            let collection = schedules_mut(&mut directory, kind);
            for key in &removed {
                collection.remove(key);
            }
            status = "Revoked";
            target_schedule_id = removed.first().cloned();
        }
        other => {
            return Err(GraphError::invalid_request(format!(
                "The action {other:?} is not supported."
            )));
        }
    }

    let mut request = Map::new();
    for (name, value) in fields {
        if !crate::graph::is_write_only_annotation(name) {
            request.insert(name.clone(), value.clone());
        }
    }
    request.insert("id".to_string(), json!(id));
    request.insert("directoryScopeId".to_string(), json!(directory_scope_id));
    request.insert("status".to_string(), json!(status));
    request.insert("createdDateTime".to_string(), json!(format(now)));
    request.insert("completedDateTime".to_string(), json!(format(now)));
    request.insert("targetScheduleId".to_string(), json!(target_schedule_id));
    request.insert("approvalId".to_string(), Value::Null);
    request.insert(
        "createdBy".to_string(),
        json!({ "user": { "id": caller.claims.oid } }),
    );
    let request = Value::Object(request);
    requests_mut(&mut directory, kind).insert(id.clone(), request.clone());
    info!(request_id = %id, action = %action, principal_id = %principal_id, "completed a role schedule request");
    Ok((StatusCode::CREATED, Json(request)))
}

fn requests_mut(
    directory: &mut Directory,
    kind: Kind,
) -> &mut std::collections::BTreeMap<String, Value> {
    match kind {
        Kind::Eligibility => &mut directory.role_eligibility_schedule_requests,
        Kind::Assignment => &mut directory.role_assignment_schedule_requests,
    }
}

fn schedules_mut(
    directory: &mut Directory,
    kind: Kind,
) -> &mut std::collections::BTreeMap<String, Value> {
    match kind {
        Kind::Eligibility => &mut directory.role_eligibility_schedules,
        Kind::Assignment => &mut directory.role_assignment_schedules,
    }
}

/// An active assignment makes its directory role active in the tenant, as assigning through
/// roleManagement does.
fn ensure_role_active(
    directory: &mut Directory,
    template: &crate::store::model::DirectoryRoleTemplate,
) {
    if directory
        .directory_roles
        .values()
        .any(|role| role.role_template_id == template.id)
    {
        return;
    }
    let role = DirectoryRole {
        id: Uuid::new_v4().to_string(),
        role_template_id: template.id.clone(),
        display_name: template.display_name.clone(),
        description: template.description.clone(),
        members: Vec::new(),
    };
    directory.directory_roles.insert(role.id.clone(), role);
}

/// When a schedule starts and ends, from a request's `scheduleInfo`. An activation with no end
/// lasts Entra's default of eight hours; anything else with no end does not expire.
fn schedule_window(
    info: Option<&Value>,
    action: &str,
    now: OffsetDateTime,
) -> Result<(OffsetDateTime, Option<OffsetDateTime>), GraphError> {
    let invalid = || GraphError::invalid_property("scheduleInfo");
    let start = match info.and_then(|info| info["startDateTime"].as_str()) {
        Some(raw) => OffsetDateTime::parse(raw, &Rfc3339).map_err(|_| invalid())?,
        None => now,
    };
    let expiration = info.map(|info| &info["expiration"]);
    let end = match expiration.and_then(|expiration| expiration["type"].as_str()) {
        Some("noExpiration") => None,
        Some("afterDateTime") => Some(
            expiration
                .and_then(|expiration| expiration["endDateTime"].as_str())
                .and_then(|raw| OffsetDateTime::parse(raw, &Rfc3339).ok())
                .ok_or_else(invalid)?,
        ),
        Some("afterDuration") => Some(
            start
                + expiration
                    .and_then(|expiration| expiration["duration"].as_str())
                    .and_then(parse_duration)
                    .ok_or_else(invalid)?,
        ),
        Some(_) => return Err(invalid()),
        None if action == "selfActivate" => Some(start + Duration::hours(DEFAULT_ACTIVATION_HOURS)),
        None => None,
    };
    Ok((start, end))
}

/// Parse the ISO 8601 durations Graph uses here, such as `PT8H`, `PT30M` or `P1D`.
fn parse_duration(raw: &str) -> Option<Duration> {
    let rest = raw.strip_prefix('P')?;
    let (days, time) = match rest.split_once('T') {
        Some((days, time)) => (days, time),
        None => (rest, ""),
    };
    let mut total = Duration::ZERO;
    if !days.is_empty() {
        total += Duration::days(days.strip_suffix('D')?.parse().ok()?);
    }
    let mut number = String::new();
    for character in time.chars() {
        if character.is_ascii_digit() {
            number.push(character);
            continue;
        }
        let value: i64 = number.parse().ok()?;
        number.clear();
        total += match character {
            'H' => Duration::hours(value),
            'M' => Duration::minutes(value),
            'S' => Duration::seconds(value),
            _ => return None,
        };
    }
    number.is_empty().then_some(total)
}

fn expiration(end: Option<OffsetDateTime>) -> Value {
    match end {
        Some(end) => {
            json!({ "type": "afterDateTime", "endDateTime": format(end), "duration": null })
        }
        None => json!({ "type": "noExpiration", "endDateTime": null, "duration": null }),
    }
}

fn format(moment: OffsetDateTime) -> String {
    moment.format(&Rfc3339).unwrap_or_default()
}

/// Whether a schedule is in force at `now`.
pub fn is_current(schedule: &Value, now: OffsetDateTime) -> bool {
    let info = &schedule["scheduleInfo"];
    let started = info["startDateTime"]
        .as_str()
        .and_then(|raw| OffsetDateTime::parse(raw, &Rfc3339).ok())
        .is_none_or(|start| start <= now);
    let unexpired = info["expiration"]["endDateTime"]
        .as_str()
        .and_then(|raw| OffsetDateTime::parse(raw, &Rfc3339).ok())
        .is_none_or(|end| now < end);
    started && unexpired
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_read_as_iso_8601() {
        assert_eq!(parse_duration("PT8H"), Some(Duration::hours(8)));
        assert_eq!(parse_duration("PT1H30M"), Some(Duration::minutes(90)));
        assert_eq!(parse_duration("P1D"), Some(Duration::days(1)));
        assert_eq!(parse_duration("P1DT2H"), Some(Duration::hours(26)));
        assert_eq!(parse_duration("8 hours"), None);
    }
}

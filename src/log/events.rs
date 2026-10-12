//! Writes every tracing event into the log, tied to the request it happened during.

use serde_json::{Map, Value, json};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use super::Log;

pub struct EventLayer(pub Log);

/// The ID of the request a span covers, as [`super::requests::record`] names it.
struct RequestId(String);

impl<S> Layer<S> for EventLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        if let (Some(Value::String(request_id)), Some(span)) =
            (fields.0.remove("request_id"), ctx.span(id))
        {
            span.extensions_mut().insert(RequestId(request_id));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let request_id = ctx.event_scope(event).and_then(|mut scope| {
            scope.find_map(|span| span.extensions().get::<RequestId>().map(|id| id.0.clone()))
        });
        let mut fields = Fields::default();
        event.record(&mut fields);
        let message = fields.0.remove("message").unwrap_or_default();
        let metadata = event.metadata();

        let entry = json!({
            "time": super::now(),
            "kind": "event",
            "requestId": request_id,
            "level": metadata.level().as_str(),
            "target": metadata.target(),
            "message": message,
            "fields": fields.0,
        });
        // A failure goes unreported: reporting it would be another event, which would fail too.
        let _ = self.0.append(&entry);
    }
}

#[derive(Default)]
struct Fields(Map<String, Value>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}").into());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.into());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_string(), value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_string(), value.into());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.insert(field.name().to_string(), value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_string(), value.into());
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;
    use crate::log::tests::TempDir;

    #[test]
    fn events_are_logged_with_the_request_they_happened_in() {
        let dir = TempDir::new();
        let log = Log::open(&dir.0).unwrap();
        let subscriber = tracing_subscriber::registry().with(EventLayer(log.clone()));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(user = "alice", count = 3, "outside");
            let request = tracing::info_span!("request", request_id = "abc");
            let _request = request.enter();
            let inner = tracing::info_span!("inner");
            let _inner = inner.enter();
            tracing::warn!(error = %"bad secret", "inside");
        });

        let page = log.page(None, None, 10).unwrap();
        let inside = &page.entries[0];
        assert_eq!(inside["kind"], "event");
        assert_eq!(inside["level"], "WARN");
        assert_eq!(inside["message"], "inside");
        assert_eq!(inside["requestId"], "abc");
        assert_eq!(inside["fields"], json!({ "error": "bad secret" }));

        let outside = &page.entries[1];
        assert_eq!(outside["level"], "INFO");
        assert_eq!(outside["message"], "outside");
        assert_eq!(outside["requestId"], serde_json::Value::Null);
        assert_eq!(outside["target"], "entra_sim::log::events::tests");
        assert_eq!(outside["fields"], json!({ "user": "alice", "count": 3 }));
    }
}

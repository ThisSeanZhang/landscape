use std::{fmt::Write as _, io};

use landscape_common::config::LogRuntimeConfig;
use landscape_ebpf::setting_libbpf_log;
use tracing::field::Visit;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::layer::{Filter, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, registry, EnvFilter, Layer};

struct KeywordFilter {
    keywords: Vec<String>,
}

impl KeywordFilter {
    fn new(keywords: Vec<String>) -> Self {
        Self {
            keywords: keywords
                .into_iter()
                .map(|k| k.trim().to_lowercase())
                .filter(|k| !k.is_empty())
                .collect(),
        }
    }

    fn is_empty(&self) -> bool {
        self.keywords.is_empty()
    }

    fn matches(&self, text: &str) -> bool {
        let text_lower = text.to_lowercase();
        self.keywords.iter().any(|k| text_lower.contains(k))
    }
}

impl<S> Filter<S> for KeywordFilter
where
    S: tracing::Subscriber,
{
    fn enabled(
        &self,
        _meta: &tracing::Metadata<'_>,
        _cx: &tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        true
    }

    fn event_enabled(
        &self,
        event: &tracing::Event<'_>,
        _cx: &tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        if *event.metadata().level() <= tracing::Level::WARN {
            return true;
        }

        struct EventTextVisitor {
            text: String,
        }

        impl EventTextVisitor {
            fn push_str(&mut self, value: &str) {
                if !self.text.is_empty() {
                    self.text.push(' ');
                }
                self.text.push_str(value);
            }

            fn push_field(&mut self, field: &tracing::field::Field, value: impl std::fmt::Debug) {
                if !self.text.is_empty() {
                    self.text.push(' ');
                }
                let _ = write!(self.text, "{}={:?}", field.name(), value);
            }
        }

        impl Visit for EventTextVisitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.push_field(field, value);
            }

            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.push_field(field, value);
            }
        }

        let mut visitor = EventTextVisitor { text: String::new() };
        visitor.push_str(event.metadata().target());
        if let Some(module_path) = event.metadata().module_path() {
            visitor.push_str(module_path);
        }
        event.record(&mut visitor);

        self.matches(&visitor.text)
    }
}

pub fn init_logger(log_config: LogRuntimeConfig) -> Result<(), Box<dyn std::error::Error>> {
    let keyword_filter = KeywordFilter::new(log_config.log_filter);
    let has_keyword_filter = !keyword_filter.is_empty();

    // Behaviour matrix for env_filter string:
    //
    // | log_filter | debug | env_filter                | KeywordFilter | Actual output                          |
    // |------------|-------|---------------------------|---------------|----------------------------------------|
    // | empty      | false | landscape=info,warn       | no            | landscape INFO+,  other WARN+          |
    // | non-empty  | false | landscape=debug,warn      | yes           | WARN/ERROR always; INFO/DEBUG by keyword|
    // | empty      | true  | landscape=debug,warn      | no            | landscape DEBUG+, other WARN+          |
    // | non-empty  | true  | landscape=debug,warn      | yes           | same as line 2                         |
    //
    // Must use debug level when log_filter is set so DEBUG events reach KeywordFilter.
    let filter_str = if log_config.debug || has_keyword_filter {
        "landscape=debug,warn"
    } else {
        "landscape=info,warn"
    };

    let env_filter = EnvFilter::new(filter_str);
    let timer_fmt = "%Y-%m-%dT%H:%M:%S%.3f%:z".to_string();

    // EnvFilter is added LAST (outermost layer) so its register_callsite / enabled /
    // event_enabled controls global filtering. If it were inner, the outer FmtLayer's
    // register_callsite (always Interest::always()) would bypass level filtering entirely.
    if log_config.log_output_in_terminal {
        let fmt_layer =
            fmt::layer().with_timer(ChronoLocal::new(timer_fmt)).with_writer(io::stdout);
        if has_keyword_filter {
            registry().with(fmt_layer.with_filter(keyword_filter)).with(env_filter).init();
        } else {
            registry().with(fmt_layer).with(env_filter).init();
        }
    } else {
        let file_appender: RollingFileAppender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .max_log_files(log_config.max_log_files)
            .filename_prefix("landscape.log")
            .build(&log_config.log_path)
            .expect("failed to initialize rolling file appender");

        let fmt_layer =
            fmt::layer().with_timer(ChronoLocal::new(timer_fmt)).with_writer(file_appender);
        if has_keyword_filter {
            registry().with(fmt_layer.with_filter(keyword_filter)).with(env_filter).init();
        } else {
            registry().with(fmt_layer).with(env_filter).init();
        }
    }

    setting_libbpf_log();
    Ok(())
}

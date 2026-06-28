use std::io;

use landscape_common::config::LogRuntimeConfig;
use landscape_ebpf::setting_libbpf_log;
use tracing::Level;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_logger(log_config: LogRuntimeConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Determine log level based on debug flag
    let (level_filter, filter) = if log_config.debug {
        (Level::DEBUG, EnvFilter::new("landscape=debug,warn"))
    } else {
        (Level::INFO, EnvFilter::new("landscape=info,warn"))
    };

    let timer = ChronoLocal::new("%Y-%m-%dT%H:%M:%S%.3f%:z".to_string());
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(level_filter)
        .with_env_filter(filter)
        .with_timer(timer);
    if log_config.log_output_in_terminal {
        // Output to terminal
        subscriber.with_writer(io::stdout).init();
    } else {
        // Use RollingFileAppender with daily rotation
        let file_appender: RollingFileAppender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .max_log_files(log_config.max_log_files)
            .filename_prefix("landscape.log")
            .build(&log_config.log_path)
            .expect("failed to initialize rolling file appender");

        subscriber.with_writer(file_appender).init();
    }

    setting_libbpf_log();
    Ok(())
}

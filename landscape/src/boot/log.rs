use std::io;

use landscape_common::args::LAND_LOG_ARGS;
use landscape_ebpf::setting_libbpf_log;
use tracing::Level;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_logger() -> Result<(), Box<dyn std::error::Error>> {
    // 根据 debug 字段决定日志级别
    let (level_filter, filter) = if LAND_LOG_ARGS.debug {
        (Level::DEBUG, EnvFilter::new("landscape=debug,warn"))
    } else {
        (Level::INFO, EnvFilter::new("landscape=info,warn"))
    };

    let subscriber =
        fmt::Subscriber::builder().with_max_level(level_filter).with_env_filter(filter);
    if LAND_LOG_ARGS.log_output_in_terminal {
        // 输出到终端
        subscriber.with_writer(io::stdout).init();
    } else {
        // 使用 RollingFileAppender，每天滚动，并且最多保留 5 个文件。
        let file_appender: RollingFileAppender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .max_log_files(LAND_LOG_ARGS.max_log_files)
            .filename_prefix("landscape.log")
            .build(&LAND_LOG_ARGS.log_path)
            .expect("failed to initialize rolling file appender");

        subscriber.with_writer(file_appender).init();
    }

    setting_libbpf_log();
    Ok(())
}

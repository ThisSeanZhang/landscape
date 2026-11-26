use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct LogRuntimeConfig {
    pub log_path: PathBuf,
    pub debug: bool,
    pub log_output_in_terminal: bool,
    pub max_log_files: usize,
    pub log_filter: Vec<String>,
}

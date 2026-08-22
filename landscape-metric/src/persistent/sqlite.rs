#[derive(Clone, Default)]
#[allow(dead_code)]
pub(crate) struct SqliteWriter;

#[allow(dead_code)]
impl SqliteWriter {
    pub(crate) async fn new(_base_path: std::path::PathBuf) -> Result<Self, String> {
        todo!("initialize persistent SQLite writer")
    }
}

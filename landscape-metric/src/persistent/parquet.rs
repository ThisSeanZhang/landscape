#[derive(Clone, Default)]
#[allow(dead_code)]
pub(crate) struct ParquetWriter;

#[allow(dead_code)]
impl ParquetWriter {
    pub(crate) async fn new(_base_path: std::path::PathBuf) -> Result<Self, String> {
        todo!("initialize persistent Parquet writer")
    }
}

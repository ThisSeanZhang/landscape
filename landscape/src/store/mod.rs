use serde::{Deserialize, Serialize};
use serde_json::Deserializer;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    ops::Range,
    path::PathBuf,
};

const JUNK_DATA_MAX_SIZE: u64 = 1024 * 8;

#[derive(Serialize, Deserialize)]
pub enum SaveUnit {
    Date(String, String),
    Del(String),
}

#[derive(Debug)]
pub struct UnitPosition {
    era: u64,
    start: u64,
    len: u64,
}

impl From<(u64, Range<u64>)> for UnitPosition {
    fn from((era, range): (u64, Range<u64>)) -> Self {
        UnitPosition {
            era,
            start: range.start,
            len: range.end - range.start,
        }
    }
}

/// 存储的文件名规则是: index.name
///
/// 文件的 index 从 1 开始
#[derive(Debug)]
pub struct StoreFileManager {
    // 存储数据的文件夹目录, 包含具体存储的路径
    path: PathBuf,
    // 存储的数据类型
    name: String,

    // 当前纪元
    current_era: u64,
    // 需要回收的空间
    junk_data_size: u64,

    // 当前纪元写入者
    writer: BufWriter<File>,

    // 索引文件, 存储了 key 以及存在哪个 文件中
    index: HashMap<String, UnitPosition>,
    // 数据索引, 根据 UnitPosition 中的纪元得到对应的 reader, 再根据 reader 进行读取数据
    readers: HashMap<u64, BufReader<File>>,
}

impl StoreFileManager {
    pub fn new(path: PathBuf, name: String) -> StoreFileManager {
        let data_floder = path.join(&name);
        // 文件夹不存在 创建它
        // max 和
        let (max_era, min_era) = if !data_floder.exists() {
            std::fs::create_dir_all(&data_floder).unwrap();
            (0, 0)
        } else {
            let mut max_index = u64::MIN;
            let mut min_index = u64::MAX;
            for dir_path in data_floder.read_dir().expect("read_dir call failed") {
                if let Ok(entry) = dir_path {
                    let file_path = entry.path();
                    // println!("文件: {:?}", entry.path());
                    if file_path.is_dir() {
                        panic!("不允许存在文件夹");
                    }
                    if file_path.extension().unwrap().to_string_lossy().to_string() != name {
                        panic!(
                            "不允许存在其他文件: 当前目录后缀为: {:?}, 存在的文件为: {:?}",
                            name, file_path
                        );
                    }
                    let index = file_path
                        .file_stem()
                        .unwrap()
                        .to_string_lossy()
                        .to_string()
                        .parse::<u64>()
                        .unwrap();
                    if index > max_index {
                        max_index = index;
                    }

                    if index < min_index {
                        min_index = index;
                    }
                }
            }

            if max_index == u64::MAX {
                (0, 0)
            } else {
                (max_index, min_index)
            }
        };

        let (current_era, writer, index, readers, junk_data_size) = if max_era == 0 {
            // 为空的文件夹, 直接创建文件
            let current_era = 1;
            let current_era_file_path = data_floder.join(format!("{}.{}", current_era, &name));
            let writer_file = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(current_era_file_path.clone())
                .unwrap();
            let reader_file =
                OpenOptions::new().read(true).truncate(false).open(current_era_file_path).unwrap();
            let mut readers = HashMap::new();
            readers.insert(current_era, BufReader::new(reader_file));

            (current_era, BufWriter::new(writer_file), HashMap::new(), readers, 0)
        } else {
            let mut index: HashMap<String, UnitPosition> = HashMap::new();
            let current_era = max_era + 1;
            let mut junk_data_size = 0;

            let mut readers = HashMap::new();
            for era in min_era..=max_era {
                let old_file = data_floder.join(format!("{}.{}", era, name));
                if old_file.exists() {
                    let file = OpenOptions::new()
                        .read(true)
                        .truncate(false)
                        .open(old_file.clone())
                        .unwrap();
                    // println!("添加 Reader: {:?}, 文件: {:?}", era, file);
                    readers.insert(era, BufReader::new(file));
                    let file =
                        OpenOptions::new().read(true).truncate(false).open(old_file).unwrap();
                    let mut reader = BufReader::new(file);
                    let mut pos = reader.seek(SeekFrom::Start(0)).unwrap();
                    // println!("初始化的 pos: {:?}", pos);
                    let mut stream = Deserializer::from_reader(reader).into_iter::<SaveUnit>();

                    while let Some(data) = stream.next() {
                        let new_pos = stream.byte_offset() as u64;
                        if let Ok(unit) = data {
                            match unit {
                                SaveUnit::Date(key, ..) => {
                                    if let Some(old_unit) = index.get(&key) {
                                        junk_data_size += old_unit.len;
                                    }
                                    index.insert(key, (era, pos..new_pos).into());
                                }
                                SaveUnit::Del(key) => {
                                    if let Some(old_unit) = index.remove(&key) {
                                        junk_data_size += old_unit.len;
                                    } else {
                                        junk_data_size += new_pos - pos;
                                    }
                                }
                            }
                        }
                        pos = new_pos;
                    }
                }
            }

            let current_era_file_path = data_floder.join(format!("{}.{}", current_era, &name));
            let writer_file = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(current_era_file_path.clone())
                .unwrap();
            let current_era_reader_file =
                OpenOptions::new().read(true).truncate(false).open(current_era_file_path).unwrap();
            readers.insert(current_era, BufReader::new(current_era_reader_file));
            (current_era, BufWriter::new(writer_file), index, readers, junk_data_size)
        };

        let mut store = StoreFileManager {
            path: data_floder,
            name,
            current_era,
            junk_data_size,
            writer,
            index,
            readers,
        };
        if store.readers.len() > 5 {
            store.periodization();
        }
        store
    }

    /// 进行文件精简
    fn periodization(&mut self) {
        let temp_collect_file_era = self.current_era + 1;
        self.current_era = temp_collect_file_era + 1;

        let current_era_path = self.path.join(format!("{}.{}", self.current_era, &self.name));
        // println!("创建文件: {:?}", current_era_path);
        let current_writer = OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(false)
            .open(current_era_path.clone())
            .unwrap();

        self.writer = BufWriter::new(current_writer);

        let periodization_path =
            self.path.join(format!("{}.{}", temp_collect_file_era, &self.name));
        let periodization_file = OpenOptions::new()
            .read(true)
            .create(true)
            .write(true)
            .truncate(false)
            .open(periodization_path.clone())
            .unwrap();
        let mut temp_collect_file_era_writer = BufWriter::new(periodization_file);

        let mut new_index: HashMap<String, UnitPosition> = HashMap::new();
        let mut periodization_file_pos = 0;
        for (key, UnitPosition { era, start, len }) in self.index.iter_mut() {
            if !self.readers.contains_key(&era) {
                let missing_reader = self.path.join(format!("{}.{}", &era, &self.name));
                // reader.seek(pos)
                let missing_reader =
                    OpenOptions::new().read(true).truncate(false).open(missing_reader).unwrap();
                self.readers.insert(*era, BufReader::new(missing_reader));
            };

            let reader = self.readers.get_mut(&era).unwrap();
            reader.seek(SeekFrom::Start(*start)).unwrap();
            let mut data = reader.take(*len);
            let copy_length = std::io::copy(&mut data, &mut temp_collect_file_era_writer).unwrap();
            new_index.insert(
                key.clone(),
                (
                    temp_collect_file_era,
                    periodization_file_pos..periodization_file_pos + copy_length,
                )
                    .into(),
            );
            periodization_file_pos += copy_length;
        }

        let mut new_readers = HashMap::new();
        let periodization_file =
            OpenOptions::new().read(true).truncate(false).open(periodization_path).unwrap();
        let periodization_reader = BufReader::new(periodization_file);
        new_readers.insert(temp_collect_file_era, periodization_reader);

        let current_era_file =
            OpenOptions::new().read(true).truncate(false).open(current_era_path).unwrap();
        let current_era_reader = BufReader::new(current_era_file);
        new_readers.insert(self.current_era, current_era_reader);

        for key in self.readers.keys() {
            let stale_file_path = self.path.join(format!("{}.{}", key, &self.name));
            if let Err(e) = std::fs::remove_file(&stale_file_path) {
                tracing::error!("{:?} cannot be deleted: {}", stale_file_path, e);
            }
        }
        self.readers = new_readers;
        self.index = new_index;
        self.junk_data_size = 0;
    }

    // update and set valve
    pub fn set(&mut self, key: String, value: String) -> Option<String> {
        let data = SaveUnit::Date(key.clone(), value);

        let currrent_pos = self.writer.seek(SeekFrom::Current(0)).unwrap();
        serde_json::to_writer(&mut self.writer, &data).unwrap();
        self.writer.flush().unwrap();
        let currrent_new_pos = self.writer.seek(SeekFrom::Current(0)).unwrap();

        let unit = (self.current_era, currrent_pos..currrent_new_pos);
        if let Some(old_unit) = self.index.insert(key, unit.into()) {
            self.junk_data_size += old_unit.len;
            if self.junk_data_size > JUNK_DATA_MAX_SIZE {
                self.periodization();
            }
        }
        None
    }

    pub fn get(&mut self, key: String) -> Option<String> {
        if let Some(UnitPosition { era, start, len }) = self.index.get(&key) {
            if let Some(reader) = self.readers.get_mut(era) {
                reader.seek(SeekFrom::Start(*start)).unwrap();
                let data = reader.take(*len);
                let unit: SaveUnit = serde_json::from_reader(data).unwrap();
                match unit {
                    SaveUnit::Date(_, value) => {
                        return Some(value);
                    }
                    _ => {}
                }
            }
        }

        None
    }

    pub fn list(&mut self) -> Option<Vec<String>> {
        let mut result = vec![];
        for UnitPosition { era, start, len } in self.index.values() {
            // println!("using: {era}, start: {start:?}, len: {len}");
            if let Some(reader) = self.readers.get_mut(era) {
                reader.seek(SeekFrom::Start(*start)).unwrap();
                let data = reader.take(*len);
                let unit: SaveUnit = serde_json::from_reader(data).unwrap();
                match unit {
                    SaveUnit::Date(_, value) => {
                        result.push(value);
                    }
                    _ => {}
                }
            }
        }

        Some(result)
    }

    pub fn pair_list(&mut self) -> Option<Vec<(String, String)>> {
        let mut result = vec![];
        for UnitPosition { era, start, len } in self.index.values() {
            // println!("using: {era}, start: {start:?}, len: {len}");
            if let Some(reader) = self.readers.get_mut(era) {
                reader.seek(SeekFrom::Start(*start)).unwrap();
                let data = reader.take(*len);
                let unit: SaveUnit = serde_json::from_reader(data).unwrap();
                match unit {
                    SaveUnit::Date(key, value) => {
                        result.push((key, value));
                    }
                    _ => {}
                }
            }
        }

        Some(result)
    }

    pub fn del(&mut self, key: String) -> Option<String> {
        if let Some(UnitPosition { len, .. }) = self.index.remove(&key) {
            let data = SaveUnit::Del(key.clone());

            let currrent_pos = self.writer.seek(SeekFrom::Current(0)).unwrap();
            serde_json::to_writer(&mut self.writer, &data).unwrap();
            self.writer.flush().unwrap();
            let currrent_new_pos = self.writer.seek(SeekFrom::Current(0)).unwrap();

            // 删除 key 的这条记录也算是垃圾
            self.junk_data_size += currrent_new_pos - currrent_pos;
            // 加上原有添加的 key 所占的空间
            self.junk_data_size += len;

            if self.junk_data_size > JUNK_DATA_MAX_SIZE {
                self.periodization();
            }
        }
        None
    }
}

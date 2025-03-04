use serde::{Deserialize, Serialize};
use serde_json::Deserializer;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    ops::Range,
    path::PathBuf,
};

// 最大垃圾空间阈值
const JUNK_DATA_MAX_SIZE: u64 = 1024 * 8;

pub trait LandScapeStore {
    fn get_store_key(&self) -> String;

    fn get_query_key(&self) -> String {
        self.get_store_key()
    }
}

#[derive(Serialize, Deserialize)]
pub enum SaveUnit<T> {
    Data(T),
    Del(String),
}

/// 用来记录当前这条数据在文件中的位置
#[derive(Debug)]
pub struct UnitPosition {
    pub era: u64,
    pub start: u64,
    pub len: u64,
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

/// 一个可扩展的文件管理器，支持存储 T 类型的对象
#[derive(Debug)]
pub struct StoreFileManager<T> {
    path: PathBuf,
    name: String,

    current_era: u64,
    junk_data_size: u64,

    writer: BufWriter<File>,

    // key -> UnitPosition
    index: HashMap<String, UnitPosition>,
    // era -> 对应文件的读句柄
    readers: HashMap<u64, BufReader<File>>,

    _marker: std::marker::PhantomData<T>,
}

impl<T> StoreFileManager<T>
where
    T: LandScapeStore + Serialize + for<'de> Deserialize<'de>,
{
    /// 创建管理器
    pub fn new(path: PathBuf, name: String) -> StoreFileManager<T> {
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
                    let mut stream = Deserializer::from_reader(reader).into_iter::<SaveUnit<T>>();

                    while let Some(data) = stream.next() {
                        let new_pos = stream.byte_offset() as u64;
                        if let Ok(unit) = data {
                            match unit {
                                SaveUnit::Data(obj) => {
                                    let key = obj.get_store_key();
                                    // 如果原本已有同名 key，则这次写入前一条就成了垃圾
                                    if let Some(old_unit) = index.get(&key) {
                                        junk_data_size += old_unit.len;
                                    }
                                    index.insert(key, (era, pos..new_pos).into());
                                }
                                SaveUnit::Del(del_key) => {
                                    // 如果索引里有，就把它删掉并标记垃圾
                                    if let Some(old_unit) = index.remove(&del_key) {
                                        junk_data_size += old_unit.len;
                                    } else {
                                        // 否则这条 Del 自己是无意义的，也算垃圾
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
            _marker: std::marker::PhantomData,
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

    /// 插入或更新一条数据
    pub fn set(&mut self, data: T) {
        // 先取出 key
        let key = data.get_store_key();

        // 准备写入 SaveUnit::Data(data)
        let current_pos = self.writer.seek(SeekFrom::Current(0)).unwrap();
        let save_unit = SaveUnit::Data(data);

        serde_json::to_writer(&mut self.writer, &save_unit).unwrap();
        self.writer.flush().unwrap();
        let new_pos = self.writer.seek(SeekFrom::Current(0)).unwrap();

        // 记录在 index 中
        let unit = UnitPosition::from((self.current_era, current_pos..new_pos));
        if let Some(old) = self.index.insert(key, unit) {
            // 原有的数据变成了垃圾
            self.junk_data_size += old.len;
            // 如果垃圾空间超过阈值就 periodization
            if self.junk_data_size > JUNK_DATA_MAX_SIZE {
                self.periodization();
            }
        }
    }

    /// 根据 key 获取该结构
    pub fn get(&mut self, key: &str) -> Option<T> {
        let pos = self.index.get(key)?;
        let reader = self.readers.get_mut(&pos.era)?;
        reader.seek(SeekFrom::Start(pos.start)).ok()?;
        let data_chunk = reader.take(pos.len);
        if let Ok(SaveUnit::Data(obj)) = serde_json::from_reader(data_chunk) {
            Some(obj)
        } else {
            None
        }
    }

    pub fn list(&mut self) -> Vec<T> {
        let mut result = Vec::new();
        for (_, pos) in &self.index {
            // 依次读出
            if let Some(reader) = self.readers.get_mut(&pos.era) {
                reader.seek(SeekFrom::Start(pos.start)).unwrap();
                let data_chunk = reader.take(pos.len);
                if let Ok(SaveUnit::Data(obj)) = serde_json::from_reader(data_chunk) {
                    result.push(obj);
                }
            }
        }
        result
    }

    /// 删除某个 key 对应的数据
    pub fn del(&mut self, key: &str) {
        // 先在 index 中把它删除，拿到旧长度
        if let Some(old_unit) = self.index.remove(key) {
            // 自身写一个 Delete 记录
            let del_unit = SaveUnit::<T>::Del(key.to_string());

            let cur_pos = self.writer.seek(SeekFrom::Current(0)).unwrap();
            serde_json::to_writer(&mut self.writer, &del_unit).unwrap();
            self.writer.flush().unwrap();
            let new_pos = self.writer.seek(SeekFrom::Current(0)).unwrap();

            // 垃圾空间增加
            self.junk_data_size += (new_pos - cur_pos) + old_unit.len;

            if self.junk_data_size > JUNK_DATA_MAX_SIZE {
                self.periodization();
            }
        }
    }

    /// 清空所有记录，重置存储状态
    pub fn truncate(&mut self) {
        // 关闭所有现有的文件句柄
        self.readers.clear();
        // 确保当前 writer 的内容刷新并关闭
        let _ = self.writer.flush();

        // 删除所有数据文件
        let dir_entries = std::fs::read_dir(&self.path).unwrap();
        for entry in dir_entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext.to_string_lossy().to_string() == self.name {
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            if stem.parse::<u64>().is_ok() {
                                let _ = std::fs::remove_file(&path);
                            }
                        }
                    }
                }
            }
        }

        // 重置内部状态
        self.current_era = 1;
        self.junk_data_size = 0;
        self.index.clear();

        // 创建新的 era 1 文件
        let current_era_file_path = self.path.join(format!("{}.{}", self.current_era, &self.name));
        let writer_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true) // 确保文件为空
            .open(&current_era_file_path)
            .unwrap();
        self.writer = BufWriter::new(writer_file);

        // 添加对应的 reader
        let reader_file = OpenOptions::new().read(true).open(current_era_file_path).unwrap();
        self.readers.insert(self.current_era, BufReader::new(reader_file));
    }
}

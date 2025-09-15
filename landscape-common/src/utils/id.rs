use uuid::Uuid;

pub fn gen_uuid() -> String {
    Uuid::new_v4().to_string()
}

pub fn gen_database_uuid() -> Uuid {
    Uuid::new_v4()
}

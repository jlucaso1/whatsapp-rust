#[derive(Clone, Debug, Default)]
pub struct ClientConfig {
    pub db_path: String,
    pub app_version_override: Option<(u32, u32, u32)>,
}

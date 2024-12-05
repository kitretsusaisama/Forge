use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Resource {
    pub name: String,
    pub path: PathBuf,
    pub resource_type: ResourceType,
}

#[derive(Debug, Clone)]
pub enum ResourceType {
    File,
    Directory,
    Environment,
}

impl Resource {
    pub fn new(name: String, path: PathBuf, resource_type: ResourceType) -> Self {
        Self {
            name,
            path,
            resource_type,
        }
    }
}

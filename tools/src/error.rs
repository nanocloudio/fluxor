//! Error types for fluxor-tools

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("UF2 error: {0}")]
    Uf2(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Module error: {0}")]
    Module(String),
}

pub type Result<T> = std::result::Result<T, Error>;

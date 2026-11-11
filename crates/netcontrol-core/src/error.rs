use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("permission denied: {0}")]
    Forbidden(String),
    #[error("operation not supported: {0}")]
    Unsupported(String),
    #[error("gateway error: {0}")]
    Gateway(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("security error: {0}")]
    Security(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        match value {
            rusqlite::Error::QueryReturnedNoRows => {
                Error::NotFound("database record not found".into())
            }
            other => Error::Database(other.to_string()),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Error::Internal(format!("json error: {value}"))
    }
}

impl From<toml::de::Error> for Error {
    fn from(value: toml::de::Error) -> Self {
        Error::Config(value.to_string())
    }
}

impl From<toml::ser::Error> for Error {
    fn from(value: toml::ser::Error) -> Self {
        Error::Config(value.to_string())
    }
}

impl From<ipnet::AddrParseError> for Error {
    fn from(value: ipnet::AddrParseError) -> Self {
        Error::Validation(value.to_string())
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(value: std::net::AddrParseError) -> Self {
        Error::Validation(format!("invalid IP address: {value}"))
    }
}

impl From<argon2::password_hash::Error> for Error {
    fn from(value: argon2::password_hash::Error) -> Self {
        Error::Security(format!("password hash error: {value}"))
    }
}

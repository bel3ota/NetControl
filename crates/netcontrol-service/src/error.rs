use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use netcontrol_core::Error;
use serde::Serialize;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication required",
        )
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "validation_error", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }
}

impl From<Error> for ApiError {
    fn from(value: Error) -> Self {
        match value {
            Error::Validation(message) => Self::bad_request(message),
            Error::NotFound(message) => Self::not_found(message),
            Error::Unauthorized => Self::unauthorized(),
            Error::Forbidden(message) => Self::forbidden(message),
            Error::Unsupported(message) => {
                Self::new(StatusCode::UNPROCESSABLE_ENTITY, "unsupported", message)
            }
            Error::Gateway(message) => Self::new(StatusCode::BAD_GATEWAY, "gateway_error", message),
            Error::Config(message) => Self::new(StatusCode::BAD_REQUEST, "config_error", message),
            Error::Security(message) => {
                tracing::error!(error = %message, "security operation failed");
                Self::internal("security operation failed")
            }
            Error::Database(message) => {
                tracing::error!(error = %message, "database operation failed");
                Self::internal("database operation failed")
            }
            Error::Io(err) => {
                tracing::error!(error = %err, "I/O operation failed");
                Self::internal("I/O operation failed")
            }
            Error::Internal(message) => {
                tracing::error!(error = %message, "internal operation failed");
                Self::internal("internal operation failed")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.code,
                message: self.message,
            },
        };
        (self.status, Json(body)).into_response()
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

//! Error module
//!
//! Contains API errors along with result types.

use std::{fmt, io};
use std::result::Result as StdResult;
use std::error::Error as StdError;

use hyper::error::Error as HyperError;
use rustc_serialize::json;
use dto::FromDTOError;

/// The result type of the API.
pub type Result<T> = StdResult<T, Error>;

/// The error type of the API.
#[derive(Debug)]
pub enum Error {
    /// Hyper request error.
    HyperError(HyperError),
    /// IO error.
    IO(io::Error),
    /// Error converting value from DTO object.
    FromDTOError(FromDTOError),
    /// JSON decode error.
    JSONDecodeError(json::DecoderError),
    /// Forbidden.
    Forbidden(String),
    /// Bad request
    BadRequest(String),
    /// Error Logging in
    ClientError(String),
    /// Not found
    NotFound(String),
    /// Internal server error.
    ServerError(String),
    /// The token type is not valid.
    InvalidTokenType,
    /// The scope is not valid.
    InvalidScope,
    /// The secret is not valid.
    InvalidSecret,
    /// Registration error.
    RegistrationError,
    /// An error occurred generating a transaction.
    TransactionError,
    /// Connection confirmation error.
    ConfirmConnectionError,
}

impl From<HyperError> for Error {
    fn from(error: HyperError) -> Error {
        Error::HyperError(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::IO(error)
    }
}

impl From<json::DecoderError> for Error {
    fn from(error: json::DecoderError) -> Error {
        Error::JSONDecodeError(error)
    }
}

impl From<FromDTOError> for Error {
    fn from(error: FromDTOError) -> Error {
        Error::FromDTOError(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::HyperError(ref e) => e.description(),
            Error::IO(ref e) => e.description(),
            Error::FromDTOError(ref e) => e.description(),
            Error::JSONDecodeError(ref e) => e.description(),
            Error::Forbidden(ref e) => e,
            Error::BadRequest(ref e) => e,
            Error::ClientError(ref e) => e,
            Error::NotFound(ref e) => e,
            Error::ServerError(ref e) => e,
            Error::TransactionError => "error generating transaction",
            Error::RegistrationError => "error registering user",
            Error::InvalidTokenType => "the provided token type is not a valid token type",
            Error::InvalidScope => "the provided scope is not a valid scope",
            Error::InvalidSecret => "the provided secret is not a valid secret",
            Error::ConfirmConnectionError => "error trying to confirm connection",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            Error::HyperError(ref e) => Some(e),
            Error::IO(ref e) => Some(e),
            _ => None,
        }
    }
}

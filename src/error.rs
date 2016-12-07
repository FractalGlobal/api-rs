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
    Hyper(HyperError),
    /// IO error.
    IO(io::Error),
    /// Error converting value from DTO object.
    FromDTO(FromDTOError),
    /// JSON decode error.
    JSONDecode(json::DecoderError),
    /// Forbidden.
    Forbidden(String),
    /// Bad request
    BadRequest(String),
    /// Error Logging in
    Client(String),
    /// Not found
    NotFound(String),
    /// Internal server error.
    Server(String),
    /// The token type is not valid.
    InvalidTokenType,
    /// The scope is not valid.
    InvalidScope,
    /// The secret is not valid.
    InvalidSecret,
    /// Registration error.
    Registration,
    /// An error occurred generating a transaction.
    Transaction,
    /// Connection confirmation error.
    ConfirmConnection,
}

impl From<HyperError> for Error {
    fn from(error: HyperError) -> Error {
        Error::Hyper(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::IO(error)
    }
}

impl From<json::DecoderError> for Error {
    fn from(error: json::DecoderError) -> Error {
        Error::JSONDecode(error)
    }
}

impl From<FromDTOError> for Error {
    fn from(error: FromDTOError) -> Error {
        Error::FromDTO(error)
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
            Error::Hyper(ref e) => e.description(),
            Error::IO(ref e) => e.description(),
            Error::FromDTO(ref e) => e.description(),
            Error::JSONDecode(ref e) => e.description(),
            Error::Forbidden(ref e) |
            Error::BadRequest(ref e) |
            Error::Client(ref e) |
            Error::NotFound(ref e) |
            Error::Server(ref e) => e,
            Error::Transaction => "error generating transaction",
            Error::Registration => "error registering user",
            Error::InvalidTokenType => "the provided token type is not a valid token type",
            Error::InvalidScope => "the provided scope is not a valid scope",
            Error::InvalidSecret => "the provided secret is not a valid secret",
            Error::ConfirmConnection => "error trying to confirm connection",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            Error::Hyper(ref e) => Some(e),
            Error::IO(ref e) => Some(e),
            _ => None,
        }
    }
}

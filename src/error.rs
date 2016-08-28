use std::{fmt, io};
use std::result::Result as StdResult;
use std::error::Error as StdError;

use hyper::error::Error as HyperError;
use rustc_serialize::json;
use dto::FromDTOError;

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug)]
pub enum Error {
    HyperError(HyperError),
    IO(io::Error),
    FromDTOError(FromDTOError),
    JSONDecodeError(json::DecoderError),
    Unauthorized,
    ServerError,
    InvalidTokenType,
    InvalidScope,
    InvalidSecret,
    RegistrationError,
    TransactionError,
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
            Error::TransactionError => "Error Generating Transaction",
            Error::RegistrationError => "Error Registering User",
            Error::Unauthorized => "the provided token is not authorized to use the method",
            Error::ServerError => "a server error occurred",
            Error::InvalidTokenType => "the provided token type is not a valid token type",
            Error::InvalidScope => "the provided scope is not a valid scope",
            Error::InvalidSecret => "the provided secret is not a valid secret",
            Error::ConfirmConnectionError => "Error trying to confirm connection",
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

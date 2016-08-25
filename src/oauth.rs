use std::fmt;
use std::str::FromStr;
use std::slice::Iter;
use std::result::Result as StdResult;

use chrono::{Duration, UTC, DateTime};

use dto::{FromDTO, AccessTokenDTO, TokenTypeDTO, FromDTOError};

use error::{Error, Result};

/// Access Token Type
pub type TokenType = TokenTypeDTO;

/// Struct representing an access token.
#[derive(Debug, Clone)]
pub struct AccessToken {
    app_id: String,
    scopes: Vec<Scope>,
    access_token: String,
    token_type: TokenType,
    expiration: DateTime<UTC>,
}

impl AccessToken {
    /// Creates an access token from stored data.
    pub fn from_data(app_id: String, scopes: Vec<Scope>, access_token: String, token_type: TokenTypeDTO, expiration: DateTime<UTC>) -> AccessToken {
        AccessToken {app_id: app_id, scopes: scopes, access_token: access_token, token_type: token_type, expiration: expiration}
    }

    /// Gets the application ID of the token.
    pub fn get_app_id(&self) -> &str {
        &self.app_id
    }

    /// Gets an iterator through the scopes of the token.
    pub fn scopes(&self) -> Iter<Scope> {
        self.scopes.iter()
    }

    /// Gets the token as a string.
    ///
    /// This string will be the one that identifies the client in the API.
    pub fn as_str(&self) -> &str {
        &self.access_token
    }

    /// Gets the type of the token.
    pub fn get_token_type(&self) -> TokenType {
        self.token_type
    }

    /// Gets the expiration time of the token.
    pub fn get_expiration(&self) -> DateTime<UTC> {
        self.expiration
    }

    /// Returns wether the access token expired or not.
    pub fn has_expired(&self) -> bool {
        self.expiration < UTC::now()
    }
}

impl FromDTO<AccessTokenDTO> for AccessToken {
    fn from_dto(dto: AccessTokenDTO) -> StdResult<AccessToken, FromDTOError> {
        let mut scopes = Vec::new();
        for scope in dto.scopes.split(',') {
            scopes.push(match Scope::from_str(scope) {
                Ok(s) => s,
                Err(_) => return Err(FromDTOError {}),
            });
        }
        if scopes.len() == 0 {
            return Err(FromDTOError {});
        }
        let expiry_time = UTC::now() + Duration::seconds(dto.expiration);

        Ok(AccessToken {app_id: dto.app_id, scopes: scopes, access_token: dto.access_token, token_type: dto.token_type, expiration: expiry_time})
    }
}

/// Enum that represents
#[derive(Debug, PartialOrd, PartialEq, Eq, Copy, Clone, RustcDecodable, RustcEncodable)]
pub enum Scope {
    /// Administration scope
    ///
    /// This scope is used for administration purposes, and will not be enabled for public
    /// development accounts.
    Admin,
    /// User scope
    ///
    /// This scope will provide access to user functionality, such as creating transactions and
    /// editing user information. It contains the user ID for which the token is valid.
    User(u64),
    /// Public scope
    ///
    /// This scope is the public scope. Every client will have access to everything provided in the
    /// admin scope.
    Public,
    /// Developer scope
    ///
    /// This scope is used for administration purposes, and will not be enabled for public
    /// development accounts.
    Developer,
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for Scope {
    type Err = Error;
    fn from_str(s: &str) -> Result<Scope> {
        match s {
            "Admin" => Ok(Scope::Admin),
            "Public" => Ok(Scope::Public),
            "Developer" => Ok(Scope::Developer),
            s => match s.rfind("User:") {
                Some(i) => Ok(Scope::User(match s[i..].parse() {
                    Ok(id) => id,
                    _ => return Err(Error::InvalidScope),
                })),
                _ => Err(Error::InvalidScope),
            },
        }
    }
}

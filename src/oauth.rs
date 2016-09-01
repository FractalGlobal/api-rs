//! OAuth module for the Fractal API.
//!
//! contains the required structs and enums for a typesafe OAuth with the API.
use std::slice::Iter;
use std::result::Result as StdResult;

use hyper::header::Bearer;
use chrono::{Duration, UTC, DateTime};

use dto::{FromDTO, AccessTokenDTO, TokenTypeDTO, FromDTOError, ScopeDTO as Scope};

use rustc_serialize::json;

/// Access Token Type
pub type TokenType = TokenTypeDTO;

/// Struct representing an access token.
#[derive(Debug, Clone)]
pub struct AccessToken {
    app_id: String,
    scopes: Vec<Scope>,
    access_token: String,
    expiration: DateTime<UTC>,
}

impl AccessToken {
    /// Creates an access token from stored data.
    pub fn from_data(app_id: String,
                     scopes: Vec<Scope>,
                     access_token: String,
                     expiration: DateTime<UTC>)
                     -> AccessToken {
        AccessToken {
            app_id: app_id,
            scopes: scopes,
            access_token: access_token,
            expiration: expiration,
        }
    }

    /// Gets the application ID of the token.
    pub fn get_app_id(&self) -> &str {
        &self.app_id
    }

    /// Gets an iterator through the scopes of the token.
    pub fn scopes(&self) -> Iter<Scope> {
        self.scopes.iter()
    }

    /// Gets the token to be sent
    pub fn get_token(&self) -> Bearer {
        Bearer { token: self.access_token.clone() }
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
        if dto.token_type != TokenTypeDTO::Bearer {
            return Err(FromDTOError::new("the token type of the access token is not valid"));
        }
        let scopes: Vec<Scope> = json::decode(&dto.scopes).unwrap();
        if scopes.len() == 0 {
            return Err(FromDTOError::new("there were no scopes in the access token"));
        }
        let expiry_time = UTC::now() + Duration::seconds(dto.expiration);

        Ok(AccessToken {
            app_id: dto.app_id,
            scopes: scopes,
            access_token: dto.access_token,
            expiration: expiry_time,
        })
    }
}

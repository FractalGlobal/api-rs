//! OAuth module for the Fractal API.
//!
//! contains the required structs and enums for a typesafe OAuth with the API.
use std::slice::Iter;
use std::result::Result as StdResult;
use std::io::Read;

use hyper::header::Bearer;
use hyper::method::Method;
use hyper::header::{Headers, Authorization, Basic};

use chrono::{Duration, UTC, DateTime};
use rustc_serialize::json;
use rustc_serialize::base64::FromBase64;
use dto::{FromDTO, AccessTokenDTO, TokenTypeDTO, FromDTOError, ScopeDTO as Scope, CreateClientDTO,
          ClientInfoDTO};

use error::{Result, Error};
use super::{Client, VoidDTO};
use super::types::ClientInfo;

/// Application's secret length.
pub const SECRET_LEN: usize = 20;

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
    pub fn from_data<I: Into<String>, SV: Into<Vec<Scope>>, T: Into<String>>(
        app_id: I, scopes: SV, access_token: T, expiration: DateTime<UTC>) -> AccessToken {
        AccessToken {
            app_id: app_id.into(),
            scopes: scopes.into(),
            access_token: access_token.into(),
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

    /// Returns wether the token is an admin token.
    pub fn is_admin(&self) -> bool {
        self.scopes.iter().any(|s| s == &Scope::Admin)
    }

    /// Returns wether the token is an admin token.
    pub fn is_public(&self) -> bool {
        self.scopes.iter().any(|s| s == &Scope::Public)
    }

    /// Returns wether the token is an admin token.
    pub fn is_user(&self, user_id: u64) -> bool {
        self.scopes.iter().any(|s| s == &Scope::User(user_id))
    }

    /// Gets the user ID if the token is a user token.
    pub fn get_user_id(&self) -> Option<u64> {
        for scope in &self.scopes {
            if let Scope::User(id) = *scope {
                return Some(id);
            }
        }
        None
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
        if scopes.is_empty() {
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

/// OAuth methods for clients.
impl Client {
    /// Gets a token from the API.
    pub fn token<I: Into<String>, S: Into<String>>(&self,
                                                   app_id: I,
                                                   secret: S)
                                                   -> Result<AccessToken> {
        let secret = secret.into();
        match secret.from_base64() {
            Ok(b) => {
                if b.len() == SECRET_LEN {
                    let mut headers = Headers::new();
                    headers.set(Authorization(Basic {
                        username: app_id.into(),
                        password: Some(secret),
                    }));
                    let mut response = self.send_request(Method::Get,
                                      format!("{}token", self.url),
                                      headers,
                                      None::<&VoidDTO>)?;
                    let mut response_str = String::new();
                    let _ = response.read_to_string(&mut response_str)?;
                    Ok(AccessToken::from_dto(json::decode(&response_str)?)?)
                } else {
                    Err(Error::InvalidSecret)
                }
            }
            Err(_) => Err(Error::InvalidSecret),
        }
    }

    /// Creates a client
    ///
    /// Creates a client with the given name, scopes and request limit per hour. An admin scoped
    /// token is required to use this API call.
    pub fn create_client<N: Into<String>, SV: Into<Vec<Scope>>>(&self,
                                                                access_token: &AccessToken,
                                                                name: N,
                                                                scopes: SV,
                                                                request_limit: Option<usize>)
                                                                -> Result<ClientInfo> {
        if access_token.scopes().any(|s| s == &Scope::Admin) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = CreateClientDTO {
                name: name.into(),
                scopes: scopes.into(),
                request_limit: request_limit,
            };
            let mut response = self.send_request(Method::Post,
                              format!("{}create_client", self.url),
                              headers,
                              Some(&dto))?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            let client_dto: ClientInfoDTO = json::decode(&response_str)?;
            Ok(ClientInfo::from_dto(client_dto)?)
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin token")))
        }
    }
}

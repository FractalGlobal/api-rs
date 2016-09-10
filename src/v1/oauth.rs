//! OAuth module for the Fractal API.
//!
//! contains the required structs and enums for a typesafe OAuth with the API.
use std::slice::Iter;
use std::result::Result as StdResult;
use std::io::Read;

use hyper::header::Bearer;
use hyper::method::Method;
use hyper::header::{Headers, Authorization, Basic, Accept, qitem};
use hyper::mime::{Mime, TopLevel, SubLevel, Attr, Value};
use hyper::status::StatusCode;

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

/// OAuth methods for clients.
impl Client {
    /// Gets a token from the API.
    pub fn token<S: AsRef<str>>(&self, app_id: S, secret: S) -> Result<AccessToken> {
        match secret.as_ref().from_base64() {
            Ok(b) => {
                if b.len() == SECRET_LEN {
                    let mut headers = Headers::new();
                    headers.set(Accept(vec![
                            qitem(Mime(TopLevel::Application, SubLevel::Json,
                                       vec![(Attr::Charset, Value::Utf8)])),
                        ]));
                    headers.set(Authorization(Basic {
                        username: String::from(app_id.as_ref()),
                        password: Some(String::from(secret.as_ref())),
                    }));
                    let mut response = try!(self.send_request(Method::Post,
                                                              format!("{}token", self.url),
                                                              headers,
                                                              None::<&VoidDTO>));

                    match response.status {
                        StatusCode::Ok => {
                            let mut response_str = String::new();
                            let _ = try!(response.read_to_string(&mut response_str));
                            Ok(try!(AccessToken::from_dto(try!(json::decode(&response_str)))))
                        }
                        StatusCode::Unauthorized => Err(Error::Unauthorized),
                        _ => Err(Error::ServerError),
                    }
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
    pub fn create_client<S: AsRef<str>>(&self,
                                        access_token: &AccessToken,
                                        name: S,
                                        scopes: &[Scope],
                                        request_limit: usize)
                                        -> Result<ClientInfo> {
        if access_token.scopes().any(|s| s == &Scope::Admin) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut scopes_vec = Vec::with_capacity(scopes.len());
            scopes_vec.clone_from_slice(scopes);
            let dto = CreateClientDTO {
                name: String::from(name.as_ref()),
                scopes: scopes_vec,
                request_limit: request_limit,
            };
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}create_client", self.url),
                                                      headers,
                                                      Some(&dto)));
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    let dto_client: ClientInfoDTO = try!(json::decode(&response_str));
                    Ok(try!(ClientInfo::from_dto(dto_client)))
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }
}

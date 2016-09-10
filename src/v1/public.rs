use std::io::Read;

use hyper::method::Method;
use hyper::header::{Headers, Authorization, Basic, Accept, qitem};
use hyper::mime::{Mime, TopLevel, SubLevel, Attr, Value};
use hyper::status::StatusCode;
use rustc_serialize::base64::FromBase64;
use rustc_serialize::json;

use dto::{FromDTO, ScopeDTO as Scope, LoginDTO, RegisterDTO, ResetPasswordDTO, ResponseDTO,
          NewPasswordDTO, CreateClientDTO, ClientInfoDTO};

use super::{Client, SECRET_LEN};

use error::{Result, Error};
use types::ClientInfo;
use oauth::AccessToken;

/// Public methods for the client.
///
/// These are the public methods for getting a token, creating and logging in users, and confirming
/// their information.
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
                                               format!("{}token", self.url).as_str(),
                                               headers,
                                               Some("grant_type=client_credentials")));

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
                                                      Some(json::encode(&dto).unwrap())));
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

    /// Registers the user
    pub fn register<S: AsRef<str>>(&self,
                                   access_token: &AccessToken,
                                   username: S,
                                   password: S,
                                   email: S)
                                   -> Result<()> {
        if access_token.scopes().any(|s| s == &Scope::Public) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let register = RegisterDTO {
                username: String::from(username.as_ref()),
                password: String::from(password.as_ref()),
                email: String::from(email.as_ref()),
            };
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}register", self.url),
                                                      headers,
                                                      Some(json::encode(&register).unwrap())));

            match response.status {
                StatusCode::Ok => Ok(()),
                StatusCode::Accepted => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    match json::decode::<ResponseDTO>(&response_str) {
                        Ok(r) => Err(Error::ClientError(r)),
                        Err(e) => Err(e.into()),
                    }
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    // TODO register_encrypted

    /// Logs the user in
    pub fn login<S: AsRef<str>>(&self,
                                access_token: &AccessToken,
                                user_email: S,
                                password: S,
                                remember_me: bool)
                                -> Result<AccessToken> {
        if access_token.scopes().any(|s| s == &Scope::Public) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = LoginDTO {
                user_email: String::from(user_email.as_ref()),
                password: String::from(password.as_ref()),
                remember_me: remember_me,
            };
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}login", self.url),
                                                      headers,
                                                      Some(json::encode(&dto).unwrap())));

            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    Ok(try!(AccessToken::from_dto(try!(json::decode(&response_str)))))
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                StatusCode::Accepted => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    match json::decode::<ResponseDTO>(&response_str) {
                        Ok(r) => Err(Error::ClientError(r)),
                        Err(e) => Err(e.into()),
                    }
                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Resends the email confirmation
    pub fn resend_email_confirmation(&self, access_token: &AccessToken) -> Result<()> {
        let mut user_id = None;
        for scope in access_token.scopes() {
            match scope {
                &Scope::User(id) => user_id = Some(id),
                _ => {}
            }
        }
        if user_id.is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let response = try!(self.send_request(Method::Get,
                                                  format!("{}resend_email_confirmation",
                                                          self.url),
                                                  headers,
                                                  None));

            match response.status {
                StatusCode::Ok => Ok(()),
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Confirms the users email
    pub fn confirm_email<S: AsRef<str>>(&self,
                                        access_token: &AccessToken,
                                        email_key: S)
                                        -> Result<()> {
        if access_token.scopes().any(|s| s == &Scope::Public) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}confirm_email/{}",
                                                              self.url,
                                                              email_key.as_ref()),
                                                      headers,
                                                      None));

            match response.status {
                StatusCode::Ok => Ok(()),
                StatusCode::Accepted => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    match json::decode::<ResponseDTO>(&response_str) {
                        Ok(r) => Err(Error::ClientError(r)),
                        Err(e) => Err(e.into()),
                    }

                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Begins a the reset password procecss
    pub fn start_reset_password<S: AsRef<str>>(&self,
                                               access_token: &AccessToken,
                                               username: S,
                                               email: S)
                                               -> Result<()> {
        if access_token.scopes().any(|s| s == &Scope::Public) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = ResetPasswordDTO {
                username: String::from(username.as_ref()),
                email: String::from(email.as_ref()),
            };
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}start_reset_password", self.url),
                                                      headers,
                                                      Some(json::encode(&dto).unwrap())));

            match response.status {
                StatusCode::Ok => Ok(()),
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                StatusCode::Accepted => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    match json::decode::<ResponseDTO>(&response_str) {
                        Ok(r) => Err(Error::ClientError(r)),
                        Err(e) => Err(e.into()),
                    }
                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Attempts to confirm the new password reset
    pub fn reset_password<S: AsRef<str>>(&self,
                                         access_token: &AccessToken,
                                         password_key: S,
                                         new_password: S)
                                         -> Result<()> {
        if access_token.scopes().any(|s| s == &Scope::Public) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = NewPasswordDTO { new_password: String::from(new_password.as_ref()) };
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}reset_password/{}",
                                                              self.url,
                                                              password_key.as_ref()),
                                                      headers,
                                                      Some(json::encode(&dto).unwrap())));

            match response.status {
                StatusCode::Ok => Ok(()),
                StatusCode::Accepted => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    match json::decode::<ResponseDTO>(&response_str) {
                        Ok(r) => Err(Error::ClientError(r)),
                        Err(e) => Err(e.into()),
                    }

                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }
}

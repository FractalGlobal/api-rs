use std::io::Read;

use hyper::method::Method;
use hyper::header::{Headers, Authorization};
use hyper::status::StatusCode;
use rustc_serialize::json;

use chrono::{NaiveDate, UTC};

use utils::Address;
use dto::{FromDTO, UserDTO, ScopeDTO as Scope, AuthenticationCodeDTO, ResponseDTO, UpdateUserDTO};

use super::{Client, VoidDTO};

use error::{Result, Error};
use super::types::User;
use super::oauth::AccessToken;

/// User methods for the client.
///
/// This are the user getters, setters and creators for the client.
impl Client {
    /// Get the user
    pub fn get_user(&self, access_token: &AccessToken, user_id: u64) -> Result<User> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(u_id) => u_id == user_id,
            &Scope::Admin => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = try!(self.send_request(Method::Get,
                                                      format!("{}user/{}", self.url, user_id),
                                                      headers,
                                                      None::<&VoidDTO>));

            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    Ok(try!(User::from_dto(try!(json::decode::<UserDTO>(&response_str)))))
                }
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

    /// Gets the logged in users info
    pub fn get_me(&self, access_token: &AccessToken) -> Result<User> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut user_id = 0;
            for scope in access_token.scopes() {
                match scope {
                    &Scope::User(id) => user_id = id,
                    _ => {}
                }
            }
            let mut response = try!(self.send_request(Method::Get,
                                                      format!("{}user/{}", self.url, user_id),
                                                      headers,
                                                      None::<&VoidDTO>));

            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    Ok(try!(User::from_dto(try!(json::decode::<UserDTO>(&response_str)))))
                }
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

    /// Gets all users.
    pub fn get_all_users(&self, access_token: &AccessToken) -> Result<Vec<User>> {
        if access_token.scopes().any(|s| s == &Scope::Admin) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = try!(self.send_request(Method::Get,
                                                      format!("{}all_users", self.url),
                                                      headers,
                                                      None::<&VoidDTO>));
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    let dto_users: Vec<UserDTO> = try!(json::decode(&response_str));
                    Ok(dto_users.into_iter()
                        .filter_map(|u| match User::from_dto(u) {
                            Ok(u) => Some(u),
                            Err(_) => None,
                        })
                        .collect())
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

    /// Deletes the given user.
    pub fn delete_user(&self, access_token: &AccessToken, user_id: u64) -> Result<()> {
        if access_token.scopes().any(|s| s == &Scope::Admin) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let response = try!(self.send_request(Method::Delete,
                                                  format!("{}user/{}", self.url, user_id),
                                                  headers,
                                                  None::<&VoidDTO>));
            match response.status {
                StatusCode::Ok => Ok(()),
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    // TODO update user

    /// Gets the authenticator qrcode to scan for 2 factor authentication
    pub fn get_authenticator_qrcode(&self,
                                    access_token: &AccessToken,
                                    user_id: u64)
                                    -> Result<String> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response =
                try!(self.send_request(Method::Get,
                                       format!("{}authenticator/{}", self.url, user_id),
                                       headers,
                                       None::<&VoidDTO>));
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    match json::decode::<ResponseDTO>(&response_str) {
                        Ok(r) => Ok(r.message),
                        Err(e) => Err(e.into()),
                    }
                }
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

    /// Authenticates the user with 2FA
    pub fn authenticate(&self, access_token: &AccessToken, user_id: u64, code: u32) -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = AuthenticationCodeDTO {
                code: code,
                timestamp: UTC::now(),
            };
            let mut response =
                try!(self.send_request(Method::Post,
                                       format!("{}authenticate/{}", self.url, user_id),
                                       headers,
                                       Some(&dto)));
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


    /// Sets the users username
    pub fn set_username<S: AsRef<str>>(&self,
                                       access_token: &AccessToken,
                                       user_id: u64,
                                       password: Option<S>,
                                       username: S)
                                       -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(u_id) => u_id == user_id,
            &Scope::Admin => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: Some(String::from(username.as_ref())),
                new_email: None,
                new_first: None,
                new_last: None,
                old_password: match password {
                    Some(pass) => Some(String::from(pass.as_ref())),
                    None => None,
                },
                new_password: None,
                new_phone: None,
                new_birthday: None,
                new_image: None,
                new_address: None,
            };
            let response = try!(self.send_request(Method::Post,
                                                  format!("{}update_user/{}", self.url, user_id),
                                                  headers,
                                                  Some(&dto)));

            match response.status {
                StatusCode::Ok => {
                    // let mut response_str = String::new();
                    // try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the users phone
    pub fn set_phone<S: AsRef<str>>(&self,
                                    access_token: &AccessToken,
                                    user_id: u64,
                                    password: Option<S>,
                                    phone: S)
                                    -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(u_id) => u_id == user_id,
            &Scope::Admin => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: None,
                new_first: None,
                new_last: None,
                old_password: match password {
                    Some(pass) => Some(String::from(pass.as_ref())),
                    None => None,
                },
                new_password: None,
                new_phone: Some(String::from(phone.as_ref())),
                new_birthday: None,
                new_image: None,
                new_address: None,
            };
            let response = try!(self.send_request(Method::Post,
                                                  format!("{}update_user/{}", self.url, user_id),
                                                  headers,
                                                  Some(&dto)));
            match response.status {
                StatusCode::Ok => {
                    // let mut response_str = String::new();
                    // try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the users birthday
    pub fn set_birthday<S: AsRef<str>>(&self,
                                       access_token: &AccessToken,
                                       user_id: u64,
                                       password: Option<S>,
                                       birthday: NaiveDate)
                                       -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(u_id) => u_id == user_id,
            &Scope::Admin => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: None,
                new_first: None,
                new_last: None,
                old_password: match password {
                    Some(pass) => Some(String::from(pass.as_ref())),
                    None => None,
                },
                new_password: None,
                new_phone: None,
                new_birthday: Some(birthday),
                new_image: None,
                new_address: None,
            };
            let response = try!(self.send_request(Method::Post,
                                                  format!("{}update_user/{}", self.url, user_id),
                                                  headers,
                                                  Some(&dto)));
            match response.status {
                StatusCode::Ok => {
                    // let mut response_str = String::new();
                    // try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the users first and last name
    pub fn set_name<S: AsRef<str>>(&self,
                                   access_token: &AccessToken,
                                   user_id: u64,
                                   password: Option<S>,
                                   first: S,
                                   last: S)
                                   -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(u_id) => u_id == user_id,
            &Scope::Admin => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: None,
                new_first: Some(String::from(first.as_ref())),
                new_last: Some(String::from(last.as_ref())),
                old_password: match password {
                    Some(pass) => Some(String::from(pass.as_ref())),
                    None => None,
                },
                new_password: None,
                new_phone: None,
                new_birthday: None,
                new_image: None,
                new_address: None,
            };
            let response = try!(self.send_request(Method::Post,
                                                  format!("{}update_user/{}", self.url, user_id),
                                                  headers,
                                                  Some(&dto)));
            match response.status {
                StatusCode::Ok => {
                    // let mut response_str = String::new();
                    // try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the users email
    pub fn set_email<S: AsRef<str>>(&self,
                                    access_token: &AccessToken,
                                    user_id: u64,
                                    password: Option<S>,
                                    email: S)
                                    -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(u_id) => u_id == user_id,
            &Scope::Admin => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: Some(String::from(email.as_ref())),
                new_first: None,
                new_last: None,
                old_password: match password {
                    Some(pass) => Some(String::from(pass.as_ref())),
                    None => None,
                },
                new_password: None,
                new_phone: None,
                new_birthday: None,
                new_image: None,
                new_address: None,
            };
            let response = try!(self.send_request(Method::Post,
                                                  format!("{}update_user/{}", self.url, user_id),
                                                  headers,
                                                  Some(&dto)));
            match response.status {
                StatusCode::Ok => {
                    // let mut response_str = String::new();
                    // try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the users profile picture
    pub fn set_image<S: AsRef<str>>(&self,
                                    access_token: &AccessToken,
                                    user_id: u64,
                                    password: Option<S>,
                                    image: S)
                                    -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(u_id) => u_id == user_id,
            &Scope::Admin => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: None,
                new_first: None,
                new_last: None,
                old_password: match password {
                    Some(pass) => Some(String::from(pass.as_ref())),
                    None => None,
                },
                new_password: None,
                new_phone: None,
                new_birthday: None,
                new_image: Some(String::from(image.as_ref())),
                new_address: None,
            };
            let response = try!(self.send_request(Method::Post,
                                                  format!("{}update_user/{}", self.url, user_id),
                                                  headers,
                                                  Some(&dto)));
            match response.status {
                StatusCode::Ok => {
                    // let mut response_str = String::new();
                    // try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the users address
    pub fn set_address<S: AsRef<str>>(&self,
                                      access_token: &AccessToken,
                                      user_id: u64,
                                      password: Option<S>,
                                      address: Address)
                                      -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(u_id) => u_id == user_id,
            &Scope::Admin => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: None,
                new_first: None,
                new_last: None,
                old_password: match password {
                    Some(pass) => Some(String::from(pass.as_ref())),
                    None => None,
                },
                new_password: None,
                new_phone: None,
                new_birthday: None,
                new_image: None,
                new_address: Some(address),
            };
            let response = try!(self.send_request(Method::Post,
                                                  format!("{}update_user/{}", self.url, user_id),
                                                  headers,
                                                  Some(&dto)));
            match response.status {
                StatusCode::Ok => {
                    // let mut response_str = String::new();
                    // try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the user password
    pub fn set_password<S: AsRef<str>>(&self,
                                       access_token: &AccessToken,
                                       old_password: S,
                                       new_password: S)
                                       -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: None,
                new_first: None,
                new_last: None,
                old_password: Some(String::from(old_password.as_ref())),
                new_password: Some(String::from(new_password.as_ref())),
                new_phone: None,
                new_birthday: None,
                new_image: None,
                new_address: None,
            };
            let response = try!(self.send_request(Method::Post,
                                                  format!("{}update_user/{}",
                                                          self.url,
                                                          access_token.scopes()
                                                              .fold(0, |acc, s| match s {
                                                                  &Scope::User(id) => id,
                                                                  _ => acc,
                                                              })),
                                                  headers,
                                                  Some(&dto)));

            match response.status {
                StatusCode::Ok => {
                    // let mut response_str = String::new();
                    // try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }
}

use std::io::Read;

use hyper::method::Method;
use hyper::header::{Headers, Authorization};
use rustc_serialize::json;
use dto::{FromDTO, ScopeDTO as Scope, LoginDTO, RegisterDTO, ResetPasswordDTO, NewPasswordDTO};

use error::{Result, Error};
use super::{Client, VoidDTO};
use super::oauth::AccessToken;

/// Public methods for the client.
///
/// These are the public methods for getting a token, creating and logging in users, and confirming
/// their information.
impl Client {
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
            let dto = RegisterDTO {
                username: String::from(username.as_ref()),
                password: String::from(password.as_ref()),
                email: String::from(email.as_ref()),
            };
            let _ = try!(self.send_request(Method::Post,
                                           format!("{}register", self.url),
                                           headers,
                                           Some(&dto)));
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
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
                                                      Some(&dto)));
            let mut response_str = String::new();
            let _ = try!(response.read_to_string(&mut response_str));
            Ok(try!(AccessToken::from_dto(try!(json::decode(&response_str)))))
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
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
            let _ = try!(self.send_request(Method::Post,
                                           format!("{}confirm_email/{}",
                                                   self.url,
                                                   email_key.as_ref()),
                                           headers,
                                           None::<&VoidDTO>));
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
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
            let _ = try!(self.send_request(Method::Post,
                                           format!("{}start_reset_password", self.url),
                                           headers,
                                           Some(&dto)));
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
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
            let _ = try!(self.send_request(Method::Post,
                                           format!("{}reset_password/{}",
                                                   self.url,
                                                   password_key.as_ref()),
                                           headers,
                                           Some(&dto)));
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
        }
    }
}

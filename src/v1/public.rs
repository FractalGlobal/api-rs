use std::io::Read;

use hyper::method::Method;
use hyper::header::{Headers, Authorization};
use rustc_serialize::json;
use dto::{FromDTO, LoginDTO, RegisterDTO, ResetPasswordDTO, NewPasswordDTO};

use error::{Result, Error};
use super::{Client, VoidDTO};
use super::oauth::AccessToken;

/// Public methods for the client.
///
/// These are the public methods for getting a token, creating and logging in users, and confirming
/// their information.
impl Client {
    /// Registers the user
    pub fn register<U: Into<String>, P: Into<String>, E: Into<String>, R: Into<String>>
        (&self,
         access_token: &AccessToken,
         username: U,
         password: P,
         email: E,
         referer: Option<R>)
         -> Result<()> {
        if access_token.is_public() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = RegisterDTO {
                username: username.into(),
                password: password.into(),
                email: email.into(),
                referer: referer.and_then(|pass| Some(pass.into())),
            };
            let _ = self.send_request(Method::Post,
                              format!("{}register", self.url),
                              headers,
                              Some(&dto))?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
        }
    }

    // TODO register_encrypted

    /// Logs the user in
    pub fn login<UM: Into<String>, P: Into<String>>(&self,
                                                    access_token: &AccessToken,
                                                    user_email: UM,
                                                    password: P,
                                                    remember_me: bool)
                                                    -> Result<AccessToken> {
        if access_token.is_public() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = LoginDTO {
                user_email: user_email.into(),
                password: password.into(),
                remember_me: remember_me,
            };
            let mut response = self.send_request(Method::Post,
                              format!("{}login", self.url),
                              headers,
                              Some(&dto))?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            Ok(AccessToken::from_dto(json::decode(&response_str)?)?)
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
        }
    }

    /// Confirms the users email
    pub fn confirm_email<S: AsRef<str>>(&self,
                                        access_token: &AccessToken,
                                        email_key: S)
                                        -> Result<()> {
        if access_token.is_public() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let _ = self.send_request(Method::Post,
                              format!("{}confirm_email/{}", self.url, email_key.as_ref()),
                              headers,
                              None::<&VoidDTO>)?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
        }
    }

    /// unConfirms the users email
    pub fn unconfirm_email<S: AsRef<str>>(&self,
                                        access_token: &AccessToken,
                                        email_key: S)
                                        -> Result<()> {
        if access_token.is_public() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let _ = self.send_request(Method::Post,
                              format!("{}unconfirm_email/{}", self.url, email_key.as_ref()),
                              headers,
                              None::<&VoidDTO>)?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
        }
    }

    /// Begins a the reset password procecss
    pub fn start_reset_password<E: Into<String>>(&self,
                                                access_token: &AccessToken,
                                                email: E)
                                                -> Result<()> {
        if access_token.is_public() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = ResetPasswordDTO {
                email: email.into(),
            };
            let _ = self.send_request(Method::Post,
                              format!("{}start_reset_password", self.url),
                              headers,
                              Some(&dto))?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
        }
    }

    /// Attempts to confirm the new password reset
    pub fn reset_password<K: AsRef<str>, P: Into<String>>(&self,
                                                          access_token: &AccessToken,
                                                          password_key: K,
                                                          new_password: P)
                                                          -> Result<()> {
        if access_token.is_public() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = NewPasswordDTO { new_password: new_password.into() };
            let _ = self.send_request(Method::Post,
                              format!("{}reset_password/{}", self.url, password_key.as_ref()),
                              headers,
                              Some(&dto))?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
        }
    }


    ///Subscribe Maililng List

    pub fn subscribe_email <S: AsRef<str>>(&self,
                                        access_token: &AccessToken,
                                        email_key: S)
                                        -> Result<()> {
        if access_token.is_public() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let _ = self.send_request(Method::Post,
                              format!("{}subscribe_email/{}", self.url, email_key.as_ref()),
                              headers,
                              None::<&VoidDTO>)?;
                              
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
        }
    }
    /// Confirms the users subscription
    pub fn confirm_subscribe_email<S: AsRef<str>>(&self,
                                        access_token: &AccessToken,
                                        email_key: S)
                                        -> Result<()> {
        if access_token.is_public(){
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let _ = self.send_request(Method::Post,
                              format!("{}confirm_subscribe_email/{}", self.url, email_key.as_ref()),
                              headers,
                              None::<&VoidDTO>)?;
                              
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
        }
    }

    /// unConfirms the users subscription
    pub fn unconfirm_subscribe_email<S: AsRef<str>>(&self,
                                        access_token: &AccessToken,
                                        email_key: S)
                                        -> Result<()> {
        if access_token.is_public(){
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let _ = self.send_request(Method::Post,
                              format!("{}unconfirm_subscribe_email/{}", self.url, email_key.as_ref()),
                              headers,
                              None::<&VoidDTO>)?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public token")))
        }
    }
}

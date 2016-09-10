//! Fractal Global Credits API.

// #![forbid(missing_docs, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(missing_docs, trivial_casts, trivial_numeric_casts, unused, unused_extern_crates,
        unused_import_braces, unused_qualifications, unused_results, variant_size_differences)]

extern crate hyper;
extern crate chrono;
extern crate rustc_serialize;
extern crate fractal_dto as dto;
extern crate fractal_utils as utils;

use std::time::Duration;
use std::io::Read;

use hyper::Client as HyperClient;
use hyper::method::Method;
use hyper::client::response::Response;
use hyper::header::{Headers, Authorization, Basic, Accept, qitem};
use hyper::mime::{Mime, TopLevel, SubLevel, Attr, Value};
use hyper::status::StatusCode;
use rustc_serialize::base64::FromBase64;
use rustc_serialize::json;

use utils::{WalletAddress, Amount, Address};
use dto::{FromDTO, UserDTO, ScopeDTO as Scope, GenerateTransactionDTO as GenerateTransaction,
          LoginDTO as Login, RegisterDTO as Register, UpdateUserDTO as UpdateUser,
          FriendRequestDTO, ConfirmFriendRequestDTO as ConfirmFriendRequest,
          ResetPasswordDTO as ResetPassword, ResponseDTO, NewPasswordDTO as NewPassword,
          CreateClientDTO, ClientInfoDTO, TransactionDTO, PendingFriendRequestDTO,
          RelationshipDTO as Relationship, AuthenticationCodeDTO as AuthenticationCode};

use chrono::{NaiveDate, UTC};

pub mod error;
pub mod types;
pub mod oauth;

use error::{Result, Error};
use types::{ClientInfo, User, Transaction, PendingFriendRequest};
use oauth::AccessToken;

/// Application's secret length.
pub const SECRET_LEN: usize = 20;

const FRACTAL_SERVER: &'static str = "https://api.fractal.global/";
const FRACTAL_DEV_SERVER: &'static str = "https://dev.fractal.global/";

/// The client struct.
///
/// This struct will be in charge of connections to the Fractal Global Credits API.
pub struct ClientV1 {
    client: HyperClient,
    url: String,
}

impl ClientV1 {
    /// Creates a new Fractal Global Credits API client.
    pub fn new() -> ClientV1 {
        ClientV1 {
            client: hyper::Client::new(),
            url: format!("{}v1/", FRACTAL_SERVER),
        }
    }

    /// Creates a new Fractal Global Credits API client.
    pub fn new_with_url<S: AsRef<str>>(url: S) -> ClientV1 {
        ClientV1 {
            client: hyper::Client::new(),
            url: format!("{}v1/", url.as_ref()),
        }
    }

    /// Creates a new Fractal Global Credits API development client.
    pub fn new_dev() -> ClientV1 {
        ClientV1 {
            client: hyper::Client::new(),
            url: format!("{}v1/", FRACTAL_DEV_SERVER),
        }
    }

    /// Sets the read timeout for requests.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.client.set_read_timeout(timeout);
    }

    /// Sets the write timeout for requests.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.client.set_write_timeout(timeout);
    }

    fn send_request<S: AsRef<str>>(&self,
                                   method: Method,
                                   url: S,
                                   headers: Headers,
                                   body: Option<S>)
                                   -> std::result::Result<Response, hyper::error::Error> {
        let mut response = self.client
            .request(method.clone(), url.as_ref())
            .headers(headers.clone());
        if let Some(ref b) = body {
            response = response.body(b.as_ref());
        }
        let response = response.send();
        if response.is_err() {
            let mut response = self.client
                .request(method, url.as_ref())
                .headers(headers.clone());
            if let Some(ref b) = body {
                response = response.body(b.as_ref());
            }
            response.send()
        } else {
            response
        }
    }

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
            let register: Register = Register {
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

    /// Begins a the reset password procecss
    pub fn start_reset_password<S: AsRef<str>>(&self,
                                               access_token: &AccessToken,
                                               username: S,
                                               email: S)
                                               -> Result<()> {
        if access_token.scopes().any(|s| s == &Scope::Public) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto: ResetPassword = ResetPassword {
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
                                                      None));

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
                                                      None));

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
            let dto: Login = Login {
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

    /// Gets all the transactions since the given transaction
    pub fn get_all_transactions(&self,
                                access_token: &AccessToken,
                                first_transaction: u64)
                                -> Result<Vec<Transaction>> {
        if access_token.scopes().any(|s| s == &Scope::Admin) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = try!(self.send_request(Method::Get,
                                                      format!("{}all_transactions/{}",
                                                              self.url,
                                                              first_transaction),
                                                      headers,
                                                      None));
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    let transactions: Vec<TransactionDTO> = try!(json::decode(&response_str));
                    Ok(transactions.into_iter()
                        .map(|t| Transaction::from_dto(t).unwrap())
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

    /// Gets all the pending friend requests for the given user.
    pub fn get_friend_requests(&self,
                               access_token: &AccessToken,
                               user_id: u64)
                               -> Result<Vec<PendingFriendRequest>> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(u_id) => u_id == user_id,
            &Scope::Admin => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response =
                try!(self.send_request(Method::Get,
                                       format!("{}pending_connections/{}", self.url, user_id),
                                       headers,
                                       None));
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    let connections: Vec<PendingFriendRequestDTO> =
                        try!(json::decode(&response_str));
                    Ok(connections.into_iter()
                        .map(|t| PendingFriendRequest::from_dto(t).unwrap())
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

    /// Gets all users from the database.
    pub fn get_all_users(&self, access_token: &AccessToken) -> Result<Vec<User>> {
        if access_token.scopes().any(|s| s == &Scope::Admin) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = try!(self.send_request(Method::Get,
                    format!("{}all_users", self.url), headers, None));
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

    /// Generates a transaction
    pub fn generate_transaction(&self,
                                access_token: &AccessToken,
                                receiver_wallet: WalletAddress,
                                receiver_id: u64,
                                amount: Amount)
                                -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto: GenerateTransaction = GenerateTransaction {
                origin_id: access_token.scopes().fold(0, |acc, s| match s {
                    &Scope::User(id) => id,
                    _ => acc,
                }),
                destination_address: receiver_wallet,
                destination_id: receiver_id,
                amount: amount,
            };
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}generate_transaction", self.url),
                                                      headers,
                                                      Some(json::encode(&dto).unwrap())));

            match response.status {
                StatusCode::Ok => {
                    // let mut response_str = String::new();
                    // try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
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
            let dto: UpdateUser = UpdateUser {
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
                                                  Some(json::encode(&dto).unwrap())));

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
            let dto: UpdateUser = UpdateUser {
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
                                                  Some(json::encode(&dto).unwrap())));
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
            let dto: UpdateUser = UpdateUser {
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
                                                  Some(json::encode(&dto).unwrap())));
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
            let dto: UpdateUser = UpdateUser {
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
                                                  Some(json::encode(&dto).unwrap())));
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
            let dto: UpdateUser = UpdateUser {
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
                                                  Some(json::encode(&dto).unwrap())));
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
            let dto: UpdateUser = UpdateUser {
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
                                                  Some(json::encode(&dto).unwrap())));
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
            let dto: UpdateUser = UpdateUser {
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
                                                  Some(json::encode(&dto).unwrap())));
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
            let dto: UpdateUser = UpdateUser {
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
                                                  Some(json::encode(&dto).unwrap())));

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

    /// Creates a pending invitation to connect to the user
    pub fn invite_user_to_connect<S: AsRef<str>>(&self,
                                                 access_token: &AccessToken,
                                                 user: u64,
                                                 relation: Relationship,
                                                 message: Option<S>)
                                                 -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = FriendRequestDTO {
                origin_id: access_token.scopes().fold(0, |acc, s| match s {
                    &Scope::User(id) => id,
                    _ => acc,
                }),
                destination_id: user,
                relationship: relation,
                message: match message {
                    Some(m) => Some(String::from(m.as_ref())),
                    None => None,
                },
            };
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}create_pending_connection",
                                                              self.url),
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

    /// Confirms a connection
    pub fn confirm_friend_request(&self,
                                  access_token: &AccessToken,
                                  connection_id: u64,
                                  user: u64)
                                  -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto: ConfirmFriendRequest = ConfirmFriendRequest {
                origin: user,
                destination: access_token.scopes().fold(0, |acc, s| match s {
                    &Scope::User(id) => id,
                    _ => acc,
                }),
                id: connection_id,
            };
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}confirm_pending_connection",
                                   self.url,
                                  ),
                                                      headers,
                                                      Some(json::encode(&dto).unwrap())));

            match response.status {
                StatusCode::Ok => Ok(()),
                StatusCode::Unauthorized => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    Err(Error::Unauthorized)
                }
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

    /// Attempts to confirm the new password reset
    pub fn confirm_new_password_reset<S: AsRef<str>>(&self,
                                                     access_token: &AccessToken,
                                                     password_key: S,
                                                     new_password: S)
                                                     -> Result<()> {
        if access_token.scopes().any(|s| s == &Scope::Public) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto: NewPassword =
                NewPassword { new_password: String::from(new_password.as_ref()) };
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

    /// Deletes the user
    pub fn delete_user(&self, access_token: &AccessToken, user_id: u64) -> Result<()> {
        if access_token.scopes().any(|s| s == &Scope::Admin) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let response = try!(self.send_request(Method::Delete,
                                                  format!("{}user/{}", self.url, user_id),
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
                                       None));
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
            let dto = AuthenticationCode {
                code: code,
                timestamp: UTC::now(),
            };
            let mut response =
                try!(self.send_request(Method::Post,
                                       format!("{}authenticate/{}", self.url, user_id),
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
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }

        } else {
            Err(Error::Unauthorized)
        }
    }
}

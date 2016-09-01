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
use hyper::header::{Headers, Authorization, Basic, Accept, qitem};
use hyper::mime::{Mime, TopLevel, SubLevel, Attr, Value};
use hyper::status::StatusCode;
use rustc_serialize::base64::FromBase64;
use rustc_serialize::json;
use dto::{FromDTO, UserDTO, ScopeDTO as Scope, GenerateTransactionDTO as GenerateTransaction,
          LoginDTO as Login, RegisterDTO as Register, UpdateUserDTO as UpdateUser,
          FractalConnectionDTO as ConnectionInvitation, ConfirmPendingConnectionDTO as ConfirmConnection,
      ResetPasswordDTO as ResetPassword};

use chrono::NaiveDate;

pub mod error;
pub mod types;
pub mod oauth;

use error::{Result, Error};
use types::{User, Transaction};
use oauth::AccessToken;

use utils::{WalletAddress, Amount, Address, Relationship};

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
                    let mut response = try!(self.client
                        .post(&format!("{}token", self.url))
                        .body("grant_type=client_credentials")
                        .headers(headers)
                        .send());

                    match response.status {
                        StatusCode::Ok => {
                            let mut response_str = String::new();
                            try!(response.read_to_string(&mut response_str));
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

    /// Gets all users from the database.
    pub fn get_all_users(&self, access_token: &AccessToken) -> Result<Vec<User>> {
        if access_token.scopes().any(|s| s == &Scope::Admin) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = try!(self.client
                .get(&format!("{}all_users", self.url))
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    let dto_users: Vec<UserDTO> = try!(json::decode(&response_str));
                    Ok(dto_users.into_iter()
                        .filter_map(|u| match User::from_dto(u) {
                            Ok(u) => Some(u),
                            Err(_) => None,
                        })
                        .collect())
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
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
            let mut response = try!(self.client
                .get(&format!("{}all_transactions/{}", self.url, first_transaction))
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    let transactions: Vec<Transaction> = try!(json::decode(&response_str));
                    Ok(transactions.into_iter().collect())
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
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
            let response = try!(self.client
                .post(&format!("{}generate_transaction", self.url))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
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

    /// Logs the user in
    pub fn login<S: AsRef<str>>(&self,
                                access_token: &AccessToken,
                                user_email: S,
                                password: S)
                                -> Result<AccessToken> {
        if access_token.scopes().any(|s| s == &Scope::Public) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto: Login = Login {
                user_email: String::from(user_email.as_ref()),
                password: String::from(password.as_ref()),
            };
            let mut response = try!(self.client
                .post(&format!("{}login", self.url))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    Ok(try!(AccessToken::from_dto(try!(json::decode(&response_str)))))
                }
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
            let response = try!(self.client
                .post(&format!("{}start_reset_password", self.url))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    Ok(())
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
                _ => {},
            }
        }
        if user_id.is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let response = try!(self.client
            .get(&format!("{}resend_email_confirmation", self.url))
            .headers(headers)
            .send());
            match response.status {
                StatusCode::Ok => {
                    Ok(())
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
            let mut response = try!(self.client
                .post(&format!("{}register", self.url))
                .body(&json::encode(&register).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    if response_str.contains("Error") {
                        Err(Error::RegistrationError)
                    } else {
                        Ok(())
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
    pub fn set_username<S: AsRef<str>>(&self, access_token: &AccessToken, user_id: u64, password: Option<S>, username: S) -> Result<()> {
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
            let mut response = try!(self.client
                .post(&format!("{}update_user/{}",
                               self.url,
                               user_id))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    Err(Error::Unauthorized)
                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the users phone
    pub fn set_phone<S: AsRef<str>>(&self, access_token: &AccessToken, user_id: u64, password: Option<S>, phone: S) -> Result<()> {
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
            let mut response = try!(self.client
                .post(&format!("{}update_user/{}",
                               self.url,
                               user_id))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    Err(Error::Unauthorized)
                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the users birthday
    pub fn set_birthday<S: AsRef<str>>(&self, access_token: &AccessToken, user_id: u64, password: Option<S>, birthday: NaiveDate) -> Result<()> {
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
            let mut response = try!(self.client
                .post(&format!("{}update_user/{}",
                               self.url,
                               user_id))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    Err(Error::Unauthorized)
                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the users first and last name
    pub fn set_name<S: AsRef<str>>(&self, access_token: &AccessToken, user_id: u64, password: Option<S>, first: S, last: S) -> Result<()> {
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
            let mut response = try!(self.client
                .post(&format!("{}update_user/{}",
                               self.url,
                               user_id))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    Err(Error::Unauthorized)
                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the users email
    pub fn set_email<S: AsRef<str>>(&self, access_token: &AccessToken, user_id: u64, password: Option<S>, email: S) -> Result<()> {
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
            let mut response = try!(self.client
                .post(&format!("{}update_user/{}",
                               self.url,
                               user_id))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    Err(Error::Unauthorized)
                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the users profile picture
    pub fn set_image<S: AsRef<str>>(&self, access_token: &AccessToken, user_id: u64, password: Option<S>, image: S) -> Result<()> {
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
            let mut response = try!(self.client
                .post(&format!("{}update_user/{}",
                               self.url,
                               user_id))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    Err(Error::Unauthorized)
                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Sets the users address
    pub fn set_address<S: AsRef<str>>(&self, access_token: &AccessToken, user_id: u64, password: Option<S>, address: Address) -> Result<()> {
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


            let mut response = try!(self.client
                .post(&format!("{}update_user/{}", self.url, user_id))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    Err(Error::Unauthorized)
                }
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
            let mut response = try!(self.client
                .post(&format!("{}update_user/{}",
                               self.url,
                               access_token.scopes().fold(0, |acc, s| match s {
                                   &Scope::User(id) => id,
                                   _ => acc,
                               })))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    Err(Error::Unauthorized)
                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Creates a pending invitation to connect to the user
    pub fn invite_user_to_connect(&self, access_token: &AccessToken, user: u64, relation: Relationship) -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto: ConnectionInvitation = ConnectionInvitation {
                origin_id:  access_token.scopes().fold(0, |acc, s| match s {
                     &Scope::User(id) => id,
                     _ => acc,
                 }),
                 destination_id: user,
                 relationship: relation,
            };
            let mut response = try!(self.client
                .post(&format!("{}create_pending_connection",
                               self.url,
                              ))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    // TODO read message and return error or success
                    Ok(())
                }
                StatusCode::Unauthorized => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    Err(Error::Unauthorized)
                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Confirms a connection
    pub fn confirm_connection(&self, access_token: &AccessToken, connection_id: u64, user: u64) -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto: ConfirmConnection = ConfirmConnection {
                origin:  user,
                 destination: access_token.scopes().fold(0, |acc, s| match s {
                      &Scope::User(id) => id,
                      _ => acc,
                  }),
                 id: connection_id,
            };
            let mut response = try!(self.client
                .post(&format!("{}confirm_pending_connection",
                               self.url,
                              ))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    if response_str.contains("Error")
                    {
                        Err(Error::ConfirmConnectionError)
                    }
                    else
                    {
                        Ok(())
                    }
                }
                StatusCode::Unauthorized => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    Err(Error::Unauthorized)
                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Confirms the users email
    pub fn confirm_email(&self, email_key: String) -> Result<()> {
        let response = try!(self.client
            .get(&format!("{}confirm_email/{}", self.url, email_key))
            .send());
            match response.status {
                StatusCode::Ok => {
                    Ok(())
                }
                _ => Err(Error::ServerError)
            }
    }

    /// Deletes the user
    pub fn delete_user(&self, access_token: &AccessToken, user_id: u64) -> Result<()> {
        if access_token.scopes().any(|s| s == &Scope::Admin) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let response = try!(self.client
                .delete(&format!("{}user/{}", self.url, user_id))
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
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

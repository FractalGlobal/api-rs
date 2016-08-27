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
use hyper::header::{Headers, Authorization, Basic, Accept, qitem, Connection, ConnectionOption};
use hyper::mime::{Mime, TopLevel, SubLevel, Attr, Value};
use hyper::status::StatusCode;
use rustc_serialize::base64::FromBase64;
use rustc_serialize::json;
use dto::{FromDTO, UserDTO, ScopeDTO as Scope, GenerateTransactionDTO as GenerateTransaction, LoginDTO as Login, RegisterDTO as Register};

pub mod error;
pub mod types;
pub mod oauth;

use error::{Result, Error};
use types::{User, Transaction};
use oauth::AccessToken;

use utils::{WalletAddress, Amount};

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
    pub fn token<S: AsRef<str>>(&mut self, app_id: S, secret: S) -> Result<AccessToken> {
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
                    headers.set(Connection(vec![ConnectionOption::Close]));
                    let mut response = try!(self.client
                        .post(&format!("{}token", self.url))
                        .body("grant_type=client_credentials")
                        .headers(headers)
                        .send());

                    match response.status {
                        StatusCode::Ok => {
                            let mut response_str = String::new();
                            try!(response.read_to_string(&mut response_str));
                            println!("{:?}", response_str);
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
    pub fn get_all_users(&self, access_token: AccessToken) -> Result<Vec<User>> {
        if access_token.scopes().any(|s| s == &Scope::Admin) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            headers.set(Connection(vec![ConnectionOption::Close]));
            let mut response = try!(self.client
                .get(&format!("{}all_users", self.url))
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
                    let dto_users: Vec<UserDTO> = try!(json::decode(&response_str));
                    Ok(dto_users.into_iter().filter_map(|u| match User::from_dto(u) {
                        Ok(u) => Some(u),
                        Err(_) => None,
                    }).collect())
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Gets all the transactions since the given transaction
    pub fn get_all_transactions(&self, access_token: AccessToken, first_transaction: u64) -> Result<Vec<Transaction>> {
        if access_token.scopes().any(|s| s == &Scope::Admin) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            headers.set(Connection(vec![ConnectionOption::Close]));
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
    pub fn generate_transaction(&self, access_token: AccessToken, receiver_wallet: WalletAddress, receiver_id: u64, amount: Amount) -> Result<()> {
        if access_token.scopes().any(|s| match s {&Scope::User(_) => true, _ => false}) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            headers.set(Connection(vec![ConnectionOption::Close]));
            let dto: GenerateTransaction = GenerateTransaction {origin_id: access_token.scopes().fold(0, |acc, s| match s {&Scope::User(id) => id, _ => acc}), destination_address: receiver_wallet, destination_id: receiver_id, amount: amount};
            let mut response = try!(self.client
                .post(&format!("{}generate_transaction", self.url))
                .body(&json::encode(&dto).unwrap())
                .headers(headers)
                .send());
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    try!(response.read_to_string(&mut response_str));
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
    pub fn login<S: AsRef<str>>(&self, access_token: AccessToken, username: S, password: S) -> Result<AccessToken> {
        if access_token.scopes().any(|s| s == &Scope::Public) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            headers.set(Connection(vec![ConnectionOption::Close]));
            let dto: Login = Login {username: String::from(username.as_ref()), password: String::from(password.as_ref())};
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

    // /// Logs the user in
    // pub fn register<S: AsRef<str>>(&self, access_token: AccessToken, username: S, password: S, email: S) -> Result<()> {
    //     if access_token.scopes().any(|s| s == &Scope::Public) && !access_token.has_expired() {
    //         let mut headers = Headers::new();
    //         headers.set(Authorization(access_token.get_token()));
    //         headers.set(Connection(vec![ConnectionOption::Close]));
    //         let mut response = try!(self.client
    //             .post(&format!("{}register", self.url))
    //             .headers(headers)
    //             .send());
    //         match response.status {
    //             StatusCode::Ok => {
    //                 let mut response_str = String::new();
    //                 try!(response.read_to_string(&mut response_str));
    //                 let transactions: Vec<Transaction> = try!(json::decode(&response_str));
    //                 Ok(transactions.into_iter().collect())
    //             }
    //             StatusCode::Unauthorized => Err(Error::Unauthorized),
    //             _ => Err(Error::ServerError),
    //         }
    //     } else {
    //         Err(Error::Unauthorized)
    //     }
    // }
}

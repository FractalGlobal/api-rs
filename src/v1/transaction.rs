use std::io::Read;

use hyper::method::Method;
use hyper::header::{Headers, Authorization};
use rustc_serialize::json;

use utils::{WalletAddress, Amount};
use dto::{FromDTO, ScopeDTO as Scope, GenerateTransactionDTO, TransactionDTO,
          PendingTransactionDTO};

use super::{Client, VoidDTO};

use error::{Result, Error};
use super::types::Transaction;
use super::oauth::AccessToken;

/// Methods for working with transactions.
impl Client {
    /// Gets the given transaction, if authorized.
    pub fn get_transaction(&self,
                           access_token: &AccessToken,
                           transaction_id: u64)
                           -> Result<Transaction> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) | &Scope::Admin => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response =
                try!(self.send_request(Method::Get,
                                       format!("{}transaction/{}", self.url, transaction_id),
                                       headers,
                                       None::<&VoidDTO>));
            let mut response_str = String::new();
            let _ = try!(response.read_to_string(&mut response_str));
            let transaction: TransactionDTO = try!(json::decode(&response_str));
            Ok(try!(Transaction::from_dto(transaction)))
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin or user \
                                               token")))
        }
    }

    /// Generates a new transaction. Returns the code of the transaction
    pub fn new_transaction(&self,
                           access_token: &AccessToken,
                           receiver_wallet: WalletAddress,
                           receiver_id: u64,
                           amount: Amount)
                           -> Result<String> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = GenerateTransactionDTO {
                origin_id: access_token.scopes().fold(0, |acc, s| match s {
                    &Scope::User(id) => id,
                    _ => acc,
                }),
                destination_address: receiver_wallet,
                destination_id: receiver_id,
                amount: amount,
            };
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}new_transaction", self.url),
                                                      headers,
                                                      Some(&dto)));
            let mut response_str = String::new();
            let _ = try!(response.read_to_string(&mut response_str));
            Ok(try!(json::decode::<PendingTransactionDTO>(&response_str)).code)
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user  token")))
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
                                                      None::<&VoidDTO>));
            let mut response_str = String::new();
            let _ = try!(response.read_to_string(&mut response_str));
            let transactions: Vec<TransactionDTO> = try!(json::decode(&response_str));
            Ok(transactions.into_iter()
                .map(|t| Transaction::from_dto(t).unwrap())
                .collect())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin token")))
        }
    }
}
